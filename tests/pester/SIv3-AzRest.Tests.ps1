#Requires -Version 5.1
<#
    AZURE OVER PLAIN REST (REQUIREMENTS 9.3, decision 2) -- engine/_shared/SI-AzRest.ps1.

    No module, no switch (#305): every engine, container, launcher and auth call that used an Az.* cmdlet goes through an
    SI wrapper ('-Az' -> '-SIAz') that does the job over plain REST with SecurityInsight's own tokens.

    OFFLINE: every HTTP call goes through Invoke-SIAzRestHttp, which is mocked here by a fake Azure (tokens, ARM, Log
    Analytics, Resource Graph, storage, Key Vault). No tenant, no network, no credentials, no Az module.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:SIRoot 'auth\Find-SICertificate.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Ws  = "/subscriptions/$($script:Sub)/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/ws-si"
    $script:WsGuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:GlobalNames = 'SI_AzureAccess_Engine', 'SI_AzureAccessEngineWarned', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_UseManagedIdentity',
                          'UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_ManagedIdentityClientId', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret',
                          'SI_SPN_CertThumbprint', 'SpnClientId', 'SpnTenantId', 'SpnClientSecret', 'SpnCertificateThumbprint',
                          'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_CertificateThumbprint_Azure', 'HighPriv_Modern_TenantID',
                          'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_ApplicationSecret_Azure', 'AzureTenantId', 'TenantId',
                          'SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SubscriptionId'

    function script:Resp([int]$Code, [string]$Content = '', [hashtable]$Headers = @{}) {
        $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $Headers.Keys) { $h[$k] = [string]$Headers[$k] }
        [pscustomobject]@{ StatusCode = $Code; Content = $Content; Bytes = $null; Headers = $h; RetryAfter = [string]$h['Retry-After'] }
    }
    function script:Json([int]$Code, $Obj, [hashtable]$Headers = @{}) { Resp $Code ($Obj | ConvertTo-Json -Depth 30 -Compress) $Headers }
    function script:BodyText($b) { if ($b -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($b) } else { [string]$b } }
    function script:Set-SecretSignIn { $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'ten-1'; $global:SI_SPN_Secret = 's3cret' }
}

Describe 'SI Azure access -- the wrappers and their REST twins' {

BeforeEach {
    $script:keep = @{}
    foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    $script:envKeep = [Environment]::GetEnvironmentVariable('SI_AZUREACCESS_ENGINE')
    [Environment]::SetEnvironmentVariable('SI_AZUREACCESS_ENGINE', $null)
    $global:SI_WorkspaceResourceId = $script:Ws
    $script:Calls = [System.Collections.Generic.List[object]]::new()
    $script:Handler = $null
    # the fake Azure: every request is recorded; $script:Handler answers (default 404)
    Mock Invoke-SIAzRestHttp {
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Body = $Body; ContentType = $ContentType; AsBytes = [bool]$AsBytes })
        if ($script:Handler) { $r = & $script:Handler $Method $Uri $Headers $Body; if ($r) { return $r } }
        return (Resp 404 '{"error":{"code":"NotFound","message":"not in the fake"}}')
    }
    Mock Start-Sleep { }
}

AfterEach {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
    [Environment]::SetEnvironmentVariable('SI_AZUREACCESS_ENGINE', $script:envKeep)
}

Describe 'there is no switch -- Azure access is REST only' {
    It 'the old switch functions are gone' {
        foreach ($n in 'Get-SIAzureAccessMode', 'Test-SIAzureRestMode', 'Test-SIAzCommand') { Get-Command -Name $n -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because $n }
    }
    It 'a leftover SI_AzureAccess_Engine = Module in a customer configuration changes nothing: the call is REST' {
        $global:SI_AzureAccess_Engine = 'Module'
        Set-SecretSignIn
        $script:Handler = { param($m, $u) if ($u -like '*login.microsoftonline.com*') { Json 200 @{ access_token = 'tok'; expires_in = 3600 } } elseif ($u -like 'https://management.azure.com/subscriptions?*') { Json 200 @{ value = @(@{ subscriptionId = 's1'; displayName = 'S1'; state = 'Enabled'; tenantId = 'ten-1' }) } } }
        Mock Invoke-SILogIngestHttp { [pscustomobject]@{ StatusCode = 200; Content = (@{ access_token = 'tok'; expires_in = 3600 } | ConvertTo-Json -Compress); RetryAfter = $null } }
        @(Get-SIAzSubscription).Count | Should -Be 1
        Should -Invoke Invoke-SIAzRestHttp -Times 1
    }
}

Describe 'a host with its own sign-in supplies tokens; unset globals are safe under StrictMode' {
    It '$global:SI_TokenProvider is consulted first (both token functions); an empty answer falls through' {
        try {
            $global:SI_TokenProvider = { param($Resource) 'hook|' + $Resource }
            Get-SIAzureToken -Audience Arm | Should -Be 'hook|https://management.azure.com/'
            Get-SILogIngestToken -Resource 'https://monitor.azure.com/' | Should -Be 'hook|https://monitor.azure.com/'
            Should -Invoke Invoke-SIAzRestHttp -Times 0 -Exactly
            $global:SI_TokenProvider = { param($Resource) '' }
            { Get-SIAzureToken -Audience Arm } | Should -Throw '*No sign-in is configured*'
        } finally { Remove-Variable -Scope Global -Name SI_TokenProvider -ErrorAction SilentlyContinue }
    }
    It 'the sign-in decision reads no unset global directly (a caller may run Set-StrictMode)' {
        $r = & {
            Set-StrictMode -Version Latest
            $o = @()
            try { $null = Resolve-SIAzRestAuth } catch { $o += $_.Exception.Message }
            $o += (Resolve-SILogIngestAuth -Bound @{}).Mode
            $o
        }
        $r[0] | Should -Match 'No sign-in is configured'
        $r[1] | Should -Be 'Run'
    }
}

Describe 'tokens -- one function per audience, for every sign-in method' {
    BeforeEach {
        Mock Get-SIManagedIdentityToken { "mi|$Resource|$ClientId" }
        Mock Get-SICertificateClientToken { "cert|$TenantId|$ClientId|$Thumbprint|$Resource" }
        Mock Invoke-SILogIngestHttp {
            $scope = [uri]::UnescapeDataString(([regex]::Match([string]$Body, 'scope=([^&]+)')).Groups[1].Value)
            [pscustomobject]@{ StatusCode = 200; Content = (@{ access_token = ('sec|' + $scope); expires_in = 3600 } | ConvertTo-Json -Compress); RetryAfter = $null }
        }
        function script:Get-AzAccessToken { throw 'the REST path must never ask an Az session for a token' }
    }
    AfterEach { Remove-Item function:\Get-AzAccessToken -ErrorAction SilentlyContinue }

    It '<Audience> as a managed identity: the identity endpoint, with the client id' -TestCases @(
        @{ Audience = 'Arm'; Res = 'https://management.azure.com/' }, @{ Audience = 'LaQuery'; Res = 'https://api.loganalytics.io/' },
        @{ Audience = 'Storage'; Res = 'https://storage.azure.com/' }, @{ Audience = 'KeyVault'; Res = 'https://vault.azure.net/' }) {
        param($Audience, $Res)
        $global:SI_UseManagedIdentity = $true; $global:SI_UAMI_ClientId = 'uami-1'
        Get-SIAzureToken -Audience $Audience | Should -Be ("mi|{0}|uami-1" -f $Res)
    }
    It '<Audience> by certificate: the client assertion from the store, thumbprint without spaces' -TestCases @(
        @{ Audience = 'Arm'; Res = 'https://management.azure.com/' }, @{ Audience = 'LaQuery'; Res = 'https://api.loganalytics.io/' },
        @{ Audience = 'Storage'; Res = 'https://storage.azure.com/' }, @{ Audience = 'KeyVault'; Res = 'https://vault.azure.net/' }) {
        param($Audience, $Res)
        $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'ten-1'; $global:SI_SPN_CertThumbprint = 'AB CD'; $global:SI_SPN_Secret = 'also-set'
        Get-SIAzureToken -Audience $Audience | Should -Be ("cert|ten-1|app-1|ABCD|{0}" -f $Res) -Because 'a certificate wins over a secret'
    }
    It '<Audience> by client secret: client_credentials with <Audience>/.default' -TestCases @(
        @{ Audience = 'Arm'; Res = 'https://management.azure.com/' }, @{ Audience = 'LaQuery'; Res = 'https://api.loganalytics.io/' },
        @{ Audience = 'Storage'; Res = 'https://storage.azure.com/' }, @{ Audience = 'KeyVault'; Res = 'https://vault.azure.net/' }) {
        param($Audience, $Res)
        Set-SecretSignIn
        Get-SIAzureToken -Audience $Audience | Should -Be ('sec|' + $Res + '.default')
    }
    It 'the internal install''s platform identity (HighPriv_*) signs in by certificate' {
        $global:HighPriv_Modern_ApplicationID_Azure = 'hp-app'; $global:HighPriv_Modern_CertificateThumbprint_Azure = 'FF00'; $global:AzureTenantId = 'hp-ten'
        Get-SIAzureToken -Audience Arm | Should -Be 'cert|hp-ten|hp-app|FF00|https://management.azure.com/'
    }
    It 'Connect-SIAzAccount (Rest) RECORDS the identity, and it wins over the configuration' {
        $global:SI_AzureAccess_Engine = 'Rest'
        Set-SecretSignIn
        $null = Connect-SIAzAccount -Identity -AccountId 'uami-x' -Subscription $script:Sub
        Get-SIAzureToken -Audience Storage | Should -Be 'mi|https://storage.azure.com/|uami-x'
        Should -Invoke Invoke-SIAzRestHttp -Times 0 -Because 'recording an identity signs nobody in'
        $cred = [pscredential]::new('app-2', (ConvertTo-SecureString 'pw2' -AsPlainText -Force))
        $null = Connect-SIAzAccount -ServicePrincipal -Tenant 'ten-2' -Credential $cred
        Get-SIAzureToken -Audience Arm | Should -Be 'sec|https://management.azure.com/.default'
        (Resolve-SIAzRestAuth).AppId | Should -Be 'app-2'
        Disconnect-SIAzAccount
        (Resolve-SIAzRestAuth).AppId | Should -Be 'app-1' -Because 'after a disconnect the configuration decides again'
    }
    It 'nothing configured: a clear error, never a fallback to an Az session' {
        { Get-SIAzureToken -Audience Arm } | Should -Throw '*No sign-in is configured*'
    }
    It 'Get-SIAzAccessToken (Rest) has the Az shape: Token, ExpiresOn, TenantId' {
        $global:SI_AzureAccess_Engine = 'Rest'
        $claims = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"tid":"ten-9","exp":1893456000,"appid":"app-9"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        Mock Get-SIAzureToken { "h.$claims.s" }
        $t = Get-SIAzAccessToken -ResourceUrl 'https://storage.azure.com/'
        $t.Token | Should -Be "h.$claims.s"
        $t.TenantId | Should -Be 'ten-9'
        $t.ExpiresOn.ToUnixTimeSeconds() | Should -Be 1893456000
    }
}

Describe 'Log Analytics query -- the data plane, the shape every caller reads' {
    BeforeEach {
        $global:SI_AzureAccess_Engine = 'Rest'
        Mock Get-SIAzureToken { "tok-$Audience" }
        $script:LaBody = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"Findings","type":"long"},{"name":"Score","type":"real"},{"name":"IsTier0","type":"bool"},{"name":"Name","type":"string"},{"name":"Props","type":"dynamic"},{"name":"Empty","type":"string"}],"rows":[["2026-10-01T12:34:56.789Z",42,7.9,true,"srv01","{\"a\":1}",null],["2026-10-02T00:00:00Z",0,0.5,false,"srv02","[]",""]]}]}'
        $script:Handler = { param($m, $u, $h, $b) if ($u -like 'https://api.loganalytics.io/v1/workspaces/*/query') { return (Resp 200 $script:LaBody) } }
    }
    It 'POSTs the query to api.loganalytics.io/v1/workspaces/{id}/query with the LA token and Prefer: wait' {
        $null = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $script:WsGuid -Query 'T | take 1' -Wait 600 -ErrorAction Stop
        $c = @($script:Calls)[0]
        $c.Method | Should -Be 'POST'
        $c.Uri | Should -Be "https://api.loganalytics.io/v1/workspaces/$($script:WsGuid)/query"
        $c.Uri | Should -Not -Match '/api/query' -Because 'the ARM /api/query route hides the semantic error'
        $c.Headers['Authorization'] | Should -Be 'Bearer tok-LaQuery'
        $c.Headers['Prefer'] | Should -Be 'wait=600'
        ((BodyText $c.Body) | ConvertFrom-Json).query | Should -Be 'T | take 1'
    }
    It '.Results: one object per row, one TEXT property per column -- as Az.OperationalInsights hands them' {
        $r = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($r.Results).Count | Should -Be 2
        $row = @($r.Results)[0]
        @($row.PSObject.Properties.Name) -join ',' | Should -Be 'TimeGenerated,Findings,Score,IsTier0,Name,Props,Empty'
        $row.TimeGenerated | Should -Be '2026-10-01T12:34:56.789Z' -Because 'the date is the text the service sent, on 5.1 and 7 alike'
        $row.TimeGenerated | Should -BeOfType [string]
        $row.Findings | Should -Be '42'
        $row.Score | Should -Be '7.9'
        $row.IsTier0 | Should -Be 'true'
        $row.Props | Should -Be '{"a":1}'
        $row.Empty | Should -BeNullOrEmpty
        # what the callers do with them
        [int]$row.Findings | Should -Be 42
        [double]$row.Score | Should -Be 7.9
        ([datetime]::Parse($row.TimeGenerated, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)).Minute | Should -Be 34
        (@($r.Results)[1]).IsTier0 -eq 'false' | Should -BeTrue
    }
    It 'an empty result: .Results is empty and falsy, as the callers test it' {
        $script:LaBody = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[]}]}'
        $r = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $script:WsGuid -Query 'q'
        @($r.Results).Count | Should -Be 0
        (-not $r.Results) | Should -BeTrue
        foreach ($x in $r.Results) { throw 'no rows expected' }
    }
    It 'a refused query throws with the service''s own code and message (SEM0100), and the body for SI-KqlError' {
        $err = '{"error":{"message":"The request had some invalid properties","code":"BadArgumentError","correlationId":"c1","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"''where'' operator: Failed to resolve table or column expression named ''SI_PublicIP_Profile_CL''"}}}}'
        $script:Handler = { param($m, $u) Resp 400 $err }
        $caught = $null
        try { $null = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $script:WsGuid -Query 'SI_PublicIP_Profile_CL' -ErrorAction Stop } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match "invalid status code 'BadRequest'" -Because 'classifiers that matched the Az message keep matching'
        $caught.Exception.Message | Should -Match 'SEM0100'
        $caught.Exception.Message | Should -Match 'Failed to resolve table or column expression'
        $caught.ErrorDetails.Message | Should -Be $err
        Test-SIKqlTableMissing -ErrorRecord $caught -TableName 'SI_PublicIP_Profile_CL' | Should -BeTrue
        Test-SIKqlTableMissing -ErrorRecord $caught -TableName 'SI_Other_CL' | Should -BeFalse
        @($script:Calls).Count | Should -Be 1 -Because 'a query defect fails on attempt 1 -- re-running fails identically'
    }
    It 'throttling (429) is retried as the service asks, then the rows come back' {
        $script:n = 0
        $script:Handler = { param($m, $u) $script:n++; if ($script:n -eq 1) { return (Resp 429 '{"error":{"code":"Throttled"}}' @{ 'Retry-After' = '4' }) }; Resp 200 $script:LaBody }
        @((Invoke-SIAzOperationalInsightsQuery -WorkspaceId $script:WsGuid -Query 'q').Results).Count | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 4 }
    }
    It '-RowsOnly (large answers): the SAME rows, read from the answer''s bytes -- never held as one text or as its tables a second time' {
        $plain = @((Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q').Results)
        # the service's answer as bytes, as the HTTP seam hands it over when asked for bytes
        $script:Handler = { param($m, $u, $h, $b) $a = Resp 200 ''; $a.Bytes = [System.Text.Encoding]::UTF8.GetBytes($script:LaBody); $a }
        $script:Calls.Clear()
        $lean = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -Wait 600 -RowsOnly
        @($script:Calls)[0].AsBytes | Should -BeTrue -Because 'the answer must arrive as bytes, not as one text'
        @($script:Calls)[0].Headers['Prefer'] | Should -Be 'wait=600'
        @($script:Calls)[0].Headers['Authorization'] | Should -Be 'Bearer tok-LaQuery'
        $rows = @($lean.Results)
        $rows.Count | Should -Be 2
        # #639: the tables are not kept beside the rows -- ONE entry, the primary table's schema, no rows
        @($lean.Tables).Count | Should -Be 1
        @($lean.Tables)[0].RowsOmitted | Should -BeTrue
        @(@($lean.Tables)[0].Rows).Count | Should -Be 0
        @($lean.Columns | ForEach-Object name) -join ',' | Should -Be (@($plain[0].PSObject.Properties.Name) -join ',')
        for ($i = 0; $i -lt 2; $i++) {
            (@($rows[$i].PSObject.Properties.Name) -join ',') | Should -Be (@($plain[$i].PSObject.Properties.Name) -join ',')
            foreach ($n in @($plain[$i].PSObject.Properties.Name)) { $rows[$i].$n | Should -BeExactly $plain[$i].$n -Because "row $i, column $n" }
        }
        $rows[0].TimeGenerated | Should -BeOfType [string]
        $rows[0].Findings | Should -Be '42'
        $rows[0].IsTier0 | Should -Be 'true'
        $rows[0].Props | Should -Be '{"a":1}'
        $rows[0].Empty | Should -BeNullOrEmpty
    }
    It '#639 THE LEAN READ IS THE DEFAULT: without -RowsOnly the answer is asked for as bytes on pwsh 7 and gives the same rows, the same text values and the column types' {
        $plain = @((Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q').Results)   # the fake answers text: the text path
        $script:Handler = { param($m, $u, $h, $b) $a = Resp 200 ''; $a.Bytes = [System.Text.Encoding]::UTF8.GetBytes($script:LaBody); $a }
        $script:Calls.Clear()
        $lean = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q'
        if ($PSVersionTable.PSEdition -eq 'Core') { @($script:Calls)[0].AsBytes | Should -BeTrue -Because 'every read is lean on pwsh 7, not only the ones that ask' }
        $rows = @($lean.Results)
        $rows.Count | Should -Be $plain.Count
        for ($i = 0; $i -lt $rows.Count; $i++) {
            (@($rows[$i].PSObject.Properties.Name) -join ',') | Should -Be (@($plain[$i].PSObject.Properties.Name) -join ',')
            foreach ($n in @($plain[$i].PSObject.Properties.Name)) {
                $rows[$i].$n | Should -BeExactly $plain[$i].$n -Because "row $i, column $n"
                if ($null -ne $plain[$i].$n) { $rows[$i].$n.GetType().FullName | Should -Be $plain[$i].$n.GetType().FullName -Because "row $i, column $n keeps its type" }
            }
        }
        @($lean.Columns | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',' | Should -Be 'TimeGenerated:datetime,Findings:long,Score:real,IsTier0:bool,Name:string,Props:dynamic,Empty:string'
        @($lean.Tables).Count | Should -Be 1
        @(@($lean.Tables)[0].Rows).Count | Should -Be 0 -Because 'the rows are never held a second time as a table'
        # the Risk Analysis reader takes its column types from the schema entry, as before
        @(@($lean.Tables)[0].Columns | ForEach-Object name) | Should -Contain 'Findings'
    }
    It '-RowsOnly: a refused query still throws with the service''s own code, and carries the body for SI-KqlError' {
        $err = '{"error":{"message":"The request had some invalid properties","code":"BadArgumentError","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"''where'' operator: Failed to resolve table or column expression named ''SI_X_CL''"}}}}'
        $script:Handler = { param($m, $u) $a = Resp 400 ''; $a.Bytes = [System.Text.Encoding]::UTF8.GetBytes($err); $a }
        $caught = $null
        try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'SI_X_CL' -RowsOnly } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match "invalid status code 'BadRequest'"
        $caught.Exception.Message | Should -Match 'SEM0100'
        $caught.ErrorDetails.Message | Should -Be $err
        Test-SIKqlTableMissing -ErrorRecord $caught -TableName 'SI_X_CL' | Should -BeTrue
        @($script:Calls).Count | Should -Be 1
    }
    It '-RowsOnly: an answer the service CUT SHORT is REFUSED by default (#639) -- its rows come back only to a caller that opts in (-AllowPartial) and reads the error itself' {
        $script:LaBody = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[["x"]]}],"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Query result set has exceeded the internal data size limit 64000000 (E_QUERY_RESULT_SET_TOO_LARGE)"}]}}'
        $script:Handler = { param($m, $u, $h, $b) $a = Resp 200 ''; $a.Bytes = [System.Text.Encoding]::UTF8.GetBytes($script:LaBody); $a }
        $caught = $null
        try { $null = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -RowsOnly } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty -Because 'a cut answer is never handed out as whole'
        $caught.Exception.Message | Should -Match 'PARTIAL answer'
        (Get-SIKqlErrorText -ErrorRecord $caught) | Should -Match 'E_QUERY_RESULT_SET_TOO_LARGE' -Because 'the paged readers cut a "too large" page in two on these words'
        $lean = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -RowsOnly -AllowPartial
        @($lean.Results).Count | Should -Be 1
        [string]$lean.Error.code | Should -Be 'PartialError'
        $lean.Partial | Should -Be 'Limit'
        (ConvertTo-Json -InputObject $lean.Error -Depth 8 -Compress) | Should -Match 'E_QUERY_RESULT_SET_TOO_LARGE'
    }
    It '-RowsOnly: an empty result is empty and falsy; a row shorter than its columns keeps every column; the primary table is found wherever it is' {
        $script:Handler = { param($m, $u, $h, $b) $a = Resp 200 ''; $a.Bytes = [System.Text.Encoding]::UTF8.GetBytes($script:LaBody); $a }
        $script:LaBody = '{"tables":[{"name":"PrimaryResult","columns":[{"name":"a","type":"string"}],"rows":[]}]}'
        $lean = Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -RowsOnly
        @($lean.Results).Count | Should -Be 0
        (-not $lean.Results) | Should -BeTrue
        $script:LaBody = '{"tables":[{"name":"Other","columns":[{"name":"z","type":"string"}],"rows":[["no"]]},{"name":"PrimaryResult","columns":[{"name":"a","type":"string"},{"name":"b","type":"long"}],"rows":[["only"]]}]}'
        $rows = @((Invoke-SILaQuery -WorkspaceId $script:WsGuid -Query 'q' -RowsOnly).Results)
        $rows.Count | Should -Be 1
        (@($rows[0].PSObject.Properties.Name) -join ',') | Should -Be 'a,b'
        $rows[0].a | Should -Be 'only'
        $rows[0].b | Should -BeNullOrEmpty
    }
    It 'Risk Analysis end to end: the workspace id from ARM, the rows from the data plane, the comma-protected array' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1')
        $script:Handler = { param($m, $u)
            if ($u -like 'https://management.azure.com/subscriptions/*/workspaces/ws-si?*') { return (Json 200 @{ id = $script:Ws; name = 'ws-si'; location = 'westeurope'; properties = @{ customerId = $script:WsGuid } }) }
            if ($u -like "https://api.loganalytics.io/v1/workspaces/$($script:WsGuid)/query") { return (Resp 200 $script:LaBody) }
        }
        $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $script:Ws -Query 'q'
        $rows.Count | Should -Be 2
        $rows[1].Name | Should -Be 'srv02'
        @($script:Calls | Where-Object { $_.Uri -like '*api.loganalytics.io*' }).Count | Should -Be 1
    }
}

Describe 'Resource Graph -- paging with $skipToken' {
    BeforeEach {
        $global:SI_AzureAccess_Engine = 'Rest'
        Mock Get-SIAzureToken { "tok-$Audience" }
        $script:Handler = { param($m, $u, $h, $b)
            if ($u -notlike 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources*') { return }
            $req = (BodyText $b) | ConvertFrom-Json
            $tok = [string]$req.options.'$skipToken'
            switch ($tok) {
                ''   { return (Json 200 @{ totalRecords = 5; count = 2; data = @(@{ id = 'r1' }, @{ id = 'r2' }); '$skipToken' = 'p2' }) }
                'p2' { return (Json 200 @{ totalRecords = 5; count = 2; data = @(@{ id = 'r3' }, @{ id = 'r4' }); '$skipToken' = 'p3' }) }
                'p3' { return (Json 200 @{ totalRecords = 5; count = 1; data = @(@{ id = 'r5' }) }) }
            }
        }
    }
    It 'Search-SIResourceGraph returns every row of every page, scoped to the subscriptions given' {
        $rows = Search-SIResourceGraph -Query 'resources' -Subscription @($script:Sub, '')
        @($rows | ForEach-Object { $_.id }) -join ',' | Should -Be 'r1,r2,r3,r4,r5'
        @($script:Calls).Count | Should -Be 3
        $first = (BodyText $script:Calls[0].Body) | ConvertFrom-Json
        @($first.subscriptions) | Should -Be @($script:Sub) -Because 'an empty subscription id never reaches Azure (it answers BadRequest)'
        $first.options.resultFormat | Should -Be 'objectArray'
        $first.options.'$top' | Should -Be 1000
        $script:Calls[0].Uri | Should -Match 'api-version=2022-10-01'
        $script:Calls[0].Headers['Authorization'] | Should -Be 'Bearer tok-Arm'
    }
    It 'Search-SIAzGraph (Rest) is one page shaped like Search-AzGraph: enumerates the rows, carries .SkipToken and .Data' {
        $page = Search-SIAzGraph -Query 'resources' -First 2
        @($page).Count | Should -Be 2
        $page.SkipToken | Should -Be 'p2'
        @($page.Data).Count | Should -Be 2
        $page.PSObject.Properties['SkipToken'] | Should -Not -BeNullOrEmpty
        $ids = foreach ($r in $page) { $r.id }; $ids -join ',' | Should -Be 'r1,r2'
    }
    It 'the engines'' own pager (Invoke-SIArgPaged) walks every page through the wrapper' {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Invoke-SIArgPaged.ps1')
        $res = Invoke-SIArgPaged -Query 'resources' -SourceLabel 'test'
        @($res.Rows | ForEach-Object { $_.id }) -join ',' | Should -Be 'r1,r2,r3,r4,r5'
    }
}

Describe 'Azure Resource Manager -- nextLink, retries, fail fast' {
    BeforeEach { Mock Get-SIAzureToken { "tok-$Audience" } }
    It 'a list follows nextLink to the end' {
        $script:Handler = { param($m, $u)
            if ($u -like '*page=2*') { return (Json 200 @{ value = @(@{ name = 'c' }) }) }
            if ($u -like 'https://management.azure.com/subscriptions/s1/resourcegroups?api-version=2021-04-01') { return (Json 200 @{ value = @(@{ name = 'a' }, @{ name = 'b' }); nextLink = 'https://management.azure.com/subscriptions/s1/resourcegroups?api-version=2021-04-01&page=2' }) }
        }
        @(Invoke-SIArm -Path '/subscriptions/s1/resourcegroups' -ApiVersion '2021-04-01' -List | ForEach-Object { $_.name }) -join ',' | Should -Be 'a,b,c'
    }
    It '429 waits the Retry-After the service sent, 5xx is retried, then the answer' {
        $script:n = 0
        $script:Handler = { param($m, $u) $script:n++
            if ($script:n -eq 1) { return (Resp 429 'slow down' @{ 'Retry-After' = '3' }) }
            if ($script:n -eq 2) { return (Resp 503 'busy') }
            Json 200 @{ name = 'ok' } }
        (Invoke-SIArm -Path '/subscriptions/s1' -ApiVersion '2022-12-01').name | Should -Be 'ok'
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 3 }
        @($script:Calls).Count | Should -Be 3
    }
    It 'any other 4xx fails FAST with the body -- one call, no retry' {
        $script:Handler = { param($m, $u) Resp 400 '{"error":{"code":"InvalidTemplate","message":"bad body"}}' }
        { Invoke-SIArm -Method PUT -Path '/subscriptions/s1/resourcegroups/rg' -ApiVersion '2021-04-01' -Body @{ location = 'x' } } | Should -Throw '*HTTP Status: 400*InvalidTemplate*'
        @($script:Calls).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 0
    }
    It '401 refreshes the token once and repeats the call' {
        $script:n = 0
        $script:Handler = { param($m, $u) $script:n++; if ($script:n -eq 1) { return (Resp 401 'expired') }; Json 200 @{ name = 'ok' } }
        (Invoke-SIArm -Path '/subscriptions/s1' -ApiVersion '2022-12-01').name | Should -Be 'ok'
        Should -Invoke Get-SIAzureToken -ParameterFilter { $ForceRefresh } -Times 1
    }
    It '404 with -AllowNotFound is $null, not an error' {
        Invoke-SIArm -Path '/subscriptions/s1/resourcegroups/none' -ApiVersion '2021-04-01' -AllowNotFound | Should -BeNullOrEmpty
    }
    It 'Invoke-SIAzRestMethod (Rest) never throws on a status, like Invoke-AzRestMethod' {
        $global:SI_AzureAccess_Engine = 'Rest'
        $script:Handler = { param($m, $u) Resp 404 '{"error":{"code":"ResourceNotFound"}}' }
        $r = Invoke-SIAzRestMethod -Path '/subscriptions/s1/x?api-version=1' -Method GET -ErrorAction Stop
        $r.StatusCode | Should -Be 404
        $r.Content | Should -Match 'ResourceNotFound'
    }
}

Describe 'the Az context, workspace, resource group and role lookups the engines make (Rest)' {
    BeforeEach {
        $global:SI_AzureAccess_Engine = 'Rest'
        Set-SecretSignIn
        Mock Get-SIAzureToken { "tok-$Audience" }
    }
    It 'Get-SIAzContext: subscription from the install''s workspace, tenant and account from the sign-in' {
        $c = Get-SIAzContext
        $c.Subscription.Id | Should -Be $script:Sub
        $c.Tenant.Id | Should -Be 'ten-1'
        $c.Account.Id | Should -Be 'app-1'
        $c.Account.Type | Should -Be 'ServicePrincipal'
        Should -Invoke Invoke-SIAzRestHttp -Times 0
    }
    It 'Set-SIAzContext switches the subscription the next lookups use; the workspace has CustomerId.Guid' {
        $null = Set-SIAzContext -SubscriptionId 'sub-2' -ErrorAction Stop
        (Get-SIAzContext).Subscription.Id | Should -Be 'sub-2'
        $script:Handler = { param($m, $u) if ($u -like 'https://management.azure.com/subscriptions/sub-2/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/ws-si?api-version=*') { Json 200 @{ id = 'wsid'; name = 'ws-si'; location = 'westeurope'; properties = @{ customerId = $script:WsGuid } } } }
        $ws = Get-SIAzOperationalInsightsWorkspace -ResourceGroupName 'rg-la' -Name 'ws-si' -ErrorAction Stop
        $ws.CustomerId.Guid | Should -Be $script:WsGuid
        [string]$ws.CustomerId | Should -Be $script:WsGuid
        $ws.ResourceId | Should -Be 'wsid'
    }
    It 'a lookup that finds nothing is a NON-terminating error: $null with SilentlyContinue, a throw with Stop' {
        Get-SIAzResourceGroup -Name 'rg-none' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        { Get-SIAzResourceGroup -Name 'rg-none' -ErrorAction Stop } | Should -Throw '*does not exist*'
        Get-SIAzOperationalInsightsWorkspace -ResourceGroupName 'rg' -Name 'none' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'role assignments carry the role NAME and principal type the engines filter on' {
        $script:Handler = { param($m, $u)
            # the assignment read asks for names only, built-ins and a scope's custom roles apart (#702); a full list read too
            if ($u -like '*/roleDefinitions?*' -and $u -match 'CustomRole') { return (Json 200 @{ value = @() }) }
            if ($u -like '*/roleDefinitions?*') { return (Json 200 @{ value = @(@{ name = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; id = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'; properties = @{ roleName = 'Contributor'; type = 'BuiltInRole'; permissions = @(@{ actions = @('*') }) } }) }) }
            if ($u -like '*/roleAssignments?*') { return (Json 200 @{ value = @(@{ id = 'ra1'; name = 'ra1'; properties = @{ scope = '/subscriptions/x/resourceGroups/rg'; principalId = 'oid-1'; principalType = 'ServicePrincipal'; roleDefinitionId = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c' } }) }) }
            if ($u -like 'https://graph.microsoft.com/*getByIds') { return (Json 200 @{ value = @(@{ id = 'oid-1'; displayName = 'sp-si' }) }) }
        }
        $a = @(Get-SIAzRoleAssignment -ObjectId 'oid-1' -Scope '/subscriptions/x/resourceGroups/rg' -ErrorAction SilentlyContinue | Where-Object { $_.RoleDefinitionName -eq 'Contributor' })
        $a.Count | Should -Be 1
        $a[0].Scope | Should -Be '/subscriptions/x/resourceGroups/rg'
        $a[0].ObjectType | Should -Be 'ServicePrincipal'
        $a[0].DisplayName | Should -Be 'sp-si'
        [uri]::UnescapeDataString((@($script:Calls | Where-Object { $_.Uri -like '*roleAssignments*' })[0].Uri)) | Should -Match "principalId eq 'oid-1'"
        (Get-SIAzRoleDefinition)[0].Name | Should -Be 'Contributor'
    }
    It 'New-SIAzRoleAssignment PUTs the role definition id and the principal' {
        $script:Handler = { param($m, $u, $h, $b)
            if ($u -like '*/roleDefinitions?api-version=*') { return (Json 200 @{ value = @(@{ name = 'rd1'; id = '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/rd1'; properties = @{ roleName = 'Monitoring Metrics Publisher' } }) }) }
            if ($m -eq 'PUT') { return (Json 201 @{ id = 'ra-new'; name = 'n'; properties = @{ principalType = 'ServicePrincipal' } }) }
        }
        $null = New-SIAzRoleAssignment -ObjectId 'oid-2' -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope '/subscriptions/x/resourceGroups/rg' -ErrorAction Stop
        $put = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put.Uri | Should -Match '^https://management.azure.com/subscriptions/x/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/[0-9a-f-]{36}\?api-version=2022-04-01$'
        $j = (BodyText $put.Body) | ConvertFrom-Json
        $j.properties.roleDefinitionId | Should -Be '/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/rd1'
        $j.properties.principalId | Should -Be 'oid-2'
    }
    It 'tags: read as TagsProperty, written with a Merge PATCH' {
        $script:Handler = { param($m, $u) if ($u -like '*/providers/Microsoft.Resources/tags/default*') { Json 200 @{ id = 't'; properties = @{ tags = @{ Owner = 'x' } } } } }
        $t = (Get-SIAzTag -ResourceId '/subscriptions/x/resourceGroups/rg/providers/A/b/c' -ErrorAction Stop).Properties.TagsProperty
        $t.ContainsKey('Owner') | Should -BeTrue
        $null = Update-SIAzTag -ResourceId '/subscriptions/x/resourceGroups/rg/providers/A/b/c' -Tag @{ AssetTag = 'T0' } -Operation Merge -ErrorAction Stop
        $p = @($script:Calls | Where-Object { $_.Method -eq 'PATCH' })[0]
        $j = (BodyText $p.Body) | ConvertFrom-Json
        $j.operation | Should -Be 'Merge'
        $j.properties.tags.AssetTag | Should -Be 'T0'
    }
}

Describe 'storage, Key Vault -- the request shapes (OAuth bearer, x-ms-version)' {
    BeforeEach {
        $global:SI_AzureAccess_Engine = 'Rest'
        Mock Get-SIAzureToken { "tok-$Audience" }
        $script:Ctx = New-SIAzStorageContext -StorageAccountName 'stsi' -UseConnectedAccount
    }
    It 'a storage context is OAuth only -- there is no key form (#307)' {
        (Get-Command New-SIAzStorageContext).Parameters.Keys | Should -Not -Contain 'StorageAccountKey'
        $script:Ctx.StorageAccountName | Should -Be 'stsi'
    }
    It 'upload: PUT block blob with the storage token and x-ms-version; If-Match for the conditional write' {
        $script:Handler = { param($m, $u) if ($m -eq 'PUT') { Resp 201 '' @{ ETag = '"0x2"' } } }
        $f = [System.IO.Path]::GetTempFileName(); [System.IO.File]::WriteAllText($f, 'hello')
        try {
            $b = Set-SIAzStorageBlobContent -File $f -Container 'sistaging' -Blob 'a/b.json' -Context $script:Ctx -Force -ErrorAction Stop
            $c = $script:Calls[0]
            $c.Method | Should -Be 'PUT'
            $c.Uri | Should -Be 'https://stsi.blob.core.windows.net/sistaging/a/b.json'
            $c.Headers['Authorization'] | Should -Be 'Bearer tok-Storage'
            $c.Headers['x-ms-version'] | Should -Be (Get-SIStorageApiVersion)
            $c.Headers['x-ms-blob-type'] | Should -Be 'BlockBlob'
            (BodyText $c.Body) | Should -Be 'hello'
            $b.Name | Should -Be 'a/b.json'
            Set-SIAzStorageBlobContentIfMatch -File $f -Container 'c' -Blob 'ledger.json' -Context $script:Ctx -IfMatchETag '"0x1"'
            $script:Calls[1].Headers['If-Match'] | Should -Be '"0x1"'
        } finally { Remove-Item $f -Force }
    }
    It 'a lost conditional write fails with 412 ConditionNotMet -- what the ledger recognises' {
        $script:Handler = { param($m, $u) Resp 412 '' @{ 'x-ms-error-code' = 'ConditionNotMet' } }
        $f = [System.IO.Path]::GetTempFileName()
        try {
            $msg = $null
            try { Set-SIAzStorageBlobContentIfMatch -File $f -Container 'c' -Blob 'ledger.json' -Context $script:Ctx -IfMatchETag '"0x1"' } catch { $msg = $_.Exception.Message }
            $msg | Should -Match 'ConditionNotMet|412'
        } finally { Remove-Item $f -Force }
    }
    It 'list: every blob under the prefix, following the marker; the Az blob shape' {
        $script:Handler = { param($m, $u)
            if ($u -like '*comp=list*marker=m2*') { return (Resp 200 '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>runlogs/b.log</Name><Properties><Last-Modified>Thu, 01 Oct 2026 10:00:00 GMT</Last-Modified><Etag>0x2</Etag><Content-Length>7</Content-Length></Properties></Blob></Blobs><NextMarker /></EnumerationResults>') }
            if ($u -like '*comp=list*') { return (Resp 200 '<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs><Blob><Name>runlogs/a.log</Name><Properties><Last-Modified>Wed, 30 Sep 2026 10:00:00 GMT</Last-Modified><Etag>0x1</Etag><Content-Length>5</Content-Length></Properties></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>') }
        }
        $l = @(Get-SIAzStorageBlob -Container 'sistaging' -Prefix 'runlogs/' -Context $script:Ctx -ErrorAction Stop)
        @($l | ForEach-Object { $_.Name }) -join ',' | Should -Be 'runlogs/a.log,runlogs/b.log'
        $l[0].Length | Should -Be 5
        $l[1].LastModified.UtcDateTime.Day | Should -Be 1
        $l[0].ICloudBlob.Properties.ETag | Should -Be '0x1'
        $script:Calls[0].Uri | Should -Match 'restype=container&comp=list&maxresults=5000&prefix=runlogs%2F'
    }
    It 'one blob: HEAD for its properties; missing = BlobNotFound, $null with SilentlyContinue' {
        $script:Handler = { param($m, $u) if ($m -eq 'HEAD' -and $u -like '*/x.json') { Resp 200 '' @{ 'Content-Length' = '3'; ETag = '"e1"'; 'Last-Modified' = 'Thu, 01 Oct 2026 10:00:00 GMT' } } }
        (Get-SIAzStorageBlob -Container 'c' -Blob 'x.json' -Context $script:Ctx -ErrorAction Stop).ICloudBlob.Properties.ETag | Should -Be '"e1"'
        Get-SIAzStorageBlob -Container 'c' -Blob 'missing.json' -Context $script:Ctx -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        { Get-SIAzStorageBlob -Container 'c' -Blob 'missing.json' -Context $script:Ctx -ErrorAction Stop } | Should -Throw '*BlobNotFound*'
    }
    It 'download: the bytes land in -Destination unchanged' {
        $script:Handler = { param($m, $u)
            if ($m -eq 'GET') { $r = Resp 200 ''; $r.Bytes = [byte[]](0xEF, 0xBB, 0xBF, 0x7B, 0x7D); return $r }
            if ($m -eq 'HEAD') { Resp 200 '' @{ 'Content-Length' = '5' } } }
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ('si-azrest-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            $null = Get-SIAzStorageBlobContent -Container 'c' -Blob 'x.json' -Destination $f -Context $script:Ctx -Force -ErrorAction Stop
            [System.IO.File]::ReadAllBytes($f).Count | Should -Be 5
            @($script:Calls | Where-Object { $_.Method -eq 'GET' })[0].AsBytes | Should -BeTrue
        } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    It 'container: HEAD restype=container; create = PUT, an existing one is not an error' {
        $script:Handler = { param($m, $u) if ($m -eq 'PUT') { Resp 409 '' @{ 'x-ms-error-code' = 'ContainerAlreadyExists' } } }
        Get-SIAzStorageContainer -Name 'sicatalog' -Context $script:Ctx -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        { New-SIAzStorageContainer -Name 'sicatalog' -Context $script:Ctx -Permission Off -ErrorAction Stop } | Should -Not -Throw
        @($script:Calls | ForEach-Object { '{0} {1}' -f $_.Method, $_.Uri }) | Should -Be @('HEAD https://stsi.blob.core.windows.net/sicatalog?restype=container', 'PUT https://stsi.blob.core.windows.net/sicatalog?restype=container')
    }
    It 'queue: the worker queue runs unchanged on the REST queue client (send, lease, delete)' {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')
        $script:Q = [System.Collections.Generic.List[string]]::new()
        $script:Handler = { param($m, $u, $h, $b)
            if ($u -like '*comp=metadata') { if ($script:qmade) { return (Resp 200 '') } else { return (Resp 404 '' @{ 'x-ms-error-code' = 'QueueNotFound' }) } }
            if ($m -eq 'PUT' -and $u -like 'https://stsi.queue.core.windows.net/work') { $script:qmade = $true; return (Resp 201 '') }
            if ($m -eq 'POST') { $script:Q.Add(([xml](BodyText $b)).QueueMessage.MessageText); return (Resp 201 '<QueueMessagesList><QueueMessage><MessageId>m1</MessageId><PopReceipt>p0</PopReceipt></QueueMessage></QueueMessagesList>') }
            if ($m -eq 'GET' -and $u -like '*/work/messages?*') {
                $txt = [System.Security.SecurityElement]::Escape($script:Q[0])
                return (Resp 200 ('<?xml version="1.0" encoding="utf-8"?><QueueMessagesList><QueueMessage><MessageId>m1</MessageId><PopReceipt>pop/1+</PopReceipt><DequeueCount>2</DequeueCount><MessageText>{0}</MessageText></QueueMessage></QueueMessagesList>' -f $txt))
            }
            if ($m -eq 'DELETE') { return (Resp 204 '') }
        }
        $script:qmade = $false
        $ctx = New-SIStorageContext -AccountName 'stsi' -UseOAuth
        Initialize-SIQueue -Context $ctx -QueueName 'work' | Should -Be 'work'
        Add-SIWorkItem -Context $ctx -QueueName 'work' -Payload @{ Shard = 3; Note = 'a<b & "c"' }
        $w = Get-SINextWorkItem -Context $ctx -QueueName 'work' -VisibilityTimeoutSeconds 3900
        $w.Payload.Shard | Should -Be 3
        $w.Payload.Note | Should -Be 'a<b & "c"' -Because 'the message text survives the XML round trip'
        $w.DequeueCount | Should -Be 2
        Complete-SIWorkItem -Context $ctx -QueueName 'work' -Id $w.Id -PopReceipt $w.PopReceipt
        $get = @($script:Calls | Where-Object { $_.Method -eq 'GET' -and $_.Uri -like '*/messages?*' })[0]
        $get.Uri | Should -Be 'https://stsi.queue.core.windows.net/work/messages?numofmessages=1&visibilitytimeout=3900'
        $del = @($script:Calls | Where-Object { $_.Method -eq 'DELETE' })[0]
        $del.Uri | Should -Be 'https://stsi.queue.core.windows.net/work/messages/m1?popreceipt=pop%2F1%2B'
    }
    It 'table: upsert = PUT the entity at its keys; a partition read follows the continuation headers' {
        $script:Handler = { param($m, $u, $h)
            if ($m -eq 'PUT') { return (Resp 204 '') }
            if ($m -eq 'GET' -and $u -like '*NextPartitionKey=*') { return (Json 200 @{ value = @(@{ PartitionKey = 'p'; RowKey = 'r2' }) }) }
            if ($m -eq 'GET') { return (Json 200 @{ value = @(@{ PartitionKey = 'p'; RowKey = 'r1' }) } @{ 'x-ms-continuation-NextPartitionKey' = 'p'; 'x-ms-continuation-NextRowKey' = 'r2' }) }
        }
        Set-SITableEntity -Account 'stsi' -Table 'SIFingerprint' -PartitionKey "o'k" -RowKey 'r1' -Entity @{ Hash = 'abc' }
        $put = $script:Calls[0]
        [uri]::UnescapeDataString($put.Uri) | Should -Be "https://stsi.table.core.windows.net/SIFingerprint(PartitionKey='o''k',RowKey='r1')"
        $put.Headers['Authorization'] | Should -Be 'Bearer tok-Storage'
        $j = (BodyText $put.Body) | ConvertFrom-Json
        $j.Hash | Should -Be 'abc'; $j.RowKey | Should -Be 'r1'
        @(Get-SITableEntity -Account 'stsi' -Table 'SIFingerprint' -PartitionKey 'p' | ForEach-Object { $_.RowKey }) -join ',' | Should -Be 'r1,r2'
    }
    It 'Key Vault: GET secrets/{name} with the vault token; SecretValue is a SecureString; a missing secret is $null' {
        $script:Handler = { param($m, $u) if ($u -like 'https://kv-si.vault.azure.net/secrets/SpnSecret?api-version=7.4') { Json 200 @{ value = 'p@ss'; id = 'https://kv-si.vault.azure.net/secrets/SpnSecret/v1' } } }
        $s = Get-SIAzKeyVaultSecret -VaultName 'kv-si' -Name 'SpnSecret' -ErrorAction Stop
        $s.SecretValue | Should -BeOfType [System.Security.SecureString]
        [System.Net.NetworkCredential]::new('', $s.SecretValue).Password | Should -Be 'p@ss'
        $script:Calls[0].Headers['Authorization'] | Should -Be 'Bearer tok-KeyVault'
        Get-SIKeyVaultSecretValue -VaultName 'kv-si' -Name 'SpnSecret' | Should -Be 'p@ss'
        Get-SIAzKeyVaultSecret -VaultName 'kv-si' -Name 'Nope' -ErrorAction Stop | Should -BeNullOrEmpty
    }
    It 'the auth helper Get-SIKvSecret reads a secret with no Az module at all' {
        Set-SecretSignIn
        . (Join-Path $script:SIRoot 'auth\Get-SIKvSecret.ps1')
        $script:Handler = { param($m, $u) if ($u -like 'https://kv-si.vault.azure.net/secrets/OpenAI-ApiKey?*') { Json 200 @{ value = 'k-123' } } }
        Get-SIKvSecret -VaultName 'kv-si' -SecretName 'OpenAI-ApiKey' | Should -Be 'k-123'
    }
}

Describe 'each wrapper is its REST twin' {
    It 'each wrapper forwards @PSBoundParameters to its twin -- never @args, never an Az cmdlet' {
        $map = Get-SIAzRestWrapperMap
        foreach ($w in $map.Keys) {
            $body = (Get-Command $w).ScriptBlock.ToString()
            $body | Should -Match ([regex]::Escape($map[$w].Rest) + ' @PSBoundParameters')
            $body | Should -Not -Match ([regex]::Escape($map[$w].Replaces) + '\b')
            $body | Should -Not -Match '@args'
        }
    }
    It 'every parameter a wrapper takes is accepted by its REST twin' {
        $map = Get-SIAzRestWrapperMap
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters
        foreach ($w in $map.Keys) {
            $rest = @((Get-Command $map[$w].Rest).Parameters.Keys)
            foreach ($p in (Get-Command $w).Parameters.Keys) { if ($p -notin $common) { $rest | Should -Contain $p -Because "$w -$p" } }
        }
    }
}

Describe 'WIRING -- no engine, container, launcher or auth file calls an Az cmdlet directly' {
    BeforeAll {
        $script:Dirs = 'engine', 'container', 'launcher', 'auth'
        $script:Files = @(foreach ($d in $script:Dirs) { Get-ChildItem (Join-Path $script:SIRoot $d) -Recurse -Filter *.ps1 })
        # names SecurityInsight defines itself (Connect-AzWithSPN, Set-AzContextFromResourceId, the ingest bridge's
        # Get-AzTokenForResource ...) are not Az cmdlets, and neither are AzLogDcrIngestPS's functions
        $own = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        Get-ChildItem $script:SIRoot -Recurse -Filter *.ps1 | ForEach-Object {
            $a = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
            foreach ($f in $a.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$own.Add(($f.Name -replace '^(global|script):', '')) }
        }
        foreach ($v in (Get-SILogIngestWrapperMap).Values) { [void]$own.Add($v.Replaces) }
        foreach ($n in 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce', 'Get-AzDcrDceDetails', 'Get-AzAccessTokenManagement', 'Get-AzLogAnalyticsTableAzDcrStatus') { [void]$own.Add($n) }
        $script:Own = $own
        $script:IsAzCmdlet = { param([string]$n) $n -and $n -match '^[A-Za-z]+-Az(?!ure)[A-Z][A-Za-z]+$' -and -not $script:Own.Contains($n) }
    }
    It 'no file calls an Az cmdlet -- not even SI-AzRest.ps1 (the guard over every module is SIv3-NoPsModules)' {
        $hits = [System.Collections.Generic.List[string]]::new()
        foreach ($file in $script:Files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if (& $script:IsAzCmdlet $n) { $hits.Add(('{0}:{1} {2}' -f $file.FullName.Substring($script:SIRoot.Length + 1), $c.Extent.StartLineNumber, $n)) }
            }
        }
        $hits | Should -BeNullOrEmpty
    }
    It 'each wrapper in SI-AzRest.ps1 is one statement: its REST twin' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1'), [ref]$null, [ref]$null)
        $map = Get-SIAzRestWrapperMap
        foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -like '*-SIAz*' }, $false)) {
            if (-not $map.Contains($f.Name)) { continue }
            $st = @($f.Body.EndBlock.Statements)
            $st.Count | Should -Be 1 -Because $f.Name
            $st[0].Extent.Text | Should -Match ('^return ,?\(' + [regex]::Escape($map[$f.Name].Rest) + ' @PSBoundParameters\)') -Because $f.Name
        }
    }
    It 'no file probes for an Az cmdlet with Get-Command any more' {
        $hits = @(foreach ($file in $script:Files) {
            if ($file.Name -eq 'SI-AzRest.ps1') { continue }
            Select-String -LiteralPath $file.FullName -Pattern "Get-Command\s+(-Name\s+)?'?((Connect|Get|Set|New|Search|Invoke|Update|Remove|Start)-Az(?!ure)[A-Za-z]+)" | Where-Object { $_.Line -notmatch '^\s*#' -and (& $script:IsAzCmdlet $_.Matches[0].Groups[2].Value) } |
                ForEach-Object { '{0}:{1}' -f $file.Name, $_.LineNumber }
        })
        $hits | Should -BeNullOrEmpty
    }
    It 'every file that calls a wrapper loads SI-AzRest.ps1 itself' {
        $wrappers = @((Get-SIAzRestWrapperMap).Keys) + 'Set-SIAzStorageBlobContentIfMatch'
        foreach ($file in $script:Files) {
            if ($file.Name -eq 'SI-AzRest.ps1') { continue }
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $calls = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.GetCommandName() -in $wrappers })
            if ($calls.Count) {
                $text = Get-Content -Raw $file.FullName
                $text | Should -Match "if \(-not \(Get-Command -Name Invoke-SIArm -ErrorAction (SilentlyContinue|Ignore)\)\) \{ \. \(Join-Path \`$PSScriptRoot '[./]*[^']*SI-AzRest\.ps1'\) \}" -Because "$($file.Name) calls the wrappers"
                $m = [regex]::Match($text, "Join-Path \`$PSScriptRoot '([^']*SI-AzRest\.ps1)'")
                Test-Path -LiteralPath (Join-Path $file.DirectoryName $m.Groups[1].Value) | Should -BeTrue -Because "$($file.Name) loads SI-AzRest.ps1 from where it is"
            }
        }
    }
    It 'SI-AzRest.ps1 ships in both editions: no Pro path, PS 5.1 safe' {
        $t = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
        # every path the Community payload leaves out (solution.publish.json excludePaths), by its file or folder name
        $excl = @((Get-Content -Raw (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json).excludePaths | Where-Object { "$_" -notlike '*.md' } | ForEach-Object { Split-Path -Leaf "$_" } | Where-Object { $_ -match '[-.]' })
        $excl.Count | Should -BeGreaterThan 0
        foreach ($e in $excl) { $t.Contains($e) | Should -BeFalse -Because "SI-AzRest.ps1 ships in Community and must not name '$e'" }
        $tok = $null; $err = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$tok, [ref]$err)
        $err | Should -BeNullOrEmpty
        @($tok | Where-Object { $_.Text -in '??', '?.', '??=' }) | Should -BeNullOrEmpty
        @([System.Text.Encoding]::UTF8.GetBytes($t) | Where-Object { $_ -gt 127 }) | Should -BeNullOrEmpty
    }
}

Describe 'the real HTTP seam (not mocked) returns status, headers and body the same way on 5.1 and 7' {
    BeforeAll {
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
    It '429: status, Retry-After, x-ms-error-code and body come back, nothing is thrown' {
        $body = '{"error":"throttled"}'
        $r = Invoke-OneShotHttp ("HTTP/1.1 429 Too Many Requests`r`nRetry-After: 7`r`nx-ms-error-code: ServerBusy`r`nContent-Length: {0}`r`nConnection: close`r`n`r`n{1}" -f $body.Length, $body) {
            param($u) (Get-Item function:Invoke-SIAzRestHttp).ScriptBlock.Invoke('PUT', $u, @{ 'x-ms-blob-type' = 'BlockBlob' }, [byte[]](1, 2, 3), 'application/octet-stream', 30, $false)
        }
        $r = @($r)[0]
        $r.StatusCode | Should -Be 429
        $r.RetryAfter | Should -Be '7'
        $r.Headers['X-MS-ERROR-CODE'] | Should -Be 'ServerBusy' -Because 'header names are case-insensitive'
        $r.Content | Should -Be $body
    }
    It '-AsBytes keeps the body as bytes' {
        $r = Invoke-OneShotHttp ("HTTP/1.1 200 OK`r`nContent-Length: 3`r`nConnection: close`r`n`r`nabc") {
            param($u) (Get-Item function:Invoke-SIAzRestHttp).ScriptBlock.Invoke('GET', $u, $null, $null, $null, 30, $true)
        }
        $r = @($r)[0]
        $r.StatusCode | Should -Be 200
        [System.Text.Encoding]::ASCII.GetString($r.Bytes) | Should -Be 'abc'
    }
    It 'no listener at all: status 0, not an exception (the retry rule treats it as transient)' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
        $r = @((Get-Item function:Invoke-SIAzRestHttp).ScriptBlock.Invoke('GET', ("http://127.0.0.1:{0}/x" -f $port), $null, $null, $null, 10, $false))[0]
        $r.StatusCode | Should -Be 0
    }
}

}
