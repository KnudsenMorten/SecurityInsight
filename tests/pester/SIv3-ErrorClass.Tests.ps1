#Requires -Version 5.1
<#
    SecurityInsight -- THE TELEMETRY ERROR CLASS AND RECORDS (SI's half of the framework uplink's Schema 2).

    What must hold:
      - Get-SIErrorClass maps a REAL failure text to exactly one value of the closed list agreed with the receiving
        side, and the list is exactly that list (no value added or renamed here alone);
      - it agrees with the classifiers SI already trusts: SI-KqlError (the response BODY decides, not "BadRequest") and
        Risk Analysis' platform prefixes (a cancellation with the service's "Fix semantic errors" tail is NOT a query
        defect -- working rule 4);
      - the `run` and `heartbeat` record shapes; Outcome from ExitReason; anonymous mode drops the tenant, the host and
        the error text and buckets the counts; identified error text is redacted and at most 4000 characters;
      - nothing sends: pure builders, wired to nothing.
    The fixture texts are the shapes SecurityInsight's own code, Risk Analysis logs and the run-health history recorded.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Telemetry.ps1')
    # an exception the way Az.OperationalInsights throws it: the message says only BadRequest, the body says why
    function script:New-LaError([string]$Body, [string]$Message = "Operation returned an invalid status code 'BadRequest'") {
        [pscustomobject]@{ Message = $Message; Response = [pscustomobject]@{ Content = $Body }; InnerException = $null }
    }
    $script:Base = @{ Edition = 'community'; Version = '3.0.0'; Ring = 2; Hosting = 'vm'; RuntimeIdentity = 'mi-vm'; LicenceState = 'none'; Now = [datetime]'2026-10-03T06:00:00Z' }
    $script:InstallId = '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'
}

Describe 'the closed list' {
    It 'is exactly the agreed list, in order, with unknown as the fallback' {
        @(Get-SIErrorClasses) | Should -Be @('graph-401', 'graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'sql-login', 'mi-unavailable',
            'throttled', 'platform-timeout', 'platform-5xx', 'kql-query-defect', 'table-missing', 'ingest-4xx', 'ingest-short-count', 'settings-error',
            'config-missing', 'licence-invalid', 'ai-error', 'guard-refused', 'report-incomplete', 'out-of-memory', 'database-full', 'transient-sql', 'unknown')
        Get-SIErrorClass -Message 'something nobody has seen before' | Should -Be 'unknown'
        Get-SIErrorClass -Message '' | Should -Be 'unknown'
        Get-SIErrorClass | Should -Be 'unknown'
    }
    It 'the platform prefixes are Risk Analysis'' own list (one definition in two places, compared here)' {
        $ra = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $block = [regex]::Match($ra, '(?s)\$script:RAPlatformFailurePrefixes = @\((.*?)\n\)').Groups[1].Value
        $raList = @([regex]::Matches($block, "(?m)^\s*'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $raList.Count | Should -BeGreaterThan 0
        @($script:SIErrorPlatformPrefixes | ForEach-Object { $_.Pattern }) | Should -Be $raList
    }
}

Describe 'real failure texts -> their class' {
    It '<Why> -> <Class>' -ForEach @(
        @{ Class = 'graph-401'; Why = 'Graph, PS 7 status line + expired token body'; Text = 'Response status code does not indicate success: 401 (Unauthorized). https://graph.microsoft.com/v1.0/users {"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired or is not yet valid."}}' }
        @{ Class = 'graph-401'; Why = 'a bare 401 with no service named'; Text = 'The remote server returned an error: (401) Unauthorized.' }
        @{ Class = 'graph-403'; Why = 'Graph Authorization_RequestDenied'; Text = 'Response status code does not indicate success: 403 (Forbidden). {"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}' }
        @{ Class = 'graph-403'; Why = 'Graph on PS 5.1'; Text = 'GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments: The remote server returned an error: (403) Forbidden.' }
        @{ Class = 'defender-403'; Why = 'MDE machines without Machine.Read.All'; Text = 'Response status code does not indicate success: 403 (Forbidden). https://api.securitycenter.microsoft.com/api/machines {"error":{"code":"Forbidden","message":"The application does not have any of the required application roles (Machine.Read.All, Machine.ReadWrite.All) to access the resource."}}' }
        @{ Class = 'defender-403'; Why = 'advanced hunting through Graph'; Text = 'POST https://graph.microsoft.com/v1.0/security/runHuntingQuery failed: 403 (Forbidden). Missing role ThreatHunting.Read.All' }
        @{ Class = 'arm-403'; Why = 'ARM AuthorizationFailed'; Text = "AuthorizationFailed: The client '00000000-0000-0000-0000-000000000001' with object id '00000000-0000-0000-0000-000000000002' does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourceGroups/read' over scope '/subscriptions/00000000-0000-0000-0000-000000000003' or the scope is invalid." }
        @{ Class = 'kv-403'; Why = 'Key Vault RBAC'; Text = "Operation returned an invalid status code 'Forbidden' Caller is not authorized to perform action on resource. Action: 'Microsoft.KeyVault/vaults/secrets/getSecret/action' Resource: 'https://kv-example.vault.azure.net' Code: ForbiddenByRbac" }
        @{ Class = 'storage-403'; Why = 'blob RBAC'; Text = 'This request is not authorized to perform this operation using this permission. RequestId:1 ErrorCode:AuthorizationPermissionMismatch https://stexample.blob.core.windows.net/sistaging' }
        @{ Class = 'sql-login'; Why = 'Azure SQL, Entra token'; Text = "Exception calling ""Open"" with ""0"" argument(s): ""Login failed for user '<token-identified principal>'.""" }
        @{ Class = 'mi-unavailable'; Why = 'no IMDS'; Text = 'ManagedIdentityCredential authentication unavailable. No Managed Identity endpoint found.' }
        @{ Class = 'mi-unavailable'; Why = 'IMDS not reachable'; Text = 'Unable to connect to the remote server (169.254.169.254:80): connection refused' }
        @{ Class = 'mi-unavailable'; Why = 'SI''s own container sign-in guard'; Text = 'managed identity: the identity token helper is not loaded -- this sign-in works only inside a SecurityInsight container.' }
        @{ Class = 'throttled'; Why = '429'; Text = 'Response status code does not indicate success: 429 (Too Many Requests). Retry-After: 30' }
        @{ Class = 'throttled'; Why = 'throttling wording'; Text = 'Request was throttled. Please retry later.' }
        @{ Class = 'platform-timeout'; Why = 'HttpClient ceiling'; Text = 'The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing.' }
        @{ Class = 'platform-timeout'; Why = 'TaskCanceled'; Text = 'A task was canceled.' }
        @{ Class = 'platform-timeout'; Why = 'cancellation with the service''s "Fix semantic errors" tail is NOT a defect (rule 4)'; Text = 'ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic errors in your query.' }
        @{ Class = 'platform-5xx'; Why = 'service-side entity resolution with the same tail'; Text = "Errors occurred while resolving remote entities. Failed to resolve name or pattern 'TvmSCASnapshotCooked' in one or more scopes: (`$Cluster='', `$Database=''). Fix semantic errors in your query." }
        @{ Class = 'platform-5xx'; Why = 'nginx 502'; Text = '[UnknownError] <html><head><title>502 Bad Gateway</title></head></html>' }
        @{ Class = 'platform-5xx'; Why = '503'; Text = 'Response status code does not indicate success: 503 (Service Unavailable).' }
        @{ Class = 'kql-query-defect'; Why = 'mixed-type case()'; Text = 'Query failed: return types are not compatible. Fix semantic errors in your query.' }
        @{ Class = 'kql-query-defect'; Why = 'syntax error'; Text = "Query could not be parsed at '|' on line [12,4]. Token: '|' SYN0002. Fix syntax errors in your query." }
        @{ Class = 'ingest-4xx'; Why = 'run health transform mismatch (#198)'; Text = "Log ingestion failed: 400 (Bad Request) InvalidTransformOutput AssetCount [produced:'Int', output:'Long'] https://dce-example.westeurope-1.ingest.monitor.azure.com" }
        @{ Class = 'ingest-4xx'; Why = 'DCE not associated'; Text = 'DCE FQDN is not associated with DCR dcr-si-run-health' }
        @{ Class = 'ingest-short-count'; Why = 'a chunk lost rows'; Text = 'the data load failed: a chunk wrote fewer rows than it carried (480 of 500)' }
        @{ Class = 'settings-error'; Why = 'Pro settings layer'; Text = 'SecurityInsight Pro: the settings database srv/db could not be read -- the run stops rather than use other settings. timeout' }
        @{ Class = 'config-missing'; Why = 'the empty AzAppId binding error'; Text = "Cannot bind argument to parameter 'AzAppId' because it is an empty string." }
        @{ Class = 'config-missing'; Why = 'the empty DcrImmutableId (#198)'; Text = "Run-health record could not be saved: Cannot bind argument to parameter 'DcrImmutableId' because it is an empty string" }
        @{ Class = 'config-missing'; Why = 'updater configuration'; Text = 'SI_UPDATER_TENANT_ID is not set on the updater job.' }
        @{ Class = 'licence-invalid'; Why = 'tampered licence'; Text = 'licence: signature verification FAILED (file tampered, or not issued by a trusted AutomateIT licensing key)' }
        @{ Class = 'licence-invalid'; Why = 'wrong tenant'; Text = "licence 'Example Corp' is not valid for tenant 00000000-0000-0000-0000-000000000009" }
        @{ Class = 'ai-error'; Why = 'content filter'; Text = 'POST https://oai-example.openai.azure.com/openai/deployments/gpt/chat/completions: 400 (Bad Request) {"error":{"code":"content_filter"}}' }
        @{ Class = 'ai-error'; Why = 'deployment missing'; Text = 'Azure OpenAI: DeploymentNotFound -- the API deployment for this resource does not exist.' }
        # #702 (1) customer B 2026-10-15: out of memory is its own class, whatever service / timeout words surround it
        @{ Class = 'out-of-memory'; Why = 'customer B rc.981: OOM inside the TimeoutSec binding (was platform-timeout)'; Text = "Cannot process argument transformation on parameter 'TimeoutSec'. Exception of type 'System.OutOfMemoryException' was thrown." }
        @{ Class = 'out-of-memory'; Why = 'customer B 3.0.0.202610151701: the blob listing could not be parsed for memory'; Text = 'Cannot convert value "<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://st.blob.core.windows.net/" ContainerName="sistaging">" to type "System.Xml.XmlDocument". Error: "Exception of type ''System.OutOfMemoryException'' was thrown."' }
        @{ Class = 'out-of-memory'; Why = 'a Graph call that ran out of memory'; Text = "Response from https://graph.microsoft.com/v1.0/users: Exception calling ""GetString"" with ""1"" argument(s): ""Exception of type 'System.OutOfMemoryException' was thrown.""" }
        @{ Class = 'out-of-memory'; Why = 'the Discover stage''s own end text'; Text = "The discovery source 'EntraUsers' did not complete (si-col-0501: out of memory) -- this identity collection is NOT COMPLETE and stays on its last good collection: Exception of type 'System.OutOfMemoryException' was thrown." }
        @{ Class = 'out-of-memory'; Why = 'Container Apps killed it'; Text = 'Container si exited: OOMKilled (exit code 137)' }
    ) {
        Get-SIErrorClass -Message $Text | Should -Be $Class
        @(Get-SIErrorClasses) | Should -Contain $Class
    }
    It 'Log Analytics: the BODY decides -- SEM0100 on a _CL table is table-missing, on a column it is a query defect' {
        $table = New-LaError '{"error":{"code":"BadArgumentError","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"''where'' operator: Failed to resolve table or column expression named ''SI_PublicIP_Profile_CL''"}}}}'
        Get-SIErrorClass -ErrorRecord $table | Should -Be 'table-missing'
        $col = New-LaError '{"error":{"code":"BadArgumentError","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"''summarize'' operator: Failed to resolve scalar expression named ''AssetName''"}}}}'
        Get-SIErrorClass -ErrorRecord $col | Should -Be 'kql-query-defect'
        (New-LaError '').Message | Should -Match 'BadRequest' -Because 'the message alone says nothing -- that is why the body is read'
        Get-SIErrorClass -Message "Table 'DeviceTvmSoftwareInventory' not present in this tenant's advanced hunting schema." | Should -Be 'table-missing'
        # #876: a 'union' leaf words it "table expression" (no "or column") -- the same missing table, never 'unknown'
        Get-SIErrorClass -Message "'union' operator: Failed to resolve table expression named 'SI_Endpoint_Profile_CL'" | Should -Be 'table-missing'
        Get-SIErrorClass -Message "'union' operator: Failed to resolve table expression named '_notALookup'" | Should -Be 'kql-query-defect'
    }
    It '#702: an OutOfMemoryException as an ErrorRecord (also wrapped) is out-of-memory; Test-SIOutOfMemoryText reads text and exceptions' {
        $er = $null
        try { throw (New-Object System.Exception('outer', (New-Object System.OutOfMemoryException))) } catch { $er = $_ }
        Get-SIErrorClass -ErrorRecord $er | Should -Be 'out-of-memory'
        Test-SIOutOfMemoryText (New-Object System.OutOfMemoryException) | Should -BeTrue
        Test-SIOutOfMemoryText 'The operation has timed out.' | Should -BeFalse
        Test-SIOutOfMemoryText $null | Should -BeFalse
        Get-SIErrorClass -Message 'The operation has timed out.' | Should -Be 'platform-timeout' -Because 'control: a plain timeout stays a timeout'
        Get-SIErrorFixKind -ErrorClass 'out-of-memory' | Should -Be 'product-defect' -Because 'the job size is SecurityInsight''s to fix, not the customer''s configuration'
    }
    It 'a real ErrorRecord (with an inner exception) is read through SI-KqlError' {
        $er = $null
        try { throw (New-Object System.Exception('outer wrapper', (New-Object System.Exception('Login failed for user ''<token-identified principal>''.')))) } catch { $er = $_ }
        Get-SIErrorClass -ErrorRecord $er | Should -Be 'sql-login'
    }
    It 'ExitReason settings-error wins over the text; a service hint routes a bare 403' {
        Get-SIErrorClass -Message 'A task was canceled.' -ExitReason 'settings-error' | Should -Be 'settings-error'
        Get-SIErrorClass -Message 'The remote server returned an error: (403) Forbidden.' -Service arm | Should -Be 'arm-403'
        Get-SIErrorClass -Message 'The remote server returned an error: (403) Forbidden.' -Service kv | Should -Be 'kv-403'
        Get-SIErrorClass -Message 'The remote server returned an error: (403) Forbidden.' | Should -Be 'unknown' -Because 'a 403 without a service is not guessed'
    }
}

Describe 'the run record' {
    It 'Outcome from ExitReason: success = ok, success-partial = warning, error / settings-error = failed; anything else refused' {
        Get-SITelemetryOutcome 'success' | Should -Be 'ok'
        Get-SITelemetryOutcome 'success-partial' | Should -Be 'warning'
        Get-SITelemetryOutcome 'error' | Should -Be 'failed'
        Get-SITelemetryOutcome 'settings-error' | Should -Be 'failed'
        { Get-SITelemetryOutcome 'crashed' } | Should -Throw '*not a run-health ExitReason*'
    }
    It 'identified (Pro): the full shape, the error class classified, exact counts, the tenant and host carried' {
        $pro = @{} + $script:Base; $pro.Edition = 'pro'; $pro.LicenceState = 'valid'; $pro.Hosting = 'container'; $pro.RuntimeIdentity = 'mi-container'   # PS 5.1: a splatted name cannot be given again
        $r = New-SITelemetryRunRecord @pro -Job 'si-ra-detailed' -ExitReason error -DurationMs 812345 `
            -FailedStep 'ra-query' -ErrorMessage 'Response status code does not indicate success: 429 (Too Many Requests).' -Counts @{ assets = 1234; findings = 56789 } `
            -TenantId '00000000-0000-0000-0000-00000000000a' -HostName 'host-example'
        @($r.PSObject.Properties.Name) | Should -Be @('Schema', 'Kind', 'Product', 'Solution', 'Edition', 'Version', 'Ring', 'Hosting', 'RuntimeIdentity', 'LicenceState',
            'WriterSource', 'ClaimedTenantId', 'Host', 'Job', 'Outcome', 'DurationMs', 'FailedStep', 'ErrorClass', 'Counts', 'ErrorText', 'Ok', 'LastSeenUtc')
        $r.Schema | Should -Be 2; $r.Kind | Should -Be 'run'; $r.Product | Should -Be 'securityinsight'
        $r.WriterSource | Should -Be 'install-key'
        $r.Outcome | Should -Be 'failed'; $r.Ok | Should -BeFalse
        $r.ErrorClass | Should -Be 'throttled'
        $r.FailedStep | Should -Be 'ra-query'
        $r.Counts.assets | Should -Be 1234; $r.Counts.findings | Should -Be 56789
        $r.ClaimedTenantId | Should -Be '00000000-0000-0000-0000-00000000000a'; $r.Host | Should -Be 'host-example'
        $r.Ring | Should -Be 2
        $r.LastSeenUtc | Should -Be '2026-10-03T06:00:00Z'
    }
    It 'a successful run carries no error class, no failed step and no error text' {
        $r = New-SITelemetryRunRecord @script:Base -Job 'si-endpoint' -ExitReason success -DurationMs 1000 -FailedStep 'collect' -ErrorMessage 'ignored' -TenantId 't' -HostName 'h'
        $r.Outcome | Should -Be 'ok'; $r.Ok | Should -BeTrue
        $r.ErrorClass | Should -BeNullOrEmpty; $r.FailedStep | Should -BeNullOrEmpty; $r.ErrorText | Should -Be ''
    }
    It 'anonymous (Community): NO tenant, NO host, NO error text -- the fields are absent -- and the counts are buckets' {
        $r = New-SITelemetryRunRecord @script:Base -Job 'si-ra-summary' -ExitReason success-partial -DurationMs 5 -FailedStep 'ingest' `
            -ErrorMessage 'Login failed for user x@example.test on server sql-example' -Counts @{ assets = 0; findings = 150; identities = 123456 } `
            -Anonymous -InstallId $script:InstallId -TenantId 'must-not-appear' -HostName 'must-not-appear'
        $names = @($r.PSObject.Properties.Name)
        foreach ($n in 'ClaimedTenantId', 'Host', 'ErrorText') { $names | Should -Not -Contain $n }
        ($r | ConvertTo-Json -Depth 5) | Should -Not -Match 'must-not-appear|example\.test|sql-example'
        $r.WriterSource | Should -Be 'anonymous'; $r.InstallId | Should -Be $script:InstallId
        $r.Outcome | Should -Be 'warning'; $r.ErrorClass | Should -Be 'sql-login'
        $r.Counts.assets | Should -Be '0'; $r.Counts.findings | Should -Be '100-1k'; $r.Counts.identities | Should -Be '100k+'
        { New-SITelemetryRunRecord @script:Base -Job 'si-trend' -ExitReason success -Anonymous } | Should -Throw '*InstallId*'
    }
    It 'the count buckets: 0, 1-100, 100-1k, 1k-10k, 10k-100k, 100k+ (UPPER bound inclusive, as the framework client and the receiver); unknown stays unknown' {
        @(0, 1, 99, 100, 101, 999, 1000, 1001, 10000, 10001, 100000, 100001, 5000000 | ForEach-Object { Get-SITelemetryCountBucket $_ }) |
            Should -Be @('0', '1-100', '1-100', '1-100', '100-1k', '100-1k', '100-1k', '1k-10k', '1k-10k', '10k-100k', '10k-100k', '100k+', '100k+')
        Get-SITelemetryCountBucket -1 | Should -BeNullOrEmpty
        Get-SITelemetryCountBucket $null | Should -BeNullOrEmpty
    }
    It 'identified error text is redacted (tokens, secrets, SAS) and at most 4000 characters' {
        $jwt = 'ey' + 'J' + ('a' * 20) + '.' + ('b' * 20) + '.' + ('c' * 20)
        $txt = "auth $jwt | Authorization: Bearer abc.def-ghi | client_secret=" + ('Q' * 30) + " | https://st.blob.core.windows.net/c?sv=1&sig=" + ('Z' * 30) + ' | Password=' + ('P' * 12) + ';' + ('x' * 9000)
        $e = ConvertTo-SITelemetryErrorText $txt
        $e | Should -Not -Match ([regex]::Escape($jwt))
        $e | Should -Match 'Bearer \[redacted\]'
        $e | Should -Match 'client_secret=\[redacted\]'
        $e | Should -Match 'sig=\[redacted\]'
        $e | Should -Match 'Password=\[redacted\]'
        $e.Length | Should -BeLessOrEqual 4000
    }
    It 'every enum is checked at the source (the receiver refuses unknown values)' {
        { New-SITelemetryRunRecord @script:Base -Job 'si-nope' -ExitReason success } | Should -Throw '*not a valid Job*'
        $b = @{} + $script:Base; $b.Hosting = 'k8s'
        { New-SITelemetryRunRecord @b -Job 'si-trend' -ExitReason success } | Should -Throw '*not a valid Hosting*'
        { New-SITelemetryRunRecord @script:Base -Job 'si-trend' -ExitReason error -ErrorClass 'disk-full' } | Should -Throw '*not a valid ErrorClass*'
        { New-SITelemetryRunRecord @script:Base -Job 'si-trend' -ExitReason success -Counts @{ secrets = 1 } } | Should -Throw '*not a count*'
        { New-SITelemetryRunRecord @script:Base -Job 'si-trend' -ExitReason error -FailedStep 'Step With Spaces' } | Should -Throw '*not a step name*'
    }
    It 'the job ids are the agreed list' {
        @((Get-SITelemetryContract).Jobs) | Should -Be @('si-ptc', 'si-endpoint', 'si-identity', 'si-azure', 'si-publicip', 'si-ra-summary', 'si-ra-detailed', 'si-trend',
            'si-schema-discovery', 'si-asset-tagging', 'si-correlation', 'si-asset-properties', 'si-cmdb', 'si-vuln-closeloop', 'si-datasync', 'si-updater', 'si-web', 'si-cmdb-sql', 'si-flow', 'si-install')
    }
}

Describe 'the heartbeat record' {
    It 'identified and anonymous shapes' {
        $h = New-SITelemetryHeartbeat -Edition pro -Version '3.0.0' -Ring 1 -Hosting container -RuntimeIdentity mi-container -LicenceState grace -TenantId 't-1' -HostName 'h-1' -Now ([datetime]'2026-10-03T00:00:00Z')
        @($h.PSObject.Properties.Name) | Should -Be @('Schema', 'Kind', 'Product', 'Solution', 'Edition', 'Version', 'Ring', 'Hosting', 'RuntimeIdentity', 'LicenceState', 'WriterSource', 'ClaimedTenantId', 'Host', 'LastSeenUtc')
        $h.Kind | Should -Be 'heartbeat'; $h.LicenceState | Should -Be 'grace'
        $a = New-SITelemetryHeartbeat -Edition community -Version '3.0.0' -Hosting arc -RuntimeIdentity mi-arc -LicenceState none -Anonymous -InstallId $script:InstallId -TenantId 't-1' -HostName 'h-1'
        @($a.PSObject.Properties.Name) | Should -Not -Contain 'ClaimedTenantId'
        @($a.PSObject.Properties.Name) | Should -Not -Contain 'Host'
        $a.InstallId | Should -Be $script:InstallId
        $a.Ring | Should -BeNullOrEmpty
        foreach ($ri in 'mi-container', 'mi-arc', 'mi-vm', 'spn-certificate', 'spn-secret') { (New-SITelemetryHeartbeat -Edition trial -Version 'v' -Hosting vm -RuntimeIdentity $ri -LicenceState valid -TenantId t).RuntimeIdentity | Should -Be $ri }
        { New-SITelemetryHeartbeat -Edition enterprise -Version 'v' -Hosting vm -RuntimeIdentity mi-vm -LicenceState valid } | Should -Throw '*not a valid Edition*'
    }
}

Describe 'the builders send nothing' {
    It 'the builders make no network call; the ONLY caller is the sender (SI-TelemetrySend.ps1, tested in SIv3-Telemetry)' {
        foreach ($f in 'SI-ErrorClass.ps1', 'SI-Telemetry.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot "engine\_shared\$f"), [ref]$null, [ref]$null)
            $cmds = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            @($cmds | Where-Object { $_ -match '^(Invoke-RestMethod|Invoke-WebRequest|Send-AitUplink|Invoke-AzRestMethod|Send-SILogData|Send-SIRunHealthRow)$' }) | Should -BeNullOrEmpty -Because $f
        }
        # the Pro paths (the publish manifest's excludePaths; a public copy has neither the manifest nor those files) are left
        # out here: a Pro caller is guarded by its own Pro suite (#718: the hourly status report job, SIv3-HeartbeatJob)
        $proPaths = @()
        $man = Join-Path $script:SIRoot 'solution.publish.json'
        if (Test-Path -LiteralPath $man) { $proPaths = @((Get-Content -Raw -LiteralPath $man | ConvertFrom-Json).excludePaths | ForEach-Object { ([string]$_).Replace('/', '\').TrimEnd('\') }) }
        $isPro = { param($full) $rel = $full.Substring($script:SIRoot.TrimEnd('\').Length + 1); [bool](@($proPaths | Where-Object { $rel -eq $_ -or $rel.StartsWith($_ + '\') }).Count) }
        $callers = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Filter '*.ps1' | Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.Name -notin 'SI-Telemetry.ps1' -and -not (& $isPro $_.FullName) } |
            Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match 'New-SITelemetry(RunRecord|Heartbeat)' } | ForEach-Object { $_.Name })
        $callers | Should -Be @('SI-TelemetrySend.ps1')
    }
}
