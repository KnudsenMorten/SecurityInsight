#Requires -Version 5.1
<#
    SecurityInsight -- WHAT KIND OF FAILURE WAS IT: one error class per failed run, for the telemetry `run` record.

    ExitReason says only success / success-partial / error / settings-error. A release-health view needs to tell "a
    permission is missing" from "the service was throttling" from "the query is broken", without free text (anonymous
    installs send no error text at all). Get-SIErrorClass maps an error to exactly ONE value of a CLOSED list -- the list
    agreed with the receiving side; anything not recognised is 'unknown', never a guess.

    It is built on the classifiers SecurityInsight already trusts:
      * SI-KqlError.ps1 -- what a Log Analytics failure REALLY said (the response body, not "BadRequest") and whether
        it was a missing table;
      * working rule 4 / Risk Analysis' bucket classifier -- the recognised PLATFORM prefixes (a cancellation or a
        service-side entity resolution carries the service's generic "Fix semantic errors" tail and is NOT a query
        defect), then syntax / semantic / type errors = query defect, then throttle, then timeout / 5xx.

    The order of the checks is the contract (first match wins):
      settings-error > guard-refused > out-of-memory > database-full > licence-invalid > mi-unavailable > sql-login > config-missing > ingest-short-count >
      table-missing > platform prefix (timeout / 5xx) > kql-query-defect > throttled > ingest-4xx >
      401 / 403 by service > ai-error > platform-timeout > platform-5xx > unknown.
    A 401 from Microsoft Graph is graph-401; a 401 from another service means the same thing as its 403 there (access
    refused) and gets that service's -403 class.

    PURE. No network. PS 5.1 safe.
#>

if (-not (Get-Command -Name Get-SIKqlErrorText -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-KqlError.ps1'))
}

# The closed list, exactly as agreed (#226). Get-SIErrorClass returns one of these and nothing else.
$script:SIErrorClasses = @(
    'graph-401', 'graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'sql-login', 'mi-unavailable',
    'throttled', 'platform-timeout', 'platform-5xx', 'kql-query-defect', 'table-missing', 'ingest-4xx',
    'ingest-short-count', 'settings-error', 'config-missing', 'licence-invalid', 'ai-error',
    # UPLINK-FIX (Invardia, 2026-10-07): a run a guard REFUSED (nothing written, by design). The run's message is
    # '<guard id> refused: <why>' (Get-SIGuardRefusalText) -- its own class, so a refusal never reads as 'unknown'.
    'guard-refused',
    # #641 (owner 2026-10-13): a Risk Analysis report that is NOT COMPLETE in its run (its rows do not match what the source
    # holds, or it is not in the run at all) -- set by Risk Analysis itself, never derived from a message
    'report-incomplete',
    # #702 (1) (customer B 2026-10-15): the process ran out of memory. Its own class, never platform-timeout -- a platform
    # class is retried in-run on the same size, which runs out again; the job-size rule raises the job one band instead.
    # (Invardia's receiver takes any ^[a-z0-9-]{1,40}$ class -- packages/core/src/uplink.ts.)
    'out-of-memory',
    # #904 (a large install 2026-10-26): Azure SQL refused a write because the database reached its maximum size (1105,
    # 40544, "has reached its size quota"). Its own class -- never 'unknown' -- so a part that failed on it opens a ticket.
    'database-full',
    # #913 (the ride test install 2026-10-27): an Azure SQL transient (9001 log not available, 40613 / 40501 / 40197 /
    # 49918-49920, 4060 during a failover, 10928 / 10929, a reset connection) that did not pass within its bounded retry.
    # Set by the caller that retried it (the pipeline runner's lock), never derived from a text: not a product defect.
    'transient-sql',
    'unknown'
)

# #904: the numbers of Azure SQL's "the database is full" refusal (1105: no space in the filegroup; 40544: the database
# reached its size quota; 1101: no new page could be allocated)
$script:SIDatabaseFullNumbers = @(1105, 40544, 1101)

# Risk Analysis' recognised platform-failure prefixes (RA-GraphHunting.ps1, $script:RAPlatformFailurePrefixes). Read
# from there when Risk Analysis is loaded, so the two can never disagree; this copy serves every other engine. A test
# compares the two lists.
$script:SIErrorPlatformPrefixes = @(
    @{ Pattern = 'Query cancelled on creation'; Class = 'platform-timeout' }
    @{ Pattern = 'ScalarEvaluator\.Evaluate failed'; Class = 'platform-timeout' }
    @{ Pattern = 'Errors occurred while resolving remote entities'; Class = 'platform-5xx' }
)

function Get-SIErrorClasses { $script:SIErrorClasses }

function Test-SIDatabaseFullError {
    <#
        PURE. #904: did Azure SQL refuse a write because the database is FULL? -Value: an ErrorRecord, an exception (its
        SqlException numbers and inner exceptions are read) or a text. SQL 1105 / 40544 / 1101, "has reached its size quota",
        "filegroup is full", "Could not allocate space" / "Could not allocate a new page".
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    $ex = if ($Value -is [System.Exception]) { $Value } elseif ($Value -is [System.Management.Automation.ErrorRecord]) { $Value.Exception } else { $null }
    $texts = New-Object System.Collections.Generic.List[string]
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { if ($script:SIDatabaseFullNumbers -contains [int]$er.Number) { return $true } } }
        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
    }
    if (-not $texts.Count) { $texts.Add([string]$Value) }
    $t = $texts -join ' | '
    return [bool]($t -match '(?i)has reached its size quota|filegroup is full|Could not allocate (space|a new page)|\b(Error|Msg|Number)[ :=]*(1105|40544)\b|\((1105|40544)\)')
}

function Get-SITransientKind {
    <#
        PURE. THE ONE DECISION of what a failed call or a failure text REALLY was (2026-10-22: a "Connection timed out" to
        SI's own storage was reported to the owner as "Microsoft throttled this run"):
          throttled    Microsoft asked us to slow down -- ONLY a real throttling answer: HTTP 429, "Too Many Requests", a
                       rate limit, SQL 40501 / 10928 / 10929 (the service is busy / resource limit)
          timeout      no answer in time: HTTP 408 / 504, SQL -2, "timed out" / "timeout" / a cancelled task
          unavailable  the service could not be reached or failed: HTTP 500 / 502 / 503, no answer at all (status 0 without a
                       timeout), a reset / refused / closed connection, a host that does not resolve, SQL 40613 / 40197 /
                       49918-49920 / 10053 / 10054 / 233 / 64
          error        anything else (a refusal, a bug, a bad request) -- never retried as transient
        -StatusCode (an HTTP status; 0 = no answer; -1 = not known), -Message (the error text), -SqlNumber (SqlException numbers).
        SecurityInsight's OWN customer sentence ("Microsoft throttled this run ...") is taken out of the text first, so a
        re-read log never classifies itself.
    #>
    param([int]$StatusCode = -1, [AllowNull()][AllowEmptyString()][string]$Message = '', [AllowNull()][int[]]$SqlNumber = @())
    $t = ([string]$Message) -replace '(?i)Microsoft throttled this run[^|]*', ''
    $sql = @($SqlNumber | Where-Object { $null -ne $_ })
    if ($StatusCode -eq 429 -or @($sql | Where-Object { $_ -in 40501, 10928, 10929 }).Count -gt 0) { return 'throttled' }
    if ($t -match '(?i)\b429\b|Too ?Many ?Requests|\bthrottl|rate limit|RequestRateTooLarge') { return 'throttled' }
    if ($StatusCode -in 408, 504 -or $sql -contains -2) { return 'timeout' }
    if ($t -match '(?i)timed? ?out|timeout|TaskCanceledException|A task was canceled|operation was canceled|\b504\b|Gateway Time-?out|\b408\b') { return 'timeout' }
    if ($StatusCode -in 500, 502, 503 -or $StatusCode -eq 0 -or @($sql | Where-Object { $_ -in 40613, 40197, 49918, 49919, 49920, 10053, 10054, 233, 64 }).Count -gt 0) { return 'unavailable' }
    if ($t -match '(?i)\b50[0-3]\b|Internal ?Server ?Error|Bad Gateway|Service ?Unavailable|ServiceUnavailable|temporarily unavailable|is not currently available|forcibly closed|connection (was )?reset|Connection reset by peer|actively refused|No such host is known|Name or service not known|transport-level error|Unable to connect to the remote server') { return 'unavailable' }
    'error'
}

function Test-SIOutOfMemoryText {
    <# PURE. Does a failure text (or an exception / ErrorRecord, read with its inner exceptions) say the process ran out of
       memory? .NET's OutOfMemoryException (also wrapped: "Exception calling ... : Exception of type
       'System.OutOfMemoryException' was thrown", "Cannot process argument transformation on parameter 'TimeoutSec'. ..."),
       Container Apps' OOMKilled, or SecurityInsight's own "out of memory" wording. #702 (1). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    $ex = if ($Value -is [System.Exception]) { $Value } elseif ($Value -is [System.Management.Automation.ErrorRecord]) { $Value.Exception } else { $null }
    while ($ex) { if ($ex -is [System.OutOfMemoryException]) { return $true }; $ex = $ex.InnerException }
    $t = if ($Value -is [System.Management.Automation.ErrorRecord]) { [string]$Value.Exception } else { [string]$Value }
    return [bool]($t -match '(?i)OutOfMemoryException|\bOOMKilled\b|\bout of memory\b')
}

# WHO FIXES IT (framework §8.5 CLOSE-LOOP, Invardia 046): the classes whose fix is the CUSTOMER's configuration -- a
# permission or consent the install's identity does not have (the five -403 classes), a licence or licensed feature it
# lacks (licence-invalid), a setting the customer must set (config-missing, settings-error). Everything else -- sign-in
# and token trouble, a missing table, ingestion, throttling, timeouts, service errors, guard refusals, unknown -- stays a
# product defect: a class is put here only when its own definition above says the customer's configuration is the cause.
$script:SICustomerConfigClasses = @('graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'licence-invalid', 'config-missing', 'settings-error')
# #913: the classes that are nobody's fix -- an Azure SQL transient that did not pass within its bounded retry. No FixKind:
# never a fix request, never a red alert (the next wake-up runs as usual).
$script:SINoFixClasses = @('transient-sql')

function Get-SICustomerConfigClasses { $script:SICustomerConfigClasses }

function Get-SIErrorFixKind {
    <#
        PURE. The FixKind of a failed report's error class: 'customer-config' for a class on the customer-configuration list,
        'product-defect' for every other class of the closed list (and anything not on it), '' when there is no class.
    #>
    param([AllowEmptyString()][AllowNull()][string]$ErrorClass)
    $c = "$ErrorClass".Trim().ToLowerInvariant()
    if (-not $c) { return '' }
    if ($script:SINoFixClasses -contains $c) { return '' }
    if ($script:SICustomerConfigClasses -contains $c) { return 'customer-config' }
    'product-defect'
}

function Get-SIErrorService {
    <# PURE. Which service a failure came from, by the host or the wording it carries: graph | defender | arm | kv |
       storage | sql | ingest | ai | loganalytics | ''. #>
    param([AllowEmptyString()][string]$Text)
    $t = [string]$Text
    if ($t -match '(?i)ingest\.monitor\.azure\.com|Logs Ingestion|log ingestion|dataCollectionRules|\bDCR\b|\bDCE\b|InvalidTransformOutput') { return 'ingest' }
    if ($t -match '(?i)openai\.azure\.com|\bOpenAI\b|content_filter|context_length_exceeded|DeploymentNotFound|chat/completions') { return 'ai' }
    if ($t -match '(?i)api\.securitycenter\.microsoft\.com|api\.security\.microsoft\.com|security/runHuntingQuery|advanced hunting|Microsoft Defender|\bMachine\.Read\.All\b|\bThreatHunting\.Read\.All\b') { return 'defender' }
    if ($t -match '(?i)\.vault\.azure\.net|Key ?Vault|ForbiddenByRbac|ForbiddenByPolicy|secrets get permission|getSecret/action') { return 'kv' }
    if ($t -match '(?i)\.(blob|table|queue|file|dfs)\.core\.windows\.net|AuthorizationPermissionMismatch|AuthorizationFailure|storage account') { return 'storage' }
    if ($t -match '(?i)database\.windows\.net|SqlException|SqlClient|\bLogin failed\b') { return 'sql' }
    if ($t -match '(?i)management\.azure\.com|AuthorizationFailed|Microsoft\.[A-Za-z]+/[A-Za-z]+/[A-Za-z/]*(read|write|action)|\bAzure Resource Manager\b|LinkedAuthorizationFailed') { return 'arm' }
    if ($t -match '(?i)graph\.microsoft\.com|Authorization_RequestDenied|Microsoft Graph|InvalidAuthenticationToken') { return 'graph' }
    if ($t -match '(?i)api\.loganalytics|loganalytics\.io|Log Analytics|SEM\d{4}|SYN\d{4}') { return 'loganalytics' }
    ''
}

function Get-SIErrorLines {
    <#
        PURE. A failed run's own words from its log (a run transcript, a console tail): the error that ENDED it -- the LAST
        [ERROR] / exception / failed / refused / denied / status-code block (transcript TerminatingError markers and WARNING:
        lines only when nothing else is there), and the lines after it up to -Max, else -- no such line --
        the LAST -Max lines that carry text. Transcript headers / footers and the ******** frames are dropped. Never the whole
        log: the uplink carries a few lines, and the caller redacts them (ConvertTo-AitUplinkRedacted). '' for no text.
    #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$Lines = @(), [int]$Max = 8, [int]$MaxChars = 1800)
    $keep = New-Object System.Collections.Generic.List[string]
    $inHeader = $false
    foreach ($raw in @($Lines)) {
        $l = ([string]$raw).TrimEnd()
        if (-not $l.Trim()) { continue }
        if ($l -match '^\*{10,}$') { $inHeader = -not $inHeader; continue }
        if ($inHeader) { continue }
        if ($l -match '^(PowerShell|Windows PowerShell) transcript (start|end)|^(Start|End) time: \d{14}|^Transcript started, output file is') { continue }
        $keep.Add($l.Trim())
    }
    if (-not $keep.Count) { return '' }
    $err = '(?i)\[(ERROR|FAIL(ED)?|FATAL)\]|\bERROR\b|Exception|\bfailed\b|could not|cannot|refused|denied|Forbidden|Unauthorized|Login failed|\b(40[0-9]|429|50[0-4])\b|throttl|timed? ?out'
    # The error that ENDED the run, not the first one in the log: every error-looking line is a candidate; the
    # transcript's own "PS>TerminatingError(...)" / ">> TerminatingError(...)" markers (written for an error the code
    # CAUGHT and went on after) and WARNING: lines count only when the log has no other error line. The LAST such line
    # is taken, from the start of its block (the error lines right before it), and the lines after it up to -Max.
    $isErr = { param($s) $s -match $err -and $s -notmatch '(?i)^\s*(VERBOSE|DEBUG)\b|\b0 (failed|errors?)\b' }
    $isWeak = { param($s) $s -match '(?i)^\s*(PS>|>>\s*)TerminatingError\(|^\s*WARNING:' }
    $strong = -1; $weak = -1
    for ($i = 0; $i -lt $keep.Count; $i++) {
        if (-not (& $isErr $keep[$i])) { continue }
        if (& $isWeak $keep[$i]) { $weak = $i } else { $strong = $i }
    }
    $first = if ($strong -ge 0) { $strong } else { $weak }
    if ($first -ge 0) {
        $wantWeak = ($strong -lt 0)
        while ($first -gt 0 -and (& $isErr $keep[$first - 1]) -and ($wantWeak -or -not (& $isWeak $keep[$first - 1]))) { $first-- }
    }
    $pick = if ($first -ge 0) { @($keep.GetRange($first, [Math]::Min($Max, $keep.Count - $first))) } else { @($keep.GetRange([Math]::Max(0, $keep.Count - $Max), [Math]::Min($Max, $keep.Count))) }
    $t = ($pick -join "`n")
    if ($t.Length -gt $MaxChars) { $t = $t.Substring(0, $MaxChars) }
    $t
}

function Get-SIErrorRecordSummary {
    <# PURE. The words of a caught error, never empty: its message, else its exception type + error id + where it was
       raised (an exception thrown without a message reached Invardia as an empty text -- si-trend x5). #>
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $ex = if ($ErrorRecord -is [System.Exception]) { $ErrorRecord } elseif ($ErrorRecord.PSObject.Properties['Exception']) { $ErrorRecord.Exception } else { $null }
    $m = if ($ex) { "$($ex.Message)".Trim() } else { "$ErrorRecord".Trim() }
    if ($m) { return $m }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($ex) { $parts.Add($ex.GetType().FullName) }
    if ($ErrorRecord.PSObject.Properties['FullyQualifiedErrorId'] -and "$($ErrorRecord.FullyQualifiedErrorId)".Trim()) { $parts.Add("id $($ErrorRecord.FullyQualifiedErrorId)") }
    if ($ErrorRecord.PSObject.Properties['InvocationInfo'] -and $ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.ScriptName) { $parts.Add(('at {0}:{1}' -f (Split-Path -Leaf $ErrorRecord.InvocationInfo.ScriptName), $ErrorRecord.InvocationInfo.ScriptLineNumber)) }
    if (-not $parts.Count) { return 'an error without a message' }
    'an error without a message (' + ($parts -join ', ') + ')'
}

function Get-SIErrorClass {
    <#
        PURE. The error class of one failure -- exactly one value of Get-SIErrorClasses.
          -ErrorRecord  an ErrorRecord or an exception (its message, response body, typed body and inner exceptions are
                        all read -- Get-SIKqlErrorText)
          -Message      a text (a run-health ErrorMessage, a log line)
          -ExitReason   the run's ExitReason: 'settings-error' is its own class whatever the text says
          -Service      a hint when the caller knows which service it called (graph, defender, arm, kv, storage, sql,
                        ingest, ai) -- used when the text does not name one
    #>
    param([AllowNull()]$ErrorRecord, [AllowEmptyString()][AllowNull()][string]$Message, [AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][string]$Service)
    if ($ExitReason -eq 'settings-error') { return 'settings-error' }
    if ("$Message" -match '^[a-z0-9][a-z0-9.-]{0,99} refused: ') { return 'guard-refused' }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($null -ne $ErrorRecord) { $parts.Add((Get-SIKqlErrorText -ErrorRecord $ErrorRecord)) }
    if ($Message) { $parts.Add($Message) }
    $t = ($parts | Where-Object { $_ }) -join ' | '
    # #702 (1): out of memory ANYWHERE in the text wins over every service / platform word around it (customer B's
    # "... parameter 'TimeoutSec'. Exception of type 'System.OutOfMemoryException' was thrown" read as platform-timeout)
    if ((Test-SIOutOfMemoryText $t) -or ($null -ne $ErrorRecord -and (Test-SIOutOfMemoryText $ErrorRecord))) { return 'out-of-memory' }
    if ([string]::IsNullOrWhiteSpace($t)) { return 'unknown' }
    # #904: the database is full -- before every service / platform word (its text names SQL and often a timeout)
    if ((Test-SIDatabaseFullError $t) -or ($null -ne $ErrorRecord -and (Test-SIDatabaseFullError $ErrorRecord))) { return 'database-full' }
    $svc =Get-SIErrorService -Text $t
    if (-not $svc -and $Service) { $svc = $Service.ToLowerInvariant() }

    # ---- the run's own configuration ----------------------------------------------------------------------------------
    if ($t -match '(?i)SecurityInsight Pro: .*settings database|in the settings database are not valid|settings documents could not be prepared') { return 'settings-error' }
    if ($t -match '(?i)\blicen[cs]e\b.*\b(invalid|not valid|expired|signature verification FAILED|tampered|no entitlement|not readable|could not be read|does not include feature|names no SecurityInsight Pro edition|does not list it)\b|no \.(pimlicense|silicense|aitlicense)|not an AutomateIT licence|signature verification FAILED.*licensing key') { return 'licence-invalid' }

    # ---- identity / sign-in -----------------------------------------------------------------------------------------
    if ($t -match '(?i)ManagedIdentityCredential|No Managed Identity endpoint|169\.254\.169\.254|IDENTITY_ENDPOINT|\bIMDS\b|MSI endpoint|managed identity.*(unavailable|not available|not found|could not|failed|is not loaded)|identity token helper is not loaded') { return 'mi-unavailable' }
    if ($t -match "(?i)Login failed for user|Cannot open (server|database) .* requested by the login|\b18456\b|token-identified principal") { return 'sql-login' }
    if ($t -match "(?i)Cannot (bind|validate) argument (to|on) parameter '(Az)?(ApplicationId|AppId|TenantId|ClientId|CertificateThumbprint|Thumbprint|SubscriptionId|VaultName|WorkspaceId|DcrImmutableId|DceUri|ServicePrincipal\w*)' because it is (an empty string|null)|is not (set|configured)|not found in the configuration|the Pro database is not configured|certificate .* was not found") { return 'config-missing' }

    # ---- ingestion --------------------------------------------------------------------------------------------------
    if ($t -match '(?i)wrote fewer rows than it carried|fewer rows than (were )?(sent|posted|expected)|short count|rows? (were )?(lost|dropped) (at|during) ingest|accepted \d+ of \d+ rows') { return 'ingest-short-count' }

    # ---- Log Analytics / advanced hunting: the query and the tables -------------------------------------------------
    # #876: a 'union' leaf says "table expression", a 'where' leaf "table or column expression" -- both: the table is not there
    if ($t -match "Failed to resolve table (?:or column )?expression named \\?['""]?([A-Za-z0-9_]+)") {
        $name = $Matches[1]
        if ($name -match '(?i)_CL$' -or $t -match '(?i)\btable\b.*(could not be found|does not exist)') { return 'table-missing' }
    }
    if ($t -match "(?i)\btable\b[^|]{0,120}\b(could not be found|does not exist)|unknown table|PathNotFoundError|not present in this tenant's advanced hunting schema") { return 'table-missing' }
    foreach ($p in $script:SIErrorPlatformPrefixes) { if ($t -match $p.Pattern) { return $p.Class } }
    if ($t -match '(?i)Fix syntax errors in your query|Fix semantic errors in your query|SyntaxError|SemanticError|return types are not compatible|\bSEM\d{4}\b|\bSYN\d{4}\b|Expected: .* in query|Failed to resolve (scalar|table or column|table) expression') { return 'kql-query-defect' }

    # ---- throttling -------------------------------------------------------------------------------------------------
    # ONE decision (Get-SITransientKind): only a real throttling answer is 'throttled'. A Retry-After header alone is not
    # (a 503 sends one too); SI's own "Microsoft throttled this run" sentence never classifies itself.
    if ((Get-SITransientKind -Message $t) -eq 'throttled') { return 'throttled' }

    # ---- status codes, by service -----------------------------------------------------------------------------------
    $code = $null
    if ($t -match '(?i)\((4\d\d)\)|status code (?:does not indicate success: )?(4\d\d)\b|\b(4\d\d) \((Bad Request|Unauthorized|Forbidden|Not Found|Request Entity Too Large|Conflict)\)|''(BadRequest|Unauthorized|Forbidden|NotFound|RequestEntityTooLarge)''') {
        $code = @($Matches[1], $Matches[2], $Matches[3], $Matches[5]) | Where-Object { $_ } | Select-Object -First 1
    }
    $named = @{ BadRequest = '400'; Unauthorized = '401'; Forbidden = '403'; NotFound = '404'; RequestEntityTooLarge = '413' }
    if ($code -and $named.ContainsKey($code)) { $code = $named[$code] }
    $is401 = ($code -eq '401') -or ($t -match '(?i)\bUnauthorized\b|InvalidAuthenticationToken|token is expired|Lifetime validation failed')
    $is403 = ($code -eq '403') -or ($t -match '(?i)\bForbidden\b|Authorization_RequestDenied|AuthorizationFailed|AuthorizationPermissionMismatch|Insufficient privileges|does not have authorization|does not have (any of )?the required|is not authorized to perform|ForbiddenByRbac|ForbiddenByPolicy|Access denied')
    if ($svc -eq 'ingest' -and ($code -match '^4\d\d$' -or $is401 -or $is403 -or $t -match '(?i)InvalidTransformOutput|is not associated with DCR|DCE FQDN')) { return 'ingest-4xx' }
    if ($is401 -or $is403) {
        switch ($svc) {
            'graph'    { if ($is401 -and -not $is403) { return 'graph-401' } else { return 'graph-403' } }
            'defender' { return 'defender-403' }
            'arm'      { return 'arm-403' }
            'kv'       { return 'kv-403' }
            'storage'  { return 'storage-403' }
            'sql'      { return 'sql-login' }
            'ai'       { return 'ai-error' }
            default    { if ($is401 -and -not $is403) { return 'graph-401' } }
        }
    }

    # ---- AI ---------------------------------------------------------------------------------------------------------
    if ($svc -eq 'ai') { return 'ai-error' }

    # ---- the platform -----------------------------------------------------------------------------------------------
    switch (Get-SITransientKind -Message $t) {
        'timeout'     { return 'platform-timeout' }
        'unavailable' { return 'platform-5xx' }
    }
    'unknown'
}
