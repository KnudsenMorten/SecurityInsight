#Requires -Version 5.1
<#
    OPENAI-CAP (owner 2026-11-21, Invardia relay): A HARD DAILY TOKEN BUDGET PER INSTALL -- THE CIRCUIT BREAKER.
    Every Azure OpenAI request of every SecurityInsight engine goes through Invoke-SIOpenAIChat (SI-OpenAIAuth.ps1), and that
    one function asks here first:
      - Test-SIAiBudgetOpen: the tokens the install used TODAY (UTC) are under the budget -> the request may go; at or over
        the budget -> it does NOT go: the breaker opens, ONE warning line is written and ONE alert event is raised per process
        (Get-SIAiBudgetAlert, sent through the -Alert seam when one is set), and every further request of the day is refused
        at once, without a send.
      - Add-SIAiBudgetUsage: after an answer, the tokens it cost (usage.prompt_tokens + usage.completion_tokens; without a
        usage block, an estimate from the request size) are added to today's ledger.
    The budget is SI_AI_DailyTokenBudget (tokens per install per UTC day). It is NEVER unbounded: no setting, 0, a negative
    or an unreadable value all mean the shipped default (Get-SIAiBudgetDefault).
    The ledger is the install's storage account (SI_STORAGE_ACCOUNT, container sistaging): one blob per writer per day,
    ai-usage/<yyyy-MM-dd>/<writer>.json, each writer adding to ITS OWN blob only -- no two engines ever write one blob,
    and the day's total is the sum of the day's blobs. A ledger that cannot be read refuses the request (said once; read
    again after a minute): unknown spend is never a reason to spend more. Without a storage account (a test, a local run) the ledger is
    this process only.
    Seams (tests): $global:SI_AiBudgetLedger = @{ Read = { param($Day) <tokens so far> }; Add = { param($Day, $Tokens) } },
    $global:SI_AiBudgetAlert = { param($Event) }, $global:SI_AiBudgetNow = { [datetime] UTC }.
#>

function Get-SIAiBudgetDefault {
    <# PURE. The shipped daily token budget per install: 200,000 tokens (about 70 batched classification requests). #>
    200000
}

function Get-SIAiDailyTokenBudget {
    <# The budget in force: SI_AI_DailyTokenBudget when it is a whole number above 0, else the default -- never infinite. #>
    $v = Get-Variable -Scope Global -Name SI_AI_DailyTokenBudget -ValueOnly -ErrorAction Ignore
    if ($null -eq $v) { $v = [Environment]::GetEnvironmentVariable('SI_AI_DAILY_TOKEN_BUDGET') }
    $n = 0L
    if ($null -ne $v -and [long]::TryParse(("$v".Trim() -replace '[,_ ]', ''), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -gt 0) { return $n }
    [long](Get-SIAiBudgetDefault)
}

function Get-SIAiBudgetDay {
    $now = if ($global:SI_AiBudgetNow -is [scriptblock]) { [datetime](& $global:SI_AiBudgetNow) } else { [datetime]::UtcNow }
    $now.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SIAiBudgetWriter {
    <# PURE-ish. This writer's blob name part: the replica / host name and the process id (only letters, digits, - and _). #>
    $h = [Environment]::GetEnvironmentVariable('CONTAINER_APP_REPLICA_NAME')
    if (-not $h) { $h = [Environment]::MachineName }
    (('{0}-{1}' -f $h, $PID) -replace '[^A-Za-z0-9_-]', '_')
}

function New-SIAiBudgetBlobLedger {
    <#
        The install ledger over the storage account -Account (container sistaging): Read = the sum of the day's blobs
        (THROWS when it cannot be read); Add = this writer's own blob rewritten with its new day total.
    #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistaging')
    $state = @{ Account = $Account; Container = $Container; Writer = (Get-SIAiBudgetWriter); Mine = @{} }
    # the blob functions CAPTURED here and called through & $fn: a .GetNewClosure() block cannot see a function that was
    # dot-sourced into a script scope (engine\_shared\SI-AzRest.ps1), only global ones
    $listFn = Get-Command -Name Get-SIBlobList -CommandType Function -ErrorAction SilentlyContinue
    $getFn = Get-Command -Name Get-SIBlobContent -CommandType Function -ErrorAction SilentlyContinue
    $setFn = Get-Command -Name Set-SIBlobContent -CommandType Function -ErrorAction SilentlyContinue
    @{
        Read = {
            param($Day)
            $sum = 0L
            if (-not $listFn -or -not $getFn) { throw 'the AI usage ledger cannot be read in this job (Get-SIBlobList / Get-SIBlobContent not loaded from engine\_shared\SI-AzRest.ps1)' }
            foreach ($b in @(& $listFn -Account $state.Account -Container $state.Container -Prefix ("ai-usage/{0}/" -f $Day))) {
                $bytes = & $getFn -Account $state.Account -Container $state.Container -Blob $b.Name -AllowMissing
                if ($null -eq $bytes) { continue }
                $o = [Text.Encoding]::UTF8.GetString([byte[]]$bytes) | ConvertFrom-Json
                $sum += [long]$o.tokens
            }
            $sum
        }.GetNewClosure()
        Add = {
            param($Day, $Tokens)
            if (-not $state.Mine.ContainsKey($Day)) { $state.Mine[$Day] = 0L }
            $state.Mine[$Day] = [long]$state.Mine[$Day] + [long]$Tokens
            $json = @{ writer = $state.Writer; day = $Day; tokens = [long]$state.Mine[$Day]; at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
            if (-not $setFn) { throw 'the AI usage ledger cannot be written in this job (Set-SIBlobContent not loaded from engine\_shared\SI-AzRest.ps1)' }
            $null = & $setFn -Account $state.Account -Container $state.Container -Blob ("ai-usage/{0}/{1}.json" -f $Day, $state.Writer) -Bytes ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
        }.GetNewClosure()
    }
}

function Get-SIAiBudgetLedger {
    <# The ledger in force: the seam, else the storage account's (SI_STORAGE_ACCOUNT, when the blob functions are loaded), else this process. #>
    if ($global:SI_AiBudgetLedger -is [hashtable] -and $global:SI_AiBudgetLedger.Read -and $global:SI_AiBudgetLedger.Add) { return $global:SI_AiBudgetLedger }
    $acct = [Environment]::GetEnvironmentVariable('SI_STORAGE_ACCOUNT')
    if (-not $acct) { $acct = [string](Get-Variable -Scope Global -Name SI_StorageAccount -ValueOnly -ErrorAction Ignore) }
    if ($acct -and (Get-Command -Name Get-SIBlobList -ErrorAction SilentlyContinue) -and (Get-Command -Name Set-SIBlobContent -ErrorAction SilentlyContinue)) {
        $global:SI_AiBudgetLedger = New-SIAiBudgetBlobLedger -Account $acct
        return $global:SI_AiBudgetLedger
    }
    if (-not ($global:SI_AiBudgetProcessUse -is [hashtable])) { $global:SI_AiBudgetProcessUse = @{} }
    $global:SI_AiBudgetLedger = @{
        Read = { param($Day) if ($global:SI_AiBudgetProcessUse.ContainsKey($Day)) { [long]$global:SI_AiBudgetProcessUse[$Day] } else { 0L } }
        Add  = { param($Day, $Tokens) if (-not $global:SI_AiBudgetProcessUse.ContainsKey($Day)) { $global:SI_AiBudgetProcessUse[$Day] = 0L }; $global:SI_AiBudgetProcessUse[$Day] = [long]$global:SI_AiBudgetProcessUse[$Day] + [long]$Tokens }
    }
    $global:SI_AiBudgetLedger
}

function Reset-SIAiBudgetState {
    <# Clears this process's breaker, ledger and counters (tests; a new process starts clean anyway). #>
    $global:SI_AiBudgetLedger = $null; $global:SI_AiBudgetProcessUse = @{}; $global:SI_AiBudgetOpenDay = ''
    $global:SI_AiBudgetSaid = $false; $global:SI_AiBudgetUsedAtRead = 0L; $global:SI_AiBudgetAddedSinceRead = 0L; $global:SI_AiBudgetReadDay = ''
    $global:SI_AiBudgetReadAt = $null; $global:SI_AiBudgetUnreadableUntil = $null; $global:SI_AiBudgetReadWarned = $false; $global:SI_AiBudgetWriteWarned = $false
}

function Get-SIAiBudgetText {
    <# PURE. The one warning line (customer words). #>
    param([long]$Used, [long]$Budget)
    ('AI daily limit reached: {0:N0} of {1:N0} tokens used today (UTC). SecurityInsight makes no more AI requests today; the run goes on without them, and AI starts again tomorrow. The limit is the setting SI_AI_DailyTokenBudget.' -f $Used, $Budget)
}

function Get-SIAiBudgetRefusedText {
    <# PURE. What Invoke-SIOpenAIChat throws for a request the open breaker refuses (callers treat it as "the AI part could not run"). #>
    'AI daily limit reached: this AI request was not sent. The run goes on without it.'
}

function Get-SIAiBudgetAlert {
    <# PURE. The alert event of an opened breaker (sent once per process through $global:SI_AiBudgetAlert). #>
    param([long]$Used, [long]$Budget, [string]$Day)
    [pscustomobject]@{ Id = 'si.ai.daily-budget-reached'; Severity = 'warning'; Area = 'ai'; Day = $Day; Used = $Used; Budget = $Budget; Text = (Get-SIAiBudgetText -Used $Used -Budget $Budget) }
}

function ConvertTo-SIAiBudgetAlertRecord {
    <#
        PURE. The uplink ALERT record of an opened breaker (Invardia's closed shape, Kind 'alert', identified only -- $null for
        an anonymous context): the envelope (Schema 2, Kind, Product, Version, Ring, Edition, ClaimedTenantId, InstallId,
        LicenceId, EnvironmentName -- each only when known), AlertId si.ai.daily-budget-reached, Severity warning,
        Measured { tokens, budgetTokens }, FirstSeenUtc, Count 1, Area ai, Job = the execution kind, ActionText.
    #>
    param([Parameter(Mandatory)]$Event, [Parameter(Mandatory)]$Context, [string]$Kind = 'flow', [datetime]$AtUtc = [datetime]::UtcNow)
    if ([string]$Context.Mode -ne 'identified') { return $null }
    $r = [ordered]@{ Schema = 2; Kind = 'alert'; Product = 'securityinsight' }
    $ctxv = { param($n) if ($Context.PSObject.Properties[$n] -and $null -ne $Context.$n -and "$($Context.$n)".Trim() -ne '') { $Context.$n } else { $null } }
    if (& $ctxv 'Version') { $r.Version = [string](& $ctxv 'Version') }
    if ($null -ne (& $ctxv 'Ring')) { $r.Ring = [int](& $ctxv 'Ring') }
    if (& $ctxv 'Edition') { $r.Edition = [string](& $ctxv 'Edition') }
    if (& $ctxv 'TenantId') { $r.ClaimedTenantId = [string](& $ctxv 'TenantId') }
    $lid = & $ctxv 'LastingInstallId'
    if ($lid -and (Get-Command -Name ConvertTo-SIInvardiaInstallId -ErrorAction SilentlyContinue)) { $lid = ConvertTo-SIInvardiaInstallId ([string]$lid) }
    if ($lid) { $r.InstallId = [string]$lid }
    if (& $ctxv 'LicenceId') { $r.LicenceId = [string](& $ctxv 'LicenceId') }
    if (& $ctxv 'EnvironmentName') { $r.EnvironmentName = [string](& $ctxv 'EnvironmentName') }
    $r.AlertId = [string]$Event.Id
    $r.Severity = 'warning'
    # Invardia's catalog (2026-11-21): Area 'ai', Measured { tokens, budgetTokens }, Job = the execution kind
    $r.Measured = [pscustomobject][ordered]@{ tokens = [long]$Event.Used; budgetTokens = [long]$Event.Budget }
    $r.FirstSeenUtc = $AtUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $r.Count = 1
    $r.Area = 'ai'
    $r.Job = $Kind
    $at = ([string]$Event.Text -replace '[\x00-\x1F\x7F]', ' ')
    if ($at.Length -gt 500) { $at = $at.Substring(0, 500) }
    $r.ActionText = $at
    [pscustomobject]$r
}

function Test-SIAiBudgetAlertLive {
    <#
        PURE. Is si.ai.daily-budget-reached live in Invardia's alert catalog? The uplink contract is CLOSED (an unknown alert
        id refuses the record), so the alert is sent only once Invardia says the id is live (server first). Until then the
        breaker still stops every request and writes its warning line; only the uplink record waits.
        LIVE since Invardia 1.0.1190 (2026-11-21).
    #>
    $true
}

function Send-SIAiBudgetAlert {
    <# The default alert sender: the record above over the uplink (as every SecurityInsight report). NEVER throws; returns the state. #>
    param([Parameter(Mandatory)]$Event, $Context, [scriptblock]$Transport)
    if (-not (Test-SIAiBudgetAlertLive) -and -not $Transport) { return 'not-live' }
    try {
        if (-not $Context) {
            if ((Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue) -and -not (Test-SITelemetryEnabled)) { return 'off' }
            if (-not $Transport -and (Get-Module -Name Pester)) { return 'test-session' }
            if (-not (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) { return 'no-telemetry' }
            $Context = Get-SITelemetryContext
        }
        $rec = ConvertTo-SIAiBudgetAlertRecord -Event $Event -Context $Context
        if (-not $rec) { return 'anonymous' }
        if (-not $Transport) {
            if (Get-Command -Name Send-SITelemetryUplink -ErrorAction SilentlyContinue) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
            elseif (Get-Command -Name Send-AitUplink -ErrorAction SilentlyContinue) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
            else { return 'no-telemetry' }
        }
        $a = & $Transport $rec ([string]$Context.Endpoint) ([string]$Context.AccessCode) 5
        if ($a -and [string]$a.Status -eq 'ok') { 'sent' } else { 'failed' }
    } catch { 'failed' }
}

function Open-SIAiBudgetBreaker {
    param([long]$Used, [long]$Budget, [string]$Day)
    $global:SI_AiBudgetOpenDay = $Day
    if ([bool]$global:SI_AiBudgetSaid) { return }
    $global:SI_AiBudgetSaid = $true
    Write-Warning (Get-SIAiBudgetText -Used $Used -Budget $Budget)
    $ev = Get-SIAiBudgetAlert -Used $Used -Budget $Budget -Day $Day
    try {
        if ($global:SI_AiBudgetAlert -is [scriptblock]) { & $global:SI_AiBudgetAlert $ev }
        else { $null = Send-SIAiBudgetAlert -Event $ev }
    } catch { Write-Warning ('AI daily limit: the alert could not be sent ({0})' -f $_.Exception.Message) }
}

function Test-SIAiBudgetOpen {
    <#
        $true = the next request may go. Reads the day's ledger once a minute (between reads, this process's own additions
        count on top), so a breaker opened by ANY engine of the install stops the others within a minute. A ledger that
        cannot be read = at the budget (the breaker opens). Never throws.
    #>
    $day = Get-SIAiBudgetDay
    if ([string]$global:SI_AiBudgetOpenDay -eq $day) { return $false }
    $budget = Get-SIAiDailyTokenBudget
    $now = [datetime]::UtcNow
    $stale = ([string]$global:SI_AiBudgetReadDay -ne $day) -or -not ($global:SI_AiBudgetReadAt -is [datetime]) -or (($now - [datetime]$global:SI_AiBudgetReadAt).TotalSeconds -ge 60)
    if ($stale) {
        # unknown spend is never a reason to spend more: an unreadable ledger refuses the request (said once), and the read
        # is tried again after a minute
        if ($global:SI_AiBudgetUnreadableUntil -is [datetime] -and $now -lt [datetime]$global:SI_AiBudgetUnreadableUntil) { return $false }
        try { $global:SI_AiBudgetUsedAtRead = [long](& (Get-SIAiBudgetLedger).Read $day) }
        catch {
            if (-not [bool]$global:SI_AiBudgetReadWarned) { $global:SI_AiBudgetReadWarned = $true; Write-Warning ('AI daily limit: today''s AI use could not be read ({0}) -- no AI request is made until it can be' -f $_.Exception.Message) }
            $global:SI_AiBudgetUnreadableUntil = $now.AddSeconds(60)
            return $false
        }
        $global:SI_AiBudgetReadDay = $day; $global:SI_AiBudgetReadAt = $now; $global:SI_AiBudgetAddedSinceRead = 0L
    }
    $used = [long]$global:SI_AiBudgetUsedAtRead + [long]$global:SI_AiBudgetAddedSinceRead
    if ($used -ge $budget) { Open-SIAiBudgetBreaker -Used $used -Budget $budget -Day $day; return $false }
    $true
}

function Get-SIAiResponseTokens {
    <# PURE. The tokens one answer cost: usage.total_tokens, else prompt + completion, else an estimate (request chars / 3, at least 1). #>
    param($Response, $Body)
    try {
        $u = $Response.usage
        if ($u) {
            if ($null -ne $u.total_tokens -and [long]$u.total_tokens -gt 0) { return [long]$u.total_tokens }
            $t = [long]$u.prompt_tokens + [long]$u.completion_tokens
            if ($t -gt 0) { return $t }
        }
    } catch { }
    $len = if ($Body -is [byte[]]) { ([byte[]]$Body).Length } else { ([string]$Body).Length }
    [long][Math]::Max(1, [Math]::Ceiling($len / 3.0))
}

function Add-SIAiBudgetUsage {
    <# Adds one answer's tokens to today's ledger. A ledger write that fails is said once; the tokens still count in this process. Never throws. #>
    param([long]$Tokens)
    if ($Tokens -le 0) { return }
    $day = Get-SIAiBudgetDay
    $global:SI_AiBudgetAddedSinceRead = [long]$global:SI_AiBudgetAddedSinceRead + $Tokens
    try { & (Get-SIAiBudgetLedger).Add $day $Tokens }
    catch {
        if (-not [bool]$global:SI_AiBudgetWriteWarned) { $global:SI_AiBudgetWriteWarned = $true; Write-Warning ('AI daily limit: today''s AI use could not be saved ({0}) -- it still counts in this run' -f $_.Exception.Message) }
    }
    $budget = Get-SIAiDailyTokenBudget
    $used = [long]$global:SI_AiBudgetUsedAtRead + [long]$global:SI_AiBudgetAddedSinceRead
    if ($used -ge $budget) { Open-SIAiBudgetBreaker -Used $used -Budget $budget -Day $day }
}
