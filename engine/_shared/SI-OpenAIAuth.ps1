#Requires -Version 5.1
<#
    #1257 AI WITHOUT A KEY (owner decision): every Azure OpenAI call of the engines signs in as the ENGINE'S OWN IDENTITY
    (its managed identity in the cloud: an Entra token for https://cognitiveservices.azure.com, sent as
    "Authorization: Bearer") -- no key. The token comes from SecurityInsight's ONE token function, Get-SIAzureToken
    (engine/_shared/SI-AzRest.ps1: the managed-identity endpoint IDENTITY_ENDPOINT in a container, the run's certificate
    sign-in elsewhere); no new sign-in mechanism, no PowerShell module.

    ORDER:
      1. the engine's identity first;
      2. no token, or Azure OpenAI answers 401 / 403 to it, AND a key is configured (OpenAI_apiKey): the key, with ONE
         plain warning per run ("AI is still using a key; ask your support partner to ...") -- and the rest of the run
         stays on the key (no second refused call per request);
      3. no key and the identity cannot be used: the AI part fails ALONE with a clear message (said once per run); every
         later AI call of the run is skipped at once; the run goes on.

    REMOVE-ME (#1257): the key fallback (step 2, Switch-SIOpenAIToKey and every OpenAI_apiKey read it serves) is a
    transition aid only. Remove it once every install's engine identity holds "Cognitive Services OpenAI User" on its
    Azure OpenAI resource (setup / the updater grant it: setup/_shared/SI-OpenAIRights.ps1).

    Used by: engine/risk-analysis/Invoke-RiskAnalysis.ps1 (the streamed AI summary), engine/asset-profiling/stages/
    Invoke-Classify.ps1 / Invoke-Enrich.ps1 / Invoke-SchemaPropose.ps1, engine/privilege-tier-classifier/
    Invoke-PrivilegeTierClassifier.ps1. Loaded by engine/asset-profiling/shared/Test-SIAIEnabled.ps1 (which every AI
    caller loads). State is GLOBAL (the callers dot-source this file in different scopes); Reset-SIOpenAIAuthState clears it.
#>

if (-not (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue)) {
    $__siOaiRest = Join-Path $PSScriptRoot 'SI-AzRest.ps1'
    if (Test-Path -LiteralPath $__siOaiRest) { . $__siOaiRest }
}

function Get-SIOpenAIResource {
    <# PURE. The token resource of Azure OpenAI (scope https://cognitiveservices.azure.com/.default). #>
    'https://cognitiveservices.azure.com/'
}

function Get-SIOpenAIKeyFallbackText {
    <# PURE. The one warning of a run that still uses the key. #>
    'AI is still using a key; ask your support partner to give the engine access to the Azure OpenAI resource.'
}

function Get-SIOpenAINoAccessText {
    <# PURE. The one message of a run whose AI part cannot run (no access and no key). #>
    'The AI part could not run: the engine has no access to the Azure OpenAI resource and no key is set. Ask your support partner to give the engine access to the Azure OpenAI resource. The rest of the run goes on.'
}

function Get-SIOpenAIModeText {
    <# PURE. The one line of a run whose AI signs in as the engine's identity; -KeySet: a (legacy) key is still configured. #>
    param([bool]$KeySet)
    if ($KeySet) { return '[AI] AI signs in to Azure OpenAI as the engine''s own identity; the key that is still set is used only if that sign-in is refused.' }
    '[AI] AI signs in to Azure OpenAI as the engine''s own identity (no key).'
}

function Reset-SIOpenAIAuthState {
    <# This run's AI sign-in state back to "try the engine's identity first" (a new run; tests). #>
    $global:SI_OpenAIModeSaid = $false
    $global:SI_OpenAIUseKey = $false
    $global:SI_OpenAIKeyWarned = $false
    $global:SI_OpenAINoAccess = $false
    $global:SI_OpenAINoAccessSaid = $false
    $global:SI_OpenAIAuthMode = ''
    Reset-SIOpenAIParamState
}

# ---------------------------------------------------------------------------------------------------------------------
# #1269 AI WORKS WITH THE NEWEST AZURE OPENAI MODELS. Every request carries the output cap as max_completion_tokens (the
# current parameter; the setting stays OpenAI_MaxTokensPerRequest). A deployment that answers 400 "unsupported parameter /
# value" naming one of the parameters below gets the request sent ONCE more with that parameter adapted, and the run
# remembers it (one log line), so every later request of the run is sent adapted from the start:
#   max_completion_tokens <-> max_tokens   (an older model / API version, or a newer model that refuses the old name)
#   temperature / top_p / presence_penalty / frequency_penalty   -> dropped, all four together (reasoning models accept
#                                                                   only their defaults)
# Each of the two groups is adapted at most once per run and a request is re-sent at most once: a second 400 is the
# service's error, and the caller's own handling (the AI summary skipped with the reason, Tier 99, ...) stays as it was.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIOpenAITokenParameters {
    <# PURE. The two names of the output cap. #>
    @('max_completion_tokens', 'max_tokens')
}

function Get-SIOpenAISamplingParameters {
    <# PURE. The sampling parameters a reasoning model accepts only at their default (dropped together). #>
    @('temperature', 'top_p', 'presence_penalty', 'frequency_penalty')
}

function Reset-SIOpenAIParamState {
    <# This run's request-parameter adaptations back to "as the caller built it" (a new run; tests). #>
    $global:SI_OpenAITokenParam = ''
    $global:SI_OpenAIDropSampling = $false
}

function Get-SIOpenAIErrorText {
    <# PURE. The answer body of a failed Invoke-RestMethod (PowerShell 7 and 5.1), else the exception's message. #>
    param($ErrorRecord)
    $t = ''
    try { if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $t = [string]$ErrorRecord.ErrorDetails.Message } } catch { }
    if (-not $t) { try { $t = [string]$ErrorRecord.Exception.Message } catch { } }
    $t
}

function Get-SIOpenAIUnsupportedParameter {
    <#
        PURE. The request parameter an Azure OpenAI 400 answer refuses ('' = not such an answer): one of
        Get-SIOpenAITokenParameters / Get-SIOpenAISamplingParameters, named by the answer's error.param or by its message
        ("Unsupported parameter: 'max_tokens' ...", "Unsupported value: 'temperature' ...",
        "Unrecognized request argument supplied: max_completion_tokens").
    #>
    param([AllowEmptyString()][string]$ErrorText)
    if ([string]::IsNullOrWhiteSpace($ErrorText)) { return '' }
    $known = @((Get-SIOpenAITokenParameters) + (Get-SIOpenAISamplingParameters))
    $msg = $ErrorText; $param = ''; $code = ''
    try {
        $j = $ErrorText | ConvertFrom-Json -ErrorAction Stop
        if ($j -and $j.PSObject.Properties['error'] -and $j.error) {
            if ($j.error.PSObject.Properties['message']) { $msg = [string]$j.error.message }
            if ($j.error.PSObject.Properties['param'])   { $param = [string]$j.error.param }
            if ($j.error.PSObject.Properties['code'])    { $code = [string]$j.error.code }
        }
    } catch { }
    $refusal = ($code -match '^unsupported_(parameter|value)$') -or ($msg -match '(?i)unsupported (parameter|value)|not supported|does not support|unrecognized request argument')
    if (-not $refusal) { return '' }
    if ($param -and ($known -contains $param.ToLowerInvariant())) { return $param.ToLowerInvariant() }
    $m = [regex]::Match($msg, "(?i)(?:unsupported (?:parameter|value):\s*'([a-z_]+)'|unrecognized request argument supplied:\s*'?([a-z_]+))")
    if ($m.Success) {
        $n = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($known -contains $n.ToLowerInvariant()) { return $n.ToLowerInvariant() }
    }
    ''
}

function Add-SIOpenAIParamAdaptation {
    <#
        Remember for the rest of the run how the deployment's refusal of -Parameter is answered; says ONE log line.
        $true = a new adaptation (send the request once more); $false = that parameter's group was adapted already in this
        run (never flip back and forth: the 400 stands).
    #>
    param([Parameter(Mandatory)][string]$Parameter)
    $p = $Parameter.ToLowerInvariant()
    if ((Get-SIOpenAITokenParameters) -contains $p) {
        if (-not [string]::IsNullOrEmpty([string](Get-Variable -Scope Global -Name SI_OpenAITokenParam -ValueOnly -ErrorAction Ignore))) { return $false }
        $use = if ($p -eq 'max_completion_tokens') { 'max_tokens' } else { 'max_completion_tokens' }
        $global:SI_OpenAITokenParam = $use
        Write-Host ("[AI] the model does not accept '{0}'; '{1}' is sent instead for the rest of this run." -f $p, $use)
        return $true
    }
    if ((Get-SIOpenAISamplingParameters) -contains $p) {
        if ([bool](Get-Variable -Scope Global -Name SI_OpenAIDropSampling -ValueOnly -ErrorAction Ignore)) { return $false }
        $global:SI_OpenAIDropSampling = $true
        Write-Host ("[AI] the model does not accept '{0}'; {1} are left at the model's defaults for the rest of this run." -f $p, ((Get-SIOpenAISamplingParameters) -join ' / '))
        return $true
    }
    $false
}

function ConvertTo-SIOpenAIAdaptedBody {
    <#
        A chat completions request body (JSON text or UTF-8 bytes; the same type comes back) with this run's adaptations
        applied: the output cap under the name the deployment accepts, the sampling parameters dropped when it refuses
        them. No adaptation in this run: the body comes back untouched.
    #>
    param([Parameter(Mandatory)]$Body)
    $tokenUse = [string](Get-Variable -Scope Global -Name SI_OpenAITokenParam -ValueOnly -ErrorAction Ignore)
    $drop = [bool](Get-Variable -Scope Global -Name SI_OpenAIDropSampling -ValueOnly -ErrorAction Ignore)
    if (-not $tokenUse -and -not $drop) { return ,$Body }
    $isBytes = $Body -is [byte[]]
    $text = if ($isBytes) { [System.Text.Encoding]::UTF8.GetString([byte[]]$Body) } else { [string]$Body }
    $cfj = @{ ErrorAction = 'Stop' }
    if ((Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $cfj['DateKind'] = 'String' }   # keep date-like text as text
    try { $o = $text | ConvertFrom-Json @cfj } catch { return ,$Body }
    if ($null -eq $o -or $o -isnot [pscustomobject]) { return ,$Body }
    $changed = $false
    if ($tokenUse) {
        $other = if ($tokenUse -eq 'max_tokens') { 'max_completion_tokens' } else { 'max_tokens' }
        if ($o.PSObject.Properties[$other]) {
            $v = $o.$other
            $o.PSObject.Properties.Remove($other)
            if (-not $o.PSObject.Properties[$tokenUse]) { $o | Add-Member -NotePropertyName $tokenUse -NotePropertyValue $v }
            $changed = $true
        }
    }
    if ($drop) {
        foreach ($s in (Get-SIOpenAISamplingParameters)) { if ($o.PSObject.Properties[$s]) { $o.PSObject.Properties.Remove($s); $changed = $true } }
    }
    if (-not $changed) { return ,$Body }
    $out = $o | ConvertTo-Json -Depth 64 -Compress
    if ($isBytes) { return ,([System.Text.Encoding]::UTF8.GetBytes($out)) }
    $out
}

function Test-SIOpenAIKeyConfigured {
    <# $true when a key is configured ($global:OpenAI_apiKey; PowerShell names are case-insensitive, so OpenAI_ApiKey too). #>
    $k = Get-Variable -Scope Global -Name OpenAI_apiKey -ValueOnly -ErrorAction Ignore
    -not [string]::IsNullOrWhiteSpace([string]$k)
}

function Test-SIOpenAIAuthRefused {
    <# PURE. $true for the answers that mean "this sign-in may not use the resource": 401 / 403. #>
    param([int]$StatusCode)
    $StatusCode -eq 401 -or $StatusCode -eq 403
}

function Get-SIOpenAIErrorStatus {
    <# PURE. The HTTP status of a failed Invoke-RestMethod (PowerShell 7 and 5.1), 0 when there was no answer. #>
    param($ErrorRecord)
    try {
        $r = $ErrorRecord.Exception.Response
        if ($null -ne $r -and $null -ne $r.StatusCode) { return [int]$r.StatusCode }
    } catch { }
    0
}

function Get-SIOpenAIAccessToken {
    <# An Entra access token for Azure OpenAI as the engine's identity (Get-SIAzureToken). THROWS when there is none. #>
    param([switch]$ForceRefresh)
    if (-not (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue)) { throw 'the engine''s sign-in helper is not loaded in this run' }
    $t = [string](Get-SIAzureToken -Resource (Get-SIOpenAIResource) -ForceRefresh:$ForceRefresh)
    if ([string]::IsNullOrWhiteSpace($t)) { throw 'no sign-in token was returned' }
    $t
}

function New-SIOpenAIKeyAuth {
    # REMOVE-ME (#1257): the key header, for the fallback only
    [pscustomobject]@{ Mode = 'Key'; Headers = @{ 'api-key' = [string](Get-Variable -Scope Global -Name OpenAI_apiKey -ValueOnly -ErrorAction Ignore) }; Reason = '' }
}

function Switch-SIOpenAIToKey {
    <#
        The engine's identity could not be used (-Reason: why, for the log). A key configured: the rest of the run uses the
        key and the warning is said ONCE. No key: Mode 'None' with the clear message, said ONCE; later calls skip at once.
        REMOVE-ME (#1257): with the key fallback gone this always answers Mode 'None'.
    #>
    param([string]$Reason = '')
    if (Test-SIOpenAIKeyConfigured) {
        $global:SI_OpenAIUseKey = $true
        $global:SI_OpenAIAuthMode = 'Key'
        if (-not [bool](Get-Variable -Scope Global -Name SI_OpenAIKeyWarned -ValueOnly -ErrorAction Ignore)) {
            $global:SI_OpenAIKeyWarned = $true
            Write-Warning (Get-SIOpenAIKeyFallbackText)
            if ($Reason) { Write-Verbose ('[AI] engine identity not used: {0}' -f $Reason) }
        }
        return (New-SIOpenAIKeyAuth)
    }
    $global:SI_OpenAINoAccess = $true
    $global:SI_OpenAIAuthMode = 'None'
    $msg = Get-SIOpenAINoAccessText
    if (-not [bool](Get-Variable -Scope Global -Name SI_OpenAINoAccessSaid -ValueOnly -ErrorAction Ignore)) {
        $global:SI_OpenAINoAccessSaid = $true
        Write-Warning $msg
        if ($Reason) { Write-Verbose ('[AI] engine identity not used: {0}' -f $Reason) }
    }
    [pscustomobject]@{ Mode = 'None'; Headers = @{}; Reason = $msg }
}

function Get-SIOpenAIAuthHeader {
    <#
        How the next Azure OpenAI call signs in: @{ Mode = 'ManagedIdentity' | 'Key' | 'None'; Headers; Reason }.
        The engine's identity first; the key only after the identity failed in this run (and only when one is configured);
        'None' = the AI part does not run (Reason = the message to say).
    #>
    if ([bool](Get-Variable -Scope Global -Name SI_OpenAINoAccess -ValueOnly -ErrorAction Ignore)) {
        return [pscustomobject]@{ Mode = 'None'; Headers = @{}; Reason = (Get-SIOpenAINoAccessText) }
    }
    # REMOVE-ME (#1257): the run already fell back to the key
    if ([bool](Get-Variable -Scope Global -Name SI_OpenAIUseKey -ValueOnly -ErrorAction Ignore) -and (Test-SIOpenAIKeyConfigured)) { return (New-SIOpenAIKeyAuth) }
    $why = ''
    try {
        $tok = Get-SIOpenAIAccessToken
        $global:SI_OpenAIAuthMode = 'ManagedIdentity'
        # said ONCE per run: how AI signs in -- and, on an install that still has a key, that the key is only the fallback
        if (-not [bool](Get-Variable -Scope Global -Name SI_OpenAIModeSaid -ValueOnly -ErrorAction Ignore)) {
            $global:SI_OpenAIModeSaid = $true
            Write-Host (Get-SIOpenAIModeText -KeySet (Test-SIOpenAIKeyConfigured))
        }
        return [pscustomobject]@{ Mode = 'ManagedIdentity'; Headers = @{ 'Authorization' = ('Bearer ' + $tok) }; Reason = '' }
    } catch { $why = ($_.Exception.Message -replace '\s+', ' ') }
    Switch-SIOpenAIToKey -Reason ('no sign-in token for Azure OpenAI: ' + $why)
}

function Get-SIOpenAIProbeStatus {
    <#
        ONE probe request (POST -Uri with -Body and -Headers) for setup\Validate-SIOpenAI.ps1's sign-in check: the HTTP status
        (0 = no answer). The same host rule as every call: the credential in -Headers goes only to an Azure OpenAI https host
        (another host = 0, nothing sent). Never throws.
    #>
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{}, $Body = '{}', [int]$TimeoutSec = 60)
    if (-not (Get-Command -Name Test-SIOpenAIEndpoint -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/shared/Test-SIAIEnabled.ps1') }
    if (Test-SIOpenAIEndpoint -Endpoint $Uri) { return 0 }
    try { [int](Invoke-WebRequest -Method Post -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json' -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop).StatusCode }
    catch { $c = 0; try { $c = [int]$_.Exception.Response.StatusCode } catch { }; $c }
}

function Invoke-SIOpenAIChat {
    <#
        ONE Azure OpenAI request (POST -Uri with -Body) with the sign-in order above; returns Invoke-RestMethod's answer.
        A 401 / 403 to the engine's identity switches to the key (when configured) and sends the request once more;
        a 400 refusing a request parameter (#1269, above) adapts it and sends the request once more (once per request);
        THROWS the clear message when the AI part cannot run, or the service's error for any other failure (the caller's
        own handling -- a warning, a retry, Tier 99 -- stays as it was).
    #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)]$Body, [string]$ContentType = 'application/json', [int]$TimeoutSec = 0)
    # where a credential goes: the token (or the fallback key) ONLY to an Azure OpenAI host -- checked here, before any
    # token is asked for, whatever the caller checked already (Test-SIOpenAIEndpoint, engine/asset-profiling/shared/Test-SIAIEnabled.ps1)
    if (-not (Get-Command -Name Test-SIOpenAIEndpoint -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/shared/Test-SIAIEnabled.ps1') }
    $why = Test-SIOpenAIEndpoint -Endpoint $Uri
    if ($why) { throw ('Azure OpenAI is not called, no credential is sent: {0}' -f $why) }
    # OPENAI-CAP (owner 2026-11-21): the install's daily token budget is asked FIRST -- at the budget nothing is sent
    # (engine/_shared/SI-AiBudget.ps1: one warning, one alert, AI starts again the next UTC day)
    if (-not (Get-Command -Name Test-SIAiBudgetOpen -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AiBudget.ps1') }
    if (-not (Test-SIAiBudgetOpen)) { throw (Get-SIAiBudgetRefusedText) }
    $auth = Get-SIOpenAIAuthHeader
    if ($auth.Mode -eq 'None') { throw $auth.Reason }
    # #1269: what this run already learned about the deployment's parameters, applied before the first send
    $send = ConvertTo-SIOpenAIAdaptedBody -Body $Body
    $adapted = $false
    # at most 3 sends: the first, once more after a refused identity, once more after a refused parameter
    for ($try = 1; $try -le 3; $try++) {
        $h = @{ 'Content-Type' = $ContentType }
        foreach ($k in @($auth.Headers.Keys)) { $h[$k] = $auth.Headers[$k] }
        $p = @{ Method = 'Post'; Uri = $Uri; Headers = $h; Body = $send; ErrorAction = 'Stop' }
        if ($TimeoutSec -gt 0) { $p['TimeoutSec'] = $TimeoutSec }
        $resp = $null
        try { $resp = Invoke-RestMethod @p }
        catch {
            $code = Get-SIOpenAIErrorStatus $_
            if ($auth.Mode -eq 'ManagedIdentity' -and (Test-SIOpenAIAuthRefused -StatusCode $code)) {
                $auth = Switch-SIOpenAIToKey -Reason ('Azure OpenAI refused the engine''s identity (HTTP {0})' -f $code)
                if ($auth.Mode -eq 'None') { throw $auth.Reason }
                continue
            }
            if ($code -eq 400 -and -not $adapted) {
                $refused = Get-SIOpenAIUnsupportedParameter -ErrorText (Get-SIOpenAIErrorText $_)
                if ($refused -and (Add-SIOpenAIParamAdaptation -Parameter $refused)) {
                    $next = ConvertTo-SIOpenAIAdaptedBody -Body $Body
                    $adapted = $true
                    # sent once more only when the body really changed (the refused parameter was in it)
                    $was = if ($send -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString([byte[]]$send) } else { [string]$send }
                    $now = if ($next -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString([byte[]]$next) } else { [string]$next }
                    if ($now -cne $was) { $send = $next; continue }
                }
            }
            throw
        }
        # OPENAI-CAP: what this answer cost counts against today's budget
        Add-SIAiBudgetUsage -Tokens (Get-SIAiResponseTokens -Response $resp -Body $send)
        return $resp
    }
}

function Test-SIOpenAIRetryable {
    <#
        PURE. OPENAI-CAP (owner 2026-11-21): may a caller send the SAME request again after this failure? Only a 408 / 429 /
        5xx or no answer at all (a network failure); never a 400 (a bug in the request: logged and skipped), never an
        auth refusal, never the daily limit. Callers make at most 2 attempts (Get-SIOpenAIMaxAttempts).
    #>
    param($ErrorRecord)
    $msg = ''
    try { $msg = [string]$ErrorRecord.Exception.Message } catch { }
    if ($msg -match '^AI daily limit reached') { return $false }
    $code = 0
    try { $code = [int](Get-SIOpenAIErrorStatus $ErrorRecord) } catch { $code = 0 }
    if ($code -eq 0) { return ($msg -notmatch 'could not run|is not called') }
    return ($code -in 408, 429 -or $code -ge 500)
}

function Get-SIOpenAIMaxAttempts {
    <# PURE. OPENAI-CAP: the most sends of one AI request by any caller (the first + one retry). #>
    2
}
