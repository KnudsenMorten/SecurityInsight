#Requires -Version 5.1
<#
    THE LOCAL SETUP WIZARD NEVER KEEPS A SENSITIVE ANSWER IN BROWSER STORAGE.

    setup\ConfigWizard\app.js mirrors the wizard's answers to localStorage so a closed tab comes back where it was.
    Passwords and API keys must never be part of that copy: they live in memory for the page session only, an
    earlier stored value is removed on load, and a feature that needs one is never applied without it.

    Static checks over app.js, the page and the README (the wizard has no JS test harness here):
      * every <input type="password" data-key> is treated as sensitive -- by its type, and its key is also in the
        central SENSITIVE_KEYS list;
      * a data-key that names a password / API key / token / client secret is a password input (a new one cannot
        be added as plain text);
      * the save path strips the sensitive keys before localStorage.setItem, and no other path writes the state;
      * the load path removes stored sensitive values (and rewrites storage) BEFORE the stored state is restored;
      * Apply refuses a feature whose sensitive answer is missing (the wizard asks for it again);
      * the page and the README say sensitive answers are not saved.
    ASCII only (PowerShell 5.1 reads a BOM-less file as Windows-1252).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Wiz    = Join-Path $script:SIRoot 'setup\ConfigWizard'
    $script:Js     = Get-Content -Raw -LiteralPath (Join-Path $script:Wiz 'app.js')
    $script:Html   = Get-Content -Raw -LiteralPath (Join-Path $script:Wiz 'Setup-SecurityInsight.html')
    $script:Readme = Get-Content -Raw -LiteralPath (Join-Path $script:Wiz 'README.md')

    # A top-level function's text: from "function <name>(" to the first "}" at the start of a line.
    function script:Get-JsFunction([string]$Name) {
        $m = [regex]::Match($script:Js, '(?ms)^function ' + [regex]::Escape($Name) + '\s*\(.*?^\}')
        if ($m.Success) { $m.Value } else { $null }
    }

    $script:PasswordInputs = @([regex]::Matches($script:Html, '<input\b[^>]*>') | ForEach-Object { $_.Value } |
        Where-Object { $_ -match 'type="password"' })
    $script:PasswordKeys = @($script:PasswordInputs | ForEach-Object {
        if ($_ -match 'data-key="([^"]+)"') { $Matches[1] } })
    $script:AllKeys = @([regex]::Matches($script:Html, 'data-key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

    $listMatch = [regex]::Match($script:Js, "const SENSITIVE_KEYS\s*=\s*\[([^\]]*)\]")
    $script:ListedKeys = @([regex]::Matches($listMatch.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })

    $script:SaveFn     = Get-JsFunction 'saveState'
    $script:LoadFn     = Get-JsFunction 'loadState'
    $script:StripFn    = Get-JsFunction 'stateForStorage'
    $script:KeysFn     = Get-JsFunction 'sensitiveKeys'
    $script:ValidateFn = Get-JsFunction 'validateApplyPayload'
}

Describe 'The wizard: sensitive answers are never written to browser storage' {

    It 'the page has the known password fields' {
        $script:PasswordKeys.Count | Should -BeGreaterOrEqual 3
        foreach ($k in 'smtpPassword', 'openAiApiKey', 'shodanApiKey') { $script:PasswordKeys | Should -Contain $k }
    }

    It 'every password input is sensitive by its type, and its key is in the central list' {
        $script:KeysFn | Should -Not -BeNullOrEmpty
        $script:KeysFn | Should -Match ([regex]::Escape("querySelectorAll('input[type=""password""][data-key]')"))
        $script:KeysFn | Should -Match 'SENSITIVE_KEYS'
        foreach ($k in $script:PasswordKeys) { $script:ListedKeys | Should -Contain $k -Because "$k is a password input" }
    }

    It 'a field that names a password, API key, token or client secret is a password input' {
        $named = @($script:AllKeys | Where-Object { $_ -match '(?i)(password|passwd|apikey|token|clientsecret|secretvalue)$' })
        $named.Count | Should -BeGreaterOrEqual 3
        foreach ($k in $named) { $script:PasswordKeys | Should -Contain $k -Because "$k names a sensitive value" }
        # The Key Vault secret NAME is a name, not a secret: it stays a normal, saved field.
        $script:PasswordKeys | Should -Not -Contain 'secretName'
    }

    It 'the save strips every sensitive key before it writes' {
        $script:StripFn | Should -Match 'sensitiveKeys\(\)\.forEach\(\s*k\s*=>\s*\{\s*delete copy\.data\[k\];'
        $script:SaveFn  | Should -Match 'localStorage\.setItem\(STORAGE_KEY,\s*JSON\.stringify\(stateForStorage\(state\)\)\)'
        $script:SaveFn  | Should -Not -Match 'JSON\.stringify\(state\)'
    }

    It 'no other path writes the wizard state to storage' {
        $writes = @([regex]::Matches($script:Js, 'localStorage\.setItem\([^;]*') | ForEach-Object { $_.Value })
        $writes.Count | Should -Be 2
        foreach ($w in $writes) {
            $w | Should -Match '^localStorage\.setItem\(STORAGE_KEY,\s*JSON\.stringify\((stateForStorage\(state\)|parsed)\)'
        }
        $script:Js | Should -Not -Match 'sessionStorage\.setItem'
        $script:Js | Should -Not -Match 'indexedDB'
        $script:Js | Should -Not -Match 'document\.cookie\s*='
    }

    It 'the load removes any stored sensitive value and rewrites storage before restoring the answers' {
        $script:LoadFn | Should -Not -BeNullOrEmpty
        $clean   = $script:LoadFn.IndexOf('delete parsed.data[k]')
        $rewrite = $script:LoadFn.IndexOf('localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed))')
        $restore = $script:LoadFn.IndexOf('Object.assign(state, parsed)')
        $clean   | Should -BeGreaterThan 0
        $rewrite | Should -BeGreaterThan $clean
        $restore | Should -BeGreaterThan $rewrite
        $script:LoadFn | Should -Match 'const keys = sensitiveKeys\(\);'
    }

    It 'Apply refuses a feature whose sensitive answer is missing (the wizard asks for it again)' {
        $script:ValidateFn | Should -Match "d\.smtpMode === 'auth' && !d\.smtpPassword\) problems\.push"
        $script:ValidateFn | Should -Match "d\.openAiMode === 'enabled' && d\.openAiResMode !== 'createNew' && !d\.openAiApiKey\) problems\.push"
        $script:ValidateFn | Should -Match "d\.shodanMode === 'enabled' && !d\.shodanApiKey\) problems\.push"
        $script:Js | Should -Match 'var problems = validateApplyPayload\(st\);'
    }

    It 'the page says each sensitive answer is not saved' {
        foreach ($k in $script:PasswordKeys) {
            $script:Html | Should -Match ('data-key="' + [regex]::Escape($k) + '"[^>]*/>\s*<span class="hint">Not saved by the wizard')
        }
    }

    It 'the README says sensitive answers are not saved and must be entered again' {
        $script:Readme | Should -Not -Match 'Every answer is saved'
        $script:Readme | Should -Match 'Sensitive answers -- passwords and API keys -- are NOT saved'
    }
}
