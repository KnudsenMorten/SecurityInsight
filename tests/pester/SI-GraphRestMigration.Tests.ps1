#Requires -Version 5.1
<#
    PURE REST INSTEAD OF THE Microsoft.Graph SDK (#113).

    🔑 Operator, 2026-09-08: *"do we need graph in image. can we use pure rest api"*. No, and REST was
    already the house style -- the four asset-profiling engines used zero `-Mg*` cmdlets, and every
    call the remaining engines made already had a REST implementation in this solution hitting the
    SAME endpoint.

    🔴 WHAT ACTUALLY BREAKS IF THIS PORT IS WRONG, and it is not the HTTP. Risk Analysis' AutoBucket
    escalation is driven by matching the TEXT of failures:

      * the 900s ceiling must read as `TaskCanceledException` -- under the SDK it arrived as that
        exception TYPE; over REST a client timeout is a WebException on 5.1 and TaskCanceled on 7.
      * a 502 must read as `502 Bad Gateway` -- Invoke-RestMethod's own message is "(502) Bad Gateway",
        PARENTHESISED, which does not match the existing `-match '502 Bad Gateway'`.

    Neither failure throws. Both silently stop the bucket ramp on exactly the reports that need it,
    which is why the signals are asserted here rather than trusted. `RA-GraphHunting.ps1` already
    carries a comment about this trap costing an escalation once.

    🔒 And the response SHAPE is asserted because `Invoke-RiskAnalysis.ps1` reads
    `$resp.Results.AdditionalProperties` in four places. The adapter reproduces the SDK's shape on
    purpose, so the port stays confined to transport.
#>

BeforeAll {
    # 🪤 THREE levels: pester -> tests -> solution root. TWO lands on `tests\`, and every path below
    # then resolves under it -- which is how this file failed on its first run, and how
    # SI-ContainerResourceNames.Tests.ps1 failed on ITS first run earlier the same day. The dot-source
    # below fails loudly, but a Test-Path-style assertion under the wrong root would just pass.
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1')
}

Describe 'the REST client is loadable and complete' {

    It 'defines the transport surface the engines call' {
        foreach ($fn in 'Get-SIGraphRestStatus','Test-SIGraphRestTransient','Invoke-SIGraphRest','Invoke-SIGraphRestPaged','Invoke-SIHuntingQueryRest') {
            Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn is called by a migrated engine"
        }
    }

    It 'does not duplicate auth -- tokens come from the one token path' {
        # Two auth paths drift into disagreeing about which identity is in use, and the symptom is a
        # 403 that looks like a permissions problem rather than a configuration one.
        $raw = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $code = ($raw -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'client_credentials'
        $code | Should -Not -Match 'oauth2/v2\.0/token'
    }
}

Describe '🔴 request bodies are UTF-8 BYTES -- the bug a live run found and no offline test could' {
    <#
        FOUND BY THE FIRST LIVE RA RUN, 2026-09-08. 18 buckets failed with
        `400 BadRequest -- "Unable to read JSON request payload."` while the previous SDK run had
        ZERO errors.

        🪤 The error names the wrong half. Content-Type WAS set and the JSON WAS valid when built --
        PS 5.1's `Invoke-RestMethod -Body <string>` transcodes to a single-byte encoding and destroys
        every non-ASCII character on the way to the wire. Measured against a local HttpListener:
        a 47-byte UTF-8 payload arrived as 35 mangled bytes; the same payload as UTF-8 BYTES arrived
        byte-exact. RA then classified it as a QUERY DEFECT -- right advice, wrong cause.

        🔑 WHY OFFLINE TESTING COULD NEVER HAVE CAUGHT IT: it needs a non-ASCII character in the
        request. KQL is ASCII. RA is the first caller to inline hundreds of real device and user names
        into a query body, and this estate is Danish -- a customer's own asset names are what broke it.
    #>

    It 'serialises to a byte array, not a string' {
        $b = New-SIGraphJsonBody -Object @{ Query = 'x' }
        $b -is [byte[]] | Should -BeTrue
    }

    It '🔴 preserves non-ASCII byte-for-byte -- the exact property that failed live' {
        $text = "Søren Nørgaard ÆØÅ"
        $b    = New-SIGraphJsonBody -Object @{ Query = $text }
        $expected = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json @{ Query = $text } -Compress))
        $b.Length | Should -Be $expected
        ([System.Text.Encoding]::UTF8.GetString($b) | ConvertFrom-Json).Query | Should -Be $text
    }

    It '🪤 PROOF the string form loses bytes -- so this cannot be "simplified" back' {
        # A multi-byte payload is strictly longer in UTF-8 than its character count. If a future edit
        # hands Invoke-RestMethod the string again, that difference is the corruption.
        $json = ConvertTo-Json @{ Query = "Søren ÆØÅ" } -Compress
        [System.Text.Encoding]::UTF8.GetByteCount($json) | Should -BeGreaterThan $json.Length
    }

    It '🔒 HuntingQuery.ps1 uses the shared byte builder too -- no second string body survives' {
        # The profiler engines' hunting call had the identical latent bug. It never bit because that
        # path sends plain ASCII KQL with no inlined customer data -- but "only sends ASCII" is a
        # property of today's callers, not of the function.
        $hq = Get-Content (Join-Path $script:SIRootDir 'engine/asset-profiling/shared/HuntingQuery.ps1') -Raw
        $hq | Should -Match 'New-SIGraphJsonBody'
        $hq | Should -Match 'charset=utf-8'
        # the old form must not come back
        $hq | Should -Not -Match '-Body \(@\{ Query = \$Query \} \| ConvertTo-Json'
    }

    It 'both POST paths declare the charset, or the service may guess' {
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        ([regex]::Matches($src, "application/json; charset=utf-8")).Count | Should -BeGreaterOrEqual 2
        # and neither may pass a bare string body again
        $src | Should -Not -Match "-Body\s+\`$json\b"
    }
}

Describe '🔴 an expected failure must not reach the transcript (the 2 -> 16 regression)' {
    <#
        FOUND BY THE SECOND LIVE RA RUN, 2026-09-08. The UTF-8 fix worked and the run completed, but
        `PS>TerminatingError` lines went from **2 (SDK) to 16 (REST)** -- the exact noise
        `SI-TranscriptNoise.Tests.ps1` exists to remove, and the operator's own words: *"it looks very
        amateur"*.

        🪤 CAUSE: `Invoke-RestMethod` throws on every non-2xx, and PowerShell writes a terminating
        error to the TRANSCRIPT even when it is caught. My first re-pointing of those tests asserted
        the code SHAPE (`catch { $probeErr = $_ }`) rather than the observable PROPERTY -- so it passed
        while the property was broken. That is the same mistake the file warns about, made while
        fixing it.

        🔑 AND THE PROBE'S EXPECTED ANSWER IS A FAILURE. `Test-AdvancedHuntingHasTable` asks whether a
        custom LA table is mirrored into XDR; normally it is not, and that arrives as a 400 -- once per
        SI_*_Profile_CL table, every run. A routing decision that worked perfectly was being logged as
        an error.
    #>

    It 'the transport returns HTTP status as DATA and does not throw on it' {
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match 'function Invoke-SIGraphHttp'
        $src | Should -Match 'System\.Net\.Http\.HttpClient'
        # HttpClient returns 4xx/5xx as a response; Invoke-RestMethod raises. The hunting path must
        # not use the raising one.
        # 🪤 STRIP COMMENTS FIRST. This function's docstring quotes `Invoke-RestMethod's own message
        # is "(502) Bad Gateway"` -- naming the thing it replaced, which is the record worth keeping.
        # Matching raw text reported that prose as a live call. Third time this trap has landed today.
        $fn   = ($src -split 'function Invoke-SIHuntingQueryRest')[1]
        $fn   = [regex]::Replace($fn, '(?s)<#.*?#>', '')
        $code = ($fn -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'Invoke-RestMethod'
    }

    It '-AsResult returns a failure as an OBJECT rather than throwing' {
        # Behavioural, not textual: an unreachable host exercises the transport-failure path without
        # any network dependency on Graph.
        $r = Invoke-SIHuntingQueryRest -Query 'X | take 1' -Token 'not-a-real-token' `
                -ApiVersion 'v1.0' -TimeoutSec 5 -AsResult 3>$null 2>$null
        $r.Ok    | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }

    It 'the success and failure shapes both carry Ok, so a caller tests ONE property' {
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match 'Results = \$rows\.ToArray\(\); Ok = \$true'
    }

    It '🔒 the PROBE uses -AsResult and does not wrap a throwing call' {
        $laq = Get-Content (Join-Path $script:SIRootDir 'engine/risk-analysis/_shared/RA-LogAnalyticsQuery.ps1') -Raw
        $probe = ($laq -split 'function Test-AdvancedHuntingHasTable')[1]
        $probe | Should -Match 'Invoke-SIHuntingQueryRest[^\r\n]*-AsResult|-AsResult'
        $probe | Should -Match '\$probe\.Ok'
        # the previous attempt: a try/catch around a throwing call. It still logged.
        $probe | Should -Not -Match 'catch\s*\{\s*\$probeErr\s*=\s*\$_\s*\}'
    }

    It '🔴 the QUERY path still throws -- RA bucket escalation is built around catching it' {
        # Asymmetry on purpose: the probe expects failure, the query does not.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $fn  = ($src -split 'function Invoke-SIHuntingQueryRest')[1]
        $fn  | Should -Match 'throw \$errText'
        $hunt = Get-Content (Join-Path $script:SIRootDir 'engine/risk-analysis/_shared/RA-GraphHunting.ps1') -Raw
        $hunt | Should -Not -Match 'Invoke-SIHuntingQueryRest[^\r\n]*-AsResult'
    }
}

Describe 'transient classification -- retry the platform, never the query' {
    <#
        CLAUDE.md working rule 4: a platform failure retried costs seconds; a query defect retried
        burns a whole run and fails identically. #99 and #106 are both that rule got wrong.
    #>

    It 'treats throttle and gateway failures as transient' -ForEach @(
        @{ Status = 429 }, @{ Status = 502 }, @{ Status = 503 }, @{ Status = 504 }, @{ Status = 0 }
    ) {
        Test-SIGraphRestTransient -Status $Status | Should -BeTrue
    }

    It 'treats auth, not-found and bad-request as PERMANENT' -ForEach @(
        @{ Status = 400 }, @{ Status = 401 }, @{ Status = 403 }, @{ Status = 404 }, @{ Status = 413 }
    ) {
        Test-SIGraphRestTransient -Status $Status | Should -BeFalse
    }

    It '🔒 408 and 409 are permanent on purpose' {
        # A request timeout and a conflict both mean "repeating this unchanged will not help".
        Test-SIGraphRestTransient -Status 408 | Should -BeFalse
        Test-SIGraphRestTransient -Status 409 | Should -BeFalse
    }

    It 'reads a status of 0 when there is no response at all' {
        # A network reset carries no status; 0 must fall to the transient side so a reset retries.
        $er = New-Object System.Management.Automation.ErrorRecord(
                (New-Object System.Exception 'boom'), 'x', 'NotSpecified', $null)
        Get-SIGraphRestStatus -ErrorRecord $er | Should -Be 0
    }
}

Describe '🔴 the hunting adapter preserves the two signals AutoBucket depends on' {

    It 'a client timeout is re-thrown as TaskCanceledException text' {
        # The type cannot survive the transport change, so the TEXT carries it -- and the text is what
        # Test-IsBucketOverflowError and RA-GraphHunting's own classifier match on.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match 'TaskCanceledException: the request was canceled due to the configured timeout'
    }

    It 'the timeout detector covers BOTH editions, not just the one it was written on' {
        # PS 5.1 raises WebException+Timeout; PS 7 raises TaskCanceledException. Matching only one
        # leaves the ramp dead on the other, and PS 5.1 is the shell customers run.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match '\[System\.Threading\.Tasks\.TaskCanceledException\]'
        $src | Should -Match 'WebExceptionStatus\]::Timeout'
    }

    It '🪤 composes the status line itself, because "(502) Bad Gateway" does NOT match' {
        # Proof that the naive form fails, so the explicit composition cannot be "simplified" away.
        '(502) Bad Gateway'      | Should -Not -Match '502 Bad Gateway'
        ('{0} {1}' -f 502, 'Bad Gateway') | Should -Match '502 Bad Gateway'
    }

    It 'does NOT retry -- the bucket loop owns retry for hunting' {
        # RA records why: retrying an identical over-large query burns 4 more attempts of up to 900s.
        # A second retry policy underneath the escalation loop multiplies every failure.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $fn = ($src -split 'function Invoke-SIHuntingQueryRest')[1]
        $fn | Should -Not -Match 'MaxAttempts'
        $fn | Should -Not -Match 'Start-Sleep'
    }

    It 'keeps the 900s ceiling, which is load-bearing rather than cosmetic' {
        # It decides WHEN escalation triggers, not merely how long a call waits.
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match '\$TimeoutSec\s*=\s*900'
    }

    It 'targets the same endpoint the SDK wrapped, on the same API version' {
        $src = Get-Content (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1') -Raw
        $src | Should -Match 'security/runHuntingQuery'
        # The cmdlet was Start-MgBETASecurityHuntingQuery; changing to v1.0 here would be a silent
        # behaviour change, not a cleanup.
        $src | Should -Match "ApiVersion\s*=\s*'beta'"
    }
}

Describe 'the migrated engines no longer call the SDK' {

    It 'the classifier and Risk Analysis contain no live -Mg* calls' {
        foreach ($f in @(
            'engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1'
            'engine/risk-analysis/_shared/RA-GraphAuth.ps1'
            'engine/risk-analysis/_shared/RA-GraphHunting.ps1'
            'engine/risk-analysis/_shared/RA-LogAnalyticsQuery.ps1'
        )) {
            $raw  = Get-Content (Join-Path $script:SIRootDir $f) -Raw
            # 🪤 BLOCK comments have to go too, not just `#` lines. These files document the SDK
            # cmdlets they REPLACED inside <# .. #> help blocks -- which is exactly the record worth
            # keeping -- and a line-only stripper reported the docstring as a live call on the first
            # run of this test.
            $code = [regex]::Replace($raw, '(?s)<#.*?#>', '')
            $code = ($code -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            # Disconnect-MgGraph survives in ONE place by design: it tears down the platform
            # framework's own session on the VM-only MSAL-cache retry, and is already catch-guarded.
            $code = $code -replace 'Disconnect-MgGraph', ''
            $code | Should -Not -Match '\b(Connect|Get|New|Update|Remove|Start|Set)-Mg[A-Za-z]' -Because "$f should reach Graph over REST now"
        }
    }

    It '🔴 no engine loads a module at all any more -- the Graph SDK included (#305)' {
        # The engines' module installer (_shared/Ensure-Module.ps1) is gone: SecurityInsight runs with no
        # PowerShell modules, Graph included.
        foreach ($e in 'privilege-tier-classifier', 'risk-analysis', 'asset-tagging') {
            Test-Path -LiteralPath (Join-Path $script:SIRootDir "engine/$e/_shared/Ensure-Module.ps1") | Should -BeFalse -Because $e
        }

        foreach ($f in @(
            'engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1'
            'engine/risk-analysis/Invoke-RiskAnalysis.ps1'
            'engine/asset-tagging/AssetTagging.ps1'
            'engine/asset-tagging/AssetTaggingMaintenance.sample.ps1'
        )) {
            (Get-Content (Join-Path $script:SIRootDir $f) -Raw) | Should -Not -Match 'Ensure-SecurityInsightModules|Ensure-Module\.ps1'
        }
    }

    It '🔒 the community-VM launchers no longer touch the Graph SDK' {
        # They probed for Microsoft.Graph.Authentication with -AutoInstall and opened a session in each
        # of three auth branches, purely so the ENGINE would inherit it. No engine reads an ambient
        # session any more -- verified: zero live Get-MgContext anywhere under engine/. So the probe
        # was installing the SDK on community VMs to satisfy a dependency that no longer exists.
        foreach ($f in (Get-ChildItem (Join-Path $script:SIRootDir 'launcher') -Recurse -Filter 'launcher.community-vm.ps1')) {
            $code = [regex]::Replace((Get-Content $f.FullName -Raw), '(?s)<#.*?#>', '')
            $code = ($code -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match 'Microsoft\.Graph' -Because "$($f.Directory.Name) should not pull the Graph SDK"
            $code | Should -Not -Match '\-Mg[A-Za-z]'
        }
    }

    It '🔴 nothing in engine/ depends on an AMBIENT Graph session' {
        # This is the property that made removing the launcher connects safe. If an engine ever starts
        # reading Get-MgContext again, it would be silently relying on a session no launcher opens.
        foreach ($f in (Get-ChildItem (Join-Path $script:SIRootDir 'engine') -Recurse -Filter '*.ps1')) {
            $code = [regex]::Replace((Get-Content $f.FullName -Raw), '(?s)<#.*?#>', '')
            $code = ($code -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match '\bGet-MgContext\b' -Because "$($f.Name) would be reading a session nothing establishes"
        }
    }


    It 'the SPN global-name bridge uses the name the token helper actually reads' {
        # 🪤 It is SI_SPN_CertThumbprint, not SI_SPN_CertificateThumbprint. The first draft used the
        # longer form -- which is what RA calls it -- and Get-SIGraphToken would have found nothing,
        # fallen through to its HighPriv fallback, and produced a 403 on a cert-only install.
        $tok = Get-Content (Join-Path $script:SIRootDir 'auth/Get-SIGraphToken.ps1') -Raw
        $tok | Should -Match '\$global:SI_SPN_CertThumbprint'
        $auth = Get-Content (Join-Path $script:SIRootDir 'engine/risk-analysis/_shared/RA-GraphAuth.ps1') -Raw
        $auth | Should -Match '\$global:SI_SPN_CertThumbprint\s*='
        $auth | Should -Not -Match '\$global:SI_SPN_CertificateThumbprint\s*='
    }
}
