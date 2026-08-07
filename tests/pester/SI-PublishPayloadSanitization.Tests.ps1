#Requires -Version 5.1
<#
.SYNOPSIS
    SI-OWNED publish-payload sanitization gate (audit findings #1a, #20, #21).

.DESCRIPTION
    Scans the files SecurityInsight would push to its PUBLIC mirror
    (KnudsenMorten/SecurityInsight) for real org identifiers and hardcoded
    secrets, and asserts that internal-only docs are not in the payload.

    SCOPE: SecurityInsight ONLY. This deliberately does not touch
    TOOLS/Test-PublicDocSanitization.ps1 or .github/workflows/publish.yml --
    both are shared by every solution in SOLUTIONS/, and each solution is an
    individual project with its own requirements and tests (operator directive
    2026-08-05). An SI finding must not change another solution's publish
    behaviour. The shared 4-public-doc gate still runs for everyone, unchanged;
    this file is SI's own, deeper check.

    Picked up automatically by tests/pester/Invoke-PrePublishGate.ps1 (globs
    *.Tests.ps1) and therefore by .github/workflows/si-preview-prepublish.yml,
    which triggers only on SOLUTIONS/SecurityInsight/** paths.

    WHY THIS EXISTS (#1a): the shared gate scans exactly four markdown files, so
    a secret inlined in a shipped .ps1 is structurally invisible to it. That is
    how a live Shodan API key reached the public mirror and sat there ~3 months.

    TIERS -- calibrated so nothing SI ships today starts failing (SI has ~30
    customers in production):
      * The four public docs (README, RELEASENOTES, docs/FEATURES, docs/DESIGN)
        FAIL on any hit. Same contract as the shared gate.
      * The rest of the payload is measured against a KNOWN BASELINE (#21). The
        23 pre-existing values do not fail; anything NEW does. That is strictly
        better than report-only -- a newly inlined secret is caught immediately
        -- while still blocking nothing that exists today.
      * Internal-only docs must not be in the payload at all.

    TRACKED FILES ONLY: CI checks out the repo, so an untracked/gitignored
    working-tree file can never reach the mirror. Scanning the raw filesystem
    produced findings CI could not reproduce (config/SecurityInsight.custom.ps1
    and launcher/*/LauncherConfig.custom.ps1 are all correctly gitignored).

    NOT COVERED HERE -- #20 is only DETECTED, not PREVENTED. Stripping nested
    internal docs from the staged payload requires a change to the shared
    .github/workflows/publish.yml, which is out of scope for an SI-only test.
    The "internal docs must not ship" block below FAILS if they are present, so
    the condition cannot regress silently while that decision is pending.
#>

BeforeDiscovery {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> SecurityInsight
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    # --- what publish.yml actually stages (flat layout) ---------------------
    # Top-level names the staging step drops. Kept in sync with publish.yml by
    # the "publish exclusions" test below, which fails if the workflow changes.
    $script:ExcludeTopNames = @('logs', 'OUTPUT', 'staging', 'internal', 'demo', 'solution.publish.json', 'CLAUDE.md')
    $script:InternalDocNames = @('REQUIREMENTS.md', 'TESTS.md', 'CLAUDE.md')
    $script:PublicDocs = @('README.md', 'RELEASENOTES.md', 'docs\FEATURES.md', 'docs\DESIGN.md')

    $script:TextExt = @(
        '.md', '.txt', '.ps1', '.psm1', '.psd1', '.json', '.jsonc', '.yaml', '.yml',
        '.cs', '.cshtml', '.razor', '.csproj', '.sln', '.props', '.targets',
        '.js', '.ts', '.css', '.html', '.htm', '.xml', '.config', '.bicep', '.tf',
        '.sh', '.bat', '.cmd', '.sql', '.ini', '.toml'
    )

    # --- the real-org-identifier denylist lives in internal/, NOT here ----------
    # 🔴 `tests/` IS PART OF THE PUBLISHED PAYLOAD. Holding the inventory of real
    # customer names, tenant/subscription ids and Key Vault names inline in this
    # file published all of it to the public mirror -- the detector leaking exactly
    # what it protects. It loads from `internal/` instead, which every publish
    # strips. The self-exclusion below meant the gate stayed GREEN while doing it:
    # a scanner that skips itself cannot see its own leak.
    #
    # Known-leaked values (#1 Shodan, #2 SPN secret) are deliberately NOT listed as
    # literal prefixes anywhere: naming a prefix publishes it, and #2's secret is
    # currently confined to the PRIVATE repo history. Both are caught without a
    # literal -- Shodan by the generic secret-literal heuristic, the SPN secret by
    # the 'AAD client secret' wire-format rule (verified: detection unchanged).
    # NOTE the casing: git tracks this folder as INTERNAL/ (uppercase). Windows'
    # case-insensitive filesystem hides that, so writing to 'internal/' silently
    # creates a SECOND path in the index -- which becomes two real directories on
    # the Linux publish runner. Both spellings are stripped from the publish
    # ($excludeNames uses case-insensitive -notin, and the recursive strip
    # lowercases), but the file must live at the tracked casing.
    $script:DenylistPath = Join-Path $script:SIRoot 'INTERNAL/SI-PublishDenylist.ps1'
    $script:HasDenylist = Test-Path -LiteralPath $script:DenylistPath
    $script:Deny = @()
    $script:Allow = @()
    if ($script:HasDenylist) {
        $dl = & $script:DenylistPath
        $script:Deny = @($dl.Deny)
        $script:Allow = @($dl.Allow)
    }

    # Secret-SHAPE rules stay HERE: they name no real value, so they are safe to
    # publish, and they must keep working even when internal/ is absent (e.g. the
    # suite run from a published mirror).
    $script:Deny += @(
        @{ name = 'private key block'; rx = '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
        @{ name = 'github PAT'; rx = '(?i)\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})' }
        @{ name = 'storage account key'; rx = '\b[A-Za-z0-9+/]{86}==' }
        @{ name = 'JWT / bearer token'; rx = '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.' }
        # A tilde token is only a secret if it also has mixed case AND a digit --
        # without the lookaheads this matches Intune ADMX policy paths.
        @{ name = 'AAD client secret'; rx = '\b(?=[A-Za-z0-9._~-]*[A-Z])(?=[A-Za-z0-9._~-]*[a-z])(?=[A-Za-z0-9._~-]*[0-9])[A-Za-z0-9._-]{3,8}~[A-Za-z0-9._~-]{28,}\b' }
    )
    $script:Allow += @('privatelink.database.windows.net', 'server.database.windows.net', '<server>.database.windows.net')

    $script:SecretAssignRx = '(?i)(shodan|api[_-]?key|apikey|client[_-]?secret|clientsecret|secret|password|passwd|\bpwd\b|token|sas|connection[_-]?string|account[_-]?key)[a-z0-9_.\[\]'']*\s*[:=]\s*[''"]([^''"$<>{}\s]{16,})[''"]'

    # A VALUE is a secret only if it is a SOLID token with mixed case AND digits.
    # Calibrated against real false positives: 'sasPolicyExpirationPeriod',
    # 'Mail_SmtpPassword', 'dcr-si-publicip-profile', '__BUCKET_FILTER__' are all
    # identifiers; 'tyScfnKkuf4hz87DaHwnhzXST3wKExfg' is not.
    function Test-SILooksLikeSecret {
        param([string]$Value)
        if ($Value.Length -lt 20) { return $false }
        if ($Value -notmatch '^[A-Za-z0-9+/=]+$') { return $false }
        if ($Value -cnotmatch '[a-z]') { return $false }
        if ($Value -cnotmatch '[A-Z]') { return $false }
        if ($Value -notmatch '[0-9]') { return $false }
        if ($Value -match '(?i)(your|example|sample|placeholder|changeme|redacted|dummy|abcdef|xxxx)') { return $false }
        return $true
    }

    # --- build the payload file list (TRACKED only) --------------------------
    Push-Location $script:SIRoot
    $trackedRaw = @(& git ls-files) | Where-Object { $_ }
    Pop-Location

    # publish.yml ALSO strips these two literal paths today, so they never reach
    # the mirror and must not be scanned. docs/REQUIREMENTS.md in particular
    # QUOTES the leaked values while documenting them (#21) -- scanning it makes
    # the audit doc flag itself, which is noise, not a finding.
    $script:StrippedToday = @('docs\REQUIREMENTS.md', 'docs\TESTS.md')

    # This scanner DEFINES the denylist, so its own source necessarily contains
    # every pattern it looks for. Scanning itself produced 10 guaranteed
    # false positives the moment the file became tracked. Exclude it by name.
    # Trade-off, stated plainly: a real secret pasted into THIS file would not be
    # caught by THIS test. That is the price of a self-hosted denylist.
    $script:SelfName = Split-Path -Leaf $PSCommandPath

    $script:PayloadFiles = @()
    foreach ($rel in $trackedRaw) {
        $parts = $rel -split '/'
        if ($script:ExcludeTopNames -contains $parts[0]) { continue }
        $leaf = $parts[-1]
        if ([IO.Path]::GetExtension($leaf) -notin $script:TextExt) { continue }
        if ($leaf -match '\.internal-(vm|azure)\.') { continue }   # publish.yml strips these
        if ($leaf -eq $script:SelfName) { continue }               # self-reference
        $win = $rel -replace '/', '\'
        if ($script:StrippedToday -contains $win) { continue }
        $script:PayloadFiles += $win
    }

    # --- scan -----------------------------------------------------------------
    $script:Findings = @()
    foreach ($rel in $script:PayloadFiles) {
        $full = Join-Path $script:SIRoot $rel
        if (-not (Test-Path -LiteralPath $full)) { continue }
        $lineNo = 0
        foreach ($line in (Get-Content -LiteralPath $full -ErrorAction SilentlyContinue)) {
            $lineNo++
            foreach ($d in $script:Deny) {
                if ($line -match $d.rx) {
                    $hit = $Matches[0]
                    if ($script:Allow -contains $hit.ToLowerInvariant()) { continue }
                    $script:Findings += [pscustomobject]@{ File = $rel; Line = $lineNo; Kind = $d.name; Match = $hit }
                }
            }
            if ($line -match $script:SecretAssignRx) {
                $val = $Matches[2]
                if (Test-SILooksLikeSecret -Value $val) {
                    $script:Findings += [pscustomobject]@{
                        File = $rel; Line = $lineNo; Kind = 'hardcoded secret literal'
                        Match = $val.Substring(0, 6) + "...($($val.Length) chars)"
                    }
                }
            }
        }
    }

    $script:DocFindings = @($script:Findings | Where-Object { $script:PublicDocs -contains $_.File })
    $script:CodeFindings = @($script:Findings | Where-Object { $script:PublicDocs -notcontains $_.File })

    # --- BASELINE (#21) -------------------------------------------------------
    # The 23 real values already in tracked files as of 2026-08-05, awaiting
    # operator triage. Keyed by file+kind (NOT line number -- an unrelated edit
    # above a hit would otherwise turn into a false failure). These do not fail
    # the gate; anything NOT on this list does. SHRINK this list as values are
    # cleaned; when it is empty, delete it and the gate becomes fully blocking.
    $script:Baseline21 = @(
        'Bootstrap-Auth.ps1|customer/company name'
        'Bootstrap-Storage.ps1|customer/company name'
        # (Setup-SecurityInsight-Unattended.ps1 held the Shodan literal until 2026-08-05.
        #  Operator directive "no secrets in public files": the key is now resolved at run
        #  time from $global:SI_Shodan_ApiKey / $env:SHODAN_API_KEY. Both its entries are
        #  gone from this baseline -- if either ever reappears, the gate FAILS, which is
        #  the point.)
        # (analyzer-web\CLAUDE.md was here until 2026-08-05, when the SIA doc set was
        # merged into docs/ and deleted -- the file no longer exists, so its entry is gone.)
        # --- #21 TRIAGE, 2026-08-06 (operator-approved) -------------------------------------
        # Resource-group names in the deploy script's own .SYNOPSIS/.EXAMPLE. ACCEPTED: naming
        # them IS the guidance -- "deploy to rg-securityinsight, NEVER PIM's rg-pim-manager-web"
        # is the #3b control written down. No credential, no tenant identifier.
        'analyzer-web\deploy\Deploy-SIAnalyzer.ps1|internal host/RG'
        #
        # 🔒 THE BASELINE IS OTHERWISE EMPTY -- THIS GATE IS NOW FULLY BLOCKING.
        #
        # Everything else that was here on 2026-08-05 is gone, and each for a reason, not by
        # being waved through:
        #   * The real TENANT GUID in privilege-tier-catalog.locked.json -- shipped inside a
        #     locked default, in a Metadata provenance block (GeneratedAt / GeneratedBy /
        #     AICallsUsed). Verified nothing reads it, then redacted.
        #   * Real tenant + subscription GUIDs in New-SISpn.ps1's .EXAMPLE, and a real Key
        #     Vault name in Get-SIKvSecret.ps1's .DESCRIPTION -- now placeholders.
        #   * README-DEPLOY.md and analyzer-web/docs/DESIGN.md -- the FILES no longer exist
        #     (#20 consolidation). A baseline naming deleted files is not harmless: it would
        #     have swallowed a genuine reappearance at those paths.
        #   * The Shodan literal (#1) and analyzer-web/CLAUDE.md (#20), removed 2026-08-05.
        #   * All 13 'customer/company name' hits -- 🔒 OPERATOR DECISION 2026-08-06, "i accept
        #     to keep my name". 2LINKIT authoring its own MIT-licensed project is authorship,
        #     not a leak. Encoded as an Allow entry in INTERNAL/SI-PublishDenylist.ps1 rather
        #     than as baseline exceptions, so the 'customer/company name' rule KEEPS CATCHING
        #     every OTHER organisation's name. Do not re-propose stripping it.
        #
        # Consequence, and the point of all of it: ANY new real org value in the published
        # payload now FAILS this gate. Do not add entries here to make a build pass -- fix the
        # value, or bring the exception to the operator.
    )
    $script:NewCodeFindings = @($script:CodeFindings | Where-Object { $script:Baseline21 -notcontains ("$($_.File)|$($_.Kind)") })

    # Internal-only docs that would reach the public payload (#20). $PayloadFiles
    # already excludes what publish.yml strips today, so whatever is left is a
    # genuine leak.
    $script:InternalDocsInPayload = @(
        $script:PayloadFiles | Where-Object { $script:InternalDocNames -contains (Split-Path -Leaf $_) }
    )

    # Pester v5: variables set in BeforeDiscovery are NOT in scope inside It
    # bodies at run time -- they silently read as empty, which made both
    # informational checks report "nothing found" while findings existed. Only
    # -ForEach data crosses the discovery/run boundary reliably, so the
    # informational blocks below take their data that way.
    $script:BaselineStillPresent = @($script:CodeFindings | Where-Object { $script:Baseline21 -contains ("$($_.File)|$($_.Kind)") })
    $script:Summary = @([pscustomobject]@{
            PayloadCount      = $script:PayloadFiles.Count
            BaselineHits      = $script:BaselineStillPresent.Count
            BaselineFiles     = @($script:BaselineStillPresent | Select-Object -ExpandProperty File -Unique).Count
            InternalDocs      = $script:InternalDocsInPayload
            HasDenylist       = $script:HasDenylist
            DenyRuleCount     = $script:Deny.Count
        })
}

Describe 'SI publish payload -- public docs carry no real org values' {

    It 'has no denied value in <_.File> (line <_.Line>, <_.Kind>)' -ForEach $script:DocFindings {
        # Same contract as the shared gate: the four public docs must be clean.
        $false | Should -BeTrue -Because "$($_.File):$($_.Line) exposes [$($_.Kind)] '$($_.Match)' on the public mirror"
    }

    It 'scanned a non-empty payload (control -- a green run must not mean "scanned nothing")' -ForEach $script:Summary {
        $_.PayloadCount | Should -BeGreaterThan 500
    }

    It 'loaded the internal denylist (control -- a green run must not mean "no rules")' -ForEach $script:Summary {
        # Without this, deleting or mislocating internal/SI-PublishDenylist.ps1 would
        # silently drop EVERY org-identifier rule and the gate would still pass --
        # the same class of failure as a scanner that excludes itself.
        $_.HasDenylist   | Should -BeTrue -Because 'internal/SI-PublishDenylist.ps1 must be present in the private repo'
        $_.DenyRuleCount | Should -BeGreaterThan 15 -Because 'the org-identifier rules must be loaded, not just the secret-shape ones'
    }
}

Describe 'SI publish payload -- no NEW real org values in shipped code (#1a/#21)' {

    It 'introduces no value outside the #21 baseline: <_.File>:<_.Line> [<_.Kind>]' -ForEach $script:NewCodeFindings {
        $false | Should -BeTrue -Because @"
$($_.File):$($_.Line) ships [$($_.Kind)] '$($_.Match)' to the PUBLIC mirror and is NOT in the #21 baseline.
Either remove the value, or -- if it is intentional -- add "$($_.File)|$($_.Kind)" to `$script:Baseline21 in this file with a note in docs/REQUIREMENTS.md #21.
"@
    }

    It 'reports the #21 baseline that is still outstanding (informational, does not fail)' -ForEach $script:Summary {
        Write-Host ""
        Write-Host "  #21 baseline still present in the public payload: $($_.BaselineHits) hit(s) across $($_.BaselineFiles) file(s)." -ForegroundColor Yellow
        Write-Host "  These are KNOWN and do not block. Triage them in docs/REQUIREMENTS.md #21, then shrink `$script:Baseline21." -ForegroundColor Yellow
        $_.BaselineHits | Should -BeGreaterThan 0 -Because 'if this reaches 0 the baseline is stale -- shrink $script:Baseline21 and make the gate blocking'
    }
}

Describe 'SI publish payload -- internal-only docs would ship (#20, informational)' {

    # INFORMATIONAL, NOT BLOCKING -- on purpose.
    # #20 cannot be FIXED from inside SI: the strip lives in the SHARED
    # .github/workflows/publish.yml, and changing shared pipeline behaviour as
    # part of SI work is exactly what this test file exists to avoid. Until that
    # change is separately approved, failing here would only turn SI's own gate
    # red over something SI cannot fix -- so it reports loudly and passes.
    # WHEN publish.yml's strip becomes recursive: flip this to a failing
    # assertion (the -ForEach list should then be empty) and delete this note.
    It 'reports internal-only docs the public publish would still stage' -ForEach $script:Summary {
        if ($_.InternalDocs.Count -eq 0) {
            Write-Host "  #20: no internal-only docs in the public payload." -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "  #20 -- these internal-only docs WOULD be pushed to the PUBLIC mirror:" -ForegroundColor Yellow
            $_.InternalDocs | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
            Write-Host "  publish.yml strips only the two literal paths docs/REQUIREMENTS.md + docs/TESTS.md," -ForegroundColor Yellow
            Write-Host "  and its `$excludeNames matches TOP-LEVEL names, so nested copies slip through." -ForegroundColor Yellow
            Write-Host "  FIX REQUIRES the shared .github/workflows/publish.yml (recursive strip by name)." -ForegroundColor Yellow
        }
        $true | Should -BeTrue
    }
}
