#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- SI's deploy contract, and a REPORT on the framework gap behind it
    (audit #43 / #44, suite T8).

.DESCRIPTION
    Two jobs, and the split is deliberate.

    1. ASSERT SI's OWN CONTRACT. `solution.deploy.json` is what tells the AutomateIT sync how to
       deploy SecurityInsight at ~30 customers. It ships WITH the code, so a mistake in it reaches
       every customer on the next nightly sync with no review step. Nothing validated it.

       The case that matters most is the `needsSchema` <-> code agreement. `needsSchema: false` is
       what exempts SI from the platform's schema-migration machinery, and the contract's own
       comment says it was *verified* -- `analyzer-web/` has no `DbContext`, `Migrations`,
       `SqlConnection` or EF. That verification was a one-time human read. This suite makes it
       continuous, in BOTH directions: adding a database without flipping the flag is caught, and
       so is flipping the flag without adding one.

       That is not hypothetical. #44 designs a connector state database. The moment it lands in the
       wrong project, `needsSchema` becomes a lie and customers run new code against an old schema.

    2. REPORT THE FRAMEWORK GAP -- deliberately NOT fix it. `sync/` is framework-owned and shared;
       SI's working agreement (CLAUDE.md rule 8) forbids editing it to solve an SI problem and
       instead requires SI's own tests to assert or report the condition so it cannot regress into
       silence. The condition (#43): `needsSchema` is RESOLVED by `sync/_SyncDeploy.ps1` and
       CONSUMED BY NOTHING. Setting it true today does literally nothing -- which is worse than a
       loud failure, because the sync stays green while the schema goes stale.

    RUNS ON A CUSTOMER TREE. `sync/` does not exist there at all -- the customer receives
    `SOLUTIONS/SecurityInsight/`, not the repo. So part 1 always runs and part 2 self-skips when
    the framework tree is absent, rather than failing and teaching everyone to ignore a red line.
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> solution root (3 levels up)
    $_root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SiRoot       = $_root
    $script:ContractPath = Join-Path $_root 'solution.deploy.json'
    $script:AnalyzerSrc  = Join-Path $_root 'analyzer-web\src'

    $script:Contract = $null
    if (Test-Path $script:ContractPath) {
        $script:Contract = Get-Content -Raw -LiteralPath $script:ContractPath | ConvertFrom-Json
    }

    # The repo root is two levels above SOLUTIONS/<X>. Present in the monorepo, ABSENT on a
    # customer tree -- which is the normal case, not a failure.
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $_root)
    $script:SyncDir  = Join-Path $script:RepoRoot 'sync'
    $script:HasSync  = Test-Path (Join-Path $script:SyncDir '_SyncDeploy.ps1')

    # Does any SIA code actually carry a relational store? This is the ground truth that
    # `needsSchema` must agree with. Searched over the C# SOURCE only -- obj/bin are build
    # output and would produce false positives from restored package metadata.
    $script:DbEvidence = @()
    if (Test-Path $script:AnalyzerSrc) {
        $script:DbEvidence = @(
            Get-ChildItem -Path $script:AnalyzerSrc -Include '*.cs','*.csproj' -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' } |
                Where-Object {
                    $t = Get-Content -Raw -LiteralPath $_.FullName
                    $t -match 'DbContext|SqlConnection|EntityFrameworkCore|Microsoft\.Data\.SqlClient'
                } |
                ForEach-Object { $_.FullName.Substring($script:SiRoot.Length).TrimStart('\') }
        )
    }

    function Get-Capability {
        param([Parameter(Mandatory)][string]$Name)
        if (-not $script:Contract) { return $null }
        return @($script:Contract.capabilities | Where-Object { $_.name -eq $Name })[0]
    }
}

# ============================================================================
Describe 'SI ships a valid deploy contract' {
# ============================================================================

    It 'solution.deploy.json exists and parses' {
        Test-Path $script:ContractPath | Should -BeTrue
        $script:Contract | Should -Not -BeNullOrEmpty
    }

    It 'names itself SecurityInsight' {
        # The sync resolves the deploy script relative to SOLUTIONS/<solution>; a wrong name here
        # points it at another solution's tree.
        $script:Contract.solution | Should -Be 'SecurityInsight'
    }

    It 'declares the code capability as REQUIRED' {
        # A customer blocking a required capability is refused and reported, never obeyed --
        # which is what stops anyone bricking their own install. `code` IS SecurityInsight.
        $code = Get-Capability -Name 'code'
        $code | Should -Not -BeNullOrEmpty
        [bool]$code.optional | Should -BeFalse
    }

    It 'declares NO SIA capability -- both web-frontend and container are retired' {
        # Operator 2026-08-08, in two steps: "remove the web-frontend from being deployed" /
        # "it is NOT used anymore and will be replaced by new design", then "remove container also".
        # BOTH were SI Analyzer, not SecurityInsight: web-frontend rolled the SIA web UI, container
        # built and rolled the SIA image, both via the same deploy hook. SIA was never delivered --
        # its hosted live-verify gate never ran -- and its one internal environment is being
        # decommissioned.
        #
        # This is the guard, and it matters precisely because re-adding one would look HARMLESS in
        # testing: the current production sync engine never invokes a deploy hook at all, so nothing
        # would happen locally. The v3 distribution/orchestration split WILL act on declared
        # capabilities and would deploy a retired app on customers' behalf. Fail loudly instead.
        $declared = @($script:Contract.capabilities | ForEach-Object { $_.name })
        foreach ($dead in @('web-frontend','container')) {
            $declared | Should -Not -Contain $dead
        }
    }

    It 'is a SINGLE-capability solution -- code only, and code is REQUIRED' {
        $declared = @($script:Contract.capabilities | ForEach-Object { $_.name })
        $declared.Count | Should -Be 1
        $declared | Should -Contain 'code'
        [bool](Get-Capability -Name 'code').optional | Should -BeFalse
    }

    It 'declares NO deploy hook -- SI updates are a pure code roll' {
        # The deploy block pointed at analyzer-web/deploy/Deploy-SIAnalyzer.ps1, which existed only
        # to build/roll/health-gate SIA. With SIA retired there is nothing to run at deploy time:
        # the sync copies files and the engines pick them up on their next scheduled run.
        $script:Contract.PSObject.Properties.Name | Should -Not -Contain 'deploy'
    }

    It 'declares NO provisioning preconditions -- they were all SIA''s' {
        # ACR + Container Apps environment (container) and the Entra app registration
        # (web-frontend) existed solely for SIA. SecurityInsight itself needs no Azure resource
        # provisioned before an update.
        $names = @()
        if ($script:Contract.PSObject.Properties.Name -contains 'requires' -and $script:Contract.requires) {
            $names = @($script:Contract.requires.PSObject.Properties.Name)
        }
        $names | Should -BeNullOrEmpty
    }

    It 'nothing references a capability that does not exist' {
        # Invariant kept from the old appliesTo/requires cross-check: whatever blocks exist, every
        # capability they name must be declared. Holds vacuously today and starts biting the moment
        # a deploy or requires block comes back.
        $declared = @($script:Contract.capabilities | ForEach-Object { $_.name })
        $referenced = @()
        if ($script:Contract.PSObject.Properties.Name -contains 'requires' -and $script:Contract.requires) {
            $referenced += @($script:Contract.requires.PSObject.Properties.Name)
        }
        if ($script:Contract.PSObject.Properties.Name -contains 'deploy' -and $script:Contract.deploy) {
            $referenced += @($script:Contract.deploy.appliesTo)
        }
        $bad = @($referenced | Where-Object { $_ -and $declared -notcontains $_ })
        $bad -join ' || ' | Should -BeNullOrEmpty
    }
}

# ============================================================================
Describe 'needsSchema must agree with the code, in BOTH directions' {
# ============================================================================

    It 'declares needsSchema explicitly' {
        # Not merely absent-and-falsy: the flag decides whether migration machinery runs, so it
        # must be a stated decision that a reader can find.
        @($script:Contract.PSObject.Properties.Name) | Should -Contain 'needsSchema'
    }

    It 'needsSchema is FALSE while no SIA code carries a relational store' {
        # Direction 1 -- the dangerous one. #44 designs a connector state DATABASE. If it lands in
        # analyzer-web/ without this flag being flipped, the contract silently lies to the sync and
        # customers run new code against an old schema, with a green sync and no error (#43).
        if ($script:DbEvidence.Count -eq 0) {
            [bool]$script:Contract.needsSchema | Should -BeFalse `
                -Because 'no DbContext / SqlConnection / EF exists in analyzer-web/src'
        } else {
            [bool]$script:Contract.needsSchema | Should -BeTrue `
                -Because ("relational store found in: {0} -- flip needsSchema and RAISE the framework gap (#43: sync resolves needsSchema and consumes it nowhere)" -f ($script:DbEvidence -join ', '))
        }
    }

    It 'needsSchema is not TRUE without a relational store to migrate' {
        # Direction 2 -- the wasteful one. Claiming a schema that does not exist opts SI into
        # machinery it does not need and makes the flag meaningless as a signal.
        if ([bool]$script:Contract.needsSchema) {
            $script:DbEvidence.Count | Should -BeGreaterThan 0
        } else {
            $true | Should -BeTrue
        }
    }
}

# ============================================================================
Describe 'FRAMEWORK GAP REPORT -- sync/ is not ours to fix (CLAUDE.md rule 8)' {
# ============================================================================

    It 'reports that needsSchema still has no consumer in the sync engine' {
        # Runtime skip, NOT `-Skip:(-not $script:HasSync)`. Pester 5 evaluates an It's -Skip:
        # parameter during DISCOVERY, while BeforeAll runs during the RUN phase -- so the variable
        # is still $null when -Skip: is read, `-not $null` is $true, and BOTH framework reports
        # skipped unconditionally, including here in the monorepo where sync/ plainly exists.
        # A report that never runs is worse than no report: it shows up green-adjacent in the gate
        # and asserts nothing. Same family as audit #37 (a lint printing PASS while holding a
        # violation) and #29 part 2 (a lint scanning folders that no longer existed).
        if (-not $script:HasSync) {
            Set-ItResult -Skipped -Because 'sync/ is absent -- this is a customer tree, where the framework repo does not exist'
            return
        }
        # #43, and this is a REPORT, not a fix: sync/ is framework-owned and shared, reaching ~30
        # customers from main with no review step, so SI must never edit it to solve an SI problem.
        # What SI can do is refuse to let the condition go quiet.
        #
        # The condition: _SyncDeploy.ps1 RESOLVES needsSchema into its effective config and then
        # nothing acts on it. Counting the hits distinguishes "resolved only" from "actually used".
        $hits = @(Select-String -Path (Join-Path $script:SyncDir '*.ps1') -Pattern 'needsSchema|NeedsSchema' -ErrorAction SilentlyContinue)
        $hits.Count | Should -BeGreaterThan 0 -Because 'the field should at least still be resolved'

        # A real consumer would branch on it or invoke something. Resolution assigns it.
        $consumers = @($hits | Where-Object {
            $l = $_.Line
            $l -notmatch '^\s*#' -and                        # comment
            $l -notmatch 'NeedsSchema\s*=' -and              # the assignment into the effective object
            $l -notmatch '\$needsSchema\s*=' -and            # the resolve itself
            $l -match 'if\s*\(|Invoke-|&\s|\bthrow\b'        # would indicate it is ACTED ON
        })

        $consumers.Count | Should -Be 0 -Because @'
when this FAILS, the framework has implemented schema migration -- which is the answer #44 phase 4
is blocked on. Re-read DOCS/REQUIREMENTS.md, then delete this case and unblock the connector DB.
Until then: setting needsSchema true does nothing, so SI must not ship a database.
'@
    }

    It 'reports that engine Container Apps Jobs are still not deployed by the sync path' {
        if (-not $script:HasSync) {
            Set-ItResult -Skipped -Because 'sync/ is absent -- this is a customer tree'
            return
        }
        # #43's other gap: Bootstrap-ContainerAppJob.ps1 creates the engine jobs, and NOTHING in
        # the deploy path invokes it, so a new connector engine would reach customers as files with
        # no job to run it. The fix is SI-side and is tracked in #44 build-order phase 3 -- this
        # case is what stops it being forgotten.
        #
        # 2026-08-08: the deploy block was REMOVED with the web-frontend capability, so there is no
        # deploy script to inspect and the gap is now total rather than partial. Guard the lookup --
        # before this check, `$script:Contract.deploy.script` was $null, Join-Path returned the SI
        # root, Get-Content threw "Could not find a part of the path", and the test still reported
        # PASS. A test that errors and passes proves nothing; that is exactly audit #49's lesson.
        $deployScript = $null
        if ($script:Contract.PSObject.Properties.Name -contains 'deploy' -and $script:Contract.deploy.script) {
            $deployScript = Join-Path $script:SiRoot ($script:Contract.deploy.script -replace '/','\')
        }
        if (-not $deployScript -or -not (Test-Path -LiteralPath $deployScript)) {
            Set-ItResult -Skipped -Because 'SI declares NO deploy hook since 2026-08-08 -- there is no deploy path that could invoke Bootstrap-ContainerAppJob.ps1, so the #43 gap stands unconditionally'
            return
        }
        $text = Get-Content -Raw -LiteralPath $deployScript
        ($text -match 'Bootstrap-ContainerAppJob') | Should -BeFalse -Because @'
when this FAILS, SI's deploy path has been wired to Bootstrap-ContainerAppJob.ps1 and engine jobs
now reach customers through the sync (#44 phase 3). Delete this case and record it in FEATURES.md.
'@
    }
}
