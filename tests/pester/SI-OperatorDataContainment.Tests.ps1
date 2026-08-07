#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #34: the guard that replaces phase 2.

.DESCRIPTION
    #34 phase 2 (migrating this environment's operator rules onto an overlay root) was
    SKIPPED by operator decision 2026-08-07: phase 1's mechanism ships and is opt-in, no
    customer is affected either way, and moving the dev fixtures buys hygiene at the cost
    of a new way to lose rules silently.

    That decision is sound only while two things stay true, and they are exactly what this
    file asserts -- because with phase 2 skipped, they are the WHOLE defence:

      1. We ship NO `*.custom.yaml`. That suffix is the operator's namespace. A tracked file
         carrying it would land in the update payload and overwrite a customer's rule of the
         same name -- the collision #34 consequence 2 describes. `PreservePatterns` does not
         protect that folder (still the old v1 layout), so nothing else would stop it.

      2. The `.gitignore` rule covering operator rules still resolves. If that glob is
         edited or broken, operator data becomes committable and reaches the PUBLIC mirror
         -- the #21 exposure shape, and #34 consequence 3.

    Naming discipline is not hypothetical here: audit #30 shipped
    `ADDomainController.custom.sample - Copy.yaml`, which loaded as a live rule and BEAT the
    shipped `.locked` rule on every host without its own override. A blacklist has to
    predict every wrong name; these assertions do not.

    🔒 If #34 phase 2 is ever revisited, this file stays -- it asserts containment, which is
    still wanted once rules live in an overlay.
#>

BeforeAll {
    $script:si   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:repo = Split-Path -Parent (Split-Path -Parent $script:si)
    $script:rel  = 'SOLUTIONS/SecurityInsight'

    function Invoke-Git {
        param([string[]]$GitArgs)
        Push-Location $script:repo
        try { & git @GitArgs 2>$null } finally { Pop-Location }
    }
}

# ============================================================================
Describe 'audit #34 -- operator rules never enter the shipped payload' {
# ============================================================================

    It 'no *.custom.yaml is TRACKED anywhere under the solution' {
        # The one that would actually overwrite a customer's rule on update.
        $tracked = @(Invoke-Git @('ls-files', $script:rel) | Where-Object { $_ -like '*.custom.yaml' })
        if ($tracked.Count) {
            throw ("These files carry the OPERATOR suffix and are tracked, so they ship and can " +
                   "overwrite a customer rule of the same name: " + ($tracked -join ', '))
        }
        $tracked.Count | Should -Be 0
    }

    It 'the .gitignore rule for operator rules still resolves' {
        # Asserted by asking git, not by reading .gitignore -- a rule can be present and be
        # overridden by a later negation, and only `check-ignore` knows the answer.
        $probe = "$($script:rel)/asset-profiling-enrichment/azure/__containment_probe__.custom.yaml"
        $out = Invoke-Git @('check-ignore', '-v', $probe)
        if (-not $out) {
            throw ("A *.custom.yaml under asset-profiling-enrichment/ is NOT ignored by git. " +
                   "Operator rules are now committable, and SI publishes its tree wholesale -- " +
                   "this is the #21 exposure shape. Restore the .gitignore rule.")
        }
        "$out" | Should -Match 'custom\.yaml'
    }

    It 'the sample files we DO ship keep the .custom.sample.yaml suffix, never .custom.yaml' {
        # Audit #30: 'ADDomainController.custom.sample - Copy.yaml' slipped through naming
        # discipline and loaded as a live rule. Anything tracked in the rule tree must be
        # .locked.yaml or .custom.sample.yaml -- nothing else.
        $tracked = @(Invoke-Git @('ls-files', "$($script:rel)/asset-profiling-enrichment") |
                     Where-Object { $_ -like '*.yaml' })
        $tracked.Count | Should -BeGreaterThan 0      # guard against a vacuous pass
        $bad = @($tracked | Where-Object { $_ -notlike '*.locked.yaml' -and $_ -notlike '*.custom.sample.yaml' })
        if ($bad.Count) {
            throw ("Tracked rule files must be *.locked.yaml or *.custom.sample.yaml. These are neither, " +
                   "and #30 proved such a file can load as a live rule: " + ($bad -join ', '))
        }
        $bad.Count | Should -Be 0
    }
}

# ============================================================================
Describe 'audit #34 -- the overlay mechanism stays available even though phase 2 was skipped' {
# ============================================================================

    It 'the loader still accepts an overlay root' {
        # Phase 2 being skipped must not mean phase 1 quietly rots. If this disappears, the
        # documented escape hatch for a customer who wants their rules out of our tree is gone.
        $loader = Join-Path $script:si 'engine\asset-profiling\shared\Get-SIRuleSet.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($loader, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIRuleSet'
        }, $true)
        $params = $fn[0].Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
        $params | Should -Contain 'EnrichmentDataRoot'
        (Get-Content -LiteralPath $loader -Raw) | Should -Match 'SI_EnrichmentDataRoot'
    }
}
