#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #34 phase 1: the operator data overlay.

.DESCRIPTION
    Operator rule data lives INSIDE the shipped code tree, interleaved with the files the sync
    overwrites:

        asset-profiling-enrichment/endpoint/
            ADDomainController.locked.yaml          <- ours, tracked, ships
            ADDomainController.custom.sample.yaml   <- ours, tracked, ships
            ADDomainController.custom.yaml          <- THEIRS, gitignored, must never ship

    A customer's rules survive an update only because they happen to be absent from the zip, not
    because anything protects them: `PreservePatterns` is still the OLD v1 layout and matches none
    of this. One tracked file with a colliding name would overwrite a customer's rule, and a
    .gitignore slip publishes their data to the public mirror.

    Phase 1 adds an external overlay root (`$global:SI_EnrichmentDataRoot`, same <engine>/ + shared/
    layout) that loads ALONGSIDE the shipped tree. The four decisions this encodes:

      1. PRECEDENCE  -- ranked: overlay *.custom.yaml (2) > in-tree *.custom.yaml (1) > *.locked (0).
      2. CUTOVER     -- both locations are READ. In-tree operator rules are warned about by name,
                        never silently ignored; silence here would be audit #29 a third time.
      3. SCOPE       -- asset-profiling-enrichment/ only. config/ is deliberately NOT in scope.
      4. PreservePatterns lives in sync/, which is FRAMEWORK-owned and shared by every solution.
                        Per SI's Rule 8 it is recorded and raised, never edited from here -- so this
                        suite ASSERTS the condition instead, and the last Describe is that assertion.

    Unset overlay MUST behave exactly as before: this is opt-in by construction, because the loader
    it changes runs on ~30 production customers.
#>

BeforeAll {
    $script:si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:loader = Join-Path $script:si 'engine\asset-profiling\shared\Get-SIRuleSet.ps1'
    if (-not (Test-Path $script:loader)) { throw "loader not found at $script:loader" }
    . $script:loader

    # The loader emits its run-summary through Write-SIInfo, which is supplied by the profiling
    # stage. Stub it to the HOST, never to the output stream -- returning a string here would be
    # captured into the rule set and silently corrupt every assertion below.
    function Write-SIInfo { param($m) Write-Host $m }

    # Build a throwaway solution tree + overlay so the assertions never depend on this
    # environment's real (gitignored) operator rules.
    function New-RuleFile {
        param([string]$Path, [string]$Id, [string]$Purpose, [int]$Detections = 1, [string]$Engine = 'azure')
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("id:        $Id")
        [void]$sb.AppendLine("appliesTo: $Engine")
        [void]$sb.AppendLine("mode:      append")
        [void]$sb.AppendLine("purpose:   '$Purpose'")
        [void]$sb.AppendLine("detections:")
        for ($i = 1; $i -le $Detections; $i++) {
            [void]$sb.AppendLine("  - id: Det$i")
            [void]$sb.AppendLine("    detect:")
            [void]$sb.AppendLine("      any:")
            [void]$sb.AppendLine("        - kind: hasAzureTagDirectOrParent")
            [void]$sb.AppendLine("          tag:   'cmdbId'")
            [void]$sb.AppendLine("          value: '$i'")
            [void]$sb.AppendLine("    set:")
            [void]$sb.AppendLine("      cmdbId: '$i'")
        }
        Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
    }

    # Pester 6 forbids a root-level AfterEach, so scratch roots are tracked and removed in one
    # root AfterAll instead of per test.
    $script:scratchRoots = New-Object System.Collections.Generic.List[string]

    function New-Scratch {
        if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("si34-" + [guid]::NewGuid().ToString('N').Substring(0,10))
        $tree    = Join-Path $root 'tree'
        $overlay = Join-Path $root 'overlay'
        New-Item -ItemType Directory -Force (Join-Path $tree 'asset-profiling-enrichment\azure') | Out-Null
        New-Item -ItemType Directory -Force (Join-Path $overlay 'azure') | Out-Null
        $script:scratchRoots.Add($root)
        [pscustomobject]@{ Root = $root; Tree = $tree; Overlay = $overlay }
    }

    function Get-Rule { param($Set, [string]$Id) $Set | Where-Object { $_.Id -eq $Id } }
}

AfterAll {
    foreach ($r in $script:scratchRoots) {
        if (Test-Path $r) { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }
    }
    if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }
}

# ============================================================================
Describe 'audit #34 -- with NO overlay configured, nothing changes' {
# ============================================================================

    It 'loads the shipped tree exactly as before, and tags every rule as tree-sourced' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleB.custom.yaml') -Id 'RuleB' -Purpose 'in-tree operator'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree 3>$null
        @($r).Count | Should -Be 2
        @($r | Where-Object { $_.Source -ne 'tree' }).Count | Should -Be 0
    }

    It 'still prefers an in-tree custom rule over its locked sibling' {
        # The pre-existing precedence must survive being re-expressed as a rank.
        $script:scratch = New-Scratch
        $d = Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure'
        New-RuleFile -Path (Join-Path $d 'RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'
        New-RuleFile -Path (Join-Path $d 'RuleA.custom.yaml') -Id 'RuleA' -Purpose 'operator override'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree 3>$null
        @($r).Count | Should -Be 1
        (Get-Rule $r 'RuleA').Purpose | Should -Be 'operator override'
    }
}

# ============================================================================
Describe 'audit #34 -- decision 1: precedence is overlay > in-tree custom > locked' {
# ============================================================================

    It 'the overlay wins a colliding id against an in-tree CUSTOM rule' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'in-tree operator'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'overlay operator'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        @($r).Count | Should -Be 1
        (Get-Rule $r 'RuleA').Purpose | Should -Be 'overlay operator'
        (Get-Rule $r 'RuleA').Source  | Should -Be 'overlay'
    }

    It 'the overlay wins a colliding id against a LOCKED rule' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'overlay operator'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        (Get-Rule $r 'RuleA').Source | Should -Be 'overlay'
    }

    It 'a shipped rule with no overlay counterpart is untouched' {
        # The overlay must ADD to the rule set, not replace it wholesale.
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleZ.custom.yaml') -Id 'RuleZ' -Purpose 'overlay only'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        @($r).Count | Should -Be 2
        (Get-Rule $r 'RuleA').Source | Should -Be 'tree'
        (Get-Rule $r 'RuleZ').Source | Should -Be 'overlay'
    }

    It 'the overlay contributes shared/ rules too, not just per-engine ones' {
        $script:scratch = New-Scratch
        New-Item -ItemType Directory -Force (Join-Path $script:scratch.Overlay 'shared') | Out-Null
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'shared\RuleS.custom.yaml') -Id 'RuleS' -Purpose 'overlay shared' -Engine 'any'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        (Get-Rule $r 'RuleS').Source | Should -Be 'overlay'
    }
}

# ============================================================================
Describe 'audit #34 -- decision 2: cutover is visible, never silent' {
# ============================================================================

    It 'in-tree operator rules are still LOADED when an overlay is active' {
        # Ignoring the old location would be #29 a third time: rules the operator believes are in
        # force, silently not applied.
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleB.custom.yaml') -Id 'RuleB' -Purpose 'left behind'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleZ.custom.yaml') -Id 'RuleZ' -Purpose 'migrated'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        (Get-Rule $r 'RuleB') | Should -Not -BeNullOrEmpty
    }

    It 'and they are WARNED about by name, so a half-done migration cannot look finished' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleB.custom.yaml') -Id 'RuleB' -Purpose 'left behind'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleZ.custom.yaml') -Id 'RuleZ' -Purpose 'migrated'

        $warnings = @()
        Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        ($warnings -join ' ') | Should -Match 'still in the SHIPPED TREE'
        ($warnings -join ' ') | Should -Match 'RuleB\.custom\.yaml'
    }

    It 'no such warning fires once nothing operator-owned is left in the tree' {
        # Negative verification: the warning must be driven by the files, not printed unconditionally.
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleZ.custom.yaml') -Id 'RuleZ' -Purpose 'migrated'

        $warnings = @()
        Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        ($warnings -join ' ') | Should -Not -Match 'still in the SHIPPED TREE'
    }

    It 'a configured-but-MISSING overlay root warns instead of silently falling back' {
        # The dangerous failure: overlay set, path wrong, run looks clean while every operator rule
        # the overlay was supposed to supply is absent.
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.locked.yaml') -Id 'RuleA' -Purpose 'shipped'

        $warnings = @()
        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot (Join-Path $script:scratch.Root 'nope') -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'does not exist'
        ($warnings -join ' ') | Should -Match 'NO overlay rules were loaded'
        @($r).Count | Should -Be 1     # the shipped tree still runs -- a bad path must not kill the run
    }
}

# ============================================================================
Describe 'audit #34 -- the overlay root comes from config' {
# ============================================================================

    It 'reads $global:SI_EnrichmentDataRoot when no parameter is passed' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Tree 'asset-profiling-enrichment\azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'in-tree'
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'from config'

        $global:SI_EnrichmentDataRoot = $script:scratch.Overlay
        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree 3>$null
        (Get-Rule $r 'RuleA').Purpose | Should -Be 'from config'
    }

    It 'an explicit -EnrichmentDataRoot beats the global' {
        $script:scratch = New-Scratch
        New-RuleFile -Path (Join-Path $script:scratch.Overlay 'azure\RuleA.custom.yaml') -Id 'RuleA' -Purpose 'explicit param'
        $global:SI_EnrichmentDataRoot = Join-Path $script:scratch.Root 'nope'

        $r = Get-SIRuleSet -Engine azure -SolutionRootOverride $script:scratch.Tree -EnrichmentDataRoot $script:scratch.Overlay 3>$null
        (Get-Rule $r 'RuleA').Purpose | Should -Be 'explicit param'
    }
}

# ============================================================================
Describe 'audit #34 -- decision 4: the sync PreservePatterns gap is ASSERTED, not fixed here' {
# ============================================================================

    It 'reports whether sync/ protects the operator rule locations' {
        # sync/ is FRAMEWORK-owned and shared by every solution; SI Rule 8 forbids editing it to
        # solve an SI problem. So SI states the condition out loud instead: if the patterns ever do
        # start covering asset-profiling-enrichment, this test says so and #34's consequence 2 can
        # be closed. It never fails the gate -- it is a REPORT, and reporting is the whole point.
        $sync = Join-Path (Split-Path -Parent (Split-Path -Parent $script:si)) 'sync'
        if (-not (Test-Path $sync)) { Set-ItResult -Skipped -Because 'sync/ is not present in this checkout'; return }

        $covered = $false
        $files = Get-ChildItem -Path $sync -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($raw -and $raw -match 'asset-profiling-enrichment') { $covered = $true; break }
        }
        if (-not $covered) {
            Write-Host "  [#34 REPORT] sync/ still does not name asset-profiling-enrichment in any PreservePatterns -- operator rules in the shipped tree survive an update only by being absent from the zip. Framework-owned; raise, do not edit." -ForegroundColor Yellow
        } else {
            Write-Host "  [#34 REPORT] sync/ now references asset-profiling-enrichment -- re-check whether #34 consequence 2 can be closed." -ForegroundColor Green
        }
        $true | Should -BeTrue
    }
}
