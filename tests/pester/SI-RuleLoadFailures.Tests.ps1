#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #29: a rule file that will not parse must be visible on a normal run.

.DESCRIPTION
    Found by running the endpoint profiler live. `Get-SIRuleSet` logged one warning per bad file
    and carried on, and the engine finished with "Engine completed successfully":

        WARNING: Get-SIRuleSet: skipping AssetTagging.custom.yaml (parse error: ...)

    In this environment ALL EIGHT `*.custom.yaml` files had been unparseable since 2026-06-11 --
    the space after each `key:` had been stripped, so `id:VisualCron` is not valid YAML. Every
    customer tagging and profiling rule was therefore inert, and nothing said so: the per-file
    warnings scroll past in a long log, and the only aggregate was a `Write-Verbose` line that
    prints for nobody by default. Same defect shape as #27.

    The counter is deliberately SEPARATE from the existing `$skipped`, because most skips are
    benign by design (sample files, foreign schemas, engine filters). A blanket "skipped=N" would
    say nothing; "N failed to parse" is actionable.
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $si 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
    if (-not (Get-Module -Name powershell-yaml)) { Import-Module powershell-yaml -Force }

    $script:RuleRoot = Join-Path ([IO.Path]::GetTempPath()) ("si29-" + [guid]::NewGuid().ToString('N'))
    # Mirror the real layout the function scans: <root>\asset-profiling-enrichment\<engine>\
    $script:RuleDir = Join-Path $script:RuleRoot 'asset-profiling-enrichment\endpoint'
    New-Item -ItemType Directory -Force -Path $script:RuleDir | Out-Null

    # One good rule, and one with the exact corruption seen live (no space after `key:`).
    Set-Content -LiteralPath (Join-Path $script:RuleDir 'GoodRule.locked.yaml') -Encoding UTF8 -Value @(
        'id: GoodRule'
        'appliesTo: endpoint'
        'detections:'
        '  - id: GoodRule'
        '    detect:'
        '      any:'
        '        - kind: hasSoftwareInstalled'
        '          tvmSoftwareNames:'
        "            - '*something*'"
    )
    Set-Content -LiteralPath (Join-Path $script:RuleDir 'BrokenRule.custom.yaml') -Encoding UTF8 -Value @(
        'id:BrokenRule'
        'appliesTo:endpoint'
        'description:'
        '  thisprosehaslostitsspacestoo'
        'detections:'
        '  -id:BrokenRule'
    )
}

AfterAll {
    if ($script:RuleRoot -and (Test-Path $script:RuleRoot)) { Remove-Item $script:RuleRoot -Recurse -Force }
}

# ============================================================================
Describe 'audit #29 -- an unparseable rule file is reported, not just skipped' {
# ============================================================================

    It 'the corrupted shape really is invalid YAML (pins the reproduction)' {
        # `id:BrokenRule` -- no space after the colon. If a future powershell-yaml accepts this,
        # the rest of these tests are testing nothing, so assert the premise.
        { Get-Content -Raw (Join-Path $script:RuleDir 'BrokenRule.custom.yaml') | ConvertFrom-Yaml -ErrorAction Stop } |
            Should -Throw
    }

    It 'warns with a COUNT and the failing file name' {
        $warnings = @()
        Get-SIRuleSet -Engine 'endpoint' -SolutionRootOverride $script:RuleRoot -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        $text = ($warnings | ForEach-Object { [string]$_ }) -join "`n"
        $text | Should -Match 'FAILED TO PARSE'
        $text | Should -Match 'BrokenRule.custom.yaml'
    }

    It 'says the rules are NOT in force -- the consequence, not just the fact' {
        $warnings = @()
        Get-SIRuleSet -Engine 'endpoint' -SolutionRootOverride $script:RuleRoot -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        (($warnings | ForEach-Object { [string]$_ }) -join "`n") | Should -Match 'NOT in force'
    }

    It 'still loads the rules that ARE valid -- it fails open, not closed' {
        # A broken custom rule must not stop a security run that still produces useful output,
        # consistent with the standing "a source failing must never block the run" decision.
        $rules = @(Get-SIRuleSet -Engine 'endpoint' -SolutionRootOverride $script:RuleRoot -WarningAction SilentlyContinue)
        @($rules | Where-Object { $_.id -eq 'GoodRule' }).Count | Should -Be 1
    }

    It 'stays quiet when every rule file parses' {
        # The warning must not become background noise, or it will be ignored like the last one.
        Remove-Item (Join-Path $script:RuleDir 'BrokenRule.custom.yaml') -Force
        $warnings = @()
        Get-SIRuleSet -Engine 'endpoint' -SolutionRootOverride $script:RuleRoot -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        (($warnings | ForEach-Object { [string]$_ }) -join "`n") | Should -Not -Match 'FAILED TO PARSE'
    }
}

# ============================================================================
Describe 'audit #30 -- only *.locked.yaml and *.custom.yaml may load as rules' {
# ============================================================================
# A SAMPLE that loads is worse than a sample that is missing: on any host without
# its own override it WINS the id-dedup and becomes the live detection rule.
# Shipped in v2.2.405 as 'ADDomainController.custom.sample - Copy.yaml' -- the old
# blacklist tested -like '*.sample.*', which needs a literal '.sample.', and that
# name reads '.sample - Copy.yaml'. Samples must exist in the folders (customer
# reference) and must never load.

    BeforeAll {
        $script:D = $script:RuleDir
        # Shipped rule + a sample whose name defeats a '.sample.'-style blacklist.
        Set-Content -LiteralPath (Join-Path $script:D 'Widget.locked.yaml') -Encoding UTF8 -Value @(
            'id: Widget', 'appliesTo: endpoint', 'purpose: identity', 'detections:'
            '  - id: Widget', '    set:', '      Tier: 1', '    detect:', '      any:'
            '        - kind: hasSoftwareInstalled', '          tvmSoftwareNames:', "            - '*shipped*'"
        )
        Set-Content -LiteralPath (Join-Path $script:D 'Widget.custom.sample - Copy.yaml') -Encoding UTF8 -Value @(
            'id: Widget', 'appliesTo: endpoint', 'purpose: identity', 'detections:'
            '  - id: Widget', '    set:', '      Tier: 3', '    detect:', '      any:'
            '        - kind: hasSoftwareInstalled', '          tvmSoftwareNames:', "            - '*SAMPLE*'"
        )
    }
    AfterAll {
        Remove-Item (Join-Path $script:D 'Widget.locked.yaml') -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $script:D 'Widget.custom.sample - Copy.yaml') -Force -ErrorAction SilentlyContinue
    }

    It 'the old blacklist really did miss this name (the defect is genuine)' {
        # Negative verification: if this ever becomes $true the bug was never real.
        'Widget.custom.sample - Copy.yaml' -like '*.sample.*' | Should -BeFalse
    }

    It 'a sample never loads, even when its name defeats a .sample. blacklist' {
        $rules = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:RuleRoot -WarningAction SilentlyContinue
        @($rules | Where-Object { $_.File -like '*sample*' }).Count | Should -Be 0
    }

    It 'the SHIPPED locked rule wins on a host with no override (sample must not)' {
        $rules = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:RuleRoot -WarningAction SilentlyContinue
        $w = @($rules | Where-Object { $_.Id -eq 'Widget' })
        $w.Count | Should -Be 1
        $w[0].File | Should -BeLike '*Widget.locked.yaml'
    }

    It 'the sample file still EXISTS on disk -- reference material, just not loaded' {
        Test-Path (Join-Path $script:D 'Widget.custom.sample - Copy.yaml') | Should -BeTrue
    }

    It 'no stray non-rule yaml ships in the real enrichment tree' {
        $si   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $tree = Join-Path $si 'asset-profiling-enrichment'
        $bad  = Get-ChildItem -Path $tree -Filter '*.yaml' -Recurse -File |
                    Where-Object { $_.Name -notlike '*.locked.yaml' -and
                                   $_.Name -notlike '*.custom.yaml' -and
                                   $_.Name -notlike '*.custom.sample.yaml' }
        $bad | Should -BeNullOrEmpty -Because "not a rule and not a canonical sample: $($bad.Name -join ', ')"
    }
}

# ============================================================================
Describe 'audit #31 -- the foreign-schema guard must actually fire' {
# ============================================================================
# ConvertFrom-Yaml returns a Hashtable, so $obj.PSObject.Properties.Name lists the
# HASHTABLE's members (Keys, Values, Count, ...) and never the YAML keys. The guard
# was therefore always false and AssetTagging files fell through to 'no id field',
# emitting a misleading WARNING every run -- the exact noise it exists to prevent.

    BeforeAll {
        Set-Content -LiteralPath (Join-Path $script:RuleDir 'AssetTagging.custom.yaml') -Encoding UTF8 -Value @(
            'AssetTagging:', '  - AssetTagName: Temp-Class', '    AssetTagValue: demo'
        )
    }
    AfterAll { Remove-Item (Join-Path $script:RuleDir 'AssetTagging.custom.yaml') -Force -ErrorAction SilentlyContinue }

    It 'PSObject.Properties cannot see YAML keys on a Hashtable (root cause)' {
        $o = ConvertFrom-Yaml -Yaml "AssetTagging:`n  - AssetTagName: x`n"
        $o -is [System.Collections.IDictionary]                  | Should -BeTrue
        $o.PSObject.Properties.Name -contains 'AssetTagging'     | Should -BeFalse
        $o.Contains('AssetTagging')                              | Should -BeTrue
    }

    It 'the AssetTagging schema is skipped SILENTLY -- no "no id field" warning' {
        $warnings = @()
        $null = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:RuleRoot `
                              -WarningVariable +warnings -WarningAction SilentlyContinue
        (($warnings | ForEach-Object { [string]$_ }) -join "`n") | Should -Not -Match 'AssetTagging.*no id field'
    }
}
