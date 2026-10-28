#Requires -Version 5.1
<#
    THE ENVIRONMENT NAMES IN SHIPPED CODE MUST BE REAL ONES (#110, renumbered from #108).

    🪤 WHY THIS EXISTS. `container/Sync-ContainerModules.ps1` carried two `.EXAMPLE` lines naming
    `acrsicont` and `rg-sicontainertest`. **No such resources have ever existed** — measured
    2026-09-07 as the management SPN across both subscriptions, 72 resource groups, not one match.
    They were the only place in the shipped tree carrying those names, and `.EXAMPLE` is precisely
    where a reader looks for the environment's actual names.

    **Three consecutive sessions read them, believed SI had a container estate, and wrote "just needs
    one `-Build -Roll`" into three separate documents.** The real estate — `rg-securityinsight` in
    `westeurope`, with the workspace, the DCE, 11 DCRs, the storage account and the SQL ledger — has
    existed the whole time, two resources short of running containers.

    🔑 THE PROPERTY, and it generalises past this one incident: **a plausible fictional resource name
    is indistinguishable from a real one.** A reader cannot tell them apart, and nothing else in the
    tree contradicts it. So the shipped code may only name resources that the deploy contract also
    names — `Bootstrap-ContainerAppJob.ps1`'s defaults, which are the canonical source.

    📌 DOCS ARE DELIBERATELY EXEMPT. `docs/` records the *history* of the mistake, including the dead
    names, and must keep being able to say them. Scoping this to executable + config files is what
    lets the post-mortem stay written down.
#>

BeforeAll {
    # 🪤 THREE levels: pester -> tests -> solution root. Two levels lands on `tests\`, and the file
    # count assertion below still passes there (tests/ holds well over 50 files), so the phantom-name
    # scan would have swept only the test tree and reported clean. Caught on the first run only
    # because the deploy-contract assertion read $null from a path that did not exist.
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    # The names that never existed. Kept as one list so a future phantom can be added in one place.
    $script:PhantomNames = @('acrsicont', 'rg-sicontainertest', 'stsicont', 'cae-sicont')

    # Executable + config surface only -- see the docs exemption above.
    $script:CodeFiles = @(
        Get-ChildItem -Path $script:SIRootDir -Recurse -Include *.ps1, *.psm1, *.psd1, *.json |
            Where-Object {
                $_.FullName -notmatch '\\docs\\' -and
                $_.FullName -notmatch '\\internal\\' -and
                $_.FullName -notmatch '\\\.git\\'
            } |
            ForEach-Object { $_.FullName }
    )
}

Describe 'shipped code names only resources that really exist (#110)' {

    It 'the tripwire can see the WHOLE solution -- not just the folder it lives in' {
        # 🪤 A bare count is not enough, and this file proved it: with $SIRootDir one level short the
        # sweep covered only `tests\`, where a count of >50 still passes. The scan must be anchored to
        # files that exist ONLY at the solution root, or "found nothing" and "looked nowhere" stay
        # indistinguishable -- which is the exact failure mode this suite keeps rediscovering.
        $script:CodeFiles.Count | Should -BeGreaterThan 50
        $leaves = @($script:CodeFiles | ForEach-Object { Split-Path $_ -Leaf })
        $leaves | Should -Contain 'Bootstrap-ContainerAppJob.ps1'
        $leaves | Should -Contain 'Start-SIInContainer.ps1'
        @($script:CodeFiles | Where-Object { $_ -match '\\engine\\' }).Count |
            Should -BeGreaterThan 0 -Because 'the engine tree must be in scope, not only tests'
    }

    It 'no phantom container resource name appears in executable or config files' {
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $script:CodeFiles) {
            $raw = Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue
            if (-not $raw) { continue }
            foreach ($name in $script:PhantomNames) {
                if ($raw -match [regex]::Escape($name)) {
                    # The one legitimate mention is the post-mortem comment in the file that carried
                    # the defect. Naming it explicitly beats a broad "ignore comments" rule, which
                    # would let the names back into a comment that then gets copied into a command.
                    $leaf = Split-Path $f -Leaf
                    if ($leaf -eq 'SI-ContainerResourceNames.Tests.ps1') { continue }
                    [void]$hits.Add(("{0}: {1}" -f $leaf, $name))
                }
            }
        }
        # 🪤 .ToArray(), not @(...). With zero hits, `,$hits.ToArray()` returns an array CONTAINING an
        # empty array and @() counts it as 1 -- the wrapper trap that has already defeated one guard
        # written in this codebase to catch exactly it.
        $found = $hits.ToArray()
        $found.Count | Should -Be 0 -Because "these resource names have never existed; three sessions believed they had a container estate because of them: $($found -join ', ')"
    }

    It 'the canonical names come from the deploy contract, and they agree with each other' {
        # If these three ever disagree, the "which name is real" question comes straight back.
        $bootstrap = Get-Content (Join-Path $script:SIRootDir 'Bootstrap-ContainerAppJob.ps1') -Raw
        $bootstrap | Should -Match "\`$ResourceGroupName\s*=\s*'rg-securityinsight'"
        $bootstrap | Should -Match "\`$AcrName\s*=\s*'acrsecurityinsight'"
        $bootstrap | Should -Match "\`$EnvName\s*=\s*'cae-securityinsight'"

        # (the image's module-sync helper that also carried them was retired with the PowerShell modules)
    }

    It '🔴 the detector actually fires on a phantom name -- proven, not assumed' {
        # A guard that cannot fail is decoration. This is the third time that lesson is paid for in
        # this tree, so it is asserted rather than trusted.
        $sample = 'az acr build --registry acrsicont --image si-orchestrator:test .'
        $matched = $false
        foreach ($name in $script:PhantomNames) { if ($sample -match [regex]::Escape($name)) { $matched = $true } }
        $matched | Should -BeTrue
    }
}
