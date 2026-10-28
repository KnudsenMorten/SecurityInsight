#Requires -Version 5.1
<#
    THE CONTAINER IS ITS OWN CONFIG LAYER, AND IT MUST NEVER REACH INTO /app/config (#111).

    🔴 WHAT THIS PREVENTS, measured rather than imagined. `Start-SIInContainer.ps1` carried an
    UNGUARDED `. '/app/config/SecurityInsight.custom.ps1'` in the privilege-tier-classifier branch,
    under a comment asserting that `COPY . /app/` had put the file there. `.dockerignore` excludes
    `**/config/` and `**/*.custom.ps1` deliberately -- they carry real tenant values and an image is a
    shared artifact -- so the file cannot exist, and with `$ErrorActionPreference = 'Stop'` the
    dot-source was FATAL.

    **privilege-tier-classifier is one of the seven engines `Bootstrap-ContainerAppJob.ps1` provisions
    by default, and it could not start at all.** Proven in the real image on 2026-09-08 (ACR run cb4):

        [SI_ROLE=worker SI_ENGINE=privilege-tier-classifier] dispatching to ...
        The term '/app/config/SecurityInsight.custom.ps1' is not recognized ...
        Container failed during run: acb_step_0.

    A second, guarded copy in the same file and a third in `Start-RiskAnalysisInContainer.ps1` were not
    fatal but were never reachable either -- their `else` branch, a warning saying the engine "may
    throw on missing Path", was the only path taken on every run for ever. A warning that always fires
    teaches operators to ignore warnings.

    🔒 WHY LOADING THAT FILE IS WORSE THAN ITS ABSENCE -- the property this file really pins. Both
    dot-sources sat AFTER the env-var hydration, so a customer config would have OVERRIDDEN the
    credentials, workspace and storage account the Container App Job just supplied. "VM-launcher parity"
    was the wrong goal: on this host the layering is inverted.

    📌 The fix was removal, so the risk is that a future session "restores parity" and re-introduces it.
    That is what these tests exist to stop.
#>

BeforeAll {
    $script:SIRootDir  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:ContainerDir = Join-Path $script:SIRootDir 'container'
    $script:Entrypoints = @(
        'Start-SIInContainer.ps1'
        'Start-RiskAnalysisInContainer.ps1'
        'Invoke-ShardProducer.ps1'
    ) | ForEach-Object { Join-Path $script:ContainerDir $_ } | Where-Object { Test-Path -LiteralPath $_ }

    # Code only -- the comments in these files deliberately quote the removed path so the post-mortem
    # survives. Stripping comment lines is what lets the explanation stay next to the fix.
    function script:CodeOf { param([string]$Path)
        ((Get-Content -LiteralPath $Path -Raw) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
}

Describe 'the container never loads config from /app/config (#111)' {

    It 'found the entrypoints -- the sweep must not pass by looking at nothing' {
        $script:Entrypoints.Count | Should -BeGreaterThan 1
    }

    It 'no entrypoint dot-sources anything under /app/config' -ForEach @( @{ Files = $null } ) {
        $offenders = @()
        foreach ($f in $script:Entrypoints) {
            $code = script:CodeOf $f
            # A dot-source of that path in any quoting style, guarded or not.
            if ($code -match '\.\s+[''"]?/app/config/') { $offenders += (Split-Path $f -Leaf) }
        }
        $offenders.Count | Should -Be 0 -Because "the image cannot contain /app/config -- .dockerignore excludes it on purpose -- and loading it would override the env vars the Container App Job supplies: $($offenders -join ', ')"
    }

    It '🔴 no UNGUARDED reference to the customer config survives -- that one was fatal' {
        # The classifier branch had no Test-Path in front of it, and $ErrorActionPreference = 'Stop'
        # turned a missing file into a dead container.
        foreach ($f in $script:Entrypoints) {
            (script:CodeOf $f) | Should -Not -Match 'SecurityInsight\.custom\.ps1'
        }
    }

    It 'storage has no mode to state: the job''s identity is the only way in (#307)' {
        $code = script:CodeOf (Join-Path $script:ContainerDir 'Start-SIInContainer.ps1')
        $code | Should -Not -Match 'UseStorageOAuth|STORAGE_KEY|AccountKey'
        $code | Should -Match 'New-SIStorageContext -AccountName \$global:SI_StorageAccount\s*(\r?\n|$)'
    }

    It 'the exclusion that makes all this true is still in .dockerignore' {
        # If these rules were ever relaxed, tenant values would reach a shared image -- and the
        # dot-sources above would start "working", which is the worse outcome, not the better one.
        $di = Get-Content (Join-Path $script:SIRootDir '.dockerignore') -Raw
        $di | Should -Match '(?m)^\*\*/\*\.custom\.ps1\s*$'
        $di | Should -Match '(?m)^\*\*/config/\s*$'
    }

    It '🔴 the detector fires on the exact line that broke the classifier -- proven, not assumed' {
        # A guard that cannot fail is decoration; this codebase has paid for that lesson repeatedly.
        $sample = ". '/app/config/SecurityInsight.custom.ps1'   # hydrate engine globals"
        $sample | Should -Match '\.\s+[''"]?/app/config/'
        $sample | Should -Match 'SecurityInsight\.custom\.ps1'
    }
}
