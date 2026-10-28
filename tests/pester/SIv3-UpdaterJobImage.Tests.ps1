#Requires -Version 5.1
<#
    SecurityInsight -- RE-RUNNING THE UPDATER SETUP NEVER DOWNGRADES THE UPDATER (found live on internal ring 1, 2026-10-10):
    setup\Install-SIUpdaterJob.ps1 -GrantSpnRoles on an existing install planned to point caj-si-updater at si-updater:v3.0.0
    while the job ran the image it had rolled itself to. What must hold (setup\_shared\SI-UpdaterJobPlan.ps1):
      - an existing job on a rolled tag KEEPS it (no build); without an image on the job, its si-updater-image tag's;
      - only an explicit -Image changes it; a new job gets the image the setup builds;
      - the job's size: kept when at least 4 CPU / 8 GiB, raised to that floor otherwise, never lowered;
      - the setup uses both (and says which image it keeps).
    Offline. PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-UpdaterJobPlan.ps1')
    $script:Ls = 'acrsi.azurecr.io'
    $script:Default = 'acrsi.azurecr.io/si-updater:v3.0.0'
    $script:Rolled = 'acrsi.azurecr.io/si-updater:v3.0.0.202610102024-2e0582308f82'
    function script:Job([string]$Image, [string]$Cpu = '4.0', [string]$Memory = '8Gi', [string]$TagImage = '') {
        $tags = [ordered]@{}; if ($TagImage) { $tags['si-updater-image'] = $TagImage; $tags['si-updater-previous'] = $script:Default }
        $cont = [ordered]@{ name = 'updater'; resources = [pscustomobject]@{ cpu = $Cpu; memory = $Memory } }
        if ($Image) { $cont.image = $Image }
        [pscustomobject]@{ name = 'caj-si-updater'; tags = [pscustomobject]$tags; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]$cont) } } }
    }
}

Describe 'the updater job''s image' {
    It 'an existing job on a rolled tag keeps it -- no build, said' {
        $p = Resolve-SIUpdaterJobImage -Existing (Job $script:Rolled -TagImage $script:Rolled) -Default $script:Default -LoginServer $script:Ls
        $p.Image | Should -Be $script:Rolled
        $p.Build | Should -BeFalse
        $p.Source | Should -Be 'job'
        $p.Why | Should -Match ([regex]::Escape($script:Rolled))
    }
    It 'a job without an image on its container keeps its si-updater-image tag''s' {
        $p = Resolve-SIUpdaterJobImage -Existing (Job '' -TagImage $script:Rolled) -Default $script:Default -LoginServer $script:Ls
        $p.Image | Should -Be $script:Rolled; $p.Source | Should -Be 'tag'; $p.Build | Should -BeFalse
    }
    It 'only an explicit -Image changes it; a new job gets the image the setup builds' {
        (Resolve-SIUpdaterJobImage -Existing (Job $script:Rolled) -Default $script:Default -Explicit 'v3.0.1' -LoginServer $script:Ls).Image | Should -Be 'acrsi.azurecr.io/si-updater:v3.0.1'
        (Resolve-SIUpdaterJobImage -Existing (Job $script:Rolled) -Default $script:Default -Explicit 'other.azurecr.io/x:1' -LoginServer $script:Ls).Image | Should -Be 'other.azurecr.io/x:1'
        $n = Resolve-SIUpdaterJobImage -Existing $null -Default $script:Default -LoginServer $script:Ls
        $n.Image | Should -Be $script:Default; $n.Build | Should -BeTrue; $n.Source | Should -Be 'new'
    }
}

Describe 'the updater job''s size' {
    It 'kept at 4 CPU / 8 GiB or larger; raised to it when smaller; never lowered' {
        (Resolve-SIUpdaterJobSize -Existing (Job $script:Rolled '4.0' '8Gi')).Change | Should -BeFalse
        (Resolve-SIUpdaterJobSize -Existing (Job $script:Rolled '8.0' '16Gi')).Change | Should -BeFalse
        $s = Resolve-SIUpdaterJobSize -Existing (Job $script:Rolled '0.5' '1Gi')
        $s.Change | Should -BeTrue; $s.Cpu | Should -Be '4.0'; $s.Memory | Should -Be '8Gi'
        $m = Resolve-SIUpdaterJobSize -Existing (Job $script:Rolled '6.0' '4Gi')
        $m.Cpu | Should -Be '6.0'; $m.Memory | Should -Be '8Gi'
    }
}

Describe 'the setup uses both' {
    It 'Install-SIUpdaterJob resolves the image before it builds, builds only for a new image, and sizes an existing job without lowering it' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1'))
        $src | Should -Match ([regex]::Escape('$imgPlan = Resolve-SIUpdaterJobImage -Existing $existing -Default $image -Explicit $explicitImage'))
        $src | Should -Match ([regex]::Escape("if (-not `$imgPlan.Build) { `$image = [string]`$imgPlan.Image; Info 'no build: the job keeps its image' } else {"))
        $src | Should -Match ([regex]::Escape('$size = Resolve-SIUpdaterJobSize -Existing $existing'))
        $src | Should -Match ([regex]::Escape('$explicitImage = [string]$Image'))
        $src.IndexOf('$explicitImage = [string]$Image') | Should -BeLessThan $src.IndexOf("`$image = '{0}/si-updater:v{1}'")
    }
}
