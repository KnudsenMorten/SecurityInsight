#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- SIA container image hardening + the listen-port contract (audit #12).

.DESCRIPTION
    Two halves of finding #12, pinned so neither can regress:

      1. The image must NOT run as root. It did, because no USER was ever declared.

      2. The listen port is a CONTRACT BETWEEN TWO FILES and nothing used to check it.
         Container Apps does not inject a port into the container -- it routes ingress
         to the container's target-port -- and SIA reads neither PORT nor WEBSITES_PORT.
         So `deploy/Dockerfile`'s ASPNETCORE_URLS and `Deploy-SIAnalyzer.ps1`'s
         $ContainerListenPort (which the deploy asserts the live ingress against) MUST
         stay equal. Editing one without the other is exactly the drift this catches.

    Note these are STATIC checks on the two files. Whether the LIVE container app's
    ingress target-port matches is a hosted-gate question -- that is what the deploy
    script's own gate answers, at deploy time.
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> solution root (3 levels up)
    $_root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SiRoot         = $_root
    $script:DockerfilePath = Join-Path $_root 'analyzer-web\deploy\Dockerfile'
    $script:DeployPath     = Join-Path $_root 'analyzer-web\deploy\Deploy-SIAnalyzer.ps1'
    $script:Dockerfile     = if (Test-Path $script:DockerfilePath) { Get-Content -Raw -LiteralPath $script:DockerfilePath } else { '' }
    $script:DeployScript   = if (Test-Path $script:DeployPath)     { Get-Content -Raw -LiteralPath $script:DeployPath }     else { '' }
}

# ============================================================================
Describe 'SIA container image (audit #12)' {
# ============================================================================

    It 'the SIA Dockerfile exists where the deploy expects it' {
        Test-Path $script:DockerfilePath | Should -BeTrue
    }

    It 'declares a USER -- the image must not run as root' {
        $script:Dockerfile | Should -Match '(?m)^\s*USER\s+\S+'
    }

    It 'that USER is not root' {
        $u = [regex]::Match($script:Dockerfile, '(?m)^\s*USER\s+(?<u>\S+)').Groups['u'].Value
        $u | Should -Not -BeNullOrEmpty
        $u | Should -Not -Be 'root'
        $u | Should -Not -Be '0'
    }

    It 'drops privilege in the RUNTIME stage, not the build stage' {
        # A USER before `AS run` would harden the throwaway SDK stage and leave the
        # shipped image as root -- green line, zero effect.
        $runStage = [regex]::Match($script:Dockerfile, '(?m)^\s*FROM\s+.*\s+AS\s+run\b')
        $runStage.Success | Should -BeTrue
        $userIdx = [regex]::Match($script:Dockerfile, '(?m)^\s*USER\s+\S+').Index
        $userIdx | Should -BeGreaterThan $runStage.Index
    }

    It 'binds Kestrel to all interfaces, not loopback' {
        # A container bound to 127.0.0.1 answers nothing through ingress.
        $script:Dockerfile | Should -Match 'ASPNETCORE_URLS=http://\+:\d+'
    }
}

# ============================================================================
Describe 'SIA listen-port contract (audit #12)' {
# ============================================================================

    BeforeAll {
        $script:ImagePort = [regex]::Match($script:Dockerfile, 'ASPNETCORE_URLS=http://\+:(?<p>\d+)').Groups['p'].Value
        $script:DeployPort = [regex]::Match($script:DeployScript, '(?m)^\s*\$ContainerListenPort\s*=\s*(?<p>\d+)').Groups['p'].Value
    }

    It 'the Dockerfile states a concrete listen port' {
        $script:ImagePort | Should -Not -BeNullOrEmpty
    }

    It 'the deploy script defines $ContainerListenPort' {
        $script:DeployPort | Should -Not -BeNullOrEmpty
    }

    It 'the image listen port and the deploy assertion agree' {
        $script:DeployPort | Should -Be $script:ImagePort
    }

    It 'EXPOSE matches the port Kestrel actually binds' {
        $expose = [regex]::Match($script:Dockerfile, '(?m)^\s*EXPOSE\s+(?<p>\d+)').Groups['p'].Value
        $expose | Should -Be $script:ImagePort
    }

    It 'the listen port is unprivileged, so a non-root user can bind it' {
        [int]$script:ImagePort | Should -BeGreaterThan 1024
    }

    It 'the deploy reads the live ingress target-port' {
        $script:DeployScript | Should -Match 'ingress\.targetPort'
    }

    It 'the deploy REFUSES a target-port mismatch rather than warning' {
        # The gate has to throw. A Write-Warning here would reproduce the original
        # defect: a config mismatch that only shows up later, as an app fault.
        $script:DeployScript | Should -Match 'INGRESS TARGET-PORT MISMATCH'
        $script:DeployScript | Should -Match 'throw\s+"INGRESS TARGET-PORT MISMATCH'
    }

    It 'the port gate runs BEFORE the image build' {
        $gateIdx  = $script:DeployScript.IndexOf('LISTEN-PORT GATE')
        $buildIdx = $script:DeployScript.IndexOf("'acr','build'")
        $gateIdx  | Should -BeGreaterThan 0
        $buildIdx | Should -BeGreaterThan 0
        $gateIdx  | Should -BeLessThan $buildIdx
    }
}
