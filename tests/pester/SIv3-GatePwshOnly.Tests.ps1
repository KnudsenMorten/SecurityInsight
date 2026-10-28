#Requires -Version 5.1
<#
    THE v3 GATE RUNS POWERSHELL 7 (operator 2026-10-09: "yes drop ps 5.1 for v3. i told that yesterday").

    Every v3 gate defaults to PowerShell 7 only: the fast gate and its -Full run (the full suite of a feature release) (tests\Invoke-FastGate.ps1),
    the same gate on Invardia's test VM (tests\Invoke-GateOnTestVm.ps1), the release (setup\Release-SI.ps1) and the
    pre-publish gate (tests\pester\Invoke-PrePublishGate.ps1), which re-runs itself under pwsh when it is started from
    Windows PowerShell 5.1. 5.1 stays reachable only as an explicit opt-in (-Runtime ps51 / both, -WindowsPowerShell).
    v2.2 on main keeps its 5.1 gate; removing the 5.1 PRODUCT code (the VM launcher) is #480.

    Replaces SI-GateRunsOnPS51.Tests.ps1 (audit #86: the pre-publish gate must be runnable on 5.1). The one part of it
    that still matters is kept: the gate resolves its tests folder in the BODY, never as a $PSScriptRoot parameter
    default (that binds empty on 5.1 under [CmdletBinding()] + -File) -- the opt-in still runs it on 5.1.

    The gate on the test VM and the release are vendor tools (not in the Community edition), so their PowerShell 7 default
    is pinned in their own suites: SIv3-GateOnTestVm.Tests.ps1 and SIv3-ReleaseSI.Tests.ps1.

    Source assertions, deliberately: executing the real gate from inside the gate would recurse.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:PrePublish = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'Invoke-PrePublishGate.ps1')
    $script:FastGate = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'tests\Invoke-FastGate.ps1')

}

Describe 'the v3 gate runs PowerShell 7' {
    It 'the fast gate (and its -Full run, the full suite) defaults to -Runtime pwsh' {
        $script:FastGate | Should -Match "\[string\]\`$Runtime = 'pwsh'"
    }
    It 'the fast gate never defaults to both runtimes or to 5.1' {
        $script:FastGate | Should -Not -Match "\`$Runtime = '(both|ps51)'"
    }
    It 'the pre-publish gate re-runs itself under pwsh when started on Windows PowerShell, unless -WindowsPowerShell' {
        $script:PrePublish | Should -Match '\[switch\]\$WindowsPowerShell'
        $script:PrePublish | Should -Match "PSEdition -ne 'Core' -and -not \`$WindowsPowerShell"
        $script:PrePublish | Should -Match 'Get-Command pwsh\.exe'
        $script:PrePublish | Should -Match 'exit \$LASTEXITCODE'
        # the re-run comes before anything is discovered or run
        $script:PrePublish.IndexOf("PSEdition -ne 'Core'") | Should -BeLessThan $script:PrePublish.IndexOf('Invoke-Pester -Configuration')
    }
    It 'the pre-publish gate resolves its tests folder in the BODY, never as a $PSScriptRoot parameter default (the 5.1 opt-in)' {
        $script:PrePublish | Should -Not -Match '\$\w+\s*=\s*\$PSScriptRoot\s*[,\)]'
        $script:PrePublish | Should -Match 'IsNullOrWhiteSpace\(\$TestsFolder\)'
    }
}
