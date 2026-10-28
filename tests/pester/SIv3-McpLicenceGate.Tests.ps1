#Requires -Version 5.1
<#
    THE MCP SERVER'S LICENCE GATE (owner 2026-10-27, SI #750 decision (3): "the AI summary is free, the chat (Ask
    SecurityInsight) and the MCP server are Pro, and the MCP server gets a licence gate instead of an install-time edition
    check"). The MCP server is deployed in EVERY edition and answers /mcp only while the installed licence record
    (cfg.InstallState 'Licence') names a Pro edition in force -- a licence bought later switches it on, a removed one off,
    with no redeploy. The gate's decision is proven in xunit (pro-management/tests/SI.Management.Web.Tests/
    McpLicenceGateTests.cs: the same rule as the web app's paid pages, deny by default, the one-minute cache); this suite
    proves the WIRING, which a green unit test never proves: the server runs the gate before /mcp, the guided install no
    longer leaves the MCP server out by edition, and the updater keeps it on the release in both editions.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Read = { param([string]$Rel) [IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }
}

Describe 'the MCP server answers only with a Pro licence (#750 (3))' {

    It 'the server registers the licence gate and runs it before the MCP endpoint is mapped' {
        $p = & $script:Read 'pro-management\src\SI.Management.Mcp\Program.cs'
        $p | Should -Match 'AddSingleton<McpLicenceGate>'
        $use = $p.IndexOf('McpLicenceGate>().IsProAsync')
        $use | Should -BeGreaterThan 0 -Because 'every /mcp request asks the gate'
        $use | Should -BeLessThan $p.IndexOf('app.MapMcp(') -Because 'the gate is middleware that runs before the MCP endpoint'
        $p | Should -Match 'StartsWithSegments\("/mcp"\)' -Because 'only the MCP endpoint is gated; /healthz stays open'
        $p | Should -Match 'Status403Forbidden'
        $p | Should -Match 'MapGet\("/healthz".*AllowAnonymous'
    }

    It 'the gate reads the updater''s licence record and denies by default' {
        $g = & $script:Read 'pro-management\src\SI.Management.Core\Licensing\McpLicenceGate.cs'
        $g | Should -Match "cfg\.InstallState WHERE Name = N'Licence'"
        $g | Should -Match 'catch \{ pro = false; \}' -Because 'a database that does not answer is not Pro'
        $g | Should -Match 'FromMinutes\(1\)'
        $g | Should -Match 'part of SecurityInsight Pro'
    }

    It 'the MCP image carries the gate (its Dockerfile copies the Core project the gate lives in)' {
        $d = & $script:Read 'pro-management\Dockerfile.mcp'
        $d | Should -Match 'SI\.Management\.Core'
    }

    It 'the guided install deploys the MCP server in every edition -- no install-time edition check' {
        $src = & $script:Read 'setup\_shared\SI-GuidedInstallData.ps1'
        $src | Should -Not -Match '\.NoMcp\s*=\s*\$true' -Because 'the licence gate, not the install, makes the MCP server Pro'
        $src | Should -Not -Match 'no MCP server -- a paid feature'
    }

    It 'the updater''s web app roll keeps the MCP server on the release in both editions' {
        $w = & $script:Read 'container\updater\_shared\SI-UpdaterWebApp.ps1'
        $roll = $w.Substring($w.IndexOf('function Invoke-SIUpdaterAppRoll'))
        $roll | Should -Match "App = \`$McpApp; Repo = 'si-management-mcp'"
        $roll | Should -Not -Match '(?i)\$ctx\.Pro\b|\$Edition\b|IsPro|NoMcp' -Because 'the roll does not decide by edition; the licence gate does at run time'
    }
}
