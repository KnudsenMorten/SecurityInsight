#Requires -Version 7.0
<#
    #755 -- THE OLD v2 SETUP SCRIPTS ARE RETIRED IN v3 (owner 2026-10-18: "retire the old scripts").

    Setup-SecurityInsight.ps1 (the phased server setup) and setup\Validate-SIPermissions.ps1 looked up and created the
    engine application by its display name (-SpnDisplayName, default sp-securityinsight) -- outside the agreed naming and
    against "never look an object up by its name". v3 installs with the guided install (setup\Install-SecurityInsight.ps1),
    the container setup and the unattended setup, and grants permissions with setup\Grant-SIIdentity.ps1 (-AppId <client id>
    for an app registration). What this keeps true:
      * neither script (nor the permission script's documentation manifest) is in the tree again;
      * no shipped file names either of them -- not a doc, a script, an error text, a settings document, the web app's help
        or a support-script list. History stays where it is history: RELEASENOTES.md, docs/REQUIREMENTS.md,
        docs/V3-HANDOFF.md, docs/TESTS.md (internal, it documents this guard), and the version-history rows of README.md (a table row that ends in a v2.x version);
      * Grant-SIIdentity takes -AppId, so an app registration has its v3 path.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:NamePattern = '(?<![-\w])Setup-SecurityInsight\.ps1|Validate-SIPermissions'
    $script:History = @('RELEASENOTES.md', 'docs/REQUIREMENTS.md', 'docs/V3-HANDOFF.md', 'docs/TESTS.md', 'tests/pester/SIv3-RetiredV2SetupScripts.Tests.ps1')
}

Describe 'the retired v2 setup scripts stay retired (#755)' {
    It '<_> is not in the tree' -ForEach @('Setup-SecurityInsight.ps1', 'setup\Validate-SIPermissions.ps1', 'release\script-docs\Validate-SIPermissions.doc.json') {
        Test-Path -LiteralPath (Join-Path $script:SIRoot $_) | Should -BeFalse -Because 'retired in v3 (#755): v3 installs with the guided install and grants with Grant-SIIdentity'
    }
    It 'no shipped file names them (history excepted)' {
        $skip = '[\\/](\.git|bin|obj|node_modules)[\\/]'
        $exts = '.ps1', '.psm1', '.psd1', '.json', '.md', '.cs', '.cshtml', '.js', '.css', '.html', '.yml', '.yaml', '.txt', '.sql'
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch $skip -and $exts -contains $_.Extension.ToLowerInvariant() })) {
            $rel = $f.FullName.Substring($script:SIRoot.Length + 1).Replace('\', '/')
            if ($script:History -contains $rel) { continue }
            $n = 0
            foreach ($line in [IO.File]::ReadLines($f.FullName)) {
                $n++
                if ($line -notmatch $script:NamePattern) { continue }
                # README's version-history table: a row that ends in the v2.x version it shipped in
                if ($rel -eq 'README.md' -and $line -match '\|\s*v2\.[0-9][0-9./ v]*\|\s*$') { continue }
                $hits.Add(('{0}:{1}' -f $rel, $n))
            }
        }
        $hits | Should -BeNullOrEmpty -Because 'name the v3 path instead: setup\Install-SecurityInsight.ps1 (the guided install) or setup\Grant-SIIdentity.ps1 (-AppId <client id> for an app registration)'
    }
    It 'Grant-SIIdentity has the app registration path (-AppId, found by its id, never by a name)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1'))
        $t | Should -Match "\[Parameter\(ParameterSetName = 'AppId', Mandatory\)\]"
        $t | Should -Match 'Find-SIGraphServicePrincipal -AppId \$AppId'
        $t | Should -Not -Match 'Find-SIGraphServicePrincipal -DisplayName'
    }
    It 'the permission note and the web app give an app registration Grant-SIIdentity -AppId' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-PermissionNote.ps1')) | Should -Match "& \`$arg 'AppId' \`$Identity\.ClientId"
        # the web app is Pro: checked only where Test-Path finds it (a Community copy has no web app)
        $web = Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\GetStarted\GetStartedPermissionFix.cs'
        if (Test-Path -LiteralPath $web) { [IO.File]::ReadAllText($web) | Should -Match 'Arg\("AppId", appId!\)' }
    }
}
