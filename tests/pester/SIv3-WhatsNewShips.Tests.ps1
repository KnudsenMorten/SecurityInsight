#Requires -Version 5.1
<#
    WHAT'S NEW REACHES THE PRO PACKAGE AND THE IMAGES (framework R0-D, Invardia 2026-11-13, after EPS 2.1.24: its Pro package was
    built from an allow-list that left out whats-new/ and WHATSNEW.md, and every Pro update stopped at the image build).
    SecurityInsight's packaging removes by DENY rules; this suite holds the POSITIVE list -- every path What's new needs:
      * survives the Pro release package (setup\_shared\SI-ReleasePayload.ps1, Get-SIReleasePayloadRules -Edition Pro);
      * survives the image build context (the solution's .dockerignore, setup\_shared\SI-AcrBuild.ps1 Test-SIDockerIgnored);
      * the web app's image copies the folder that holds its embedded copy (pro-management\Dockerfile: COPY pro-management/src/),
        and the project embeds it (SI.Management.Web.csproj: EmbeddedResource WhatsNew\*.json).
    Offline, pure: reads the rules and the files; builds nothing.
#>

BeforeDiscovery {
    # the release payload rules are the vendor's (a Community copy does not carry them): this suite runs where they ship
    $script:HasRules = Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'setup\_shared\SI-ReleasePayload.ps1')
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $rp = Join-Path $script:Root 'setup\_shared\SI-ReleasePayload.ps1'; if (Test-Path -LiteralPath $rp) { . $rp }
    . (Join-Path $script:Root 'setup\_shared\SI-AcrBuild.ps1')
    $v = (Get-Content -Raw -LiteralPath (Join-Path $script:Root 'VERSION')).Trim()
    $web = 'pro-management/src/SI.Management.Web'
    # every path the shipped product needs for What's new (the release command's own helper release/SI-WhatsNew.ps1 is
    # vendor-only and is deliberately NOT here)
    $script:Needed = @(
        "whats-new/$v.json",
        'WHATSNEW.md',
        "$web/WhatsNew/$v.json",
        "$web/wwwroot/lib/whatsnew/whats-new.js",
        "$web/wwwroot/lib/whatsnew/whats-new.css",
        "$web/wwwroot/js/whats-new-page.js",
        "$web/wwwroot/js/whats-new-badge.js",
        "$web/wwwroot/css/whats-new-theme.css")
}

Describe 'every path What''s new needs ships in the Pro package and the image context' -Skip:(-not $script:HasRules) {
    It 'each needed path exists in the tree' {
        foreach ($p in $script:Needed) { Test-Path -LiteralPath (Join-Path $script:Root $p) | Should -BeTrue -Because "$p is what the product shows" }
    }
    It 'the Pro release package keeps every one of them' {
        $rules = Get-SIReleasePayloadRules -Edition Pro
        foreach ($p in $script:Needed) { Get-SIReleaseExclusionReason -RelativePath $p -Rules $rules | Should -BeNullOrEmpty -Because "$p must reach the Pro package" }
    }
    It 'the image build context keeps every one of them' {
        $rules = Get-SIDockerIgnoreRules -Text (Get-Content -Raw -LiteralPath (Join-Path $script:Root '.dockerignore'))
        foreach ($p in $script:Needed) { Test-SIDockerIgnored -RelativePath $p -Rules $rules | Should -BeFalse -Because "$p must reach the image build" }
    }
    It 'the web app image copies its source folder, and the project embeds the What''s new copy' {
        $df = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'pro-management\Dockerfile')
        $df | Should -Match '(?m)^COPY pro-management/src/ pro-management/src/'
        $proj = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'pro-management\src\SI.Management.Web\SI.Management.Web.csproj')
        $proj | Should -Match '<EmbeddedResource Include="WhatsNew\\\*\.json"'
    }
}
