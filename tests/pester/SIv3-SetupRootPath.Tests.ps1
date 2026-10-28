#Requires -Version 5.1
<#
    THE SERVER SETUP SIGNS IN THROUGH SETUP'S OWN CLIENT (#140, #305, #524).

    The phased v2 server setup this file first covered (its root path and its module check) is
    retired in v3 (#755); what stays checked is the unattended server setup: it loads setup\_shared\SI-SetupAzure.ps1
    (no PowerShell module), every sign-in -- a person, an app by secret and by certificate -- goes through
    Connect-SISetupAzure, and the Internal flavour (the AutomateIT platform module's sign-in) is refused and reads no
    platform global.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
}

Describe 'the unattended server setup loads its REST layer from setup\_shared (#305)' {
    It 'every sign-in goes through Connect-SISetupAzure: a person, an app by secret and by certificate' {
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1') | Should -BeTrue
        $u = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Setup-SecurityInsight-Unattended.ps1') -Raw
        $u | Should -Match ([regex]::Escape(". (Join-Path `$repoRoot 'setup\_shared\SI-SetupAzure.ps1')"))
        $u | Should -Match '-ApplicationId \$envApp -ClientSecret \$envSec'
        $u | Should -Match '-ApplicationId \$envApp -CertificateThumbprint \$envThumb'
        $u | Should -Match 'Connect-SISetupAzure -TenantId \$cfg\.Sub\.TenantId -SubscriptionId \$cfg\.Sub\.SubscriptionId -Force'
        $u | Should -Not -Match '(?m)^\s*Import-Module\s+(Az|AzLogDcrIngestPS|Microsoft\.Graph)'
    }
    It 'the Internal flavour is refused, and no platform global is read (#524)' {
        $u = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Setup-SecurityInsight-Unattended.ps1') -Raw
        $u | Should -Match "if \(\`$cfg\.Flavour -eq 'Internal'\) \{\s+throw `"The Internal flavour"
        $u | Should -Not -Match 'Auth_Internal|HighPriv_|KV_HighPriv_|Connect-SIPlatform|AutomateITPS\.psd1'
    }
}
