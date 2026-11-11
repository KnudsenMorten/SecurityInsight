#Requires -Version 5.1
<#
    ONE LIST OF PEOPLE (#1172, owner 2026-11-10 at a customer: "it is a mesh" / "too complex") -- the engine half.

    The web app's list of people (Configuration > Reports and alerts) writes every report's OWN recipient list exactly,
    empties the default list (MailTo) and records who confirmed it (SIWeb_MailRecipientsConfirmed, handed to every job by
    the settings layer). What these tests keep true:
      * before the list is confirmed nothing changes: own list, else the older name, else the default list;
      * once confirmed, a report goes to its OWN list only -- nobody ticked = nobody, and the run is NOT stopped for it
        (Invoke-RiskAnalysis: the start check and the routing both honour it);
      * the confirmation reaches the jobs (it is one of the web settings the settings layer hands them);
      * the safety-check mail with nobody ticked and the default list emptied falls to the SuperAdmins (its safety net);
      * a new install never puts the person installing on any recipient list.
    Offline: no tenant.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-MailRecipients.ps1')
    $script:Ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
}

Describe 'Resolve-SIReportRecipients: a report''s recipients' {
    It 'before the list is confirmed: its own list, else the older name, else the default list (as always)' {
        @(Resolve-SIReportRecipients -Own @('own@contoso.example') -Legacy @('old@contoso.example') -Default @('all@contoso.example')) | Should -Be @('own@contoso.example')
        @(Resolve-SIReportRecipients -Own @() -Legacy @('old@contoso.example') -Default @('all@contoso.example')) | Should -Be @('old@contoso.example')
        @(Resolve-SIReportRecipients -Own $null -Legacy $null -Default @('all@contoso.example', '')) | Should -Be @('all@contoso.example')
    }
    It 'once confirmed: its OWN list only -- nobody ticked means NOBODY, never the default list (negative)' {
        @(Resolve-SIReportRecipients -Own @() -Legacy @('old@contoso.example') -Default @('all@contoso.example') -Exact $true).Count | Should -Be 0
        @(Resolve-SIReportRecipients -Own $null -Default @('all@contoso.example') -Exact $true).Count | Should -Be 0
        @(Resolve-SIReportRecipients -Own @('a@contoso.example; b@contoso.example', ' ') -Default @('all@contoso.example') -Exact $true) | Should -Be @('a@contoso.example', 'b@contoso.example')
    }
    It 'the confirmation is read from the setting the web app writes' {
        Test-SIMailRecipientsExact -Globals @{} | Should -BeFalse
        Test-SIMailRecipientsExact -Globals @{ SIWeb_MailRecipientsConfirmed = '   ' } | Should -BeFalse
        Test-SIMailRecipientsExact -Globals @{ SIWeb_MailRecipientsConfirmed = '2026-11-10T09:00:00Z|admin@contoso.example' } | Should -BeTrue
    }
}

Describe 'WIRING: the jobs see the confirmation and the Risk Analysis honours it' {
    BeforeAll { . (Join-Path $script:Root 'engine\pro-settings\SI-ProSettings.ps1') }
    It 'the settings layer hands SIWeb_MailRecipientsConfirmed to every job' {
        @(Get-SIProWebSettingsForEngines) | Should -Contain 'SIWeb_MailRecipientsConfirmed'
        $v = @(ConvertFrom-SIProWebSettingRows -Rows @([pscustomobject]@{ Name = 'SIWeb_MailRecipientsConfirmed'; Scope = 'engine:management-web'; ValueJson = '"2026-11-10T09:00:00Z|admin@contoso.example"' }))
        $v[0].Value | Should -Be '2026-11-10T09:00:00Z|admin@contoso.example'
    }
    It 'the Risk Analysis routing resolves the own list exactly once confirmed, and the default list only before' {
        $script:Ra | Should -Match 'SI-MailRecipients\.ps1'
        $script:Ra | Should -Match '\$__exactTo = \[bool\]\(Test-SIMailRecipientsExact\)'
        $script:Ra | Should -Match 'Resolve-SIReportRecipients -Own \$global:RiskAnalysis_Detailed_To -Exact \$true'
        $script:Ra | Should -Match 'Resolve-SIReportRecipients -Own \$global:RiskAnalysis_Summary_To -Exact \$true'
        $script:Ra | Should -Match 'if \(\$__detailedTo\.Count -gt 0 -or \$__exactTo\) \{ \$__detailedTo \}\s+else \{ @\(\$global:MailTo\) \}'
        $script:Ra | Should -Match 'if \(\$__summaryTo\.Count -gt 0 -or \$__exactTo\)\s+\{ \$__summaryTo \}\s+else \{ @\(\$global:MailTo\) \}'
    }
    It 'nobody ticked never stops the run once confirmed: the start check and the routing check both let it through' {
        $script:Ra | Should -Match '-not \$__hasPerTmplTo -and \[string\]::IsNullOrWhiteSpace\(\[string\]\$global:SIWeb_MailRecipientsConfirmed\)\)'
        $m = [regex]::Match($script:Ra, '(?s)if \(\$__exactTo\) \{\s+Write-Info "Mail: no one at your organisation is ticked for this report[^"]*"\s+\$global:Report_SendMail = \$false\s+\} else \{\s+throw "SendMail was enabled')
        $m.Success | Should -BeTrue -Because 'with the list confirmed, an empty list turns the mail off instead of throwing'
    }
}

Describe 'the safety-check mail once the default list is emptied' {
    BeforeAll { . (Join-Path $script:Root 'engine\_shared\SI-Guard.ps1') }
    It 'goes to the people ticked for it; with nobody ticked, to the SuperAdmins (its safety net) -- never an old default list' {
        (Get-SIGuardMailRecipients -Globals @{ SI_GuardMail_To = @('it@contoso.example'); MailTo = @() } -SuperAdminMails @('sa@contoso.example')).To | Should -Be @('it@contoso.example')
        $r = Get-SIGuardMailRecipients -Globals @{ SI_GuardMail_To = @(); MailTo = @() } -SuperAdminMails @('sa@contoso.example')
        @($r.To) | Should -Be @('sa@contoso.example')
        $r.Source | Should -Be 'SuperAdmins'
    }
}

Describe 'a new install never puts the person installing on a recipient list' {
    BeforeAll {
        . (Join-Path $script:Root 'setup\_shared\SI-GuidedInstall.ps1')
        $script:Gi = [IO.File]::ReadAllText((Join-Path $script:Root 'setup\_shared\SI-GuidedInstall.ps1'))
    }
    It 'no recipients given: no one -- not the signed-in installer' {
        $ctx = [pscustomobject]@{ Values = @{}; Facts = @{ userPrincipalName = 'installer@partner.example'; account = 'installer@partner.example' } }
        @(Get-SIInstallMailRecipients -Ctx $ctx).Count | Should -Be 0
        $ctx.Values['mailTo'] = @('soc@contoso.example')
        @(Get-SIInstallMailRecipients -Ctx $ctx) | Should -Be @('soc@contoso.example')
    }
    It 'the recipients function reads only the answer given for that purpose' {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Gi, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIInstallMailRecipients' }, $true) | Select-Object -First 1
        $fn | Should -Not -BeNullOrEmpty
        $fn.Body.Extent.Text | Should -Not -Match 'userPrincipalName|Facts\['
    }
    It 'no recipient list in the install is written from the installer''s sign-in' {
        $bad = @($script:Gi -split "`n" | Where-Object { $_ -match '(\[''(MailTo|[A-Za-z_]+_To)''\]\s*=|\b(MailTo|SummaryTo|DetailedTo)\s*=)' -and $_ -match 'userPrincipalName|Facts\[''account''\]' })
        $bad | Should -BeNullOrEmpty
    }
}
