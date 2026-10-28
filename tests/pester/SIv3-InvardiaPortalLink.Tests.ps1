#Requires -Version 5.1
<#
    #710 -- THE CUSTOMER MAIL LINKS STRAIGHT TO THE INSTALL'S PAGE IN THE INVARDIA PORTAL (framework 8.16 "Order and links",
    Invardia 1.0.488: every identified uplink answer is 202 { environmentId }). Owner 2026-10-16: ONE line under the summary,
    "See details and history: <portal link>".

    What must hold:
      - the environmentId is read from Invardia's answer in any shape, only as a GUID (lower-case);
      - an identified run records an id it does not have yet ONCE per process (cfg.InstallState 'InvardiaEnvironment', on
        the Pro database the run has open), and the in-process facts carry it at once; anonymous never; the id already
        recorded = nothing written; a failing database never fails the run;
      - the run-start read (Read-SIInstallRingFacts) brings it back;
      - the line sits directly under the summary (the summary block every SI mail starts with since #728, the Risk Analysis
        mail's included), HTML and text, HTML-encoded; no id / not a GUID / no summary = no line; never twice; never in a mail
        that carries a one-time secret (-NoPdf);
      - Send-SIMail adds it from the environment (Get-SIMailEnvironment reads the recorded id);
      - wiring: the Risk Analysis mail (ConvertTo-RAReportMailHtml) starts with the summary block the line goes under;
      - owner 2026-10-16 ("Add to both"): the daily close-loop mail and the management summary have no summary -- they
        carry the line at their TOP (a place-holder the transport fills only when the id is known, removed otherwise),
        same rules: once, HTML-encoded, no id = no line.
    Offline -- every post, mail and database call is a fake.
#>

BeforeDiscovery {
    # the close-loop and exemption mails are Pro (engine\asset-cmdb): their Describe runs only where Test-Path finds them --
    # skipped in a Community copy, which has neither mail
    $script:HasCloseLoopMail = Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1')
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-MailTransport.ps1')
    $script:Env = '6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b'
    $script:Env2 = '6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4c'
    $script:Url = 'https://portal.invardia.com/#/environments/' + $script:Env
    $script:Tenant = '11111111-2222-3333-4444-555555555555'
    $script:T0 = [datetime]::new(2026, 10, 16, 6, 0, 0, [DateTimeKind]::Utc)
    function script:New-Ctx([string]$Mode = 'identified') {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://uplink.test'; AccessCode = $(if ($Mode -eq 'anonymous') { 'community' } else { 'inv-TESTKEY-0123456789' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = 'valid'; Version = '3.0.0'; Hosting = 'container'
                           RuntimeIdentity = 'mi-container'; InstallId = $(if ($Mode -eq 'anonymous') { '0f0e0d0c-0b0a-4908-8706-050403020100' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { $script:Tenant }); StateDirectory = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))); LicenceId = '' }
    }
    function script:New-Rc { [pscustomobject]@{ Engine = 'endpoint'; ShardIndex = 0; StartedAt = $script:T0.AddMinutes(-5) } }
    function script:New-Capture([string]$EnvironmentId = '') {
        $c = @{ List = (New-Object System.Collections.Generic.List[object]); Env = $EnvironmentId; Seen = (New-Object System.Collections.Generic.List[string]) }
        $c.Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $c.List.Add($Record); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted'; SupersededBy = ''; EnvironmentId = $c.Env } }.GetNewClosure()
        $c.On = { param($id) $c.Seen.Add($id) }.GetNewClosure()
        $c
    }
    function script:New-FakeStore([object[]]$Rows = @(), [switch]$Throw) {
        $s = @{ Sql = (New-Object System.Collections.Generic.List[object]); Rows = $Rows; Throw = [bool]$Throw }
        $s.Invoke = { param($sql, $p, $mode) if ($s.Throw) { throw 'Login failed for user' }; $s.Sql.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode }); if ($mode -eq 'reader') { , $s.Rows } }.GetNewClosure()
        $s
    }
    function script:Reset-Telemetry { $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $global:SI_ProSettingsStore = $null; $global:SI_InstallRingFacts = $null }
    function script:New-Facts([string]$Value = '') { [pscustomobject]@{ UpdateState = ''; Ring = ''; Endpoints = ''; PipelineSchedule = ''; SecretHandover = ''; InvardiaEnvironment = $Value } }
    # a MAIL-2 mail with a summary, and one without
    $script:WithSummary = (New-SIMailLayout -Title 'Run finished' -Summary 'Everything ran.' -Paragraphs @('Detail paragraph.')).Html
    $script:NoSummary = (New-SIMailLayout -Title 'Notice' -Paragraphs @('Only a paragraph.')).Html
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $global:SI_ProSettingsStore = $null; $global:SI_InstallRingFacts = $null
}

Describe 'the environment id and the portal link' {
    It 'environmentId is read from the answer in any shape, only as a lower-case GUID' {
        Get-SIInvardiaEnvironmentIdFromAnswer ([pscustomobject]@{ environmentId = $script:Env }) | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromAnswer ('{"environmentId":"' + $script:Env.ToUpperInvariant() + '"}') | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromAnswer @{ environmentId = $script:Env; supersededBy = $script:Env2 } | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromAnswer '' | Should -Be ''
        Get-SIInvardiaEnvironmentIdFromAnswer $null | Should -Be ''
        Get-SIInvardiaEnvironmentIdFromAnswer ([pscustomobject]@{ environmentId = 'env-1"><script>' }) | Should -Be ''
        Get-SIInvardiaEnvironmentIdFromAnswer ([pscustomobject]@{ supersededBy = $script:Env }) | Should -Be ''
    }
    It 'the URL is the install''s page in the Invardia customer portal; no GUID = no URL' {
        Get-SIInvardiaPortalUrl $script:Env | Should -Be $script:Url
        Get-SIInvardiaPortalUrl $script:Env.ToUpperInvariant() | Should -Be $script:Url
        Get-SIInvardiaPortalUrl '' | Should -Be ''
        Get-SIInvardiaPortalUrl 'javascript:alert(1)' | Should -Be ''
    }
    It 'the stored value round-trips (JSON or a bare GUID); anything else is no id' {
        $v = ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env -NowUtc $script:T0
        $v.Length | Should -BeLessOrEqual 400
        ($v | ConvertFrom-Json).environmentId | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromValue $v | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromValue $script:Env | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdFromValue 'garbage' | Should -Be ''
        { ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId 'nope' } | Should -Throw
    }
}

Describe 'the line under the summary' {
    It 'MAIL-2 summary box: the line follows it, before the rest; HTML-encoded; text "See details and history: <url>"' {
        $h = Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId $script:Env
        $h | Should -Match 'data-si-portal-link'
        $sumEnd = $h.IndexOf('</div>', $h.IndexOf('data-mail-summary'))
        $at = $h.IndexOf('data-si-portal-link')
        $at | Should -BeGreaterThan $sumEnd
        $at | Should -BeLessThan $h.IndexOf('Detail paragraph.')
        # the href is HTML-encoded: the '#' stays, nothing raw from outside (the id is a validated GUID)
        $h | Should -Match ([regex]::Escape('See details and history: <a href="' + [System.Net.WebUtility]::HtmlEncode($script:Url) + '"'))
        $t = ConvertTo-SIMailText -Html $h
        $t | Should -Match ([regex]::Escape('See details and history: ' + $script:Url))
        # the line stands on its own between the summary and the detail
        $t.IndexOf('Everything ran.') | Should -BeLessThan $t.IndexOf('See details and history:')
        $t.IndexOf('See details and history:') | Should -BeLessThan $t.IndexOf('Detail paragraph.')
    }
    It 'the web app''s summary block (MailBrand.Summary shape, a div since #728) gets it too' {
        $wb = '<html><body><div data-mail-summary style="margin:0 0 18px 0;"><p style="margin:0;"><strong>Open:</strong> 3</p></div><p style="margin:0 0 14px 0;">Body.</p></body></html>'
        $h = Add-SIInvardiaPortalLink -BodyHtml $wb -EnvironmentId $script:Env
        $h.IndexOf('data-si-portal-link') | Should -BeGreaterThan $h.IndexOf('</div>')
        $h.IndexOf('data-si-portal-link') | Should -BeLessThan $h.IndexOf('Body.')
    }
    It 'a mail queued by an older web app (a table summary box) gets it too' {
        $wb = '<html><body><table cellpadding="0" style="margin:4px 0 12px 0;" data-mail-summary><tr><td><div>Open</div><div>3</div></td></tr></table><p style="margin:0 0 14px 0;">Body.</p></body></html>'
        $h = Add-SIInvardiaPortalLink -BodyHtml $wb -EnvironmentId $script:Env
        $h.IndexOf('data-si-portal-link') | Should -BeGreaterThan $h.IndexOf('</table>')
        $h.IndexOf('data-si-portal-link') | Should -BeLessThan $h.IndexOf('Body.')
    }
    It 'no id, an id that is not a GUID, or a mail without a summary: the body is unchanged' {
        Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId '' | Should -Be $script:WithSummary
        Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId $null | Should -Be $script:WithSummary
        Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId '<b>x</b>' | Should -Be $script:WithSummary
        Add-SIInvardiaPortalLink -BodyHtml $script:NoSummary -EnvironmentId $script:Env | Should -Be $script:NoSummary
        Add-SIInvardiaPortalLink -BodyHtml '' -EnvironmentId $script:Env | Should -Be ''
    }
    It 'never twice' {
        $once = Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId $script:Env
        $twice = Add-SIInvardiaPortalLink -BodyHtml $once -EnvironmentId $script:Env
        $twice | Should -Be $once
        ([regex]::Matches($twice, 'data-si-portal-link')).Count | Should -Be 1
    }
    It 'no internal numbers in the line: only the wording and the portal URL' {
        $line = Get-SIInvardiaPortalLinkHtml $script:Env
        $t = ConvertTo-SIMailText -Html $line
        $t | Should -Be ('See details and history: ' + $script:Url)
    }
}

Describe 'the Risk Analysis mail (its body: ConvertTo-RAReportMailHtml, RA-ReportMail.ps1)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        # #636: the protection score (both views) replaced the old 0-100 KPI in the mail
        $prot = [pscustomobject]@{ Technical = 50.4; Lifecycle = 53.7; TechnicalGood = 500; LifecycleGood = 540; Assets = 1000; NoDate = 12; Findings = 300
            Grace = @{ device = 30; identity = 30; cloud_resource = 30; public_ip = 30 }
            Rows = @([pscustomobject]@{ Figure = 'lifecycle'; Dim1 = 'Devices'; Dim2 = '(all)'; Value = 85.1; Assets = 400; Total = 470 }, [pscustomobject]@{ Figure = 'technical'; Dim1 = 'Devices'; Dim2 = '(all)'; Value = 74.7; Assets = 350; Total = 470 }) }
        $kpi = [pscustomobject]@{ Protection = $prot; TotalRows = 1234
            SevCount = @{ Critical = 5; High = 40; Medium = 300; Low = 889 }
            SevByDomain = @{ Endpoint = @{ Critical = 3; High = 30; Medium = 200; Low = 667; Total = 900 }; Identity = @{ Critical = 2; High = 10; Medium = 100; Low = 222; Total = 334 }
                             Azure = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 }; PublicIP = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Total = 0 } } }
        $script:RaBody = ConvertTo-RAReportMailHtml -Kpi $kpi -ReportLabel 'RiskAnalysis_Detailed' -TenantTag 'contoso.example' -GeneratedAt '2026-10-17 06:00 +02:00' -SolutionVersion '3.0.0' -GrainNoteHtml 'The two reports count differently.'
    }
    It 'the mail starts with its summary block (wiring: the line has a summary to go under)' {
        $script:RaBody | Should -Match '<div data-mail-summary'
        $script:RaBody.IndexOf('data-mail-summary') | Should -BeLessThan $script:RaBody.IndexOf('Findings by domain')
    }
    It 'the line comes directly after the summary, before everything below it; one line, no table' {
        $h = Add-SIInvardiaPortalLink -BodyHtml $script:RaBody -EnvironmentId $script:Env
        ([regex]::Matches($h, 'data-si-portal-link')).Count | Should -Be 1
        # #827 (owner 2026-10-20): the two names, each value in its band's words
        $h | Should -Match ('(?s)Protection Score, within Accepted Lifecycle:</strong> <strong[^>]*>53\.7 % · Moderate</strong>.{1,200}Protection Score, Actual Risks:</strong> <strong[^>]*>50\.4 % · Moderate</strong>.*?</p></div><p data-si-portal-link="1"[^>]*>See details and history: <a href="' + [regex]::Escape($script:Url) + '"')
        $h.IndexOf('data-si-portal-link') | Should -BeLessThan $h.IndexOf('Findings by domain')
        $h.IndexOf('data-si-portal-link') | Should -BeLessThan $h.IndexOf('Protection Score by asset type')
        $h | Should -Match 'Devices.{0,80}85\.1 %</strong> within Accepted Lifecycle'
        $h | Should -Not -Match '/100'
        $h | Should -Not -Match '(?i)<(table|tr|td|th)\b'
        $t = ConvertTo-SIMailText -Html $h
        $t.IndexOf('Protection Score, within Accepted Lifecycle: 53.7 %') | Should -BeLessThan $t.IndexOf('See details and history:')
        $t.IndexOf('Protection Score, within Accepted Lifecycle: 53.7 %') | Should -BeGreaterOrEqual 0
        $t.IndexOf('See details and history:') | Should -BeLessThan $t.IndexOf('Findings by domain')
    }
    It 'the engine builds its mail with it' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match '\$bodyHtml = ConvertTo-RAReportMailHtml -Kpi \$kpi'
    }
    It 'the Risk Analysis mail is sent through Send-SIMail (where the line is added)' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match '\$__mailRes = Send-SIMail -Settings \$__mailSettings'
    }
}
Describe 'Send-SIMail adds it from the recorded id' {
    BeforeAll {
        function script:Send-Fake([string]$Body, $Facts, [switch]$NoPdf) {
            $sent = New-Object System.Collections.Generic.List[object]
            $http = { param($u, $t, $b) if (@($b.message.toRecipients).Count) { $sent.Add($b) }; [pscustomobject]@{ StatusCode = 202; Body = '' } }.GetNewClosure()
            $global:SI_InstallRingFacts = $Facts
            $envInfo = Get-SIMailEnvironment -Globals @{ SIWeb_EnvironmentName = 'Contoso'; SI_InstallRingFacts = $Facts }
            $settings = [pscustomobject]@{ Mode = 'sharedMailbox'; Off = $false; Problems = @(); SharedMailbox = 'si@contoso.example'; From = 'si@contoso.example'; MaxAttachmentMb = 3; Environment = $envInfo }
            $r = Send-SIMail -Settings $settings -To 'a@contoso.example' -Subject 'Run' -BodyHtml $Body -Http $http -TokenProvider { 'ey.x.y' } -PdfBuilder { [pscustomobject]@{ Bytes = $null; Error = 'no pdf in this test' } } -NoPdf:$NoPdf 6>$null
            [pscustomobject]@{ R = $r; Html = $(if ($sent.Count) { [string]$sent[0].message.body.content } else { '' }) }
        }
    }
    BeforeEach {
        Reset-Telemetry
        Mock -CommandName Get-SIMailRestriction -MockWith { [pscustomobject]@{ AllowsSend = $true; State = 'verified'; Detail = '' } }
    }
    It 'the environment carries the recorded id; none recorded = none' {
        (Get-SIMailEnvironment -Globals @{ SI_InstallRingFacts = (New-Facts (ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env)) }).InvardiaEnvironmentId | Should -Be $script:Env
        (Get-SIMailEnvironment -Globals @{ SI_InstallRingFacts = (New-Facts '') }).InvardiaEnvironmentId | Should -Be ''
        (Get-SIMailEnvironment -Globals @{}).InvardiaEnvironmentId | Should -Be ''
    }
    It 'a mail with a summary and a recorded id: the line in the HTML sent and in the text' {
        $x = Send-Fake -Body $script:WithSummary -Facts (New-Facts (ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env))
        $x.R.Sent | Should -BeTrue
        $x.Html | Should -Match 'data-si-portal-link'
        $x.R.Text | Should -Match ([regex]::Escape('See details and history: ' + $script:Url))
    }
    It 'no recorded id: no line (never a broken or a start-page link)' {
        $x = Send-Fake -Body $script:WithSummary -Facts (New-Facts '')
        $x.R.Sent | Should -BeTrue
        $x.Html | Should -Not -Match 'data-si-portal-link'
        $x.R.Text | Should -Not -Match 'See details and history'
        $x.Html | Should -Not -Match 'portal\.invardia\.com/#/environments'
    }
    It 'a mail that carries a one-time secret (-NoPdf, the sign-in mails) never gets it' {
        $x = Send-Fake -Body $script:WithSummary -Facts (New-Facts (ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env)) -NoPdf
        $x.Html | Should -Not -Match 'data-si-portal-link'
    }
}

Describe 'the two mails without a summary carry it at the TOP (owner 2026-10-16: "Add to both")' -Skip:(-not $script:HasCloseLoopMail) {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-cmdb\_shared\SI-ExemptionMail.ps1')
        $script:Until = [datetime]::new(2026, 10, 16, 6, 0, 0, [DateTimeKind]::Utc)
        function script:CloseLoopHtml([switch]$Changed) {
            $ev = if ($Changed) { , @(@{ EventId = 1; At = $script:Until.AddHours(-2); Action = 'Open'; Reason = 'Reported by SecurityInsight'; Cve = 'CVE-2026-0001'; AssetName = 'host-1'; CorrelationId = 'aid-1'; Severity = 'Critical'; FirstSeen = $script:Until.AddHours(-2); State = 'Open'; Tier = [byte]0 }) } else { , @() }
            $rep = Get-SICloseLoopMailReport -Events $ev -Open @() -Since $script:Until.AddHours(-24) -Until $script:Until -Top 15
            ConvertTo-SICloseLoopMailHtml -Report $rep -TenantTag 'contoso.example' -WebBaseUrl 'https://si.contoso.example' -Version '3.0.0'
        }
        # the management summary as the web app queues it (MgmtSummaryComposer + MailLayout.Normalize: no summary box)
        $script:MgmtBody = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body data-si-mail-layout="1" style="margin:0;padding:16px 24px;"><p style="font-size:12px;margin:0 0 12px 0;">Data: the Summary report''s figures.</p><h2>Risk score KPI</h2><p style="margin:0 0 14px 0;">The estate''s risk score is 71/100.</p></body></html>'
        function script:Send-Body([string]$Body, [string]$EnvironmentId) {
            $sent = New-Object System.Collections.Generic.List[object]
            $http = { param($u, $t, $b) if (@($b.message.toRecipients).Count) { $sent.Add($b) }; [pscustomobject]@{ StatusCode = 202; Body = '' } }.GetNewClosure()
            $v = if ($EnvironmentId) { ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $EnvironmentId } else { '' }
            $facts = New-Facts $v
            $global:SI_InstallRingFacts = $facts
            $envInfo = Get-SIMailEnvironment -Globals @{ SIWeb_EnvironmentName = 'Contoso'; SI_InstallRingFacts = $facts }
            $settings = [pscustomobject]@{ Mode = 'sharedMailbox'; Off = $false; Problems = @(); SharedMailbox = 'si@contoso.example'; From = 'si@contoso.example'; MaxAttachmentMb = 3; Environment = $envInfo }
            $r = Send-SIMail -Settings $settings -To 'a@contoso.example' -Subject 'Daily' -BodyHtml $Body -Http $http -TokenProvider { 'ey.x.y' } -PdfBuilder { [pscustomobject]@{ Bytes = $null; Error = 'no pdf in this test' } } 6>$null
            [pscustomobject]@{ R = $r; Html = $(if ($sent.Count) { [string]$sent[0].message.body.content } else { '' }) }
        }
    }
    BeforeEach {
        Reset-Telemetry
        Mock -CommandName Get-SIMailRestriction -MockWith { [pscustomobject]@{ AllowsSend = $true; State = 'verified'; Detail = '' } }
    }

    It 'the daily close-loop mail has the place-holder right under its banner, above its summary (quiet day and a day with changes)' {
        foreach ($h in @((CloseLoopHtml), (CloseLoopHtml -Changed))) {
            ([regex]::Matches($h, [regex]::Escape('<!-- SI portal link -->'))).Count | Should -Be 1
            $h | Should -Not -Match 'SI portal link row'
            $at = $h.IndexOf('<!-- SI portal link -->')
            $at | Should -BeGreaterThan $h.IndexOf('Vulnerability close-loop')
            $at | Should -BeLessThan $h.IndexOf('data-close-loop-summary')
            $at | Should -BeLessThan $h.IndexOf('Open the close-loop page')
            # #728: its summary is not a data-mail-summary block -- that would move the line under the summary
            $h | Should -Not -Match 'data-mail-summary'
        }
        $q = CloseLoopHtml
        $q.IndexOf('<!-- SI portal link -->') | Should -BeLessThan $q.IndexOf('Nothing changed in the last 24 hours')
    }
    It 'the daily close-loop mail, id known: ONE line at the top, a paragraph of its own (no table row), HTML-encoded, in the text first' {
        foreach ($b in @((CloseLoopHtml), (CloseLoopHtml -Changed))) {
            $x = Send-Body -Body $b -EnvironmentId $script:Env
            $x.R.Sent | Should -BeTrue
            ([regex]::Matches($x.Html, 'data-si-portal-link')).Count | Should -Be 1
            $x.Html | Should -Match ('(?s)<p data-si-portal-link="1"[^>]*>See details and history: <a href="' + [regex]::Escape([System.Net.WebUtility]::HtmlEncode($script:Url)) + '"[^>]*>[^<]*</a></p>\s*<div data-close-loop-summary')
            $x.Html | Should -Not -Match '(?i)<(table|tr|td)\b'
            $x.Html | Should -Not -Match 'SI portal link'
            $x.R.Text | Should -Match ([regex]::Escape('See details and history: ' + $script:Url))
            $x.R.Text.IndexOf('See details and history:') | Should -BeLessThan $x.R.Text.IndexOf('Open the close-loop page')
        }
        $q = Send-Body -Body (CloseLoopHtml) -EnvironmentId $script:Env
        $q.R.Text.IndexOf('See details and history:') | Should -BeLessThan $q.R.Text.IndexOf('Nothing changed in the last 24 hours')
    }
    It 'the daily close-loop mail, no id: no line and no place-holder sent' {
        $x = Send-Body -Body (CloseLoopHtml -Changed) -EnvironmentId ''
        $x.R.Sent | Should -BeTrue
        $x.Html | Should -Not -Match 'data-si-portal-link'
        $x.Html | Should -Not -Match 'SI portal link'
        $x.R.Text | Should -Not -Match 'See details and history'
    }
    It 'the close-loop job sends the daily mail through Send-SICloseLoopMail -> Send-SIMail (wiring)' {
        $job = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-cmdb\Invoke-SICloseLoopMail.ps1'))
        $job | Should -Match ([regex]::Escape('[void](Send-SICloseLoopMail -Smtp $smtp -To $to -Subject $subject -BodyHtml $html)'))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-cmdb\_shared\SI-CloseLoopMail.ps1')) | Should -Match '\$r = Send-SIMail -Settings \$Smtp'
    }

    It 'the management summary: the place-holder goes right after <body> -- once, never into a mail with a summary' {
        $a = Add-SIInvardiaPortalLinkAnchor -BodyHtml $script:MgmtBody
        $a | Should -Match ([regex]::Escape('style="margin:0;padding:16px 24px;"><!-- SI portal link --><p'))
        Add-SIInvardiaPortalLinkAnchor -BodyHtml $a | Should -Be $a
        Add-SIInvardiaPortalLinkAnchor -BodyHtml '<p>kpi</p>' | Should -Be '<!-- SI portal link --><p>kpi</p>'
        Add-SIInvardiaPortalLinkAnchor -BodyHtml '' | Should -Be ''
        # the get-started reminder (same outbox) has a summary box: the line stays under it
        Add-SIInvardiaPortalLinkAnchor -BodyHtml $script:WithSummary | Should -Be $script:WithSummary
        $line = Add-SIInvardiaPortalLink -BodyHtml $script:WithSummary -EnvironmentId $script:Env
        Add-SIInvardiaPortalLinkAnchor -BodyHtml $line | Should -Be $line
    }
    It 'the management summary, id known: ONE line at the top, before the data line; no id: none' {
        $x = Send-Body -Body (Add-SIInvardiaPortalLinkAnchor -BodyHtml $script:MgmtBody) -EnvironmentId $script:Env
        ([regex]::Matches($x.Html, 'data-si-portal-link')).Count | Should -Be 1
        $x.Html.IndexOf('data-si-portal-link') | Should -BeLessThan $x.Html.IndexOf('Data: the Summary report')
        $x.Html | Should -Not -Match 'SI portal link'
        $x.R.Text | Should -Match ([regex]::Escape('See details and history: ' + $script:Url))
        $x.R.Text.IndexOf('See details and history:') | Should -BeLessThan $x.R.Text.IndexOf('Data: the Summary report')
        $n = Send-Body -Body (Add-SIInvardiaPortalLinkAnchor -BodyHtml $script:MgmtBody) -EnvironmentId ''
        $n.Html | Should -Not -Match 'data-si-portal-link'
        $n.Html | Should -Not -Match 'SI portal link'
    }
    It 'the mail job marks every queued management summary before it sends (wiring; the job itself: SIv3-ExemptionMail)' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-cmdb\_shared\SI-ExemptionMail.ps1')) | Should -Match ([regex]::Escape('$body = Add-SIInvardiaPortalLinkAnchor -BodyHtml ([string](Get-SIExemptionValue $p ''BodyHtml''))'))
    }
}

Describe 'the id is learnt from Invardia''s answer' {
    BeforeEach { Reset-Telemetry }
    It 'SI''s sender returns the environmentId of a 202 answer' {
        Mock -CommandName Invoke-RestMethod -MockWith { [pscustomobject]@{ environmentId = '6F1C2A3B-4D5E-4F60-8A7B-9C0D1E2F3A4B' } }
        $r = Send-SITelemetryUplink -Record @{ a = 1 } -Endpoint 'https://uplink.example.test/api/uplink/v1/report' -AccessCode 'inv-K'
        $r.Status | Should -Be 'ok'
        $r.EnvironmentId | Should -Be $script:Env
        Mock -CommandName Invoke-RestMethod -MockWith { $null }
        (Send-SITelemetryUplink -Record @{ a = 1 } -Endpoint 'https://uplink.example.test/api/uplink/v1/report' -AccessCode 'inv-K').EnvironmentId | Should -Be ''
    }
    It 'an identified run records a new id ONCE per process, and the in-process facts carry it at once' {
        $global:SI_InstallRingFacts = New-Facts ''
        $c = New-Capture -EnvironmentId $script:Env
        $r = Send-SITelemetryRunEnd -RunContext (New-Rc) -ExitReason 'success' -Context (New-Ctx) -Transport $c.Transport -Now $script:T0 -HeartbeatCounts { @{} } -SetupCatalog ([pscustomobject]@{ steps = @(); findings = @(); controls = @() }) -OnEnvironment $c.On 6>$null
        $r.Status | Should -Be 'ok'
        $c.List.Count | Should -BeGreaterThan 1
        @($c.Seen) | Should -Be @($script:Env)
        Get-SIInvardiaEnvironmentIdKnown | Should -Be $script:Env
        (Get-SIMailEnvironment).InvardiaEnvironmentId | Should -Be $script:Env
    }
    It 'the id already recorded: nothing written' {
        $global:SI_InstallRingFacts = New-Facts (ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env)
        $c = New-Capture -EnvironmentId $script:Env
        $null = Send-SITelemetryRunEnd -RunContext (New-Rc) -ExitReason 'success' -Context (New-Ctx) -Transport $c.Transport -Now $script:T0 -OnEnvironment $c.On -NoHeartbeat
        $c.Seen.Count | Should -Be 0
    }
    It 'a different id (the environment was re-created) replaces it' {
        $global:SI_InstallRingFacts = New-Facts (ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env2)
        $c = New-Capture -EnvironmentId $script:Env
        $null = Send-SITelemetryRunEnd -RunContext (New-Rc) -ExitReason 'success' -Context (New-Ctx) -Transport $c.Transport -Now $script:T0 -OnEnvironment $c.On -NoHeartbeat
        @($c.Seen) | Should -Be @($script:Env)
        Get-SIInvardiaEnvironmentIdKnown | Should -Be $script:Env
    }
    It 'anonymous never; an answer without a GUID records nothing' {
        $c = New-Capture -EnvironmentId $script:Env
        $null = Send-SITelemetryRunEnd -RunContext (New-Rc) -ExitReason 'success' -Context (New-Ctx -Mode anonymous) -Transport $c.Transport -Now $script:T0 -OnEnvironment $c.On -NoHeartbeat
        $c.Seen.Count | Should -Be 0
        Reset-Telemetry
        $c2 = New-Capture -EnvironmentId 'env-42'
        $null = Send-SITelemetryRunEnd -RunContext (New-Rc) -ExitReason 'success' -Context (New-Ctx) -Transport $c2.Transport -Now $script:T0 -OnEnvironment $c2.On -NoHeartbeat
        $c2.Seen.Count | Should -Be 0
    }
    It 'by default on the Pro database the run has open -- a failing database never fails the run' {
        $store = New-FakeStore
        $global:SI_ProSettingsStore = $store
        (Invoke-SIInvardiaEnvironmentNotice -EnvironmentId $script:Env -NowUtc $script:T0) | Should -BeTrue
        $store.Sql.Count | Should -Be 1
        $store.Sql[0].Sql | Should -Match 'cfg\.InstallState'
        $store.Sql[0].P.Name | Should -Be 'InvardiaEnvironment'
        ($store.Sql[0].P.Value | ConvertFrom-Json).environmentId | Should -Be $script:Env
        $global:SI_ProSettingsStore = New-FakeStore -Throw
        { Invoke-SIInvardiaEnvironmentNotice -EnvironmentId $script:Env } | Should -Not -Throw
        (Invoke-SIInvardiaEnvironmentNotice -EnvironmentId $script:Env) | Should -BeFalse
        $global:SI_ProSettingsStore = $null
        (Invoke-SIInvardiaEnvironmentNotice -EnvironmentId $script:Env) | Should -BeFalse
        (Invoke-SIInvardiaEnvironmentNotice -EnvironmentId 'not-a-guid') | Should -BeFalse
    }
    It 'the facts the run-start read returns give the id back (the read itself: SIv3-InstallRing, a Pro suite)' {
        $v = ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $script:Env
        Get-SIInvardiaEnvironmentIdKnown -Facts (New-Facts $v) | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdKnown -Facts @{ InvardiaEnvironment = $v } | Should -Be $script:Env
        Get-SIInvardiaEnvironmentIdKnown -Facts (New-Facts '') | Should -Be ''
        Get-SIInvardiaEnvironmentIdKnown -Facts $null | Should -Be ''
    }
}
