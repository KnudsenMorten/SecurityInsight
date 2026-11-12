#Requires -Version 5.1
<#
    #1211 MAIL-ENV (framework 12.11a MAIL-ENV + 8.14 ENV-NAME-MASTER; owner, support: "What eng is this" / "In the mail I see
    only prod and not tailspin-prod") -- EVERY SecurityInsight mail names its environment BY HANDLE and its tenant:

        subject     [<KIND>] <handle>[ (<display name>)] - <severity word: ><what happened> [<ticket>] [SecurityInsight]
        first line  the same text, the first line of the body
        tenant line Tenant: <name> (<tenant id>)          (a sign-in mail keeps only the first line)

    Built in ONE place (engine\_shared\SI-MailEnvironment.ps1, called by Send-SIMail, the only sender -- the web app queues
    its mails in an outbox that the close-loop job sends through Send-SIMail). What these tests keep true:
      * the handle and the kind tag (Production -> PROD) in the subject and the first line;
      * the display name only when it differs from the handle and says more ("PROD" next to "tailspin-prod" says nothing);
      * the tenant line (name + id), Invardia's tenant id when the settings have none;
      * NO KEY (a Community install without the opt-in): the configured name stands in, and nothing calls Invardia;
      * INVARDIA UNREACHABLE: the heartbeat keeps the last good handle; a mail read that fails keeps the value read last;
      * NEVER another customer's name: Invardia's customer / managedBy names are never kept nor shown;
      * GUARD: no mail leaves SecurityInsight except through Send-SIMail, which applies the prefix and the first line.
    Offline: no relay, no Graph, no Invardia.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name Invoke-SIInvardiaEnvironmentRead -ErrorAction SilentlyContinue)) { . (Join-Path $script:Root 'engine\_shared\SI-InvardiaEnvironment.ps1') }
    . (Join-Path $script:Root 'engine\_shared\SI-MailTransport.ps1')
    $script:Tid = '11111111-2222-3333-4444-555555555555'
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-12T06:00:00', [DateTimeKind]::Utc)
    $script:Answer = '{"environmentId":"e-1","environmentName":"PROD","kind":"Production","handle":"adatum-prod","tenantId":"' + $script:Tid + '","customer":{"name":"Fabrikam Holding"},"managedBy":{"name":"Northwind MSP"},"displayName":"PROD"}'
    function script:Rec([string]$Handle = 'adatum-prod', [string]$Kind = 'Production', [string]$Name = 'PROD', [string]$Display = '', [string]$TenantId = $script:Tid) {
        ([ordered]@{ name = $Name; id = 'e-1'; kind = $Kind; handle = $Handle; tenantId = $TenantId; displayName = $(if ($Display) { $Display } else { $null }); readUtc = '2026-11-12T05:30:00Z' } | ConvertTo-Json -Compress)
    }
    function script:EnvOf([hashtable]$Extra = @{}, $Record = (Rec)) {
        $g = @{ SIWeb_EnvironmentName = 'PROD'; SI_UpdateRing = 2; SI_ProSqlServer = 'sql.example' }
        if ($null -ne $Record) { $g.SI_MailInvardiaEnvironment = $Record }
        foreach ($k in $Extra.Keys) { $g[$k] = $Extra[$k] }
        Get-SIMailEnvironment -Globals $g
    }
    function script:New-FakeJwt { $enc = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject $o))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }; '{0}.{1}.sig' -f (& $enc @{ alg = 'none' }), (& $enc @{ roles = @(); tid = 't' }) }
    $script:Calls = New-Object System.Collections.ArrayList
    $calls = $script:Calls
    $script:Http = {
        param($u, $t, $b)
        [void]$calls.Add($b)
        $box = [uri]::UnescapeDataString(($u -replace '^https://graph.microsoft.com/v1.0/users/', '' -replace '/sendMail$', ''))
        if ($box -ne 'securityinsight@contoso.example') { return [pscustomobject]@{ StatusCode = 403; Body = '{"error":{"code":"ErrorAccessDenied","message":"denied"}}' } }
        if (-not @($b.message.toRecipients).Count) { return [pscustomobject]@{ StatusCode = 400; Body = '{"error":{"code":"ErrorInvalidRecipients","message":"recipient"}}' } }
        [pscustomobject]@{ StatusCode = 202; Body = '' }
    }.GetNewClosure()
    $script:MailG = @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'securityinsight@contoso.example'; SI_Mail_ProbeMailbox = 'someone@contoso.example'
                       SIWeb_EnvironmentName = 'PROD'; SI_UpdateRing = 2; SI_ProSqlServer = 'sql.example'; SIWeb_TenantName = 'Contoso'; SI_SPN_TenantId = $script:Tid
                       SI_MailInvardiaEnvironment = (Rec) }
    $global:SI_MailForwardMap = @{}
    function script:Send-Test([hashtable]$G = $script:MailG, [string]$Subject = 'Data quality alert', [switch]$NoPdf, [string]$Severity = 'Warning') {
        $script:SIMailRestrictionCache.Clear(); $script:Calls.Clear()
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $G) -To 'a@contoso.example' -Subject $Subject -BodyHtml '<p>Fewer rows than usual.</p>' -Severity $Severity `
                         -Http $script:Http -TokenProvider { New-FakeJwt } -NoPdf:$NoPdf -PdfBuilder { [pscustomobject]@{ Bytes = $null; Error = 'no pdf in this test' } } 6>$null
        $m = @($script:Calls | Where-Object { @($_.message.toRecipients).Count })[0].message
        [pscustomobject]@{ R = $r; Subject = [string]$m.subject; Html = [string]$m.body.content; Text = (ConvertTo-SIMailText -Html ([string]$m.body.content)) }
    }
}

AfterAll { Remove-Variable -Name SI_MailForwardMap -Scope Global -ErrorAction SilentlyContinue }

Describe 'the subject and the first line name the environment by handle' {
    It 'the kind tag: Production -> PROD, Test -> TEST, Development -> DEV; an unknown kind is no tag' {
        ConvertTo-SIMailKindTag 'Production' | Should -Be 'PROD'
        ConvertTo-SIMailKindTag 'Test' | Should -Be 'TEST'
        ConvertTo-SIMailKindTag 'Development' | Should -Be 'DEV'
        ConvertTo-SIMailKindTag 'customer' | Should -Be ''
        ConvertTo-SIMailKindTag $null | Should -Be ''
    }
    It 'subject: [PROD] adatum-prod - Warning: ... [SecurityInsight] (the display name "PROD" alone says nothing)' {
        $e = EnvOf
        Get-SIMailSubject -Subject 'Data quality alert' -Severity Warning -Environment $e | Should -Be '[PROD] adatum-prod - Warning: Data quality alert [SecurityInsight]'
        $s = Get-SIMailSubject -Subject 'Daily summary' -Environment $e
        $s | Should -Be '[PROD] adatum-prod - Daily summary [SecurityInsight]'
        Get-SIMailSubject -Subject $s -Environment $e | Should -Be $s -Because 'never wrapped twice'
    }
    It 'a row queued with the older "[<name>] " prefix is re-formatted, not wrapped' {
        Get-SIMailSubject -Subject '[PROD] Test mail' -Environment (EnvOf) | Should -Be '[PROD] adatum-prod - Test mail [SecurityInsight]'
    }
    It 'the sent mail: subject, FIRST LINE of the body = the subject, then the tenant line (name + id)' {
        $x = Send-Test
        $x.R.Sent | Should -BeTrue
        $x.Subject | Should -Be '[PROD] adatum-prod - Warning: Data quality alert [SecurityInsight]'
        $lines = @($x.Text -split "`r?`n" | Where-Object { $_.Trim() })
        $lines[0] | Should -Be $x.Subject
        $lines[1] | Should -Be ('Tenant: Contoso ({0})' -f $script:Tid)
        @([regex]::Matches($x.Html, 'data-si-mail-env=')).Count | Should -Be 1
    }
    It 'a sign-in mail (-NoPdf) stays short: the first line, no tenant line at the top' {
        $x = Send-Test -Subject 'Your sign-in link' -Severity '' -NoPdf
        $x.Subject | Should -Be '[PROD] adatum-prod - Your sign-in link [SecurityInsight]'
        @($x.Text -split "`r?`n" | Where-Object { $_.Trim() })[0] | Should -Be $x.Subject
        ([regex]::Match($x.Html, '(?s)<div data-si-mail-env=.*?</div>')).Value | Should -Not -Match 'Tenant:'
    }
    It 'the lines are added once and HTML-encoded' {
        $b = Add-SIMailEnvironmentLines -BodyHtml '<html><body><p>x</p></body></html>' -Subject '[PROD] adatum-prod - <b>x</b> & y' -Environment (EnvOf)
        $b | Should -Match '&lt;b&gt;x&lt;/b&gt; &amp; y'
        $b | Should -Match '^<html><body><div data-si-mail-env="1"'
        Add-SIMailEnvironmentLines -BodyHtml $b -Subject 'other' -Environment (EnvOf) | Should -Be $b
    }
}

Describe 'the display name only when it differs and says more' {
    It '<Why>' -ForEach @(
        @{ Why = 'differs and says more: shown';           H = 'contoso';      D = 'Contoso production'; Out = '[PROD] contoso (Contoso production) - Report [SecurityInsight]' }
        @{ Why = 'a part of the handle ("PROD"): left out'; H = 'tailspin-prod'; D = 'PROD';               Out = '[PROD] tailspin-prod - Report [SecurityInsight]' }
        @{ Why = 'the handle itself: left out';             H = 'adatum-prod';     D = 'ADATUM-PROD';           Out = '[PROD] adatum-prod - Report [SecurityInsight]' }
        @{ Why = 'the kind word alone: left out';           H = 'acme';         D = 'Production';         Out = '[PROD] acme - Report [SecurityInsight]' }
        @{ Why = 'none: left out';                          H = 'acme';         D = '';                   Out = '[PROD] acme - Report [SecurityInsight]' }
    ) {
        $rec = Rec -Handle $H -Name $(if ($D) { $D } else { 'x' }) -Display $D
        if (-not $D) { $rec = Rec -Handle $H -Name 'acme' }
        Get-SIMailSubject -Subject 'Report' -Environment (EnvOf -Record $rec) | Should -Be $Out
    }
    It 'a long display name is left to the body, so the subject keeps room (at most 120 characters)' {
        $e = EnvOf -Record (Rec -Handle 'contoso-lab-environment-number-one' -Display ('Contoso Production Security Operations ' * 3))
        $s = Get-SIMailSubject -Subject ('A long text ' * 20) -Environment $e
        $s | Should -Match '^\[PROD\] contoso-lab-environment-number-one - '
        $s.Length | Should -BeLessOrEqual 120
    }
}

Describe 'the tenant line' {
    It 'name + id; Invardia''s tenant id when the settings have none; Invardia''s display name when no tenant name is set' {
        (Get-SIMailEnvIdentity -Environment (EnvOf -Extra @{ SIWeb_TenantName = 'Contoso'; SI_SPN_TenantId = $script:Tid })).TenantLine | Should -Be "Tenant: Contoso ($($script:Tid))"
        (Get-SIMailEnvIdentity -Environment (EnvOf -Extra @{ SIWeb_TenantName = 'Contoso' })).TenantLine | Should -Be "Tenant: Contoso ($($script:Tid))"
        (Get-SIMailEnvIdentity -Environment (EnvOf -Record (Rec -Display 'Contoso production'))).TenantLine | Should -Be "Tenant: Contoso production ($($script:Tid))"
        (Get-SIMailEnvIdentity -Environment ([pscustomobject]@{ Name = 'x'; TenantId = $script:Tid })).TenantLine | Should -Be "Tenant: $($script:Tid)"
        (Get-SIMailEnvIdentity -Environment ([pscustomobject]@{ Name = 'x' })).TenantLine | Should -Be ''
    }
}

Describe 'NO KEY: a Community install without the opt-in' {
    It 'no kept record: the configured name stands in for the handle, no kind tag' {
        $e = EnvOf -Record $null -Extra @{ SIWeb_EnvironmentName = 'Contoso lab' }
        $e.Handle | Should -Be ''
        Get-SIMailSubject -Subject 'Report' -Environment $e | Should -Be 'Contoso lab - Report [SecurityInsight]'
        Get-SIMailSubject -Subject 'Report' -Environment (EnvOf -Record $null -Extra @{ SIWeb_EnvironmentName = $null; SI_InstallId = 'inv-1' }) | Should -Be 'Report [SecurityInsight]'
    }
    It 'the mail side never calls Invardia (no network call in the file); the heartbeat asks nothing without the key' {
        $src = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\SI-MailEnvironment.ps1'))
        $code = (($src -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match '(?i)Invoke-RestMethod|Invoke-WebRequest|HttpClient|Invoke-SIUpdateNowHttp|invardia\.com'
        $calls = New-Object System.Collections.ArrayList
        $http = { param($Uri, $Key) [void]$calls.Add($Uri); [pscustomobject]@{ Status = 200; Body = $script:Answer; Error = '' } }.GetNewClosure()
        $ctx = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://stub.example.test/api/uplink/v1/report'; AccessCode = '' }
        (Invoke-SIInvardiaEnvironmentRead -Context $ctx -Invoke { , @() } -Http $http).Status | Should -Be 'skipped'
        $calls.Count | Should -Be 0
    }
}

Describe 'INVARDIA UNREACHABLE: the last good value' {
    BeforeAll {
        function script:New-Store([string]$Value = $null) {
            $s = [pscustomobject]@{ Value = $Value; Saves = 0 }
            $inv = { param($sql, $p, $mode)
                if ($sql -match "SELECT Value FROM cfg\.InstallState WHERE Name = N'InvardiaEnvironment'") { if ($s.Value) { return , @(@{ Value = $s.Value }) }; return , @() }
                if ($sql -match 'SELECT @n AS Saved') { $s.Saves++; $s.Value = $p.Value; return , @(@{ Saved = 1 }) }
                , @() }.GetNewClosure()
            $s | Add-Member -NotePropertyName Invoke -NotePropertyValue $inv
            $s
        }
        $script:Ctx = [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/api/uplink/v1/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' }
    }
    It 'the heartbeat keeps the handle, the kind and the tenant id; a failed read leaves them as they were' {
        $st = New-Store
        $ok = { param($Uri, $Key) [pscustomobject]@{ Status = 200; Body = $script:Answer; Error = '' } }
        (Invoke-SIInvardiaEnvironmentRead -Context $script:Ctx -Invoke $st.Invoke -Http $ok -Now $script:Now).Status | Should -Be 'read'
        $kept = $st.Value
        $j = $kept | ConvertFrom-Json
        $j.handle | Should -Be 'adatum-prod'; $j.kind | Should -Be 'Production'; $j.tenantId | Should -Be $script:Tid
        foreach ($bad in @({ param($Uri, $Key) throw 'network down' }, { param($Uri, $Key) [pscustomobject]@{ Status = 503; Body = ''; Error = '' } })) {
            (Invoke-SIInvardiaEnvironmentRead -Context $script:Ctx -Invoke $st.Invoke -Http $bad -Now $script:Now).Status | Should -Be 'kept'
            $st.Value | Should -Be $kept
        }
        (Get-SIMailInvardiaRecord -Invoke $st.Invoke -NoCache).Handle | Should -Be 'adatum-prod' -Because 'the mail reads the kept row'
    }
    It 'the mail side: a database read that fails keeps the value this process read last' {
        $script:SIMailEnvCache = $null
        $good = { param($sql, $p, $mode) , @(@{ Value = (Rec -Handle 'adatum-prod') }) }
        (Get-SIMailInvardiaRecord -Invoke $good -NoCache).Handle | Should -Be 'adatum-prod'
        (Get-SIMailInvardiaRecord -Invoke { param($sql, $p, $mode) throw 'SQL down' } -NoCache).Handle | Should -Be 'adatum-prod'
        (Get-SIMailInvardiaRecord -Invoke { param($sql, $p, $mode) , @() } -NoCache).Handle | Should -Be 'adatum-prod' -Because 'a row that is gone never blanks it'
        $script:SIMailEnvCache = $null
    }
    It 'an older kept row (name / kind only) still reads; the configured name stands in for the missing handle' {
        $e = EnvOf -Record '{"name":"Contoso production","id":"e-1","kind":"Production","readUtc":"2026-11-08T09:00:00Z"}' -Extra @{ SIWeb_EnvironmentName = 'Contoso' }
        Get-SIMailSubject -Subject 'Report' -Environment $e | Should -Be '[PROD] Contoso (Contoso production) - Report [SecurityInsight]'
    }
}

Describe 'NEVER another customer''s name' {
    It 'Invardia''s customer and managedBy names are never kept, never in a subject, never in a body' {
        $env = ConvertFrom-SIInvardiaEnvironment -Body $script:Answer
        $v = New-SIInvardiaEnvironmentStateValue -Environment $env -ReadUtc $script:Now
        $v | Should -Match '"handle":"adatum-prod"'
        $v | Should -Not -Match 'Fabrikam|Northwind'
        $r = ConvertFrom-SIMailInvardiaRecord $script:Answer
        ($r | ConvertTo-Json -Compress) | Should -Not -Match 'Fabrikam|Northwind'
        $g = @{} + $script:MailG; $g.SI_MailInvardiaEnvironment = $script:Answer
        $x = Send-Test -G $g
        $x.Subject | Should -Not -Match 'Fabrikam|Northwind'
        $x.Html | Should -Not -Match 'Fabrikam|Northwind'
    }
    It 'the kept value still fits cfg.InstallState (400 characters) and keeps the handle longest' {
        $big = [pscustomobject]@{ Name = ("<'&>" * 50); Id = ('x' * 64); Kind = 'Production'; Handle = 'adatum-prod'; TenantId = $script:Tid; DisplayName = ('d' * 200) }
        $v = New-SIInvardiaEnvironmentStateValue -Environment $big -ReadUtc $script:Now
        $v.Length | Should -BeLessOrEqual 400
        ($v | ConvertFrom-Json).handle | Should -Be 'adatum-prod'
    }
}

Describe 'GUARD: every mail goes through the one prefix' {
    BeforeAll {
        $script:Ps = @(Get-ChildItem -Path $script:Root -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notmatch '[\\/](tests|\.git|node_modules|bin|obj)[\\/]' })
        function script:Rel($f) { $f.FullName.Substring($script:Root.Length + 1).Replace('/', '\') }
        function script:Code($f) { ((Get-Content -LiteralPath $f.FullName) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
    }
    It 'Send-SIMail builds the subject and the first lines BEFORE any transport' {
        $t = Code (Get-Item (Join-Path $script:Root 'engine\_shared\SI-MailTransport.ps1'))
        $subj = $t.IndexOf('$Subject = Get-SIMailSubject -Subject $Subject -Environment $envInfo')
        $lines = $t.IndexOf('$BodyHtml = Add-SIMailEnvironmentLines -BodyHtml $BodyHtml -Subject $Subject -Environment $envInfo -Short:$NoPdf')
        $graph = $t.IndexOf('$resp = & $Http (''https://graph.microsoft.com/v1.0/users/{0}/sendMail''')
        $smtp = $t.IndexOf('$out = @(Send-MailAnonymous @smtpArgs)')
        foreach ($i in $subj, $lines, $graph, $smtp) { $i | Should -BeGreaterThan 0 }
        $subj | Should -BeLessThan $lines
        $lines | Should -BeLessThan $graph
        $lines | Should -BeLessThan $smtp
        (Code (Get-Item (Join-Path $script:Root 'engine\_shared\SI-MailEnvironment.ps1'))) | Should -Match 'function Get-SIMailEnvIdentity'
        $t | Should -Match '\$prefix = \(Get-SIMailEnvIdentity -Environment \$Environment\)\.Prefix'
    }
    It 'no other PowerShell file sends a Graph mail (only the transport names the sendMail route)' {
        $hits = @($script:Ps | Where-Object { (Code $_) -match '(?i)/sendMail\b' } | ForEach-Object { Rel $_ })
        $hits | Should -Contain 'engine\_shared\SI-MailTransport.ps1' -Because 'a green scan must have scanned something'
        @($hits | Where-Object { $_ -ne 'engine\_shared\SI-MailTransport.ps1' }) | Should -BeNullOrEmpty
    }
    It 'the setup script''s own test mail (an admin''s check while the mail is set up, before the install can name itself) is the one known exception' {
        $c = Code (Get-Item (Join-Path $script:Root 'setup\Set-SIMail.ps1'))
        @([regex]::Matches($c, '(?<![-\w])Send-MailMessage\s+@')).Count | Should -Be 1
        $c | Should -Not -Match '(?i)/sendMail\b' -Because 'it never sends through Graph'
    }
    It 'the web app never sends a mail itself: every web mail is queued and sent by the close-loop job through Send-SIMail' {
        $cs = @(Get-ChildItem -Path (Join-Path $script:Root 'pro-management\src') -Recurse -Filter '*.cs' -File | Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' })
        $cs.Count | Should -BeGreaterThan 50
        @($cs | Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match '(?i)new\s+SmtpClient\(|MailKit|graph\.microsoft\.com/v1\.0/users/[^"]*/sendMail|\.SendMail\(' } | ForEach-Object { Rel $_ }) | Should -BeNullOrEmpty
    }
}
