#Requires -Version 5.1
<#
    MAIL-1 -- THE ONE MAIL TRANSPORT (engine\_shared\SI-MailTransport.ps1).

    What these tests keep true:
      * the mode: SI_Mail_Mode none | smtp | sharedMailbox (and its aliases); not set = smtp when SmtpServer is set
        (an existing install keeps working), else none; the install parameter mailMode, and the older bool 'mail';
      * the shared mailbox: the Graph sendMail request (URL, token, HTML body, To / Cc, importance, attachments,
        not saved to Sent Items), sent as SecurityInsight's own identity -- through a fake HTTP seam;
      * attachments: Graph takes at most 3 MB inline -- a larger file is left out and said, never a failed mail;
      * SecurityInsight REFUSES to send as the shared mailbox until the restriction is verified (a tenant-wide Graph
        Mail.Send, or a send as another mailbox that is allowed = unrestricted; nothing verified = unverified);
      * EVERY sender goes through Send-SIMail: no file but RA-Mail.ps1 (the SMTP transports) and the standalone
        setup\Set-SIMail.ps1 talks SMTP itself.
    Offline: no relay, no Graph -- seams replaced by fakes that record calls.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-MailTransport.ps1')
    function script:New-FakeJwt([string[]]$Roles = @()) {
        $enc = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -InputObject $o))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        '{0}.{1}.sig' -f (& $enc @{ alg = 'none' }), (& $enc @{ roles = $Roles; tid = 't' })
    }
    function script:New-Graph {
        <# A fake Graph: -Allowed = mailboxes the identity may send as; records every call. #>
        param([string[]]$Allowed = @(), [int]$SendStatus = 202)
        $calls = New-Object System.Collections.ArrayList
        $http = {
            param($u, $t, $b)
            [void]$calls.Add([pscustomobject]@{ Uri = $u; Token = $t; Body = $b })
            $box = [uri]::UnescapeDataString(($u -replace '^https://graph.microsoft.com/v1.0/users/', '' -replace '/sendMail$', ''))
            $probe = -not @($b.message.toRecipients).Count
            if ($Allowed -notcontains $box) { return [pscustomobject]@{ StatusCode = 403; Body = '{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}' } }
            if ($probe) { return [pscustomobject]@{ StatusCode = 400; Body = '{"error":{"code":"ErrorInvalidRecipients","message":"At least one recipient is not valid."}}' } }
            [pscustomobject]@{ StatusCode = $SendStatus; Body = $(if ($SendStatus -eq 202) { '' } else { '{"error":{"code":"ErrorQuotaExceeded","message":"quota"}}' }) }
        }.GetNewClosure()
        [pscustomobject]@{ Http = $http; Calls = $calls }
    }
    $script:Shared = @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'securityinsight@contoso.example'; SI_Mail_ProbeMailbox = 'someone@contoso.example' }
}

Describe 'the mode' {
    It '<V> / SmtpServer <S> -> <Mode> (<Source>)' -ForEach @(
        @{ V = 'sharedMailbox'; S = '';      Mode = 'sharedMailbox'; Source = 'setting' }
        @{ V = 'SHARED';        S = '';      Mode = 'sharedMailbox'; Source = 'setting' }
        @{ V = 'graph';         S = 'relay'; Mode = 'sharedMailbox'; Source = 'setting' }
        @{ V = 'smtp';          S = '';      Mode = 'smtp';          Source = 'setting' }
        @{ V = 'none';          S = 'relay'; Mode = 'none';          Source = 'setting' }
        @{ V = 'off';           S = '';      Mode = 'none';          Source = 'setting' }
        @{ V = '';              S = 'relay'; Mode = 'smtp';          Source = 'legacy-smtp' }
        @{ V = $null;           S = '';      Mode = 'none';          Source = 'default' }
    ) {
        $r = Resolve-SIMailMode -Value $V -SmtpServer $S
        $r.Mode | Should -Be $Mode
        $r.Source | Should -Be $Source
        $r.Problem | Should -BeNullOrEmpty
    }
    It 'an unknown mode is a problem, and sends nothing' {
        $r = Resolve-SIMailMode -Value 'carrier-pigeon' -SmtpServer 'relay'
        $r.Mode | Should -Be 'none'
        $r.Problem | Should -Match 'not one of none, smtp, sharedMailbox'
        (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'carrier-pigeon' }).Problems | Should -Match 'not one of'
    }
    It 'install: mailMode wins; else the older bool mail (true = smtp, false = none); else sharedMailbox' {
        Resolve-SIInstallMailMode -Values @{ mailMode = 'smtp'; mail = $false } | Should -Be 'smtp'
        Resolve-SIInstallMailMode -Values @{ mail = $true } | Should -Be 'smtp'
        Resolve-SIInstallMailMode -Values @{ mail = $false } | Should -Be 'none'
        Resolve-SIInstallMailMode -Values @{} | Should -Be 'sharedMailbox'
        Resolve-SIInstallMailMode -Values @{ mailMode = 'sharedMailbox' } | Should -Be 'sharedMailbox'
    }
}

Describe 'the settings' {
    It 'sharedMailbox: the mailbox is the sender, it must be set and be an address; attachments at most 3 MB' {
        $s = Get-SIMailSettings -Globals $script:Shared
        $s.Mode | Should -Be 'sharedMailbox'
        $s.From | Should -Be 'securityinsight@contoso.example'
        $s.SharedMailbox | Should -Be 'securityinsight@contoso.example'
        $s.MaxAttachmentMb | Should -Be 3
        @($s.Problems).Count | Should -Be 0
        (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'sharedMailbox' }).Problems | Should -Match 'SI_Mail_From'
        (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'not-an-address' }).Problems | Should -Match 'not a mail address'
    }
    It 'none on purpose is Off (not a problem); nothing set at all is a problem that says how to set it up' {
        $off = Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'none' }
        $off.Off | Should -BeTrue
        @($off.Problems).Count | Should -Be 0
        $unset = Get-SIMailSettings -Globals @{}
        $unset.Off | Should -BeFalse
        $unset.Problems | Should -Match 'Set-SIMail'
    }
    It 'smtp (an existing install, mode not set): the relay settings as before; SI_Mail_From wins over SMTPFrom' {
        $s = Get-SIMailSettings -Globals @{ SmtpServer = 'relay.example.invalid'; SMTPFrom = 'old@example.invalid'; SI_Mail_From = 'new@example.invalid' }
        $s.Mode | Should -Be 'smtp'; $s.ModeSource | Should -Be 'legacy-smtp'
        $s.Anonymous | Should -BeTrue; $s.Port | Should -Be 25
        $s.From | Should -Be 'new@example.invalid'
        $a = Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'smtp'; SmtpServer = 'relay.example.invalid'; SMTP_UseSSL = $true; SMTPUser = 'u'; Mail_SendAnonymous = $false }
        $a.Port | Should -Be 587
        $a.Problems | Should -Match 'SMTPPassword'
    }
}

Describe 'the Graph sendMail request' {
    It 'has the HTML body, To and Cc, importance, attachments as fileAttachment and is not saved to Sent Items' {
        $b = New-SIGraphSendMailBody -To @('a@x.example', ' ', 'b@x.example') -Cc @('c@x.example') -Subject 'S' -BodyHtml '<p>æøå</p>' -Priority High `
                -Attachments @(@{ Name = 'r.xlsx'; ContentType = 'application/x'; Bytes = [byte[]](1, 2, 3) })
        $b.saveToSentItems | Should -BeFalse
        $b.message.subject | Should -Be 'S'
        $b.message.body.contentType | Should -Be 'HTML'
        $b.message.body.content | Should -Be '<p>æøå</p>'
        @($b.message.toRecipients | ForEach-Object { $_.emailAddress.address }) | Should -Be @('a@x.example', 'b@x.example')
        $b.message.ccRecipients[0].emailAddress.address | Should -Be 'c@x.example'
        $b.message.importance | Should -Be 'high'
        $b.message.attachments[0].'@odata.type' | Should -Be '#microsoft.graph.fileAttachment'
        $b.message.attachments[0].contentBytes | Should -Be ([Convert]::ToBase64String([byte[]](1, 2, 3)))
        $json = ConvertTo-Json -InputObject $b -Depth 12 -Compress
        $json | Should -Match '"toRecipients":\['
    }
    It 'a verified shared mailbox: probes (no recipient), then POSTs /users/{mailbox}/sendMail with the identity''s token -> sent' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $s = Get-SIMailSettings -Globals $script:Shared
        $r = Send-SIMail -Settings $s -To 'a@contoso.example' -Subject 'Report' -BodyHtml '<b>x</b>' -Http $g.Http -TokenProvider { New-FakeJwt } 6>$null
        $r.Sent | Should -BeTrue
        $r.Restriction.State | Should -Be 'verified'
        $send = @($g.Calls | Where-Object { @($_.Body.message.toRecipients).Count })
        $send.Count | Should -Be 1
        $send[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/securityinsight%40contoso.example/sendMail'
        $send[0].Token | Should -Match '^ey'
        $send[0].Body.message.body.content | Should -Match '<b>x</b>.*<div data-si-mail-footer' -Because 'the body goes through the one mail layout (MAIL-2), then the footer'
        @($g.Calls | Where-Object { -not @($_.Body.message.toRecipients).Count }).Count | Should -Be 2 -Because 'the shared mailbox and the other mailbox are probed, with no recipient'
    }
    It 'a Graph refusal is a failed send with the reason, never a throw' {
        $script:SIMailRestrictionCache.Clear()
        $g = New-Graph -Allowed @('securityinsight@contoso.example') -SendStatus 503
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } 6>$null
        $r.Sent | Should -BeFalse
        $r.Error | Should -Match '503'
    }
}

Describe 'attachments through the shared mailbox' {
    BeforeAll {
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-mail-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp | Out-Null
        $script:Small = Join-Path $script:Tmp 'small.xlsx'; [IO.File]::WriteAllBytes($script:Small, [byte[]](1..200))
        $script:Big = Join-Path $script:Tmp 'big.xlsx'; [IO.File]::WriteAllBytes($script:Big, (New-Object byte[] (3MB)))
    }
    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    It 'the plan keeps what fits in the encoded budget and leaves out the rest' {
        $p = Get-SIMailAttachmentPlan -Paths @('a', 'b') -MaxMb 3 -SizeOf { param($x) if ($x -eq 'a') { 1MB } else { 2MB } }
        $p.Include | Should -Be @('a')
        $p.Dropped[0].Path | Should -Be 'b'
        $p.Dropped[0].EncodedMb | Should -Be 2.7
    }
    It 'a 3 MB workbook (~4.1 MB encoded) is left out; the small one goes, base64' {
        $script:SIMailRestrictionCache.Clear()
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'S' -BodyHtml 'x' -Attachments @($script:Small, $script:Big) -Http $g.Http -TokenProvider { New-FakeJwt } -NoPdf 6>$null
        $r.Sent | Should -BeTrue
        @($r.Dropped).Count | Should -Be 1
        $r.Dropped[0].Path | Should -Be $script:Big
        $att = @(@($g.Calls | Where-Object { @($_.Body.message.toRecipients).Count })[0].Body.message.attachments)
        $att.Count | Should -Be 1
        $att[0].name | Should -Be 'small.xlsx'
        $att[0].contentType | Should -Be 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
}

Describe 'refusal until the restriction is verified' {
    BeforeEach { $script:SIMailRestrictionCache.Clear() }
    It 'Mail.Send reaches another mailbox -> unrestricted: NOT sent, and says why' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example', 'someone@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } 6>$null
        $r.Sent | Should -BeFalse
        $r.Restriction.State | Should -Be 'unrestricted'
        $r.Error | Should -Match 'not restricted to the shared mailbox'
        @($g.Calls | Where-Object { @($_.Body.message.toRecipients).Count }).Count | Should -Be 0 -Because 'nothing is sent while unrestricted'
    }
    It 'a tenant-wide Graph Mail.Send and no other mailbox to prove a policy -> unrestricted' {
        $v = Get-SIMailRestrictionVerdict -TokenHasMailSend $true -Self 'allowed' -Other '' -Mailbox 'm' -ProbeMailbox ''
        $v.State | Should -Be 'unrestricted'; $v.AllowsSend | Should -BeFalse
        $v.Detail | Should -Match 'tenant-wide'
    }
    It 'a tenant-wide Mail.Send that an Application Access Policy restricts -> legacy-policy (sends, says move)' {
        $v = Get-SIMailRestrictionVerdict -TokenHasMailSend $true -Self 'allowed' -Other 'denied' -Mailbox 'm' -ProbeMailbox 'p'
        $v.State | Should -Be 'legacy-policy'; $v.AllowsSend | Should -BeTrue
    }
    It 'no role on the mailbox yet -> not-granted; attested -> verified' {
        (Get-SIMailRestrictionVerdict -Self 'denied' -Mailbox 'm').State | Should -Be 'not-granted'
        (Get-SIMailRestrictionVerdict -Self 'allowed' -Other '' -Mailbox 'm' -Attestation 'admin, 2026-10-07').State | Should -Be 'verified'
    }
    It 'owner 2026-10-19: no probe mailbox and NO tenant-wide Mail.Send -> verified by the token itself (the only send right is the scoped role)' {
        $v = Get-SIMailRestrictionVerdict -TokenHasMailSend $false -Self 'allowed' -Other '' -Mailbox 'm@x' -ProbeMailbox ''
        $v.State | Should -Be 'verified'; $v.AllowsSend | Should -BeTrue
        $v.Detail | Should -Be 'restricted by Exchange RBAC for Applications: the identity holds no tenant-wide Mail.Send; its only send right is the role scoped to m@x'
    }
    It 'a probe mailbox that does not exist never blocks sending: verified by the token, with one note' {
        $v = Get-SIMailRestrictionVerdict -TokenHasMailSend $false -Self 'allowed' -Other 'not-found' -Mailbox 'm@x' -ProbeMailbox 'gone@x'
        $v.State | Should -Be 'verified'; $v.AllowsSend | Should -BeTrue
        $v.Detail | Should -Match 'Exchange RBAC for Applications'
        $v.Detail | Should -Match ([regex]::Escape('the probe mailbox gone@x does not exist -- remove or correct SI_Mail_ProbeMailbox'))
        # a probe that answers 'denied' is still the stronger proof (unchanged)
        (Get-SIMailRestrictionVerdict -TokenHasMailSend $false -Self 'allowed' -Other 'denied' -Mailbox 'm' -ProbeMailbox 'p').Detail | Should -Match 'sending as p is refused'
        # a tenant-wide Mail.Send with a probe that cannot be used: unchanged (unrestricted, refused)
        (Get-SIMailRestrictionVerdict -TokenHasMailSend $true -Self 'allowed' -Other 'not-found' -Mailbox 'm' -ProbeMailbox 'gone@x').State | Should -Be 'unrestricted'
    }
    It 'without a test mailbox and without a tenant-wide Mail.Send the mail is SENT (the token proves the restriction)' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'securityinsight@contoso.example' }) -To 'a@x.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } -NoPdf 6>$null
        $r.Sent | Should -BeTrue
        $r.Restriction.State | Should -Be 'verified'
        $r.Restriction.Detail | Should -Match 'Exchange RBAC for Applications'
    }
    It 'without a test mailbox but WITH a tenant-wide Mail.Send the send is refused (unchanged)' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'securityinsight@contoso.example' }) -To 'a@x.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt -Roles @('Mail.Send') } 6>$null
        $r.Sent | Should -BeFalse
        $r.Restriction.State | Should -Be 'unrestricted'
    }
    It 'probe answers: 400 InvalidRecipients = allowed, 403 = denied, 404 = not-found' {
        Get-SIMailProbeVerdict -StatusCode 400 -Body '{"error":{"code":"ErrorInvalidRecipients","message":"x"}}' | Should -Be 'allowed'
        Get-SIMailProbeVerdict -StatusCode 403 -Body '{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}' | Should -Be 'denied'
        Get-SIMailProbeVerdict -StatusCode 404 -Body '{"error":{"code":"ErrorInvalidUser","message":"x"}}' | Should -Be 'not-found'
        Get-SIMailProbeVerdict -StatusCode 500 -Body 'boom' | Should -Be 'error'
    }
    It 'the status for the web app fits cfg.InstallState (400 characters) and is written with a MERGE' {
        $j = ConvertTo-SIMailRestrictionJson -Restriction ([pscustomobject]@{ State = 'unverified'; Detail = ('x' * 800); Mailbox = 'm@x.example'; CheckedUtc = '2026-10-07T10:00:00Z' })
        $j.Length | Should -BeLessOrEqual 400
        (ConvertFrom-Json $j).state | Should -Be 'unverified'
        $seen = New-Object System.Collections.ArrayList
        Write-SIMailRestrictionState -Invoke { param($sql, $p, $mode) [void]$seen.Add(@{ Sql = $sql; P = $p; Mode = $mode }) } -Restriction ([pscustomobject]@{ State = 'verified'; Detail = 'd'; Mailbox = 'm'; CheckedUtc = 'c' }) | Should -BeTrue
        $seen[0].Sql | Should -Match "MERGE cfg.InstallState"
        $seen[0].Sql | Should -Match "N'MailRestriction'"
    }
}

Describe '#719 every send leaves its outcome for the heartbeat (cfg.InstallState MailLastSent / MailLastFailed)' {
    BeforeEach {
        $script:SIMailRestrictionCache.Clear()
        $script:Rec = New-Object System.Collections.ArrayList
        $global:SI_MailSendRecordUnavailable = $null
        $global:SI_MailSendRecordInvoke = { param($sql, $p, $mode) [void]$script:Rec.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode }) }
    }
    AfterEach { $global:SI_MailSendRecordInvoke = $null; $global:SI_MailSendRecordUnavailable = $null }
    It 'a sent mail writes MailLastSent (a MERGE by key, the time and the mode -- no error)' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'Vulnerability close-loop' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } -NoPdf 6>$null
        $r.Sent | Should -BeTrue
        $script:Rec.Count | Should -Be 1
        $script:Rec[0].Sql | Should -Match 'MERGE cfg\.InstallState'
        $script:Rec[0].Mode | Should -Be 'nonquery'
        $script:Rec[0].P.Name | Should -Be 'MailLastSent'
        $v = ConvertFrom-Json $script:Rec[0].P.Value
        $v.mode | Should -Be 'sharedMailbox'
        $v.PSObject.Properties.Name | Should -Not -Contain 'error'
        $v.utc | Should -Not -BeNullOrEmpty
    }
    It 'a refused mail writes MailLastFailed with the error; the mail result is unchanged' {
        $g = New-Graph -Allowed @('securityinsight@contoso.example') -SendStatus 403
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } -NoPdf 6>$null
        $r.Sent | Should -BeFalse
        $script:Rec.Count | Should -Be 1
        $script:Rec[0].P.Name | Should -Be 'MailLastFailed'
        (ConvertFrom-Json $script:Rec[0].P.Value).error | Should -Match '403 \(Forbidden\)' -Because 'the status with its name, which the heartbeat classifies (graph-403)'
    }
    It 'a record that cannot be written never fails the mail; mail off records nothing' {
        $global:SI_MailSendRecordInvoke = { throw 'database unreachable' }
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        (Send-SIMail -Settings (Get-SIMailSettings -Globals $script:Shared) -To 'a@contoso.example' -Subject 'S' -BodyHtml 'x' -Http $g.Http -TokenProvider { New-FakeJwt } -NoPdf 6>$null).Sent | Should -BeTrue
        $global:SI_MailSendRecordInvoke = { param($sql, $p, $mode) [void]$script:Rec.Add($p) }
        $null = Send-SIMail -Settings (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'none' }) -To 'a@x.example' -Subject 'S' -BodyHtml 'x' 6>$null
        $script:Rec.Count | Should -Be 0
    }
    It 'no database in the job: no record, and no second attempt to open one in the process' {
        $global:SI_MailSendRecordInvoke = $null
        Get-SIMailSendRecordInvoke | Should -BeNullOrEmpty
        $global:SI_MailSendRecordUnavailable | Should -BeTrue
    }
    It 'the value fits cfg.InstallState (400 characters) however long the error' {
        $j = ConvertTo-SIMailSendRecordJson -Utc ([datetime]'2026-10-17T07:55:00Z').ToUniversalTime() -Mode 'smtp' -ErrorText ('relay said no ' * 80)
        $j.Length | Should -BeLessOrEqual 400
        (ConvertFrom-Json $j).error | Should -Match '^relay said no'
        $s = ConvertFrom-Json (ConvertTo-SIMailSendRecordJson -Utc ([datetime]::SpecifyKind([datetime]'2026-10-17T07:55:00', 'Utc')) -Mode 'smtp')
        "$($s.utc)" | Should -Not -BeNullOrEmpty
        (ConvertTo-SIMailSendRecordJson -Utc ([datetime]::SpecifyKind([datetime]'2026-10-17T07:55:00', 'Utc')) -Mode 'smtp') | Should -Match '"utc":"2026-10-17T07:55:00Z"'
    }
}

Describe 'mail off, and SMTP through the same function' {
    It 'Off: nothing is sent, not a failure that throws' {
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals @{ SI_Mail_Mode = 'none' }) -To 'a@x.example' -Subject 'S' -BodyHtml 'x' 6>$null
        $r.Sent | Should -BeFalse; $r.Off | Should -BeTrue
    }
    It 'smtp anonymous: Send-MailAnonymous with the relay settings; its last bool is the verdict' {
        $script:Relay = New-Object System.Collections.ArrayList
        function Send-MailAnonymous { param($SmtpServer, $Port, $UseSsl, $From, $To, $Subject, $BodyHtml, $Attachments, $Priority)
            [void]$script:Relay.Add(@{ Server = $SmtpServer; From = $From }); Write-Output 'line'; return $false }
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals @{ SmtpServer = 'relay.example.invalid'; SMTPFrom = 'si@example.invalid' }) -To 'a@x.example' -Subject 'S' -BodyHtml 'x' 6>$null
        $r.Sent | Should -BeFalse
        $script:Relay[0].Server | Should -Be 'relay.example.invalid'
    }
}

Describe 'every mail names its environment (subject prefix + footer, built once in the transport)' {
    BeforeAll {
        $script:EnvG = @{ SI_Mail_Mode = 'sharedMailbox'; SI_Mail_From = 'securityinsight@contoso.example'; SI_Mail_ProbeMailbox = 'someone@contoso.example'
                          SIWeb_EnvironmentName = 'Internal'; SI_UpdateRing = 1; SI_ProSqlServer = 'sql.example'; SIWeb_TenantName = 'Contoso'
                          SI_SPN_TenantId = '11111111-1111-1111-1111-111111111111'; SI_Version = '3.0.0.1'; SIWeb_PublicBaseUrl = 'https://si.contoso.example/' }
    }
    It 'the environment reads as the web app header shows it' {
        $e = Get-SIMailEnvironment -Globals $script:EnvG
        $e.Display | Should -Be 'Internal (ring 1, PRO)'
        $e.WebUrl | Should -Be 'https://si.contoso.example'
        (Get-SIMailEnvironment -Globals @{ SI_InstallId = 'inv-1' }).Display | Should -Be 'your SecurityInsight (COMMUNITY)'
        # #449 (ring 1, live): a name that already carries its brackets is shown once -- never "(ring 1, PRO) (PRO)"
        (Get-SIMailEnvironment -Globals @{ SIWeb_EnvironmentName = 'Internal (ring 1, PRO)'; SI_ProSqlServer = 'sql.example' }).Display | Should -Be 'Internal (ring 1, PRO)'
    }
    It 'subject prefix once; footer with environment, tenant name + id, solution + version and the link; inside the body element' {
        $e = Get-SIMailEnvironment -Globals $script:EnvG
        $s = Get-SIMailSubject -Subject 'Report' -Environment $e
        # MAIL-3 (#653): the name only in the subject (no ring, no edition -- they stay in the footer), the product last
        $s | Should -Be '[Internal] Report [SecurityInsight]'
        Get-SIMailSubject -Subject $s -Environment $e | Should -Be $s
        $b = Add-SIMailFooter -BodyHtml '<html><body><p>x</p></body></html>' -Environment $e
        $b | Should -Match 'Environment: <b>Internal \(ring 1, PRO\)</b>'
        $b | Should -Match 'Contoso \(11111111-1111-1111-1111-111111111111\)'
        $b | Should -Match 'SecurityInsight v3\.0\.0\.1'
        $b | Should -Match 'href="https://si\.contoso\.example"'
        $b | Should -Match 'data-si-mail-footer.*</body></html>$'
        $b | Should -Not -Match '(?i)this tenant'
        (Add-SIMailFooter -BodyHtml $b -Environment $e) | Should -Be $b
    }
    It 'the shared mailbox path sends it (Graph body + subject)' {
        $script:SIMailRestrictionCache.Clear()
        $g = New-Graph -Allowed @('securityinsight@contoso.example')
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $script:EnvG) -To 'a@contoso.example' -Subject 'Report' -BodyHtml '<p>x</p>' -Http $g.Http -TokenProvider { New-FakeJwt } 6>$null
        $r.Sent | Should -BeTrue
        $m = @($g.Calls | Where-Object { @($_.Body.message.toRecipients).Count })[0].Body.message
        $m.subject | Should -Be '[Internal] Report [SecurityInsight]'
        $m.body.content | Should -Match 'data-si-mail-footer'
    }
    It 'the SMTP path sends it too' {
        $script:Seen = $null
        function Send-MailAnonymous { param($SmtpServer, $Port, $UseSsl, $From, $To, $Subject, $BodyHtml, $Attachments, $Priority) $script:Seen = @{ S = $Subject; B = $BodyHtml }; return $true }
        $g2 = @{} + $script:EnvG; $g2.SI_Mail_Mode = 'smtp'; $g2.SmtpServer = 'relay.example.invalid'
        $r = Send-SIMail -Settings (Get-SIMailSettings -Globals $g2) -To 'a@x.example' -Subject 'Digest' -BodyHtml '<p>x</p>' 6>$null
        $r.Sent | Should -BeTrue
        $script:Seen.S | Should -Be '[Internal] Digest [SecurityInsight]'
        $script:Seen.B | Should -Match 'data-si-mail-footer'
    }
    It 'it is built in the transport, not per sender' {
        $t = Get-Content -Raw (Join-Path $script:Root 'engine\_shared\SI-MailTransport.ps1')
        $t | Should -Match '\$Subject = Get-SIMailSubject -Subject \$Subject -Environment \$envInfo -Severity \$Severity'
        $t | Should -Match '\$BodyHtml = Add-SIMailFooter -BodyHtml \$BodyHtml'
    }
}
Describe 'wiring: every sender goes through the one transport' {
    BeforeAll {
        $script:Ps = @(Get-ChildItem -Path $script:Root -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notmatch '[\\/](tests|\.git|node_modules|bin|obj)[\\/]' })
        function script:Rel($f) { $f.FullName.Substring($script:Root.Length + 1).Replace('/', '\') }
        function script:Code($f) { ((Get-Content -LiteralPath $f.FullName) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
    }
    It 'only RA-Mail.ps1 (the SMTP transports) and the standalone setup\Set-SIMail.ps1 call Send-MailMessage' {
        $hits = @($script:Ps | Where-Object { (Code $_) -match '(?<![-\w])Send-MailMessage\s+(-|@)' } | ForEach-Object { Rel $_ })
        @($hits | Where-Object { $_ -notin @('engine\risk-analysis\_shared\RA-Mail.ps1', 'setup\Set-SIMail.ps1') }) | Should -BeNullOrEmpty
        $hits | Should -Contain 'engine\risk-analysis\_shared\RA-Mail.ps1' -Because 'a green scan must have scanned something'
    }
    It 'only the transport calls Send-MailAnonymous / Send-MailSecure' {
        $hits = @($script:Ps | Where-Object { (Code $_) -match '(?<!function |-Name )\bSend-Mail(Anonymous|Secure)\s+(-|@)' } | ForEach-Object { Rel $_ })
        @($hits | Where-Object { $_ -ne 'engine\_shared\SI-MailTransport.ps1' }) | Should -BeNullOrEmpty
        $hits | Should -Contain 'engine\_shared\SI-MailTransport.ps1'
    }
    It 'nothing else talks SMTP (.NET SmtpClient / MailKit) in PowerShell' {
        @($script:Ps | Where-Object { (Code $_) -match '(?i)Net\.Mail\.SmtpClient|MailKit' } | ForEach-Object { Rel $_ }) | Should -BeNullOrEmpty
    }
    It 'the senders route through Send-SIMail (found by what they define, not by path)' {
        $def = { param($fn) @($script:Ps | Where-Object { (Code $_) -match ('(?m)^function {0}\b' -f [regex]::Escape($fn)) }) | Select-Object -First 1 }
        $guard = & $def 'Send-SIGuardMailDefault'
        $guard | Should -Not -BeNullOrEmpty
        (Code $guard) | Should -Match 'Send-SIMail -Settings \$Smtp'
        (Code (Get-Item (Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))) | Should -Match 'Send-SIMail -Settings \$__mailSettings'
        $cl = & $def 'Send-SICloseLoopMail'
        if ($cl) {
            # Pro: the close-loop family (close-loop, exemption, sign-in, governance, department, task digest) shares it
            (Code $cl) | Should -Match 'Send-SIMail -Settings \$Smtp'
            @($script:Ps | Where-Object { (Code $_) -match 'Send-SICloseLoopMail -Smtp' }).Count | Should -BeGreaterOrEqual 4
        }
        @($script:Ps | Where-Object { (Code $_) -match 'Send-SIGuardMailDefault -Smtp' }).Count | Should -BeGreaterOrEqual 2 -Because 'the guards and the updater''s licence mail'
    }
    It 'the C# side: no SmtpClient anywhere (the retired analyzer''s sender is deleted); the Pro web app never talks to a mail server' {
        $cs = @(Get-ChildItem -Path $script:Root -Recurse -Filter '*.cs' -File | Where-Object { $_.FullName -notmatch '[\\/](tests|bin|obj)[\\/]' })
        $hits = @($cs | Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match 'new SmtpClient\(' } | ForEach-Object { Rel $_ })
        @($hits) | Should -BeNullOrEmpty
    }
}