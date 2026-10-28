#Requires -Version 5.1
<#
    #701 -- Set-SIMail.ps1 when Exchange Online REFUSES the sign-in (customer ticket 2026-10-15: four 401s from the Exchange
    admin API, then "the mailbox does not exist" although the shared mailbox existed).

    What these tests keep true:
      * a refusal (401 / 403) NEVER yields "does not exist": the plan builder with an unknown mailbox does not throw, the
        hand-over creates the mailbox only when asked for ("only if it does not exist yet"), and the run says plainly
        that Exchange refused the sign-in (with the status), the likely reasons (an eligible PIM role not activated --
        activate, wait, re-run in a new window; or no Exchange Administrator), prints the commands, and exits NOT DONE (2);
      * the Exchange token's role is read from the token itself (wids): Exchange / Global Administrator active, or "not
        active in this sign-in -- if it is eligible in PIM, activate it first";
      * the Exchange token comes from the Exchange Online PowerShell client (fb78d390-...), through the same browser
        sign-in (code + PKCE, the account pre-filled, its own refresh token) -- every other resource stays on the Azure
        PowerShell client.
    Offline: no tenant. The end-to-end run is a child PowerShell process (the script ends with exit).
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'setup\Set-SIMail.ps1') -LoadFunctionsOnly
    $script:Ids = @([pscustomobject]@{ ObjectId = 'o-1'; AppId = 'aaaaaaaa-1111-2222-3333-444444444444'; DisplayName = 'id-si-prod-pro-ca' })
    function script:New-FakeJwt([hashtable]$Claims) {
        $enc = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        '{0}.{1}.sig' -f (& $enc '{"alg":"none"}'), (& $enc ($Claims | ConvertTo-Json -Compress))
    }
}

Describe 'a refusal is never "the mailbox does not exist"' {
    It 'the plan with an UNKNOWN mailbox and -CreateMailbox $false does not throw and creates no mailbox' {
        $p = @(New-SIMailExoPlan -MailboxExists $false -MailboxKnown $false -CreateMailbox $false -Address 'si@contoso.example' -ScopeName 'S' -Identities $script:Ids)
        @($p | Where-Object Cmdlet -eq 'New-Mailbox').Count | Should -Be 0
        @($p.Cmdlet) | Should -Contain 'New-ServicePrincipal'
        @($p.Cmdlet) | Should -Contain 'New-ManagementScope'
    }
    It 'the plan with an UNKNOWN mailbox and -CreateMailbox hands over New-Mailbox "only if it does not exist yet"' {
        $p = @(New-SIMailExoPlan -MailboxExists $false -MailboxKnown $false -CreateMailbox $true -Address 'si@contoso.example' -ScopeName 'S' -Identities $script:Ids)
        ($p | Where-Object Cmdlet -eq 'New-Mailbox').What | Should -Match 'only if it does not exist yet'
    }
    It 'CONTROL: a mailbox Exchange really reported missing, with -CreateMailbox $false, is still refused' {
        { New-SIMailExoPlan -MailboxExists $false -MailboxKnown $true -CreateMailbox $false -Address 'si@contoso.example' -ScopeName 'S' -Identities $script:Ids } | Should -Throw '*does not exist*'
    }
    It 'the status of a refusal: <Text> -> <Out>' -ForEach @(
        @{ Text = 'Response status code does not indicate success: 401 (Unauthorized).'; Out = '401 Unauthorized' }
        @{ Text = 'The remote server returned an error: (403) Forbidden.'; Out = '403 Forbidden' }
        @{ Text = 'no status here'; Out = '' }
    ) { Get-SIMailHttpStatus -Text $Text | Should -Be $Out }
    It 'the refusal text: refused + status, the mailbox NOT known, PIM activation + new window, the Exchange role' {
        $t = (Get-SIMailExoRefusalLines -Status '401 Unauthorized' -Address 'si@contoso.example' -RoleText 'neither ... is active') -join "`n"
        $t | Should -Match 'Exchange Online refused this sign-in \(HTTP 401 Unauthorized\)'
        $t | Should -Match 'could NOT be read -- this is not a sign that it is missing'
        $t | Should -Match 'ELIGIBLE in Entra PIM is not activated'
        $t | Should -Match 'wait a few minutes'
        $t | Should -Match 'NEW PowerShell window'
        $t | Should -Match 'does not hold Exchange Administrator'
        $t | Should -Not -Match '(?i)mailbox \S+ does not exist'
    }
    It '#761: a 401 is said as "the token was not accepted", a 403 as "a role is missing" -- never the other way round' {
        $t401 = (Get-SIMailExoRefusalLines -Status '401 Unauthorized' -Address 'si@contoso.example') -join "`n"
        $t401 | Should -Match 'did not ACCEPT the sign-in itself \(the token\)'
        $t401 | Should -Not -CMatch 'a ROLE is missing'
        $t403 = (Get-SIMailExoRefusalLines -Status '403 Forbidden' -Address 'si@contoso.example') -join "`n"
        $t403 | Should -Match 'a ROLE is missing'
        $t403 | Should -Not -CMatch 'did not ACCEPT'
        $t403 | Should -Not -Match '(?i)mailbox \S+ does not exist'
    }
}

Describe '#773: the Exchange answer -- the HTTP status first, the body only when it can be read (a customer install: HTTP 403 with 435 zero bytes read as "The archive entry was compressed using an unsupported compression method")' {
    BeforeAll {
        function script:GzipBytes([string]$s) {
            $ms = New-Object System.IO.MemoryStream
            $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
            $b = [Text.Encoding]::UTF8.GetBytes($s); $gz.Write($b, 0, $b.Length); $gz.Dispose(); , $ms.ToArray()
        }
        function script:ZlibBytes([string]$s) {
            $ms = New-Object System.IO.MemoryStream
            $ms.WriteByte(0x78); $ms.WriteByte(0x9C)
            $df = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
            $b = [Text.Encoding]::UTF8.GetBytes($s); $df.Write($b, 0, $b.Length); $df.Dispose(); , $ms.ToArray()
        }
    }
    AfterEach { $global:SI_MailExoHttp = $null }
    It 'every InvokeCommand call carries the JSON format, the anchor mailbox and Accept-Encoding identity -- built in one place' {
        $h = Get-SIMailExoHeaders -Anchor 'UPN:admin@contoso.example'
        $h['Accept-Encoding'] | Should -Be 'identity'
        $h['X-ResponseFormat'] | Should -Be 'json'
        $h['X-AnchorMailbox'] | Should -Be 'UPN:admin@contoso.example'
        $src = [IO.File]::ReadAllText((Join-Path $script:Root 'setup\Set-SIMail.ps1'))
        @([regex]::Matches($src, 'X-AnchorMailbox''\s*=')).Count | Should -Be 1 -Because 'one place builds the Exchange headers'
        $src | Should -Match ([regex]::Escape('ConvertFrom-SIMailExoAnswer -Answer (Invoke-SIMailExoHttp -Uri $exoUri -Token $tok -Body $body -Headers $hdr) -Uri $exoUri'))
    }
    It 'the plain client: no automatic decompression, the STATUS read before the body' {
        $fn = (Get-Command Invoke-SIMailExoHttp).Definition
        $fn | Should -Match 'AutomaticDecompression = \[System\.Net\.DecompressionMethods\]::None'
        $fn.IndexOf('$code = [int]$rs.StatusCode') | Should -BeLessThan $fn.IndexOf('ReadAsByteArrayAsync') -Because 'the status is read before the body'
    }
    It 'the body: zero bytes / NUL text / a broken stream are no text; gzip and zlib-deflate open by their own header; plain JSON is itself' {
        ConvertFrom-SIMailExoBytes -Bytes (New-Object byte[] 435) | Should -BeExactly ''
        ConvertFrom-SIMailExoBytes -Bytes $null | Should -BeExactly ''
        ConvertFrom-SIMailExoBytes -Bytes ([byte[]](0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00)) | Should -BeExactly '' -Because 'a broken gzip never throws'
        ConvertFrom-SIMailExoBytes -Bytes ([byte[]](0x00, 0x00, 0x00)) -ContentEncoding 'deflate' | Should -BeExactly ''
        ConvertFrom-SIMailExoBytes -Bytes (GzipBytes '{"value":[{"Name":"S1"}]}') | Should -Be '{"value":[{"Name":"S1"}]}'
        ConvertFrom-SIMailExoBytes -Bytes (ZlibBytes '{"value":[]}') | Should -Be '{"value":[]}'
        ConvertFrom-SIMailExoBytes -Bytes ([Text.Encoding]::UTF8.GetBytes('{"error":"x"}')) | Should -Be '{"error":"x"}'
    }
    It 'a 403 with a zero-filled body is a REFUSAL with its status -- never "not a refusal"' {
        $global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) [pscustomobject]@{ StatusCode = 403; Bytes = (New-Object byte[] 435); ContentEncoding = '' } }
        $a = Invoke-SIMailExoHttp -Uri 'https://outlook.office365.com/adminapi/beta/t/InvokeCommand' -Token 't' -Body '{}'
        $a.StatusCode | Should -Be 403; $a.Text | Should -BeExactly ''; $a.Bytes | Should -Be 435
        $err = $null; try { $null = ConvertFrom-SIMailExoAnswer -Answer $a } catch { $err = $_.Exception.Message }
        $err | Should -Match 'HTTP Status: 403 \(Forbidden\) Response: \(no readable body\)'
        Test-SIMailExoDenied -Text $err | Should -BeTrue
        Get-SIMailHttpStatus -Text $err | Should -Be '403 Forbidden'
    }
    It 'a gzip body is read: 200 -> the answer; 403 -> the refusal with Exchange''s own words' {
        $global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) [pscustomobject]@{ StatusCode = 200; Bytes = (GzipBytes '{"value":[{"Name":"SecurityInsight-Sender"}]}'); ContentEncoding = 'gzip' } }
        $r = ConvertFrom-SIMailExoAnswer -Answer (Invoke-SIMailExoHttp -Uri 'u' -Token 't' -Body '{}')
        @($r.value)[0].Name | Should -Be 'SecurityInsight-Sender'
        $global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) [pscustomobject]@{ StatusCode = 403; Bytes = (GzipBytes '{"error":{"message":"Access denied"}}'); ContentEncoding = 'gzip' } }
        { ConvertFrom-SIMailExoAnswer -Answer (Invoke-SIMailExoHttp -Uri 'u' -Token 't' -Body '{}') } | Should -Throw '*403 (Forbidden)*Access denied*'
        # a 200 that cannot be read is never an empty success
        $global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) [pscustomobject]@{ StatusCode = 200; Bytes = (New-Object byte[] 8); ContentEncoding = '' } }
        { ConvertFrom-SIMailExoAnswer -Answer (Invoke-SIMailExoHttp -Uri 'u' -Token 't' -Body '{}') } | Should -Throw '*could not be read*'
    }
    It 'the recorder''s unread answer is recognised; the roles of the token are named; the sentence is exact' {
        Test-SIMailExoUnreadAnswer -Text 'POST https://outlook.office365.com/adminapi/beta/x/InvokeCommand failed. HTTP Status: 0 (NoResponse) Response: The archive entry was compressed using an unsupported compression method.' | Should -BeTrue
        Test-SIMailExoUnreadAnswer -Text 'Response status code does not indicate success: 403 (Forbidden).' | Should -BeFalse
        $held = Get-SIMailExoHeldRoleNames -Claims ([pscustomobject]@{ roles = @('Exchange.ManageAsApp'); wids = @('31392ffb-586c-42d1-9346-e59415a2cc4e', '0997a1d0-0d1d-4acb-b408-d5ca73121e90') })
        $held | Should -Be 'Exchange Recipient Administrator, role 0997a1d0-0d1d-4acb-b408-d5ca73121e90'
        Get-SIMailExoHeldRoleNames -Claims ([pscustomobject]@{ wids = @('b79fbf4d-3ef9-4689-8143-76b194e85509') }) | Should -BeExactly ''
        Get-SIMailExoLacksRoleText -HeldRoles 'Exchange Recipient Administrator' | Should -BeExactly 'this sign-in lacks the Exchange role needed: Exchange Administrator, or the Role Management role group (it holds Exchange Recipient Administrator)'
        Get-SIMailExoLacksRoleText -HeldRoles '' | Should -Match '\(it holds no directory role\)$'
        (Get-SIMailExoRefusalLines -Status '403 Forbidden' -Address 'si@contoso.example' -HeldRoles 'Exchange Recipient Administrator') -join "`n" | Should -Match ([regex]::Escape('this sign-in lacks the Exchange role needed: Exchange Administrator, or the Role Management role group (it holds Exchange Recipient Administrator)'))
    }
}

Describe 'the role in the Exchange token' {
    It 'Exchange Administrator in wids = active' {
        $v = Get-SIMailExoRoleVerdict -Claims ([pscustomobject]@{ upn = 'a@b.example'; scp = 'Exchange.Manage'; wids = @('29232cdf-9323-42fd-ade2-1d097af3e4de') })
        $v.State | Should -Be 'active'; $v.Text | Should -Match 'Exchange Administrator is active'
        $v.Text | Should -Not -Match 'Exchange\.Manage\)'
    }
    It 'Global Administrator in wids = active' {
        (Get-SIMailExoRoleVerdict -Claims ([pscustomobject]@{ upn = 'a@b.example'; scp = 'Exchange.Manage'; wids = @('62e90394-69f5-4237-9190-012177145e10') })).State | Should -Be 'active'
    }
    It 'wids without either role = missing: "if it is eligible in PIM, activate it first"' {
        $v = Get-SIMailExoRoleVerdict -Claims ([pscustomobject]@{ upn = 'a@b.example'; scp = 'Exchange.Manage'; wids = @('b79fbf4d-3ef9-4689-8143-76b194e85509') })
        $v.State | Should -Be 'missing'; $v.Text | Should -Match 'if the role is eligible in PIM, activate it first'
    }
    It 'no wids = unknown; a delegated token without Exchange.Manage is said' {
        $v = Get-SIMailExoRoleVerdict -Claims ([pscustomobject]@{ upn = 'a@b.example'; scp = 'user_impersonation' })
        $v.State | Should -Be 'unknown'; $v.Text | Should -Match 'Exchange\.Manage'
        (Get-SIMailExoRoleVerdict -Claims $null).State | Should -Be 'unknown'
    }
}

Describe 'the run: Exchange refuses -- 401 to an admin whose shared mailbox exists; 403 with a zero-filled body to the Support app in a support session (#773)' {
    BeforeAll {
        # one child PowerShell per run (the script ends with exit): -Prelude adds the scenario's own fakes
        function script:Invoke-MailRun([string]$Name, [string]$ExoTok, [string]$Prelude, [string]$ExoThrow) {
            $out = Join-Path ([IO.Path]::GetTempPath()) ('si-mail-' + $Name + '-' + [guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($out)
            $graphTok = New-FakeJwt @{ tid = '11111111-1111-1111-1111-111111111111'; upn = 'admin@contoso.example'; scp = 'Directory.AccessAsUser.All' }
            $child = @"
`$env:SI_SCRIPT_RUN_QUIET = '1'
function global:Connect-SISetupAzure { param([string]`$TenantId, [string]`$SubscriptionId) }
function global:Get-SISetupAccessToken { param([string]`$Resource) if (`$Resource -like '*outlook*') { '$ExoTok' } else { '$graphTok' } }
function global:Invoke-SIRestMethod { [CmdletBinding()]
    param([string]`$Method, [string]`$Uri, `$Headers, `$Body, [string]`$ContentType, [int]`$TimeoutSec)
    if (`$Uri -like 'https://outlook.office365.com/*') { throw '$ExoThrow' }
    if (`$Uri -like '*subscribedSkus*') { return [pscustomobject]@{ value = @([pscustomobject]@{ servicePlans = @([pscustomobject]@{ servicePlanName = 'EXCHANGE_S_STANDARD' }) }) } }
    if (`$Uri -like '*/organization') { return [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @([pscustomobject]@{ name = 'contoso.onmicrosoft.com'; isInitial = `$true }) }) } }
    if (`$Uri -like '*appId eq ''00000003-0000-0000-c000-000000000000''*') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'g'; appRoles = @([pscustomobject]@{ id = 'ms'; value = 'Mail.Send'; allowedMemberTypes = @('Application') }) }) } }
    if (`$Uri -like '*/appRoleAssignments*') { return [pscustomobject]@{ value = @() } }
    if (`$Uri -like '*/servicePrincipals/o-1*') { return [pscustomobject]@{ id = 'o-1'; appId = 'aaaaaaaa-1111-2222-3333-444444444444'; displayName = 'id-si'; servicePrincipalType = 'ManagedIdentity' } }
    throw ('unexpected call ' + `$Uri)
}
$Prelude
& '$((Join-Path $script:Root 'setup\Set-SIMail.ps1'))' -MailboxName 'SecurityInsight' -MailDomain 'contoso.example' -CreateMailbox `$false -UseSignedInAccount -Apply -IdentityObjectId 'o-1' -TenantId '11111111-1111-1111-1111-111111111111' -OutFile '$out\r.json' *>&1 | ForEach-Object { "`$_" }
"exit=`$LASTEXITCODE"
"@
            $f = Join-Path $out 'run.ps1'; [IO.File]::WriteAllText($f, $child)
            $exe = (Get-Process -Id $PID).Path
            $text = (& $exe -NoProfile -NonInteractive -File $f 2>&1 | Out-String)
            $res = Get-Content -Raw (Join-Path $out 'r.json') -ErrorAction SilentlyContinue | ConvertFrom-Json
            Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
            [pscustomobject]@{ Text = $text; Result = $res }
        }
        # 401: the plain client (no support session) answers 401 with no body
        $exoTok = New-FakeJwt @{ tid = '11111111-1111-1111-1111-111111111111'; upn = 'admin@contoso.example'; scp = 'Exchange.Manage'; wids = @('b79fbf4d-3ef9-4689-8143-76b194e85509') }
        $r401 = Invoke-MailRun -Name '401' -ExoTok $exoTok -ExoThrow 'not used: no support session' -Prelude '$global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) [pscustomobject]@{ StatusCode = 401; Bytes = [byte[]]@(); ContentEncoding = '''' } }'
        $script:Text = $r401.Text; $script:Result = $r401.Result
        # 403 in a support session: the recorder could not read the answer (the live message); the plain client reads the
        # status: 403 with 435 zero bytes. The Support app holds only Exchange Recipient Administrator.
        $appTok = New-FakeJwt @{ tid = '11111111-1111-1111-1111-111111111111'; appid = 'cccccccc-1111-2222-3333-444444444444'; roles = @('Exchange.ManageAsApp'); wids = @('31392ffb-586c-42d1-9346-e59415a2cc4e') }
        $pre = @'
function global:Test-SISupportRequestRoute { param([string]$Audience, $Auth, [string]$Uri) $true }
$global:SIPesterRawCalls = 0
$global:SI_MailExoHttp = { param($Uri, $Token, $Body, $Headers) $global:SIPesterRawCalls++; [pscustomobject]@{ StatusCode = 403; Bytes = (New-Object byte[] 435); ContentEncoding = '' } }
'@
        $r403 = Invoke-MailRun -Name '403' -ExoTok $appTok -Prelude $pre -ExoThrow 'POST https://outlook.office365.com/adminapi/beta/11111111-1111-1111-1111-111111111111/InvokeCommand failed. HTTP Status: 0 (NoResponse) Response: The archive entry was compressed using an unsupported compression method.'
        $script:Text403 = $r403.Text; $script:Result403 = $r403.Result
    }

    It 'never says the mailbox does not exist, and never throws the -CreateMailbox error' {
        $script:Text | Should -Not -Match '(?i)does not exist, and creating it was not asked for'
        $script:Text | Should -Not -Match '(?i)mailbox does not exist'
    }
    It 'says Exchange refused this sign-in, with the status, the reasons, and the role read from the token' {
        $script:Text | Should -Match 'Exchange Online refused this sign-in \(HTTP 401 Unauthorized\)'
        $script:Text | Should -Match 'ELIGIBLE in Entra PIM is not activated'
        $script:Text | Should -Match 'NEW PowerShell window'
        $script:Text | Should -Match 'neither Exchange Administrator nor Global Administrator is active in this sign-in'
    }
    It 'prints the commands for the Exchange administrator, without New-Mailbox (-CreateMailbox $false)' {
        $script:Text | Should -Match 'For your Exchange administrator'
        $script:Text | Should -Match 'New-ServicePrincipal'
        $script:Text | Should -Match 'Test-ServicePrincipalAuthorization'
        $script:Text | Should -Not -Match 'New-Mailbox -'
    }
    It 'exits NOT DONE (2, handed over), never green' {
        $script:Text | Should -Match 'RESULT: NOT DONE'
        $script:Text | Should -Match 'exit=2'
        $script:Result.ok | Should -BeFalse
        $script:Result.reason | Should -Match 'Exchange refused this sign-in \(HTTP 401 Unauthorized\)'
    }
    It '#773 403 + a zero-filled body in a support session: a REFUSAL with its status and the roles the sign-in holds -- never "not a refusal"' {
        $script:Text403 | Should -Not -Match 'its answer is not a refusal'
        $script:Text403 | Should -Match 'Exchange Online refused this sign-in \(HTTP 403 Forbidden\)'
        $script:Text403 | Should -Match ([regex]::Escape('this sign-in lacks the Exchange role needed: Exchange Administrator, or the Role Management role group (it holds Exchange Recipient Administrator)'))
        $script:Text403 | Should -Match 'its HTTP status is read directly'
        $script:Text403 | Should -Match 'For your Exchange administrator'
        $script:Text403 | Should -Match 'New-ManagementScope'
        $script:Text403 | Should -Match 'exit=2'
        $script:Result403.ok | Should -BeFalse
        $script:Result403.reason | Should -Match 'Exchange refused this sign-in \(HTTP 403 Forbidden\): this sign-in lacks the Exchange role needed'
    }
}

Describe 'the Exchange token comes from the Exchange Online PowerShell client' {
    BeforeAll {
        $script:GlobalNames = 'SI_SetupSignInState', 'SI_SetupSignInClientId', 'SI_SetupExchangeClientId'
        $script:keep = @{}; foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
        . (Join-Path $script:Root 'setup\_shared\SI-SetupSignIn.ps1')
        if (-not (Get-Command Invoke-SIAzRestHttp -ErrorAction SilentlyContinue)) { function script:Invoke-SIAzRestHttp { param($Method, $Uri, $Body, $ContentType, $Headers, $TimeoutSec) } }
    }
    AfterAll { foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] } }
    BeforeEach {
        foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $script:Calls = [System.Collections.Generic.List[object]]::new(); $script:Opened = [System.Collections.Generic.List[string]]::new()
        $script:ExoTok = New-FakeJwt @{ tid = 'tid-1'; upn = 'admin@contoso.example'; aud = 'https://outlook.office365.com'; scp = 'Exchange.Manage' }
        $script:ArmTok = New-FakeJwt @{ tid = 'tid-1'; upn = 'admin@contoso.example'; aud = 'https://management.azure.com/' }
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([pscustomobject]@{ Uri = $Uri; Body = [string]$Body })
            $f = ConvertFrom-SIQueryString -Query ([string]$Body)
            $tok = if ($f['scope'] -like 'https://outlook.office365.com/*') { $script:ExoTok } else { $script:ArmTok }
            [pscustomobject]@{ StatusCode = 200; Content = (@{ access_token = $tok; refresh_token = ('rt-' + $f['client_id']); expires_in = 3600 } | ConvertTo-Json -Compress) }
        }
        Mock Test-SISignInInteractive { $true }
        Mock Open-SISignInBrowser { $script:Opened.Add($Url); $true }
        Mock Wait-SILoopbackAuthCode { $q = ConvertFrom-SIQueryString -Query ([uri]$script:Opened[-1]).Query; '?code=c&state=' + [uri]::EscapeDataString($q['state']) }
        Mock Write-Host { }
    }
    It 'the client ids: Azure PowerShell for setup, the Exchange Online PowerShell client for Exchange' {
        Get-SISignInClientId | Should -Be '1950a258-227b-4e31-a9cf-717495945fc2'
        Get-SISignInExchangeClientId | Should -Be 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
        Test-SISignInExchangeResource -Resource 'https://outlook.office365.com' | Should -BeTrue
        Test-SISignInExchangeResource -Resource 'https://graph.microsoft.com' | Should -BeFalse
    }
    It 'Exchange: one browser sign-in with fb78d390 (PKCE, the account pre-filled, no account picker); then its own refresh token' {
        $null = Connect-SISetupUser -TenantId 'tid-1' -Method Browser
        $script:Opened.Count | Should -Be 1
        Get-SISetupUserToken -Resource 'https://outlook.office365.com' | Should -Be $script:ExoTok
        $script:Opened.Count | Should -Be 2
        $u = ConvertFrom-SIQueryString -Query ([uri]$script:Opened[1]).Query
        $u['client_id'] | Should -Be 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
        $u['scope'] | Should -Match '^https://outlook\.office365\.com/\.default offline_access'
        $u['code_challenge_method'] | Should -Be 'S256'
        $u['login_hint'] | Should -Be 'admin@contoso.example'
        $u.ContainsKey('prompt') | Should -BeFalse
        $x = ConvertFrom-SIQueryString -Query (@($script:Calls | Where-Object { $_.Body -match 'grant_type=authorization_code' })[-1].Body)
        $x['client_id'] | Should -Be 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
        $x['code_verifier'] | Should -Not -BeNullOrEmpty
        # a fresh Exchange token: the Exchange client's own refresh token, no browser
        $null = Get-SISetupUserToken -Resource 'https://outlook.office365.com' -ForceRefresh
        $script:Opened.Count | Should -Be 2
        $r = ConvertFrom-SIQueryString -Query $script:Calls[-1].Body
        $r['grant_type'] | Should -Be 'refresh_token'; $r['client_id'] | Should -Be 'fb78d390-0c51-40cd-8e17-fdbfab77341b'; $r['refresh_token'] | Should -Be 'rt-fb78d390-0c51-40cd-8e17-fdbfab77341b'
        # every other resource stays on the Azure PowerShell client
        $null = Get-SISetupUserToken -Resource 'https://graph.microsoft.com'
        (ConvertFrom-SIQueryString -Query $script:Calls[-1].Body)['client_id'] | Should -Be '1950a258-227b-4e31-a9cf-717495945fc2'
    }
}
