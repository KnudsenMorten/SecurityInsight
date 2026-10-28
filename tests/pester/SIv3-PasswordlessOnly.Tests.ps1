#Requires -Version 5.1
<#
    #549 PASSWORDLESS-ONLY ACCOUNTS ARE READ, NOT GUESSED (owner 2026-10-10: "Yes, add the permission").

    What these keep true:
      1. PERMISSION   UserAuthenticationMethod.Read.All is in the collection identity's catalog (config/permissions.locked.json)
                      and in every grant path (the container grant plan Grant-SIIdentity and the guided install use,
                      the wizard's New-SISpn); the engine's own self-check reports it missing
      2. THE RULE     a password method present = false; no password + a cloud-only member + a passwordless sign-in method =
                      true; everything else (not read whole, synchronised / guest without a cloud password, nothing to sign
                      in with) = unknown -- NEVER false
      3. THE READ     Graph $batch, 20 users per request, only the users the profile keeps (no guests, no soft-deleted, a
                      disabled account only while disabled accounts are collected); a 429 is retried with its Retry-After;
                      throttled out / refused / partial = unknown for the users not read, the run state says so, ONE plain
                      line (information -- also when refused: Get Started shows the missing permission); after a refusal nothing more is asked
      4. MAPPING      the 'authenticationMethods' part of the Entra record fills si_passwordless_only (true / false); an
                      unknown verdict leaves the field out
      5. WIRING       the identity discovery reads the methods per page before the records are built and stamps
                      ENTRA_AuthMethodsReadComplete + ENTRA_PasswordlessOnly
    OFFLINE: Graph is a fake (-Post / -Sleep seams); no tenant is touched.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    $script:Info = New-Object System.Collections.Generic.List[string]
    $script:Warn = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
    function script:Write-SIWarn { param($Message) $script:Warn.Add([string]$Message) }
    . (Join-Path $script:Shared 'Invoke-SIPagedRest.ps1')
    . (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    $script:Model = Get-SIDataModel
    function script:Map($Object) {
        (ConvertTo-SIRecord -Object $Object -Mapping $script:Model.Mappings['entra'] -RecordType 'user' -Catalog $script:Model['field-catalog'] `
            -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]'2026-10-10T03:00:00Z') -RunId 'run-1').Record
    }
    # fictional users and methods
    function script:U([string]$Id, [string]$Type = 'Member', $Synced = $null, $Enabled = $true) {
        [pscustomobject]@{ id = $Id; userPrincipalName = "$Id@contoso.test"; userType = $Type; onPremisesSyncEnabled = $Synced; accountEnabled = $Enabled }
    }
    function script:M([string[]]$Types) { @($Types | ForEach-Object { [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$_"; id = "m-$_" } }) }
    function script:Ok([string[]]$Types) { @{ Status = 200; Headers = $null; Body = [pscustomobject]@{ value = @(M $Types) } } }
    function script:Status([int]$Code, $RetryAfter = $null) {
        $h = $null; if ($null -ne $RetryAfter) { $h = [pscustomobject]@{ 'Retry-After' = [string]$RetryAfter } }
        @{ Status = $Code; Headers = $h; Body = [pscustomobject]@{ error = [pscustomobject]@{ code = "HTTP$Code" } } }
    }
    $script:Password     = @('passwordAuthenticationMethod', 'microsoftAuthenticatorAuthenticationMethod')
    $script:Passwordless = @('fido2AuthenticationMethod', 'microsoftAuthenticatorAuthenticationMethod')
    # the fake $batch endpoint: answers each request through $script:Answer { param($UserId, $PostNo) } -> Ok / Status
    $script:Posts = New-Object System.Collections.Generic.List[string]
    $script:Sleeps = New-Object System.Collections.Generic.List[int]
    $script:Post = {
        param($Body)
        $script:Posts.Add([string]$Body)
        $n = $script:Posts.Count
        $reqs = @(($Body | ConvertFrom-Json).requests)
        [pscustomobject]@{ responses = @(foreach ($r in $reqs) {
            $uid = ([string]$r.url -split '/')[2]
            $a = & $script:Answer $uid $n
            if ($null -ne $a) { [pscustomobject]@{ id = [string]$r.id; status = $a.Status; headers = $a.Headers; body = $a.Body } }
        }) }
    }
    $script:Sleep = { param($Seconds) $script:Sleeps.Add([int]$Seconds) }
    function script:Read($Users, [int]$MaxRounds = 5) {
        Get-SIEntraPasswordlessByUser -Token 'tok' -Users $Users -Post $script:Post -Sleep $script:Sleep -MaxRounds $MaxRounds
    }
}

Describe 'the permission: requested, granted, checked' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        . (Join-Path $script:SIRoot 'engine\_shared\SI-PermissionCheck.ps1')
        $script:Cat = Get-SIPermissionCatalog -Path (Join-Path $script:SIRoot 'config\permissions.locked.json')
        $script:GraphApi = @($script:Cat.identities.collection.api | Where-Object { $_.resourceAppId -eq '00000003-0000-0000-c000-000000000000' })[0]
    }
    It 'is in the collection identity''s Microsoft Graph roles (application, always -- not conditional)' {
        @($script:GraphApi.roles) | Should -Contain 'UserAuthenticationMethod.Read.All'
        @($script:GraphApi.conditionalRoles | ForEach-Object { $_.role }) | Should -Not -Contain 'UserAuthenticationMethod.Read.All'
        @($script:Cat.identities.tagging.api | ForEach-Object { @($_.roles) }) | Should -Not -Contain 'UserAuthenticationMethod.Read.All' -Because 'asset tagging reads no sign-in methods'
    }
    It 'is read only (the collection identity never writes)' {
        @($script:GraphApi.roles | Where-Object { $_ -match 'Write' }) | Should -BeNullOrEmpty
    }
    It 'the grant plan Grant-SIIdentity and the guided install apply asks for it' {
        @(($script:SIContainerIdentityAppRoles | Where-Object { $_.Resource -eq 'Microsoft Graph' }).Roles) | Should -Contain 'UserAuthenticationMethod.Read.All'
        $plan = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity)
        @($plan | Where-Object { $_.Kind -eq 'AppRole' -and $_.Role -eq 'UserAuthenticationMethod.Read.All' -and $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000' }).Count | Should -Be 1
    }
    It 'the wizard requests it' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\ConfigWizard\backend\New-SISpn.ps1'))
        $s | Should -Match "'UserAuthenticationMethod\.Read\.All',"
    }
    It 'the engine''s own self-check reports it missing from a token without it' {
        $without = @($script:GraphApi.roles | Where-Object { $_ -ne 'UserAuthenticationMethod.Read.All' })
        $r = @(Test-SIPermissionApiRoles -Api $script:GraphApi -TokenRoles $without -Fix 'f')
        @($r | Where-Object State -eq 'missing' | ForEach-Object Item) | Should -Be @('UserAuthenticationMethod.Read.All')
        @(Test-SIPermissionApiRoles -Api $script:GraphApi -TokenRoles @($script:GraphApi.roles) -Fix 'f' | Where-Object State -ne 'ok').Count | Should -Be 0
    }
}

Describe 'the rule: password present = false, passwordless only = true, everything else unknown' {
    It 'a password method present = false (whatever else the user holds)' {
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Password) -ReadComplete $true -User (U 'a') | Should -BeFalse
        $null -eq (Get-SIPasswordlessOnlyVerdict -Methods (M $script:Password) -ReadComplete $true -User (U 'a')) | Should -BeFalse
        Get-SIPasswordlessOnlyVerdict -Methods (M @('passwordAuthenticationMethod')) -ReadComplete $true -User (U 'a' 'Member' $true) | Should -BeFalse -Because 'a synchronised account with a cloud password is false too'
    }
    It 'no password + a passwordless sign-in method + a cloud-only member = true -- for each documented method type' -ForEach @(
        'fido2AuthenticationMethod', 'windowsHelloForBusinessAuthenticationMethod', 'microsoftAuthenticatorAuthenticationMethod',
        'platformCredentialAuthenticationMethod', 'x509CertificateAuthenticationMethod', 'temporaryAccessPassAuthenticationMethod',
        'phoneAuthenticationMethod', 'qrCodePinAuthenticationMethod') {
        Get-SIPasswordlessOnlyVerdict -Methods (M @($_)) -ReadComplete $true -User (U 'a') | Should -BeTrue
    }
    It 'the type is matched case-insensitively and strings work as well as objects' {
        Get-SIPasswordlessOnlyVerdict -Methods @('#Microsoft.Graph.Fido2AuthenticationMethod') -ReadComplete $true -User (U 'a') | Should -BeTrue
        Get-SIPasswordlessOnlyVerdict -Methods @('#microsoft.graph.PASSWORDAuthenticationMethod', '#microsoft.graph.fido2AuthenticationMethod') -ReadComplete $true -User (U 'a') | Should -BeFalse
    }
    It 'a list not read whole = unknown, even when it shows a password or only passwordless methods' {
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Password) -ReadComplete $false -User (U 'a') | Should -BeNullOrEmpty
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Passwordless) -ReadComplete $false -User (U 'a') | Should -BeNullOrEmpty
    }
    It 'a synchronised or guest account without a cloud password = unknown (its password lives elsewhere)' {
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Passwordless) -ReadComplete $true -User (U 'a' 'Member' $true) | Should -BeNullOrEmpty
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Passwordless) -ReadComplete $true -User (U 'a' 'Guest') | Should -BeNullOrEmpty
        $ext = [pscustomobject]@{ id = 'x'; userPrincipalName = 'ada_fabrikam.test#EXT#@contoso.test'; userType = 'Member'; onPremisesSyncEnabled = $null }
        Get-SIPasswordlessOnlyVerdict -Methods (M $script:Passwordless) -ReadComplete $true -User $ext | Should -BeNullOrEmpty
    }
    It 'no password and nothing to sign in with (no methods, or only an e-mail / OATH code) = unknown' {
        Get-SIPasswordlessOnlyVerdict -Methods @() -ReadComplete $true -User (U 'a') | Should -BeNullOrEmpty
        Get-SIPasswordlessOnlyVerdict -Methods (M @('emailAuthenticationMethod', 'softwareOathAuthenticationMethod')) -ReadComplete $true -User (U 'a') | Should -BeNullOrEmpty
    }
}

Describe 'which users are read: the users the profile keeps, whose answer can be true or false' {
    It 'members are read; guests, external accounts and soft-deleted users are not' {
        $del = U 'del'; $del | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $true
        $del2 = U 'del2'; $del2 | Add-Member -NotePropertyName deletedDateTime -NotePropertyValue '2026-10-01T00:00:00Z'
        $ext = [pscustomobject]@{ id = 'ext'; userPrincipalName = 'a_b.test#EXT#@contoso.test'; userType = $null; accountEnabled = $true }
        $sel = @(Select-SIAuthMethodReadUsers -Users @((U 'm1'), (U 'g1' 'Guest'), $del, $del2, $ext, (U 's1' 'Member' $true)))
        @($sel | ForEach-Object id) | Should -Be @('m1', 's1') -Because 'a synchronised member is read: a cloud password makes it false'
    }
    It 'a disabled account is read only while disabled accounts are collected' {
        @(Select-SIAuthMethodReadUsers -Users @((U 'on'), (U 'off' 'Member' $null $false)) -IncludeDisabled $true | ForEach-Object id) | Should -Be @('on', 'off')
        @(Select-SIAuthMethodReadUsers -Users @((U 'on'), (U 'off' 'Member' $null $false)) -IncludeDisabled $false | ForEach-Object id) | Should -Be @('on')
    }
}

Describe 'the read: Graph $batch with fixtures' {
    BeforeEach {
        Reset-SIEntraAuthMethodsState
        $script:Posts.Clear(); $script:Sleeps.Clear(); $script:Info.Clear(); $script:Warn.Clear()
        $global:SIRecordCaptureState = $null
    }
    AfterAll { $global:SIRecordCaptureState = $null }

    It 'asks 20 users per request, the documented URL; password present -> false, passwordless only -> true' {
        $users = @(1..45 | ForEach-Object { U ('u{0:D2}' -f $_) })
        $script:Answer = { param($Uid, $PostNo) if ($Uid -eq 'u07') { Ok $script:Passwordless } else { Ok $script:Password } }
        $map = Read $users
        $script:Posts.Count | Should -Be 3
        $first = $script:Posts[0] | ConvertFrom-Json
        @($first.requests).Count | Should -Be 20
        @($first.requests)[0].method | Should -Be 'GET'
        @($first.requests)[0].url | Should -Be '/users/u01/authentication/methods'
        @(($script:Posts[2] | ConvertFrom-Json).requests).Count | Should -Be 5
        $map.Count | Should -Be 45
        $map['u07'].PasswordlessOnly | Should -BeTrue
        $map['u08'].PasswordlessOnly | Should -BeFalse
        $null -eq $map['u08'].PasswordlessOnly | Should -BeFalse -Because 'a password that was read is a real "no"'
        $map['u08'].ReadComplete | Should -BeTrue
        $st = Get-SIEntraAuthMethodsState
        ($st.Complete, $st.Read, $st.Unread, $st.PasswordlessOnly, $st.Refused) | Should -Be @($true, 45, 0, 1, $false)
        $script:Sleeps.Count | Should -Be 0
    }
    It 'a throttled user (429) is read again after the Retry-After it was given; throttling alone is not a failure' {
        $script:Answer = { param($Uid, $PostNo) if ($Uid -eq 'b' -and $PostNo -eq 1) { Status 429 7 } elseif ($Uid -eq 'b') { Ok $script:Passwordless } else { Ok $script:Password } }
        $map = Read @((U 'a'), (U 'b'))
        $script:Posts.Count | Should -Be 2
        @(($script:Posts[1] | ConvertFrom-Json).requests | ForEach-Object url) | Should -Be @('/users/b/authentication/methods') -Because 'only the throttled user is asked again'
        $script:Sleeps | Should -Contain 7
        $map['b'].PasswordlessOnly | Should -BeTrue
        $st = Get-SIEntraAuthMethodsState
        $st.Complete | Should -BeTrue
        $st.Throttled | Should -BeTrue
    }
    It 'throttled out: the users not read stay UNKNOWN (absent), never false; one plain information line, no warning' {
        $script:Answer = { param($Uid, $PostNo) if ($Uid -eq 'a') { Ok $script:Password } else { Status 429 2 } }
        $map = Read @((U 'a'), (U 'b'), (U 'c')) -MaxRounds 3
        $script:Posts.Count | Should -Be 3
        $map.Count | Should -Be 1
        $map.ContainsKey('b') | Should -BeFalse
        $st = Get-SIEntraAuthMethodsState
        ($st.Complete, $st.Throttled, $st.Refused, $st.Read, $st.Unread) | Should -Be @($false, $true, $false, 1, 2)
        Write-SIEntraAuthMethodsOutcome
        $script:Warn.Count | Should -Be 0
        $line = @($script:Info)[-1]
        $line | Should -Match 'checked for 1 of 3 users'
        $line | Should -Match 'slow down'
        $line | Should -Match 'unknown, never as no'
        $line | Should -Not -Match '#\d'
    }
    It 'a throttled batch request (the whole POST answers 429) is retried with backoff, then read' {
        $n = @{ Calls = 0 }
        # the fake's own state lives in this test's scope: a closure has a script scope of its own
        $post = { param($Body) $n.Calls++; if ($n.Calls -eq 1) { throw [System.Exception]::new('The remote server returned an error: (429) Too Many Requests.') }
                  [pscustomobject]@{ responses = @(foreach ($r in @(($Body | ConvertFrom-Json).requests)) { [pscustomobject]@{ id = [string]$r.id; status = 200; headers = $null; body = [pscustomobject]@{ value = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }) } } }) } }.GetNewClosure()
        $map = Get-SIEntraPasswordlessByUser -Token 'tok' -Users @((U 'a')) -Post $post -Sleep $script:Sleep
        $n.Calls | Should -Be 2
        $script:Sleeps.Count | Should -Be 1
        $map['a'].PasswordlessOnly | Should -BeFalse
        (Get-SIEntraAuthMethodsState).Complete | Should -BeTrue
    }
    It 'refused (the POST answers 403): nothing is decided, the read stops, and the next page asks nothing; one plain information line, no warning' {
        $n = @{ Calls = 0 }
        $post = { param($Body) $n.Calls++; throw [System.Exception]::new('The remote server returned an error: (403) Forbidden.') }.GetNewClosure()
        $map = Get-SIEntraPasswordlessByUser -Token 'tok' -Users @(1..45 | ForEach-Object { U "r$_" }) -Post $post -Sleep $script:Sleep
        $map.Count | Should -Be 0
        $n.Calls | Should -Be 1 -Because 'the permission is tenant-wide: asking on only collects more refusals'
        $map2 = Get-SIEntraPasswordlessByUser -Token 'tok' -Users @((U 'next-page')) -Post $post -Sleep $script:Sleep
        $map2.Count | Should -Be 0
        $n.Calls | Should -Be 1
        $st = Get-SIEntraAuthMethodsState
        ($st.Refused, $st.Complete, $st.Requested, $st.Read, $st.Unread) | Should -Be @($true, $false, 46, 0, 46)
        Write-SIEntraAuthMethodsOutcome
        $script:Warn.Count | Should -Be 0 -Because 'a missing permission is shown in Get Started; a warning every run until consent is noise'
        $line = @($script:Info)[-1]
        $line | Should -Match 'UserAuthenticationMethod\.Read\.All'
        $line | Should -Match 'admin consent'
        $line | Should -Match 'unknown, never as no'
        $line | Should -Not -Match '#\d'
    }
    It 'refused per item (403 inside the batch): the read stops after that request' {
        $script:Answer = { param($Uid, $PostNo) Status 403 }
        $map = Read @(1..45 | ForEach-Object { U "i$_" })
        $map.Count | Should -Be 0
        $script:Posts.Count | Should -Be 1
        (Get-SIEntraAuthMethodsState).Refused | Should -BeTrue
    }
    It 'partial: a paged list, a user gone (404) and an unanswered request are never decided from part of the answer' {
        $script:Answer = {
            param($Uid, $PostNo)
            switch ($Uid) {
                'paged' { @{ Status = 200; Headers = $null; Body = [pscustomobject]@{ value = @(M @('fido2AuthenticationMethod')); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users/paged/authentication/methods?$skiptoken=x' } } }
                'gone'  { Status 404 }
                'quiet' { if ($PostNo -eq 1) { $null } else { Ok $script:Password } }
                default { Ok $script:Passwordless }
            }
        }
        $map = Read @((U 'paged'), (U 'gone'), (U 'quiet'), (U 'ok'))
        $map.ContainsKey('paged') | Should -BeFalse -Because 'a list with a next page was not read whole -- unknown, even though what came holds no password'
        $map.ContainsKey('gone') | Should -BeFalse
        $map['quiet'].PasswordlessOnly | Should -BeFalse -Because 'an unanswered request is asked again'
        $map['ok'].PasswordlessOnly | Should -BeTrue
        $st = Get-SIEntraAuthMethodsState
        $st.Complete | Should -BeFalse
        $st.Unread | Should -Be 2
    }
    It 'the state adds up over several pages and is reset per run' {
        $script:Answer = { param($Uid, $PostNo) Ok $script:Password }
        $null = Read @((U 'p1'), (U 'p2'))
        $null = Read @((U 'p3'))
        (Get-SIEntraAuthMethodsState).Read | Should -Be 3
        Reset-SIEntraAuthMethodsState
        Get-SIEntraAuthMethodsState | Should -BeNullOrEmpty
    }
    It 'a complete read says so in one information line' {
        $script:Answer = { param($Uid, $PostNo) if ($Uid -eq 'pl') { Ok $script:Passwordless } else { Ok $script:Password } }
        $null = Read @((U 'pl'), (U 'pw'))
        Write-SIEntraAuthMethodsOutcome
        $script:Warn.Count | Should -Be 0
        @($script:Info)[-1] | Should -Match 'sign-in methods read for 2 users; 1 sign in passwordless only'
    }
    It 'never throws: a fake that returns nothing leaves everyone unknown' {
        { Get-SIEntraPasswordlessByUser -Token 'tok' -Users @((U 'z')) -Post { param($Body) $null } -Sleep $script:Sleep -MaxRounds 2 } | Should -Not -Throw
        (Get-SIEntraAuthMethodsState).Complete | Should -BeFalse
    }
}

Describe 'mapping: the authenticationMethods part fills si_passwordless_only' {
    BeforeEach { Reset-SIEntraAuthMethodsState; $script:Posts.Clear(); $global:SIRecordCaptureState = $null; $null = Reset-SIRecordCapture }
    AfterAll { $global:SIRecordCaptureState = $null }
    BeforeAll {
        function script:RecordObject([string]$Id) {
            $rec = $null
            if (-not $global:SIRecordCaptureState.Records.TryGetValue("entra|user|$Id", [ref]$rec)) { return $null }
            $o = [pscustomobject]@{ user = [pscustomobject]@{ id = $Id; userPrincipalName = "$Id@contoso.test" } }
            foreach ($k in $rec.Parts.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue ($rec.Parts[$k].SIJson | ConvertFrom-Json) -Force }
            $o
        }
    }
    It 'passwordless only -> true; a password -> false (a real "no"); synchronised without a cloud password -> the field is left out (unknown)' {
        $script:Answer = { param($Uid, $PostNo) switch ($Uid) { 'pl' { Ok $script:Passwordless } 'pw' { Ok $script:Password } 'sy' { Ok $script:Passwordless } } }
        $null = Read @((U 'pl'), (U 'pw'), (U 'sy' 'Member' $true))
        (Map (RecordObject 'pl'))['si_passwordless_only'] | Should -BeTrue
        $pw = Map (RecordObject 'pw')
        $pw.Contains('si_passwordless_only') | Should -BeTrue
        $pw['si_passwordless_only'] | Should -BeFalse
        $sy = RecordObject 'sy'
        $sy.authenticationMethods.readComplete | Should -BeTrue
        $sy.authenticationMethods.PSObject.Properties['passwordlessOnly'] | Should -BeNullOrEmpty
        (Map $sy).Contains('si_passwordless_only') | Should -BeFalse
    }
    It 'a user not read (throttled out, refused) gets no part at all -- the field stays unknown' {
        $script:Answer = { param($Uid, $PostNo) Status 429 1 }
        $null = Read @((U 'th')) -MaxRounds 2
        RecordObject 'th' | Should -BeNullOrEmpty
        $o = [pscustomobject]@{ user = [pscustomobject]@{ id = 'th'; userPrincipalName = 'th@contoso.test' } }
        (Map $o).Contains('si_passwordless_only') | Should -BeFalse
    }
    It 'the catalog and the Entra mapping agree: the part is declared, the field is bool, its authority is Entra, no needsRead' {
        $obj = @($script:Model.Mappings['entra'].objects | Where-Object { $_.recordType -eq 'user' })[0]
        $obj.parts.PSObject.Properties['authenticationMethods'] | Should -Not -BeNullOrEmpty
        $f = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_passwordless_only' })[0]
        $f.type | Should -Be 'bool'
        @($f.resolution.authority) | Should -Be @('entra')
        $f.PSObject.Properties['needsRead'] | Should -BeNullOrEmpty
        $f.description | Should -Not -Match '#\d'
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
}

Describe 'wiring: the identity discovery reads the methods and stamps the outcome' {
    BeforeAll { $script:Disc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1')) }
    It 'loads the read, resets the state per run and follows the disabled-accounts collection setting' {
        $script:Disc | Should -Match ([regex]::Escape('shared/SI-AuthMethodsRead.ps1'))
        $script:Disc | Should -Match ([regex]::Escape('Reset-SIEntraAuthMethodsState'))
        $script:Disc | Should -Match ([regex]::Escape('Test-SIDisabledIncluded -Stage Collect'))
        $script:Disc | Should -Match ([regex]::Escape('Select-SIAuthMethodReadUsers -Users $PageUsers -IncludeDisabled $authReadDisabled'))
    }
    It 'reads before the records are built -- per streamed page AND for the whole set -- and says the outcome once per path' {
        ([regex]::Matches($script:Disc, [regex]::Escape('& $readAuthMethods')).Count) | Should -Be 2
        ([regex]::Matches($script:Disc, 'Write-SIEntraAuthMethodsOutcome').Count) | Should -Be 2
        $i = $script:Disc.IndexOf('& $readAuthMethods @($PageRows)'); $j = $script:Disc.IndexOf('foreach ($su in $PageRows) { $batch.Add((& $buildUser $su)) }')
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
        $k = $script:Disc.IndexOf('& $readAuthMethods $rows.ToArray()'); $l = $script:Disc.IndexOf('& $buildUser $u', $k)
        ($k -gt 0 -and $l -gt $k) | Should -BeTrue
    }
    It 'stamps the per-user completeness and a verdict that is null unless the read was complete' {
        $script:Disc | Should -Match ([regex]::Escape('ENTRA_AuthMethodsReadComplete  = if ($pw) { [bool]$pw.ReadComplete } else { $false }'))
        $script:Disc | Should -Match ([regex]::Escape('ENTRA_PasswordlessOnly         = if ($pw -and [bool]$pw.ReadComplete) { $pw.PasswordlessOnly } else { $null }'))
    }
}
