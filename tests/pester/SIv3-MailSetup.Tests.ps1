#Requires -Version 5.1
<#
    MAIL-1 SETUP -- setup\Set-SIMail.ps1 (the standalone, module-free script an Exchange administrator runs) and the
    guided install's e-mail page (install parameters mailMode / mailFrom / mailboxCreate; the older 'mail' bool).

    What these tests keep true:
      * the Exchange calls are the InvokeCommand body the Exchange Online module sends, with the right anchor;
      * the plan: create the mailbox (when missing and asked), register each identity, ONE scope on that mailbox only,
        'Application Mail.Send' per identity on that scope; nothing when everything is there; a scope of the same name
        on ANOTHER mailbox is refused, never re-pointed;
      * the commands handed to an Exchange administrator are exact PowerShell;
      * the verdicts: Test-ServicePrincipalAuthorization in scope / not in scope; a tenant-wide Graph Mail.Send found;
        Exchange plans beyond Foundation; already-exists / dehydrated / not-materialised / denied;
      * install: mailMode default sharedMailbox, the older mail=true -> smtp and mail=false -> none, mailFrom default.
    Offline: no tenant.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'setup\Set-SIMail.ps1') -LoadFunctionsOnly
    $script:Ids = @([pscustomobject]@{ ObjectId = 'o-1'; AppId = 'aaaaaaaa-1111-2222-3333-444444444444'; DisplayName = 'id-si-prod-pro-ca' },
                    [pscustomobject]@{ ObjectId = 'o-2'; AppId = 'bbbbbbbb-1111-2222-3333-444444444444'; DisplayName = 'uami-si-updater' })
}

Describe 'the Exchange request' {
    It 'is the InvokeCommand body of the Exchange Online module (cmdlet + parameters)' {
        $j = New-SIMailExoRequestBody -Cmdlet 'New-Mailbox' -Parameters @{ Shared = $true; Name = 'SecurityInsight'; PrimarySmtpAddress = 'si@contoso.example' }
        $o = ConvertFrom-Json $j
        $o.CmdletInput.CmdletName | Should -Be 'New-Mailbox'
        $o.CmdletInput.Parameters.Shared | Should -BeTrue
        $o.CmdletInput.Parameters.PrimarySmtpAddress | Should -Be 'si@contoso.example'
    }
    It 'anchors on the signed-in person, or on the organization''s system mailbox for an app' {
        Get-SIMailExoAnchor -Upn 'admin@contoso.example' -InitialDomain 'contoso.onmicrosoft.com' | Should -Be 'UPN:admin@contoso.example'
        Get-SIMailExoAnchor -Upn '' -InitialDomain 'contoso.onmicrosoft.com' | Should -Be 'UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@contoso.onmicrosoft.com'
    }
}

Describe 'the plan' {
    It 'fresh tenant: mailbox, registrations, the scope on that mailbox only, the scoped role per identity -- in that order' {
        $p = @(New-SIMailExoPlan -MailboxExists $false -Address 'si@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids)
        @($p | ForEach-Object Cmdlet) | Should -Be @('New-Mailbox', 'New-ServicePrincipal', 'New-ServicePrincipal', 'New-ManagementScope', 'New-ManagementRoleAssignment', 'New-ManagementRoleAssignment')
        $p[0].Parameters.Shared | Should -BeTrue
        $p[3].Parameters.RecipientRestrictionFilter | Should -Be "PrimarySmtpAddress -eq 'si@contoso.example'"
        $p[4].Parameters.Role | Should -Be 'Application Mail.Send'
        $p[4].Parameters.CustomResourceScope | Should -Be 'SecurityInsight-Sender'
        $p[4].Parameters.App | Should -Be 'aaaaaaaa-1111-2222-3333-444444444444'
        $p[4].Parameters.Name | Should -Be 'SecurityInsight-MailSend-aaaaaaaa'
    }
    It 'everything in place: an empty plan (a re-run changes nothing)' {
        $sps = @($script:Ids | ForEach-Object { [pscustomobject]@{ AppId = $_.AppId; ObjectId = $_.ObjectId; Identity = $_.ObjectId } })
        $sc = @([pscustomobject]@{ Name = 'SecurityInsight-Sender'; RecipientFilter = "PrimarySmtpAddress -eq 'si@contoso.example'" })
        $as = @($script:Ids | ForEach-Object { [pscustomobject]@{ Role = 'Application Mail.Send'; CustomResourceScope = 'SecurityInsight-Sender'; RoleAssignee = $_.ObjectId; Name = 'x' } })
        @(New-SIMailExoPlan -MailboxExists $true -Address 'si@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -ExoServicePrincipals $sps -Scopes $sc -Assignments $as).Count | Should -Be 0
    }
    It 'another product''s scope is left alone; a scope of OUR name on another mailbox is refused' {
        $pim = @([pscustomobject]@{ Name = 'PIM4EntraPS-Sender'; RecipientFilter = "PrimarySmtpAddress -eq 'pim@contoso.example'" })
        @(New-SIMailExoPlan -MailboxExists $true -Address 'si@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -Scopes $pim | Where-Object Cmdlet -eq 'New-ManagementScope').Count | Should -Be 1
        $ours = @([pscustomobject]@{ Name = 'SecurityInsight-Sender'; RecipientFilter = "PrimarySmtpAddress -eq 'other@contoso.example'" })
        { New-SIMailExoPlan -MailboxExists $true -Address 'si@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -Scopes $ours } | Should -Throw '*another mailbox*'
    }
    It 'the mailbox''s primary address changed (#444, live at a customer): our scope on its OLD address is re-pointed -- another mailbox still refused' {
        $ours = @([pscustomobject]@{ Name = 'SecurityInsight-Sender'; RecipientRestrictionFilter = "PrimarySmtpAddress -eq 'SecurityInsight@contoso.onmicrosoft.com'" })
        $own = @('SMTP:SecurityInsight@contoso.example', 'smtp:SecurityInsight@contoso.onmicrosoft.com')
        $p = @(New-SIMailExoPlan -MailboxExists $true -Address 'SecurityInsight@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -Scopes $ours -MailboxAddresses $own)
        $re = @($p | Where-Object Cmdlet -eq 'Set-ManagementScope')
        $re.Count | Should -Be 1
        $re[0].Parameters.Identity | Should -Be 'SecurityInsight-Sender'
        $re[0].Parameters.RecipientRestrictionFilter | Should -Be "PrimarySmtpAddress -eq 'SecurityInsight@contoso.example'"
        @($p | Where-Object Cmdlet -eq 'New-ManagementScope') | Should -BeNullOrEmpty
        # an address that is NOT one of this mailbox's: refused, never re-pointed
        { New-SIMailExoPlan -MailboxExists $true -Address 'SecurityInsight@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -Scopes $ours -MailboxAddresses @('SMTP:SecurityInsight@contoso.example') } | Should -Throw '*another mailbox*'
        # a filter with no address in it at all: refused
        $odd = @([pscustomobject]@{ Name = 'SecurityInsight-Sender'; RecipientRestrictionFilter = "Department -eq 'IT'" })
        { New-SIMailExoPlan -MailboxExists $true -Address 'SecurityInsight@contoso.example' -ScopeName 'SecurityInsight-Sender' -Identities $script:Ids -Scopes $odd -MailboxAddresses $own } | Should -Throw '*another mailbox*'
        # the plan reads the mailbox's own addresses from Exchange (Get-Mailbox EmailAddresses)
        [IO.File]::ReadAllText((Join-Path $script:Root 'setup\Set-SIMail.ps1')) | Should -Match '-MailboxAddresses \$\(if \(\$mailboxExists -and \$mb'
    }
    It 'a missing mailbox that must not be created is refused' {
        { New-SIMailExoPlan -MailboxExists $false -CreateMailbox $false -Address 'si@contoso.example' -ScopeName 'S' -Identities $script:Ids } | Should -Throw '*does not exist*'
    }
    It 'the handed-over commands are exact PowerShell' {
        $i = [pscustomobject]@{ Cmdlet = 'New-ManagementScope'; Parameters = @{ Name = 'SecurityInsight-Sender'; RecipientRestrictionFilter = "PrimarySmtpAddress -eq 'si@contoso.example'" } }
        ConvertTo-SIMailExoCommandText -Item $i | Should -Be "New-ManagementScope -Name 'SecurityInsight-Sender' -RecipientRestrictionFilter 'PrimarySmtpAddress -eq ''si@contoso.example'''"
        ConvertTo-SIMailExoCommandText -Item ([pscustomobject]@{ Cmdlet = 'New-Mailbox'; Parameters = @{ Shared = $true; Name = 'SecurityInsight' } }) | Should -Be "New-Mailbox -Name 'SecurityInsight' -Shared"
    }
}

Describe 'the verdicts' {
    It 'Test-ServicePrincipalAuthorization: Application Mail.Send in scope, or not' {
        (Get-SIMailAuthorizationVerdict -Rows @([pscustomobject]@{ RoleName = 'Application Mail.Send'; InScope = $true })).InScope | Should -BeTrue
        (Get-SIMailAuthorizationVerdict -Rows @([pscustomobject]@{ RoleName = 'Application Mail.Send'; InScope = 'False' })).InScope | Should -BeFalse
        (Get-SIMailAuthorizationVerdict -Rows @([pscustomobject]@{ RoleName = 'Application Mail.Read'; InScope = $true })).InScope | Should -BeFalse
    }
    It 'a tenant-wide Graph Mail.Send is found among the app-role assignments' {
        $a = @([pscustomobject]@{ id = '1'; resourceId = 'graph'; appRoleId = 'ms' }, [pscustomobject]@{ id = '2'; resourceId = 'graph'; appRoleId = 'other' })
        @(Select-SIMailTenantWideMailSend -Assignments $a -GraphSpId 'graph' -MailSendRoleId 'ms').id | Should -Be '1'
    }
    It 'Exchange plans: Foundation alone cannot host a mailbox' {
        @(Select-SIMailExchangePlans -SubscribedSkus @([pscustomobject]@{ servicePlans = @([pscustomobject]@{ servicePlanName = 'EXCHANGE_S_FOUNDATION' }) })).Count | Should -Be 0
        Select-SIMailExchangePlans -SubscribedSkus @([pscustomobject]@{ servicePlans = @([pscustomobject]@{ servicePlanName = 'EXCHANGE_S_STANDARD' }) }) | Should -Be 'EXCHANGE_S_STANDARD'
    }
    It 'create outcomes: <Text> -> <Out>' -ForEach @(
        @{ C = 'New-ManagementScope'; Text = 'ADObjectAlreadyExistsException: exists'; Out = 'exists' }
        @{ C = 'New-ManagementScope'; Text = 'InvalidOperationInDehydratedContextException'; Out = 'dehydrated' }
        @{ C = 'New-ManagementRoleAssignment'; Text = "The operation couldn't be performed because object couldn't be found"; Out = 'retry' }
        @{ C = 'New-Mailbox'; Text = 'The remote server returned an error: (403) Forbidden.'; Out = 'denied' }
        @{ C = 'New-Mailbox'; Text = 'something else entirely'; Out = 'fail' }
    ) { Resolve-SIMailExoCreateOutcome -Cmdlet $C -ErrorText $Text | Should -Be $Out }
    It 'the address: given, else SecurityInsight at the initial domain; a bad one is refused' {
        (Resolve-SIMailSenderAddress -SharedMailbox 'si@contoso.example').Address | Should -Be 'si@contoso.example'
        (Resolve-SIMailSenderAddress -MailboxName 'SecurityInsight' -InitialDomain 'contoso.onmicrosoft.com').Address | Should -Be 'SecurityInsight@contoso.onmicrosoft.com'
        (Resolve-SIMailSenderAddress -SharedMailbox 'nope').Reason | Should -Match 'not a mail address'
    }
    It 'the settings it prints, per mode' {
        $s = Get-SIMailSettingsToSet -Mode sharedMailbox -Address 'si@contoso.example' -ProbeMailbox 'admin@contoso.example'
        $s.SI_Mail_Mode | Should -Be 'sharedMailbox'; $s.SI_Mail_From | Should -Be 'si@contoso.example'; $s.SI_Mail_ProbeMailbox | Should -Be 'admin@contoso.example'
        $m = Get-SIMailSettingsToSet -Mode smtp -SmtpServer 'relay.contoso.example' -SmtpPort 587 -SmtpUseSsl $true -SmtpUser 'u' -From 'si@contoso.example'
        $m.Mail_SendAnonymous | Should -BeFalse; $m.SMTPPort | Should -Be 587
        @($m.Keys) | Should -Not -Contain 'SMTPPassword' -Because 'the password goes to Key Vault, never to configuration'
    }
    It 'the script never loads a module' {
        (Get-Content -Raw (Join-Path $script:Root 'setup\Set-SIMail.ps1')) | Should -Not -Match '(?im)^\s*(Import-Module|#Requires\s+-Modules)|Connect-ExchangeOnline\s*$'
    }
}

Describe 'the guided install''s e-mail page' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\_shared\SI-MailTransport.ps1')
        $script:Spec = Get-Content -Raw (Join-Path $script:Root 'setup\install-parameters.json') | ConvertFrom-Json
    }
    It 'mailMode: sharedMailbox by default, smtp behind "I use my own SMTP relay", none' {
        $p = $script:Spec.parameters | Where-Object key -eq 'mailMode'
        $p.default | Should -Be 'sharedMailbox'
        @($p.options.value) | Should -Be @('sharedMailbox', 'smtp', 'none')
        ($p.options | Where-Object value -eq 'smtp').label | Should -Be 'I use my own SMTP relay'
        ($script:Spec.parameters | Where-Object key -eq 'mailFrom').showIf.mailMode | Should -Be 'sharedMailbox'
        ($script:Spec.parameters | Where-Object key -eq 'mailboxCreate').default | Should -BeTrue
        foreach ($k in 'smtpServer', 'smtpPort', 'smtpUser', 'smtpFrom') { ($script:Spec.parameters | Where-Object key -eq $k).showIf.mailMode | Should -Be 'smtp' }
        @($script:Spec.parameters | Where-Object key -eq 'mail').Count | Should -Be 0 -Because 'the older bool is still ACCEPTED, but no longer asked'
    }
    It 'no example relay host is named anywhere in the parameters' {
        (Get-Content -Raw (Join-Path $script:Root 'setup\install-parameters.json')) | Should -Not -Match '(?i)brevo|sendgrid|postmark'
    }
    It 'the older answer: mail=true -> smtp, mail=false -> none; mailMode wins' {
        Resolve-SIInstallMailMode -Values @{ mail = $true } | Should -Be 'smtp'
        Resolve-SIInstallMailMode -Values @{ mail = $false } | Should -Be 'none'
        Resolve-SIInstallMailMode -Values @{ mail = $true; mailMode = 'sharedMailbox' } | Should -Be 'sharedMailbox'
    }
    It 'Test-SIInstallConfig takes the older mail bool and maps it' {
        . (Join-Path $script:Root 'setup\_shared\SI-GuidedInstall.ps1')
        $cfg = @{ installId = 'inv-test-1'; tenantId = '11111111-1111-1111-1111-111111111111'; subscriptionId = '22222222-2222-2222-2222-222222222222'
                  mail = $true; mailTo = @('soc@contoso.example'); smtpServer = 'smtp.contoso.example'; smtpFrom = 'si@contoso.example' }
        $r = Test-SIInstallConfig -Config $cfg -Spec $script:Spec
        @($r.Errors | Where-Object { $_ -match '^mail' }) | Should -BeNullOrEmpty
        $r.Values['mailMode'] | Should -Be 'smtp'
        $r.Values['smtpServer'] | Should -Be 'smtp.contoso.example'
        $r2 = Test-SIInstallConfig -Config @{ installId = 'inv-test-2'; tenantId = '11111111-1111-1111-1111-111111111111'; subscriptionId = '22222222-2222-2222-2222-222222222222'; mail = $false } -Spec $script:Spec
        $r2.Values['mailMode'] | Should -Be 'none'
        $r3 = Test-SIInstallConfig -Config @{ installId = 'inv-test-3'; tenantId = '11111111-1111-1111-1111-111111111111'; subscriptionId = '22222222-2222-2222-2222-222222222222' } -Spec $script:Spec
        $r3.Values['mailMode'] | Should -Be 'sharedMailbox'
        $r3.Values['mailboxCreate'] | Should -BeTrue
        $r3.Values.Contains('smtpServer') | Should -BeFalse
    }
    It 'the shared mailbox defaults to SecurityInsight at the installer''s domain; recipients default to the installer' {
        . (Join-Path $script:Root 'setup\_shared\SI-GuidedInstall.ps1')
        $ctx = [pscustomobject]@{ Values = @{}; Facts = @{ userPrincipalName = 'admin@contoso.example' } }
        Get-SIInstallMailbox -Ctx $ctx | Should -Be 'SecurityInsight@contoso.example'
        @(Get-SIInstallMailRecipients -Ctx $ctx) | Should -Be @('admin@contoso.example')
        $ctx.Values['mailFrom'] = 'alerts@contoso.example'; $ctx.Values['mailTo'] = @('soc@contoso.example')
        Get-SIInstallMailbox -Ctx $ctx | Should -Be 'alerts@contoso.example'
        @(Get-SIInstallMailRecipients -Ctx $ctx) | Should -Be @('soc@contoso.example')
        Get-SIInstallMailbox -Ctx ([pscustomobject]@{ Values = @{}; Facts = @{ userPrincipalName = 'an-app-id' } }) | Should -Be ''
    }
}

Describe 'Set-SIMail -ActivateExchangeAdmin: the Support app''s Exchange Administrator is time-bound, through Entra PIM' {
    BeforeAll { $script:MailSrc = [IO.File]::ReadAllText((Join-Path $script:Root 'setup\Set-SIMail.ps1')) }
    It 'is opt-in, for an app sign-in, only with -Apply, and lasts hours (default 2, at most 8)' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'setup\Set-SIMail.ps1'), [ref]$null, [ref]$null)
        $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names | Should -Contain 'ActivateExchangeAdmin'
        $names | Should -Contain 'ExchangeAdminHours'
        $script:MailSrc | Should -Match ([regex]::Escape('[ValidateRange(1, 8)][int]$ExchangeAdminHours = 2'))
        $script:MailSrc | Should -Match ([regex]::Escape('if ($ActivateExchangeAdmin -and $isApp -and $Apply) {'))
    }
    It 'requests the role through roleAssignmentScheduleRequests with an expiry -- never a standing roleAssignments POST' {
        $script:MailSrc | Should -Match 'roleManagement/directory/roleAssignmentScheduleRequests'
        $script:MailSrc | Should -Match "expiration = @\{ type = 'afterDuration'"
        $script:MailSrc | Should -Not -Match 'roleManagement/directory/roleAssignments[''"]'
    }
    It 'activates BEFORE any Exchange token is minted, and reads the role back before going on' {
        $script:MailSrc.IndexOf('if ($ActivateExchangeAdmin -and $isApp -and $Apply) {') | Should -BeLessThan $script:MailSrc.IndexOf("Step '[4] Exchange: read what exists'")
        $script:MailSrc | Should -Match 'is not active on read-back'
    }
}
