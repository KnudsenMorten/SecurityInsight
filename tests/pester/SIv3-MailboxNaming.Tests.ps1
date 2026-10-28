#Requires -Version 5.1
<#
    THE COMPANY NAMES THE SHARED MAILBOX (#503; framework MAIL-1 "The company names the mailbox").
    What these tests keep true for setup\Set-SIMail.ps1:
      * the mailbox name, the domain (-MailDomain) and the display name are parameters; the address is
        -SharedMailbox, else <MailboxName>@<MailDomain>, else <MailboxName>@<the tenant's initial domain>;
      * the Exchange scope and the role assignments follow the mailbox name ('<name>-Sender', '<name>-MailSend-<app id>');
      * an existing scope that filters exactly this mailbox is ADOPTED, and an assignment that grants Mail.Send on it is
        adopted whatever it is called -- never duplicated;

    Offline (functions only). PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'setup\Set-SIMail.ps1') -LoadFunctionsOnly
    $script:Ids = @([pscustomobject]@{ AppId = 'aaaaaaaa-1111-2222-3333-444444444444'; ObjectId = 'bbbbbbbb-1111-2222-3333-444444444444'; DisplayName = 'uami-si' })
    $script:Src = [IO.File]::ReadAllText((Join-Path $script:Root 'setup\Set-SIMail.ps1'))
}

Describe 'the address' {
    It 'is the given address, else name@domain, else name@initial domain' {
        (Resolve-SIMailSenderAddress -SharedMailbox 'x@contoso.example' -MailboxName 'ignored' -MailDomain 'other.example').Address | Should -Be 'x@contoso.example'
        (Resolve-SIMailSenderAddress -MailboxName 'it-alerts' -MailDomain 'contoso.example' -InitialDomain 'contoso.onmicrosoft.com').Address | Should -Be 'it-alerts@contoso.example'
        (Resolve-SIMailSenderAddress -MailboxName 'it-alerts' -MailDomain '@contoso.example').Address | Should -Be 'it-alerts@contoso.example'
        (Resolve-SIMailSenderAddress -MailboxName 'it-alerts' -InitialDomain 'contoso.onmicrosoft.com').Address | Should -Be 'it-alerts@contoso.onmicrosoft.com'
    }
    It 'refuses a name or a domain that is not one' {
        (Resolve-SIMailSenderAddress -MailboxName 'it alerts' -MailDomain 'contoso.example').Reason | Should -Match 'not a mailbox name'
        (Resolve-SIMailSenderAddress -MailboxName 'it-alerts' -MailDomain 'contoso').Reason | Should -Match 'not a mail domain'
    }
    It 'takes -MailDomain as a parameter' {
        $script:Src | Should -Match '\[string\]\$MailDomain'
        $script:Src | Should -Match 'Resolve-SIMailSenderAddress -SharedMailbox \$SharedMailbox -MailboxName \$MailboxName -InitialDomain \$initialDomain -MailDomain \$MailDomain'
    }
}

Describe 'the Exchange objects follow the mailbox name' {
    It 'the scope is NAME-Sender and the assignment NAME-MailSend-APPID' {
        Resolve-SIMailScopeName -MailboxName 'IT Alerts' -Address 'it.alerts@contoso.example' | Should -Be 'IT-Alerts-Sender'
        Get-SIMailAssignmentName -AppId 'aaaaaaaa-1111-2222-3333-444444444444' -MailboxName 'it-alerts' | Should -Be 'it-alerts-MailSend-aaaaaaaa'
        $p = @(New-SIMailExoPlan -MailboxExists $false -Address 'it-alerts@contoso.example' -MailboxName 'it-alerts' -DisplayName 'IT alerts' -ScopeName 'it-alerts-Sender' -Identities $script:Ids)
        ($p | Where-Object Cmdlet -eq 'New-Mailbox').Parameters.Name | Should -Be 'it-alerts'
        ($p | Where-Object Cmdlet -eq 'New-ManagementRoleAssignment').Parameters.Name | Should -Be 'it-alerts-MailSend-aaaaaaaa'
    }
    It 'the defaults stay as before (SecurityInsight-Sender, SecurityInsight-MailSend-...)' {
        Resolve-SIMailScopeName -MailboxName 'SecurityInsight' -Address 'SecurityInsight@contoso.example' | Should -Be 'SecurityInsight-Sender'
        Get-SIMailAssignmentName -AppId 'aaaaaaaa-1111-2222-3333-444444444444' | Should -Be 'SecurityInsight-MailSend-aaaaaaaa'
    }
    It 'a given -ScopeName wins' {
        Resolve-SIMailScopeName -ScopeName 'Corp-SI' -MailboxName 'x' -Address 'x@contoso.example' | Should -Be 'Corp-SI'
    }
}

Describe 'what exists is adopted, never duplicated' {
    It 'a scope that already filters exactly this mailbox is adopted, whatever it is called' {
        $sc = @([pscustomobject]@{ Name = 'Corp mail scope'; RecipientRestrictionFilter = "PrimarySmtpAddress -eq 'it-alerts@contoso.example'" },
                [pscustomobject]@{ Name = 'Other'; RecipientRestrictionFilter = "PrimarySmtpAddress -eq 'other@contoso.example'" })
        $name = Resolve-SIMailScopeName -MailboxName 'it-alerts' -Address 'it-alerts@contoso.example' -Scopes $sc
        $name | Should -Be 'Corp mail scope'
        @(New-SIMailExoPlan -MailboxExists $true -Address 'it-alerts@contoso.example' -MailboxName 'it-alerts' -ScopeName $name -Identities $script:Ids -Scopes $sc |
            Where-Object Cmdlet -in 'New-ManagementScope', 'Set-ManagementScope').Count | Should -Be 0
    }
    It 'an assignment that grants Mail.Send on a scope of this mailbox counts, whatever its name' {
        $sps = @($script:Ids | ForEach-Object { [pscustomobject]@{ AppId = $_.AppId; ObjectId = $_.ObjectId; Identity = $_.ObjectId } })
        $sc = @([pscustomobject]@{ Name = 'Corp mail scope'; RecipientRestrictionFilter = "PrimarySmtpAddress -eq 'it-alerts@contoso.example'" })
        $as = @([pscustomobject]@{ Role = 'Application Mail.Send'; CustomResourceScope = 'Corp mail scope'; RoleAssignee = $script:Ids[0].ObjectId; Name = 'made by hand' })
        @(New-SIMailExoPlan -MailboxExists $true -Address 'it-alerts@contoso.example' -MailboxName 'it-alerts' -ScopeName 'it-alerts-Sender' -Identities $script:Ids `
            -ExoServicePrincipals $sps -Scopes $sc -Assignments $as | Where-Object Cmdlet -eq 'New-ManagementRoleAssignment').Count | Should -Be 0
    }
    It 'the scope is resolved from what Exchange holds before the plan is made' {
        $script:Src | Should -Match ([regex]::Escape("`$ScopeName = Resolve-SIMailScopeName -ScopeName `$ScopeName -MailboxName `$MailboxName -Address `$address -Scopes @(`$reads['Get-ManagementScope'])"))
    }
}
