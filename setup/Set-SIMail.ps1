<#
.SYNOPSIS
    Set up how SecurityInsight sends its mail: an Office 365 shared mailbox (recommended) or your own SMTP relay.

.DESCRIPTION
    ONE file, no PowerShell modules (native REST only), so it can be downloaded on its own and run by your Exchange
    administrator. PLAN BY DEFAULT: without -Apply it reads, prints what it would change and the exact commands, and
    changes nothing.

    -Mode sharedMailbox (the default, recommended)
      SecurityInsight sends as ONE shared mailbox through Microsoft Graph (sendMail), signed in as its OWN managed
      identity. The send right is granted ONLY in Exchange Online, scoped to that one mailbox ("RBAC for Applications"):
        1. the shared mailbox -- created when it does not exist (-CreateMailbox, on by default)
        2. SecurityInsight's identities registered in Exchange           New-ServicePrincipal
        3. a management scope that matches only that mailbox             New-ManagementScope 'SecurityInsight-Sender'
        4. the role 'Application Mail.Send' on that scope, per identity   New-ManagementRoleAssignment
        5. NO tenant-wide Microsoft Graph Mail.Send on any of those identities -- one is REMOVED with -Apply.
           Exchange RBAC for Applications is ADDITIVE: a tenant-wide Graph Mail.Send next to the scoped role keeps
           winning, and the identity could then send as every mailbox in the tenant.
        6. verify: Test-ServicePrincipalAuthorization -- in scope for the shared mailbox, NOT in scope for another
           mailbox (-ProbeMailbox, default: the signed-in person, or an existing user mailbox).
      An Application Access Policy (the older way) is not used.
      Exchange is driven through the same REST endpoint the Exchange Online PowerShell module uses
      (https://outlook.office365.com/adminapi/beta/<tenant>/InvokeCommand); no module is installed or loaded.

    -Mode smtp
      Your own SMTP relay (any relay: server, port, STARTTLS, user). The password goes to the install's Key Vault
      (secret SI-Smtp-Password), never into configuration. -TestTo sends one test mail through the relay.

    -Mode none
      SecurityInsight sends no mail.

    The settings SecurityInsight reads (SI_Mail_Mode, SI_Mail_From, SI_Mail_ProbeMailbox, and the SMTP settings) are
    printed at the end. Pro: set them on Settings > E-mail (or the web app's "Set up mail" flow does all of this with a
    click). Community: put them in config\SecurityInsight.custom.ps1.

    WHO RUNS IT
      sharedMailbox: an account (or app) with the Exchange Administrator role, or -- narrowest -- an Exchange role group
      holding the roles "Mail Recipient Creation" (creates the mailbox) and "Role Management" (registers the identity,
      the scope and the role assignment). Reading the identities' Microsoft Graph permissions needs
      Application.Read.All; removing a tenant-wide Mail.Send needs AppRoleAssignment.ReadWrite.All (or Privileged Role
      Administrator / Cloud Application Administrator).
      Sign-in: -UseSignedInAccount uses setup's own sign-in (Azure Cloud Shell, the browser, or the Invardia support
      session's tokens -- never the az CLI). Without it the script
      asks for nothing secret and stops at the plan, printing the commands for your Exchange administrator.

.EXAMPLE
    .\Set-SIMail.ps1 -SharedMailbox securityinsight@contoso.com -ResourceGroup rg-si-prod-pro-ca -SubscriptionId <sub> -UseSignedInAccount
    Plan: what would be created and granted, with the commands. Nothing is changed.

.EXAMPLE
    .\Set-SIMail.ps1 -SharedMailbox securityinsight@contoso.com -ResourceGroup rg-si-prod-pro-ca -SubscriptionId <sub> -UseSignedInAccount -Apply

.EXAMPLE
    .\Set-SIMail.ps1 -Mode smtp -SmtpServer relay.contoso.com -SmtpPort 587 -SmtpUseSsl -SmtpUser si@contoso.com -From si@contoso.com -KeyVaultName kv-si-prod-pro-ca -UseSignedInAccount -Apply

.NOTES
    Solution : SecurityInsight -- docs\MAIL.md. Re-running is safe: every step reads first, "already there" is success.

.LINK
    https://invardia.com/docs/si/scripts/Set-SIMail/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('sharedMailbox', 'smtp', 'none')][string]$Mode = 'sharedMailbox',
    [string]$TenantId,
    # sharedMailbox: the address SecurityInsight sends as. Empty = <MailboxName>@<MailDomain>, and without -MailDomain
    # <MailboxName>@<the tenant's initial domain>. The company names the mailbox (its own naming): -MailboxName,
    # -MailDomain and -DisplayName; the defaults are only defaults.
    [string]$SharedMailbox,
    [string]$MailboxName = 'SecurityInsight',
    [string]$MailDomain,
    [string]$DisplayName = 'SecurityInsight',
    [bool]$CreateMailbox = $true,
    # The Exchange management scope. Empty = a scope that already filters exactly this mailbox is ADOPTED, else
    # '<MailboxName>-Sender'. The role assignments are named '<MailboxName>-MailSend-<app id>'.
    [string]$ScopeName = '',
    # SecurityInsight's sending identities: service principal OBJECT ids. Or resolved from -SubscriptionId +
    # -ResourceGroup: every user-assigned identity there, and the system-assigned identity of every container app,
    # container apps job and web app there.
    [string[]]$IdentityObjectId = @(),
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    # identities in -ResourceGroup that never send mail (asset tagging, the MCP server) are left out
    [string]$ExcludeIdentityPattern = '(?i)tagging|mcp',
    # A mailbox OUTSIDE the scope, to prove the restriction. Empty = the signed-in person (when it has a mailbox).
    [string]$ProbeMailbox,
    # smtp
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [switch]$SmtpUseSsl,
    [string]$SmtpUser,
    [securestring]$SmtpPassword,
    [string]$From,
    [string]$KeyVaultName,
    [string]$SmtpPasswordSecretName = 'SI-Smtp-Password',
    [string[]]$TestTo = @(),
    # sign-in: setup's own REST sign-in (a person in Cloud Shell / the browser, or the Invardia support session) -- no az CLI
    [switch]$UseSignedInAccount,
    # an app sign-in (the Invardia Support app): activate its own Exchange Administrator role through Entra PIM, time-bound
    [switch]$ActivateExchangeAdmin,
    [ValidateRange(1, 8)][int]$ExchangeAdminHours = 2,
    [switch]$Apply,
    [string]$OutFile,
    # #564: how long one Exchange action (and the scope check) may wait for Exchange; 0 = no waiting at all (the guided
    # install passes a short value and defers the rest to Get Started -- a slow Exchange never holds an install)
    [ValidateRange(0, 3600)][int]$TimeoutSeconds = 900,
    # tests: define the functions and stop
    [switch]$LoadFunctionsOnly
)

# =====================================================================================================================
#  PURE helpers (tested offline: tests\pester\SIv3-MailSetup.Tests.ps1)
# =====================================================================================================================
$script:SIMailSystemMailboxGuid = 'bb558c35-97f1-4cb9-8ff7-d53741dc928c'

function New-SIMailExoRequestBody {
    <# PURE. The InvokeCommand body for one Exchange cmdlet, as the Exchange Online module sends it. #>
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{})
    $p = [ordered]@{}
    foreach ($k in @($Parameters.Keys | Sort-Object)) { $p[$k] = $Parameters[$k] }
    ConvertTo-Json -Depth 10 -Compress -InputObject ([ordered]@{ CmdletInput = [ordered]@{ CmdletName = $Cmdlet; Parameters = $p } })
}

function Get-SIMailExoHeaders {
    <#
        PURE. The headers of every Exchange admin API call (InvokeCommand). #773 (a customer install, 2026-10-19, in a support session):
        "InvokeCommand failed. HTTP Status: 0 (NoResponse) Response: The archive entry was compressed using an unsupported
        compression method." -- Exchange answers some tenants COMPRESSED ('deflate' as zlib), and the HTTP layer's own
        decoding fails on it before any status is read, so the read looked like no answer at all. 'Accept-Encoding:
        identity' asks for the plain JSON (Invardia's own Exchange calls send the same); nothing else changes.
    #>
    param([Parameter(Mandatory)][string]$Anchor)
    @{ 'X-ResponseFormat' = 'json'; 'X-AnchorMailbox' = $Anchor; 'Accept-Encoding' = 'identity' }
}

function Get-SIMailExoAnchor {
    <# PURE. X-AnchorMailbox: the signed-in person (delegated token) or the organization's system mailbox (an app). #>
    param([string]$Upn, [Parameter(Mandatory)][string]$InitialDomain)
    if ("$Upn".Trim()) { return ('UPN:{0}' -f "$Upn".Trim()) }
    'UPN:SystemMailbox{{{0}}}@{1}' -f $script:SIMailSystemMailboxGuid, $InitialDomain
}

function ConvertFrom-SIMailJwt {
    <# PURE. The claims of a JWT (no signature check -- only to read who it is and which roles it carries). #>
    param([string]$Token)
    try {
        $p = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
    } catch { $null }
}

function Test-SIMailAlreadyExists {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    "$Text" -match '(?i)ADObjectAlreadyExistsException|already exists|Permission being assigned already exists|is already assigned|already been assigned|already in use'
}

function Test-SIMailExoNotFound {
    param([AllowEmptyString()][AllowNull()][string]$Text)
    "$Text" -match "(?i)ManagementObjectNotFoundException|couldn't be found|could not be found|was not found|\bnot found\b|\b404\b"
}

function Test-SIMailExoDenied {
    <# 401/403 or Exchange's own access-denied: the signed-in identity lacks the Exchange role. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    "$Text" -match '(?i)\b401\b|\b403\b|Forbidden|Unauthorized|AccessDenied|isn''t authorized|is not authorized|not allowed to|The term .* is not recognized'
}

function Get-SIMailHttpStatus {
    <# PURE. The HTTP status of a refusal as words ('401 Unauthorized', '403 Forbidden'); '' when the text names none. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = "$Text"
    if ($t -match '(?i)\b401\b|Unauthorized') { return '401 Unauthorized' }
    if ($t -match '(?i)\b403\b|Forbidden') { return '403 Forbidden' }
    if ($t -match '\((\d{3})\)') { return $Matches[1] }
    ''
}

function Get-SIMailExoRoleVerdict {
    <#
        PURE. Which admin role the Exchange token carries (claims 'wids' for a person, 'roles' for an app) and whether it
        holds Exchange.Manage. Returns @{ State = active | missing | unknown; Text }.
        missing = the token lists the person's roles and neither Exchange Administrator nor Global Administrator is among
        them (an eligible PIM role that was not activated before the sign-in looks exactly like this).
    #>
    param($Claims)
    $ga = '62e90394-69f5-4237-9190-012177145e10'; $ea = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    if (-not $Claims) { return [pscustomobject]@{ State = 'unknown'; Text = 'the Exchange sign-in could not be read, so its roles are not known' } }
    $wids = @(); if ($Claims.PSObject.Properties['wids']) { $wids = @($Claims.wids | ForEach-Object { "$_".ToLowerInvariant() }) }
    $names = @(); if ($wids -contains $ga) { $names += 'Global Administrator' }; if ($wids -contains $ea) { $names += 'Exchange Administrator' }
    $scp = if ($Claims.PSObject.Properties['scp']) { " $($Claims.scp) " } else { '' }
    $isApp = -not ($Claims.PSObject.Properties['scp'] -or $Claims.PSObject.Properties['upn'])
    $scpNote = if (-not $isApp -and $scp -notmatch '(?i)\sExchange\.Manage(V2)?\s') { ' The sign-in does not carry the Exchange administration permission (Exchange.Manage).' } else { '' }
    if ($names.Count) { return [pscustomobject]@{ State = 'active'; Text = ('the role {0} is active in this sign-in.{1}' -f ($names -join ' and '), $scpNote) } }
    if ($Claims.PSObject.Properties['wids']) {
        return [pscustomobject]@{ State = 'missing'; Text = ('neither Exchange Administrator nor Global Administrator is active in this sign-in -- if the role is eligible in PIM, activate it first.{0}' -f $scpNote) }
    }
    [pscustomobject]@{ State = 'unknown'; Text = ('the sign-in does not list its roles, so whether Exchange Administrator is active is not known from it.{0}' -f $scpNote) }
}

function Get-SIMailExoRefusalLines {
    <# PURE. What the person reads when Exchange refused the sign-in: never "the mailbox does not exist". #>
    param([string]$Status, [Parameter(Mandatory)][string]$Address, [string]$RoleText,
          # #773: the directory roles the Exchange token holds (Get-SIMailExoHeldRoleNames)
          [AllowEmptyString()][string]$HeldRoles = '')
    $s = if ("$Status".Trim()) { ' (HTTP {0})' -f "$Status".Trim() } else { '' }
    @(
        ('Exchange Online refused this sign-in{0}. Nothing was changed in Exchange.' -f $s)
        (Get-SIMailExoLacksRoleText -HeldRoles $HeldRoles)
        ('Whether the mailbox {0} exists could NOT be read -- this is not a sign that it is missing.' -f $Address)
        $(if ("$RoleText".Trim()) { 'In this sign-in: ' + "$RoleText".Trim() })
        $(if ("$Status" -match '401') { 'HTTP 401 means Exchange did not ACCEPT the sign-in itself (the token) -- not that a role is missing. Sign in again in a NEW PowerShell window; if it stays 401, the sign-in has no Exchange administration permission.' }
          elseif ("$Status" -match '403') { 'HTTP 403 means Exchange accepted the sign-in but a ROLE is missing for this account.' })
        'The likely reasons:'
        '  1. An admin role that is ELIGIBLE in Entra PIM is not activated. Activate Exchange Administrator (or Global Administrator) in PIM, wait a few minutes, then run the same command again in a NEW PowerShell window (a sign-in keeps the roles it had when it was made).'
        '  2. The account does not hold Exchange Administrator (or Global Administrator), nor an Exchange role group with "Mail Recipient Creation" + "Role Management".'
    ) | Where-Object { $_ }
}

function Resolve-SIMailExoCreateOutcome {
    <# PURE. exists = success (a re-run) | dehydrated = wait | retry = Exchange has not materialised a new service
       principal yet | denied = missing Exchange role | fail. #>
    param([string]$Cmdlet, [AllowEmptyString()][AllowNull()][string]$ErrorText)
    if (Test-SIMailAlreadyExists -Text $ErrorText) { return 'exists' }
    if ("$ErrorText" -like '*InvalidOperationInDehydratedContextException*') { return 'dehydrated' }
    if ($Cmdlet -eq 'New-ManagementRoleAssignment' -and (Test-SIMailExoNotFound -Text $ErrorText)) { return 'retry' }
    if (Test-SIMailExoDenied -Text $ErrorText) { return 'denied' }
    'fail'
}

function Select-SIMailExchangePlans {
    <# PURE. Exchange service plans BEYOND EXCHANGE_S_FOUNDATION. Foundation alone (it comes with Entra ID P2) reports
       'exchange enabled' while no mailbox can be created. Empty = this tenant cannot host the shared mailbox. #>
    param([AllowEmptyCollection()][object[]]$SubscribedSkus = @())
    @(@($SubscribedSkus).servicePlans | Where-Object { $_ -and "$($_.servicePlanName)" -like '*EXCHANGE*' -and "$($_.servicePlanName)" -ne 'EXCHANGE_S_FOUNDATION' } |
        ForEach-Object { "$($_.servicePlanName)" } | Sort-Object -Unique)
}

function Resolve-SIMailSenderAddress {
    <# PURE. -SharedMailbox, else <MailboxName>@<MailDomain>, else <MailboxName>@<initial domain>. Returns @{ Address; Reason }. #>
    param([string]$SharedMailbox, [string]$MailboxName, [string]$InitialDomain, [string]$MailDomain)
    $a = "$SharedMailbox".Trim()
    if ($a) {
        if ($a -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return [pscustomobject]@{ Address = ''; Reason = ("'{0}' is not a mail address" -f $a) } }
        return [pscustomobject]@{ Address = $a; Reason = '' }
    }
    $local = "$MailboxName".Trim()
    if ($local -notmatch '^[A-Za-z0-9._-]{1,64}$') { return [pscustomobject]@{ Address = ''; Reason = ("'{0}' is not a mailbox name (letters, digits, dot, dash, underscore)" -f $local) } }
    $domain = "$MailDomain".Trim().TrimStart('@')
    if ($domain) {
        if ($domain -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { return [pscustomobject]@{ Address = ''; Reason = ("'{0}' is not a mail domain" -f $domain) } }
        return [pscustomobject]@{ Address = ('{0}@{1}' -f $local, $domain); Reason = '' }
    }
    if (-not "$InitialDomain".Trim()) { return [pscustomobject]@{ Address = ''; Reason = 'no -SharedMailbox or -MailDomain, and the tenant''s initial domain could not be read' } }
    [pscustomobject]@{ Address = ('{0}@{1}' -f $local, "$InitialDomain".Trim()); Reason = '' }
}

function ConvertTo-SIMailNamePart {
    <# PURE. A mailbox name as part of an Exchange object name: letters, digits and dashes; never empty. #>
    param([string]$MailboxName)
    $p = (("$MailboxName".Trim() -replace '[^A-Za-z0-9-]+', '-') -replace '-{2,}', '-').Trim('-')
    if (-not $p) { $p = 'Mail' }
    if ($p.Length -gt 40) { $p = $p.Substring(0, 40).TrimEnd('-') }
    $p
}

function Get-SIMailAssignmentName {
    <# PURE. The role assignment's name, one per identity: '<MailboxName>-MailSend-<first 8 of the app id>' (the mailbox name follows the company's naming). #>
    param([Parameter(Mandatory)][string]$AppId, [string]$MailboxName = 'SecurityInsight')
    '{0}-MailSend-{1}' -f (ConvertTo-SIMailNamePart -MailboxName $MailboxName), ($AppId -replace '-', '').Substring(0, 8)
}

function Get-SIMailScopesFor {
    <# PURE. The names of the existing Exchange scopes that filter exactly this mailbox (what they grant, not what they are called). #>
    param([object[]]$Scopes = @(), [Parameter(Mandatory)][string]$Address)
    $want = "PrimarySmtpAddress -eq '{0}'" -f $Address
    @($Scopes | Where-Object { $_ -and ("$($_.RecipientRestrictionFilter)$($_.RecipientFilter)".Trim() -ieq $want) } | ForEach-Object { "$($_.Name)" } | Where-Object { $_ })
}

function Resolve-SIMailScopeName {
    <#
        PURE. The scope to use: -ScopeName when given; else an existing scope that already filters exactly this mailbox
        (adopted, never duplicated); else '<MailboxName>-Sender'.
    #>
    param([string]$ScopeName, [string]$MailboxName, [Parameter(Mandatory)][string]$Address, [object[]]$Scopes = @())
    if ("$ScopeName".Trim()) { return "$ScopeName".Trim() }
    $existing = @(Get-SIMailScopesFor -Scopes $Scopes -Address $Address)
    if ($existing.Count) { return $existing[0] }
    '{0}-Sender' -f (ConvertTo-SIMailNamePart -MailboxName $MailboxName)
}

function Get-SIMailExoIds {
    <# PURE. Every id an Exchange service principal / assignment may name an identity by (lower case). #>
    param([object[]]$ExoServicePrincipals = @(), [string]$AppId, [string]$ObjectId)
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($AppId, $ObjectId)) { if ("$v".Trim()) { $ids.Add("$v".Trim().ToLowerInvariant()) } }
    foreach ($s in @($ExoServicePrincipals | Where-Object { $_ -and (("$($_.AppId)" -eq $AppId) -or ("$($_.ObjectId)" -eq $ObjectId)) })) {
        foreach ($v in @($s.Identity, $s.Name, $s.ObjectId, $s.AppId, $s.DisplayName)) { if ("$v".Trim()) { $ids.Add("$v".Trim().ToLowerInvariant()) } }
    }
    @($ids | Select-Object -Unique)
}

function New-SIMailExoPlan {
    <#
        PURE. What to create in Exchange, given what exists: the mailbox (when missing and -CreateMailbox), each
        identity's registration, the scope, each identity's scoped 'Application Mail.Send'. Ordered; empty = in place.
        A scope of this name that filters ANOTHER mailbox is refused (never re-pointed silently). A scope that filters an
        address of THIS mailbox (-MailboxAddresses: its proxy addresses) is re-pointed to its primary address: the
        mailbox's primary address changed (live 2026-10-07: an install's moved from the onmicrosoft domain to its own,
        and the old filter then matched nothing -- SecurityInsight could not send). A scope name: Resolve-SIMailScopeName.
    #>
    param([bool]$MailboxExists, [bool]$CreateMailbox = $true, [Parameter(Mandatory)][string]$Address, [string]$MailboxName = 'SecurityInsight',
          [string]$DisplayName = 'SecurityInsight', [Parameter(Mandatory)][string]$ScopeName, [object[]]$Identities = @(),
          [object[]]$ExoServicePrincipals = @(), [object[]]$Scopes = @(), [object[]]$Assignments = @(),
          [AllowEmptyCollection()][string[]]$MailboxAddresses = @(),
          # $false = Exchange could not be read (refused / no answer): whether the mailbox exists is UNKNOWN -- never
          # "does not exist". The hand-over then creates it only when asked for, and says "only if it does not exist yet".
          [bool]$MailboxKnown = $true)
    $plan = New-Object System.Collections.Generic.List[object]
    if (-not $MailboxKnown) {
        if ($CreateMailbox) {
            $plan.Add([pscustomobject]@{ Cmdlet = 'New-Mailbox'; What = ('create the shared mailbox {0} -- only if it does not exist yet' -f $Address)
                                         Parameters = @{ Shared = $true; Name = $MailboxName; DisplayName = $DisplayName; PrimarySmtpAddress = $Address } })
        }
    } elseif (-not $MailboxExists) {
        if (-not $CreateMailbox) { throw ("the mailbox {0} does not exist, and creating it was not asked for (-CreateMailbox `$false)" -f $Address) }
        $plan.Add([pscustomobject]@{ Cmdlet = 'New-Mailbox'; What = ('create the shared mailbox {0}' -f $Address)
                                     Parameters = @{ Shared = $true; Name = $MailboxName; DisplayName = $DisplayName; PrimarySmtpAddress = $Address } })
    }
    foreach ($i in @($Identities)) {
        $known = @($ExoServicePrincipals | Where-Object { $_ -and ("$($_.AppId)" -eq "$($i.AppId)" -or "$($_.ObjectId)" -eq "$($i.ObjectId)") })
        if (-not $known.Count) {
            $plan.Add([pscustomobject]@{ Cmdlet = 'New-ServicePrincipal'; What = ('register {0} ({1}) in Exchange' -f $i.DisplayName, $i.AppId)
                                         Parameters = @{ AppId = "$($i.AppId)"; ObjectId = "$($i.ObjectId)"; DisplayName = ('SecurityInsight - {0}' -f $i.DisplayName) } })
        }
    }
    $filter = "PrimarySmtpAddress -eq '$Address'"
    $scope = @($Scopes | Where-Object { $_ -and "$($_.Name)" -eq $ScopeName }) | Select-Object -First 1
    if ($scope) {
        $have = "$($scope.RecipientFilter)$($scope.RecipientRestrictionFilter)"
        if ($have -and $have -notmatch [regex]::Escape($Address)) {
            $named = @([regex]::Matches($have, "'([^']+@[^']+)'") | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
            $own = @($MailboxAddresses | Where-Object { $_ } | ForEach-Object { ("$_" -replace '^(?i)smtp:', '').ToLowerInvariant() })
            if (-not $named.Count -or @($named | Where-Object { $own -notcontains $_ }).Count) {
                throw ("the Exchange scope '{0}' already exists for another mailbox ({1}) -- refusing to re-point it; pass another -ScopeName" -f $ScopeName, $have)
            }
            $plan.Add([pscustomobject]@{ Cmdlet = 'Set-ManagementScope'; What = ('re-point scope {0} to {1} (the mailbox''s primary address changed; it filtered {2})' -f $ScopeName, $Address, ($named -join ', '))
                                         Parameters = @{ Identity = $ScopeName; RecipientRestrictionFilter = $filter } })
        }
    } else {
        $plan.Add([pscustomobject]@{ Cmdlet = 'New-ManagementScope'; What = ('scope {0} -> {1} only' -f $ScopeName, $Address)
                                     Parameters = @{ Name = $ScopeName; RecipientRestrictionFilter = $filter } })
    }
    # an assignment counts by what it grants: Mail.Send for this identity on this scope -- or on any other scope that
    # filters exactly this mailbox -- whatever it is called (adopted, never duplicated)
    $granting = @(@($ScopeName) + @(Get-SIMailScopesFor -Scopes $Scopes -Address $Address) | Select-Object -Unique)
    foreach ($i in @($Identities)) {
        $ids = Get-SIMailExoIds -ExoServicePrincipals $ExoServicePrincipals -AppId "$($i.AppId)" -ObjectId "$($i.ObjectId)"
        $name = Get-SIMailAssignmentName -AppId "$($i.AppId)" -MailboxName $MailboxName
        $has = @($Assignments | Where-Object { $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and $granting -contains "$($_.CustomResourceScope)" -and (
                    ($ids -contains "$($_.RoleAssignee)".ToLowerInvariant()) -or ($ids -contains "$($_.App)".ToLowerInvariant()) -or "$($_.Name)" -eq $name) })
        if (-not $has.Count) {
            $plan.Add([pscustomobject]@{ Cmdlet = 'New-ManagementRoleAssignment'; What = ('Application Mail.Send for {0}, scoped to {1}' -f $i.DisplayName, $ScopeName)
                                         Parameters = @{ Name = $name; App = "$($i.AppId)"; Role = 'Application Mail.Send'; CustomResourceScope = $ScopeName } })
        }
    }
    $plan.ToArray()
}

function ConvertTo-SIMailExoCommandText {
    <# PURE. One plan item as the PowerShell line an Exchange administrator runs (Connect-ExchangeOnline first). #>
    param([Parameter(Mandatory)]$Item)
    $parts = foreach ($k in @($Item.Parameters.Keys | Sort-Object)) {
        $v = $Item.Parameters[$k]
        if ($v -is [bool]) { if ($v) { '-{0}' -f $k } else { '-{0}:$false' -f $k } }
        else { "-{0} '{1}'" -f $k, ("$v" -replace "'", "''") }
    }
    ('{0} {1}' -f $Item.Cmdlet, ($parts -join ' ')).Trim()
}

function Get-SIMailAuthorizationVerdict {
    <#
        PURE. Test-ServicePrincipalAuthorization rows -> does the identity hold 'Application Mail.Send' IN SCOPE for the
        mailbox? Returns @{ InScope; Rows }. A row with RoleName 'Application Mail.Send' and InScope true = in scope.
    #>
    param([object[]]$Rows = @())
    $send = @($Rows | Where-Object { $_ -and "$($_.RoleName)" -eq 'Application Mail.Send' })
    [pscustomobject]@{ InScope = [bool](@($send | Where-Object { "$($_.InScope)" -eq 'True' }).Count); Rows = $send.Count }
}

function Select-SIMailTenantWideMailSend {
    <# PURE. The app-role assignments that are a tenant-wide Microsoft Graph Mail.Send. #>
    param([object[]]$Assignments = @(), [string]$GraphSpId, [string]$MailSendRoleId)
    @($Assignments | Where-Object { $_ -and "$($_.resourceId)" -eq $GraphSpId -and "$($_.appRoleId)" -eq $MailSendRoleId })
}

function Get-SIMailSettingsToSet {
    <# PURE. The settings SecurityInsight reads for the chosen mode (name -> value). #>
    param([string]$Mode, [string]$Address, [string]$ProbeMailbox, [string]$SmtpServer, [int]$SmtpPort, [bool]$SmtpUseSsl, [string]$SmtpUser, [string]$From)
    $s = [ordered]@{ SI_Mail_Mode = $Mode }
    switch ($Mode) {
        'sharedMailbox' { $s.SI_Mail_From = $Address; if ("$ProbeMailbox".Trim()) { $s.SI_Mail_ProbeMailbox = "$ProbeMailbox".Trim() } }
        'smtp' {
            $s.SmtpServer = $SmtpServer; $s.SMTPPort = $SmtpPort; $s.SMTP_UseSSL = [bool]$SmtpUseSsl
            if ("$SmtpUser".Trim()) { $s.SMTPUser = $SmtpUser; $s.Mail_SendAnonymous = $false } else { $s.Mail_SendAnonymous = $true }
            if ("$From".Trim()) { $s.SI_Mail_From = $From }
        }
    }
    $s
}

# ---------------------------------------------------------------------------------------------------------------------
#  #773 THE EXCHANGE ANSWER: THE HTTP STATUS FIRST, THE BODY ONLY WHEN IT CAN BE READ (a customer install, 2026-10-19, in
#  the Support session: InvokeCommand answered HTTP 403, application/json, no Content-Encoding, 435 bytes of 0x00 -- the
#  HTTP layer's automatic decoding threw "The archive entry was compressed using an unsupported compression method"
#  before the status was read, and the run said "its answer is not a refusal"). Asking for 'identity' did not help: a
#  client that decompresses by itself adds its own Accept-Encoding. So the Exchange call is made with a plain HttpClient
#  (AutomaticDecompression None): the status is read first, the bytes after it, and a body is decoded only when it is
#  valid (gzip / zlib-deflate by its own header, then text); a body that cannot be read is '' -- never an error that hides
#  the status. In a Support session the call goes through the recorder first (every action is recorded); a READ whose
#  answer the recorder could not read is asked once more this way, for its status.
# ---------------------------------------------------------------------------------------------------------------------
$script:SIMailDirectoryRoleNames = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'; '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    '31392ffb-586c-42d1-9346-e59415a2cc4e' = 'Exchange Recipient Administrator'; 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Global Reader'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'; '5d6b6bb7-de71-4623-b4af-96380a352509' = 'Security Reader'
    '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'; 'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'; '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' = 'Directory Readers'
    '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'; 'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'; '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
}

function Get-SIMailExoHeldRoleNames {
    <# PURE. The directory roles the Exchange token holds (its 'wids'), as names ('role <id>' for one not known here); the
       default member role is not a role anyone holds on purpose and is left out. '' when the token lists none. #>
    param($Claims)
    if (-not $Claims -or -not $Claims.PSObject.Properties['wids']) { return '' }
    $n = @(@($Claims.wids) | ForEach-Object { "$_".ToLowerInvariant() } | Where-Object { $_ -and $_ -ne 'b79fbf4d-3ef9-4689-8143-76b194e85509' } | Select-Object -Unique |
        ForEach-Object { if ($script:SIMailDirectoryRoleNames.ContainsKey($_)) { $script:SIMailDirectoryRoleNames[$_] } else { 'role ' + $_ } })
    ($n -join ', ')
}

function Get-SIMailExoLacksRoleText {
    <# PURE. The one sentence for a refused Exchange read: which role is needed and which the sign-in holds. #>
    param([string]$HeldRoles)
    $h = if ("$HeldRoles".Trim()) { "$HeldRoles".Trim() } else { 'no directory role' }
    'this sign-in lacks the Exchange role needed: Exchange Administrator, or the Role Management role group (it holds {0})' -f $h
}

function ConvertFrom-SIMailExoBytes {
    <#
        PURE. The bytes of an Exchange answer -> its text, ONLY when they can be read: gzip (1F 8B) and zlib-deflate
        (78 xx, or Content-Encoding deflate) are opened by their own header; text with NUL characters, or nothing but zero
        bytes, is not text. '' when the body cannot be read -- it never throws.
    #>
    param([AllowNull()][byte[]]$Bytes, [string]$ContentEncoding)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    $b = $Bytes
    try {
        $open = $null
        if ($b.Length -ge 2 -and $b[0] -eq 0x1F -and $b[1] -eq 0x8B) { $open = 'gzip' }
        elseif ($b.Length -ge 2 -and $b[0] -eq 0x78 -and ((([int]$b[0]) * 256 + [int]$b[1]) % 31) -eq 0) { $open = 'zlib' }
        elseif ("$ContentEncoding" -match '(?i)\bdeflate\b') { $open = 'deflate' }
        if ($open) {
            if (-not ('System.IO.Compression.GZipStream' -as [type])) { Add-Type -AssemblyName System.IO.Compression }
            $offset = 0; if ($open -eq 'zlib') { $offset = 2 }
            $in = New-Object System.IO.MemoryStream($b, $offset, ($b.Length - $offset))
            $z = if ($open -eq 'gzip') { New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress) } else { New-Object System.IO.Compression.DeflateStream($in, [System.IO.Compression.CompressionMode]::Decompress) }
            $out = New-Object System.IO.MemoryStream
            try { $z.CopyTo($out) } finally { $z.Dispose() }
            $b = $out.ToArray()
        }
    } catch { return '' }
    if ($b.Length -eq 0) { return '' }
    $nonZero = $false; foreach ($x in $b) { if ($x -ne 0) { $nonZero = $true; break } }
    if (-not $nonZero) { return '' }
    $t = [Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xFEFF)
    if ($t.IndexOf([char]0) -ge 0) { return '' }
    $t
}

function Test-SIMailExoUnreadAnswer {
    <# PURE. The recorder's error for an Exchange answer it could not read (no status: a decode failure, no answer). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    "$Text" -match '(?i)HTTP Status: 0 \(NoResponse\)|unsupported compression method|archive entry|Block length does not match|The response ended prematurely|magic number in GZip header'
}

function ConvertFrom-SIMailExoAnswer {
    <# PURE. @{ StatusCode; Text } -> the parsed answer on 2xx; else THROWS with the HTTP status in words (the refusal path
       reads 401 / 403 from it). A 2xx whose body cannot be read throws too -- never an empty success. #>
    param([Parameter(Mandatory)]$Answer, [string]$Uri = 'InvokeCommand')
    $code = [int]$Answer.StatusCode; $text = [string]$Answer.Text
    if ($code -ge 200 -and $code -lt 300) {
        if (-not $text.Trim()) { throw ('POST {0}: Exchange answered HTTP {1}, but the answer could not be read (no readable body)' -f $Uri, $code) }
        try { return ($text | ConvertFrom-Json) } catch { throw ('POST {0}: Exchange answered HTTP {1}, but the answer is not JSON: {2}' -f $Uri, $code, $(if ($text.Length -gt 200) { $text.Substring(0, 200) } else { $text })) }
    }
    $name = switch ($code) { 0 { 'NoResponse' } 400 { 'BadRequest' } 401 { 'Unauthorized' } 403 { 'Forbidden' } 404 { 'NotFound' } 429 { 'TooManyRequests' } 500 { 'InternalServerError' } 502 { 'BadGateway' } 503 { 'ServiceUnavailable' } 504 { 'GatewayTimeout' } default { 'HTTP' } }
    throw ('POST {0} failed. HTTP Status: {1} ({2}) Response: {3}' -f $Uri, $code, $name, $(if ($text.Trim()) { $text } else { '(no readable body)' }))
}

function Invoke-SIMailExoHttp {
    <#
        One InvokeCommand POST with a plain HttpClient: AutomaticDecompression None (no Accept-Encoding of its own), the
        STATUS read first, then the bytes, decoded only when valid (ConvertFrom-SIMailExoBytes). Returns @{ StatusCode;
        Text; Bytes }. Tests set $global:SI_MailExoHttp { param($Uri, $Token, $Body, $Headers) @{ StatusCode; Bytes;
        ContentEncoding } } -- the network answer; the decoding is this function's either way.
    #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Body, [hashtable]$Headers = @{}, [int]$TimeoutSec = 180)
    $raw = $null
    if ($global:SI_MailExoHttp -is [scriptblock]) { $raw = & $global:SI_MailExoHttp $Uri $Token $Body $Headers }
    else {
        if (-not ('System.Net.Http.HttpClient' -as [type])) { Add-Type -AssemblyName System.Net.Http }
        $hd = New-Object System.Net.Http.HttpClientHandler
        $hd.AutomaticDecompression = [System.Net.DecompressionMethods]::None
        $c = New-Object System.Net.Http.HttpClient($hd)
        $c.Timeout = [TimeSpan]::FromSeconds([Math]::Max(10, $TimeoutSec))
        try {
            $rq = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $Uri)
            [void]$rq.Headers.TryAddWithoutValidation('Authorization', 'Bearer ' + $Token)
            foreach ($k in @($Headers.Keys)) { [void]$rq.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k]) }
            $rq.Content = New-Object System.Net.Http.StringContent($Body, [Text.Encoding]::UTF8, 'application/json')
            $rs = $c.SendAsync($rq).GetAwaiter().GetResult()
            $code = [int]$rs.StatusCode
            [byte[]]$bytes = $null
            try { $bytes = $rs.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult() } catch { $bytes = $null }
            $raw = [pscustomobject]@{ StatusCode = $code; Bytes = $bytes; ContentEncoding = (@($rs.Content.Headers.ContentEncoding) -join ',') }
        } finally { $c.Dispose() }
    }
    [byte[]]$rb = $null; if ($null -ne $raw.Bytes) { $rb = [byte[]]$raw.Bytes }
    $n = 0; if ($rb) { $n = $rb.Length }
    [pscustomobject]@{ StatusCode = [int]$raw.StatusCode; Text = (ConvertFrom-SIMailExoBytes -Bytes $rb -ContentEncoding ([string]$raw.ContentEncoding)); Bytes = $n }
}

if ($LoadFunctionsOnly) { return }

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIMail' -Quiet:($false)
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the plan: nothing is created, granted or removed
try {
$ErrorActionPreference = 'Stop'

# =====================================================================================================================
#  The run
# =====================================================================================================================
$result = [ordered]@{ ok = $false; mode = $Mode; apply = [bool]$Apply; tenantId = ''; mailbox = ''; scope = $ScopeName; identities = @(); steps = @(); commands = @(); settings = $null; reason = '' }
function Note([string]$m, [string]$c = 'Gray') { Write-Host ('    ' + $m) -ForegroundColor $c }
function Step([string]$m) { Write-Host ''; Write-Host ('--- {0} ---' -f $m) -ForegroundColor Cyan }
function Add-Step([string]$name, [string]$state, [string]$detail) { $result.steps += [ordered]@{ step = $name; state = $state; detail = $detail } }
function Save-Result {
    if (-not "$OutFile".Trim()) { return }
    try { ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch { Write-Warning ("could not write {0}: {1}" -f $OutFile, $_.Exception.Message) }
}
function Stop-SIMail([string]$reason) { $result.reason = $reason; Save-Result; Write-Host ''; Write-Host ('RESULT: STOPPED -- ' + $reason) -ForegroundColor Red; exit 1 }

# #521: setup's own REST sign-in, never the az CLI (an existing sign-in in this process is reused).
if (-not (Get-Command -Name Connect-SISetupAzure -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
if (-not (Get-Command -Name Get-SISetupAccessToken -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1')) }
function Get-SIMailToken {
    param([Parameter(Mandatory)][string]$Resource)
    if (-not $UseSignedInAccount) { throw 'no sign-in: pass -UseSignedInAccount (setup''s own sign-in: Azure Cloud Shell, the browser, or the Invardia support session)' }
    if (-not $script:SIMailSignedIn) {
        $ca = @{}; if ($TenantId) { $ca.TenantId = $TenantId }; if ($SubscriptionId) { $ca.SubscriptionId = $SubscriptionId }
        $null = Connect-SISetupAzure @ca
        $script:SIMailSignedIn = $true
    }
    $t = "$(Get-SISetupAccessToken -Resource $Resource)".Trim()
    if (-not $t) { throw ("the sign-in gave no token for {0}{1}" -f $Resource, $(if ($TenantId) { " in tenant $TenantId" } else { '' })) }
    $t
}

function Invoke-SIMailRest {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Token, $Body, [hashtable]$Headers = @{}, [int]$TimeoutSec = 180)
    $h = @{ Authorization = 'Bearer ' + $Token }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    $a = @{ Method = $Method; Uri = $Uri; Headers = $h; ErrorAction = 'Stop'; TimeoutSec = $TimeoutSec }
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -Depth 20 -Compress -InputObject $Body }
        $a.Body = [Text.Encoding]::UTF8.GetBytes($json); $a.ContentType = 'application/json; charset=utf-8'
    }
    Invoke-SIRestMethod @a   # #548: through the support recorder in a support session
}

function Get-SIMailErrorText($er) { ("{0} {1}" -f $er.Exception.Message, $er.ErrorDetails.Message) -replace '\s+', ' ' }

function Get-SIMailGraphAll {
    param([Parameter(Mandatory)][string]$Path)
    $u = if ($Path -like 'http*') { $Path } else { 'https://graph.microsoft.com/v1.0/' + $Path }
    $items = @(); $n = 0
    while ($u) {
        if (++$n -gt 50) { throw ('more than 50 pages reading {0}' -f $Path) }
        $r = Invoke-SIMailRest -Uri $u -Token $script:GraphToken
        $items += @($r.value)
        $u = if ($r.PSObject.Properties['@odata.nextLink']) { [string]$r.'@odata.nextLink' } else { $null }
    }
    $items
}

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host (' SecurityInsight mail -- {0} ({1})' -f $Mode, $(if ($Apply) { 'APPLY' } else { 'plan only: nothing is changed' })) -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

if ($Mode -eq 'none') {
    $result.settings = Get-SIMailSettingsToSet -Mode 'none'
    Note 'SecurityInsight sends no mail. Set SI_Mail_Mode = none (Settings > E-mail, or config\SecurityInsight.custom.ps1).' 'Yellow'
    $result.ok = $true; Save-Result; return
}

# ---------------------------------------------------------------------------------------------------------------------
#  smtp
# ---------------------------------------------------------------------------------------------------------------------
if ($Mode -eq 'smtp') {
    Step 'SMTP relay'
    if (-not "$SmtpServer".Trim()) { Stop-SIMail '-SmtpServer is required for -Mode smtp' }
    $fromAddr = if ("$From".Trim()) { "$From".Trim() } elseif ("$SmtpUser".Trim() -match '@') { "$SmtpUser".Trim() } else { '' }
    if (-not $fromAddr) { Stop-SIMail '-From (the sender address) is required' }
    Note ("relay {0}:{1} ({2}), {3}, from {4}" -f $SmtpServer, $SmtpPort, $(if ($SmtpUseSsl) { 'STARTTLS' } else { 'no TLS' }), $(if ($SmtpUser) { 'signs in as ' + $SmtpUser } else { 'anonymous' }), $fromAddr)
    if ("$SmtpUser".Trim()) {
        if (-not $KeyVaultName) { Stop-SIMail ('-KeyVaultName is required: the SMTP password goes to the install''s Key Vault (secret {0}), never into configuration' -f $SmtpPasswordSecretName) }
        if (-not $Apply) { Note ("would store the SMTP password in Key Vault {0} as {1} (asked for with -Apply)" -f $KeyVaultName, $SmtpPasswordSecretName) 'Yellow' }
        else {
            if (-not $SmtpPassword) { $SmtpPassword = Read-Host -AsSecureString ('Password for {0} (not shown)' -f $SmtpUser) }
            $plain = (New-Object System.Management.Automation.PSCredential ('x', $SmtpPassword)).GetNetworkCredential().Password
            if (-not $plain) { Stop-SIMail 'the password is empty -- refusing to store a blank secret' }
            try {
                $kvTok = Get-SIMailToken -Resource 'https://vault.azure.net'
                $null = Invoke-SIMailRest -Method PUT -Uri ('https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $KeyVaultName, $SmtpPasswordSecretName) -Token $kvTok -Body @{ value = $plain }
                $back = Invoke-SIMailRest -Uri ('https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $KeyVaultName, $SmtpPasswordSecretName) -Token $kvTok
                if ("$($back.value)" -ne $plain) { throw 'read-back mismatch' }
                Note ("stored and read back: {0}/{1}" -f $KeyVaultName, $SmtpPasswordSecretName) 'Green'; Add-Step 'smtp-password' 'stored' $SmtpPasswordSecretName
            } catch { Stop-SIMail ("the SMTP password could not be stored in Key Vault {0}: {1} (Key Vault Secrets Officer is needed)" -f $KeyVaultName, (Get-SIMailErrorText $_)) }
        }
    }
    if ($TestTo.Count -and $Apply) {
        Step 'test mail through the relay'
        # MAIL-3 (#653): the product last; this standalone script cannot read the environment's name, so no '[<name>]'
        try {
            $p = @{ SmtpServer = $SmtpServer; Port = $SmtpPort; From = $fromAddr; To = $TestTo; Subject = 'Test mail [SecurityInsight]'; Body = '<p>SecurityInsight can send mail through this relay.</p>'; BodyAsHtml = $true; Encoding = 'UTF8'; ErrorAction = 'Stop' }
            if ($SmtpUseSsl) { $p.UseSsl = $true }
            if ("$SmtpUser".Trim() -and $plain) { $p.Credential = New-Object System.Management.Automation.PSCredential ($SmtpUser, (ConvertTo-SecureString $plain -AsPlainText -Force)) }
            # The ONE place outside the engine's transport that talks SMTP: this file is downloaded on its own and cannot load it.
            Send-MailMessage @p 3>$null
            Note ('test mail accepted by the relay for {0}' -f ($TestTo -join ', ')) 'Green'; Add-Step 'smtp-test' 'sent' ($TestTo -join ', ')
        } catch { Add-Step 'smtp-test' 'failed' (Get-SIMailErrorText $_); Note ('test mail FAILED: ' + (Get-SIMailErrorText $_)) 'Red' }
    }
    $plain = $null
    $result.settings = Get-SIMailSettingsToSet -Mode smtp -SmtpServer $SmtpServer -SmtpPort $SmtpPort -SmtpUseSsl ([bool]$SmtpUseSsl) -SmtpUser $SmtpUser -From $fromAddr
    Step 'settings for SecurityInsight'
    foreach ($k in $result.settings.Keys) { Note ('{0} = {1}' -f $k, $result.settings[$k]) 'White' }
    $result.ok = $true; Save-Result; return
}

# ---------------------------------------------------------------------------------------------------------------------
#  sharedMailbox
# ---------------------------------------------------------------------------------------------------------------------
Step 'sign-in'
try { $script:GraphToken = Get-SIMailToken -Resource 'https://graph.microsoft.com' } catch { Stop-SIMail $_.Exception.Message }
$gClaims = ConvertFrom-SIMailJwt $script:GraphToken
if (-not $TenantId) { $TenantId = [string]$gClaims.tid }
$result.tenantId = $TenantId
$signedInUpn = [string]$(if ($gClaims.upn) { $gClaims.upn } elseif ($gClaims.unique_name -and "$($gClaims.unique_name)" -match '@') { $gClaims.unique_name } else { '' })
$isApp = -not $signedInUpn
Note ('tenant {0}, signed in as {1}' -f $TenantId, $(if ($isApp) { 'the app ' + $gClaims.appid } else { $signedInUpn }))

# -ActivateExchangeAdmin (the Invardia Support app; the same model PIM uses): an app gets the Exchange Administrator role it
# needs here for -ExchangeAdminHours only, through Entra PIM (roleAssignmentScheduleRequests) -- it ends by itself, never a
# standing assignment. BEFORE any Exchange token is minted: the role is in the token's claims at issue.
if ($ActivateExchangeAdmin -and $isApp -and $Apply) {
    Step 'Exchange Administrator for this app (time-bound, through Entra PIM)'
    $exRole = '29232cdf-9323-42fd-ade2-1d097af3e4de'   # Exchange Administrator (built-in; definition id = template id)
    $me = @((Invoke-SIMailRest -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $gClaims.appid) -Token $script:GraphToken).value)[0]
    if (-not $me) { Stop-SIMail 'the signed-in app has no service principal in this tenant' }
    $readActive = { @((Invoke-SIMailRest -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '{0}' and roleDefinitionId eq '{1}'" -f $me.id, $exRole) -Token $script:GraphToken).value).Count -gt 0 }
    $active = $false
    try { $active = & $readActive } catch { Stop-SIMail ('the app''s directory roles could not be read: {0}' -f (Get-SIMailErrorText $_)) }
    if ($active) { Note 'Exchange Administrator is already active for this app' 'DarkGray' }
    else {
        $req = @{ action = 'adminAssign'; principalId = $me.id; roleDefinitionId = $exRole; directoryScopeId = '/'
            justification = 'SecurityInsight mail setup (Set-SIMail.ps1): the shared mailbox and its scoped send right'
            scheduleInfo = @{ startDateTime = [datetime]::UtcNow.ToString('o'); expiration = @{ type = 'afterDuration'; duration = ('PT{0}H' -f $ExchangeAdminHours) } } }
        try { $null = Invoke-SIMailRest -Method POST -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests' -Token $script:GraphToken -Body $req }
        catch { Stop-SIMail ('Exchange Administrator could not be activated for this app ({0}) -- assign it ACTIVE and TIME-BOUND in Entra > Roles > Exchange Administrator, then re-run' -f (Get-SIMailErrorText $_)) }
        $until = (Get-Date).AddMinutes(3)
        while (-not $active -and (Get-Date) -lt $until) { Start-Sleep -Seconds 10; try { $active = & $readActive } catch { } }
        if (-not $active) { Stop-SIMail 'the Exchange Administrator request was accepted but the role is not active on read-back -- re-run in a few minutes' }
        Note ('Exchange Administrator active for {0} hour(s), ends by itself (verified by read-back)' -f $ExchangeAdminHours) 'Green'
        Add-Step 'exchange-admin' 'activated' ('PT{0}H' -f $ExchangeAdminHours)
    }
}

Step '[0] Exchange Online plan'
try { $skus = @((Invoke-SIMailRest -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -Token $script:GraphToken).value) }
catch { $skus = $null; Note ('subscribedSkus could not be read ({0}) -- not checked' -f (Get-SIMailErrorText $_)) 'DarkYellow' }
if ($null -ne $skus) {
    $plans = @(Select-SIMailExchangePlans -SubscribedSkus $skus)
    if (-not $plans.Count) { Stop-SIMail 'this tenant has no Exchange Online plan beyond EXCHANGE_S_FOUNDATION -- a shared mailbox cannot be created or used (Foundation comes with Entra ID P2 and only creates directory objects). Add an Exchange Online plan; a shared mailbox itself needs no licence.' }
    Note ('Exchange plan(s): {0}' -f ($plans -join ', ')) 'Green'
}

Step '[1] the shared mailbox address'
$org = $null; try { $org = @((Invoke-SIMailRest -Uri 'https://graph.microsoft.com/v1.0/organization' -Token $script:GraphToken).value)[0] } catch { }
$initialDomain = if ($org) { "$(@(@($org.verifiedDomains) | Where-Object { $_.isInitial }) | Select-Object -First 1 | ForEach-Object { $_.name })".Trim() } else { '' }
$addr = Resolve-SIMailSenderAddress -SharedMailbox $SharedMailbox -MailboxName $MailboxName -InitialDomain $initialDomain -MailDomain $MailDomain
if ($addr.Reason) { Stop-SIMail $addr.Reason }
$address = $addr.Address; $result.mailbox = $address
Note ('SecurityInsight sends as {0}' -f $address) 'Green'

Step '[2] SecurityInsight''s sending identities'
$oids = @($IdentityObjectId | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $oids.Count -and $SubscriptionId -and $ResourceGroup) {
    try {
        $armTok = Get-SIMailToken -Resource 'https://management.azure.com'
        $base = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers' -f $SubscriptionId, $ResourceGroup
        foreach ($u in @(
                @{ Uri = "$base/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31"; Kind = 'uami' },
                @{ Uri = "$base/Microsoft.App/containerApps?api-version=2024-03-01"; Kind = 'sys' },
                @{ Uri = "$base/Microsoft.App/jobs?api-version=2024-03-01"; Kind = 'sys' },
                @{ Uri = "$base/Microsoft.Web/sites?api-version=2023-12-01"; Kind = 'sys' })) {
            $list = @(); try { $list = @((Invoke-SIMailRest -Uri $u.Uri -Token $armTok).value) } catch { }
            foreach ($r in $list) {
                $p = if ($u.Kind -eq 'uami') { "$($r.properties.principalId)" } elseif ($r.identity -and "$($r.identity.type)" -match 'SystemAssigned') { "$($r.identity.principalId)" } else { '' }
                if ($p -and $oids -notcontains $p -and -not ($ExcludeIdentityPattern -and "$($r.name)" -match $ExcludeIdentityPattern)) { $oids += $p; Note ('{0}: {1} -> {2}' -f $(if ($u.Kind -eq 'uami') { 'managed identity' } else { 'system identity of' }), $r.name, $p) 'DarkGray' }
            }
        }
    } catch { Stop-SIMail ('the identities in {0} could not be read: {1}' -f $ResourceGroup, (Get-SIMailErrorText $_)) }
}
if (-not $oids.Count) { Stop-SIMail 'no sending identity: pass -IdentityObjectId (service principal object ids), or -SubscriptionId + -ResourceGroup of the install' }
$identities = @()
foreach ($o in $oids) {
    try { $sp = Invoke-SIMailRest -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}?`$select=id,appId,displayName,servicePrincipalType" -f $o) -Token $script:GraphToken }
    catch { Stop-SIMail ('service principal {0} was not found: {1}' -f $o, (Get-SIMailErrorText $_)) }
    $identities += [pscustomobject]@{ ObjectId = [string]$sp.id; AppId = [string]$sp.appId; DisplayName = [string]$sp.displayName; Type = [string]$sp.servicePrincipalType }
    Note ('sends as {0} (app id {1}, object id {2})' -f $sp.displayName, $sp.appId, $sp.id) 'Green'
}
$result.identities = @($identities | ForEach-Object { [ordered]@{ name = $_.DisplayName; appId = $_.AppId; objectId = $_.ObjectId } })

Step '[3] no tenant-wide Microsoft Graph Mail.Send (it would defeat the scope)'
$graphSp = @((Invoke-SIMailRest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -Token $script:GraphToken).value)[0]
$mailSendRole = @($graphSp.appRoles | Where-Object { $_.value -eq 'Mail.Send' -and $_.allowedMemberTypes -contains 'Application' })[0]
foreach ($i in $identities) {
    try { $found = @(Select-SIMailTenantWideMailSend -Assignments @(Get-SIMailGraphAll -Path ("servicePrincipals/{0}/appRoleAssignments" -f $i.ObjectId)) -GraphSpId $graphSp.id -MailSendRoleId $mailSendRole.id) }
    catch { Stop-SIMail ('the Graph permissions of {0} could not be read, so a tenant-wide Mail.Send cannot be ruled out: {1}' -f $i.DisplayName, (Get-SIMailErrorText $_)) }
    if (-not $found.Count) { Note ('{0}: no tenant-wide Mail.Send -- correct' -f $i.DisplayName) 'Green'; Add-Step ('graph-mailsend:' + $i.AppId) 'absent' ''; continue }
    if (-not $Apply) { Note ('{0}: HOLDS a tenant-wide Mail.Send -- would REMOVE it (-Apply)' -f $i.DisplayName) 'Yellow'; Add-Step ('graph-mailsend:' + $i.AppId) 'would-remove' ''; continue }
    foreach ($a in $found) {
        try { $null = Invoke-SIMailRest -Method DELETE -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments/{1}' -f $i.ObjectId, $a.id) -Token $script:GraphToken }
        catch { Stop-SIMail ('the tenant-wide Mail.Send on {0} could not be removed: {1}' -f $i.DisplayName, (Get-SIMailErrorText $_)) }
    }
    Note ('{0}: tenant-wide Mail.Send REMOVED' -f $i.DisplayName) 'Green'; Add-Step ('graph-mailsend:' + $i.AppId) 'removed' ''
}

Step '[4] Exchange: read what exists'
$exoUri = 'https://outlook.office365.com/adminapi/beta/{0}/InvokeCommand' -f $TenantId
$anchor = Get-SIMailExoAnchor -Upn $signedInUpn -InitialDomain $initialDomain
function Invoke-SIMailExo {
    param([Parameter(Mandatory)][string]$Cmdlet, [hashtable]$Parameters = @{})
    $tok = Get-SIMailToken -Resource 'https://outlook.office365.com'
    $body = New-SIMailExoRequestBody -Cmdlet $Cmdlet -Parameters $Parameters
    $hdr = Get-SIMailExoHeaders -Anchor $anchor
    # #773: in a Support session through the recorder (every action recorded); a READ whose answer the recorder could not
    # read (no status) is asked once more with the plain client, for its STATUS -- a change is never sent twice
    if ((Test-Path -LiteralPath 'Function:\Test-SISupportRequestRoute') -and (Test-SISupportRequestRoute -Audience 'Exchange')) {
        try { return (Invoke-SIMailRest -Method POST -Uri $exoUri -Token $tok -Body $body -Headers $hdr) }
        catch {
            $t = Get-SIMailErrorText $_
            if (-not (Test-SIMailExoUnreadAnswer -Text $t) -or $Cmdlet -notmatch '^(Get|Test)-') { throw }
            Note ('Exchange''s answer to {0} could not be read through the support session -- its HTTP status is read directly' -f $Cmdlet) 'DarkGray'
        }
    }
    ConvertFrom-SIMailExoAnswer -Answer (Invoke-SIMailExoHttp -Uri $exoUri -Token $tok -Body $body -Headers $hdr) -Uri $exoUri
}
$exoDenied = $false; $exoErr = ''
$reads = @{}
# the Exchange sign-in first (its own client, see SI-SetupSignIn.ps1), and which admin role it carries -- read from the
# token itself, before any Exchange call
$exoRole = $null
$exoHeld = ''
try { $exoClaims = ConvertFrom-SIMailJwt (Get-SIMailToken -Resource 'https://outlook.office365.com'); $exoRole = Get-SIMailExoRoleVerdict -Claims $exoClaims; $exoHeld = Get-SIMailExoHeldRoleNames -Claims $exoClaims }
catch { Stop-SIMail ('the sign-in for Exchange Online did not complete: {0}' -f $_.Exception.Message) }
Note ('Exchange sign-in: {0}' -f $exoRole.Text) $(if ($exoRole.State -eq 'active') { 'DarkGray' } else { 'Yellow' })
foreach ($c in @(@{ C = 'Get-ServicePrincipal'; P = @{} }, @{ C = 'Get-ManagementScope'; P = @{} }, @{ C = 'Get-ManagementRoleAssignment'; P = @{ RoleAssigneeType = 'ServicePrincipal' } })) {
    $ok = $false
    foreach ($try in 1..4) {
        try { $reads[$c.C] = @((Invoke-SIMailExo -Cmdlet $c.C -Parameters $c.P).value); $ok = $true; break }
        catch { $exoErr = Get-SIMailErrorText $_; if ($try -lt 4 -and $exoErr -match '(?i)\b429\b|\b50[234]\b|timed out') { Start-Sleep -Seconds 15 } else { break } }
    }
    if (-not $ok) { if (Test-SIMailExoDenied -Text $exoErr) { $exoDenied = $true }; break }
}
$mailboxExists = $false
if (-not $exoDenied -and $reads.Count -eq 3) {
    try { $mb = @((Invoke-SIMailExo -Cmdlet 'Get-Mailbox' -Parameters @{ Identity = $address }).value) | Select-Object -First 1; if ($mb) { $mailboxExists = $true; Note ('mailbox exists ({0})' -f $mb.RecipientTypeDetails) 'DarkGray' } }
    catch {
        $e = Get-SIMailErrorText $_
        if (Test-SIMailExoDenied -Text $e) { $exoDenied = $true; $exoErr = $e }   # a refusal is never "does not exist"
        elseif (-not (Test-SIMailExoNotFound -Text $e)) { Stop-SIMail ('could not check whether {0} exists ({1}) -- refusing to create it on a guess' -f $address, $e) }
        else { Note 'mailbox does not exist yet' 'DarkGray' }
    }
}
# what Exchange was read is all that is known: after a refusal or no answer the mailbox is UNKNOWN, never "missing"
$exoRead = (-not $exoDenied -and $reads.Count -eq 3)
$exoShort = $(if ($exoErr.Length -gt 300) { $exoErr.Substring(0, 300) } else { $exoErr })
if ($exoDenied) {
    # Exchange REFUSED this sign-in (recognised as a refusal): say so plainly, plan from nothing, hand the commands over.
    foreach ($l in @(Get-SIMailExoRefusalLines -Status (Get-SIMailHttpStatus -Text $exoErr) -Address $address -RoleText $exoRole.Text -HeldRoles $exoHeld)) { Note $l 'Yellow' }
    Note ('Exchange answered: {0}' -f $exoShort) 'DarkGray'
} elseif ($reads.Count -ne 3) {
    # NOT a recognised refusal (no answer, an answer that could not be read, a server error): say what Exchange
    # answered -- never "no Exchange rights" on a guess. The commands are still printed below, for whoever takes over.
    Note ('Exchange did not answer the read, and its answer is not a refusal: {0}' -f $(if ($exoShort) { $exoShort } else { '(no answer text)' })) 'Yellow'
    Note 'Whether this sign-in has an Exchange role is NOT known from that. Run the same command again; if it stays, the commands below work for an Exchange administrator.' 'Yellow'
}
# the scope: the one given, else one that already filters exactly this mailbox (adopted), else <MailboxName>-Sender
$ScopeName = Resolve-SIMailScopeName -ScopeName $ScopeName -MailboxName $MailboxName -Address $address -Scopes @($reads['Get-ManagementScope'])
$result.scope = $ScopeName
Note ('Exchange scope: {0}' -f $ScopeName) 'DarkGray'
$plan = @(New-SIMailExoPlan -MailboxExists $mailboxExists -MailboxKnown $exoRead -CreateMailbox $CreateMailbox -Address $address -MailboxName $MailboxName -DisplayName $DisplayName -ScopeName $ScopeName `
            -Identities $identities -ExoServicePrincipals @($reads['Get-ServicePrincipal']) -Scopes @($reads['Get-ManagementScope']) -Assignments @($reads['Get-ManagementRoleAssignment']) `
            -MailboxAddresses $(if ($mailboxExists -and $mb -and $mb.PSObject.Properties['EmailAddresses']) { @($mb.EmailAddresses | ForEach-Object { [string]$_ }) } else { @() }))
$result.commands = @($plan | ForEach-Object { ConvertTo-SIMailExoCommandText -Item $_ })
Step '[5] Exchange: the plan'
if (-not $plan.Count) { Note 'mailbox, registrations, scope and scoped role assignments are in place' 'Green' }
foreach ($p in $plan) { Note ('{0}  ->  {1}' -f $p.What, (ConvertTo-SIMailExoCommandText -Item $p)) 'White' }

if ($plan.Count -and (-not $exoRead -or -not $Apply)) {
    Write-Host ''
    Write-Host '  For your Exchange administrator (Connect-ExchangeOnline first), in this order:' -ForegroundColor White
    foreach ($l in $result.commands) { Write-Host ('    ' + $l) -ForegroundColor White }
    foreach ($i in $identities) { Write-Host ("    Test-ServicePrincipalAuthorization -Identity '{0}' -Resource '{1}'" -f $i.AppId, $address) -ForegroundColor White }
}
if ($exoDenied) {
    # NOT DONE, never green: exit 2 = handed to the Exchange administrator (the guided install reads it that way)
    $exoStatus = Get-SIMailHttpStatus -Text $exoErr
    Add-Step 'exchange' 'handed-over' ('Exchange refused this sign-in{0}' -f $(if ($exoStatus) { " (HTTP $exoStatus)" } else { '' }))
    $result.ok = $false; $result.reason = ('Exchange refused this sign-in{0}: {1} -- nothing was changed; the Exchange steps are handed to the Exchange administrator' -f $(if ($exoStatus) { " (HTTP $exoStatus)" } else { '' }), (Get-SIMailExoLacksRoleText -HeldRoles $exoHeld))
    Save-Result
    Write-Host ''
    Write-Host ('RESULT: NOT DONE -- ' + $result.reason) -ForegroundColor Red
    exit 2
}
# not a recognised refusal: NOT handed over as "no rights" -- stopped, with what Exchange answered (exit 1: try again)
if ($reads.Count -ne 3) { Add-Step 'exchange' 'failed' ('Exchange did not answer the read: {0}' -f $exoShort); Stop-SIMail ('Exchange could not be read, and its answer is not a refusal ({0}) -- nothing was changed; run the same command again' -f $(if ($exoShort) { $exoShort } else { 'no answer text' })) }

if ($Apply -and $plan.Count) {
    Step '[6] Exchange: apply'
    foreach ($p in $plan) {
        $stop = (Get-Date).AddSeconds($TimeoutSeconds); $done = $false
        while (-not $done) {
            try { $null = Invoke-SIMailExo -Cmdlet $p.Cmdlet -Parameters $p.Parameters; Note ('{0}: done' -f $p.What) 'Green'; Add-Step $p.Cmdlet 'created' $p.What; $done = $true }
            catch {
                $e = Get-SIMailErrorText $_
                switch (Resolve-SIMailExoCreateOutcome -Cmdlet $p.Cmdlet -ErrorText $e) {
                    'exists' { Note ('{0}: already there' -f $p.What) 'DarkGray'; Add-Step $p.Cmdlet 'already' $p.What; $done = $true }
                    'dehydrated' {
                        if ((Get-Date) -ge $stop) { Stop-SIMail ('{0}: the Exchange organization is still not customizable' -f $p.What) }
                        try { $null = Invoke-SIMailExo -Cmdlet 'Enable-OrganizationCustomization' } catch { }
                        Note 'the Exchange organization is not customizable yet -- waiting' 'DarkGray'; Start-Sleep -Seconds 60
                    }
                    'retry' { if ((Get-Date) -ge $stop) { Stop-SIMail ('{0}: Exchange never made the new service principal usable' -f $p.What) }; Note 'Exchange has not made the new registration usable yet -- waiting' 'DarkGray'; Start-Sleep -Seconds 30 }
                    'denied' { Stop-SIMail ('{0}: refused -- this needs the Exchange Administrator role, or the roles "Mail Recipient Creation" + "Role Management" ({1})' -f $p.What, $e) }
                    default { Stop-SIMail ('{0} failed: {1}' -f $p.What, $e) }
                }
            }
        }
        if ($p.Cmdlet -eq 'New-Mailbox') {
            $seen = $false; $until = (Get-Date).AddSeconds([Math]::Min(240, [Math]::Max(30, $TimeoutSeconds)))   # #564: bounded by -TimeoutSeconds
            while (-not $seen -and (Get-Date) -lt $until) { try { $seen = [bool](@((Invoke-SIMailExo -Cmdlet 'Get-Mailbox' -Parameters @{ Identity = $address }).value).Count) } catch { }; if (-not $seen) { Start-Sleep -Seconds 10 } }
            if (-not $seen) { Stop-SIMail ('the mailbox {0} was created but is not visible after 4 minutes -- re-run (safe)' -f $address) }
        }
    }
}

Step '[7] verify the restriction'
$verified = $true
if (-not $Apply -and $plan.Count) { Note 'not verified: the plan has not been applied' 'Yellow'; $verified = $false }
else {
    if (-not "$ProbeMailbox".Trim() -and $signedInUpn) { $ProbeMailbox = $signedInUpn }
    if (-not "$ProbeMailbox".Trim()) {
        try { $u = @((Invoke-SIMailRest -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Member' and mail ne null&`$select=mail,userPrincipalName&`$top=5&`$count=true" -Token $script:GraphToken -Headers @{ ConsistencyLevel = 'eventual' }).value) | Where-Object { "$($_.mail)" -ne $address } | Select-Object -First 1; if ($u) { $ProbeMailbox = [string]$u.mail } } catch { }
    }
    foreach ($i in $identities) {
        $inOk = $false; $outOk = $null; $until = (Get-Date).AddSeconds([Math]::Min($TimeoutSeconds, 600))
        while ($true) {
            try { $inOk = (Get-SIMailAuthorizationVerdict -Rows @((Invoke-SIMailExo -Cmdlet 'Test-ServicePrincipalAuthorization' -Parameters @{ Identity = $i.AppId; Resource = $address }).value)).InScope } catch { $inOk = $false }
            if ($inOk -or (Get-Date) -ge $until) { break }
            Note ('{0}: not in scope yet -- waiting for Exchange' -f $i.DisplayName) 'DarkGray'; Start-Sleep -Seconds 30
        }
        if ("$ProbeMailbox".Trim()) {
            try { $outOk = (Get-SIMailAuthorizationVerdict -Rows @((Invoke-SIMailExo -Cmdlet 'Test-ServicePrincipalAuthorization' -Parameters @{ Identity = $i.AppId; Resource = $ProbeMailbox }).value)).InScope } catch { $outOk = $null }
        }
        $line = '{0}: {1} -> {2}; {3} -> {4}' -f $i.DisplayName, $address, $(if ($inOk) { 'IN scope' } else { 'NOT in scope' }), $(if ($ProbeMailbox) { $ProbeMailbox } else { '(no other mailbox to test)' }), $(if ($null -eq $outOk) { 'not tested' } elseif ($outOk) { 'IN SCOPE (NOT RESTRICTED)' } else { 'not in scope (restricted)' })
        $good = $inOk -and ($outOk -eq $false)
        Note $line $(if ($good) { 'Green' } else { 'Red' })
        Add-Step ('verify:' + $i.AppId) $(if ($good) { 'verified' } else { 'not-verified' }) $line
        if (-not $good) { $verified = $false }
    }
}

$result.settings = Get-SIMailSettingsToSet -Mode sharedMailbox -Address $address -ProbeMailbox $ProbeMailbox
Step 'settings for SecurityInsight'
foreach ($k in $result.settings.Keys) { Note ('{0} = {1}' -f $k, $result.settings[$k]) 'White' }
Note 'Pro: Settings > E-mail (or the "Set up mail" flow). Community: config\SecurityInsight.custom.ps1. SecurityInsight re-checks the restriction itself before it sends.' 'DarkGray'
$result.ok = [bool]($verified -or -not $Apply)
Save-Result
Write-Host ''
if ($Apply) { Write-Host $(if ($verified) { 'RESULT: shared mailbox ready -- Mail.Send scoped to ' + $address } else { 'RESULT: NOT verified -- see above' }) -ForegroundColor $(if ($verified) { 'Green' } else { 'Red' }) }
else { Write-Host 'RESULT: plan only -- re-run with -Apply to make these changes' -ForegroundColor Yellow }
if ($Apply -and -not $verified) { exit 1 }
} finally { Stop-SIScriptRun -Run $siRun }
