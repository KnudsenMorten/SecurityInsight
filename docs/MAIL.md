# SecurityInsight mail

SecurityInsight sends its mail — Risk Analysis reports, safety-check (guard) alerts, the close-loop, exemption,
governance and department mails, the task digest and licence notices — in one of three ways, chosen with the setting
`SI_Mail_Mode`:

| Mode | How | When |
|---|---|---|
| `sharedMailbox` (recommended) | An Office 365 **shared mailbox**, through Microsoft Graph (`sendMail`), signed in as SecurityInsight's **own managed identity**. No password exists anywhere. | Every new install. |
| `smtp` | **Your own SMTP relay** (anonymous, or with a user name; the password is kept in the install's Key Vault as `SI-Smtp-Password`). | You must use your own relay. |
| `none` | No mail. Reports are still written. | — |

When `SI_Mail_Mode` is not set, an install that has `SmtpServer` set keeps using that relay, so an upgraded install
keeps working until you switch.

| Setting | Meaning |
|---|---|
| `SI_Mail_Mode` | `sharedMailbox`, `smtp` or `none`. |
| `SI_Mail_From` | The shared mailbox SecurityInsight sends as. With `smtp` it is the From address. |
| `SI_Mail_ProbeMailbox` | An ordinary mailbox **outside** the scope (for example, an administrator's mailbox). SecurityInsight checks that it may **not** send as this mailbox. |
| `SI_Mail_RestrictionAttestation` | Who confirmed the restriction, and when. It counts only when no other mailbox can be tested. |
| `SmtpServer`, `SMTPPort`, `SMTP_UseSSL`, `SMTPUser`, `Mail_SendAnonymous` | The SMTP relay (`smtp` only). |

**Every mail names its environment.** The subject starts with the environment's name, as the web app's header shows it (for example `[Production (ring 3, PRO)]`). The footer shows the environment, the tenant name and tenant id, the SecurityInsight version and a link to that environment's web app. The name comes from the web app's *Environment name* setting (`SIWeb_EnvironmentName`) and the tenant name from *Tenant name* (`SIWeb_TenantName`).

## The shared mailbox: one mailbox, and nothing else

SecurityInsight's identity may send as the shared mailbox **and only as it**. This is set up in Exchange Online with
*RBAC for Applications*, not with a tenant-wide permission:

1. **The shared mailbox.** SecurityInsight can create it, for example `SecurityInsight@contoso.com`. A shared mailbox
   needs no licence. The tenant needs an Exchange Online plan; `EXCHANGE_S_FOUNDATION` alone is not enough.
2. **SecurityInsight's identities are registered in Exchange** (`New-ServicePrincipal`). These are the engine jobs'
   managed identity, the web app's identity and the updater's identity.
3. **A management scope that matches only that mailbox** (`New-ManagementScope 'SecurityInsight-Sender'`).
4. **The role `Application Mail.Send` on that scope**, one assignment per identity (`New-ManagementRoleAssignment`).
5. **No tenant-wide Microsoft Graph `Mail.Send`** on any of those identities. Permissions from Exchange RBAC for
   Applications are *added* to what Entra ID grants. If a tenant-wide `Mail.Send` were also granted, the identity could
   send as every mailbox in the tenant. Setup removes such a grant.

Application Access Policies (the older way) are not used.

**SecurityInsight refuses to send until the restriction is verified.** Before it sends, it checks two things as its
own identity: it may send as the shared mailbox, and it may **not** send as `SI_Mail_ProbeMailbox`. The check sends
nothing, because both requests have no recipient. If the identity holds a tenant-wide `Mail.Send`, or could send as the
other mailbox, nothing is sent. The reason shows on the home page, on **Settings > E-mail** and in the run's log.

Microsoft Graph accepts at most about **3 MB of attachments** in one mail. A larger report workbook is left out. The mail
still goes, with the summary, and it says where the workbook is (the export storage, or on disk). Sending a larger file
would need a wider permission (`Mail.ReadWrite`), which SecurityInsight does not ask for.

## Setting it up

You can set it up in either of two ways:

- **In the web app (Pro):** go to **Settings > E-mail > Set up mail**. This is SuperAdmin only, and every step is on the
  audit trail. Choose *Create a new shared mailbox* or *Use an existing one*, then press the button. It creates the
  mailbox, registers the identities, creates the scope and the role assignment, verifies the restriction, saves the
  settings and sends a test mail. If your account lacks the Exchange role, it shows the commands for your Exchange
  administrator.
- **With the script:** `setup\Set-SIMail.ps1` is one file with no PowerShell modules, and it can be downloaded on its
  own. It shows the plan by default and changes nothing until you add `-Apply` (run it once without `-Apply` to see the
  plan):

  ```powershell
  Invoke-WebRequest https://invardia.com/support/si/Set-SIMail.ps1 -OutFile Set-SIMail.ps1
  ./Set-SIMail.ps1 -SharedMailbox securityinsight@contoso.com -SubscriptionId <subscription> -ResourceGroup <SecurityInsight's resource group> -UseSignedInAccount -Apply
  ```

  Your own SMTP relay instead (the password is asked for and stored in Key Vault):

  ```powershell
  Invoke-WebRequest https://invardia.com/support/si/Set-SIMail.ps1 -OutFile Set-SIMail.ps1
  ./Set-SIMail.ps1 -Mode smtp -SmtpServer <relay> -SmtpPort 587 -SmtpUseSsl -SmtpUser <user> -From <sender> -KeyVaultName <vault> -UseSignedInAccount -Apply -TestTo you@contoso.com
  ```

  `-UseSignedInAccount` uses setup's own browser sign-in (Azure Cloud Shell, or the browser) -- never the Azure CLI.
  The script calls Exchange Online through the same REST endpoint that the Exchange Online PowerShell module uses.
  [What does Set-SIMail do?](https://invardia.com/docs/si/scripts/Set-SIMail/)

**Who can run it:** an account with the **Exchange Administrator** role. The narrowest alternative is an Exchange role
group that holds only the roles **Mail Recipient Creation** (to create the mailbox) and **Role Management** (to register
the identities and create the scope and the role assignment). Reading the identities' Graph permissions needs
`Application.Read.All`. Removing a tenant-wide `Mail.Send` needs `AppRoleAssignment.ReadWrite.All`, or the Privileged
Role Administrator or Cloud Application Administrator role. Without Exchange rights the script stops at the plan and
prints the exact Exchange Online PowerShell commands, in order, for the Exchange administrator:

```powershell
New-Mailbox -Shared -Name 'SecurityInsight' -DisplayName 'SecurityInsight' -PrimarySmtpAddress 'securityinsight@contoso.com'
New-ServicePrincipal -AppId '<identity client id>' -ObjectId '<identity object id>' -DisplayName 'SecurityInsight - <identity>'
New-ManagementScope -Name 'SecurityInsight-Sender' -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'securityinsight@contoso.com'"
New-ManagementRoleAssignment -Name 'SecurityInsight-MailSend-<id>' -App '<identity client id>' -Role 'Application Mail.Send' -CustomResourceScope 'SecurityInsight-Sender'
Test-ServicePrincipalAuthorization -Identity '<identity client id>' -Resource 'securityinsight@contoso.com'   # InScope: True
Test-ServicePrincipalAuthorization -Identity '<identity client id>' -Resource '<another mailbox>'             # InScope: False
```

A new role assignment can take up to about two hours to take effect in Exchange. Until then SecurityInsight reports
*not granted yet* and does not send.

## The guided install

The install's e-mail page asks for the shared mailbox first:

| Parameter | Meaning |
|---|---|
| `mailMode` | `sharedMailbox` (default), `smtp` (*I use my own SMTP relay*), or `none`. |
| `mailFrom` | The shared mailbox address. If empty, it is `SecurityInsight@<your sign-in domain>`. |
| `mailboxCreate` | Create the mailbox when it does not exist (default on). |
| `mailTo` | The report recipients. If empty, you (the person installing) receive them. |
| `smtpServer`, `smtpPort`, `smtpUser`, `smtpFrom` | Your relay (`smtp` only). The password is asked for in the shell and stored in Key Vault. |

The older parameter `mail` is still accepted: `true` means `smtp` and `false` means `none`.
