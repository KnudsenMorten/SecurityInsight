<!-- public:start -->

# PlatformConfiguration

One-time infrastructure provisioning for running **any** community or internal solution
on this platform (SecurityInsight, EntraPolicySuite, PIM4EntraPS, and anything else
published from the same monorepo).

The five engines here cover every piece of infra a solution needs:

| Engine | Purpose | Run on host |
| --- | --- | --- |
| `New-EntraApp` | Create (or reuse) an Entra App registration + SP, add API permissions, grant admin consent, assign Azure RBAC, optionally upload a cert and/or create a client secret. | Anywhere with Graph + Azure admin rights. |
| `New-SelfSignedCertificate` | Create / reuse a cert in the local Windows cert store, export the public key as `.cer` ready to hand to `New-EntraApp -CertificatePublicKeyPath`. | The machine that will later run the solution launcher. |
| `Enable-VmManagedIdentity` | Turn on system-assigned MI on an Azure VM or Arc-enabled server and (optionally) grant `Key Vault Secrets User` + other RBAC. | Any Azure-connected host. |
| `New-KeyVaultForSolution` | Create / reuse a Key Vault, write a solution's SPN secret into it, grant reader MIs `Key Vault Secrets User`. | Any Azure-connected host. |
| `New-AzureFunctionHost` | Provision a Function App (PowerShell 7.4) with system-assigned MI, backing storage, and optional KV binding. Ready for a solution's `launcher.community-azure.template.ps1`. | Any Azure-connected host. |

Each engine has the standard 4-launcher matrix (`internal-vm`, `internal-azure`,
`community-vm`, `community-azure`) under `launchers/<Engine>/` and supports the four
community auth modes documented in [`LauncherConfig.sample.ps1`](launchers/New-EntraApp/LauncherConfig.sample.ps1).

## Recommended flows

### Community VM (you're running on a Windows box in your own tenant)

```powershell
# 0. Clone this repo.
git clone https://github.com/KnudsenMorten/PlatformConfiguration.git
cd PlatformConfiguration

# 1. Bootstrap auth for the onboarding run itself. Easiest path: use the
#    testing-only plaintext SPN pattern of an already-existing admin SPN
#    in LauncherConfig.ps1 (see launchers/New-EntraApp/LauncherConfig.sample.ps1).
cd launchers\New-EntraApp
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1

# 2. Create the target solution's SPN.
.\launcher.community-vm.template.ps1 `
    -AppDisplayName SecurityInsight-SPN `
    -GraphApplicationPermissions @('ThreatHunting.Read.All','Directory.Read.All') `
    -DefenderApplicationPermissions @('Machine.ReadWrite.All') `
    -AzureRbacRoles @{ 'Reader' = '/subscriptions/<sub-id>' }

# 3. (Optional) create a cert and upload it to the new SPN for cert-based auth.
cd ..\New-SelfSignedCertificate
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1
.\launcher.community-vm.template.ps1 -Subject 'CN=SecurityInsight-SPN'

# Then go back and upload the .cer to the app:
cd ..\New-EntraApp
.\launcher.community-vm.template.ps1 `
    -AppDisplayName SecurityInsight-SPN `
    -CertificatePublicKeyPath '..\New-SelfSignedCertificate\Output\CN_SecurityInsight-SPN.cer' `
    -SkipSecretCreation
```

Now paste the Tenant/Client/Secret (or cert thumbprint) from the onboarding
Output/\*-onboarding.json into the target solution's
`LauncherConfig.ps1` and run that solution's launcher.

### Community Azure (you want the solution to run in an Azure Function in your tenant)

```powershell
# 1. Create the SPN for the solution.
cd launchers\New-EntraApp
# (same as above)
.\launcher.community-vm.template.ps1 -AppDisplayName SecurityInsight-SPN ...

# 2. Create the Key Vault and store the secret.
cd ..\New-KeyVaultForSolution
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1
.\launcher.community-vm.template.ps1 `
    -VaultName kv-securityinsight-prod -ResourceGroup rg-securityinsight-host `
    -Location westeurope -SecretName SecurityInsight-Secret `
    -SecretValue '<secret from previous step output>'

# 3. Create the Function App host and bind it to the Key Vault.
cd ..\New-AzureFunctionHost
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1
.\launcher.community-vm.template.ps1 `
    -FunctionAppName fn-securityinsight-prod `
    -ResourceGroup rg-securityinsight-host `
    -Location westeurope `
    -StorageAccountName stsi0prod0a1b2c `
    -KeyVaultName kv-securityinsight-prod `
    -TenantId '<tenant-id>' -SubscriptionIdForSolution '<sub-id>'

# 4. Deploy the solution's scripts + launchers into the Function App's wwwroot/,
#    then the community-azure launcher picks up PLATFORM_TENANT_ID /
#    PLATFORM_KEYVAULT / PLATFORM_SUBSCRIPTION_ID env vars automatically.
```

### Internal VM / Internal Azure

The internal flavours assume the 2LINKIT automation framework is already in place
(FUNCTIONS/2LINKIT-Functions.psm1, a production Key Vault `kv-platform-automation-p`,
Connect_Azure helper). These engines' internal-* launchers use the same bootstrap —
they pick up the existing platform identities rather than creating new ones.

For a fresh internal VM:

```powershell
cd launchers\Enable-VmManagedIdentity
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
.\launcher.internal-vm.template.ps1 -VmName vm-platform-01 -ResourceGroup rg-platform `
    -KeyVaultName kv-platform-automation-p
```

After the MI is enabled + granted Key Vault Secrets User, every other solution's
internal launcher works without further setup.

## Output artefacts

Each engine writes a JSON manifest under `SCRIPTS\Output\` with the values you need
for the target solution's LauncherConfig (tenant id, client id, cert thumbprint,
secret value if created, etc.). **Handle these files as sensitive material** — the
`.gitignore` covers `Output/` but don't email them around.

## Rerun safety

All five engines are idempotent. Running twice with the same inputs either reuses
the existing object or updates it in place. The only non-idempotent action is
**client secret creation in New-EntraApp** — each run adds a new password credential
to the app. Either use `-SkipSecretCreation` on subsequent runs, or accept that you
accumulate old (unused) password entries.

## Auth methods for the onboarding run itself

PlatformConfiguration engines use the standard four auth methods that every community
launcher supports — see
[`launchers/New-EntraApp/LauncherConfig.sample.ps1`](launchers/New-EntraApp/LauncherConfig.sample.ps1).
You can choose:

1. Managed Identity (if running from an Azure VM that already has rights).
2. SPN + Key Vault-stored secret.
3. SPN + certificate.
4. SPN + plaintext secret **(testing only)**.

For the very first run in a fresh tenant, Method 4 is often unavoidable — you're
bootstrapping, and the Entra app doesn't yet exist. Use an admin's own test SPN with
the minimum permissions needed (Application.ReadWrite.All + RoleManagement.ReadWrite.Directory
+ Owner at tenant root), run PlatformConfiguration once, then rotate to Method 1/2/3 for
the resulting solution SPN.

## Bug reports, PRs, discussions

Same story as every other community repo from this author:

- **Bugs / feature requests:** [Issues](https://github.com/KnudsenMorten/PlatformConfiguration/issues/new/choose)
- **Questions / "has anyone tried...":** [Discussions](https://github.com/KnudsenMorten/PlatformConfiguration/discussions)
- **PRs:** fork → branch → PR against `main`. Accepted PRs are bridged into an upstream
  monorepo; the next release republishes them here with your commit attribution preserved.

<!-- public:end -->
