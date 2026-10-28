#Requires -Version 5.1
<#
    SI -- ONE KEY VAULT, RESOLVED IN ONE PLACE.

    🔒 Operator, 2026-08-31: *"use the keyvault for the SI instance, so it is captured into one SI
    keyvault."*

    🔴 THE PROBLEM THIS FIXES IS THAT SI ALREADY NAMED ITS VAULT THREE WAYS, and each caller picked
    one:
      $global:SI_KeyVaultName        written by the Config Wizard (Write-SICustomConfig.ps1)
      $global:SpnKeyVaultName        the name the config reference shows (Connect-SIAzCli read it; deleted)
      $env:SI_DIAGNOSTICS_VAULT      the diagnostics scripts' own resolution
    A customer who set one and not the others got a component that could not find the vault -- and the
    failure surfaces as "no credential", which reads like a permissions problem and is not. Three
    spellings of one fact is the same defect class as `EgNodeId`/`ExposureGraphNodeId`, which cost a
    silent correlation split.

    ✅ SO: every SI component resolves the vault through HERE, in a fixed order, and any one of the
    three globals being set is enough. Nothing is renamed and no existing install breaks -- the
    resolution simply stops depending on which name the customer happened to use.

    ⛔ NO DEFAULT, EVER. There is no sensible fallback vault name: guessing one would send a secret
    read at some other customer's vault, or at an internal one. Unresolved is an error with a message
    that says what to set.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

function Get-SIVaultName {
    <#
        The SI Key Vault for this install.

          -VaultName  an explicit override, which always wins (a CLI parameter, a test)

        Order after that: SI_KeyVaultName -> SpnKeyVaultName -> SI_DIAGNOSTICS_VAULT env ->
        SI_DiagnosticsVaultName. The diagnostics names come LAST on purpose: they exist so a
        developer's sandbox vault is reachable, and they must never take precedence over a customer's
        configured vault on a real run.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$VaultName,
        # Return $null instead of throwing. For callers that treat "no vault" as a supported state --
        # the CMDB connector's plan-only path needs no secrets at all.
        [Parameter()][switch]$AllowMissing
    )

    if (-not [string]::IsNullOrWhiteSpace($VaultName))                       { return $VaultName.Trim() }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_KeyVaultName))  { return ([string]$global:SI_KeyVaultName).Trim() }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnKeyVaultName))  { return ([string]$global:SpnKeyVaultName).Trim() }
    if (-not [string]::IsNullOrWhiteSpace([string]$env:SI_DIAGNOSTICS_VAULT)){ return ([string]$env:SI_DIAGNOSTICS_VAULT).Trim() }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DiagnosticsVaultName)) { return ([string]$global:SI_DiagnosticsVaultName).Trim() }

    if ($AllowMissing) { return $null }
    throw ('SI: no Key Vault is configured. Set $global:SI_KeyVaultName in config\SecurityInsight.custom.ps1 ' +
           '(the Config Wizard writes it for you). $global:SpnKeyVaultName is also accepted for installs ' +
           'that predate that name. The vault holds the SPN secret and any integration credentials, and ' +
           'there is deliberately no default -- guessing a vault name would send a secret read somewhere ' +
           'it does not belong.')
}

# ---------------------------------------------------------------------------------------------------
# THE SERVICENOW SECRET NAMES, in one place so the connector and the diagnostics cannot drift.
#
# 🔑 CANONICAL NAMES FIRST, LEGACY SECOND. The diagnostics scripts seeded `servicenow-pdi-*` while the
# connector was being proven against a developer instance. Those keep working -- an operator should not
# have to re-seed a vault to pick up a rename -- but a new install gets the `SI-ServiceNow-*` names,
# which say which SOLUTION owns them in a vault that may hold secrets for several.
# ---------------------------------------------------------------------------------------------------
$script:SIServiceNowSecretNames = [ordered]@{
    Instance = @('SI-ServiceNow-Instance', 'servicenow-pdi-instance')
    User     = @('SI-ServiceNow-User',     'servicenow-pdi-user')
    Password = @('SI-ServiceNow-Password', 'servicenow-pdi-password')
}

function Get-SIServiceNowSecretName {
    <# The candidate secret names for one part, canonical first. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Instance','User','Password')][string]$Part)
    @($script:SIServiceNowSecretNames[$Part])
}

function Get-SIServiceNowCredentialFromVault {
    <#
        The ServiceNow instance URL and integration credential, from the ONE SI vault.

        Returns @{ Instance; Credential; InstanceSecretName } or $null when the vault holds none of
        them -- which is a supported state for a plan-only run and must not throw there.

        🪤 A PARTIAL SET IS AN ERROR, NOT A DEGRADED SUCCESS. An instance URL with no credential would
        build a connection that fails on the first call with a 401, which reads like a permissions
        problem at the customer's end. Say which secret is missing instead.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$VaultName,
        # Injectable so this is testable without a vault. Takes (vault, secretName), returns the value
        # or $null.
        [Parameter()][scriptblock]$Reader
    )

    $vault = Get-SIVaultName -VaultName $VaultName -AllowMissing
    if ([string]::IsNullOrWhiteSpace($vault)) { return $null }

    if (-not $Reader) {
        $Reader = {
            param($v, $n)
            try { Get-SIKvSecret -VaultName $v -SecretName $n } catch { $null }
        }
    }

    $found = @{}
    foreach ($part in @('Instance','User','Password')) {
        foreach ($name in (Get-SIServiceNowSecretName -Part $part)) {
            $val = & $Reader $vault $name
            if (-not [string]::IsNullOrWhiteSpace([string]$val)) {
                $found[$part] = [string]$val
                if ($part -eq 'Instance') { $found['InstanceSecretName'] = $name }
                break
            }
        }
    }

    if ($found.Count -eq 0) { return $null }

    $missing = @()
    foreach ($part in @('Instance','User','Password')) { if (-not $found.ContainsKey($part)) { $missing += $part } }
    if ($missing.Count -gt 0) {
        throw ("SI: the ServiceNow credential in Key Vault '{0}' is INCOMPLETE -- missing {1}. Expected {2}. " -f `
                $vault, ($missing -join ', '),
                (@('Instance','User','Password') | ForEach-Object { (Get-SIServiceNowSecretName -Part $_)[0] }) -join ' / ') +
              'A partial set would build a connection that fails on the first call with a 401, which reads like a permissions problem at the customer end.'
    }

    $sec = New-Object System.Security.SecureString
    foreach ($ch in ([string]$found['Password']).ToCharArray()) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()

    [pscustomobject]@{
        Instance           = [string]$found['Instance']
        Credential         = (New-Object System.Management.Automation.PSCredential([string]$found['User'], $sec))
        InstanceSecretName = [string]$found['InstanceSecretName']
        VaultName          = $vault
    }
}
