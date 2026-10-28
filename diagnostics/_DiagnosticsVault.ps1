# 🔒 THE VAULT NAME IS NOT HARD-CODED, AND THAT IS DELIBERATE.
# These PoC scripts read a ServiceNow sandbox credential from an internal Key Vault. Naming that
# vault in source ships an internal infrastructure name to the PUBLIC mirror -- the publish
# sanitization guard fails the gate on exactly that, and it is right to. Resolve it at runtime
# instead: set SI_DIAGNOSTICS_VAULT, or pass -VaultName.
function Get-SIDiagnosticsVaultName {
    [CmdletBinding()]
    param([string]$VaultName)
    if ($VaultName)                                    { return $VaultName }
    if ($env:SI_DIAGNOSTICS_VAULT)                             { return $env:SI_DIAGNOSTICS_VAULT }
    if ($global:SI_DiagnosticsVaultName)                       { return $global:SI_DiagnosticsVaultName }
    throw ("No Key Vault configured for the PoC scripts. Set `$env:SI_DIAGNOSTICS_VAULT = '<vault>' " +
           "(or pass -VaultName). The vault holds servicenow-pdi-instance / -user / -password.")
}
