function Get-PlatformSecret {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$AsPlainText
    )

    # Tolerate two Context shapes:
    #   1. Properly-shaped PlatformContext from New-PlatformContext (has .Providers.Secret + .Tenant.KeyVaultName)
    #   2. Flat short-circuit object from older Initialize-PlatformAutomationFramework (only AppId/Thumb/KeyVaultName)
    # When the .Providers shape is missing, fall back to direct Get-AzKeyVaultSecret using whatever
    # KeyVault name we can find on the Context OR in the v1-contract globals. This keeps existing
    # customer installs working when their FUNCTIONS\ folder predates the New-PlatformContext fix.
    $providerKind = $null
    if ($Context.PSObject.Properties.Name -contains 'Providers' -and $Context.Providers) {
        $providerKind = $Context.Providers.Secret
    }

    switch ($providerKind) {
        'KeyVault' { return Get-PlatformSecretKeyVault -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'Local'    { return Get-PlatformSecretLocal    -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'None'     { throw "Get-PlatformSecret: secret provider disabled on this context." }
        default    {
            # Compatibility fallback: no .Providers means an older / minimal context. Treat as KeyVault.
            $kvName = $null
            if ($Context.PSObject.Properties.Name -contains 'KeyVaultName' -and $Context.KeyVaultName) {
                $kvName = $Context.KeyVaultName
            } elseif ($Context.PSObject.Properties.Name -contains 'Tenant' -and $Context.Tenant -and $Context.Tenant.KeyVaultName) {
                $kvName = $Context.Tenant.KeyVaultName
            } elseif ($global:KV_HighPriv_KeyVaultName) {
                $kvName = $global:KV_HighPriv_KeyVaultName
            }
            if (-not $kvName) {
                throw "Get-PlatformSecret: Context has no .Providers and no resolvable KeyVault name (.KeyVaultName, .Tenant.KeyVaultName, or `$global:KV_HighPriv_KeyVaultName all empty)."
            }
            $sec = Get-AzKeyVaultSecret -VaultName $kvName -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
            if (-not $sec) { throw "Get-PlatformSecret (compat fallback): secret '$Name' not found in vault '$kvName'." }
            if ($AsPlainText) {
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec.SecretValue)
                try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
                finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            }
            return $sec.SecretValue
        }
    }
}
