function Import-LegacyGlobals {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [switch]$Quiet
    )

    $m = $Context.Identity.Modern
    $l = $Context.Identity.Legacy

    $map = [ordered]@{
        'HighPriv_Modern_ApplicationID_Azure'                                 = $m.Azure.AppId
        'HighPriv_Modern_CertificateThumbprint_Azure'                         = $m.Azure.Thumbprint
        'HighPriv_Modern_Secret_Azure'                                        = $m.Azure.Secret
        'HighPriv_Modern_ApplicationID_O365'                                  = $m.O365.AppId
        'HighPriv_Modern_CertificateThumbprint_O365'                          = $m.O365.Thumbprint
        'HighPriv_Modern_Secret_O365'                                         = $m.O365.Secret
        'HighPriv_Modern_ApplicationID_ResourceOnBoarding'                    = $m.ResourceOnBoarding.AppId
        'HighPriv_Modern_ApplicationID_LogIngestion_DCR'                      = $m.LogIngestionDCR.AppId
        'HighPriv_Modern_Secret_LogIngestion_DCR'                             = $m.LogIngestionDCR.Secret
        'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Prod' = $l.ResourceOnBoarding.InternalProd
        'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_DMZ_Prod'      = $l.ResourceOnBoarding.DMZProd
        'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Dev'  = $l.ResourceOnBoarding.InternalDev
        'HighPriv_Legacy_SecureCredentials_RessourceOnBoarding_Internal_Test' = $l.ResourceOnBoarding.InternalTest
        'HighPriv_Legacy_SecureCredentials_Internal_Prod'                     = $l.Internal.Prod
        'HighPriv_Legacy_SecureCredentials_DMZ_Prod'                          = $l.DMZ.Prod
        'HighPriv_Legacy_SecureCredentials_Internal_Dev'                      = $l.Internal.Dev
        'HighPriv_Legacy_SecureCredentials_Internal_Test'                     = $l.Internal.Test
        'HighPriv_Provision_Azure_VM_LocalAdmin'                              = $l.ProvisionVMLocalAdmin
        'SecureCredentialsSMTP'                                               = $l.SMTP
    }

    foreach ($name in $map.Keys) {
        $value = $map[$name]
        Set-Variable -Name $name -Value $value -Scope Global -Force
    }

    if (-not $Quiet) {
        $nullNames = @($map.Keys | Where-Object { $null -eq $map[$_] })
        $legacyOnPrem = $nullNames | Where-Object { $_ -like '*Legacy_SecureCredentials*' }

        Write-Warning ("[AutomateITPS.Compat] Back-compat shim set {0} legacy global(s) (correlationId={1}). Migrate consumers to accept -Context.`nUnset: {2}" -f $map.Count, $Context.CorrelationId, ($nullNames -join ', '))

        if ($legacyOnPrem -and -not $Context.Capabilities.OnPremAD) {
            Write-Warning ("[AutomateITPS.Compat] Host '{0}' has no OnPremAD capability; all Legacy_SecureCredentials_* globals are `$null. Any AD-touching script will fail fast." -f $Context.Host.Kind)
        }
    }

    return [string[]]$map.Keys
}
