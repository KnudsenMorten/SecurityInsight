function Initialize-PlatformLegacyIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [hashtable]$Mapping,

        [switch]$IgnoreMissing
    )

    if (-not $Mapping -or $Mapping.Count -eq 0) {
        $Mapping = [ordered]@{
            'Legacy.Internal.Prod'                       = @{ UserName = 'Legacy-UserName-Internal-Prod';                     Password = 'Legacy-Password-Internal-Prod' }
            'Legacy.Internal.Dev'                        = @{ UserName = 'Legacy-UserName-Internal-Dev';                      Password = 'Legacy-Password-Internal-Dev' }
            'Legacy.Internal.Test'                       = @{ UserName = 'Legacy-UserName-Internal-Test';                     Password = 'Legacy-Password-Internal-Test' }
            'Legacy.DMZ.Prod'                            = @{ UserName = 'Legacy-UserName-DMZ-Prod';                          Password = 'Legacy-Password-DMZ-Prod' }
            'Legacy.ResourceOnBoarding.InternalProd'     = @{ UserName = 'Legacy-UserName-ResourceOnBoarding-Internal-Prod';  Password = 'Legacy-Password-ResourceOnBoarding-Internal-Prod' }
            'Legacy.ResourceOnBoarding.DMZProd'          = @{ UserName = 'Legacy-UserName-ResourceOnBoarding-DMZ-Prod';       Password = 'Legacy-Password-ResourceOnBoarding-DMZ-Prod' }
            'Legacy.ResourceOnBoarding.InternalDev'      = @{ UserName = 'Legacy-UserName-ResourceOnBoarding-Internal-Dev';   Password = 'Legacy-Password-ResourceOnBoarding-Internal-Dev' }
            'Legacy.ResourceOnBoarding.InternalTest'     = @{ UserName = 'Legacy-UserName-ResourceOnBoarding-Internal-Test';  Password = 'Legacy-Password-ResourceOnBoarding-Internal-Test' }
            'Legacy.ProvisionVMLocalAdmin'               = @{ UserName = 'Azure-VM-LocalAdmin-UserName';                      Password = 'Azure-VM-LocalAdmin-Password' }
        }
    }

    foreach ($path in $Mapping.Keys) {
        $pair = $Mapping[$path]
        try {
            $user = Get-PlatformSecret -Context $Context -Name $pair.UserName -AsPlainText
            $pw   = Get-PlatformSecret -Context $Context -Name $pair.Password
            $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pw
            Set-ContextIdentityValue -Context $Context -Path $path -Value $cred
        }
        catch {
            if (-not $IgnoreMissing) { throw }
            # -IgnoreMissing semantics: caller accepts that legacy on-prem creds
            # (Azure-VM-LocalAdmin-*, Legacy-*-Internal/DMZ-Prod, etc.) are optional
            # in v2 cloud-only deployments. Don't fire Write-Warning -- most customer
            # KVs don't carry these secrets, and the noise on every launcher start
            # was misleading. Use -Verbose for diagnostic runs.
            Write-Verbose "Initialize-PlatformLegacyIdentity: '$path' skipped -- $($_.Exception.Message)"
        }
    }

    $Context
}
