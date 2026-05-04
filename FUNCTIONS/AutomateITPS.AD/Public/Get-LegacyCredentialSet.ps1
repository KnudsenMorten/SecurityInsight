function Get-LegacyCredentialSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    Assert-OnPremAD -Context $Context -Operation 'Get-LegacyCredentialSet'

    [pscustomobject]@{
        Internal           = $Context.Identity.Legacy.Internal
        DMZ                = $Context.Identity.Legacy.DMZ
        ResourceOnBoarding = $Context.Identity.Legacy.ResourceOnBoarding
        SMTP               = $Context.Identity.Legacy.SMTP
        ProvisionVMLocalAdmin = $Context.Identity.Legacy.ProvisionVMLocalAdmin
    }
}
