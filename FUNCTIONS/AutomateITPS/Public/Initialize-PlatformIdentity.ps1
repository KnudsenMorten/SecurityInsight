function Initialize-PlatformIdentity {
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
            'Modern.Azure.AppId'                   = 'Modern-ApplicationId-Azure'
            'Modern.Azure.Thumbprint'              = 'Modern-CertificateThumbprint-Azure'
            'Modern.Azure.Secret'                  = 'Modern-Secret-Azure'
            'Modern.O365.AppId'                    = 'Modern-ApplicationId-O365'
            'Modern.O365.Thumbprint'               = 'Modern-CertificateThumbprint-O365'
            'Modern.O365.Secret'                   = 'Modern-Secret-O365'
            'Modern.ResourceOnBoarding.AppId'      = 'Modern-ApplicationId-ResourceOnboarding'
            'Modern.ResourceOnBoarding.Thumbprint' = 'Modern-CertificateThumbprint-ResourceOnboarding'
            'Modern.ResourceOnBoarding.Secret'     = 'Modern-Secret-ResourceOnboarding'
            'Modern.LogIngestionDCR.AppId'         = 'Modern-ApplicationId-LogIngestion'
            'Modern.LogIngestionDCR.Secret'        = 'Modern-Secret-LogIngestion'
        }
    }

    foreach ($path in $Mapping.Keys) {
        $secretName = $Mapping[$path]
        $asPlain    = $path -notmatch '\.Secret$'
        try {
            $value = Get-PlatformSecret -Context $Context -Name $secretName -AsPlainText:$asPlain
            Set-ContextIdentityValue -Context $Context -Path $path -Value $value
        }
        catch {
            if (-not $IgnoreMissing) { throw }
            Write-Warning "Initialize-PlatformIdentity: '$secretName' -> $path failed: $($_.Exception.Message)"
        }
    }

    $Context
}
