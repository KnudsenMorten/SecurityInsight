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

    switch ($Context.Providers.Secret) {
        'KeyVault' { return Get-PlatformSecretKeyVault -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'Local'    { return Get-PlatformSecretLocal    -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'None'     { throw "Get-PlatformSecret: secret provider disabled on this context." }
        default    { throw "Get-PlatformSecret: unknown provider '$($Context.Providers.Secret)'." }
    }
}
