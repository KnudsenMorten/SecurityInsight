function Get-PlatformSecret {
<#
.SYNOPSIS
    Read a secret from the platform Key Vault using the active PlatformContext.

.DESCRIPTION
    Thin dispatcher over the per-provider implementations
    (Get-PlatformSecretKeyVault / Get-PlatformSecretLocal). Provider is
    selected by the Context's `.Providers.Secret` field.

    v2.3 cleanup: dropped the v2.2.170 dual-shape "flat object" compat
    fallback. Single Context shape supported now (the one New-PlatformContext
    produces). All callers come via Connect-Platform which builds a proper
    PlatformContext, so the fallback isn't needed anymore.

.PARAMETER Context
    PlatformContext object from New-PlatformContext (or returned by
    Connect-Platform).

.PARAMETER Name
    KV secret name (e.g. 'Modern-Secret', 'OpenAI-ApiKey', 'SI-Shodan-ApiKey').

.PARAMETER AsPlainText
    Return the secret as a plain `[string]` instead of a `[securestring]`.
    Use only when the consuming API requires plain text (most do, since
    Azure APIs unwrap to plain anyway).

.OUTPUTS
    [securestring] or [string] (with -AsPlainText).

.EXAMPLE
    $key = Get-PlatformSecret -Context $global:Context -Name 'OpenAI-ApiKey' -AsPlainText
#>
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)] [pscustomobject]$Context,
        [Parameter(Mandatory)] [string]$Name,
        [switch]$AsPlainText
    )

    if (-not ($Context.PSObject.Properties.Name -contains 'Providers') -or -not $Context.Providers) {
        throw "Get-PlatformSecret: Context is malformed (no .Providers field). Was the Context built by New-PlatformContext / Connect-Platform? Got type: $($Context.GetType().Name)"
    }

    switch ($Context.Providers.Secret) {
        'KeyVault' { return Get-PlatformSecretKeyVault -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'Local'    { return Get-PlatformSecretLocal    -Context $Context -Name $Name -AsPlainText:$AsPlainText }
        'None'     { throw "Get-PlatformSecret: secret provider is 'None' on this context (read disabled)." }
        default    { throw "Get-PlatformSecret: unknown provider '$($Context.Providers.Secret)'." }
    }
}
