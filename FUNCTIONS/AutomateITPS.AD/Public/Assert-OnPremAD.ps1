function Assert-OnPremAD {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [string]$Operation = 'operation'
    )

    if (-not $Context.Capabilities.OnPremAD) {
        throw ("Assert-OnPremAD: '{0}' requires on-prem AD. Host '{1}' does not have line-of-sight to a domain controller. Run from a domain-joined VM or Azure Automation Hybrid Worker." -f $Operation, $Context.Host.Kind)
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Assert-OnPremAD: ActiveDirectory module not installed (install RSAT Active Directory PowerShell on this host)."
    }
}
