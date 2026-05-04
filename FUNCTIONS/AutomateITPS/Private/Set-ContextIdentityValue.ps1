function Set-ContextIdentityValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()]$Value
    )

    $segments = $Path -split '\.'
    $cur = $Context.Identity
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        $next = $cur.PSObject.Properties[$segments[$i]]
        if (-not $next) {
            throw "Set-ContextIdentityValue: segment '$($segments[$i])' missing on context at path '$Path'."
        }
        $cur = $next.Value
    }
    $last = $segments[-1]
    if (-not $cur.PSObject.Properties[$last]) {
        throw "Set-ContextIdentityValue: final segment '$last' missing on context at path '$Path'."
    }
    $cur.$last = $Value
}
