function Resolve-PlatformGMSACredentials {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [switch]$IgnoreMissing
    )

    Assert-OnPremAD -Context $Context -Operation 'Resolve-PlatformGMSACredentials'

    $updated = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[string]
    $failed  = New-Object System.Collections.Generic.List[pscustomobject]

    $paths = @(
        'Internal.Prod','Internal.Dev','Internal.Test','DMZ.Prod',
        'ResourceOnBoarding.InternalProd','ResourceOnBoarding.DMZProd','ResourceOnBoarding.InternalDev','ResourceOnBoarding.InternalTest'
    )

    foreach ($p in $paths) {
        $segs = $p -split '\.'
        $parent = $Context.Identity.Legacy
        for ($i = 0; $i -lt $segs.Count - 1; $i++) { $parent = $parent.($segs[$i]) }
        $leaf = $segs[-1]
        $cred = $parent.$leaf

        if (-not $cred) {
            $skipped.Add("$p (unset)") | Out-Null
            continue
        }
        if ($cred.UserName -notlike '*gMSA*' -and $cred.UserName -notlike '*sMSA*') {
            $skipped.Add("$p (not gMSA)") | Out-Null
            continue
        }

        $split = $cred.UserName -split '\\', 2
        if ($split.Count -ne 2) {
            $failed.Add([pscustomobject]@{ Path = $p; UserName = $cred.UserName; Reason = 'username not in DOMAIN\\account form' })
            if (-not $IgnoreMissing) { throw ("Resolve-PlatformGMSACredentials: '{0}' username '{1}' not in DOMAIN\\account form." -f $p, $cred.UserName) }
            continue
        }

        $domain  = $split[0]
        $account = $split[1]
        if (-not $account.EndsWith('$')) { $account = "$account`$" }

        try {
            $rootDN    = ($domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
            $searchRoot = "LDAP://$rootDN"
            $new = Get-GMSACredential -Context $Context -GMSAName $account -Domain $domain -SearchRoot $searchRoot
            $parent.$leaf = $new
            $updated.Add($p) | Out-Null
        }
        catch {
            $failed.Add([pscustomobject]@{ Path = $p; UserName = $cred.UserName; Reason = $_.Exception.Message })
            if (-not $IgnoreMissing) { throw }
        }
    }

    [pscustomobject]@{
        Updated = [string[]]$updated
        Skipped = [string[]]$skipped
        Failed  = [pscustomobject[]]$failed
    }
}
