function Get-GMSACredential {
    [CmdletBinding(DefaultParameterSetName='Zone')]
    [OutputType([System.Management.Automation.PSCredential])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(ParameterSetName='Zone', Mandatory)]
        [ValidateSet('Internal_Prod','Internal_Dev','Internal_Test','DMZ_Prod')]
        [string]$Zone,

        [Parameter(ParameterSetName='Zone')]
        [switch]$ResourceOnBoarding,

        [Parameter(ParameterSetName='Direct', Mandatory)]
        [string]$GMSAName,

        [Parameter(ParameterSetName='Direct')]
        [string]$Domain,

        [Parameter(ParameterSetName='Direct')]
        [string]$SearchRoot
    )

    Assert-OnPremAD -Context $Context -Operation "Get-GMSACredential ($($PSCmdlet.ParameterSetName))"

    if ($PSCmdlet.ParameterSetName -eq 'Zone') {
        $cred = if ($ResourceOnBoarding) {
            $key = switch ($Zone) {
                'Internal_Prod' { 'InternalProd' }
                'DMZ_Prod'      { 'DMZProd' }
                'Internal_Dev'  { 'InternalDev' }
                'Internal_Test' { 'InternalTest' }
            }
            $Context.Identity.Legacy.ResourceOnBoarding.$key
        } else {
            $parts = $Zone -split '_'
            $Context.Identity.Legacy.$($parts[0]).$($parts[1])
        }
        if (-not $cred) {
            throw ("Get-GMSACredential: credential for zone '{0}' (ResourceOnBoarding=$ResourceOnBoarding) not present on context. Run Initialize-PlatformLegacyIdentity first; if the account is gMSA, follow with Resolve-PlatformGMSACredentials to replace the KV stub password with the real one from the DC." -f $Zone)
        }
        return $cred
    }

    if (-not $Domain)     { $Domain = $env:USERDOMAIN }
    if (-not $SearchRoot) {
        $rootDN    = ($Domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
        $SearchRoot = "LDAP://$rootDN"
    }

    $dEntryRoot = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $SearchRoot
    $searcher   = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $dEntryRoot
    $searcher.Filter = "(&(name=$($GMSAName.TrimEnd('$')))(objectCategory=msDS-GroupManagedServiceAccount))"
    [void]$searcher.PropertiesToLoad.Add('name')
    [void]$searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
    $searcher.SearchRoot.AuthenticationType = 'Sealing'

    $accounts = $searcher.FindAll()
    foreach ($a in $accounts) {
        if (-not $a.Properties.'msds-managedpassword') { continue }

        $pw = $a.Properties.'msds-managedpassword'
        [byte[]]$blob = $pw.ForEach({ $_ })

        $ms = New-Object System.IO.MemoryStream -ArgumentList (,$blob)
        $br = New-Object System.IO.BinaryReader -ArgumentList $ms
        try {
            $null = $br.ReadInt16()  # version
            $null = $br.ReadInt16()  # reserved
            $null = $br.ReadInt32()  # length
            $pwOffset = $br.ReadInt16()

            $secure = New-Object System.Security.SecureString
            for ($i = $pwOffset; $i -le $blob.Length; $i += 2) {
                $c = [System.BitConverter]::ToChar($blob, $i)
                if ($c -eq [char]::MinValue) { break }
                $secure.AppendChar($c)
            }
            $secure.MakeReadOnly()

            return (New-Object System.Management.Automation.PSCredential -ArgumentList @("$Domain\$GMSAName", $secure))
        }
        finally {
            $br.Dispose()
            $ms.Dispose()
        }
    }

    throw "Get-GMSACredential: could not retrieve msDS-ManagedPassword for '$GMSAName' in domain '$Domain'. The current host must be listed in PrincipalsAllowedToRetrieveManagedPassword of the gMSA object."
}
