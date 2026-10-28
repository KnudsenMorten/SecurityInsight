#Requires -Version 5.1
<#
    The tenant as a mail shows it: '<primary domain> (<tenant id>)', e.g. 'contoso.onmicrosoft.com (1111...)'.

    WHY (#243, operator 2026-10-04: "it shows the tenant id in subject of the email, in v2.2 it shows the
    onmicrosoft primary domain name - include both"). v2.2 took the name from framework globals
    ($global:TenantShort / $global:TenantNameOrganization, set by the internal platform defaults). A v3 install
    signing in with a managed identity never sets them, so the subject fell through to the tenant id alone.

    The domain is resolved in this order, and the first answer wins:
      1. $global:SI_TenantDomain               -- the explicit setting
      2. $global:TenantNameOrganization / $global:TenantShort -- the v2.2 framework globals, when present
      3. Microsoft Graph GET /organization as the run's own identity (managed identity or SPN, through
         Get-SIGraphToken): the verified domain marked isInitial -- the tenant's onmicrosoft.com domain.
         Directory.Read.All, already in the engine identity's grants, covers it.
    The answer (or the failure) is cached per tenant for the process, so one run asks Graph at most once.
    When the domain cannot be read the display is the tenant id alone, with ONE verbose line -- this never fails
    a run or a mail.

    Windows PowerShell 5.1 and PowerShell 7. No ?. / ??.
#>

function Get-SITenantDisplayGlobal {
    # One setting, from -Globals when given, else from the session's globals. '' when unset.
    param([string]$Name, $Globals)
    $v = $null
    if ($null -ne $Globals) {
        if ($Globals.ContainsKey($Name)) { $v = $Globals[$Name] }
    } else {
        $v = Get-Variable -Scope Global -Name $Name -ValueOnly -ErrorAction SilentlyContinue
    }
    if ($null -eq $v) { return '' }
    return ([string]$v).Trim()
}

function Reset-SITenantDisplayCache {
    $global:SI_TenantDisplayCache = @{}
}

function Select-SITenantInitialDomain {
    <# The organization response -> @{ Domain; TenantId }: the isInitial verified domain (else the default one). #>
    param($Response)
    $org = $null
    if ($null -ne $Response) {
        if ($Response.PSObject.Properties['value']) { $org = @($Response.value) | Select-Object -First 1 }
        else { $org = $Response }
    }
    $out = @{ Domain = ''; TenantId = '' }
    if ($null -eq $org) { return $out }
    if ($org.PSObject.Properties['id'] -and $org.id) { $out.TenantId = [string]$org.id }
    $doms = @()
    if ($org.PSObject.Properties['verifiedDomains'] -and $org.verifiedDomains) { $doms = @($org.verifiedDomains) }
    foreach ($d in $doms) { if ($d -and $d.isInitial -eq $true -and $d.name) { $out.Domain = [string]$d.name; return $out } }
    foreach ($d in $doms) { if ($d -and $d.isDefault -eq $true -and $d.name) { $out.Domain = [string]$d.name; return $out } }
    return $out
}

function Get-SITenantDisplayName {
    <#
    .SYNOPSIS
        '<domain> (<tenant id>)' for mail subjects and headers; the id alone, or the domain alone, when only one is
        known; '' when neither is.
    .PARAMETER Globals
        The settings as a hashtable (tests, and engines that pass their globals around). Omitted: the session's globals.
    .PARAMETER GraphGet
        Returns the GET /organization response. Default: Get-SIGraphToken + Invoke-SIGraphRest when both are loaded,
        otherwise no Graph call is made.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Globals = $null,
        [scriptblock]$GraphGet = $null
    )
    $id = ''
    try {
        foreach ($n in 'AzureTenantID', 'SpnTenantId', 'SI_SPN_TenantId', 'SI_TenantId', 'HighPriv_Modern_TenantID') {
            $id = Get-SITenantDisplayGlobal -Name $n -Globals $Globals
            if ($id) { break }
        }
        $domain = ''
        foreach ($n in 'SI_TenantDomain', 'TenantNameOrganization', 'TenantShort') {
            $domain = Get-SITenantDisplayGlobal -Name $n -Globals $Globals
            if ($domain) { break }
        }

        if (-not $domain) {
            if ($null -eq $global:SI_TenantDisplayCache -or $global:SI_TenantDisplayCache -isnot [hashtable]) { Reset-SITenantDisplayCache }
            $key = if ($id) { $id.ToLowerInvariant() } else { '(no tenant id)' }
            if ($global:SI_TenantDisplayCache.ContainsKey($key)) {
                $hit = $global:SI_TenantDisplayCache[$key]
                $domain = [string]$hit.Domain
                if (-not $id) { $id = [string]$hit.TenantId }
            } else {
                $why = ''
                $found = @{ Domain = ''; TenantId = '' }
                if ($null -eq $GraphGet -and (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) -and (Get-Command -Name Invoke-SIGraphRest -ErrorAction SilentlyContinue)) {
                    $GraphGet = {
                        $tok = Get-SIGraphToken -Resource Graph
                        Invoke-SIGraphRest -Uri '/organization?$select=id,verifiedDomains' -Token $tok -TimeoutSec 30 -MaxAttempts 2
                    }
                }
                if ($null -eq $GraphGet) { $why = 'no Microsoft Graph sign-in is loaded in this engine' }
                else {
                    try {
                        $found = Select-SITenantInitialDomain -Response (& $GraphGet)
                        if (-not $found.Domain) { $why = 'Microsoft Graph returned no initial domain' }
                    } catch {
                        $why = $_.Exception.Message
                    }
                }
                if ($why) { Write-Verbose ("The tenant's domain could not be read ({0}); the mail shows the tenant id." -f $why) }
                $domain = [string]$found.Domain
                if (-not $id -and $found.TenantId) { $id = [string]$found.TenantId }
                $global:SI_TenantDisplayCache[$key] = @{ Domain = $domain; TenantId = [string]$found.TenantId }
            }
        }

        if ($domain -and $id -and -not [string]::Equals($domain, $id, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ('{0} ({1})' -f $domain, $id)
        }
        if ($domain) { return $domain }
        return $id
    } catch {
        Write-Verbose ("The tenant's domain could not be read ({0}); the mail shows the tenant id." -f $_.Exception.Message)
        return $id
    }
}
