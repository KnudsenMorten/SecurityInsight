#Requires -Version 5.1
<#
    PRO BUSINESS LICENCE LIMITS AT COLLECTION (#474; framework section 12.6 LICENCE-DIMENSION).

    A Pro Business licence carries a signed `limits` object -- SecurityInsight reads `devices` (e.g. 250). The endpoint
    collection counts the devices it discovered against it. A limit is a WARNING, never a stop (#448): every device is
    collected, nothing is left out, no run is failed. From 90 % of the limit the run says so; above the limit it says how
    many devices are above it; above the limit + 10 % it is the alarm (the same thresholds as the web app's banner,
    pro-management LicenceDimension.Usage). Pro Enterprise (no limits), Community and an unlicensed install: nothing.

    The result is kept in $global:SI_LicenceUsage (Dimension, Limit, Devices, State, Message) for whatever reports it on,
    and the run's END record carries the message when the limit is reached.
#>

$script:SILicenceWarnFrom  = 0.90
$script:SILicenceAlarmAbove = 1.10

function Get-SILicenceLimitState {
    <#
        PURE. The devices a run saw against the licence's device limit. -Limit $null = no limit (state 'none').
        Returns @{ Limit; Devices; Share; State = none | ok | near | over | alarm; Message } -- the message in plain words:
        what the licence covers, what the run saw, that nothing was left out, and what to do.
    #>
    param([AllowNull()][Nullable[int]]$Limit, [long]$Devices, [string]$What = 'devices')
    if ($null -eq $Limit -or $Devices -lt 0) { return [pscustomobject]@{ Limit = $Limit; Devices = $Devices; Share = $null; State = 'none'; Message = '' } }
    $cap = [int]$Limit
    $share = if ($cap -eq 0) { $(if ($Devices -gt 0) { [double]::PositiveInfinity } else { 0.0 }) } else { [double]$Devices / $cap }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $covers = 'Your Pro Business licence covers {0} {1}' -f $cap.ToString('N0', $inv), $What
    $goesOn = 'All {0} were collected -- nothing is left out and nothing is stopped.' -f $Devices.ToString('N0', $inv)
    $how = 'To stay within the licence, ask Invardia for a higher limit or for Pro Enterprise (no limit).'
    if ($Devices -gt $cap) {
        $state = if ($share -gt $script:SILicenceAlarmAbove) { 'alarm' } else { 'over' }
        $msg = '{0}; this run found {1} -- {2} above the limit. {3} {4}' -f $covers, $Devices.ToString('N0', $inv), ($Devices - $cap).ToString('N0', $inv), $goesOn, $how
        return [pscustomobject]@{ Limit = $cap; Devices = $Devices; Share = $share; State = $state; Message = $msg }
    }
    if ($share -ge $script:SILicenceWarnFrom) {
        $pct = [math]::Floor($share * 100)
        $msg = '{0}; this run found {1} ({2} % of the limit, {3} left). Nothing is stopped when the limit is passed. {4}' -f $covers, $Devices.ToString('N0', $inv), $pct, ($cap - $Devices).ToString('N0', $inv), $how
        return [pscustomobject]@{ Limit = $cap; Devices = $Devices; Share = $share; State = 'near'; Message = $msg }
    }
    [pscustomobject]@{ Limit = $cap; Devices = $Devices; Share = $share; State = 'ok'; Message = ('{0}; this run found {1}.' -f $covers, $Devices.ToString('N0', $inv)) }
}

function Get-SILicenceDeviceLimit {
    <# The signed device limit of a VALID Pro Business licence, else $null (Enterprise, Community, invalid, no licence). #>
    param([AllowNull()]$License)
    if ($null -eq $License) { return $null }
    $dim = if (Get-Command -Name Get-SILicenceDimension -ErrorAction SilentlyContinue) { Get-SILicenceDimension -License $License } else { '' }
    if ($dim -ne 'Pro Business') { return $null }
    $l = $License.Limits
    if ($l -is [System.Collections.IDictionary] -and $l.Contains('devices')) { return [int]$l['devices'] }
    return $null
}

function Invoke-SILicenceLimitCheck {
    <#
        After the endpoint collection's discovery: count the devices against a Pro Business licence. NEVER throws, never
        stops or shortens the run. Returns the state (Get-SILicenceLimitState) or $null when there is nothing to check.
        -License / -Log are seams for tests; by default the install's licence (Get-SILicense) and Write-Warning / Write-Host.
    #>
    param([Parameter(Mandatory)][string]$Engine, [long]$DeviceCount = -1, $License, [scriptblock]$Log)
    $global:SI_LicenceUsage = $null
    try {
        if ($Engine -ne 'endpoint' -or $DeviceCount -lt 0) { return $null }
        if (-not $PSBoundParameters.ContainsKey('License')) {
            if (-not (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue)) {
                $fc = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'SI-FeatureCatalog.ps1')
                if (Test-Path -LiteralPath $fc) { . $fc }
            }
            if (-not (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue)) { return $null }
            $License = Get-SILicense
        }
        $limit = Get-SILicenceDeviceLimit -License $License
        if ($null -eq $limit) { return $null }
        $s = Get-SILicenceLimitState -Limit $limit -Devices $DeviceCount
        $global:SI_LicenceUsage = [pscustomobject]@{ Dimension = 'Pro Business'; Limit = $s.Limit; Devices = $s.Devices; State = $s.State; Message = $s.Message }
        if (-not $Log) { $Log = { param($level, $msg) if ($level -eq 'WARN') { Write-Warning $msg } else { Write-Host (' [licence] {0}' -f $msg) } } }
        $level = if ($s.State -in 'near', 'over', 'alarm') { 'WARN' } else { 'INFO' }
        & $Log $level ('[licence] ' + $s.Message)
        return $s
    } catch {
        try { Write-Warning ('[licence] the device limit could not be checked: {0}' -f $_.Exception.Message) } catch { }
        return $null
    }
}
