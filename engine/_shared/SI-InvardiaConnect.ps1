#Requires -Version 5.1
<#
    SecurityInsight -- "CONNECT THIS INSTALL TO INVARDIA" (framework PRO-COMMUNITY-SAME, owner 2026-11-11: opt-in for the
    Community edition). ONE setting, read in ONE place: SI_Invardia_Connect.

    A Community install sends NOTHING that identifies its tenant or its install -- no status report (not even the anonymous
    one: it carries the install's own id), no licence request, no install key claim, no "Update now" poll keyed to the
    install, no failure report -- unless its user said yes to "Connect this install to Invardia: health reports + updates
    on request". A Pro install is connected (its licence is the agreement), as before.

      1. the setting, when it is set: $global:SI_Invardia_Connect (the install's configuration), else the job's environment
         SI_CFG_SI_Invardia_Connect, else SI_INVARDIA_CONNECT -- on / true / yes / 1 = connected; off / false / no / 0 = not;
      2. not set: connected for a Pro install (the edition the caller knows: pro / trial), or an install that holds an
         Invardia install key (it was connected when the key was given); a Community install is NOT connected.

    Every call that carries a tenant id or an install id asks Test-SIInvardiaConnect first. A call that carries neither --
    the anonymous read of the signed release manifest for a ring -- needs no yes. PURE; never throws.
#>

function Get-SIInvardiaConnectSetting {
    <# PURE. The setting's value when it is set: $true / $false; $null when it is not set (or not a yes / no word). #>
    param([AllowNull()]$Value = $global:SI_Invardia_Connect,
          [AllowNull()][AllowEmptyString()][string]$EnvValue = $(if ("$env:SI_CFG_SI_Invardia_Connect".Trim()) { $env:SI_CFG_SI_Invardia_Connect } else { $env:SI_INVARDIA_CONNECT }))
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { return $v }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        if ($s -in @('on', 'true', 'yes', '1', 'connected')) { return $true }
        if ($s -in @('off', 'false', 'no', '0', 'disconnected')) { return $false }
    }
    $null
}

function Test-SIInvardiaConnect {
    <# PURE. Is this install connected to Invardia (may a call carry its tenant id or install id)? See the header. #>
    param([AllowEmptyString()][string]$Edition = '', [bool]$HasInstallKey = $false,
          [AllowNull()]$Value = $global:SI_Invardia_Connect,
          [AllowNull()][AllowEmptyString()][string]$EnvValue = $(if ("$env:SI_CFG_SI_Invardia_Connect".Trim()) { $env:SI_CFG_SI_Invardia_Connect } else { $env:SI_INVARDIA_CONNECT }))
    $set = Get-SIInvardiaConnectSetting -Value $Value -EnvValue $EnvValue
    if ($null -ne $set) { return [bool]$set }
    if ("$Edition".Trim().ToLowerInvariant() -in @('pro', 'trial')) { return $true }
    [bool]$HasInstallKey
}

function Get-SIInvardiaConnectSkipText {
    <# PURE. The one line a call that was not made says. #>
    param([string]$What = 'nothing')
    ('not connected to Invardia (SI_Invardia_Connect): {0} is sent -- a Community install sends nothing that identifies it until "Connect this install to Invardia" is answered yes' -f $What)
}
