#Requires -Version 5.1
<#
    Discovery source: Entra ID device registry.

    Endpoint: GET https://graph.microsoft.com/v1.0/devices
    Auth:     Microsoft Graph with Device.Read.All

    Returns Entra-registered/joined/hybrid devices, INCLUDING BYOD that
    Defender doesn't see. Pages through the full result set via
    @odata.nextLink.

    OS-hint inference from the operatingSystem string (Windows/macOS/Linux/
    iOS/Android).
#>

function Get-DiscoveryFromEntra {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'Entra discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Entra: token acquisition failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    $rows = New-Object System.Collections.ArrayList
    # also $select deviceId (the AAD device GUID, distinct from the
    # Entra object id) -- it's the cross-source join key MDE + EG also expose.
    # approximateLastSignInDateTime drives the SI_ExcludeInactive_Endpoint /
    # SI_RequireMdeActive_Endpoint filter so a device that's stale in MDE but
    # signed in to Entra in last N days still counts as active.
    $url = 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,deviceCategory,trustType,profileType,registrationDateTime,approximateLastSignInDateTime&$top=999'

    try {
        do {
            $resp = Invoke-RestMethod -Method Get -Uri $url `
                -Headers @{ Authorization = ('Bearer ' + $token) }
            foreach ($d in $resp.value) { [void]$rows.Add($d) }
            $url = $resp.'@odata.nextLink'
        } while ($url)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('Entra: /devices call failed -- {0}' -f $msg)
        return @()
    }

    foreach ($d in $rows) {
        $name = $d.displayName
        if (-not $name) { $name = $d.id }
        $hint = switch -Wildcard ($d.operatingSystem) {
            'Windows*' { 'windows' }
            'macOS*'   { 'mac' }
            'Linux*'   { 'linux' }
            'iOS'      { 'mobile-ios' }
            'iPadOS*'  { 'mobile-ios' }
            'Android*' { 'mobile-android' }
            default    { 'unknown' }
        }
        @{
            AssetId           = 'entra:' + $d.id
            Source            = 'EntraDevice'
            Hint              = $hint
            Name              = $name
            NormalizedKey     = $name.ToLowerInvariant()
            EntraId           = $d.id              # preserved for back-compat with code that reads $a.EntraId
            ENTRA_ObjectId    = $d.id
            ENTRA_AadDeviceId = $d.deviceId        # AAD device GUID (matches MDE.aadDeviceId / EG.rawData.aadDeviceId) -- cross-source merge key
            ENTRA_DisplayName = $d.displayName
            ENTRA_OS          = $d.operatingSystem
            ENTRA_TrustType   = $d.trustType
            ENTRA_ProfileType = $d.profileType
            ENTRA_Category    = $d.deviceCategory
            ENTRA_RegisteredAt= $d.registrationDateTime
            ENTRA_ApproximateLastSignInDateTime = $d.approximateLastSignInDateTime
            # keep the unprefixed OS so the legacy `elseif ($a.OS)` branch
            # in Invoke-Collect still triggers for pure Entra-device records (devices
            # MDE + EG don't see). Cross-source-merged records hit the EG branch first
            # which now passes through all ENTRA_* fields.
            OS                = $d.operatingSystem
        }
    }
}
