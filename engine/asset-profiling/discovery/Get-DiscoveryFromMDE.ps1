#Requires -Version 5.1
<#
    Discovery source: Defender for Endpoint direct device API.

    The Defender API path:
        GET https://api.securitycenter.microsoft.com/api/machines
    Auth: WindowsDefenderATP token (Resource = 'Defender') with
          Machine.Read.All on WindowsDefenderATP.

    fix: was using Resource=MDE (audience api.security.microsoft.com,
    Microsoft Threat Protection). Customers grant Machine.Read.All on the
    LEGACY WindowsDefenderATP app (api.securitycenter.microsoft.com), so the
    token from the new XDR audience didn't carry that role -> 403. Switched
    to Resource=Defender + matching URL.

    PREVIEW.4 NOTE: in most tenants this source is REDUNDANT with
    ExposureGraph -- ExposureGraph (via Advanced Hunting) returns every
    device Defender knows about, which is a superset of what /api/machines
    returns. This connector exists for tenants WITHOUT MDE Plan 2 (where
    ExposureGraph isn't available) but WITH Defender for Business or
    legacy MDE Plan 1, where /api/machines is the only device-list route.

    For it stays a stub returning empty -- enable when a customer
    on Defender for Business / MDE P1 needs it.
#>

function Get-DiscoveryFromMDE {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'MDE direct discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    # Most tenants are covered by ExposureGraph; emit a soft note instead of
    # 403'ing on tenants without MDE-direct API access. Real impl below.
    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Defender
    } catch {
        Write-Warning ('MDE direct: token acquisition failed -- {0}. (ExposureGraph already covers most tenants.)' -f $_.Exception.Message)
        return @()
    }

    $rows = New-Object System.Collections.ArrayList
    $url = 'https://api.securitycenter.microsoft.com/api/machines'

    try {
        do {
            $resp = Invoke-RestMethod -Method Get -Uri $url `
                -Headers @{ Authorization = ('Bearer ' + $token) }
            foreach ($m in $resp.value) { [void]$rows.Add($m) }
            $url = $resp.'@odata.nextLink'
        } while ($url)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('MDE direct: /api/machines failed -- {0}. (ExposureGraph already covers most tenants.)' -f $msg)
        return @()
    }

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'MdeDevices' -ErrorAction SilentlyContinue
    foreach ($m in $rows) {
        $_i++
        try { Write-SIProgress -Label 'MdeDevices' -Index $_i -Total $_total } catch { }
        $name = if ($m.computerDnsName) { $m.computerDnsName } else { $m.id }
        # NormalizedKey wants the SHORT hostname for cross-source merge.
        # MDE returns FQDN (e.g. "strv-mok-dt-03.2linkit.local") while EG + Entra
        # return short names ("strv-mok-dt-03"). Different NormalizedKey -> no
        # merge -> 2-3 separate rows for the same device. Keep MDE_DeviceName as
        # the original (forensics + display); use short name for routing only.
        $shortName = $name
        if ($shortName -is [string] -and $shortName.Contains('.')) {
            $shortName = $shortName.Substring(0, $shortName.IndexOf('.'))
        }
        $hint = switch -Wildcard ($m.osPlatform) {
            'Windows*' { 'windows' }
            'macOS*'   { 'mac' }
            'Linux*'   { 'linux' }
            default    { 'unknown' }
        }
        # MDE_*-prefixed keys mirror the ENTRA_*/EG_*/AZ_* convention used by
        # other discoveries -- Stage Collect's elseif chain detects MDE records
        # via $a.MDE_DeviceId and the row builder's key map resolves these
        # cleanly. Top-level routing fields (AssetId/Source/Hint/Name/NormalizedKey)
        # remain unprefixed -- they're wire envelope, not metadata.
        @{
            AssetId             = 'mde:' + $m.id
            Source              = 'MDEDevice'
            Hint                = $hint
            Name                = $name
            NormalizedKey       = $shortName.ToLowerInvariant()
            MDE_DeviceId        = $m.id
            MDE_DeviceName      = $name
            MDE_OSPlatform      = $m.osPlatform
            MDE_OSVersion       = $m.osVersion
            MDE_OSProcessor     = $m.osProcessor
            MDE_SensorHealthState = $m.healthStatus
            MDE_RiskScore       = $m.riskScore
            MDE_ExposureScore   = $m.exposureLevel
            MDE_OnboardingStatus= $m.onboardingStatus
            MDE_MachineGroup    = $m.rbacGroupName
            MDE_MachineTags     = $m.machineTags
            MDE_LastSeen        = $m.lastSeen
            MDE_FirstSeen       = $m.firstSeen
            MDE_AadDeviceId     = $m.aadDeviceId
            MDE_PublicIp        = $m.publicIp
            MDE_VulnerabilityCount = $m.vulnerabilityCount
            MDE_MissingKbCount  = $m.missingKbCount
            MDE_DefenderAvStatus= $m.defenderAvStatus
        }
    }
}
