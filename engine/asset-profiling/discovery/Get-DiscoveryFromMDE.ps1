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

# #412 one pull per source: at the full asset-metadata level each machine object below is ALSO kept whole -- the same
# object the emit block reads, from the same request (there never was any narrowing in the request). Security: nothing.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

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

    # Audit #4: retry transient failures and KEEP the pages already collected. A
    # throttle mid-pagination used to discard every page and return @(), which the
    # caller could not tell apart from "this tenant has no devices". A source that
    # dies after retries degrades the run; it must never block it.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1')

    # The asset of ONE Defender machine row -- shared by the whole-set loop below and the streaming path (#475).
    $buildMachine = {
        param($m)
        Add-SIFullSourceObject -SourceSystem 'mde' -Object $m -AnchorColumn 'MdeDeviceId' -AnchorValue ([string]$m.id)
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
            # 🔴 `$m.version`, NOT `$m.osVersion` -- FIXED 2026-08-31, and it had been null since this
            # file was written. MEASURED against the live API: /api/machines returns 30 distinct
            # property names across 146 machines and `osVersion` is NOT one of them; the OS version
            # ships as `version`. So MDE_OSVersion -- and the OsVersion column the schema declares from
            # it -- has always been empty on every MDE-sourced row.
            # 🔑 Found by the asset-properties add-on's widening report, which compares the WIDE pull
            # against the narrow baseline and names any baseline field the source does not return. That
            # check exists to catch an upstream change; its first real catch was a field the source
            # never returned in the first place.
            MDE_OSVersion       = $m.version
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
            # 🔴 THE ONLY BRIDGE FROM A DEVICE TO ITS AZURE VM (#204). Defender reports an Azure VM's ARM id in
            # `vmMetadata.resourceId`; the endpoint row builder has always read MDE_AzureResourceId into the
            # AzureResourceId column and the correlation identifiers, and nothing ever produced it. Measured
            # 2026-10-02: 9 of 206 machines carry it (mgmt1, dc1, dc3 among them), and 0 of 4 Azure VMs were
            # correlated with their device. The Exposure Graph carries no ARM id, so it cannot be the bridge.
            MDE_AzureResourceId = $(if ($m.vmMetadata -and $m.vmMetadata.resourceId) { [string]$m.vmMetadata.resourceId } else { $null })
            # 🔴 THESE FOUR ARE NOT RETURNED BY /api/machines AND NEVER HAVE BEEN -- measured
            # 2026-08-31 across 146 machines: the response carries 30 property names and none of these
            # is among them. They are kept, assigning $null explicitly, ONLY so the next reader does not
            # "add" them again and re-create four permanently-empty columns.
            # 📌 `publicIp` and `defenderAvStatus` are not machine-list properties at all;
            # `vulnerabilityCount` and `missingKbCount` come from the TVM endpoints, which is a
            # different call this discovery does not make. Producing them is a FEATURE (another API),
            # not a repair -- the same distinction the AssetName dead-candidate notes draw.
            MDE_PublicIp        = $null
            MDE_VulnerabilityCount = $null
            MDE_MissingKbCount  = $null
            MDE_DefenderAvStatus= $null
            # 🔴 `managedBy` -- the field whose ABSENCE meant Get-SICmdbAssetType's `intune-device`
            # branch could never fire, so 94 of 238 assets classified `unknown` and routed to
            # match-only. It has been in this API response the whole time; the emit block simply did
            # not copy it. Added 2026-08-31 with the schema column and the builder mapping, because any
            # one of the three alone is a no-op -- which is exactly how it went unnoticed.
            MDE_ManagedBy       = $m.managedBy
            MDE_ManagedByStatus = $m.managedByStatus
        }
    }

    # #475 STREAMING (the discover phase of a run collected in parts): each page becomes assets and goes straight into
    # the parts -- the source is never all held.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        $onPage = { param($PageRows) $batch = New-Object System.Collections.Generic.List[object]; foreach ($m in $PageRows) { $x = & $buildMachine $m; if ($x) { $batch.Add($x) } }; $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray() }
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'MDE /api/machines' -OnPage $onPage
        if (-not $page.Complete) { Write-Warning ('MDE: {0} -- continuing with {1} row(s) from {2} page(s); the run is NOT blocked.' -f $page.Error, $page.Count, $page.Pages) }
        Set-SIFullSourcePull -SourceSystem 'mde' -Complete ([bool]$page.Complete) -ErrorText ([string]$page.Error)
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['MDE'] = [int]$page.Count }
        Write-SIInfo ('   MDE: {0} row(s) streamed into {1} part(s), page by page' -f $page.Count, $stream.Parts)
        return
    }

    $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'MDE /api/machines'
    foreach ($m in $page.Rows) { [void]$rows.Add($m) }
    if (-not $page.Complete) {
        Write-Warning ('MDE direct: {0} -- continuing with {1} device(s) from {2} page(s); the run is NOT blocked. (ExposureGraph already covers most tenants.)' -f `
            $page.Error, $rows.Count, $page.Pages)
    }
    Set-SIFullSourcePull -SourceSystem 'mde' -Complete ([bool]$page.Complete) -ErrorText ([string]$page.Error)

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'MdeDevices' -ErrorAction SilentlyContinue
    foreach ($m in $rows) {
        $_i++
        try { Write-SIProgress -Label 'MdeDevices' -Index $_i -Total $_total } catch { }
        & $buildMachine $m
    }
}
