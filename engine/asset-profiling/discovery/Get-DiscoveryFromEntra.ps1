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

# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

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
    # #497 onPremisesSecurityIdentifier (the AD computer account's SID of a hybrid-joined device) joins the Entra device to its AD
    # computer in the model (ad_sid); onPremisesSyncEnabled says it is synced. Same read, same permission (Device.Read.All).
    # LIST KEPT at the security level (what the risk profile needs; tens of thousands of devices). At the full level the list is DROPPED and the device is read whole (SI-FullAssetProperties.ps1, the whole-object sources).
    $url = 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,deviceCategory,trustType,profileType,registrationDateTime,approximateLastSignInDateTime,accountEnabled,onPremisesSecurityIdentifier,onPremisesSyncEnabled&$top=999'

    # Audit #4: retry transient failures and KEEP the pages already collected.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1')

    # The asset of ONE Entra device row -- shared by the whole-set loop below and the streaming path (#475).
    $buildDevice = {
        param($d)
        Add-SIFullSourceObject -SourceSystem 'entra-device' -Object $d -AnchorColumn 'AadDeviceId' -AnchorValue ([string]$d.deviceId)
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
            # #533: the device account's own enabled state in Entra -- "disabled" is read from the directory, never inferred
            # from inactivity (SI_DisabledAssets_*). Carried to Properties.collect.entra.AccountEnabled on the profile row.
            ENTRA_AccountEnabled = $d.accountEnabled
            # keep the unprefixed OS so the legacy `elseif ($a.OS)` branch
            # in Invoke-Collect still triggers for pure Entra-device records (devices
            # MDE + EG don't see). Cross-source-merged records hit the EG branch first
            # which now passes through all ENTRA_* fields.
            OS                = $d.operatingSystem
        }
    }

    # #475 STREAMING (the discover phase of a run collected in parts): each page becomes assets and goes straight into
    # the parts -- the source is never all held.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        $onPage = { param($PageRows) $batch = New-Object System.Collections.Generic.List[object]; foreach ($d in $PageRows) { $x = & $buildDevice $d; if ($x) { $batch.Add($x) } }; $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray() }
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'Entra /devices' -OnPage $onPage
        if (-not $page.Complete) { Write-Warning ('Entra: {0} -- continuing with {1} row(s) from {2} page(s); the run is NOT blocked.' -f $page.Error, $page.Count, $page.Pages) }
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['Entra'] = [int]$page.Count }
        Write-SIInfo ('   Entra: {0} row(s) streamed into {1} part(s), page by page' -f $page.Count, $stream.Parts)
        return
    }

    if (Test-SIFullAssetPropertiesOn) {
        # #412 full asset metadata: ONE wide pull -- the $select above UNION the device's other properties. The record
        # below reads the same fields from it, so the security record is unchanged.
        $page = Invoke-SIFullAwareGraphPull -SourceSystem 'entra-device' -SecurityUrl $url -Label 'Entra /devices' -Fetch { param($u, $l) Invoke-SIPagedRest -Url $u -Token $token -SourceLabel $l }
    } else {
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'Entra /devices'
    }
    foreach ($d in $page.Rows) { [void]$rows.Add($d) }
    if (-not $page.Complete) {
        Write-Warning ('Entra: {0} -- continuing with {1} device(s) from {2} page(s); the run is NOT blocked.' -f `
            $page.Error, $rows.Count, $page.Pages)
    }

    foreach ($d in $rows) {
        & $buildDevice $d
    }
}
