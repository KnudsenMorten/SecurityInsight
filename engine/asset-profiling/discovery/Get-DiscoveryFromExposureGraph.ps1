#Requires -Version 5.1
<#
    Discovery source: Defender ExposureGraph (via Microsoft Graph Advanced
    Hunting).

    KQL:
        ExposureGraphNodes
        | where NodeLabel == 'device'
        | distinct NodeId, NodeName, NodeProperties

    Returns every device the ExposureGraph knows about -- includes managed
    Defender devices PLUS unmanaged devices Defender discovered via network
    scanning. This is the broadest endpoint discovery source.

    Auth: Microsoft Graph token with ThreatHunting.Read.All on the
    ExposureGraph schema. License: Microsoft Defender for Endpoint Plan 2 OR
    Microsoft Defender Vulnerability Management.

    Endpoint: POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
#>

function Get-DiscoveryFromExposureGraph {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'ExposureGraph discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('ExposureGraph: token acquisition failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # NodeProperties is a 'dynamic' column -- can't be used in `distinct`
    # (returns 400). Convert to string first; NodeId is already unique so
    # `distinct` isn't needed.
    $kql = @'
ExposureGraphNodes
| where NodeLabel == 'device'
| project NodeId, NodeName, NodePropertiesJson = tostring(NodeProperties)
'@


    # The asset of ONE Exposure Graph device node row -- shared by the whole-set loop below and the streaming path (#475).
    $buildEgNode = {
        param($r)
        $name = if ($r.NodeName) { $r.NodeName } else { $r.NodeId }

        # Parse NodeProperties for OS-hint inference + a few load-bearing
        # downstream fields. Format from the EG schema:
        #   { "rawData": { "osPlatform": "...", "deviceType": "...",
        #                  "deviceCategory": "...", "machineGroup": "...",
        #                  "exposureScore": "...", "riskScore": "...",
        #                  "onboardingStatus": "...", ... } }
        $os         = $null
        $devType    = $null
        $devCat     = $null
        $mdeOnboard = $null
        $exposure   = $null
        $risk       = $null
        if ($r.NodePropertiesJson) {
            try {
                $raw = ($r.NodePropertiesJson | ConvertFrom-Json).rawData
                if ($raw) {
                    $os         = $raw.osPlatform
                    $devType    = $raw.deviceType
                    $devCat     = $raw.deviceCategory
                    $mdeOnboard = $raw.onboardingStatus
                    $exposure   = $raw.exposureScore
                    $risk       = $raw.riskScore
                }
            } catch { }
        }

        $hint = switch -Wildcard ($os) {
            'Windows*'        { if ($devType -eq 'Server') { 'windows-server' } else { 'windows' } }
            '*Server*'        { 'windows-server' }
            'macOS*'          { 'mac' }
            'Linux*'          { 'linux' }
            'Ubuntu*'         { 'linux' }
            'Centos*'         { 'linux' }
            'iOS'             { 'mobile-ios' }
            'iPadOS'          { 'mobile-ios' }
            'Android*'        { 'mobile-android' }
            default           { if ($devCat -eq 'IoT') { 'iot' } else { 'unknown' } }
        }

        @{
            AssetId          = 'eg:' + $r.NodeId
            Source           = 'ExposureGraph'
            Hint             = $hint
            Name             = $name
            NormalizedKey    = $name.ToLowerInvariant()
            EgNodeId         = $r.NodeId
            EgOS             = $os
            EgDeviceType     = $devType
            EgDeviceCategory = $devCat
            EgOnboardStatus  = $mdeOnboard
            EgExposureScore  = $exposure
            EgRiskScore      = $risk
        }
    }

    # #475 STREAMING (the discover phase of a run collected in parts): one hunting query for every node is cut off at the
    # hunting row limit on a large estate -- the nodes are read in BUCKETS of ~20,000 (hash of the node id), each sent
    # straight into the parts.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        # every hunting request through the SHARED retrying request (Invoke-SIHuntingGraphRequest, HuntingQuery.ps1: 429 / 5xx /
        # no answer waited out, an expired token renewed); a failure that stays is thrown, named
        if (-not (Get-Command -Name Invoke-SIHuntingGraphRequest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1') }
        if (-not (Get-Command -Name New-SIGraphJsonBody -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-GraphRest.ps1') }
        $egToken = $token
        $hunt = { param([string]$Query) $a = Invoke-SIHuntingGraphRequest -Query $Query -Token { param([bool]$Force) $egToken }; if (-not $a.Ok) { throw ([string]$a.Error) }; @($a.Rows) }
        # the bucket count needs the node COUNT. It is retried like every request; when it still fails there is NO fallback to
        # one unbucketed query (at 500,000 nodes it is cut at Microsoft's 100,000-row limit): the discovery is INCOMPLETE
        # this run, said by name, and its nodes are UNKNOWN -- never removed
        $total = $null; $countErr = ''
        try { $c = @(& $hunt ($kql.TrimEnd() + "`n| count")); $n = 0L; if ($c.Count -gt 0 -and [long]::TryParse([string]$c[0].Count, [ref]$n)) { $total = $n } else { $countErr = 'the count came back without a number' } } catch { $countErr = $_.Exception.Message }
        if ($null -eq $total) {
            $egIncomplete = ('ExposureGraph: the node count could not be read ({0}) -- the Exposure Graph discovery is INCOMPLETE this run: no nodes were read (one query without buckets would be cut at Microsoft''s 100,000-row limit). Its nodes are UNKNOWN this run, not removed.' -f $countErr)
            if (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue) { Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete $false -ErrorText ('node count failed: ' + $countErr) }
            if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['ExposureGraph'] = 0 }
            # THROWN (review 2, S5): Invoke-Discover counts this source as NOT COMPLETE -- the run ends success-partial, the CMDB never reads the snapshot as complete
            throw $egIncomplete
        }
        $buckets = [int][Math]::Max(1, [Math]::Ceiling($total / 20000.0))
        $taken = 0; $failed = 0
        for ($bk = 0; $bk -lt $buckets; $bk++) {
            $q = $kql; if ($buckets -gt 1) { $q = $kql.TrimEnd() + ("`n| where hash(NodeId, {0}) == {1}" -f $buckets, $bk) }
            try { $bucketRows = @(& $hunt $q) } catch { $failed++; Write-Warning ('ExposureGraph: bucket {0} of {1} failed -- {2}. Its nodes are UNKNOWN this run, not removed.' -f ($bk + 1), $buckets, $_.Exception.Message); continue }
            $batch = New-Object System.Collections.Generic.List[object]; foreach ($r in $bucketRows) { $x = & $buildEgNode $r; if ($x) { $batch.Add($x) } }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray(); $taken += $batch.Count; $bucketRows = $null; $batch = $null
        }
        if (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue) { Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete ($failed -eq 0) }
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['ExposureGraph'] = $taken }
        Write-SIInfo ('   ExposureGraph: {0} node(s) in {1} bucket(s) streamed into {2} part(s)' -f $taken, $buckets, $stream.Parts)
        return
    }

    Write-SIInfo "   ExposureGraph: fetching device nodes from advanced hunting (this can take 30-120s for large tenants) ..."
    $_egStart = [datetime]::UtcNow
    # through the SHARED retrying hunting request (429 / 5xx / no answer waited out, an expired token renewed)
    if (-not (Get-Command -Name Invoke-SIHuntingGraphRequest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1') }
    if (-not (Get-Command -Name New-SIGraphJsonBody -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-GraphRest.ps1') }
    $egToken = $token
    $a = Invoke-SIHuntingGraphRequest -Query $kql -Token { param([bool]$Force) $egToken }
    if (-not $a.Ok) {
        Write-Warning ('ExposureGraph: hunting query failed -- {0}' -f $a.Error)
        return @()
    }

    $rows = @($a.Rows)
    Write-SIInfo ("   ExposureGraph: received {0} device node(s) in {1:n1}s" -f $rows.Count, ([datetime]::UtcNow - $_egStart).TotalSeconds)

    foreach ($r in $rows) {
        & $buildEgNode $r
    }
}
