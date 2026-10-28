#Requires -Version 5.1
<#
    SecurityInsight -- THE RING THIS INSTALL REPORTS (framework §8.4 / §8.7): every heartbeat and run report carries it, so
    Invardia can judge the install's update level against the version approved for its ring. The SAME order the web app's
    header uses (HeaderContext.RingOf): the updater's state > the ring recorded for the install > the setting SI_UpdateRing.

    PURE, both editions (the telemetry sender ships in Community too). The two Pro database rows it reads are fetched by
    Read-SIInstallRingFacts (engine\_shared\SI-InstallRing.ps1, Pro). Rings are the framework's: 0 dev, 1 internal,
    2 early release, 3 broad. PS 5.1 and 7.
#>

function ConvertTo-SIReportedRing {
    <# PURE. A ring as the product writes it -- 0..3 (number or text), 'r0'..'r3', 'ring 1', 'prod' (= 3) -- or $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $t = ("$Value").Trim().ToLowerInvariant()
    if (-not $t) { return $null }
    if ($t -eq 'prod') { return 3 }
    $t = $t -replace '^(ring\s*|r)', ''
    $n = 0
    if (-not [int]::TryParse($t, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $null }
    if ($n -lt 0 -or $n -gt 3) { return $null }
    [int]$n
}

function Get-SIRingFromUpdateState {
    <#
        PURE. The ring in the updater's state: the compact cfg.InstallState 'UpdateState' row ({ code: { ring } }) or the
        full SI-Update-State ({ code: { lastRing, appliedRing } }). Code first, then templates -- as the header reads it.
        $null when the updater has recorded no ring.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not $o) { return $null }
    foreach ($kind in 'code', 'templates') {
        if (-not $o.PSObject.Properties[$kind] -or $null -eq $o.$kind) { continue }
        $k = $o.$kind
        foreach ($f in 'ring', 'lastRing', 'appliedRing') {
            if ($k.PSObject.Properties[$f] -and $null -ne $k.$f) { $r = ConvertTo-SIReportedRing $k.$f; if ($null -ne $r) { return $r } }
        }
    }
    $null
}

function Get-SIRingFromInstallRow {
    <# PURE. The ring in the install's recorded row (cfg.InstallState 'Ring': { "ring": 1, ... }), or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not $o -or -not $o.PSObject.Properties['ring']) { return $null }
    ConvertTo-SIReportedRing $o.ring
}

function Resolve-SIReportedRing {
    <#
        PURE. The ring an uplink report carries, and where it came from. In order:
          1. -UpdaterRing      the ring the updater resolved in THIS process (the updater's own reports;
                               the guided install passes the ring it installs with)                  source 'updater'
          2. -UpdateStateJson  the updater's recorded state (cfg.InstallState 'UpdateState')          source 'updater-state'
          3. -InstallRingJson  the ring recorded for the install (cfg.InstallState 'Ring')            source 'install'
          4. -Setting          SI_UpdateRing (the Pro database, else the configuration)              source 'setting'
          5. -CommunityRing    a Community install's ring from config\update.custom.json             source 'community'
        Returns @{ Ring (0..3 or $null); Source }. A value that is not a ring is skipped, never guessed.
    #>
    param([AllowNull()]$UpdaterRing, [AllowNull()][AllowEmptyString()][string]$UpdateStateJson, [AllowNull()][AllowEmptyString()][string]$InstallRingJson,
          [AllowNull()]$Setting, [AllowNull()]$CommunityRing)
    $r = ConvertTo-SIReportedRing $UpdaterRing
    if ($null -ne $r) { return [pscustomobject]@{ Ring = $r; Source = 'updater' } }
    $r = Get-SIRingFromUpdateState -Json $UpdateStateJson
    if ($null -ne $r) { return [pscustomobject]@{ Ring = $r; Source = 'updater-state' } }
    $r = Get-SIRingFromInstallRow -Json $InstallRingJson
    if ($null -ne $r) { return [pscustomobject]@{ Ring = $r; Source = 'install' } }
    $r = ConvertTo-SIReportedRing $Setting
    if ($null -ne $r) { return [pscustomobject]@{ Ring = $r; Source = 'setting' } }
    $r = ConvertTo-SIReportedRing $CommunityRing
    if ($null -ne $r) { return [pscustomobject]@{ Ring = $r; Source = 'community' } }
    [pscustomobject]@{ Ring = $null; Source = '' }
}
