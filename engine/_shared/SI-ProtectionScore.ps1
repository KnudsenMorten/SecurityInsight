# =====================================================================================================================
# THE PROTECTION SCORE -- ONE engine function for both editions (#636, owner 2026-10-19; the model of #1361, 2026-11-25).
#
# Owner, verbatim: "here i propose we define a new number which defines our ability to protect our assets. that is a % from
# 0-100. a higher number is good" / "i think we need to have 2 views as both are accepted by mgmt: view 1 shows the raw
# protection score where a new patch coming out yesterday impacts our score, as assets technically are vulnerable - the
# other includes our lifecycle, which are under 'accepted risks' lifecycle process" / (on the old 0-100 KPI) "replace it with
# the Protection score everywhere ... both editions, same core functionality".
# #1361 (owner 2026-11-25): "tier 0 must impact harder where tier 3 less" ("Fixed share per tier") / "it must combine
# vulnerability on the tiers weight. vulnerability must also be weighted" (points VH 25 / H 10 / M 3 / L 1, "Per fix",
# "Severity points only").
#
#   IN SCOPE     the ACTIVE CIs that can carry findings: devices, identities (groups left out), cloud resources, public IPs
#   ITEM         one open, non-exempted thing to fix on an asset in scope: a patch finding is grouped per (asset, recommended
#                update -- its id, else its name) = ONE item however many CVEs it closes, its points the highest of its
#                findings'; every other finding (configuration, identity, Azure, attack path, a CVE without a fix) = one item
#   POINTS       per SI severity (SI_ProtectionScore_SeverityPoints: Very High=25, High=10, Medium=3, Low=1; Critical is the
#                source's word for Very High) -- ONE function, Get-SIProtectionItemPoints; a severity at 0 points does not count
#   HEALTH       an asset's health = max(0, 100 - its Very High / High items' points - min(SI_ProtectionScore_MinorPointsCap,
#                default 20, its Medium / Low items' points)); an asset with no item = 100 (owner 2026-11-25: "Yes, this
#                model" -- "easy to explain, easy to impact")
#   TIER %       the average health of the tier's in-scope assets (unclassified = Tier 3)
#   SCORE        sum over the tiers of share x tier % (SI_ProtectionScore_TierShares: 40, 30, 20, 10), whatever the number of
#                assets; a tier with no asset in scope hands its share to the tiers that have assets, pro rata. Rounded 0.1.
#                A tier's own row = its tier %; an asset type's row = the same formula within that type; type x tier = the
#                average health. GOOD STANDING (the secondary "N of M assets" figure) = no open Very High / High item.
#   TECHNICAL    "Actual Risks": every item counts
#   LIFECYCLE    "within accepted lifecycle": an item counts when at least one of its findings counts -- a patch finding
#                younger than its asset type's grace (SI_ProtectionScore_GraceDays_Device | _Identity | _CloudResource |
#                _PublicIp, default 30 days) does not; any other finding has its own grace (_OtherGraceDays_*, default 0)
#   AGE          the first that is known: the fix's release (si_fix_release_date, else the 2nd Tuesday of the recommended
#                update's month), the SOURCE's own first-seen (si_source_first_seen / si_source_first_detected), SI's first
#                detection; none = the finding counts (conservative), and how many had none is told
#
# COUNTED, NOT KEPT (owner 2026-10-22: "500,000 devices / millions of findings"): per asset only its points so far and, for
# a patch item, its key with its highest points -- memory grows with the assets and their fixes, never with the CVEs.
# Community: Risk Analysis feeds the Detailed run's findings and its CI index through New- / Add- / Complete-SIProtectionTally
# (no SQL). Pro: the data sync writes the same rules as SQL per collection (Get-SIKeyFigureProtectionSql); a test holds the two
# to the same answer on one fixture. Community-safe: no Pro file, no module; PS 5.1 and 7.
# =====================================================================================================================

$script:SIProtectionTypes = [ordered]@{ device = 'Devices'; identity = 'Identities'; cloud_resource = 'Cloud resources'; public_ip = 'Public IPs' }
$script:SIProtectionGroupTypes = @('group', 'security group', 'microsoft 365 group')
$script:SIProtectionBasis = @(@(1, 'fix release'), @(2, 'source first seen'), @(3, 'SI first detected'), @(0, 'no date (counted)'))
# SI's severity scale, in the order of the points setting
# (functions, not script variables: a caller that loads this file inside a function keeps them)
function Get-SIProtectionScale { <# SI's severity scale, highest first (rank 4 .. 1). #> @('Very High', 'High', 'Medium', 'Low') }
function Get-SIProtectionDefaultPoints { <# The default points per open fix (SI_ProtectionScore_SeverityPoints). #> [ordered]@{ 'Very High' = 25; 'High' = 10; 'Medium' = 3; 'Low' = 1 } }
function Get-SIProtectionDefaultShares { <# The default tier shares, Tier 0..3 (SI_ProtectionScore_TierShares). #> , [double[]]@(40.0, 30.0, 20.0, 10.0) }

function Get-SIProtectionScoreSettings {
    <#
        PURE. The protection score's settings, from -Settings (a dictionary) or the globals: @{ Points (SI severity -> points);
        Shares (Tier 0..3); Grace / OtherGrace = @{ device; identity; cloud_resource; public_ip } }. A missing or invalid value
        = the default.
    #>
    param($Settings)
    $val = {
        param($n)
        if ($Settings -is [System.Collections.IDictionary]) { if ($Settings.Contains($n)) { return $Settings[$n] }; return $null }
        Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue
    }
    $days = {
        param($n, [int]$default = 30)
        $x = 0; $v = & $val $n
        if ($null -ne $v -and [int]::TryParse(([string]$v).Trim(), [ref]$x) -and $x -ge 0 -and $x -le 3650) { return $x }
        $default
    }
    # the tier shares: four numbers >= 0 with a sum above 0, else the default
    $w = Get-SIProtectionDefaultShares
    $raw = [string](& $val 'SI_ProtectionScore_TierShares')
    if ("$raw".Trim()) {
        $parts = @("$raw".Trim().Trim('"') -split '[,;\s]+' | Where-Object { $_ -ne '' })
        $vals = New-Object System.Collections.Generic.List[double]
        foreach ($p in $parts) { $d = 0.0; if ([double]::TryParse($p, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and $d -ge 0) { $vals.Add($d) } }
        $sum = 0.0; foreach ($x in $vals) { $sum += $x }
        if ($parts.Count -eq 4 -and $vals.Count -eq 4 -and $sum -gt 0) { $w = $vals.ToArray() }
    }
    # owner 2026-11-25: Medium and Low together cost at most this many points per asset (0 = they do not count), 0..100
    $cap = 20; $cx = 0; $cv = & $val 'SI_ProtectionScore_MinorPointsCap'
    if ($null -ne $cv -and [int]::TryParse(([string]$cv).Trim().Trim('"'), [ref]$cx) -and $cx -ge 0 -and $cx -le 100) { $cap = $cx }
    @{
        MinorCap   = $cap
        Points     = (ConvertFrom-SIProtectionPointsSetting ([string](& $val 'SI_ProtectionScore_SeverityPoints')))
        Shares     = @($w)
        Grace      = @{
            device         = (& $days 'SI_ProtectionScore_GraceDays_Device')
            identity       = (& $days 'SI_ProtectionScore_GraceDays_Identity')
            cloud_resource = (& $days 'SI_ProtectionScore_GraceDays_CloudResource')
            public_ip      = (& $days 'SI_ProtectionScore_GraceDays_PublicIp')
        }
        # #860 (owner 2026-10-21: "grace 0 for non-patch"): the grace of a finding WITHOUT a patch cycle (configuration,
        # identity, Azure, attack paths -- Test-SIProtectionPatchFinding), per asset type; default 0 = it counts from day one
        OtherGrace = @{
            device         = (& $days 'SI_ProtectionScore_OtherGraceDays_Device' 0)
            identity       = (& $days 'SI_ProtectionScore_OtherGraceDays_Identity' 0)
            cloud_resource = (& $days 'SI_ProtectionScore_OtherGraceDays_CloudResource' 0)
            public_ip      = (& $days 'SI_ProtectionScore_OtherGraceDays_PublicIp' 0)
        }
    }
}

function ConvertFrom-SIProtectionPointsSetting {
    <#
        PURE. SI_ProtectionScore_SeverityPoints ('Very High=25,High=10,Medium=3,Low=1') as an ordered map of SI severity ->
        points (whole numbers 0..100). A severity left out keeps its default; any entry that is not '<SI severity>=<number>' =
        the whole default.
    #>
    param([string]$Raw)
    $m = Get-SIProtectionDefaultPoints
    $t = "$Raw".Trim().Trim('"')
    if (-not $t) { return $m }
    $out = [ordered]@{}; foreach ($k in $m.Keys) { $out[$k] = $m[$k] }
    foreach ($e in @($t -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $kv = $e -split '=', 2
        if ($kv.Count -ne 2) { return $m }
        $name = @(Get-SIProtectionScale | Where-Object { $_ -eq $kv[0].Trim() })   # -eq: case-insensitive
        $n = 0
        if ($name.Count -ne 1 -or -not [int]::TryParse($kv[1].Trim(), [ref]$n) -or $n -lt 0 -or $n -gt 100) { return $m }
        $out[$name[0]] = $n
    }
    $out
}

function ConvertTo-SIProtectionSeverity {
    <# PURE. A finding's severity on SI's scale (Very High | High | Medium | Low), $null when it is none of them: Critical is the source's word for Very High, Medium-High counts as High. #>
    param([string]$Severity)
    $s = "$Severity".Trim().ToLowerInvariant()
    switch ($s) {
        'very high' { return 'Very High' } 'critical' { return 'Very High' }
        'high' { return 'High' } 'medium-high' { return 'High' } 'mediumhigh' { return 'High' }
        'medium' { return 'Medium' } 'low' { return 'Low' }
    }
    $null
}

function Get-SIProtectionItemPoints {
    <#
        PURE. THE ONE PLACE an item's points come from (owner 2026-11-25: "Severity points only"): the points of its SI
        severity (-Points: Get-SIProtectionScoreSettings' Points). 0 = it does not count. The Pro SQL's twin is the CASE
        Get-SIProtectionPointsSql writes from the same map.
    #>
    param([string]$Severity, [Parameter(Mandatory)]$Points)
    $s = ConvertTo-SIProtectionSeverity $Severity
    if ($null -eq $s) { return 0 }
    [int]$Points[$s]
}

function Test-SIProtectionPatchFinding {
    <#
        PURE. #860: whether a finding has a PATCH CYCLE -- a vulnerability with a vendor fix -- and so gets the accepted-lifecycle
        grace (SI_ProtectionScore_GraceDays_*). The same test as the Pro SQL (Get-SIKeyFigureProtectionSql): the finding names
        its fix -- a fix release date (si_fix_release_date), a recommended update (its name or its id), or a patch cycle a
        source gave that is a cycle (In monthly cycle / Catch-up). Anything else -- a configuration, an identity or Azure
        finding, an attack path, a CVE with no fix -- is not a patch: its grace is SI_ProtectionScore_OtherGraceDays_* (0).
    #>
    param($FixRelease, [string]$UpdateName, [string]$UpdateId, [string]$PatchCycle)
    if ($null -ne (ConvertTo-SIProtectionDate $FixRelease)) { return $true }
    if ("$UpdateName".Trim() -or "$UpdateId".Trim()) { return $true }
    $c = "$PatchCycle".Trim().ToLowerInvariant()
    $c.StartsWith('in monthly') -or $c.StartsWith('catch')
}

function ConvertTo-SIProtectionDate {
    <# PURE. A date a row carries (datetime, ISO text, $null / blank / DBNull) as a UTC datetime, $null when none. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = ([string]$Value).Trim()
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    $null
}

function New-SIProtectionTally {
    <# The tally of one run / collection: -CollectionTime is "now" for the ages; -Settings as Get-SIProtectionScoreSettings reads them. #>
    param([datetime]$CollectionTime = [datetime]::UtcNow, $Settings)
    $cfg = Get-SIProtectionScoreSettings -Settings $Settings
    # the counted findings are COUNTED, never kept (owner 2026-10-22: "500,000 devices / millions of findings"): per age basis
    # (0..3) the number of findings and the distinct CIs -- memory grows with the assets, not with the findings
    $basisCis = @{}; foreach ($b in 0..3) { $basisCis[$b] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal) }
    [pscustomobject]@{
        CollectionTime = $CollectionTime
        Settings       = $cfg
        Assets         = @{}       # CI id (lower) -> @{ Type; Tier; B; TechP; LifeP; TechHi; LifeHi; Fixes }
        BasisCount     = @{ 0 = 0L; 1 = 0L; 2 = 0L; 3 = 0L }
        BasisCis       = $basisCis
    }
}

function Add-SIProtectionAsset {
    <#
        One CI of the inventory. Out of scope (not added): inactive, a class without findings of its own, a group.
        -Tier 0..3 or $null (unclassified = Tier 3's share).
    #>
    param([Parameter(Mandatory)]$Tally, [string]$Id, [string]$Class, [string]$AssetType, $Tier, [bool]$Active = $true)
    if (-not $Id -or -not $Active) { return }
    $c = "$Class".Trim().ToLowerInvariant()
    if (-not $script:SIProtectionTypes.Contains($c)) { return }
    if ($script:SIProtectionGroupTypes -contains "$AssetType".Trim().ToLowerInvariant()) { return }
    $t = $null; $ti = 0
    if ($null -ne $Tier -and -not ($Tier -is [System.DBNull]) -and [int]::TryParse(([string]$Tier).Trim(), [ref]$ti) -and $ti -ge 0 -and $ti -le 3) { $t = $ti }
    # B = the tier whose share the asset counts in (unclassified = Tier 3); Tech/Life Major/Minor = the points of the items
    # that are not a fix (one each), per view; Fixes = per recommended update its highest severity rank and whether it counts
    # in the lifecycle view (created on the asset's first fix only)
    $Tally.Assets[$Id.Trim().ToLowerInvariant()] = @{ Class = $c; Type = $script:SIProtectionTypes[$c]; Tier = $(if ($null -eq $t) { 'Unclassified' } else { 'Tier ' + $t })
        B = $(if ($null -eq $t) { 3 } else { [int]$t }); TechMajor = 0; TechMinor = 0; LifeMajor = 0; LifeMinor = 0; TechHi = $false; LifeHi = $false; Fixes = $null }
}

function Get-SIProtectionAge {
    <#
        PURE. The age basis of one finding: @{ Basis = 1 fix release | 2 source first seen | 3 SI first detected | 0 none; Date }.
        -FixRelease wins; else the 2nd Tuesday of -UpdateName's month; then -SourceFirstSeen; then -FirstDetected.
    #>
    param($FixRelease, [string]$UpdateName, $SourceFirstSeen, $FirstDetected)
    $d = ConvertTo-SIProtectionDate $FixRelease
    if ($null -eq $d -and $UpdateName) {
        if (-not (Test-Path -Path 'function:Get-SIPatchCycleMonth')) { . (Join-Path $PSScriptRoot 'SI-PatchCycle.ps1') }
        $m = Get-SIPatchCycleMonth -UpdateName $UpdateName
        if ($null -ne $m) { $d = Get-SIPatchCycleRelease -Month $m }
    }
    if ($null -ne $d) { return @{ Basis = 1; Date = $d } }
    $d = ConvertTo-SIProtectionDate $SourceFirstSeen
    if ($null -ne $d) { return @{ Basis = 2; Date = $d } }
    $d = ConvertTo-SIProtectionDate $FirstDetected
    if ($null -ne $d) { return @{ Basis = 3; Date = $d } }
    @{ Basis = 0; Date = $null }
}

function Add-SIProtectionFinding {
    <#
        One open finding. Not counted: a severity at 0 points (Get-SIProtectionItemPoints), an exempted one, one on a CI that is
        not in scope (call Add-SIProtectionAsset for the inventory first). A PATCH finding with a recommended update (its id,
        else its name) joins that fix's ONE item on the asset (its points = the highest); any other finding is its own item.
        The age decides whether it counts in the lifecycle view; a fix counts there when one of its findings does.
    #>
    param([Parameter(Mandatory)]$Tally, [string]$CiId, [string]$Severity, [bool]$Exempted = $false,
          $FixRelease, [string]$UpdateName, $SourceFirstSeen, $FirstDetected, [string]$UpdateId, [string]$PatchCycle)
    if ($Exempted -or -not $CiId) { return }
    $pts = Get-SIProtectionItemPoints -Severity $Severity -Points $Tally.Settings.Points
    if ($pts -le 0) { return }
    $a = $Tally.Assets[$CiId.Trim().ToLowerInvariant()]
    if ($null -eq $a) { return }
    $age = Get-SIProtectionAge -FixRelease $FixRelease -UpdateName $UpdateName -SourceFirstSeen $SourceFirstSeen -FirstDetected $FirstDetected
    $patch = Test-SIProtectionPatchFinding -FixRelease $FixRelease -UpdateName $UpdateName -UpdateId $UpdateId -PatchCycle $PatchCycle
    $b = [int]$age.Basis
    $Tally.BasisCount[$b] = [long]$Tally.BasisCount[$b] + 1
    [void]$Tally.BasisCis[$b].Add($CiId.Trim().ToLowerInvariant())
    # #860: only a patch finding gets the accepted-lifecycle grace; every other finding has its own (default 0)
    $grace = $(if ($patch) { [int]$Tally.Settings.Grace[$a.Class] } else { [int]$Tally.Settings.OtherGrace[$a.Class] })
    $life = ($null -eq $age.Date -or ($Tally.CollectionTime.Date - $age.Date.Date).Days -ge $grace)
    # R = the severity's rank on SI's scale (Very High 4 .. Low 1): a fix's severity is the highest of its findings
    $r = 4 - [array]::IndexOf([string[]](Get-SIProtectionScale), [string](ConvertTo-SIProtectionSeverity $Severity))
    $key = $(if ("$UpdateId".Trim()) { "$UpdateId".Trim().ToLowerInvariant() } elseif ("$UpdateName".Trim()) { "$UpdateName".Trim().ToLowerInvariant() } else { '' })
    if (-not $key) { Add-SIProtectionItem -Asset $a -Rank $r -Points $pts -Life $life; return }
    if ($null -eq $a.Fixes) { $a.Fixes = @{} }
    $f = $a.Fixes[$key]
    if ($null -eq $f) { $a.Fixes[$key] = @{ R = $r; Life = $life }; return }
    if ($r -gt $f.R) { $f.R = $r }
    if ($life) { $f.Life = $true }
}

function Add-SIProtectionItem {
    <#
        One item's points on its asset, per view: Very High / High = major (and out of good standing), Medium / Low = minor
        (capped together per asset at Complete-SIProtectionTally: SI_ProtectionScore_MinorPointsCap).
    #>
    param([Parameter(Mandatory)]$Asset, [int]$Rank, [int]$Points, [bool]$Life)
    if ($Points -le 0) { return }
    if ($Rank -ge 3) { $Asset.TechMajor += $Points; $Asset.TechHi = $true; if ($Life) { $Asset.LifeMajor += $Points; $Asset.LifeHi = $true } }
    else { $Asset.TechMinor += $Points; if ($Life) { $Asset.LifeMinor += $Points } }
}

function Get-SIProtectionHealth {
    <# PURE. An asset's health: max(0, 100 - its major points - min(the minor cap, its minor points)). The SQL twin: #pc in Get-SIKeyFigureProtectionSql. #>
    param([int]$Major, [int]$Minor, [int]$MinorCap)
    [double][Math]::Max(0, 100 - $Major - [Math]::Min($MinorCap, $Minor))
}

function Add-SIProtectionRow {
    <#
        One Risk Analysis finding row (both editions read the same row): the CI (si_ci_id), the severity, the exemption,
        the fix's release / the update's name, the source's first-seen, SI's first detection.
    #>
    param([Parameter(Mandatory)]$Tally, $Row)
    if ($null -eq $Row) { return }
    $g = {
        param([string[]]$names)
        foreach ($n in $names) {
            $v = $null
            if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n] } }
            elseif ($Row.PSObject.Properties[$n]) { $v = $Row.$n }
            if ($null -ne $v -and -not ($v -is [System.DBNull]) -and "$v".Trim()) { return $v }
        }
        $null
    }
    Add-SIProtectionFinding -Tally $Tally -CiId ([string](& $g @('si_ci_id'))) -Severity ([string](& $g @('si_severity', 'SecuritySeverity', 'Severity'))) `
        -Exempted ([bool](& $g @('SI_ExemptionId', 'si_exemption_id'))) -FixRelease (& $g @('si_fix_release_date')) `
        -UpdateName ([string](& $g @('si_fix_recommended_update', 'RecommendedSecurityUpdate'))) `
        -UpdateId ([string](& $g @('si_fix_recommended_update_id', 'RecommendedSecurityUpdateId'))) -PatchCycle ([string](& $g @('si_patch_cycle'))) `
        -SourceFirstSeen (& $g @('si_source_first_seen', 'si_source_first_detected')) -FirstDetected (& $g @('si_first_detected', 'FirstDetected'))
}

function Get-SIProtectionShareScore {
    <#
        PURE. #1361: the score over tiers -- sum of share x the tier's average health, over the tiers (0..3) that have assets
        (their shares scaled to 100). -N / -Sum: per tier the assets and the sum of their health. $null when no asset; the
        plain average when every tier present has a share of 0. Not rounded. The SQL twin: the share UPDATE of
        Get-SIKeyFigureProtectionSql.
    #>
    param([Parameter(Mandatory)][double[]]$Shares, [Parameter(Mandatory)][long[]]$N, [Parameter(Mandatory)][double[]]$Sum)
    $num = 0.0; $den = 0.0; $all = 0L; $allSum = 0.0
    foreach ($b in 0..3) {
        if ($N[$b] -le 0) { continue }
        $all += $N[$b]; $allSum += $Sum[$b]
        $num += $Shares[$b] * ($Sum[$b] / $N[$b]); $den += $Shares[$b]
    }
    if ($all -le 0) { return $null }
    if ($den -le 0) { return $allSum / $all }
    $num / $den
}

function Complete-SIProtectionTally {
    <#
        PURE over the tally. The protection score in the shape the Pro key figures store it: Rows of
        @{ Figure = technical | lifecycle | agebasis; Dim1 = asset type | (all) | age basis; Dim2 = tier | (all) | ''; Value; Assets; Total },
        plus Technical / Lifecycle (the score, $null when no asset is in scope), the assets in good standing per view (no open
        Very High / High item), Assets (in scope), NoDate, Findings. Value: a tier's cell (or type x tier) = the average
        health of its assets; a cell over every tier ((all), an asset type) = the tier-share score.
    #>
    param([Parameter(Mandatory)]$Tally)
    # ONE pass over the assets (never a pass per group): each asset's health in each view, added to its four cells -- (all) x
    # (all), its type, its tier, its type x tier -- per share tier (B)
    $cells = @{}
    $cap = [int]$Tally.Settings.MinorCap
    foreach ($a in $Tally.Assets.Values) {
        if ($null -ne $a.Fixes) {
            # each fix once, at its highest severity's points (the asset's items are final here; Complete runs once)
            foreach ($f in $a.Fixes.Values) { Add-SIProtectionItem -Asset $a -Rank $f.R -Points (Get-SIProtectionItemPoints -Severity (Get-SIProtectionScale)[4 - $f.R] -Points $Tally.Settings.Points) -Life $f.Life }
            $a.Fixes = $null
        }
        $th = [bool]$a.TechHi; $lh = [bool]$a.LifeHi
        $ht = Get-SIProtectionHealth -Major $a.TechMajor -Minor $a.TechMinor -MinorCap $cap
        $hl = Get-SIProtectionHealth -Major $a.LifeMajor -Minor $a.LifeMinor -MinorCap $cap
        foreach ($k in @(@('(all)', '(all)'), @($a.Type, '(all)'), @('(all)', $a.Tier), @($a.Type, $a.Tier))) {
            $key = $k[0] + '|' + $k[1]
            $c = $cells[$key]
            if ($null -eq $c) {
                $c = @{ D1 = $k[0]; D2 = $k[1]; N = 0; TechGood = 0; LifeGood = 0; BN = [long[]]@(0, 0, 0, 0); BTech = [double[]]@(0, 0, 0, 0); BLife = [double[]]@(0, 0, 0, 0) }
                $cells[$key] = $c
            }
            $c.N++; $c.BN[$a.B]++; $c.BTech[$a.B] += $ht; $c.BLife[$a.B] += $hl
            if (-not $th) { $c.TechGood++ }
            if (-not $lh) { $c.LifeGood++ }
        }
    }
    $shares = [double[]]@($Tally.Settings.Shares)
    $round = { param($x) if ($null -eq $x) { $null } else { [Math]::Round([double]$x, 1, [MidpointRounding]::AwayFromZero) } }
    $valueOf = {
        param($c, $view)
        $sum = $(if ($view -eq 'technical') { $c.BTech } else { $c.BLife })
        if ($c.D2 -ne '(all)') { $t = 0.0; foreach ($x in $sum) { $t += $x }; return (& $round ($t / $c.N)) }
        & $round (Get-SIProtectionShareScore -Shares $shares -N $c.BN -Sum $sum)
    }
    # the order of the rows: (all) first, then each type, each tier, each type x tier
    $rank = { param($c) if ($c.D1 -eq '(all)' -and $c.D2 -eq '(all)') { 0 } elseif ($c.D2 -eq '(all)') { 1 } elseif ($c.D1 -eq '(all)') { 2 } else { 3 } }
    $ordered = @($cells.Values | Sort-Object @{ Expression = { & $rank $_ } }, @{ Expression = { $_.D1 } }, @{ Expression = { $_.D2 } })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($view in 'technical', 'lifecycle') {
        foreach ($c in $ordered) {
            $good = $(if ($view -eq 'technical') { $c.TechGood } else { $c.LifeGood })
            $rows.Add([pscustomobject]@{ Figure = $view; Dim1 = $c.D1; Dim2 = $c.D2; Value = (& $valueOf $c $view); Assets = $good; Total = $c.N })
        }
    }
    $counted = [long]0; foreach ($b in 0..3) { $counted += [long]$Tally.BasisCount[$b] }
    foreach ($pair in $script:SIProtectionBasis) {
        $b = [int]$pair[0]
        $rows.Add([pscustomobject]@{ Figure = 'agebasis'; Dim1 = [string]$pair[1]; Dim2 = ''; Value = [double]$Tally.BasisCount[$b]; Assets = $Tally.BasisCis[$b].Count; Total = $counted })
    }
    $all = $cells['(all)|(all)']
    $tech = $null; $life = $null; $techN = 0; $lifeN = 0; $n = 0
    if ($null -ne $all) { $tech = & $valueOf $all 'technical'; $life = & $valueOf $all 'lifecycle'; $techN = $all.TechGood; $lifeN = $all.LifeGood; $n = $all.N }
    [pscustomobject]@{
        Technical = $tech; TechnicalGood = $techN
        Lifecycle = $life; LifecycleGood = $lifeN
        Assets    = $n
        NoDate    = [long]$Tally.BasisCount[0]
        Findings  = $counted
        Grace     = $Tally.Settings.Grace
        Shares    = $Tally.Settings.Shares
        Points    = $Tally.Settings.Points
        MinorCap  = $Tally.Settings.MinorCap
        Rows      = $rows.ToArray()
        Source    = 'tally'
    }
}

function ConvertFrom-SIProtectionKeyFigures {
    <#
        PURE. THE STORED PROTECTION SCORE of one collection (Pro: sidata.KeyFigure, written by the data sync -- the numbers the web
        app shows) in the shape Complete-SIProtectionTally answers, so the mail renders it with the SAME code and never computes a
        score of its own (owner 2026-10-22: "one computation, never two that can differ"). -Rows: the collection's KeyFigure rows
        of Block 'protection' (technical | lifecycle | agebasis) and Block 'headline' (protection_technical | protection_lifecycle),
        as objects or dictionaries. Answers $null when the collection has no stored score yet; a stored score that is not
        available (Available = 0) answers Lifecycle = $null and its Note -- the one plain reason the data sync stored.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), $Settings)
    $v = {
        param($r, [string]$n)
        $x = $null
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $x = $r[$n] } } elseif ($null -ne $r -and $r.PSObject.Properties[$n]) { $x = $r.$n }
        if ($x -is [System.DBNull]) { $null } else { $x }
    }
    $rs = @($Rows | Where-Object { $null -ne $_ })
    $head = { param($fig) @($rs | Where-Object { [string](& $v $_ 'Block') -eq 'headline' -and [string](& $v $_ 'Figure') -eq $fig }) | Select-Object -First 1 }
    $hl = & $head 'protection_lifecycle'; $ht = & $head 'protection_technical'
    if ($null -eq $hl -or $null -eq $ht) { return $null }
    $cfg = Get-SIProtectionScoreSettings -Settings $Settings
    $num = { param($x) if ($null -eq $x -or "$x" -eq '') { $null } else { [double]$x } }
    $int = { param($x) if ($null -eq $x -or "$x" -eq '') { 0 } else { [long]$x } }
    $available = [bool](& $v $hl 'Available') -and $null -ne (& $v $hl 'Value')
    $prot = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rs) {
        if ([string](& $v $r 'Block') -ne 'protection') { continue }
        $f = [string](& $v $r 'Figure'); if ($f -notin 'technical', 'lifecycle', 'agebasis') { continue }
        $prot.Add([pscustomobject]@{ Figure = $f; Dim1 = [string](& $v $r 'Dim1'); Dim2 = [string](& $v $r 'Dim2'); Value = (& $num (& $v $r 'Value')); Assets = (& $int (& $v $r 'Assets')); Total = (& $int (& $v $r 'Total')) })
    }
    $basis = @($prot | Where-Object { $_.Figure -eq 'agebasis' })
    $noDate = @($basis | Where-Object { $_.Dim1 -eq 'no date (counted)' } | Select-Object -First 1)
    [pscustomobject]@{
        Technical = $(if ($available) { & $num (& $v $ht 'Value') } else { $null }); TechnicalGood = (& $int (& $v $ht 'Assets'))
        Lifecycle = $(if ($available) { & $num (& $v $hl 'Value') } else { $null }); LifecycleGood = (& $int (& $v $hl 'Assets'))
        Assets    = (& $int (& $v $hl 'Total'))
        NoDate    = $(if ($noDate.Count) { [long]$noDate[0].Value } else { 0 })
        Findings  = $(if ($basis.Count) { [long]$basis[0].Total } else { 0 })
        Grace     = $cfg.Grace
        Shares    = $cfg.Shares
        Points    = $cfg.Points
        MinorCap  = $cfg.MinorCap
        Rows      = $prot.ToArray()
        Source    = 'stored'
        Note      = $(if ($available) { $null } else { $n = [string](& $v $hl 'Note'); if ($n.Trim()) { $n.Trim() } else { 'the stored figures of this run have no score' } })
    }
}

function Get-SIProtectionBands {
    <#
        The Protection Score's bands, highest first: data-model\protection-score-bands.locked.json -- the ONE definition the web
        app embeds a copy of (a test keeps the two equal). A missing or unreadable file = the same four bands built in.
    #>
    if ($script:SIProtectionBandsCache) { return $script:SIProtectionBandsCache }
    $bands = $null
    try {
        $f = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'protection-score-bands.locked.json')
        if (Test-Path -LiteralPath $f) { $bands = @((Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).bands | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Min = [double]$_.min; Tone = [string]$_.tone; Ink = [string]$_.ink } }) }
    } catch { $bands = $null }
    if (-not $bands -or $bands.Count -eq 0) {
        $bands = @([pscustomobject]@{ Name = 'Very Good'; Min = 90; Tone = 'very-good'; Ink = '#1b5e20' }, [pscustomobject]@{ Name = 'Good'; Min = 75; Tone = 'good'; Ink = '#2e7d32' },
                   [pscustomobject]@{ Name = 'Moderate'; Min = 50; Tone = 'moderate'; Ink = '#a14a00' }, [pscustomobject]@{ Name = 'At Risk'; Min = 0; Tone = 'at-risk'; Ink = '#c62828' })
    }
    $script:SIProtectionBandsCache = @($bands | Sort-Object Min -Descending)
    $script:SIProtectionBandsCache
}

function Get-SIProtectionBand {
    <# PURE (after the one read). The band of a 0-100 score: @{ Name; Tone; Ink (the mail colour) }; $null score = Unknown. #>
    param($Score)
    $unknown = [pscustomobject]@{ Name = 'Unknown'; Tone = 'unknown'; Ink = '#546e7a' }
    if ($null -eq $Score -or "$Score" -eq '') { return $unknown }
    $s = [double]$Score
    foreach ($b in (Get-SIProtectionBands)) {
        if ($s -ge $b.Min) {
            $ink = '#333333'
            if ($b.Ink) { $ink = $b.Ink }
            return [pscustomobject]@{ Name = $b.Name; Tone = $b.Tone; Ink = $ink }
        }
    }
    $unknown
}

function Get-SIProtectionModelWords {
    <#
        PURE. #1361: the score's rule in one sentence, with the values in force (the defaults when -Points / -Shares are not
        given): "The average health of the active assets (100 less 25 per open Very High fix, 10 per High, 3 per Medium, 1 per
        Low), each tier a fixed share: Tier 0 40 %, Tier 1 30 %, Tier 2 20 %, Tier 3 10 %".
    #>
    param($Points, $Shares, $MinorCap)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $p = $(if ($null -ne $Points) { $Points } else { Get-SIProtectionDefaultPoints })
    $s = @($(if ($null -ne $Shares -and @($Shares).Count -eq 4) { $Shares } else { Get-SIProtectionDefaultShares }))
    $pv = { param($k) if ($p -is [System.Collections.IDictionary]) { if ($p.Contains($k)) { return $p[$k] } } elseif ($p.PSObject.Properties[$k]) { return $p.$k }; (Get-SIProtectionDefaultPoints)[$k] }
    $pw = [string]::Format($inv, '100 less {0} per open Very High fix, {1} per High, {2} per Medium, {3} per Low; Medium and Low together at most {4}', [int](& $pv 'Very High'), [int](& $pv 'High'), [int](& $pv 'Medium'), [int](& $pv 'Low'), $(if ($null -ne $MinorCap -and "$MinorCap" -ne '') { [int]$MinorCap } else { 20 }))
    $sw = (0..3 | ForEach-Object { [string]::Format($inv, 'Tier {0} {1:0.##} %', $_, [double]$s[$_]) }) -join ', '
    "The average health of the active assets ($pw), each tier a fixed share: $sw"
}

function ConvertTo-SIProtectionMailHtml {
    <#
        PURE. The protection score as mail lines (the Risk Analysis mail; Community too): both views, the accepted lifecycle
        first, and how many findings had no date. -Score: Complete-SIProtectionTally's or ConvertFrom-SIProtectionKeyFigures's
        answer; without a score, ONE plain line says why (-Reason, else the score's own Note).
    #>
    param($Score, [string]$Reason)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Score -or $null -eq $Score.Lifecycle) {
        return ('<p data-mail-protection="none" style="margin:0 0 12px 0;"><strong>Protection Score:</strong> {0}</p>' -f [System.Net.WebUtility]::HtmlEncode((Get-SIProtectionNoScoreText -Score $Score -Reason $Reason)))
    }
    $graceVals = @($Score.Grace.Values | Sort-Object -Unique)
    $grace = $(if ($graceVals.Count -eq 1) { [string]::Format($inv, '{0} days', $graceVals[0]) } else { [string]::Format($inv, 'devices {0}, identities {1}, cloud resources {2}, public IPs {3} days', $Score.Grace.device, $Score.Grace.identity, $Score.Grace.cloud_resource, $Score.Grace.public_ip) })
    $sb = New-Object System.Text.StringBuilder
    $bl = Get-SIProtectionBand -Score $Score.Lifecycle; $bt = Get-SIProtectionBand -Score $Score.Technical
    [void]$sb.Append('<div data-mail-protection="1" style="margin:0 0 12px 0;">')
    # owner 2026-10-20: the two names, and each value in its band's words and colour (protection-score-bands.locked.json)
    [void]$sb.Append([string]::Format($inv, '<p style="margin:0 0 4px 0;"><strong>Protection Score, within Accepted Lifecycle:</strong> <span data-band="{5}" style="color:{4};font-weight:700;">{0:0.0} % &middot; {3}</span> ({1:N0} of {2:N0} assets in good standing)</p>', $Score.Lifecycle, $Score.LifecycleGood, $Score.Assets, $bl.Name, $bl.Ink, $bl.Tone))
    [void]$sb.Append([string]::Format($inv, '<p style="margin:0 0 4px 0;"><strong>Protection Score, Actual Risks:</strong> <span data-band="{5}" style="color:{4};font-weight:700;">{0:0.0} % &middot; {3}</span> ({1:N0} of {2:N0})</p>', $Score.Technical, $Score.TechnicalGood, $Score.Assets, $bt.Name, $bt.Ink, $bt.Tone))
    [void]$sb.Append([string]::Format($inv, '<p style="margin:0;font-size:12px;color:#5a6a7a;">Higher is better. {3}. Good standing = no open Very High / High fix. Accepted lifecycle: {0}. {1:N0} of {2:N0} counted findings had no usable date and count as open.</p>', $grace, $Score.NoDate, $Score.Findings, [System.Net.WebUtility]::HtmlEncode((Get-SIProtectionModelWords -Points $Score.Points -Shares $Score.Shares -MinorCap $Score.MinorCap))))
    [void]$sb.Append('</div>')
    $sb.ToString()
}

# THE REASONS a mail has no score -- one plain sentence each (owner 2026-10-22: "the mail must say WHY in one plain line, never a misleading
# line that the score comes later"). The mail prints "Protection Score: not shown for this run -- <reason>."
$script:SIProtectionReasons = [ordered]@{
    'no-cis'        = 'no CIs are stored yet, so no asset is in scope (the CIs are built from the collected data before Risk Analysis runs)'
    'no-scope'      = 'no active asset is in scope (devices, identities, cloud resources and public IPs; groups are left out)'
    'summary'       = 'it is in the Detailed report, which counts the findings of every asset'
    'not-figured'   = 'the data sync has not computed this run''s figures; the web app''s Executive overview shows the last computed score'
    'figures-failed'= 'the data sync could not compute this run''s figures; the web app''s Executive overview shows the last computed score'
    'not-taken-in'  = 'the data sync did not take this run''s results in, so no score was computed for it'
    'no-wait'       = 'it is computed by the data sync after this run, and this mail could not wait for it; the web app''s Executive overview shows it once computed'
    # review B1 / S1 (2026-10-22)
    'mail-not-ready'= 'the protection score is shown in SecurityInsight'
    'not-computed'  = 'not computed for this run'
}

function Get-SIProtectionReason {
    <# PURE. One reason sentence by its code (see above), with an optional detail in brackets ("... (the error)"). #>
    param([Parameter(Mandatory)][string]$Code, [string]$Detail)
    $t = [string]$script:SIProtectionReasons[$Code]
    if (-not $t) { $t = $Code }
    if ("$Detail".Trim()) { $t = $(if ($Code -eq 'not-computed') { '{0} -- {1}' } else { '{0} ({1})' }) -f $t, "$Detail".Trim().TrimEnd('.') }
    $t
}

function Get-SIProtectionNoScoreText {
    <# PURE. The text after "Protection Score:" when there is no score: -Reason, else the stored score's Note, else a plain default. #>
    param($Score, [string]$Reason)
    $why = "$Reason".Trim()
    if (-not $why -and $null -ne $Score -and $Score.PSObject.Properties['Note'] -and "$($Score.Note)".Trim()) { $why = "$($Score.Note)".Trim() }
    if (-not $why -and $null -ne $Score -and [long]$Score.Assets -eq 0) { $why = Get-SIProtectionReason 'no-scope' }
    if (-not $why) { $why = 'no score was computed for this run' }
    # review S1: 'not computed for this run -- <reason>' is said as it is
    if ($why.StartsWith('not computed for this run')) { return ($why.TrimEnd('.') + '.') }
    'not shown for this run -- ' + $why.TrimEnd('.') + '.'
}
