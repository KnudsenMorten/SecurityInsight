# =====================================================================================================================
# THE PROTECTION SCORE -- ONE engine function for both editions (#636, owner 2026-10-19).
#
# Owner, verbatim: "here i propose we define a new number which defines our ability to protect our assets. that is a % from
# 0-100. a higher number is good" / "i think we need to have 2 views as both are accepted by mgmt: view 1 shows the raw
# protection score where a new patch coming out yesterday impacts our score, as assets technically are vulnerable - the
# other includes our lifecycle, which are under 'accepted risks' lifecycle process" / (on the old 0-100 KPI) "replace it with
# the Protection score everywhere ... both editions, same core functionality".
#
#   IN SCOPE     the ACTIVE CIs that can carry findings: devices, identities (groups left out), cloud resources, public IPs
#   GOOD         no open, non-exempted finding of a counted severity (SI_ProtectionScore_Severities: Very High, Critical, High)
#   WEIGHT       the CI's tier (SI_ProtectionScore_TierWeights: 8, 4, 2, 1; unclassified = Tier 3)
#   TECHNICAL    every such finding counts
#   LIFECYCLE    "within accepted lifecycle": a finding younger than its asset type's grace does not count
#                (SI_ProtectionScore_GraceDays_Device | _Identity | _CloudResource | _PublicIp, default 30 days)
#   AGE          the first that is known: the fix's release (si_fix_release_date, else the 2nd Tuesday of the recommended
#                update's month), the SOURCE's own first-seen (si_source_first_seen / si_source_first_detected), SI's first
#                detection; none = the finding counts (conservative), and how many had none is told
#
# Community: Risk Analysis feeds the Detailed run's findings and its CI index through New- / Add- / Complete-SIProtectionTally
# (no SQL). Pro: the data sync writes the same rules as SQL per collection (Get-SIKeyFigureProtectionSql); a test holds the two
# to the same answer on one fixture. Community-safe: no Pro file, no module; PS 5.1 and 7.
# =====================================================================================================================

$script:SIProtectionTypes = [ordered]@{ device = 'Devices'; identity = 'Identities'; cloud_resource = 'Cloud resources'; public_ip = 'Public IPs' }
$script:SIProtectionGroupTypes = @('group', 'security group', 'microsoft 365 group')
$script:SIProtectionBasis = @(@(1, 'fix release'), @(2, 'source first seen'), @(3, 'SI first detected'), @(0, 'no date (counted)'))

function Get-SIProtectionScoreSettings {
    <#
        PURE. The protection score's settings, from -Settings (a dictionary) or the globals: @{ Severities; Weights (Tier 0..3);
        Grace = @{ device; identity; cloud_resource; public_ip } }. A missing or invalid value = the default.
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
    $w = @(8.0, 4.0, 2.0, 1.0)
    $raw = [string](& $val 'SI_ProtectionScore_TierWeights')
    if ($raw) {
        $parts = @($raw -split '[,;\s]+' | Where-Object { $_ -ne '' })
        $vals = New-Object System.Collections.Generic.List[double]
        foreach ($p in $parts) { $d = 0.0; if ([double]::TryParse($p, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and $d -ge 0) { $vals.Add($d) } }
        if ($parts.Count -eq 4 -and $vals.Count -eq 4) { $w = $vals.ToArray() }
    }
    $sev = @('Very High', 'Critical', 'High')
    $rawSev = [string](& $val 'SI_ProtectionScore_Severities')
    if ($rawSev) { $s = @($rawSev -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); if ($s.Count -gt 0) { $sev = $s } }
    @{
        Severities = $sev
        Weights    = $w
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
    $sevSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $cfg.Severities) { [void]$sevSet.Add([string]$s) }
    # the counted findings are COUNTED, never kept (owner 2026-10-22: "500,000 devices / millions of findings"): per age basis
    # (0..3) the number of findings and the distinct CIs -- memory grows with the assets, not with the findings
    $basisCis = @{}; foreach ($b in 0..3) { $basisCis[$b] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal) }
    [pscustomobject]@{
        CollectionTime = $CollectionTime
        Settings       = $cfg
        SevSet         = $sevSet
        Assets         = @{}       # CI id (lower) -> @{ Type; Tier; W; Tech; Life }
        BasisCount     = @{ 0 = 0L; 1 = 0L; 2 = 0L; 3 = 0L }
        BasisCis       = $basisCis
    }
}

function Add-SIProtectionAsset {
    <#
        One CI of the inventory. Out of scope (not added): inactive, a class without findings of its own, a group.
        -Tier 0..3 or $null (unclassified = Tier 3's weight).
    #>
    param([Parameter(Mandatory)]$Tally, [string]$Id, [string]$Class, [string]$AssetType, $Tier, [bool]$Active = $true)
    if (-not $Id -or -not $Active) { return }
    $c = "$Class".Trim().ToLowerInvariant()
    if (-not $script:SIProtectionTypes.Contains($c)) { return }
    if ($script:SIProtectionGroupTypes -contains "$AssetType".Trim().ToLowerInvariant()) { return }
    $t = $null; $ti = 0
    if ($null -ne $Tier -and -not ($Tier -is [System.DBNull]) -and [int]::TryParse(([string]$Tier).Trim(), [ref]$ti) -and $ti -ge 0 -and $ti -le 3) { $t = $ti }
    $w = $Tally.Settings.Weights[$(if ($null -eq $t) { 3 } else { $t })]
    $Tally.Assets[$Id.Trim().ToLowerInvariant()] = @{ Class = $c; Type = $script:SIProtectionTypes[$c]; Tier = $(if ($null -eq $t) { 'Unclassified' } else { 'Tier ' + $t }); W = [double]$w; Tech = $false; Life = $false }
}

function Get-SIProtectionAge {
    <#
        PURE. The age basis of one finding: @{ Basis = 1 fix release | 2 source first seen | 3 SI first detected | 0 none; Date }.
        -FixRelease wins; else the 2nd Tuesday of -UpdateName's month; then -SourceFirstSeen; then -FirstDetected.
    #>
    param($FixRelease, [string]$UpdateName, $SourceFirstSeen, $FirstDetected)
    $d = ConvertTo-SIProtectionDate $FixRelease
    if ($null -eq $d -and $UpdateName) {
        if (-not (Get-Command -Name Get-SIPatchCycleMonth -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-PatchCycle.ps1') }
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
        One open finding. Not counted: a severity the settings do not count, an exempted one, one on a CI that is not in scope
        (call Add-SIProtectionAsset for the inventory first). The age decides the lifecycle view.
    #>
    param([Parameter(Mandatory)]$Tally, [string]$CiId, [string]$Severity, [bool]$Exempted = $false,
          $FixRelease, [string]$UpdateName, $SourceFirstSeen, $FirstDetected, [string]$UpdateId, [string]$PatchCycle)
    if ($Exempted -or -not $CiId) { return }
    if (-not $Tally.SevSet.Contains("$Severity".Trim())) { return }
    $a = $Tally.Assets[$CiId.Trim().ToLowerInvariant()]
    if ($null -eq $a) { return }
    $age = Get-SIProtectionAge -FixRelease $FixRelease -UpdateName $UpdateName -SourceFirstSeen $SourceFirstSeen -FirstDetected $FirstDetected
    $patch = Test-SIProtectionPatchFinding -FixRelease $FixRelease -UpdateName $UpdateName -UpdateId $UpdateId -PatchCycle $PatchCycle
    $b = [int]$age.Basis
    $Tally.BasisCount[$b] = [long]$Tally.BasisCount[$b] + 1
    [void]$Tally.BasisCis[$b].Add($CiId.Trim().ToLowerInvariant())
    $a.Tech = $true
    # #860: only a patch finding gets the accepted-lifecycle grace; every other finding has its own (default 0)
    $grace = $(if ($patch) { [int]$Tally.Settings.Grace[$a.Class] } else { [int]$Tally.Settings.OtherGrace[$a.Class] })
    if ($null -eq $age.Date -or ($Tally.CollectionTime.Date - $age.Date.Date).Days -ge $grace) { $a.Life = $true }
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

function Complete-SIProtectionTally {
    <#
        PURE over the tally. The protection score in the shape the Pro key figures store it: Rows of
        @{ Figure = technical | lifecycle | agebasis; Dim1 = asset type | (all) | age basis; Dim2 = tier | (all) | ''; Value; Assets; Total },
        plus Technical / Lifecycle (the overall %, $null when no asset is in scope), Assets (in scope), NoDate, Findings.
    #>
    param([Parameter(Mandatory)]$Tally)
    # ONE pass over the assets (never a pass per group): each asset adds its weight to its four cells -- (all) x (all), its type,
    # its tier, its type x tier -- with how much of it is in good standing in each view
    $cells = @{}
    foreach ($a in $Tally.Assets.Values) {
        foreach ($k in @(@('(all)', '(all)'), @($a.Type, '(all)'), @('(all)', $a.Tier), @($a.Type, $a.Tier))) {
            $key = $k[0] + '|' + $k[1]
            $c = $cells[$key]
            if ($null -eq $c) { $c = @{ D1 = $k[0]; D2 = $k[1]; W = 0.0; N = 0; TechW = 0.0; TechN = 0; LifeW = 0.0; LifeN = 0 }; $cells[$key] = $c }
            $c.W += $a.W; $c.N++
            if (-not $a.Tech) { $c.TechW += $a.W; $c.TechN++ }
            if (-not $a.Life) { $c.LifeW += $a.W; $c.LifeN++ }
        }
    }
    $pctOf = { param($num, $den) if ($den -gt 0) { [Math]::Round(100.0 * $num / $den, 1, [MidpointRounding]::AwayFromZero) } else { $null } }
    # the order of the rows: (all) first, then each type, each tier, each type x tier
    $rank = { param($c) if ($c.D1 -eq '(all)' -and $c.D2 -eq '(all)') { 0 } elseif ($c.D2 -eq '(all)') { 1 } elseif ($c.D1 -eq '(all)') { 2 } else { 3 } }
    $ordered = @($cells.Values | Sort-Object @{ Expression = { & $rank $_ } }, @{ Expression = { $_.D1 } }, @{ Expression = { $_.D2 } })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($view in 'technical', 'lifecycle') {
        foreach ($c in $ordered) {
            $num = $(if ($view -eq 'technical') { $c.TechW } else { $c.LifeW }); $good = $(if ($view -eq 'technical') { $c.TechN } else { $c.LifeN })
            $rows.Add([pscustomobject]@{ Figure = $view; Dim1 = $c.D1; Dim2 = $c.D2; Value = (& $pctOf $num $c.W); Assets = $good; Total = $c.N })
        }
    }
    $counted = [long]0; foreach ($b in 0..3) { $counted += [long]$Tally.BasisCount[$b] }
    foreach ($pair in $script:SIProtectionBasis) {
        $b = [int]$pair[0]
        $rows.Add([pscustomobject]@{ Figure = 'agebasis'; Dim1 = [string]$pair[1]; Dim2 = ''; Value = [double]$Tally.BasisCount[$b]; Assets = $Tally.BasisCis[$b].Count; Total = $counted })
    }
    $all = $cells['(all)|(all)']
    $tech = $null; $life = $null; $techN = 0; $lifeN = 0; $n = 0
    if ($null -ne $all) { $tech = & $pctOf $all.TechW $all.W; $life = & $pctOf $all.LifeW $all.W; $techN = $all.TechN; $lifeN = $all.LifeN; $n = $all.N }
    [pscustomobject]@{
        Technical = $tech; TechnicalGood = $techN
        Lifecycle = $life; LifecycleGood = $lifeN
        Assets    = $n
        NoDate    = [long]$Tally.BasisCount[0]
        Findings  = $counted
        Grace     = $Tally.Settings.Grace
        Weights   = $Tally.Settings.Weights
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
        Weights   = $cfg.Weights
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
    [void]$sb.Append([string]::Format($inv, '<p style="margin:0;font-size:12px;color:#5a6a7a;">Higher is better. Good standing = no open Very High / High finding; tier-weighted. Accepted lifecycle: {0}. {1:N0} of {2:N0} counted findings had no usable date and count as open.</p>', $grace, $Score.NoDate, $Score.Findings))
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
