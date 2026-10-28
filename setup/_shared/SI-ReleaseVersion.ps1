#Requires -Version 5.1
<#
    SecurityInsight (vendor) -- THE RELEASE NUMBER (#919, owner decision 2026-10-28): from SI's next release on, versions are
    3.0.1, 3.0.2, ... -- the PATCH grows per release, the MINOR for a real feature release (VERSION says 3.1.0) -- instead of
    3.0.0.<yyyyMMddHHmm>. The date / build stays where it is read: BUILD.json (built, display, shortCommit), the release
    notes, the support bundle and the version badge's tooltip. Never a date in the number.

      * Get-SINextReleaseVersion: the next number after the highest RELEASED one of VERSION's major.minor; the first release
        of a major.minor that has none is VERSION itself when it is not taken, else its next patch. Repeatable: the same
        inputs give the same number (no clock), and a number decided for a commit that was never released is reused for it.
      * a version that is not GREATER than the highest released one is refused; so is a MAJOR jump (the major only is
        compared: 3.0.1 after 3.0.0.<build> is fine; 2.x never leads to 3.x -- v3 is installed side by side).
      * every compare is numeric per part, 64-bit, a missing part = 0 -- the rule of every compare SI uses (the updater,
        the run gate, the Invardia manifest, the Community channel, the telemetry's fixedIn): 3.0.1 > 3.0.0.202610272235.
    PURE. PS 5.1 and 7.
#>

function ConvertTo-SIReleaseVersionParts {
    <# PURE. '3.0.1' -> 3,0,1 (64-bit); a leading 'v' and '+build' / '-label' tails are not read. $null when not a version. #>
    param([AllowNull()][AllowEmptyString()][string]$Version)
    $m = [regex]::Match("$Version".Trim(), '^v?(\d{1,18}(?:\.\d{1,18}){0,4})')
    if (-not $m.Success) { return $null }
    , [long[]]@($m.Groups[1].Value.Split('.') | ForEach-Object { [long]$_ })
}

function Compare-SIReleaseVersion {
    <# PURE. -1 / 0 / 1, numeric per part (64-bit), a missing part counts as 0. $null when either is not a version. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    $pa = ConvertTo-SIReleaseVersionParts $A; $pb = ConvertTo-SIReleaseVersionParts $B
    if ($null -eq $pa -or $null -eq $pb) { return $null }
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { [long]0 }; $y = if ($i -lt $pb.Count) { $pb[$i] } else { [long]0 }
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    0
}

function Get-SIReleaseVersionsFromState {
    <# PURE. Every version the release state (Release-SI's release-state.json, -State) records: each ring's Version and
       PreviousVersion, and the numbers decided before (assigned). Unique, as text. #>
    param($State)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $State) { return @() }
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    foreach ($r in 0..3) {
        $rec = & $get $State ("ring$r")
        foreach ($k in 'Version', 'PreviousVersion') { $v = "$(& $get $rec $k)".Trim(); if ($v -and -not $out.Contains($v)) { $out.Add($v) } }
    }
    foreach ($a in @(& $get $State 'assignedVersions')) { $v = "$(& $get $a 'Version')".Trim(); if ($v -and -not $out.Contains($v)) { $out.Add($v) } }
    $out.ToArray()
}

function Test-SIReleaseMajorJump {
    <# PURE. #919 (3) / (4): is -To another MAJOR than -From? The MAJOR only (3.0.1 after 3.0.0.202610272235: no; 2.2.460 -> 3.0.1:
       yes). $false when either is not a version (nothing to compare). #>
    param([AllowNull()][AllowEmptyString()][string]$From, [AllowNull()][AllowEmptyString()][string]$To)
    $a = ConvertTo-SIReleaseVersionParts $From; $b = ConvertTo-SIReleaseVersionParts $To
    if ($null -eq $a -or $null -eq $b) { return $false }
    ($a[0] -ne $b[0])
}

function Get-SINextReleaseVersion {
    <#
        PURE. #919: the version of the next release. -BaseVersion: the VERSION file of the commit (3.0.0, or 3.1.0 for a feature
        release); -Released: every version released or decided before (Get-SIReleaseVersionsFromState); -Commit and
        -Assigned (@(@{ Version; Commit; Released })): a number decided for THIS commit and never released is reused (a
        release run again gives the same number). Returns @{ Ok; Version; Reason; Highest }:
          * the next patch after the highest released 3-part number of VERSION's major.minor; a 4-part build of it
            (3.0.0.<yyyyMMddHHmm>) counts as patch <its third part>; none of that major.minor = VERSION itself when it is
            greater than everything released, else VERSION's patch + 1;
          * refused (Ok = $false) when the result is not GREATER than the highest released version, or its MAJOR is not the
            highest released major (a major jump is the owner's decision, never a release's number).
    #>
    param([Parameter(Mandatory)][string]$BaseVersion, [string[]]$Released = @(), [string]$Commit = '', [object[]]$Assigned = @())
    $no = { param($why, $hi) [pscustomobject]@{ Ok = $false; Version = ''; Reason = $why; Highest = $hi } }
    $base = ConvertTo-SIReleaseVersionParts $BaseVersion
    if ($null -eq $base -or $base.Count -lt 3) { return (& $no ("VERSION '{0}' is not major.minor.patch" -f $BaseVersion) '') }
    $rel = @(@($Released) | Where-Object { $null -ne (ConvertTo-SIReleaseVersionParts $_) })
    $hi = ''; foreach ($v in $rel) { if (-not $hi -or (Compare-SIReleaseVersion $v $hi) -gt 0) { $hi = $v } }
    if ($hi -and (Test-SIReleaseMajorJump -From $hi -To $BaseVersion)) {
        return (& $no ("VERSION {0} is another MAJOR than the highest released {1} -- a major version is the owner's decision (side by side), never a release number" -f $BaseVersion, $hi) $hi)
    }
    # a number decided for this commit before and never released: the same again (repeatable)
    if ("$Commit".Trim()) {
        foreach ($a in @($Assigned)) {
            if (-not $a) { continue }
            $ac = "$($a.Commit)".Trim(); $av = "$($a.Version)".Trim()
            if ($ac -and $av -and ($ac.StartsWith($Commit.Trim(), [StringComparison]::OrdinalIgnoreCase) -or $Commit.Trim().StartsWith($ac, [StringComparison]::OrdinalIgnoreCase)) -and -not [bool]$a.Released -and
                (Compare-SIReleaseVersion $av $BaseVersion) -ge 0 -and -not (Test-SIReleaseMajorJump -From $av -To $BaseVersion)) {
                $higher = @($rel | Where-Object { $_ -ne $av -and (Compare-SIReleaseVersion $_ $av) -ge 0 })
                if (-not $higher.Count) { return [pscustomobject]@{ Ok = $true; Version = $av; Reason = ('{0}: the number decided for this commit before (never released) -- the same again' -f $av); Highest = $hi } }
            }
        }
    }
    $patch = [long]-1
    foreach ($v in $rel) {
        $p = ConvertTo-SIReleaseVersionParts $v
        if ($p.Count -ge 3 -and $p[0] -eq $base[0] -and $p[1] -eq $base[1] -and $p[2] -gt $patch) { $patch = $p[2] }
    }
    $next = if ($patch -lt 0) { '{0}.{1}.{2}' -f $base[0], $base[1], $base[2] } else { '{0}.{1}.{2}' -f $base[0], $base[1], ($patch + 1) }
    if ($patch -lt 0 -and $hi -and (Compare-SIReleaseVersion $next $hi) -le 0) { $next = '{0}.{1}.{2}' -f $base[0], $base[1], ($base[2] + 1) }
    if ($hi -and (Compare-SIReleaseVersion $next $hi) -le 0) {
        return (& $no ("the next number {0} is not greater than the highest released {1} -- refused (VERSION {2})" -f $next, $hi, $BaseVersion) $hi)
    }
    [pscustomobject]@{ Ok = $true; Version = $next; Highest = $hi
                       Reason = $(if ($hi) { ('{0}: the next number after the highest released {1}' -f $next, $hi) } else { ('{0}: the first release' -f $next) }) }
}

function Resolve-SIReleaseVersion {
    <#
        #919: the version of the release of -Commit, decided from the release state (-StateFile, Release-SI's
        release-state.json: every ring's Version / PreviousVersion and the numbers decided before) and VERSION (-BaseVersion),
        then RECORDED there (assignedVersions, the last 50) so a later release never takes the same number and a re-run of
        this commit takes the same one. -NoRecord: decide only (a plan). THROWS when the number is refused
        (Get-SINextReleaseVersion: not greater than the highest released, or a major jump). Returns the decision.
    #>
    param([Parameter(Mandatory)][string]$StateFile, [Parameter(Mandatory)][string]$BaseVersion, [Parameter(Mandatory)][string]$Commit, [switch]$NoRecord)
    $st = $null
    if (Test-Path -LiteralPath $StateFile) { try { $st = [IO.File]::ReadAllText($StateFile) | ConvertFrom-Json } catch { throw ("the release state {0} could not be read ({1}) -- the release number is not decided from a guess" -f $StateFile, $_.Exception.Message) } }
    $assigned = @(); if ($st -and $st.PSObject.Properties['assignedVersions']) { $assigned = @($st.assignedVersions) }
    $d = Get-SINextReleaseVersion -BaseVersion $BaseVersion -Released @(Get-SIReleaseVersionsFromState -State $st) -Commit $Commit -Assigned $assigned
    if (-not $d.Ok) { throw ("the release number is refused: {0}" -f $d.Reason) }
    if (-not $NoRecord) {
        # read again just before the write (another ring's release may have written since)
        $fresh = $null; if (Test-Path -LiteralPath $StateFile) { try { $fresh = [IO.File]::ReadAllText($StateFile) | ConvertFrom-Json } catch { $fresh = $null } }
        $o = [ordered]@{}; if ($fresh) { foreach ($pp in $fresh.PSObject.Properties) { $o[$pp.Name] = $pp.Value } }
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($a in @($(if ($o.Contains('assignedVersions')) { $o['assignedVersions'] }))) { if ($a -and "$($a.Version)" -ne $d.Version) { $list.Add($a) } }
        $list.Add([pscustomobject]([ordered]@{ Version = $d.Version; Commit = $Commit; Released = $false; DecidedUtc = [datetime]::UtcNow.ToString('o') }))
        $o['assignedVersions'] = @($list | Select-Object -Last 50)
        $dir = Split-Path -Parent $StateFile; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        [IO.File]::WriteAllText($StateFile, (ConvertTo-Json -InputObject $o -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    $d
}
