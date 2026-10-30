#Requires -Version 5.1
<#
    SecurityInsight (vendor) -- THE RELEASE NUMBER (#919, owner decision 2026-10-28): from SI's next release on, versions are
    3.0.1, 3.0.2, ... -- the PATCH grows per release, the MINOR for a real feature release (VERSION says 3.1.0) -- instead of
    3.0.0.<yyyyMMddHHmm>. The date / build stays where it is read: BUILD.json (built, display, shortCommit), the release
    notes, the support bundle and the version badge's tooltip. Never a date in the number.

    #938 (owner 2026-10-29): THE TREE'S VERSION IS THE RELEASE NUMBER, and only a REGISTERED number is used up.
      * TAKEN = a number Invardia holds: every ring's Version / PreviousVersion in Release-SI's release-state.json, and every
        number recorded as REGISTERED there (assignedVersions, Registered = true -- written by Save-SIReleaseVersionRegistered
        right after Invardia accepted the package). A number decided for an attempt that stopped before (a red gate, a
        failed build) is NOT taken: the next attempt -- whatever its commit -- uses the same number.
      * Get-SINextReleaseVersion: the number is VERSION (major.minor.patch) when it is greater than every taken number. A
        number this SAME commit registered before is used again (the next ring of the same release). VERSION at or below
        the highest taken number is REFUSED, naming the next free number (set VERSION to it, with its release-notes entry);
        so is a MAJOR jump (the major only is compared: 3.0.1 after 3.0.0.<build> is fine; 2.x never leads to 3.x -- v3 is
        installed side by side). Repeatable: the same inputs give the same number (no clock).
      * every compare is numeric per part, 64-bit, a missing part = 0 -- the rule of every compare SI uses (the updater,
        the run gate, the Invardia manifest, the Community channel, the telemetry's fixedIn): 3.0.1 > 3.0.0.202610272235.
    PURE except Resolve-SIReleaseVersion (reads the state) and Save-SIReleaseVersionRegistered (writes it). PS 5.1 and 7.
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

function Get-SIReleaseStateField {
    <# PURE. One field of a state object (hashtable or object); $null when absent. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    $null
}

function Get-SIReleaseTakenFromState {
    <# PURE. Every number Invardia holds, from the release state (-State, Release-SI's release-state.json): each ring's
       Version (with the ring's Commit) and PreviousVersion, and each number recorded as REGISTERED (assignedVersions with
       Registered = true). A number only DECIDED for an attempt that stopped is not taken. Returns @(@{ Version; Commit }). #>
    param($State)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $State) { return @() }
    foreach ($r in 0..3) {
        $rec = Get-SIReleaseStateField $State ("ring$r")
        $v = "$(Get-SIReleaseStateField $rec 'Version')".Trim()
        if ($v) { $out.Add([pscustomobject]@{ Version = $v; Commit = "$(Get-SIReleaseStateField $rec 'Commit')".Trim() }) }
        $pv = "$(Get-SIReleaseStateField $rec 'PreviousVersion')".Trim()
        if ($pv) { $out.Add([pscustomobject]@{ Version = $pv; Commit = '' }) }
    }
    foreach ($a in @(Get-SIReleaseStateField $State 'assignedVersions')) {
        if (-not $a -or -not [bool](Get-SIReleaseStateField $a 'Registered')) { continue }
        $v = "$(Get-SIReleaseStateField $a 'Version')".Trim()
        if ($v) { $out.Add([pscustomobject]@{ Version = $v; Commit = "$(Get-SIReleaseStateField $a 'Commit')".Trim() }) }
    }
    $out.ToArray()
}

function Get-SIReleaseVersionsFromState {
    <# PURE. The taken numbers (Get-SIReleaseTakenFromState) as text, unique. #>
    param($State)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in @(Get-SIReleaseTakenFromState -State $State)) { $v = [string]$t.Version; if ($v -and -not $out.Contains($v)) { $out.Add($v) } }
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

function Test-SIReleaseSameCommit {
    <# PURE. Two commit ids name the same commit (one may be the short form of the other). Empty = never. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    $x = "$A".Trim(); $y = "$B".Trim()
    if (-not $x -or -not $y) { return $false }
    $x.StartsWith($y, [StringComparison]::OrdinalIgnoreCase) -or $y.StartsWith($x, [StringComparison]::OrdinalIgnoreCase)
}

function Get-SINextReleaseVersion {
    <#
        PURE. #919 / #938: the version of the next release. -BaseVersion: the tree's VERSION (major.minor.patch) -- the number
        itself; -Released: every TAKEN number (Get-SIReleaseVersionsFromState); -Commit and -Assigned (@(@{ Version; Commit }),
        Get-SIReleaseTakenFromState): a number THIS commit registered before is used again. Returns @{ Ok; Version; Reason;
        Highest; NextFree }:
          * VERSION, when it is greater than every taken number (a number decided for an attempt that stopped is not taken);
          * the number this commit registered, when it is VERSION (the same release, another ring);
          * refused (Ok = $false) when VERSION is not greater than the highest taken number -- NextFree names the number to
            set -- or when VERSION's MAJOR is not the highest taken major (a major jump is the owner's decision).
    #>
    param([Parameter(Mandatory)][string]$BaseVersion, [string[]]$Released = @(), [string]$Commit = '', [object[]]$Assigned = @())
    $no = { param($why, $hi, $free) [pscustomobject]@{ Ok = $false; Version = ''; Reason = $why; Highest = $hi; NextFree = $free } }
    $base = ConvertTo-SIReleaseVersionParts $BaseVersion
    if ($null -eq $base -or $base.Count -ne 3) { return (& $no ("VERSION '{0}' is not major.minor.patch" -f $BaseVersion) '' '') }
    $baseText = '{0}.{1}.{2}' -f $base[0], $base[1], $base[2]
    $rel = @(@($Released) + @(@($Assigned) | Where-Object { $_ } | ForEach-Object { [string]$_.Version }) | Where-Object { $null -ne (ConvertTo-SIReleaseVersionParts $_) })
    $hi = ''; foreach ($v in $rel) { if (-not $hi -or (Compare-SIReleaseVersion $v $hi) -gt 0) { $hi = $v } }
    if ($hi -and (Test-SIReleaseMajorJump -From $hi -To $baseText)) {
        return (& $no ("VERSION {0} is another MAJOR than the highest released {1} -- a major version is the owner's decision (side by side), never a release number" -f $baseText, $hi) $hi '')
    }
    # the same release again (another ring): a number THIS commit registered, and it is VERSION
    foreach ($a in @($Assigned)) {
        if (-not $a) { continue }
        if ((Test-SIReleaseSameCommit "$($a.Commit)" $Commit) -and (Compare-SIReleaseVersion "$($a.Version)" $baseText) -eq 0) {
            return [pscustomobject]@{ Ok = $true; Version = $baseText; Highest = $hi; NextFree = ''
                                      Reason = ('{0}: registered for this commit before -- the same release again' -f $baseText) }
        }
    }
    if ($hi -and (Compare-SIReleaseVersion $baseText $hi) -le 0) {
        $hp = ConvertTo-SIReleaseVersionParts $hi
        $free = '{0}.{1}.{2}' -f $hp[0], $(if ($hp.Count -ge 2) { $hp[1] } else { 0 }), ($(if ($hp.Count -ge 3) { $hp[2] } else { 0 }) + 1)
        return (& $no ("VERSION {0} is not greater than the highest released or registered number {1} -- set VERSION to {2} (and add its release-notes entry), then release again" -f $baseText, $hi, $free) $hi $free)
    }
    [pscustomobject]@{ Ok = $true; Version = $baseText; Highest = $hi; NextFree = ''
                       Reason = $(if ($hi) { ('{0}: VERSION, greater than the highest released or registered {1}' -f $baseText, $hi) } else { ('{0}: the first release' -f $baseText) }) }
}

function Read-SIReleaseStateFile {
    <# The release state (-StateFile); $null when there is none. THROWS when it cannot be read (never a guessed number). #>
    param([Parameter(Mandatory)][string]$StateFile)
    if (-not (Test-Path -LiteralPath $StateFile)) { return $null }
    try { [IO.File]::ReadAllText($StateFile) | ConvertFrom-Json }
    catch { throw ("the release state {0} could not be read ({1}) -- the release number is not decided from a guess" -f $StateFile, $_.Exception.Message) }
}

function Resolve-SIReleaseVersion {
    <#
        #919 / #938: the version of the release of -Commit, DECIDED (never recorded here) from the release state (-StateFile,
        Release-SI's release-state.json: the taken numbers) and the tree's VERSION (-BaseVersion). The number is recorded only
        when Invardia accepted the package (Save-SIReleaseVersionRegistered, Publish-SIRelease), so an attempt that stops
        before uses up nothing. THROWS when the number is refused (Get-SINextReleaseVersion). Returns the decision.
    #>
    param([Parameter(Mandatory)][string]$StateFile, [Parameter(Mandatory)][string]$BaseVersion, [Parameter(Mandatory)][string]$Commit)
    $st = Read-SIReleaseStateFile -StateFile $StateFile
    $taken = @(Get-SIReleaseTakenFromState -State $st)
    $d = Get-SINextReleaseVersion -BaseVersion $BaseVersion -Released @($taken | ForEach-Object { [string]$_.Version }) -Commit $Commit -Assigned $taken
    if (-not $d.Ok) { throw ("the release number is refused: {0}" -f $d.Reason) }
    $d
}

function Save-SIReleaseVersionRegistered {
    <#
        #938: records -Version as REGISTERED for -Commit in the release state (assignedVersions, Registered = true, the last
        50) -- called right after Invardia accepted the package. From then on the number is taken. The file is read again just
        before the write (another ring's release may have written since); every other field is kept. Returns $true.
    #>
    param([Parameter(Mandatory)][string]$StateFile, [Parameter(Mandatory)][string]$Version, [string]$Commit = '')
    $fresh = $null; if (Test-Path -LiteralPath $StateFile) { try { $fresh = [IO.File]::ReadAllText($StateFile) | ConvertFrom-Json } catch { $fresh = $null } }
    $o = [ordered]@{}; if ($fresh) { foreach ($pp in $fresh.PSObject.Properties) { $o[$pp.Name] = $pp.Value } }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($(if ($o.Contains('assignedVersions')) { $o['assignedVersions'] }))) { if ($a -and "$($a.Version)" -ne $Version) { $list.Add($a) } }
    $list.Add([pscustomobject]([ordered]@{ Version = $Version; Commit = $Commit; Registered = $true; RegisteredUtc = [datetime]::UtcNow.ToString('o') }))
    $o['assignedVersions'] = @($list | Select-Object -Last 50)
    $dir = Split-Path -Parent $StateFile; if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [IO.File]::WriteAllText($StateFile, (ConvertTo-Json -InputObject $o -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $true
}
