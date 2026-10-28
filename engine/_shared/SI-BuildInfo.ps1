#Requires -Version 5.1
<#
    WHICH BUILD OF SecurityInsight IS THIS (operator 2026-10-05: "change the version in any release, so I can keep
    track in the GUI what version I am at").

    ONE build identity, computed ONCE when a build/package/image is made, stamped into BUILD.json next to VERSION, and
    only READ at run time. Nothing here asks git at run time: an install, a container image or a customer package has
    no .git folder, and the answer must not change between the build and the run.

      version      the product version from VERSION                         3.0.0
      display      what people see: the version, plus -rc.<n> for a       3.0.0-rc.12   (pre-release build)
                   build that is not the tagged release                    3.0.0         (release build)
      rc           n = commits on the branch since VERSION last changed    12 / $null for a release
                   (git rev-list --first-parent --count <commit that last changed VERSION>..HEAD)
      commit       the full commit; shortCommit its first 7 characters
      builtUtc     when the build was made (UTC, ISO 8601)
      channel/ring where it is going, when the builder knows it (else null)

    A RELEASE build is HEAD carrying the tag SI-<VERSION> (or SecurityInsight-v<VERSION>, the public twin).
    Anything else is a pre-release and says so.

    Functions:
      Get-SIBuildInfo     BUILD TIME. From git when the folder is a git work tree, else what BUILD.json says.
      Read-SIBuildInfo    RUN TIME. BUILD.json; without it the VERSION file with "build unknown"; never git.
      Write-SIBuildInfo   writes BUILD.json (UTF-8, no BOM).
      Format-SIBuildLine  "3.0.0-rc.12 (build 0dc9062, 2026-10-05 14:10 UTC)" for banners and logs.
    PowerShell 5.1 and 7, Windows and Linux.
#>

function ConvertTo-SIBuildDisplay {
    <# PURE. 3.0.0 + rc 12 -> 3.0.0-rc.12; rc $null (a release) -> 3.0.0. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Version, [AllowNull()]$Rc)
    $v = "$Version".Trim()
    if (-not $v) { return '' }
    if ($null -eq $Rc -or "$Rc" -eq '') { return $v }
    '{0}-rc.{1}' -f $v, ([int]$Rc)
}

function Read-SIVersionFile {
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $f = [System.IO.Path]::Combine($SolutionRoot, 'VERSION')
    if (-not [System.IO.File]::Exists($f)) { return '' }
    try { return ([System.IO.File]::ReadAllText($f)).Trim() } catch { return '' }
}

function New-SIBuildInfoObject {
    param([string]$Version, $Rc, [string]$Commit, [string]$BuiltUtc, $Channel, $Ring, [string]$Source)
    $c = "$Commit".Trim()
    [pscustomobject][ordered]@{
        version     = "$Version".Trim()
        display     = (ConvertTo-SIBuildDisplay -Version $Version -Rc $Rc)
        commit      = $c
        shortCommit = $(if ($c.Length -ge 7) { $c.Substring(0, 7) } else { $c })
        builtUtc    = "$BuiltUtc"
        rc          = $(if ($null -eq $Rc -or "$Rc" -eq '') { $null } else { [int]$Rc })
        channel     = $(if ("$Channel".Trim()) { "$Channel".Trim() } else { $null })
        ring        = $(if ($null -ne $Ring -and "$Ring" -ne '') { [int]$Ring } else { $null })
        source      = $Source
    }
}

function Read-SIBuildInfo {
    <#
        RUN TIME. What this install / image / package says about its build. Order: <SolutionRoot>/BUILD.json, then the
        VERSION file (display = the version, no commit: "build unknown"), then '(dev)'. Never throws, never calls git.
        source = 'BUILD.json' | 'VERSION' | 'none'.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $bj = [System.IO.Path]::Combine($SolutionRoot, 'BUILD.json')
    if ([System.IO.File]::Exists($bj)) {
        try {
            $j = [System.IO.File]::ReadAllText($bj) | ConvertFrom-Json
            if ("$($j.version)".Trim()) {
                $o = New-SIBuildInfoObject -Version ([string]$j.version) -Rc $j.rc -Commit ([string]$j.commit) -BuiltUtc ([string]$j.builtUtc) `
                        -Channel $j.channel -Ring $(if ($j.PSObject.Properties['ring']) { $j.ring } else { $null }) -Source 'BUILD.json'
                # the stamped display wins: it is what the build said, and the reader must not re-derive it differently
                if ("$($j.display)".Trim()) { $o.display = "$($j.display)".Trim() }
                # the release stamped by Publish-SIRelease travels on (an image build writes BUILD.json again from this)
                if ($j.PSObject.Properties['release'] -and "$($j.release)".Trim()) { $o | Add-Member -NotePropertyName 'release' -NotePropertyValue "$($j.release)".Trim() -Force }
                return $o
            }
        } catch { }
    }
    $v = Read-SIVersionFile -SolutionRoot $SolutionRoot
    if ($v) { return (New-SIBuildInfoObject -Version $v -Rc $null -Commit '' -BuiltUtc '' -Source 'VERSION') }
    New-SIBuildInfoObject -Version '(dev)' -Rc $null -Commit '' -BuiltUtc '' -Source 'none'
}

function Invoke-SIBuildGit {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string[]]$GitArgs)
    $global:LASTEXITCODE = 0
    $out = & git -C $Root @GitArgs 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    (@($out) -join "`n").Trim()
}

function Get-SIBuildInfo {
    <#
        BUILD TIME. Compute the build identity of <SolutionRoot> (the folder holding VERSION).
        In a git work tree: commit = HEAD; release when HEAD carries SI-<VERSION> / SecurityInsight-v<VERSION>, else
        rc = commits since the commit that last changed VERSION. -Ref builds the identity of another ref (a package of a tag). Without git (an install, an extracted package): what
        BUILD.json says (Read-SIBuildInfo). -NoGit forces the second path (tests). -Now pins the build time (tests).
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot, [string]$Channel, $Ring, $Now, [switch]$NoGit, [string]$Ref = 'HEAD')
    $root = (Resolve-Path -LiteralPath $SolutionRoot).Path
    $ts = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
    $built = $ts.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $gitOk = $false
    if (-not $NoGit -and (Get-Command -Name git -ErrorAction SilentlyContinue)) {
        $gitOk = ((Invoke-SIBuildGit -Root $root -GitArgs @('rev-parse', '--is-inside-work-tree')) -eq 'true')
    }
    if (-not $gitOk) {
        $r = Read-SIBuildInfo -SolutionRoot $root
        if ($Channel) { $r.channel = $Channel }
        if ($null -ne $Ring -and "$Ring" -ne '') { $r.ring = [int]$Ring }
        return $r
    }
    $version = if ($Ref -eq 'HEAD') { Read-SIVersionFile -SolutionRoot $root } else { "$(Invoke-SIBuildGit -Root $root -GitArgs @('show', ('{0}:./VERSION' -f $Ref)))".Trim() }
    if (-not $version) { $version = '(dev)' }
    $head = Invoke-SIBuildGit -Root $root -GitArgs @('rev-parse', ('{0}^{{commit}}' -f $Ref))
    $tags = @("$(Invoke-SIBuildGit -Root $root -GitArgs @('tag', '--points-at', $Ref))" -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $isRelease = ($tags -contains ('SI-{0}' -f $version)) -or ($tags -contains ('SecurityInsight-v{0}' -f $version))
    $rc = $null
    if (-not $isRelease) {
        $verCommit = Invoke-SIBuildGit -Root $root -GitArgs @('log', '-1', '--format=%H', $Ref, '--', 'VERSION')
        $count = if ($verCommit) { Invoke-SIBuildGit -Root $root -GitArgs @('rev-list', '--first-parent', '--count', ('{0}..{1}' -f $verCommit, $Ref)) }
                 else { Invoke-SIBuildGit -Root $root -GitArgs @('rev-list', '--first-parent', '--count', $Ref) }
        $n = 0
        if (-not [int]::TryParse("$count", [ref]$n)) { $n = 0 }
        $rc = $n
    }
    New-SIBuildInfoObject -Version $version -Rc $rc -Commit $head -BuiltUtc $built -Channel $Channel -Ring $Ring -Source 'git'
}

function Initialize-SIBuildInfoFile {
    <#
        2026-10-28 (the Community edition): a SecurityInsight folder WITHOUT BUILD.json -- the public copy, a Community release
        zip from GitHub -- gets one, so the web app image builds (pro-management/Dockerfile copies BUILD.json, AppInfo reads it).
        Present = left exactly as it is (a Pro release archive is stamped by Publish-SIRelease). Absent = written from what the
        folder knows without git (Read-SIBuildInfo: its VERSION; no commit -- "build unknown"), -Channel / -Ring when given.
        The app images' source hash leaves BUILD.json out (SI-FastRoll.ps1), so stamping never changes an image tag.
        Returns 'present' | 'written'. Throws when the folder has no VERSION (not a release).
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot, [string]$Channel, $Ring)
    $bj = [System.IO.Path]::Combine($SolutionRoot, 'BUILD.json')
    if ([System.IO.File]::Exists($bj)) { return 'present' }
    if (-not [System.IO.File]::Exists([System.IO.Path]::Combine($SolutionRoot, 'VERSION'))) { throw ("{0} holds no VERSION -- not a SecurityInsight release" -f $SolutionRoot) }
    $info = Read-SIBuildInfo -SolutionRoot $SolutionRoot
    if ($Channel) { $info.channel = $Channel }
    if ($null -ne $Ring -and "$Ring" -ne '') { $info.ring = [int]$Ring }
    $null = Write-SIBuildInfo -Info $info -Path $bj
    'written'
}

function Write-SIBuildInfo {
    <# Writes BUILD.json {version, display, commit, shortCommit, builtUtc, rc, channel, ring} (UTF-8, no BOM). #>
    param([Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$Path)
    $o = [ordered]@{
        version = [string]$Info.version; display = [string]$Info.display; commit = [string]$Info.commit
        shortCommit = [string]$Info.shortCommit; builtUtc = [string]$Info.builtUtc; rc = $Info.rc
        channel = $Info.channel; ring = $Info.ring
    }
    # the release this package IS at Invardia (3.0.0.<build number>) -- stamped by Publish-SIRelease; the run compares the
    # error catalogue's fixedIn with it (#709). Only when known: older readers ignore an extra field.
    if ($Info.PSObject.Properties['release'] -and "$($Info.release)".Trim()) { $o.release = "$($Info.release)".Trim() }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $o -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
    $Path
}

function Format-SIBuildLine {
    <# PURE. "3.0.0-rc.12 (build 0dc9062, 2026-10-05 14:10 UTC, ring 1)"; no commit known -> "3.0.0 (build unknown)". #>
    param([Parameter(Mandatory)]$Info)
    $parts = New-Object System.Collections.Generic.List[string]
    if ("$($Info.shortCommit)".Trim()) { $parts.Add(('build {0}' -f $Info.shortCommit)) } else { $parts.Add('build unknown') }
    if ("$($Info.builtUtc)".Trim()) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse([string]$Info.builtUtc, [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
            $parts.Add(($d.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'))
        }
    }
    if ($null -ne $Info.ring -and "$($Info.ring)" -ne '') { $parts.Add(('ring {0}' -f $Info.ring)) }
    if ("$($Info.channel)".Trim()) { $parts.Add(('channel {0}' -f $Info.channel)) }
    '{0} ({1})' -f $Info.display, ($parts -join ', ')
}

function New-SIBuildArchiveArgs {
    <#
        For a package built with `git archive` of SOLUTIONS/SecurityInsight at -Ref: the git archive options that ADD the
        build's BUILD.json at <Prefix>SOLUTIONS/SecurityInsight/BUILD.json (an untracked file -- git archive --add-file)
        and then set the archive's own -Prefix. Use them in place of --prefix=<Prefix>:
            $b = New-SIBuildArchiveArgs -RepoRoot $repo -Ref $Ref -Prefix 'securityinsight-src-3.0.0/' -WorkDir $OutDir
            git -C $repo archive --format=zip @($b.Args) -o $zip $Ref -- SOLUTIONS/SecurityInsight
        Returns @{ Args; Info; File }. Git applies the LAST --prefix before --add-file to that file, and the last one
        overall to the tree -- which is why the order is fixed here, in one place.
    #>
    param([Parameter(Mandatory)][string]$RepoRoot, [string]$Ref = 'HEAD', [Parameter(Mandatory)][string]$Prefix,
          [Parameter(Mandatory)][string]$WorkDir, [string]$Channel, $Ring,
          # the release version at Invardia (3.0.0.<build number>), stamped as BUILD.json 'release'
          [string]$ReleaseVersion)
    $sol = [System.IO.Path]::Combine($RepoRoot, 'SOLUTIONS', 'SecurityInsight')
    $info = Get-SIBuildInfo -SolutionRoot $sol -Ref $Ref -Channel $Channel -Ring $Ring
    if ("$ReleaseVersion".Trim()) { $info | Add-Member -NotePropertyName 'release' -NotePropertyValue "$ReleaseVersion".Trim() -Force }
    $dir = [System.IO.Path]::Combine($WorkDir, ('build-' + [guid]::NewGuid().ToString('N').Substring(0, 8)))
    $file = Write-SIBuildInfo -Info $info -Path ([System.IO.Path]::Combine($dir, 'BUILD.json'))
    $p = if ($Prefix.EndsWith('/')) { $Prefix } else { $Prefix + '/' }
    [pscustomobject]@{
        Args = @(('--prefix={0}SOLUTIONS/SecurityInsight/' -f $p), ('--add-file={0}' -f $file), ('--prefix={0}' -f $p))
        Info = $info
        File = $file
    }
}
