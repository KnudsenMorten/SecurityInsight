#Requires -Version 5.1
<#
    SecurityInsight Community -- THE UPDATE CLIENT (framework UPDATE-1, SI #270).

    A Community install updates from Invardia's signed Community channel, per RING -- never by "whatever is on main":

      1. READ the manifest of THIS install's ring (owner + Invardia + PIM, 2026-10-28 -- the same route PIM's Community
         edition reads): GET https://invardia.com/api/updates/securityinsight/community/<ring>, ANONYMOUS (no install key,
         no code, no licence); 200 = { manifest, manifestB64, signature, keyId, downloadUrl } (the SAME shape and verifier as
         a Pro install's answer), 204 = nothing released to the ring yet, 404 = no such ring. (The channel.json file on an
         update-channel branch of the public repository is RETIRED, 2026-10-28.)
      2. VERIFY the entry for THIS install's ring (engine/_shared/InvardiaUpdate.verify.ps1, byte-identical to the framework
         verifier): RS256 over the base64-DECODED manifest bytes against the EMBEDDED trusted keys; product securityinsight,
         kind community, a ring the manifest names IS this install's ring; the same MAJOR version as installed; the
         sequence is not lower than the one applied here (no replay; a rollback is a NEW, higher sequence naming an older
         version); manualStep / minFromVersion HOLD with the reason; the download link is https.
      3. DOWNLOAD the release zip (no git needed) and prove it is the signed one: zip, the signed size AND the signed SHA-256.
      4. APPLY BY HOST:
           VM        -- the scheduled SecurityInsight tasks are paused (a running engine = wait for the next run), every
                        file the release replaces or removes is backed up, the release files are written (*.custom.*, logs,
                        output, data and this client's own state are NEVER touched), the install is health-checked
                        (version, every file's hash, every script parses, the client is still there), and on ANY failure
                        the backup is restored and verified. The tasks are resumed in every case.
           container -- after the files, the NEW release's setup\Invoke-SIContainerUpdate.ps1 -Apply builds the image in
                        your registry, rolls the jobs, verifies, and restores the previous image itself on failure; the
                        files are then rolled back too, so the folder and the containers never disagree.
      5. RECORD the applied sequence + version (.si-update\state.json) so an older manifest is never applied again.

    🔒 Nothing here runs git, and nothing here trusts a key it did not ship with. Every call that leaves the process goes
    through -Seams, so the tests run offline. PS 5.1 safe. NEVER THROWS: every outcome is a result with an Action + Reason.
    There is no dry run (#276): running the update updates when -- and only when -- the channel for this ring says so.
#>

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

. ([IO.Path]::Combine($PSScriptRoot, 'InvardiaUpdate.verify.ps1'))
# The ONE trust list (UPDATE-1.2): the keys embedded in the framework verifier -- captured here, passed explicitly.
$script:SICommunityTrustedKeys = @($script:InvardiaUpdateTrustedKeys)

$script:SICommunityUpdateProduct        = 'securityinsight'
$script:SICommunityUpdateKind           = 'community'
# Invardia's Community route (rings 2 and 3); the signed manifest names the archive, which must be an https link
$script:SICommunityUpdateBaseUrl        = 'https://invardia.com'
$script:SICommunityUpdateDownloadPrefix = 'https://'
$script:SICommunityUpdateRings          = @(2, 3)
$script:SICommunityUpdateDefaultRing    = 3
$script:SICommunityUpdateStateFolder    = '.si-update'
# The files that carry the update itself: a release without them would strand every install that takes it.
$script:SICommunityUpdateClientFiles    = @('Update-SecurityInsight.ps1', 'engine/_shared/SI-CommunityUpdate.ps1', 'engine/_shared/InvardiaUpdate.verify.ps1')
# The files earlier releases shipped that a release no longer has, with the SHA-256 of every shipped version -- carried BY
# the release being applied. The FIRST update by this client (no installed-files list yet) removes such a file only when it
# is byte for byte a shipped version: a changed copy is kept, a customer file is never on the list.
$script:SICommunityRetiredManifest      = 'engine/_shared/SI-PreviousReleaseFiles.locked.json'
# Files only the PRO package carries (Get-SICommunityInstallKind): a folder with any of them is never updated from the
# community channel -- that would replace SecurityInsight Pro with the public edition.
$script:SICommunityProOnlyMarkers       = @('setup/_shared/SI-GuidedInstallPro.ps1', 'engine/_shared/SI-InvardiaUpdate.ps1', 'engine/asset-cmdb/Invoke-SICmdb.ps1')

# =====================================================================================================================
#  Pure helpers
# =====================================================================================================================
function ConvertTo-SICommunityRelPath {
    <# PURE. A relative path in one form: forward slashes, no leading slash. #>
    param([AllowEmptyString()][string]$Path)
    "$Path".Replace('\', '/').TrimStart('/')
}

function Test-SICommunityCustomerPath {
    <#
        PURE. TRUE for a path the CUSTOMER owns -- never written, replaced, removed or backed up by an update:
        any *.custom.* file (a shipped *.custom.sample.* is the product's), the run output folders (logs, output, data,
        staging), the git folder, this client's own state, and config\asset-tagging.config.json.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RelPath)
    $p = ConvertTo-SICommunityRelPath $RelPath
    if (-not $p) { return $true }
    $parts = @($p -split '/')
    $first = $parts[0].ToLowerInvariant()
    if (@('.git', '.si-update', 'logs', 'output', 'data', 'staging') -contains $first) { return $true }
    $leaf = $parts[-1]
    if ($leaf -match '(?i)\.custom\.' -and $leaf -notmatch '(?i)\.custom\.sample\.') { return $true }
    if ($leaf -match '(?i)\.corrupted$') { return $true }
    if ($p -ieq 'config/asset-tagging.config.json') { return $true }
    $false
}

function Get-SICommunityInstallKind {
    <#
        Which update path owns this folder?
          community -- the public edition: this client updates it.
          sync      -- a SOLUTIONS\SecurityInsight folder of an AutomateIT tree: Sync-AutomateIT updates it (ring 1 and the
                       internal rings live in the framework's release map, not here).
          private   -- the private payload (a Pro-only file present, $SICommunityProOnlyMarkers): the Pro updater / the sync updates it. The
                       community channel would replace it with the public edition, so it is never applied here.
    #>
    param([Parameter(Mandatory)][string]$Root)
    $parent = Split-Path -Parent $Root
    if ($parent -and (Split-Path -Leaf $parent) -ieq 'SOLUTIONS') {
        $top = Split-Path -Parent $parent
        if ($top -and ((Test-Path -LiteralPath ([IO.Path]::Combine($top, 'bootstrap', 'Sync-AutomateIT.json'))) -or (Test-Path -LiteralPath ([IO.Path]::Combine($top, 'sync'))))) { return 'sync' }
    }
    # The private payload's markers: files ONLY the Pro package carries -- its guided-install steps, its Invardia update
    # client, the ServiceNow CMDB connector. NOT a LICENSE-* file or an engine\pro-* folder any more: since 2026-10-27
    # (SI #750) the Community edition ships LICENSE-PRO (the paid web pages it carries) and engine\pro-settings /
    # engine\pro-data (its database), so those markers would have stopped every Community install from updating.
    foreach ($m in $script:SICommunityProOnlyMarkers) {
        # one segment at a time: [IO.Path]::Combine(object[]) binds to the wrong overload in PowerShell
        $p = $Root; foreach ($seg in @($m -split '/')) { $p = [IO.Path]::Combine($p, $seg) }
        if (Test-Path -LiteralPath $p) { return 'private' }
    }
    'community'
}

function Test-SICommunityMajorVersion {
    <# PURE. '' when the release has the installed MAJOR version, else the reason (owner 2026-10-28: no update ever crosses a
       major version; an installed version that cannot be read fails closed). #>
    param([AllowEmptyString()][AllowNull()][string]$Installed, [AllowEmptyString()][AllowNull()][string]$Release)
    $maj = { param($v) $m = [regex]::Match("$v".Trim(), '^v?(\d+)\.'); if ($m.Success) { [int]$m.Groups[1].Value } else { -1 } }
    $i = & $maj $Installed; $r = & $maj $Release
    if ($r -lt 0) { return ("the release names no readable version ('{0}')" -f $Release) }
    if ($i -lt 0) { return ("the installed version cannot be read ('{0}'), so a release of another major version cannot be ruled out" -f $Installed) }
    if ($i -ne $r) { return ("the release is SecurityInsight {0}, another major version than the installed {1} -- a new major version is installed beside the old one, never as an update" -f $Release, $Installed) }
    ''
}

function Get-SICommunityRunningVersion {
    param([Parameter(Mandatory)][string]$Root)
    $f = [IO.Path]::Combine($Root, 'VERSION')
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    "$([IO.File]::ReadAllText($f))".Trim().TrimStart([char]0xFEFF)
}

function Get-SICommunityUpdateSettings {
    <#
        This install's ring and channel. -Ring (this run only) > config\update.custom.json { "ring": 2 } > 3 (broad).
        Only Community rings (2, 3) are valid here -- ring 1 is internal and is never read from the public channel.
        Returns @{ Ring; RingSource; BaseUrl; DownloadPrefix; Problems }. Never throws. config\update.custom.json may also name
        "baseUrl" (https, or a local folder for an offline rehearsal) instead of Invardia's.
    #>
    param([Parameter(Mandatory)][string]$Root, [int]$Ring = 0, [string]$BaseUrl)
    $problems = New-Object System.Collections.Generic.List[string]
    $cfg = $null
    $file = [IO.Path]::Combine($Root, 'config', 'update.custom.json')
    if (Test-Path -LiteralPath $file) {
        try { $cfg = [IO.File]::ReadAllText($file).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop }
        catch { $problems.Add(('config\update.custom.json cannot be read ({0}) -- ring {1} is used' -f $_.Exception.Message, $script:SICommunityUpdateDefaultRing)) }
    }
    $prop = { param($n) if ($cfg -and $cfg.PSObject.Properties[$n] -and "$($cfg.$n)".Trim()) { "$($cfg.$n)".Trim() } else { '' } }
    $r = $script:SICommunityUpdateDefaultRing; $src = 'default'
    if ($Ring -gt 0) { $r = $Ring; $src = 'parameter' }
    elseif (& $prop 'ring') {
        $n = 0
        if ([int]::TryParse((& $prop 'ring'), [ref]$n)) { $r = $n; $src = 'config\update.custom.json' }
        else { $problems.Add(("config\update.custom.json names ring '{0}', which is not a number -- ring {1} is used" -f (& $prop 'ring'), $script:SICommunityUpdateDefaultRing)) }
    }
    if ($script:SICommunityUpdateRings -notcontains $r) {
        $problems.Add(('ring {0} is not a Community ring (2 = early release, 3 = broad) -- ring {1} is used' -f $r, $script:SICommunityUpdateDefaultRing))
        $r = $script:SICommunityUpdateDefaultRing; $src = 'default'
    }
    $url = @($BaseUrl, (& $prop 'baseUrl')) | Where-Object { "$_".Trim() } | Select-Object -First 1
    if ($url -and "$url" -match '^http://') { $problems.Add(("the update base '{0}' is not https -- Invardia's is used" -f $url)); $url = '' }
    if (-not $url) { $url = $script:SICommunityUpdateBaseUrl }
    $prefix = & $prop 'downloadPrefix'
    if (-not $prefix) { $prefix = $script:SICommunityUpdateDownloadPrefix }
    [pscustomobject]@{ Ring = [int]$r; RingSource = $src; BaseUrl = "$url".Trim(); DownloadPrefix = $prefix; Problems = $problems.ToArray() }
}

function Get-SICommunityManifestUri {
    <# PURE. Invardia's Community route (the same one PIM's Community edition reads, 2026-10-28): <base>/api/updates/securityinsight/community/<ring>. #>
    param([Parameter(Mandatory)][string]$BaseUrl, [Parameter(Mandatory)][int]$Ring)
    '{0}/api/updates/{1}/community/{2}' -f $BaseUrl.TrimEnd('/', '\'), $script:SICommunityUpdateProduct, $Ring
}

function Invoke-SICommunityManifestHttp {
    <#
        The one anonymous GET of the Community manifest (the default GetManifest seam). Returns @{ Status; Body } -- an HTTP
        error is a status, never a throw; no answer at all throws. A base that is a local folder (tests, an offline rehearsal)
        reads <folder>\<ring>.json: present = 200, absent = 204.
    #>
    param([Parameter(Mandatory)][string]$Url)
    if ($Url -notmatch '^[a-z][a-z0-9+.-]*://' -or $Url -match '^file://') {
        $p = ($Url -replace '^file:///?', '')
        $ring = Split-Path -Leaf $p
        $file = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $p))))) ($ring + '.json')
        if (Test-Path -LiteralPath $file) { return [pscustomobject]@{ Status = 200; Body = [IO.File]::ReadAllText($file) } }
        return [pscustomobject]@{ Status = 204; Body = '' }
    }
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
    try {
        $r = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -TimeoutSec 60 -Headers @{ Accept = 'application/json'; 'Cache-Control' = 'no-cache' } -ErrorAction Stop
        [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $(if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }) }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if ($resp -and $resp.StatusCode) { return [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = '' } }
        throw
    }
}

function Read-SICommunityManifestAnswer {
    <#
        PURE. Invardia's answer -> @{ Action; Entry; Reason }: 200 + JSON = 'entry' (the signed answer { manifest, manifestB64,
        signature, keyId, downloadUrl }, checked by Test-SICommunityChannelEntry); 204 = 'none' (nothing released to the
        ring yet); 404 = 'refused' (no such ring); 200 without JSON = 'refused'; anything else = 'network' (asked again later).
    #>
    param([AllowNull()]$Answer, [int]$Ring)
    $st = if ($Answer) { [int]$Answer.Status } else { 0 }
    if ($st -eq 204) { return [pscustomobject]@{ Action = 'none'; Entry = $null; Reason = ("nothing is released to ring {0} yet" -f $Ring) } }
    if ($st -eq 404) { return [pscustomobject]@{ Action = 'refused'; Entry = $null; Reason = ("Invardia knows no Community ring {0} (404)" -f $Ring) } }
    if ($st -ne 200) { return [pscustomobject]@{ Action = 'network'; Entry = $null; Reason = ("the Community manifest answered {0}" -f $st) } }
    $e = $null; try { $e = "$($Answer.Body)".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop } catch { $e = $null }
    if (-not $e) { return [pscustomobject]@{ Action = 'refused'; Entry = $null; Reason = 'the Community manifest answer is not JSON' } }
    [pscustomobject]@{ Action = 'entry'; Entry = $e; Reason = '' }
}
function Test-SICommunityChannelEntry {
    <#
        PURE (given the keys). Everything about one ring's entry, BEFORE anything is downloaded.
        Returns @{ Action; Reason; Version; Sequence; Sha256; Size; DownloadUrl; IsRollback; ManualStep }, Action:
          update   -- verified, newer sequence, nothing holds it
          current  -- this sequence is applied already (or this install already runs the version the ring names)
          hold     -- verified, but manualStep (not accepted) or minFromVersion (this install is older) holds it
          refused  -- signature, product, kind, ring binding, replay, link or shape -- nothing moves
    #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][int]$Ring, [AllowNull()][object[]]$TrustedKeys,
          [long]$AppliedSequence = 0, [AllowEmptyString()][string]$RunningVersion = '', [long]$AcceptManualStepSequence = -1,
          [AllowEmptyString()][string]$DownloadPrefix = $script:SICommunityUpdateDownloadPrefix,
          # Invardia's ring route (/api/updates/securityinsight/community/<ring>, 2026-10-28): the URL names the ring, so a
          # manifest that carries no ring is accepted; one that names ANOTHER ring is still refused
          [switch]$RingOptional)
    $out = { param($a, $why, $v = $null)
        [pscustomobject]@{ Action = $a; Reason = $why
            Version = $(if ($v) { $v.version } else { '' }); Sequence = $(if ($v) { [long]$v.sequence } else { [long]0 })
            Sha256 = $(if ($v) { $v.sha256 } else { '' }); Size = $(if ($v) { [long]$v.size } else { [long]0 })
            DownloadUrl = $(if ($v) { $v.downloadUrl } else { '' }); IsRollback = $false
            ManualStep = $(if ($v -and $v.manifest) { "$($v.manifest.manualStep)".Trim() } else { '' }) } }
    $keys = @($TrustedKeys | Where-Object { $_ })
    $v = Test-InvardiaManifest -Response $Entry -TrustedKeys $keys -Kind $script:SICommunityUpdateKind -AppliedSequence ([int][Math]::Min([long][int]::MaxValue, [Math]::Max([long]0, $AppliedSequence))) `
            -RunningVersion $RunningVersion -Product $script:SICommunityUpdateProduct
    if (-not $v.ok) { return (& $out 'refused' $v.reason) }
    $m = $v.manifest
    # The signed ring IS the ring asked for: the ring-2 entry pasted into ring 3's slot must not reach ring 3 early.
    $signedRing = 0
    $hasRing = ($m.PSObject.Properties['ring'] -and "$($m.ring)".Trim())
    if (($hasRing -or -not $RingOptional) -and (-not [int]::TryParse("$($m.ring)", [ref]$signedRing) -or $signedRing -ne $Ring)) {
        return (& $out 'refused' ("the entry in ring {0}'s slot is signed for ring '{1}' -- refused" -f $Ring, $m.ring))
    }
    if ([long]$v.size -le 0) { return (& $out 'refused' 'the signed manifest carries no archive size') }
    if ("$DownloadPrefix".Trim() -and -not "$($v.downloadUrl)".StartsWith("$DownloadPrefix".Trim(), [StringComparison]::OrdinalIgnoreCase)) {
        return (& $out 'refused' ("the download link is not on the release host ({0})" -f "$DownloadPrefix".Trim()))
    }
    $r = & $out 'update' $v.reason $v
    if ($v.hold) {
        $ms = "$($m.manualStep)".Trim()
        if (-not $ms -or $AcceptManualStepSequence -ne [long]$v.sequence) { $r.Action = 'hold'; $r.Reason = $v.reason; return $r }
        # The manual step is accepted for exactly this sequence -- minFromVersion still holds on its own.
        $mf = "$($m.minFromVersion)".Trim()
        if ($mf -and "$RunningVersion".Trim() -and (Compare-InvardiaReleaseVersion "$RunningVersion" $mf) -lt 0) {
            $r.Action = 'hold'; $r.Reason = ("HELD -- {0} can only be installed from {1} or later; this install runs {2}" -f $v.version, $mf, $RunningVersion); return $r
        }
    }
    if ($AppliedSequence -gt 0 -and [long]$v.sequence -eq $AppliedSequence) {
        $r.Action = 'current'; $r.Reason = ("{0} (sequence {1}) is applied already" -f $v.version, $v.sequence); return $r
    }
    if ($AppliedSequence -le 0 -and "$RunningVersion".Trim() -and (Compare-InvardiaReleaseVersion "$RunningVersion" $v.version) -eq 0) {
        $r.Action = 'current'; $r.Reason = ("this install already runs {0}, the version ring {1} names (sequence {2})" -f $v.version, $Ring, $v.sequence); return $r
    }
    if ("$RunningVersion".Trim() -and (Compare-InvardiaReleaseVersion $v.version "$RunningVersion") -lt 0) {
        $r.IsRollback = $true; $r.Reason = ("ROLLBACK: ring {0} names {1} (sequence {2}), older than the {3} this install runs" -f $Ring, $v.version, $v.sequence, $RunningVersion)
    } else { $r.Reason = ("ring {0} has {1} (sequence {2})" -f $Ring, $v.version, $v.sequence) }
    $r
}

function Get-SICommunityFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create(); $fs = [System.IO.File]::OpenRead($Path)
    try { ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLowerInvariant() } finally { $fs.Dispose(); $sha.Dispose() }
}

function Get-SICommunityShippedFileHash {
    <#
        SHA-256 (lower-case hex) of a file's bytes with every CRLF read as LF -- a git checkout with autocrlf and a zip of
        the same release hash the same. -Bytes or -Path; $null when the file cannot be read.
    #>
    param([byte[]]$Bytes, [string]$Path)
    try {
        if ($Path) { $Bytes = [IO.File]::ReadAllBytes($Path) }
        if ($null -eq $Bytes) { return $null }
        if ([Array]::IndexOf($Bytes, [byte]13) -ge 0) {
            # Latin-1 maps every byte to one char and back, so this is a byte-exact CRLF -> LF
            $l1 = [System.Text.Encoding]::GetEncoding(28591)
            $Bytes = $l1.GetBytes($l1.GetString($Bytes).Replace("`r`n", "`n"))
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } catch { return $null }
}

function Get-SICommunityRetiredFiles {
    <#
        The files under -Root that earlier releases shipped, that the release being applied (-PayloadRoot, its -Files) no
        longer has, and that are still EXACTLY a shipped version (the release's retired-files list). Never a customer path.
        Returns @{ Remove (relative paths); Kept (changed copies left in place) }. No list in the release = nothing.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$PayloadRoot, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Files)
    $res = [pscustomobject]@{ Remove = @(); Kept = @() }
    $mf = [IO.Path]::Combine($PayloadRoot, $script:SICommunityRetiredManifest)
    if (-not (Test-Path -LiteralPath $mf)) { return $res }
    $doc = $null
    try { $doc = [IO.File]::ReadAllText($mf) | ConvertFrom-Json -ErrorAction Stop } catch { return $res }
    if (-not $doc -or -not $doc.PSObject.Properties['files'] -or $null -eq $doc.files) { return $res }
    $set = @{}; foreach ($f in $Files) { $set[(ConvertTo-SICommunityRelPath $f).ToLowerInvariant()] = $true }
    $remove = New-Object System.Collections.Generic.List[string]; $kept = New-Object System.Collections.Generic.List[string]
    foreach ($p in $doc.files.PSObject.Properties) {
        $rel = ConvertTo-SICommunityRelPath $p.Name
        if (-not $rel -or $rel -match '(^|/)\.\.(/|$)' -or $rel -match ':') { continue }
        if ($set.ContainsKey($rel.ToLowerInvariant()) -or (Test-SICommunityCustomerPath $rel)) { continue }
        $local = [IO.Path]::Combine($Root, $rel)
        if (-not (Test-Path -LiteralPath $local -PathType Leaf)) { continue }
        $h = Get-SICommunityShippedFileHash -Path $local
        if ($h -and (@($p.Value) -contains $h)) { $remove.Add($rel) } else { $kept.Add($rel) }
    }
    $res.Remove = @($remove.ToArray()); $res.Kept = @($kept.ToArray())
    $res
}

function Expand-SICommunityArchive {
    <#
        The release zip -> -Destination, entry by entry: either slash, no rooted path, no '..' (a zip-slip entry is refused,
        and so is the whole archive). Returns the PAYLOAD ROOT: the folder that holds VERSION (the zip's root, or its one
        top folder). Throws with the reason.
    #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$Destination)
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $destFull = [IO.Path]::GetFullPath($Destination).TrimEnd('\', '/')
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($e in $zip.Entries) {
            $name = ConvertTo-SICommunityRelPath $e.FullName
            if (-not $name -or $name.EndsWith('/')) { continue }
            if ($name -match '(^|/)\.\.(/|$)' -or $name -match ':' -or $e.FullName -match '^[\\/]') { throw ("the archive holds an unsafe path '{0}' -- refused" -f $e.FullName) }
            $target = [IO.Path]::GetFullPath([IO.Path]::Combine($destFull, $name.Replace('/', [IO.Path]::DirectorySeparatorChar)))
            if (-not $target.StartsWith($destFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw ("the archive holds an unsafe path '{0}' -- refused" -f $e.FullName) }
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true)
        }
    } finally { $zip.Dispose() }
    if (Test-Path -LiteralPath ([IO.Path]::Combine($destFull, 'VERSION'))) { return $destFull }
    $tops = @(Get-ChildItem -LiteralPath $destFull -Force)
    if ($tops.Count -eq 1 -and $tops[0].PSIsContainer -and (Test-Path -LiteralPath ([IO.Path]::Combine($tops[0].FullName, 'VERSION')))) { return $tops[0].FullName }
    throw 'the archive holds no VERSION file -- it is not a SecurityInsight release'
}

function Get-SICommunityPayloadFiles {
    <# The release's files (relative, '/'), customer-owned names left out. #>
    param([Parameter(Mandatory)][string]$PayloadRoot)
    $base = [IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\', '/')
    @(Get-ChildItem -LiteralPath $base -Recurse -File -Force | ForEach-Object { ConvertTo-SICommunityRelPath ($_.FullName.Substring($base.Length)) } |
        Where-Object { -not (Test-SICommunityCustomerPath $_) } | Sort-Object)
}

function Test-SICommunityInstallHealth {
    <#
        The installed folder after the files were written: VERSION is the signed version; every release file is on disk with
        the release's hash; every PowerShell file parses; the update client is still there (else the install could never
        update again). Returns @{ Ok; Reason }.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$PayloadRoot, [Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)][string]$Version)
    $have = Get-SICommunityRunningVersion -Root $Root
    if ($have -ne $Version) { return [pscustomobject]@{ Ok = $false; Reason = ("VERSION reads '{0}', the release is {1}" -f $have, $Version) } }
    foreach ($c in $script:SICommunityUpdateClientFiles) {
        if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($Root, $c)))) { return [pscustomobject]@{ Ok = $false; Reason = ("the update client file {0} is missing" -f $c) } }
    }
    foreach ($rel in $Files) {
        $dst = [IO.Path]::Combine($Root, $rel); $src = [IO.Path]::Combine($PayloadRoot, $rel)
        if (-not (Test-Path -LiteralPath $dst)) { return [pscustomobject]@{ Ok = $false; Reason = ("{0} is missing after the update" -f $rel) } }
        if ((Get-SICommunityFileSha256 $dst) -ne (Get-SICommunityFileSha256 $src)) { return [pscustomobject]@{ Ok = $false; Reason = ("{0} is not the release's file after the update" -f $rel) } }
        if ($rel -match '(?i)\.ps(m|d)?1$') {
            $tok = $null; $err = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($dst, [ref]$tok, [ref]$err)
            if ($err -and @($err).Count) { return [pscustomobject]@{ Ok = $false; Reason = ("{0} does not parse: {1}" -f $rel, @($err)[0].Message) } }
        }
    }
    [pscustomobject]@{ Ok = $true; Reason = '' }
}

# =====================================================================================================================
#  State
# =====================================================================================================================
function Get-SICommunityStateDir { param([Parameter(Mandatory)][string]$Root) [IO.Path]::Combine($Root, $script:SICommunityUpdateStateFolder) }

function Read-SICommunityUpdateState {
    param([Parameter(Mandatory)][string]$Root)
    $s = [ordered]@{ ring = 0; appliedSequence = [long]0; appliedVersion = ''; appliedUtc = ''; lastCheckUtc = ''; lastAction = ''; lastReason = '' }
    $f = [IO.Path]::Combine((Get-SICommunityStateDir $Root), 'state.json')
    if (Test-Path -LiteralPath $f) {
        try {
            $j = [IO.File]::ReadAllText($f) | ConvertFrom-Json -ErrorAction Stop
            foreach ($k in @($s.Keys)) { if ($j.PSObject.Properties[$k] -and $null -ne $j.$k) { $s[$k] = $j.$k } }
            $n = [long]0; [void][long]::TryParse("$($s.appliedSequence)", [ref]$n); $s.appliedSequence = $n
        } catch { }
    }
    $s
}

function Write-SICommunityUpdateState {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)]$State)
    $d = Get-SICommunityStateDir $Root
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    [IO.File]::WriteAllText([IO.Path]::Combine($d, 'state.json'), (ConvertTo-Json -InputObject $State -Depth 4))
}

function Read-SICommunityInstalledFiles {
    <# The files the last update installed ($null when no update by this client has run yet). #>
    param([Parameter(Mandatory)][string]$Root)
    $f = [IO.Path]::Combine((Get-SICommunityStateDir $Root), 'installed-files.txt')
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    , @([IO.File]::ReadAllLines($f) | Where-Object { "$_".Trim() } | ForEach-Object { ConvertTo-SICommunityRelPath "$_".Trim() })
}

# =====================================================================================================================
#  Seams (default: the real machine) -- every call that leaves the process
# =====================================================================================================================
function New-SICommunityUpdateSeams {
    @{
        GetManifest = { param($Url) Invoke-SICommunityManifestHttp -Url $Url }
        Download = { param($Url, $OutFile)
            try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop | Out-Null }
        GetTasks = {
            param($Root)
            if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) { return @() }
            @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
                $a = @($_.Actions)[0]
                [pscustomobject]@{ TaskPath = [string]$_.TaskPath; TaskName = [string]$_.TaskName; State = [string]$_.State
                                   Execute = $(if ($a) { [string]$a.Execute } else { '' }); Arguments = $(if ($a) { [string]$a.Arguments } else { '' }) } }) }
        DisableTask = { param($t) Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null }
        EnableTask  = { param($t) Enable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null }
        # The NEW release's container step, in a fresh process (the new code, not this process's loaded functions).
        ContainerUpdate = { param($Root)
            $hook = [IO.Path]::Combine($Root, 'setup', 'Invoke-SIContainerUpdate.ps1')
            if (-not (Test-Path -LiteralPath $hook)) { return 0 }
            $exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            & $exe -NoProfile -ExecutionPolicy Bypass -File $hook -Apply | ForEach-Object { Write-Host "    $_" }
            $LASTEXITCODE }
        # Optional extra health check after the files: { param($Root, $Version) } -> @{ Ok; Reason }
        HealthCheck = $null
        Now = { [datetime]::UtcNow }
    }
}

function Get-SICommunityUpdateTaskPlan {
    <#
        PURE. The scheduled tasks of THIS install: under \SecurityInsight\, or whose action names this folder.
          Self    -- the task that runs this update (Update-SecurityInsight.ps1, or the job flow that runs it as a step):
                     never a blocker, never paused.
          Busy    -- another of this install's tasks is RUNNING: an engine mid-run -> the update waits for the next run.
          Pause   -- Ready tasks, paused while the files are swapped and resumed afterwards (also after a rollback).
        Disabled tasks are left exactly as they are.
    #>
    param([AllowNull()][object[]]$Tasks, [Parameter(Mandatory)][string]$Root)
    $rootText = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $mine = @($Tasks | Where-Object { $_ } | Where-Object {
        ("$($_.TaskPath)" -like '\SecurityInsight\*') -or ("$($_.Arguments) $($_.Execute)".IndexOf($rootText, [StringComparison]::OrdinalIgnoreCase) -ge 0) })
    $isSelf = { param($t) "$($t.Arguments) $($t.Execute)" -match '(?i)Update-SecurityInsight\.ps1|Invoke-SIJobFlowRun\.ps1' }
    [pscustomobject]@{
        Self  = @($mine | Where-Object { & $isSelf $_ })
        Busy  = @($mine | Where-Object { -not (& $isSelf $_) -and "$($_.State)" -eq 'Running' })
        Pause = @($mine | Where-Object { -not (& $isSelf $_) -and "$($_.State)" -eq 'Ready' })
    }
}

# =====================================================================================================================
#  Apply on the VM folder: backup -> write -> health -> (container) -> commit, or restore
# =====================================================================================================================
function Invoke-SICommunityFileApply {
    <#
        Writes the release (-PayloadRoot, -Files) over -Root. Every file that is replaced or removed is backed up first;
        files in -PreviousFiles (what the last update installed) that the release no longer has are removed; with no
        previous list only -RetiredFiles are removed (unchanged copies of files earlier releases shipped,
        Get-SICommunityRetiredFiles) -- backed up and restored like the rest.
        Then the health check, then -AfterApply { } -> 0 / exit code (the container step). ANY failure restores the backup,
        removes what was added, and VERIFIES the restore. Returns @{ Ok; RolledBack; Reason; Added; Replaced; Removed; Kept }.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$PayloadRoot, [Parameter(Mandatory)][string[]]$Files,
          [Parameter(Mandatory)][string]$Version, [AllowNull()][string[]]$PreviousFiles, [Parameter(Mandatory)][string]$BackupDir,
          [scriptblock]$HealthCheck, [scriptblock]$AfterApply, [AllowEmptyCollection()][string[]]$RetiredFiles = @())
    $added = New-Object System.Collections.Generic.List[string]
    $backed = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $set = @{}; foreach ($f in $Files) { $set[$f.ToLowerInvariant()] = $true }
    $toRemove = @()
    if ($null -ne $PreviousFiles) {
        $toRemove = @($PreviousFiles | Where-Object { -not $set.ContainsKey($_.ToLowerInvariant()) -and -not (Test-SICommunityCustomerPath $_) -and (Test-Path -LiteralPath ([IO.Path]::Combine($Root, $_))) })
    }
    $seen = @{}; foreach ($r in $toRemove) { $seen[$r.ToLowerInvariant()] = $true }
    foreach ($r in @($RetiredFiles)) {
        $r = ConvertTo-SICommunityRelPath $r
        if (-not $r -or $seen.ContainsKey($r.ToLowerInvariant()) -or $set.ContainsKey($r.ToLowerInvariant()) -or (Test-SICommunityCustomerPath $r)) { continue }
        if (Test-Path -LiteralPath ([IO.Path]::Combine($Root, $r))) { $toRemove += $r; $seen[$r.ToLowerInvariant()] = $true }
    }
    $res = [pscustomobject]@{ Ok = $false; RolledBack = $false; Reason = ''; Added = 0; Replaced = 0; Removed = 0; Kept = 0 }
    $restore = {
        param($why)
        $problems = New-Object System.Collections.Generic.List[string]
        foreach ($a in $added) { try { Remove-Item -LiteralPath ([IO.Path]::Combine($Root, $a)) -Force -ErrorAction Stop } catch { $problems.Add($a) } }
        foreach ($b in $backed) {
            try {
                $dst = [IO.Path]::Combine($Root, $b); New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
                Copy-Item -LiteralPath ([IO.Path]::Combine($BackupDir, $b)) -Destination $dst -Force -ErrorAction Stop
                if ((Get-SICommunityFileSha256 $dst) -ne (Get-SICommunityFileSha256 ([IO.Path]::Combine($BackupDir, $b)))) { $problems.Add($b) }
            } catch { $problems.Add($b) }
        }
        $res.RolledBack = ($problems.Count -eq 0)
        $res.Reason = if ($problems.Count -eq 0) { "$why -- the previous version was restored and verified" }
                      else { "$why -- AND THE RESTORE IS INCOMPLETE for $($problems.Count) file(s) (first: $($problems[0])); the backup is kept in $BackupDir" }
    }
    try {
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        foreach ($rel in @($Files) + @($toRemove)) {
            $dst = [IO.Path]::Combine($Root, $rel)
            if (Test-Path -LiteralPath $dst) {
                $bk = [IO.Path]::Combine($BackupDir, $rel); New-Item -ItemType Directory -Force -Path (Split-Path -Parent $bk) | Out-Null
                Copy-Item -LiteralPath $dst -Destination $bk -Force -ErrorAction Stop
                $backed.Add($rel)
            }
        }
    } catch { $res.Reason = ("the backup could not be made ({0}) -- nothing was changed" -f $_.Exception.Message); return $res }
    try {
        foreach ($rel in $Files) {
            $dst = [IO.Path]::Combine($Root, $rel)
            $existed = Test-Path -LiteralPath $dst
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            Copy-Item -LiteralPath ([IO.Path]::Combine($PayloadRoot, $rel)) -Destination $dst -Force -ErrorAction Stop
            if ($existed) { $res.Replaced++ } else { $added.Add($rel) }
        }
        foreach ($rel in $toRemove) { Remove-Item -LiteralPath ([IO.Path]::Combine($Root, $rel)) -Force -ErrorAction Stop; $removed.Add($rel) }
    } catch { & $restore ("writing the release failed ({0})" -f $_.Exception.Message); return $res }
    $h = Test-SICommunityInstallHealth -Root $Root -PayloadRoot $PayloadRoot -Files $Files -Version $Version
    if ($h.Ok -and $HealthCheck) { try { $h = & $HealthCheck $Root $Version } catch { $h = [pscustomobject]@{ Ok = $false; Reason = $_.Exception.Message } } }
    if (-not $h.Ok) { & $restore ("the health check failed: {0}" -f $h.Reason); return $res }
    if ($AfterApply) {
        $code = 1
        try { $code = [int](& $AfterApply) } catch { $code = 1 }
        if ($code -ne 0) { & $restore ("the container update failed (exit {0}; it restores the containers' previous image itself)" -f $code); return $res }
    }
    $res.Ok = $true; $res.Added = $added.Count; $res.Removed = $removed.Count
    $res
}

# =====================================================================================================================
#  The update run
# =====================================================================================================================
function Invoke-SICommunityUpdate {
    <#
        One update run of a Community install. Returns @{ Action; Reason; Ring; FromVersion; ToVersion; Sequence; Log }.
        Action: updated | current | none | hold | waiting | refused | network | rolledback | error | not-community.
        Exit-code meaning for the caller: refused / rolledback / network / error are failures; the rest are not.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [int]$Ring = 0, [string]$BaseUrl, [long]$AcceptManualStepSequence = -1,
          [switch]$SkipContainerUpdate, [System.Collections.IDictionary]$Seams = @{}, [AllowNull()][object[]]$TrustedKeys)
    $s = New-SICommunityUpdateSeams
    foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] }
    $keys = if ($PSBoundParameters.ContainsKey('TrustedKeys')) { @($TrustedKeys) } else { @($script:SICommunityTrustedKeys) }
    $log = New-Object System.Collections.Generic.List[string]
    $Root = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $from = Get-SICommunityRunningVersion -Root $Root
    $res = [pscustomobject]@{ Action = 'error'; Reason = ''; Ring = 0; FromVersion = $from; ToVersion = $from; Sequence = [long]0; Log = $log }
    $done = { param($a, $why) $res.Action = $a; $res.Reason = $why; $log.Add(("{0}: {1}" -f $a, $why)); $res }
    $state = $null; $paused = @()
    try {
        $kind = Get-SICommunityInstallKind -Root $Root
        if ($kind -eq 'sync') { return (& $done 'not-community' 'this folder is part of an AutomateIT tree -- Sync-AutomateIT updates it; the community channel is not used here') }
        if ($kind -eq 'private') { return (& $done 'not-community' 'this folder holds SecurityInsight Pro -- it is updated by the Pro updater (from Invardia) or by Sync-AutomateIT; the community channel would replace it with the public edition') }
        $cfg = Get-SICommunityUpdateSettings -Root $Root -Ring $Ring -BaseUrl $BaseUrl
        foreach ($p in $cfg.Problems) { $log.Add("note: $p") }
        $res.Ring = $cfg.Ring
        $log.Add(("this install: {0}, ring {1} ({2})" -f $(if ($from) { $from } else { 'unknown version' }), $cfg.Ring, $cfg.RingSource))
        if (Test-Path -LiteralPath ([IO.Path]::Combine($Root, '.git'))) {
            $log.Add('note: this folder is also a git clone. This command keeps it current from the signed channel; a scheduled "git pull" here stops working once an update moves it past the public main branch (git then reports local changes) -- remove that scheduled pull.')
        }
        $state = Read-SICommunityUpdateState -Root $Root
        $state.lastCheckUtc = ([datetime](& $s.Now)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        # ---- 1. the Community manifest of this ring, from Invardia (anonymous) ----
        $ans = $null
        try { $ans = & $s.GetManifest (Get-SICommunityManifestUri -BaseUrl $cfg.BaseUrl -Ring $cfg.Ring) } catch { return (& $done 'network' ("the Community manifest could not be read: {0} -- nothing changed; the next run asks again" -f $_.Exception.Message)) }
        $rd = Read-SICommunityManifestAnswer -Answer $ans -Ring $cfg.Ring
        if ($rd.Action -eq 'none') { return (& $done 'none' ("{0} -- this install stays on {1}" -f $rd.Reason, $from)) }
        if ($rd.Action -eq 'network') { return (& $done 'network' ("{0} -- nothing changed; the next run asks again" -f $rd.Reason)) }
        if ($rd.Action -eq 'refused') { return (& $done 'refused' ("{0} -- nothing changed" -f $rd.Reason)) }
        $entry = $rd.Entry

        # ---- 2. verify before anything is downloaded ----
        $chk = Test-SICommunityChannelEntry -Entry $entry -Ring $cfg.Ring -TrustedKeys $keys -AppliedSequence ([long]$state.appliedSequence) `
                    -RunningVersion $from -AcceptManualStepSequence $AcceptManualStepSequence -DownloadPrefix $cfg.DownloadPrefix -RingOptional
        $res.Sequence = $chk.Sequence
        if ($chk.Action -eq 'refused') { return (& $done 'refused' ("{0} -- nothing changed" -f $chk.Reason)) }
        if ($chk.Action -eq 'hold') { return (& $done 'hold' ("{0} -- this install stays on {1}" -f $chk.Reason, $from)) }
        if ($chk.Action -eq 'current') {
            if ([long]$state.appliedSequence -lt $chk.Sequence) { $state.appliedSequence = $chk.Sequence; $state.appliedVersion = $chk.Version; $state.ring = $cfg.Ring }
            return (& $done 'current' $chk.Reason)
        }
        # owner 2026-10-28: a release of ANOTHER MAJOR VERSION is never installed as an update (a new major version is a new
        # installation beside the old one) -- refused before anything is downloaded
        $mj = Test-SICommunityMajorVersion -Installed $from -Release ([string]$chk.Version)
        if ($mj) { return (& $done 'refused' ("{0} -- nothing changed" -f $mj)) }
        $log.Add($chk.Reason)

        # ---- 3. an engine mid-run? wait for the next run ----
        $plan = Get-SICommunityUpdateTaskPlan -Tasks @(& $s.GetTasks $Root) -Root $Root
        if (@($plan.Busy).Count) { return (& $done 'waiting' ("{0} is running ({1}) -- the update waits for the next run; nothing changed" -f (@($plan.Busy | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join ', '), $chk.Version)) }

        # ---- 4. download + prove it is the signed archive ----
        # SHORT paths: Windows PowerShell 5.1 cannot write a path over 260 characters, and a release path is up to ~170 long.
        $work = [IO.Path]::Combine((Get-SICommunityStateDir $Root), 'w')
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        $zip = [IO.Path]::Combine($work, 'r.zip')
        try { & $s.Download $chk.DownloadUrl $zip | Out-Null } catch { return (& $done 'network' ("the release could not be downloaded: {0} -- nothing changed" -f $_.Exception.Message)) }
        $a = Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $chk.Sha256 -ExpectedSize $chk.Size
        if (-not $a.ok) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue; return (& $done 'refused' ("{0} -- nothing changed" -f $a.reason)) }
        $payload = $null
        try { $payload = Expand-SICommunityArchive -ZipPath $zip -Destination ([IO.Path]::Combine($work, 'p')) } catch { return (& $done 'refused' ("{0} -- nothing changed" -f $_.Exception.Message)) }
        $pv = Get-SICommunityRunningVersion -Root $payload
        if ($pv -ne $chk.Version) { return (& $done 'refused' ("the archive says it is {0}, the signed manifest names {1} -- nothing changed" -f $pv, $chk.Version)) }
        $files = Get-SICommunityPayloadFiles -PayloadRoot $payload
        foreach ($c in $script:SICommunityUpdateClientFiles) {
            if (@($files) -notcontains $c) { return (& $done 'refused' ("the release does not carry the update client ({0}) -- installing it would end updates for this install; nothing changed" -f $c)) }
        }

        # ---- 5. apply by host ----
        foreach ($t in @($plan.Pause)) { try { & $s.DisableTask $t; $paused += $t } catch { $log.Add(("note: {0}{1} could not be paused: {2}" -f $t.TaskPath, $t.TaskName, $_.Exception.Message)) } }
        $previous = Read-SICommunityInstalledFiles -Root $Root
        $backup = [IO.Path]::Combine((Get-SICommunityStateDir $Root), 'b', $(if ($from) { $from } else { 'unknown' }))
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue }
        $after = $null
        if (-not $SkipContainerUpdate) { $cu = $s.ContainerUpdate; $rootForHook = $Root; $after = { & $cu $rootForHook }.GetNewClosure() }
        # The first update by this client: no list of what an update installed, so the files an earlier release shipped and
        # this one no longer has are found by the release's retired-files list -- removed only when unchanged.
        $retired = [pscustomobject]@{ Remove = @(); Kept = @() }
        if ($null -eq $previous) { $retired = Get-SICommunityRetiredFiles -Root $Root -PayloadRoot $payload -Files $files }
        $apply = Invoke-SICommunityFileApply -Root $Root -PayloadRoot $payload -Files $files -Version $chk.Version -PreviousFiles $previous -BackupDir $backup -HealthCheck $s.HealthCheck -AfterApply $after -RetiredFiles @($retired.Remove)
        if (-not $apply.Ok) {
            $state.lastAction = 'rolledback'; $state.lastReason = $apply.Reason
            return (& $done $(if ($apply.RolledBack -or -not $apply.Reason.Contains('INCOMPLETE')) { 'rolledback' } else { 'error' }) $apply.Reason)
        }
        $state.appliedSequence = $chk.Sequence; $state.appliedVersion = $chk.Version; $state.ring = $cfg.Ring
        $state.appliedUtc = ([datetime](& $s.Now)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $d = Get-SICommunityStateDir $Root; New-Item -ItemType Directory -Force -Path $d | Out-Null
        [IO.File]::WriteAllLines([IO.Path]::Combine($d, 'installed-files.txt'), [string[]]@($files))
        # keep ONE backup: the version just replaced
        foreach ($old in @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($d, 'b')) -Directory -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $backup })) { Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        $res.ToVersion = $chk.Version
        if ($null -eq $previous) {
            $log.Add(('note: this was the first update by the signed channel; {0} file(s) of the previous version that this release no longer has were removed (unchanged shipped files; kept in the backup)' -f @($retired.Remove).Count))
            if (@($retired.Kept).Count) { $log.Add(('note: {0} file(s) of the previous version that this release no longer has were left in place because they were changed (first: {1}); delete them when you no longer need them' -f @($retired.Kept).Count, @($retired.Kept)[0])) }
        }
        $why = ("{0} -> {1} (ring {2}, sequence {3}): {4} replaced, {5} added, {6} removed; your *.custom.* files and run output were not touched; the previous version is kept in {7}" -f
                $from, $chk.Version, $cfg.Ring, $chk.Sequence, $apply.Replaced, $apply.Added, $apply.Removed, $backup)
        return (& $done 'updated' $why)
    } catch {
        return (& $done 'error' ("the update did not complete: {0}" -f $_.Exception.Message))
    } finally {
        foreach ($t in $paused) { try { & $s.EnableTask $t } catch { $log.Add(("WARNING: {0}{1} could not be resumed: {2} -- enable it by hand" -f $t.TaskPath, $t.TaskName, $_.Exception.Message)) } }
        if ($state) {
            if (-not $state.lastAction -or $state.lastAction -ne 'rolledback' -or $res.Action -ne 'rolledback') { $state.lastAction = $res.Action; $state.lastReason = $res.Reason }
            try { Write-SICommunityUpdateState -Root $Root -State $state } catch { $log.Add(("WARNING: the update state could not be saved: {0}" -f $_.Exception.Message)) }
        }
    }
}
