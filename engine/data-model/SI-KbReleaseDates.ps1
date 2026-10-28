#Requires -Version 5.1
<#
    #772 THE RELEASE DATE OF A MICROSOFT UPDATE, PER KB -- for the patch cycle (owner 2026-10-19: "yes, read the fix release
    date from defender").

    WHY HERE AND NOT FROM DEFENDER. None of the Defender vulnerability sources SI reads names when a FIX was released:
      DeviceTvmSoftwareVulnerabilities     RecommendedSecurityUpdate (a name) + RecommendedSecurityUpdateId (the KB) -- no date
      DeviceTvmSoftwareVulnerabilitiesKB   PublishedDate / LastModifiedTime are the CVE's (si_published), not the fix's
      GET /api/vulnerabilities             publishedOn / updatedOn / firstDetected -- the CVE's
      GET /api/recommendations             recommendedVersion, remediationType, status -- no date
      GET machines/{id}/getmissingkbs      id (KB), name, osBuild, url, machineMissedOn, cveAddressed -- no date (SI does not call it)
      Exposure Graph                       the CVE / device nodes -- no fix date
    Microsoft's public Security Update Guide does: the CVRF v3.0 API (https://api.msrc.microsoft.com/cvrf/v3.0, public, no
    sign-in) lists one document per release (2026-Oct, and an out-of-band release as its own document) with its release
    date, and every document names the KB of each vendor fix (Remediations, Type 2 = Vendor Fix, Description = the KB
    number). A KB's release date = the release date of the earliest document that names it (a remediation's own Date wins
    when it carries one).

    ONCE PER RUN, CACHED IN THE INSTALL, NEVER PER FINDING: Pro keeps the dates in sidata.KbReleaseDate (one row per KB + a
    state row), Community in a file (SettingsPath\OUTPUT\msrc-kb-release-dates.json). A cache read within the last day is
    used as it is; else the update list is read once, and only the documents of the last 24 months that are new or revised since the cache are read. An update older than that window keeps the name rule (its
    month's Patch Tuesday) -- it is catch-up either way.

    OFF / NO NETWORK: SI_PatchCycle_MsrcDates (default on) off = no call at all; a call that fails (no network, a private
    network that does not allow api.msrc.microsoft.com, a proxy) is said in ONE line and the patch cycle uses what the cache
    holds and, for the rest, the update names' Patch Tuesday. REST only (Invoke-RestMethod), no module. PowerShell 5.1.
#>

$script:SIMsrcBase = 'https://api.msrc.microsoft.com/cvrf/v3.0'
$script:SIKbReleaseDates = $null

function Test-SIMsrcDatesOn {
    <# PURE over the setting. SI_PatchCycle_MsrcDates: on unless off / false / 0 / no. #>
    param($Setting = $global:SI_PatchCycle_MsrcDates)
    if ($null -eq $Setting -or -not ([string]$Setting).Trim()) { return $true }
    ([string]$Setting).Trim().ToLowerInvariant() -notin 'off', 'false', '0', 'no', '$false'
}

function Get-SIMsrcMonths {
    <# PURE. How many months back the release documents are read: 24 -- an update older than that is catch-up whichever
       date it has, and its name's Patch Tuesday says so. #>
    24
}

function ConvertTo-SIKbKey {
    <# PURE. 'KB5127648' / '5127648' / 'kb 5127648' -> 'KB5127648'; '' when it is not a KB number. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $m = [regex]::Match($Value.Trim(), '^(?i)(?:KB\s*)?(\d{6,8})$')
    if ($m.Success) { return 'KB' + $m.Groups[1].Value }
    ''
}

function Get-SIKbKeysFromText {
    <# PURE. Every KB number a text names ("... (KB5127648)", "KB5127648;KB5127649"), in order, once each. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $out = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Text)) { return , $out.ToArray() }
    foreach ($m in [regex]::Matches($Text, '(?i)\bKB\s*(\d{6,8})\b')) { $k = 'KB' + $m.Groups[1].Value; if (-not $out.Contains($k)) { $out.Add($k) } }
    foreach ($p in $Text.Split(';')) { $k = ConvertTo-SIKbKey $p; if ($k -and -not $out.Contains($k)) { $out.Add($k) } }
    , $out.ToArray()
}

function ConvertTo-SIMsrcDate {
    <# PURE. A CVRF date (ISO text or a parsed datetime) as a UTC date, or $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().Date }
    $o = [datetime]::MinValue
    if ([datetime]::TryParse(([string]$Value), [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal), [ref]$o)) { return [datetime]::SpecifyKind($o.Date, [System.DateTimeKind]::Utc) }
    $null
}

function ConvertTo-SIMsrcStamp {
    <# PURE. A document's revision time as one invariant text (ISO, UTC) -- the same whether JSON gave text or a parsed date. #>
    param($Value)
    $d = ConvertTo-SIMsrcDateTime $Value
    if ($null -eq $d) { return [string]$Value }
    $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-SIMsrcUpdateList {
    <# PURE. The /updates answer -> the release documents: Id, Release (InitialReleaseDate), Current (CurrentReleaseDate), Url. #>
    param($Answer)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($Answer.value)) {
        if ($null -eq $u -or -not $u.ID) { continue }
        $list.Add([pscustomobject]@{ Id = [string]$u.ID; Release = (ConvertTo-SIMsrcDate $u.InitialReleaseDate); Current = (ConvertTo-SIMsrcStamp $u.CurrentReleaseDate)
                                     Url = (Get-SIMsrcDocumentUrl -Id ([string]$u.ID) -CvrfUrl $u.CvrfUrl) })
    }
    , $list.ToArray()
}

function Get-SIMsrcDocumentUrl {
    <# PURE. The address of one release document: the answer's own CvrfUrl when it is a whole https address with a host,
       else built from the API's base and the document id. A link that is relative ('/cvrf/v3.0/cvrf/2026-Oct', 'cvrf/...'),
       empty, padded with blanks or without a host ('https:///cvrf/...') made "Invalid URI: The hostname could not be parsed"
       and stopped the whole read. #>
    param([string]$Id, $CvrfUrl)
    $raw = ([string]$CvrfUrl).Trim()
    $u = $null
    if ($raw -and [uri]::TryCreate($raw, [UriKind]::Absolute, [ref]$u) -and $u.Scheme -in 'https', 'http' -and $u.Host) { return $u.AbsoluteUri }
    $base = [uri]($script:SIMsrcBase.TrimEnd('/') + '/')
    if ($raw -and -not ($raw -match '^[a-z][a-z0-9+.-]*:')) {
        # a relative link: against the API's host when it starts with '/', else under the API's base
        $rel = $null
        if ([uri]::TryCreate($base, $raw, [ref]$rel) -and $rel.Host) { return $rel.AbsoluteUri }
    }
    '{0}/cvrf/{1}' -f $script:SIMsrcBase.TrimEnd('/'), [uri]::EscapeDataString(([string]$Id).Trim())
}

function ConvertFrom-SIMsrcDocument {
    <# PURE. One CVRF document -> KB -> its release date (the remediation's own Date, else the document's release date). #>
    param($Document, $Release)
    $out = @{}
    $docDate = $Release
    if ($null -eq $docDate -and $Document.DocumentTracking) { $docDate = ConvertTo-SIMsrcDate $Document.DocumentTracking.InitialReleaseDate }
    foreach ($v in @($Document.Vulnerability)) {
        foreach ($r in @($v.Remediations)) {
            if ($null -eq $r) { continue }
            # Type 2 = Vendor Fix (a KB); a mitigation / workaround names none
            if ($null -ne $r.Type -and [string]$r.Type -notin '2', 'Vendor Fix') { continue }
            $kb = ''
            if ($r.Description) { $kb = ConvertTo-SIKbKey ([string]$(if ($r.Description.Value) { $r.Description.Value } else { $r.Description })) }
            if (-not $kb) { continue }
            $d = $null
            foreach ($n in 'Date', 'ReleaseDate') { if ($r.PSObject.Properties[$n] -and $r.$n) { $d = ConvertTo-SIMsrcDate $r.$n; if ($d) { break } } }
            if ($null -eq $d) { $d = $docDate }
            if ($null -eq $d) { continue }
            if (-not $out.ContainsKey($kb) -or $d -lt $out[$kb]) { $out[$kb] = $d }
        }
    }
    $out
}

function Merge-SIKbReleaseDates {
    <# PURE. KB dates into the cache's map: the EARLIER date of a KB wins (its first release). #>
    param([hashtable]$Into, [hashtable]$From)
    foreach ($k in @($From.Keys)) { $d = $From[$k]; if ($null -eq $d) { continue }; if (-not $Into.ContainsKey($k) -or $d -lt $Into[$k]) { $Into[$k] = $d } }
    $Into
}

function New-SIKbDateFileStore {
    <# The Community cache: one JSON file { fetchedAt, documents: { id: currentReleaseDate }, kbs: { KB: 'yyyy-MM-dd' } }. -Path '' = memory only. #>
    param([string]$Path)
    $s = [pscustomobject]@{ Kind = 'file'; Path = $Path }
    $s | Add-Member -MemberType ScriptMethod -Name Load -Value {
        $c = @{ FetchedAt = $null; Documents = @{}; Kbs = @{} }
        if (-not $this.Path -or -not (Test-Path -LiteralPath $this.Path)) { return $c }
        try {
            $j = Get-Content -Raw -LiteralPath $this.Path | ConvertFrom-Json
            $c.FetchedAt = ConvertTo-SIMsrcDateTime $j.fetchedAt
            if ($j.documents) { foreach ($p in $j.documents.PSObject.Properties) { $c.Documents[$p.Name] = ConvertTo-SIMsrcStamp $p.Value } }
            if ($j.kbs) { foreach ($p in $j.kbs.PSObject.Properties) { $d = ConvertTo-SIMsrcDate $p.Value; if ($d) { $c.Kbs[$p.Name] = $d } } }
        } catch { }
        $c
    }
    $s | Add-Member -MemberType ScriptMethod -Name Save -Value {
        param($c)
        if (-not $this.Path) { return }
        $kbs = [ordered]@{}; foreach ($k in @($c.Kbs.Keys | Sort-Object)) { $kbs[$k] = ([datetime]$c.Kbs[$k]).ToString('yyyy-MM-dd') }
        $doc = [ordered]@{ fetchedAt = ([datetime]$c.FetchedAt).ToUniversalTime().ToString('o'); documents = $c.Documents; kbs = $kbs }
        $dir = Split-Path -Parent $this.Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        [IO.File]::WriteAllText($this.Path, ($doc | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding($false)))
    }
    $s
}

function ConvertTo-SIMsrcDateTime {
    <# PURE. A date-time (ISO text or a datetime) as UTC, or $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
    $o = [datetime]::MinValue
    if ([datetime]::TryParse(([string]$Value), [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal), [ref]$o)) { return [datetime]::SpecifyKind($o, [System.DateTimeKind]::Utc) }
    $null
}

function Get-SIKbDateSqlReadSql {
    <# Pro: the cached dates (sidata.KbReleaseDate; the state row Kb = '$state' carries the fetch time and the documents read). #>
    "IF OBJECT_ID('sidata.KbReleaseDate') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(16)) AS Kb, CAST(NULL AS DATE) AS ReleaseDate, CAST(NULL AS NVARCHAR(MAX)) AS Detail, CAST(NULL AS DATETIME2(0)) AS UpdatedAt WHERE 1 = 0; RETURN; END
SELECT Kb, ReleaseDate, Detail, UpdatedAt FROM sidata.KbReleaseDate;"
}

function Get-SIKbDateSqlWriteSql {
    <# Pro: the whole cache in ONE statement (@j = [{Kb, ReleaseDate, Detail}]); a KB keeps its earliest date. #>
    @'
IF OBJECT_ID('sidata.KbReleaseDate') IS NULL BEGIN SELECT 0; RETURN; END
SET XACT_ABORT ON;
BEGIN TRAN;
MERGE sidata.KbReleaseDate AS t
USING (SELECT Kb, TRY_CONVERT(date, ReleaseDate) AS ReleaseDate, Detail FROM OPENJSON(@j) WITH (Kb nvarchar(16), ReleaseDate nvarchar(10), Detail nvarchar(max) '$.Detail')) AS s
ON t.Kb = s.Kb
WHEN MATCHED THEN UPDATE SET ReleaseDate = CASE WHEN s.Kb = N'$state' OR t.ReleaseDate IS NULL OR s.ReleaseDate < t.ReleaseDate THEN s.ReleaseDate ELSE t.ReleaseDate END,
                             Detail = s.Detail, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Kb, ReleaseDate, Detail, UpdatedAt) VALUES (s.Kb, s.ReleaseDate, s.Detail, SYSUTCDATETIME());
COMMIT;
SELECT @@ROWCOUNT;
'@
}

function New-SIKbDateSqlStore {
    <# The Pro cache in sidata.KbReleaseDate, through the run's SQL invoke (& $Invoke $sql $params 'reader' | 'scalar'). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $s = [pscustomobject]@{ Kind = 'sql'; Invoke = $Invoke }
    $s | Add-Member -MemberType ScriptMethod -Name Load -Value {
        $c = @{ FetchedAt = $null; Documents = @{}; Kbs = @{} }
        foreach ($r in @(& $this.Invoke (Get-SIKbDateSqlReadSql) @{} 'reader')) {
            if ($null -eq $r) { continue }
            $kb = [string]$r.Kb
            if ($kb -eq '$state') {
                $c.FetchedAt = ConvertTo-SIMsrcDateTime ([string]$r.UpdatedAt)
                try { $j = ([string]$r.Detail) | ConvertFrom-Json; foreach ($p in $j.PSObject.Properties) { $c.Documents[$p.Name] = ConvertTo-SIMsrcStamp $p.Value } } catch { }
                continue
            }
            $d = ConvertTo-SIMsrcDate $r.ReleaseDate; if ($kb -and $d) { $c.Kbs[$kb] = $d }
        }
        $c
    }
    $s | Add-Member -MemberType ScriptMethod -Name Save -Value {
        param($c)
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($k in @($c.Kbs.Keys)) { $rows.Add([ordered]@{ Kb = [string]$k; ReleaseDate = ([datetime]$c.Kbs[$k]).ToString('yyyy-MM-dd'); Detail = $null }) }
        $rows.Add([ordered]@{ Kb = '$state'; ReleaseDate = ([datetime]$c.FetchedAt).ToString('yyyy-MM-dd'); Detail = ($c.Documents | ConvertTo-Json -Compress -Depth 3) })
        $null = & $this.Invoke (Get-SIKbDateSqlWriteSql) @{ j = (ConvertTo-Json -InputObject $rows.ToArray() -Compress -Depth 3) } 'scalar'
    }
    $s
}

function Invoke-SIMsrcGet {
    <# One GET of the public MSRC API as JSON (REST only; 30 s; no sign-in). #>
    param([Parameter(Mandatory)][string]$Url)
    Invoke-RestMethod -Method Get -Uri $Url -Headers @{ Accept = 'application/json' } -TimeoutSec 30 -ErrorAction Stop
}

function Initialize-SIKbReleaseDates {
    <#
    .SYNOPSIS  Once per run: the KB release dates into memory (Get-SIKbReleaseDate reads them), from the install's cache and,
               when the cache is older than a day, the MSRC API (only the documents that are new or revised). Never throws:
               a refused / failed call is said in ONE line and the cache (and the name rule) is used. Returns the number of KBs.
               -Fetch: the GET (tests pass a fake); -Now: the clock (tests).
    #>
    param($Store, [scriptblock]$Fetch, $Now, [scriptblock]$Log)
    if ($null -eq $Log) { $Log = { param($l, $m) } }
    if ($null -eq $Fetch) { $Fetch = { param($u) Invoke-SIMsrcGet -Url $u } }
    $at = $(if ($null -ne $Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow })
    $cache = @{ FetchedAt = $null; Documents = @{}; Kbs = @{} }
    if ($null -ne $Store) { try { $cache = $Store.Load() } catch { & $Log 'INFO' ('the cached Microsoft update release dates could not be read ({0}) -- they are read again' -f $_.Exception.Message) } }
    $script:SIKbReleaseDates = $cache.Kbs
    if (-not (Test-SIMsrcDatesOn)) {
        & $Log 'INFO' 'patch cycle: the Microsoft update release dates are not read (SI_PatchCycle_MsrcDates is off) -- the update names'' Patch Tuesday is used'
        return $cache.Kbs.Count
    }
    if ($null -ne $cache.FetchedAt -and ($at - [datetime]$cache.FetchedAt).TotalHours -lt 24 -and $cache.Kbs.Count -gt 0) { return $cache.Kbs.Count }
    try {
        $docs = ConvertFrom-SIMsrcUpdateList (& $Fetch ($script:SIMsrcBase + '/updates'))
        $from = $at.AddMonths(-(Get-SIMsrcMonths))
        $read = 0; $notRead = 0
        foreach ($d in $docs) {
            if ($null -ne $d.Release -and $d.Release -lt $from) { continue }
            if ($cache.Documents.ContainsKey($d.Id) -and [string]$cache.Documents[$d.Id] -eq [string]$d.Current) { continue }
            # ONE DOCUMENT FAILS ALONE: a document that cannot be read (a bad address, a time-out) is said once (its address
            # in the verbose log) and NOT marked read, so it is asked again next run; every other document is kept and saved
            try {
                $kbs = ConvertFrom-SIMsrcDocument -Document (& $Fetch $d.Url) -Release $d.Release
            } catch {
                $notRead++
                Write-Verbose ('patch cycle: the release document {0} ({1}) could not be read -- {2}' -f $d.Id, $d.Url, $_.Exception.Message)
                continue
            }
            $null = Merge-SIKbReleaseDates -Into $cache.Kbs -From $kbs
            $cache.Documents[$d.Id] = [string]$d.Current
            $read++
        }
        if ($notRead -gt 0) { & $Log 'INFO' ('patch cycle: {0} of the Security Update Guide''s release documents could not be read this run -- the others are kept, and those are read again next run' -f $notRead) }
        # a document not read makes the cache a day old, so the next run asks for it (and only it) again
        $cache.FetchedAt = $(if ($notRead -gt 0) { $at.AddHours(-24) } else { $at })
        if ($null -ne $Store) { try { $Store.Save($cache) } catch { & $Log 'INFO' ('the Microsoft update release dates could not be kept ({0}) -- they are read again next run' -f $_.Exception.Message) } }
        $script:SIKbReleaseDates = $cache.Kbs
        if ($read -gt 0) { & $Log 'INFO' ('patch cycle: the release dates of {0} Microsoft update(s) known ({1} release document(s) read from the Security Update Guide)' -f $cache.Kbs.Count, $read) }
    } catch {
        & $Log 'INFO' ('patch cycle: the Microsoft update release dates could not be read from api.msrc.microsoft.com ({0}) -- {1} cached date(s) and, for the rest, the update names'' Patch Tuesday are used' -f $_.Exception.Message, $cache.Kbs.Count)
    }
    $cache.Kbs.Count
}

function Get-SIKbReleaseDate {
    <# PURE over the loaded dates. The newest release date of the KBs given (a fix that needs several is released when the last is), or $null. #>
    param([string[]]$Kbs, [hashtable]$Dates = $script:SIKbReleaseDates)
    if ($null -eq $Dates -or $Dates.Count -eq 0) { return $null }
    $best = $null
    foreach ($k in $Kbs) { if ($k -and $Dates.ContainsKey($k)) { $d = $Dates[$k]; if ($null -eq $best -or $d -gt $best) { $best = $d } } }
    $best
}
