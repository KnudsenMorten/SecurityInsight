#Requires -Version 5.1
<#
    THE NAMES OF THE PEOPLE AND GROUPS FOR THE WEB APP'S PEOPLE PICKER, FROM SECURITYINSIGHT'S OWN COLLECTION (owner
    2026-11-16: "can engine provide the data" -- yes; framework GRAPH-PICKER under SECURE-WEB-1: the internet-facing web
    identity never holds or uses a directory-read Graph permission -- pickers read the product's own store, filled by the
    engine identity).

    THE STORE (sql\si-data-schema.sql): sidata.DirectoryName (one narrow row per user / group), sidata.DirectoryNameLoad (the
    newest read per kind: when, complete, rows), sidata.DirectorySearchRequest ("Search the tenant" requests).

    WHO FILLS IT -- the ENGINE identity, with rights it already holds (setup\_shared\si-identity-rights.json):
      USERS   the identity collection's own user pages (Get-DiscoveryFromEntraUsers): each page's users are recorded here as
              they come (Add-SIDirectoryNamePage) -- NO extra Graph call, the same read (User.Read.All).
      GROUPS  ONE light read of the groups (Read-SIDirectoryGroups): id, displayName, mail, securityEnabled, mailEnabled,
              groupTypes -- no members -- paged ($top=999) and bounded in time (-BudgetSeconds, default 900) (Group.Read.All).
      SEARCH  an Admin's "Search the tenant" (Invoke-SIDirectorySearchRequests, in the engine's background job
              caj-si-signin-methods): Graph startswith on the name / sign-in name / mail, at most 20 users + 20 groups,
              READS ONLY; what it finds is stored as names (Source 'search'); the request row records the outcome.

    UNKNOWN IS NOT GONE. A complete read replaces the kind's 'collection' rows (a row not seen by it goes); a read that failed
    or stopped part-way (an error, Microsoft throttling past the retries, the time budget) removes NOTHING and is recorded as
    not complete. The picker shows the time of the newest read.

    NEVER FAILS A COLLECTION: no database, the tables not there yet, an error = said ONCE, and the collection goes on.
    PowerShell 5.1 and 7. Graph and SQL only behind seams (-Invoke, -Fetch). Tests: tests\pester\SIv3-DirectoryNames.Tests.ps1.
#>

$script:SIDirectoryNames = @{ PageRows = 1000; GroupBudgetSeconds = 900; SearchTop = 20; RequestMaxAgeHours = 24; RequestBatch = 10 }
$script:SIDirectoryNamesMissingTables = "IF OBJECT_ID(N'sidata.DirectoryName') IS NULL OR OBJECT_ID(N'sidata.DirectoryNameLoad') IS NULL THROW 50000, N'the tables of the people picker''s names are not in the database yet (the next update adds them)', 1;"

# =====================================================================================================================
#  PURE
# =====================================================================================================================
function Get-SIDirectoryNameValue {
    <# PURE. A property of a Graph object (object or dictionary); $null when absent. #>
    param([AllowNull()]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function ConvertTo-SIDirectoryNameRow {
    <#
        PURE. One Graph user or group as the narrow row the store keeps (only what the picker needs -- nothing else of the
        object is read): @{ ObjectId; Kind; DisplayName; Upn; Mail; AccountEnabled; Guest; SecurityEnabled; MailEnabled;
        GroupTypes }. $null when the object has no id. Texts are cut to the column sizes.
    #>
    param([AllowNull()]$Object, [Parameter(Mandatory)][ValidateSet('user', 'group')][string]$Kind)
    $id = [string](Get-SIDirectoryNameValue $Object 'id')
    if (-not $id.Trim()) { return $null }
    $cut = { param($v, [int]$n) if ($null -eq $v) { return $null }; $s = ([string]$v).Trim(); if (-not $s) { return $null }; if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
    $bool = { param($v) if ($null -eq $v) { return $null }; [bool]$v }
    $row = [ordered]@{ ObjectId = $id.Trim().ToLowerInvariant(); Kind = $Kind; DisplayName = (& $cut (Get-SIDirectoryNameValue $Object 'displayName') 256)
        Upn = $null; Mail = (& $cut (Get-SIDirectoryNameValue $Object 'mail') 256); AccountEnabled = $null; Guest = $false
        SecurityEnabled = $null; MailEnabled = $null; GroupTypes = $null }
    if ($Kind -eq 'user') {
        $row.Upn = & $cut (Get-SIDirectoryNameValue $Object 'userPrincipalName') 256
        $row.AccountEnabled = & $bool (Get-SIDirectoryNameValue $Object 'accountEnabled')
        $row.Guest = ([string](Get-SIDirectoryNameValue $Object 'userType') -eq 'Guest') -or ([string]$row.Upn -match '#EXT#')
    } else {
        $row.SecurityEnabled = & $bool (Get-SIDirectoryNameValue $Object 'securityEnabled')
        $row.MailEnabled = & $bool (Get-SIDirectoryNameValue $Object 'mailEnabled')
        $gt = @(Get-SIDirectoryNameValue $Object 'groupTypes') | Where-Object { $null -ne $_ -and ([string]$_).Trim() } | ForEach-Object { ([string]$_).Trim() }
        $row.GroupTypes = & $cut ((@($gt) -join ',')) 200
    }
    $row
}

function ConvertTo-SIDirectoryODataText {
    <# PURE. A text for a Graph $filter string literal ('' for '), or $null when it is not a search text (2..100 characters, no control character). #>
    param([AllowNull()][string]$Text)
    $t = ([string]$Text).Trim()
    if ($t.Length -lt 2 -or $t.Length -gt 100) { return $null }
    foreach ($ch in $t.ToCharArray()) { if ([char]::IsControl($ch)) { return $null } }
    $t.Replace("'", "''")
}

function Get-SIDirectorySearchUrls {
    <#
        PURE. The two Graph reads of "Search the tenant" for -Text: users whose name, sign-in name or mail starts with it, and
        groups whose name or mail starts with it -- at most -Top of each, only the picker's properties. $null when the text is
        not a search text.
    #>
    param([AllowNull()][string]$Text, [int]$Top = $script:SIDirectoryNames.SearchTop)
    $v = ConvertTo-SIDirectoryODataText $Text
    if ($null -eq $v) { return $null }
    $uf = "startswith(displayName,'$v') or startswith(userPrincipalName,'$v') or startswith(mail,'$v')"
    $gf = "startswith(displayName,'$v') or startswith(mail,'$v')"
    [pscustomobject]@{
        Users  = ('https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType&$top={0}&$filter={1}' -f $Top, [uri]::EscapeDataString($uf))
        Groups = ('https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail,securityEnabled,mailEnabled,groupTypes&$top={0}&$filter={1}' -f $Top, [uri]::EscapeDataString($gf))
    }
}

function Get-SIDirectoryGroupsUrl {
    <# PURE. The light group read: the picker's properties only, no members, 999 a page. #>
    'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,mail,securityEnabled,mailEnabled,groupTypes&$top=999'
}

# =====================================================================================================================
#  SQL (the seam: { param($Sql, $Params, $Mode) } = New-SIRecordSqlInvoke)
# =====================================================================================================================
function Get-SIDirectoryNamePageSql {
    <# ONE statement per page: the rows (@rows = JSON of ConvertTo-SIDirectoryNameRow) upserted, seen @now, Source @source
       ('collection' | 'search'). A 'search' row never takes over a row the collection keeps (its Source stays). Answers Written. #>
    @"
SET NOCOUNT ON;
$($script:SIDirectoryNamesMissingTables)
DECLARE @t DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @now, 127), SYSUTCDATETIME());
DECLARE @r TABLE (ObjectId NVARCHAR(64) NOT NULL PRIMARY KEY, Kind NVARCHAR(8) NOT NULL, DisplayName NVARCHAR(256) NULL, Upn NVARCHAR(256) NULL, Mail NVARCHAR(256) NULL,
                  AccountEnabled BIT NULL, Guest BIT NOT NULL, SecurityEnabled BIT NULL, MailEnabled BIT NULL, GroupTypes NVARCHAR(200) NULL);
INSERT @r (ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest, SecurityEnabled, MailEnabled, GroupTypes)
SELECT LOWER(x.ObjectId), MAX(x.Kind), MAX(LEFT(x.DisplayName, 256)), MAX(LEFT(x.Upn, 256)), MAX(LEFT(x.Mail, 256)), MAX(CAST(x.AccountEnabled AS INT)), MAX(CASE WHEN x.Guest = 1 THEN 1 ELSE 0 END),
       MAX(CAST(x.SecurityEnabled AS INT)), MAX(CAST(x.MailEnabled AS INT)), MAX(LEFT(x.GroupTypes, 200))
FROM OPENJSON(@rows) WITH (ObjectId NVARCHAR(64), Kind NVARCHAR(8), DisplayName NVARCHAR(400), Upn NVARCHAR(400), Mail NVARCHAR(400), AccountEnabled BIT, Guest BIT,
                           SecurityEnabled BIT, MailEnabled BIT, GroupTypes NVARCHAR(400)) x
WHERE x.ObjectId IS NOT NULL AND x.ObjectId <> N'' AND x.Kind IN (N'user', N'group')
GROUP BY LOWER(x.ObjectId);
MERGE sidata.DirectoryName AS d
USING @r AS s ON d.ObjectId = s.ObjectId
WHEN MATCHED THEN UPDATE SET Kind = s.Kind, DisplayName = s.DisplayName, Upn = s.Upn, Mail = s.Mail, AccountEnabled = s.AccountEnabled, Guest = s.Guest,
     SecurityEnabled = s.SecurityEnabled, MailEnabled = s.MailEnabled, GroupTypes = s.GroupTypes, SeenAt = @t,
     Source = CASE WHEN @source = N'search' THEN d.Source ELSE N'collection' END
WHEN NOT MATCHED THEN INSERT (ObjectId, Kind, DisplayName, Upn, Mail, AccountEnabled, Guest, SecurityEnabled, MailEnabled, GroupTypes, Source, SeenAt)
     VALUES (s.ObjectId, s.Kind, s.DisplayName, s.Upn, s.Mail, s.AccountEnabled, s.Guest, s.SecurityEnabled, s.MailEnabled, s.GroupTypes, CASE WHEN @source = N'search' THEN N'search' ELSE N'collection' END, @t);
SELECT @@ROWCOUNT AS Written;
"@
}

function Get-SIDirectoryNameDoneSql {
    <#
        The end of one read of a kind (@kind user | group) that started at @start: recorded in sidata.DirectoryNameLoad (@complete,
        @rows, @detail). ONLY a complete read (@complete = 1) lets go of the kind's 'collection' rows it did not see (SeenAt <
        @start) -- in slices of 5000, so a large tenant never holds one long lock -- and of 'search' rows older than 30 days.
        An incomplete read removes nothing. Answers Removed.
    #>
    @"
SET NOCOUNT ON;
$($script:SIDirectoryNamesMissingTables)
DECLARE @s DATETIME2(3) = TRY_CONVERT(DATETIME2(3), @start, 127), @k NVARCHAR(8) = @kind, @ok BIT = CASE WHEN @complete = N'1' THEN 1 ELSE 0 END, @n INT = 0, @gone INT = 1;
IF @k NOT IN (N'user', N'group') OR @s IS NULL THROW 50000, N'a read of the people picker''s names needs its kind and its start', 1;
IF @ok = 1
BEGIN
    WHILE @gone > 0
    BEGIN
        DELETE TOP (5000) FROM sidata.DirectoryName WHERE Kind = @k AND Source = N'collection' AND SeenAt < @s;
        SET @gone = @@ROWCOUNT; SET @n += @gone;
    END
    SET @gone = 1;
    WHILE @gone > 0
    BEGIN
        DELETE TOP (5000) FROM sidata.DirectoryName WHERE Kind = @k AND Source = N'search' AND SeenAt < DATEADD(DAY, -30, @s);
        SET @gone = @@ROWCOUNT; SET @n += @gone;
    END
END
MERGE sidata.DirectoryNameLoad AS t
USING (SELECT @k AS Kind) AS x ON t.Kind = x.Kind
WHEN MATCHED THEN UPDATE SET ReadAt = SYSUTCDATETIME(), Complete = @ok, [Rows] = ISNULL(TRY_CONVERT(INT, @rows), 0), Detail = LEFT(@detail, 400)
WHEN NOT MATCHED THEN INSERT (Kind, ReadAt, Complete, [Rows], Detail) VALUES (@k, SYSUTCDATETIME(), @ok, ISNULL(TRY_CONVERT(INT, @rows), 0), LEFT(@detail, 400));
SELECT @n AS Removed;
"@
}

function Get-SIDirectorySearchPendingSql {
    <# The waiting "Search the tenant" requests, oldest first (at most @n); a request older than a day is closed as expired first. #>
    @"
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.DirectorySearchRequest') IS NULL BEGIN SELECT CAST(NULL AS BIGINT) AS RequestId WHERE 1 = 0; RETURN; END
UPDATE sidata.DirectorySearchRequest SET DoneUtc = SYSUTCDATETIME(), Outcome = N'expired', Detail = N'not looked up within a day -- ask again'
WHERE DoneUtc IS NULL AND RequestedUtc < DATEADD(HOUR, -$($script:SIDirectoryNames.RequestMaxAgeHours), SYSUTCDATETIME());
SELECT TOP (ISNULL(TRY_CONVERT(INT, @n), 10)) RequestId, SearchText, RequestedBy FROM sidata.DirectorySearchRequest WHERE DoneUtc IS NULL ORDER BY RequestId;
"@
}

function Get-SIDirectorySearchDoneSql {
    <# One request's outcome (done | failed | refused), the number found and a short detail -- only while it is still open. #>
    'SET NOCOUNT ON; UPDATE sidata.DirectorySearchRequest SET DoneUtc = SYSUTCDATETIME(), Outcome = @outcome, Found = TRY_CONVERT(INT, @found), Detail = LEFT(@detail, 400) WHERE RequestId = TRY_CONVERT(BIGINT, @id) AND DoneUtc IS NULL; SELECT @@ROWCOUNT AS Recorded;'
}

# =====================================================================================================================
#  The store handle
# =====================================================================================================================
function New-SIDirectoryNameStore {
    <# The handle on the store: @{ Invoke; Usable; Note; Noted; Rows (per kind) }. -Invoke: the data seam; none = the install's
       database (New-SIRecordSqlInvoke); no database = not usable. #>
    param([scriptblock]$Invoke, [switch]$NoDatabaseLookup)
    if (-not $Invoke -and -not $NoDatabaseLookup) {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
            $rs = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-RecordSql.ps1')
            if ([IO.File]::Exists($rs)) { try { . $rs } catch { } }
        }
        if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { try { $Invoke = New-SIRecordSqlInvoke } catch { $Invoke = $null } }
    }
    $s = [pscustomobject]@{ Invoke = $Invoke; Usable = [bool]$Invoke; Note = ''; Noted = $false; Rows = @{ user = 0; group = 0 }; Failed = @{ user = $false; group = $false } }
    if (-not $Invoke) { $s.Note = 'no database is configured for this install' }
    $s
}

function Set-SIDirectoryNameStoreBroken {
    <# The store is given up for the rest of the run; said ONCE (information: the collection goes on). #>
    param([Parameter(Mandatory)]$Store, [string]$Why)
    $Store.Usable = $false
    if (-not $Store.Note) { $Store.Note = $Why }
    if (-not $Store.Noted) {
        $Store.Noted = $true
        $m = ('[directory] the names for the people picker could not be saved ({0}) -- the picker keeps the names of the last run that saved them' -f $Why)
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m }
    }
}

function Add-SIDirectoryNamePage {
    <#
        One page of Graph users or groups into the store, in ONE statement per -PageRows. Reads the objects only (never changes
        them). Never throws: a failure marks the kind's read as not complete (nothing is removed at its end) and gives the store
        up for the run. Answers the rows written.
    #>
    param([AllowNull()]$Store, [AllowNull()][object[]]$Objects, [Parameter(Mandatory)][ValidateSet('user', 'group')][string]$Kind,
          [string]$Source = 'collection', [datetime]$Now = [datetime]::UtcNow, [int]$PageRows = $script:SIDirectoryNames.PageRows)
    if ($null -eq $Store -or -not $Store.Usable) { if ($Store) { $Store.Failed[$Kind] = $true }; return 0 }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($o in @($Objects)) { $r = ConvertTo-SIDirectoryNameRow -Object $o -Kind $Kind; if ($r) { $rows.Add($r) } }
    if ($rows.Count -eq 0) { return 0 }
    # its own name: $now would be the [datetime] parameter $Now (names are not case-sensitive) and turn the text back into a date
    $seenText = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
    $written = 0
    try {
        for ($i = 0; $i -lt $rows.Count; $i += $PageRows) {
            $slice = @($rows.GetRange($i, [Math]::Min($PageRows, $rows.Count - $i)).ToArray())
            $j = ConvertTo-Json -InputObject $slice -Compress -Depth 4
            if (-not $j.TrimStart().StartsWith('[')) { $j = '[' + $j + ']' }
            $null = & $Store.Invoke (Get-SIDirectoryNamePageSql) @{ rows = $j; now = $seenText; source = $Source } 'rows'
            $written += $slice.Count
        }
    } catch {
        $Store.Failed[$Kind] = $true
        Set-SIDirectoryNameStoreBroken -Store $Store -Why ([string]$_.Exception.Message)
    }
    $Store.Rows[$Kind] = [int]$Store.Rows[$Kind] + $written
    $written
}

function Complete-SIDirectoryNameRead {
    <#
        The end of one read of -Kind that started at -Start: recorded; a COMPLETE read (and every page saved) lets go of the
        rows it did not see, anything else removes nothing. Never throws. Answers @{ Complete; Removed; Line }.
    #>
    param([AllowNull()]$Store, [Parameter(Mandatory)][ValidateSet('user', 'group')][string]$Kind, [Parameter(Mandatory)][datetime]$Start,
          [bool]$Complete, [int]$Count = 0, [string]$Why = '')
    $label = if ($Kind -eq 'user') { 'users' } else { 'groups' }
    $out = [pscustomobject]@{ Complete = $false; Removed = 0; Line = '' }
    if ($null -eq $Store -or -not $Store.Invoke) { $out.Line = ('[directory] {0} for the people picker: not saved ({1})' -f $label, $(if ($Store) { $Store.Note } else { 'no database' })); return $out }
    $ok = [bool]$Complete -and -not [bool]$Store.Failed[$Kind] -and $Store.Usable
    if (-not $Why -and -not $ok) { $Why = if ($Store.Failed[$Kind]) { 'not every page was saved' } else { 'the read did not complete' } }
    $detail = if ($ok) { ('{0} {1} read' -f $Count, $label) } else { ('{0} {1} read; not complete: {2}' -f $Count, $label, $Why) }
    try {
        $r = @(& $Store.Invoke (Get-SIDirectoryNameDoneSql) @{ kind = $Kind; start = $Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
            complete = $(if ($ok) { '1' } else { '0' }); rows = [string]$Count; detail = $detail } 'rows' | Where-Object { $null -ne $_ }) | Select-Object -Last 1
        if ($r) { $v = Get-SIDirectoryNameValue $r 'Removed'; if ($null -ne $v -and $v -isnot [DBNull]) { $out.Removed = [int]$v } }
        $out.Complete = $ok
    } catch {
        Set-SIDirectoryNameStoreBroken -Store $Store -Why ([string]$_.Exception.Message)
        $out.Complete = $false
    }
    $out.Line = if ($out.Complete) { ('[directory] {0:N0} {1} saved for the people picker ({2:N0} no longer listed let go)' -f $Count, $label, $out.Removed) }
                else { ('[directory] {0:N0} {1} saved for the people picker; the read was not complete ({2}) -- nothing was let go, the names of earlier reads stay' -f $Count, $label, $Why) }
    $out
}

# =====================================================================================================================
#  Graph (the seam: -Fetch { param($Url) } -> the parsed page)
# =====================================================================================================================
function Invoke-SIDirectoryGraphGet {
    <# One Graph page: GET with the token, a few retries on 429 / 5xx (Retry-After honoured, at most 30 s). Throws past them. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token, [int]$MaxAttempts = 4)
    $hdr = @{ Authorization = ('Bearer ' + $Token) }
    $a = 0
    while ($true) {
        $a++
        try { return (Invoke-RestMethod -Method Get -Uri $Url -Headers $hdr -ErrorAction Stop) }
        catch {
            $st = 0; try { $st = [int]$_.Exception.Response.StatusCode } catch { $st = 0 }
            if ($st -notin 429, 500, 502, 503, 504 -or $a -ge $MaxAttempts) { throw }
            $d = [Math]::Pow(2, $a)
            try { $ra = $_.Exception.Response.Headers.RetryAfter; if ($ra -and $ra.Delta) { $d = [Math]::Min(30, [int]$ra.Delta.TotalSeconds) } } catch { }
            Start-Sleep -Seconds ([int]$d)
        }
    }
}

function New-SIDirectoryGraphFetch {
    <# The default Graph page reader { param($Url) } for -Token. The token is NEVER part of a script block's text (a block's
       text reaches logs, error records and transcripts): it is a variable the closure holds, and the page function is held
       as its own script block (${function:...}, bound where it was loaded -- a GetNewClosure() block runs in a module scope
       of its own and would not find it by name). #>
    param([Parameter(Mandatory)][string]$Token)
    $siDirGraphGet = ${function:Invoke-SIDirectoryGraphGet}
    $siDirGraphToken = $Token
    { param($Url) & $siDirGraphGet -Url $Url -Token $siDirGraphToken }.GetNewClosure()
}

function Read-SIDirectoryGroups {
    <#
        ONE light read of the tenant's groups into the store: the picker's properties only, no members, page by page (each page
        saved as it comes, never all held), for at most -BudgetSeconds. Complete only when the last page was read inside the
        budget and every page saved; otherwise nothing is let go (unknown is not gone). Never throws. -Clock { } -> now (UTC).
        Answers @{ Complete; Count; Pages; Removed; Line }.
    #>
    param([AllowNull()]$Store, [Parameter(Mandatory)][scriptblock]$Fetch, [int]$BudgetSeconds = $script:SIDirectoryNames.GroupBudgetSeconds,
          [scriptblock]$Clock, [string]$Url = (Get-SIDirectoryGroupsUrl))
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    $out = [pscustomobject]@{ Complete = $false; Count = 0; Pages = 0; Removed = 0; Line = '' }
    if ($null -eq $Store -or -not $Store.Usable) { $out.Line = ('[directory] groups for the people picker: not read ({0})' -f $(if ($Store) { $Store.Note } else { 'no database' })); return $out }
    $start = [datetime](& $Clock)
    $next = $Url; $why = ''; $complete = $false
    while ($next) {
        if (([datetime](& $Clock) - $start).TotalSeconds -ge $BudgetSeconds) { $why = ('the {0}-second budget was used' -f $BudgetSeconds); break }
        $page = $null
        try { $page = & $Fetch $next } catch { $why = ('Microsoft Graph answered: {0}' -f (([string]$_.Exception.Message) -split "`n")[0]); break }
        $vals = @(); if ($page -and (Get-SIDirectoryNameValue $page 'value')) { $vals = @(Get-SIDirectoryNameValue $page 'value') }
        $out.Count += $vals.Count; $out.Pages++
        $null = Add-SIDirectoryNamePage -Store $Store -Objects $vals -Kind 'group' -Now $start
        if (-not $Store.Usable) { $why = 'a page could not be saved'; break }
        $next = [string](Get-SIDirectoryNameValue $page '@odata.nextLink')
        if (-not $next) { $complete = $true }
    }
    $done = Complete-SIDirectoryNameRead -Store $Store -Kind 'group' -Start $start -Complete $complete -Count $out.Count -Why $why
    $out.Complete = $done.Complete; $out.Removed = $done.Removed; $out.Line = $done.Line
    $out
}

function Complete-SIDirectoryNamesOfCollection {
    <#
        The identity collection's end of the user read (Get-DiscoveryFromEntraUsers): the users' read recorded (complete or
        not), then the ONE light group read. -Token: a Graph token (asked again through Get-SIGraphToken when it is loaded --
        the user pages may have taken longer than one token lives). Never throws; writes its lines (information only).
    #>
    param([AllowNull()]$Store, [Parameter(Mandatory)][datetime]$Start, [bool]$UsersComplete, [int]$UsersCount, [string]$Token, [scriptblock]$Fetch)
    $say = { param($m) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m } }
    try {
        if ($null -eq $Store -or -not $Store.Invoke) { return }
        $u = Complete-SIDirectoryNameRead -Store $Store -Kind 'user' -Start $Start -Complete $UsersComplete -Count $UsersCount
        & $say $u.Line
        if (-not $Store.Usable) { return }
        if (-not $Fetch) {
            $tk = $Token
            if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { try { $t2 = [string](Get-SIGraphToken -Resource Graph); if ($t2) { $tk = $t2 } } catch { } }
            if (-not $tk) { & $say '[directory] groups for the people picker: not read (no Microsoft Graph sign-in)'; return }
            $Fetch = New-SIDirectoryGraphFetch -Token $tk
        }
        $g = Read-SIDirectoryGroups -Store $Store -Fetch $Fetch
        & $say $g.Line
    } catch { & $say ('[directory] the names for the people picker: not finished ({0}) -- the collection goes on' -f (([string]$_.Exception.Message) -split "`n")[0]) }
}

function Search-SITenantDirectory {
    <#
        "Search the tenant" (an Admin's request, READS ONLY): users and groups whose name, sign-in name or mail starts with
        -Text, at most -Top of each. Answers @{ Users; Groups } (Graph objects) -- throws when Graph refuses (the request then
        records it).
    #>
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][scriptblock]$Fetch, [int]$Top = $script:SIDirectoryNames.SearchTop)
    $u = Get-SIDirectorySearchUrls -Text $Text -Top $Top
    if ($null -eq $u) { throw 'not a search text (2 to 100 characters, no control character)' }
    $users = @(); $groups = @()
    $p = & $Fetch $u.Users; if ($p -and (Get-SIDirectoryNameValue $p 'value')) { $users = @(Get-SIDirectoryNameValue $p 'value') | Select-Object -First $Top }
    $p = & $Fetch $u.Groups; if ($p -and (Get-SIDirectoryNameValue $p 'value')) { $groups = @(Get-SIDirectoryNameValue $p 'value') | Select-Object -First $Top }
    [pscustomobject]@{ Users = @($users); Groups = @($groups) }
}

function Invoke-SIDirectorySearchRequests {
    <#
        The waiting "Search the tenant" requests (sidata.DirectorySearchRequest), oldest first: each looked up in Graph
        (Search-SITenantDirectory), what was found stored as names (Source 'search'), the outcome recorded (done | failed |
        refused). -Invoke: the data seam; -Fetch: the Graph page reader (made from -TokenProvider only when a request waits).
        Never throws. Answers @{ Handled; Found; Lines }.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Fetch, [scriptblock]$TokenProvider, [int]$Batch = $script:SIDirectoryNames.RequestBatch)
    $out = [pscustomobject]@{ Handled = 0; Found = 0; Lines = (New-Object System.Collections.Generic.List[string]) }
    if (-not $Invoke) { return $out }
    $rows = @()
    try { $rows = @(& $Invoke (Get-SIDirectorySearchPendingSql) @{ n = [string]$Batch } 'rows' | Where-Object { $null -ne $_ -and (Get-SIDirectoryNameValue $_ 'RequestId') }) }
    catch { $out.Lines.Add(('[directory] the people picker''s tenant searches could not be read ({0})' -f (([string]$_.Exception.Message) -split "`n")[0])); return $out }
    if ($rows.Count -eq 0) { return $out }
    if (-not $Fetch -and $TokenProvider) { try { $tk = [string](& $TokenProvider); if ($tk) { $Fetch = New-SIDirectoryGraphFetch -Token $tk } } catch { $Fetch = $null } }
    $store = New-SIDirectoryNameStore -Invoke $Invoke
    foreach ($r in $rows) {
        $id = [string](Get-SIDirectoryNameValue $r 'RequestId'); $text = [string](Get-SIDirectoryNameValue $r 'SearchText')
        $outcome = 'done'; $found = 0; $detail = ''
        if ($null -eq (ConvertTo-SIDirectoryODataText $text)) { $outcome = 'refused'; $detail = 'not a search text (2 to 100 characters, no control character)' }
        elseif (-not $Fetch) { $outcome = 'failed'; $detail = 'no Microsoft Graph sign-in for the engine this run' }
        else {
            try {
                $f = Search-SITenantDirectory -Text $text -Fetch $Fetch
                $store.Usable = $true; $store.Failed = @{ user = $false; group = $false }
                $found += Add-SIDirectoryNamePage -Store $store -Objects $f.Users -Kind 'user' -Source 'search'
                $found += Add-SIDirectoryNamePage -Store $store -Objects $f.Groups -Kind 'group' -Source 'search'
                if (-not $store.Usable) { $outcome = 'failed'; $detail = ('found but not saved: {0}' -f $store.Note) }
                else { $detail = ('{0} user(s) and {1} group(s) found' -f @($f.Users).Count, @($f.Groups).Count) }
            } catch { $outcome = 'failed'; $detail = ('Microsoft Graph answered: {0}' -f (([string]$_.Exception.Message) -split "`n")[0]) }
        }
        try { $null = & $Invoke (Get-SIDirectorySearchDoneSql) @{ id = $id; outcome = $outcome; found = [string]$found; detail = $detail } 'rows' } catch { }
        $out.Handled++; $out.Found += $found
        $out.Lines.Add(('[directory] a tenant search for the people picker: {0} -- {1}' -f $outcome, $detail))
    }
    $out
}
