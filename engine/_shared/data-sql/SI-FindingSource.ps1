#Requires -Version 5.1
<#
    THE READERS' FINDING SOURCE (REQUIREMENTS #1332, the finding history model; docs\DESIGN.md "Finding history model",
    "The readers"). The engine's READER jobs (data out, the vulnerability close-loop) read the findings through ONE seam: a
    statement that READS sidata.Finding / sidata.vExemptedFinding / sidata.vCurrentFinding is sent to sidata.vFinding /
    sidata.vExemptedFindingServed / sidata.vCurrentFindingServed (sql\si-data-schema.sql), which give every collection back
    either as its stored rows or as its history -- the history only for a collection whose every compare of its run was the
    same (sidata.FindingSourceOf). A statement that WRITES the findings (INSERT / UPDATE / DELETE / MERGE / TRUNCATE / ALTER /
    an index ON it, or an UPDATE / DELETE through its alias) is never changed (one-statement-ok: this help text names the
    statements it leaves alone -- it is no statement). A quoted name (OBJECT_ID('sidata.Finding'),
    COL_LENGTH(...)) is never changed. While no collection is served from the history (sidata.FindingSourceActive), or on a
    database without these objects, every statement goes exactly as written -- the readers read the tables as before.
    The web app and the MCP server do the same in SI.Management.Core (ProData\FindingSource.cs, the same rules, the same
    test cases). The data sync's own builders are NOT routed: they read while the rows are being rewritten.
    PowerShell 5.1 and 7. No PowerShell module.
#>

$script:SIFindingSource = [ordered]@{
    # name read -> name served (the views of sql\si-data-schema.sql)
    Routes      = [ordered]@{ 'sidata.Finding' = 'sidata.vFinding'; 'sidata.vExemptedFinding' = 'sidata.vExemptedFindingServed'; 'sidata.vCurrentFinding' = 'sidata.vCurrentFindingServed' }
    ContextKey  = 'si.finding.source'
    # a reader that keeps today's stored rows while its history plan is slower (the findings list, REQUIREMENTS #1332): never routed
    StoredMarker = '/* si.finding.source: stored */'
    # the source lists are decided ONCE per statement from a cached answer this old at most; a collection that stops being served
    # keeps its (verified) history this long at most -- the history step waits this long before it removes members it served
    CacheSeconds = 15
    MaxListChars = 3800
    # the ids a collection made AFTER the answer can take within its cache time: read from their stored rows
    AheadIds     = 20
}

function Get-SIFindingSourceContract { $script:SIFindingSource }

function Test-SIFindingSourceWrites {
    <# PURE. Does -Sql WRITE sidata.Finding (then it is never routed)? A write target, an index ON it, or an UPDATE / DELETE
       through an alias the statement gives it. #>
    param([AllowEmptyString()][string]$Sql)
    if (-not $Sql) { return $false }
    $t = '(?:\[?sidata\]?\.\[?Finding\]?)(?![A-Za-z0-9_\]])'
    if ($Sql -match ('(?is)\b(?:UPDATE|INSERT(?:\s+INTO)?|DELETE(?:\s+TOP\s*\(\s*[^)]*\))?(?:\s+FROM)?|MERGE(?:\s+INTO)?|TRUNCATE\s+TABLE|ALTER\s+TABLE|ON|INTO)\s+' + $t)) { return $true }
    $kw = @('AS', 'WITH', 'WHERE', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'OUTER', 'ON', 'GROUP', 'ORDER', 'UNION', 'SET', 'SELECT', 'FROM', 'AND', 'OR', 'OPTION', 'PIVOT', 'UNPIVOT', 'TABLESAMPLE')
    foreach ($m in [regex]::Matches($Sql, '(?i)' + $t + '\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*)')) {
        $a = $m.Groups[1].Value
        if ($kw -contains $a.ToUpperInvariant()) { continue }
        if ($Sql -match ('(?i)\b(?:UPDATE|DELETE(?:\s+TOP\s*\(\s*[^)]*\))?(?:\s+FROM)?)\s+' + [regex]::Escape($a) + '\b(?!\.)')) { return $true }
    }
    $false
}

function ConvertTo-SIFindingSourceSql {
    <# PURE. -Sql with every READ of the routed names sent to the served views; unchanged when it writes the findings. A name
       right after a quote, a bracket or a dot (a quoted name, another schema's) is left as it is. #>
    param([AllowEmptyString()][string]$Sql)
    if (-not $Sql -or $Sql -notmatch '(?i)sidata\.(Finding|vExemptedFinding|vCurrentFinding)(?![A-Za-z0-9_])') { return $Sql }
    if (Test-SIFindingSourceWrites -Sql $Sql) { return $Sql }
    if ($Sql.Contains([string]$script:SIFindingSource.StoredMarker)) { return $Sql }
    $out = $Sql
    foreach ($k in $script:SIFindingSource.Routes.Keys) {
        $out = [regex]::Replace($out, '(?i)(?<![A-Za-z0-9_.''\[\]])' + [regex]::Escape($k) + '(?![A-Za-z0-9_])', [string]$script:SIFindingSource.Routes[$k])
    }
    $out
}

function Get-SIFindingSourceListsSql {
    <# The served / stored lists and the newest collection id (sidata.FindingSourceLists); nothing on a database without them. #>
    "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.FindingSourceLists') IS NULL OR OBJECT_ID(N'sidata.vFinding') IS NULL SELECT CAST(N'[]' AS nvarchar(max)) AS Served, CAST(N'[]' AS nvarchar(max)) AS Stored, 0 AS MaxId ELSE EXEC (N'SELECT Served, Stored, MaxId FROM sidata.FindingSourceLists()');"
}

function ConvertTo-SIFindingSourceLists {
    <# PURE. The lists' row -> @{ Active; Served; Stored; MaxId }. Active only when a collection is served AND both lists fit
       one session-context value (else: not active -- the tables, as before). #>
    param($Row)
    $g = { param($n) if ($null -eq $Row) { return $null }; if ($Row -is [System.Collections.IDictionary]) { $v = $Row[$n] } else { $v = $Row.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $sv = [string](& $g 'Served'); $st = [string](& $g 'Stored'); $mx = & $g 'MaxId'
    $mxl = if ($null -eq $mx) { 0L } else { [long]$mx }
    if ($st -cmatch '^\[(\d+(,\d+)*)?\]$') { $ahead = (1..$script:SIFindingSource.AheadIds | ForEach-Object { [string]($mxl + $_) }) -join ','; $st = if ($st -eq '[]') { "[$ahead]" } else { $st.TrimEnd(']') + ",$ahead]" } }
    if (-not $sv) { $sv = '[]' }; if (-not $st) { $st = '[]' }
    $ok = ($sv -cmatch '^\[(\d+(,\d+)*)?\]$') -and ($st -cmatch '^\[(\d+(,\d+)*)?\]$') -and $sv -ne '[]' -and $sv.Length -le $script:SIFindingSource.MaxListChars -and $st.Length -le $script:SIFindingSource.MaxListChars
    [pscustomobject]@{ Active = [bool]$ok; Served = $sv; Stored = $st; MaxId = $(if ($null -eq $mx) { 0L } else { [long]$mx }) }
}

function Read-SIFindingSourceLists {
    <# The database's lists now; not active when they cannot be read. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try { $r = @(@(& $Invoke (Get-SIFindingSourceListsSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1; return (ConvertTo-SIFindingSourceLists -Row $r) }
    catch { return [pscustomobject]@{ Active = $false; Served = '[]'; Stored = '[]'; MaxId = 0L } }
}

function Test-SIFindingSourceActive {
    <# Is any collection served from the history now? #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    (Read-SIFindingSourceLists -Invoke $Invoke).Active
}

function Get-SIFindingSourceContextSql {
    <# PURE. The statement that hands one statement its source lists (session context of its connection): -Served / -Stored
       JSON arrays of ids, -MaxId the newest id known. -Clear: no lists (every collection's stored rows). #>
    param([string]$Served = '[]', [string]$Stored = '[]', [long]$MaxId = 0, [switch]$Clear)
    if ($Clear) { return "EXEC sys.sp_set_session_context @key = N'si.finding.served', @value = NULL; EXEC sys.sp_set_session_context @key = N'si.finding.stored', @value = NULL; EXEC sys.sp_set_session_context @key = N'si.finding.maxid', @value = NULL;" }
    foreach ($x in $Served, $Stored) { if ($x -cnotmatch '^\[(\d+(,\d+)*)?\]$') { throw 'a source list is not a list of ids' } }
    "EXEC sys.sp_set_session_context @key = N'si.finding.served', @value = N'$Served'; EXEC sys.sp_set_session_context @key = N'si.finding.stored', @value = N'$Stored'; EXEC sys.sp_set_session_context @key = N'si.finding.maxid', @value = $MaxId;"
}

function New-SIFindingSourceInvoke {
    <#
        A reader job's seam (-Invoke: & $invoke $sql $params $mode ...) whose READS of the findings go to the served views, the
        source decided ONCE per statement: the lists (asked at most every CacheSeconds) handed to the statement as session
        context in the same batch. Not active = every statement exactly as written. -Lists forces the answer (a test).
        Every other argument goes through unchanged; the seam's own marks (note properties) are kept.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Lists = $null, [int]$CacheSeconds = $script:SIFindingSource.CacheSeconds)
    $inner = $Invoke
    $route = ${function:ConvertTo-SIFindingSourceSql}
    $ctx = ${function:Get-SIFindingSourceContextSql}
    $read = ${function:Read-SIFindingSourceLists}
    $state = @{ Lists = $Lists; Fixed = ($null -ne $Lists); At = [datetime]::MinValue; Cache = $CacheSeconds }
    # SUP-2026-00687 (3.1.44, internal's first run): NOT a GetNewClosure(). A closure runs in its own module scope, and the
    # inner seam New-SIRecordSqlInvoke builds names Invoke-SIRecordSqlDb, which the reader job loaded in ITS script scope --
    # inside the closure "Invoke-SIRecordSqlDb is not recognized" and the close-loop failed. The wrapper's state is kept in
    # one process-wide table under an id, and the wrapper runs where it is called, exactly like the seam it wraps.
    if ($null -eq $global:SIFindingSourceSeams) { $global:SIFindingSourceSeams = [hashtable]::Synchronized(@{}) }
    $id = [guid]::NewGuid().ToString('N')
    $global:SIFindingSourceSeams[$id] = @{ Inner = $inner; Route = $route; Ctx = $ctx; Read = $read; State = $state }
    $outer = [scriptblock]::Create(@"
`$e = `$global:SIFindingSourceSeams['$id']
`$a = @(`$args)
if (`$a.Count -gt 0 -and `$a[0] -is [string]) {
    `$st = `$e.State
    if (-not `$st.Fixed -and ([datetime]::UtcNow - `$st.At).TotalSeconds -ge `$st.Cache) {
        `$st.Lists = & `$e.Read -Invoke `$e.Inner; `$st.At = [datetime]::UtcNow
    }
    `$l = `$st.Lists
    if (`$l -and `$l.Active) {
        `$r = & `$e.Route `$a[0]
        if (-not [object]::ReferenceEquals(`$r, `$a[0]) -and `$r -cne `$a[0]) { `$a[0] = (& `$e.Ctx -Served `$l.Served -Stored `$l.Stored -MaxId `$l.MaxId) + "``n" + `$r }
    }
}
& `$e.Inner @a
"@)
    foreach ($p in @($inner.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })) {
        $outer | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
    }
    $outer | Add-Member -NotePropertyName SIFindingSourceRouted -NotePropertyValue $true -Force
    $outer
}