#Requires -Version 5.1
<#
    SecurityInsight -- A SOURCE THAT WENT SILENT HOLDS THE REPORTS THAT READ IT (owner 2026-10-25: "Build the rule for the
    next release" -- a finding must never close because a source went silent; REQUIREMENTS #900).

    Live 2026-10-25 (internal): the Defender table DeviceTvmBrowserExtensions returned 0 rows in one collection although it
    had rows in every run before; Device_BrowserExtensions_Detailed was recorded Complete with ExpectedRows 0 / StoredRows 0,
    so its 3 findings would have closed as "remediated" -- a close on silence, not on a fix. The report-level row-drop
    guard (ra.output.row-drop) would have seen it, but that guard is off by default; and the source state
    (sidata.SourceState) knows collection steps, not the Defender tables a report reads.

    THE RULE (always on: a damage brake, no setting):
      * every source table the reports of the run read (a Defender / Sentinel table at a table position of the report's
        query -- Get-RASourceTables) is counted ONCE per run, ONE `summarize count()` query per route (advanced hunting,
        Log Analytics), timed, with a phase row (cfg.StepPhaseTime);
      * a table that counts 0 now and HAD rows before (its last non-zero count, kept in sidata.RaSourceCount -- or, for a
        table never counted before, a report reading it that had rows at its previous complete run) is SILENT, and stays silent
        until it has rows again (two silent runs in a row hold twice);
      * every report that reads a silent table -- also as a lookup only -- is NOT COMPLETE: it keeps its last complete
        result and nothing of it closes (the per-report freeze: sidata.RaReportStatus NotComplete, scope 'reports',
        Resolve-SIReportScopedComplete). A WARNING every run says which table, its last non-zero count and date, which
        reports are held, and what an Admin can do when the feature was really retired (switch the reports off);
      * a table that was always empty is never silent (a feature the customer does not use); a report that goes to 0
        while its tables still have rows closes as usual (everything fixed);
      * the count of a route cannot be had (it failed, it timed out): the FALLBACK holds a report reading a table of that
        route only when its own source count (ExpectedRows) went from > 0 at its last complete run to 0 now.
    Never a block: it warns and holds those reports only, the run goes on and is partial at worst. Never throws.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

# #902: the one list of hold kinds (data-model/hold-kinds.locked.json) -- the kind a deliberate hold may carry
if (-not (Get-Command -Name Test-SIHoldKind -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-HoldKinds.ps1')) }

# the tables a report reads that a source fills -- exact names (a column such as DeviceKey, or a let such as
# DeviceInfoLatest, is not a table). SI's own *_CL tables are not here: their completeness is the profile runs' and the
# source state's (sidata.SourceState).
$script:RASilentHuntingTables = '(?:DeviceInfo|DeviceNetworkInfo|DeviceLogonEvents|DeviceProcessEvents|DeviceNetworkEvents|DeviceFileEvents|DeviceRegistryEvents|DeviceEvents|DeviceImageLoadEvents|DeviceFileCertificateInfo|DeviceTvm[A-Za-z]+|DeviceBaselineCompliance[A-Za-z]+|IdentityInfo|IdentityLogonEvents|IdentityQueryEvents|IdentityDirectoryEvents|IdentityAccountInfo|ExposureGraphNodes|ExposureGraphEdges|AlertInfo|AlertEvidence|CloudAppEvents|BehaviorInfo|BehaviorEntities|EmailEvents|EmailUrlInfo|EmailAttachmentInfo|EmailPostDeliveryEvents|UrlClickEvents|EntraIdSignInEvents|EntraIdSpnSignInEvents|AADSignInEventsBeta|AADSpnSignInEventsBeta)'
$script:RASilentLogTables = '(?:SigninLogs|AuditLogs|AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AADManagedIdentitySignInLogs|AADProvisioningLogs|IntuneAuditLogs|MicrosoftGraphActivityLogs)'

function Get-RASourceTables {
    <# PURE. The source tables -Query reads at a TABLE position (start of a statement, after a pipe, '(', ',', '=', union
       [isfuzzy=...], join [kind=...]), comments and string literals left out: @(@{ Table; Route }) sorted by table, Route
       'hunting' (Defender, advanced hunting) or 'loganalytics' (Sentinel tables). #>
    param([AllowEmptyString()][AllowNull()][string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }
    $s = [regex]::Replace($Query, '//[^\r\n]*', '')
    $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '""')
    $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "''")
    $anchor = '(?m)(?:^|\||\(|,|=|\bunion\b(?:\s+(?:isfuzzy|withsource|kind)\s*=\s*\w+)*|\bjoin\b(?:\s+(?:kind|hint\.\w+)\s*=\s*\w+)*)\s*'
    $out = @{}
    foreach ($m in [regex]::Matches($s, ($anchor + '(' + $script:RASilentHuntingTables + ')\b(?!\s*\()'))) { $out[$m.Groups[1].Value] = 'hunting' }
    foreach ($m in [regex]::Matches($s, ($anchor + '(' + $script:RASilentLogTables + ')\b(?!\s*\()'))) { $out[$m.Groups[1].Value] = 'loganalytics' }
    @($out.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Table = [string]$_; Route = [string]$out[$_] } })
}

function Get-RASourceTableMap {
    <# PURE. The report -> source table map for the reports of the run: -Reports the catalog entries (ReportName,
       ReportQuery), -Names the reports of the run (none = every entry). @{ Reports = @{ report -> [string[]] tables };
       Routes = @{ table -> route } }. A report that reads no source table is not in Reports. #>
    param([AllowEmptyCollection()][object[]]$Reports = @(), [AllowEmptyCollection()][string[]]$Names = @())
    $want = $null
    if (@($Names | Where-Object { $_ }).Count) { $want = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); foreach ($n in $Names) { if ($n) { [void]$want.Add([string]$n) } } }
    $map = @{}; $routes = @{}
    foreach ($r in @($Reports)) {
        if ($null -eq $r) { continue }
        $name = ''; $q = ''
        if ($r -is [System.Collections.IDictionary]) { $name = [string]$r['ReportName']; $q = (@($r['ReportQuery']) -join "`n") }
        else { if ($r.PSObject.Properties['ReportName']) { $name = [string]$r.ReportName }; if ($r.PSObject.Properties['ReportQuery']) { $q = (@($r.ReportQuery) -join "`n") } }
        if (-not $name) { continue }
        if ($null -ne $want -and -not $want.Contains($name)) { continue }
        $t = @(Get-RASourceTables -Query $q)
        if (-not $t.Count) { continue }
        $map[$name] = [string[]]@($t | ForEach-Object { $_.Table })
        foreach ($x in $t) { $routes[$x.Table] = $x.Route }
    }
    [pscustomobject]@{ Reports = $map; Routes = $routes }
}

function Get-RASourceCountKql {
    <# PURE. ONE count query for the tables of one route: each table's rows (a table that does not exist answers nothing,
       isfuzzy -- read as 0). Log Analytics: the 30 days advanced hunting answers by itself. #>
    param([Parameter(Mandatory)][string[]]$Tables, [ValidateSet('hunting', 'loganalytics')][string]$Route = 'hunting')
    $list = (@($Tables | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
    $win = ''
    if ($Route -eq 'loganalytics') { $win = "`n| where TimeGenerated > ago(30d)" }
    ("union withsource=SISourceTable isfuzzy=true {0}{1}`n| summarize SIRows = count() by SISourceTable" -f $list, $win)
}

function Get-RASourceRouteLabel {
    <# PURE. The route as a person reads it. #>
    param([string]$Route)
    if ($Route -eq 'loganalytics') { 'Log Analytics' } else { 'advanced hunting' }
}

function Invoke-RASourceCounts {
    <#
        The run's source counts: ONE query per route (-RunQuery { param($Route, $Kql) rows }, rows with SISourceTable and
        SIRows), each timed (-Phase { param($Name, $Seconds, $Rows) } -- the log line and the phase row). A table the answer
        does not name is 0 (isfuzzy: it does not exist). A route whose query fails is FAILED (its tables are not counted:
        the fallback judges their reports). Never throws.
        @{ Counts = @{ table -> long }; Failed = @{ route -> why }; Seconds = @{ route -> s }; Routes = @{ table -> route };
           Queries = n; At = UTC }
    #>
    param([hashtable]$Routes = @{}, [Parameter(Mandatory)][scriptblock]$RunQuery, [scriptblock]$Phase, [scriptblock]$Log, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [pscustomobject]@{ Counts = @{}; Failed = @{}; Seconds = @{}; Routes = $Routes; Queries = 0; At = $NowUtc.ToUniversalTime() }
    foreach ($route in @('hunting', 'loganalytics')) {
        $tables = @(@($Routes.Keys) | Where-Object { [string]$Routes[$_] -eq $route } | Sort-Object)
        if (-not $tables.Count) { continue }
        $out.Queries++
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $rows = @(& $RunQuery $route (Get-RASourceCountKql -Tables $tables -Route $route) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $got = @{}
            foreach ($r in $rows) {
                $t = $null; $n = $null
                if ($r -is [System.Collections.IDictionary]) { $t = $r['SISourceTable']; $n = $r['SIRows'] }
                else { if ($r.PSObject.Properties['SISourceTable']) { $t = $r.SISourceTable }; if ($r.PSObject.Properties['SIRows']) { $n = $r.SIRows } }
                if (-not $t) { continue }
                # a table in another workspace answers as 'workspace(...).T' or '<db>.T' -- the table is the last part
                $tn = (([string]$t) -split '\.')[-1].Trim()
                $v = 0L; if ($null -ne $n -and -not ($n -is [System.DBNull])) { $v = [long]$n }
                $got[$tn] = [long]$got[$tn] + $v
            }
            foreach ($t in $tables) { $out.Counts[$t] = $(if ($got.ContainsKey($t)) { [long]$got[$t] } else { 0L }) }
            $sw.Stop(); $out.Seconds[$route] = $sw.Elapsed.TotalSeconds
            if ($Phase) { try { & $Phase ('source count: {0}' -f (Get-RASourceRouteLabel $route)) $sw.Elapsed.TotalSeconds ([long]$tables.Count) } catch { } }
        } catch {
            $sw.Stop(); $out.Seconds[$route] = $sw.Elapsed.TotalSeconds
            $why = ([string]$_.Exception.Message -split "`n")[0]
            if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
            $out.Failed[$route] = $why
            if ($Phase) { try { & $Phase ('source count: {0} (failed)' -f (Get-RASourceRouteLabel $route)) $sw.Elapsed.TotalSeconds ([long]-1) } catch { } }
            if ($Log) { & $Log 'WARN' ('source count: the {0} tables could not be counted this run ({1}) -- {2} table(s): the reports reading them are held only when their own source count went from rows to none' -f (Get-RASourceRouteLabel $route), $why, $tables.Count) }
        }
    }
    $out
}

function Format-RASourceCountLine {
    <# PURE. The run's one line about the counts: queries, tables, seconds per route, the silent tables. #>
    param($Counts)
    if ($null -eq $Counts) { return 'source count: not run' }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($route in @('hunting', 'loganalytics')) {
        $n = @(@($Counts.Routes.Keys) | Where-Object { [string]$Counts.Routes[$_] -eq $route }).Count
        if (-not $n) { continue }
        $s = 0.0; if ($Counts.Seconds.ContainsKey($route)) { $s = [double]$Counts.Seconds[$route] }
        $st = if ($Counts.Failed.ContainsKey($route)) { 'FAILED' } else { 'counted' }
        $parts.Add(('{0}: {1} table(s) {2} in {3} s' -f (Get-RASourceRouteLabel $route), $n, $st, $s.ToString('0.0', $inv)))
    }
    $zero = @(@($Counts.Counts.Keys) | Where-Object { [long]$Counts.Counts[$_] -eq 0 } | Sort-Object)
    $z = ''; if ($zero.Count) { $z = (' -- no rows now: {0}' -f ($zero -join ', ')) }
    ('source count: {0} source table(s) in {1} quer(ies) ({2}){3}' -f @($Counts.Routes.Keys).Count, [int]$Counts.Queries, ($parts -join '; '), $z)
}

function Get-RASourceCountSql {
    <# The T-SQL of the source counts (one place; the real-SQL test runs it against sql\si-data-schema.sql). Every value
       is text (the seam's rule). 'Read': the stored state of the tables named (@tables, JSON). 'Write': this run's state of
       each table counted (@states, JSON) in ONE statement. 'Reports': per report named (@names, JSON) its source count now
       (this collection, @t / @g) and at its newest earlier COMPLETE run of the same grain (its previous complete run).
       A database without sidata.RaSourceCount answers nothing and changes nothing. #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Write', 'Reports')][string]$Name)
    switch ($Name) {
        'Read' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RaSourceCount') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(128)) AS SourceTable, CAST(NULL AS BIGINT) AS LastRows, CAST(NULL AS DATETIME2(3)) AS LastCountedAt, CAST(NULL AS BIGINT) AS LastNonZeroRows,
           CAST(NULL AS DATETIME2(3)) AS LastNonZeroAt, CAST(NULL AS DATETIME2(3)) AS SilentSince, CAST(NULL AS NVARCHAR(400)) AS SilentNote WHERE 1 = 0;
    RETURN;
END
SELECT s.SourceTable, s.LastRows, s.LastCountedAt, s.LastNonZeroRows, s.LastNonZeroAt, s.SilentSince, s.SilentNote
FROM sidata.RaSourceCount s WHERE s.SourceTable IN (SELECT [value] FROM OPENJSON(@tables));
'@ }
        'Write' { @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RaSourceCount') IS NULL BEGIN SELECT 0 AS Written; RETURN; END
MERGE sidata.RaSourceCount AS t
USING (SELECT j.SourceTable, TRY_CONVERT(BIGINT, j.LastRows) AS LastRows, TRY_CONVERT(DATETIME2(3), NULLIF(j.LastCountedAt, N''), 127) AS LastCountedAt,
              TRY_CONVERT(BIGINT, NULLIF(j.LastNonZeroRows, N'')) AS LastNonZeroRows, TRY_CONVERT(DATETIME2(3), NULLIF(j.LastNonZeroAt, N''), 127) AS LastNonZeroAt,
              TRY_CONVERT(DATETIME2(3), NULLIF(j.SilentSince, N''), 127) AS SilentSince, NULLIF(j.SilentNote, N'') AS SilentNote
       FROM OPENJSON(@states) WITH (SourceTable NVARCHAR(128) '$.T', LastRows NVARCHAR(30) '$.R', LastCountedAt NVARCHAR(40) '$.At', LastNonZeroRows NVARCHAR(30) '$.NzR',
                                    LastNonZeroAt NVARCHAR(40) '$.NzAt', SilentSince NVARCHAR(40) '$.Ss', SilentNote NVARCHAR(400) '$.Sn') j
       WHERE NULLIF(j.SourceTable, N'') IS NOT NULL) AS s ON t.SourceTable = s.SourceTable
WHEN MATCHED THEN UPDATE SET LastRows = s.LastRows, LastCountedAt = s.LastCountedAt, LastNonZeroRows = s.LastNonZeroRows, LastNonZeroAt = s.LastNonZeroAt,
     SilentSince = s.SilentSince, SilentNote = s.SilentNote, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (SourceTable, LastRows, LastCountedAt, LastNonZeroRows, LastNonZeroAt, SilentSince, SilentNote)
     VALUES (s.SourceTable, s.LastRows, s.LastCountedAt, s.LastNonZeroRows, s.LastNonZeroAt, s.SilentSince, s.SilentNote);
SELECT @@ROWCOUNT AS Written;
'@ }
        'Reports' { @'
SET NOCOUNT ON;
DECLARE @tt DATETIME2(3) = CONVERT(DATETIME2(3), @t, 126);
IF OBJECT_ID('sidata.RaReportStatus') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS BIGINT) AS NowRows, CAST(NULL AS BIGINT) AS BeforeRows, CAST(NULL AS DATETIME2(3)) AS BeforeAt WHERE 1 = 0;
    RETURN;
END
SELECT n.[value] AS ReportName,
       (SELECT TOP (1) COALESCE(s.ExpectedRows, s.RetrievedRows) FROM sidata.RaReportStatus s
        WHERE s.CollectionTime = @tt AND s.Grain = @g AND s.ReportName = n.[value]) AS NowRows,
       b.R AS BeforeRows, b.T AS BeforeAt
FROM OPENJSON(@names) n
OUTER APPLY (SELECT TOP (1) COALESCE(s.ExpectedRows, s.RetrievedRows) AS R, s.CollectionTime AS T FROM sidata.RaReportStatus s
             WHERE s.Grain = @g AND s.ReportName = n.[value] AND s.State = N'Complete' AND s.CollectionTime < @tt
             ORDER BY s.CollectionTime DESC) b;
'@ }
    }
}

function ConvertTo-RASourceTimeText {
    <# PURE. A time as the ISO text the statements take ('' for none); a database value back as UTC [datetime] or $null. #>
    param($Value, [switch]$FromDb)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or "$Value" -eq '') { if ($FromDb) { return $null } else { return '' } }
    if ($FromDb) {
        if ($Value -is [datetime]) { return [datetime]::SpecifyKind([datetime]$Value, 'Utc') }
        try { return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return $null }
    }
    ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
}

function Format-RASourceWhen {
    <# PURE. "2026-10-25 06:22 UTC". #>
    param($Utc)
    if ($null -eq $Utc) { return 'an earlier run' }
    ([datetime]$Utc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
}

function Resolve-RASilentSources {
    <#
        PURE. Each counted table's state after this run, and whether it is SILENT. -Counts @{ table -> long } (only the
        tables counted this run), -Prior @{ table -> stored row (Read) }, -Evidence @{ table -> @{ Report; Rows; At } } (a
        report reading it that had rows at its previous complete run -- used ONLY for a table with no counted non-zero value).
          rows now               -> not silent; its last non-zero count is now; a silence ends (Back)
          0, had rows before     -> SILENT (its last non-zero count and date said), until it has rows again
          0, no counted row ever, a report reading it had rows at its previous complete run -> SILENT (that report's rows
                                    said) -- judged again EVERY run, also when a silence is stored (coordinator 2026-10-26)
          0, otherwise           -> not silent (it never had rows: a feature not in use); a stored silence ends (Back)
        @{ table -> @{ Table; Silent; Back; Note; Rows; State = @{ T; R; At; NzR; NzAt; Ss; Sn } } }
    #>
    param([hashtable]$Counts = @{}, [hashtable]$Prior = @{}, [hashtable]$Evidence = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $val = { param($r, $n) if ($null -eq $r) { $null } elseif ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
    $out = @{}
    foreach ($t in @($Counts.Keys | Sort-Object)) {
        $c = [long]$Counts[$t]
        $p = $Prior[$t]
        $nzR = & $val $p 'LastNonZeroRows'; if ($nzR -is [System.DBNull]) { $nzR = $null }
        $nzAt = ConvertTo-RASourceTimeText (& $val $p 'LastNonZeroAt') -FromDb
        $ss = ConvertTo-RASourceTimeText (& $val $p 'SilentSince') -FromDb
        $sn = & $val $p 'SilentNote'; if ($sn -is [System.DBNull]) { $sn = $null }
        $silent = $false; $back = $false; $note = ''
        if ($c -gt 0) {
            $back = ($null -ne $ss)
            $nzR = $c; $nzAt = $now; $ss = $null; $sn = $null
        } elseif ($null -ne $nzAt -and $null -ne $nzR -and [long]$nzR -gt 0) {
            $silent = $true
            $note = ('it had {0} row(s) on {1}' -f [long]$nzR, (Format-RASourceWhen $nzAt))
            if ($null -eq $ss) { $ss = $now }
            $sn = $note
        } elseif ($Evidence.ContainsKey($t) -and $null -ne $Evidence[$t]) {
            # no counted non-zero value ever (a first count, or a silence stored without one): judged EVERY run by the
            # reports -- one of them had rows at its previous complete run (a held run is NotComplete, so it keeps pointing
            # at the run that had them)
            $e = $Evidence[$t]
            $silent = $true
            $note = ('report {0} had {1} row(s) at its previous run ({2})' -f [string]$e.Report, [long]$e.Rows, (Format-RASourceWhen $e.At))
            if ($null -eq $ss) { $ss = $now }
            $sn = $note
        } else {
            # never had a counted row and no report had rows at its previous run: not silent -- a silence stored without
            # one (the first-count rule before 2026-10-26) is released here
            $back = ($null -ne $ss)
            $ss = $null; $sn = $null
        }
        $out[$t] = [pscustomobject]@{ Table = $t; Silent = $silent; Back = $back; Note = $note; Rows = $c
            State = [ordered]@{ T = $t; R = [string]$c; At = (ConvertTo-RASourceTimeText $now); NzR = $(if ($null -ne $nzR) { [string][long]$nzR } else { '' })
                                NzAt = (ConvertTo-RASourceTimeText $nzAt); Ss = (ConvertTo-RASourceTimeText $ss); Sn = $(if ($sn) { [string]$sn } else { '' }) } }
    }
    $out
}

function Get-RASilentSourceHolds {
    <#
        PURE. The reports to hold this run: @(@{ Report; Why; Tables; Fallback }) in report order.
          -Map      report -> tables (Get-RASourceTableMap .Reports)
          -Tables   table -> resolved state (Resolve-RASilentSources)
          -Unknown  the tables whose route could not be counted this run (table -> why)
          -Status   report -> @{ NowRows; BeforeRows; BeforeAt } (Get-RASourceCountSql 'Reports')
          -Accepted report -> the tables an Admin accepted as empty for good for THAT report (#902 (5), cfg.RaSourceAccept)
        A report reading a SILENT table is held -- unless EVERY silent table it reads is accepted for it (then it runs as
        usual: empty and complete). A report that reads no silent table but a table that could not be counted is held only
        when its source count went from > 0 at its last complete run to 0 now (the fallback; an acceptance never covers it).
    #>
    param([hashtable]$Map = @{}, [hashtable]$Tables = @{}, [hashtable]$Unknown = @{}, [hashtable]$Status = @{}, [hashtable]$Accepted = @{})
    if ($null -eq $Accepted) { $Accepted = @{} }
    $val = { param($r, $n) if ($null -eq $r) { $null } elseif ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
    foreach ($rep in @($Map.Keys | Sort-Object)) {
        $ts = @($Map[$rep])
        $silent = @($ts | Where-Object { $Tables.ContainsKey($_) -and $Tables[$_].Silent } | Sort-Object)
        if ($silent.Count) {
            $acc = @($Accepted[$rep] | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $open = @($silent | Where-Object { $acc -notcontains $_ })
            # every silent table of it accepted as empty for this report: not held for them (the fallback below still judges it)
            $silent = $open
        }
        if ($silent.Count) {
            $what = (@($silent | ForEach-Object { '{0} returned no rows ({1})' -f $_, [string]$Tables[$_].Note }) -join '; ')
            [pscustomobject]@{ Report = [string]$rep; Tables = [string[]]$silent; Fallback = $false
                Why = ('a source went silent: {0} -- the report kept its last result, nothing of it closed' -f $what) }
            continue
        }
        $unk = @($ts | Where-Object { $Unknown.ContainsKey($_) } | Sort-Object)
        if (-not $unk.Count) { continue }
        $s = $Status[$rep]
        $now = & $val $s 'NowRows'; $bef = & $val $s 'BeforeRows'
        if ($null -eq $now -or $now -is [System.DBNull] -or $null -eq $bef -or $bef -is [System.DBNull]) { continue }
        if ([long]$now -ne 0 -or [long]$bef -le 0) { continue }
        $at = ConvertTo-RASourceTimeText (& $val $s 'BeforeAt') -FromDb
        [pscustomobject]@{ Report = [string]$rep; Tables = [string[]]$unk; Fallback = $true
            Why = ('its source tables could not be counted this run ({0}: {1}) and the report''s source count went from {2} at its last complete run ({3}) to 0 -- held as a source that went silent: the report kept its last result, nothing of it closed' -f ($unk -join ', '), [string]$Unknown[$unk[0]], [long]$bef, (Format-RASourceWhen $at)) }
    }
}

function Get-RASilentSourceWarnings {
    <# PURE. The WARNING lines of the run, one per silent table (its last non-zero count and date, the reports held, what an
       Admin can do), and one for the reports the fallback held. -Accepted (#902 (5)): report -> the tables accepted as empty
       for it -- those reports are named as accepted, not as held. #>
    param([hashtable]$Map = @{}, [hashtable]$Tables = @{}, [AllowEmptyCollection()][object[]]$Holds = @(), [hashtable]$Accepted = @{})
    if ($null -eq $Accepted) { $Accepted = @{} }
    foreach ($t in @($Tables.Keys | Where-Object { $Tables[$_].Silent } | Sort-Object)) {
        $all = @($Map.Keys | Where-Object { @($Map[$_]) -contains $t } | Sort-Object)
        $acc = @($all | Where-Object { @($Accepted[$_] | ForEach-Object { [string]$_ }) -contains $t })
        $reps = @($all | Where-Object { $acc -notcontains $_ })
        if ($acc.Count) { ('source {0} returned no rows this run; {1} -- an Admin accepted it as empty for report(s) {2}: they show empty and complete. Accepted until {0} has rows again.' -f $t, [string]$Tables[$t].Note, ($acc -join ', ')) }
        if (-not $reps.Count) { continue }
        ('source {0} returned no rows this run; {1} -- report(s) {2} kept their last result and nothing of them closed. They are held every run until {0} has rows again. If this source was really retired for this install, an Admin can switch those reports off (Reports > the report > Report it), or accept the empty source for a report (Run health > Risk Analysis reports > Accept as empty).' -f $t, [string]$Tables[$t].Note, ($reps -join ', '))
    }
    $fb = @($Holds | Where-Object { $_ -and $_.Fallback })
    if ($fb.Count) {
        ('the source tables could not be counted this run, and {0} report(s) went from rows at their last complete run to none: {1} -- they kept their last result and nothing of them closed' -f $fb.Count, (@($fb | ForEach-Object { $_.Report }) -join ', '))
    }
}

function Invoke-RASilentSourceCheck {
    <#
        The end of the run (the producer, the result in the database): judges this run's source counts (-Counts,
        Invoke-RASourceCounts) against what is stored, writes each counted table's state, and answers the reports to hold
        (Get-RASilentSourceHolds) with the warning lines. -Invoke the database seam; -TimeText / -Grain this collection.
        Never throws: a database that cannot be read or written holds nothing and says so.
        @{ Holds; Warnings; Tables; Back; Error }
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$TimeText, [Parameter(Mandatory)][string]$Grain, [hashtable]$Map = @{}, $Counts,
          [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Log, [hashtable]$Accepted = @{})
    # -Accepted (#902 (5)): report -> the tables an Admin accepted as empty for it (the active acceptances of this run)
    $out = [pscustomobject]@{ Holds = @(); Warnings = @(); Tables = @{}; Back = @(); Error = '' }
    try {
        if ($null -eq $Counts -or -not @($Map.Keys).Count) { return $out }
        $rows = { param($sql, $p) @(& $Invoke $sql $p 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
        $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
        $counted = @($Counts.Counts.Keys)
        $prior = @{}
        if ($counted.Count) {
            foreach ($r in (& $rows (Get-RASourceCountSql 'Read') @{ tables = (ConvertTo-Json -InputObject @($counted) -Compress) })) { $k = [string](& $val $r 'SourceTable'); if ($k) { $prior[$k] = $r } }
        }
        # what each report said: now, and at its previous complete run of this grain (one statement)
        $status = @{}
        foreach ($r in (& $rows (Get-RASourceCountSql 'Reports') @{ t = $TimeText; g = $Grain; names = (ConvertTo-Json -InputObject @($Map.Keys | Sort-Object) -Compress) })) {
            $k = [string](& $val $r 'ReportName'); if ($k) { $status[$k] = $r }
        }
        # the evidence for a table never counted before: a report reading it had rows at its PREVIOUS complete run of this
        # grain (live 2026-10-26: "had rows 11 days ago" held a sign-in report whose table was never exported -- rows long
        # ago are no evidence the table just went silent)
        $evidence = @{}
        $noRowsEver = { param($t) if (-not $prior.ContainsKey($t)) { return $true }; $n = & $val $prior[$t] 'LastNonZeroRows'; ($null -eq $n -or $n -is [System.DBNull] -or [long]$n -le 0) }
        foreach ($t in @($counted | Where-Object { [long]$Counts.Counts[$_] -eq 0 -and (& $noRowsEver $_) })) {
            $best = $null
            foreach ($rep in @($Map.Keys | Where-Object { @($Map[$_]) -contains $t } | Sort-Object)) {
                $s = $status[$rep]; if ($null -eq $s) { continue }
                $er = & $val $s 'BeforeRows'; if ($null -eq $er -or $er -is [System.DBNull] -or [long]$er -le 0) { continue }
                $ea = ConvertTo-RASourceTimeText (& $val $s 'BeforeAt') -FromDb
                if ($null -eq $best -or ($null -ne $ea -and $ea -gt $best.At)) { $best = [pscustomobject]@{ Report = $rep; Rows = [long]$er; At = $ea } }
            }
            if ($best) { $evidence[$t] = $best }
        }
        $resolved = Resolve-RASilentSources -Counts $Counts.Counts -Prior $prior -Evidence $evidence -NowUtc $NowUtc
        $out.Tables = $resolved
        if (@($resolved.Keys).Count) {
            $null = & $Invoke (Get-RASourceCountSql 'Write') @{ states = (ConvertTo-Json -InputObject @($resolved.Keys | Sort-Object | ForEach-Object { $resolved[$_].State }) -Compress -Depth 3) } 'scalar'
        }
        $unknown = @{}
        foreach ($t in @($Counts.Routes.Keys)) { $rt = [string]$Counts.Routes[$t]; if ($Counts.Failed.ContainsKey($rt)) { $unknown[$t] = [string]$Counts.Failed[$rt] } }
        $out.Holds = @(Get-RASilentSourceHolds -Map $Map -Tables $resolved -Unknown $unknown -Status $status -Accepted $Accepted)
        $out.Warnings = @(Get-RASilentSourceWarnings -Map $Map -Tables $resolved -Holds $out.Holds -Accepted $Accepted)
        $out.Back = @($resolved.Keys | Where-Object { $resolved[$_].Back } | Sort-Object)
    } catch {
        $out.Error = [string]$_.Exception.Message
        $out.Holds = @(); $out.Warnings = @()
        if ($Log) { & $Log 'WARN' ('source count: the silent-source check could not be made this run ({0}) -- no report is held for it' -f $out.Error) }
    }
    $out
}

# =====================================================================================================================
#  #901 A DELIBERATE HOLD PUBLISHES (owner: "a report fails alone, the job completes ... we use last known good data")
# =====================================================================================================================
function Add-RADeliberateHold {
    <# A report SI holds ON PURPOSE at its last complete result, with the exact reason it was given (Add-RAReportFailure):
       -Kind: a kind of THE list (#902, data-model/hold-kinds.locked.json -- 'silent-source' #900, 'role-read' #899); a kind
       that is not in it is NOT kept, so the report stays a real failure (the safe direction). -Names: what the hold is about
       (the silent tables), kept for the stored HoldNames, the uplink item's MissingName and the Admin's acceptance.
       Kept in -Store (report -> @{ Kind; Whys; Names }). Returns nothing. #>
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Report, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Why,
          [AllowEmptyCollection()][string[]]$Names = @())
    if (-not (Test-SIHoldKind -Kind $Kind)) { Write-Verbose ("not a hold kind of the list: '{0}' -- {1} stays a real failure" -f $Kind, $Report); return }
    if (-not $Store.ContainsKey($Report)) { $Store[$Report] = @{ Kind = $Kind; Whys = (New-Object System.Collections.Generic.List[string]); Names = (New-Object System.Collections.Generic.List[string]) } }
    if (-not $Store[$Report].ContainsKey('Names')) { $Store[$Report].Names = (New-Object System.Collections.Generic.List[string]) }
    if (-not $Store[$Report].Whys.Contains($Why)) { $Store[$Report].Whys.Add($Why) }
    foreach ($n in @($Names | Where-Object { "$_".Trim() })) { if (-not $Store[$Report].Names.Contains([string]$n)) { $Store[$Report].Names.Add([string]$n) } }
}

function Get-RADeliberateHoldKind {
    <#
        PURE. The HoldKind a NotComplete report is stored with ('' = none: the run stays partial for it, as before). A kind
        ONLY when the report was held on purpose (-Holds, Add-RADeliberateHold) AND nothing else is wrong with it: every
        failure the run recorded for it (-Failures @{ Report; Why }) is one of those holds, the row-count guard did not flag
        it (-Flagged), no query slice of it was lost (-BucketLoss, 'report :: ...'), and it was not held back (#877, -HeldBack).
    #>
    param([Parameter(Mandatory)][string]$Report, [hashtable]$Holds = @{}, [AllowEmptyCollection()][object[]]$Failures = @(),
          [AllowEmptyCollection()][string[]]$Flagged = @(), [AllowEmptyCollection()][string[]]$BucketLoss = @(), [AllowEmptyCollection()][string[]]$HeldBack = @())
    if (-not $Holds.ContainsKey($Report)) { return '' }
    if (@($Flagged) -contains $Report -or @($HeldBack) -contains $Report) { return '' }
    if (@($BucketLoss | Where-Object { $_ -and ((([string]$_) -split ' :: ', 2)[0]) -eq $Report }).Count) { return '' }
    $mine = @($Failures | Where-Object { $_ -and [string]$_.Report -eq $Report } | ForEach-Object { [string]$_.Why })
    if (-not $mine.Count) { return '' }
    foreach ($w in $mine) { if (-not $Holds[$Report].Whys.Contains($w)) { return '' } }
    [string]$Holds[$Report].Kind
}

function Split-RAReportFailures {
    <#
        PURE. SUP-2026-00322: the run's report failures split by THE rule of a deliberate hold (Get-RADeliberateHoldKind --
        the one the stored HoldKind uses, never a second rule). Returns @{ Real; Held }:
          Real  the failures (as given, @{ Report; Why }) of every report whose kind is '' -- a report that really did not
                complete: the mail says Failed for it, the run record names it as incomplete;
          Held  one entry per report held ON PURPOSE, @{ Report; Kind; Why } (Why without the 'not complete: ' lead) -- its
                last complete result is shown and nothing of it closes: said as information, never as a failure.
        -Failures @{ Report; Why } (Add-RAReportFailure); -Holds / -Flagged / -BucketLoss / -HeldBack as
        Get-RADeliberateHoldKind takes them. Report order is kept.
        #902: each Held entry also carries Names (what the hold is about, Add-RADeliberateHold -Names), HeldRuns and
        KeptResultAt (-Streak: report -> @{ HeldRuns; KeptResultAt }, Read-RAStreamHoldStreak; none = 1 run, not known) and
        Escalated (Test-SIHoldEscalated with -Grain: a Detailed hold of escalateAfterDetailedRuns runs or more -- a real
        problem to tell; the report still keeps its last complete result). Whether a report is held does NOT change.
    #>
    param([AllowEmptyCollection()][object[]]$Failures = @(), [hashtable]$Holds = @{}, [AllowEmptyCollection()][string[]]$Flagged = @(),
          [AllowEmptyCollection()][string[]]$BucketLoss = @(), [AllowEmptyCollection()][string[]]$HeldBack = @(),
          [hashtable]$Streak = @{}, [AllowEmptyString()][string]$Grain = '')
    if ($null -eq $Holds) { $Holds = @{} }
    if ($null -eq $Streak) { $Streak = @{} }
    $all = @($Failures | Where-Object { $null -ne $_ })
    $kinds = @{}
    $real = New-Object System.Collections.Generic.List[object]
    $held = New-Object System.Collections.Generic.List[object]
    foreach ($f in $all) {
        $r = [string]$f.Report
        if (-not $kinds.ContainsKey($r)) {
            $k = ''
            if ($r) { $k = [string](Get-RADeliberateHoldKind -Report $r -Holds $Holds -Failures $all -Flagged @($Flagged) -BucketLoss @($BucketLoss) -HeldBack @($HeldBack)) }
            $kinds[$r] = $k
            if ($k) {
                $whys = @($all | Where-Object { [string]$_.Report -eq $r } | ForEach-Object { ([string]$_.Why) -replace '^\s*not complete:\s*', '' } | Where-Object { "$_".Trim() } | Select-Object -Unique)
                $names = @(); if ($Holds[$r] -and $Holds[$r].ContainsKey('Names') -and $Holds[$r].Names) { $names = @($Holds[$r].Names.ToArray()) }
                $hr = 1; $kept = $null
                $sk = $Streak[$r]
                if ($sk) { if ($sk.HeldRuns) { $hr = [int]$sk.HeldRuns }; if ($sk.KeptResultAt) { $kept = $sk.KeptResultAt } }
                $held.Add([pscustomobject]@{ Report = $r; Kind = $k; Why = ($whys -join '; '); Names = [string[]]$names; HeldRuns = $hr; KeptResultAt = $kept
                                             Escalated = [bool](Test-SIHoldEscalated -HeldRuns $hr -Grain $Grain) })
            }
        }
        if (-not $kinds[$r]) { $real.Add($f) }
    }
    [pscustomobject]@{ Real = $real.ToArray(); Held = $held.ToArray() }
}

# =====================================================================================================================
#  #902 (5) A SOURCE THAT IS EMPTY FOR GOOD: an Admin accepts it PER REPORT (cfg.RaSourceAccept, written by the web app)
# =====================================================================================================================
function Get-RASourceAcceptSql {
    <# The T-SQL of the acceptances (one place; the real-SQL test runs it). 'Active': every acceptance not cleared. 'Clear':
       the acceptances named (@clears, JSON [{ Id; How }]) cleared by this run (@runId), each with its cfg.ChangeLog row, in
       ONE transaction. A database without the table answers nothing and changes nothing. #>
    param([Parameter(Mandatory)][ValidateSet('Active', 'Clear')][string]$Name)
    switch ($Name) {
        'Active' { @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.RaSourceAccept') IS NULL
BEGIN
    SELECT CAST(NULL AS BIGINT) AS AcceptId, CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS NVARCHAR(128)) AS SourceTable,
           CAST(NULL AS NVARCHAR(256)) AS AcceptedBy, CAST(NULL AS DATETIME2(0)) AS AcceptedUtc WHERE 1 = 0;
    RETURN;
END
SELECT AcceptId, ReportName, SourceTable, AcceptedBy, AcceptedUtc FROM cfg.RaSourceAccept WHERE ClearedUtc IS NULL ORDER BY ReportName, SourceTable;
'@ }
        'Clear' { @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('cfg.RaSourceAccept') IS NULL BEGIN SELECT 0 AS Cleared; RETURN; END
DECLARE @c TABLE (AcceptId BIGINT NOT NULL, How NVARCHAR(16) NOT NULL);
INSERT @c (AcceptId, How) SELECT j.Id, j.How FROM OPENJSON(@clears) WITH (Id BIGINT '$.Id', How NVARCHAR(16) '$.How') j WHERE j.How IN (N'rows-back', N'not-read');
DECLARE @done TABLE (AcceptId BIGINT, ReportName NVARCHAR(256), SourceTable NVARCHAR(128), How NVARCHAR(16));
BEGIN TRAN;
UPDATE a SET ClearedUtc = SYSUTCDATETIME(), ClearedHow = c.How, ClearedBy = N'SecurityInsight', ClearedRunId = NULLIF(@runId, N'')
OUTPUT inserted.AcceptId, inserted.ReportName, inserted.SourceTable, inserted.ClearedHow INTO @done
FROM cfg.RaSourceAccept a JOIN @c c ON c.AcceptId = a.AcceptId WHERE a.ClearedUtc IS NULL;
IF OBJECT_ID('cfg.ChangeLog') IS NOT NULL
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    SELECT LEFT(N'source-accept/' + d.ReportName + N'/' + d.SourceTable, 128), N'riskanalysis', N'sourceaccept', N'Reset', N'accepted', NULL, N'SecurityInsight',
           CASE d.How WHEN N'rows-back' THEN N'the source has rows again' ELSE N'the report no longer reads the source' END
    FROM @done d;
COMMIT;
SELECT COUNT(*) AS Cleared FROM @done;
'@ }
    }
}

function ConvertTo-RASourceAcceptMap {
    <# PURE. The active acceptances (rows of 'Active') as report -> [string[]] tables (what Get-RASilentSourceHolds and the
       report fingerprint take). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $out = @{}
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $rep = ''; $tab = ''
        if ($r -is [System.Collections.IDictionary]) { $rep = [string]$r['ReportName']; $tab = [string]$r['SourceTable'] } else { $rep = [string]$r.ReportName; $tab = [string]$r.SourceTable }
        if (-not $rep -or -not $tab) { continue }
        if (-not $out.ContainsKey($rep)) { $out[$rep] = @() }
        if (@($out[$rep]) -notcontains $tab) { $out[$rep] = [string[]](@($out[$rep]) + @($tab) | Sort-Object) }
    }
    $out
}

function Get-RASourceAcceptClears {
    <#
        PURE. The acceptances this run clears: @(@{ Id; Report; Table; How }).
          rows-back  the table was COUNTED this run (-Counts: table -> rows, counted only) with rows -- the source is back;
          not-read   the report is in this run (-RunReports) and no longer reads the table (-Map: report -> tables).
        A table whose count failed this run (not in -Counts) is neither cleared nor anything else: the next counted run decides.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Counts = @{}, [hashtable]$Map = @{}, [AllowEmptyCollection()][string[]]$RunReports = @())
    if ($null -eq $Counts) { $Counts = @{} }
    if ($null -eq $Map) { $Map = @{} }
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $id = $null; $rep = ''; $tab = ''
        if ($r -is [System.Collections.IDictionary]) { $id = $r['AcceptId']; $rep = [string]$r['ReportName']; $tab = [string]$r['SourceTable'] } else { $id = $r.AcceptId; $rep = [string]$r.ReportName; $tab = [string]$r.SourceTable }
        if ($null -eq $id -or -not $rep -or -not $tab) { continue }
        if ($Counts.ContainsKey($tab) -and [long]$Counts[$tab] -gt 0) { [pscustomobject]@{ Id = [long]$id; Report = $rep; Table = $tab; How = 'rows-back' }; continue }
        if (@($RunReports) -contains $rep -and @($Map[$rep]) -notcontains $tab) { [pscustomobject]@{ Id = [long]$id; Report = $rep; Table = $tab; How = 'not-read' } }
    }
}

function Get-RASourceAcceptLines {
    <# PURE. The run's lines about the acceptances: one per acceptance that applies, one per acceptance cleared. #>
    param([hashtable]$Accepted = @{}, [AllowEmptyCollection()][object[]]$Clears = @())
    foreach ($rep in @($Accepted.Keys | Sort-Object)) {
        ('source accepted as empty: report {0} reads {1}, accepted as empty for good by an Admin -- it is not held for it, it shows empty and complete, and its findings close as ''Report changed''' -f $rep, (@($Accepted[$rep]) -join ', '))
    }
    foreach ($c in @($Clears | Where-Object { $_ })) {
        $why = if ($c.How -eq 'rows-back') { ('{0} has rows again' -f $c.Table) } else { ('the report no longer reads {0}' -f $c.Table) }
        ('source acceptance cleared: report {0}, source {1} -- {2}; the report is judged as usual from now on' -f $c.Report, $c.Table, $why)
    }
}
