#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE DATA SYNC WORKS ON WHAT CHANGED (REQUIREMENTS #1319, design note SCALE-2 #1314; owner 2026-11-23:
    "data quality + stability in the runs are prio 1, performance is prio 2. nothing in the design must break prio 1 ... we
    need to make sure that we trust the views + data shown + data sent to any connector").

    THE RULE (#1314 (5)): this changes HOW a collection is built, never WHAT is published or sent. The published-run pointer,
    the publish checks, the verification step, data health and every connector guard are untouched; every table a page or a
    connector reads is the same table, written with the same values.

    ONE SETTING, SI_Data_ChangedSet (solution setting), ON BY DEFAULT (owner 2026-11-23: "new features ship on by default
    when they add value"):
      off     every phase is built exactly as before; nothing of this file reads or writes a row.
      shadow  (troubleshooting only -- it doubles the work at a large install) every phase that can is built BOTH ways: from what changed (into side rows) and in full as before; the two are
              compared row for row, column for column; the FULL result is what is kept, shown and sent. A difference is a
              WARNING on the run (the run's report opens the fix request) with its count, a few finding ids and column
              names -- never a value.
      on      (the default; empty, not set or a typo) the changed-set result is kept, PLUS the per-run SAMPLE CHECK: about one CI in ten (seeded, the seed logged)
              is built in full and compared; any difference = this run is built in FULL before anything is published, and
              the same warning.

    THE FINDING HASH (sidata.FindingHash, per collection, worked out set-based in FindingId ranges at the start of the first
    phase that uses it): SHA-256 over every column of sidata.Finding that reaches a view or a connector -- the joined ones
    included (tier, department, exemption, CI lifecycle, CMDB, risk parts, ...) -- each NULL-marked and length-prefixed, in
    name order, and the finding's document with the run's own time taken out (top-level keys only, only in a JSON object).
    Never the finding's id, its collection, the run's own ordering or what a LATER phase writes onto the row (the prepared
    view columns themselves, the importance rank, the remediation key). The column list is read from the database and named
    by its HashSet (a changed field list = another HashSet = a full build). docs\DESIGN.md lists the fields.

    THE BASE = the PUBLISHED collection (sidata.PublishedRun 'current', not partial) -- the one trusted run (#780); never just
    "the newest stored". FULL BUILD (today's path, unchanged) and why, recorded per phase in sidata.ChangedSetRun:
      nothing published yet; the published collection is this one or not older; it is not complete / retired / partial; it
      has no hashes for this field list, or changed after them; this collection's hashes could not be made; the published
      collection's phase was built with another BUILD FINGERPRINT (#1331: the phase's fingerprint = the hashed field list, the
      phase's own statement and settings, and the build fingerprint -- the data-model files (mappings, outputs, rules, the
      locked model files), the #1318 typing statement's fingerprint, the template set in force with the customer's
      overrides, and the solution settings that change what the build writes; NOT the version: an update that leaves all of
      them as they were is built from what changed as usual, an update that moves one is a full build, and the run says
      which part moved); the weekly full build is due -- ONLY when the rolling full check could not run (#1331, below);
      the phase's own reasons.

    THE ROLLING FULL CHECK (#1331, SCALE-3 track D; on top of the ~10 % random sample): every quick build also builds IN FULL
    and compares one seventh of ALL CIs -- a CI's part is fixed (SHA-256 of its AssetKey, first 3 bytes, mod 7: the same part
    every run), the run's part is the next one after the part of the phase's last finished run (0 after none, recorded per
    run in sidata.ChangedSetRun.RollingSlot and logged). So every CI is built in full and compared at least once in any 7
    consecutive quick builds. Any difference = the run is built in full before anything is published and the same warning
    (the fix request) -- exactly as the random sample. The weekly full build stays ONLY as the fallback when the rolling
    check could not run: the database does not record it yet, or a quick build in the last 7 days ran without it.

    CARRIED, NEVER INFERRED: a finding of the new collection whose hash equals a finding of the base carries THAT finding's
    result (set-based, by id, in ranges); every other finding is built as before. What a phase carries is a pure function of
    a part of the hash's input, so equal hashes give equal results. Removals and closes are NOT decided here: every phase
    that removes or closes keeps its own full key-to-key compare (the findings per CI's swap, the lifecycle, the changes,
    the remediation tasks), unchanged.

    PER PHASE (docs\DESIGN.md "The data sync works on what changed"):
      view context (finding side)  changed-set -- the prepared view columns are a function of the finding's document only
      findings per CI (work rows)  changed-set -- the projected document fields of the work table, carried from the
                                   published collection's kept work rows; the staging, the CI lookups and the swap run as
                                   before over the whole set
      issue context, summary groups, key figures, changes, remediation tasks   full (their reasons in DESIGN.md)

    Never fails a phase: anything that goes wrong here is said, recorded as 'failed' and the phase is built in full.
    PowerShell 5.1 and 7 (no ?. / ??, no ternary). No PowerShell module: every statement through the data sync's seam.
#>

# #1354 (owner 2026-11-24, "Fix + history ON") THE ROW'S WRITER -- ONE list for the finding hash here AND the finding history's
# state (SI-DataHistory.ps1 reads these; sql\si-data-schema.sql carries the same names, held equal by a test): which release
# wrote the row (Risk Analysis' SolutionVersion, its column and the document's field) and how its insert typed it (#1318). They
# move with every release and say nothing about the finding, so neither hash reads them: a release alone changes no hash.
$script:SIDataRowWriter = [ordered]@{
    Columns   = @('RaRowSolutionVersion', 'TypedOnInsert', 'TypedStatement')
    DocFields = @('SolutionVersion')
}

$script:SIDataChangedSet = [ordered]@{
    Setting       = 'SI_Data_ChangedSet'
    FullDays      = 7          # the weekly full build: a phase built in full (or shadow) less than this many days ago may carry
    SamplePercent = 10         # the sample check (on): about one CI in ten, as data health's 10 %
    RollParts     = 7          # #1331 the rolling full check: one part in seven of all CIs is built in full every quick build
    # #1331 the build fingerprint: the folders (under the solution) whose files shape what the build writes, and the solution
    # settings that change it (their values; a setting not set counts as not set). The typing statement (#1318) and the
    # template set (cfg.Template + cfg.ItemOverride) are read on their own.
    BuildFolders  = @('data-model')
    BuildSettings = @('SI_Data_ParseAtInsert', 'ReportTemplate', 'RiskAnalysis_ReportTemplate_Default_Detailed', 'RiskAnalysis_ReportTemplate_Default_Summary')
    BuildPartNames = [ordered]@{ m = 'the data-model files (mappings, outputs, rules)'; y = 'the typing statement'; t = 'the template set'; s = 'the settings that change what the build writes' }
    # the hash's own rule (a change of the rule = another HashSet = a full build). fh2 (#1354): the row's writer left out
    HashVersion   = 'fh2'
    # the phases and their number in sidata.ChangedSetCarry
    Phases        = [ordered]@{ 'view-context' = 1; 'swap' = 2 }
    PhaseNames    = @{ 'view-context' = 'the prepared view columns'; 'swap' = 'the findings per CI' }
    # the document's keys the run itself moves (left out of the hash; never read by anything this file carries)
    RunFields     = @('CollectionTime', 'TimeGenerated', 'si_collection_time', '_TimeReceived', '_ItemId', '_BilledSize') + @($script:SIDataRowWriter.DocFields)
    # sidata.Finding columns NOT in the hash: the row's identity, its document (hashed on its own, without the run's time),
    # the run's own ordering / bucketing / tracing of the row, what a later phase writes onto the row, and the row's writer
    NotHashed     = @('FindingId', 'CollectionId', 'DetailJson', 'ImportanceRank', 'RemediationKey', 'RaSeq', 'RaSort', 'RaBucket', 'RaDedup',
                      'RaTraceHash', 'RaTraceKey', 'RaTraceSuffixed', 'RaReport') + @($script:SIDataRowWriter.Columns)
    # the collection's marks of a later rewrite of its finding rows (a hash older than any of them is stale)
    Stamps        = @('DerivedAt', 'ResolvedAt', 'ServicesDerivedAt', 'CorrelatedAt', 'CiLifecycleAt', 'RiskPartsAt', 'TypedAt', 'RaRowsAt')
    # the findings per CI's work-row values read from the finding's document (the rest are the finding's own columns)
    WorkJson      = @('Weighted', 'Component', 'Factors', 'SevRank', 'SubCi', 'PatchCycle', 'CvePublished', 'Cat', 'SubCat')
}
$script:SIDataChangedSetRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))

function Get-SIDataChangedSetContract { $script:SIDataChangedSet }

function Test-SIDataChangedSetColumnName {
    <# PURE. Is -Name a plain column identifier (the only text this file ever puts between [ ] in a statement)? #>
    param([AllowEmptyString()][AllowNull()][string]$Name)
    [bool]("$Name" -cmatch '^[A-Za-z][A-Za-z0-9_]{0,127}$')
}

function Get-SIDataChangedSetListColumns {
    <# The prepared view columns of -List (view-stored-columns.json), each a plain identifier. THROWS on any other name, or on an
       empty list: a malformed list never reaches a statement's text -- the phase is built in full (its caller catches it). #>
    param($List)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($List.finding)) {
        if ($null -eq $e) { continue }
        $c = [string]$e.column
        if (-not (Test-SIDataChangedSetColumnName $c)) { throw 'the list of prepared view columns is not well formed' }
        $out.Add($c)
    }
    if (-not $out.Count) { throw 'the list of prepared view columns is empty' }
    # (returned as its items: every caller takes them with @( ))
    $out.ToArray()
}

function Get-SIDataChangedSetSafeError {
    <# PURE. An error as the run may record and say it (sidata.ChangedSetRun.Why / DiffDetail, the run's warning, the log): the SQL
       error number when it is one, and the first line of its message with every quoted or bracketed part taken out (a
       database message can quote a value -- "the nvarchar value '...'", "The duplicate key value is (...)"), at most 160
       characters. Never a value of a finding. #>
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $msg = if ($ex) { [string]$ex.Message } else { [string]$ErrorRecord }
    $num = $null; $x = $ex
    while ($x) {
        if ($x.GetType().Name -eq 'SqlException' -and $x.PSObject.Properties['Number']) { $num = [int]$x.Number; $msg = [string]$x.Message; break }
        $x = $x.InnerException
    }
    if ($null -eq $num) { $m = [regex]::Match($msg, '(?i)\b(?:Msg|error)\s+(\d{3,6})\b'); if ($m.Success) { $num = [int]$m.Groups[1].Value } }
    $line = (($msg -split "`n")[0]).Trim()
    $line = [regex]::Replace($line, "N?'[^']*'?", '<value>')
    $line = [regex]::Replace($line, '"[^"]*"?', '<value>')
    $line = [regex]::Replace($line, '\([^)]*\)?', '(...)')
    $line = [regex]::Replace($line, '\[[^\]]*\]?', '[...]')
    if ($line.Length -gt 160) { $line = $line.Substring(0, 157) + '...' }
    if ($null -ne $num) { return ('SQL error {0}: {1}' -f $num, $line) }
    $line
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE SWITCH
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SIDataChangedSetMode {
    <# PURE. A stored value -> 'off' | 'shadow' | 'on'. ON BY DEFAULT (owner 2026-11-23: a feature that adds value ships on):
       only the exact words off / shadow switch it; anything else -- empty, not set, a typo -- is the default, on (with the
       automatic full builds and the sample check, which are part of on). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return 'on' }
    $v = ("$Value".Trim() -replace '^"|"$', '').Trim().ToLowerInvariant()
    if ($v -in 'off', 'false', '0') { return 'off' }
    if ($v -eq 'shadow') { return 'shadow' }
    'on'
}

function Read-SIDataChangedSetMode {
    <# The install's switch: the job's own value when it is set (-Value, $global:SI_Data_ChangedSet: the custom file), else
       the solution setting (cfg.Setting). Not set / not readable = the default, ON (its safety -- the automatic full builds
       and the sample check -- is part of on). Returns @{ Mode; Source }. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $Value = $global:SI_Data_ChangedSet)
    if ($null -ne $Value -and "$Value".Trim() -ne '') { $o = [pscustomobject]@{ Mode = (ConvertTo-SIDataChangedSetMode $Value); Source = 'job' } }
    else {
        try {
            $rows = @(@(& $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT ValueJson FROM cfg.Setting WHERE Name = @N AND Scope = N'solution';" @{ N = $script:SIDataChangedSet.Setting } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $v = $null
            if ($rows.Count) { $r = $rows[0]; if ($r -is [System.Collections.IDictionary]) { $v = $r['ValueJson'] } elseif ($r.PSObject.Properties['ValueJson']) { $v = $r.ValueJson } }
            $o = [pscustomobject]@{ Mode = (ConvertTo-SIDataChangedSetMode $v); Source = $(if ($null -eq $v) { 'the default' } else { 'setting' }) }
        } catch { $o = [pscustomobject]@{ Mode = 'on'; Source = 'the default (the setting was not readable)' } }
    }
    # a database the update has not reached yet (no tables of this build): built as before, said once by the caller
    if ($o.Mode -ne 'off') {
        $ready = $false
        try { $ready = ([string](& $Invoke (Get-SIDataChangedSetSchemaCheckSql) @{} 'scalar') -eq '1') } catch { $ready = $false }
        if (-not $ready) { $o = [pscustomobject]@{ Mode = 'off'; Source = 'the database does not have its tables yet (the update adds them)' } }
    }
    $o
}

function Get-SIDataChangedSetSchemaCheckSql {
    <# 1 when the database has every table this build writes (sql\si-data-schema.sql), else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.FindingHash') IS NOT NULL AND OBJECT_ID('sidata.FindingHashState') IS NOT NULL AND COL_LENGTH('sidata.FindingHashState', 'StampHash') IS NOT NULL AND OBJECT_ID('sidata.ChangedSetRun') IS NOT NULL AND OBJECT_ID('sidata.ChangedSetCarry') IS NOT NULL AND OBJECT_ID('sidata.PublishedRun') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataChangedSetVersion {
    <# The solution's version (VERSION) -- said in the log only. #1331: it is NOT part of a phase's fingerprint any more (the build
       fingerprint is): an update that does not change what the build produces is built from what changed as usual. #>
    try { return ([IO.File]::ReadAllText([IO.Path]::Combine($script:SIDataChangedSetRoot, 'VERSION'))).Trim() } catch { return 'unknown' }
}

$script:SIDataChangedSetBuildPrint = $null

function Get-SIDataChangedSetFilesPrint {
    <# The fingerprint of the files under -Folders (relative to -Root): SHA-256 over '<relative path, / separated, lower case>
       <SHA-256 of the file>' per file, ordinal order, line ends made one ('none' when there is no file). The same files give the
       same print on every machine; a file added, removed, renamed or changed gives another. #>
    param([string]$Root = $script:SIDataChangedSetRoot, [string[]]$Folders = $script:SIDataChangedSet.BuildFolders)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($fo in @($Folders)) {
        $dir = [IO.Path]::Combine($Root, $fo)
        if (-not [IO.Directory]::Exists($dir)) { continue }
        foreach ($f in [IO.Directory]::GetFiles($dir, '*', [IO.SearchOption]::AllDirectories)) {
            $rel = $f.Substring($Root.TrimEnd('\', '/').Length).TrimStart('\', '/').Replace('\', '/').ToLowerInvariant()
            $txt = ([IO.File]::ReadAllText($f)).Replace("`r`n", "`n")
            $lines.Add(('{0} {1}' -f $rel, (Get-SIDataChangedSetSha -Text $txt)))
        }
    }
    if (-not $lines.Count) { return 'none' }
    $a = $lines.ToArray(); [Array]::Sort($a, [StringComparer]::Ordinal)
    Get-SIDataChangedSetSha -Text ($a -join "`n")
}

function Get-SIDataChangedSetTemplatePrintSql {
    <# PURE. The template set in force as ONE hash (hex): every live cfg.Template row (kind, key, content) and every customer
       override (cfg.ItemOverride: kind, key, state, body), ordinal order. 'none' on a database without the tables. #>
    $t = "(SELECT STRING_AGG(CONVERT(nvarchar(max), CONCAT(t.Kind, N'/', t.ItemKey, N'=', CONVERT(nvarchar(64), HASHBYTES('SHA2_256', t.BodyJson), 2))), N'|') WITHIN GROUP (ORDER BY t.Kind COLLATE Latin1_General_BIN2, t.ItemKey COLLATE Latin1_General_BIN2) FROM cfg.Template AS t WHERE t.RetiredAt IS NULL)"
    $o = "(SELECT STRING_AGG(CONVERT(nvarchar(max), CONCAT(o.Kind, N'/', o.ItemKey, N'=', o.State, N':', ISNULL(CONVERT(nvarchar(64), HASHBYTES('SHA2_256', o.BodyJson), 2), N'-'))), N'|') WITHIN GROUP (ORDER BY o.Kind COLLATE Latin1_General_BIN2, o.ItemKey COLLATE Latin1_General_BIN2) FROM cfg.ItemOverride AS o)"
    @"
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.Template') IS NULL SELECT N'none' AS P
ELSE IF OBJECT_ID(N'cfg.ItemOverride') IS NULL SELECT CONVERT(nvarchar(64), HASHBYTES('SHA2_256', CONCAT($t, N'#')), 2) AS P
ELSE SELECT CONVERT(nvarchar(64), HASHBYTES('SHA2_256', CONCAT($t, N'#', $o)), 2) AS P;
"@
}

function Get-SIDataChangedSetSettingsPrintSql {
    <# PURE. The settings that change what the build writes (the contract's BuildSettings) as their names and stored values, read
       in name order (the caller hashes them). Nothing when cfg.Setting is not there. #>
    $in = (@($script:SIDataChangedSet.BuildSettings | ForEach-Object { if ($_ -cnotmatch '^[A-Za-z][A-Za-z0-9_]{0,127}$') { throw 'a build setting is not a plain name' }; "N'$_'" })) -join ', '
    "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT Name AS N, Scope AS S, ValueJson AS V FROM cfg.Setting WHERE Name IN ($in) ORDER BY Name, Scope;"
}

function Get-SIDataChangedSetTypingPrint {
    <# The #1318 typing statement's fingerprint for the whole switch set (every expression the derive can carry), or 'none' when
       the derive is not loaded in this process. #>
    if (-not (Get-Command -Name Get-SIDataTypedFingerprint -ErrorAction SilentlyContinue)) { return 'none' }
    Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts
}

function ConvertTo-SIDataChangedSetBuildParts {
    <# PURE. The build fingerprint's parts as the text recorded per run (sidata.ChangedSetRun.BuildParts): 'm=<16>;y=<16>;t=<16>;s=<16>'. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Parts)
    (@($script:SIDataChangedSet.BuildPartNames.Keys | ForEach-Object { '{0}={1}' -f $_, (Get-SIDataChangedSetSha -Length 16 -Text ([string]$Parts[$_])) })) -join ';'
}

function Compare-SIDataChangedSetBuildParts {
    <# PURE. The parts of the build fingerprint that differ between two recorded texts (-Base, -Now), by name; @() when they are
       the same; $null when the base recorded none (an older build -- the caller says it plainly). #>
    param([AllowNull()][AllowEmptyString()][string]$Base, [Parameter(Mandatory)][string]$Now)
    if (-not $Base) { return $null }
    $rd = { param($t) $h = @{}; foreach ($kv in ($t -split ';')) { $p = $kv -split '=', 2; if ($p.Count -eq 2) { $h[$p[0]] = $p[1] } }; $h }
    $b = & $rd $Base; $n = & $rd $Now
    , @($script:SIDataChangedSet.BuildPartNames.Keys | Where-Object { [string]$b[$_] -ne [string]$n[$_] } | ForEach-Object { [string]$script:SIDataChangedSet.BuildPartNames[$_] })
}

function Get-SIDataChangedSetBuildFingerprint {
    <#
        #1331 THE BUILD FINGERPRINT: what decides whether the build PRODUCES the same results as the build that made the published
        collection -- the data-model files (mappings, outputs, rules, the locked model files), the #1318 typing statement, the
        template set in force (with the customer's overrides) and the settings that change what the build writes. With the
        hashed field list and each phase's own statement (Get-SIDataChangedSetFingerprint) it is the phase's fingerprint.
        Worked out once per run (Reset-SIDataChangedSetRunState forgets it). Returns @{ Print; Parts (the recorded text) }.
        THROWS when a part cannot be read (the phase is then built in full: any doubt = full).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Root = $script:SIDataChangedSetRoot)
    if ($script:SIDataChangedSetBuildPrint) { return $script:SIDataChangedSetBuildPrint }
    $p = [ordered]@{}
    $p['m'] = Get-SIDataChangedSetFilesPrint -Root $Root
    $p['y'] = Get-SIDataChangedSetTypingPrint
    $tp = & $Invoke (Get-SIDataChangedSetTemplatePrintSql) @{} 'scalar'
    $p['t'] = $(if ($null -eq $tp -or $tp -is [System.DBNull]) { 'empty' } else { [string]$tp })
    $rows = @(@(& $Invoke (Get-SIDataChangedSetSettingsPrintSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $p['s'] = (@($rows | ForEach-Object { '{0}|{1}|{2}' -f (Get-SIDataChangedSetRowValue $_ 'N'), (Get-SIDataChangedSetRowValue $_ 'S'), (Get-SIDataChangedSetRowValue $_ 'V') })) -join "`n"
    $parts = ConvertTo-SIDataChangedSetBuildParts -Parts $p
    $o = [pscustomobject]@{ Print = (Get-SIDataChangedSetSha -Text $parts); Parts = $parts }
    $script:SIDataChangedSetBuildPrint = $o
    $o
}

function Get-SIDataChangedSetSha {
    <# PURE. The SHA-256 of a text (UTF-8) as hex; -Length: its first characters. #>
    param([AllowEmptyString()][string]$Text, [int]$Length = 64)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    ([System.BitConverter]::ToString($h)).Replace('-', '').Substring(0, [Math]::Min(64, [Math]::Max(1, $Length)))
}

function Get-SIDataChangedSetFingerprint {
    <# PURE. A phase's fingerprint: its name, the BUILD fingerprint (-Build, Get-SIDataChangedSetBuildFingerprint .Print; #1331 --
       no longer the version), the hash's field list and the phase's own text (its statement and settings). Equal fingerprints =
       the published collection's phase result was made the way this run would make it. #>
    param([Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][string]$HashSet, [AllowEmptyString()][string]$PhaseText = '', [Parameter(Mandatory)][string]$Build)
    Get-SIDataChangedSetSha -Text ('{0}|{1}|{2}|{3}' -f $Phase, $Build, $HashSet, (Get-SIDataChangedSetSha -Text $PhaseText))
}

function Get-SIDataChangedSetRollExpr {
    <# PURE. #1331 the rolling part (0..6) of one finding's CI (-Asset: its AssetKey expression): the first 3 bytes of the
       SHA-256 of the AssetKey (as nvarchar), mod 7 -- unseeded, so a CI is in the same part every run. #>
    param([Parameter(Mandatory)][string]$Asset)
    "(CONVERT(int, SUBSTRING(HASHBYTES('SHA2_256', CONVERT(nvarchar(400), ISNULL($Asset, N''))), 1, 3)) % $([int]$script:SIDataChangedSet.RollParts))"
}

function Get-SIDataChangedSetRollPartOf {
    <# PURE. The same part as Get-SIDataChangedSetRollExpr, worked out here (UTF-16LE bytes, as SQL hashes an nvarchar). #>
    param([AllowNull()][AllowEmptyString()][string]$CiId)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes([string]$CiId)) } finally { $sha.Dispose() }
    [int]((([int]$h[0] * 65536) + ([int]$h[1] * 256) + [int]$h[2]) % [int]$script:SIDataChangedSet.RollParts)
}

function Get-SIDataChangedSetNextRollSlot {
    <# PURE. #1331 the part this run builds in full: the one after the part of the phase's last finished run (-Last), 0 after none. #>
    param([AllowNull()]$Last)
    if ($null -eq $Last -or $Last -is [System.DBNull]) { return 0 }
    [int](([int]$Last + 1) % [int]$script:SIDataChangedSet.RollParts)
}

function Get-SIDataChangedSetSampleSql {
    <# PURE. The sample check's choice of one finding's CI (-Asset: its AssetKey expression): 1 for about -Percent of the CIs
       (@Seed, @SamplePct) AND (#1331) every CI of this run's rolling part (@RollSlot 0..6; -1 = none), else 0 -- the same CI is
       in or out for every one of its findings. #>
    param([Parameter(Mandatory)][string]$Asset)
    "CASE WHEN (CONVERT(int, SUBSTRING(HASHBYTES('SHA2_256', CONCAT(CONVERT(nvarchar(12), CONVERT(int, @Seed)), N'|', ISNULL($Asset, N''))), 1, 2)) % 100) < CONVERT(int, @SamplePct) THEN 1 " +
    "WHEN CONVERT(int, @RollSlot) >= 0 AND $(Get-SIDataChangedSetRollExpr -Asset $Asset) = CONVERT(int, @RollSlot) THEN 1 ELSE 0 END"
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE FINDING HASH
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataFindingHashExcluded {
    <# The columns the hash leaves out: the contract's NotHashed + the prepared view columns (written by the view context
       AFTER the hash; -List: view-stored-columns.json). #>
    param($List)
    $x = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $script:SIDataChangedSet.NotHashed) { [void]$x.Add([string]$c) }
    if ($List) { foreach ($c in (Get-SIDataChangedSetListColumns -List $List)) { [void]$x.Add($c) } }
    , $x
}

function Get-SIDataFindingHashColumns {
    <# The hashed columns: every column of sidata.Finding this database has, but the excluded ones -- in ordinal name order
       (the same order on every install with the same columns). -List: the prepared view columns' list. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, $List)
    $ex = Get-SIDataFindingHashExcluded -List $List
    $rows = @(@(& $Invoke "SELECT c.name AS N FROM sys.columns AS c WHERE c.object_id = OBJECT_ID(N'sidata.Finding') AND c.is_computed = 0;" @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        $n = if ($r -is [System.Collections.IDictionary]) { [string]$r['N'] } else { [string]$r.N }
        if ($n -and -not $ex.Contains($n) -and $n -match '^[A-Za-z][A-Za-z0-9_]{0,127}$') { $names.Add($n) }
    }
    $a = $names.ToArray(); [Array]::Sort($a, [StringComparer]::Ordinal)
    , [string[]]$a
}

function Get-SIDataFindingHashSetId {
    <# PURE. The identity of the hash's field list: 16 hex characters of the SHA-256 of the rule, the columns and the run fields. #>
    param([Parameter(Mandatory)][string[]]$Columns)
    Get-SIDataChangedSetSha -Length 16 -Text ('{0}|{1}|{2}' -f $script:SIDataChangedSet.HashVersion, ($Columns -join ','), ($script:SIDataChangedSet.RunFields -join ','))
}

function Get-SIDataChangedSetColumnPart {
    <# PURE. One column of a hash: NULL marked apart from empty, its length, its bytes. #>
    param([Parameter(Mandatory)][string]$Alias, [Parameter(Mandatory)][string]$Column)
    if (-not (Test-SIDataChangedSetColumnName $Alias) -or -not (Test-SIDataChangedSetColumnName $Column)) { throw 'a column name of the hash is not a plain identifier' }
    'CASE WHEN {0}.[{1}] IS NULL THEN 0x00 ELSE 0x01 + CAST(DATALENGTH({0}.[{1}]) AS binary(4)) + CAST({0}.[{1}] AS varbinary(max)) END' -f $Alias, $Column
}

function Get-SIDataFindingHashRangeSql {
    <#
        PURE. ONE FindingId range (@After < FindingId <= @Upto) of one collection (@CollectionId): the hash of every finding that
        has none yet, into sidata.FindingHash -- ONE statement, the document never copied or rewritten (review 2026-11-23: the
        #temp copy of every document and its JSON_MODIFY rewrite cost hundreds of MB of tempdb a range). The hash = the columns
        (-Columns, each NULL-marked and length-prefixed) and then the document:
          a JSON OBJECT   0x02 + its top-level properties read ONCE (OPENJSON), the run's own fields left out, each as
                          length:key|type|length:value, in binary key order -- the same properties give the same hash
                          whatever their order or the text's spacing, and every value the phases read (JSON_VALUE /
                          OPENJSON of a top-level field) is one of them, exactly. A document that names a key twice is
                          given a hash of its own (never carried): which of the two JSON_VALUE reads depends on their order.
          anything else   0x01 + the document's bytes (0x00 when there is none).
        Answers the hashes written.
    #>
    param([Parameter(Mandatory)][string[]]$Columns)
    $rf = (@($script:SIDataChangedSet.RunFields | ForEach-Object { if ($_ -cnotmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') { throw 'a run field is not a plain name' }; "N'$_'" })) -join ', '
    $parts = @($Columns | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias 'f' -Column $_ })
    $parts += "CASE WHEN j.J = 1 THEN 0x02 + CAST(CONCAT(CASE WHEN a.N <> a.D THEN CONVERT(nvarchar(36), NEWID()) END, a.N, N'#', a.T) AS varbinary(max)) WHEN f.DetailJson IS NULL THEN 0x00 ELSE 0x01 + CAST(f.DetailJson AS varbinary(max)) END"
    $first = "SUBSTRING(f.DetailJson, PATINDEX(N'%[^' + CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) + N']%', f.DetailJson), 1)"
    @"
SET NOCOUNT ON;
INSERT sidata.FindingHash (CollectionId, FindingId, FindingHash)
SELECT f.CollectionId, f.FindingId, HASHBYTES('SHA2_256', $($parts -join ' + '))
FROM sidata.Finding AS f
CROSS APPLY (SELECT CASE WHEN f.DetailJson IS NOT NULL AND $first = N'{' AND ISJSON(f.DetailJson) = 1 THEN 1 ELSE 0 END AS J) AS j
OUTER APPLY (SELECT COUNT_BIG(*) AS N, COUNT_BIG(DISTINCT o.[key] COLLATE Latin1_General_BIN2) AS D,
                    STRING_AGG(CONVERT(nvarchar(max), CONCAT(DATALENGTH(o.[key]), N':', o.[key], N'|', o.[type], N'|', ISNULL(DATALENGTH(o.[value]), -1), N':', o.[value])), N'')
                        WITHIN GROUP (ORDER BY o.[key] COLLATE Latin1_General_BIN2) AS T
             FROM OPENJSON(CASE WHEN j.J = 1 THEN f.DetailJson END) AS o
             WHERE o.[key] COLLATE Latin1_General_BIN2 NOT IN ($rf)) AS a
WHERE f.CollectionId = CONVERT(int, @CollectionId) AND f.FindingId > CONVERT(bigint, @After) AND f.FindingId <= CONVERT(bigint, @Upto)
  AND NOT EXISTS (SELECT 1 FROM sidata.FindingHash AS x WHERE x.CollectionId = f.CollectionId AND x.FindingId = f.FindingId);
SELECT @@ROWCOUNT;
"@
}

function Get-SIDataChangedSetStampExpr {
    <# The latest mark of a later rewrite of a collection's rows (-Alias: the sidata.Collection alias), over the marks this
       database has (-Have); 'CAST(NULL AS datetime2(3))' when it has none. #>
    param([Parameter(Mandatory)][string]$Alias, [string[]]$Have = @())
    $use = @($script:SIDataChangedSet.Stamps | Where-Object { $Have -contains $_ })
    if (-not $use.Count) { return 'CAST(NULL AS datetime2(3))' }
    '(SELECT MAX(v) FROM (VALUES {0}) AS sx (v))' -f ((@($use | ForEach-Object { '(CONVERT(datetime2(3), {0}.[{1}]))' -f $Alias, $_ })) -join ', ')
}

function Get-SIDataChangedSetStampHashExpr {
    <# The collection's marks as ONE hash (-Alias: the sidata.Collection alias; -Have: the marks this database has): its status,
       kind and time and every rewrite mark, NULL kept apart. Recorded with the collection's finding hashes
       (sidata.FindingHashState.StampHash) and compared every time they are used: a mark that moved -- set, cleared or put
       back -- means the hashes are stale (a full build), never fresher. #>
    param([Parameter(Mandatory)][string]$Alias, [string[]]$Have = @())
    if (-not (Test-SIDataChangedSetColumnName $Alias)) { throw 'not a plain alias' }
    $parts = @("ISNULL(CONVERT(nvarchar(16), $Alias.Status), N'-')", "ISNULL(CONVERT(nvarchar(16), $Alias.Kind), N'-')", "ISNULL(CONVERT(nvarchar(30), $Alias.CollectionTime, 126), N'-')")
    foreach ($s in @($script:SIDataChangedSet.Stamps | Where-Object { $Have -contains $_ })) { $parts += ("ISNULL(CONVERT(nvarchar(30), {0}.[{1}], 126), N'-')" -f $Alias, $s) }
    "HASHBYTES('SHA2_256', CONCAT(" + ($parts -join ", N'|', ") + '))'
}

function Get-SIDataChangedSetStampColumns {
    <# The marks sidata.Collection has (of the contract's Stamps). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $in = (@($script:SIDataChangedSet.Stamps | ForEach-Object { "N'$_'" })) -join ', '
    $rows = @(@(& $Invoke "SELECT c.name AS N FROM sys.columns AS c WHERE c.object_id = OBJECT_ID(N'sidata.Collection') AND c.name IN ($in);" @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    , [string[]]@($rows | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [string]$_['N'] } else { [string]$_.N } })
}

function Get-SIDataChangedSetRowValue {
    <# PURE. One column of a reader row (dictionary or object); DBNull = $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    $v
}

function Read-SIDataFindingHashState {
    <# One collection's hashes: @{ Fresh; Rows; Findings; Hashes; Set; BuiltAt; Stamp }. Fresh = made for this field list (-SetId),
       one per finding, and not older than the collection's latest rewrite of its rows. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string]$SetId, [string[]]$Stamps)
    if ($null -eq $Stamps) { $Stamps = Get-SIDataChangedSetStampColumns -Invoke $Invoke }
    $sx = Get-SIDataChangedSetStampExpr -Alias 'c' -Have $Stamps
    $shx = Get-SIDataChangedSetStampHashExpr -Alias 'c' -Have $Stamps
    $r = @(@(& $Invoke @"
SET NOCOUNT ON;
SELECT s.HashSet, s.[Rows] AS HRows, s.BuiltAt, $sx AS Stamp, CASE WHEN s.StampHash = $shx THEN 1 ELSE 0 END AS Same,
       (SELECT COUNT_BIG(*) FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId) AS N,
       (SELECT COUNT_BIG(*) FROM sidata.FindingHash AS h WHERE h.CollectionId = c.CollectionId) AS H
FROM sidata.Collection AS c LEFT JOIN sidata.FindingHashState AS s ON s.CollectionId = c.CollectionId
WHERE c.CollectionId = CONVERT(int, @CollectionId);
"@ @{ CollectionId = [string]$CollectionId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $set = [string](Get-SIDataChangedSetRowValue $r 'HashSet'); $built = Get-SIDataChangedSetRowValue $r 'BuiltAt'; $stamp = Get-SIDataChangedSetRowValue $r 'Stamp'
    $n = [long](Get-SIDataChangedSetRowValue $r 'N'); $h = [long](Get-SIDataChangedSetRowValue $r 'H'); $hr = Get-SIDataChangedSetRowValue $r 'HRows'
    $same = [int](Get-SIDataChangedSetRowValue $r 'Same') -eq 1
    $fresh = ($set.Trim() -eq $SetId) -and ($null -ne $built) -and ($null -ne $hr) -and ([long]$hr -eq $n) -and ($h -eq $n) -and $same -and (($null -eq $stamp) -or ([datetime]$stamp -le [datetime]$built))
    [pscustomobject]@{ Fresh = [bool]$fresh; Rows = $h; Findings = $n; Hashes = $h; Set = $set.Trim(); BuiltAt = $built; Stamp = $stamp }
}

$script:SIDataChangedSetHashFailed = @{}

function Reset-SIDataChangedSetRunState {
    <# A new data sync run: what this process remembered of the last one (a collection whose hashes failed, the build
       fingerprint #1331) is forgotten. #>
    $script:SIDataChangedSetHashFailed = @{}
    $script:SIDataChangedSetBuildPrint = $null
}

function Invoke-SIDataFindingHash {
    <#
        Every finding of one collection has its hash for this field list (-Columns / -SetId): a fresh set is kept as it is;
        a stale one (another field list, a mark of the collection moved after it, not one per finding) goes and is made again,
        in FindingId ranges -- AT ONCE on a seam that hands out connections (as many as the database has cores, one on a DTU
        database or one whose log is at its limit: the fills' own rule), the range's size measured from the one before
        (-FirstSize only the first), paced by the database's own load. The hashes made must be one per finding -- else it
        throws (nothing is carried from an incomplete set). A collection whose hashes FAILED once this run is not tried again
        in this run (review 2026-11-23: the second phase hashed it again, doubling the cost) -- it throws at once, the phase
        builds in full. Returns @{ Rows; Built }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string[]]$Columns,
          [Parameter(Mandatory)][string]$SetId, [long]$FirstSize = 5000, [long]$TargetMs = 5000, [int]$Workers = 0, [scriptblock]$Log = { param($l, $m) })
    $key = '{0}|{1}' -f $CollectionId, $SetId
    if ($script:SIDataChangedSetHashFailed.ContainsKey($key)) { throw ('the finding hashes of this collection failed earlier this run ({0})' -f $script:SIDataChangedSetHashFailed[$key]) }
    try {
        $stamps = Get-SIDataChangedSetStampColumns -Invoke $Invoke
        $st = Read-SIDataFindingHashState -Invoke $Invoke -CollectionId $CollectionId -SetId $SetId -Stamps $stamps
        if ($st.Fresh) { return [pscustomobject]@{ Rows = [long]$st.Rows; Built = $false } }
        $cidText = [string]$CollectionId
        $null = & $Invoke 'SET NOCOUNT ON; DELETE FROM sidata.FindingHashState WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = $cidText } 'nonquery'
        if ([long]$st.Hashes -gt 0) {
            while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingHash WHERE CollectionId = CONVERT(int, @CollectionId); SELECT @@ROWCOUNT;' @{ CollectionId = $cidText } 'scalar') -gt 0) { }
        }
        $b = @(@(& $Invoke 'SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = $cidText } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $lo = Get-SIDataChangedSetRowValue $b 'Lo'; $hi = Get-SIDataChangedSetRowValue $b 'Hi'
        $n = 0L
        if ($null -ne $lo) {
            $sql = Get-SIDataFindingHashRangeSql -Columns $Columns
            $ci = $null; if ($Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo -and (Get-Command -Name Invoke-SIDataParallelRanges -ErrorAction SilentlyContinue)) { $ci = $Invoke.SIConnectionInfo }
            $maxWorkers = 1
            if ($ci -and $Workers -ne 1) {
                $maxWorkers = $(if ($Workers -gt 1) { $Workers } elseif (Get-Command -Name Get-SIDataFillWorkers -ErrorAction SilentlyContinue) { Get-SIDataFillWorkers -Invoke $Invoke } else { 1 })
                if ($maxWorkers -gt 1 -and $Workers -le 0 -and (Get-Command -Name Get-SIDataFillRangeCount -ErrorAction SilentlyContinue)) {
                    $rc = Get-SIDataFillRangeCount -Kind (Read-SIDataFillDatabaseKind -Invoke $Invoke) -Cores $maxWorkers
                    if ([int]$rc.Count -lt $maxWorkers) { $maxWorkers = [int]$rc.Count }
                }
            }
            if ($maxWorkers -le 1) {
                $n = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql $sql -Params @{ CollectionId = $cidText } -Lo ([long]$lo) -Hi ([long]$hi) -FirstSize $FirstSize -TargetMs $TargetMs -Log $Log
            } else {
                $after = [long]$lo - 1; $size = [Math]::Max(1L, $FirstSize); $workersNow = $maxWorkers; $lastMs = 0L
                $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
                while ($after -lt [long]$hi) {
                    if ($paced) {
                        $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log
                        if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)); $workersNow = [Math]::Max(1, $workersNow - 1) }
                        elseif ($workersNow -lt $maxWorkers -and [string]$pace.State -eq 'normal') { $workersNow++ }
                    }
                    $wave = New-Object System.Collections.Generic.List[object]; $from = $after
                    for ($k = 0; $k -lt $workersNow -and $from -lt [long]$hi; $k++) { $to = [Math]::Min([long]$hi, $from + $size); $wave.Add(@($from, $to)); $from = $to }
                    $ms = 0L
                    foreach ($r in (Invoke-SIDataParallelRanges -ConnectionInfo $ci -Sql $sql -CollectionId $CollectionId -Ranges $wave.ToArray() -Log $Log -What 'the finding hashes')) { $n += [long]$r.N; if ([long]$r.Ms -gt $ms) { $ms = [long]$r.Ms } }
                    $lastMs = $ms; $after = $from
                    if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $ms -TargetMs $TargetMs -Minimum 1 }
                }
            }
        }
        if ($n -ne [long]$st.Findings) { throw ('the finding hashes of the collection came out {0:N0} for {1:N0} finding(s)' -f $n, [long]$st.Findings) }
        # the collection's own marks are recorded with the hashes (Get-SIDataChangedSetStampHashExpr): a later change of them is seen
        $shx = Get-SIDataChangedSetStampHashExpr -Alias 'c' -Have $stamps
        $null = & $Invoke ("SET NOCOUNT ON; INSERT sidata.FindingHashState (CollectionId, HashSet, [Rows], BuiltAt, StampHash) SELECT c.CollectionId, @Set, CONVERT(bigint, @Rows), SYSUTCDATETIME(), {0} FROM sidata.Collection AS c WHERE c.CollectionId = CONVERT(int, @CollectionId);" -f $shx) @{ CollectionId = $cidText; Set = $SetId; Rows = [string]$n } 'nonquery'
        [pscustomobject]@{ Rows = $n; Built = $true }
    } catch {
        $script:SIDataChangedSetHashFailed[$key] = Get-SIDataChangedSetSafeError $_
        throw
    }
}

function Test-SIDataChangedSetHashWanted {
    <# Are this collection's hashes of use: nothing is published yet (it becomes the base once published), or it is newer than
       the published collection? An older one (prepared again for another list) is never a base -- no hash is made for it.
       Not readable = yes. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId)
    $sql = "SET NOCOUNT ON; SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.Name = N'current' AND p.DetailedCollectionId IS NOT NULL) THEN 1 " +
           "WHEN (SELECT n.CollectionTime FROM sidata.Collection AS n WHERE n.CollectionId = CONVERT(int, @CollectionId)) > " +
           "(SELECT b.CollectionTime FROM sidata.PublishedRun AS p JOIN sidata.Collection AS b ON b.CollectionId = p.DetailedCollectionId WHERE p.Name = N'current') THEN 1 ELSE 0 END;"
    try { return ([string](& $Invoke $sql @{ CollectionId = [string]$CollectionId } 'scalar') -ne '0') } catch { return $true }
}

function Invoke-SIDataChangedSetRanges {
    <# One statement (-Sql, with @After / @Upto and -Params) over the FindingId range -Lo..-Hi, a range per call, the range's size
       from the measured time of the one before (Get-SIDataNextSize), paced by the database's own load. Sums the answers. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [Parameter(Mandatory)][hashtable]$Params,
          [Parameter(Mandatory)][long]$Lo, [Parameter(Mandatory)][long]$Hi, [long]$FirstSize = 50000, [long]$TargetMs = 5000,
          [scriptblock]$Log = { param($l, $m) }, [scriptblock]$OnRange)
    $after = $Lo - 1; $size = [Math]::Max(1L, $FirstSize); $n = 0L; $lastMs = 0L
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $sized = [bool](Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue)
    while ($after -lt $Hi) {
        if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } }
        $upto = [long][Math]::Min([double]$Hi, [double]$after + [double]$size)
        $p = @{}; foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }
        $p['After'] = [string]$after; $p['Upto'] = [string]$upto
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $v = & $Invoke $Sql $p 'scalar'
        $lastMs = $sw.ElapsedMilliseconds
        if ($null -ne $v -and -not ($v -is [System.DBNull])) { $n += [long]$v }
        if ($OnRange) { & $OnRange $after $upto $v }
        $after = $upto
        if ($sized) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
    }
    $n
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE BASE AND THE DECISION (full or changed-set, and why)
# ---------------------------------------------------------------------------------------------------------------------

function Resolve-SIDataChangedSetBuild {
    <#
        How ONE phase builds ONE collection this run: @{ Phase; Mode; Build; Why; BaseId; BaseTime; Seed; Fingerprint; RollSlot;
        RollReady; BuildParts }. Build: 'off' (the switch is off -- nothing recorded), 'full' (today's path; Why says why),
        'shadow' (both ways, the full result kept) or 'changed-set' (on). The base is the PUBLISHED collection only. Never
        throws (a read that fails = full).
        #1331: -BuildParts is this run's build fingerprint as recorded (Get-SIDataChangedSetBuildFingerprint .Parts); a phase
        fingerprint that differs from the base's names the parts that moved. RollSlot = the part of all CIs this quick build
        builds in full (the one after the phase's last finished run's); the weekly full build is due ONLY when the rolling
        check could not run (RollReady false: the database does not record it yet; or a quick build of the last FullDays days
        ran without it).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Phase, [Parameter(Mandatory)][long]$CollectionId,
          [Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][string]$Fingerprint, [Parameter(Mandatory)][string]$SetId,
          [int]$FullDays = $script:SIDataChangedSet.FullDays, [int]$Seed = 0, [string[]]$Stamps, [string]$BuildParts = '')
    $o = [ordered]@{ Phase = $Phase; Mode = $Mode; Build = 'full'; Why = ''; BaseId = $null; BaseTime = $null; Seed = $null; Fingerprint = $Fingerprint
                     RollSlot = $null; RollReady = $false; BuildParts = $BuildParts }
    if ($Mode -notin 'shadow', 'on') { $o.Build = 'off'; $o.Why = 'the switch is off'; return [pscustomobject]$o }
    try {
        if ($null -eq $Stamps) { $Stamps = Get-SIDataChangedSetStampColumns -Invoke $Invoke }
        $retired = [string](& $Invoke "SELECT CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL THEN 0 ELSE 1 END;" @{} 'scalar') -eq '1'
        $ret = if ($retired) { 'CASE WHEN b.RetiredAt IS NULL THEN 0 ELSE 1 END' } else { '0' }
        # #1331 the database records the rolling check and the build fingerprint's parts (sql\si-data-schema.sql)
        $roll = [string](& $Invoke (Get-SIDataChangedSetRollReadySql) @{} 'scalar') -eq '1'
        $o.RollReady = $roll
        $rollSql = if ($roll) {
            @"
       (SELECT TOP (1) r.RollingSlot FROM sidata.ChangedSetRun AS r WHERE r.Phase = @Phase AND r.Outcome = N'ok' AND r.RollingSlot IS NOT NULL ORDER BY r.ChangedSetRunId DESC) AS LastSlot,
       (SELECT COUNT_BIG(*) FROM sidata.ChangedSetRun AS r WHERE r.Phase = @Phase AND r.Outcome = N'ok' AND r.Build = N'changed-set' AND r.RollingSlot IS NULL AND r.StartedAt >= DATEADD(day, -CONVERT(int, @FullDays), SYSUTCDATETIME())) AS NoRoll,
       (SELECT TOP (1) r.BuildParts FROM sidata.ChangedSetRun AS r WHERE r.Phase = @Phase AND r.CollectionId = p.DetailedCollectionId AND r.Outcome = N'ok' ORDER BY r.ChangedSetRunId DESC) AS BaseParts,
"@
        } else { "       CAST(NULL AS tinyint) AS LastSlot, CAST(NULL AS bigint) AS NoRoll, CAST(NULL AS nvarchar(200)) AS BaseParts,`r`n" }
        $bsx = Get-SIDataChangedSetStampExpr -Alias 'b' -Have $Stamps
        $bshx = Get-SIDataChangedSetStampHashExpr -Alias 'b' -Have $Stamps
        $r = @(@(& $Invoke @"
SET NOCOUNT ON;
SELECT p.DetailedCollectionId AS BaseId, CONVERT(int, p.[Partial]) AS BasePartial, b.CollectionTime AS BaseTime, b.Status AS BaseStatus, b.Kind AS BaseKind,
       $ret AS BaseRetired, n.CollectionTime AS NewTime,
       bs.HashSet AS BaseSet, bs.BuiltAt AS BaseBuilt, bs.[Rows] AS BaseRows,
       (SELECT COUNT_BIG(*) FROM sidata.Finding AS bf WHERE bf.CollectionId = p.DetailedCollectionId) AS BaseN,
       (SELECT COUNT_BIG(*) FROM sidata.FindingHash AS bh WHERE bh.CollectionId = p.DetailedCollectionId) AS BaseH, $bsx AS BaseStamp, CASE WHEN bs.StampHash = $bshx THEN 1 ELSE 0 END AS BaseSame, ns.HashSet AS NewSet,
       (SELECT TOP (1) r.ChangedSetRunId FROM sidata.ChangedSetRun AS r WHERE r.Phase = @Phase AND r.CollectionId = p.DetailedCollectionId AND r.Outcome = N'ok' AND r.Fingerprint = @Fp ORDER BY r.ChangedSetRunId DESC) AS BaseRun,
       (SELECT MAX(r.StartedAt) FROM sidata.ChangedSetRun AS r WHERE r.Phase = @Phase AND r.Outcome = N'ok' AND r.Build IN (N'full', N'shadow') AND r.Fingerprint = @Fp) AS LastFull,
$rollSql       SYSUTCDATETIME() AS NowUtc
FROM (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = CONVERT(int, @CollectionId)) AS n
LEFT JOIN sidata.PublishedRun AS p ON p.Name = N'current'
LEFT JOIN sidata.Collection AS b ON b.CollectionId = p.DetailedCollectionId
LEFT JOIN sidata.FindingHashState AS bs ON bs.CollectionId = p.DetailedCollectionId
LEFT JOIN sidata.FindingHashState AS ns ON ns.CollectionId = CONVERT(int, @CollectionId);
"@ @{ CollectionId = [string]$CollectionId; Phase = $Phase; Fp = $Fingerprint; FullDays = [string]$FullDays } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $g = { param($n) Get-SIDataChangedSetRowValue $r $n }
        $baseId = & $g 'BaseId'
        $fmt = { param($t) if ($null -eq $t) { '' } else { ([datetime]$t).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } }
        if ($null -eq $r -or $null -eq (& $g 'NewTime')) { $o.Why = 'the collection is not stored'; return [pscustomobject]$o }
        if ($null -eq $baseId) { $o.Why = 'nothing is published yet -- there is no trusted collection to build from'; return [pscustomobject]$o }
        $o.BaseId = [long]$baseId; $o.BaseTime = & $g 'BaseTime'
        if ([long]$baseId -eq $CollectionId) { $o.Why = 'this collection is the published one'; return [pscustomobject]$o }
        if ([string](& $g 'BaseStatus') -ne 'Complete' -or [string](& $g 'BaseKind') -ne 'Detailed' -or [int](& $g 'BaseRetired') -ne 0) { $o.Why = 'the published collection is not complete'; return [pscustomobject]$o }
        if ([datetime](& $g 'BaseTime') -ge [datetime](& $g 'NewTime')) { $o.Why = 'the published collection is not older than this one'; return [pscustomobject]$o }
        if ([int](& $g 'BasePartial') -ne 0) { $o.Why = 'the published run is partial'; return [pscustomobject]$o }
        if ([string](& $g 'BaseSet') -ne $SetId) { $o.Why = 'the published collection has no finding hashes for this field list'; return [pscustomobject]$o }
        $bst = & $g 'BaseStamp'
        $bRows = & $g 'BaseRows'; $bN = [long](& $g 'BaseN'); $bH = [long](& $g 'BaseH')
        if ($null -eq $bRows -or [long]$bRows -ne $bN -or $bH -ne $bN) { $o.Why = 'the published collection''s findings and their hashes are not one for one any more'; return [pscustomobject]$o }
        if ([int](& $g 'BaseSame') -ne 1 -or ($null -ne $bst -and [datetime]$bst -gt [datetime](& $g 'BaseBuilt'))) { $o.Why = 'the published collection''s findings were rewritten after their hashes were made'; return [pscustomobject]$o }
        if ([string](& $g 'NewSet') -ne $SetId) { $o.Why = 'this collection''s finding hashes are not made'; return [pscustomobject]$o }
        if ($null -eq (& $g 'BaseRun')) {
            # #1331 say WHICH part of the build moved (the build fingerprint's parts recorded with the base), or that the field
            # list / the phase's own statement did
            $moved = $null; if ($BuildParts) { $moved = Compare-SIDataChangedSetBuildParts -Base ([string](& $g 'BaseParts')) -Now $BuildParts }
            if ($null -eq $moved) { $o.Why = 'the published collection was built by an older build or with other settings (no build fingerprint to compare)' }
            elseif (@($moved).Count) { $o.Why = ('the update changes what the build produces ({0})' -f (@($moved) -join ', ')) }
            else { $o.Why = 'the update changes what the build produces (the field list or this phase''s own statement)' }
            return [pscustomobject]$o
        }
        $lf = & $g 'LastFull'; $now = & $g 'NowUtc'
        if ($null -eq $lf) { $o.Why = 'no full build of this build is recorded'; return [pscustomobject]$o }
        # #1331 the weekly full build is the FALLBACK only: when the rolling full check could not run
        $noRoll = & $g 'NoRoll'
        $rollRan = $roll -and ($null -ne $noRoll) -and ([long]$noRoll -eq 0)
        if (-not $rollRan -and ([datetime]$now - [datetime]$lf).TotalDays -ge $FullDays) {
            $o.Why = ('the weekly full build is due (none in the last {0} days, and the rolling full check could not run: {1})' -f $FullDays, $(if (-not $roll) { 'the database does not record it yet' } else { ('{0:N0} quick build(s) of the last {1} days ran without it' -f [long]$noRoll, $FullDays) }))
            return [pscustomobject]$o
        }
        $o.Build = $(if ($Mode -eq 'shadow') { 'shadow' } else { 'changed-set' })
        $o.Why = ('built from what changed since the published collection of {0}' -f (& $fmt $o.BaseTime))
        $o.Seed = $(if ($Seed -ne 0) { $Seed } else { Get-Random -Minimum 1 -Maximum 2147483647 })
        if ($roll) { $o.RollSlot = Get-SIDataChangedSetNextRollSlot -Last (& $g 'LastSlot') }
    } catch {
        $o.Build = 'full'; $o.Why = ('what changed could not be read ({0})' -f (Get-SIDataChangedSetSafeError $_))
    }
    [pscustomobject]$o
}

function Get-SIDataChangedSetRollReadySql {
    <# 1 when sidata.ChangedSetRun records the rolling full check and the build fingerprint's parts (#1331), else 0. #>
    "SELECT CASE WHEN COL_LENGTH('sidata.ChangedSetRun', 'RollingSlot') IS NOT NULL AND COL_LENGTH('sidata.ChangedSetRun', 'BuildParts') IS NOT NULL THEN 1 ELSE 0 END;"
}

function Start-SIDataChangedSetRun {
    <# The phase's record (sidata.ChangedSetRun): why it is full or changed-set, its base, its fingerprint, the sample's seed and
       (#1331, where the database has the columns) the rolling part and the build fingerprint's parts. Answers its id. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Decision, [Parameter(Mandatory)][long]$CollectionId)
    $why = [string]$Decision.Why; if ($why.Length -gt 400) { $why = $why.Substring(0, 400) }
    $p = @{ Phase = [string]$Decision.Phase; CollectionId = [string]$CollectionId; BaseId = $(if ($null -ne $Decision.BaseId) { [string]$Decision.BaseId } else { $null })
            Mode = [string]$Decision.Mode; Build = [string]$Decision.Build; Why = $why; Fp = [string]$Decision.Fingerprint
            Seed = $(if ($null -ne $Decision.Seed) { [string]$Decision.Seed } else { $null }) }
    $roll = $false
    if ($Decision.PSObject.Properties['RollReady']) { $roll = [bool]$Decision.RollReady }
    if ($roll) {
        # (a part is recorded only for a quick build: a build decided full builds every CI in full anyway)
        $p['Slot'] = $(if ($null -ne $Decision.RollSlot -and [string]$Decision.Build -in 'shadow', 'changed-set') { [string]$Decision.RollSlot } else { $null })
        $bp = [string]$Decision.BuildParts; if ($bp.Length -gt 200) { $bp = $bp.Substring(0, 200) }
        $p['Parts'] = $(if ($bp) { $bp } else { $null })
        return [long](& $Invoke @'
SET NOCOUNT ON;
INSERT sidata.ChangedSetRun (Phase, CollectionId, BaseCollectionId, Mode, Build, Why, Fingerprint, SampleSeed, RollingSlot, BuildParts)
OUTPUT inserted.ChangedSetRunId
VALUES (@Phase, CONVERT(int, @CollectionId), CONVERT(int, @BaseId), @Mode, @Build, @Why, @Fp, CONVERT(int, @Seed), CONVERT(tinyint, @Slot), @Parts);
'@ $p 'scalar')
    }
    [long](& $Invoke @'
SET NOCOUNT ON;
INSERT sidata.ChangedSetRun (Phase, CollectionId, BaseCollectionId, Mode, Build, Why, Fingerprint, SampleSeed)
OUTPUT inserted.ChangedSetRunId
VALUES (@Phase, CONVERT(int, @CollectionId), CONVERT(int, @BaseId), @Mode, @Build, @Why, @Fp, CONVERT(int, @Seed));
'@ $p 'scalar')
}

function Complete-SIDataChangedSetRun {
    <# The phase's record finished: what was carried, compared, differed (keys / column names only), whether it fell back to
       the full build, and its outcome (ok = a base for the next run; failed = never). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$RunId, [string]$Build, [string]$Outcome = 'ok',
          $Findings, $Carried, $Compared, $Differences, [string]$Detail, $SampleCis, [switch]$FellBack)
    $s = { param($v) if ($null -eq $v) { $null } else { [string]$v } }
    $d = [string]$Detail; if ($d.Length -gt 1000) { $d = $d.Substring(0, 1000) }
    $null = & $Invoke @'
SET NOCOUNT ON;
UPDATE sidata.ChangedSetRun SET Build = COALESCE(@Build, Build), Outcome = @Outcome, Findings = CONVERT(bigint, @Findings), Carried = CONVERT(bigint, @Carried),
       Compared = CONVERT(bigint, @Compared), Differences = CONVERT(bigint, @Differences), DiffDetail = NULLIF(@Detail, N''), SampleCis = CONVERT(bigint, @SampleCis),
       FellBack = CONVERT(bit, @FellBack), EndedAt = SYSUTCDATETIME()
WHERE ChangedSetRunId = CONVERT(bigint, @RunId);
'@ @{ RunId = [string]$RunId; Build = $(if ($Build) { $Build } else { $null }); Outcome = $Outcome; Findings = (& $s $Findings); Carried = (& $s $Carried); Compared = (& $s $Compared)
      Differences = (& $s $Differences); Detail = $d; SampleCis = (& $s $SampleCis); FellBack = $(if ($FellBack) { '1' } else { '0' }) } 'nonquery'
}

function Clear-SIDataChangedSetCarry {
    <# The working pairs of one phase go -- this collection's (made again) and any other collection's (a run that stopped). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$PhaseNo)
    while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.ChangedSetCarry WHERE Phase = CONVERT(tinyint, @P); SELECT @@ROWCOUNT;' @{ P = [string]$PhaseNo } 'scalar') -gt 0) { }
}

function Clear-SIDataChangedSetOldHashes {
    <# Only the hashes a later run can use are kept: the published collection's and every newer one's; the others go (their
       collections are older than the trusted base, or no longer stored). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($l, $m) })
    try {
        $old = @(@(& $Invoke @'
SET NOCOUNT ON;
SELECT s.CollectionId FROM sidata.FindingHashState AS s
LEFT JOIN sidata.Collection AS c ON c.CollectionId = s.CollectionId
WHERE c.CollectionId IS NULL
   OR c.CollectionTime < (SELECT b.CollectionTime FROM sidata.PublishedRun AS p JOIN sidata.Collection AS b ON b.CollectionId = p.DetailedCollectionId WHERE p.Name = N'current');
'@ @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-SIDataChangedSetRowValue $_ 'CollectionId') })
        foreach ($c in $old) {
            $null = & $Invoke 'SET NOCOUNT ON; DELETE FROM sidata.FindingHashState WHERE CollectionId = CONVERT(int, @C);' @{ C = $c } 'nonquery'
            while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingHash WHERE CollectionId = CONVERT(int, @C); SELECT @@ROWCOUNT;' @{ C = $c } 'scalar') -gt 0) { }
        }
    } catch { & $Log 'INFO' ('what changed: older finding hashes were not cleared this run ({0}) -- the next run does it' -f (Get-SIDataChangedSetSafeError $_)) }
}

function Get-SIDataChangedSetPairsSql {
    <#
        PURE. ONE FindingId range of the new collection: its findings whose hash equals a finding of the base (@BaseId) -- the
        pairs whose result is carried -- into sidata.ChangedSetCarry (@P), with whether the finding's CI is in the sample
        (@Seed / @SamplePct). -Work (the findings per CI): only the keyed findings, and only a base finding that has its work row.
    #>
    param([switch]$Work)
    $sample = Get-SIDataChangedSetSampleSql -Asset 'f.AssetKey'
    $wj = ''; $kw = ''
    if ($Work) {
        $wj = "`nJOIN sidata.CiFindingDbWork AS wb ON wb.FindingId = b.FindingId"
        $kw = " AND f.RaFindingKey IS NOT NULL AND CHARINDEX(N'|', f.RaFindingKey) > 1"
    }
    @"
SET NOCOUNT ON;
INSERT sidata.ChangedSetCarry (Phase, CollectionId, FindingId, BaseFindingId, Sample)
SELECT CONVERT(tinyint, @P), CONVERT(int, @CollectionId), h.FindingId, MIN(b.FindingId), CONVERT(bit, MAX($sample))
FROM sidata.FindingHash AS h
JOIN sidata.FindingHash AS b ON b.CollectionId = CONVERT(int, @BaseId) AND b.FindingHash = h.FindingHash
JOIN sidata.Finding AS bf ON bf.CollectionId = b.CollectionId AND bf.FindingId = b.FindingId
JOIN sidata.Finding AS f ON f.CollectionId = h.CollectionId AND f.FindingId = h.FindingId$wj
WHERE h.CollectionId = CONVERT(int, @CollectionId) AND h.FindingId > CONVERT(bigint, @After) AND h.FindingId <= CONVERT(bigint, @Upto)$kw
GROUP BY h.FindingId;
SELECT @@ROWCOUNT;
"@
}

function Get-SIDataChangedSetCountSql {
    <# PURE. The pairs of one phase and collection (@P, @CollectionId): all of them, the sampled ones, the CIs sampled and (#1331)
       the CIs of this run's rolling part (@RollSlot; -1 = none) among them. #>
    'SET NOCOUNT ON; SELECT COUNT_BIG(*) AS N, ISNULL(SUM(CONVERT(int, k.Sample)), 0) AS S, (SELECT COUNT(DISTINCT f.AssetKey) FROM sidata.ChangedSetCarry AS k2 JOIN sidata.Finding AS f ON f.CollectionId = k2.CollectionId AND f.FindingId = k2.FindingId WHERE k2.Phase = CONVERT(tinyint, @P) AND k2.CollectionId = CONVERT(int, @CollectionId) AND k2.Sample = 1) AS SC, ' +
    '(SELECT COUNT(DISTINCT f.AssetKey) FROM sidata.ChangedSetCarry AS k3 JOIN sidata.Finding AS f ON f.CollectionId = k3.CollectionId AND f.FindingId = k3.FindingId WHERE k3.Phase = CONVERT(tinyint, @P) AND k3.CollectionId = CONVERT(int, @CollectionId) AND k3.Sample = 1 AND CONVERT(int, @RollSlot) >= 0 AND ' +
    (Get-SIDataChangedSetRollExpr -Asset 'f.AssetKey') + ' = CONVERT(int, @RollSlot)) AS RC FROM sidata.ChangedSetCarry AS k WHERE k.Phase = CONVERT(tinyint, @P) AND k.CollectionId = CONVERT(int, @CollectionId);'
}

function Get-SIDataChangedSetRollText {
    <# PURE. The rolling full check in a few words for the log (-Slot 0..6 or $null, -Cis). #>
    param($Slot, [long]$Cis)
    if ($null -eq $Slot) { return 'the rolling full check did not run' }
    'the rolling full check builds part {0} of {1} of all CIs in full ({2:N0} CI(s) with unchanged findings)' -f ([int]$Slot + 1), [int]$script:SIDataChangedSet.RollParts, $Cis
}

function Format-SIDataChangedSetDetail {
    <# PURE. The differing rows in a few words: finding ids and column names, never a value. #>
    param([object[]]$Rows)
    $parts = @(@($Rows) | Where-Object { $_ } | ForEach-Object {
        $id = Get-SIDataChangedSetRowValue $_ 'FindingId'; $c = [string](Get-SIDataChangedSetRowValue $_ 'Cols')
        if (-not $c) { $c = 'missing' }
        'finding {0}: {1}' -f $id, $c })
    ($parts -join '; ')
}

function Get-SIDataChangedSetWarningText {
    <# PURE. The run's warning for one phase's result (-Result: a phase result with Phase, Differences, Detail, FellBack,
       Problem), or '' when there is nothing to say. Plain words; no value of a finding, only its id and column names. #>
    param($Result)
    if ($null -eq $Result) { return '' }
    $g = { param($n) Get-SIDataChangedSetRowValue $Result $n }
    $name = [string]$script:SIDataChangedSet.PhaseNames[[string](& $g 'Phase')]; if (-not $name) { $name = [string](& $g 'Phase') }
    $d = & $g 'Differences'; $p = [string](& $g 'Problem')
    if ($null -ne $d -and [long]$d -gt 0) {
        $tail = if ([bool](& $g 'FellBack')) { 'this run was built in full before anything was published' } else { 'the full build was kept' }
        return ('the quick build of {0} from what changed differed from the full build in {1:N0} row(s) ({2}) -- {3}: nothing different was shown or sent' -f $name, [long]$d, [string](& $g 'Detail'), $tail)
    }
    if ($p) { return ('the quick build of {0} from what changed could not be checked this run ({1}) -- it was built in full' -f $name, $p) }
    ''
}

# ---------------------------------------------------------------------------------------------------------------------
#  PHASE 1: THE PREPARED VIEW COLUMNS (sidata.Finding's finding context, SI-DataViewContext.ps1)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataContextOutHashExpr {
    <# PURE. The hash of one finding's prepared view columns (-List) of the row aliased -Alias: every column, NULL marked. #>
    param([Parameter(Mandatory)]$List, [Parameter(Mandatory)][string]$Alias)
    $parts = @(Get-SIDataChangedSetListColumns -List $List | ForEach-Object { Get-SIDataChangedSetColumnPart -Alias $Alias -Column $_ })
    "HASHBYTES('SHA2_256', " + ($parts -join ' + ') + ')'
}

function Get-SIDataContextCarrySql {
    <#
        PURE. ONE FindingId range of the new collection: -Part copy -- the prepared view columns of every carried finding that is
        not in the sample, from its base finding (only where they differ: an unchanged value is never written again); -Part
        base -- the hash of the base finding's columns kept on the pair (@All = 1: every pair, shadow; else the sampled ones),
        what the full build is compared with; -Part compare -- the pairs whose finding, built in full, differs from that hash;
        -Part detail -- the first few of them with the names of the columns that differ.
    #>
    param([Parameter(Mandatory)]$List, [Parameter(Mandatory)][ValidateSet('copy', 'base', 'compare', 'detail', 'verify')][string]$Part)
    $cols = @(Get-SIDataChangedSetListColumns -List $List)
    $k = "k.Phase = 1 AND k.CollectionId = CONVERT(int, @CollectionId) AND k.FindingId > CONVERT(bigint, @After) AND k.FindingId <= CONVERT(bigint, @Upto)"
    switch ($Part) {
        'copy' {
            $set = (@($cols | ForEach-Object { '    [{0}] = b.[{0}]' -f $_ })) -join ",`r`n"
            $cb = (@($cols | ForEach-Object { 'CONVERT(varbinary(max), b.[{0}])' -f $_ })) -join ', '
            $cf = (@($cols | ForEach-Object { 'CONVERT(varbinary(max), f.[{0}])' -f $_ })) -join ', '
            @"
SET NOCOUNT ON;
UPDATE f SET
$set
FROM sidata.Finding AS f
JOIN sidata.ChangedSetCarry AS k ON k.Phase = 1 AND k.CollectionId = f.CollectionId AND k.FindingId = f.FindingId AND k.Sample = 0
JOIN sidata.Finding AS b ON b.CollectionId = CONVERT(int, @BaseId) AND b.FindingId = k.BaseFindingId
WHERE f.CollectionId = CONVERT(int, @CollectionId) AND f.FindingId > CONVERT(bigint, @After) AND f.FindingId <= CONVERT(bigint, @Upto)
  AND EXISTS (SELECT $cb EXCEPT SELECT $cf);
SELECT @@ROWCOUNT;
"@
        }
        'verify' {
            $cb = (@($cols | ForEach-Object { 'CONVERT(varbinary(max), b.[{0}])' -f $_ })) -join ', '
            $cf = (@($cols | ForEach-Object { 'CONVERT(varbinary(max), f.[{0}])' -f $_ })) -join ', '
            @"
SET NOCOUNT ON;
SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry AS k
JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId
LEFT JOIN sidata.Finding AS b ON b.CollectionId = CONVERT(int, @BaseId) AND b.FindingId = k.BaseFindingId
WHERE $k AND k.Sample = 0
  AND (b.FindingId IS NULL OR EXISTS (SELECT $cb EXCEPT SELECT $cf));
"@
        }
        'base' {
            @"
SET NOCOUNT ON;
UPDATE k SET OutHash = $(Get-SIDataContextOutHashExpr -List $List -Alias 'b')
FROM sidata.ChangedSetCarry AS k
JOIN sidata.Finding AS b ON b.CollectionId = CONVERT(int, @BaseId) AND b.FindingId = k.BaseFindingId
WHERE k.Phase = 1 AND k.CollectionId = CONVERT(int, @CollectionId) AND k.FindingId > CONVERT(bigint, @After) AND k.FindingId <= CONVERT(bigint, @Upto)
  AND (CONVERT(int, @All) = 1 OR k.Sample = 1);
SELECT @@ROWCOUNT;
"@
        }
        'compare' {
            @"
SET NOCOUNT ON;
SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry AS k
JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId
WHERE $k AND k.OutHash IS NOT NULL AND $(Get-SIDataContextOutHashExpr -List $List -Alias 'f') <> k.OutHash;
"@
        }
        'detail' {
            $which = (@($cols | ForEach-Object { "CASE WHEN EXISTS (SELECT CONVERT(varbinary(max), f.[{0}]) EXCEPT SELECT CONVERT(varbinary(max), b.[{0}])) THEN N'{0}' END" -f $_ })) -join ', '
            @"
SET NOCOUNT ON;
SELECT TOP (3) k.FindingId, CONCAT_WS(N', ', $which) AS Cols
FROM sidata.ChangedSetCarry AS k
JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId
JOIN sidata.Finding AS b ON b.CollectionId = CONVERT(int, @BaseId) AND b.FindingId = k.BaseFindingId
WHERE $k AND k.OutHash IS NOT NULL AND $(Get-SIDataContextOutHashExpr -List $List -Alias 'f') <> k.OutHash
ORDER BY k.FindingId;
"@
        }
    }
}

function ConvertFrom-SIDataContextResumeMark {
    <# PURE. A prepared-context resume mark: '<FindingId>' (a full fill) or '<FindingId>;cs;<build>;<seed>;<base>' (a quick build) ->
       @{ Upto; Tail; Build; Seed; BaseId }, $null when it is no mark. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    $m = [regex]::Match([string]$Value, '^\s*(-?\d+)(;cs;(shadow|changed-set);(\d+);(\d+))?\s*$')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ Upto = [long]$m.Groups[1].Value; Tail = [string]$m.Groups[2].Value; Build = [string]$m.Groups[3].Value
                       Seed = $(if ($m.Groups[4].Success) { [int]$m.Groups[4].Value } else { $null }); BaseId = [string]$m.Groups[5].Value }
}

function Get-SIDataContextChangedSetFill {
    <# PURE. The field fill (-Fill, Get-SIDataFindingContextSql) leaving out the carried findings that are not in the sample. #>
    param([Parameter(Mandatory)][string]$Fill)
    $re = [regex]::new('f\.FindingId <= @Upto')
    if (-not $re.IsMatch($Fill)) { throw 'the field fill is not in the shape the carried findings are left out of' }
    $re.Replace($Fill, 'f.FindingId <= @Upto AND NOT EXISTS (SELECT 1 FROM sidata.ChangedSetCarry AS csk WHERE csk.Phase = 1 AND csk.CollectionId = f.CollectionId AND csk.FindingId = f.FindingId AND csk.Sample = 0)', 1)
}

function Start-SIDataViewContextChangedSet {
    <#
        PHASE 1, before the field fill of one collection: its hashes, the decision, the record and -- shadow / changed-set --
        the pairs (and, on, the carried columns copied from the published collection). Returns the phase's state
        @{ Phase; Build; Why; Mode; BaseId; Seed; RunId; Fill; Carried; Sampled; SampleCis; Findings; Problem } or $null when the
        switch is off. Never throws: a failure is said, recorded 'failed' and the collection is built in full.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)]$List, [Parameter(Mandatory)][string]$SetId,
          [Parameter(Mandatory)][string]$Fill, [Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][long]$Lo, [Parameter(Mandatory)][long]$Hi,
          [int]$Seed = 0, [int]$SamplePercent = -1, $BuildPrint, [scriptblock]$Log = { param($l, $m) },
          # the collection's resume mark as it is stored (Get-SIDataContextMarkReadSql): a mark of a quick build names its build, base
          # and seed (ConvertFrom-SIDataContextResumeMark); the same build from the same base goes on with the SAME seed, anything
          # else is filled again from the start
          [AllowNull()][AllowEmptyString()][string]$ResumeMark)
    if ($Mode -notin 'shadow', 'on') { return $null }
    if ($SamplePercent -lt 0) { $SamplePercent = [int]$script:SIDataChangedSet.SamplePercent }
    $st = [ordered]@{ Phase = 'view-context'; Build = 'full'; Why = ''; Mode = $Mode; BaseId = $null; Seed = $null; RunId = $null; Fill = $Fill
                      Carried = 0L; Sampled = 0L; SampleCis = 0L; Findings = ($Hi - $Lo + 1); Problem = ''; SamplePercent = $SamplePercent; ResumeOk = $true; MarkTail = ''; RollSlot = $null; RollCis = 0L }
    $rm = ConvertFrom-SIDataContextResumeMark $ResumeMark
    try {
        $null = Get-SIDataChangedSetListColumns -List $List
        # nothing the list reads may be a field the hash leaves out (the run's own time)
        $rf = @($script:SIDataChangedSet.RunFields)
        $read = @(@($List.finding) | ForEach-Object { @($_.fields) + @(@($_.flags) | Where-Object { $_ } | ForEach-Object { $_.field }) } | Where-Object { $_ -and $rf -contains [string]$_ })
        $cols = Get-SIDataFindingHashColumns -Invoke $Invoke -List $List
        $hashSet = Get-SIDataFindingHashSetId -Columns $cols
        if ($null -eq $BuildPrint) { $BuildPrint = Get-SIDataChangedSetBuildFingerprint -Invoke $Invoke }
        $fp = Get-SIDataChangedSetFingerprint -Phase 'view-context' -HashSet $hashSet -PhaseText ($SetId + '|' + $Fill) -Build ([string]$BuildPrint.Print)
        $made = $true
        if (Test-SIDataChangedSetHashWanted -Invoke $Invoke -CollectionId $CollectionId) { try { $hr = Invoke-SIDataFindingHash -Invoke $Invoke -CollectionId $CollectionId -Columns $cols -SetId $hashSet -Log $Log; $st.Findings = [long]$hr.Rows }
        catch { $made = $false; $st.Problem = ('the finding hashes were not made: {0}' -f (Get-SIDataChangedSetSafeError $_)) } }
        $d = Resolve-SIDataChangedSetBuild -Invoke $Invoke -Phase 'view-context' -CollectionId $CollectionId -Mode $Mode -Fingerprint $fp -SetId $hashSet -Seed $Seed -BuildParts ([string]$BuildPrint.Parts)
        if ($rm -and $rm.Tail -and $d.Build -in 'shadow', 'changed-set' -and $rm.Build -eq $d.Build -and [string]$rm.BaseId -eq [string]$d.BaseId) { $d.Seed = $rm.Seed }
        if ($read.Count) { $d.Build = 'full'; $d.Why = ('the prepared columns read a field the hash leaves out ({0})' -f ($read -join ', ')) }
        elseif (-not $made) { $d.Build = 'full'; $d.Why = $st.Problem }
        $st.Build = $d.Build; $st.Why = $d.Why; $st.BaseId = $d.BaseId; $st.Seed = $d.Seed
        if ($st.Build -in 'shadow', 'changed-set') { $st.RollSlot = $d.RollSlot }
        $st.RunId = Start-SIDataChangedSetRun -Invoke $Invoke -Decision $d -CollectionId $CollectionId
        if ($st.Build -in 'shadow', 'changed-set') { $st.MarkTail = ';cs;{0};{1};{2}' -f $st.Build, $st.Seed, $st.BaseId }
        # a mark of another quick build (another seed, base or kind) is never gone on from; a plain mark (a full fill) is
        $st.ResumeOk = (-not $rm) -or (-not $rm.Tail) -or ($rm.Tail -eq $st.MarkTail)
        if ($st.Build -in 'shadow', 'changed-set') {
            Clear-SIDataChangedSetCarry -Invoke $Invoke -PhaseNo 1
            $p = @{ P = '1'; CollectionId = [string]$CollectionId; BaseId = [string]$st.BaseId; Seed = [string]$st.Seed; SamplePct = [string]$SamplePercent; RollSlot = $(if ($null -ne $st.RollSlot) { [string]$st.RollSlot } else { '-1' }) }
            $null = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataChangedSetPairsSql) -Params $p -Lo $Lo -Hi $Hi -Log $Log
            $c = @(@(& $Invoke (Get-SIDataChangedSetCountSql) @{ P = '1'; CollectionId = [string]$CollectionId; RollSlot = $p['RollSlot'] } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $st.Carried = [long](Get-SIDataChangedSetRowValue $c 'N'); $st.Sampled = [long](Get-SIDataChangedSetRowValue $c 'S'); $st.SampleCis = [long](Get-SIDataChangedSetRowValue $c 'SC'); $st.RollCis = [long](Get-SIDataChangedSetRowValue $c 'RC')
            $all = $(if ($st.Build -eq 'shadow') { '1' } else { '0' })
            $pb = @{ CollectionId = [string]$CollectionId; BaseId = [string]$st.BaseId; All = $all }
            $null = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataContextCarrySql -List $List -Part base) -Params $pb -Lo $Lo -Hi $Hi -Log $Log
            if ($st.Build -eq 'changed-set') {
                $null = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataContextCarrySql -List $List -Part copy) -Params $pb -Lo $Lo -Hi $Hi -Log $Log
                # every carried finding now holds exactly its base finding's columns (a base finding gone or rewritten meanwhile = the
                # collection is built in full: the caller's fill then reads every finding)
                $bad = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataContextCarrySql -List $List -Part verify) -Params $pb -Lo $Lo -Hi $Hi -Log $Log
                if ($bad -ne 0) { throw ('{0:N0} carried finding(s) do not hold their published finding''s columns' -f $bad) }
                # the base's compare value of every sampled pair is there (a pair without one would never be compared)
                $noOut = [long](& $Invoke 'SET NOCOUNT ON; SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry WHERE Phase = 1 AND CollectionId = CONVERT(int, @CollectionId) AND Sample = 1 AND OutHash IS NULL;' @{ CollectionId = [string]$CollectionId } 'scalar')
                if ($noOut -ne 0) { throw ('{0:N0} sampled finding(s) have no value to be compared with' -f $noOut) }
                $st.Fill = Get-SIDataContextChangedSetFill -Fill $Fill
                & $Log 'INFO' ('context     : collection {0} -- {1}: {2:N0} of {3:N0} finding(s) unchanged and carried; the rest built as before; the sample check builds {4:N0} CI(s) in full (seed {5}); {6}' -f $CollectionId, $st.Why, ($st.Carried - $st.Sampled), $st.Findings, $st.SampleCis, $st.Seed, (Get-SIDataChangedSetRollText -Slot $st.RollSlot -Cis $st.RollCis))
            } else {
                & $Log 'INFO' ('context     : collection {0} -- shadow: built in full as before AND compared with what changed since the published collection ({1:N0} unchanged finding(s) to compare)' -f $CollectionId, $st.Carried)
            }
        } else {
            & $Log 'INFO' ('context     : collection {0} -- built in full: {1}' -f $CollectionId, $st.Why)
        }
    } catch {
        $st.Build = 'full'; $st.Fill = $Fill; $st.Problem = (Get-SIDataChangedSetSafeError $_); $st.MarkTail = ''
        # what was copied before the failure stays only until the full fill reads every finding: never go on from a mark
        $st.ResumeOk = $false
        & $Log 'WARN' ('context     : what changed could not be prepared for collection {0} ({1}) -- it is built in full' -f $CollectionId, (Get-SIDataChangedSetSafeError $_))
        if ($st.RunId) { try { Complete-SIDataChangedSetRun -Invoke $Invoke -RunId $st.RunId -Build 'full' -Outcome 'failed' -Detail $st.Problem } catch { } }
        $st.RunId = $null
    }
    [pscustomobject]$st
}

function Test-SIDataViewContextChangedSet {
    <#
        PHASE 1, after the field fill: the compared pairs (shadow: every carried finding; on: the sampled ones, built in full)
        against their base's columns. Returns @{ Compared; Differences; Detail; Redo } -- Redo = on and a difference: the
        caller fills the whole collection again (the full build). Never throws (a compare that fails = Redo on, a problem).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$State, [Parameter(Mandatory)]$List, [Parameter(Mandatory)][long]$CollectionId,
          [Parameter(Mandatory)][long]$Lo, [Parameter(Mandatory)][long]$Hi, [scriptblock]$Log = { param($l, $m) })
    $out = [ordered]@{ Compared = 0L; Differences = 0L; Detail = ''; Redo = $false }
    if ($null -eq $State -or $State.Build -notin 'shadow', 'changed-set') { return [pscustomobject]$out }
    try {
        $p = @{ CollectionId = [string]$CollectionId; BaseId = [string]$State.BaseId }
        $out.Compared = $(if ($State.Build -eq 'shadow') { [long]$State.Carried } else { [long]$State.Sampled })
        $out.Differences = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataContextCarrySql -List $List -Part compare) -Params $p -Lo $Lo -Hi $Hi -Log $Log
        if ($out.Differences -gt 0) {
            $rows = @(@(& $Invoke (Get-SIDataContextCarrySql -List $List -Part detail) (@{ CollectionId = [string]$CollectionId; BaseId = [string]$State.BaseId; After = [string]($Lo - 1); Upto = [string]$Hi }) 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $out.Detail = Format-SIDataChangedSetDetail -Rows $rows
            $out.Redo = ($State.Build -eq 'changed-set')
            & $Log 'WARN' ('context     : collection {0} -- the quick build differed from the full build in {1:N0} of {2:N0} compared finding(s) ({3}) -- {4}' -f $CollectionId, $out.Differences, $out.Compared, $out.Detail, $(if ($out.Redo) { 'the whole collection is built in full now' } else { 'the full build is kept' }))
        } else {
            & $Log 'OK' ('context     : collection {0} -- the quick build equals the full build on {1:N0} compared finding(s)' -f $CollectionId, $out.Compared)
        }
    } catch {
        $State.Problem = ('the compare could not run: {0}' -f (Get-SIDataChangedSetSafeError $_))
        $out.Redo = ($State.Build -eq 'changed-set')
        & $Log 'WARN' ('context     : collection {0} -- the quick build could not be compared ({1}) -- {2}' -f $CollectionId, (Get-SIDataChangedSetSafeError $_), $(if ($out.Redo) { 'the whole collection is built in full now' } else { 'the full build is kept' }))
    }
    [pscustomobject]$out
}

# ---------------------------------------------------------------------------------------------------------------------
#  PHASE 2: THE FINDINGS PER CI'S WORK ROWS (sidata.CiFindingDbWork, SI-DataCi.ps1 Invoke-SIDataCiFindingFromDbRanged)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataCiWorkCarrySql {
    <#
        PURE. ONE FindingId range of the new collection: -Part carry -- the work row of every carried finding not in the sample:
        the finding's own columns, and the values the fill reads from its document taken from the base finding's work row;
        -Part compare -- the compared pairs (@All = 1: every pair, shadow; else the sampled ones) whose work row, built in full,
        differs from the base's (or is missing); -Part detail -- the first few with the names of the values that differ.
    #>
    param([Parameter(Mandatory)][ValidateSet('carry', 'compare', 'detail')][string]$Part)
    $j = @($script:SIDataChangedSet.WorkJson)
    foreach ($c in $j) { if (-not (Test-SIDataChangedSetColumnName $c)) { throw 'a work-row column name is not a plain identifier' } }
    $k = "k.Phase = 2 AND k.CollectionId = CONVERT(int, @CollectionId) AND k.FindingId > CONVERT(bigint, @After) AND k.FindingId <= CONVERT(bigint, @Upto)"
    $diff = "(wc.FindingId IS NULL OR EXISTS (SELECT $((@($j | ForEach-Object { 'CONVERT(varbinary(max), wc.[{0}])' -f $_ })) -join ', ') EXCEPT SELECT $((@($j | ForEach-Object { 'CONVERT(varbinary(max), wb.[{0}])' -f $_ })) -join ', ')))"
    switch ($Part) {
        'carry' {
            @"
SET NOCOUNT ON;
INSERT sidata.CiFindingDbWork (KeyHash, FindingId, RaSeq, RaFindingKey, AssetKey, RaAssetId, ConfigurationId, Title, AssetName, SecurityDomain, ReportName, Tier, RiskScore, ExemptionId,
                               Weighted, Component, Factors, SevRank, SubCi, PatchCycle, CvePublished, Cat, SubCat)
SELECT CHECKSUM(f.RaFindingKey), f.FindingId, f.RaSeq, f.RaFindingKey, f.AssetKey, f.RaAssetId, f.ConfigurationId, f.Title, f.AssetName, f.SecurityDomain, f.ReportName,
       f.Tier, f.RiskScore, f.ExemptionId,
       wb.Weighted, wb.Component, wb.Factors, wb.SevRank, wb.SubCi, wb.PatchCycle, wb.CvePublished, wb.Cat, wb.SubCat
FROM sidata.ChangedSetCarry AS k
JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId
JOIN sidata.CiFindingDbWork AS wb ON wb.FindingId = k.BaseFindingId
WHERE $k AND k.Sample = 0
  AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingDbWork AS wx WHERE wx.FindingId = k.FindingId);
SELECT @@ROWCOUNT;
"@
        }
        'compare' {
            @"
SET NOCOUNT ON;
SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry AS k
JOIN sidata.CiFindingDbWork AS wb ON wb.FindingId = k.BaseFindingId
LEFT JOIN sidata.CiFindingDbWork AS wc ON wc.FindingId = k.FindingId
WHERE $k AND (CONVERT(int, @All) = 1 OR k.Sample = 1) AND $diff;
"@
        }
        'detail' {
            $which = (@($j | ForEach-Object { "CASE WHEN wc.FindingId IS NOT NULL AND EXISTS (SELECT CONVERT(varbinary(max), wc.[{0}]) EXCEPT SELECT CONVERT(varbinary(max), wb.[{0}])) THEN N'{0}' END" -f $_ })) -join ', '
            @"
SET NOCOUNT ON;
SELECT TOP (3) k.FindingId, CASE WHEN wc.FindingId IS NULL THEN N'missing' ELSE CONCAT_WS(N', ', $which) END AS Cols
FROM sidata.ChangedSetCarry AS k
JOIN sidata.CiFindingDbWork AS wb ON wb.FindingId = k.BaseFindingId
LEFT JOIN sidata.CiFindingDbWork AS wc ON wc.FindingId = k.FindingId
WHERE $k AND (CONVERT(int, @All) = 1 OR k.Sample = 1) AND $diff
ORDER BY k.FindingId;
"@
        }
    }
}

function Get-SIDataCiWorkChangedSetFill {
    <# PURE. The work table's fill (-Fill, Get-SIDataCiDbWorkFillSql or its narrow form) leaving out a finding that already has its
       work row (a carried one). #>
    param([Parameter(Mandatory)][string]$Fill)
    $re = [regex]::new("CHARINDEX\(N'\|', f\.RaFindingKey\) > 1;")
    if (-not $re.IsMatch($Fill)) { throw 'the work table''s fill is not in the shape the carried findings are left out of' }
    $re.Replace($Fill, "CHARINDEX(N'|', f.RaFindingKey) > 1`r`n  AND NOT EXISTS (SELECT 1 FROM sidata.CiFindingDbWork AS wx WHERE wx.FindingId = f.FindingId);", 1)
}

function Start-SIDataCiWorkChangedSet {
    <#
        PHASE 2, before the work table's fill of the new collection (-CollectionId, its ids -Lo..-Hi): the decision, the record
        and -- when the work table still holds the PUBLISHED collection's rows, whole (its mark) -- the pairs and, on, the
        carried work rows. The work table then holds the base's rows AND the carried ones; the caller fills the rest (on: the
        findings without a work row; shadow: every finding, as before), then Complete-SIDataCiWorkChangedSet compares, takes the
        base's rows away and checks the count. Returns the phase's state or $null when the switch is off. Never throws: a
        failure = the full build (the caller empties the work table and fills it as before).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][long]$Lo, [Parameter(Mandatory)][long]$Hi,
          [Parameter(Mandatory)][string]$Mode, [string]$FillText = '', [int]$Seed = 0, [int]$SamplePercent = -1, $BuildPrint,
          [scriptblock]$Log = { param($l, $m) })
    if ($Mode -notin 'shadow', 'on') { return $null }
    if ($SamplePercent -lt 0) { $SamplePercent = [int]$script:SIDataChangedSet.SamplePercent }
    $st = [ordered]@{ Phase = 'swap'; Build = 'full'; Why = ''; Mode = $Mode; BaseId = $null; Seed = $null; RunId = $null; Carried = 0L; Sampled = 0L; SampleCis = 0L
                      Findings = 0L; BaseLo = $null; BaseHi = $null; Problem = ''; SamplePercent = $SamplePercent; Compared = 0L; Differences = 0L; Detail = ''; FellBack = $false; RollSlot = $null; RollCis = 0L }
    try {
        $list = $null
        if (Get-Command -Name Get-SIViewStoredColumns -ErrorAction SilentlyContinue) { $list = Get-SIViewStoredColumns }
        if (-not $list) { throw 'the list of prepared view columns is not loaded (the hash leaves them out)' }
        $cols = Get-SIDataFindingHashColumns -Invoke $Invoke -List $list
        $hashSet = Get-SIDataFindingHashSetId -Columns $cols
        if ($null -eq $BuildPrint) { $BuildPrint = Get-SIDataChangedSetBuildFingerprint -Invoke $Invoke }
        $fp = Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet $hashSet -PhaseText $FillText -Build ([string]$BuildPrint.Print)
        $made = $true
        if (Test-SIDataChangedSetHashWanted -Invoke $Invoke -CollectionId $CollectionId) { try { $hr = Invoke-SIDataFindingHash -Invoke $Invoke -CollectionId $CollectionId -Columns $cols -SetId $hashSet -Log $Log; $st.Findings = [long]$hr.Rows }
        catch { $made = $false; $st.Problem = ('the finding hashes were not made: {0}' -f (Get-SIDataChangedSetSafeError $_)) } }
        $d = Resolve-SIDataChangedSetBuild -Invoke $Invoke -Phase 'swap' -CollectionId $CollectionId -Mode $Mode -Fingerprint $fp -SetId $hashSet -Seed $Seed -BuildParts ([string]$BuildPrint.Parts)
        if (-not $made) { $d.Build = 'full'; $d.Why = $st.Problem }
        if ($d.Build -in 'shadow', 'changed-set') {
            # the work table must hold the published collection's rows, whole: its mark, its count, and the index by finding
            $hasIx = [string](& $Invoke "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CiFindingDbWork_FindingId' AND object_id = OBJECT_ID('sidata.CiFindingDbWork')) THEN 1 ELSE 0 END;" @{} 'scalar') -eq '1'
            $wm = $null; try { $wm = ConvertFrom-SIDataCiWorkMark (& $Invoke (Get-SIDataCiWorkMarkReadSql) @{ Name = (Get-SIDataCiWorkMarkName -CollectionId ([long]$d.BaseId)); CollectionId = [string]$d.BaseId } 'scalar') } catch { $wm = $null }
            $bb = @(@(& $Invoke (Get-SIDataCiDbWorkBoundsSql) @{ CollectionId = [string]$d.BaseId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $blo = Get-SIDataChangedSetRowValue $bb 'Lo'; $bhi = Get-SIDataChangedSetRowValue $bb 'Hi'
            $have = -1L; try { $have = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.CiFindingDbWork;' @{} 'scalar') } catch { $have = -1L }
            $outside = -1L
            if ($null -ne $blo) { try { $outside = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.CiFindingDbWork WHERE FindingId < CONVERT(bigint, @Lo) OR FindingId > CONVERT(bigint, @Hi);' @{ Lo = [string]$blo; Hi = [string]$bhi } 'scalar') } catch { $outside = -1L } }
            if (-not $hasIx) { $d.Build = 'full'; $d.Why = 'the database does not have the work rows'' index by finding yet (the update adds it)' }
            elseif ($null -eq $wm -or $null -eq $blo -or $wm.Upto -lt [long]$bhi -or $wm.Rows -ne $have -or $outside -ne 0) { $d.Build = 'full'; $d.Why = 'the work rows of the published collection are not kept whole' }
            else { $st.BaseLo = [long]$blo; $st.BaseHi = [long]$bhi }
        }
        $st.Build = $d.Build; $st.Why = $d.Why; $st.BaseId = $d.BaseId; $st.Seed = $d.Seed
        if ($st.Build -in 'shadow', 'changed-set') { $st.RollSlot = $d.RollSlot }
        $st.RunId = Start-SIDataChangedSetRun -Invoke $Invoke -Decision $d -CollectionId $CollectionId
        if ($st.Build -in 'shadow', 'changed-set') {
            Clear-SIDataChangedSetCarry -Invoke $Invoke -PhaseNo 2
            $p = @{ P = '2'; CollectionId = [string]$CollectionId; BaseId = [string]$st.BaseId; Seed = [string]$st.Seed; SamplePct = [string]$SamplePercent; RollSlot = $(if ($null -ne $st.RollSlot) { [string]$st.RollSlot } else { '-1' }) }
            $null = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataChangedSetPairsSql -Work) -Params $p -Lo $Lo -Hi $Hi -Log $Log
            $c = @(@(& $Invoke (Get-SIDataChangedSetCountSql) @{ P = '2'; CollectionId = [string]$CollectionId; RollSlot = $p['RollSlot'] } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $st.Carried = [long](Get-SIDataChangedSetRowValue $c 'N'); $st.Sampled = [long](Get-SIDataChangedSetRowValue $c 'S'); $st.SampleCis = [long](Get-SIDataChangedSetRowValue $c 'SC'); $st.RollCis = [long](Get-SIDataChangedSetRowValue $c 'RC')
            if ($st.Build -eq 'changed-set') {
                $added = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataCiWorkCarrySql -Part carry) -Params @{ CollectionId = [string]$CollectionId } -Lo $Lo -Hi $Hi -Log $Log
                if ($added -ne ($st.Carried - $st.Sampled)) { throw ('{0:N0} work row(s) were carried for {1:N0} unchanged finding(s)' -f $added, ($st.Carried - $st.Sampled)) }
                & $Log 'INFO' ('v3 model    : the findings per CI -- {0}: {1:N0} unchanged finding(s) carried; the rest read as before; the sample check reads {2:N0} CI(s) in full (seed {3}); {4}' -f $st.Why, $added, $st.SampleCis, $st.Seed, (Get-SIDataChangedSetRollText -Slot $st.RollSlot -Cis $st.RollCis))
            } else {
                & $Log 'INFO' ('v3 model    : the findings per CI -- shadow: read in full as before AND compared with what changed since the published collection ({0:N0} unchanged finding(s) to compare)' -f $st.Carried)
            }
        } else {
            & $Log 'INFO' ('v3 model    : the findings per CI -- read in full: {0}' -f $st.Why)
        }
    } catch {
        $st.Problem = (Get-SIDataChangedSetSafeError $_); $st.Build = 'failed'
        & $Log 'WARN' ('v3 model    : what changed could not be prepared for the findings per CI ({0}) -- they are read in full' -f (Get-SIDataChangedSetSafeError $_))
        if ($st.RunId) { try { Complete-SIDataChangedSetRun -Invoke $Invoke -RunId $st.RunId -Build 'full' -Outcome 'failed' -Detail $st.Problem } catch { } }
        $st.RunId = $null
    }
    [pscustomobject]$st
}

function Complete-SIDataCiWorkChangedSet {
    <#
        PHASE 2, after the fill: the compared pairs (shadow: all; on: the sampled ones, read in full) against the base's work rows;
        the base's rows taken away (a FindingId range at a time); the work table must then hold exactly -Rows rows of the new
        collection, each once -- else it THROWS (nothing is staged or swapped). Returns @{ Compared; Differences; Detail; Redo }
        -- Redo = on and a difference: the caller reads the collection in full (the work table emptied first).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$State, [Parameter(Mandatory)][long]$CollectionId,
          [Parameter(Mandatory)][long]$Lo, [Parameter(Mandatory)][long]$Hi, [Parameter(Mandatory)][long]$Rows, [scriptblock]$Log = { param($l, $m) })
    $out = [ordered]@{ Compared = 0L; Differences = 0L; Detail = ''; Redo = $false }
    $all = $(if ($State.Build -eq 'shadow') { '1' } else { '0' })
    $p = @{ CollectionId = [string]$CollectionId; All = $all }
    try {
        $out.Compared = $(if ($State.Build -eq 'shadow') { [long]$State.Carried } else { [long]$State.Sampled })
        $out.Differences = Invoke-SIDataChangedSetRanges -Invoke $Invoke -Sql (Get-SIDataCiWorkCarrySql -Part compare) -Params $p -Lo $Lo -Hi $Hi -Log $Log
        if ($out.Differences -gt 0) {
            $pd = @{ CollectionId = [string]$CollectionId; All = $all; After = [string]($Lo - 1); Upto = [string]$Hi }
            $out.Detail = Format-SIDataChangedSetDetail -Rows @(@(& $Invoke (Get-SIDataCiWorkCarrySql -Part detail) $pd 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $out.Redo = ($State.Build -eq 'changed-set')
        }
    } catch {
        $State.Problem = ('the compare could not run: {0}' -f (Get-SIDataChangedSetSafeError $_))
        $out.Redo = ($State.Build -eq 'changed-set')
    }
    # the base's rows go (they are older ids: a range of the index by finding at a time), and the work table must then hold
    # exactly -Rows rows of the new collection, each once. Either going wrong = the full build (the caller empties the work
    # table and reads the collection in full), never a failure of the findings per CI (review 2026-11-23)
    try {
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.CiFindingDbWork WHERE FindingId >= CONVERT(bigint, @Lo) AND FindingId <= CONVERT(bigint, @Hi); SELECT @@ROWCOUNT;' @{ Lo = [string]$State.BaseLo; Hi = [string]$State.BaseHi } 'scalar') -gt 0) { }
        if (-not $out.Redo) {
            $chk = @(@(& $Invoke 'SET NOCOUNT ON; SELECT COUNT_BIG(*) AS W, COUNT_BIG(DISTINCT FindingId) AS D, SUM(CASE WHEN FindingId < CONVERT(bigint, @Lo) OR FindingId > CONVERT(bigint, @Hi) THEN 1 ELSE 0 END) AS O FROM sidata.CiFindingDbWork;' @{ Lo = [string]$Lo; Hi = [string]$Hi } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            $w = [long](Get-SIDataChangedSetRowValue $chk 'W'); $dd = [long](Get-SIDataChangedSetRowValue $chk 'D'); $o = Get-SIDataChangedSetRowValue $chk 'O'
            if ($w -ne $Rows -or $dd -ne $w -or ($null -ne $o -and [long]$o -ne 0)) {
                throw ('the work rows came out {0:N0} ({1:N0} distinct, {2} of another collection) for {3:N0} read' -f $w, $dd, $o, $Rows)
            }
        }
    } catch {
        $State.Problem = ('the work rows could not be checked: {0}' -f (Get-SIDataChangedSetSafeError $_))
        $out.Redo = $true
    }
    if ($out.Differences -gt 0) {
        & $Log 'WARN' ('v3 model    : the findings per CI -- the quick build differed from the full build in {0:N0} of {1:N0} compared finding(s) ({2}) -- {3}' -f $out.Differences, $out.Compared, $out.Detail, $(if ($out.Redo) { 'the collection is read in full now' } else { 'the full build is kept' }))
    } elseif ($State.Problem) {
        & $Log 'WARN' ('v3 model    : the findings per CI -- the quick build could not be compared ({0}) -- {1}' -f $State.Problem, $(if ($out.Redo) { 'the collection is read in full now' } else { 'the full build is kept' }))
    } else {
        & $Log 'OK' ('v3 model    : the findings per CI -- the quick build equals the full build on {0:N0} compared finding(s)' -f $out.Compared)
    }
    [pscustomobject]$out
}

function ConvertTo-SIDataChangedSetResult {
    <# PURE. A phase's state + its compare -> the result the data sync keeps (and Get-SIDataSyncIssues reads). #>
    param($State, $Check)
    if ($null -eq $State) { return $null }
    $g = { param($o, $n) Get-SIDataChangedSetRowValue $o $n }
    [pscustomobject]@{
        Phase = [string](& $g $State 'Phase'); Mode = [string](& $g $State 'Mode'); Build = [string](& $g $State 'Build'); Why = [string](& $g $State 'Why')
        BaseId = (& $g $State 'BaseId'); Seed = (& $g $State 'Seed'); Carried = [long](& $g $State 'Carried'); SampleCis = [long](& $g $State 'SampleCis')
        Compared = $(if ($Check) { [long](& $g $Check 'Compared') } else { 0L }); Differences = $(if ($Check) { [long](& $g $Check 'Differences') } else { 0L })
        Detail = $(if ($Check) { [string](& $g $Check 'Detail') } else { '' }); FellBack = $(if ($Check) { [bool](& $g $Check 'Redo') } else { $false })
        Problem = [string](& $g $State 'Problem')
        # #1331 the rolling full check's part this run (0..6; $null = it did not run) and its CIs with unchanged findings
        RollSlot = (& $g $State 'RollSlot'); RollCis = [long](& $g $State 'RollCis')
    }
}
