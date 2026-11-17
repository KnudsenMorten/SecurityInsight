#Requires -Version 5.1
<#
    SecurityInsight Pro -- REMEDIATION TASKS PER CI (REQUIREMENTS #1277; owner 2026-11-16: "one vulnerability per CI per task to
    perform" -- the CVEs / findings the task resolves are information on it). Additive to the Remediations (#636, one fix applied
    to many assets: SI-DataRemediation.ps1), which are not changed.

    ONE TASK = ONE THING TO DO ON ONE CI. Built by the data sync per collection, after the findings per CI and their lifecycle
    (sidata.CiFindingState) are stored:

      THE TASK KEY -- the finding field map's grouping rule (data-model/finding-fields.locked.json: si_security_grouping_parent
        and its kind, the SAME rule the ServiceNow grouping column uses -- one rule, never two), worked out ONCE per distinct
        finding signature (the fields the rule reads), never per finding:
          CVE on the OS        the update name ("(Last updated at ...)" cut), else "Security update KB<id>"
          other CVE            "Update <product> <version> (<vendor>)" -- SEVERAL VERSIONS ON ONE CI = SEVERAL TASKS (the
                               finding's ';'-separated versions are split, one task each)
          a BUNDLED library    the software evidence (Get-SISoftwareEvidence, the one interface to it): a copy that lies in
                               ANOTHER product's folder (install kind 'bundled') is ONE TASK PER APPLICATION -- "Update
                               <application> (bundles <product> <version>)", with every path of that copy; the fix comes from
                               that product's vendor. The product's own task stays only when a copy is NOT bundled.
          configuration / Azure / attack path / identity rule   the title (one task per setting)
          identity object      "Identity risk review: <category>"
          no known fix         no task (the finding keeps none -- never a guessed one)
        A name equal to the finding's asset or CMDB name is never a task.
      THE LINKS -- sidata.RemediationTaskFinding: every finding of the task (many-to-many). The finding keeps its own key.

    THE LIFECYCLE, RUN TO RUN (the close-loop rules -- absence is not remediation):
      open      while any linked finding is open (the task is worked out again from this collection's findings)
      closed    fixed            ONLY ON POSITIVE EVIDENCE: every linked finding is gone and the finding lifecycle closed it
                                 as remediated (which needs complete Risk Analysis runs); or -- a bundled task -- the finding is
                                 still there but the software evidence of that copy on the CI was READ this run with its paths on
                                 disk and none of the task's paths holds that library version any more. A finding still there
                                 whose task no longer comes out (its version moved or went blank, the rule names another task or
                                 none, the name is now the asset's own) closes as "task changed" -- never "fixed".
                exempted         every finding still there is exempted (an exempted finding never opens or keeps open a task; it
                                 stays visible on the asset); the exemption undone = the task reopens
                asset retired    the CI is retired (never "fixed")
                report changed   the report that found it asks something else now
                task changed     the finding is still there but now belongs to another task (its fix text changed)
      kept      anything not known: an incomplete or unknown run, a finding absent but not closed yet, a CI not seen or frozen,
                a bundled copy whose evidence was not read or was read without a path on disk (a registry row only), a CI whose
                evidence page failed to read -- the task is carried exactly as it was (InThisCollection = 0)
      reopened  a closed task worked out again (ReopenCount)
    Closed tasks are carried in every later collection for SI_Pro_FindingStateRetentionDays (365), like the closed findings.

    WHAT IS WRITTEN: sidata.RemediationTask / RemediationTaskFinding for the NEWEST complete collection (the base is the newest
    collection built before it), a range of CIs per transaction; the task rows of collections older than that base are removed.
    Collection.RemediationTasksAt marks it. ONE BUILD AT A TIME (an exclusive lock over the whole build). Every path on a task
    is kept in full (owner 2026-11-17). READ-ONLY towards every source. Never fails the data sync. No PowerShell
    module: every statement through the data sync's own SQL seam (-Invoke sql params mode).
    PowerShell 5.1 and 7: no ?. / ??, no ternary.
#>

$script:SIRemTaskRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command -Name Get-SIFindingFieldPlan -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRemTaskRoot, 'data-model', 'SI-FindingFieldMapper.ps1')) }
if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRemTaskRoot, 'data-model', 'SI-DataModelTemplates.ps1')) }
if (-not (Get-Command -Name Get-SISoftwareEvidence -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRemTaskRoot, '_shared', 'SI-SoftwareEvidence.ps1')) }

# (lists are returned by functions, never read from a script variable: a file dot-sourced inside a function keeps its variables
# in THAT scope -- the trap of #961)

function Get-SIRemediationTaskColumns {
    <# PURE. The SI fields the grouping rule may read -> their stored column over a finding row f (k = the key parts). #>
    [ordered]@{
        si_finding_type              = 'k.Typ'
        si_finding_key               = 'k.FKey'
        si_cve                       = 'f.Cve'
        si_component                 = 'f.Component'
        si_fix_recommended_update    = 'f.FixRecommendedUpdate'
        si_fix_recommended_update_id = 'f.FixRecommendedUpdateId'
        si_affected_product          = 'f.AffectedProduct'
        si_affected_vendor           = 'f.AffectedVendor'
        si_affected_version          = 'f.AffectedVersion'
        si_title                     = 'f.Title'
        si_category                  = 'f.Category'
        si_subcategory               = 'f.Subcategory'
        si_security_domain           = 'f.SecurityDomain'
        si_report_name               = 'f.ReportName'
        si_severity                  = 'f.Severity'
    }
}

function Get-SIRemediationTaskRuleFields {
    <#
        PURE. The fields the grouping rule reads (every item of si_security_grouping_parent / _name / _kind: its source paths,
        its template placeholders, its condition's fields), the finding type always. @{ Known (stored on the finding);
        Unknown (not stored -- such a source gives no task) }.
    #>
    param([Parameter(Mandatory)]$Plan)
    $cols = Get-SIRemediationTaskColumns
    $seen = New-Object 'System.Collections.Generic.List[string]'
    $seen.Add('si_finding_type')
    foreach ($fld in 'si_security_grouping_parent', 'si_security_grouping_name', 'si_security_grouping_kind') {
        if (-not $Plan.Items.ContainsKey($fld)) { continue }
        foreach ($it in $Plan.Items[$fld]) {
            $names = New-Object 'System.Collections.Generic.List[string]'
            foreach ($s in @($it.Sources)) {
                $ss = [string]$s
                if ($ss.StartsWith('$template:')) { foreach ($m in [regex]::Matches($ss, '\{([A-Za-z_][A-Za-z0-9_\.]*)\}')) { $names.Add($m.Groups[1].Value) } }
                elseif (-not $ss.StartsWith('$')) { $names.Add($ss) }
            }
            if ($null -ne $it.When) { foreach ($w in @(Get-SIConditionFields $it.When)) { $names.Add([string]$w) } }
            foreach ($n in $names) {
                $root = ([regex]::Match([string]$n, '^[A-Za-z_][A-Za-z0-9_]*')).Value
                if ($root -and -not $seen.Contains($root)) { $seen.Add($root) }
            }
        }
    }
    $known = @($seen | Where-Object { $cols.Contains($_) })
    $unknown = @($seen | Where-Object { -not $cols.Contains($_) })
    [pscustomobject]@{ Known = [string[]]$known; Unknown = [string[]]$unknown }
}

function Get-SIRemediationTaskKeyApplySql {
    <# PURE. The parts of a finding row f: its owner (the CI, or asset:<id>) and finding key, as the findings per CI make them. #>
    @'
CROSS APPLY (SELECT CHARINDEX(N'|', f.RaFindingKey) AS P) AS sp
CROSS APPLY (SELECT LEFT(f.RaFindingKey, sp.P - 1) AS OwnerKey, SUBSTRING(f.RaFindingKey, sp.P + 1, 900) AS KeyPart) AS o
CROSS APPLY (SELECT LEFT(CASE WHEN LOWER(f.ConfigurationId) = o.KeyPart THEN f.ConfigurationId ELSE o.KeyPart END, 256) AS FKey) AS k0
CROSS APPLY (SELECT k0.FKey, CASE WHEN k0.FKey LIKE N'CVE-[0-9][0-9][0-9][0-9]-%' THEN N'cve' ELSE N'recommendation' END AS Typ) AS k
'@
}

function Get-SIRemediationTaskSigExpr {
    <# PURE. The finding's SIGNATURE: SHA-256 over the finding type and every field the rule reads (in -Fields' order). #>
    param([Parameter(Mandatory)][string[]]$Fields)
    $cols = Get-SIRemediationTaskColumns
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($f in $Fields) { $parts.Add(("ISNULL(CONVERT(nvarchar(max), {0}), N'')" -f $cols[$f])) }
    "HASHBYTES('SHA2_256', CONCAT(N'', " + ($parts -join ", NCHAR(31), ") + "))"
}

function Get-SIRemediationTaskSigSql {
    <# One row per distinct signature of the collection's findings (@CollectionId): SigHash, the fields (c0..cn), N. #>
    param([Parameter(Mandatory)][string[]]$Fields)
    $cols = Get-SIRemediationTaskColumns
    $sel = New-Object 'System.Collections.Generic.List[string]'
    $agg = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $Fields.Count; $i++) { $sel.Add(("CONVERT(nvarchar(4000), {0}) AS c{1}" -f $cols[$Fields[$i]], $i)); $agg.Add(("MAX(x.c{0}) AS c{0}" -f $i)) }
    @"
SET NOCOUNT ON;
SELECT CONVERT(varchar(64), x.SigHash, 2) AS SigHex, $($agg -join ', '), COUNT_BIG(*) AS N
FROM (SELECT $(Get-SIRemediationTaskSigExpr -Fields $Fields) AS SigHash, $($sel -join ', ')
      FROM sidata.Finding AS f
$(Get-SIRemediationTaskKeyApplySql)
      WHERE f.CollectionId = CONVERT(int, @CollectionId) AND f.RaFindingKey IS NOT NULL AND sp.P > 1) AS x
GROUP BY x.SigHash;
"@
}

function Get-SIRemediationTaskKey {
    <# PURE. The task key: '<kind>|<name, trimmed, lower case>' -- in full, never cut (the task id is a hash of it). #>
    param([string]$Kind, [string]$Name)
    $k = ('{0}|{1}' -f ([string]$Kind).Trim().ToLowerInvariant(), ([string]$Name).Trim().ToLowerInvariant())
    $k
}

function Split-SIRemediationTaskList {
    <# PURE. A ';'-separated value -> its distinct non-blank items (case-insensitive), in order. #>
    param($Value)
    $out = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return , $out.ToArray() }
    foreach ($p in ([string]$Value).Split(';')) { $t = $p.Trim(); if ($t -and $seen.Add($t)) { $out.Add($t) } }
    , $out.ToArray()
}

function ConvertTo-SIRemediationTaskUnits {
    <#
    .SYNOPSIS  PURE. THE TASK RULE for one finding signature: the field values (-Values: SI field -> value, the finding type
               among them) -> the tasks it belongs to, each @{ TaskKey; TaskName; Kind; Product; Vendor; Version }. The name and
               the kind are the finding field map's si_security_grouping_parent / _kind (-Map); a finding naming SEVERAL
               versions of one product (or several products of one version) is split first -- one task per version. No value =
               no task (an empty list).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values, [Parameter(Mandatory)]$Map, $Plan, $ValueMaps)
    if ($null -eq $Plan) { $Plan = Get-SIFindingFieldPlan -Map $Map }
    $prods = Split-SIRemediationTaskList $Values['si_affected_product']
    $vers = Split-SIRemediationTaskList $Values['si_affected_version']
    $vends = Split-SIRemediationTaskList $Values['si_affected_vendor']
    $variants = New-Object System.Collections.Generic.List[object]
    if ($prods.Count -le 1 -and $vers.Count -gt 1) { foreach ($v in $vers) { $variants.Add(@{ si_affected_version = $v }) } }
    elseif ($prods.Count -gt 1 -and $vers.Count -le 1) { foreach ($p in $prods) { $variants.Add(@{ si_affected_product = $p }) } }
    else { $variants.Add(@{}) }
    $units = [ordered]@{}
    foreach ($var in $variants) {
        $h = [ordered]@{}
        foreach ($k in $Values.Keys) { $v = $Values[$k]; if ($v -is [System.DBNull]) { $v = $null }; $h[[string]$k] = $v }
        foreach ($k in $var.Keys) { $h[[string]$k] = $var[$k] }
        $item = [pscustomobject]$h
        $vals = ConvertTo-SIFindingFieldValues -Item $item -Map $Map -Plan $Plan -ValueMaps $ValueMaps -Fields @('si_security_grouping_parent', 'si_security_grouping_kind')
        $name = ''; if ($vals.Contains('si_security_grouping_parent')) { $name = ([string]$vals['si_security_grouping_parent']).Trim() }
        if (-not $name) { continue }
        $kind = ''; if ($vals.Contains('si_security_grouping_kind')) { $kind = ([string]$vals['si_security_grouping_kind']).Trim().ToLowerInvariant() }
        if (-not $kind) { $kind = 'other' }
        $prod = ''; $ver = ''; $vend = ''
        if ($kind -eq 'software-upgrade') {
            $pp = Split-SIRemediationTaskList $h['si_affected_product']; if ($pp.Count -eq 1) { $prod = $pp[0] }
            $vv = Split-SIRemediationTaskList $h['si_affected_version']; if ($vv.Count -eq 1) { $ver = $vv[0] }
            if ($vends.Count -eq 1) { $vend = $vends[0] }
        }
        $key = Get-SIRemediationTaskKey -Kind $kind -Name $name
        if ($units.Contains($key)) { continue }
        $units[$key] = [pscustomobject][ordered]@{ TaskKey = $key; TaskName = $name; Kind = $kind; Product = $prod; Vendor = $vend; Version = $ver }
    }
    , @($units.Values)
}

function Get-SIRemediationTaskAppKeyName {
    <# PURE. An application's name as a task's KEY holds it: every version in it left out (a number with its dots, dashes,
       underscores and plus signs, a leading 'v'), so a folder named after its version (jdk-17.0.1 -> jdk-17.0.2, Python311 ->
       Python312) keeps the same task when the application updates. The name shown keeps the version. #>
    param([string]$Name)
    $k = [regex]::Replace([string]$Name, '(?i)[\s._+-]*v?\d[\d._+-]*', ' ')
    $k = ([regex]::Replace($k, '\s+', ' ')).Trim(' ', '-', '_', '.')
    if (-not $k) { return [string]$Name }
    $k
}

function Get-SIRemediationTaskBundledUnits {
    <#
    .SYNOPSIS  PURE. The software evidence of ONE software on ONE CI (-Rows: the evidence rows of the CI's devices for that
               product and version) -> @{ Known (evidence was read: at least one copy); KeepPlain (a copy that is NOT bundled
               exists -- the product's own task stays); DiskPaths (every path on disk of that software, ';' -- '' when the
               evidence has no disk path, only a registry row: then nothing is known about any copy's place); Units (one per
               application that bundles it: TaskKey, TaskName, Application, Paths, EvidenceAt) }. A registry row of a copy that
               has a disk path says nothing on its own.
               THE TASK'S IDENTITY NEVER HOLDS THE APPLICATION'S VERSION: an application updated from 1.2 to 1.3 that still
               bundles the same library keeps the same task (its key is the application's name); the name shows the version the
               inventory names (one version, else none).
               Every path is kept IN FULL, a user name in it included (owner 2026-11-17: the evidence an Admin needs).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$Product, [Parameter(Mandatory)][string]$Version)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    $res = [pscustomobject]@{ Known = ($rows.Count -gt 0); KeepPlain = $false; DiskPaths = ''; Units = @() }
    if ($rows.Count -eq 0) { return $res }
    $g = { param($r, $n) $x = Get-SIEvValue $r $n; if ($x -is [System.DBNull]) { $null } else { $x } }
    $disk = @($rows | Where-Object { [string](& $g $_ 'PathType') -eq 'disk' })
    if ($disk.Count -eq 0) { $res.KeepPlain = $true; return $res }
    $all = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $apps = [ordered]@{}
    foreach ($r in $disk) {
        $fp = [string](& $g $r 'FullPath')
        if ($fp) { [void]$all.Add($fp) }
        if ([string](& $g $r 'InstallKind') -ne 'bundled') { $res.KeepPlain = $true; continue }
        $an = ([string](& $g $r 'Application')).Trim()
        if (-not $an) { $res.KeepPlain = $true; continue }
        # one unit per application KEY. A FOLDER-derived name leaves its version out of the key (two copies under versioned
        # folders -- jdk-17, jdk-21 -- are one task with every path of both); a name the INVENTORY matched keeps it (Python 2.7 and
        # Python 3.11 are two applications), and the inventory's own version field is never part of the key
        $inv = ([string](& $g $r 'ApplicationSource') -eq 'inventory')
        $keyApp = $(if ($inv) { $an } else { Get-SIRemediationTaskAppKeyName $an })
        $ak = $keyApp.ToLowerInvariant()
        if ($apps.Contains($ak) -and $apps[$ak].Name -cne $an) { $apps[$ak].Name = $keyApp }
        if (-not $apps.Contains($ak)) { $apps[$ak] = @{ KeyApp = $keyApp; Name = $an; Versions = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)); Paths = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase)); At = $null } }
        if ([string](& $g $r 'ApplicationSource') -eq 'inventory') { $av = ([string](& $g $r 'ApplicationVersion')).Trim(); if ($av) { [void]$apps[$ak].Versions.Add($av) } }
        if ($fp) { [void]$apps[$ak].Paths.Add($fp) }
        $ct = & $g $r 'CollectionTime'
        if ($null -ne $ct -and "$ct" -ne '') { try { $t = [datetime]$ct; if ($null -eq $apps[$ak].At -or $t -gt $apps[$ak].At) { $apps[$ak].At = $t } } catch { } }
    }
    $res.DiskPaths = (@($all) -join ';')
    $units = New-Object System.Collections.Generic.List[object]
    foreach ($a in $apps.Values) {
        # the key: the application's name only (never its version); the name: with its version when the inventory names one
        $keyName = ('Update {0} (bundles {1} {2})' -f $a.KeyApp, $Product, $Version)
        $shown = $a.Name; if ($a.Versions.Count -eq 1) { $shown = $a.Name + ' ' + @($a.Versions)[0] }
        $name = ('Update {0} (bundles {1} {2})' -f $shown, $Product, $Version)
        $units.Add([pscustomobject][ordered]@{ TaskKey = (Get-SIRemediationTaskKey -Kind 'bundled-upgrade' -Name $keyName); TaskName = $name; Application = $a.Name
                                               Paths = (@($a.Paths) -join ';'); EvidenceAt = $a.At })
    }
    $res.Units = $units.ToArray()
    $res
}

function Get-SIRemediationTaskSoftwareSql {
    <# The software units on each CI of the collection (@CollectionId, the signatures of build @BuildId): owner, product, vendor,
       version, and the CI's Defender device ids (';'). #>
    @"
SET NOCOUNT ON;
WITH u AS (
    SELECT DISTINCT LEFT(o.OwnerKey, 450) AS OwnerKey, s.Product, s.Vendor, s.Version
    FROM sidata.Finding AS f
$(Get-SIRemediationTaskKeyApplySql)
    JOIN sidata.RemediationTaskSig AS s ON s.BuildId = CONVERT(uniqueidentifier, @BuildId) AND s.SigHash = {SIG}
    WHERE f.CollectionId = CONVERT(int, @CollectionId) AND f.RaFindingKey IS NOT NULL AND sp.P > 1
      AND s.Kind = N'software-upgrade' AND s.Product <> N'' AND s.Version <> N'')
SELECT u.OwnerKey, u.Product, u.Vendor, u.Version,
       CASE WHEN u.OwnerKey LIKE N'asset:%' THEN LOWER(SUBSTRING(u.OwnerKey, 7, 450))
            ELSE (SELECT STRING_AGG(CONVERT(nvarchar(max), LOWER(l.NativeId)), N';') FROM sidata.CiLink AS l WHERE l.CiId = u.OwnerKey AND l.Provider = N'mde') END AS DeviceIds
FROM u
ORDER BY u.OwnerKey;
"@
}

function Get-SIRemediationTaskStageSql {
    <# The build's working rows: -Part sig (@rows: [{h,u,k,n,d,p,v,r}]) | split (@rows: [{o,p,v,r,keep,k,n,a,x,t}]) | clear (THIS
       build's rows, @BuildId) | orphans (the rows of builds that ended without clearing theirs -- run ONLY while this build
       holds the build lock, and only rows written at least a day ago: no build runs that long, so never a running build's). #>
    param([Parameter(Mandatory)][ValidateSet('sig', 'split', 'clear', 'orphans')][string]$Part)
    switch ($Part) {
        'sig' { @'
INSERT sidata.RemediationTaskSig (BuildId, SigHash, UnitNo, TaskKey, TaskName, Kind, Product, Vendor, Version)
SELECT CONVERT(uniqueidentifier, @BuildId), CONVERT(binary(32), j.h, 2), j.u, j.k, j.n, j.d, ISNULL(j.p, N''), ISNULL(j.v, N''), ISNULL(j.r, N'')
FROM OPENJSON(@rows) WITH (h varchar(64) '$.h', u int '$.u', k nvarchar(max) '$.k', n nvarchar(max) '$.n', d nvarchar(32) '$.d',
                           p nvarchar(400) '$.p', v nvarchar(400) '$.v', r nvarchar(400) '$.r') AS j;
'@ }
        'split' { @'
INSERT sidata.RemediationTaskSplit (BuildId, ComboHash, OwnerKey, KeepPlain, TaskKey, TaskName, Application, Paths, EvidenceAt)
SELECT CONVERT(uniqueidentifier, @BuildId), HASHBYTES('SHA2_256', CONCAT(j.o, NCHAR(31), ISNULL(j.v, N''), NCHAR(31), j.p, NCHAR(31), j.r)), j.o, j.keep,
       j.k, j.n, j.a, j.x, TRY_CONVERT(datetime2(3), j.t, 127)
FROM OPENJSON(@rows) WITH (o nvarchar(450) '$.o', p nvarchar(400) '$.p', v nvarchar(400) '$.v', r nvarchar(400) '$.r', keep bit '$.keep',
                           k nvarchar(max) '$.k', n nvarchar(max) '$.n', a nvarchar(max) '$.a', x nvarchar(max) '$.x', t nvarchar(40) '$.t') AS j;
'@ }
        'clear' { 'DELETE FROM sidata.RemediationTaskSplit WHERE BuildId = CONVERT(uniqueidentifier, @BuildId); DELETE FROM sidata.RemediationTaskSig WHERE BuildId = CONVERT(uniqueidentifier, @BuildId);' }
        'orphans' { 'DELETE FROM sidata.RemediationTaskSplit WHERE BuildId <> CONVERT(uniqueidentifier, @BuildId) AND CreatedAt < DATEADD(hour, -24, SYSUTCDATETIME()); DELETE FROM sidata.RemediationTaskSig WHERE BuildId <> CONVERT(uniqueidentifier, @BuildId) AND CreatedAt < DATEADD(hour, -24, SYSUTCDATETIME());' }
    }
}

function Get-SIRemediationTaskBuildSql {
    <#
        THE BUILD of one collection (@CollectionId) over its base (@BaseId, '' = none -- a first build), the signatures and the
        bundled splits of build @BuildId: the tasks and their links worked out, the lifecycle applied, both tables of the
        collection replaced a range of CIs at a time (each range one short transaction; @FirstTake its first size, measured
        from there) and Collection.RemediationTasksAt stamped after the last range. @HoldOwners (JSON list): the owners whose
        evidence could not be read -- held as they are. Answers one row: Tasks, Open, Closed, NewlyClosed, Kept, Reopened,
        Links, Findings, NoTask, WriteRanges, Held. -Fields: the signature's fields (Get-SIRemediationTaskSigExpr).
    #>
    param([Parameter(Mandatory)][string[]]$Fields)
    $sig = Get-SIRemediationTaskSigExpr -Fields $Fields
    $combo = { param($o, $v, $p, $r) "HASHBYTES('SHA2_256', CONCAT($o, NCHAR(31), ISNULL($v, N''), NCHAR(31), $p, NCHAR(31), $r))" }
    $hashCols = "CONCAT(o.TaskName, NCHAR(31), o.Kind, NCHAR(31), ISNULL(o.Product, N''), NCHAR(31), ISNULL(o.Vendor, N''), NCHAR(31), ISNULL(o.Version, N''), NCHAR(31), ISNULL(o.Application, N''), NCHAR(31), ISNULL(o.ApplicationPaths, N''), NCHAR(31), o.Findings, NCHAR(31), o.Cves, NCHAR(31), ISNULL(o.HighestSeverity, N''), NCHAR(31), ISNULL(CONVERT(nvarchar(40), o.MaxRiskScore, 2), N''), NCHAR(31), ISNULL(CONVERT(nvarchar(4), o.Tier), N''), NCHAR(31), ISNULL(o.CiOwner, N''), NCHAR(31), ISNULL(o.CiDepartment, N''), NCHAR(31), ISNULL(o.CmdbId, N''), NCHAR(31), o.State, NCHAR(31), ISNULL(o.ClosedWhy, N''), NCHAR(31), ISNULL(CONVERT(nvarchar(30), o.ClosedAt, 126), N''), NCHAR(31), CONVERT(nvarchar(30), o.FirstSeen, 126), NCHAR(31), o.ReopenCount)"
    $text = @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c INT = CONVERT(int, @CollectionId), @b INT = TRY_CONVERT(int, NULLIF(@BaseId, N'')), @bid UNIQUEIDENTIFIER = CONVERT(uniqueidentifier, @BuildId),
        @keep INT = CONVERT(int, @KeepClosedDays);
DECLARE @ct DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @c);
-- THE BUILD LOCK IS PROVEN before anything is written (and again before every range below): it is held by this build's own
-- session; a lock that could be granted now means that session is gone -- the build stops, nothing more is written
IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost -- nothing is written this run', 1;
DECLARE @now DATETIME2(3) = SYSUTCDATETIME();
-- where the build's time goes (ms since the start, per phase -- returned as BuildPhases)
DECLARE @ph NVARCHAR(400) = N'', @pt DATETIME2(3) = SYSUTCDATETIME();
-- the reports of this collection that are COMPLETE (a run whose incompleteness is not one named report: none)
DECLARE @runOk BIT = ISNULL((SELECT CASE WHEN NULLIF(x.RaPartialReason, N'') IS NULL OR x.RaPartialScope = N'reports' THEN 1 ELSE 0 END FROM sidata.Collection AS x WHERE x.CollectionId = @c), 0);
CREATE TABLE #rep (ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
IF @runOk = 1 AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL
    INSERT #rep (ReportName) SELECT DISTINCT s.ReportName FROM sidata.RaReportStatus AS s WHERE s.CollectionTime = @ct AND s.Grain = N'Detailed' AND s.State = N'Complete';
-- ONE CODE PATH FOR EVERY SIZE: THE TASKS ARE WORKED OUT AND WRITTEN A RANGE OF CIs AT A TIME. Every rule below decides per CI
-- (its findings, its base tasks, its evidence), so a range of CIs gives exactly the rows the whole collection would -- and what
-- the server holds at once (tempdb, sorts, memory) is one range, never the collection. The collection's findings are listed
-- once by CI (narrow: CI + finding id); each range reads its own findings by id.
CREATE TABLE #fo (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingId BIGINT NOT NULL);
INSERT #fo (OwnerKey, FindingId)
SELECT LEFT(o.OwnerKey, 450), f.FindingId
FROM sidata.Finding AS f
{APPLY}
WHERE f.CollectionId = @c AND f.RaFindingKey IS NOT NULL AND sp.P > 1;
CREATE CLUSTERED INDEX CX_fo ON #fo (OwnerKey);
-- the owners whose software evidence could not be read this run (a page of the evidence read failed): UNKNOWN -- held
CREATE TABLE #hold (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
INSERT #hold (OwnerKey) SELECT DISTINCT LEFT(j.[value], 450) FROM OPENJSON(ISNULL(NULLIF(@HoldOwners, N''), N'[]')) AS j WHERE j.[value] IS NOT NULL;
-- the CIs, in key order: this collection's findings, the base's tasks, and what this collection already has (written before)
CREATE TABLE #w (Rn INT IDENTITY(1, 1) NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL UNIQUE);
INSERT #w (OwnerKey) SELECT x.OwnerKey FROM (SELECT OwnerKey FROM #fo UNION SELECT OwnerKey FROM sidata.RemediationTask WHERE CollectionId = @b
                                             UNION SELECT OwnerKey FROM sidata.RemediationTask WHERE CollectionId = @c
                                             UNION SELECT OwnerKey FROM sidata.RemediationTaskFinding WHERE CollectionId = @c) AS x ORDER BY x.OwnerKey;
CREATE TABLE #wk (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
-- the working tables of ONE range (emptied for each)
-- the findings of the range: owner, key, signature; Own = this run's own row in a complete report
CREATE TABLE #f (FindingId BIGINT NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL,
                 SigHash BINARY(32) NOT NULL, AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL, CmdbName NVARCHAR(400) NULL, Cve NVARCHAR(256) NULL,
                 Title NVARCHAR(1000) NULL, SevRank TINYINT NOT NULL, RiskScore FLOAT NULL, Weighted FLOAT NULL, Tier TINYINT NULL, SecurityDomain NVARCHAR(128) NULL,
                 DepartmentId INT NULL, Own BIT NOT NULL, Exempt BIT NOT NULL);
CREATE INDEX IX_f ON #f (OwnerKey, FindingKey) INCLUDE (Own, Exempt);
-- the owners of the range: the CI's lifecycle -- active | retired | hold (not seen, frozen, gone, or its evidence not read this run)
CREATE TABLE #o (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Lc NVARCHAR(16) NOT NULL, CiId NVARCHAR(64) NULL,
                 CiOwner NVARCHAR(400) NULL, CiDept NVARCHAR(400) NULL, CmdbId NVARCHAR(256) NULL);
-- the base's tasks of the range (by task, and by CI: the units below ask, per finding, whether the base has that copy as
-- an open bundled task -- a seek per CI, never a scan of every base task per finding)
SELECT TOP (0) p.* INTO #p FROM sidata.RemediationTask AS p;
CREATE UNIQUE CLUSTERED INDEX CX_p ON #p (TaskId);
CREATE INDEX IX_p_owner ON #p (OwnerKey, Kind, State) INCLUDE (Product, Version);
-- the units of every finding of an ACTIVE CI: its signature's tasks; a software unit whose evidence was read: its bundled tasks,
-- and its own task only when a copy is not bundled. A name equal to the asset's own name is never a task. A software unit whose
-- evidence has no disk path this run (none read, or a registry row only) while the base has its copy as a BUNDLED task gets no
-- plain task: where that copy is is not known this run (the bundled task is kept as it was) -- never a guessed second task.
CREATE TABLE #l (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, TaskKey NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NOT NULL, TaskName NVARCHAR(MAX) NOT NULL,
                 Kind NVARCHAR(32) NOT NULL, Product NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Vendor NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL,
                 Version NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Application NVARCHAR(MAX) NULL, Paths NVARCHAR(MAX) NULL, EvidenceAt DATETIME2(3) NULL,
                 FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, FindingId BIGINT NOT NULL);
CREATE INDEX IX_l ON #l (OwnerKey, FindingKey) INCLUDE (Product, Version);
-- the tasks worked out from this collection
CREATE TABLE #t (TaskId BINARY(32) NOT NULL PRIMARY KEY, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, TaskKey NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NOT NULL,
                 TaskName NVARCHAR(MAX) NOT NULL, Kind NVARCHAR(32) NOT NULL, Product NVARCHAR(400) NULL, Vendor NVARCHAR(400) NULL, Version NVARCHAR(400) NULL,
                 Application NVARCHAR(MAX) NULL, Paths NVARCHAR(MAX) NULL, EvidenceAt DATETIME2(3) NULL, Findings INT NOT NULL, Cves INT NOT NULL, SevRank TINYINT NULL,
                 MaxRisk FLOAT NULL, MaxWeighted FLOAT NULL, Tier TINYINT NULL, Doms INT NOT NULL, Dom NVARCHAR(128) NULL, Depts INT NOT NULL, Dept INT NULL,
                 AssetKey NVARCHAR(400) NULL, AssetName NVARCHAR(400) NULL);
-- the links of those tasks (one per task and finding key)
CREATE TABLE #k (TaskId BINARY(32) NOT NULL, FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL,
                 FindingId BIGINT NOT NULL, Cve NVARCHAR(256) NULL, Title NVARCHAR(1000) NULL, SevRank TINYINT NULL, RiskScore FLOAT NULL, Version NVARCHAR(400) NULL,
                 PRIMARY KEY (TaskId, FindingKey));
-- THE BASE'S OPEN TASKS NOT WORKED OUT NOW (on an active CI): what each of their findings is now. "fixed" ONLY ON POSITIVE
-- EVIDENCE that the finding is gone -- never because a task with the same key did not come out this run:
--   fixed    the finding is gone and the finding lifecycle closed it as remediated (complete runs); or -- a BUNDLED task --
--            the finding is still there, the software evidence of that copy on this CI was READ this run WITH its paths on
--            disk, and none of the task's paths holds that library version any more (the application no longer bundles it)
--   retired / report   closed as asset retired / report changed by the lifecycle
--   changed  the finding is still there (in a complete report) but no task with this key comes out now: its version moved or
--            went blank, the grouping rule now names another task or none, the name is now the asset's own; a bundled copy
--            whose paths still hold the library under another application's name
--   unknown  anything else -- kept as it was: absent but not closed, seen only in an incomplete report or carried; a bundled
--            copy whose evidence was not read, or was read without a path on disk (a registry row only); a task written with a
CREATE TABLE #ls (TaskId BINARY(32) NOT NULL, St NVARCHAR(16) NOT NULL);
CREATE TABLE #d (TaskId BINARY(32) NOT NULL PRIMARY KEY, Unknown INT NOT NULL, Fixed INT NOT NULL, Retired INT NOT NULL, Report INT NOT NULL, Exempted INT NOT NULL, N INT NOT NULL);
-- THE COLLECTION'S TASKS: the ones worked out now (open; reopened when the base had them closed) + the base's tasks not worked
-- out now (closed by the rules above, or carried as they were) + the base's closed tasks within the retention
SELECT TOP (0) CAST(NULL AS NVARCHAR(16)) AS Src, p.* INTO #out FROM #p AS p;
CREATE UNIQUE CLUSTERED INDEX CX_out ON #out (TaskId);
-- the run's totals, added up range by range (the CIs of two ranges never overlap)
DECLARE @nTasks INT = 0, @nOpen INT = 0, @nClosed INT = 0, @nNewlyClosed INT = 0, @nKept INT = 0, @nReopened INT = 0, @nFindings INT = 0, @noTask INT = 0,
        @nOwn INT = 0, @states NVARCHAR(MAX) = NULL;
DECLARE @msF BIGINT = 0, @msU BIGINT = 0, @msT BIGINT = 0, @msB BIGINT = 0, @msO BIGINT = 0, @msW BIGINT = 0, @tp DATETIME2(3);
-- THE WRITE, A RANGE OF OWNERS AT A TIME: each range (the CIs in key order) is its own short transaction -- its old task and link
-- rows deleted and its new ones inserted together -- so the locks stay at row / page level and the log is bounded, and every CI
-- shows either its old set or its new one, never half. The range is sized by measuring (about two seconds of work), never a
-- fixed limit. The collection is marked built (RemediationTasksAt -- what the outputs and the hand-off read) only after the
-- last range; a write that stops part-way leaves it unmarked and the next run writes it again, range by range.
DECLARE @wn INT = (SELECT COUNT(*) FROM #w), @lo INT = 1, @take INT = ISNULL(TRY_CONVERT(int, NULLIF(@FirstTake, N'')), 0), @t0 DATETIME2(3), @ms INT, @ranges INT = 0, @maxTake INT = 0;
IF @take < 1 SET @take = 256;
SET @ph = @ph + N'list=' + CONVERT(nvarchar(12), DATEDIFF(millisecond, @pt, SYSUTCDATETIME())) + N';';
WHILE @lo <= @wn
BEGIN
    IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost part-way -- the collection is not marked built; the next run writes it again', 1;
    SET @t0 = SYSUTCDATETIME(); SET @tp = @t0;
    TRUNCATE TABLE #wk; TRUNCATE TABLE #f; TRUNCATE TABLE #o; TRUNCATE TABLE #p; TRUNCATE TABLE #l; TRUNCATE TABLE #t; TRUNCATE TABLE #k;
    TRUNCATE TABLE #ls; TRUNCATE TABLE #d; TRUNCATE TABLE #out;
    INSERT #wk (OwnerKey) SELECT OwnerKey FROM #w WHERE Rn >= @lo AND Rn < @lo + @take;
    INSERT #f
SELECT f.FindingId, LEFT(o.OwnerKey, 450), k.FKey, {SIG}, f.AssetKey, f.AssetName, COALESCE(NULLIF(f.ContextCmdbName, N''), f.CmdbName),
       CASE WHEN k.Typ = N'cve' THEN UPPER(k.FKey) END, f.Title,
       CASE LOWER(LTRIM(RTRIM(f.Severity))) WHEN N'very high' THEN 4 WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium-high' THEN 2
            WHEN N'medium' THEN 2 WHEN N'moderate' THEN 2 WHEN N'low' THEN 1 ELSE 0 END,
       f.RiskScore, ISNULL(f.RiskScoreWeighted, f.RiskScore), f.Tier, f.SecurityDomain, f.DepartmentId,
       CASE WHEN f.CarriedFrom IS NULL AND EXISTS (SELECT 1 FROM #rep AS r WHERE r.ReportName = f.ReportName) THEN 1 ELSE 0 END,
       CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END
FROM #fo AS x
    JOIN #wk AS wf ON wf.OwnerKey = x.OwnerKey
    JOIN sidata.Finding AS f ON f.CollectionId = @c AND f.FindingId = x.FindingId
{APPLY}
WHERE f.RaFindingKey IS NOT NULL AND sp.P > 1;
    INSERT #o
SELECT x.OwnerKey,
       CASE WHEN EXISTS (SELECT 1 FROM #hold AS h WHERE h.OwnerKey = x.OwnerKey) THEN N'hold'
            WHEN x.OwnerKey LIKE N'asset:%' THEN N'active' WHEN c.CiId IS NULL THEN N'hold' WHEN LOWER(LTRIM(RTRIM(c.Lifecycle))) = N'retired' THEN N'retired'
            WHEN c.Lifecycle IS NULL OR LOWER(LTRIM(RTRIM(c.Lifecycle))) = N'active' THEN N'active' ELSE N'hold' END,
       c.CiId, c.Owner, c.Department, c.CmdbId
FROM (SELECT OwnerKey FROM #f UNION SELECT r.OwnerKey FROM sidata.RemediationTask AS r JOIN #wk AS wb ON wb.OwnerKey = r.OwnerKey WHERE r.CollectionId = @b) AS x
LEFT JOIN sidata.Ci AS c ON x.OwnerKey NOT LIKE N'asset:%' AND c.CiId = LEFT(x.OwnerKey, 64);
    INSERT #p SELECT r.* FROM sidata.RemediationTask AS r JOIN #wk AS wp ON wp.OwnerKey = r.OwnerKey WHERE r.CollectionId = @b;
    SET @msF = @msF + DATEDIFF(millisecond, @tp, SYSUTCDATETIME()); SET @tp = SYSUTCDATETIME();
INSERT #l
SELECT f.OwnerKey, s.TaskKey, s.TaskName, s.Kind, s.Product, s.Vendor, s.Version, NULL, NULL, NULL, f.FindingKey, f.FindingId
FROM #f AS f
JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskSig AS s ON s.BuildId = @bid AND s.SigHash = f.SigHash
OUTER APPLY (SELECT TOP (1) x.KeepPlain FROM sidata.RemediationTaskSplit AS x
             WHERE s.Kind = N'software-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_F}
             ORDER BY x.KeepPlain DESC) AS kp
OUTER APPLY (SELECT MAX(CASE WHEN x.TaskKey IS NULL AND ISNULL(x.Paths, N'') <> N'' THEN 1 ELSE 0 END) AS HasDisk FROM sidata.RemediationTaskSplit AS x
             WHERE s.Kind = N'software-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_F}) AS dk
WHERE f.Exempt = 0 AND (kp.KeepPlain IS NULL OR kp.KeepPlain = 1)
  AND NOT (s.Kind = N'software-upgrade' AND ISNULL(dk.HasDisk, 0) = 0
           AND EXISTS (SELECT 1 FROM #p AS hb WHERE hb.OwnerKey = f.OwnerKey AND hb.Kind = N'bundled-upgrade' AND hb.State = N'open'
                                                AND ISNULL(hb.Product, N'') = s.Product AND ISNULL(hb.Version, N'') = s.Version))
  AND LOWER(LTRIM(RTRIM(s.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.AssetName, N''))))
  AND LOWER(LTRIM(RTRIM(s.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.CmdbName, N''))));
INSERT #l
SELECT f.OwnerKey, x.TaskKey, x.TaskName, N'bundled-upgrade', s.Product, s.Vendor, s.Version, x.Application, x.Paths, x.EvidenceAt, f.FindingKey, f.FindingId
FROM #f AS f
JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskSig AS s ON s.BuildId = @bid AND s.SigHash = f.SigHash AND s.Kind = N'software-upgrade'
JOIN sidata.RemediationTaskSplit AS x ON x.BuildId = @bid AND x.ComboHash = {COMBO_F} AND x.TaskKey IS NOT NULL
WHERE f.Exempt = 0 AND LOWER(LTRIM(RTRIM(x.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.AssetName, N''))))
  AND LOWER(LTRIM(RTRIM(x.TaskName))) <> LOWER(LTRIM(RTRIM(ISNULL(f.CmdbName, N''))));
    SET @msU = @msU + DATEDIFF(millisecond, @tp, SYSUTCDATETIME()); SET @tp = SYSUTCDATETIME();
INSERT #t
SELECT HASHBYTES('SHA2_256', CONCAT(g.OwnerKey, N'|', g.TaskKey)), g.OwnerKey, g.TaskKey, g.TaskName, g.Kind, NULLIF(g.Product, N''), NULLIF(g.Vendor, N''),
       NULLIF(g.Version, N''), g.Application, g.Paths, g.EvidenceAt, g.Findings, g.Cves, g.SevRank, g.MaxRisk, g.MaxWeighted, g.Tier,
       g.Doms, CASE WHEN g.Doms = 1 THEN g.Dom END, g.Depts, CASE WHEN g.Depts = 1 THEN g.Dept END, g.AssetKey, g.AssetName
FROM (SELECT l.OwnerKey, l.TaskKey, MAX(l.TaskName) AS TaskName, MAX(l.Kind) AS Kind, MAX(l.Product) AS Product, MAX(l.Vendor) AS Vendor,
             CASE WHEN MIN(l.Version) = MAX(l.Version) THEN MAX(l.Version) ELSE N'' END AS Version, MAX(l.Application) AS Application,
             MAX(l.Paths) AS Paths, MAX(l.EvidenceAt) AS EvidenceAt, COUNT(DISTINCT l.FindingKey) AS Findings, COUNT(DISTINCT f.Cve) AS Cves,
             MAX(f.SevRank) AS SevRank, MAX(f.RiskScore) AS MaxRisk, MAX(f.Weighted) AS MaxWeighted, MIN(f.Tier) AS Tier,
             COUNT(DISTINCT ISNULL(f.SecurityDomain, N'')) AS Doms, MAX(f.SecurityDomain) AS Dom,
             COUNT(DISTINCT ISNULL(f.DepartmentId, -1)) AS Depts, MAX(f.DepartmentId) AS Dept, MAX(f.AssetKey) AS AssetKey, MAX(f.AssetName) AS AssetName
      FROM #l AS l JOIN #f AS f ON f.FindingId = l.FindingId
      GROUP BY l.OwnerKey, l.TaskKey) AS g;
INSERT #k
SELECT t.TaskId, l.FindingKey, MAX(l.OwnerKey), MIN(l.FindingId), MAX(f.Cve), MAX(f.Title), MAX(f.SevRank), MAX(f.RiskScore), NULLIF(MAX(l.Version), N'')
FROM #l AS l JOIN #t AS t ON t.OwnerKey = l.OwnerKey AND t.TaskKey = l.TaskKey JOIN #f AS f ON f.FindingId = l.FindingId
GROUP BY t.TaskId, l.FindingKey;
    SET @msT = @msT + DATEDIFF(millisecond, @tp, SYSUTCDATETIME()); SET @tp = SYSUTCDATETIME();
INSERT #ls
SELECT p.TaskId,
       CASE WHEN fx.AnyRow = 1 AND fx.Live = 0 THEN N'exempted'
            WHEN fx.OwnLive = 1 THEN
                 CASE WHEN p.Kind <> N'bundled-upgrade' THEN N'changed'
                      WHEN ISNULL(p.Version, N'') = N'' OR ISNULL(p.ApplicationPaths, N'') = N'' THEN N'unknown'
                      WHEN ev.HasDisk = 1 AND pa.Held = 0 THEN N'fixed'
                      WHEN ev.HasDisk = 1 THEN N'changed'
                      WHEN ev.Found = 1 THEN N'unknown'
                      -- not read this run, and the finding still names that version: not known
                      WHEN EXISTS (SELECT 1 FROM #f AS f2 JOIN sidata.RemediationTaskSig AS s2 ON s2.BuildId = @bid AND s2.SigHash = f2.SigHash
                                   WHERE f2.OwnerKey = p.OwnerKey AND f2.FindingKey = pl.FindingKey AND s2.Kind = N'software-upgrade'
                                     AND s2.Product = ISNULL(p.Product, N'') AND s2.Version = p.Version) THEN N'unknown'
                      ELSE N'changed' END
            WHEN fx.AnyRow = 1 THEN N'unknown'
            WHEN st.State = N'closed' AND st.CloseReason = N'remediated' THEN N'fixed'
            WHEN st.State = N'closed' AND st.CloseReason = N'asset_retired' THEN N'retired'
            WHEN st.State = N'closed' AND st.CloseReason = N'report changed' THEN N'report'
            WHEN st.State = N'closed' AND st.CloseReason = N'rekeyed' THEN N'changed'
            ELSE N'unknown' END
FROM #p AS p
JOIN #o AS o ON o.OwnerKey = p.OwnerKey AND o.Lc = N'active'
JOIN sidata.RemediationTaskFinding AS pl ON pl.CollectionId = @b AND pl.TaskId = p.TaskId
LEFT JOIN sidata.CiFindingState AS st ON st.OwnerKey = p.OwnerKey AND st.FindingKey = pl.FindingKey
OUTER APPLY (SELECT MAX(1) AS AnyRow, MAX(CASE WHEN f.Exempt = 0 THEN 1 ELSE 0 END) AS Live, MAX(CASE WHEN f.Own = 1 AND f.Exempt = 0 THEN 1 ELSE 0 END) AS OwnLive
             FROM #f AS f WHERE f.OwnerKey = p.OwnerKey AND f.FindingKey = pl.FindingKey) AS fx
-- the copy's evidence this run (bundled): read at all (Found), read with its paths on disk (HasDisk)
OUTER APPLY (SELECT MAX(1) AS Found, MAX(CASE WHEN ISNULL(x.Paths, N'') <> N'' THEN 1 ELSE 0 END) AS HasDisk FROM sidata.RemediationTaskSplit AS x
             WHERE p.Kind = N'bundled-upgrade' AND x.BuildId = @bid AND x.ComboHash = {COMBO_P} AND x.TaskKey IS NULL) AS ev
-- the task's own paths against them: one still holds it (Held) -- both sides the full paths as the evidence gives them
OUTER APPLY (SELECT MAX(z.Held) AS Held
             FROM (SELECT CASE WHEN EXISTS (SELECT 1 FROM sidata.RemediationTaskSplit AS x WHERE x.BuildId = @bid AND x.ComboHash = {COMBO_P} AND x.TaskKey IS NULL
                                                  AND CHARINDEX(N';' + LTRIM(RTRIM(s.[value])) + N';', N';' + ISNULL(x.Paths, N'') + N';') > 0) THEN 1 ELSE 0 END AS Held
                   FROM STRING_SPLIT(CASE WHEN p.Kind = N'bundled-upgrade' THEN ISNULL(p.ApplicationPaths, N'') ELSE N'' END, N';') AS s
                   WHERE LTRIM(RTRIM(s.[value])) <> N'') AS z) AS pa
WHERE p.State = N'open' AND NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.TaskId = p.TaskId);
INSERT #d SELECT TaskId, SUM(CASE WHEN St = N'unknown' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'fixed' THEN 1 ELSE 0 END),
                 SUM(CASE WHEN St = N'retired' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'report' THEN 1 ELSE 0 END), SUM(CASE WHEN St = N'exempted' THEN 1 ELSE 0 END), COUNT(*)
FROM #ls GROUP BY TaskId;
    SET @msB = @msB + DATEDIFF(millisecond, @tp, SYSUTCDATETIME()); SET @tp = SYSUTCDATETIME();
INSERT #out (Src, CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths, EvidenceAt,
             Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner, CiDepartment, CmdbId,
             FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
SELECT CASE WHEN p.TaskId IS NULL THEN N'new' WHEN p.State = N'closed' THEN N'reopened' ELSE N'seen' END,
       @c, t.TaskId, t.OwnerKey, o.CiId, t.AssetKey, t.AssetName, t.TaskKey, t.TaskName, t.Kind, t.Product, t.Vendor, t.Version, t.Application, t.Paths, t.EvidenceAt,
       t.Findings, t.Cves, CASE t.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END,
       t.MaxRisk, t.MaxWeighted, t.Tier, t.Dom, ad.DepartmentId, CASE WHEN ad.DepartmentId IS NULL THEN 0 ELSE 1 END, o.CiOwner, o.CiDept, o.CmdbId,
       ISNULL(p.FirstSeen, @ct), @ct, N'open', NULL, NULL, ISNULL(p.ReopenCount, 0) + CASE WHEN p.State = N'closed' THEN 1 ELSE 0 END, 1, 0x00, @now, p.SentInScope
FROM #t AS t
JOIN #o AS o ON o.OwnerKey = t.OwnerKey
LEFT JOIN #p AS p ON p.TaskId = t.TaskId
-- a task belongs to ONE CI: the CI's own department (sidata.Asset.DepartmentId -- the department its views scope by)
LEFT JOIN sidata.Asset AS ad ON ad.AssetKey = t.AssetKey;
INSERT #out (Src, CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths, EvidenceAt,
             Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner, CiDepartment, CmdbId,
             FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
SELECT z.Src, @c, p.TaskId, p.OwnerKey, p.CiId, p.AssetKey, p.AssetName, p.TaskKey, p.TaskName, p.Kind, p.Product, p.Vendor, p.Version, p.Application, p.ApplicationPaths, p.EvidenceAt,
       p.Findings, p.Cves, p.HighestSeverity, p.MaxRiskScore, p.MaxWeightedRisk, p.Tier, p.SecurityDomain, p.DepartmentId, p.Departments, p.CiOwner, p.CiDepartment, p.CmdbId,
       p.FirstSeen, p.LastSeen, CASE WHEN z.Why IS NULL THEN p.State ELSE N'closed' END, CASE WHEN z.Why IS NULL THEN p.ClosedAt ELSE @ct END,
       ISNULL(z.Why, p.ClosedWhy), p.ReopenCount, 0, p.RowHash, p.ChangedAt, p.SentInScope
FROM #p AS p
LEFT JOIN #o AS o ON o.OwnerKey = p.OwnerKey
LEFT JOIN #d AS d ON d.TaskId = p.TaskId
CROSS APPLY (SELECT CASE WHEN p.State = N'closed' THEN N'carried-closed'
                         WHEN o.Lc = N'retired' THEN N'closed'
                         WHEN o.Lc = N'active' AND d.TaskId IS NOT NULL AND d.Unknown = 0 AND d.N > 0 THEN N'closed'
                         ELSE N'kept' END AS Src,
                    CASE WHEN p.State = N'closed' THEN NULL
                         WHEN o.Lc = N'retired' THEN N'asset retired'
                         WHEN o.Lc = N'active' AND d.TaskId IS NOT NULL AND d.Unknown = 0 AND d.N > 0 THEN
                              CASE WHEN d.Fixed = d.N THEN N'fixed' WHEN d.Fixed + d.Exempted = d.N THEN N'exempted' WHEN d.Retired > 0 THEN N'asset retired' WHEN d.Report > 0 THEN N'report changed' ELSE N'task changed' END
                         END AS Why) AS z
WHERE NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.TaskId = p.TaskId)
  AND (p.State = N'open' OR p.ClosedAt >= DATEADD(day, -@keep, @ct));
UPDATE o SET RowHash = HASHBYTES('SHA2_256', {HASHCOLS}) FROM #out AS o;
UPDATE o SET ChangedAt = CASE WHEN p.TaskId IS NOT NULL AND p.RowHash = o.RowHash THEN p.ChangedAt ELSE @now END
FROM #out AS o LEFT JOIN #p AS p ON p.TaskId = o.TaskId;
    SET @noTask = @noTask + (SELECT COUNT(*) FROM (SELECT DISTINCT f.OwnerKey, f.FindingKey FROM #f AS f JOIN #o AS o ON o.OwnerKey = f.OwnerKey AND o.Lc = N'active'
                                                   WHERE f.Exempt = 0 AND NOT EXISTS (SELECT 1 FROM #l AS l WHERE l.OwnerKey = f.OwnerKey AND l.FindingKey = f.FindingKey)) AS q);
    SELECT @nTasks = @nTasks + COUNT(*), @nOpen = @nOpen + SUM(CASE WHEN State = N'open' THEN 1 ELSE 0 END), @nClosed = @nClosed + SUM(CASE WHEN State = N'closed' THEN 1 ELSE 0 END),
           @nNewlyClosed = @nNewlyClosed + SUM(CASE WHEN Src = N'closed' THEN 1 ELSE 0 END), @nKept = @nKept + SUM(CASE WHEN Src = N'kept' THEN 1 ELSE 0 END),
           @nReopened = @nReopened + SUM(CASE WHEN Src = N'reopened' THEN 1 ELSE 0 END)
    FROM #out HAVING COUNT(*) > 0;
    SET @nFindings = @nFindings + (SELECT COUNT(*) FROM (SELECT DISTINCT OwnerKey, FindingKey FROM #f) AS q);
    SET @nOwn = @nOwn + (SELECT COUNT(*) FROM #f WHERE Own = 1);
    IF EXISTS (SELECT 1 FROM #ls) SET @states = CONCAT(@states + N',', (SELECT STRING_AGG(CONVERT(nvarchar(max), St), N',') FROM #ls));
    SET @msO = @msO + DATEDIFF(millisecond, @tp, SYSUTCDATETIME()); SET @tp = SYSUTCDATETIME();
    BEGIN TRAN;
    DELETE l FROM sidata.RemediationTaskFinding AS l JOIN #wk AS w ON w.OwnerKey = l.OwnerKey WHERE l.CollectionId = @c;
    DELETE t FROM sidata.RemediationTask AS t JOIN #wk AS w ON w.OwnerKey = t.OwnerKey WHERE t.CollectionId = @c;
    INSERT sidata.RemediationTask (CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Vendor, Version, Application, ApplicationPaths,
                                   EvidenceAt, Findings, Cves, HighestSeverity, MaxRiskScore, MaxWeightedRisk, Tier, SecurityDomain, DepartmentId, Departments, CiOwner,
                                   CiDepartment, CmdbId, FirstSeen, LastSeen, State, ClosedAt, ClosedWhy, ReopenCount, InThisCollection, RowHash, ChangedAt, SentInScope)
    SELECT o.CollectionId, o.TaskId, o.OwnerKey, o.CiId, o.AssetKey, o.AssetName, o.TaskKey, o.TaskName, o.Kind, o.Product, o.Vendor, o.Version, o.Application, o.ApplicationPaths,
           o.EvidenceAt, o.Findings, o.Cves, o.HighestSeverity, o.MaxRiskScore, o.MaxWeightedRisk, o.Tier, o.SecurityDomain, o.DepartmentId, o.Departments, o.CiOwner,
           o.CiDepartment, o.CmdbId, o.FirstSeen, o.LastSeen, o.State, o.ClosedAt, o.ClosedWhy, o.ReopenCount, o.InThisCollection, o.RowHash, o.ChangedAt, o.SentInScope
    FROM #out AS o JOIN #wk AS w ON w.OwnerKey = o.OwnerKey;
    INSERT sidata.RemediationTaskFinding (CollectionId, TaskId, FindingKey, OwnerKey, FindingId, Cve, Title, Severity, RiskScore, Version, InThisCollection, SentInScope)
    SELECT @c, k.TaskId, k.FindingKey, k.OwnerKey, k.FindingId, k.Cve, k.Title,
           CASE k.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END, k.RiskScore, k.Version, 1, bl.SentInScope
    FROM #k AS k JOIN #out AS o ON o.TaskId = k.TaskId JOIN #wk AS w ON w.OwnerKey = o.OwnerKey
    LEFT JOIN sidata.RemediationTaskFinding AS bl ON bl.CollectionId = @b AND bl.TaskId = k.TaskId AND bl.FindingKey = k.FindingKey;
    INSERT sidata.RemediationTaskFinding (CollectionId, TaskId, FindingKey, OwnerKey, FindingId, Cve, Title, Severity, RiskScore, Version, InThisCollection, SentInScope)
    SELECT @c, pl.TaskId, pl.FindingKey, pl.OwnerKey, NULL, pl.Cve, pl.Title, pl.Severity, pl.RiskScore, pl.Version, 0, pl.SentInScope
    FROM sidata.RemediationTaskFinding AS pl
    JOIN #out AS o ON o.TaskId = pl.TaskId AND o.InThisCollection = 0
    JOIN #wk AS w ON w.OwnerKey = o.OwnerKey
    WHERE pl.CollectionId = @b;
    COMMIT;
    SET @msW = @msW + DATEDIFF(millisecond, @tp, SYSUTCDATETIME());
    SET @ranges = @ranges + 1;
    IF @take > @maxTake SET @maxTake = @take;
    SET @lo = @lo + @take;
    -- the range is sized by its WRITE (the transaction: about two seconds, as before) -- the working out before it holds no lock,
    -- and a larger range spreads what every range costs anyway over more CIs
    SET @ms = DATEDIFF(millisecond, @tp, SYSUTCDATETIME());
    SET @take = CASE WHEN @ms < 1000 AND @take < @wn THEN @take * 2 WHEN @ms > 4000 AND @take > 1 THEN @take / 2 ELSE @take END;
END
IF APPLOCK_TEST(N'public', N'si-remediation-task-build', N'Exclusive', N'Session') = 1 THROW 51277, N'the build lock was lost before the collection was marked -- the next run writes it again', 1;
UPDATE sidata.Collection SET RemediationTasksAt = SYSUTCDATETIME() WHERE CollectionId = @c;
SET @ph = @ph + CONCAT(N'findings=', @msF, N';owners+units=', @msU, N';tasks+links=', @msT, N';base-states=', @msB, N';out+hash=', @msO, N';write=', @msW, N';ranges=', @ranges, N';largest-range=', @maxTake, N';');
SELECT @nTasks AS Tasks, @nOpen AS [Open], @nClosed AS Closed, @nNewlyClosed AS NewlyClosed, @nKept AS Kept, @nReopened AS Reopened,
       (SELECT COUNT(*) FROM sidata.RemediationTaskFinding WHERE CollectionId = @c) AS Links, @nFindings AS Findings, @noTask AS NoTask,
       @nOwn AS OwnRows, (SELECT COUNT(*) FROM #rep) AS CompleteReports, @states AS LinkStates, @ranges AS WriteRanges, (SELECT COUNT(*) FROM #hold) AS Held, @ph AS BuildPhases;
'@
    $text = $text.Replace('{SIG}', $sig).Replace('{APPLY}', (Get-SIRemediationTaskKeyApplySql)).Replace('{HASHCOLS}', $hashCols)
    $text = $text.Replace('{COMBO_F}', (& $combo 'f.OwnerKey' 's.Vendor' 's.Product' 's.Version'))
    $text.Replace('{COMBO_P}', (& $combo 'p.OwnerKey' 'p.Vendor' "ISNULL(p.Product, N'')" 'p.Version'))
}

function Get-SIRemediationTaskSchemaCheckSql {
    <# 1 when the database carries what the tasks are built from and written to; else 0. #>
    $need = @(
        "OBJECT_ID('sidata.RemediationTask')", "OBJECT_ID('sidata.RemediationTaskFinding')", "OBJECT_ID('sidata.RemediationTaskSig')", "OBJECT_ID('sidata.RemediationTaskSplit')",
        "OBJECT_ID('sidata.CiFindingState')", "OBJECT_ID('sidata.CiBuildState')", "OBJECT_ID('sidata.Ci')", "OBJECT_ID('sidata.CiLink')",
        "COL_LENGTH('sidata.Collection', 'RemediationTasksAt')", "COL_LENGTH('sidata.Collection', 'ContextAt')", "COL_LENGTH('sidata.Collection', 'RetiredAt')",
        "COL_LENGTH('sidata.Collection', 'RaPartialReason')", "COL_LENGTH('sidata.Collection', 'RaPartialScope')",
        "COL_LENGTH('sidata.Finding', 'RaFindingKey')", "COL_LENGTH('sidata.Finding', 'CarriedFrom')", "COL_LENGTH('sidata.Finding', 'Component')",
        "COL_LENGTH('sidata.Finding', 'Category')", "COL_LENGTH('sidata.Finding', 'Subcategory')", "COL_LENGTH('sidata.Finding', 'AffectedVersion')",
        "COL_LENGTH('sidata.Finding', 'AffectedProduct')", "COL_LENGTH('sidata.Finding', 'AffectedVendor')", "COL_LENGTH('sidata.Finding', 'FixRecommendedUpdate')",
        "COL_LENGTH('sidata.Finding', 'FixRecommendedUpdateId')", "COL_LENGTH('sidata.Finding', 'DepartmentId')", "COL_LENGTH('sidata.Finding', 'RiskScoreWeighted')",
        "COL_LENGTH('sidata.Finding', 'CmdbName')", "COL_LENGTH('sidata.Finding', 'ContextCmdbName')", "COL_LENGTH('sidata.Ci', 'Owner')", "COL_LENGTH('sidata.Ci', 'Department')", "COL_LENGTH('sidata.Asset', 'DepartmentId')", "COL_LENGTH('sidata.Finding', 'ExemptionId')",
        "COL_LENGTH('sidata.RemediationTask', 'SentInScope')", "COL_LENGTH('sidata.RemediationTaskFinding', 'SentInScope')",
        "COL_LENGTH('sidata.RemediationTaskSig', 'CreatedAt')", "COL_LENGTH('sidata.RemediationTaskSplit', 'CreatedAt')")
    'SELECT CASE WHEN ' + (($need | ForEach-Object { "$_ IS NOT NULL" }) -join ' AND ') + ' THEN 1 ELSE 0 END'
}

function Get-SIRemediationTaskPendingSql {
    <#
        The NEWEST complete Detailed collection (its context prepared -- the fix columns come from there) with: whether its tasks
        are built, its base (the newest collection built before it that still has its task rows), and the moment the finding
        lifecycle last processed (sidata.CiBuildState FindingStateSnapshot -- the tasks wait for it).
    #>
    @'
SELECT TOP (1) c.CollectionId, c.CollectionTime, c.RemediationTasksAt, c.ContextAt,
       (SELECT TOP (1) b.CollectionId FROM sidata.Collection AS b
        WHERE b.Kind = N'Detailed' AND b.RemediationTasksAt IS NOT NULL AND b.CollectionTime < c.CollectionTime
          AND EXISTS (SELECT 1 FROM sidata.RemediationTask AS t WHERE t.CollectionId = b.CollectionId)
        ORDER BY b.CollectionTime DESC) AS BaseId,
       (SELECT TOP (1) TRY_CONVERT(datetime2(3), s.Value, 127) FROM sidata.CiBuildState AS s WHERE s.Name = N'FindingStateSnapshot') AS StateAt
FROM sidata.Collection AS c
WHERE c.Kind = N'Detailed' AND c.Status = 'Complete' AND c.RetiredAt IS NULL AND c.ContextAt IS NOT NULL
ORDER BY c.CollectionTime DESC;
'@
}

function Get-SIRemediationTaskRetentionSql {
    <# One batch (@Take rows) of the task rows of collections OLDER than the base (@KeepFrom: the oldest collection kept);
       their mark is cleared once their rows are gone. Answers the rows removed. #>
    @'
SET NOCOUNT ON;
DECLARE @t DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = CONVERT(int, @KeepFrom));
DECLARE @n INT = 0;
IF @t IS NOT NULL
BEGIN
    DELETE TOP (CONVERT(int, @Take)) l FROM sidata.RemediationTaskFinding AS l
    WHERE l.CollectionId IN (SELECT c.CollectionId FROM sidata.Collection AS c WHERE c.CollectionTime < @t);
    SET @n = @@ROWCOUNT;
    IF @n = 0
    BEGIN
        DELETE TOP (CONVERT(int, @Take)) t FROM sidata.RemediationTask AS t
        WHERE t.CollectionId IN (SELECT c.CollectionId FROM sidata.Collection AS c WHERE c.CollectionTime < @t);
        SET @n = @@ROWCOUNT;
    END
    IF @n = 0
        UPDATE c SET RemediationTasksAt = NULL FROM sidata.Collection AS c
        WHERE c.CollectionTime < @t AND c.RemediationTasksAt IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM sidata.RemediationTask AS t WHERE t.CollectionId = c.CollectionId);
END
SELECT @n;
'@
}

function ConvertTo-SIRemediationTaskHex {
    <# PURE. A binary value (byte[]) as upper-case hex; '' for none. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return '' }
    $bytes = [byte[]]$Value
    [BitConverter]::ToString($bytes).Replace('-', '')
}

function Write-SIRemediationTaskStage {
    <# The working rows of one build, 1000 per statement. -Part sig | split. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$BuildId, [Parameter(Mandatory)][string]$Part,
          [AllowEmptyCollection()][System.Collections.Generic.List[object]]$Rows)
    if ($null -eq $Rows -or $Rows.Count -eq 0) { return 0 }
    $sql = Get-SIRemediationTaskStageSql -Part $Part
    for ($i = 0; $i -lt $Rows.Count; $i += 1000) {
        $chunk = $Rows.GetRange($i, [Math]::Min(1000, $Rows.Count - $i)).ToArray()   # (not $part: -Part is a [string] parameter of this function)
        $null = & $Invoke $sql @{ BuildId = $BuildId; rows = (ConvertTo-Json -InputObject @($chunk) -Compress -Depth 4) } 'nonquery'
    }
    $Rows.Count
}

function Invoke-SIRemediationTaskSignatures {
    <#
        The rule over every distinct signature of the collection: read (Get-SIRemediationTaskSigSql), worked out
        (ConvertTo-SIRemediationTaskUnits), written to the build's working rows. Returns @{ Signatures; Units; NoUnit }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string]$BuildId,
          [Parameter(Mandatory)][string[]]$Fields, [Parameter(Mandatory)]$Map, $Plan, $ValueMaps)
    if ($null -eq $Plan) { $Plan = Get-SIFindingFieldPlan -Map $Map }
    $rows = @(@(& $Invoke (Get-SIRemediationTaskSigSql -Fields $Fields) @{ CollectionId = [string]$CollectionId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $out = New-Object System.Collections.Generic.List[object]
    $res = [pscustomobject]@{ Signatures = $rows.Count; Units = 0; NoUnit = 0 }
    foreach ($r in $rows) {
        $hex = [string]$r['SigHex']
        if ($hex -notmatch '^[0-9A-Fa-f]{64}$') { throw ('a finding signature came back without its hash ({0})' -f $hex) }
        $vals = [ordered]@{}
        for ($i = 0; $i -lt $Fields.Count; $i++) { $v = $r[('c{0}' -f $i)]; if ($v -is [System.DBNull]) { $v = $null }; $vals[$Fields[$i]] = $v }
        $units = ConvertTo-SIRemediationTaskUnits -Values $vals -Map $Map -Plan $Plan -ValueMaps $ValueMaps
        if (@($units).Count -eq 0) { $res.NoUnit++; continue }
        $n = 0
        foreach ($u in @($units)) {
            $n++
            $out.Add([ordered]@{ h = $hex; u = $n; k = $u.TaskKey; n = $u.TaskName; d = $u.Kind; p = $u.Product; v = $u.Vendor; r = $u.Version })
        }
    }
    $res.Units = Write-SIRemediationTaskStage -Invoke $Invoke -BuildId $BuildId -Part 'sig' -Rows $out
    $res
}

function Invoke-SIRemediationTaskEvidence {
    <#
        THE BUNDLED SPLIT: every software unit on a CI (Get-SIRemediationTaskSoftwareSql) against the CI's software evidence
        (Get-SISoftwareEvidence, its Defender devices, a page of about -DevicesPerPage devices at a time) -> the build's split rows
        (Get-SIRemediationTaskBundledUnits): one row per bundled application, and one that says the evidence was read (its
        Paths: every path on disk of that software, in full -- empty when only a registry row was read).
        A PAGE WHOSE EVIDENCE READ FAILS does not fail the build: the CIs of that page are UNKNOWN this run (Held -- the build
        keeps every task of theirs exactly as it was; never a plain task guessed for a bundled copy, never one closed), the
        other pages build as usual. Returns @{ Units; Read; Bundled; Held (the owner keys held); Failed (pages); Error }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string]$BuildId,
          [Parameter(Mandatory)][string[]]$Fields, [int]$DevicesPerPage = 500, [scriptblock]$ReadEvidence)
    if (-not $ReadEvidence) { $ReadEvidence = { param($Inv, $Ids) Get-SISoftwareEvidence -Invoke $Inv -DeviceIds $Ids } }
    $sql = (Get-SIRemediationTaskSoftwareSql).Replace('{SIG}', (Get-SIRemediationTaskSigExpr -Fields $Fields))
    $rows = @(@(& $Invoke $sql @{ CollectionId = [string]$CollectionId; BuildId = $BuildId } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $res = [pscustomobject]@{ Units = $rows.Count; Read = 0; Bundled = 0; Held = (New-Object System.Collections.Generic.List[string]); Failed = 0; Error = '' }
    if ($rows.Count -eq 0) { return $res }
    $g = { param($r, $n) $x = $r[$n]; if ($x -is [System.DBNull]) { $null } else { $x } }
    # the owners in order, each with its devices and its units
    $owners = [ordered]@{}
    foreach ($r in $rows) {
        $o = [string](& $g $r 'OwnerKey')
        if (-not $owners.Contains($o)) {
            $devs = @(([string](& $g $r 'DeviceIds')).Split(';') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
            $owners[$o] = @{ Devices = $devs; Units = (New-Object System.Collections.Generic.List[object]) }
        }
        $owners[$o].Units.Add($r)
    }
    $page = New-Object System.Collections.Generic.List[string]
    $pageDevs = New-Object System.Collections.Generic.List[string]
    $flush = {
        if ($page.Count -eq 0) { return }
        $ev = @()
        if ($pageDevs.Count -gt 0) {
            try { $ev = @(& $ReadEvidence $Invoke ([string[]]$pageDevs.ToArray())) }
            catch {
                # this page's CIs are UNKNOWN this run: held as they are (the other pages go on)
                $res.Failed++; if (-not $res.Error) { $res.Error = $_.Exception.Message }
                foreach ($o in $page) { $res.Held.Add([string]$o) }
                $page.Clear(); $pageDevs.Clear()
                return
            }
        }
        $ix = @{}
        foreach ($e in $ev) {
            if ($null -eq $e) { continue }
            $k = ('{0}|{1}|{2}' -f ([string](Get-SIEvValue $e 'DeviceId')).ToLowerInvariant(), ([string](Get-SIEvValue $e 'Product')).Trim().ToLowerInvariant(), ([string](Get-SIEvValue $e 'Version')).Trim())
            if (-not $ix.ContainsKey($k)) { $ix[$k] = New-Object System.Collections.Generic.List[object] }
            $ix[$k].Add($e)
        }
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($o in $page) {
            $own = $owners[$o]
            foreach ($u in $own.Units) {
                $prod = [string](& $g $u 'Product'); $vend = [string](& $g $u 'Vendor'); $ver = [string](& $g $u 'Version')
                $match = New-Object System.Collections.Generic.List[object]
                foreach ($d in $own.Devices) {
                    $k = ('{0}|{1}|{2}' -f $d, $prod.Trim().ToLowerInvariant(), $ver.Trim())
                    if (-not $ix.ContainsKey($k)) { continue }
                    foreach ($e in $ix[$k]) { if (-not $vend -or ([string](Get-SIEvValue $e 'Vendor')).Trim().ToLowerInvariant() -eq $vend.Trim().ToLowerInvariant()) { $match.Add($e) } }
                }
                $b = Get-SIRemediationTaskBundledUnits -Rows $match.ToArray() -Product $prod -Version $ver
                if (-not $b.Known) { continue }
                $res.Read++
                $keep = [bool]$b.KeepPlain
                $out.Add([ordered]@{ o = $o; p = $prod; v = $vend; r = $ver; keep = $keep; k = $null; n = $null; a = $null; x = [string]$b.DiskPaths; t = $null })
                foreach ($x in @($b.Units)) {
                    $res.Bundled++
                    $t = $null; if ($null -ne $x.EvidenceAt) { $t = ([datetime]$x.EvidenceAt).ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) }
                    $out.Add([ordered]@{ o = $o; p = $prod; v = $vend; r = $ver; keep = $keep; k = $x.TaskKey; n = $x.TaskName; a = $x.Application; x = $x.Paths; t = $t })
                }
            }
        }
        $null = Write-SIRemediationTaskStage -Invoke $Invoke -BuildId $BuildId -Part 'split' -Rows $out
        $page.Clear(); $pageDevs.Clear()
    }
    foreach ($o in $owners.Keys) {
        $devs = @($owners[$o].Devices)
        if ($pageDevs.Count -gt 0 -and ($pageDevs.Count + $devs.Count) -gt $DevicesPerPage) { & $flush }
        $page.Add([string]$o)
        foreach ($d in $devs) { if (-not $pageDevs.Contains($d)) { $pageDevs.Add($d) } }
    }
    & $flush
    $res
}

function Get-SIRemediationTaskLockSql {
    <# The build lock: one build of the tasks at a time across every data sync (sp_getapplock, exclusive, owned by the session of
       a connection held open for the whole build). -Part take (answers sp_getapplock's result; < 0 = held by another build) |
       release. #>
    param([Parameter(Mandatory)][ValidateSet('take', 'release')][string]$Part)
    if ($Part -eq 'take') { return "SET NOCOUNT ON; DECLARE @l int; EXEC @l = sp_getapplock @Resource = N'si-remediation-task-build', @LockMode = N'Exclusive', @LockOwner = N'Session', @LockTimeout = 0; SELECT @l;" }
    "SET NOCOUNT ON; IF APPLOCK_MODE(N'public', N'si-remediation-task-build', N'Session') <> N'NoLock' EXEC sp_releaseapplock @Resource = N'si-remediation-task-build', @LockOwner = N'Session'; SELECT 1;"
}

function Invoke-SIDataRemediationTasks {
    <#
    .SYNOPSIS  Builds the remediation tasks of the NEWEST complete collection (once; after the finding lifecycle processed it),
               over the newest collection built before it. Never throws.
               ONE BUILD AT A TIME: on a seam that holds a connection for a session (the data sync's own), the whole build runs
               under an exclusive lock (sp_getapplock 'si-remediation-task-build'); a second data sync that finds it held skips
               the tasks with one line (nothing changed -- never a build on half data). A build clears only its OWN working
               rows; the rows a build left behind when it ended abnormally are removed only while this build holds the lock.
               A seam without a session builds nothing (never a build without the lock).
    .PARAMETER Map            the finding field map (default: the run's data model, Get-SIFindingFieldMap)
    .PARAMETER KeepClosedDays how long a closed task is carried (default SI_Pro_FindingStateRetentionDays, else 365)
    .PARAMETER ReadEvidence   tests: { param($Invoke, [string[]]$DeviceIds) } -> evidence rows (default Get-SISoftwareEvidence)
    .PARAMETER FirstTake      the first write range's size in CIs (measured from there; default 256)
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, $Map, $ValueMaps, [int]$KeepClosedDays = 0,
          [scriptblock]$ReadEvidence, [int]$DevicesPerPage = 500, [switch]$Force, [int]$FirstTake = 0,
          # tests: { param([string[]]$Fields) } -> the build's SQL (the scale bench's reference build); default Get-SIRemediationTaskBuildSql
          [scriptblock]$BuildSql)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $buildId = [guid]::NewGuid().ToString()
    $st = @{ Staged = $false; Locked = $false }
    # THE BUILD (under the lock when the seam can hold one)
    $work = {
        $p = @(@(& $Invoke (Get-SIRemediationTaskPendingSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($null -eq $p) { return [pscustomobject]@{ Status = 'ok'; Built = $false; Why = 'no complete collection' } }
        $g = { param($n) $x = $p[$n]; if ($x -is [System.DBNull]) { $null } else { $x } }
        $cid = [long](& $g 'CollectionId'); $ct = [datetime](& $g 'CollectionTime')
        $at = & $g 'RemediationTasksAt'; $ctx = & $g 'ContextAt'
        if (-not $Force -and $null -ne $at -and ($null -eq $ctx -or [datetime]$at -ge [datetime]$ctx)) { return [pscustomobject]@{ Status = 'ok'; Built = $false; Why = 'built' } }
        $stateAt = & $g 'StateAt'
        if ($null -eq $stateAt -or [datetime]$stateAt -lt $ct) {
            & $Log 'INFO' ('remediation tasks: the collection of {0:yyyy-MM-dd HH:mm} UTC waits for its findings'' lifecycle -- its tasks follow on the next run.' -f $ct)
            return [pscustomobject]@{ Status = 'ok'; Built = $false; Why = 'waits for the finding lifecycle' }
        }
        $base = & $g 'BaseId'
        $map = $Map
        if ($null -eq $map) { $map = Get-SIFindingFieldMap }
        if ($null -eq $map) {
            & $Log 'WARN' 'remediation tasks: the data model has no finding field map -- the tasks per asset are not built.'
            return [pscustomobject]@{ Status = 'no-map' }
        }
        $vmaps = $ValueMaps
        if ($null -eq $vmaps) { try { $vmaps = (Get-SIDataModelTemplate -Name 'value-maps').Document.maps } catch { $vmaps = $null } }
        $keepDays = $KeepClosedDays
        if ($keepDays -le 0) {
            $keepDays = 365
            $sv = Get-Variable -Name SI_Pro_FindingStateRetentionDays -Scope Global -ValueOnly -ErrorAction SilentlyContinue
            $n = 0; if ($null -ne $sv -and [int]::TryParse([string]$sv, [ref]$n) -and $n -gt 0) { $keepDays = $n }
        }
        $plan = Get-SIFindingFieldPlan -Map $map
        $rf = Get-SIRemediationTaskRuleFields -Plan $plan
        if (@($rf.Unknown).Count) { & $Log 'INFO' ('remediation tasks: the grouping rule reads {0}, which the stored findings do not carry -- such a source gives no task' -f (@($rf.Unknown) -join ', ')) }
        $fields = [string[]]@($rf.Known)
        if ($DryRun) {
            & $Log 'INFO' ('remediation tasks: the collection of {0:yyyy-MM-dd HH:mm} UTC would get its tasks; nothing is written.' -f $ct)
            return [pscustomobject]@{ Status = 'dry-run'; CollectionId = $cid }
        }
        $clock = [Diagnostics.Stopwatch]::StartNew()
        # working rows a build left behind (it ended abnormally): removed only while THIS build holds the lock -- then no other
        # build is running, so no running build's rows are ever touched
        if ($st.Locked) { $null = & $Invoke (Get-SIRemediationTaskStageSql -Part 'orphans') @{ BuildId = $buildId } 'nonquery' }
        $st.Staged = $true
        $lap = [Diagnostics.Stopwatch]::StartNew(); $laps = New-Object System.Collections.Generic.List[string]
        $sig = Invoke-SIRemediationTaskSignatures -Invoke $Invoke -CollectionId $cid -BuildId $buildId -Fields $fields -Map $map -Plan $plan -ValueMaps $vmaps
        $laps.Add(('signatures={0:N0}' -f $lap.Elapsed.TotalSeconds)); $lap.Restart()
        $ev = Invoke-SIRemediationTaskEvidence -Invoke $Invoke -CollectionId $cid -BuildId $buildId -Fields $fields -ReadEvidence $ReadEvidence -DevicesPerPage $DevicesPerPage
        if ($ev.Failed -gt 0) {
            & $Log 'WARN' ('remediation tasks: the software evidence of {0} CI(s) could not be read ({1} page(s): {2}) -- their tasks are kept exactly as they were this run; every other CI is built.' -f $ev.Held.Count, $ev.Failed, $ev.Error)
        }
        $laps.Add(('evidence={0:N0}' -f $lap.Elapsed.TotalSeconds)); $lap.Restart()
        $sql = $(if ($BuildSql) { [string](& $BuildSql $fields) } else { Get-SIRemediationTaskBuildSql -Fields $fields })
        $r = @(@(& $Invoke $sql @{ CollectionId = [string]$cid; BaseId = $(if ($null -ne $base) { [string]$base } else { '' }); BuildId = $buildId; KeepClosedDays = [string]$keepDays
                                    HoldOwners = (ConvertTo-Json -InputObject @($ev.Held.ToArray()) -Compress); FirstTake = [string]$FirstTake } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $v = { param($n) if ($null -eq $r) { 0 } else { $x = $r[$n]; if ($x -is [System.DBNull]) { 0 } else { [long]$x } } }
        $laps.Add(('build={0:N0}' -f $lap.Elapsed.TotalSeconds)); $lap.Restart()
        # the task rows of collections older than the base are removed (the base and this one stay)
        $removed = 0L
        $keepFrom = $(if ($null -ne $base) { [long]$base } else { $cid })
        while ($true) {
            $n = [long](& $Invoke (Get-SIRemediationTaskRetentionSql) @{ KeepFrom = [string]$keepFrom; Take = '20000' } 'scalar')
            $removed += $n
            if ($n -le 0) { break }
        }
        $res = [pscustomobject]@{ Status = 'ok'; Built = $true; CollectionId = $cid; BaseId = $base; Tasks = (& $v 'Tasks'); Open = (& $v 'Open'); Closed = (& $v 'Closed')
                                  NewlyClosed = (& $v 'NewlyClosed'); Kept = (& $v 'Kept'); Reopened = (& $v 'Reopened'); Links = (& $v 'Links'); Findings = (& $v 'Findings')
                                  NoTask = (& $v 'NoTask'); OwnRows = (& $v 'OwnRows'); CompleteReports = (& $v 'CompleteReports'); LinkStates = $(if ($r -and -not ($r['LinkStates'] -is [System.DBNull])) { [string]$r['LinkStates'] } else { '' }); Signatures = $sig.Signatures; Bundled = $ev.Bundled; EvidenceRead = $ev.Read; Removed = $removed
                                  WriteRanges = (& $v 'WriteRanges'); Held = (& $v 'Held'); EvidenceFailed = $ev.Failed; Locked = [bool]$st.Locked
                                  Seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
                                  Phases = ('{0}; retention={1:N0} s; in the build (ms): {2}' -f ($laps -join ' s; '), $lap.Elapsed.TotalSeconds, $(if ($r -and -not ($r['BuildPhases'] -is [System.DBNull])) { [string]$r['BuildPhases'] } else { '' })) }
        & $Log 'OK' ('remediation tasks: the collection of {0:yyyy-MM-dd HH:mm} UTC -- {1} task(s) ({2} open, {3} closed, {4} closed this run, {5} kept as they were while their findings are not known), {6} finding(s) without a known fix get no task ({7} s: {8})' -f `
            $ct, $res.Tasks, $res.Open, $res.Closed, $res.NewlyClosed, $res.Kept, $res.NoTask, $res.Seconds, $res.Phases)
        return $res
    }
    try {
        if (([int](& $Invoke (Get-SIRemediationTaskSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'INFO' 'remediation tasks: the database does not have the task tables yet (the updater adds them) -- the tasks per asset are not built.'
            return [pscustomobject]@{ Status = 'no-schema' }
        }
        if ($DryRun) { return (& $work) }
        # NEVER WITHOUT THE LOCK: a seam that cannot hold a connection for a session builds no tasks (said) -- another build's
        # clean-up could otherwise remove this build's working rows
        $sp = $Invoke.PSObject.Properties['SISqlSession']
        if ($null -eq $sp -or -not [bool]$sp.Value) {
            & $Log 'WARN' 'remediation tasks: this database connection cannot hold the build lock -- the tasks per asset are not built this run (they show the last complete set).'
            return [pscustomobject]@{ Status = 'no-lock'; Built = $false; Why = 'no session to hold the build lock' }
        }
        $box = @{ R = $null }
        $onSession = {
            param($Run)
            $lk = [int](& $Run (Get-SIRemediationTaskLockSql -Part 'take') 'scalar')
            if ($lk -lt 0) {
                & $Log 'INFO' 'remediation tasks: another data sync is building the tasks right now -- this run leaves them to it (nothing is changed here; the tasks are built once).'
                $box.R = [pscustomobject]@{ Status = 'ok'; Built = $false; Why = 'busy' }
                return 0
            }
            $st.Locked = $true
            try { $box.R = & $work }
            finally { try { $null = & $Run (Get-SIRemediationTaskLockSql -Part 'release') 'scalar' } catch { } }
            return 0
        }
        $null = & $Invoke $null $null 'session' $onSession
        return $box.R
    } catch {
        & $Log 'WARN' ('remediation tasks: not completed this run -- {0}. Tried again on the next run; the tasks per asset show the last complete set.' -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    } finally {
        if ($st.Staged) { try { $null = & $Invoke (Get-SIRemediationTaskStageSql -Part 'clear') @{ BuildId = $buildId } 'nonquery' } catch { } }
    }
}
