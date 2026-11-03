#Requires -Version 5.1
<#
    SecurityInsight -- RETIRE AT ONCE ON PROOF OF DELETION (REQUIREMENTS #1057, owner decisions 2026-11-02).

    Owner, verbatim: "a deleted object in AD or Azure must retire the assets + its vulnerabilities when it is gone. same with
    intune, when a device is removed from intune, then it should be retired - and not wait 30 days. so if these deleted object
    values are defined, they win over the default 30 days."

    PROOF OF DELETION ONLY (owner): a positive signal from the source --
      entra   the object is in Entra ID's deleted items (/directory/deletedItems: users, devices, groups)
      azure   a deletion in Azure Resource Graph's resource changes (resourcechanges, its deletion change type -- the last 14 days)
      intune  the managed device's removal in Intune's audit events (/deviceManagement/auditEvents)
    Merely MISSING from a list keeps today's window: a source outage or a permission gap never retires an asset (absence is
    never remediation). A read that is not complete decides nothing -- what it did return is still proof.

    A per-install switch per source, OFF by default (SI_DeletionProof_Entra / _Azure / _Intune). Off, nothing here runs a
    read and the CI build is exactly as before. On:
      1. CANDIDATES  the records of that source missing from their feed's newest COMPLETE collection (sidata.CiRecord; only
                     those can be proven deleted -- a record the source still lists is never touched)
      2. PROOF       the source's own deletion signal, matched to the candidates by their own id
      3. RECORDED    sidata.CiDeletionProof (one row per proven record; a record listed again -- an Entra restore -- or a source
                     switched off loses its row), and the proven record is due in the next CI build (CiRecord.NextDueAt)
      4. CI BUILD    Get-SIRecordLink (SI-CiBuild.ps1): a proven record missing from a complete newer collection is GONE,
                     "deleted in <source>"; Get-SICiLifecycle (SI-CiLifecycle.ps1): a CI with no active or held link and a
                     deleted one is RETIRED AT ONCE -- the proof wins over the not-seen / grace-period window
      5. FINDINGS    close as "asset deleted in <source>" (SI-DataCiLifecycle.ps1 and the vulnerability close-loop), never as
                     fixed / remediated
    UNDONE: an object restored (Entra ID keeps deleted items 30 days) is listed again -> its record is active -> the CI is
    reactivated (the lifecycle's own rule) and its proof row is removed.
    PowerShell 5.1: no ?. / ??, no ternary. No Set-StrictMode.
#>

# the readers' Graph token, pager and Resource Graph call -- loaded by Invoke-SIDeletionProof only when a switch is on
$script:SIDeletionProofReaderFiles = @(
    @{ Command = 'Get-SIGraphToken'; Path = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'auth', 'Get-SIGraphToken.ps1') },
    @{ Command = 'Invoke-SIPagedRest'; Path = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'asset-profiling', 'shared', 'Invoke-SIPagedRest.ps1') },
    @{ Command = 'Search-SIResourceGraph'; Path = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-AzRest.ps1') }
)

# source -> its setting, its name in words, the providers / record types whose records its proof can retire
$script:SIDeletionProofSources = [ordered]@{
    entra  = [pscustomobject]@{ Setting = 'SI_DeletionProof_Entra';  Label = 'Entra ID'; Providers = @('entra', 'eg') }
    azure  = [pscustomobject]@{ Setting = 'SI_DeletionProof_Azure';  Label = 'Azure';    Providers = @('azure') }
    intune = [pscustomobject]@{ Setting = 'SI_DeletionProof_Intune'; Label = 'Intune';   Providers = @('intune') }
}

function ConvertTo-SIDeletionProofFlag {
    <# PURE. A setting's value -> on / off (only a real true is on; anything else, unset included, is off). #>
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    ([string]$Value).Trim().ToLowerInvariant() -in 'true', '1', 'on', 'yes', '$true'
}

function Get-SIDeletionProofChoice {
    <#
        PURE. The install's switches -> @{ entra; azure; intune (bool); On (the source keys switched on); Any }.
        -Globals: name -> value (tests); not given = the live globals.
    #>
    param([hashtable]$Globals)
    $out = [ordered]@{}
    $on = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($script:SIDeletionProofSources.Keys)) {
        $name = [string]$script:SIDeletionProofSources[$k].Setting
        $v = $null
        if ($null -ne $Globals) { if ($Globals.ContainsKey($name)) { $v = $Globals[$name] } }
        else { $gv = Get-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue; if ($gv) { $v = $gv.Value } }
        $out[$k] = ConvertTo-SIDeletionProofFlag $v
        if ($out[$k]) { $on.Add($k) }
    }
    $out['On'] = $on.ToArray()
    $out['Any'] = ($on.Count -gt 0)
    [pscustomobject]$out
}

function Get-SIDeletionProofLabel {
    <# PURE. A source key -> its name in words ('entra' -> 'Entra ID'); an unknown key as it is. #>
    param([string]$Source)
    $k = ([string]$Source).Trim().ToLowerInvariant()
    if ($script:SIDeletionProofSources.Contains($k)) { return [string]$script:SIDeletionProofSources[$k].Label }
    [string]$Source
}

function Get-SIDeletionProofCloseReason {
    <# PURE. The close reason of a finding whose asset was deleted (owner: "asset deleted in <source>") -- never a fix. #>
    param([string]$Source)
    'asset deleted in ' + (Get-SIDeletionProofLabel $Source)
}

function Get-SIDeletionProofSourceOfReason {
    <#
        PURE. The source NAME a CI lifecycle reason / evidence text says the asset was deleted in ('Entra ID', 'Azure',
        'Intune'), or '' -- the reason Get-SICiLifecycle writes is "retired at once: deleted in <source> (...)".
    #>
    param([AllowEmptyString()][string]$Text)
    if (-not $Text) { return '' }
    foreach ($k in @($script:SIDeletionProofSources.Keys)) {
        $l = [string]$script:SIDeletionProofSources[$k].Label
        if ($Text -match ('retired at once: deleted in ' + [regex]::Escape($l) + '(\W|$)')) { return $l }
    }
    ''
}

# =====================================================================================================================
#  1. CANDIDATES -- the records missing from a complete newer collection of their feed
# =====================================================================================================================
function Get-SIDeletionProofCandidatesSql {
    <#
        The records of the providers in @prov (JSON array) that are MISSING from their feed's newest collection while that
        collection was COMPLETE (the CI build's own feed rule, Get-SIRecordLinkState), collected within @lbDays. An Exposure
        Graph record only for users and groups (the Entra ID objects it names by their Entra object id). Per record its
        native id (the record key after 'provider:') and its Entra object id (sidata.RecordIdentifier AadObjectId).
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.CiRecord') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(450)) AS RecordKey WHERE 1 = 0; RETURN; END
DECLARE @lb DATETIME2(3) = DATEADD(day, -CAST(@lbDays AS INT), SYSUTCDATETIME());
WITH f AS (SELECT Provider, ISNULL(RecordType, N'') AS RecordType, MAX(CollectionTime) AS Latest FROM sidata.CiRecord
           WHERE CollectionTime >= @lb AND Provider IN (SELECT [value] FROM OPENJSON(@prov)) GROUP BY Provider, ISNULL(RecordType, N'')),
     fl AS (SELECT f.Provider, f.RecordType, f.Latest, MIN(CAST(ISNULL(r.Complete, 1) AS INT)) AS Complete
            FROM f JOIN sidata.CiRecord r ON r.Provider = f.Provider AND ISNULL(r.RecordType, N'') = f.RecordType AND r.CollectionTime = f.Latest
            GROUP BY f.Provider, f.RecordType, f.Latest)
SELECT r.RecordKey, r.Provider, ISNULL(r.RecordType, N'') AS RecordType,
       CASE WHEN CHARINDEX(N':', r.RecordKey) > 0 THEN LOWER(SUBSTRING(r.RecordKey, CHARINDEX(N':', r.RecordKey) + 1, 450)) ELSE LOWER(r.RecordKey) END AS NativeId,
       (SELECT TOP 1 LOWER(i.IdValue) FROM sidata.RecordIdentifier i WHERE i.RecordKey = r.RecordKey AND i.IdType = N'AadObjectId') AS AadObjectId
FROM sidata.CiRecord r
JOIN fl ON fl.Provider = r.Provider AND fl.RecordType = ISNULL(r.RecordType, N'')
WHERE fl.Complete = 1 AND r.CollectionTime >= @lb AND r.CollectionTime < fl.Latest
  AND (r.Provider <> N'eg' OR ISNULL(r.RecordType, N'') IN (N'user', N'group'));
'@
}

# =====================================================================================================================
#  2. PROOF -- each source's own deletion signal (ids, lower-case -> @{ DeletedAt; Evidence })
# =====================================================================================================================
function Add-SIDeletionProofItem {
    param([hashtable]$Into, [string]$Id, $At, [string]$Evidence)
    if (-not $Id) { return }
    $k = $Id.Trim().ToLowerInvariant(); if (-not $k) { return }
    $t = $null
    if ($At -is [datetime]) { $t = ([datetime]$At).ToUniversalTime() }
    elseif ($At) { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$At, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$d)) { $t = $d } }
    if ($Into.ContainsKey($k) -and $null -ne $Into[$k].DeletedAt -and ($null -eq $t -or $t -le $Into[$k].DeletedAt)) { return }
    $Into[$k] = [pscustomobject]@{ DeletedAt = $t; Evidence = $Evidence }
}

function Get-SIDeletionProofValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] }; return $null }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function Read-SIEntraDeletionProof {
    <#
        Entra ID's deleted items: users, devices and groups (/directory/deletedItems/microsoft.graph.<type>; Directory.Read.All,
        which the engine identity has). Returns @{ Ok; Users; Devices; Groups (id -> @{ DeletedAt; Evidence }); Error } --
        Devices is keyed by the device id (deviceId, the Entra device record's key) AND the object id. Ok = $false when a read
        was not complete: what it did return is still proof.
        -Fetch: test seam { param($Url, $OnPage) } -> @{ Complete; Error } (calls $OnPage with each page's rows).
    #>
    param([scriptblock]$Fetch)
    $res = [ordered]@{ Ok = $true; Users = @{}; Devices = @{}; Groups = @{}; Error = '' }
    if (-not $Fetch) {
        $Fetch = {
            param($Url, $OnPage)
            $tk = ''
            if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { $tk = [string](Get-SIGraphToken -Resource Graph) }
            if (-not $tk) { throw 'no Microsoft Graph token' }
            Invoke-SIPagedRest -Url ('https://graph.microsoft.com/v1.0' + $Url) -Token $tk -SourceLabel 'deletion proof (Entra ID deleted items)' -OnPage $OnPage
        }
    }
    $errs = New-Object System.Collections.Generic.List[string]
    $reads = @(
        @{ Url = '/directory/deletedItems/microsoft.graph.user?$select=id,deletedDateTime&$top=999'; Into = $res.Users; Kind = 'user' },
        @{ Url = '/directory/deletedItems/microsoft.graph.device?$select=id,deviceId,deletedDateTime&$top=999'; Into = $res.Devices; Kind = 'device' },
        @{ Url = '/directory/deletedItems/microsoft.graph.group?$select=id,deletedDateTime&$top=999'; Into = $res.Groups; Kind = 'group' }
    )
    foreach ($rd in $reads) {
        # (the page block finds $dpInto / $dpKind here: it runs below this function, as Read-SIEntraGroupIds' does)
        $dpInto = $rd.Into; $dpKind = [string]$rd.Kind
        try {
            $r = & $Fetch $rd.Url {
                param($dpRows)
                foreach ($x in @($dpRows)) {
                    $at = Get-SIDeletionProofValue $x 'deletedDateTime'
                    $ev = ('in the Entra ID deleted items ({0})' -f $dpKind)
                    Add-SIDeletionProofItem -Into $dpInto -Id ([string](Get-SIDeletionProofValue $x 'id')) -At $at -Evidence $ev
                    if ($dpKind -eq 'device') { Add-SIDeletionProofItem -Into $dpInto -Id ([string](Get-SIDeletionProofValue $x 'deviceId')) -At $at -Evidence $ev }
                }
            }
            if ($null -ne $r -and (Get-SIDeletionProofValue $r 'Complete') -eq $false) { $res.Ok = $false; $errs.Add([string](Get-SIDeletionProofValue $r 'Error')) }
        } catch { $res.Ok = $false; $errs.Add(('{0}s: {1}' -f $dpKind, $_.Exception.Message)) }
    }
    $res.Error = (@($errs | Where-Object { $_ }) -join '; ')
    [pscustomobject]$res
}

function Get-SIAzureDeletionKql {
    <# PURE. Azure Resource Graph: every resource DELETED in the last -Days days (resourcechanges keeps 14), newest delete. #>
    param([int]$Days = 14)
    if ($Days -lt 1 -or $Days -gt 14) { $Days = 14 }
    @"
resourcechanges
| extend ChangeTime = todatetime(properties.changeAttributes.timestamp), ResourceId = tolower(tostring(properties.targetResourceId)), ChangeType = tostring(properties.changeType)
| where ChangeTime > ago($($Days)d) and ChangeType =~ 'Delete' and isnotempty(ResourceId)
| summarize DeletedAt = max(ChangeTime) by ResourceId
| order by ResourceId asc
"@
}

function Read-SIAzureDeletionProof {
    <#
        Azure: a Delete in Resource Graph's resource changes (Reader, which the engine identity has). Returns @{ Ok; Resources
        (lower resource id -> @{ DeletedAt; Evidence }); Error }. -Fetch: test seam { param($Query) } -> the rows; throws on a
        failed read.
    #>
    param([scriptblock]$Fetch)
    $res = [ordered]@{ Ok = $true; Resources = @{}; Error = '' }
    if (-not $Fetch) {
        $Fetch = {
            param($Query)
            Search-SIResourceGraph -Query $Query
        }
    }
    try {
        foreach ($x in @(& $Fetch (Get-SIAzureDeletionKql))) {
            if ($null -eq $x) { continue }
            Add-SIDeletionProofItem -Into $res.Resources -Id ([string](Get-SIDeletionProofValue $x 'ResourceId')) -At (Get-SIDeletionProofValue $x 'DeletedAt') -Evidence 'a Delete in the Azure resource changes'
        }
    } catch { $res.Ok = $false; $res.Error = $_.Exception.Message }
    [pscustomobject]$res
}

function Read-SIIntuneDeletionProof {
    <#
        Intune: the managed device DELETED in Intune's audit events (/deviceManagement/auditEvents, activityOperationType
        Delete on a ManagedDevice resource, a successful one) since -SinceDays days. Returns @{ Ok; Devices (managed device id
        -> @{ DeletedAt; Evidence }); Error }. Intune's audit events need DeviceManagementApps.Read.All -- an identity without
        it answers 403: the read is not complete and decides nothing (said once per run by the caller).
        -Fetch: test seam { param($Url, $OnPage) } -> @{ Complete; Error }.
    #>
    param([scriptblock]$Fetch, [int]$SinceDays = 30, [datetime]$Now = [datetime]::UtcNow)
    $res = [ordered]@{ Ok = $true; Devices = @{}; Error = '' }
    if (-not $Fetch) {
        $Fetch = {
            param($Url, $OnPage)
            $tk = ''
            if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { $tk = [string](Get-SIGraphToken -Resource Graph) }
            if (-not $tk) { throw 'no Microsoft Graph token' }
            Invoke-SIPagedRest -Url ('https://graph.microsoft.com/v1.0' + $Url) -Token $tk -SourceLabel 'deletion proof (Intune audit events)' -OnPage $OnPage
        }
    }
    if ($SinceDays -lt 1) { $SinceDays = 30 }
    $since = $Now.ToUniversalTime().AddDays(-$SinceDays).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $dpInto = $res.Devices
    try {
        $r = & $Fetch ('/deviceManagement/auditEvents?$filter=activityDateTime ge {0}' -f $since) {
            param($dpRows)
            foreach ($x in @($dpRows)) {
                if ([string](Get-SIDeletionProofValue $x 'activityOperationType') -ne 'Delete') { continue }
                $result = [string](Get-SIDeletionProofValue $x 'activityResult')
                if ($result -and $result -notmatch '^(?i)success') { continue }
                foreach ($rs in @(Get-SIDeletionProofValue $x 'resources')) {
                    if ($null -eq $rs) { continue }
                    $t = ('{0} {1}' -f [string](Get-SIDeletionProofValue $rs 'type'), [string](Get-SIDeletionProofValue $rs 'auditResourceType'))
                    if ($t -notmatch '(?i)\bManagedDevice\b') { continue }
                    Add-SIDeletionProofItem -Into $dpInto -Id ([string](Get-SIDeletionProofValue $rs 'resourceId')) -At (Get-SIDeletionProofValue $x 'activityDateTime') -Evidence 'a Delete of the managed device in the Intune audit events'
                }
            }
        }
        if ($null -ne $r -and (Get-SIDeletionProofValue $r 'Complete') -eq $false) { $res.Ok = $false; $res.Error = [string](Get-SIDeletionProofValue $r 'Error') }
    } catch { $res.Ok = $false; $res.Error = $_.Exception.Message }
    [pscustomobject]$res
}

function Find-SIDeletionProofMatches {
    <#
        PURE. The candidates (Get-SIDeletionProofCandidatesSql rows) a source's proof covers -> rows @{ k (record key); s
        (source); d (deleted at, ISO); e (evidence) }. Matched by the record's OWN id only:
          entra   provider entra, record type user: its object id in the deleted users; device: its device id in the deleted
                  devices; provider eg (users, groups): its Entra object id in the deleted users / groups
          azure   provider azure: its resource id in the deleted resources
          intune  provider intune, record type device: its managed device id in the deleted devices
        -Proof: source key -> the reader's result (Read-SI<Source>DeletionProof).
    #>
    param([AllowEmptyCollection()][object[]]$Candidates = @(), [hashtable]$Proof = @{})
    $out = New-Object System.Collections.Generic.List[object]
    $fmt = { param($d) if ($d -is [datetime]) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
    foreach ($c in @($Candidates)) {
        if ($null -eq $c) { continue }
        $key = [string](Get-SIDeletionProofValue $c 'RecordKey'); if (-not $key) { continue }
        $p = ([string](Get-SIDeletionProofValue $c 'Provider')).ToLowerInvariant()
        $rt = ([string](Get-SIDeletionProofValue $c 'RecordType')).ToLowerInvariant()
        $nid = ([string](Get-SIDeletionProofValue $c 'NativeId')).Trim().ToLowerInvariant()
        $oid = Get-SIDeletionProofValue $c 'AadObjectId'; if ($oid -is [DBNull]) { $oid = '' }; $oid = ([string]$oid).Trim().ToLowerInvariant()
        $hit = $null; $src = ''
        if ($Proof.ContainsKey('entra') -and $null -ne $Proof['entra']) {
            $e = $Proof['entra']
            if ($p -eq 'entra' -and $rt -eq 'user' -and $nid -and $e.Users.ContainsKey($nid)) { $hit = $e.Users[$nid]; $src = 'entra' }
            elseif ($p -eq 'entra' -and $rt -eq 'device' -and $nid -and $e.Devices.ContainsKey($nid)) { $hit = $e.Devices[$nid]; $src = 'entra' }
            elseif ($p -eq 'eg' -and $rt -eq 'user' -and $oid -and $e.Users.ContainsKey($oid)) { $hit = $e.Users[$oid]; $src = 'entra' }
            elseif ($p -eq 'eg' -and $rt -eq 'group' -and $oid -and $e.Groups.ContainsKey($oid)) { $hit = $e.Groups[$oid]; $src = 'entra' }
        }
        if ($null -eq $hit -and $p -eq 'azure' -and $Proof.ContainsKey('azure') -and $null -ne $Proof['azure'] -and $nid -and $Proof['azure'].Resources.ContainsKey($nid)) { $hit = $Proof['azure'].Resources[$nid]; $src = 'azure' }
        if ($null -eq $hit -and $p -eq 'intune' -and $rt -eq 'device' -and $Proof.ContainsKey('intune') -and $null -ne $Proof['intune'] -and $nid -and $Proof['intune'].Devices.ContainsKey($nid)) { $hit = $Proof['intune'].Devices[$nid]; $src = 'intune' }
        if ($null -eq $hit) { continue }
        $out.Add([ordered]@{ k = $key; s = $src; d = (& $fmt $hit.DeletedAt); e = [string]$hit.Evidence })
    }
    $out.ToArray()
}

# =====================================================================================================================
#  3. RECORDED -- sidata.CiDeletionProof, and the proven records due in the next CI build
# =====================================================================================================================
function Get-SIDeletionProofWriteSql {
    <#
        ONE statement: @rows (JSON [{ k; s; d; e }]) are recorded (a record already proven keeps its first proof); a proof row
        whose source is no longer switched on (@on, JSON array of source keys), whose record is gone from sidata.CiRecord or
        whose record is LISTED AGAIN (its collection is the newest of its feed -- an Entra restore) is removed. Every record
        whose proof was added or removed is due in the next CI build (NextDueAt = now: its group is rebuilt). Answers
        Added / Removed.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.CiDeletionProof') IS NULL OR OBJECT_ID(N'sidata.CiRecord') IS NULL BEGIN SELECT 0 AS Added, 0 AS Removed; RETURN; END
DECLARE @now DATETIME2(3) = SYSUTCDATETIME();
IF OBJECT_ID('tempdb..#dpChg') IS NOT NULL DROP TABLE #dpChg;
CREATE TABLE #dpChg (RecordKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, Act NCHAR(1) NOT NULL);
INSERT sidata.CiDeletionProof (RecordKey, Source, DeletedAt, Evidence, ProvedAt)
OUTPUT inserted.RecordKey, N'a' INTO #dpChg (RecordKey, Act)
SELECT x.k, LEFT(x.s, 16), x.d, LEFT(x.e, 400), @now
FROM (SELECT k, MAX(s) AS s, MAX(d) AS d, MAX(e) AS e
      FROM OPENJSON(@rows) WITH (k NVARCHAR(450), s NVARCHAR(16), d DATETIME2(3), e NVARCHAR(400)) WHERE k IS NOT NULL GROUP BY k) x
WHERE x.s IN (SELECT [value] FROM OPENJSON(@on))
  AND EXISTS (SELECT 1 FROM sidata.CiRecord r WHERE r.RecordKey = x.k)
  AND NOT EXISTS (SELECT 1 FROM sidata.CiDeletionProof p WHERE p.RecordKey = x.k);
WITH fl AS (SELECT Provider, ISNULL(RecordType, N'') AS RecordType, MAX(CollectionTime) AS Latest FROM sidata.CiRecord
            WHERE Provider IN (SELECT DISTINCT r.Provider FROM sidata.CiDeletionProof p JOIN sidata.CiRecord r ON r.RecordKey = p.RecordKey)
            GROUP BY Provider, ISNULL(RecordType, N''))
DELETE p OUTPUT deleted.RecordKey, N'r' INTO #dpChg (RecordKey, Act)
FROM sidata.CiDeletionProof p
LEFT JOIN sidata.CiRecord r ON r.RecordKey = p.RecordKey
LEFT JOIN fl ON fl.Provider = r.Provider AND fl.RecordType = ISNULL(r.RecordType, N'')
WHERE p.Source NOT IN (SELECT [value] FROM OPENJSON(@on)) OR r.RecordKey IS NULL OR r.CollectionTime >= fl.Latest /* one-statement-ok: only the deletion-proof rows, a few per run */;
IF COL_LENGTH('sidata.CiRecord', 'NextDueAt') IS NOT NULL
    EXEC sp_executesql N'UPDATE r SET NextDueAt = @n FROM sidata.CiRecord r WHERE r.RecordKey IN (SELECT RecordKey FROM #dpChg) AND (r.NextDueAt IS NULL OR r.NextDueAt > @n) /* one-statement-ok: only the records whose proof changed (#dpChg) */;', N'@n DATETIME2(3)', @n = @now;
SELECT (SELECT COUNT(*) FROM #dpChg WHERE Act = N'a') AS Added, (SELECT COUNT(*) FROM #dpChg WHERE Act = N'r') AS Removed;
DROP TABLE #dpChg;
'@
}

function Get-SIDeletionProofReadSql {
    <# The recorded proofs of the sources switched on (@on, JSON array): what the CI build reads. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.CiDeletionProof') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(450)) AS RecordKey, CAST(NULL AS NVARCHAR(16)) AS Source, CAST(NULL AS DATETIME2(3)) AS DeletedAt, CAST(NULL AS NVARCHAR(400)) AS Evidence WHERE 1 = 0; RETURN; END
SELECT p.RecordKey, p.Source, p.DeletedAt, p.Evidence FROM sidata.CiDeletionProof p WHERE p.Source IN (SELECT [value] FROM OPENJSON(@on));
'@
}

function ConvertTo-SIDeletionProofIndex {
    <# PURE. Proof rows -> record key -> @{ Source; Label; DeletedAt; Evidence } (what Get-SIRecordLink takes). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $idx = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string](Get-SIDeletionProofValue $r 'RecordKey'); if (-not $k) { continue }
        $s = [string](Get-SIDeletionProofValue $r 'Source')
        $d = Get-SIDeletionProofValue $r 'DeletedAt'; if ($d -is [DBNull]) { $d = $null }
        if ($null -ne $d -and -not ($d -is [datetime])) { $x = [datetime]::MinValue; if ([datetime]::TryParse([string]$d, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$x)) { $d = $x } else { $d = $null } }
        $e = Get-SIDeletionProofValue $r 'Evidence'; if ($e -is [DBNull]) { $e = '' }
        $idx[$k] = [pscustomobject]@{ Source = $s; Label = (Get-SIDeletionProofLabel $s); DeletedAt = $d; Evidence = [string]$e }
    }
    $idx
}

function Invoke-SIDeletionProof {
    <#
        The CI build's deletion-proof step (Invoke-SICiBuild calls it before it finds the dirty groups). Never throws.
          -Sql      the install database seam { param($Sql, $Params, $Mode) }
          -Choice   Get-SIDeletionProofChoice (not given = the install's settings)
          -Readers  test seam: source key -> { } -> the reader's result (default: Read-SI<Source>DeletionProof)
          -DryRun   reads, records nothing
        Returns @{ Index (record key -> proof, for the CI build); Added; Removed; Proven (source -> count); Issues }.
        All switches off: the proof rows of a source switched off are still removed (their CIs are rebuilt), no source is read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, $Choice, [int]$LookbackDays = 30, [hashtable]$Readers, [scriptblock]$Log, [switch]$DryRun)
    if (-not $Log) { $Log = { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host ('[' + $l + '] ' + $m) } } }
    if ($null -eq $Choice) { $Choice = Get-SIDeletionProofChoice }
    $res = [ordered]@{ Index = @{}; Added = 0; Removed = 0; Proven = [ordered]@{}; Issues = New-Object System.Collections.Generic.List[string] }
    $onJson = ConvertTo-Json -InputObject @([string[]]@($Choice.On)) -Compress
    if (-not $onJson.TrimStart().StartsWith('[')) { $onJson = '[' + $onJson + ']' }
    $rows = @()
    if ($Choice.Any) {
        $provs = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($Choice.On)) { foreach ($p in @($script:SIDeletionProofSources[$k].Providers)) { if (-not $provs.Contains($p)) { $provs.Add($p) } } }
        $cands = @()
        try { $cands = @(& $Sql (Get-SIDeletionProofCandidatesSql) @{ prov = (ConvertTo-Json -InputObject @($provs.ToArray()) -Compress); lbDays = [string]([Math]::Max(1, $LookbackDays)) } 'rows') }
        catch { $res.Issues.Add(('the records to check could not be read ({0})' -f $_.Exception.Message)); $cands = @() }
        $cands = @($cands | Where-Object { $null -ne $_ })
        if ($cands.Count -gt 0 -and -not $Readers) {
            # (dot-sourced HERE: the readers below run inside this function and find them)
            foreach ($rf in $script:SIDeletionProofReaderFiles) {
                if (-not (Get-Command -Name $rf.Command -ErrorAction SilentlyContinue) -and [IO.File]::Exists($rf.Path)) { try { . $rf.Path } catch { } }
            }
        }
        if ($cands.Count -gt 0) {
            $proof = @{}
            foreach ($k in @($Choice.On)) {
                $label = Get-SIDeletionProofLabel $k
                # only a source with a candidate of its own is read
                $mine = @($cands | Where-Object { @($script:SIDeletionProofSources[$k].Providers) -contains ([string](Get-SIDeletionProofValue $_ 'Provider')).ToLowerInvariant() })
                if ($mine.Count -eq 0) { continue }
                $read = $null
                try {
                    if ($Readers -and $Readers.ContainsKey($k)) { $read = & $Readers[$k] }
                    else {
                        switch ($k) {
                            'entra'  { $read = Read-SIEntraDeletionProof }
                            'azure'  { $read = Read-SIAzureDeletionProof }
                            'intune' { $read = Read-SIIntuneDeletionProof -SinceDays ([Math]::Max(1, $LookbackDays)) }
                        }
                    }
                } catch { $read = $null; $res.Issues.Add(('{0}: {1}' -f $label, $_.Exception.Message)) }
                if ($null -eq $read) { continue }
                if (-not $read.Ok) {
                    # ABSENCE IS NEVER REMEDIATION: a read that is not complete adds only what it did return (each a proof)
                    $res.Issues.Add(('{0}: the deletion read was not complete ({1}) -- only the deletions it returned count this run; nothing is retired for a deletion it could not read' -f $label, [string]$read.Error))
                }
                $proof[$k] = $read
            }
            $rows = @(Find-SIDeletionProofMatches -Candidates $cands -Proof $proof)
        }
        foreach ($k in @($Choice.On)) { $res.Proven[$k] = @($rows | Where-Object { $_.s -eq $k }).Count }
        & $Log 'INFO' ('CIs: deletion proof -- {0} record(s) missing from a complete collection checked; proven deleted: {1}' -f @($cands).Count, ((@($Choice.On) | ForEach-Object { '{0} {1}' -f (Get-SIDeletionProofLabel $_), [int]$res.Proven[$_] }) -join ', '))
        foreach ($i in $res.Issues) { & $Log 'WARN' ('CIs: deletion proof -- ' + $i) }
    }
    if (-not $DryRun) {
        try {
            $rj = ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
            if (-not $rj -or -not $rj.TrimStart().StartsWith('[')) { $rj = '[' + $rj + ']' }
            if (@($rows).Count -eq 0) { $rj = '[]' }
            $w = @(& $Sql (Get-SIDeletionProofWriteSql) @{ rows = $rj; on = $onJson } 'rows') | Select-Object -First 1
            $res.Added = [int](Get-SIDeletionProofValue $w 'Added'); $res.Removed = [int](Get-SIDeletionProofValue $w 'Removed')
            if ($res.Added -gt 0 -or $res.Removed -gt 0) { & $Log 'INFO' ('CIs: deletion proof -- {0} record(s) newly proven deleted, {1} proof(s) no longer apply (listed again, or the source switched off); their CIs are rebuilt in this build' -f $res.Added, $res.Removed) }
        } catch {
            # every switch off: only the clean-up of a switched-off source ran -- nothing to say (a database without the table)
            if (-not $Choice.Any) { return [pscustomobject]$res }
            $res.Issues.Add(('the proofs could not be recorded ({0})' -f $_.Exception.Message)); & $Log 'WARN' ('CIs: deletion proof -- the proofs could not be recorded ({0}); nothing new retires on a deletion this build' -f $_.Exception.Message) }
    }
    if ($Choice.Any) {
        try { $res.Index = ConvertTo-SIDeletionProofIndex -Rows @(& $Sql (Get-SIDeletionProofReadSql) @{ on = $onJson } 'rows') }
        catch { $res.Index = @{}; $res.Issues.Add(('the recorded proofs could not be read ({0})' -f $_.Exception.Message)); & $Log 'WARN' ('CIs: deletion proof -- the recorded proofs could not be read ({0}); no CI retires on a deletion this build' -f $_.Exception.Message) }
    }
    [pscustomobject]$res
}
