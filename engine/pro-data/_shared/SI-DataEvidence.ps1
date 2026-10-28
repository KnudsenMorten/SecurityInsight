#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE CORRELATION EVIDENCE (#299): why SecurityInsight says these source records are ONE CI, and
    how good the correlation is, per collection.

    The customer's own discovery (a CMDB, ServiceNow Discovery) sees part of the estate and does not correlate across
    sources; SecurityInsight's one-CI-per-real-asset IS the value, and it is judged on evidence. So every CI carries, per
    source record behind it: the source system that reported each key, the rule that put the record into the CI and how
    much that rule is worth, when the source last saw it -- plus the CI's id history (aliases, re-keys, merges) and the
    values its sources disagree on. Nothing here decides a correlation: the correlation engine already did (its map
    carries the join basis and the join confidence per group); this file only RECORDS its reasoning in the Pro database.
    Read-only towards every source -- it reads what the profiles and the correlation map already published.

    THE VOCABULARY (sql\si-data-schema.sql, CORRELATION EVIDENCE):
      MatchRule   exact-id    a durable id two source records share (the join key)                       -> exact
                  graph-link  an Exposure Graph node id two records share (the engine's graph-inferred)   -> strong
                  same-record the key is on a record that joined by another key, or on the CI's only record -> the
                              record's own confidence (exact for a lone record or a deterministic join, strong for a
                              graph-linked one)
                  cmdb-pinned / cmdb-rule / cmdb-id / cmdb-name   how the CMDB / ServiceNow reconcile matched the
                              record: pinned -> exact, a rule or an id -> strong, by name -> weak
                  unresolved  the CI is known only from a Risk Analysis finding; no source record matched it -> weak
      Confidence  exact | strong | weak. A CI's confidence is its weakest discovery row; the CMDB / ServiceNow match is
                  evidence on the page and its own figure in the report (CmdbState), never part of the CI's confidence --
                  and never a discovery source in the CI's source count.
      History     alias  a record's SI id moved while its durable id stayed (the #279 shape: MGMT1's id moved from its
                         Entra device id to its Defender device id, both still on the record)
                  rekey  the CI's key changed (an asset id became a ledger id, or the ledger re-minted it)
                  merge  a CI's durable ids now belong to another CI that already existed
      Conflicts   Name / OS / Domain / CMDB CI: two records of one CI disagree. 'Possible duplicate': another CI with the
                  same host name and no shared durable id (the #298 shape) -- shown, never merged here.

    PURE functions build the rows (provable offline); Invoke-SIDataEvidence writes them through the -Invoke seam, guarded:
    a database whose schema predates the tables is told once and the collection load is not affected.
    PS 5.1 safe: no ?. / ??, no ternary. No Set-StrictMode (it leaks into the caller's scope).
#>

# The shared identifier vocabulary (joinable = durable). Loaded, not copied.
if (-not (Get-Command -Name Get-SIJoinableIdTypes -ErrorAction SilentlyContinue)) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-AssetIdentity.ps1')
}

# EntityIds "source" -> the source system as the customer knows it
$script:SIEvidenceSourceNames = @{
    'mde' = 'Defender'; 'defender' = 'Defender'; 'mdatp' = 'Defender'
    'entra' = 'Entra'; 'aad' = 'Entra'; 'azuread' = 'Entra'; 'intune' = 'Intune'
    'exposuregraph' = 'Exposure Graph'; 'eg' = 'Exposure Graph'
    'azure' = 'Azure'; 'arm' = 'Azure'
    'ad' = 'Active Directory'; 'activedirectory' = 'Active Directory'; 'mdi' = 'Active Directory'
    'shodan' = 'Shodan'
}
# key type -> the source system that issues it, when the record does not say
$script:SIEvidenceTypeSource = @{
    'mdedeviceid' = 'Defender'; 'aaddeviceid' = 'Entra'; 'aadobjectid' = 'Entra'; 'intunedeviceid' = 'Intune'
    'exposuregraphnodeid' = 'Exposure Graph'; 'egnodeid' = 'Exposure Graph'
    'azureresourceid' = 'Azure'; 'azurevmid' = 'Azure'; 'cloudnativeresourceid' = 'Defender for Cloud'
    'activedirectoryobjectguid' = 'Active Directory'; 'securityidentifier' = 'Active Directory'; 'onpremobjectguid' = 'Active Directory'
    'ipaddress' = 'Shodan'
}
$script:SIEvidenceConfidenceRank = @{ 'exact' = 0; 'strong' = 1; 'weak' = 2 }

function Get-SIEvidenceSource {
    <# PURE. The source system of one key: what the record says (EntityIds source), else what issues that key type. #>
    param([AllowEmptyString()][string]$Said, [AllowEmptyString()][string]$KeyType, [string]$RecordKind = '')
    $s = ([string]$Said).Trim().ToLowerInvariant().Replace(' ', '')
    if ($s -and $script:SIEvidenceSourceNames.ContainsKey($s)) { return $script:SIEvidenceSourceNames[$s] }
    $t = ([string]$KeyType).ToLowerInvariant()
    if ($script:SIEvidenceTypeSource.ContainsKey($t)) { return $script:SIEvidenceTypeSource[$t] }
    if ($s) { return (Get-Culture).TextInfo.ToTitleCase($s) }
    if ($RecordKind -eq 'finding') { return 'Risk Analysis' }
    'SecurityInsight'
}

function Get-SIEvidenceWeakest {
    <# PURE. The weakest of several confidences (exact < strong < weak); 'exact' for none. #>
    param([AllowEmptyCollection()][string[]]$Values = @())
    $w = 'exact'
    foreach ($v in @($Values)) { if ($v -and $script:SIEvidenceConfidenceRank.ContainsKey($v) -and $script:SIEvidenceConfidenceRank[$v] -gt $script:SIEvidenceConfidenceRank[$w]) { $w = $v } }
    $w
}

function ConvertTo-SIEvidenceCmdbRule {
    <# PURE. The CMDB / ServiceNow reconcile verdict of a record -> @{ Rule; Confidence } or $null (not matched). #>
    param([AllowEmptyString()][string]$State, [AllowEmptyString()][string]$Phase)
    $s = ([string]$State).Trim().ToLowerInvariant(); $p = ([string]$Phase).Trim().ToLowerInvariant()
    if ($s -notlike 'matched*') { return $null }
    if ($s -eq 'matched-pinned' -or $p -eq 'pin' -or $p -eq 'pinned') { return [pscustomobject]@{ Rule = 'cmdb-pinned'; Confidence = 'exact' } }
    if ($s -eq 'matched-fuzzy' -or $p -eq 'fuzzy') { return [pscustomobject]@{ Rule = 'cmdb-name'; Confidence = 'weak' } }
    if ($s -eq 'matched-by-rule' -or $s -eq 'matched-rule' -or $p -eq 'rule') { return [pscustomobject]@{ Rule = 'cmdb-rule'; Confidence = 'strong' } }
    [pscustomobject]@{ Rule = 'cmdb-id'; Confidence = 'strong' }
}

function Get-SIEvidenceShortName {
    <#
        PURE. The comparable form of a host / VM name: lower-case, the first DNS label. '' for a name that is no name: a
        generated one (unnamed-...) or an id standing in for a name (a GUID, a 32/40-hex Exposure Graph / Defender id --
        measured on ring 1, 2026-10-05: an Exposure-Graph-only Azure record is named by its node id, and comparing that to
        the device's host name read as a name conflict on every graph-linked server).
    #>
    param([AllowEmptyString()][string]$Name)
    $n = ([string]$Name).Trim().ToLowerInvariant()
    if (-not $n -or $n.StartsWith('unnamed-')) { return '' }
    if ($n -match '^[0-9a-f]{32}$' -or $n -match '^[0-9a-f]{40}$' -or $n -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or $n.StartsWith('/subscriptions/')) { return '' }
    if ($n.Contains('@')) { return $n }   # an identity: the whole name
    ($n -split '\.', 2)[0]
}

function ConvertFrom-SIEvidenceEntityIds {
    <# PURE. EntityIds (JSON text or objects) -> @( @{ Source; Type; Id } ). Unreadable text -> none. #>
    param([AllowNull()]$EntityIds)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $EntityIds) { return , $out.ToArray() }
    $e = $EntityIds
    if ($e -is [string]) {
        if (-not $e.Trim()) { return , $out.ToArray() }
        try { $e = ConvertFrom-Json -InputObject $e -ErrorAction Stop } catch { return , $out.ToArray() }
    }
    foreach ($x in @($e)) {
        if ($null -eq $x) { continue }
        $t = [string]$x.type; $v = [string]$x.id
        if (-not $t -or -not $v) { continue }
        $out.Add([pscustomobject]@{ Source = [string]$x.source; Type = $t; Id = $v })
    }
    , $out.ToArray()
}

function Build-SIDataEvidence {
    <#
        PURE. The correlation evidence of one load.
          -Set               Build-SIDataAssets output (Assets, Members per AssetKey)
          -Index             New-SIDataIdentityIndex output (the correlation map: identifiers, join basis, join confidence)
          -EvidenceProfiles  lower(SI_AssetId) -> the record's Get-SIDataEvidenceProfileKql row (+ Kind)
        Returns @{ Evidence; Conflicts; Correlation; Skipped }:
          Evidence     one row per (CI, record, key)
          Conflicts    one row per (CI, field, record) for every field two records disagree on, plus 'Possible duplicate'
          Correlation  one row per CI: records, sources, weakest confidence, join rule, conflicts, possible duplicate,
                       CMDB state (IdChanges is filled by Invoke-SIDataEvidence from what the history detection found)
          Skipped      keys too long for the evidence columns (reported, never cut)
    #>
    param(
        [Parameter(Mandatory)]$Set,
        [hashtable]$Index = @{},
        [hashtable]$EvidenceProfiles = @{},
        [int]$MaxKeyLength = 256
    )
    $joinable = @{}; foreach ($t in @(Get-SIJoinableIdTypes)) { $joinable[(Get-SICanonicalIdType -Type $t).ToLowerInvariant()] = $true }
    $evidence = New-Object System.Collections.Generic.List[object]
    $conflicts = New-Object System.Collections.Generic.List[object]
    $correlation = New-Object System.Collections.Generic.List[object]
    $skipped = 0
    $byName = @{}   # short name -> @(AssetKey) for possible duplicates (endpoints and Azure VMs only)
    $assetOf = @{}; foreach ($a in @($Set.Assets)) { $assetOf[[string]$a.AssetKey] = $a }

    foreach ($a in @($Set.Assets)) {
        $key = [string]$a.AssetKey
        $members = @()
        if ($Set.Members -and $Set.Members.ContainsKey($key)) { $members = @($Set.Members[$key]) }
        if ($members.Count -eq 0) { continue }
        $multi = $members.Count -gt 1
        $rows = New-Object System.Collections.Generic.List[object]
        $seen = @{}
        $names = @(); $oses = @(); $domains = @(); $cmdbIds = @()
        $cmdbState = $null; $cmdbSource = $null; $cmdbId = $null
        $hasExactJoin = $false; $hasGraphJoin = $false; $unresolved = $false
        $isVm = $false
        foreach ($m in $members) {
            $aid = [string]$m.SIAssetId; $la = $aid.ToLowerInvariant()
            $e = $Index[$la]
            $p = $EvidenceProfiles[$la]
            $kind = [string]$m.Kind
            if (-not $kind -and $e) { $kind = [string]$e.Engine }
            $profiled = [bool]$m.Profiled
            if (-not $profiled -and -not $e) { $kind = 'finding' }
            if (-not $kind) { $kind = 'finding' }
            # the record's own confidence: a lone record is exact; a joined one is as good as the engine's join
            $recConf = 'exact'
            if ($multi -and $e) {
                switch ([string]$e.JoinConfidence) { 'graph-inferred' { $recConf = 'strong' } default { $recConf = 'exact' } }
            }
            $recSeen = $null; if ($p) { try { $recSeen = ConvertTo-SIDataUtc $p.CollectionTime } catch { $recSeen = $null } }
            if ($null -eq $recSeen) { $recSeen = $m.LastSeen }
            $mdeSeen = $null; $egSeen = $null
            if ($p) {
                try { $mdeSeen = ConvertTo-SIDataUtc $p.MdeLastSeen } catch { $mdeSeen = $null }
                try { $egSeen = ConvertTo-SIDataUtc $p.EgLastSeen } catch { $egSeen = $null }
            }
            # the keys: what the record reports (with its source), what the correlation map knows (with the join basis)
            $keys = New-Object System.Collections.Generic.List[object]
            $kseen = @{}
            $addKey = {
                param([string]$type, [string]$value, [string]$said, [bool]$joinKey)
                $type = Get-SICanonicalIdType -Type $type
                $value = $value.Trim().ToLowerInvariant()
                if (-not $type -or -not $value) { return }
                $kk = $type.ToLowerInvariant() + '|' + $value
                if ($kseen.ContainsKey($kk)) { if ($joinKey) { $kseen[$kk].IsJoinKey = $true }; if ($said -and -not $kseen[$kk].Said) { $kseen[$kk].Said = $said }; return }
                $o = [pscustomobject]@{ Type = $type; Value = $value; Said = $said; IsJoinKey = $joinKey }
                $kseen[$kk] = $o; $keys.Add($o)
            }
            if ($p) { foreach ($x in (ConvertFrom-SIEvidenceEntityIds -EntityIds $p.EntityIds)) { & $addKey $x.Type $x.Id $x.Source $false } }
            if ($e) { foreach ($i in $e.Identifiers) { & $addKey ([string]$i.Type) ([string]$i.Value) '' ([bool]$i.IsJoinBasis -and $multi) } }
            if ($p) {
                if ([string]$p.OnPremSid) { & $addKey 'SecurityIdentifier' ([string]$p.OnPremSid) 'ad' $false }
                if ([string]$p.OnPremObjectGuid) { & $addKey 'OnPremObjectGuid' ([string]$p.OnPremObjectGuid) 'ad' $false }
            }
            if ($keys.Count -eq 0) { & $addKey 'SI_AssetId' $aid '' $false }
            if (-not $profiled -and -not $e) { $unresolved = $true }
            foreach ($k in $keys) {
                $src = Get-SIEvidenceSource -Said $k.Said -KeyType $k.Type -RecordKind $kind
                if ($kind -eq 'finding') { $src = 'Risk Analysis' }
                if ($k.IsJoinKey) {
                    if ($k.Type -ieq 'ExposureGraphNodeId') { $rule = 'graph-link'; $conf = 'strong'; $hasGraphJoin = $true }
                    else { $rule = 'exact-id'; $conf = 'exact'; $hasExactJoin = $true }
                } elseif ($kind -eq 'finding') { $rule = 'unresolved'; $conf = 'weak' }
                else { $rule = 'same-record'; $conf = $recConf }
                $srcSeen = $null
                if ($src -eq 'Defender') { $srcSeen = $mdeSeen } elseif ($src -eq 'Exposure Graph') { $srcSeen = $egSeen }
                if ($k.Value.Length -gt $MaxKeyLength -or $k.Type.Length -gt 64 -or $aid.Length -gt 400) { $skipped++; continue }
                $rk = $la + '|' + $k.Type.ToLowerInvariant() + '|' + $k.Value
                if ($seen.ContainsKey($rk)) { continue }
                $seen[$rk] = $true
                $rows.Add([pscustomobject]@{ AssetKey = $key; Source = $src; RecordKind = $kind; MemberAssetId = $aid; KeyType = $k.Type; KeyValue = $k.Value
                    MatchRule = $rule; Confidence = $conf; IsJoinKey = [bool]$k.IsJoinKey; SourceLastSeen = $srcSeen; RecordSeenAt = $recSeen })
                if ($k.Type -ieq 'AzureResourceId' -and $k.Value -match '/providers/microsoft\.compute/virtualmachines/') { $isVm = $true }
            }
            # the CMDB / ServiceNow verdict on this record
            if ($p) {
                $csrc = ([string]$p.CmdbSource).Trim().ToLowerInvariant()
                if ($csrc -eq 'servicenow' -or $csrc -eq 'generic-csv') {
                    $st = ([string]$p.CmdbMatchState).Trim().ToLowerInvariant()
                    $cr = ConvertTo-SIEvidenceCmdbRule -State $st -Phase ([string]$p.CmdbMatchPhase)
                    if ($cr -and [string]$p.CmdbId) {
                        $cmdbState = 'matched'; $cmdbSource = $csrc; if (-not $cmdbId) { $cmdbId = ([string]$p.CmdbId).Trim() }
                        $cmdbIds += ([string]$p.CmdbId).Trim().ToLowerInvariant()
                        $csName = 'CMDB'; if ($csrc -eq 'servicenow') { $csName = 'ServiceNow' }
                        $cv = ([string]$p.CmdbId).Trim()
                        if ($cv.Length -le $MaxKeyLength) {
                            $rows.Add([pscustomobject]@{ AssetKey = $key; Source = $csName; RecordKind = $kind; MemberAssetId = $aid; KeyType = 'CmdbId'; KeyValue = $cv.ToLowerInvariant()
                                MatchRule = $cr.Rule; Confidence = $cr.Confidence; IsJoinKey = $false; SourceLastSeen = $null; RecordSeenAt = $recSeen })
                        } else { $skipped++ }
                    } elseif ($st -eq 'stale-cache') { if ($cmdbState -ne 'matched') { $cmdbState = 'stale'; $cmdbSource = $csrc } }
                    elseif ($st) { if (-not $cmdbState) { $cmdbState = 'si-only'; $cmdbSource = $csrc } }
                }
            }
            # the values records can disagree on
            $nm = [string]$m.Name; if (-not $nm -and $p) { $nm = [string]$p.Hostname }
            if ($kind -ne 'finding' -and $kind -ne 'publicip' -and (Get-SIEvidenceShortName $nm)) { $names += [pscustomobject]@{ Member = $aid; Kind = $kind; Value = $nm; Cmp = (Get-SIEvidenceShortName $nm) } }
            if ($p -and [string]$p.OsPlatform) { $oses += [pscustomobject]@{ Member = $aid; Kind = $kind; Value = [string]$p.OsPlatform; Cmp = ([string]$p.OsPlatform).Trim().ToLowerInvariant() } }
            $dom = ''
            if ($p -and [string]$p.OnPremDomainName) { $dom = [string]$p.OnPremDomainName }
            elseif ($p -and ([string]$p.Hostname).Contains('.')) { $dom = (([string]$p.Hostname) -split '\.', 2)[1] }
            if ($dom) { $domains += [pscustomobject]@{ Member = $aid; Kind = $kind; Value = $dom; Cmp = $dom.Trim().ToLowerInvariant() } }
        }
        foreach ($r in $rows) { $evidence.Add($r) }

        # conflicts: a field with two or more different values across the CI's records. A row's source is the record's
        # own primary system (its first key's source, said as the customer knows it).
        $nConf = 0
        $recSource = @{}
        foreach ($r in $rows) { if (-not $recSource.ContainsKey($r.MemberAssetId) -and $r.Source -notin @('SecurityInsight', 'CMDB', 'ServiceNow')) { $recSource[$r.MemberAssetId] = $r.Source } }
        foreach ($f in @(@('Name', $names), @('OS', $oses), @('Domain', $domains))) {
            $vals = @($f[1])
            if (@($vals | ForEach-Object { $_.Cmp } | Sort-Object -Unique).Count -lt 2) { continue }
            $nConf++
            foreach ($v in $vals) {
                $src = 'SecurityInsight'; if ($recSource.ContainsKey($v.Member)) { $src = $recSource[$v.Member] }
                $conflicts.Add([pscustomobject]@{ AssetKey = $key; Field = $f[0]; Source = $src; MemberAssetId = $v.Member; Value = $v.Value })
            }
        }
        if (@($cmdbIds | Sort-Object -Unique).Count -ge 2) {
            $nConf++
            foreach ($r in @($rows | Where-Object { $_.KeyType -eq 'CmdbId' })) { $conflicts.Add([pscustomobject]@{ AssetKey = $key; Field = 'CMDB CI'; Source = $r.Source; MemberAssetId = $r.MemberAssetId; Value = $r.KeyValue }) }
        }

        $srcs = @($rows | Where-Object { $_.Source -notin @('CMDB', 'ServiceNow') } | ForEach-Object { $_.Source } | Sort-Object -Unique)
        if ($srcs.Count -gt 1) { $srcs = @($srcs | Where-Object { $_ -ne 'SecurityInsight' }) }
        $join = 'single-record'
        if ($unresolved -and -not $multi) { $join = 'unresolved' }
        elseif ($multi) { if ($hasExactJoin) { $join = 'exact-id' } elseif ($hasGraphJoin) { $join = 'graph-link' } else { $join = 'exact-id' } }
        $correlation.Add([pscustomobject]@{ AssetKey = $key; AssetName = [string]$a.AssetName; AssetKind = [string]$a.AssetKind; Tier = $a.Tier
            Records = $members.Count; SourceCount = $srcs.Count; Sources = ($srcs -join '; ')
            Confidence = (Get-SIEvidenceWeakest -Values @($rows | Where-Object { $_.Source -notin @('CMDB', 'ServiceNow') } | ForEach-Object { $_.Confidence })); JoinRule = $join
            Conflicts = $nConf; IdChanges = 0; PossibleDuplicateOf = $null; CmdbState = $cmdbState; CmdbSource = $cmdbSource; CmdbId = $cmdbId })
        $sn = Get-SIEvidenceShortName ([string]$a.AssetName)
        if ($sn -and ([string]$a.AssetKind -eq 'endpoint' -or ([string]$a.AssetKind -eq 'azure' -and $isVm))) {
            if (-not $byName.ContainsKey($sn)) { $byName[$sn] = New-Object System.Collections.Generic.List[string] }
            $byName[$sn].Add($key)
        }
    }

    # possible duplicates: two CIs with the same host name and no shared durable id (they would be ONE CI otherwise)
    $corrOf = @{}; foreach ($c in $correlation) { $corrOf[$c.AssetKey] = $c }
    foreach ($n in @($byName.Keys)) {
        $keysOf = @($byName[$n] | Sort-Object)
        if ($keysOf.Count -lt 2) { continue }
        foreach ($k in $keysOf) {
            $other = @($keysOf | Where-Object { $_ -ne $k })[0]
            $corrOf[$k].PossibleDuplicateOf = $other
            $oname = [string]$assetOf[$other].AssetName; if (-not $oname) { $oname = $other }
            $conflicts.Add([pscustomobject]@{ AssetKey = $k; Field = 'Possible duplicate'; Source = 'SecurityInsight'; MemberAssetId = $other; Value = $oname })
        }
    }
    [pscustomobject]@{ Evidence = $evidence.ToArray(); Conflicts = $conflicts.ToArray(); Correlation = $correlation.ToArray(); Skipped = $skipped }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE SQL (fixed text; every value a parameter or OPENJSON)
# ------------------------------------------------------------------------------------------------------------------

function Get-SIDataEvidenceSchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.AssetEvidence') IS NOT NULL AND OBJECT_ID('sidata.AssetIdHistory') IS NOT NULL AND OBJECT_ID('sidata.AssetConflict') IS NOT NULL AND OBJECT_ID('sidata.AssetCorrelation') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'CorrelatedAt') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataEvidenceUpsertSql {
    <# One chunk of evidence rows: a known row (same CI, record, key) is refreshed and stamped with this load; a new one is added. #>
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @e TABLE (AssetKey nvarchar(400), H binary(32), Source nvarchar(32), RecordKind nvarchar(16), MemberAssetId nvarchar(400), KeyType nvarchar(64),
                  KeyValue nvarchar(256), MatchRule nvarchar(24), Confidence nvarchar(8), IsJoinKey bit, SourceLastSeen datetime2(3), RecordSeenAt datetime2(3));
INSERT @e SELECT j.AssetKey, HASHBYTES('SHA2_256', LOWER(j.MemberAssetId) + N'|' + j.KeyType + N'|' + j.KeyValue), j.Source, j.RecordKind, j.MemberAssetId, j.KeyType,
       j.KeyValue, j.MatchRule, j.Confidence, j.IsJoinKey, TRY_CONVERT(datetime2(3), j.SourceLastSeen, 126), TRY_CONVERT(datetime2(3), j.RecordSeenAt, 126)
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), Source nvarchar(32), RecordKind nvarchar(16), MemberAssetId nvarchar(400), KeyType nvarchar(64), KeyValue nvarchar(256),
                        MatchRule nvarchar(24), Confidence nvarchar(8), IsJoinKey bit, SourceLastSeen nvarchar(40), RecordSeenAt nvarchar(40)) j;
UPDATE t SET Source = s.Source, RecordKind = s.RecordKind, MatchRule = s.MatchRule, Confidence = s.Confidence, IsJoinKey = s.IsJoinKey,
             SourceLastSeen = COALESCE(s.SourceLastSeen, t.SourceLastSeen), RecordSeenAt = COALESCE(s.RecordSeenAt, t.RecordSeenAt),
             FirstSeen = CASE WHEN CONVERT(datetime2(3), @SeenAt, 126) < t.FirstSeen THEN CONVERT(datetime2(3), @SeenAt, 126) ELSE t.FirstSeen END,
             LastSeen = CASE WHEN CONVERT(datetime2(3), @SeenAt, 126) > t.LastSeen THEN CONVERT(datetime2(3), @SeenAt, 126) ELSE t.LastSeen END,
             LastLoadId = @LoadId
FROM sidata.AssetEvidence t JOIN @e s ON s.AssetKey = t.AssetKey AND s.H = t.EvidenceHash;
INSERT sidata.AssetEvidence (AssetKey, EvidenceHash, Source, RecordKind, MemberAssetId, KeyType, KeyValue, MatchRule, Confidence, IsJoinKey, SourceLastSeen, RecordSeenAt,
                             FirstSeen, LastSeen, FirstLoadId, LastLoadId)
SELECT s.AssetKey, s.H, s.Source, s.RecordKind, s.MemberAssetId, s.KeyType, s.KeyValue, s.MatchRule, s.Confidence, s.IsJoinKey, s.SourceLastSeen, s.RecordSeenAt,
       CONVERT(datetime2(3), @SeenAt, 126), CONVERT(datetime2(3), @SeenAt, 126), @LoadId, @LoadId
FROM @e s WHERE NOT EXISTS (SELECT 1 FROM sidata.AssetEvidence t WHERE t.AssetKey = s.AssetKey AND t.EvidenceHash = s.H);
COMMIT;
SELECT COUNT(*) FROM @e;
'@
}

function Get-SIDataEvidenceHistorySql {
    <#
        After every evidence chunk of one load (@LoadId): what moved, recorded once each, returned as rows (AssetKey,
        EventType). Durable keys only (-DurableTypes: the joinable identifier types, plus SI_AssetId for the identifier
        ledger), so a host name or an IP that moves is never an id change.
          alias  a durable key of this CI is on a record that is new in this load, and was on another record of the SAME
                 CI that is not in this load any more
          rekey / merge  a durable key this load put on CI B was on CI A in an earlier load (evidence, or the identifier
                 ledger sidata.AssetIdentifier -- so a database with history before the evidence existed shows it from the
                 first load), and A is not in this load: merge when B already existed before, else rekey
    #>
    param([Parameter(Mandatory)][string[]]$DurableTypes)
    $list = (@($DurableTypes | Where-Object { $_ -match '^[A-Za-z_]+$' } | Sort-Object -Unique) | ForEach-Object { "N'" + $_ + "'" }) -join ', '
    if (-not $list) { throw 'no durable identifier types' }
    @"
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @h TABLE (AssetKey nvarchar(400), EventType nvarchar(8), PreviousId nvarchar(400), CurrentId nvarchar(400), ViaType nvarchar(64), ViaValue nvarchar(256));
DECLARE @now TABLE (AssetKey nvarchar(400) PRIMARY KEY);
INSERT @now SELECT DISTINCT e.AssetKey FROM sidata.AssetEvidence e WHERE e.LastLoadId = @LoadId;
INSERT @h
SELECT x.AssetKey, N'alias', x.PreviousId, x.CurrentId, x.KeyType, x.KeyValue FROM (
    SELECT n.AssetKey, o.MemberAssetId AS PreviousId, n.MemberAssetId AS CurrentId, n.KeyType, n.KeyValue,
           ROW_NUMBER() OVER (PARTITION BY n.AssetKey, o.MemberAssetId ORDER BY n.KeyType, n.MemberAssetId) AS rn
    FROM sidata.AssetEvidence n
    JOIN sidata.AssetEvidence o ON o.AssetKey = n.AssetKey AND o.KeyType = n.KeyType AND o.KeyValue = n.KeyValue AND o.MemberAssetId <> n.MemberAssetId
    WHERE n.LastLoadId = @LoadId AND n.FirstLoadId = @LoadId AND o.LastLoadId < @LoadId AND n.KeyType IN ($list)
      AND NOT EXISTS (SELECT 1 FROM sidata.AssetEvidence z WHERE z.AssetKey = o.AssetKey AND z.MemberAssetId = o.MemberAssetId AND z.LastLoadId = @LoadId)
) AS x WHERE x.rn = 1;
INSERT @h
SELECT x.AssetKey, CASE WHEN x.Existed = 1 THEN N'merge' ELSE N'rekey' END, x.PreviousId, x.AssetKey, x.KeyType, x.KeyValue FROM (
    SELECT n.AssetKey, o.AssetKey AS PreviousId, n.KeyType, n.KeyValue,
           CASE WHEN EXISTS (SELECT 1 FROM sidata.AssetEvidence y WHERE y.AssetKey = n.AssetKey AND y.FirstLoadId < @LoadId)
                  OR EXISTS (SELECT 1 FROM sidata.AssetIdentifier y WHERE y.AssetKey = n.AssetKey AND y.FirstSeen < CONVERT(datetime2(3), @SeenAt, 126)) THEN 1 ELSE 0 END AS Existed,
           ROW_NUMBER() OVER (PARTITION BY n.AssetKey, o.AssetKey ORDER BY n.KeyType, n.KeyValue) AS rn
    FROM sidata.AssetEvidence n
    JOIN (SELECT a.AssetKey, a.KeyType, a.KeyValue FROM sidata.AssetEvidence a WHERE a.LastLoadId < @LoadId
          UNION
          SELECT i.AssetKey, i.IdentifierType, i.IdentifierValue FROM sidata.AssetIdentifier i) AS o
      ON o.KeyType = n.KeyType AND o.KeyValue = n.KeyValue AND o.AssetKey <> n.AssetKey
    WHERE n.LastLoadId = @LoadId AND n.KeyType IN ($list)
      AND NOT EXISTS (SELECT 1 FROM @now w WHERE w.AssetKey = o.AssetKey)
) AS x WHERE x.rn = 1;
INSERT sidata.AssetIdHistory (AssetKey, EventType, PreviousId, CurrentId, ViaType, ViaValue, DetectedAt, LoadId)
OUTPUT inserted.AssetKey, inserted.EventType
SELECT h.AssetKey, h.EventType, h.PreviousId, h.CurrentId, h.ViaType, h.ViaValue, CONVERT(datetime2(3), @SeenAt, 126), @LoadId
FROM (SELECT AssetKey, EventType, PreviousId, CurrentId, ViaType, ViaValue,
             ROW_NUMBER() OVER (PARTITION BY AssetKey, EventType, PreviousId ORDER BY ViaType, ViaValue) AS rn FROM @h) AS h
WHERE h.rn = 1
  AND NOT EXISTS (SELECT 1 FROM sidata.AssetIdHistory t WHERE t.AssetKey = h.AssetKey AND t.EventType = h.EventType AND t.PreviousId = h.PreviousId);
COMMIT;
"@
}

function Get-SIDataEvidenceConflictSql {
    <# One chunk of conflict rows: a known one (same CI, field, source, record) is refreshed and stamped with this load; a new one is added. #>
    @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @c TABLE (AssetKey nvarchar(400), H binary(32), Field nvarchar(32), Source nvarchar(32), MemberAssetId nvarchar(400), Value nvarchar(400));
INSERT @c SELECT j.AssetKey, HASHBYTES('SHA2_256', j.Field + N'|' + j.Source + N'|' + LOWER(j.MemberAssetId)), j.Field, j.Source, j.MemberAssetId, LEFT(j.Value, 400)
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), Field nvarchar(32), Source nvarchar(32), MemberAssetId nvarchar(400), Value nvarchar(max)) j;
UPDATE t SET Value = s.Value,
             FirstSeen = CASE WHEN CONVERT(datetime2(3), @SeenAt, 126) < t.FirstSeen THEN CONVERT(datetime2(3), @SeenAt, 126) ELSE t.FirstSeen END,
             LastSeen = CASE WHEN CONVERT(datetime2(3), @SeenAt, 126) > t.LastSeen THEN CONVERT(datetime2(3), @SeenAt, 126) ELSE t.LastSeen END,
             LastLoadId = @LoadId
FROM sidata.AssetConflict t JOIN @c s ON s.AssetKey = t.AssetKey AND s.H = t.ConflictHash;
INSERT sidata.AssetConflict (AssetKey, ConflictHash, Field, Source, MemberAssetId, Value, FirstSeen, LastSeen, FirstLoadId, LastLoadId)
SELECT s.AssetKey, s.H, s.Field, s.Source, s.MemberAssetId, s.Value, CONVERT(datetime2(3), @SeenAt, 126), CONVERT(datetime2(3), @SeenAt, 126), @LoadId, @LoadId
FROM @c s WHERE NOT EXISTS (SELECT 1 FROM sidata.AssetConflict t WHERE t.AssetKey = s.AssetKey AND t.ConflictHash = s.H);
COMMIT;
SELECT COUNT(*) FROM @c;
'@
}

function Get-SIDataEvidenceCorrelationSql {
    <# One chunk of the collection's per-CI correlation rows (the collection is new, or was cleared before a re-run). #>
    @'
INSERT sidata.AssetCorrelation (CollectionId, AssetKey, AssetName, AssetKind, Tier, Records, SourceCount, Sources, Confidence, JoinRule, Conflicts, IdChanges,
                                PossibleDuplicateOf, CmdbState, CmdbSource, CmdbId)
SELECT @LoadId, j.AssetKey, NULLIF(j.AssetName, ''), NULLIF(j.AssetKind, ''), j.Tier, j.Records, j.SourceCount, NULLIF(j.Sources, ''), j.Confidence, j.JoinRule,
       j.Conflicts, j.IdChanges, j.PossibleDuplicateOf, j.CmdbState, j.CmdbSource, j.CmdbId
FROM OPENJSON(@j) WITH (AssetKey nvarchar(400), AssetName nvarchar(400), AssetKind nvarchar(16), Tier tinyint, Records int, SourceCount int, Sources nvarchar(400),
                        Confidence nvarchar(8), JoinRule nvarchar(24), Conflicts int, IdChanges int, PossibleDuplicateOf nvarchar(400), CmdbState nvarchar(12),
                        CmdbSource nvarchar(16), CmdbId nvarchar(256)) j;
SELECT @@ROWCOUNT;
'@
}

function Get-SIDataEvidenceClearCorrelationSql {
    'DELETE FROM sidata.AssetCorrelation WHERE CollectionId = @LoadId; SELECT @@ROWCOUNT;'
}

function Get-SIDataEvidenceStampSql {
    'UPDATE sidata.Collection SET CorrelatedAt = SYSUTCDATETIME() WHERE CollectionId = @LoadId; SELECT @@ROWCOUNT;'
}

# ------------------------------------------------------------------------------------------------------------------
#  THE WRITE OF ONE LOAD
# ------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataEvidence {
    <#
        Writes the correlation evidence of one loaded collection (-CollectionId, its -CollectionTime): evidence rows, the id
        history found by this load, conflicts, and the per-CI correlation rows; then stamps Collection.CorrelatedAt.
        Returns @{ Evidence; History; Aliases; Rekeys; Merges; Conflicts; Correlation; Skipped }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter(Mandatory)]$Set,
        [Parameter(Mandatory)][int]$CollectionId,
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [hashtable]$Index = @{},
        [hashtable]$EvidenceProfiles = @{},
        [ref]$ChunkChars,
        [scriptblock]$Log
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    if (-not $ChunkChars) { $chunkLocal = [long]0; $ChunkChars = [ref]$chunkLocal }
    $built = Build-SIDataEvidence -Set $Set -Index $Index -EvidenceProfiles $EvidenceProfiles
    $seenAt = Format-SIDataSqlTime -Time $CollectionTime
    $base = @{ LoadId = $CollectionId; SeenAt = $seenAt }

    $evItems = @($built.Evidence | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; Source = $_.Source; RecordKind = $_.RecordKind
        MemberAssetId = $_.MemberAssetId; KeyType = $_.KeyType; KeyValue = $_.KeyValue; MatchRule = $_.MatchRule; Confidence = $_.Confidence; IsJoinKey = [bool]$_.IsJoinKey
        SourceLastSeen = $_.SourceLastSeen; RecordSeenAt = $_.RecordSeenAt }) })
    $nEv = Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataEvidenceUpsertSql) -Items $evItems -Params $base -ChunkChars $ChunkChars -What 'correlation evidence'

    # the id history this load reveals -- after EVERY evidence row of the load is stamped
    $durable = @(@(Get-SIJoinableIdTypes | ForEach-Object { Get-SICanonicalIdType -Type $_ }) + 'SI_AssetId')
    $histRaw = & $Invoke (Get-SIDataEvidenceHistorySql -DurableTypes $durable) $base 'reader'
    $hist = @(@($histRaw) | Where-Object { $_ })
    $changes = @{}
    $count = @{ alias = 0; rekey = 0; merge = 0 }
    foreach ($h in $hist) {
        $k = [string]$h['AssetKey']; $t = [string]$h['EventType']
        if (-not $changes.ContainsKey($k)) { $changes[$k] = 0 }
        $changes[$k]++
        if ($count.ContainsKey($t)) { $count[$t]++ }
    }

    $cfItems = @($built.Conflicts | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; Field = $_.Field; Source = $_.Source
        MemberAssetId = $_.MemberAssetId; Value = $_.Value }) })
    $nCf = 0L
    if ($cfItems.Count -gt 0) { $nCf = Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataEvidenceConflictSql) -Items $cfItems -Params $base -ChunkChars $ChunkChars -What 'correlation conflicts' }

    foreach ($c in $built.Correlation) { if ($changes.ContainsKey([string]$c.AssetKey)) { $c.IdChanges = [int]$changes[[string]$c.AssetKey] } }
    [void](& $Invoke (Get-SIDataEvidenceClearCorrelationSql) @{ LoadId = $CollectionId } 'scalar')
    $coItems = @($built.Correlation | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; AssetName = $_.AssetName; AssetKind = $_.AssetKind
        Tier = $_.Tier; Records = [int]$_.Records; SourceCount = [int]$_.SourceCount; Sources = $_.Sources; Confidence = $_.Confidence; JoinRule = $_.JoinRule
        Conflicts = [int]$_.Conflicts; IdChanges = [int]$_.IdChanges; PossibleDuplicateOf = $_.PossibleDuplicateOf; CmdbState = $_.CmdbState; CmdbSource = $_.CmdbSource; CmdbId = $_.CmdbId }) })
    $nCo = Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataEvidenceCorrelationSql) -Items $coItems -Params @{ LoadId = $CollectionId } -ChunkChars $ChunkChars -What 'correlation per CI'
    $stamped = [int](& $Invoke (Get-SIDataEvidenceStampSql) @{ LoadId = $CollectionId } 'scalar')
    if ($stamped -ne 1) { throw ("the correlation evidence of collection {0} could not be stamped" -f $CollectionId) }
    if ($built.Skipped -gt 0) { & $Log 'WARN' ("  {0} correlation key(s) are longer than the evidence columns and were not stored" -f $built.Skipped) }

    $multi = @($built.Correlation | Where-Object { $_.SourceCount -ge 2 }).Count
    $weak = @($built.Correlation | Where-Object { $_.Confidence -eq 'weak' }).Count
    $withConflict = @($built.Correlation | Where-Object { $_.Conflicts -gt 0 }).Count
    $dups = @($built.Correlation | Where-Object { $_.PossibleDuplicateOf }).Count
    & $Log 'OK' ("  correlation : {0} CI(s), {1} seen by two or more sources, {2} weak match(es), {3} with a conflict, {4} possible duplicate(s); id changes found: {5} alias, {6} re-key, {7} merge" -f `
        $nCo, $multi, $weak, $withConflict, $dups, $count.alias, $count.rekey, $count.merge)
    [pscustomobject]@{ Evidence = $nEv; History = $hist.Count; Aliases = $count.alias; Rekeys = $count.rekey; Merges = $count.merge; Conflicts = $nCf; Correlation = $nCo; Skipped = $built.Skipped }
}

function Read-SIDataEvidenceProfiles {
    <#
        Reads the evidence columns of every profile table once per run (-ReadOrSkip: the sync's reader that turns a missing
        table into $null). Returns lower(SI_AssetId) -> row (+ Kind).
    #>
    param([Parameter(Mandatory)][scriptblock]$ReadOrSkip)
    $out = @{}
    foreach ($pair in @(@('endpoint', 'SI_Endpoint_Profile_CL'), @('identity', 'SI_Identity_Profile_CL'), @('azure', 'SI_Azure_Profile_CL'), @('publicip', 'SI_PublicIP_Profile_CL'))) {
        $rows = & $ReadOrSkip (Get-SIDataEvidenceProfileKql -TableName $pair[1]) $pair[1]
        foreach ($r in @($rows)) {
            if ($null -eq $r -or -not [string]$r.SI_AssetId) { continue }
            $o = [pscustomobject]@{ Kind = $pair[0]; SI_AssetId = [string]$r.SI_AssetId; CollectionTime = $r.CollectionTime; EntityIds = [string]$r.EntityIds
                Hostname = [string]$r.Hostname; OsPlatform = [string]$r.OsPlatform; OnPremDomainName = [string]$r.OnPremDomainName; OnPremSid = [string]$r.OnPremSid
                OnPremObjectGuid = [string]$r.OnPremObjectGuid; MdeLastSeen = [string]$r.MdeLastSeen; EgLastSeen = [string]$r.EgLastSeen; CmdbId = [string]$r.CmdbId
                CmdbSource = [string]$r.CmdbSource; CmdbMatchState = [string]$r.CmdbMatchState; CmdbMatchPhase = [string]$r.CmdbMatchPhase }
            $out[([string]$r.SI_AssetId).ToLowerInvariant()] = $o
        }
    }
    $out
}
