#Requires -Version 5.1
<#
    #1399 THE ONE ACCEPTED-SNAPSHOT RULE FOR SI_AzureRecommendation_CL (the two-agent review of 9c8b49a87: "make every reader use the
    same accepted-snapshot rule -- one definition"). Every reader of the Defender for Cloud recommendations -- the two Risk
    Analysis Defender recommendation reports, the graph reports' Defender hand-off (_dfcPairs), the in-engine Defender filter
    (RA-DefenderFilter.ps1) and the data sync (SI-DataKql.ps1) -- takes its snapshot and its rows from THESE functions; the
    locked report catalog carries their output between //__SI_REC_SNAPSHOT_BEGIN__ and //__SI_REC_SNAPSHOT_END__, and
    tests\pester\SIv3-MemoryStream.Tests.ps1 proves every such block is exactly what they write.

    THE RULE (Invoke-SIRecommendations posts the rows of a snapshot, then its 'SnapshotComplete' marker with the number of
    distinct keys it holds):
      1. the newest snapshot whose marker is there and that holds at least that many distinct keys (an EXACT count) -- a
         marker of 0 (#1416 (c): a complete read that found no unhealthy recommendation) is a snapshot of no rows: all fixed;
      2. else the newest snapshot from before the first marker (published before 3.1.52);
      3. else the newest snapshot there is -- NEVER no snapshot while one is there: an empty answer would read as every
         recommendation fixed. #1416 (a): such a snapshot is NOT complete and is never presented as whole -- every reader
         asks which step took its snapshot (Get-SIAzureRecPartialKql / Get-SIAzureRecPartialReason): a Risk Analysis report
         that reads it ends not complete (its findings unknown for the run, not resolved: nothing is closed off it), the data
         sync says it.
    THE ROWS: one per key (resource id, row kind, primary entity id, assessment key) -- a snapshot posted twice (a retry, or
    every part of a run before 3.1.52) is never read twice; the marker row is never a row.
    PURE text. PowerShell 5.1 and 7.
#>

function Get-SIAzureRecKeyKql {
    <# PURE. The key of one row of SI_AzureRecommendation_CL: what makes it one row (and what the marker's count counts). #>
    'strcat(tostring(column_ifexists("PrimaryEntityId", "")), "|", tostring(column_ifexists("RowKind", "")), "|", tolower(tostring(column_ifexists("ResourceIdLower", ""))), "|", tolower(tostring(column_ifexists("AssessmentKey", ""))))'
}

function Get-SIAzureRecRowKey {
    <# PURE. The same key in PowerShell, for the marker's count (Invoke-SIRecommendations). #>
    param([Parameter(Mandatory)]$Row)
    $v = { param($n) $p = $Row.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' } }
    '{0}|{1}|{2}|{3}' -f (& $v 'PrimaryEntityId'), (& $v 'RowKind'), (& $v 'ResourceIdLower').ToLowerInvariant(), (& $v 'AssessmentKey').ToLowerInvariant()
}

function Get-SIAzureRecAcceptedTimeKql {
    <#
        PURE. The CollectionTime of the snapshot to read (the rule above), as ONE scalar expression over -Source (a tabular
        expression: a let name, or "(SI_AzureRecommendation_CL | where ...)") -- self-contained, so a binding the engine
        fetches on its own (_dfcPairs) carries it whole.
    #>
    param([Parameter(Mandatory)][string]$Source)
    $k = Get-SIAzureRecKeyKql
    $m = 'tostring(column_ifexists("RowKind", "")) == "SnapshotComplete"'
    $r = 'tostring(column_ifexists("RowKind", "")) != "SnapshotComplete"'
    @"
toscalar(($Source | where $m | where isnotempty(CollectionTime) | summarize _siExp = max(toint(column_ifexists("AffectedEntityCount", int(null)))) by CollectionTime
    | join kind=leftouter ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime, _siK = $k | summarize _siN = count() by CollectionTime) on CollectionTime
    | where coalesce(_siN, 0) >= _siExp | project CollectionTime, _siP = 1)
    | union ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime
        | extend _siFm = toscalar($Source | where $m | where isnotempty(CollectionTime) | summarize min(CollectionTime))
        | where isnull(_siFm) or CollectionTime < _siFm | project CollectionTime, _siP = 2)
    | union ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime | project CollectionTime, _siP = 3)
    | summarize arg_max(CollectionTime, *) by _siP
    | summarize arg_min(_siP, CollectionTime)
    | project CollectionTime)
"@
}

function Get-SIAzureRecAcceptedRuleKql {
    <#
        PURE. #1416 (a): the snapshot the rule above takes AND which of its three steps took it, as ONE tabular expression
        over -Source: one row (CollectionTime, SnapshotRule = 1 | 2 | 3), none when the table holds no snapshot at all. Made
        FROM Get-SIAzureRecAcceptedTimeKql's own text (its toscalar( ... | project CollectionTime) opened up), so the snapshot
        it names is always the one every reader reads -- one definition, never a copy.
          SnapshotRule 1 = a snapshot with its marker and every key it counts (complete);
                       2 = a snapshot from before the first marker (published before 3.1.52: read as whole, as before);
                       3 = the newest snapshot there is, NOT complete (no complete one is left in the window) -- the readers
                           never present it as whole (Get-SIAzureRecPartialReason).
    #>
    param([Parameter(Mandatory)][string]$Source)
    $t = (Get-SIAzureRecAcceptedTimeKql -Source $Source).TrimEnd()
    if (-not $t.StartsWith('toscalar(') -or -not $t.EndsWith('| project CollectionTime)')) { throw 'Get-SIAzureRecAcceptedRuleKql: the accepted-snapshot rule no longer has the shape this reads (toscalar( ... | project CollectionTime))' }
    $inner = $t.Substring('toscalar('.Length, $t.Length - 'toscalar('.Length - 1)
    $inner.Substring(0, $inner.Length - '| project CollectionTime'.Length) + '| project CollectionTime, SnapshotRule = _siP'
}

function Get-SIAzureRecPartialKql {
    <#
        PURE. #1416 (a): the one-row answer a reader asks before it reads the recommendations -- the accepted snapshot of
        SI_AzureRecommendation_CL over -LookbackDays (8, the window every reader reads) and its step (SnapshotRule). -AsOf:
        the snapshot in force at that collection time (the data sync's own window, Get-SIDataRecommendationsKql).
    #>
    param([int]$LookbackDays = 8, [object]$AsOf = $null)
    $until = ''
    if ($null -ne $AsOf -and [string]$AsOf -ne '') {
        # every fraction kept (7 digits, the data sync's own literal -- ConvertTo-SIDataKqlTime): a snapshot taken AT the
        # collection's time (a flow run gives every step its start time) must never be cut off by a rounded literal
        $lit = if (Get-Command -Name ConvertTo-SIDataKqlTime -ErrorAction SilentlyContinue) { ConvertTo-SIDataKqlTime -Time ([datetime]$AsOf) }
               else { 'datetime({0})' -f ([datetime]$AsOf).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture) }
        $until = ' | where CollectionTime <= {0}' -f $lit
    }
    $src = '(SI_AzureRecommendation_CL | where TimeGenerated > ago({0}d){1})' -f $LookbackDays, $until
    Get-SIAzureRecAcceptedRuleKql -Source $src
}

function Get-SIAzureRecPartialReason {
    <#
        PURE. #1416 (a): -Rows = the answer of Get-SIAzureRecPartialKql. '' when the snapshot every reader takes is whole (step
        1 or 2) or there is none; else the plain words for the step 3 case -- the newest snapshot is NOT complete and no
        complete one is left in the window. A reader never presents that snapshot as whole: Risk Analysis ends each report
        that reads it as not complete (its findings unknown, not resolved -- nothing is closed off it), the data sync says it.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows, [int]$LookbackDays = 8)
    # however a reader hands its rows over (one array, an array holding that array, or rows)
    $r = @(@($Rows) | ForEach-Object { $_ } | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    if ($null -eq $r) { return '' }
    # a row as an object (Log Analytics) or as a dictionary (a seam that hands hashtables)
    $val = { param($n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $rule = & $val 'SnapshotRule'
    if ($null -eq $rule -or $rule -is [System.DBNull] -or [string]$rule -eq '') { return '' }
    if ([int]$rule -ne 3) { return '' }
    $at = ''
    $tv = & $val 'CollectionTime'
    if ($null -ne $tv -and $tv -isnot [System.DBNull] -and [string]$tv -ne '') {
        try {
            $dt = if ($tv -is [datetime]) { ([datetime]$tv).ToUniversalTime() } else { [datetime]::Parse([string]$tv, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
            $at = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, ' (of {0:yyyy-MM-dd HH:mm} UTC)', $dt)
        } catch { $at = '' }
    }
    'the newest Defender for Cloud recommendation snapshot{0} is not complete, and no complete snapshot is left in the last {1} days' -f $at, $LookbackDays
}

function Get-SIAzureRecRowsKql {
    <# PURE. The rows of the snapshot at -Time (a scalar expression or let name) of -Source: one per key, never the marker. #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Time)
    @"
$Source
    | where CollectionTime == $Time and tostring(column_ifexists("RowKind", "")) != "SnapshotComplete"
    | extend _siTg = column_ifexists("TimeGenerated", datetime(null)), _siKey = $(Get-SIAzureRecKeyKql)
    | summarize arg_max(_siTg, *) by _siKey
    | project-away _siKey*, _siTg*
"@
}

function Get-SIAzureRecSnapshotBlocks {
    <#
        PURE. The generated blocks of the locked catalog, by the -Source they read: 'report' (the Defender recommendation
        reports' _recLatest + _rec over _recAll) and 'handoff' (the snapshot filter of _dfcPairs: its keys come from the same snapshot). Whitespace made one.
    #>
    $tbl = '(SI_AzureRecommendation_CL | where TimeGenerated > ago(8d))'
    [ordered]@{
        report  = ('let _recLatest = {0}; let _rec = {1}' -f (Get-SIAzureRecAcceptedTimeKql -Source '_recAll'), (Get-SIAzureRecRowsKql -Source '_recAll' -Time '_recLatest'))
        # the hand-off keeps its own shape (the engine fetches and cuts it); it reads the same snapshot
        handoff = ('| where CollectionTime == {0}' -f (Get-SIAzureRecAcceptedTimeKql -Source $tbl))
    }
}
