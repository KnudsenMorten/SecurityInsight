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
      1. the newest snapshot whose marker is there and that holds at least that many distinct keys (an EXACT count);
      2. else the newest snapshot from before the first marker (published before 3.1.52);
      3. else the newest snapshot there is -- NEVER no snapshot while one is there: an empty answer would read as every
         recommendation fixed.
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
    | join kind=inner ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime, _siK = $k | summarize _siN = count() by CollectionTime) on CollectionTime
    | where _siN >= _siExp | project CollectionTime, _siP = 1)
    | union ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime
        | extend _siFm = toscalar($Source | where $m | where isnotempty(CollectionTime) | summarize min(CollectionTime))
        | where isnull(_siFm) or CollectionTime < _siFm | project CollectionTime, _siP = 2)
    | union ($Source | where $r | where isnotempty(CollectionTime) | summarize by CollectionTime | project CollectionTime, _siP = 3)
    | summarize arg_max(CollectionTime, *) by _siP
    | summarize arg_min(_siP, CollectionTime)
    | project CollectionTime)
"@
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
