#Requires -Version 5.1
<#
    THE SUMMARY GROUPINGS, STORED PER COLLECTION (Pro; REQUIREMENTS #636 -- owner 2026-10-19: "summary could be build as views
    with the detailed data instead"). The data sync writes, once per complete Detailed collection, the groupings of
    data-model\summary-groupings.locked.json -- computed by THE engine function (engine\_shared\SI-SummaryGroupings.ps1
    Invoke-SISummaryGrouping -AsSql) from the collection's findings -- into sidata.SummaryGroup (every finding),
    sidata.SummaryGroupCounted (#264: without the exempted ones) and sidata.SummaryGroupState (built at, the definition's hash,
    how many groups). The grouped views page, sort and filter those typed, indexed rows -- never a GROUP BY over every finding
    per request, never a second Risk Analysis (the pattern of sidata.CveSummary, #767).
    EXISTING INSTALLS: the schema adds the tables (the updater applies sql\si-data-schema.sql); the next data sync fills every
    stored complete collection, newest first, within a time budget (the rest follow on the next runs). #1217 (live 2026-11-12,
    a large install: the Summary of the ONLY collection the web app listed -- the published one -- said "not built ... comes
    with the next data sync" for a day and would have kept saying it): a collection the web app can show is NEVER left to a
    later run -- the published collection, the complete one before it (the list and the comparison show it, the retention
    keeps it) and every complete collection newer than the published one (the run's own, published at the end of the run)
    are written first and the time budget never stops them; the budget paces only the older ones. Before, the budget let
    only the newest through when one collection took longer than the budget, so a published collection whose grouped rows
    were missed once (its prepared context failed that run) was passed over by every run after it. #1218 (owner 2026-11-12:
    "Last 7 runs"): the retention keeps the newest SI_Data_KeepCollections complete collections, so the shown set is the
    published one + the newest kept ones at or before it (TOP (that count)) + the newer ones. A collection is written
    again when it was derived or prepared again after its rows were built, or when the definition changed. Until a collection
    has its rows the grouped view says they are being prepared. The retention removes them with the collection
    (Get-SIDataPurgeCollectionSql). Never fails the data sync.
#>

if (-not (Get-Command -Name Invoke-SISummaryGrouping -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-SummaryGroupings.ps1'))
}

function Get-SIDataSummaryGroupsSchemaCheckSql {
    <# 1 when the database carries the three tables, every finding column the definition reads and the published collection's view (#1217); else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID('sidata.vPublishedCollection') IS NOT NULL AND OBJECT_ID('sidata.SummaryGroupCounted') IS NOT NULL AND OBJECT_ID('sidata.SummaryGroupState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'HasExploit') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskRating') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Category') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Subcategory') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ContextAt') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'MitreTactics') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'MitreTechniques') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ComplianceTags') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Cvss') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroupState', 'Groupings') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroup', 'AttributesJson') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroupCounted', 'AttributesJson') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'FixRemediation') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'SourceFirstDetected') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataSummaryGroupsPendingSql {
    <#
        Complete Detailed collections whose views' columns are derived (risk rating, exploit flag) and whose context is prepared
        (category, subcategory), and whose grouped rows are missing -- new loads and, once, every collection stored before the
        tables existed -- older than the derive or the prepared context, or built from another definition (@Hash). Never a
        retired collection.
        #1217 Shown = 1: a collection the web app can show -- the published one (sidata.vPublishedCollection) and the complete
        one before it, or one newer than the published one (the run's own, published at the end of the run). Those come first
        (newest first), then the rest, newest first; the caller never leaves a Shown one to a later run.
        #1218 -Keep: the web app can show every collection the retention keeps -- the newest -Keep complete ones at or before
        the published one are Shown (TOP (-Keep); at least 2; not given = 2, the old rule).
    #>
    param([int]$Keep = 2)
    $k = [Math]::Max(2, $Keep)
    $live = ''; $liveK = ''
    if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c'; $liveK = Get-SIDataLiveFilter -Alias 'k' }
    $pub = "(SELECT TOP (1) pc.CollectionTime FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed')"
    $shown = "CASE WHEN c.CollectionTime >= $pub OR c.CollectionId IN (SELECT TOP ($k) k.CollectionId FROM sidata.Collection AS k WHERE k.Status = 'Complete' AND k.Kind = 'Detailed'$liveK AND k.CollectionTime <= $pub ORDER BY k.CollectionTime DESC) THEN 1 ELSE 0 END"
    "SELECT c.CollectionId, c.CollectionTime, $shown AS Shown FROM sidata.Collection AS c LEFT JOIN sidata.SummaryGroupState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND c.ContextAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt OR s.BuiltAt < c.ContextAt OR s.DefinitionHash <> @Hash)$live ORDER BY Shown DESC, c.CollectionTime DESC"
}

function Get-SIDataSummaryGroupsSql {
    <# ONE collection (@CollectionId, @Hash): THE engine function's statement (Invoke-SISummaryGrouping -AsSql). #>
    param($Plan)
    Invoke-SISummaryGrouping -AsSql -Plan $Plan
}

function Invoke-SIDataSummaryGroups {
    <#
    .SYNOPSIS  Writes the grouped rows of every complete collection that has none (or older ones). Never throws.
    .NOTES     The collections the web app can show first (#1217: the run's own, the published one, the one before it --
               newest first), then the rest newest first. -BudgetSeconds: when the OTHER collections of an existing install
               take longer than this in one run, they follow on the next runs (said); it never stops a collection the web app
               can show. A pace, not a limit on the data: every finding of a collection is counted. Paced by the database's own
               load (SI-SqlPacing.ps1) when loaded.
               #1218 -Keep: how many complete collections the retention keeps (the data sync's count) -- the newest -Keep at or
               before the published one are shown, so built in this run however long it takes (paced, never skipped); with
               7 kept, the first run after the update builds up to 7 of them once each.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900, $Plan, [int]$Keep = 2)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (-not $Plan) { $Plan = Get-SISummaryGroupingPlan }
        if (([int](& $Invoke (Get-SIDataSummaryGroupsSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' 'groupings   : the database does not have the grouped Summary tables yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the grouped views say they are being prepared until then.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke (Get-SIDataSummaryGroupsPendingSql -Keep $Keep) @{ Hash = $Plan.Hash } 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
        if ($DryRun) {
            & $Log 'INFO' ("groupings   : {0} collection(s) would get their grouped Summary rows; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0; Groups = 0 } }
        $sql = Get-SIDataSummaryGroupsSql -Plan $Plan
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $done = 0; $groups = [long]0
        # #1180: collections done of all, said and recorded as the step's progress (at most every minute; a collection is
        # ONE statement, so this moves once per collection)
        $sgTick = $null
        if (Get-Command -Name New-SIStepProgressTicker -ErrorAction SilentlyContinue) { $sgTick = New-SIStepProgressTicker -What 'groupings   : the grouped Summary rows' -Unit 'collections' -Total ([long]$pending.Count) -Invoke $Invoke -Log $Log -EverySeconds 60 }
        foreach ($p in $pending) {
            # #1217 a collection the web app can show is never left to a later run: the budget paces only the others
            $sv = if ($p -is [System.Collections.IDictionary]) { $p['Shown'] } else { $p.Shown }
            $shown = ("$sv" -eq '1') -or ($sv -eq $true)
            if ($done -gt 0 -and -not $shown -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            if ($paced) { $null = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            # 2026-10-25 over this run's narrow findings (read ONCE, shared with the steps after) where they can be made
            $n = if (Get-Command -Name Invoke-SIDataNarrowOrWide -ErrorAction SilentlyContinue) { Invoke-SIDataNarrowOrWide -Invoke $Invoke -Sql $sql -Params @{ CollectionId = [int]$p['CollectionId']; Hash = $Plan.Hash } -Mode 'scalar' -CollectionId ([long]$p['CollectionId']) -What 'the grouped Summary rows' -Log $Log }
                  else { & $Invoke $sql @{ CollectionId = [int]$p['CollectionId']; Hash = $Plan.Hash } 'scalar' }
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            if ("$n" -match '^\d+$') { $groups += [long]"$n" }
            $done++
            if ($sgTick -and $done -lt $pending.Count) { $null = Step-SIStepProgressTicker -Ticker $sgTick -Done $done }
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("groupings   : {0} collection(s) got their grouped Summary rows ({1} group(s)) -- the grouped views read them" -f $done, $groups)
        if ($left -gt 0) { & $Log 'INFO' ("groupings   : {0} older collection(s) follow on the next run(s) -- their grouped views say they are being prepared until then" -f $left) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Groups = $groups; Pending = $left }
    } catch {
        & $Log 'WARN' ("groupings   : the grouped Summary rows were not completed this run -- {0}. They are tried again on the next run; until then the grouped views say the collection is being prepared." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}
