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
    stored complete collection, newest first, within a time budget (the rest follow on the next runs). A collection is written
    again when it was derived or prepared again after its rows were built, or when the definition changed. Until a collection
    has its rows the grouped view says they are being prepared. The retention removes them with the collection
    (Get-SIDataPurgeCollectionSql). Never fails the data sync.
#>

if (-not (Get-Command -Name Invoke-SISummaryGrouping -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-SummaryGroupings.ps1'))
}

function Get-SIDataSummaryGroupsSchemaCheckSql {
    <# 1 when the database carries the three tables and every finding column the definition reads; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID('sidata.SummaryGroupCounted') IS NOT NULL AND OBJECT_ID('sidata.SummaryGroupState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'HasExploit') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskRating') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Category') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Subcategory') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ContextAt') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'MitreTactics') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'MitreTechniques') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ComplianceTags') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Cvss') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroupState', 'Groupings') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroup', 'AttributesJson') IS NOT NULL AND COL_LENGTH('sidata.SummaryGroupCounted', 'AttributesJson') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'FixRemediation') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'SourceFirstDetected') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataSummaryGroupsPendingSql {
    <#
        Complete Detailed collections whose views' columns are derived (risk rating, exploit flag) and whose context is prepared
        (category, subcategory), and whose grouped rows are missing -- new loads and, once, every collection stored before the
        tables existed -- older than the derive or the prepared context, or built from another definition (@Hash). Newest
        first. Never a retired collection.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.SummaryGroupState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND c.ContextAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt OR s.BuiltAt < c.ContextAt OR s.DefinitionHash <> @Hash)$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataSummaryGroupsSql {
    <# ONE collection (@CollectionId, @Hash): THE engine function's statement (Invoke-SISummaryGrouping -AsSql). #>
    param($Plan)
    Invoke-SISummaryGrouping -AsSql -Plan $Plan
}

function Invoke-SIDataSummaryGroups {
    <#
    .SYNOPSIS  Writes the grouped rows of every complete collection that has none (or older ones). Never throws.
    .NOTES     Newest collection first, so the collection a view opens by default is the first one written. -BudgetSeconds:
               when the collections of an existing install take longer than this in one run, the rest follow on the next runs
               (said). A pace, not a limit on the data: every finding of a collection is counted. Paced by the database's own
               load (SI-SqlPacing.ps1) when loaded.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900, $Plan)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (-not $Plan) { $Plan = Get-SISummaryGroupingPlan }
        if (([int](& $Invoke (Get-SIDataSummaryGroupsSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' 'groupings   : the database does not have the grouped Summary tables yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the grouped views say they are being prepared until then.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke (Get-SIDataSummaryGroupsPendingSql) @{ Hash = $Plan.Hash } 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
        if ($DryRun) {
            & $Log 'INFO' ("groupings   : {0} collection(s) would get their grouped Summary rows; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0; Groups = 0 } }
        $sql = Get-SIDataSummaryGroupsSql -Plan $Plan
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $done = 0; $groups = [long]0
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            if ($paced) { $null = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            # 2026-10-25 over this run's narrow findings (read ONCE, shared with the steps after) where they can be made
            $n = if (Get-Command -Name Invoke-SIDataNarrowOrWide -ErrorAction SilentlyContinue) { Invoke-SIDataNarrowOrWide -Invoke $Invoke -Sql $sql -Params @{ CollectionId = [int]$p['CollectionId']; Hash = $Plan.Hash } -Mode 'scalar' -CollectionId ([long]$p['CollectionId']) -What 'the grouped Summary rows' -Log $Log }
                  else { & $Invoke $sql @{ CollectionId = [int]$p['CollectionId']; Hash = $Plan.Hash } 'scalar' }
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            if ("$n" -match '^\d+$') { $groups += [long]"$n" }
            $done++
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
