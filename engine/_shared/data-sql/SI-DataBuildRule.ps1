#Requires -Version 5.1
<#
    SecurityInsight Pro -- #1226 THE BUILD RULE (SCALE-3 A, owner 2026-11-12: "a failed / stopped / partial collection is never
    built"): which collections a build step may build. ONE definition, loaded by the data sync (through SI-DataSql.ps1) and by
    the update's own key-figures step (setup\Invoke-SIContainerUpdate.ps1, 9i) -- so both build exactly the same collections.
    No module, no other file needed. PS 5.1 safe.
#>

# which of the rule's parts the database can carry (Set-SIDataBuildReady, once per process); none = every complete collection
# is built, as before
$script:SIDataBuildTrustReady = $false
$script:SIDataBuildViewsReady = $false
$script:SIDataBuildRetiredReady = $false

function Get-SIDataBuildReadySql {
    <# What the build rule can read, as ONE number (a seam that answers one value per statement is enough): 1 = the verdict
       table sidata.CollectionTrust, 2 = the mark sidata.Collection.ViewsReadyAt, 4 = the retention mark
       sidata.Collection.RetiredAt -- added up. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CollectionTrust') IS NOT NULL THEN 1 ELSE 0 END + CASE WHEN COL_LENGTH('sidata.Collection', 'ViewsReadyAt') IS NOT NULL THEN 2 ELSE 0 END + CASE WHEN COL_LENGTH('sidata.Collection', 'RetiredAt') IS NOT NULL THEN 4 ELSE 0 END"
}

function Set-SIDataBuildReady {
    <# The build rule's parts in force for this process (Get-SIDataBuildFilter). -Answer: Get-SIDataBuildReadySql's number
       (anything else = the rule off). #>
    param($Answer)
    $n = 0; if ($null -ne $Answer -and $Answer -isnot [System.DBNull]) { [void][int]::TryParse(([string]$Answer).Trim(), [ref]$n) }
    if ($n -lt 0 -or $n -gt 7) { $n = 0 }
    $script:SIDataBuildTrustReady = [bool]($n -band 1)
    $script:SIDataBuildViewsReady = [bool]($n -band 2)
    $script:SIDataBuildRetiredReady = [bool]($n -band 4)
}

function Get-SIDataBuildFilter {
    <#
        #1226 ONLY A TRUSTED, CURRENT COLLECTION IS BUILT (SCALE-3 A): the text every build step's "which collections are
        pending" query appends (the views' data, the departments, the counted twins, the context, the summaries, the
        aggregates, the remediations, the key figures -- in the data sync and in the update) -- never the readers of what is
        shown or sent. A collection is NOT built
          (1) when its own verdict (sidata.CollectionTrust, written by Risk Analysis with it) says it is not trusted -- a run
              that did not finish its steps or was built on partial source data; it is pruned by the retention;
          (2) when it was never built (no view showed it: ViewsReadyAt empty) and a NEWER trusted complete collection of its
              kind exists (not retired) -- the collection of a stopped run beside the newer one (the "two collections in one
              run" of 2026-11-12, 34,261 s of views at a large install); no page could ever show it.
        A database without the verdict table / the mark: that part is off (every complete collection is built, as before).
        -Alias: the outer alias of sidata.Collection ('' = the table itself, unaliased).
    #>
    param([string]$Alias = '')
    $o = if ($Alias) { $Alias.TrimEnd('.') } else { 'sidata.Collection' }
    $out = ''
    $untrusted = { param($a) "EXISTS (SELECT 1 FROM sidata.CollectionTrust AS bt WHERE bt.CollectionTime = $a.CollectionTime AND bt.Grain = $a.Kind AND bt.Trusted = 0)" }
    if ($script:SIDataBuildTrustReady) { $out += ' AND NOT ' + (& $untrusted $o) }
    if ($script:SIDataBuildViewsReady) {
        $newerTrusted = "EXISTS (SELECT 1 FROM sidata.Collection AS bn WHERE bn.Kind = $o.Kind AND bn.Status = N'Complete' AND bn.CollectionTime > $o.CollectionTime"
        if ($script:SIDataBuildRetiredReady) { $newerTrusted += ' AND bn.RetiredAt IS NULL' }
        if ($script:SIDataBuildTrustReady) { $newerTrusted += ' AND NOT ' + (& $untrusted 'bn') }
        $newerTrusted += ')'
        $out += " AND NOT ($o.ViewsReadyAt IS NULL AND $newerTrusted)"
    }
    $out
}
