#Requires -Version 5.1
<#
    A FAKE LOG ANALYTICS FOR THE PAGED FINDING READ (#639) -- shared by the suites that test Invoke-SIDataCiSync.
    It answers the data sync's reader seam { param($kql, $table) } exactly as the real one answers the paged read of the newest
    SI_Finding_CL collection:
      * the count query (Get-SIDataCiFindingCountKql: 'summarize Rows = count()') -> one row: Rows (-CountRows, default the
        rows it holds), Bytes, CollectionTimeText;
      * a page's count (Get-SIDataCiFindingPageKql -CountOnly: 'PageRows = count()') -> PageRows, OneKey;
      * a page -> the rows whose index every cut of the page keeps (Get-SIDataPageFilter: the first cut is the index modulo
        its parts, a deeper cut takes the next bit -- so cutting a page always separates its rows in the end);
      * -MaxPageRows N: a page of more than N rows throws OutOfMemoryException (the job could not hold it) -- the reader must
        read it again in halves;
      * -DropRows N: N rows are never answered (a cut answer the service did not say was cut) -- the count must catch it;
      * #829 -LastIngest: when the collection's newest row arrived (the count row's LastIngest); -RunHealth: the rows the
        run-health read (SI_RunHealth_CL) answers -- @{ StartedAt; DurationSec; ExitReason } (none by default).
    Every query it answered is in .Calls; every query that read rows is in .RowReads.
#>
function New-SIFakeFindingReader {
    param([object[]]$Rows = @(), [long]$CountRows = -1, [int]$MaxPageRows = 0, [int]$DropRows = 0, [string]$TimeText = '2026-10-12T03:00:00Z',
          [string]$LastIngest = '', [object[]]$RunHealth = @())
    $calls = New-Object System.Collections.ArrayList
    $rowReads = New-Object System.Collections.ArrayList
    $st = @{ Rows = @($Rows); Count = $(if ($CountRows -ge 0) { $CountRows } else { [long]@($Rows).Count }); Max = $MaxPageRows; Drop = $DropRows; Time = $TimeText; Ooms = 0; LastIngest = $LastIngest; RunHealth = @($RunHealth) }
    $r = {
        param([string]$kql, [string]$table)
        [void]$calls.Add($kql)
        if ($table -eq 'SI_RunHealth_CL') { return , @($st.RunHealth) }
        if ($table -ne 'SI_Finding_CL') { return , @() }
        if ($kql -match 'summarize Rows = count\(\)') {
            if ($st.Count -le 0) { return , @([pscustomobject]@{ Rows = '0'; Bytes = ''; CollectionTimeText = '' }) }
            return , @([pscustomobject]@{ Rows = [string]$st.Count; Bytes = '4096'; CollectionTimeText = $st.Time; LastIngest = $st.LastIngest })
        }
        $all = @($st.Rows)
        $cuts = [regex]::Matches($kql, 'hash\((?:strcat\("(\d+)\|", _pk\)|_pk), (\d+)\) == (\d+)')
        $page = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt ($all.Count - $st.Drop); $i++) {
            $in = $true
            foreach ($c in $cuts) {
                $d = 0; if ($c.Groups[1].Success) { $d = [int]$c.Groups[1].Value }
                $n = [int]$c.Groups[2].Value
                $b = $i % $n; if ($d -gt 0) { $b = ($i -shr ($d - 1)) % $n }
                if ($b -ne [int]$c.Groups[3].Value) { $in = $false; break }
            }
            if ($in) { $page.Add($all[$i]) }
        }
        if ($kql -match 'PageRows = count\(\)') { return , @([pscustomobject]@{ PageRows = [string]$page.Count; OneKey = $(if ($page.Count -le 1) { 'true' } else { 'false' }) }) }
        if ($st.Max -gt 0 -and $page.Count -gt $st.Max) { $st.Ooms++; throw ([System.OutOfMemoryException]::new('Exception of type ''System.OutOfMemoryException'' was thrown.')) }
        [void]$rowReads.Add($kql)
        return , $page.ToArray()
    }.GetNewClosure()
    [pscustomobject]@{ Read = $r; Calls = $calls; RowReads = $rowReads; State = $st }
}

function New-SIFakeFindingRows {
    param([int]$Count, [string]$Ci = 'ci-1', [string]$TimeText = '2026-10-12T03:00:00Z',
          [string]$LastIngest = '', [object[]]$RunHealth = @())
    , @(1..$Count | ForEach-Object { [pscustomobject]@{ si_ci_id = $Ci; si_finding_key = "K$_"; si_risk_score = '1'; si_severity = 'high'; si_collection_time = $TimeText } })
}
