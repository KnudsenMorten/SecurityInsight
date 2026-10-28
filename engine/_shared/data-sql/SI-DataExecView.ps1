#Requires -Version 5.1
<#
    #288 -- the Risk Analysis EXECUTIVE VIEW into the Pro database.

    Every Risk Analysis run keeps what its mail showed (engine/risk-analysis/_shared/RA-ExecView.ps1), one file per
    report grain, beside the shared Top-50 snapshot:  <container>/risk-analysis/RiskAnalysis_ExecView_<Grain>.json.
    The data sync copies each one into sidata.RiskExecView (one row per grain), and the web app's Overview >
    "Risk Analysis (executive)" page reads that row -- so the page shows the mail's own figures, never a recomputation.

    A view is only replaced by a NEWER one (GeneratedAt), so re-running the sync, or an older file found on a second
    host, never moves the page backwards. A file that is not a view (wrong shape, wrong grain) is refused and said.
    Nothing here ever fails the data sync: the findings load is the job's purpose, this is a side copy.
#>

Set-StrictMode -Off

function Get-SIDataExecViewSchemaCheckSql { "SELECT CASE WHEN OBJECT_ID('sidata.RiskExecView') IS NOT NULL THEN 1 ELSE 0 END" }

function Get-SIDataExecViewUpsertSql {
    <# Insert, or replace when newer. The grain is the key; GeneratedAt decides. #>
    @'
MERGE sidata.RiskExecView AS t
USING (SELECT @Grain AS Grain) AS s ON t.Grain = s.Grain
WHEN MATCHED AND t.GeneratedAt < CONVERT(datetime2(3), @GeneratedAt, 126) THEN
    UPDATE SET GeneratedAt = CONVERT(datetime2(3), @GeneratedAt, 126), CollectionTime = CONVERT(datetime2(3), @CollectionTime, 126),
               ReportTemplate = @ReportTemplate, Mode = @Mode, Leader = @Leader, FiguresFromGrain = @FiguresFromGrain,
               PayloadJson = @PayloadJson, LoadedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN
    INSERT (Grain, GeneratedAt, CollectionTime, ReportTemplate, Mode, Leader, FiguresFromGrain, PayloadJson)
    VALUES (@Grain, CONVERT(datetime2(3), @GeneratedAt, 126), CONVERT(datetime2(3), @CollectionTime, 126), @ReportTemplate, @Mode, @Leader, @FiguresFromGrain, @PayloadJson);
SELECT @@ROWCOUNT;
'@
}

function ConvertFrom-SIDataExecViewJson {
    <#
    .SYNOPSIS
        PURE. The view file's text -> the row to store, or a Problem saying why it is refused.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Json, [Parameter(Mandatory)][ValidateSet('Summary', 'Detailed')][string]$ExpectedGrain)

    $fail = { param($why) [pscustomobject]@{ Row = $null; Problem = $why } }
    if ([string]::IsNullOrWhiteSpace($Json)) { return (& $fail 'empty file') }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return (& $fail ('not JSON: ' + $_.Exception.Message)) }
    if ($null -eq $o -or -not $o.PSObject.Properties['SchemaVersion']) { return (& $fail 'not an executive view (no SchemaVersion)') }
    if ([int]$o.SchemaVersion -ne 1) { return (& $fail ('unknown SchemaVersion {0}' -f $o.SchemaVersion)) }
    if ([string]$o.Grain -ne $ExpectedGrain) { return (& $fail ("the file names grain '{0}', expected '{1}'" -f $o.Grain, $ExpectedGrain)) }
    if ([string]$o.Mode -notin @('Consistent', 'PerReport')) { return (& $fail ("unknown mode '{0}'" -f $o.Mode)) }
    if ([string]$o.Leader -notin @('Summary', 'Detailed')) { return (& $fail ("unknown leader '{0}'" -f $o.Leader)) }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $toSql = {
        param($v)
        if ($null -eq $v -or [string]$v -eq '') { return $null }
        $d = if ($v -is [datetime]) { [datetime]$v } else { [datetime]::Parse([string]$v, $inv, [System.Globalization.DateTimeStyles]::RoundtripKind) }
        $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv)
    }
    try { $gen = & $toSql $o.GeneratedAt } catch { $gen = $null }
    if (-not $gen) { return (& $fail 'no usable GeneratedAt') }
    $ct = $null; try { $ct = & $toSql $o.CollectionTime } catch { $ct = $null }
    $from = if ($o.FiguresFrom -and [string]$o.FiguresFrom.Grain -in @('Summary', 'Detailed')) { [string]$o.FiguresFrom.Grain } else { $ExpectedGrain }
    [pscustomobject]@{
        Row = [ordered]@{
            Grain = $ExpectedGrain; GeneratedAt = $gen; CollectionTime = $ct; ReportTemplate = [string]$o.ReportTemplate
            Mode = [string]$o.Mode; Leader = [string]$o.Leader; FiguresFromGrain = $from
            # stored as the engine wrote it -- the page parses exactly what the mail rendered
            PayloadJson = $Json.Trim()
        }
        Problem = $null
    }
}

function Invoke-SIDataExecViewSync {
    <#
    .SYNOPSIS
        Carry both grains' executive views into sidata.RiskExecView. Never throws.
    .PARAMETER ReadView
        { param([string]$BlobName) } -> the file's text, or $null when there is none. Injected so the core is testable.
    .OUTPUTS
        { Stored; Unchanged; Missing; Refused; Problem }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ReadView,
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter()][AllowNull()][string]$Top50BlobName,
        [switch]$DryRun,
        [scriptblock]$Log = { param($l, $m) }
    )
    $res = [pscustomobject]@{ Stored = @(); Unchanged = @(); Missing = @(); Refused = @(); Problem = $null }
    try {
        if ([int](& $Invoke (Get-SIDataExecViewSchemaCheckSql) @{} 'scalar') -ne 1) {
            $res.Problem = 'sidata.RiskExecView is not in the database yet -- the updater adds it with the data schema; until then the web app cannot show the Risk Analysis executive view.'
            & $Log 'WARN' ('exec view : ' + $res.Problem)
            return $res
        }
        foreach ($grain in 'Summary', 'Detailed') {
            $blob = Get-RAExecViewBlobName -Grain $grain -Top50BlobName $Top50BlobName
            $text = $null
            try { $text = & $ReadView $blob } catch { $text = $null; & $Log 'WARN' ("exec view : {0} could not be read -- {1}" -f $blob, $_.Exception.Message) }
            if ([string]::IsNullOrWhiteSpace([string]$text)) { $res.Missing += $grain; continue }
            $c = ConvertFrom-SIDataExecViewJson -Json ([string]$text) -ExpectedGrain $grain
            if ($c.Problem) { $res.Refused += ('{0}: {1}' -f $grain, $c.Problem); & $Log 'WARN' ("exec view : {0} refused -- {1}" -f $blob, $c.Problem); continue }
            if ($DryRun) { $res.Stored += $grain; continue }
            $n = [int](& $Invoke (Get-SIDataExecViewUpsertSql) $c.Row 'scalar')
            if ($n -gt 0) { $res.Stored += $grain } else { $res.Unchanged += $grain }
        }
        & $Log 'OK' ("exec view : stored {0} | unchanged {1} | none yet {2}{3}" -f `
            $(if ($res.Stored.Count) { $res.Stored -join ', ' } else { '-' }), $(if ($res.Unchanged.Count) { $res.Unchanged -join ', ' } else { '-' }),
            $(if ($res.Missing.Count) { $res.Missing -join ', ' } else { '-' }), $(if ($DryRun) { '   (DRY RUN)' } else { '' }))
    } catch {
        $res.Problem = $_.Exception.Message
        & $Log 'WARN' ("exec view : not carried this run -- {0}. The findings load is not affected." -f $res.Problem)
    }
    return $res
}
