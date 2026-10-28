#Requires -Version 5.1
<#
    THE DATA OUT OF A RISK ANALYSIS REPORT, GENERATED (REQUIREMENTS #692 (c) / (d), owner 2026-10-15: "data-out is project
    si-fields. ability to extend new si-fields both in and out. we do this automatically. important that we dont chg names as
    fx integrations, connectors will break"; owner 2026-10-19: "let every report carry the generated output block").

    Every query report of the catalog (RiskAnalysis_Queries_Locked.yaml) ends in ONE generated block, never edited by hand:

        //__SI_OUT_BEGIN__
        // DATA OUT ... (what the block is)
        // out <the report's output columns, in order -- its OutputPropertyOrder, pinned in the output contract>
        // si  <each SI finding field the report fills, with the report column that fills it>
        //__SI_OUT_END__

    It is the report's DECLARATION of its data out, in the query itself: which output columns it delivers (the engine shapes
    every row to exactly these, in this order -- a name never changes, additions only) and which generic si_* finding fields
    they become (Risk Analysis' findings, SI_Finding_CL / sidata.Finding -- what ServiceNow, the SQL hand-off and every other
    connector read). Comment lines only: the block changes no row and no column, pasted into the portal or run by the
    engine (the engine takes it out before it sends the query, Remove-RAOutBlock).
    GENERATED from the data, so a new field reaches every report automatically: the out line from the report's own
    OutputPropertyOrder, the si lines from the core map below (the fields RA-Findings.ps1 sets from fixed columns) and the
    field catalog's row-column map (data-model/finding-texts.locked.json rowColumns). tools/ra-ci/Set-RaOutBlock.ps1 writes
    them; tests/pester/SIv3-ReportOutBlock.Tests.ps1 fails when a report's block differs from what this file generates.

    KQL rules: no colon in a // comment, no ';' (the hybrid pre-fetcher cuts at the first ';'). PowerShell 5.1.
#>

$script:RAOutBegin = '//__SI_OUT_BEGIN__'
$script:RAOutEnd   = '//__SI_OUT_END__'

# The SI finding fields RA-Findings.ps1 (ConvertTo-SIFindings) sets from FIXED report columns -- in its order. The guard test
# checks every pair against that file, so the two never drift apart.
$script:RAOutCoreMap = [ordered]@{
    si_ci_id                = @('si_ci_id', 'AssetId')
    si_finding_key          = @('ConfigurationId')
    si_title                = @('ConfigurationName')
    si_asset_name           = @('AssetName')
    si_security_domain      = @('SecurityDomain')
    si_report_name          = @('AssetDetectedInReportName')
    si_severity             = @('SecuritySeverity')
    si_risk_score           = @('RiskScoreTotal')
    si_weighted_risk_score  = @('RiskScoreTotal_Weighted')
    si_finding_risk_factors = @('RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed')
    si_tier                 = @('CriticalityTier')
    si_cvss                 = @('MaxCvssScore')
    si_exemption_id         = @('SI_ExemptionId')
}

$script:RAOutRowColumnsCache = $null

function Get-RAOutRowColumns {
    <#
        The field catalog's row-column map (data-model/finding-texts.locked.json rowColumns): ordered si field -> the report
        columns that fill it (first non-empty). -Path: another file (tests). Never throws: unreadable = an empty map.
    #>
    param([string]$Path = '')
    if (-not $Path -and $null -ne $script:RAOutRowColumnsCache) { return $script:RAOutRowColumnsCache }
    $map = [ordered]@{}
    try {
        $p = $Path
        if (-not $p) { $p = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'data-model', 'finding-texts.locked.json') }
        $doc = ([System.IO.File]::ReadAllText($p)).TrimStart([char]0xFEFF) | ConvertFrom-Json
        if ($doc.PSObject.Properties['rowColumns'] -and $doc.rowColumns) {
            foreach ($pp in $doc.rowColumns.PSObject.Properties) { $map[[string]$pp.Name] = @(@($pp.Value) | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
        }
    } catch { $map = [ordered]@{} }
    if (-not $Path) { $script:RAOutRowColumnsCache = $map }
    $map
}

function Remove-RAOutBlock {
    <# PURE. The query without its generated data-out block (comments only -- nothing the query computes is taken out). #>
    param([AllowEmptyString()][string]$Query = '')
    if (-not $Query -or $Query.IndexOf($script:RAOutBegin) -lt 0) { return $Query }
    $q = [regex]::Replace($Query, '(?s)[ \t]*' + [regex]::Escape($script:RAOutBegin) + '.*?' + [regex]::Escape($script:RAOutEnd) + '[ \t]*(\r?\n)?', '')
    $q.TrimEnd()
}

function Get-RAOutBlockLines {
    <#
        PURE. One report's generated data-out block, as lines (no indent): -OutputColumns its OutputPropertyOrder, -Body its
        query (the block, the other generated blocks and the comments are left out before the columns are looked up),
        -RowColumns Get-RAOutRowColumns. An si field is listed with the FIRST of its columns the report has (an output
        column, or a name its own query writes); a field none of whose columns it has is not listed. Deterministic.
    #>
    param([AllowEmptyCollection()][string[]]$OutputColumns = @(), [AllowEmptyString()][string]$Body = '', $RowColumns = $null)
    if ($null -eq $RowColumns) { $RowColumns = Get-RAOutRowColumns }
    $b = [regex]::Replace([string]$Body, '(?s)//__([A-Z_]+)_BEGIN__.*?//__\1_END__', ' ')
    $b = [regex]::Replace($b, '//[^\r\n]*', ' ')
    $outs = @($OutputColumns | Where-Object { "$_".Trim() } | ForEach-Object { ([string]$_).Trim() })
    # where a column is looked for, in order: the output columns, the report's last shaping step (its final project /
    # summarize and what follows -- the columns a row leaves the query with), then anywhere in its own query
    $ms = [regex]::Matches($b, '\|\s*(project|summarize)\b')
    $shape = if ($ms.Count) { $b.Substring($ms[$ms.Count - 1].Index) } else { $b }
    $inText = { param([string]$t, [string]$c) [regex]::IsMatch($t, '(?<![A-Za-z0-9_])' + [regex]::Escape($c) + '(?![A-Za-z0-9_])') }
    $si = New-Object System.Collections.Generic.List[string]; $done = @{}
    foreach ($m in @($script:RAOutCoreMap, $RowColumns)) {
        foreach ($f in @($m.Keys)) {
            if ($done.ContainsKey([string]$f)) { continue }
            $cands = @($m[$f] | ForEach-Object { [string]$_ } | Where-Object { $_ })
            $pick = @($cands | Where-Object { $outs -contains $_ }) + @($cands | Where-Object { & $inText $shape $_ }) + @($cands | Where-Object { & $inText $b $_ })
            if ($pick.Count) { $si.Add(('{0} <- {1}' -f $f, $pick[0])); $done[[string]$f] = 1 }
        }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($script:RAOutBegin)
    $lines.Add('// DATA OUT, generated from the output contract and the field catalog (tools/ra-ci/Set-RaOutBlock.ps1), never edited by hand')
    $lines.Add('// out = the output columns, in order (the engine shapes every row to them, a name never changes, additions only)')
    $lines.Add('// si = the SI finding fields the report fills, each with the report column that fills it')
    for ($i = 0; $i -lt $outs.Count; $i += 8) { $lines.Add('// out ' + (($outs[$i..([Math]::Min($i + 7, $outs.Count - 1))]) -join ', ')) }
    $sa = $si.ToArray()
    for ($i = 0; $i -lt $sa.Count; $i += 4) { $lines.Add('// si ' + (($sa[$i..([Math]::Min($i + 3, $sa.Count - 1))]) -join ', ')) }
    $lines.Add($script:RAOutEnd)
    # plain output, one line per item (callers write @(...))
    $lines.ToArray()
}

function Find-RAOutQueryBlock {
    <# PURE. The line range of one report's query body: @{ Start; End (exclusive); Indent } or $null (the two shapes the catalog uses). #>
    param([string[]]$Lines, [int]$From, [int]$To)
    $q = -1
    for ($i = $From; $i -lt $To; $i++) {
        if ($Lines[$i] -match '^\s*ReportQuery:\s*\|-?\s*$') { $q = $i; break }
        if ($Lines[$i] -match '^\s*ReportQuery:\s*$' -and ($i + 1) -lt $To -and $Lines[$i + 1] -match '^\s*-\s*\|-?\s*$') { $q = $i + 1; break }
    }
    if ($q -lt 0) { return $null }
    $start = $q + 1; $indent = $null
    for ($i = $start; $i -lt $To; $i++) { if ($Lines[$i].Trim()) { $indent = ([regex]::Match($Lines[$i], '^\s*')).Value; break } }
    if ($null -eq $indent) { return $null }
    $end = $start
    for ($i = $start; $i -lt $To; $i++) { $l = $Lines[$i]; if ($l.Trim() -and -not $l.StartsWith($indent)) { break }; $end = $i + 1 }
    while ($end -gt $start -and -not $Lines[$end - 1].Trim()) { $end-- }
    @{ Start = $start; End = $end; Indent = $indent }
}

function Update-RAOutBlocksInCatalog {
    <#
        PURE. The catalog text with every query report's data-out block (re)generated at the end of its query: an existing
        block is replaced, a missing one appended. Everything else stays byte for byte (line endings kept). Returns
        @{ Text; Reports (names); Changed (names whose block was added or differs) }.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Yaml, $RowColumns = $null)
    if ($null -eq $RowColumns) { $RowColumns = Get-RAOutRowColumns }
    $nl = "`n"; if ($Yaml.Contains("`r`n")) { $nl = "`r`n" }
    $lines = New-Object System.Collections.Generic.List[string]; foreach ($l in ($Yaml -split "`r?`n")) { $lines.Add($l) }
    $heads = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*-\s*ReportName:\s*\S') { $heads.Add($i) } }
    $names = New-Object System.Collections.Generic.List[string]; $changed = New-Object System.Collections.Generic.List[string]
    for ($h = $heads.Count - 1; $h -ge 0; $h--) {
        $from = $heads[$h]; $to = $(if ($h + 1 -lt $heads.Count) { $heads[$h + 1] } else { $lines.Count })
        $name = ([regex]::Match($lines[$from], 'ReportName:\s*(\S+)')).Groups[1].Value
        $blk = Find-RAOutQueryBlock -Lines $lines.ToArray() -From $from -To $to
        if ($null -eq $blk) { continue }
        $names.Add($name)
        # the report's OutputPropertyOrder (its own lines, inside the report)
        $outs = New-Object System.Collections.Generic.List[string]
        for ($i = $from; $i -lt $to; $i++) {
            if ($lines[$i] -match '^(\s*)OutputPropertyOrder:\s*$') {
                for ($j = $i + 1; $j -lt $to; $j++) { $mm = [regex]::Match($lines[$j], '^\s*-\s*(\S+)\s*$'); if (-not $mm.Success) { break }; $outs.Add($mm.Groups[1].Value) }
                break
            }
        }
        # the existing block (if any) and the body without it
        $bs = -1; $be = -1
        for ($i = $blk.Start; $i -lt $blk.End; $i++) { if ($lines[$i].Trim() -eq $script:RAOutBegin) { $bs = $i }; if ($bs -ge 0 -and $lines[$i].Trim() -eq $script:RAOutEnd) { $be = $i; break } }
        $bodyLines = New-Object System.Collections.Generic.List[string]
        for ($i = $blk.Start; $i -lt $blk.End; $i++) { if ($bs -ge 0 -and $i -ge $bs -and $i -le $be) { continue }; $bodyLines.Add($lines[$i]) }
        $gen = @((Get-RAOutBlockLines -OutputColumns $outs.ToArray() -Body ($bodyLines -join "`n") -RowColumns $RowColumns) | ForEach-Object { $blk.Indent + $_ })
        if ($bs -ge 0) {
            $old = @($lines.GetRange($bs, $be - $bs + 1))
            if (($old -join "`n") -ceq ($gen -join "`n")) { continue }
            $lines.RemoveRange($bs, $be - $bs + 1); $lines.InsertRange($bs, [string[]]$gen)
        } else {
            $lines.InsertRange($blk.End, [string[]]$gen)
        }
        $changed.Add($name)
    }
    $names.Reverse(); $changed.Reverse()
    @{ Text = ($lines -join $nl); Reports = $names.ToArray(); Changed = $changed.ToArray() }
}
