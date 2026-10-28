#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Finding exemptions (SecurityInsight Pro, REQUIREMENTS 9.3.3 phase C; #252 governed flow; #264 marks).
#
#  AN EXEMPTION NEVER REMOVES A FINDING (#264, operator: "exempted data goes into the raw data, but the views
#  control what to show"). The management GUI's approved exemptions (cfg.Exemption) are written by the settings layer
#  to <SI_ProRaSettingsPath>/RiskAnalysisExemptions.json, and this file MARKS the rows they cover -- it never drops one:
#      SI_ExemptionId         the exemption that covers the row ('' = not exempted)
#      SI_ExemptedUntil       its end date (yyyy-MM-dd; '' = no end date, or not exempted)
#      SI_ExemptionRequestId  the request (#252) it was approved from ('' when none)
#  Every row of a run carries the three columns once the file exists (blank when not exempted), so the Log Analytics
#  table learns them from the schema sample. The data sync copies the mark into the Pro database; every view, report and
#  mail decides at READ time whether exempted findings are shown and counted (the settings + a per-view tick).
#  Before #264 an exemption with an asset dropped the row here and an exemption without one became a KQL exclusion --
#  so an exempted finding vanished, which a ticketing sync reads as "fixed". Both are marks now.
#
#  No file (every Community run, every run without an exemption) = rows pass through unchanged, no columns added.
#  An unreadable file is NOT ignored silently: it is warned, and nothing is marked -- an exemption that cannot be read
#  must never hide a finding it was not meant to hide.
#
#  Do NOT add $PSScriptRoot-dependent code here (see RA-ExcludeLists.ps1).
#######################################################################################################

# The mark's columns, in this order, on every row of a run that has exemptions.
$script:RAExemptionMarkColumns = @('SI_ExemptionId', 'SI_ExemptedUntil', 'SI_ExemptionRequestId')

function Get-RAExemptionMarkColumns { $script:RAExemptionMarkColumns }

function Get-RAExemptions {
    <# The exemptions of this run (cached), or $null when there are none. #>
    [CmdletBinding()]
    param()
    if ($null -ne $script:_RAExemptionsCache) {
        if ($script:_RAExemptionsCache -is [string]) { return $null }
        return $script:_RAExemptionsCache
    }
    $script:_RAExemptionsCache = '__none__'
    if ([string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath)) { return $null }
    $path = Join-Path ([string]$global:SI_ProRaSettingsPath) 'RiskAnalysisExemptions.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 ("[exempt] {0} could not be read -- no exemption is marked: {1}" -f $path, $_.Exception.Message) }
        else { Write-Warning ("[exempt] {0} could not be read -- no exemption is marked: {1}" -f $path, $_.Exception.Message) }
        return $null
    }
    # an exemption names an asset, an issue (CVE / configuration id), or both; one naming neither is not applied
    $list = @($body.exemptions | Where-Object {
        $null -ne $_ -and (-not [string]::IsNullOrWhiteSpace([string]$_.assetKey) -or -not [string]::IsNullOrWhiteSpace([string]$_.cve) -or -not [string]::IsNullOrWhiteSpace([string]$_.configurationId))
    })
    if ($list.Count -eq 0) { return $null }
    $script:_RAExemptionsCache = [pscustomobject]@{
        AssetColumns   = @($body.matchAssetColumns | ForEach-Object { [string]$_ } | Where-Object { $_ })
        FindingColumns = @($body.matchFindingColumns | ForEach-Object { [string]$_ } | Where-Object { $_ })
        Exemptions     = $list
        Path           = $path
    }
    $script:_RAExemptionsCache
}

function Get-RAExemptionFor {
    <#
        PURE over the cached file. The exemption that covers ONE row of a report, or $null. An exemption covers the row when
          - it applies to this report (it names it, or it is global), AND
          - its asset key (when it has one) equals (case-insensitive) any of the row's asset columns, AND
          - its CVE / configuration id (when it has one) equals any of the row's finding columns -- the file's list plus the
            report's own ConfigurationIdInputName.
        An exemption with an asset and no issue covers every row of that asset; one with an issue and no asset covers that
        issue on every asset. Several match: the lowest id wins (stable across runs).
    #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)]$Index)
    $valueOf = {
        param($r, [string]$col)
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($col)) { return [string]$r[$col] } else { return $null } }
        $p = $r.PSObject.Properties[$col]
        if ($p) { [string]$p.Value } else { $null }
    }
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Index.AssetColumns) {
        $v = & $valueOf $Row $c
        if (-not [string]::IsNullOrWhiteSpace($v)) { $k = $v.ToLowerInvariant(); if ($Index.ByAsset.ContainsKey($k)) { foreach ($e in $Index.ByAsset[$k]) { $cands.Add($e) } } }
    }
    foreach ($e in $Index.IssueOnly) { $cands.Add($e) }
    $best = $null
    foreach ($e in $cands) {
        $want = @(@([string]$e.cve, [string]$e.configurationId) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hit = $false
        if ($want.Count -eq 0) { $hit = $true }
        else {
            foreach ($c in $Index.FindingColumns) {
                $v = & $valueOf $Row $c
                if ([string]::IsNullOrWhiteSpace($v)) { continue }
                foreach ($w in $want) { if ($v -ieq $w) { $hit = $true; break } }
                if ($hit) { break }
            }
        }
        if ($hit -and ($null -eq $best -or [long]$e.id -lt [long]$best.id)) { $best = $e }
    }
    $best
}

function Set-RAExemptionMarks {
    <#
        EVERY row of one report, each carrying the exemption mark (SI_ExemptionId / SI_ExemptedUntil /
        SI_ExemptionRequestId; blank when not exempted). Never drops a row. No exemptions this run = the rows unchanged.
        Call it as @(Set-RAExemptionMarks ...), as the engine does for every row list.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Rows, [Parameter(Mandatory)][string]$ReportName, [string[]]$FindingColumns = @())
    if ($null -eq $Rows) { return @() }
    $all = @($Rows)
    $ex = Get-RAExemptions
    if ($null -eq $ex -or $all.Count -eq 0) { return $all }
    $mine = @($ex.Exemptions | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.report) -or [string]$_.report -eq $ReportName })
    $findCols = @(@($ex.FindingColumns) + @($FindingColumns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) | Select-Object -Unique)
    $byAsset = @{}
    $issueOnly = New-Object System.Collections.Generic.List[object]
    foreach ($e in $mine) {
        if ([string]::IsNullOrWhiteSpace([string]$e.assetKey)) { $issueOnly.Add($e); continue }
        $k = ([string]$e.assetKey).ToLowerInvariant()
        if (-not $byAsset.ContainsKey($k)) { $byAsset[$k] = New-Object System.Collections.Generic.List[object] }
        $byAsset[$k].Add($e)
    }
    $index = [pscustomobject]@{ AssetColumns = $ex.AssetColumns; FindingColumns = $findCols; ByAsset = $byAsset; IssueOnly = $issueOnly.ToArray() }
    $marked = 0
    foreach ($row in $all) {
        $e = $null
        if ($mine.Count -gt 0) { $e = Get-RAExemptionFor -Row $row -Index $index }
        $id = ''; $until = ''; $req = ''
        if ($e) {
            $marked++
            $id = [string]$e.id
            if (-not [string]::IsNullOrWhiteSpace([string]$e.expiresAt)) {
                $d = [datetime]::MinValue
                if ([datetime]::TryParse([string]$e.expiresAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) {
                    $until = $d.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
                }
            }
            if ($e.PSObject.Properties['requestId'] -and -not [string]::IsNullOrWhiteSpace([string]$e.requestId)) { $req = [string]$e.requestId }
        }
        if ($row -is [System.Collections.IDictionary]) { $row['SI_ExemptionId'] = $id; $row['SI_ExemptedUntil'] = $until; $row['SI_ExemptionRequestId'] = $req }
        else {
            Add-Member -InputObject $row -NotePropertyName 'SI_ExemptionId' -NotePropertyValue $id -Force
            Add-Member -InputObject $row -NotePropertyName 'SI_ExemptedUntil' -NotePropertyValue $until -Force
            Add-Member -InputObject $row -NotePropertyName 'SI_ExemptionRequestId' -NotePropertyValue $req -Force
        }
    }
    if ($marked -gt 0) {
        $msg = "[exempt] {0}: {1} row(s) marked as exempted (kept; the views decide whether they are shown and counted)" -f $ReportName, $marked
        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $msg } else { Write-Verbose $msg }
    }
    $all
}

function Test-RARowExempted {
    <# PURE. The shared predicate, for Risk Analysis's own outputs: the row carries an exemption mark. #>
    param([Parameter(Mandatory)][AllowNull()]$Row)
    if ($null -eq $Row) { return $false }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('SI_ExemptionId')) { $v = $Row['SI_ExemptionId'] } }
    elseif ($Row.PSObject.Properties['SI_ExemptionId']) { $v = $Row.SI_ExemptionId }
    -not [string]::IsNullOrWhiteSpace([string]$v)
}

function Select-RAReportRows {
    <#
        PURE. Risk Analysis's OWN read-time view of the run: the rows its workbook, JSON, mail and summary count. Exempted
        rows are left out unless -IncludeExempted (SI_Exempted_CountInManagement). Log Analytics always gets every row.
        Returns @{ Rows; Exempted } -- Exempted = how many marked rows were left out (0 when included).
    #>
    param([AllowNull()][object[]]$Rows, [switch]$IncludeExempted)
    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($IncludeExempted) { return [pscustomobject]@{ Rows = $all; Exempted = 0 } }
    $kept = New-Object System.Collections.Generic.List[object]; $n = 0
    foreach ($r in $all) { if (Test-RARowExempted -Row $r) { $n++ } else { $kept.Add($r) } }
    [pscustomobject]@{ Rows = $kept.ToArray(); Exempted = $n }
}

function Select-RANonExemptRows {
    <#
        The rows of one report WITHOUT the exempted ones -- kept for callers that want only the counted rows of one report.
        It marks first (Set-RAExemptionMarks) and then leaves the marked rows out of what it RETURNS; the engine itself no
        longer calls it (it marks, and decides what to count at read time).
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Rows, [Parameter(Mandatory)][string]$ReportName, [string[]]$FindingColumns = @())
    @(Set-RAExemptionMarks -Rows $Rows -ReportName $ReportName -FindingColumns $FindingColumns | Where-Object { -not (Test-RARowExempted -Row $_) })
}
