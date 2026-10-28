#Requires -Version 5.1
<#
    THE EXECUTIVE VIEW SNAPSHOT -- what one Risk Analysis mail showed, kept so the Pro web app can show it again.

    Management reads the Risk Analysis mail: the Risk Score KPI and its band, the domain x severity table, the
    per-domain scores, the AI-written analysis and the Top-50 risky assets. The web app's Overview > Executive report >
    "Risk Analysis" page shows the same view. It must show the SAME figures as the mail of the same run, so it never
    recomputes them: every run writes the object its mail rendered, once per report grain:

        <container>/risk-analysis/RiskAnalysis_ExecView_Summary.json
        <container>/risk-analysis/RiskAnalysis_ExecView_Detailed.json

    and the Pro data sync carries both into sidata.RiskExecView (engine/_shared/data-sql/SI-DataExecView.ps1).

    🔒 THIS IS NOT THE SHARED AI-SUMMARY SNAPSHOT. RiskAnalysis_Top50_Shared.json is the file the follower ADOPTS in
    Consistent mode, and PerReport deliberately neither reads nor writes it. This file is the opposite: it is written
    in EVERY mode, one per grain, and nothing in the engine ever reads it back -- so it cannot change what a mail
    shows. It records what the mail showed, including whose figures they were (FiguresFrom) and the agreement mode in
    force, which is what the page needs to say "figures from the Summary report, as in the mails".

    Everything here is PURE except Save-RAExecViewFile (disk + blob), which never throws: losing the web view must
    never cost a customer the nightly report.
#>

Set-StrictMode -Off
# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function ConvertTo-RAExecViewCounts {
    <#
    .SYNOPSIS
        PURE. A hashtable or a PSCustomObject (what ConvertFrom-Json returns) -> an ordered name -> int map.
        Nested maps (SevByDomain) are converted one level down.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value, [switch]$Nested)

    $out = [ordered]@{}
    if ($null -eq $Value) { return $out }
    # (a list, never += on an array in a loop)
    $pairList = New-Object 'System.Collections.Generic.List[object]'
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { $pairList.Add(@([string]$k, $Value[$k])) } }
    else { foreach ($p in @($Value.PSObject.Properties)) { $pairList.Add(@([string]$p.Name, $p.Value)) } }
    $pairs = $pairList.ToArray()
    foreach ($kv in @($pairs | Sort-Object { $_[0] })) {
        if ($Nested) { $out[$kv[0]] = ConvertTo-RAExecViewCounts -Value $kv[1] }
        else {
            $n = 0
            [void][int]::TryParse([string]$kv[1], [ref]$n)
            $out[$kv[0]] = $n
        }
    }
    return $out
}

function Get-RAExecViewAssetId {
    <#
    .SYNOPSIS
        PURE. The asset id from the Top-50 aggregation key ('id:<id>' -> '<id>'). A name-only key ('name:...') has no
        id, so $null: the page then links the name to a search instead of guessing a CI.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key)) { return $null }
    if ($Key -match '^id:(.+)$') { return $Matches[1].Trim() }
    return $null
}

function ConvertTo-RAExecViewAsset {
    <#
    .SYNOPSIS
        PURE. One Top-50 asset (the live aggregate, or the same object read back from the shared snapshot) -> the
        shape the web app reads. The numbers are exactly the ones the AI was given to copy into the mail.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Asset, [Parameter(Mandatory)][int]$Rank)

    $domains = @()
    if ($null -ne $Asset.Domains) { $domains = @(@($Asset.Domains) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique) }
    $items = @()
    if ($null -ne $Asset.TopItems) { $items = @(@($Asset.TopItems) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Select-Object -First 12) }
    $key = if ($Asset.PSObject.Properties['AssetKey']) { [string]$Asset.AssetKey } else { '' }
    [ordered]@{
        Rank              = $Rank
        Asset             = [string]$Asset.Asset
        AssetId           = (Get-RAExecViewAssetId -Key $key)
        Tier              = [string]$Asset.TierLevel
        WeightedRiskScore = [double]$Asset.TotalRiskScore_Weighted
        TotalRiskScore    = [double]$Asset.TotalRiskScore
        Findings          = [int]$Asset.Findings
        Domains           = @($domains)
        TopItems          = @($items)
        CmdbName          = [string]$Asset.CmdbName
        CmdbCriticality   = [string]$Asset.CmdbCriticality
    }
}

function ConvertTo-RAExecViewFinding {
    <#
    .SYNOPSIS
        PURE. One Top finding (live aggregate or read back) -> the web app's shape, with its five hottest assets.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Finding, [Parameter(Mandatory)][int]$Rank)

    $scores = @()
    $ars = $Finding.AssetRiskScores
    if ($null -ne $ars) {
        $pairs = if ($ars -is [System.Collections.IDictionary]) { @($ars.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Asset = [string]$_.Key; W = [double]$_.Value } }) }
                 else { @($ars.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Asset = [string]$_.Name; W = [double]$_.Value } }) }
        $scores = @($pairs | Sort-Object -Property @{ e = 'W'; Descending = $true }, @{ e = 'Asset'; Descending = $false } | Select-Object -First 5 | ForEach-Object { [ordered]@{ Asset = $_.Asset; WeightedRiskScore = $_.W } })
    }
    [ordered]@{
        Rank               = $Rank
        ConfigurationId    = [string]$Finding.ConfId
        Name               = [string]$Finding.ConfName
        Category           = [string]$Finding.Category
        Subcategory        = [string]$Finding.Subcategory
        Severity           = [string]$Finding.Severity
        Domain             = [string]$Finding.Domain
        AffectedAssetCount = [int]$Finding.AffectedAssetCount
        WeightedRiskScore  = [double]$Finding.TotalRiskScore_Weighted
        TotalRiskScore     = [double]$Finding.TotalRiskScore
        TopAffectedAssets  = @($scores)
    }
}

function New-RAExecViewSnapshot {
    <#
    .SYNOPSIS
        PURE. The executive view of one run: exactly what its mail rendered.

    .PARAMETER Kpi
        $global:RA_KPI AFTER the cache override -- i.e. the KPI the mail shows. $null when the roll-up failed; the
        page then says there is no score for this run instead of showing the mail's 100 placeholder.
    .PARAMETER FiguresFromTemplate
        The report whose figures the mail carried: this run's own template, or the leader's when it adopted them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Summary', 'Detailed')][string]$Grain,
        [Parameter()][AllowNull()][string]$ReportTemplate,
        [Parameter()][AllowNull()][string]$Tenant,
        [Parameter(Mandatory)][datetime]$GeneratedAtUtc,
        [Parameter()][AllowNull()][object]$CollectionTime,
        [Parameter()][AllowNull()][string]$SolutionVersion,
        [Parameter(Mandatory)][ValidateSet('Consistent', 'PerReport')][string]$Mode,
        [Parameter(Mandatory)][ValidateSet('Summary', 'Detailed')][string]$Leader,
        [Parameter()][int]$MaxAgeHours = 24,
        [Parameter()][AllowNull()][string]$FiguresFromTemplate,
        [Parameter()][AllowNull()][object]$FiguresGeneratedAt,
        [Parameter()][AllowNull()][object]$Kpi,
        [Parameter()][bool]$AISummaryEnabled,
        [Parameter()][AllowNull()][string]$AISummaryText,
        [Parameter()][AllowNull()][object[]]$TopAssets,
        [Parameter()][AllowNull()][object[]]$TopFindings
    )

    $fromTpl = if ([string]::IsNullOrWhiteSpace($FiguresFromTemplate)) { [string]$ReportTemplate } else { $FiguresFromTemplate }
    $fromGrain = Get-RAReportGrainLabel -ReportTemplate $fromTpl
    if (-not $fromGrain) { $fromGrain = $Grain }

    $kpiOut = $null
    if ($null -ne $Kpi -and $null -ne $Kpi.GlobalScore) {
        $sbd = ConvertTo-RAExecViewCounts -Value $Kpi.SevByDomain -Nested
        # The mail's Total row: SevCount + TotalRows (derived from the per-domain rows when the KPI was adopted).
        $kpiOut = [ordered]@{
            GlobalScore = [int]$Kpi.GlobalScore
            Band        = [string]$Kpi.Band
            DomainScore = (ConvertTo-RAExecViewCounts -Value $Kpi.DomainScore)
            SevByDomain = $sbd
            SevCount    = (ConvertTo-RAExecViewCounts -Value $Kpi.SevCount)
            TotalRows   = [int]$Kpi.TotalRows
        }
        # #636 (owner 2026-10-19): the PROTECTION SCORE replaces the old 0-100 KPI on every page -- both views and the split by asset
        # type (GlobalScore / Band / DomainScore stay in the payload only for views kept before; nothing shows them)
        $p = $null; if ($Kpi.PSObject.Properties['Protection']) { $p = $Kpi.Protection }
        if ($null -ne $p -and $null -ne $p.Lifecycle) {
            $types = [ordered]@{}
            foreach ($row in @($p.Rows)) { if ($null -ne $row -and $row.Dim2 -eq '(all)' -and $row.Dim1 -ne '(all)' -and $row.Figure -in 'technical', 'lifecycle') { if (-not $types.Contains([string]$row.Dim1)) { $types[[string]$row.Dim1] = [ordered]@{ Assets = [int]$row.Total } }; $types[[string]$row.Dim1][$(if ($row.Figure -eq 'technical') { 'Technical' } else { 'Lifecycle' })] = $row.Value } }
            $kpiOut['Protection'] = [ordered]@{ Lifecycle = [double]$p.Lifecycle; Technical = [double]$p.Technical; LifecycleGood = [int]$p.LifecycleGood; TechnicalGood = [int]$p.TechnicalGood
                                         Assets = [int]$p.Assets; NoDate = [int]$p.NoDate; Findings = [int]$p.Findings; ByType = $types }
        }
    }

    # (lists, never += on an array in a loop)
    $assetList = New-Object 'System.Collections.Generic.List[object]'; $r = 0
    foreach ($a in @($TopAssets)) { if ($null -eq $a) { continue }; $r++; $assetList.Add((ConvertTo-RAExecViewAsset -Asset $a -Rank $r)) }
    $assets = $assetList.ToArray()
    $findingList = New-Object 'System.Collections.Generic.List[object]'; $r = 0
    foreach ($f in @($TopFindings)) { if ($null -eq $f) { continue }; $r++; $findingList.Add((ConvertTo-RAExecViewFinding -Finding $f -Rank $r)) }
    $findings = $findingList.ToArray()

    $ct = $null
    if ($null -ne $CollectionTime -and [string]$CollectionTime -ne '') { try { $ct = ([datetime]$CollectionTime).ToUniversalTime().ToString('o') } catch { $ct = [string]$CollectionTime } }
    $fga = $null
    if ($null -ne $FiguresGeneratedAt -and [string]$FiguresGeneratedAt -ne '') {
        try {
            $d = if ($FiguresGeneratedAt -is [datetime]) { [datetime]$FiguresGeneratedAt } else { [datetime]::Parse([string]$FiguresGeneratedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) }
            $fga = $d.ToUniversalTime().ToString('o')
        } catch { $fga = $null }
    }
    if (-not $fga) { $fga = $GeneratedAtUtc.ToUniversalTime().ToString('o') }

    [ordered]@{
        SchemaVersion     = 1
        Grain             = $Grain
        ReportTemplate    = [string]$ReportTemplate
        Tenant            = [string]$Tenant
        GeneratedAt       = $GeneratedAtUtc.ToUniversalTime().ToString('o')
        CollectionTime    = $ct
        SolutionVersion   = [string]$SolutionVersion
        Mode              = $Mode
        Leader            = $Leader
        MaxAgeHours       = $MaxAgeHours
        # Consistent mode only shares figures through the AI summary snapshot -- with the AI summary off, each report
        # shows its own KPI even in Consistent mode, and the page must say so rather than claim agreement.
        SharesFigures     = [bool]($Mode -eq 'Consistent' -and $AISummaryEnabled)
        FiguresFrom       = [ordered]@{ Grain = $fromGrain; ReportTemplate = $fromTpl; GeneratedAt = $fga }
        Kpi               = $kpiOut
        AISummaryEnabled  = [bool]$AISummaryEnabled
        AISummaryText     = [string]$AISummaryText
        TopAssets         = @($assets)
        TopFindings       = @($findings)
    }
}

function Get-RAExecViewBlobName {
    <#
    .SYNOPSIS
        PURE. The blob for one grain, beside the shared Top-50 snapshot ('risk-analysis/RiskAnalysis_ExecView_<Grain>.json').
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Summary', 'Detailed')][string]$Grain, [Parameter()][AllowNull()][string]$Top50BlobName)
    $folder = 'risk-analysis'
    if (-not [string]::IsNullOrWhiteSpace($Top50BlobName) -and $Top50BlobName.Contains('/')) { $folder = $Top50BlobName.Substring(0, $Top50BlobName.LastIndexOf('/')) }
    if ([string]::IsNullOrWhiteSpace($folder)) { return ('RiskAnalysis_ExecView_{0}.json' -f $Grain) }
    return ('{0}/RiskAnalysis_ExecView_{1}.json' -f $folder.TrimEnd('/'), $Grain)
}

function Save-RAExecViewFile {
    <#
    .SYNOPSIS
        Write the snapshot to the output folder and mirror it to the blob. NEVER throws; returns what was written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter()][AllowNull()][string]$StorageAccount,
        [Parameter()][string]$Container = 'sistaging',
        [Parameter(Mandatory)][string]$BlobName
    )
    $res = [pscustomobject]@{ Local = $false; Blob = $false; Error = $null }
    try {
        [System.IO.File]::WriteAllText($LocalPath, $Json, (New-Object System.Text.UTF8Encoding($false)))
        $res.Local = $true
    } catch { $res.Error = 'local: ' + $_.Exception.Message; return $res }
    if ([string]::IsNullOrWhiteSpace($StorageAccount)) { return $res }
    try {
        if (-not (Get-Command -Name New-SIAzStorageContext -ErrorAction SilentlyContinue)) { return $res }
        $ctx = New-SIAzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount -ErrorAction Stop
        if (-not (Get-SIAzStorageContainer -Name $Container -Context $ctx -ErrorAction SilentlyContinue)) {
            New-SIAzStorageContainer -Name $Container -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
        }
        $prev = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
        try { Set-SIAzStorageBlobContent -Container $Container -File $LocalPath -Blob $BlobName -Context $ctx -Force -ErrorAction Stop | Out-Null }
        finally { $ProgressPreference = $prev }
        $res.Blob = $true
    } catch { $res.Error = 'blob: ' + $_.Exception.Message }
    return $res
}
