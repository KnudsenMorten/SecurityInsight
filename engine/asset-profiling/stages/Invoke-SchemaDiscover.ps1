#Requires -Version 5.1
<#
    SchemaDiscover stage (schema-discovery engine, ).

    Sweeps the Microsoft Defender XDR Advanced Hunting surface to build a
    complete picture of EVERY exploitable property/edge Microsoft currently
    exposes. Output of this stage is consumed by SchemaDiff to detect
    Microsoft-shipped additions since the last sweep.

    Coverage:
      1. ExposureGraphNodes  -- distinct NodeLabel + sample props per label
      2. ExposureGraphEdges  -- distinct EdgeLabel + (Source,Edge,Target) triples
      3. Hunting tables      -- column schema (via getschema operator) for
                                the relevant XDR tables

    Outputs to RunContext.SchemaCatalog: hashtable with three keys
    (NodeProperties, EdgeTriples, TableColumns).
#>

# dot-source the shared KQL submitter so this stage doesn't
# depend on Stage Enrich (which the schema-discovery pipeline never loads).
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1')

function Get-SISchemaNodeLabels {
    [CmdletBinding()]
    param()

    $kql = 'ExposureGraphNodes | distinct NodeLabel | order by NodeLabel asc'
    @(Invoke-SIHuntingQuery -Query $kql -QueryEngine DefenderGraph) | ForEach-Object { [string]$_.NodeLabel }
}

function Get-SISchemaPropertiesPerLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Labels,
        [int]$SamplePerLabel = 100
    )

    $byLabel = @{}
    foreach ($lbl in $Labels) {
        if ([string]::IsNullOrWhiteSpace($lbl)) { continue }
        # Pull a sample of N nodes for this label, project NodePropertiesJson.
        # We then walk the JSON in PowerShell to enumerate every distinct
        # top-level + nested property path.
        $sampleKql = @"
ExposureGraphNodes
| where NodeLabel == '$lbl'
| take $SamplePerLabel
| project NodePropertiesJson = tostring(NodeProperties)
"@
        $rows = @(Invoke-SIHuntingQuery -Query $sampleKql -QueryEngine DefenderGraph)
        $paths = New-Object System.Collections.Generic.HashSet[string]
        foreach ($r in $rows) {
            if ([string]::IsNullOrWhiteSpace($r.NodePropertiesJson)) { continue }
            try {
                $obj = $r.NodePropertiesJson | ConvertFrom-Json -ErrorAction Stop
                Get-SIJsonPropertyPaths -Object $obj -Prefix '' -Set $paths
            } catch { }
        }
        $byLabel[$lbl] = ($paths | Sort-Object)
        Write-SIInfo ("   {0,-30}  {1} unique property paths from {2} samples" -f $lbl, $paths.Count, $rows.Count)
    }
    $byLabel
}

function Get-SIJsonPropertyPaths {
    <#
        Recursive walker. Enumerates every dot-path in a JSON object. Arrays
        contribute one entry "<path>[*]" plus walks their first element to
        capture inner shape (since arrays of mixed types are rare in EG).
        Caps recursion depth at 6 to avoid pathological inputs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$Set,
        [int]$Depth = 0
    )

    if ($Depth -gt 6 -or $null -eq $Object) { return }

    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string]) {
        # Array
        $void = $Set.Add(($Prefix + '[*]'))
        $first = $null
        foreach ($el in $Object) { $first = $el; break }
        if ($null -ne $first) {
            Get-SIJsonPropertyPaths -Object $first -Prefix ($Prefix + '[*]') -Set $Set -Depth ($Depth + 1)
        }
        return
    }
    if ($Object -is [psobject]) {
        foreach ($p in $Object.PSObject.Properties) {
            $path = if ($Prefix) { ($Prefix + '.' + $p.Name) } else { $p.Name }
            $void = $Set.Add($path)
            Get-SIJsonPropertyPaths -Object $p.Value -Prefix $path -Set $Set -Depth ($Depth + 1)
        }
        return
    }
    # Scalar -- the path itself was added by the parent. Nothing further.
}

function Get-SISchemaEdgeTriples {
    [CmdletBinding()]
    param([int]$SamplePerEdge = 1000)

    # First, enumerate all distinct edge labels.
    $edgeLabels = @(Invoke-SIHuntingQuery -Query 'ExposureGraphEdges | distinct EdgeLabel | order by EdgeLabel asc' -QueryEngine DefenderGraph) | ForEach-Object { [string]$_.EdgeLabel }

    $triples = @{}
    foreach ($el in $edgeLabels) {
        if ([string]::IsNullOrWhiteSpace($el)) { continue }
        $kql = @"
ExposureGraphEdges
| where EdgeLabel == '$el'
| take $SamplePerEdge
| summarize Count = count() by SourceNodeLabel, EdgeLabel, TargetNodeLabel
| order by Count desc
"@
        $rows = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine DefenderGraph)
        if ($rows.Count -gt 0) {
            $triples[$el] = $rows | ForEach-Object {
                @{
                    Source = [string]$_.SourceNodeLabel
                    Edge   = [string]$_.EdgeLabel
                    Target = [string]$_.TargetNodeLabel
                    SampleCount = [int64]$_.Count
                }
            }
        }
    }
    $triples
}

function Get-SISchemaHuntingTableColumns {
    [CmdletBinding()]
    # -Tables: exactly these tables (continuous discovery asks for the tables SecurityInsight reads besides the list below)
    param([string[]]$Tables = @())

    # Curated list of high-signal hunting tables. getschema is the canonical
    # way to enumerate columns server-side. Add tables here as Microsoft
    # ships them; the customer can extend via $global:SI_SchemaTables.
    $defaultTables = @(
        'DeviceInfo','DeviceLogonEvents','DeviceProcessEvents','DeviceFileEvents',
        'IdentityInfo','IdentityLogonEvents','IdentityDirectoryEvents','IdentityQueryEvents',
        'AlertEvidence','AlertInfo',
        'EmailEvents','EmailUrlInfo','EmailAttachmentInfo',
        'CloudAppEvents','UrlClickEvents',
        'ExposureGraphNodes','ExposureGraphEdges'
    )
    $tables = if (@($Tables).Count -gt 0) { @($Tables) } elseif ($global:SI_SchemaTables) { @($global:SI_SchemaTables) } else { $defaultTables }

    $byTable = @{}
    foreach ($t in $tables) {
        $kql = ('{0} | getschema' -f $t)
        try {
            $cols = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine DefenderGraph) | ForEach-Object {
                @{ Name = [string]$_.ColumnName; Type = [string]$_.ColumnType }
            }
            if ($cols.Count -gt 0) { $byTable[$t] = $cols }
        } catch { }
    }
    $byTable
}

function Invoke-SISchemaDiscover {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    if ($RunContext.StorageContext.Mode -eq 'Mock') {
        $RunContext | Add-Member -MemberType NoteProperty -Name SchemaCatalog -Value @{
            NodeLabels      = @('user','device','application')
            NodeProperties  = @{ user = @('rawData.accountEnabled','rawData.accountName'); device = @('rawData.deviceCategory') }
            EdgeTriples     = @{ 'has access to' = @(@{ Source='user'; Edge='has access to'; Target='storageaccount' }) }
            TableColumns    = @{}
        } -Force
        return [pscustomobject]@{
            Stage   = 'SchemaDiscover'
            Summary = 'mock (stubbed)'
        }
    }

    Write-SIInfo '   Enumerating EG NodeLabels ...'
    $labels = Get-SISchemaNodeLabels
    Write-SIInfo ('   Found {0} distinct labels' -f $labels.Count)

    Write-SIInfo '   Sampling properties per label ...'
    $nodeProps = Get-SISchemaPropertiesPerLabel -Labels $labels -SamplePerLabel 100

    Write-SIInfo '   Enumerating EG EdgeLabels + triples ...'
    $edgeTriples = Get-SISchemaEdgeTriples -SamplePerEdge 1000
    Write-SIInfo ('   Found {0} edge labels' -f $edgeTriples.Keys.Count)

    Write-SIInfo '   Sampling hunting table column schemas ...'
    $tableCols = Get-SISchemaHuntingTableColumns
    Write-SIInfo ('   Captured schemas for {0} tables' -f $tableCols.Keys.Count)

    $catalog = @{
        CapturedAt      = ([datetime]::UtcNow.ToString('o'))
        NodeLabels      = $labels
        NodeProperties  = $nodeProps
        EdgeTriples     = $edgeTriples
        TableColumns    = $tableCols
    }
    $RunContext | Add-Member -MemberType NoteProperty -Name SchemaCatalog -Value $catalog -Force

    # CONTINUOUS DISCOVERY FOR EVERY SOURCE (engine/data-model/SI-SourceDiscovery.ps1): what the sources offer beyond what
    # the runs read -- Microsoft Graph's published model, the hunting tables' columns (the ones above plus the Defender
    # tables SecurityInsight reads), the node types not recorded yet, a sample of Defender for Cloud assessments -- saved
    # for the web app's "New context available". The extra tables are NOT added to the catalog above (its additions are
    # drafted into rules); they are read here only. Never fails the sweep.
    $discoveryText = ''
    try {
        $dmRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
        if (-not (Get-Command -Name Get-SIEgRecordType -ErrorAction SilentlyContinue)) { . (Join-Path $dmRoot 'SI-RecordCapture.ps1') }
        if (-not (Get-Command -Name Invoke-SISourceDiscoverySweep -ErrorAction SilentlyContinue)) { . (Join-Path $dmRoot 'SI-SourceDiscovery.ps1') }
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $dmRoot 'SI-RecordSql.ps1') }
        if (-not (Get-Command -Name Get-SIObjectLedgerConnection -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($dmRoot, 'identity', 'SI-ObjectLedgerStore.ps1')) }
        if (Test-SISourceDiscoveryOn) {
            $sweepTables = @{}
            foreach ($k in @($tableCols.Keys)) { $sweepTables[$k] = $tableCols[$k] }
            $more = @(Get-SISourceDiscoveryHuntingTables | Where-Object { -not $sweepTables.ContainsKey($_) })
            if ($more.Count -gt 0) { $extra = Get-SISchemaHuntingTableColumns -Tables $more; foreach ($k in @($extra.Keys)) { $sweepTables[$k] = $extra[$k] } }
            $sweep = Invoke-SISourceDiscoverySweep -Catalog @{ TableColumns = $sweepTables; NodeProperties = $nodeProps } -Invoke (New-SIRecordSqlInvoke) `
                -RunId ('schema-' + [string]$RunContext.RunId)
            if ($sweep -and $sweep.Result) {
                $discoveryText = Get-SISourceDiscoverySummaryText -Result $sweep.Result -What 'the weekly sweep of every source'
                Write-SIInfo ('   ' + $discoveryText)
                foreach ($sp in @($sweep.Providers)) { if ($sp -and $sp.Error) { Write-SIInfo ('   {0}: not read this week -- {1}' -f $sp.Provider, $sp.Error) } }
            }
        }
    } catch { Write-Warning ('The weekly list of what each source offers could not be built -- {0}. The schema sweep itself is unaffected.' -f $_.Exception.Message) }

    # #689 WEEKLY CONTEXT DISCOVERY FOR RISK ANALYSIS (engine/data-model/SI-ContextDiscovery.ps1) -- the same step the Risk
    # Analysis Detailed run takes once a week, here with the edge labels this sweep already read; the Detailed run then
    # finds it done. Never fails the sweep.
    $contextText = ''
    try {
        $siRootCd = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        if (-not (Get-Command -Name Invoke-SIContextDiscovery -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($siRootCd, 'engine', 'data-model', 'SI-ContextDiscovery.ps1')) }
        if (Test-SIContextDiscoveryOn) {
            $cdInvoke = $null
            if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { $cdInvoke = New-SIRecordSqlInvoke }
            $cd = Invoke-SIContextDiscovery -SIRoot $siRootCd -Invoke $cdInvoke -EdgeTriples $edgeTriples -RunId ('context-schema-' + [string]$RunContext.RunId)
            $contextText = Get-SIContextDiscoverySummaryText -Result $cd
            Write-SIInfo ('   ' + $contextText)
            foreach ($l in @($cd.Lines)) { Write-SIInfo ('   ' + $l) }
        }
    } catch { Write-Warning ('The weekly context discovery could not run -- {0}. The schema sweep itself is unaffected.' -f $_.Exception.Message) }

    [pscustomobject]@{
        Stage           = 'SchemaDiscover'
        SourceDiscovery = $discoveryText
        ContextDiscovery = $contextText
        NodeLabels      = $labels.Count
        EdgeLabels      = $edgeTriples.Keys.Count
        Tables          = $tableCols.Keys.Count
        TotalNodeProps  = (($nodeProps.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum
        Summary         = ('{0} node labels, {1} edge labels, {2} tables, {3} total node-property paths' -f $labels.Count, $edgeTriples.Keys.Count, $tableCols.Keys.Count, (($nodeProps.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum)
    }
}
