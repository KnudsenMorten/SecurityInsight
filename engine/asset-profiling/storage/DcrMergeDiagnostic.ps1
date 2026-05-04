#Requires -Version 5.1
<#
    DcrMergeDiagnostic.ps1

    OPTIONAL pre-merge diagnostic for the AzLogDcrIngestPS DCR-merge path.

    User report: "AzLogDcrIngestPS keeps merging the DCR every run -- which
    column is causing the schema diff?". The module logs "merging schema"
    but doesn't say WHAT differs.

    This file adds a one-shot helper that:
      1. Fetches the existing DCR from ARM via `az rest`.
      2. Reads streamDeclarations[0].columns -- the DCR's current schema.
      3. Compares it to the in-memory row sample's columns (NoteProperty set).
      4. Logs:
           [+] columns ADDED (in row, not in DCR)            -> trigger schema-extend
           [-] columns REMOVED (in DCR, not in row)          -> orphaned (no row carries them this run)
           [~] columns TYPE-MISMATCHED                       -> merge will rewrite type metadata

    Gating:
      - OFF by default. Enable per-launcher via $global:SI_DcrMergeDiagnostic = $true.
      - On any failure path (missing az CLI, ARM 404, JSON parse error) the
        diagnostic logs a warning and returns silently. NEVER throws --
        diagnostics must not break the ingest pipeline.

    Why an external az-rest call rather than tapping into AzLogDcrIngestPS:
      The module is a published PSGallery dependency; modifying it is out
      of scope. Calling `az rest` is auth-free piggy-back on the operator's
      existing az-cli context (Bootstrap-Auth.ps1 already requires az login
      for everything else). Cross-platform (works in container + VM).

    Usage (called from Stage Output before CheckCreateUpdate-TableDcr-Structure):
        . (Join-Path $PSScriptRoot '..\storage\DcrMergeDiagnostic.ps1')
        Invoke-SIDcrMergeDiagnostic -DcrName $dcrName -DcrResourceGroup $global:SI_DcrResourceGroup -SchemaSample $schemaSample
#>

function _Get-SIDcrColumnTypeMap {
    <# Internal -- inspect a sample row's NoteProperty values + return a map
       of @{column = inferred-DCR-type}. Mirrors AzLogDcrIngestPS's coarse
       inference (string / dynamic / long / real / boolean / datetime).
       Used to compare against the DCR's declared column types. #>
    param([Parameter(Mandatory)]$SampleRow)
    $map = @{}
    foreach ($p in $SampleRow.PSObject.Properties) {
        $name = $p.Name
        $val  = $p.Value
        $type = 'string'
        if     ($null -eq $val)                                 { $type = 'string' }   # default; DCR can't infer from null, falls back to string
        elseif ($val -is [bool])                                 { $type = 'boolean' }
        elseif ($val -is [int] -or $val -is [long])              { $type = 'long' }
        elseif ($val -is [double] -or $val -is [decimal])        { $type = 'real' }
        elseif ($val -is [datetime])                             { $type = 'datetime' }
        elseif ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) { $type = 'dynamic' }
        elseif ($val -is [System.Collections.IDictionary])       { $type = 'dynamic' }
        elseif ($val -is [PSCustomObject])                       { $type = 'dynamic' }
        else                                                     { $type = 'string' }
        $map[$name] = $type
    }
    return $map
}

function _Get-SIDcrSchemaFromArm {
    <# Internal -- fetch the DCR's streamDeclarations[0].columns via az CLI.
       Returns @{ Found = $true|$false; Columns = @{name = type}; Error = '...' }. #>
    param(
        [Parameter(Mandatory)][string]$DcrName,
        [Parameter(Mandatory)][string]$DcrResourceGroup,
        [string]$SubscriptionId
    )
    $result = @{ Found = $false; Columns = @{}; Error = $null }

    if (-not (Get-Command -Name az -ErrorAction SilentlyContinue)) {
        $result.Error = 'az CLI not on PATH'
        return $result
    }

    # Resolve sub: argument > $global:SI_AzSubscriptionId > current az context.
    $sub = $SubscriptionId
    if (-not $sub) { $sub = [string]$global:SI_AzSubscriptionId }
    if (-not $sub) {
        try {
            $accountJson = (az account show --output json 2>$null) -join "`n"
            if ($accountJson) {
                $acct = $accountJson | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($acct -and $acct.id) { $sub = [string]$acct.id }
            }
        } catch { }
    }
    if (-not $sub) {
        $result.Error = 'unable to resolve subscription id (no -SubscriptionId, no $global:SI_AzSubscriptionId, no az account context)'
        return $result
    }

    $url = ('https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Insights/dataCollectionRules/{2}?api-version=2022-06-01' -f `
            $sub, $DcrResourceGroup, $DcrName)
    try {
        $raw = (az rest --method get --url $url --output json 2>$null) -join "`n"
    } catch {
        $result.Error = ('az rest failed: {0}' -f $_.Exception.Message)
        return $result
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $result.Error = 'DCR not found (empty az rest response -- is this a first-run / pre-provisioning state?)'
        return $result
    }
    try {
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $result.Error = ('DCR response JSON parse failed: {0}' -f $_.Exception.Message)
        return $result
    }
    if (-not $obj.properties -or -not $obj.properties.streamDeclarations) {
        $result.Error = 'DCR has no streamDeclarations (malformed?)'
        return $result
    }
    # streamDeclarations is an object map, not an array. Take the first stream
    # (DCRs created by AzLogDcrIngestPS only have one Custom-* stream).
    $firstStream = $null
    foreach ($p in $obj.properties.streamDeclarations.PSObject.Properties) {
        $firstStream = $p.Value
        break
    }
    if (-not $firstStream -or -not $firstStream.columns) {
        $result.Error = 'DCR streamDeclarations has no columns'
        return $result
    }
    foreach ($col in $firstStream.columns) {
        if ($col.name) { $result.Columns[[string]$col.name] = [string]$col.type }
    }
    $result.Found = $true
    return $result
}

function Invoke-SIDcrMergeDiagnostic {
    <#
        Compare the in-memory schema sample's columns to the existing DCR's
        declared columns. Logs the diff. No-op when $global:SI_DcrMergeDiagnostic
        is not $true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DcrName,
        [Parameter(Mandatory)][string]$DcrResourceGroup,
        [Parameter(Mandatory)][object[]]$SchemaSample,
        [string]$SubscriptionId
    )
    if (-not $global:SI_DcrMergeDiagnostic) { return }
    if (-not $SchemaSample -or $SchemaSample.Count -eq 0) {
        Write-SIInfo '[dcr-merge-diag] schema sample empty -- skipping diagnostic.'
        return
    }

    Write-Host ''
    Write-SIStep '[dcr-merge-diag] running pre-merge schema-diff against existing DCR...'

    # Build the in-memory column->type map by walking the FIRST sample row.
    # (AzLogDcrIngestPS itself walks the full sample to infer types; for a
    # diagnostic the first non-empty row is enough -- this isn't intended to
    # exactly replicate the module's logic, just surface obvious diffs.)
    $rowMap = _Get-SIDcrColumnTypeMap -SampleRow $SchemaSample[0]

    # Fetch the DCR's current schema.
    $dcrInfo = _Get-SIDcrSchemaFromArm -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -SubscriptionId $SubscriptionId
    if (-not $dcrInfo.Found) {
        Write-Warning ('[dcr-merge-diag] cannot read DCR {0}: {1}. Diagnostic skipped.' -f $DcrName, $dcrInfo.Error)
        return
    }
    $dcrMap = $dcrInfo.Columns

    $added   = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]

    foreach ($col in $rowMap.Keys) {
        if (-not $dcrMap.ContainsKey($col)) {
            [void]$added.Add(('{0} ({1})' -f $col, $rowMap[$col]))
        } else {
            $rType = $rowMap[$col]
            $dType = $dcrMap[$col]
            if ($rType -ne $dType) {
                [void]$changed.Add(('{0}: row={1} dcr={2}' -f $col, $rType, $dType))
            }
        }
    }
    foreach ($col in $dcrMap.Keys) {
        if (-not $rowMap.ContainsKey($col)) {
            [void]$removed.Add(('{0} ({1})' -f $col, $dcrMap[$col]))
        }
    }

    Write-SIStep ('[dcr-merge-diag] DCR {0}: {1} columns, sample row: {2} columns' -f $DcrName, $dcrMap.Count, $rowMap.Count)
    if ($added.Count -eq 0 -and $removed.Count -eq 0 -and $changed.Count -eq 0) {
        Write-SIOk '[dcr-merge-diag] NO DIFF -- DCR schema matches in-memory row schema. The merge call should be a no-op.'
    } else {
        if ($added.Count -gt 0) {
            Write-SIWarn ('[dcr-merge-diag] [+] {0} column(s) ADDED (will trigger DCR schema-extend):' -f $added.Count)
            foreach ($c in $added) { Write-SIWarn ('    + ' + $c)}
        }
        if ($removed.Count -gt 0) {
            Write-SIWarn ('[dcr-merge-diag] [-] {0} column(s) ORPHANED in DCR (no row carries them this run -- merge keeps them):' -f $removed.Count)
            foreach ($c in $removed) { Write-SIWarn ('    - ' + $c)}
        }
        if ($changed.Count -gt 0) {
            Write-SIInfo ('[dcr-merge-diag] [~] {0} column(s) TYPE-MISMATCHED (merge will rewrite metadata):' -f $changed.Count)
            foreach ($c in $changed) { Write-SIInfo ('    ~ ' + $c)}
        }
    }
    Write-Host ''
}
