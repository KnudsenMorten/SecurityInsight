#Requires -Version 5.1
<#
    SchemaDiff stage. Loads the previous baseline from staging blob,
    compares to RunContext.SchemaCatalog produced by SchemaDiscover,
    classifies each finding as New / Removed / Unchanged, and stamps
    the diff onto RunContext.SchemaDiff for the AI proposer.

    Baseline blob name: schema-baseline.json (in staging container,
    NOT shard-scoped -- the baseline is global to the engine).
#>

function Invoke-SISchemaDiff {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    if (-not $RunContext.SchemaCatalog) {
        return [pscustomobject]@{ Stage='SchemaDiff'; Summary='no catalog from SchemaDiscover -- skipped' }
    }

    $current  = $RunContext.SchemaCatalog
    $baseline = $null

    if ($RunContext.StorageContext.Mode -ne 'Mock') {
        try {
            $blob = Get-AzStorageBlob -Container $RunContext.StagingContainer -Blob 'schema-baseline.json' -Context $RunContext.StorageContext.AzContext -ErrorAction Stop
            $tmp  = New-TemporaryFile
            $null = Get-AzStorageBlobContent -CloudBlob $blob.ICloudBlob -Destination $tmp.FullName -Force -Context $RunContext.StorageContext.AzContext -ErrorAction Stop
            $baseline = Get-Content -Raw $tmp.FullName | ConvertFrom-Json
            Remove-Item -Path $tmp.FullName -Force
        } catch {
            # First run: no baseline yet. EVERYTHING in $current is "new".
            Write-SIInfo '   No prior baseline found -- this is the first sweep. All findings will register as new.'
        }
    }

    $diff = @{
        NewNodeLabels       = New-Object System.Collections.ArrayList
        NewNodeProperties   = New-Object System.Collections.ArrayList   # @{ Label; Path }
        NewEdgeLabels       = New-Object System.Collections.ArrayList
        NewEdgeTriples      = New-Object System.Collections.ArrayList   # @{ Source; Edge; Target }
        NewTableColumns     = New-Object System.Collections.ArrayList   # @{ Table; Column; Type }
    }

    if ($null -eq $baseline) {
        # First sweep: everything new.
        foreach ($lbl in $current.NodeLabels) { [void]$diff.NewNodeLabels.Add($lbl) }
        foreach ($lbl in $current.NodeProperties.Keys) {
            foreach ($p in $current.NodeProperties[$lbl]) {
                [void]$diff.NewNodeProperties.Add(@{ Label = $lbl; Path = $p })
            }
        }
        foreach ($el in $current.EdgeTriples.Keys) {
            [void]$diff.NewEdgeLabels.Add($el)
            foreach ($t in $current.EdgeTriples[$el]) {
                [void]$diff.NewEdgeTriples.Add(@{ Source = $t.Source; Edge = $t.Edge; Target = $t.Target })
            }
        }
        foreach ($tbl in $current.TableColumns.Keys) {
            foreach ($c in $current.TableColumns[$tbl]) {
                [void]$diff.NewTableColumns.Add(@{ Table = $tbl; Column = $c.Name; Type = $c.Type })
            }
        }
    } else {
        # Compare to baseline. Anything in current but not in baseline = new.
        $baseLabels = @($baseline.NodeLabels)
        foreach ($lbl in $current.NodeLabels) {
            if ($baseLabels -notcontains $lbl) { [void]$diff.NewNodeLabels.Add($lbl) }
        }

        foreach ($lbl in $current.NodeProperties.Keys) {
            $basePropsForLabel = if ($baseline.NodeProperties.PSObject.Properties[$lbl]) {
                @($baseline.NodeProperties.$lbl)
            } else { @() }
            foreach ($p in $current.NodeProperties[$lbl]) {
                if ($basePropsForLabel -notcontains $p) {
                    [void]$diff.NewNodeProperties.Add(@{ Label = $lbl; Path = $p })
                }
            }
        }

        $baseEdgeLabels = @($baseline.EdgeTriples.PSObject.Properties.Name)
        foreach ($el in $current.EdgeTriples.Keys) {
            if ($baseEdgeLabels -notcontains $el) { [void]$diff.NewEdgeLabels.Add($el) }
            $baseTriples = if ($baseline.EdgeTriples.PSObject.Properties[$el]) { @($baseline.EdgeTriples.$el) } else { @() }
            foreach ($t in $current.EdgeTriples[$el]) {
                $key = ('{0}|{1}|{2}' -f $t.Source, $t.Edge, $t.Target)
                $exists = $baseTriples | Where-Object { (('{0}|{1}|{2}' -f $_.Source, $_.Edge, $_.Target) -eq $key) } | Select-Object -First 1
                if (-not $exists) {
                    [void]$diff.NewEdgeTriples.Add(@{ Source = $t.Source; Edge = $t.Edge; Target = $t.Target })
                }
            }
        }

        foreach ($tbl in $current.TableColumns.Keys) {
            $baseCols = if ($baseline.TableColumns.PSObject.Properties[$tbl]) {
                @($baseline.TableColumns.$tbl) | ForEach-Object { [string]$_.Name }
            } else { @() }
            foreach ($c in $current.TableColumns[$tbl]) {
                if ($baseCols -notcontains $c.Name) {
                    [void]$diff.NewTableColumns.Add(@{ Table = $tbl; Column = $c.Name; Type = $c.Type })
                }
            }
        }
    }

    $RunContext | Add-Member -MemberType NoteProperty -Name SchemaDiff -Value $diff -Force

    [pscustomobject]@{
        Stage             = 'SchemaDiff'
        NewNodeLabels     = $diff.NewNodeLabels.Count
        NewNodeProperties = $diff.NewNodeProperties.Count
        NewEdgeLabels     = $diff.NewEdgeLabels.Count
        NewEdgeTriples    = $diff.NewEdgeTriples.Count
        NewTableColumns   = $diff.NewTableColumns.Count
        Summary           = ('new -- labels:{0} props:{1} edges:{2} triples:{3} cols:{4}' -f $diff.NewNodeLabels.Count, $diff.NewNodeProperties.Count, $diff.NewEdgeLabels.Count, $diff.NewEdgeTriples.Count, $diff.NewTableColumns.Count)
    }
}
