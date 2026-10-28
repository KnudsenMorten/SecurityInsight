#Requires -Version 5.1
<#
    Convert-EgBlob.ps1

    Recursive scrubber for Microsoft Exposure Graph rawData blobs. EG JSON
    includes @odata.type annotations on every collection / sub-object
    (#Collection(String), #Int64, #microsoft.graph.security.dynamicColumnValue,
    ...). They are noise inside Properties.collect.exposureGraph; KQL
    parse_json doesn't need them and they bloat the column.

    Walks hashtables, pscustomobjects, and arrays. Scalar values pass through
    unchanged. Used by all *ProfileRow builders that surface an EG rawData
    blob (identity, endpoint, publicip, azure).
#>

function ConvertTo-SICleanedEgBlob {
    param([Parameter()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [datetime]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in $Value.Keys) {
            if ([string]$k -like '*@odata.type') { continue }
            $out[[string]$k] = ConvertTo-SICleanedEgBlob -Value $Value[$k]
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $out = New-Object System.Collections.ArrayList
        foreach ($item in $Value) { [void]$out.Add((ConvertTo-SICleanedEgBlob -Value $item)) }
        return $out.ToArray()
    }
    if ($Value.PSObject -and $Value.PSObject.Properties) {
        $out = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) {
            if ($p.Name -like '*@odata.type') { continue }
            $out[$p.Name] = ConvertTo-SICleanedEgBlob -Value $p.Value
        }
        return $out
    }
    return $Value
}
