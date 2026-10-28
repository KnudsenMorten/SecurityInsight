#Requires -Version 5.1
<#
    SecurityInsight SOURCE OF TRUTH BY PROVIDER TIMESTAMPS -- REQUIREMENTS #459, V3-DATA-MODEL 2.6.

    Resolve-SICiField (SI-CiBuild.ps1) picks each SI field's value on the CI: fresh candidates only (the record's provider
    timestamp -- the mapping object's 'timestamp', si_source_last_seen -- within the field's staleDays), then the first
    provider in the field's authority order; no fresh candidate -> the newest value, marked stale; risk booleans any-true;
    lists union. The winner is recorded in si_field_sources {provider, record, observed_at, stale}.

    This file adds what 2.6 asks for beyond the winner: CONFLICTS. When other FRESH providers hold a different value for a
    single-value (authority) field, they are recorded beside the winner (si_field_sources.<field>.conflicts), so a
    disagreement is visible on the CI page instead of silently lost -- "AD still says 10.0.0.5, Defender says 10.0.4.17".
    It never changes the value.

    Each provider's "last updated" field (the mapping object's timestamp; a missing value = the collection time):
      mde     machine.lastSeen                          (sensor heartbeat)
      entra   device.approximateLastSignInDateTime      (devices; users and service principals: the directory read)
      intune  device.lastSyncDateTime
      eg      node.NodeProperties.rawData.lastSeen
      ad      lastLogonTimestamp                        (replicates with a 9-14 day lag)
      mdi     identity.Timestamp
      azure   the collection time                       (Resource Graph has no last seen)
      shodan  host.last_update
      cmdb    ci.UpdatedAt;  servicenow  ci.sys_updated_on
    Get-SIProviderTimestampFields reads them from the mappings (the mappings are the one source).

    PURE. PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIItemValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

$script:SIFieldConflictMax = 5

function Get-SIProviderTimestampFields {
    <# PURE. Per provider and record type: the source path of its "last updated" timestamp ('$collection_time' = none). #>
    param([Parameter(Mandatory)]$Model)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Model.Mappings.Keys) {
        foreach ($o in @($Model.Mappings[$p].objects)) {
            if ($null -eq $o) { continue }
            $out.Add([pscustomobject]@{ Provider = [string]$p; RecordType = [string]$o.recordType; Timestamp = [string]$o.timestamp })
        }
    }
    return $out.ToArray()   # unrolled: foreach and @() both read it as the list
}

function ConvertTo-SIFieldCompareText {
    <# PURE. A value as comparable text: trimmed, case-insensitive; a list as its sorted, de-duplicated items. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return ([string]$Value).ToLowerInvariant() }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [string]) { return $Value.Trim().ToLowerInvariant() }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) {
        $xs = [string[]]@(foreach ($x in $Value) { ConvertTo-SIFieldCompareText $x } )
        $xs = [string[]]@($xs | Where-Object { $_ } | Select-Object -Unique)
        [Array]::Sort($xs, [StringComparer]::Ordinal)
        return ($xs -join '|')
    }
    if ($Value -is [ValueType]) { return ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)).ToLowerInvariant() }
    return (($Value | ConvertTo-Json -Compress -Depth 6)).ToLowerInvariant()
}

function Get-SICiFieldConflicts {
    <#
    .SYNOPSIS  PURE. The fresh candidates of a single-value (authority) field that disagree with the resolved value.
    .PARAMETER Candidates  as Resolve-SICiField takes them: @{ Record; Provider; Key; State }
    .PARAMETER Resolved    Resolve-SICiField's result (@{ Value; Provider; Record; Stale })
    .OUTPUTS   [ [ordered]@{ provider; record; value; observed_at } ] -- at most 5, freshest first; empty when the field
               is not an authority field, the value is stale (nothing fresh to disagree with) or every source agrees.
    #>
    param([Parameter(Mandatory)]$Field, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Candidates, $Resolved, [datetime]$Now = [datetime]::UtcNow)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Resolved -or [bool]$Resolved.Stale) { return , $out.ToArray() }
    if ([string]$Field.resolution.policy -ne 'authority') { return , $out.ToArray() }
    $staleDays = 30
    if ($null -ne $Field.resolution.staleDays) { $staleDays = [double]$Field.resolution.staleDays }
    # (2026-10-16: the winner's text is made only when another candidate has to be compared with it -- most CIs have one
    # record, and this runs for every field of every CI)
    $other = $false
    foreach ($c in $Candidates) { if ($null -ne $c -and [string]$c.Key -ne [string]$Resolved.Record) { $other = $true; break } }
    if (-not $other) { return , $out.ToArray() }
    $win = ConvertTo-SIFieldCompareText $Resolved.Value
    $seenText = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Candidates) {
        if ($null -eq $c -or [string]$c.Key -eq [string]$Resolved.Record) { continue }
        $v = Get-SIItemValue $c.Record ([string]$Field.name)
        if (Test-SIValueEmpty $v) { if (-not ($v -is [bool])) { continue } }
        $seen = ConvertTo-SIUtcOrNull (Get-SIItemValue $c.Record 'si_source_last_seen')
        $fresh = ($c.State -in 'active', 'frozen') -and ($null -ne $seen) -and ((($Now - $seen).TotalDays) -le $staleDays)
        if (-not $fresh) { continue }
        $t = ConvertTo-SIFieldCompareText $v
        if ($t -eq $win) { continue }
        $rows.Add([pscustomobject]@{ Seen = $seen; Text = $t; Entry = [ordered]@{ provider = [string]$c.Provider; record = [string]$c.Key; value = $v; observed_at = $seen } })
    }
    foreach ($r in @($rows.ToArray() | Sort-Object -Property @{ Expression = { $_.Seen }; Descending = $true })) {
        if ($out.Count -ge $script:SIFieldConflictMax) { break }
        if (-not $seenText.Add(('{0}|{1}' -f $r.Entry.provider, $r.Text))) { continue }
        $out.Add($r.Entry)
    }
    return , $out.ToArray()
}
