#Requires -Version 5.1
<#
    SI v3 PoC-0 -- CORRELATION COVERAGE, the pure analysis half.

    Dot-source this. It contains NO I/O and NO Azure calls, so every number it produces can be tested
    against synthetic rows before it is trusted against real ones.

    WHY THAT SPLIT MATTERS HERE. This measurement is supposed to DECIDE an architecture: if most assets
    carry hard cross-engine identifiers, correlation is a join; if they do not, it is fuzzy matching and
    several downstream decisions change. A miscounted number would send the design the wrong way, and a
    counting bug is indistinguishable from a real finding -- the same shape as this solution's own
    silent-loss history (#48/#57/#58.5) and of the -ForEach discovery trap in
    SI-CmdbColumnNaming.Tests.ps1, where 9 assertions generated zero cases and still reported green.

    🔒 READ-ONLY BY CONSTRUCTION. Nothing here writes, and the live query half (Measure-*.ps1) issues
    only KQL reads.
#>

# NO Set-StrictMode here. MEASURED 2026-08-12: Set-StrictMode in a dot-sourced file LEAKS INTO THE
# CALLER'S SCOPE, so a library silently overrides the strictness its host chose -- and the shipped
# engines run Set-StrictMode -Off ("designed for non-StrictMode environments"). This file is dot-sourced
# by its tests today and is a promotion candidate for the connector work; removing it here means the
# hazard does not travel with the code, which is exactly how it reached the correlation engine.
# The identifiers that could carry cross-engine identity. Ordered strongest-first: a match on an earlier
# one is a harder fact than a match on a later one (a resource id is authoritative; a hostname is a guess).
$script:SIIdentityFields = @(
    @{ Name = 'ExposureGraphNodeId';       Strength = 'graph'  }
    @{ Name = 'AzureResourceId';           Strength = 'hard'   }
    @{ Name = 'MdeDeviceId';               Strength = 'hard'   }
    @{ Name = 'AadDeviceId';               Strength = 'hard'   }
    @{ Name = 'ActiveDirectoryObjectGuid'; Strength = 'hard'   }
    @{ Name = 'SecurityIdentifier';        Strength = 'hard'   }
    @{ Name = 'MachineSid';                Strength = 'hard'   }
    @{ Name = 'AzureVmId';                 Strength = 'hard'   }
    @{ Name = 'Hostname';                  Strength = 'soft'   }
    @{ Name = 'AssetName';                 Strength = 'soft'   }
)

function Get-SIIdentityFieldCatalog {
    <#  The identifier list, so tests and callers agree on it rather than each keeping a copy. #>
    @($script:SIIdentityFields | ForEach-Object { [pscustomobject]$_ })
}

function Get-SIRowIdentifier {
    <#
        Read one identifier off a row, whether it sits as a flat column or inside EntityIds[].
        Returns $null when absent, empty, or whitespace -- an empty string is NOT coverage.
    #>
    param(
        [Parameter(Mandatory)] $Row,
        [Parameter(Mandatory)] [string] $Name
    )

    # 1. flat column
    $direct = $null
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Name)) { $direct = $Row[$Name] }
    } elseif ($Row.PSObject.Properties[$Name]) {
        $direct = $Row.$Name
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$direct)) { return [string]$direct }

    # 2. inside EntityIds[] -- @{type=...; id=...}
    $entity = $null
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains('EntityIds')) { $entity = $Row['EntityIds'] }
    } elseif ($Row.PSObject.Properties['EntityIds']) {
        $entity = $Row.EntityIds
    }
    if ($null -eq $entity) { return $null }

    # EntityIds may arrive as a JSON string from Log Analytics.
    if ($entity -is [string]) {
        if ([string]::IsNullOrWhiteSpace($entity)) { return $null }
        try { $entity = $entity | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    }

    foreach ($e in @($entity)) {
        if ($null -eq $e) { continue }
        $t = $null; $v = $null
        if ($e -is [System.Collections.IDictionary]) {
            if ($e.Contains('type')) { $t = $e['type'] }
            if ($e.Contains('id'))   { $v = $e['id'] }
        } else {
            if ($e.PSObject.Properties['type']) { $t = $e.type }
            if ($e.PSObject.Properties['id'])   { $v = $e.id }
        }
        # EntityIds type names are not guaranteed to match column names exactly (EgNodeId vs
        # ExposureGraphNodeId), so compare case-insensitively on both known spellings.
        if ($null -ne $t -and -not [string]::IsNullOrWhiteSpace([string]$v)) {
            $tn = [string]$t
            if ($tn -ieq $Name) { return [string]$v }
            if ($Name -ieq 'ExposureGraphNodeId' -and $tn -ieq 'EgNodeId') { return [string]$v }
        }
    }
    return $null
}

function Get-SICoverageStats {
    <#
        Per-engine coverage: for each identifier, how many rows carry it.
        Returns one object per identifier plus the row total, so a caller can report percentages
        without recomputing the denominator (and without dividing by zero).
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows,
        [Parameter(Mandatory)] [string] $Engine
    )

    $total = @($Rows).Count
    $out = foreach ($f in (Get-SIIdentityFieldCatalog)) {
        $n = 0
        foreach ($r in $Rows) {
            if ($null -ne (Get-SIRowIdentifier -Row $r -Name $f.Name)) { $n++ }
        }
        [pscustomobject]@{
            Engine   = $Engine
            Field    = $f.Name
            Strength = $f.Strength
            Present  = $n
            Total    = $total
            # 🪤 0 rows must read as 0%, never 100% and never a divide-by-zero. An empty engine is the
            #    single most likely way this measurement lies, and "0 rows is NOT a pass in this tenant".
            Percent  = if ($total -gt 0) { [math]::Round(100.0 * $n / $total, 1) } else { 0.0 }
        }
    }
    @($out)
}

function Get-SICrossEngineOverlap {
    <#
        The number that actually decides the architecture: how many rows in engine A can be linked to a
        row in engine B by a SHARED value of some identifier.

        Deliberately counts DISTINCT A-rows linked, not pairs -- a single A row matching five B rows is
        one correlated asset and five ambiguity problems, and conflating those would flatter the result.
        Ambiguous is reported separately for exactly that reason.
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RowsA,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RowsB,
        [Parameter(Mandatory)] [string] $Field
    )

    # index B by identifier value
    $index = @{}
    foreach ($b in $RowsB) {
        $v = Get-SIRowIdentifier -Row $b -Name $Field
        if ($null -eq $v) { continue }
        $k = $v.ToLowerInvariant()
        if (-not $index.ContainsKey($k)) { $index[$k] = New-Object System.Collections.ArrayList }
        [void]$index[$k].Add($b)
    }

    $linked = 0; $ambiguous = 0; $carriers = 0
    foreach ($a in $RowsA) {
        $v = Get-SIRowIdentifier -Row $a -Name $Field
        if ($null -eq $v) { continue }
        $carriers++
        $k = $v.ToLowerInvariant()
        if ($index.ContainsKey($k)) {
            $linked++
            if ($index[$k].Count -gt 1) { $ambiguous++ }
        }
    }

    [pscustomobject]@{
        Field         = $Field
        RowsA         = @($RowsA).Count
        RowsB         = @($RowsB).Count
        # rows in A that even carry the identifier -- the ceiling on what could ever link
        CarriersA     = $carriers
        Linked        = $linked
        Ambiguous     = $ambiguous
        # percentage of ALL A rows, not of carriers: the honest denominator for "can we correlate the estate"
        PercentOfAll  = if (@($RowsA).Count -gt 0) { [math]::Round(100.0 * $linked / @($RowsA).Count, 1) } else { 0.0 }
    }
}

function Get-SIFindingAttachRate {
    <#
        PoC-2 in miniature, and the a1b gap made numeric: what fraction of RA finding rows can be tied to
        a profile row at all, and by what. AssetName is included ONLY to show how much weight would fall
        on a display-name match if the hard identifiers stay absent -- it is not an endorsement of it.
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $ProfileRows,
        [string[]] $TryFields = @('MdeDeviceId','AzureResourceId','EntraAccountObjectId','AssetName')
    )

    $out = foreach ($f in $TryFields) {
        $r = Get-SICrossEngineOverlap -RowsA $Findings -RowsB $ProfileRows -Field $f
        [pscustomobject]@{
            Field        = $f
            Findings     = $r.RowsA
            Carriers     = $r.CarriersA
            Attached     = $r.Linked
            Ambiguous    = $r.Ambiguous
            PercentOfAll = $r.PercentOfAll
        }
    }
    @($out)
}
