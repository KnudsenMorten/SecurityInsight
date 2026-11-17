#Requires -Version 7.0
<#
    THE REFERENCE: the software-evidence join of release 3.1.29's review line (commit 01cde9eba), kept verbatim under other names
    so a test can prove the faster code writes EXACTLY the same three fields on every row (SIv3-RaEvidenceStoredOnly).
    Uses the product's Get-RASoftwareEvidenceRowValue / Get-SIEvValue / Get-SIFindingEvidenceKey / Format-SIEvidenceApplication
    / Get-SISoftwareEvidence (unchanged). Test-only: never loaded by the engine.
#>
function New-SIFindingEvidenceIndexReference {
    <# PURE. Evidence rows -> key (Get-SIFindingEvidenceKey) -> @{ Paths; Kinds; BundledBy } (each a sorted distinct list). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $ix = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = Get-SIFindingEvidenceKey ([string](Get-SIEvValue $r 'DeviceId')) ([string](Get-SIEvValue $r 'Vendor')) ([string](Get-SIEvValue $r 'Product')) ([string](Get-SIEvValue $r 'Version'))
        if (-not $ix.ContainsKey($k)) {
            $ix[$k] = @{ Paths = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal))
                         Kinds = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal))
                         BundledBy = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)) }
        }
        $f = [string](Get-SIEvValue $r 'FullPath'); if ($f) { [void]$ix[$k].Paths.Add($f) }
        $kd = [string](Get-SIEvValue $r 'InstallKind'); if ($kd) { [void]$ix[$k].Kinds.Add($kd) }
        if ($kd -eq 'bundled') { $a = Format-SIEvidenceApplication $r; if ($a) { [void]$ix[$k].BundledBy.Add($a) } }
    }
    return $ix
}

function Get-SIFindingEvidenceValuesReference {
    <#
    .SYNOPSIS  PURE. The evidence fields of ONE finding row: the device (-DeviceId) and the software it names (';'-separated
               vendor / product / version lists, as the Defender reports carry them) joined to the index. Every combination
               present in the index counts (only real copies are in it). @{ Paths; Kinds; BundledBy } as ';'-joined text,
               or $null when no copy of the finding's software is in the evidence (unknown -- the row is left as it is).
    #>
    param([hashtable]$Index, [string]$DeviceId, [string]$Vendors, [string]$Products, [string]$Versions)
    if ($null -eq $Index -or $Index.Count -eq 0 -or -not $DeviceId) { return $null }
    $vs = @(([string]$Vendors) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); if ($vs.Count -eq 0) { $vs = @('') }
    $ps = @(([string]$Products) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $ns = @(([string]$Versions) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); if ($ns.Count -eq 0) { $ns = @('') }
    if ($ps.Count -eq 0) { return $null }
    $paths = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $kinds = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $by = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $hit = $false
    foreach ($v in $vs) { foreach ($p in $ps) { foreach ($n in $ns) {
        $k = Get-SIFindingEvidenceKey $DeviceId $v $p $n
        if ($Index.ContainsKey($k)) { $hit = $true; $e = $Index[$k]; foreach ($x in $e.Paths) { [void]$paths.Add($x) }; foreach ($x in $e.Kinds) { [void]$kinds.Add($x) }; foreach ($x in $e.BundledBy) { [void]$by.Add($x) } }
    } } }
    if (-not $hit) { return $null }
    return @{ Paths = (@($paths) -join ';'); Kinds = (@($kinds) -join ';'); BundledBy = (@($by) -join ';') }
}

function Add-RASoftwareEvidenceReference {
    <#
        Puts si_evidence_paths / si_install_kind / si_bundled_by on every row of a device + software with stored evidence. Returns
        the rows. -Invoke: the SQL seam (the Risk Analysis stream's); none = the rows unchanged. -Read: test seam
        { param($DeviceIds) rows } instead of the database read. -Log { param($message) }: the one message of a failed read.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [scriptblock]$Invoke, [scriptblock]$Read, [scriptblock]$Log)
    $cand = New-Object 'System.Collections.Generic.List[object]'
    $devs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if (Get-RASoftwareEvidenceRowValue $r @('si_evidence_paths')) { continue }
        $d = Get-RASoftwareEvidenceRowValue $r @('MdeDeviceId', 'DeviceId')
        $p = Get-RASoftwareEvidenceRowValue $r @('SI_AffectedProduct', 'si_affected_product')
        if (-not $d -or -not $p) { continue }
        $cand.Add($r); [void]$devs.Add($d.ToLowerInvariant())
    }
    if ($cand.Count -eq 0 -or (-not $Invoke -and -not $Read)) { return , @($Rows) }
    $ev = @()
    try {
        if ($Read) { $ev = @(& $Read @($devs)) } else { $ev = @(Get-SISoftwareEvidence -Invoke $Invoke -DeviceIds @($devs)) }
    } catch {
        if (-not $script:RefSaid) {
            $script:RefSaid = $true
            $m = ('Where the affected software is (its paths, install kind and the application it is bundled in) could not be read from the database in this run ({0}). The findings are complete without it; those fields stay empty (unknown).' -f $_.Exception.Message)
            if ($Log) { & $Log $m } else { Write-Warning $m }
        }
        return , @($Rows)
    }
    if ($ev.Count -eq 0) { return , @($Rows) }
    $ix = New-SIFindingEvidenceIndexReference -Rows $ev
    $setv = {
        param($r, $n, $v)
        if ($r -is [System.Collections.IDictionary]) { $r[$n] = $v } else { $r | Add-Member -NotePropertyName $n -NotePropertyValue $v -Force }
    }
    foreach ($r in $cand) {
        $x = Get-SIFindingEvidenceValuesReference -Index $ix -DeviceId (Get-RASoftwareEvidenceRowValue $r @('MdeDeviceId', 'DeviceId')) `
            -Vendors (Get-RASoftwareEvidenceRowValue $r @('SI_AffectedVendor', 'si_affected_vendor')) `
            -Products (Get-RASoftwareEvidenceRowValue $r @('SI_AffectedProduct', 'si_affected_product')) `
            -Versions (Get-RASoftwareEvidenceRowValue $r @('SI_AffectedVersion', 'si_affected_version'))
        if ($null -eq $x) { continue }
        & $setv $r 'si_evidence_paths' $x.Paths
        & $setv $r 'si_install_kind' $x.Kinds
        if ($x.BundledBy) { & $setv $r 'si_bundled_by' $x.BundledBy }
    }
    , @($Rows)
}

