#Requires -Version 5.1
<#
    WHERE THE AFFECTED SOFTWARE IS, ON EVERY FINDING OF THAT SOFTWARE (#1219 / #1277): si_evidence_paths (every path of the
    copy), si_install_kind (installed / bundled / user-profile / data-folder / registry-only / unknown) and si_bundled_by (the
    application a bundled library copy belongs to -- whose vendor ships the fix).

    From the software evidence the endpoint collection stored (sidata.SoftwareEvidence, engine/_shared/SI-SoftwareEvidence.ps1),
    each device's newest run (the only one kept; a device whose evidence is unknown gives none), joined to the row by device + vendor + product + version
    (the Defender reports' MdeDeviceId and SI_AffectedVendor / SI_AffectedProduct / SI_AffectedVersion). One read per bucket of
    rows, only the bucket's devices. The FINDING COUNT IS THE SOURCE'S: nothing is added or removed -- a row gets its paths as
    a list. A row whose copy is not in the evidence keeps the three fields empty (unknown, never "none"). A read that fails is
    said once per run and changes no row. si_affected_path (the report's own first paths) is left exactly as it is.
    STORED ONLY: the three fields go on the stored finding (sidata.Finding, where the web pages and an output column an admin
    switched on read them) and NEVER into Risk Analysis' own outputs -- the workbook, the JSON file, Log Analytics, the AI
    summary, the KPIs, SI_Finding_CL keep exactly their columns and values (RA-SqlStream.ps1 $script:RAStreamStoredOnlyCols).
    Every path, in full: no cap, no "+N more" (owner 2026-11-17).
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.
if (-not (Get-Command -Name Get-SISoftwareEvidence -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-SoftwareEvidence.ps1') }

function Get-RASoftwareEvidenceRowValue {
    <# PURE. The first non-empty of -Names on a row (object or dictionary), '' when none. #>
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $v = $null
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n] } }
        elseif ($Row.PSObject.Properties[$n]) { $v = $Row.$n }
        if ($null -ne $v -and -not ($v -is [System.DBNull]) -and "$v".Trim()) { return ([string]$v).Trim() }
    }
    ''
}

# EVERY PATH, IN FULL (owner 2026-11-17): the field carries every path of the copy, no cap and no "+N more".

function Add-RASoftwareEvidence {
    <#
        Puts si_evidence_paths / si_install_kind / si_bundled_by on every row of a device + software with stored evidence. Returns
        the rows. -Invoke: the SQL seam (the Risk Analysis stream's); none = the rows unchanged. -Read: test seam
        { param($DeviceIds) rows } instead of the database read. -Log { param($message) }: the one message of a failed read.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [scriptblock]$Invoke, [scriptblock]$Read, [scriptblock]$Log, [int]$DevicesPerRead = 100)
    # each candidate row with its software read ONCE (device, vendors, products, versions), grouped by device
    $byDev = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]' ([StringComparer]::OrdinalIgnoreCase)
    # (read in place, as Get-RASoftwareEvidenceRowValue reads them: the first name with a non-empty value, trimmed -- no call
    # per value; at a large install this loop sees every missing-CVE row)
    $nEv = @('si_evidence_paths'); $nDev = @('MdeDeviceId', 'DeviceId'); $nProd = @('SI_AffectedProduct', 'si_affected_product')
    $nVend = @('SI_AffectedVendor', 'si_affected_vendor'); $nVer = @('SI_AffectedVersion', 'si_affected_version')
    $vals = [string[]]::new(5)
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $isD = $r -is [System.Collections.IDictionary]; $pp = $null; if (-not $isD) { $pp = $r.PSObject.Properties }
        $j = 0
        foreach ($names in $nEv, $nDev, $nProd, $nVend, $nVer) {
            $s = ''
            foreach ($n in $names) {
                $v = $null
                if ($isD) { if ($r.Contains($n)) { $v = $r[$n] } } else { $q = $pp[$n]; if ($q) { $v = $q.Value } }
                if ($null -ne $v -and -not ($v -is [System.DBNull])) { $s = ([string]$v).Trim(); if ($s) { break } }
            }
            $vals[$j++] = $s
            if ($j -eq 1 -and $s) { break }   # already carries its paths
        }
        if ($vals[0]) { continue }
        $d = $vals[1]; $p = $vals[2]
        if (-not $d -or -not $p) { continue }
        $d = $d.ToLowerInvariant()
        $l = $null; if (-not $byDev.TryGetValue($d, [ref]$l)) { $l = New-Object 'System.Collections.Generic.List[object]'; $byDev[$d] = $l }
        $l.Add([object[]]@($r, $vals[3], $p, $vals[4]))
    }
    if ($byDev.Count -eq 0 -or (-not $Invoke -and -not $Read)) { return , @($Rows) }
    # ONE READ PER $DevicesPerRead DEVICES (memory stays flat at any size): the evidence of a group of devices is read, indexed,
    # put on the rows of those devices and let go before the next group -- never every device's evidence at once
    $all = @($byDev.Keys)
    for ($at = 0; $at -lt $all.Count; $at += $DevicesPerRead) {
        $group = @($all[$at..([Math]::Min($all.Count, $at + $DevicesPerRead) - 1)])
        $ev = @()
        try {
            if ($Read) { $ev = @(& $Read $group) } else { $ev = @(Get-SISoftwareEvidence -Invoke $Invoke -DeviceIds $group) }
        } catch {
            if (-not $global:RA_SoftwareEvidenceSaid) {
                $global:RA_SoftwareEvidenceSaid = $true
                $m = ('Where the affected software is (its paths, install kind and the application it is bundled in) could not be read from the database in this run ({0}). The findings are complete without it; those fields stay empty (unknown) on every finding whose evidence was not read.' -f $_.Exception.Message)
                if ($Log) { & $Log $m } else { Write-Warning $m }
            }
            return , @($Rows)
        }
        if ($ev.Count -eq 0) { foreach ($d in $group) { $byDev[$d] = $null }; continue }
        $ix = New-SIFindingEvidenceIndex -Rows $ev
        $ev = $null
        # one answer per copy: the CVE rows of one software copy on one device ask the same question -- answered once
        $memo = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
        $none = [object]::new()
        foreach ($d in $group) {
            foreach ($c in $byDev[$d]) {
                $mk = $d + [char]1 + $c[1] + [char]1 + $c[2] + [char]1 + $c[3]
                $x = $null
                if (-not $memo.TryGetValue($mk, [ref]$x)) {
                    $x = Get-SIFindingEvidenceValues -Index $ix -DeviceId $d -Vendors $c[1] -Products $c[2] -Versions $c[3]
                    if ($null -eq $x) { $x = $none }
                    $memo[$mk] = $x
                }
                if ([object]::ReferenceEquals($x, $none)) { continue }
                $r = $c[0]
                if ($r -is [System.Collections.IDictionary]) {
                    $r['si_evidence_paths'] = $x.Paths; $r['si_install_kind'] = $x.Kinds
                    if ($x.BundledBy) { $r['si_bundled_by'] = $x.BundledBy }
                } else {
                    # as Add-Member -Force: the note property set, added when the row has none
                    $pp = $r.PSObject.Properties
                    $q = $pp['si_evidence_paths']; if ($q) { $q.Value = $x.Paths } else { $pp.Add([psnoteproperty]::new('si_evidence_paths', $x.Paths)) }
                    $q = $pp['si_install_kind']; if ($q) { $q.Value = $x.Kinds } else { $pp.Add([psnoteproperty]::new('si_install_kind', $x.Kinds)) }
                    if ($x.BundledBy) { $q = $pp['si_bundled_by']; if ($q) { $q.Value = $x.BundledBy } else { $pp.Add([psnoteproperty]::new('si_bundled_by', $x.BundledBy)) } }
                }
            }
            $byDev[$d] = $null   # this device's rows are done: its list is let go
        }
        $ix = $null; $memo = $null   # the group's index and answers are let go before the next group
    }
    , @($Rows)
}
