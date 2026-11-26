#Requires -Version 5.1
<#
    Get-SIDefenderSoftwareEvidence -- WHERE each software copy is on the devices of this run: Defender advanced hunting
    DeviceTvmSoftwareEvidenceBeta (DiskPaths, RegistryPaths, LastSeenTime per device x software x version), EVERY path, every
    drive, the registry too, no cap. Read with the software inventory of the same devices (DeviceTvmSoftwareInventory: the
    device's own products + versions, to name the application a copy lies in), ONE query per page of devices -- the way the
    endpoint collection reads the inventory (Read-SIHuntingPages: each page retried, a failed page asked once more at the end).

      a missing table   (the tenant has no DeviceTvmSoftwareEvidenceBeta, or the read is refused) or an EMPTY table: said
                        ONCE, the evidence of every device is UNKNOWN for this run -- never "no evidence" -- and stored as such
      a page that       its devices are UNKNOWN for this run (state 'unknown' in sidata.SoftwareEvidenceDevice); the other
      failed            pages are kept
      a device read     state 'read' and its rows (none = Defender reported no path for it this run)
    ONLY THE NEWEST RUN IS KEPT (owner 2026-11-16): a device's rows are REPLACED by this run's (Write-SISoftwareEvidence, one
    transaction per chunk, shown only once complete); a device UNKNOWN this run keeps no rows -- an older run's paths are never
    shown as current.

    Per page: the rows (engine/_shared/SI-SoftwareEvidence.ps1 ConvertTo-SISoftwareEvidenceRows -- install kind, application)
    go to sidata.SoftwareEvidence / SoftwareEvidenceDevice (Write-SISoftwareEvidence), the device's record gets part
    'softwareEvidence' (data-model/mappings/mde.locked.json -> si_software_evidence_paths / si_software_install_kind /
    si_software_bundled_by) and the device's compact evidence is handed back for the software rules (Metadata
    'SoftwareEvidence'). READ ONLY towards Defender. Never throws. PowerShell 5.1 / 7, REST only.
#>

if (-not (Get-Command -Name ConvertTo-SISoftwareEvidenceRows -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-SoftwareEvidence.ps1') }
if (-not (Get-Command -Name Read-SIHuntingPages -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-HuntingPages.ps1') }

# devices per evidence query (a page, not a limit: every device is read, page by page; a cut answer is read whole in parts)
$script:SI_MdeEvidencePageDevices = 200

function Get-SIDefenderSoftwareEvidenceKql {
    <# PURE. One advanced hunting query for a page of Defender device ids (checked hex ids, never free text): the evidence rows
       (Kind 'e', every path as Defender has it) and the device's inventory products (Kind 'i': vendor, name, version). The
       evidence table is read WITHOUT a fuzzy union: a tenant that does not have it answers an error (unknown), not "none". #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds)
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[0-9a-f]{16,64}$' } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return '' }
    $list = ($ids | ForEach-Object { '"' + $_ + '"' }) -join ','
    return @"
let _ids = dynamic([$list]);
let _ev = DeviceTvmSoftwareEvidenceBeta
| extend DeviceId = tolower(tostring(DeviceId))
| where DeviceId in (_ids)
| project DeviceId, Kind = "e", SoftwareVendor = tolower(tostring(SoftwareVendor)), SoftwareName = tolower(tostring(SoftwareName)), SoftwareVersion = tostring(SoftwareVersion),
          DiskPaths = todynamic(column_ifexists("DiskPaths", dynamic([]))), RegistryPaths = todynamic(column_ifexists("RegistryPaths", dynamic([]))),
          LastSeenTime = todatetime(column_ifexists("LastSeenTime", datetime(null)));
let _inv = union isfuzzy=true (datatable(DeviceId:string, SoftwareVendor:string, SoftwareName:string)[]), (DeviceTvmSoftwareInventory)
| extend DeviceId = tolower(tostring(DeviceId))
| where DeviceId in (_ids)
| extend SoftwareVendor = tolower(tostring(SoftwareVendor)), SoftwareName = tolower(tostring(SoftwareName)), SoftwareVersion = tostring(column_ifexists("SoftwareVersion", ""))
| where isnotempty(SoftwareName)
| distinct DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| project DeviceId, Kind = "i", SoftwareVendor, SoftwareName, SoftwareVersion, DiskPaths = dynamic(null), RegistryPaths = dynamic(null), LastSeenTime = datetime(null);
union _ev, _inv
| order by DeviceId asc, Kind asc
"@
}

function Get-SIDefenderSoftwareEvidenceProbeKql {
    <# PURE. Does the tenant have the evidence table, with rows? One row or none; an error when the table is not there. #>
    'DeviceTvmSoftwareEvidenceBeta | take 1 | project DeviceId = tostring(DeviceId)'
}

function Read-SIDefenderSoftwareEvidence {
    <#
    .SYNOPSIS  Reads, derives, stores and hands back the software evidence of the given Defender devices. Never throws.
    .OUTPUTS   @{ State ('read' | 'unknown'); Reason; ByDevice (device id -> compact evidence, ConvertTo-SISoftwareEvidenceDevice;
               only devices whose page was READ); Devices; Rows; Pages; Failed; Stored; StoreNote }
    .PARAMETER Query  test seam { param($kql) rows } (throws like a failed call); default the product's hunting request.
    .PARAMETER Invoke the SQL seam { param($Sql, $Params, $Mode) }; none = the install's database when one is configured.
    .PARAMETER NoStore  read and derive only (nothing is written).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [datetime]$CollectionTime = [datetime]::UtcNow,
          [scriptblock]$Query, [scriptblock]$Invoke, [switch]$NoStore, [int]$PageDevices = $script:SI_MdeEvidencePageDevices)
    $res = @{ State = 'unknown'; Reason = ''; ByDevice = @{}; Devices = 0; Rows = 0L; Pages = 0; Failed = 0; Stored = 0L; StoreNote = '' }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { $res.Reason = 'no devices'; return $res }
    # the database (optional: without one the evidence is still derived for the rules and the records)
    if (-not $NoStore -and -not $Invoke) {
        try {
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
                $rs = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-RecordSql.ps1')
                if ([IO.File]::Exists($rs)) { . $rs }
            }
            if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { $Invoke = New-SIRecordSqlInvoke }
        } catch { $Invoke = $null }
        if (-not $Invoke) { $res.StoreNote = 'no database is configured -- the evidence is used by this run only' }
    }
    $ask = {
        param([string]$q)
        if ($Query) {
            try { return [pscustomobject]@{ Ok = $true; Rows = @(& $Query $q); Error = '' } }
            catch { $m = $_.Exception.Message; return [pscustomobject]@{ Ok = $false; Rows = @(); Error = $m } }
        }
        if (-not (Get-Command -Name Invoke-SIHuntingQueryResult -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/HuntingQuery.ps1') }
        Invoke-SIHuntingQueryResult -Query $q
    }
    # THE TABLE FIRST: missing, refused or empty = the evidence of every device is unknown this run (said once by the caller)
    $probe = & $ask (Get-SIDefenderSoftwareEvidenceProbeKql)
    $none = ''
    if (-not $probe.Ok) { $none = ('the Defender software evidence (DeviceTvmSoftwareEvidenceBeta) could not be read: {0}' -f [string]$probe.Error) }
    elseif (@($probe.Rows | Where-Object { $null -ne $_ }).Count -eq 0) { $none = 'the Defender software evidence (DeviceTvmSoftwareEvidenceBeta) holds no rows in this tenant' }
    if ($none) {
        $res.Reason = $none
        # ONLY THE NEWEST RUN IS KEPT: every device of this run is UNKNOWN now -- its earlier paths go, never shown as current
        if ($Invoke) {
            $u = Write-SISoftwareEvidenceUnknown -Invoke $Invoke -CollectionTime $CollectionTime -DeviceIds $ids
            if ($u.Missing) { $res.StoreNote = 'the database is not updated yet (sidata.SoftwareEvidence is missing) -- run the updater' }
            elseif ($u.Errors -gt 0) { $res.StoreNote = ('{0} write(s) to the database failed ({1}) -- those devices may still show their earlier evidence' -f $u.Errors, $u.First) }
        }
        return $res
    }

    # the store's state lives in a table: the page block below runs inside Read-SIHuntingPages, where a plain assignment
    # would make a variable of its own
    $st = @{ Missing = $false; Errors = 0; First = '' }
    $byDevice = $res.ByDevice
    $keep = {
        param($rows)
        $ev = @{}; $inv = @{}
        foreach ($r in @($rows)) {
            if ($null -eq $r) { continue }
            $d = ([string]$r.DeviceId).Trim().ToLowerInvariant(); if (-not $d) { continue }
            if ([string]$r.Kind -eq 'i') {
                if (-not $inv.ContainsKey($d)) { $inv[$d] = New-Object System.Collections.Generic.List[object] }
                $inv[$d].Add(@{ Vendor = [string]$r.SoftwareVendor; Name = [string]$r.SoftwareName; Version = [string]$r.SoftwareVersion })
            } else {
                if (-not $ev.ContainsKey($d)) { $ev[$d] = New-Object System.Collections.Generic.List[object] }
                $ev[$d].Add($r)
            }
        }
        $pageRows = New-Object System.Collections.Generic.List[object]
        $pageDevs = New-Object System.Collections.Generic.List[object]
        foreach ($d in @(@($ev.Keys) + @($inv.Keys) | Sort-Object -Unique)) {
            $i = @(); if ($inv.ContainsKey($d)) { $i = $inv[$d].ToArray() }
            $e = @(); if ($ev.ContainsKey($d)) { $e = $ev[$d].ToArray() }
            $rowsD = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $d -Evidence $e -Inventory $i)
            $byDevice[$d] = ConvertTo-SISoftwareEvidenceDevice -Rows $rowsD -Inventory $i
            foreach ($x in $rowsD) { $pageRows.Add($x) }
            $pageDevs.Add(@{ DeviceId = $d; State = 'read'; Rows = $rowsD.Count })
            $part = ConvertTo-SISoftwareEvidencePart -Rows $rowsD
            if ($null -ne $part -and (Test-Path -Path 'function:Add-SIRecordPart')) {
                try { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $d -Part 'softwareEvidence' -Object $part } catch { }
            }
        }
        $res.Rows += $pageRows.Count
        if ($Invoke -and -not $st.Missing -and $pageDevs.Count -gt 0) {
            $w = Write-SISoftwareEvidence -Invoke $Invoke -CollectionTime $CollectionTime -Devices $pageDevs.ToArray() -Rows $pageRows.ToArray()
            if ($w.Missing) { $st.Missing = $true }
            elseif ($w.Error) { $st.Errors++; if (-not $st.First) { $st.First = [string]$w.Error } }
            else { $res.Stored += [long]$w.Written }
        }
    }
    $read = Read-SIHuntingPages -Ids $ids -Kql { param($p) Get-SIDefenderSoftwareEvidenceKql -DeviceIds $p } -Query $Query -PageSize $PageDevices -OnRows $keep
    $res.Pages = $read.Pages
    $res.State = 'read'
    # the devices of read pages with no row at all (no evidence, no inventory): read, nothing found; the devices of failed
    # pages: unknown -- both recorded, so the findings never take an older collection's paths for a device read this run
    $rest = New-Object System.Collections.Generic.List[object]
    foreach ($d in $ids) {
        if ($byDevice.ContainsKey($d)) { continue }
        if ($read.ReadIds.Contains($d)) { $byDevice[$d] = [ordered]@{ State = 'read'; Items = @() }; $rest.Add(@{ DeviceId = $d; State = 'read'; Rows = 0 }) }
        else { $rest.Add(@{ DeviceId = $d; State = 'unknown'; Rows = 0 }) }
    }
    foreach ($fl in $read.Failed) { $res.Failed += [int]$fl.Count }
    if ($Invoke -and -not $st.Missing -and $rest.Count -gt 0) {
        for ($i = 0; $i -lt $rest.Count; $i += 2000) {
            $w = Write-SISoftwareEvidence -Invoke $Invoke -CollectionTime $CollectionTime -Devices @($rest.ToArray()[$i..([Math]::Min($i + 2000, $rest.Count) - 1)]) -Rows @()
            if ($w.Missing) { $st.Missing = $true; break }
            if ($w.Error) { $st.Errors++; if (-not $st.First) { $st.First = [string]$w.Error } }
        }
    }
    $res.Devices = @($byDevice.Keys).Count
    if ($read.Failed.Count -gt 0) {
        $fx = $read.Failed[0]
        $res.Reason = ('{0} device(s) were not read ({1} -- {2}); their evidence is unknown this run' -f $res.Failed, (Get-SIHuntingFailureKind $fx), [string]$fx.Error)
    }
    if ($st.Missing) { $res.StoreNote = 'the database is not updated yet (sidata.SoftwareEvidence is missing) -- run the updater; the evidence is used by this run only' }
    elseif ($st.Errors -gt 0) { $res.StoreNote = ('{0} write(s) to the database failed ({1}) -- those devices'' evidence is not stored for this collection' -f $st.Errors, $st.First) }
    elseif ($Invoke) {
        $ret = Invoke-SISoftwareEvidenceRetention -Invoke $Invoke
        if ($ret.Error) { $res.StoreNote = ('the older evidence could not be removed: {0}' -f $ret.Error) }
    }
    return $res
}

function Format-SIDefenderSoftwareEvidenceLine {
    <# PURE. The run log line of the read: what was read and stored, or why the evidence is unknown. #>
    param($Result, [int]$Asked = 0)
    if ($null -eq $Result) { return 'Defender software evidence: not read -- unknown this run (not "no evidence")' }
    if ([string]$Result.State -ne 'read') { return ('Defender software evidence: UNKNOWN this run (not "no evidence") -- {0}. Software rules with path or install-kind conditions match by name as before.' -f [string]$Result.Reason) }
    $t = ('Defender software evidence: {0} of {1} device(s) read, {2:N0} path(s), {3} page(s)' -f [int]$Result.Devices, $Asked, [long]$Result.Rows, [int]$Result.Pages)
    if ([long]$Result.Stored -gt 0) { $t += (', {0:N0} row(s) stored' -f [long]$Result.Stored) }
    if ($Result.Reason) { $t += (' -- ' + [string]$Result.Reason) }
    if ($Result.StoreNote) { $t += (' -- ' + [string]$Result.StoreNote) }
    $t
}
