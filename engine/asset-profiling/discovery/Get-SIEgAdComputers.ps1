#Requires -Version 5.1
<#
    Get-SIEgAdComputers -- on-premises Active Directory COMPUTER accounts from the cloud signals, as provider records
    (REQUIREMENTS #497, the decided order: cloud signals first; the optional on-prem hybrid collector is a later phase,
    its contract is in DESIGN.md "On-premises Active Directory in the model").

    WHAT. The Exposure Graph's AD computer-account nodes (NodeLabel 'computer-account' -- what Defender for Identity and
    Defender for Endpoint learnt of each AD computer). Each node becomes ONE record of provider eg, record type device
    (Get-SIEgRecordType), mapped by data-model/mappings/eg.locked.json: eg_node_id, si_asset_name, and the AD ids it
    carries -- ad_sid (the computer account's SID) and ad_object_guid -- which JOIN it, in the CI build, to the Entra
    device of a hybrid-joined computer (onPremisesSecurityIdentifier -> ad_sid) and to the Defender device when the graph
    names it. An AD computer no other source knows stands alone as its own device CI (the same rule as an AD-only
    identity, V3-DATA-MODEL 2.4.1): it is an asset, not noise.

    The ids are resolved here into node.SIEntityIds (plain {type,id}) the mapping reads first: EG's own EntityIds are
    JSON strings, and an AD id may sit only in rawData (sid / objectSid / objectGuid ...).

    HOW. A count probe, then hash buckets of at most SI_EgAdComputerPageRows (default 5,000) nodes per answer -- the
    number of buckets follows the count, every node in exactly one bucket; each answer becomes record parts (which
    the producer's record stream writes and lets go) and is released. The same code for every tenant size.
    COMPLETENESS. A bucket that fails marks the Exposure Graph pull NOT complete (its nodes are unknown this run, never
    gone). A tenant whose graph has no computer-account node captures nothing and says so: the source is not present.
    READ ONLY (advanced hunting, ThreatHunting.Read.All -- the permission the Exposure Graph reads already hold). Never
    throws into the discover stage. PowerShell 7, REST only.
#>

$script:SIEgAdComputerLabel = 'computer-account'

function Get-SIEgAdComputerKql {
    <# PURE. The node query (-Buckets > 1: one hash bucket of it), or the count probe (-Count). #>
    param([int]$Buckets = 1, [int]$Bucket = 0, [switch]$Count)
    $q = "ExposureGraphNodes`n| where NodeLabel == '$($script:SIEgAdComputerLabel)'"
    if ($Count) { return ($q + "`n| count") }
    if ($Buckets -gt 1) { $q += ("`n| where hash(NodeId, {0}) == {1}" -f $Buckets, $Bucket) }
    $q + "`n| project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties"
}

function Get-SIEgAdComputerIds {
    <#
        PURE. The AD ids of one computer-account node row: @{ Sid; Guid } -- from EntityIds (SecurityIdentifier,
        ActiveDirectoryObjectGuid / OnPremisesObjectId), else rawData (sid, objectSid, securityIdentifier,
        onPremisesSecurityIdentifier; objectGuid, objectGUID, adObjectId). Only a well-formed SID (S-1-...) and GUID count.
    #>
    param([AllowNull()]$Row)
    $sid = ''; $guid = ''
    if ($null -eq $Row) { return @{ Sid = ''; Guid = '' } }
    $g = { param($o, $n) if ($null -eq $o) { return $null }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $ids = & $g $Row 'EntityIds'
    if ($ids -is [string]) { try { $ids = $ids | ConvertFrom-Json } catch { $ids = @() } }
    foreach ($e in @($ids)) {
        if ($e -is [string]) { try { $e = $e | ConvertFrom-Json } catch { continue } }
        if ($null -eq $e) { continue }
        $t = ([string](& $g $e 'type')).ToLowerInvariant(); $v = ([string](& $g $e 'id')).Trim()
        if (-not $v) { continue }
        if (-not $sid -and $t -eq 'securityidentifier' -and $v -match '^(?i)s-1-\d+(-\d+)+$') { $sid = $v.ToUpperInvariant() }
        if (-not $guid -and $t -in 'activedirectoryobjectguid', 'onpremisesobjectid' -and $v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $guid = $v.ToLowerInvariant() }
    }
    $props = & $g $Row 'NodeProperties'
    if ($props -is [string]) { try { $props = $props | ConvertFrom-Json } catch { $props = $null } }
    $raw = & $g $props 'rawData'; if ($null -eq $raw) { $raw = $props }
    if (-not $sid) {
        foreach ($k in 'sid', 'objectSid', 'securityIdentifier', 'onPremisesSecurityIdentifier') {
            $v = ([string](& $g $raw $k)).Trim()
            if ($v -match '^(?i)s-1-\d+(-\d+)+$') { $sid = $v.ToUpperInvariant(); break }
        }
    }
    if (-not $guid) {
        foreach ($k in 'objectGuid', 'objectGUID', 'adObjectId', 'onPremisesObjectId') {
            $v = ([string](& $g $raw $k)).Trim()
            if ($v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $guid = $v.ToLowerInvariant(); break }
        }
    }
    @{ Sid = $sid; Guid = $guid }
}

function ConvertTo-SIEgAdComputerNode {
    <# PURE. One node row -> the node object the record capture keeps (the Exposure Graph node shape), with SIEntityIds. #>
    param([Parameter(Mandatory)][AllowNull()]$Row)
    if ($null -eq $Row -or -not [string]$Row.NodeId) { return $null }
    $node = $null
    if (Get-Command -Name ConvertTo-SIFullExposureGraphNode -ErrorAction SilentlyContinue) { $node = ConvertTo-SIFullExposureGraphNode -Row $Row }
    else { $node = [pscustomobject]@{ NodeId = $Row.NodeId; NodeLabel = $Row.NodeLabel; NodeName = $Row.NodeName; EntityIds = $Row.EntityIds; NodeProperties = $Row.NodeProperties } }
    $ids = Get-SIEgAdComputerIds -Row $Row
    $res = New-Object System.Collections.Generic.List[object]
    if ($ids.Sid) { $res.Add([pscustomobject]@{ type = 'SecurityIdentifier'; id = $ids.Sid }) }
    if ($ids.Guid) { $res.Add([pscustomobject]@{ type = 'ActiveDirectoryObjectGuid'; id = $ids.Guid }) }
    $node | Add-Member -NotePropertyName 'SIEntityIds' -NotePropertyValue $res.ToArray() -Force
    $node | Add-Member -NotePropertyName 'SIIdentitySource' -NotePropertyValue 'ad' -Force
    $node
}

function Invoke-SIEgAdComputerQuery {
    <# One hunting query -> @{ Ok; Rows; Error }. Retries a transient failure (5 / 15 s); never throws. #>
    param([Parameter(Mandatory)][string]$Kql)
    $last = ''
    for ($a = 1; $a -le 3; $a++) {
        try {
            if (Get-Command -Name Invoke-SIEgIdentityQuery -ErrorAction SilentlyContinue) {
                $r = Invoke-SIEgIdentityQuery -Query $Kql -MaxAttempts 1
                if ($r.Ok) { return $r }
                $last = [string]$r.Error
            } else {
                . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth\Get-SIGraphToken.ps1')
                $token = Get-SIGraphToken -Resource Graph
                $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -ErrorAction Stop `
                    -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } -Body (@{ Query = $Kql } | ConvertTo-Json -Compress)
                $rows = if ($resp.results) { @($resp.results) } elseif ($resp.Results) { @($resp.Results) } else { @() }
                return @{ Ok = $true; Rows = $rows; Error = '' }
            }
        } catch {
            $last = [string]$_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $last = [string]$_.ErrorDetails.Message }
            # a refused query (400) gives the same answer when asked again -- it must be fixed, not retried
            if ($last -match '(?i)semantic error|syntax error|BadRequest|\(400\)') { break }
        }
        if ($a -lt 3) { Start-Sleep -Seconds (5 * [Math]::Pow(3, $a - 1)) }
    }
    @{ Ok = $false; Rows = @(); Error = $last }
}

function Invoke-SIEgAdComputerCapture {
    <#
    .SYNOPSIS  Reads every computer-account node of the Exposure Graph and hands each to the record capture. Returns
               @{ Nodes; Buckets; Failed; Present; Text } -- Present = $false when the graph has no such node (the source
               is not present). Never throws.
    .PARAMETER Query  test seam: { param($Kql) } -> @{ Ok; Rows; Error }.
    #>
    param([scriptblock]$Query, [int]$PageRows = 0)
    $out = @{ Nodes = 0; Buckets = 0; Failed = 0; Present = $true; Text = '' }
    if (-not (Get-Command -Name Add-SIRecordPartFromSource -ErrorAction SilentlyContinue)) { $out.Text = 'AD computers from the Exposure Graph: the record capture is not loaded -- nothing read.'; return $out }
    if ($PageRows -le 0) { $PageRows = 5000; if ($global:SI_EgAdComputerPageRows -and [int]$global:SI_EgAdComputerPageRows -gt 0) { $PageRows = [int]$global:SI_EgAdComputerPageRows } }
    $ask = { param($k) if ($Query) { & $Query $k } else { Invoke-SIEgAdComputerQuery -Kql $k } }
    try {
        $total = $null
        $probe = & $ask (Get-SIEgAdComputerKql -Count)
        if ($probe.Ok) {
            $first = @($probe.Rows) | Select-Object -First 1; $n = 0L
            foreach ($c in 'Count', 'count_') { if ($first -and $first.PSObject.Properties[$c] -and [long]::TryParse([string]$first.$c, [ref]$n)) { $total = $n; break } }
            if ($null -eq $total) { $total = 0L }
        }
        if ($null -ne $total -and $total -eq 0) {
            $out.Present = $false
            $out.Text = 'AD computers from the Exposure Graph: the graph has no AD computer account -- the source is not present on this tenant (nothing removed).'
            return $out
        }
        # an unknown count (the probe failed): enough buckets that a large graph still answers in pages
        $buckets = 8
        if ($null -ne $total) { $buckets = [int][Math]::Max(1, [Math]::Ceiling($total / [double]$PageRows)) }
        $out.Buckets = $buckets
        $err = ''
        for ($b = 0; $b -lt $buckets; $b++) {
            $r = & $ask (Get-SIEgAdComputerKql -Buckets $buckets -Bucket $b)
            if (-not $r.Ok) { $out.Failed++; $err = [string]$r.Error; continue }
            foreach ($row in @($r.Rows)) {
                $node = ConvertTo-SIEgAdComputerNode -Row $row
                if ($null -eq $node) { continue }
                Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object $node
                $out.Nodes++
            }
            $r = $null
        }
        if ($out.Failed -gt 0) {
            if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'eg' -Complete $false -ErrorText ('AD computer accounts: ' + $err) }
            $out.Text = ('AD computers from the Exposure Graph: {0} node(s); {1} of {2} page(s) could not be read ({3}) -- their computers are UNKNOWN this run, not removed.' -f $out.Nodes, $out.Failed, $buckets, $err)
        } else {
            if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'eg' -Complete $true }
            $out.Text = ('AD computers from the Exposure Graph: {0} computer account(s) in {1} page(s)' -f $out.Nodes, $buckets)
        }
    } catch {
        $out.Failed++
        if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'eg' -Complete $false -ErrorText ('AD computer accounts: ' + $_.Exception.Message) }
        $out.Text = ('AD computers from the Exposure Graph: not read ({0}) -- they are UNKNOWN this run, not removed.' -f $_.Exception.Message)
    }
    $out
}
