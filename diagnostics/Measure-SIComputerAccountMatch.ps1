#Requires -Version 7.0
<#
.SYNOPSIS
    #1052 READ ONLY, OFFLINE. Which Defender device each AD computer account of an install would enrich -- decided by the
    product's own code (Resolve-SIEgAdComputerMatch) from the two Advanced Hunting answers, saved as JSON. Counts per state
    (matched / ambiguous / no_device / not_onboarded / not_domain_joined / domain_mismatch / domain_unproven / no_name), the
    domain controllers and where each lands, and the accounts the domain map proves. Writes nothing anywhere but -OutCsv.

.DESCRIPTION
    1. In Advanced Hunting (read only), run the text of Get-SIEgAdComputerDomainKql -> save the rows as -DomainJson.
    2. Run Get-SIEgAdComputerKql (one bucket: no -Buckets; a large graph: every bucket, rows appended) -> -NodesJson.
       (pwsh: . .\engine\asset-profiling\discovery\Get-SIEgAdComputers.ps1; Get-SIEgAdComputerKql | Set-Clipboard)
    3. .\diagnostics\Measure-SIComputerAccountMatch.ps1 -NodesJson nodes.json -DomainJson domains.json [-OutCsv out.csv]

.EXAMPLE
    .\diagnostics\Measure-SIComputerAccountMatch.ps1 -NodesJson C:\tmp\ca-nodes.json -DomainJson C:\tmp\ca-domains.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NodesJson,
    [Parameter(Mandatory)][string]$DomainJson,
    [string]$OutCsv
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\asset-profiling\discovery\Get-SIEgAdComputers.ps1')
$read = { param($p) $o = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; if ($o.PSObject.Properties['results']) { $o = $o.results } elseif ($o.PSObject.Properties['Results']) { $o = $o.Results }; @($o) }
$nodes = & $read $NodesJson
$map = ConvertTo-SIEgAdComputerDomainMap -Rows (& $read $DomainJson)
$out = foreach ($n in $nodes) {
    if ($null -eq $n -or -not [string]$n.NodeId) { continue }
    $m = Resolve-SIEgAdComputerMatch -Row $n -DomainMap $map
    $raw = Get-SIEgAdComputerRaw -Row $n
    $dc = $false; if ($raw -and $raw.PSObject.Properties['isDomainController']) { $dc = ([string]$raw.isDomainController) -eq 'True' }
    [pscustomobject]@{ NodeId = [string]$n.NodeId; Name = [string]$n.NodeName; DomainController = $dc; State = $m.State; DeviceId = $m.DeviceId; DeviceName = $m.DeviceName; Reason = $m.Reason }
}
$out = @($out)
''
'#1052 computer accounts: {0}' -f $out.Count
$out | Group-Object State | Sort-Object Count -Descending | ForEach-Object { '  {0,-18} {1,7}' -f $_.Name, $_.Count }
''
'domain map: {0} domain SID(s), {1} with a proven DNS suffix' -f $map.Count, @($map.Values | Where-Object { $_.Suffix }).Count
foreach ($k in @($map.Keys | Sort-Object)) { '  {0}  ->  {1}   ({2})' -f $k, $(if ($map[$k].Suffix) { $map[$k].Suffix } else { '(not proven)' }), ((@($map[$k].Suffixes.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })) -join ', ') }
''
'domain controllers: {0} -- matched (the role moves to the real device, Tier 0): {1}' -f @($out | Where-Object DomainController).Count, @($out | Where-Object { $_.DomainController -and $_.State -eq 'matched' }).Count
$out | Where-Object DomainController | Sort-Object State, Name | Format-Table Name, State, DeviceName, Reason -AutoSize -Wrap
if ($OutCsv) { $out | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding utf8; 'written: {0}' -f $OutCsv }
