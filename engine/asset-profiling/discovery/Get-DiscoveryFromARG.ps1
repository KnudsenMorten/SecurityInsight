#Requires -Version 5.1
<#
    Discovery source: Azure Resource Graph (ARG).

    Returns endpoint-class assets the ARM control plane knows about:
    Azure VMs + Azure ARC machines. Pages through the full result set.

    Asset shape (returned as hashtable):
      AssetId       -- composite, source-prefixed: 'arg:<lowercased-resource-id>'
      Source        -- 'AzureVM' or 'ARCMachine'
      Hint          -- 'windows-server' / 'linux-server' / 'unknown'
      Name          -- resource short name
      NormalizedKey -- lowercased name for cross-source dedup
      RG, Subscription -- raw fields used downstream
#>

function Get-DiscoveryFromARG {
    [CmdletBinding()]
    param(
        [Parameter()][string[]]$SubscriptionIds = @()    # empty = all visible subs
    )

    $kql = @'
Resources
| where type in~ ('microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines')
| extend Source = case(
    type =~ 'microsoft.compute/virtualmachines',  'AzureVM',
    type =~ 'microsoft.hybridcompute/machines',   'ARCMachine',
    'Unknown')
| extend Hint = case(
    tostring(properties.osProfile.windowsConfiguration) != '', 'windows-server',
    tostring(properties.osProfile.linuxConfiguration)   != '', 'linux-server',
    tostring(properties.osType) =~ 'Windows',                  'windows-server',
    tostring(properties.osType) =~ 'Linux',                    'linux-server',
    'unknown')
| project ResourceId = tolower(id), Source, Hint, ResourceGroup = resourceGroup, Subscription = subscriptionId, Name = name
| order by ResourceId asc
'@

    # Paged with retry, and a failing page keeps the pages already collected (#125) -- this loop used
    # to have no error handling at all, so a throttle either threw the whole source away or ended the
    # paging with no warning.

    # The asset of ONE Resource Graph virtual machine row -- shared by the whole-set loop below and the streaming path (#475).
    $buildVm = {
        param($r)
        @{
            AssetId       = 'arg:' + $r.ResourceId
            Source        = $r.Source
            Hint          = $r.Hint
            Name          = $r.Name
            NormalizedKey = $r.Name.ToLowerInvariant()
            RG            = $r.ResourceGroup
            Subscription  = $r.Subscription
        }
    }

    # #475 STREAMING (the discover phase of a run collected in parts): this source is small (virtual machines); it is read
    # whole and its assets go to the parts in batches.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1')
        $argResult = Invoke-SIArgPaged -Query $kql -SourceLabel 'ARG discovery' -SubscriptionIds $SubscriptionIds
        $batch = New-Object System.Collections.Generic.List[object]; $taken = 0
        foreach ($r in $argResult.Rows) { $x = & $buildVm $r; if ($x) { $batch.Add($x) }; if ($batch.Count -ge 1000) { $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray(); $taken += $batch.Count; $batch.Clear() } }
        if ($batch.Count) { $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray(); $taken += $batch.Count }
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['ARG'] = $taken }
        return
    }

    . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1')
    $argResult = Invoke-SIArgPaged -Query $kql -SourceLabel 'ARG discovery' -SubscriptionIds $SubscriptionIds
    $rows = New-Object System.Collections.ArrayList
    foreach ($r in $argResult.Rows) { [void]$rows.Add($r) }

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'ArgResources' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'ArgResources' -Index $_i -Total $_total } catch { }
        & $buildVm $r
    }
}
