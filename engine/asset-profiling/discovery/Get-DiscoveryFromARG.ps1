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

    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    do {
        $params = @{ Query = $kql; First = 1000 }
        if ($SubscriptionIds.Count -gt 0) { $params['Subscription'] = $SubscriptionIds }
        if ($skipToken)                    { $params['SkipToken']    = $skipToken }
        $page = Search-AzGraph @params
        foreach ($r in $page) { [void]$rows.Add($r) }
        $skipToken = $page.SkipToken
    } while ($skipToken)

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'ArgResources' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'ArgResources' -Index $_i -Total $_total } catch { }
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
}
