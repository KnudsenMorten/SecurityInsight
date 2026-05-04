#Requires -Version 5.1
<#
    Use-SIAzContext -- Switch the current Az PowerShell context to the
    subscription that owns a given LA workspace ARM ResourceId, only when
    the current context is on a different subscription.

    Why: SI engines query SI_WorkspaceResourceId AND, optionally,
    SI_DefenderWorkspaceResourceId, which can live in DIFFERENT subscriptions
    (community workspace + internal Defender workspace, etc.). The SPN's
    default Az context is whatever Connect-AzAccount happened to land on --
    Get-AzOperationalInsightsWorkspace -ResourceGroupName ... fails with
    'ResourceGroupNotFound' when context is on the wrong subscription.

    This helper parses the sub from the ARM ResourceId and Set-AzContext-es
    only when needed (idempotent; cheap when the context already matches).

    Returns the previous SubscriptionId so callers can restore context if
    they want to (most don't bother -- engines run forward-only).
#>

function Use-SIAzContext {
    [CmdletBinding()]
    param(
        # Either a full LA workspace ResourceId, or a bare subscription GUID.
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        # Optional log sink ({param($msg,$lvl)}) for engines that have a Write-Log helper.
        [scriptblock]$Logger
    )

    $targetSub = $null
    if ($WorkspaceResourceId -match '^/subscriptions/(?<sub>[^/]+)/') {
        $targetSub = $matches.sub
    } elseif ($WorkspaceResourceId -match '^[0-9a-fA-F-]{36}$') {
        $targetSub = $WorkspaceResourceId
    } else {
        throw "Use-SIAzContext: cannot extract subscription from '$WorkspaceResourceId' -- expected ARM ResourceId or bare subscription GUID."
    }

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    $currentSub = if ($ctx) { $ctx.Subscription.Id } else { $null }

    if ($currentSub -eq $targetSub) {
        return $currentSub  # no-op
    }

    if ($Logger) {
        & $Logger "Switching Az context to subscription $targetSub (was $currentSub)" 'INFO'
    }
    Set-AzContext -SubscriptionId $targetSub -ErrorAction Stop | Out-Null
    return $currentSub
}
