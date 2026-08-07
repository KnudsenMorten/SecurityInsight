#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Microsoft Graph connection for the high-privilege SPN, and the reconnect guard.
#
#  The two functions that own the Graph session: the initial cert/secret connect, and the
#  max-age check every hunting call runs through before it submits.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Connect-GraphHighPriv {
    [CmdletBinding()]
    param()

    # v2.2.234 -- branch on cert vs secret. Connect-MicrosoftGraphPS only takes
    # AppSecret; for SPN+cert we fall through to Connect-MgGraph directly
    # (Microsoft.Graph.Authentication module ships with the rest of the SDK,
    # so no extra dependency).
    $hasCert = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ($hasCert) {
        Write-Info "Connecting to Microsoft Graph (app+certificate)..."
        Connect-MgGraph -TenantId $global:SpnTenantId `
                        -ClientId $global:SpnClientId `
                        -CertificateThumbprint $global:SpnCertificateThumbprint `
                        -NoWelcome -ErrorAction Stop
    } else {
        Write-Info "Connecting to Microsoft Graph (app+secret)..."
        Connect-MicrosoftGraphPS -AppId $global:SpnClientId `
                                 -AppSecret $global:SpnClientSecret `
                                 -TenantId $global:SpnTenantId
    }

    # increase Graph SDK HTTP timeout + tune retries
    Set-MgRequestContext -ClientTimeout 900 -MaxRetry 6 -RetryDelay 5 -RetriesTimeLimit 600

    $script:GraphLastConnectUtc = [datetime]::UtcNow
    Write-Ok ("Graph connected at {0:u}" -f $script:GraphLastConnectUtc)
    Write-Info "Graph request context: ClientTimeout=900s, MaxRetry=6, RetryDelay=5s, RetriesTimeLimit=600s"
}

function Ensure-GraphAuth {
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 45
    )

    $need = $false

    if ($script:GraphLastConnectUtc -eq [datetime]::MinValue) { $need = $true }
    else {
        $ageMin = ([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes
        if ($ageMin -ge $MaxAgeMinutes) { $need = $true }
    }

    if ($need) {
        Connect-GraphHighPriv
    }
}
