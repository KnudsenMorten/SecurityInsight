function Get-PlatformData {
<#
.SYNOPSIS
    Read bootstrap\platform-data.json (Smtp/LogAnalytics/AzMG/AD/Mail bundle).

.DESCRIPTION
    Successor to v1's Default_Variables.psm1 wall-of-globals. Engines call
    Initialize-PlatformDefaults which reads this file and projects the values
    into $global:Smtp_*, $global:LogAnalytics_*, etc. Get-PlatformData lets
    ops scripts read the structured form directly without the global pollution.

.PARAMETER Path
    Override path. Default: <repo>\bootstrap\platform-data.json.

.OUTPUTS
    PSCustomObject -- the parsed data file.

.EXAMPLE
    $data = Get-PlatformData
    $data.Smtp.Server       # 'smtp.example.com'
    $data.Mail.RecipientsSecurityInsightDetailed
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$Path
    )

    if (-not $Path) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Get-PlatformData: cannot locate repo root from $PSScriptRoot. Pass -Path."
        }
        $Path = Join-Path $repoRoot 'bootstrap\platform-data.json'
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Get-PlatformData: not found at $Path. Run Initialize-PlatformVm or Convert-V1ToPlatform to create one."
    }

    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
