function Set-PlatformData {
<#
.SYNOPSIS
    Write bootstrap\platform-data.json (Smtp/LogAnalytics/AzMG/AD/Mail).

.DESCRIPTION
    Used by Initialize-PlatformVm + Convert-V1ToPlatform to lay down a fresh
    data file. Accepts a single -Data hashtable / pscustomobject (the entire
    payload) so callers can build it however they like (interactive prompts,
    capture from v1 globals, paste from a template).

.PARAMETER Path
    Override path. Default: <repo>\bootstrap\platform-data.json.

.PARAMETER Data
    Hashtable or pscustomobject containing Smtp/LogAnalytics/AzMG/AD/Mail
    sub-objects. Top-level structure must match the platform-data.sample.json
    schema; sub-fields are passthrough (engines tolerate missing optional fields).

.PARAMETER Force
    Overwrite without prompting.

.EXAMPLE
    Set-PlatformData -Data @{
        Smtp         = @{ Server='smtp.x.com'; Port=25; From='auto@x.com'; ToOps=@('ops@x.com') }
        LogAnalytics = @{ WorkspaceId='...'; WorkspaceName='log-x' }
    } -Force
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [string]$Path,
        [Parameter(Mandatory)] $Data,
        [switch]$Force
    )

    if (-not $Path) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Set-PlatformData: cannot locate repo root from $PSScriptRoot. Pass -Path."
        }
        $Path = Join-Path $repoRoot 'bootstrap\platform-data.json'
    }

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Set-PlatformData: $Path exists. Use -Force to overwrite."
    }

    # Inject schema marker if caller didn't.
    $payload = $Data
    if ($payload -is [hashtable]) {
        if (-not $payload.ContainsKey('$schema')) { $payload['$schema'] = 'AutomateIT.PlatformData/v2.3' }
    } elseif ($payload -is [pscustomobject]) {
        if (-not ($payload.PSObject.Properties.Name -contains '$schema')) {
            $payload | Add-Member -NotePropertyName '$schema' -NotePropertyValue 'AutomateIT.PlatformData/v2.3' -Force
        }
    }

    if ($PSCmdlet.ShouldProcess($Path, 'Write platform-data.json')) {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $json = $payload | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
        Write-Verbose "Set-PlatformData: wrote $Path"
    }
}
