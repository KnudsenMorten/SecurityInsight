function Get-PlatformStateLocalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$Key
    )

    $file = Get-LocalStateFile -Context $Context -ScriptName $ScriptName
    if (-not (Test-Path -LiteralPath $file)) { return $null }

    $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $obj = $raw | ConvertFrom-Json
    if ($null -eq $obj) { return $null }
    if (-not ($obj.PSObject.Properties.Name -contains $Key)) { return $null }

    return $obj.$Key
}

function Set-PlatformStateLocalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowNull()]$Value
    )

    $file = Get-LocalStateFile -Context $Context -ScriptName $ScriptName
    $dir  = Split-Path -Parent $file
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $table = @{}
    if (Test-Path -LiteralPath $file) {
        $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $obj = $raw | ConvertFrom-Json
            if ($obj) {
                foreach ($p in $obj.PSObject.Properties) { $table[$p.Name] = $p.Value }
            }
        }
    }
    $table[$Key] = $Value

    $json = $table | ConvertTo-Json -Depth 20
    $tmp  = $file + '.tmp'
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -NoNewline
    Move-Item -LiteralPath $tmp -Destination $file -Force
}

function Get-LocalStateFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName
    )
    $root = if ($Context.SettingsPath) { $Context.SettingsPath } else { $env:TEMP }
    $safe = ($ScriptName -replace '[^a-zA-Z0-9_.-]','_')
    Join-Path (Join-Path $root 'state') "$safe.json"
}
