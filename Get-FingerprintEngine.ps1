#Requires -Version 5.1
<#
    SecurityInsight v2.2 — fingerprint engine.
    Used by Collect (fp_meta) and Enrich (fp_enrich) stages to gate downstream skip.
    Pure PowerShell 5.1 — no pwsh 7-only operators.
#>

function Get-AssetFingerprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Inputs,

        [Parameter(Mandatory)]
        [ValidateSet('fp_meta','fp_enrich')]
        [string]$Category
    )

    $orderedKeys = $Inputs.Keys | Sort-Object
    $sb          = New-Object System.Text.StringBuilder

    foreach ($k in $orderedKeys) {
        $v = $Inputs[$k]

        if ($null -eq $v) {
            $v = '<null>'
        }
        elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
            $v = (($v | ForEach-Object { "$_" }) | Sort-Object) -join '|'
        }

        [void]$sb.AppendFormat('{0}={1};', $k, $v)
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ('{0}:{1}' -f $Category, ([System.BitConverter]::ToString($hash) -replace '-',''))
    }
    finally {
        $sha.Dispose()
    }
}

function Test-FingerprintMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Current,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Cached
    )
    if ([string]::IsNullOrEmpty($Cached)) { return $false }
    return ($Current -eq $Cached)
}

