function Set-PlatformLocalSecret {
    [CmdletBinding(DefaultParameterSetName='Plain')]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName='Plain')]
        [string]$Value,

        [Parameter(Mandatory, ParameterSetName='Secure')]
        [securestring]$SecureValue,

        [string]$Path
    )

    Assert-WindowsPlatform -Feature 'Local secret provider (DPAPI)'

    if ($PSCmdlet.ParameterSetName -eq 'Secure') {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
        try   { $Value = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }

    $file = if ($Path) { $Path } else { Get-LocalSecretFile }
    $dir  = Split-Path -Parent $file
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $store = @{}
    if (Test-Path -LiteralPath $file) {
        $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $obj = $raw | ConvertFrom-Json
            foreach ($p in $obj.PSObject.Properties) { $store[$p.Name] = $p.Value }
        }
    }

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    try {
        $cipherBytes  = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $store[$Name] = [Convert]::ToBase64String($cipherBytes)
    }
    finally {
        [Array]::Clear($plainBytes, 0, $plainBytes.Length)
    }

    $json = $store | ConvertTo-Json -Depth 5
    $tmp  = $file + '.tmp'
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -NoNewline
    Move-Item -LiteralPath $tmp -Destination $file -Force
}
