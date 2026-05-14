Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Get-PlatformSecretLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Name,
        [switch]$AsPlainText
    )

    Assert-WindowsPlatform -Feature 'Local secret provider (DPAPI)'

    $path = Get-LocalSecretFile
    if (-not (Test-Path -LiteralPath $path)) {
        # v2.2.291 -- downgrade to Write-Verbose. Same rationale as the KV
        # provider: optional missing secrets on a fresh install shouldn't
        # spam the launcher output. Run with -Verbose to surface these.
        Write-Verbose ("Get-PlatformSecretLocal: store not found at {0} (returning `$null). Populate with Set-PlatformLocalSecret if you need this secret." -f $path)
        return $null
    }

    $store = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not ($store.PSObject.Properties.Name -contains $Name)) {
        Write-Verbose ("Get-PlatformSecretLocal: secret '{0}' not found in {1} (returning `$null)." -f $Name, $path)
        return $null
    }

    $cipherBytes = [Convert]::FromBase64String($store.$Name)
    $plainBytes  = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $cipherBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
        $plain = [System.Text.Encoding]::UTF8.GetString($plainBytes)
        if ($AsPlainText) { return $plain }
        $ss = New-Object System.Security.SecureString
        foreach ($c in $plain.ToCharArray()) { $ss.AppendChar($c) }
        $ss.MakeReadOnly()
        return $ss
    }
    finally {
        if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    }
}

function Get-LocalSecretFile {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($env:AUTOMATEIT_SECRETS_FILE) { return $env:AUTOMATEIT_SECRETS_FILE }
    Join-Path $env:USERPROFILE '.automateit\secrets.dpapi.json'
}

function Assert-WindowsPlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Feature)
    $isWin = $true
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $isWin = [bool]$IsWindows
    }
    if (-not $isWin) {
        throw "$Feature requires Windows (DPAPI). Current platform is not Windows."
    }
}
