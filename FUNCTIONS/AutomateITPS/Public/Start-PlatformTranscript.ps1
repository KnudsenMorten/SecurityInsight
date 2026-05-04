function Start-PlatformTranscript {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$ScriptName,

        [string]$Directory
    )

    $cloudHosts = @('AzureFunction','LogicApp')
    if ($Context.Host.Kind -in $cloudHosts) {
        Write-PlatformLog -Context $Context -Severity Debug -Event 'transcript.skip' -Message "Transcript skipped on host '$($Context.Host.Kind)' (stdout already captured)." -ScriptName $ScriptName
        return $null
    }

    if (-not $Directory) {
        $root = if ($Context.SettingsPath) { $Context.SettingsPath } else { $env:TEMP }
        $Directory = Join-Path $root 'transcripts'
    }
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }

    $safe = ($ScriptName -replace '[^a-zA-Z0-9_.-]','_')
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $path = Join-Path $Directory "$safe-$stamp-$($Context.CorrelationId).log"

    Start-Transcript -Path $path -Force | Out-Null
    Write-PlatformLog -Context $Context -Event 'transcript.start' -Message "Transcript: $path" -ScriptName $ScriptName
    return $path
}
