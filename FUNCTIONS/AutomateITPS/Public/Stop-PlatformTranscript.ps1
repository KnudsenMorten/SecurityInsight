function Stop-PlatformTranscript {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context
    )

    try {
        Stop-Transcript | Out-Null
    }
    catch {
        return
    }

    if ($Context) {
        Write-PlatformLog -Context $Context -Event 'transcript.stop' -Message 'Transcript stopped'
    }
}
