function Write-PlatformLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Debug','Info','Warn','Error')]
        [string]$Severity = 'Info',

        [string]$Event,

        [hashtable]$Data,

        [string]$ScriptName
    )

    $entry = [ordered]@{
        ts            = [datetime]::UtcNow.ToString('o')
        severity      = $Severity
        correlationId = $Context.CorrelationId
        host          = $Context.Host.Kind
        computer      = $Context.Host.ComputerName
    }
    if ($ScriptName) { $entry.script = $ScriptName }
    if ($Event)      { $entry.event  = $Event }
    $entry.message = $Message
    if ($Data)       { $entry.data   = $Data }

    $json = $entry | ConvertTo-Json -Compress -Depth 8

    switch ($Severity) {
        'Error' { [Console]::Error.WriteLine($json) }
        'Warn'  { Write-Warning $json }
        'Debug' { Write-Debug   $json }
        default { Write-Host    $json }
    }
}
