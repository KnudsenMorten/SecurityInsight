function Get-HostEnvironment {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:PLATFORM_HOST) { return $env:PLATFORM_HOST }

    if ($env:FUNCTIONS_WORKER_RUNTIME)   { return 'AzureFunction' }
    if ($env:AUTOMATION_ASSET_ACCOUNTID) { return 'HybridWorker' }
    if ($env:WEBSITE_SITE_NAME -and $env:LOGIC_APP_WORKFLOW_NAME) { return 'LogicApp' }

    $domainJoined = $false
    try {
        $domainJoined = [bool]($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME)
    } catch { }

    if ($domainJoined) { return 'VM' }
    return 'Dev'
}
