function Get-PlatformState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$ScriptName,

        [Parameter(Mandatory)]
        [string]$Key
    )

    switch ($Context.Providers.State) {
        'AzureTable' { return Get-PlatformStateAzureTable -Context $Context -ScriptName $ScriptName -Key $Key }
        'LocalJson'  { return Get-PlatformStateLocalJson  -Context $Context -ScriptName $ScriptName -Key $Key }
        'None'       { throw "Get-PlatformState: state provider disabled on this context." }
        default      { throw "Get-PlatformState: unknown provider '$($Context.Providers.State)'." }
    }
}
