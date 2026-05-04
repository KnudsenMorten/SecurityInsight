function Set-PlatformState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$ScriptName,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    switch ($Context.Providers.State) {
        'AzureTable' { Set-PlatformStateAzureTable -Context $Context -ScriptName $ScriptName -Key $Key -Value $Value; return }
        'LocalJson'  { Set-PlatformStateLocalJson  -Context $Context -ScriptName $ScriptName -Key $Key -Value $Value; return }
        'None'       { throw "Set-PlatformState: state provider disabled on this context." }
        default      { throw "Set-PlatformState: unknown provider '$($Context.Providers.State)'." }
    }
}
