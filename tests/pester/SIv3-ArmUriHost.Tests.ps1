#Requires -Version 7.0
<#
    AN AZURE RESOURCE MANAGER ADDRESS ALWAYS HAS ITS HOST.

    Why: 2026-10-12, a new install in a Support session stopped at "Container registry and image". Get-SIArmUri read the
    host from a script variable of setup\_shared\SI-UpdateRest.ps1. A script that finds the functions already defined by
    its caller does not dot-source that file again ("if (-not (Get-Command Invoke-SIRestJson)) { . SI-UpdateRest.ps1 }"),
    so in its scope the variable did not exist and the request went out as '/subscriptions/...' without a host.
    Offline, pure.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-UpdateRest.ps1'))
}

Describe 'Get-SIArmUri: the address is whole in every scope' {
    It 'a path gets the host and the api version; a full address is kept' {
        Get-SIArmUri -Path '/subscriptions/x/resourceGroups/y' -ApiVersion '2023-07-01' | Should -Be 'https://management.azure.com/subscriptions/x/resourceGroups/y?api-version=2023-07-01'
        Get-SIArmUri -Path 'https://management.azure.com/subscriptions/x?api-version=2020-01-01' -ApiVersion '2023-07-01' | Should -Be 'https://management.azure.com/subscriptions/x?api-version=2020-01-01'
    }
    It 'the host is there when the file''s script variables are not in the caller''s scope' {
        Remove-Variable -Name SIUpdateArmBase -Scope Script -ErrorAction SilentlyContinue
        Get-SIArmUri -Path '/subscriptions/x' -ApiVersion '2023-07-01' | Should -Match '^https://management\.azure\.com/subscriptions/x\?'
    }
    It 'the function does not read the host from a script variable' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-UpdateRest.ps1'))
        $src | Should -Not -Match '\$script:SIUpdateArmBase \+ \$Path'
    }
}
