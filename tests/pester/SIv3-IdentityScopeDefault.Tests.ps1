#Requires -Version 5.1
<#
    Owner 2026-11-04: the two Exposure Graph scope switches set at one large install become SecurityInsight's DEFAULT:
    SI_Identity_SkipNeverSyncedDisabledAd and SI_Identity_SkipDeletedGroups are ON by default.
      * the shipped default (launcher\_lib\SecurityInsight.shared-defaults.ps1) and the settings catalog both say ON;
      * an install that never stored a value takes the new default (the shipped defaults load first, a stored value is
        laid over them -- nothing to migrate);
      * a value an install stored (a customer's or support's choice) is kept, ON or OFF;
      * THE CONTAINER (2026-11-07): it never loads the shared defaults, and the Pro settings layer sets a global only for a
        stored row -- so with no row the switches must still be ON: the code's own default (SI-IdentityScopeChoice.ps1) and
        the container's catalog defaults (Set-SIContainerCatalogDefaults) both say ON; the CI build's choice too.
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'shared', 'SI-IdentityScopeChoice.ps1'))
    $script:Names = @('SI_Identity_SkipNeverSyncedDisabledAd', 'SI_Identity_SkipDeletedGroups')
    $script:Catalog = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'settings.catalog.locked.json')) | ConvertFrom-Json
    function script:Read-SharedDefaults {
        # the shipped defaults, read the way the launcher loads them (the file sets globals)
        foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        . ([IO.Path]::Combine($script:SIRoot, 'launcher', '_lib', 'SecurityInsight.shared-defaults.ps1'))
    }
}

AfterAll {
    foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
}

Describe 'the two Exposure Graph scope switches are on by default' {
    It 'the settings catalog says default ON for <_>' -ForEach @('SI_Identity_SkipNeverSyncedDisabledAd', 'SI_Identity_SkipDeletedGroups') {
        $n = $_
        $s = @($script:Catalog.settings | Where-Object { $_.name -eq $n }) | Select-Object -First 1
        $s | Should -Not -BeNullOrEmpty
        $s.default | Should -BeTrue
        $s.defaultText | Should -Match '^On'
    }
    It 'unset: an install that never stored a value gets both switches ON from the shipped defaults' {
        Read-SharedDefaults
        $c = Get-SIIdentityScopeChoice
        $c.SkipNeverSyncedDisabledAd | Should -BeTrue
        $c.SkipDeletedGroups | Should -BeTrue
        $c.Any | Should -BeTrue
    }
    It 'set: a value the install stored (OFF) is laid over the default and kept' {
        Read-SharedDefaults
        $global:SI_Identity_SkipNeverSyncedDisabledAd = $false   # the stored choice, applied after the shipped defaults
        $global:SI_Identity_SkipDeletedGroups = 'false'
        $c = Get-SIIdentityScopeChoice
        $c.SkipNeverSyncedDisabledAd | Should -BeFalse
        $c.SkipDeletedGroups | Should -BeFalse
        $c.Any | Should -BeFalse
    }
    It 'set: one switch stored OFF, the other left unset -> only the stored one is off' {
        Read-SharedDefaults
        $global:SI_Identity_SkipDeletedGroups = $false
        $c = Get-SIIdentityScopeChoice
        $c.SkipNeverSyncedDisabledAd | Should -BeTrue
        $c.SkipDeletedGroups | Should -BeFalse
    }
}

Describe 'the container path: no shared defaults, no stored row' {
    BeforeAll {
        function script:Clear-Switches { foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    }
    It 'globals unset and the shared defaults NOT loaded: both ON, Any ON (the code''s own default)' {
        Clear-Switches
        $c = Get-SIIdentityScopeChoice
        ($c.SkipNeverSyncedDisabledAd, $c.SkipDeletedGroups, $c.Any) | Should -Be @($true, $true, $true)
    }
    It 'a stored no stays OFF: ''false'' / $false' {
        Clear-Switches
        $global:SI_Identity_SkipNeverSyncedDisabledAd = 'false'; $global:SI_Identity_SkipDeletedGroups = $false
        $c = Get-SIIdentityScopeChoice
        ($c.SkipNeverSyncedDisabledAd, $c.SkipDeletedGroups, $c.Any) | Should -Be @($false, $false, $false)
        Clear-Switches
    }
    It 'the in-code default = the catalog default = the shared-defaults value, for <_>' -ForEach @('SI_Identity_SkipNeverSyncedDisabledAd', 'SI_Identity_SkipDeletedGroups') {
        $n = $_
        $code = @($script:SIIdentityScopeSettings.Values | Where-Object { $_.Setting -eq $n })[0].Default
        $cat = (@($script:Catalog.settings | Where-Object { $_.name -eq $n }) | Select-Object -First 1).default
        Read-SharedDefaults
        $shared = Get-Variable -Name $n -Scope Global -ValueOnly
        Clear-Switches
        $code | Should -BeTrue
        $cat | Should -Be $code
        $shared | Should -Be $code
    }
    It 'the CI build''s choice (Get-SICiIdentityChoice) is ON with the globals unset, and follows a stored no' {
        . ([IO.Path]::Combine($script:SIRoot, 'engine', 'data-model', 'SI-CiBuild.ps1'))
        Clear-Switches
        $script:SICiIdentityChoiceCache = $null
        $c = Get-SICiIdentityChoice
        $c | Should -Not -BeNullOrEmpty
        ($c.SkipNeverSyncedDisabledAd, $c.SkipDeletedGroups) | Should -Be @($true, $true)
        # the cache is keyed by the two globals: a stored no is seen at once
        $global:SI_Identity_SkipDeletedGroups = $false
        (Get-SICiIdentityChoice).SkipDeletedGroups | Should -BeFalse
        Clear-Switches
        (Get-SICiIdentityChoice).SkipDeletedGroups | Should -BeTrue
    }
}