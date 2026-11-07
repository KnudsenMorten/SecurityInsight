#Requires -Version 5.1
<#
    Owner 2026-11-04: the two Exposure Graph scope switches set at one large install become SecurityInsight's DEFAULT:
    SI_Identity_SkipNeverSyncedDisabledAd and SI_Identity_SkipDeletedGroups are ON by default.
      * the shipped default (launcher\_lib\SecurityInsight.shared-defaults.ps1) and the settings catalog both say ON;
      * an install that never stored a value takes the new default (the shipped defaults load first, a stored value is
        laid over them -- nothing to migrate);
      * a value an install stored (a customer's or support's choice) is kept, ON or OFF.
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
