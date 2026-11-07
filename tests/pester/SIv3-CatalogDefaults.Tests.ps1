#Requires -Version 5.1
<#
    AN UNSTORED SETTING READS THE CATALOG DEFAULT -- IN THE CONTAINER TOO (framework rule; found 2026-11-07: the two identity
    scope switches, shipped ON, ran OFF in every container whose install never stored them).
      * ONE TABLE: for every catalog setting with a default (secrets left out), the container start path -- the catalog
        defaults (Set-SIContainerCatalogDefaults), never launcher\_lib\SecurityInsight.shared-defaults.ps1 -- leaves the
        global at the catalog default, by the catalog's own type; the few left out are named, each with its reason;
      * the order: a value already there is kept, the customer's SI_CFG_* values and a stored cfg.Setting row still win;
      * both container entry points apply them before the engine's defaults file and the customer's values, and neither
        loads the shared-defaults file;
      * the catalog and the shared defaults never disagree where both state a value.
    Offline; globals restored after; PS 5.1 + pwsh 7.
#>

BeforeDiscovery {
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $cat = [IO.File]::ReadAllText([IO.Path]::Combine($siRoot, 'config', 'settings.catalog.locked.json')) | ConvertFrom-Json
    $script:WithDefault = @($cat.settings | Where-Object { $null -ne $_.default -and -not $_.secret } | ForEach-Object { @{ Name = [string]$_.name; Type = [string]$_.type } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'container', '_shared', 'SI-ContainerConfig.ps1'))
    $script:CatalogPath = [IO.Path]::Combine($script:SIRoot, 'config', 'settings.catalog.locked.json')
    $script:Catalog = [IO.File]::ReadAllText($script:CatalogPath) | ConvertFrom-Json
    $script:Names = @($script:Catalog.settings | ForEach-Object { [string]$_.name })
    # the names this suite sets: saved and restored, so no other suite sees a global from here
    $script:Saved = @{}
    foreach ($n in $script:Names) { $v = Get-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue; if ($v) { $script:Saved[$n] = $v.Value } }
    function script:Clear-CatalogGlobals { foreach ($n in $script:Names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    function script:ConvertTo-Comparable($v) { if ($null -eq $v) { return '<null>' }; if ($v -is [array]) { return ('@(' + ((@($v) | ForEach-Object { [string]$_ }) -join ',') + ')') }; ('{0}:{1}' -f $v.GetType().Name, [Convert]::ToString($v, [Globalization.CultureInfo]::InvariantCulture)) }
    # the container start path, with no stored row
    Clear-CatalogGlobals
    $script:Applied = Set-SIContainerCatalogDefaults -CatalogPath $script:CatalogPath
    $script:After = @{}; foreach ($n in $script:Names) { $script:After[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    Clear-CatalogGlobals
}

AfterAll {
    Clear-CatalogGlobals
    foreach ($k in @($script:Saved.Keys)) { Set-Variable -Name $k -Scope Global -Value $script:Saved[$k] }
}

Describe 'every catalog setting with a default: the container''s value with no stored row is the catalog default' {
    It '<Name> (<Type>)' -ForEach $script:WithDefault {
        $s = @($script:Catalog.settings | Where-Object { $_.name -eq $Name })[0]
        $why = $null
        if ($script:SICatalogDefaultNotApplied.Contains($Name)) { $why = 'unset has a meaning of its own: ' + $script:SICatalogDefaultNotApplied[$Name] }
        elseif ($script:SIConfigProtected -contains $Name) { $why = 'the container states it from its own env vars' }
        elseif ($Name.StartsWith('SIWeb_')) { $why = 'a web-app setting' }
        elseif (Test-SIConfigNameIsSecret -Name $Name) { $why = 'a secret-looking name' }
        if ($why) {
            $script:After[$Name] | Should -BeNullOrEmpty -Because ('{0} is left unset on purpose ({1})' -f $Name, $why)
            return
        }
        $want = ConvertFrom-SICatalogDefault -Setting $s
        (ConvertTo-Comparable $script:After[$Name]) | Should -Be (ConvertTo-Comparable $want) -Because "the catalog says $($s.default | ConvertTo-Json -Compress)"
        switch ($Type) {
            'bool'   { $script:After[$Name] | Should -BeOfType [bool] }
            'int'    { ($script:After[$Name] -is [int] -or $script:After[$Name] -is [long]) | Should -BeTrue }
            'number' { $script:After[$Name] | Should -BeOfType [double] }
            'list'   { , $script:After[$Name] | Should -BeOfType [array] }
            default  { $script:After[$Name] | Should -BeOfType [string] }
        }
    }
    It 'the left-out list is short and every entry is a catalog setting with a default' {
        $withDefault = @($script:Catalog.settings | Where-Object { $null -ne $_.default } | ForEach-Object { [string]$_.name })
        foreach ($k in @($script:SICatalogDefaultNotApplied.Keys)) { $withDefault | Should -Contain $k }
        @($script:SICatalogDefaultNotApplied.Keys).Count | Should -BeLessOrEqual 3
    }
}

Describe 'the order: what is there wins' {
    AfterEach { Clear-CatalogGlobals }
    It 'a value already set is never touched (an engine''s defaults file run earlier, a test)' {
        Clear-CatalogGlobals
        $global:SI_ActiveStaleDays = 45; $global:SI_Identity_SkipDeletedGroups = $false
        $r = Set-SIContainerCatalogDefaults -CatalogPath $script:CatalogPath
        $global:SI_ActiveStaleDays | Should -Be 45
        $global:SI_Identity_SkipDeletedGroups | Should -BeFalse
        @($r.Kept) | Should -Contain 'SI_ActiveStaleDays'
        $global:SI_Identity_SkipNeverSyncedDisabledAd | Should -BeTrue -Because 'the one left unset gets its default'
    }
    It 'the customer''s SI_CFG_* value, imported after the defaults, wins' {
        Clear-CatalogGlobals
        $null = Set-SIContainerCatalogDefaults -CatalogPath $script:CatalogPath
        $null = Import-SIConfigFromEnv -Environment @{ SI_CFG_SI_Identity_SkipDeletedGroups = 'false'; SI_CFG_SI_ActiveStaleDays = '14' }
        $global:SI_Identity_SkipDeletedGroups | Should -BeFalse
        [int]$global:SI_ActiveStaleDays | Should -Be 14
    }
    It 'a stored cfg.Setting row, laid over by the Pro settings layer, wins' {
        . ([IO.Path]::Combine($script:SIRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
        Clear-CatalogGlobals
        $null = Set-SIContainerCatalogDefaults -CatalogPath $script:CatalogPath
        $global:SI_Identity_SkipDeletedGroups | Should -BeTrue
        $c = ConvertFrom-SIProSettingRows -Rows @(@{ Name = 'SI_Identity_SkipDeletedGroups'; Scope = 'solution'; ValueJson = 'false'; KeyVaultSecretName = $null }) -Catalog @($script:Catalog.settings) -Engine 'identity'
        @($c.Refused).Count | Should -Be 0
        foreach ($k in @($c.Values.Keys)) { Set-Variable -Name $k -Value $c.Values[$k] -Scope Global }   # as Invoke-SIProSettingsLayer does
        $global:SI_Identity_SkipDeletedGroups | Should -BeFalse
    }
}

Describe 'the container entry points apply them first, and never load the shared defaults' {
    It '<_>: the catalog defaults come before the engine''s defaults file and the customer''s values' -ForEach @('container/Start-SIInContainer.ps1', 'container/Start-RiskAnalysisInContainer.ps1') {
        $text = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, $_))
        $cd = $text.IndexOf('Set-SIContainerCatalogDefaults')
        $cd | Should -BeGreaterThan 0
        $ed = $text.IndexOf('Get-SIContainerEngineDefaultsPath')
        $cfg = $text.IndexOf('Import-SIConfigFromEnv')
        $cd | Should -BeLessThan $ed
        $cd | Should -BeLessThan $cfg
        $pro = $text.IndexOf('Invoke-SIProSettingsLayer')
        if ($pro -ge 0) { $cd | Should -BeLessThan $pro }
        $text | Should -Not -Match 'SecurityInsight\.shared-defaults\.ps1'
    }
}

Describe 'the catalog and the shared defaults never disagree' {
    It 'every setting both state has the same value' {
        Clear-CatalogGlobals
        $null = . ([IO.Path]::Combine($script:SIRoot, 'launcher', '_lib', 'SecurityInsight.shared-defaults.ps1')) 6>$null
        $diff = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($script:Catalog.settings | Where-Object { $null -ne $_.default -and -not $_.secret })) {
            $v = Get-Variable -Name $s.name -Scope Global -ErrorAction SilentlyContinue
            if (-not $v -or $null -eq $v.Value) { continue }
            $want = ConvertFrom-SICatalogDefault -Setting $s
            if ((@($v.Value) | ForEach-Object { [string]$_ }) -join ',' -ne ((@($want) | ForEach-Object { [string]$_ }) -join ',')) { $diff.Add(('{0}: catalog {1}, shared defaults {2}' -f $s.name, ($s.default | ConvertTo-Json -Compress), ($v.Value | ConvertTo-Json -Compress))) }
        }
        Clear-CatalogGlobals
        @($diff) | Should -BeNullOrEmpty
    }
}
