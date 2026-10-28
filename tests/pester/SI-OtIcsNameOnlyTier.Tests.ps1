#Requires -Version 5.1
<#
    #907 -- A NAME ALONE NEVER MAKES A DEVICE TIER 0 (OT / ICS).
    Five Linux devices named ics-<n> became Tier 0 through the shipped OT / ICS rule, whose single detection fired on ANY of
    OT software, a name (^ot-, ^ics-, ^plc<n>, ^scada<n>) or an OT tier 0 machine tag. A name is a weak signal: it now gives
    Tier 1 with a purpose that says "by name only -- check it"; Tier 0 needs the OT software or the OT machine tag.
    Proved with the engine's own loader (Get-SIRuleSet) and evaluator (Invoke-SIRuleEval) on the SHIPPED rule file.

    #908 (engine side) -- a custom rule that still carries the shipped sample's '# SAMPLE / TEMPLATE' header is loaded as
    before (the run never drops a rule on suspicion) but the loader WARNS that it is the shipped example.
    Offline: a scratch rule tree, nothing live.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleEval.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
    function Write-SIInfo { param($m) }
    $script:Saved = $global:SI_EnrichmentDataRoot
    if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }

    $script:RuleId = 'OTICSControllerWithDirectNetworkAdjacencyToTier0Systems'
    $script:Folder = 'asset-profiling-enrichment\endpoint\AssetProfileByApplicationServiceDetection'
    $script:Shipped = Join-Path $script:SIRoot (Join-Path $script:Folder "$($script:RuleId).locked.yaml")

    # a scratch tree holding ONLY the shipped OT / ICS rule, loaded by the engine's own loader
    $script:Tree = Join-Path ([System.IO.Path]::GetTempPath()) ('si907-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force (Join-Path $script:Tree $script:Folder) | Out-Null
    Copy-Item -LiteralPath $script:Shipped -Destination (Join-Path $script:Tree $script:Folder)
    $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:Tree 3>$null
    $script:Rule = @(@($all) | Where-Object { $_.Id -eq $script:RuleId })[0]

    # the tvmSoftware index the engine builds (Build-SIRuleIndexes): device id -> 'vendor/name'
    $script:SIRuleIndexes = @{ tvmSoftware = @{ 'dev-sw' = @('siemens/siemens_simatic_wincc_7.5') } }
    function script:Eval([hashtable]$Asset) { Invoke-SIRuleEval -Asset ([pscustomobject]$Asset) -Rule $script:Rule }
}

AfterAll {
    Remove-Item -Recurse -Force $script:Tree -ErrorAction SilentlyContinue
    if ($null -ne $script:Saved) { $global:SI_EnrichmentDataRoot = $script:Saved }
}

Describe '#907 -- the OT / ICS rule: evidence gives Tier 0, a name alone gives Tier 1 (check it)' {
    It 'the shipped rule loads with the evidence detection FIRST (first match wins inside a rule)' {
        $script:Rule | Should -Not -BeNullOrEmpty
        @($script:Rule.Detections).Count | Should -Be 2
        [string]@($script:Rule.Detections)[0].Id | Should -Be $script:RuleId
        [int]@($script:Rule.Detections)[0].Set.Tier | Should -Be 0
        [int]@($script:Rule.Detections)[1].Set.Tier | Should -Be 1
    }
    It 'the Tier 0 detection carries no name condition; the name condition sits only in the Tier 1 detection' {
        foreach ($d in @($script:Rule.Detections)) {
            $kinds = @(@($d.Detect.any) + @($d.Detect.all) | Where-Object { $_ } | ForEach-Object { [string]$_.kind })
            if ([int]$d.Set.Tier -eq 0) { $kinds | Should -Not -Contain 'nameMatches' } else { $kinds | Should -Be @('nameMatches') }
        }
    }
    It 'a Linux device named ics-<n> with no OT software and no OT tag -> Tier 1, purpose says "by name only -- check it"' {
        foreach ($n in 'ics-25130', 'ics-2511', 'ics-22-7211', 'ICS-25118', 'ot-line1', 'plc7', 'scada2') {
            $h = Eval @{ Name = $n; MDE_DeviceId = 'dev-none'; OSPlatform = 'Linux' }
            $h | Should -Not -BeNullOrEmpty -Because $n
            [int]$h.Set.Tier | Should -Be 1 -Because $n
            [string]$h.DetectionId | Should -Be 'OTICSDeviceByNameOnly'
            [string]$h.Set.Purpose | Should -Match 'by name only -- check'
        }
    }
    It 'OT software installed -> Tier 0, whatever the name' {
        foreach ($n in 'ics-1', 'plantpc01') {
            $h = Eval @{ Name = $n; MDE_DeviceId = 'dev-sw' }
            [int]$h.Set.Tier | Should -Be 0 -Because $n
            [string]$h.DetectionId | Should -Be $script:RuleId
        }
    }
    It 'an OT / ICS tier 0 machine tag -> Tier 0, whatever the name' {
        foreach ($tag in 'OT-Tier0', 'ics tier 0') {
            $h = Eval @{ Name = 'linuxbox7'; MDE_DeviceId = 'dev-none'; MDE_MachineGroup = $tag }
            [int]$h.Set.Tier | Should -Be 0 -Because $tag
        }
    }
    It 'nothing OT about it -> the rule does not fire' {
        Eval @{ Name = 'kontor'; MDE_DeviceId = 'dev-none'; MDE_MachineGroup = 'Servers' } | Should -BeNullOrEmpty
    }
    It 'the shipped sample mirrors the locked rule body (the sample is the locked rule under the sample header)' {
        $locked = [IO.File]::ReadAllText($script:Shipped)
        $sample = [IO.File]::ReadAllText(($script:Shipped -replace '\.locked\.yaml$', '.custom.sample.yaml'))
        $at = $sample.IndexOf("id:        $($script:RuleId)")
        $at | Should -BeGreaterThan 0
        $sample.Substring(0, $at) | Should -Match '(?m)^# SAMPLE / TEMPLATE'
        $sample.Substring($at) | Should -BeExactly $locked
    }
}

Describe '#908 (engine) -- a live custom rule that is still the shipped example is loaded and WARNED about' {
    BeforeAll {
        $script:T2 = Join-Path ([System.IO.Path]::GetTempPath()) ('si908-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
        $ep = Join-Path $script:T2 'asset-profiling-enrichment\endpoint'
        New-Item -ItemType Directory -Force $ep | Out-Null
        $sample = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'asset-profiling-enrichment\endpoint\AssetProfileByIPSubnet.custom.sample.yaml'))
        [IO.File]::WriteAllText((Join-Path $ep 'AssetProfileByIPSubnet.custom.yaml'), $sample)
        # the same rule, reviewed: header removed
        $reviewed = $sample -replace '(?m)^#\s*SAMPLE\s*/\s*TEMPLATE[^\r\n]*\r?\n', ''
        [IO.File]::WriteAllText((Join-Path $ep 'Reviewed.custom.yaml'), ($reviewed -replace '(?m)^id:\s*AssetProfileByIPSubnet', 'id: Reviewed'))
    }
    AfterAll { Remove-Item -Recurse -Force $script:T2 -ErrorAction SilentlyContinue }

    It 'warns for the sample-marked file only, and still loads both (no rule is dropped on suspicion)' {
        $w = $null
        $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:T2 -WarningVariable w 3>$null
        $ids = @(@($all) | ForEach-Object { [string]$_.Id })
        $ids | Should -Contain 'AssetProfileByIPSubnet'
        $ids | Should -Contain 'Reviewed'
        $ex = @($w | Where-Object { [string]$_ -match 'shipped EXAMPLE' })
        $ex.Count | Should -Be 1
        [string]$ex[0] | Should -Match 'AssetProfileByIPSubnet\.custom\.yaml'
    }
}
