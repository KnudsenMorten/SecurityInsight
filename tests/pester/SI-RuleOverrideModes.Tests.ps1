#Requires -Version 5.1
<#
    ENRICHMENT RULE OVERRIDE MODES (#470) -- overwrite / append / merge / disable, as declared.
    A customer rule (*.custom.yaml) combines with the shipped rule of the same id (*.locked.yaml) by its mode; the
    override grain is one detection, never the file (V3-DATA-MODEL §2.4.5). Offline: a scratch rule tree, nothing live.
    Also: the shipped samples claim nothing the loader does not do (no non-existent kind, no unwired mode).
#>

BeforeAll {
    $script:si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:si 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
    function Write-SIInfo { param($m) Write-Host $m }
    $script:Saved = $global:SI_EnrichmentDataRoot
    if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }
    $script:Roots = New-Object System.Collections.Generic.List[string]

    function script:New-Tree {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('si470-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Force (Join-Path $root 'asset-profiling-enrichment\endpoint') | Out-Null
        $script:Roots.Add($root)
        $root
    }
    # one rule file: -Dets = @( @('DetId', tier), ... )
    function script:Write-Rule([string]$Root, [string]$File, [string]$Mode, [string]$Purpose, [object[]]$Dets, [string]$Scope = '') {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('id:        RuleA'); $lines.Add('appliesTo: endpoint'); $lines.Add("mode:      $Mode")
        if ($Purpose) { $lines.Add("purpose:   '$Purpose'") }
        if ($Scope) { $lines.Add("osPlatformScope: [$Scope]") }
        if ($Mode -ne 'disable') {
            $lines.Add('detections:')
            foreach ($d in $Dets) {
                $lines.Add("  - id: $($d[0])"); $lines.Add('    detect:'); $lines.Add('      any:'); $lines.Add('        - kind: nameMatches')
                $lines.Add('          namePatterns:'); $lines.Add("            - '(?i)^$($d[0])'"); $lines.Add('    set:'); $lines.Add("      Tier: $($d[1])")
            }
        }
        [System.IO.File]::WriteAllText((Join-Path $Root "asset-profiling-enrichment\endpoint\$File"), ($lines -join "`r`n") + "`r`n")
    }
    # the loader returns its rules as ONE array object (,$results): assigned first, then enumerated
    function script:Load([string]$Root) { $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $Root 3>$null; @(@($all) | Where-Object { $_.Id -eq 'RuleA' })[0] }
    function script:DetMap($Rule) { $h = [ordered]@{}; foreach ($d in @($Rule.Detections)) { $h[[string]$d.Id] = [int]$d.Set.Tier }; $h }
}

AfterAll {
    foreach ($r in $script:Roots) { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue }
    if ($null -ne $script:Saved) { $global:SI_EnrichmentDataRoot = $script:Saved }
}

Describe 'A custom rule combines with the shipped rule of the same id by its mode' {
    BeforeEach {
        $script:T = New-Tree
        Write-Rule $script:T 'RuleA.locked.yaml' 'locked' 'shipped' @(@('Web', 2), @('Db', 1))
    }
    It 'overwrite: the custom rule replaces the shipped one' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'overwrite' 'mine' @(, @('Mine', 0))
        $r = Load $script:T
        @($r).Count | Should -Be 1
        (DetMap $r).Keys -join ',' | Should -Be 'Mine'
        $r.Purpose | Should -Be 'mine'
    }
    It 'no mode / locked on a custom file is overwrite (the behaviour before #470)' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'locked' 'mine' @(, @('Mine', 0))
        (DetMap (Load $script:T)).Keys -join ',' | Should -Be 'Mine'
    }
    It 'append: the shipped detections stay and the new ones are added; a repeated id does NOT change a shipped detection' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'append' 'mine' @(@('Mine', 0), @('Db', 3))
        $warn = $null
        $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:T -WarningVariable warn 3>$null; $r = @(@($all) | Where-Object { $_.Id -eq 'RuleA' })[0]
        $m = DetMap $r
        ($m.Keys -join ',') | Should -Be 'Web,Db,Mine'
        $m['Db'] | Should -Be 1 -Because 'append never replaces a shipped detection'
        ($warn -join ' ') | Should -Match "repeats shipped detection id\(s\) Db"
        $r.Purpose | Should -Be 'shipped' -Because 'append adds to the shipped rule; its label stays'
        $r.Mode | Should -Be 'append'
        $r.BaseFile | Should -Match 'RuleA\.locked\.yaml$'
        $r.File | Should -Match 'RuleA\.custom\.yaml$'
    }
    It 'merge: a custom detection EXTENDS the shipped one of the same id (any: entries added, its set: keys win); new ids are added; the custom label wins' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'merge' 'mine' @(@('Db', 0), @('Mine', 3))
        $r = Load $script:T
        $m = DetMap $r
        ($m.Keys -join ',') | Should -Be 'Web,Db,Mine'
        $m['Db'] | Should -Be 0
        $m['Web'] | Should -Be 2
        $db = @($r.Detections | Where-Object { $_.Id -eq 'Db' })[0]
        @($db.Detect.any).Count | Should -Be 2 -Because 'the shipped name pattern AND the custom one both match now'
        $r.Purpose | Should -Be 'mine'
    }
    It 'merge: the extended detection carries both name patterns' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'merge' '' @(, @('Db', 0))
        $db = @((Load $script:T).Detections | Where-Object { $_.Id -eq 'Db' })[0]
        $pats = @($db.Detect.any | ForEach-Object { @($_.namePatterns) })
        $pats.Count | Should -Be 2
        foreach ($p in $pats) { 'Db-host' -match $p | Should -BeTrue }
    }
    It 'disable: the shipped rule is turned off' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'disable' '' @()
        $r = Load $script:T
        $r.Mode | Should -Be 'disable'
        @($r.Detections).Count | Should -Be 0
    }
    It 'disable with detection ids: only those shipped detections are dropped' {
        [System.IO.File]::WriteAllText((Join-Path $script:T 'asset-profiling-enrichment\endpoint\RuleA.custom.yaml'), "id: RuleA`r`nappliesTo: endpoint`r`nmode: disable`r`ndetections:`r`n  - id: Db`r`n")
        $r = Load $script:T
        $r.Mode | Should -Not -Be 'disable'
        ((DetMap $r).Keys -join ',') | Should -Be 'Web'
        @($r.DisabledDetections) | Should -Be @('Db')
    }
    It 'an unknown mode warns and replaces (overwrite)' {
        Write-Rule $script:T 'RuleA.custom.yaml' 'combine' 'mine' @(, @('Mine', 0))
        $warn = $null
        $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:T -WarningVariable warn 3>$null; $r = @(@($all) | Where-Object { $_.Id -eq 'RuleA' })[0]
        (DetMap $r).Keys -join ',' | Should -Be 'Mine'
        ($warn -join ' ') | Should -Match "mode 'combine'"
    }
    It 'append: osPlatformScope is the union; empty on either side means every OS' {
        $t = New-Tree
        Write-Rule $t 'RuleA.locked.yaml' 'locked' 'shipped' @(, @('Web', 2)) 'Windows'
        Write-Rule $t 'RuleA.custom.yaml' 'append' '' @(, @('Mine', 0)) 'Linux'
        @((Load $t).osPlatformScope) -join ',' | Should -Be 'Windows,Linux'
        $u = New-Tree
        Write-Rule $u 'RuleA.locked.yaml' 'locked' 'shipped' @(, @('Web', 2)) 'Windows'
        Write-Rule $u 'RuleA.custom.yaml' 'append' '' @(, @('Mine', 0))
        @((Load $u).osPlatformScope).Count | Should -Be 0
    }
}

Describe 'With no shipped rule of that id every mode is the rule as written' {
    It '<Mode>' -TestCases @(@{ Mode = 'append' }, @{ Mode = 'merge' }, @{ Mode = 'overwrite' }) {
        $t = New-Tree
        Write-Rule $t 'RuleA.custom.yaml' $Mode 'mine' @(@('Mine', 0), @('Other', 1))
        $r = Load $t
        (DetMap $r).Keys -join ',' | Should -Be 'Mine,Other'
        $r.Purpose | Should -Be 'mine'
    }
}

Describe 'The shipped samples claim only what the loader does' {
    It 'no sample names a detect kind the rule engine does not have' {
        $ruleEval = Get-Content -Raw -LiteralPath (Join-Path $script:si 'engine\asset-profiling\shared\RuleEval.ps1')
        $known = @([regex]::Matches($ruleEval, "'(?<k>[A-Za-z]+)'\s*=\s*'Test-SIKind_") | ForEach-Object { $_.Groups['k'].Value })
        $known.Count | Should -BeGreaterThan 5
        $samples = @(Get-ChildItem -LiteralPath (Join-Path $script:si 'asset-profiling-enrichment') -Recurse -File -Filter '*.sample.yaml')
        $bad = foreach ($f in $samples) {
            foreach ($m in [regex]::Matches((Get-Content -Raw -LiteralPath $f.FullName), '(?m)(kind:\s*|^\s*#?\s*\*\s+)(?<k>has[A-Za-z]+|eg[A-Za-z]+|nameMatches|osPlatform|groupMembership|mostFrequentUserTier|ipInRange)\b')) {
                if ($known -notcontains $m.Groups['k'].Value) { '{0}: {1}' -f $f.Name, $m.Groups['k'].Value }
            }
        }
        @($bad | Select-Object -Unique) | Should -BeNullOrEmpty
    }
    It 'no sample says a mode is not wired or treated as locked' {
        $samples = @(Get-ChildItem -LiteralPath (Join-Path $script:si 'asset-profiling-enrichment') -Recurse -File -Filter '*.sample.yaml')
        foreach ($f in $samples) {
            $t = Get-Content -Raw -LiteralPath $f.FullName
            $t | Should -Not -Match 'are wired today|treated as\s*#?\s*`?locked' -Because $f.Name
            $t | Should -Not -Match "'append' = add to locked" -Because $f.Name
        }
    }
    It 'the loader no longer says the modes are not implemented' {
        (Get-Content -Raw -LiteralPath (Join-Path $script:si 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')) | Should -Not -Match 'NOT yet implemented'
    }
}
