#Requires -Version 5.1
<#
    #244 -- EVERY PROFILER SAYS WHICH SOURCE SET THE TIER, AND THE DATA SYNC CARRIES IT TO THE PRO DATABASE.

    (The data sync half -- the profile read and Merge-SIDataTierAttribution -- is Pro code and is tested in
    SIv3-DataSync.Tests.ps1.)

    The operator saw every asset on the Pro tier board read "set by (not recorded)", with every wire going to that one
    chip. Two causes, both closed here:
      1. only the endpoint profiler wrote SI_TierSetBy / SI_TierReason / SI_TierClaims -- identity, azure and publicip
         rows carried none;
      2. the data sync read only name + tier from the profile tables, and the PropertiesJson it stored is keyed by
         source system ({ "mde": {...} }), so the board's '$.SI_TierSetBy' never existed in it.

    Builders run in a CHILD PROCESS: all four define Get-SIDerivedValue, so dot-sourcing more than one into a single
    scope means the last silently wins and the suite measures the wrong file.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Shared = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'
    . (Join-Path $script:Shared 'Get-SITierAttribution.ps1')

    # One built row's three attribution columns, as JSON, from a child process (5.1 when available, else this host).
    function script:BuildAttribution {
        param([Parameter(Mandatory)][string]$Builder, [Parameter(Mandatory)][string]$Function, [Parameter(Mandatory)][string]$RecordScript, [string]$Engine)
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$(Join-Path $script:Shared $Builder)'
`$rec = $RecordScript
`$rc  = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z'; Engine = '$Engine'; RunId = 'r1' }
`$row = $Function -Record `$rec -RunContext `$rc
'<ATTR>' + (ConvertTo-Json -Compress -InputObject ([ordered]@{ SetBy = [string]`$row.SI_TierSetBy; Reason = [string]`$row.SI_TierReason; Claims = [string]`$row.SI_TierClaims; Tier = [string]`$row.Tier; Has = [bool](`$row.PSObject.Properties['SI_TierSetBy']) }))
"@
        # the child runs the gate's own PowerShell (v3 gates PowerShell 7 only, 2026-10-09; 5.1 on the opt-in)
        $exe = (Get-Process -Id $PID).Path
        $env51 = $env:PSModulePath
        if ($exe -match '(?i)\\WindowsPowerShell\\v1\.0\\powershell\.exe$') { $env:PSModulePath = 'C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules' }
        # -EncodedCommand: the record carries JSON, and Windows PowerShell 5.1 strips the inner quotes of a plain
        # -Command argument -- the child would read mangled JSON and every row would honestly say 'default'.
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        try { $out = & $exe -NoProfile -NonInteractive -EncodedCommand $enc 2>&1 } finally { $env:PSModulePath = $env51 }
        $line = @($out) | Where-Object { "$_" -like '<ATTR>*' } | Select-Object -Last 1
        if (-not $line) { throw ("the builder produced no row; output was: {0}" -f (($out | Select-Object -Last 6) -join ' | ')) }
        ConvertFrom-Json -InputObject (([string]$line) -replace '^<ATTR>', '')
    }
}

Describe 'Get-SIProfileTierSources -- the claims a non-endpoint row can make' {

    It 'a profile rule that set the tier is the source, with the rule as evidence' {
        $v = [pscustomobject]@{ SI_Tier = 0; SI_RuleTier = 0; SI_RuleMatches = @([pscustomobject]@{ RuleId = 'r-dc'; DetectionId = 'd1'; Tier = 0 }, [pscustomobject]@{ RuleId = 'r-x'; Tier = 2 }) }
        $s = Get-SIProfileTierSources -Verdict $v -ClassifyStatus 'no-ai'
        $a = Get-SITierAttribution -FinalTier 0 -Sources $s
        $a.SI_TierSetBy | Should -Be 'rule'
        $a.SI_TierReason | Should -Match 'r-dc/d1'
        $s.ContainsKey('ClassifyVerdict') | Should -BeFalse -Because 'the classification cannot be told apart from the rule when both say 0'
    }

    It 'the classification verdict is the source when it is lower than every rule' {
        $v = @{ SI_Tier = 1; SI_RuleTier = 2; SI_RuleMatches = @(@{ RuleId = 'r-app'; Tier = 2 }) }
        (Get-SITierAttribution -FinalTier 1 -Sources (Get-SIProfileTierSources -Verdict $v -ClassifyStatus 'deterministic')).SI_TierSetBy | Should -Be 'classification'
    }

    It 'per-source verdicts (identity) are claims; a source with no tier is no claim' {
        $ps = @{ EntraRolesPermanent = [pscustomobject]@{ Tier = 0; TopMatch = 'Global Administrator'; MatchCount = 1 }
                 AzureRoles = [pscustomobject]@{ Tier = $null; TopMatch = $null; MatchCount = 0 } }
        $s = Get-SIProfileTierSources -Verdict @{ SI_Tier = 0 } -PerSource $ps -ClassifyStatus 'catalog'
        $s.ContainsKey('AzureRoles') | Should -BeFalse
        $s.ContainsKey('ClassifyVerdict') | Should -BeFalse -Because "'catalog' IS the per-source classification"
        $a = Get-SITierAttribution -FinalTier 0 -Sources $s
        $a.SI_TierSetBy | Should -Be 'entra-role'
        $a.SI_TierReason | Should -Match 'Global Administrator'
    }

    It 'nothing matched -> default; nothing is invented' {
        (Get-SITierAttribution -FinalTier 3 -Sources (Get-SIProfileTierSources -Verdict @{ SI_Tier = $null } -ClassifyStatus 'no-ai')).SI_TierSetBy | Should -Be 'default'
    }

    It 'an operator override that moved the tier is the source' {
        $a = Get-SITierAttribution -FinalTier 1 -Sources @{ SIRules = [pscustomobject]@{ Tier = 3; TopMatch = 'r'; MatchCount = 1 } } -OverrideBy 'ops 2026-10-01: payroll' -ComputedTier 3
        $a.SI_TierSetBy | Should -Be 'override'
        $a.SI_TierReason | Should -Match 'operator override \(ops 2026-10-01: payroll\)'
        $a.SI_TierReason | Should -Match 'computed Tier 3'
        $a.SI_TierClaims | Should -Match '"Source":"rule"' -Because 'the claims are still recorded beside the override'
    }

    It 'Set-SIProfileTierAttribution always writes the three columns' {
        $row = [ordered]@{}
        Set-SIProfileTierAttribution -Row $row -FinalTier 2 -Sources @{ OwnerAssetTier = [pscustomobject]@{ Tier = 2; TopMatch = 'endpoint web7'; MatchCount = 1 } }
        $row['SI_TierSetBy'] | Should -Be 'owner'
        $row['SI_TierClaims'] | Should -Match '^\['
    }
}

Describe 'every profiler records its tier source (built rows)' {

    It 'identity: an Entra role sets the tier -> entra-role' {
        $rec = @'
[pscustomobject]@{
    AssetId = 'entra-user:11111111-2222-3333-4444-555555555555'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; SI_Classify_Status = 'catalog'
    Metadata = @{ ENTRA_UserId = '11111111-2222-3333-4444-555555555555'; ENTRA_DisplayName = 'Ada Admin'; ENTRA_UPN = 'ada@contoso.test' }
    Verdict = [pscustomobject]@{ SI_Tier = 0; TierSources = '{"EntraID_Roles_Permanent":{"Tier":0,"CatalogMatches":[{"Role":"Global Administrator","Tier":0}]}}' }
}
'@
        $a = script:BuildAttribution -Builder 'Build-IdentityProfileRow.ps1' -Function 'Build-SIIdentityProfileRow' -RecordScript $rec -Engine 'identity'
        $a.Has | Should -BeTrue
        $a.SetBy | Should -Be 'entra-role'
        $a.Reason | Should -Match 'Global Administrator'
        $a.Claims | Should -Match '"SourceKey":"EntraRolesPermanent"'
    }

    It 'azure: a profile rule sets the tier -> rule' {
        $rec = @'
[pscustomobject]@{
    AssetId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'; PrimaryEntityId = '/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1'
    SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; SI_Classify_Status = 'no-ai'
    Metadata = @{ Name = 'vm1'; AZ_ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1' }
    Verdict = [pscustomobject]@{ SI_Tier = 0; SI_RuleTier = 0; SI_RuleMatches = @([pscustomobject]@{ RuleId = 'same-machine'; DetectionId = 'device'; Tier = 0 }) }
}
'@
        $a = script:BuildAttribution -Builder 'Build-AzureProfileRow.ps1' -Function 'Build-SIAzureProfileRow' -RecordScript $rec -Engine 'azure'
        $a.Has | Should -BeTrue
        $a.SetBy | Should -Be 'rule'
        $a.Reason | Should -Match 'same-machine/device'
    }

    It 'publicip: the owning asset sets the tier -> owner, named in the evidence' {
        $rec = @'
[pscustomobject]@{
    AssetId = 'ip:203.0.113.9'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'
    Metadata = @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint'; IP_AssetName = 'dc1' }
    Verdict = [pscustomobject]@{ SI_Tier = 3 }
}
'@
        $a = script:BuildAttribution -Builder 'Build-PublicIpProfileRow.ps1' -Function 'Build-SIPublicIpProfileRow' -RecordScript $rec -Engine 'publicip'
        $a.Tier | Should -Be '0'
        $a.SetBy | Should -Be 'owner'
        $a.Reason | Should -Match 'endpoint dc1'
    }

    It 'publicip without an owner: nothing matched -> default' {
        $rec = @'
[pscustomobject]@{ AssetId = 'ip:203.0.113.10'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; Metadata = @{ IP_Address = '203.0.113.10' }; Verdict = $null }
'@
        (script:BuildAttribution -Builder 'Build-PublicIpProfileRow.ps1' -Function 'Build-SIPublicIpProfileRow' -RecordScript $rec -Engine 'publicip').SetBy | Should -Be 'default'
    }
}

Describe 'the three columns are declared ADDITIVELY in every profile schema' {

    It '<s>: SI_TierSetBy / SI_TierReason / SI_TierClaims are declared, once each, as strings' -ForEach @(
        @{ s = 'endpoint.schema.locked.json' }, @{ s = 'identity.schema.locked.json' }, @{ s = 'azure.schema.locked.json' }, @{ s = 'public-ip.schema.locked.json' }
    ) {
        $j = Get-Content -Raw -LiteralPath (Join-Path (Join-Path $script:SIRootDir 'asset-profiling-schema') $s) | ConvertFrom-Json
        foreach ($n in 'SI_TierSetBy', 'SI_TierReason', 'SI_TierClaims') {
            $f = @($j.fields | Where-Object { $_.name -eq $n })
            $f.Count | Should -Be 1
            $f[0].type | Should -Be 'string'
        }
    }

    It '<s>: adding them removed or retyped nothing (every field of the committed schema is still there, same type)' -ForEach @(
        @{ s = 'identity.schema.locked.json' }, @{ s = 'azure.schema.locked.json' }, @{ s = 'public-ip.schema.locked.json' }
    ) {
        $rel = 'SOLUTIONS/SecurityInsight/asset-profiling-schema/' + $s
        $base = $null
        try { $base = (& git -C $script:SIRootDir show ("origin/si-v3:" + $rel) 2>$null) -join "`n" } catch { $base = $null }
        if (-not $base) { Set-ItResult -Skipped -Because 'origin/si-v3 is not available in this clone'; return }
        $old = ConvertFrom-Json -InputObject $base
        $new = Get-Content -Raw -LiteralPath (Join-Path (Join-Path $script:SIRootDir 'asset-profiling-schema') $s) | ConvertFrom-Json
        foreach ($f in @($old.fields)) {
            $m = @($new.fields | Where-Object { $_.name -eq $f.name })
            $m.Count | Should -BeGreaterOrEqual 1 -Because "$($f.name) must survive"
            $m[0].type | Should -Be $f.type
        }
    }
}
