#Requires -Version 5.1
<#
    SCALE: the identity profiler's Exposure Graph identity index (#475; customer H 2026-10-08: 73,404 EG identity rows ran the
    identity job out of memory at 2 GiB AND at 8 GiB).

      * MEASURED, not guessed: ~73,400 identity nodes of realistic size (a rawData of ~60 properties, ~2.5 KB) go through
        the real Get-SIExposureGraphIdentities with the hunting query faked; the managed memory the index holds after it
        returns is measured and printed (the run log shows the number), and must stay under the ceiling.
      * The index still finds every node by Entra object id, and an entry carries the rawData fields the profile reads.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    $script:N = 73400
    # one realistic rawData: the fields the profile reads + the kind of bulk EG carries (arrays, nested metadata)
    function script:New-FakeRawData([int]$i) {
        $noise = @{}
        foreach ($k in 1..30) { $noise["prop$k"] = "value-$k-" + ('x' * 20) }
        $o = [ordered]@{
            accountObjectId = ([guid]::NewGuid()).ToString(); accountUpn = "user$i@contoso.example"; accountDisplayName = "User $i"
            accountEnabled = $true; isMfaRegistered = ($i % 3 -eq 0); isSensitive = ($i % 97 -eq 0); jobTitle = 'Teacher'
            assignedRoles = @(); criticalityLevel = 3; onPremSyncEnabled = $true; hasLeakedCredentials = $false
            identityMetadata = @{ source = 'EntraID'; lastModified = '2026-10-01T00:00:00Z'; tags = @('a', 'b', 'c') }
            otherMailAddresses = @("u$i@alt.example"); alternativeNames = @("user$i", "u$i")
        }
        foreach ($k in $noise.Keys) { $o[$k] = $noise[$k] }
        $o
    }
    $script:Rows = New-Object System.Collections.Generic.List[object]
    $script:Oids = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $script:N; $i++) {
        $raw = New-FakeRawData $i
        $script:Oids.Add([string]$raw.accountObjectId)
        $script:Rows.Add([pscustomobject]@{
            NodeId = "nid-$i"; NodeLabel = 'user'; NodeName = "User $i"; Categories = '["identity"]'
            EntityIds = ('["{{\"type\":\"AadObjectId\",\"id\":\"objectid={0}\"}}"]' -f $raw.accountObjectId)
            NodeProperties = (ConvertTo-Json -InputObject @{ rawData = $raw } -Compress -Depth 6)
        })
    }
}

Describe 'the Exposure Graph identity index at customer H''s size' {
    It 'indexes ~73,400 identity nodes within a bounded memory, and still finds every node' {
        Mock Invoke-SIEgIdentityQuery {
            param($Query)
            if ($Query -match '\| count$') { return [pscustomobject]@{ Ok = $true; Rows = @([pscustomobject]@{ Count = $(if ($Query -match "'user'") { $script:N } else { 0 }) }); Error = '' } }
            if ($Query -match "NodeLabel == 'user'") {
                if ($Query -match '_bucket = hash\(NodeId, (\d+)\) \| where _bucket == (\d+)') {
                    $n = [int]$Matches[1]; $b = [int]$Matches[2]
                    $slice = for ($i = $b; $i -lt $script:Rows.Count; $i += $n) { $script:Rows[$i] }
                    return [pscustomobject]@{ Ok = $true; Rows = @($slice); Error = '' }
                }
                return [pscustomobject]@{ Ok = $true; Rows = @($script:Rows); Error = '' }
            }
            [pscustomobject]@{ Ok = $true; Rows = @(); Error = '' }
        }
        # #882 (C6): the buckets go out in parallel waves through -SendMany, whose default signs in to Graph -- the seam
        # sends each query of a wave through the faked query above (never a sign-in in an offline test)
        $script:SIEgIdentitySendMany = { param([string[]]$qs) , @(foreach ($q in $qs) { $r = Invoke-SIEgIdentityQuery -Query $q; [pscustomobject]@{ Ok = [bool]$r.Ok; Rows = $r.Rows; Status = 200; RetryAfter = $null; Error = [string]$r.Error } }) }
        $script:SIEgIdentitySleep = { param($s) }
        $script:_SICache = @{}
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
        $before = [GC]::GetTotalMemory($true)
        try { $map = Get-SIExposureGraphIdentities 6>$null } finally { $script:SIEgIdentitySendMany = $null; $script:SIEgIdentitySleep = $null }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
        $after = [GC]::GetTotalMemory($true)
        $mb = [Math]::Round(($after - $before) / 1MB, 1)
        Write-Host ("SCALE: the EG identity index for {0:N0} nodes holds {1:N1} MB of managed memory ({2:N0} keys)" -f $script:N, $mb, $map.Count)
        @($script:Oids | Select-Object -First 50 | Where-Object { -not $map.ContainsKey($_) }).Count | Should -Be 0
        $e = $map[$script:Oids[0]]
        $e.RawData.accountUpn | Should -Be 'user0@contoso.example'
        $mb | Should -BeLessThan 1500 -Because 'the index must fit a worker comfortably at this size'
    }
}

Describe 'only the rawData fields that are read are kept (SI-EgRawTrim.ps1)' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-EgRawTrim.ps1') }
    It 'keeps what the schema, the mapping, the rules'' signals and paths, and code read -- and nothing else' {
        $rules = @([pscustomobject]@{ Detections = @([pscustomobject]@{ Detect = [pscustomobject]@{ kind = 'egDetectedRoles'; egSignals = @('isCustomerFlag') } },
                                                    [pscustomobject]@{ Detect = @{ kind = 'egKustoQuery'; where = 'EgRawData.customerPath.x == 1' } }) })
        $k = Get-SIEgIdentityKeepKeys -Texts @('{"path":"eg.user.NodeProperties.rawData.accountUpn"}', '{"from":"node.NodeProperties.rawData.isMfaRegistered"}') -Rules $rules
        foreach ($f in 'accountUpn', 'isMfaRegistered', 'isCustomerFlag', 'customerPath', 'isDomainController', 'managedIdentityMetadata', 'accountObjectId') { $k.Contains($f) | Should -BeTrue -Because $f }
        $k.Contains('prop1') | Should -BeFalse
        $r = Select-SIEgRawFields -Raw ([pscustomobject]@{ accountUpn = 'a'; prop1 = 'noise'; managedIdentityMetadata = @{ accountType = 'x' } }) -Keep $k
        @($r.PSObject.Properties.Name) | Sort-Object | Should -Be @('accountUpn', 'managedIdentityMetadata')
        $r.managedIdentityMetadata.accountType | Should -Be 'x' -Because 'a kept top field stays whole'
    }
    It 'keeps EVERYTHING when it cannot tell what is read (no schema, no rule loader)' {
        Get-SIEgIdentityKeepKeys -SIRoot (Join-Path $TestDrive 'nowhere') | Should -BeNullOrEmpty
        $raw = [pscustomobject]@{ a = 1; b = 2 }
        Select-SIEgRawFields -Raw $raw -Keep $null | Should -Be $raw
    }
    It 'the real install''s keep-set holds the identity schema''s fields and the shipped rules'' signals' {
        $k = Get-SIEgIdentityKeepKeys -SIRoot $script:SIRoot
        $k | Should -Not -BeNullOrEmpty
        foreach ($f in 'accountUpn', 'isMfaRegistered', 'assignedRoles', 'isDomainController') { $k.Contains($f) | Should -BeTrue -Because $f }
    }
    It 'every field engine code reads with Get-SIEgValue is on the code list (a new read must be added there)' {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-EgRawTrim.ps1')
        $read = foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -Filter '*.ps1') {
            foreach ($m in [regex]::Matches([IO.File]::ReadAllText($f.FullName), "Get-SIEgValue \S+ '([A-Za-z0-9_]+)")) { $m.Groups[1].Value }
        }
        $missing = @($read | Sort-Object -Unique | Where-Object { $script:SIEgRawCodeFields -notcontains $_ })
        $missing | Should -BeNullOrEmpty
    }
}

Describe 'the Exposure Graph identity index is let go after discovery (customer H: 3.6 GB in use after Discover, then Collect ran out)' {
    It 'only discovery reads the index -- a later caller would fetch the whole graph again after the release' {
        $eng = Join-Path $script:SIRoot 'engine'
        $callers = @(Get-ChildItem -Path $eng -Filter *.ps1 -Recurse | Where-Object {
                $_.Name -ne 'IdentityRoleFetcher.ps1' -and ([IO.File]::ReadAllText($_.FullName) -match '(?m)^[^#\r\n]*\bGet-SIExposureGraphIdentities\b') } | ForEach-Object { $_.Name } | Sort-Object)
        $callers | Should -Be @('Get-DiscoveryFromEntraServicePrincipals.ps1', 'Get-DiscoveryFromEntraUsers.ps1')
    }
    It 'the engine releases it right after Discover and measures memory after a full collection' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $run | Should -Match ([regex]::Escape("if (`$s -eq 'Discover' -and (Get-Variable -Name _SICache -Scope Script"))
        $run | Should -Match ([regex]::Escape("`$script:_SICache.Remove('EgIdentitiesMap')"))
        $i = $run.IndexOf("`$script:_SICache.Remove('EgIdentitiesMap')")
        $j = $run.IndexOf('[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()')
        $k = $run.IndexOf("memory after {0}")
        ($i -gt 0 -and $j -gt $i -and $k -gt $j) | Should -BeTrue -Because 'released, then collected, then measured'
        # the cache key the engine releases is the one the fetcher fills
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')) | Should -Match ([regex]::Escape("`$script:_SICache['EgIdentitiesMap'] = `$egMap"))
    }
}
