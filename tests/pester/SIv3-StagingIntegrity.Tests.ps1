#Requires -Version 5.1
<#
    PROFILING STAGING MUST NOT LOSE, DUPLICATE OR MIS-FILE RECORDS (#122).

    Three defects, all silent:
      * Profile and Reconcile re-wrote the Classify stage with `-ShardIndex <shard>` and the DEFAULT
        replica 0, while Classify writes `-ShardIndex 0 -ReplicaIndex <shard>`. In a sharded container
        run, replica k>=1 wrote its enriched overlay under replica 0, and Output (which reads THIS
        replica) got the raw Classify rows. Reconcile also read every replica.
      * single-process mode APPENDED every write to one list per stage, so the Profile and Reconcile
        re-writes duplicated every record (2 -> 4 -> 8 by Output).
      * Discover's `$assets = $assets | Where-Object/Select-Object` unwrapped a single survivor into a
        bare hashtable -- .Count became its KEY count and the slice produced nulls. Measured: with
        -AssetLimit 1 the pre-fix Discover threw on the null records.
    All three were latent on the VM path (shard 0, single-process off, no AssetLimit) -- real, not yet
    biting.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $ap = Join-Path $script:SIRoot 'engine\asset-profiling'
    # SCRIPT scope, never global: a global stub outlives this file in the gate's single process and
    # once silenced the Trend suite's output. The functions under test are dot-sourced into this same
    # scope, so they still resolve it.
    function script:Write-SIInfo { param($m) }
    . (Join-Path $ap 'storage\StorageContext.ps1')
    . (Join-Path $ap 'storage\StagingBlob.ps1')
    . (Join-Path $ap 'stages\Invoke-Discover.ps1')
    $script:StagesDir = Join-Path $ap 'stages'
}

Describe 'single-process staging behaves like blob staging' {
    BeforeEach {
        $global:SI_SingleProcess = $true
        $script:SIStageCache = @{}
        $script:Ctx = New-SIStorageContext -Mock
    }
    AfterEach { $global:SI_SingleProcess = $null }

    It 'a RE-WRITE of the same shard replaces it -- no duplication' {
        $recs = @(@{ AssetId = 'a' }, @{ AssetId = 'b' })
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ShardIndex 0 -ReplicaIndex 0 -Records $recs
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ShardIndex 0 -ReplicaIndex 0 -Records $recs
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ShardIndex 0 -ReplicaIndex 0 -Records $recs
        @(Read-SIStageShards -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify').Count | Should -Be 2
    }

    It 'different shards still accumulate' {
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Discover' -ShardIndex 0 -Records @(@{ AssetId = 'a' })
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Discover' -ShardIndex 1 -Records @(@{ AssetId = 'b' })
        @(Read-SIStageShards -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Discover').Count | Should -Be 2
    }

    It 'a replica-scoped read returns only that replica' {
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ShardIndex 0 -ReplicaIndex 0 -Records @(@{ AssetId = 'r0' })
        $null = Write-SIStageShard -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ShardIndex 0 -ReplicaIndex 1 -Records @(@{ AssetId = 'r1' })
        $got = @(Read-SIStageShards -Context $script:Ctx -ContainerName 'c' -RunId 'r' -Stage 'Classify' -ReplicaIndex 1)
        $got.Count      | Should -Be 1
        $got[0].AssetId | Should -Be 'r1'
    }
}

Describe 'Discover keeps a single surviving asset' {
    It '-AssetLimit 1 stages exactly one real asset (the pre-fix code threw on nulls)' {
        $global:SI_SingleProcess = $null
        $ctx = New-SIStorageContext -Mock
        $ctx.MockState.Blobs['sistaging'] = @{}
        $rc = [pscustomobject]@{ StorageContext = $ctx; StagingContainer = 'sistaging'; RunId = 'r1'; AssetLimit = 1; ShardIndex = 0; ShardCount = 1; Engine = 'endpoint' }
        $res = Invoke-SIDiscover -RunContext $rc
        $res.AssetCount | Should -Be 1
        $recs = @(Read-SIStageShards -Context $ctx -ContainerName 'sistaging' -RunId 'r1' -Stage 'Discover')
        $recs.Count      | Should -Be 1
        $recs[0].AssetId | Should -Be 'dev-srv-exch01'
    }

    It 'both filter sites in the real (non-mock) path are wrapped in @()' {
        $src = Get-Content -LiteralPath (Join-Path $script:StagesDir 'Invoke-Discover.ps1') -Raw
        ([regex]::Matches($src, '\$assets = @\(\$assets \| Select-Object -First \$RunContext\.AssetLimit\)')).Count | Should -Be 2
        $src | Should -Match '(?s)% \$shardCount\) -eq \$shardIndex\s*\}.{0,400}\$assets = @\(\$assets\)'
    }
}

Describe 'WIRING -- every stage uses ONE staging key: shard 0 of this replica' {
    It 'every Write-SIStageShard / Read-SIStageShards call in Collect..Output passes -ReplicaIndex' {
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($stage in 'Collect','Enrich','Classify','Profile','Reconcile','Output') {
            $file = Join-Path $script:StagesDir ("Invoke-{0}.ps1" -f $stage)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
            $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                                    @('Write-SIStageShard','Read-SIStageShards') -contains $n.GetCommandName() }, $true)
            foreach ($c in $calls) {
                $text = $c.Extent.Text
                if ($text -notmatch '-ReplicaIndex') { [void]$missing.Add(("{0}:{1} {2}" -f $stage, $c.Extent.StartLineNumber, $c.GetCommandName())) }
                if ($c.GetCommandName() -eq 'Write-SIStageShard' -and $text -notmatch '-ShardIndex 0\b') {
                    [void]$missing.Add(("{0}:{1} writes a non-zero ShardIndex" -f $stage, $c.Extent.StartLineNumber))
                }
            }
        }
        $missing.Count | Should -Be 0 -Because ($missing -join '; ')
    }
}
