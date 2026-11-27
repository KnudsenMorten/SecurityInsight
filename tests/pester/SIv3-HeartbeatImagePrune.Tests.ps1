#Requires -Version 5.1
<#
    #1424 -- the heartbeat's Update.imagePrune (engine/_shared/SI-HeartbeatFields.ps1) from the record the updater's clean-up
    step writes (container/updater/_shared/SI-UpdaterImagePrune.ps1 ConvertTo-SIUpdaterImagePruneValue, cfg.InstallState
    'ImagePrune'). Framework IMAGE-PRUNE CONTRACT point 5; Invardia's core block (packages/core/src/heartbeatstate.ts,
    SI_HEARTBEAT_CONTRACT.Update.imagePrune, soft: a bad value drops this key alone):

      imagePrune { done: bool, deleted: int, atUtc: iso, version,
                   repos: arr max 20 unique 'repo' of { repo: str<=80 /^[a-z0-9][a-z0-9._/-]{0,79}$/ req, before, kept, children,
                                                         deleted, left, failed: int } }

    What must hold:
      - the key set is EXACTLY Invardia's (pinned against a copy of its contract), each value only when known (never null);
      - the updater's record is WHOLE (cfg.InstallState.Value is NVARCHAR(MAX) since #1426); only above a last-resort size it
        gives up detail in a fixed order, never a made-up count, and says so; an older record (left only) still sends each repository's left;
      - not read back (-1), an unknown name, a bad record = that value / entry left out, never the rest of Update;
      - Update's key order: the five, signal, runningImages, imagePrune, revisions (the last key);
      - the switch UpdateSendImagePrune; the settings read names the row.
    Offline: no database, no ARM -- every reader is a seam.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImagePrune.ps1')
    $script:OwnRepos = @($script:SIImagePruneOwnRepos)
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-26T10:00:00', [DateTimeKind]::Utc)
    $script:At = [datetime]::SpecifyKind([datetime]'2026-11-26T03:12:00', [DateTimeKind]::Utc)
    function script:Repo([string]$Name, [int]$Before, [int]$Kept, [int]$Children, [int]$Deleted, [int]$Left, [int]$Failed = 0) {
        [pscustomobject]@{ Repo = $Name; Base = $false; Before = $Before; Kept = $Kept; Children = $Children; Deleted = $Deleted; Failed = $Failed; Left = $Left; Pending = 0; Line = '' }
    }
    $script:Result = [pscustomobject]@{ Done = $true; Reason = 'old images: 7 deleted in 2 repositories'; Lines = @()
        Repos = @((Repo 'si-orchestrator' 4 1 0 3 1), (Repo 'si-management' 6 2 1 4 2 1)) }
    $script:OnlyUpdate = @{}; foreach ($n in (Get-SIHeartbeatFieldsContract).Names) { $script:OnlyUpdate[$n] = $false }; $script:OnlyUpdate['Update'] = $true
    function script:StateRow([string]$Value) { [pscustomobject]@{ K = 'state'; Name = 'ImagePrune'; S = $null; T1 = $script:At; T2 = $null; T3 = $null; T4 = $null; N1 = $null; N2 = $null; Txt = $Value; Txt2 = $null } }
    function script:UpdRow { [pscustomobject]@{ K = 'state'; Name = 'UpdateState'; S = $null; T1 = $script:At; T2 = $null; T3 = $null; T4 = $null; N1 = $null; N2 = $null
        Txt = '{"source":"invardia","lastCheckUtc":"2026-11-26T03:00:00Z","code":{"version":"3.1.53","sequence":9,"ring":1,"action":"update","applied":9,"hold":""},"error":""}'; Txt2 = $null } }
}

Describe '#1424 Update.imagePrune -- the last update''s clean-up of old images on the heartbeat' {
AfterEach { $global:SI_HeartbeatFieldProblemsSaid = $null; $global:SI_HeartbeatJobWarned = $null }

Describe 'the updater''s record (cfg.InstallState ImagePrune -- NVARCHAR(MAX) since #1426, whole at every real install)' {
    It 'carries at, done, deleted, the version, left per repository and each repository''s six counts' {
        $j = ConvertTo-SIUpdaterImagePruneValue -Result $script:Result -NowUtc $script:At -Version '3.1.53'
        $j | Should -BeExactly '{"at":"2026-11-26T03:12:00Z","done":true,"deleted":7,"v":"3.1.53","left":{"si-orchestrator":1,"si-management":2},"r":{"si-orchestrator":[4,1,0,3,1,0],"si-management":[6,2,1,4,2,1]},"why":""}'
    }
    It 'review nit 4: EVERY repository SI creates, with counts of 10 and more -- r and left survive whole (over 400 characters), nothing is said' {
        $script:OwnRepos.Count | Should -Be 12 -Because 'the real list of the clean-up ($script:SIImagePruneOwnRepos)'
        $all = [pscustomobject]@{ Done = $true; Reason = ''; Lines = @(); Repos = @($script:OwnRepos | ForEach-Object { Repo $_ 25 10 12 15 10 10 }) }
        $lines = New-Object System.Collections.Generic.List[string]
        $j = ConvertTo-SIUpdaterImagePruneValue -Result $all -NowUtc $script:At -Version '3.1.53' -Log { param($l) $lines.Add($l) }.GetNewClosure()
        $j.Length | Should -BeGreaterThan 400 -Because 'the old 400-character column would have shed r here'
        $o = $j | ConvertFrom-Json
        @($o.r.PSObject.Properties).Count | Should -Be 12
        @($o.left.PSObject.Properties).Count | Should -Be 12
        @($o.r.'si-management-mcp-base') | Should -Be @(25, 10, 12, 15, 10, 10)
        $lines.Count | Should -Be 0 -Because 'nothing was given up'
        # and the heartbeat sends all twelve with their six counts
        $v = Get-SIHeartbeatImagePrune -Rows @((StateRow $j))
        @($v.repos).Count | Should -Be 12
        foreach ($r in $v.repos) { @($r.PSObject.Properties.Name) | Should -Be @('repo', 'before', 'kept', 'children', 'deleted', 'left', 'failed') }
    }
    It 'no version / not a version: v left out; a clean-up that did not run says why' {
        $j = ConvertTo-SIUpdaterImagePruneValue -Result ([pscustomobject]@{ Done = $false; Reason = 'old images: not cleaned up -- the update did not end healthy, so every image is kept'; Repos = @(); Lines = @() }) -NowUtc $script:At -Version 'not a version!'
        $o = $j | ConvertFrom-Json
        $o.PSObject.Properties['v'] | Should -BeNullOrEmpty
        $o.PSObject.Properties['r'] | Should -BeNullOrEmpty
        $o.done | Should -BeFalse
        $o.why | Should -Match '^not cleaned up'
    }
    It 'LAST RESORT above the size limit: left goes (r has it), then r (left only) -- never a made-up count, and what was given up is SAID' {
        $script:SIImagePruneValueMax | Should -Be 32000 -Because 'the default last-resort size'
        $many = [pscustomobject]@{ Done = $true; Reason = 'x'; Lines = @(); Repos = @(1..8 | ForEach-Object { Repo ('si-mgmt-base-{0:00}' -f $_) 3 1 0 2 1 }) }
        $lines = New-Object System.Collections.Generic.List[string]
        $j = ConvertTo-SIUpdaterImagePruneValue -Result $many -NowUtc $script:At -Version '3.1.53' -MaxChars 400 -Log { param($l) $lines.Add($l) }.GetNewClosure()
        $j.Length | Should -BeLessOrEqual 400
        $o = $j | ConvertFrom-Json
        $o.PSObject.Properties['left'] | Should -BeNullOrEmpty -Because 'r carries the same count'
        @($o.r.PSObject.Properties).Count | Should -Be 8
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match '^NOTE: old images: the clean-up record is longer than 400 characters -- .*images left .*were left out'
        $huge = [pscustomobject]@{ Done = $true; Reason = 'x'; Lines = @(); Repos = @(1..12 | ForEach-Object { Repo ('si-mgmt-base-{0:00}' -f $_) 3 1 0 2 1 }) }
        $lines2 = New-Object System.Collections.Generic.List[string]
        $j2 = ConvertTo-SIUpdaterImagePruneValue -Result $huge -NowUtc $script:At -Version '3.1.53' -MaxChars 400 -Log { param($l) $lines2.Add($l) }.GetNewClosure()
        $j2.Length | Should -BeLessOrEqual 400
        $o2 = $j2 | ConvertFrom-Json
        $o2.PSObject.Properties['r'] | Should -BeNullOrEmpty
        @($o2.left.PSObject.Properties).Count | Should -Be 12 -Because 'every repository still sends its count left'
        $lines2[0] | Should -Match 'the per-repository counts .* of 12 repositories were left out'
    }
    It 'both writes of the record pass the release (-Version) and say what was given up (-Log to the run log)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImagePrune.ps1'))
        ([regex]::Matches($src, [regex]::Escape("-Name 'ImagePrune' -Value (ConvertTo-SIUpdaterImagePruneValue -Result `$res -Version `$Version -Log { param(`$l) Write-UpdLog `$l })"))).Count | Should -Be 2
    }
    It 'the column holds it: cfg.InstallState.Value is NVARCHAR(MAX), widened once on an older install (#1426)' {
        $ddl = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        $ddl | Should -Match 'Value\s+NVARCHAR\(MAX\)\s+NOT NULL'
        $ddl | Should -Match ([regex]::Escape("ALTER TABLE cfg.InstallState ALTER COLUMN Value NVARCHAR(MAX) NOT NULL"))
        ([regex]::Matches($ddl, 'ALTER TABLE cfg\.InstallState ALTER COLUMN Value')).Count | Should -Be 1 -Because 'one widening, never a second ALTER'
    }
}
Describe 'the heartbeat value' {
    It 'the record -> exactly Invardia''s shape, every value its type, nothing null' {
        $rec = ConvertTo-SIUpdaterImagePruneValue -Result $script:Result -NowUtc $script:At -Version '3.1.53'
        $v = Get-SIHeartbeatImagePrune -Rows @((StateRow $rec))
        @($v.PSObject.Properties.Name) | Should -Be @('done', 'deleted', 'atUtc', 'version', 'repos')
        ($v | ConvertTo-Json -Depth 6 -Compress) | Should -BeExactly '{"done":true,"deleted":7,"atUtc":"2026-11-26T03:12:00Z","version":"3.1.53","repos":[{"repo":"si-orchestrator","before":4,"kept":1,"children":0,"deleted":3,"left":1,"failed":0},{"repo":"si-management","before":6,"kept":2,"children":1,"deleted":4,"left":2,"failed":1}]}'
        Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateImagePrune -Update (Get-SIHeartbeatUpdate -Rows @((UpdRow)) -Installed '3.1.53' -NowUtc $script:Now) -ImagePrune $v) | Should -BeNullOrEmpty
    }
    It 'one repository stays an array on the wire' {
        $one = [pscustomobject]@{ Done = $true; Reason = ''; Lines = @(); Repos = @((Repo 'si-updater' 3 1 0 2 1)) }
        $v = Get-SIHeartbeatImagePrune -Rows @((StateRow (ConvertTo-SIUpdaterImagePruneValue -Result $one -NowUtc $script:At -Version '3.1.53')))
        ($v | ConvertTo-Json -Depth 6 -Compress) | Should -Match '"repos":\[\{"repo":"si-updater",'
    }
    It 'an OLDER record (at / done / deleted / left only): each repository sends its left alone; no version' {
        $v = Get-SIHeartbeatImagePrune -Rows @((StateRow '{"at":"2026-11-20T03:00:00Z","done":true,"deleted":4,"left":{"si-orchestrator":1,"si-updater":-1},"why":""}'))
        ($v | ConvertTo-Json -Depth 6 -Compress) | Should -BeExactly '{"done":true,"deleted":4,"atUtc":"2026-11-20T03:00:00Z","repos":[{"repo":"si-orchestrator","left":1},{"repo":"si-updater"}]}' -Because '-1 = not read back: left out, never sent as a count'
    }
    It 'a clean-up that did not run: done false, deleted 0, no repos' {
        $rec = ConvertTo-SIUpdaterImagePruneValue -Result ([pscustomobject]@{ Done = $false; Reason = 'old images: not cleaned up -- x'; Repos = @(); Lines = @() }) -NowUtc $script:At -Version '3.1.53'
        ((Get-SIHeartbeatImagePrune -Rows @((StateRow $rec))) | ConvertTo-Json -Depth 6 -Compress) | Should -BeExactly '{"done":false,"deleted":0,"atUtc":"2026-11-26T03:12:00Z","version":"3.1.53"}'
    }
    It 'no record, a record that does not parse, nothing known: $null (left out)' {
        Get-SIHeartbeatImagePrune -Rows @() | Should -BeNullOrEmpty
        Get-SIHeartbeatImagePrune -Rows @((StateRow 'not json')) | Should -BeNullOrEmpty
        Get-SIHeartbeatImagePrune -Rows @((StateRow '{"why":"x"}')) | Should -BeNullOrEmpty
        Get-SIHeartbeatImagePrune -Rows @((StateRow '[1,2]')) | Should -BeNullOrEmpty
    }
    It 'a name that is not a repository is left out; a name taken once; over 20 the failed / left ones first' {
        $v = Get-SIHeartbeatImagePrune -Rows @((StateRow '{"at":"2026-11-26T03:00:00Z","done":true,"deleted":1,"r":{"Bad Name!":[1,1,0,0,1,0],"si-base":[2,1,0,1,1,0]}}'))
        @($v.repos | ForEach-Object { $_.repo }) | Should -Be @('si-base')
        $r = [ordered]@{}; foreach ($i in 1..25) { $r[('repo-{0:00}' -f $i)] = @(1, 1, 0, 0, 0, $(if ($i -eq 25) { 1 } else { 0 })) }
        $lo = New-Object System.Collections.Generic.List[string]
        $v2 = Get-SIHeartbeatImagePrune -Rows @((StateRow (([ordered]@{ at = '2026-11-26T03:00:00Z'; done = $true; deleted = 0; r = $r }) | ConvertTo-Json -Compress -Depth 5))) -LeftOut $lo
        @($lo) | Should -Be @('repo-20', 'repo-21', 'repo-22', 'repo-23', 'repo-24') -Because 'review nit 3: the repositories with no room are named (the problems line), never dropped silently'
        @($v2.repos).Count | Should -Be 20
        @($v2.repos | ForEach-Object { $_.repo }) | Should -Contain 'repo-25' -Because 'the repository with a failed delete is kept'
        Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateImagePrune -Update (Get-SIHeartbeatUpdate -Rows @((UpdRow)) -Installed '3.1.53' -NowUtc $script:Now) -ImagePrune $v2) | Should -BeNullOrEmpty
    }
    It 'the validator refuses what Invardia refuses -- and a null (not known = left out)' {
        $u = Get-SIHeartbeatUpdate -Rows @((UpdRow)) -Installed '3.1.53' -NowUtc $script:Now
        $ok = { [pscustomobject][ordered]@{ done = $true; deleted = 3; atUtc = '2026-11-26T03:12:00Z'; version = '3.1.53'; repos = [object[]]@([pscustomobject][ordered]@{ repo = 'si-orchestrator'; left = 1 }) } }
        $t = { param([scriptblock]$Change) $x = & $ok; & $Change $x; Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateImagePrune -Update $u -ImagePrune $x) }
        & $t { param($x) } | Should -BeNullOrEmpty
        & $t { param($x) $x.done = 'yes' } | Should -Match 'done'
        & $t { param($x) $x.deleted = -1 } | Should -Match 'deleted'
        & $t { param($x) $x.atUtc = '26-11-2026' } | Should -Match 'atUtc'
        & $t { param($x) $x.version = 'v 1' } | Should -Match 'version'
        & $t { param($x) $x.deleted = $null } | Should -Match 'deleted is null'
        & $t { param($x) $x | Add-Member -NotePropertyName why -NotePropertyValue 'x' } | Should -Match 'agreed'
        & $t { param($x) $x.repos[0].repo = 'Si_Orchestrator' } | Should -Match 'repository name'
        & $t { param($x) $x.repos = [object[]]@($x.repos[0], $x.repos[0]) } | Should -Match 'more than once'
        & $t { param($x) $x.repos = [object[]]@(1..21 | ForEach-Object { [pscustomobject]@{ repo = "r$_" } }) } | Should -Match 'at most 20'
        & $t { param($x) $x.repos[0] | Add-Member -NotePropertyName pending -NotePropertyValue 1 } | Should -Match 'agreed'
        & $t { param($x) $x.repos[0].PSObject.Properties.Remove('repo') } | Should -Match 'repo is missing'
    }
    It 'the key set is EXACTLY Invardia''s contract (a copy of SI_HEARTBEAT_CONTRACT.Update.imagePrune, heartbeatstate.ts)' {
        # Invardia packages/core/src/heartbeatstate.ts (read 2026-11-26):
        #   imagePrune: soft({ t: 'obj', fields: { done: bool, deleted: int(), atUtc: iso(), version,
        #     repos: { t: 'arr', max: IMAGE_PRUNE_REPOS_MAX (20), unique: 'repo', item: { t: 'obj', fields: {
        #       repo: { t: 'str', max: 80, re: /^[a-z0-9][a-z0-9._/-]{0,79}$/, req: true },
        #       before: int(), kept: int(), children: int(), deleted: int(), left: int(), failed: int() } } } } })
        $c = Get-SIHeartbeatFieldsContract
        $c.UpdateImagePruneField | Should -BeExactly 'imagePrune'
        $c.UpdateImagePruneFields | Should -Be @('done', 'deleted', 'atUtc', 'version', 'repos')
        $c.UpdateImagePruneRepoFields | Should -Be @('repo', 'before', 'kept', 'children', 'deleted', 'left', 'failed')
        $c.MaxImagePruneRepos | Should -Be 20
        $c.UpdateSendImagePrune | Should -BeTrue
    }
}

Describe 'on the heartbeat: Update carries it before revisions; a problem never costs the rest of Update' {
    It 'the five, imagePrune, revisions (the last key) -- from the settings read already made' {
        $rec = ConvertTo-SIUpdaterImagePruneValue -Result $script:Result -NowUtc $script:At -Version '3.1.53'
        $rev = [pscustomobject][ordered]@{ single = $true; activeRevisions = 1; apps = 2; readUtc = '2026-11-26T09:59:00Z' }
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch $script:OnlyUpdate -CfgRows @((UpdRow), (StateRow $rec)) -Installed '3.1.53' -Revisions $rev -Log { param($l) }
        @($f['Update'].PSObject.Properties.Name) | Should -Be @('installed', 'available', 'lastUpdaterRunUtc', 'lastUpdaterResult', 'nextUpdateUtc', 'imagePrune', 'revisions')
        $f['Update'].imagePrune.version | Should -BeExactly '3.1.53'
        @($f['Update'].imagePrune.repos).Count | Should -Be 2
        ($f['Update'] | ConvertTo-Json -Depth 8 -Compress) | Should -Match '"imagePrune":\{"done":true,"deleted":7,"atUtc":"2026-11-26T03:12:00Z","version":"3.1.53","repos":\[\{"repo":"si-orchestrator","before":4,"kept":1,"children":0,"deleted":3,"left":1,"failed":0\}'
    }
    It 'no record: Update as before (no key); a bad record: Update as before, said once' {
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch $script:OnlyUpdate -CfgRows @((UpdRow)) -Installed '3.1.53' -Log { param($l) }
        $f['Update'].PSObject.Properties['imagePrune'] | Should -BeNullOrEmpty
        $f['Update'].installed | Should -BeExactly '3.1.53'
        Mock Get-SIHeartbeatImagePrune { [pscustomobject]@{ done = 'maybe' } }
        $lines = New-Object System.Collections.Generic.List[string]
        $global:SI_HeartbeatFieldProblemsSaid = $null
        $g = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch $script:OnlyUpdate -CfgRows @((UpdRow), (StateRow '{}')) -Installed '3.1.53' -Log { param($l) $lines.Add($l) }.GetNewClosure()
        $g['Update'].PSObject.Properties['imagePrune'] | Should -BeNullOrEmpty
        $g['Update'].installed | Should -BeExactly '3.1.53'
        ($lines -join ' ') | Should -Match 'image clean-up result was left out'
    }
    It 'the settings read names the row; the switch is the one place' {
        (Get-SIHeartbeatFieldsCfgSql) | Should -Match "N'ImagePrune'"
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatFields.ps1'))
        $src | Should -Match ([regex]::Escape('$c.UpdateSendImagePrune -and $null -ne $CfgRows'))
        $src | Should -Match ([regex]::Escape('the image clean-up result has room for {0} repositories -- not in it: {1}'))
    }
}
}
