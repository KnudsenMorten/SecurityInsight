#Requires -Version 5.1
<#
    SI #1207 (framework PRO-COMMUNITY-SAME, owner 2026-11-11: "it must be same pro community") -- ONE UPDATE CLIENT FOR BOTH
    EDITIONS. A Community install runs the SAME flow as Pro (container/updater/_shared/SI-UpdaterInvardia.ps1,
    Invoke-SIUpdaterFromInvardia): the same install key slot and claim, ring, run gate, roll, state, failure reports. ONLY the
    manifest address and its credential differ: without a licence, a Community install reads Invardia's ANONYMOUS Community
    route for its ring (container/updater/_shared/SI-UpdaterCommunity.ps1) and takes the public release zip. Rings 0-3 for
    both. An existing Community install's earlier state row (cfg.InstallState 'CommunityUpdateState') is carried over.

    EVERYTHING IS OFFLINE. The route, the download, the vault, the run gate, the roll and the database are seams or mocks;
    manifests are signed with a TEST key made here (never Invardia's), passed as the trust list; a real HTTP call fails the
    test. Needs no Pro file: the one client ships in the Community copy too.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
    if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-CommunityUpdate.ps1') }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $script:RealHttp = New-Object System.Collections.Generic.List[string]
    Mock Invoke-WebRequest { $script:RealHttp.Add([string]$Uri); throw 'no network in tests' }
    Mock Invoke-RestMethod { $script:RealHttp.Add([string]$Uri); throw 'no network in tests' }
    # the run's stages to Invardia are their own suite (SIv3-UpdateTrack); here they are recorded only
    $script:Tracked = New-Object System.Collections.Generic.List[string]
    Mock Invoke-SIUpdaterTrackHook { $script:Tracked.Add([string]$What) }

    function script:B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:Other = [System.Security.Cryptography.RSA]::Create(2048)
    $pub = $script:Rsa.ExportParameters($false)
    $script:Keys = @(@{ keyId = 'test-update-key'; n = (B64Url $pub.Modulus); e = (B64Url $pub.Exponent) })
    $script:Host1 = 'https://github.com/KnudsenMorten/SecurityInsight/releases/download/'
    # what a release must carry for the one client to keep updating the install (read from the client itself)
    $script:Need = @(@($script:SICommunityUpdateClientFiles) + @($script:SIUpdaterCommunityRequiredFiles) | Where-Object { $_ } | Sort-Object -Unique)
    if ($script:Need.Count -lt 5) { $script:Need = @('engine/_shared/SI-CommunityUpdate.ps1', 'engine/_shared/InvardiaUpdate.verify.ps1', 'engine/_shared/SI-InvardiaUpdate.ps1', 'setup/Invoke-SIContainerUpdate.ps1', 'container/updater/Start-SIUpdater.ps1', 'container/updater/_shared/SI-UpdaterInvardia.ps1', 'container/updater/_shared/SI-UpdaterCommunity.ps1') }

    function script:Hash([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
    # A Community release zip: VERSION (-ArchiveVersion when it should lie), the files an update needs (-Omit one), BUILD.json.
    function script:New-Release([string]$Version, [string]$ArchiveVersion = '', [string]$Omit = '') {
        $dir = Join-Path $TestDrive ("rel-$Version-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        [IO.File]::WriteAllText((Join-Path $dir 'VERSION'), $(if ($ArchiveVersion) { $ArchiveVersion } else { $Version }))
        [IO.File]::WriteAllText((Join-Path $dir 'BUILD.json'), '{"display":"' + $Version + '","commit":"A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"}')
        foreach ($f in $script:Need) {
            if ($f -eq $Omit) { continue }
            $p = Join-Path $dir $f; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
            [IO.File]::WriteAllText($p, "# $f $Version")
        }
        $zip = "$dir.zip"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($dir, $zip)
        $zip
    }
    function script:Url([string]$v) { "$($script:Host1)v$v/SecurityInsight-v$v.zip" }
    function script:New-Entry([string]$Zip, [string]$Version, [int]$Ring, [long]$Sequence, [hashtable]$Extra = @{}, $Signer = $script:Rsa, [string]$DownloadUrl) {
        $m = [ordered]@{ product = 'securityinsight'; kind = 'community'; ring = $Ring; sequence = $Sequence; version = $Version
                         sha256 = (Hash $Zip); size = (Get-Item -LiteralPath $Zip).Length; minFromVersion = $null; manualStep = $null }
        foreach ($k in $Extra.Keys) { $m[$k] = $Extra[$k] }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $Signer.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if (-not $DownloadUrl) { $DownloadUrl = Url $Version }
        [ordered]@{ manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key'; downloadUrl = $DownloadUrl }
    }
    function script:New-Channel([hashtable]$Rings) {
        $r = [ordered]@{}; foreach ($k in ($Rings.Keys | Sort-Object)) { $r["$k"] = $Rings[$k] }
        ([ordered]@{ schema = 1; product = 'securityinsight'; rings = $r } | ConvertTo-Json -Depth 6)
    }
    # The world: Invardia's Community route, URL -> zip, the install's Key Vault, the earlier Community state row, what the
    # gate answers, and a record of every step.
    function script:New-World([string]$Channel, [hashtable]$Files = @{}, [string]$OldRow = '', $Gate = $null, [string]$Edition = 'community') {
        $w = @{ Channel = $Channel; Files = $Files; Vault = @{}; OldRow = $OldRow; Gate = $Gate; Edition = $Edition
                ChannelReads = (New-Object System.Collections.Generic.List[string]); ProPulls = (New-Object System.Collections.Generic.List[string])
                Downloads = (New-Object System.Collections.Generic.List[string]); PostRolls = (New-Object System.Collections.Generic.List[string])
                Sizings = (New-Object System.Collections.Generic.List[string]); Waits = (New-Object System.Collections.Generic.List[string]) }
        if (-not $w.Gate) { $w.Gate = [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no pipeline run is going'; RunId = ''; LockTaken = $false; Holder = '' } }
        $w.Seams = @{
            # Invardia's anonymous Community route, faked: GET .../community/<ring> -> 200 + the ring's signed entry, 204 when
            # nothing is released to it; $w.Status forces an answer (404, 500); a Channel that is no JSON is the body as is
            GetManifest = { param($u) $w.ChannelReads.Add($u)
                            if ($w.Status) { return [pscustomobject]@{ Status = [int]$w.Status; Body = '' } }
                            $c = $null; try { $c = $w.Channel | ConvertFrom-Json -ErrorAction Stop } catch { $c = $null }
                            if (-not $c -or -not $c.PSObject.Properties['rings']) { return [pscustomobject]@{ Status = 200; Body = [string]$w.Channel } }
                            $ringNo = ($u -split '/')[-1]
                            $e = $c.rings.PSObject.Properties[$ringNo]
                            if (-not $e) { return [pscustomobject]@{ Status = 204; Body = '' } }
                            [pscustomobject]@{ Status = 200; Body = ($e.Value | ConvertTo-Json -Depth 6) } }.GetNewClosure()
            # the install route (a licensed install) -- never asked by a Community install without a licence
            Http        = { param($u, $b, $k, $hn, $id) $w.ProPulls.Add($u); [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } }.GetNewClosure()
            Download    = { param($u, $f) $w.Downloads.Add($u); if (-not $w.Files.ContainsKey($u)) { throw "404 $u" }; Copy-Item -LiteralPath $w.Files[$u] -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }.GetNewClosure()
            ReadSecret  = { param($n) if ($w.Vault.ContainsKey($n)) { $w.Vault[$n] } else { $null } }.GetNewClosure()
            WriteSecret = { param($n, $v) $w.Vault[$n] = $v }.GetNewClosure()
            TenantId    = { '11111111-2222-3333-4444-555555555555' }
            # the install key claim (an install with a licence and no key): Invardia is not reached in a test
            ClaimHttp   = { param($u, $b) [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = 'offline in tests' } }
            ReadEdition = { $w.Edition }.GetNewClosure()
            ReadCommunityState = { $w.OldRow }.GetNewClosure()
            Now         = { [datetime]'2026-10-27T18:30:00Z' }
            CommunityTrustedKeys = { $script:Keys }
            PreRoll     = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = $null } }
            PostRoll    = { param($r, $v, $c) $w.PostRolls.Add("$v|$c"); [pscustomobject]@{ Code = 0; Text = "this environment now runs SecurityInsight $v" } }.GetNewClosure()
            SizingPass  = { param($why) $w.Sizings.Add($why) }.GetNewClosure()
            SelfRetry   = { $null }
            RunGate     = { param($h) $w.Gate }.GetNewClosure()
            ReadWaits   = { $null }
            WriteWaits  = { param($v) $w.Waits.Add("$v") }.GetNewClosure()
        }
        $w
    }
    function script:Invoke-Run($World, [string]$Deployed = '3.0.0', [hashtable]$Env = @{}, [string[]]$Blocked = @()) {
        $log = @(Invoke-SIUpdaterFromInvardia -Env $Env -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Blocked $Blocked -Store $null -Deployed $Deployed `
                    -SIRoot $script:SIRoot -Seams $World.Seams -Work (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) 6>&1 | ForEach-Object { $_ })
        $rc = @($log | Where-Object { $_ -is [int] }) | Select-Object -Last 1
        [pscustomobject]@{ Code = $rc; Log = (@($log | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n")
                           State = (ConvertFrom-SIInvardiaUpdateState -Json ([string]$World.Vault['SI-Update-State'])) }
    }
    $script:Z301 = New-Release '3.0.1'
}

AfterAll {
    $script:RealHttp.Count | Should -Be 0 -Because 'no test may reach the network'
}

Describe 'ONE update client: a Community install runs the Pro flow, only the manifest address differs' {
    BeforeEach {
        $script:Rolls = New-Object System.Collections.Generic.List[object]
        $script:RollCode = 0
        # the extracted release's VERSION is read AT the roll
        Mock Invoke-SIUpdaterRoll { $script:Rolls.Add([pscustomobject]@{ Root = $SIRoot; RootVersion = [IO.File]::ReadAllText((Join-Path $SIRoot 'VERSION')); Version = $Version; Commit = $Commit; Store = $Store }); [pscustomobject]@{ Code = $script:RollCode; Held = $false; Reason = '' } }
    }
    It 'there is no edition fork any more: no Get-SIUpdaterEditionPath, no Invoke-SIUpdaterFromCommunity; Start-SIUpdater loads only the one client' {
        Get-Command -Name Get-SIUpdaterEditionPath -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command -Name Invoke-SIUpdaterFromCommunity -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $start = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $start | Should -Not -Match 'SI_UpdaterEdition' -Because 'nothing in the updater switches on the edition'
        $start | Should -Not -Match "_shared/SI-UpdaterCommunity\.ps1'\)" -Because 'Start-SIUpdater never loads a second client'
        $start | Should -Match "_shared/SI-UpdaterInvardia\.ps1"
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')) | Should -Match "'SI-UpdaterCommunity\.ps1'" -Because 'the Community route is a part of the one client'
    }
    It 'the manifest address follows the licence, then the recorded edition -- never the files the image carries' {
        (Resolve-SIUpdaterUpdateRoute -HasLicence $true -Edition 'community').Route | Should -Be 'invardia' -Because 'a licence decides'
        (Resolve-SIUpdaterUpdateRoute -HasLicence $false -Edition 'community').Route | Should -Be 'community'
        (Resolve-SIUpdaterUpdateRoute -HasLicence $false -Edition '' -Source 'community').Route | Should -Be 'community' -Because 'an install made before the tag: the job''s recorded source'
        (Resolve-SIUpdaterUpdateRoute -HasLicence $false -Edition 'pro' -Source 'community').Route | Should -Be 'invardia' -Because 'a Pro install waiting for its licence never takes the Community package'
        (Resolve-SIUpdaterUpdateRoute -HasLicence $false -Edition '' -Source 'invardia').Route | Should -Be 'invardia'
    }
    It 'ring 3 has a newer release: the anonymous route read, verified, downloaded, size + SHA-256 checked, extracted, ROLLED; post-roll; the sequence recorded in the one state' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0
        $w.ChannelReads | Should -Be @('https://invardia.com/api/updates/securityinsight/community/3') -Because 'Invardia''s anonymous Community route for this ring'
        $w.ProPulls.Count | Should -Be 0 -Because 'the install route is never asked without a licence'
        $w.Downloads | Should -Be @((Url '3.0.1'))
        $script:Rolls.Count | Should -Be 1
        $script:Rolls[0].Version | Should -Be '3.0.1'
        $script:Rolls[0].RootVersion | Should -Be '3.0.1' -Because 'the roll runs the EXTRACTED release'
        $script:Rolls[0].Commit | Should -Be 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'
        $w.PostRolls | Should -Be @('3.0.1|a1b2c3d4e5f60718293a4b5c6d7e8f9012345678')
        $r.State.code.appliedSequence | Should -Be 7; $r.State.code.appliedVersion | Should -Be '3.0.1'; $r.State.code.appliedRing | Should -Be 3
        $r.State.source | Should -Be 'community'; $r.State.channel | Should -Be 'community'
        $r.Log | Should -Match 'install key: off' -Because 'the same key slot and claim run for every install (no licence = no key, said)'
        $w.Sizings.Count | Should -Be 0 -Because 'a roll sizes the install itself'
        $script:Tracked | Should -Contain 'open' -Because 'the run is tracked the same way as Pro'
    }
    It 'rings 0-3 for both editions: a Community install on ring 0 or 1 reads that ring' {
        foreach ($ring in 0, 1, 2) {
            $w = New-World (New-Channel @{ $ring = (New-Entry $script:Z301 '3.0.1' $ring 4) }) @{ (Url '3.0.1') = $script:Z301 }
            $r = Invoke-Run $w -Env @{ SI_UPDATER_RING = "$ring" }
            $r.Code | Should -Be 0
            $w.ChannelReads | Should -Be @("https://invardia.com/api/updates/securityinsight/community/$ring")
            $r.State.code.appliedSequence | Should -Be 4; $r.State.code.appliedRing | Should -Be $ring
        }
        { Get-SIUpdaterCommunityManifestUri -BaseUrl 'https://x' -Ring 0 } | Should -Not -Throw
        { Get-SIUpdaterCommunityManifestUri -BaseUrl 'https://x' -Ring 4 } | Should -Throw
    }
    It 'no ring recorded: the Community route takes ring 3 (broad); the install route keeps "no ring, no pull"' {
        (Resolve-SIUpdaterInvardiaRing -EnvRing '' -DefaultRing 3 -Channel community).Ring | Should -Be 3
        (Resolve-SIUpdaterInvardiaRing -EnvRing '').Ring | Should -BeNullOrEmpty
        (Resolve-SIUpdaterInvardiaRing -EnvRing '1' -DefaultRing 3 -Channel community).Ring | Should -Be 1 -Because 'ring 1 is a ring for a Community install too'
    }
    It 'SI_UPDATER_COMMUNITY_BASE_URL overrides Invardia''s base (https only); http is refused and Invardia read' {
        $w = New-World (New-Channel @{}) @{}
        $null = Invoke-Run $w -Env @{ SI_UPDATER_COMMUNITY_BASE_URL = 'https://test.example' }
        $w.ChannelReads | Should -Be @('https://test.example/api/updates/securityinsight/community/3')
        $w2 = New-World (New-Channel @{}) @{}
        $r2 = Invoke-Run $w2 -Env @{ SI_UPDATER_COMMUNITY_BASE_URL = 'http://test.example' }
        $w2.ChannelReads | Should -Be @('https://invardia.com/api/updates/securityinsight/community/3')
        $r2.Log | Should -Match 'not https'
    }
    It 'nothing released to the ring (204): none, nothing downloaded, the sizes checked, exit 0' {
        $w = New-World (New-Channel @{ 2 = (New-Entry $script:Z301 '3.0.1' 2 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $r.State.code.lastAction | Should -Be 'none'
        $w.Sizings.Count | Should -Be 1
    }
    It 'Invardia answers 404 or 5xx: nothing changes, exit 0, the state says why' {
        $w = New-World (New-Channel @{}) @{}; $w.Status = 404
        $r = Invoke-Run $w
        $r.Code | Should -Be 0; $r.State.code.lastAction | Should -Be 'notfound'; $r.State.lastError | Should -Match '404'
        $w2 = New-World (New-Channel @{}) @{}; $w2.Status = 503
        $r2 = Invoke-Run $w2
        $r2.Code | Should -Be 0; $r2.State.code.lastAction | Should -Be 'network'
    }
    It 'the jobs run the version the ring names: current -- nothing downloaded or rolled, the sequence counts as applied, the sizes are checked' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w -Deployed '3.0.1'
        $r.Code | Should -Be 0
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $r.State.code.appliedSequence | Should -Be 7
        $w.Sizings.Count | Should -Be 1
    }
    It 'a manualStep HOLDS the release (nothing downloaded); SI_UPDATER_ACCEPT_MANUAL_STEP=community:<n> (or code:<n>) releases exactly it' {
        $e = New-Entry $script:Z301 '3.0.1' 3 8 -Extra @{ manualStep = 'make a database backup first' }
        $w = New-World (New-Channel @{ 3 = $e }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0; $r.State.code.lastAction | Should -Be 'hold'; $r.State.code.hold | Should -Not -BeNullOrEmpty
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        foreach ($acc in 'community:8', 'code:8') {
            $script:Rolls.Clear()
            $w2 = New-World (New-Channel @{ 3 = $e }) @{ (Url '3.0.1') = $script:Z301 }
            $null = Invoke-Run $w2 -Env @{ SI_UPDATER_ACCEPT_MANUAL_STEP = $acc }
            $script:Rolls.Count | Should -Be 1 -Because $acc
        }
    }
    It 'forward-only (the Pro rule): a FIRST entry that names a version older than the jobs run is held, never rolled back to' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 5) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w -Deployed '3.0.2'
        $r.Log | Should -Match 'never moves the jobs backward'
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'the customer blocks engine-image: the route is not read at all' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $null = Invoke-Run $w -Blocked @('engine-image')
        $w.ChannelReads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'a pipeline run is going (the run gate says WAIT): nothing rolled, the wait handed to the pipeline runner, exit 0' {
        $wait = [pscustomobject]@{ Go = $false; Verdict = 'Wait'; Kind = 'run'; Reason = 'update waits: run r-1 is running'; RunId = 'r-1'; LockTaken = $false; Holder = '' }
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 } -Gate $wait
        $r = Invoke-Run $w
        $r.Code | Should -Be 0
        $script:Rolls.Count | Should -Be 0
        $w.Waits.Count | Should -Be 1; $w.Waits[0] | Should -Not -BeNullOrEmpty
        $r.State.waitsSinceUtc | Should -Not -BeNullOrEmpty
        $r.State.code.appliedSequence | Should -Be -1 -Because 'nothing was applied'
    }
    It 'a failed roll fails the run (exit 1) and records nothing as applied' {
        $script:RollCode = 1
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1
        $r.State.code.appliedSequence | Should -Be -1
        $w.PostRolls.Count | Should -Be 0
    }
}

Describe 'COMPAT: an existing Community install keeps what its earlier updater applied' {
    BeforeEach { Mock Invoke-SIUpdaterRoll { [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } } }
    It 'the CommunityUpdateState row is carried into the one state when it has no applied code: a REPLAYED (lower) sequence is refused, nothing downloaded' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 } -OldRow '{"seq":9,"ver":"3.0.2","ring":3,"at":"2026-10-20T18:30:00Z"}'
        $r = Invoke-Run $w -Deployed '3.0.2'
        $r.Log | Should -Match 'earlier Community record is carried over'
        $r.State.code.appliedSequence | Should -Be 9; $r.State.code.appliedVersion | Should -Be '3.0.2'
        $r.State.code.lastAction | Should -Be 'refused'
        $w.Downloads.Count | Should -Be 0
    }
    It 'a newer sequence after the carried-over one rolls (no "first manifest" hold for a Community install that applied before)' {
        $z = New-Release '3.0.3'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z '3.0.3' 3 10) }) @{ (Url '3.0.3') = $z } -OldRow '{"seq":9,"ver":"3.0.2","ring":3,"at":"2026-10-20T18:30:00Z"}'
        $r = Invoke-Run $w -Deployed '3.0.2'
        $r.Code | Should -Be 0; $r.State.code.appliedSequence | Should -Be 10
    }
    It 'Merge-SIUpdaterCommunityState is used once: a state that has applied code is never overwritten by the old row' {
        $s = ConvertFrom-SIInvardiaUpdateState -Json ''
        Merge-SIUpdaterCommunityState -State $s -Json '{"seq":4,"ver":"3.0.1","ring":2}' | Should -BeTrue
        $s.code.appliedSequence | Should -Be 4; $s.code.appliedRing | Should -Be 2; $s.channel | Should -Be 'community'
        Merge-SIUpdaterCommunityState -State $s -Json '{"seq":9,"ver":"3.0.9","ring":3}' | Should -BeFalse
        $s.code.appliedSequence | Should -Be 4
        Merge-SIUpdaterCommunityState -State (ConvertFrom-SIInvardiaUpdateState -Json '') -Json '' | Should -BeFalse
    }
    It 'the manifest address moved (a Community install got a licence): the applied sequence starts again from the version rule' {
        $w = New-World (New-Channel @{}) @{} -Edition 'community'
        $w.Vault['SI-Update-State'] = '{"source":"community","channel":"community","code":{"appliedSequence":40,"appliedVersion":"3.0.2"}}'
        $w.Vault['SI-License'] = 'a licence file'
        $r = Invoke-Run $w -Deployed '3.0.2' -Env @{ SI_UPDATER_RING = '3' }
        $r.Log | Should -Match 'manifest address moved from community to invardia'
        $r.State.channel | Should -Be 'invardia'
        $w.ChannelReads.Count | Should -Be 0 -Because 'a licensed install asks the install route'
    }
}

Describe 'NEGATIVE: what the Community route refuses -- nothing is rolled' {
    BeforeEach {
        $script:Rolls = New-Object System.Collections.Generic.List[object]
        Mock Invoke-SIUpdaterRoll { $script:Rolls.Add($Version); [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
    }
    It 'a manifest of another product or another kind is refused before any download' {
        foreach ($x in @(@{ product = 'pim4entraps' }, @{ kind = 'code' })) {
            $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Extra $x) }) @{ (Url '3.0.1') = $script:Z301 }
            $r = Invoke-Run $w
            $r.State.code.lastAction | Should -Be 'refused'; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        }
    }
    It 'owner 2026-10-28: a release of ANOTHER MAJOR VERSION is refused before any download' {
        $z4 = New-Release '4.0.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z4 '4.0.0' 3 9) }) @{ (Url '4.0.0') = $z4 }
        $r = Invoke-Run $w -Deployed '3.0.1'
        $r.State.code.lastAction | Should -Be 'refused'; $r.State.lastError | Should -Match 'another major version'
        $w.Downloads.Count | Should -Be 0 -Because 'refused before anything is downloaded'
        $script:Rolls.Count | Should -Be 0
        Test-SIUpdaterCommunityMajor -Installed '2.2.460' -Release '3.0.0' | Should -Match 'another major version'
        Test-SIUpdaterCommunityMajor -Installed '3.0.0.202610261957' -Release '3.1.0' | Should -BeNullOrEmpty
        Test-SIUpdaterCommunityMajor -Installed '' -Release '3.0.1' | Should -Match 'cannot be read' -Because 'fail closed'
    }
    It 'signed by a key this release does not trust -> refused before any download' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Signer $script:Other) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.State.code.lastAction | Should -Be 'refused'; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'the ring-2 entry pasted into ring 3''s slot -> refused (the SIGNED ring is checked)' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 2 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Log | Should -Match 'signed for ring'; $w.Downloads.Count | Should -Be 0
    }
    It 'a download link that is not https -> refused' {
        $bad = 'http://evil.example/SecurityInsight-v3.0.1.zip'
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -DownloadUrl $bad) }) @{ $bad = $script:Z301 }
        $null = Invoke-Run $w
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'an archive of another size than the signed one -> refused after the download, exit 1' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Extra @{ size = ((Get-Item $script:Z301).Length + 1) }) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'code REFUSED'; $script:Rolls.Count | Should -Be 0
    }
    It 'an archive whose VERSION is not the signed version -> refused, exit 1' {
        $z = New-Release '3.0.1' -ArchiveVersion '3.0.9'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z '3.0.1' 3 7) }) @{ (Url '3.0.1') = $z }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match '3\.0\.9'; $script:Rolls.Count | Should -Be 0
    }
    It 'a release without the update client (it would end updates for the install) -> refused, exit 1' {
        $z = New-Release '3.0.1' -Omit 'container/updater/_shared/SI-UpdaterInvardia.ps1'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z '3.0.1' 3 7) }) @{ (Url '3.0.1') = $z }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'SI-UpdaterInvardia'; $script:Rolls.Count | Should -Be 0
    }
    It 'an answer that is not JSON -> refused; a route that cannot be read -> nothing changes, exit 0 (the next run asks again)' {
        $r = Invoke-Run (New-World 'this is not json')
        $r.State.code.lastAction | Should -Be 'refused'
        $w = New-World ''; $w.Seams.GetManifest = { param($u) throw 'timeout' }
        $r2 = Invoke-Run $w
        $r2.Code | Should -Be 0; $r2.State.code.lastAction | Should -Be 'network'
    }
}

Describe 'the updater runs the same steps for every install' {
    It 'a Community install runs the endpoints and the one client exactly as Pro; the licence ask (it carries the tenant) only after its yes to "Connect this install to Invardia"' {
        Mock Connect-SIUpdaterRest { 'the test identity' }
        Mock Test-SIUpdaterRunNow { $true }
        Mock Invoke-SIUpdaterSecretHandover { [pscustomobject]@{ Report = @() } }
        Mock Invoke-SIUpdaterLicenceRequest { }
        Mock Invoke-SIUpdaterRecordEndpoints { @() }
        Mock Get-SIUpdaterDeployed { '3.0.0' }
        Mock Get-SIUpdaterAutoSwitches { $null }
        Mock Get-SIUpdaterInstallEdition { 'community' }
        Mock Invoke-SIUpdaterFromInvardia { 0 }
        $savedConn = $global:SI_Invardia_Connect; $global:SI_Invardia_Connect = $null
        try {
            $e = @{ SI_UPDATER_TENANT_ID = '11111111-2222-3333-4444-555555555555'; SI_UPDATER_CLIENT_ID = 'cid'; SI_UPDATER_SUBSCRIPTION_ID = 'sub'; SI_UPDATER_RESOURCE_GROUP = 'rg'
                    SI_UPDATER_ACR = 'acr'; SI_UPDATER_KEY_VAULT = 'kv'; SI_UPDATER_AUTH = 'ManagedIdentity'; SI_UPDATER_SOURCE = 'community'; SI_INVARDIA_CONNECT = 'off' }
            (Invoke-SIUpdater -Env $e 6>$null) | Should -Be 0
            Should -Invoke Invoke-SIUpdaterFromInvardia -Times 1 -Exactly -ParameterFilter { $Deployed -eq '3.0.0' -and $ResourceGroup -eq 'rg' }
            Should -Invoke Invoke-SIUpdaterLicenceRequest -Times 0 -Exactly -Because 'a Community install that did not say yes sends nothing that identifies it'
            $global:SI_UpdaterConnected | Should -BeFalse
            $e.SI_INVARDIA_CONNECT = 'on'
            (Invoke-SIUpdater -Env $e 6>$null) | Should -Be 0
            Should -Invoke Invoke-SIUpdaterLicenceRequest -Times 1 -Exactly -Because 'connected: it asks Invardia like Pro; the answer decides the features'
        } finally { $global:SI_Invardia_Connect = $savedConn; $global:SI_UpdaterConnected = $null }
    }
    It 'a Pro install (the install route) is connected and asks for its licence, as before; the Community route only after the yes' {
        Test-SIUpdaterInvardiaConnected -Route 'invardia' -Get { param($k) '' } | Should -BeTrue
        Test-SIUpdaterInvardiaConnected -Route 'community' -Get { param($k) '' } | Should -BeFalse
        Test-SIUpdaterInvardiaConnected -Route 'community' -Get { param($k) if ($k -eq 'SI_INVARDIA_CONNECT') { 'on' } else { '' } } | Should -BeTrue
    }
    It 'the updater job''s setup: one client for both editions, rings 0-3 for a Community install, the edition never read from the files the copy carries' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1'))
        $code = [regex]::Replace($src, '(?s)<#.*?#>', '')
        $code | Should -Not -Match '\$UpdateRing -lt 2' -Because 'rings 0-3 for both editions'
        $code | Should -Not -Match 'not a Community ring'
        $code | Should -Not -Match 'SI-UpdaterCommunity\.ps1' -Because 'the edition is a parameter, never a file test'
        $code | Should -Match "ValidateSet\('invardia', 'community', 'feed'\)"
        # the client's own release checks accept every ring
        $script:SICommunityUpdateRings | Should -Be @(0, 1, 2, 3)
    }
    It 'SI_UPDATER_SOURCE accepts community (what setup writes on a Community install''s updater)' {
        Get-SIUpdaterSourceKind -Source 'community' -SourceUrl '' | Should -Be 'community'
    }
    It 'a Community run''s failures take the same path as Pro''s; the telemetry client sends them only from a connected install' {
        $sent = New-Object System.Collections.Generic.List[object]
        try {
            if (Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue) { Add-SIUpdaterFailure -Step 'download' -Text 'a test failure' }
            $null = @(Invoke-SIUpdaterFailureReport -ExitCode 1 -StartedAt ([datetime]::UtcNow) -Env @{ SI_TELEMETRY_ENABLED = 'true'; SI_UPDATER_SOURCE = 'community' } -ReadKey { '' } -Send { param($a) $sent.Add($a) })
            $sent.Count | Should -BeGreaterThan 0 -Because 'no edition test skips the report (PRO-COMMUNITY-SAME)'
        } finally { if ($global:SI_UpdaterFailures) { $global:SI_UpdaterFailures.Clear() } }
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        [regex]::Match($src, '(?s)function Invoke-SIUpdaterFailureReport \{.*?\r?\n\}').Value | Should -Not -Match '(?i)community'
        # the report's context follows the run's connection (framework PRO-COMMUNITY-SAME, opt-in): not connected = edition
        # community = the telemetry client's Connected gate sends nothing (SIv3-ProCommunitySame proves the gate)
        $ut = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterTelemetry.ps1'))
        $ut | Should -Match ([regex]::Escape('elseif ($global:SI_UpdaterConnected -eq $false) { ''community'' }'))
    }
    It 'the roll steps ship in their own file and the one client loads them' {
        $steps = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRollSteps.ps1'))
        foreach ($f in 'Resolve-SIUpdaterRunningRelease', 'Get-SIUpdaterNeedsQuiet', 'Invoke-SIUpdaterInvardiaPreRoll', 'Invoke-SIUpdaterInvardiaPostRoll', 'Invoke-SIUpdaterInvardiaSelfRetry', 'Save-SIUpdaterInvardiaStateRow') {
            $steps | Should -Match ("(?m)^function {0} " -f [regex]::Escape($f))
        }
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')) | Should -Match "'SI-UpdaterRollSteps\.ps1'"
    }
}
