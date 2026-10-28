#Requires -Version 5.1
<#
    SI #750 (b) -- THE COMMUNITY EDITION'S IN-CLOUD UPDATER (owner 2026-10-18: "the IN-CLOUD UPDATER, as Pro, on the community
    channel"): container/updater/_shared/SI-UpdaterCommunity.ps1 (Invoke-SIUpdaterFromCommunity), its wiring in
    Start-SIUpdater.ps1 (Get-SIUpdaterEditionPath: a Pro image always takes Invardia; an image without the Invardia client
    takes the signed Community channel) and the shared roll steps (_shared/SI-UpdaterRollSteps.ps1).

    EVERYTHING IS OFFLINE. The channel, the download, the run gate, the roll and the database are seams or mocks; manifests are
    signed with a TEST key made here (never Invardia's), passed as the trust list; a real HTTP call fails the test. Runs on
    Windows PowerShell 5.1 and PowerShell 7. Needs no Pro file: it runs in the Community copy too.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterCommunity.ps1')
    if (-not (Get-Command -Name Test-SICommunityChannelEntry -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-CommunityUpdate.ps1') }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $script:RealHttp = New-Object System.Collections.Generic.List[string]
    Mock Invoke-WebRequest { $script:RealHttp.Add([string]$Uri); throw 'no network in tests' }
    Mock Invoke-RestMethod { $script:RealHttp.Add([string]$Uri); throw 'no network in tests' }

    function script:B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $script:Rsa = New-Object System.Security.Cryptography.RSACng 2048
    $script:Other = New-Object System.Security.Cryptography.RSACng 2048
    $pub = $script:Rsa.ExportParameters($false)
    $script:Keys = @(@{ keyId = 'test-update-key'; n = (B64Url $pub.Modulus); e = (B64Url $pub.Exponent) })
    $script:Host1 = 'https://github.com/KnudsenMorten/SecurityInsight/releases/download/'
    $script:Need = @('Update-SecurityInsight.ps1', 'engine/_shared/SI-CommunityUpdate.ps1', 'engine/_shared/InvardiaUpdate.verify.ps1',
                     'setup/Invoke-SIContainerUpdate.ps1', 'container/updater/Start-SIUpdater.ps1', 'container/updater/_shared/SI-UpdaterCommunity.ps1')

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
        ([ordered]@{ schema = 1; product = 'securityinsight'; rings = $r; history = @() } | ConvertTo-Json -Depth 6)
    }
    # The world: the channel, URL -> zip, the database rows, what the gate answers, and a record of every step.
    function script:New-World([string]$Channel, [hashtable]$Files = @{}, [hashtable]$Rows = @{}, $Gate = $null) {
        $w = @{ Channel = $Channel; Files = $Files; Rows = $Rows; Gate = $Gate; ChannelReads = (New-Object System.Collections.Generic.List[string])
                Downloads = (New-Object System.Collections.Generic.List[string]); PostRolls = (New-Object System.Collections.Generic.List[string])
                Sizings = (New-Object System.Collections.Generic.List[string]); Waits = (New-Object System.Collections.Generic.List[string]) }
        if (-not $w.Gate) { $w.Gate = [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no pipeline run is going'; RunId = ''; LockTaken = $false; Holder = '' } }
        $w.Seams = @{
            # Invardia's Community route, faked (2026-10-28): GET .../community/<ring> -> 200 + the ring's signed entry,
            # 204 when nothing is released to it; $w.Status forces an answer (404, 500); a Channel that is no JSON is the body as is
            GetManifest = { param($u) $w.ChannelReads.Add($u)
                            if ($w.Status) { return [pscustomobject]@{ Status = [int]$w.Status; Body = '' } }
                            $c = $null; try { $c = $w.Channel | ConvertFrom-Json -ErrorAction Stop } catch { $c = $null }
                            if (-not $c -or -not $c.PSObject.Properties['rings']) { return [pscustomobject]@{ Status = 200; Body = [string]$w.Channel } }
                            $ringNo = ($u -split '/')[-1]
                            $e = $c.rings.PSObject.Properties[$ringNo]
                            if (-not $e) { return [pscustomobject]@{ Status = 204; Body = '' } }
                            [pscustomobject]@{ Status = 200; Body = ($e.Value | ConvertTo-Json -Depth 6) } }.GetNewClosure()
            Download    = { param($u, $f) $w.Downloads.Add($u); if (-not $w.Files.ContainsKey($u)) { throw "404 $u" }; Copy-Item -LiteralPath $w.Files[$u] -Destination $f -Force }.GetNewClosure()
            Now         = { [datetime]'2026-10-27T18:30:00Z' }
            TrustedKeys = { $script:Keys }
            ReadState   = { $w.Rows['CommunityUpdateState'] }.GetNewClosure()
            WriteState  = { param($n, $j) $w.Rows[$n] = $j }.GetNewClosure()
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
        $log = @(Invoke-SIUpdaterFromCommunity -Env $Env -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Blocked $Blocked -Store $null -Deployed $Deployed `
                    -SIRoot $script:SIRoot -Seams $World.Seams -Work (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) 6>&1 | ForEach-Object { $_ })
        $rc = @($log | Where-Object { $_ -is [int] }) | Select-Object -Last 1
        [pscustomobject]@{ Code = $rc; Log = (@($log | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n")
                           State = (ConvertFrom-SIUpdaterCommunityState -Json $World.Rows['CommunityUpdateState'])
                           View = $(if ($World.Rows['UpdateState']) { $World.Rows['UpdateState'] | ConvertFrom-Json } else { $null }) }
    }
    $script:Z301 = New-Release '3.0.1'
}

AfterAll {
    $script:RealHttp.Count | Should -Be 0 -Because 'no test may reach the network'
}

Describe 'the Community updater applies a signed release (Invoke-SIUpdaterFromCommunity)' {
    BeforeEach {
        $script:Rolls = New-Object System.Collections.Generic.List[object]
        $script:RollCode = 0
        # the extracted release's VERSION is read AT the roll: the run removes its work folder when it ends
        Mock Invoke-SIUpdaterRoll { $script:Rolls.Add([pscustomobject]@{ Root = $SIRoot; RootVersion = [IO.File]::ReadAllText((Join-Path $SIRoot 'VERSION')); Version = $Version; Commit = $Commit; Store = $Store }); [pscustomobject]@{ Code = $script:RollCode; Held = $false; Reason = '' } }
    }
    It 'ring 3 has a newer release: verified, downloaded, size + SHA-256 checked, extracted, ROLLED from the extracted root; post-roll; the sequence recorded' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0
        $w.ChannelReads | Should -Be @('https://invardia.com/api/updates/securityinsight/community/3') -Because 'Invardia''s anonymous Community route for this ring, unless the job overrides the base'
        $w.Downloads | Should -Be @((Url '3.0.1'))
        $script:Rolls.Count | Should -Be 1
        $script:Rolls[0].Version | Should -Be '3.0.1'
        $script:Rolls[0].RootVersion | Should -Be '3.0.1' -Because 'the roll runs the EXTRACTED release'
        $script:Rolls[0].Commit | Should -Be 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'
        $w.PostRolls | Should -Be @('3.0.1|a1b2c3d4e5f60718293a4b5c6d7e8f9012345678')
        $r.State.appliedSequence | Should -Be 7; $r.State.appliedVersion | Should -Be '3.0.1'; $r.State.ring | Should -Be 3
        $r.View.source | Should -Be 'community'; $r.View.code.applied | Should -Be 7; $r.View.code.action | Should -Be 'applied'
        $w.Rows['UpdateState'].Length | Should -BeLessOrEqual 400
        $w.Sizings.Count | Should -Be 0 -Because 'a roll sizes the install itself'
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
    It 'Invardia answers 204 (nothing released to the ring): none, nothing downloaded, exit 0' {
        $w = New-World (New-Channel @{ 2 = (New-Entry $script:Z301 '3.0.1' 2 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $r.View.code.action | Should -Be 'none'
    }
    It 'Invardia answers 404 (no such ring): refused, exit 1; any other status: nothing changes, exit 0' {
        $w = New-World (New-Channel @{}) @{}; $w.Status = 404
        (Invoke-Run $w).Code | Should -Be 1
        $w2 = New-World (New-Channel @{}) @{}; $w2.Status = 503
        $r2 = Invoke-Run $w2
        $r2.Code | Should -Be 0; $r2.View.code.action | Should -Be 'network'
    }
    It 'a manifest of another product or another kind is refused before any download' {
        foreach ($x in @(@{ product = 'pim4entraps' }, @{ kind = 'code' })) {
            $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Extra $x) }) @{ (Url '3.0.1') = $script:Z301 }
            $r = Invoke-Run $w
            $r.Code | Should -Be 1; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        }
    }
    It 'the jobs run the version the ring names: current -- nothing downloaded or rolled, the sequence counts as applied, the sizes are checked' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w -Deployed '3.0.1'
        $r.Code | Should -Be 0
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $r.State.appliedSequence | Should -Be 7
        @($w.Sizings) | Should -Be @('the code is current')
    }
    It 'nothing released to this install''s ring: none -- nothing downloaded or rolled' {
        $w = New-World (New-Channel @{ 2 = (New-Entry $script:Z301 '3.0.1' 2 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'nothing is released to ring 3'
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'a manualStep HOLDS the release (nothing downloaded); SI_UPDATER_ACCEPT_MANUAL_STEP=community:<sequence> releases exactly it' {
        $e = New-Entry $script:Z301 '3.0.1' 3 8 -Extra @{ manualStep = 'make a database backup first' }
        $w = New-World (New-Channel @{ 3 = $e }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 0; $r.View.code.action | Should -Be 'hold'; $r.View.code.hold | Should -Not -BeNullOrEmpty
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $w2 = New-World (New-Channel @{ 3 = $e }) @{ (Url '3.0.1') = $script:Z301 }
        $null = Invoke-Run $w2 -Env @{ SI_UPDATER_ACCEPT_MANUAL_STEP = 'community:8' }
        $script:Rolls.Count | Should -Be 1
    }
    It 'forward-only: a FIRST entry that names a version older than the jobs run is held, never rolled back to' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 5) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w -Deployed '3.0.2'
        $r.View.code.action | Should -Be 'hold'; $r.Log | Should -Match 'never moves the jobs backward'
        $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'the customer blocks engine-image: the channel is not read at all' {
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
        $r.View.waits | Should -Not -BeNullOrEmpty
        $r.State.appliedSequence | Should -Be 0 -Because 'nothing was applied'
    }
    It 'a failed roll fails the run (exit 1) and records nothing as applied' {
        $script:RollCode = 1
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1
        $r.State.appliedSequence | Should -Be 0
        $w.PostRolls.Count | Should -Be 0
    }
}

Describe 'NEGATIVE: what the Community updater refuses -- nothing is rolled, exit 1' {
    BeforeEach {
        $script:Rolls = New-Object System.Collections.Generic.List[object]
        Mock Invoke-SIUpdaterRoll { $script:Rolls.Add($Version); [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
    }
    It 'owner 2026-10-28: a release of ANOTHER MAJOR VERSION is refused before any download (4.x on a 3.x install; a 3.x release on 2.2)' {
        $z4 = New-Release '4.0.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z4 '4.0.0' 3 9) }) @{ (Url '4.0.0') = $z4 }
        $r = Invoke-Run $w -Deployed '3.0.1'
        $r.Code | Should -Be 1
        $w.Downloads.Count | Should -Be 0 -Because 'refused before anything is downloaded'
        $script:Rolls.Count | Should -Be 0
        Test-SIUpdaterCommunityMajor -Installed '3.0.1' -Release '4.0.0' | Should -Match 'another major version'
        Test-SIUpdaterCommunityMajor -Installed '2.2.460' -Release '3.0.0' | Should -Match 'another major version'
        Test-SIUpdaterCommunityMajor -Installed '3.0.0.202610261957' -Release '3.1.0' | Should -BeNullOrEmpty
        Test-SIUpdaterCommunityMajor -Installed '' -Release '3.0.1' | Should -Match 'cannot be read' -Because 'fail closed'
        Test-SIUpdaterCommunityMajor -Installed '3.0.0' -Release 'x' | Should -Match 'no readable version'
    }
    It 'signed by a key this release does not trust -> refused before any download' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Signer $script:Other) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
        $r.View.code.action | Should -Be 'refused'
    }
    It 'the ring-2 entry pasted into ring 3''s slot -> refused (the SIGNED ring is checked)' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 2 7) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'signed for ring'; $w.Downloads.Count | Should -Be 0
    }
    It 'a download link that is not https -> refused' {
        $bad = 'http://evil.example/SecurityInsight-v3.0.1.zip'
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -DownloadUrl $bad) }) @{ $bad = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'an archive whose SHA-256 is not the signed one -> refused after the download' {
        $other = New-Release '3.0.1'
        $e = New-Entry $script:Z301 '3.0.1' 3 7
        $w = New-World (New-Channel @{ 3 = $e }) @{ (Url '3.0.1') = $other }
        if ((Get-Item $other).Length -ne (Get-Item $script:Z301).Length) { Set-ItResult -Skipped -Because 'the two test zips differ in size; the size test covers that'; return }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'SHA-256'; $script:Rolls.Count | Should -Be 0
    }
    It 'an archive of another size than the signed one -> refused' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7 -Extra @{ size = ((Get-Item $script:Z301).Length + 1) }) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'bytes'; $script:Rolls.Count | Should -Be 0
    }
    It 'an archive whose VERSION is not the signed version -> refused' {
        $z = New-Release '3.0.1' -ArchiveVersion '3.0.9'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z '3.0.1' 3 7) }) @{ (Url '3.0.1') = $z }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match '3\.0\.9'; $script:Rolls.Count | Should -Be 0
    }
    It 'a release without this updater (it would end updates for the install) -> refused' {
        $z = New-Release '3.0.1' -Omit 'container/updater/_shared/SI-UpdaterCommunity.ps1'
        $w = New-World (New-Channel @{ 3 = (New-Entry $z '3.0.1' 3 7) }) @{ (Url '3.0.1') = $z }
        $r = Invoke-Run $w
        $r.Code | Should -Be 1; $r.Log | Should -Match 'SI-UpdaterCommunity'; $script:Rolls.Count | Should -Be 0
    }
    It 'a REPLAYED (lower) sequence than the one applied here -> refused' {
        $w = New-World (New-Channel @{ 3 = (New-Entry $script:Z301 '3.0.1' 3 7) }) @{ (Url '3.0.1') = $script:Z301 } -Rows @{ CommunityUpdateState = '{"seq":9,"ver":"3.0.2","ring":3,"at":"2026-10-20T18:30:00Z"}' }
        $r = Invoke-Run $w -Deployed '3.0.2'
        $r.Code | Should -Be 1; $w.Downloads.Count | Should -Be 0; $script:Rolls.Count | Should -Be 0
    }
    It 'a channel that is not JSON -> refused; a channel that cannot be read -> nothing changes, exit 0 (the next run asks again)' {
        $r = Invoke-Run (New-World 'this is not json')
        $r.Code | Should -Be 1
        $w = New-World ''; $w.Seams.GetManifest = { param($u) throw 'timeout' }
        $r2 = Invoke-Run $w
        $r2.Code | Should -Be 0; $r2.View.code.action | Should -Be 'network'
    }
}

Describe 'the Community ring: 2 or 3 only' {
    It 'SI_UPDATER_RING 2 or 3 is the ring; anything else is ring 3, said' {
        (Resolve-SIUpdaterCommunityRing -EnvRing '2').Ring | Should -Be 2
        (Resolve-SIUpdaterCommunityRing -EnvRing '3').Ring | Should -Be 3
        $r = Resolve-SIUpdaterCommunityRing -EnvRing '1'
        $r.Ring | Should -Be 3; $r.Reason | Should -Match 'not a Community ring'
        (Resolve-SIUpdaterCommunityRing -EnvRing 'zero').Ring | Should -Be 3
    }
    It 'no job ring: the recorded install ring (2 / 3), else the Update ring setting, else 3; a recorded 0 / 1 is ring 3, said' {
        $store = [pscustomobject]@{ Invoke = { } }
        Mock Read-SIInstallRing { [pscustomobject]@{ Ring = 2 } }
        (Resolve-SIUpdaterCommunityRing -EnvRing '' -Store $store).Ring | Should -Be 2
        Mock Read-SIInstallRing { [pscustomobject]@{ Ring = 1 } }
        $r = Resolve-SIUpdaterCommunityRing -EnvRing '' -Store $store
        $r.Ring | Should -Be 3; $r.Reason | Should -Match 'not a Community ring'
        Mock Read-SIInstallRing { $null }
        Mock Read-SIUpdateRingSetting { 2 }
        (Resolve-SIUpdaterCommunityRing -EnvRing '' -Store $store).Ring | Should -Be 2
        Mock Read-SIUpdateRingSetting { $null }
        (Resolve-SIUpdaterCommunityRing -EnvRing '' -Store $store).Ring | Should -Be 3
        (Resolve-SIUpdaterCommunityRing -EnvRing '').Ring | Should -Be 3 -Because 'no database: ring 3'
    }
    It 'a run on ring 2 reads ring 2''s entry' {
        Mock Invoke-SIUpdaterRoll { [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
        $w = New-World (New-Channel @{ 2 = (New-Entry $script:Z301 '3.0.1' 2 4) }) @{ (Url '3.0.1') = $script:Z301 }
        $r = Invoke-Run $w -Env @{ SI_UPDATER_RING = '2' }
        $r.Code | Should -Be 0; $r.State.ring | Should -Be 2; $r.State.appliedSequence | Should -Be 4
    }
}

Describe 'the updater takes the Community path only where the Invardia client is absent' {
    It 'Get-SIUpdaterEditionPath: the Invardia hook = invardia (always, a Pro image never takes the public channel); else the Community hook + client = community; else none' {
        $h = Join-Path $TestDrive 'hooks'; $si = Join-Path $TestDrive 'si'
        New-Item -ItemType Directory -Force -Path $h, (Join-Path $si 'engine\_shared') | Out-Null
        Get-SIUpdaterEditionPath -HookFolder $h -SIRoot $si | Should -Be ''
        Set-Content -LiteralPath (Join-Path $h 'SI-UpdaterCommunity.ps1') -Value '#'
        Get-SIUpdaterEditionPath -HookFolder $h -SIRoot $si | Should -Be '' -Because 'the hook alone is not enough: the signed client must be there too'
        Set-Content -LiteralPath (Join-Path $si 'engine\_shared\SI-CommunityUpdate.ps1') -Value '#'
        Get-SIUpdaterEditionPath -HookFolder $h -SIRoot $si | Should -Be 'community'
        Set-Content -LiteralPath (Join-Path $h 'SI-UpdaterInvardia.ps1') -Value '#'
        Get-SIUpdaterEditionPath -HookFolder $h -SIRoot $si | Should -Be 'invardia'
    }
    It 'the run on the Community path asks Invardia NOTHING: no licence request, no install key; it hands over to the Community hook' {
        Mock Get-SIUpdaterEditionPath { 'community' }
        Mock Connect-SIUpdaterRest { 'the test identity' }
        Mock Test-SIUpdaterRunNow { $true }
        Mock Invoke-SIUpdaterSecretHandover { [pscustomobject]@{ Report = @() } }
        Mock Invoke-SIUpdaterLicenceRequest { }
        Mock Invoke-SIUpdaterRecordEndpoints { @() }
        Mock Get-SIUpdaterDeployed { '3.0.0' }
        Mock Invoke-SIUpdaterFromCommunity { 0 }
        $e = @{ SI_UPDATER_TENANT_ID = '11111111-2222-3333-4444-555555555555'; SI_UPDATER_CLIENT_ID = 'cid'; SI_UPDATER_SUBSCRIPTION_ID = 'sub'; SI_UPDATER_RESOURCE_GROUP = 'rg'
                SI_UPDATER_ACR = 'acr'; SI_UPDATER_KEY_VAULT = 'kv'; SI_UPDATER_AUTH = 'ManagedIdentity'; SI_UPDATER_SOURCE = 'community' }
        try {
            (Invoke-SIUpdater -Env $e 6>$null) | Should -Be 0
            Should -Invoke Invoke-SIUpdaterFromCommunity -Times 1 -Exactly -ParameterFilter { $Deployed -eq '3.0.0' -and $ResourceGroup -eq 'rg' }
            Should -Invoke Invoke-SIUpdaterLicenceRequest -Times 0 -Exactly
            Get-Command -Name Request-SIInvardiaInstallKey -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because 'the Invardia client is never loaded on the Community path'
        } finally { $global:SI_UpdaterEdition = $null }
    }
    It 'SI_UPDATER_SOURCE accepts community (what setup writes on a Community updater)' {
        Get-SIUpdaterSourceKind -Source 'community' -SourceUrl '' | Should -Be 'community'
    }
    It 'a Community run reports nothing to Invardia (no failure report, no tracking)' {
        $sent = New-Object System.Collections.Generic.List[object]
        $global:SI_UpdaterEdition = 'community'
        try {
            if (Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue) { Add-SIUpdaterFailure -Step 'download' -Text 'a test failure' }
            $r = @(Invoke-SIUpdaterFailureReport -ExitCode 1 -StartedAt ([datetime]::UtcNow) -Env @{ SI_TELEMETRY_ENABLED = 'true' } -ReadKey { '' } -Send { param($a) $sent.Add($a) })
            $r.Count | Should -Be 0
            $sent.Count | Should -Be 0
        } finally { $global:SI_UpdaterEdition = $null; if ($global:SI_UpdaterFailures) { $global:SI_UpdaterFailures.Clear() } }
    }
    It 'the shared roll steps ship in their own file and the Pro hook loads them (the Community updater rolls exactly as Pro)' {
        $steps = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRollSteps.ps1'))
        foreach ($f in 'Resolve-SIUpdaterRunningRelease', 'Get-SIUpdaterNeedsQuiet', 'Invoke-SIUpdaterInvardiaPreRoll', 'Invoke-SIUpdaterInvardiaPostRoll', 'Invoke-SIUpdaterInvardiaSelfRetry', 'Save-SIUpdaterInvardiaStateRow') {
            $steps | Should -Match ("(?m)^function {0} " -f [regex]::Escape($f))
        }
        $steps | Should -Not -Match 'SI-InvardiaUpdate\.ps1' -Because 'the shared steps never need the Pro client'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) | Should -Match "_shared/SI-UpdaterRollSteps\.ps1"
        $inv = Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'
        if (Test-Path -LiteralPath $inv) { [IO.File]::ReadAllText($inv) | Should -Match "'SI-UpdaterRollSteps\.ps1'" }
        $hook = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterCommunity.ps1'))
        $hook | Should -Match 'Invoke-SIUpdaterRoll -SIRoot \$payload'
        $hook | Should -Match 'Invoke-SIUpdaterInvardiaPostRoll -SIRoot \$payload'
        $hook | Should -Match '& \$passGate'
    }
}
