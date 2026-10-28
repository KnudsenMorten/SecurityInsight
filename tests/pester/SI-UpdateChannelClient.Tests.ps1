#Requires -Version 5.1
<#
    THE COMMUNITY UPDATE CLIENT (framework UPDATE-1, SI #270): Update-SecurityInsight.ps1 + engine/_shared/SI-CommunityUpdate.ps1
    + engine/_shared/InvardiaUpdate.verify.ps1. The SAME file ships in the 2.2 hand-over release and in v3.

    EVERYTHING IS OFFLINE: the channel, the download, the scheduled tasks and the container step are seams; manifests are
    signed with a TEST key made here (never Invardia's) and the test key is passed as the trust list. The install is a
    fixture folder. Runs on Windows PowerShell 5.1 and PowerShell 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1'))
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    function script:B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $script:Rsa = New-Object System.Security.Cryptography.RSACng 2048       # (5.1: RSA.Create()'s KeySize is read-only)
    $script:Other = New-Object System.Security.Cryptography.RSACng 2048
    $pub = $script:Rsa.ExportParameters($false)
    $script:Keys = @(@{ keyId = 'test-update-key'; n = (B64Url $pub.Modulus); e = (B64Url $pub.Exponent) })
    $script:Host1 = 'https://github.com/KnudsenMorten/SecurityInsight/releases/download/'
    $script:ClientFiles = @('Update-SecurityInsight.ps1', 'engine/_shared/SI-CommunityUpdate.ps1', 'engine/_shared/InvardiaUpdate.verify.ps1')

    function script:Hash([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
    function script:Snapshot([string]$root) {
        $h = @{}; $base = (Get-Item -LiteralPath $root).FullName.TrimEnd('\')
        Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.FullName -notlike "$base\.si-update\*" } | ForEach-Object { $h[$_.FullName.Substring($base.Length + 1)] = (Hash $_.FullName) }
        $h
    }
    function script:Same($a, $b) { if ($a.Count -ne $b.Count) { return $false }; foreach ($k in $a.Keys) { if ($b[$k] -ne $a[$k]) { return $false } }; $true }

    # A release zip: VERSION, the client trio (the REAL files), engine files; -Extra rel=>content; -NoClient; -Slip.
    function script:New-Release([string]$Version, [hashtable]$Extra = @{}, [switch]$NoClient, [switch]$TopFolder, [switch]$Slip) {
        $dir = Join-Path $TestDrive ("rel-$Version-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $root = if ($TopFolder) { Join-Path $dir "securityinsight-$Version" } else { $dir }
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'engine\_shared'), (Join-Path $root 'config') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'VERSION'), $Version)
        if (-not $NoClient) { foreach ($c in $script:ClientFiles) { Copy-Item -LiteralPath (Join-Path $script:SIRoot $c) -Destination (Join-Path $root $c) } }
        [IO.File]::WriteAllText((Join-Path $root 'engine\a.ps1'), "# engine a $Version`n'a'")
        [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.sample.ps1'), "# sample $Version")
        [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), '# A RELEASE MUST NEVER OVERWRITE THIS')
        foreach ($k in $Extra.Keys) { $p = Join-Path $root $k; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; [IO.File]::WriteAllText($p, $Extra[$k]) }
        $zip = "$dir.zip"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($dir, $zip)
        if ($Slip) { $z = [System.IO.Compression.ZipFile]::Open($zip, 'Update'); try { $e = $z.CreateEntry('../evil.ps1'); $w = New-Object IO.StreamWriter($e.Open()); $w.Write('x'); $w.Dispose() } finally { $z.Dispose() } }
        $zip
    }
    function script:New-Entry([string]$Zip, [string]$Version, [int]$Ring, [long]$Sequence, [hashtable]$Extra = @{}, $Signer = $script:Rsa, [string]$Url) {
        $m = [ordered]@{ product = 'securityinsight'; kind = 'community'; ring = $Ring; sequence = $Sequence; version = $Version
                         sha256 = (Hash $Zip).ToLowerInvariant(); size = (Get-Item -LiteralPath $Zip).Length; minFromVersion = $null; manualStep = $null }
        foreach ($k in $Extra.Keys) { $m[$k] = $Extra[$k] }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $Signer.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if (-not $Url) { $Url = "$($script:Host1)v$Version/SecurityInsight-v$Version.zip" }
        [ordered]@{ manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key'; downloadUrl = $Url }
    }
    function script:New-Channel([hashtable]$Rings) {
        $r = [ordered]@{}; foreach ($k in ($Rings.Keys | Sort-Object)) { $r["$k"] = $Rings[$k] }
        ([ordered]@{ schema = 1; product = 'securityinsight'; rings = $r; history = @() } | ConvertTo-Json -Depth 6)
    }
    # A 2.2-shaped install: VERSION, the client, an engine file, customer files, run output.
    function script:New-Install([string]$Version = '3.0.1', [int]$Ring = 0) {
        $root = Join-Path $TestDrive ("inst-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'engine\_shared'), (Join-Path $root 'config'), (Join-Path $root 'launcher\endpoint'), (Join-Path $root 'logs') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'VERSION'), $Version)
        foreach ($c in $script:ClientFiles) { Copy-Item -LiteralPath (Join-Path $script:SIRoot $c) -Destination (Join-Path $root $c) }
        [IO.File]::WriteAllText((Join-Path $root 'engine\a.ps1'), "# engine a $Version")
        [IO.File]::WriteAllText((Join-Path $root 'engine\old-only.ps1'), '# only in the old version')
        [IO.File]::WriteAllText((Join-Path $root 'config\SecurityInsight.custom.ps1'), '$global:Mine = 1  # the customer''s')
        [IO.File]::WriteAllText((Join-Path $root 'launcher\endpoint\LauncherConfig.custom.ps1'), '# customer launcher')
        [IO.File]::WriteAllText((Join-Path $root 'config\my-rules.custom.yaml'), 'mine: true')
        [IO.File]::WriteAllText((Join-Path $root 'logs\run.log'), 'log')
        if ($Ring) { [IO.File]::WriteAllText((Join-Path $root 'config\update.custom.json'), ('{{ "ring": {0} }}' -f $Ring)) }
        $root
    }
    # The world: channel text, URL -> zip, tasks, container exit code, an extra health check.
    function script:New-World([string]$Channel, [hashtable]$Files = @{}, [object[]]$Tasks = @(), [int]$ContainerExit = 0, $Health = $null) {
        $w = @{ Channel = $Channel; Files = $Files; Downloads = (New-Object System.Collections.Generic.List[string]); Disabled = (New-Object System.Collections.Generic.List[string]); Enabled = (New-Object System.Collections.Generic.List[string]); ContainerCalls = 0 }
        $w.Seams = @{
            # Invardia's Community route, faked: GET .../community/<ring> -> 200 + the ring's signed entry, 204 when none; a
            # Channel that is no JSON is answered as it is (refused); $w.Status forces an answer
            GetManifest = { param($u)
                            if ($w.Status) { return [pscustomobject]@{ Status = [int]$w.Status; Body = '' } }
                            $c = $null; try { $c = $w.Channel | ConvertFrom-Json -ErrorAction Stop } catch { $c = $null }
                            if (-not $c -or -not $c.PSObject.Properties['rings']) { return [pscustomobject]@{ Status = 200; Body = [string]$w.Channel } }
                            $e = $c.rings.PSObject.Properties[($u -split '/')[-1]]
                            if (-not $e) { return [pscustomobject]@{ Status = 204; Body = '' } }
                            [pscustomobject]@{ Status = 200; Body = ($e.Value | ConvertTo-Json -Depth 6) } }.GetNewClosure()
            Download = { param($u, $f) $w.Downloads.Add($u); if (-not $w.Files.ContainsKey($u)) { throw "404 $u" }; Copy-Item -LiteralPath $w.Files[$u] -Destination $f -Force }.GetNewClosure()
            GetTasks = { param($r) $Tasks }.GetNewClosure()
            DisableTask = { param($t) $w.Disabled.Add($t.TaskName) }.GetNewClosure()
            EnableTask = { param($t) $w.Enabled.Add($t.TaskName) }.GetNewClosure()
            ContainerUpdate = { param($r) $w.ContainerCalls++; $ContainerExit }.GetNewClosure()
            HealthCheck = $Health
        }
        $w
    }
    function script:Run($root, $w, [hashtable]$More = @{}) { Invoke-SICommunityUpdate -Root $root -Seams $w.Seams -TrustedKeys $script:Keys @More }
    function script:Url([string]$v) { "$($script:Host1)v$v/SecurityInsight-v$v.zip" }
}

Describe 'the signature and the archive' {
    It 'a valid signed entry for the ring updates the install; the customer''s files and run output are untouched' {
        $root = New-Install
        $before = Snapshot $root
        $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip }
        $r = Run $root $w
        $r.Action | Should -Be 'updated'; $r.ToVersion | Should -Be '3.1.0'
        [IO.File]::ReadAllText((Join-Path $root 'VERSION')) | Should -Be '3.1.0'
        [IO.File]::ReadAllText((Join-Path $root 'engine\a.ps1')) | Should -Match '3\.1\.0'
        foreach ($c in 'config\SecurityInsight.custom.ps1', 'launcher\endpoint\LauncherConfig.custom.ps1', 'config\my-rules.custom.yaml', 'logs\run.log') {
            (Hash (Join-Path $root $c)) | Should -Be $before[$c] -Because "$c is the customer's"
        }
        Test-Path (Join-Path $root 'config\SecurityInsight.custom.sample.ps1') | Should -BeTrue
        (Read-SICommunityUpdateState -Root $root).appliedSequence | Should -Be 5
        (Get-SICommunityRunningVersion -Root $root) | Should -Be '3.1.0'
    }
    It 'a zip with one top folder is applied the same way' {
        $root = New-Install; $zip = New-Release '3.1.0' -TopFolder
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip }
        (Run $root $w).Action | Should -Be 'updated'
    }
    It 'NEGATIVE: signed by a key the install does not trust -> refused, nothing downloaded, nothing changed' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5 -Signer $script:Other) }) @{ (Url '3.1.0') = $zip }
        $r = Run $root $w
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'does not verify'
        $w.Downloads.Count | Should -Be 0
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'NEGATIVE: the manifest changed after signing -> refused' {
        $root = New-Install; $zip = New-Release '3.1.0'
        $e = New-Entry $zip '3.1.0' 3 5
        $evil = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($e.manifestB64)).Replace('"sequence":5', '"sequence":50')
        $e.manifestB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($evil))
        (Run $root (New-World (New-Channel @{ 3 = $e }) @{ (Url '3.1.0') = $zip })).Action | Should -Be 'refused'
    }
    It 'NEGATIVE: an empty trust list refuses everything' {
        $root = New-Install; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip }
        (Invoke-SICommunityUpdate -Root $root -Seams $w.Seams -TrustedKeys @()).Action | Should -Be 'refused'
    }
    It 'NEGATIVE: a REPLAYED (lower-sequence) manifest is refused; the same sequence is current' {
        $root = New-Install; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip }
        (Run $root $w).Action | Should -Be 'updated'
        (Run $root $w).Action | Should -Be 'current'
        $old = New-Release '3.1.1'
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $old '3.1.1' 3 4) }) @{ (Url '3.1.1') = $old })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'REPLAY'
    }
    It 'NEGATIVE: the archive is not the signed SIZE -> refused, nothing changed' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $e = New-Entry $zip '3.1.0' 3 5 -Extra @{ size = ((Get-Item $zip).Length + 1) }
        $r = Run $root (New-World (New-Channel @{ 3 = $e }) @{ (Url '3.1.0') = $zip })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'bytes'
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'NEGATIVE: the archive is not the signed SHA-256 -> refused, nothing changed' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'; $other = New-Release '3.1.0' -Extra @{ 'x.txt' = 'other' }
        $e = New-Entry $zip '3.1.0' 3 5 -Extra @{ size = (Get-Item $other).Length }
        $r = Run $root (New-World (New-Channel @{ 3 = $e }) @{ (Url '3.1.0') = $other })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'SHA-256'
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'NEGATIVE: a link off the release host, a release without the update client, and an unsafe zip path are refused' {
        $root = New-Install; $before = Snapshot $root
        $zip = New-Release '3.1.0'
        (Run $root (New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5 -Url 'http://evil.example/si.zip') }) @{ 'http://evil.example/si.zip' = $zip })).Reason | Should -Match '(?i)https|release host'
        $nc = New-Release '3.1.0' -NoClient
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $nc '3.1.0' 3 5) }) @{ (Url '3.1.0') = $nc })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'update client'
        $slip = New-Release '3.1.0' -Slip
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $slip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $slip })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match 'unsafe path'
        Same $before (Snapshot $root) | Should -BeTrue
        Test-Path (Join-Path (Split-Path $root) 'evil.ps1') | Should -BeFalse
    }
    It 'NEGATIVE: the archive says another version than the signed manifest -> refused' {
        $root = New-Install; $zip = New-Release '3.1.1'
        (Run $root (New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip })).Reason | Should -Match 'says it is 3\.1\.1'
    }
}

Describe 'ring gating' {
    It 'a ring-3 install (the default) STAYS on 2.2 when only ring 2 is open' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 2 = (New-Entry $zip '3.1.0' 2 5) }) @{ (Url '3.1.0') = $zip }
        $r = Run $root $w
        $r.Action | Should -Be 'none'; $r.Ring | Should -Be 3
        $r.Reason | Should -Match 'nothing is released to ring 3'
        $w.Downloads.Count | Should -Be 0
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'a ring-2 install (config\update.custom.json) takes the ring-2 release' {
        $root = New-Install -Ring 2; $zip = New-Release '3.1.0'
        $r = Run $root (New-World (New-Channel @{ 2 = (New-Entry $zip '3.1.0' 2 5) }) @{ (Url '3.1.0') = $zip })
        $r.Action | Should -Be 'updated'; $r.Ring | Should -Be 2
        Test-Path (Join-Path $root 'config\update.custom.json') | Should -BeTrue
    }
    It 'a ring-2 install takes ring 2 even when ring 3 holds an older version; a ring-3 install takes ring 3''s' {
        $z2 = New-Release '3.1.0'; $z3 = New-Release '3.0.2'
        $ch = New-Channel @{ 2 = (New-Entry $z2 '3.1.0' 2 6); 3 = (New-Entry $z3 '3.0.2' 3 5) }
        $files = @{ (Url '3.1.0') = $z2; (Url '3.0.2') = $z3 }
        $a = New-Install -Ring 2; (Run $a (New-World $ch $files)).ToVersion | Should -Be '3.1.0'
        $b = New-Install; (Run $b (New-World $ch $files)).ToVersion | Should -Be '3.0.2'
    }
    It 'NEGATIVE: the ring-2 entry pasted into ring 3''s slot is refused (the signed ring is bound to the slot)' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 2 5) }) @{ (Url '3.1.0') = $zip })
        $r.Action | Should -Be 'refused'; $r.Reason | Should -Match "signed for ring '2'"
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'ring 1 (internal) and nonsense are never read from the channel: they fall back to ring 3 and say so' {
        $root = New-Install; [IO.File]::WriteAllText((Join-Path $root 'config\update.custom.json'), '{ "ring": 1 }')
        $s = Get-SICommunityUpdateSettings -Root $root
        $s.Ring | Should -Be 3; ($s.Problems -join ' ') | Should -Match 'not a Community ring'
    }
}

Describe 'holds: minFromVersion and manualStep' {
    It 'minFromVersion newer than this install HOLDS with the reason, and nothing is downloaded' {
        $root = New-Install -Version '3.0.0'; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5 -Extra @{ minFromVersion = '3.0.1' }) }) @{ (Url '3.1.0') = $zip }
        $r = Run $root $w
        $r.Action | Should -Be 'hold'; $r.Reason | Should -Match '3\.0\.1'
        $w.Downloads.Count | Should -Be 0
        $r2 = Run (New-Install -Version '3.0.1') $w
        $r2.Action | Should -Be 'updated'
    }
    It 'manualStep HOLDS until that exact sequence is accepted; accepting another sequence does not release it' {
        $root = New-Install; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 7 -Extra @{ manualStep = 'grant the new permission first' }) }) @{ (Url '3.1.0') = $zip }
        (Run $root $w).Reason | Should -Match 'grant the new permission'
        (Run $root $w @{ AcceptManualStepSequence = 6 }).Action | Should -Be 'hold'
        (Run $root $w @{ AcceptManualStepSequence = 7 }).Action | Should -Be 'updated'
    }
    It 'an accepted manual step still HOLDS on minFromVersion' {
        $root = New-Install -Version '3.0.0'; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 7 -Extra @{ manualStep = 'x'; minFromVersion = '3.0.1' }) }) @{ (Url '3.1.0') = $zip }
        (Run $root $w @{ AcceptManualStepSequence = 7 }).Action | Should -Be 'hold'
    }
    It 'a rollback is a NEW, higher sequence naming an older version, and it is applied' {
        $root = New-Install; $z1 = New-Release '3.1.1'; $z0 = New-Release '3.1.0'
        (Run $root (New-World (New-Channel @{ 3 = (New-Entry $z1 '3.1.1' 3 5) }) @{ (Url '3.1.1') = $z1 })).Action | Should -Be 'updated'
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $z0 '3.1.0' 3 6) }) @{ (Url '3.1.0') = $z0 })
        $r.Action | Should -Be 'updated'; $r.ToVersion | Should -Be '3.1.0'; ($r.Log -join ' ') | Should -Match 'ROLLBACK'
    }
}

Describe 'VM apply: backup, health check, rollback, tasks' {
    It 'a FAILED health check restores the previous version byte for byte, and resumes the paused tasks' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0' -Extra @{ 'engine\new.ps1' = '# new' }
        $tasks = @([pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = 'endpoint'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = "-File $root\launcher\x.ps1" })
        $bad = { param($r, $v) [pscustomobject]@{ Ok = $false; Reason = 'simulated failure' } }
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip } -Tasks $tasks -Health $bad
        $r = Run $root $w
        $r.Action | Should -Be 'rolledback'; $r.Reason | Should -Match 'simulated failure'; $r.Reason | Should -Match 'restored and verified'
        Same $before (Snapshot $root) | Should -BeTrue
        Test-Path (Join-Path $root 'engine\new.ps1') | Should -BeFalse
        @($w.Disabled) | Should -Be @('endpoint'); @($w.Enabled) | Should -Be @('endpoint')
        (Read-SICommunityUpdateState -Root $root).appliedSequence | Should -Be 0
    }
    It 'a release whose script does not parse is rolled back by the built-in health check' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0' -Extra @{ 'engine\broken.ps1' = 'function x {' }
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip })
        $r.Action | Should -Be 'rolledback'; $r.Reason | Should -Match 'does not parse'
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'a FAILED container step (it restores the image itself) rolls the files back too' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip } -ContainerExit 1
        $r = Run $root $w
        $r.Action | Should -Be 'rolledback'; $r.Reason | Should -Match 'container update failed'
        $w.ContainerCalls | Should -Be 1
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It '-SkipContainerUpdate does not run the container step' {
        $root = New-Install; $zip = New-Release '3.1.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip } -ContainerExit 1
        (Run $root $w @{ SkipContainerUpdate = $true }).Action | Should -Be 'updated'
        $w.ContainerCalls | Should -Be 0
    }
    It 'a RUNNING engine task makes the update wait (nothing changed); the task running the update is never a blocker' {
        $root = New-Install; $before = Snapshot $root; $zip = New-Release '3.1.0'
        $self = [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = 'SecurityInsight (flow)'; State = 'Running'; Execute = 'powershell.exe'; Arguments = "-File $root\engine\flow\Invoke-SIJobFlowRun.ps1" }
        $busy = [pscustomobject]@{ TaskPath = '\'; TaskName = 'identity'; State = 'Running'; Execute = 'powershell.exe'; Arguments = "-File $root\launcher\identity\launcher.ps1" }
        $ch = New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }
        $r = Run $root (New-World $ch @{ (Url '3.1.0') = $zip } -Tasks @($self, $busy))
        $r.Action | Should -Be 'waiting'; Same $before (Snapshot $root) | Should -BeTrue
        $w = New-World $ch @{ (Url '3.1.0') = $zip } -Tasks @($self)
        (Run $root $w).Action | Should -Be 'updated'
        $w.Disabled.Count | Should -Be 0
    }
    It 'the next update removes files the new release no longer has -- never a customer file' {
        $root = New-Install; $z1 = New-Release '3.1.0' -Extra @{ 'engine\dropped.ps1' = '# goes away' }
        (Run $root (New-World (New-Channel @{ 3 = (New-Entry $z1 '3.1.0' 3 5) }) @{ (Url '3.1.0') = $z1 })).Action | Should -Be 'updated'
        Test-Path (Join-Path $root 'engine\old-only.ps1') | Should -BeTrue -Because 'the first update by the channel keeps files it did not install'
        $z2 = New-Release '3.1.1'
        (Run $root (New-World (New-Channel @{ 3 = (New-Entry $z2 '3.1.1' 3 6) }) @{ (Url '3.1.1') = $z2 })).Action | Should -Be 'updated'
        Test-Path (Join-Path $root 'engine\dropped.ps1') | Should -BeFalse
        Test-Path (Join-Path $root 'config\SecurityInsight.custom.ps1') | Should -BeTrue
        Test-Path (Join-Path $root 'config\my-rules.custom.yaml') | Should -BeTrue
    }
    It 'the FIRST update removes the files the release lists as retired -- only unchanged shipped copies (CRLF or LF), never a changed or customer file' {
        $root = New-Install
        # what an earlier release shipped: two files the new release no longer has, one of them checked out with CRLF
        [IO.File]::WriteAllText((Join-Path $root 'engine\Ensure-Module.ps1'), "# installs modules`r`nInstall-Module X`r`n")
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'viewer') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'viewer\Start-Viewer.ps1'), "# viewer`n")
        [IO.File]::WriteAllText((Join-Path $root 'engine\Changed.ps1'), "# shipped, then edited by the customer`n")
        $h = @{
            'engine/Ensure-Module.ps1' = @(Get-SICommunityShippedFileHash -Bytes ([Text.Encoding]::UTF8.GetBytes("# installs modules`nInstall-Module X`n")))
            'viewer/Start-Viewer.ps1'  = @(Get-SICommunityShippedFileHash -Bytes ([Text.Encoding]::UTF8.GetBytes("# viewer`n")))
            'engine/Changed.ps1'       = @(Get-SICommunityShippedFileHash -Bytes ([Text.Encoding]::UTF8.GetBytes("# shipped`n")))
            'config/SecurityInsight.custom.ps1' = @(Get-SICommunityShippedFileHash -Path (Join-Path $root 'config\SecurityInsight.custom.ps1'))
            'engine/a.ps1'             = @('0' * 64)
        }
        $manifest = ([ordered]@{ schema = 1; files = $h } | ConvertTo-Json -Depth 4)
        $zip = New-Release '3.1.0' -Extra @{ 'engine\_shared\SI-PreviousReleaseFiles.locked.json' = $manifest }
        $r = Run $root (New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip })
        $r.Action | Should -Be 'updated'
        Test-Path (Join-Path $root 'engine\Ensure-Module.ps1') | Should -BeFalse -Because 'an unchanged shipped copy (here with CRLF) is retired'
        Test-Path (Join-Path $root 'viewer\Start-Viewer.ps1') | Should -BeFalse
        Test-Path (Join-Path $root 'engine\Changed.ps1') | Should -BeTrue -Because 'a changed copy is never removed'
        Test-Path (Join-Path $root 'config\SecurityInsight.custom.ps1') | Should -BeTrue -Because 'a customer file is never removed, even when listed'
        Test-Path (Join-Path $root 'engine\a.ps1') | Should -BeTrue -Because 'a file the release ships is never removed'
        Test-Path (Join-Path $root 'engine\old-only.ps1') | Should -BeTrue -Because 'a file the list does not name stays'
        ($r.Log -join "`n") | Should -Match '2 file\(s\) of the previous version that this release no longer has were removed'
        ($r.Log -join "`n") | Should -Match '1 file\(s\) .* left in place because they were changed'
        Test-Path (Join-Path $root '.si-update\b\3.0.1\engine\Ensure-Module.ps1') | Should -BeTrue -Because 'what is removed is in the backup'
    }
    It 'NEGATIVE: a failed health check puts the retired files back, byte for byte' {
        $root = New-Install
        [IO.File]::WriteAllText((Join-Path $root 'engine\Ensure-Module.ps1'), "# installs modules`n")
        $before = Snapshot $root
        $h = @{ 'engine/Ensure-Module.ps1' = @(Get-SICommunityShippedFileHash -Path (Join-Path $root 'engine\Ensure-Module.ps1')) }
        $zip = New-Release '3.1.0' -Extra @{ 'engine\_shared\SI-PreviousReleaseFiles.locked.json' = ([ordered]@{ schema = 1; files = $h } | ConvertTo-Json -Depth 4) }
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5) }) @{ (Url '3.1.0') = $zip } -Health { param($r, $v) [pscustomobject]@{ Ok = $false; Reason = 'test' } }
        (Run $root $w).Action | Should -Be 'rolledback'
        Same $before (Snapshot $root) | Should -BeTrue
    }
    It 'the shipped retired-files list names no file this release ships and no customer file, and is valid' {
        $p = Join-Path $script:SIRoot 'engine\_shared\SI-PreviousReleaseFiles.locked.json'
        if (-not (Test-Path -LiteralPath $p)) { Set-ItResult -Skipped -Because 'the 2.2 hand-over carries the client, not the list'; return }
        $doc = [IO.File]::ReadAllText($p) | ConvertFrom-Json
        $doc.schema | Should -Be 1
        $names = @($doc.files.PSObject.Properties.Name)
        $names.Count | Should -BeGreaterThan 0
        # a listed file still in this tree must be one the Community release leaves out (solution.publish.json excludePaths)
        $pubFile = Join-Path $script:SIRoot 'solution.publish.json'
        $ex = if (Test-Path -LiteralPath $pubFile) { @(([IO.File]::ReadAllText($pubFile) | ConvertFrom-Json).excludePaths | ForEach-Object { "$_".Trim('/') }) } else { @() }
        foreach ($n in $names) {
            if (Test-Path -LiteralPath (Join-Path $script:SIRoot $n)) {
                @($ex | Where-Object { $n -eq $_ -or $n.StartsWith($_ + '/') }).Count | Should -BeGreaterThan 0 -Because "$n is in this tree, so the Community release must leave it out"
            }
            Test-SICommunityCustomerPath $n | Should -BeFalse -Because $n
            foreach ($x in @($doc.files.$n)) { $x | Should -Match '^[0-9a-f]{64}$' }
        }
    }
}

Describe 'Invardia''s Community route (owner + Invardia + PIM, 2026-10-28)' {
    It 'reads GET <base>/api/updates/securityinsight/community/<ring>; 204 = none, 404 = refused, another status = network' {
        Get-SICommunityManifestUri -BaseUrl 'https://invardia.com/' -Ring 2 | Should -BeExactly 'https://invardia.com/api/updates/securityinsight/community/2'
        $root = New-Install
        $w = New-World (New-Channel @{}) @{}
        (Run $root $w).Action | Should -Be 'none'
        $w.Status = 404; (Run $root $w).Action | Should -Be 'refused'
        $w.Status = 503; (Run $root $w).Action | Should -Be 'network'
        (Run $root (New-World 'not json')).Action | Should -Be 'refused'
    }
    It 'a manifest of another product or kind is refused before any download' {
        foreach ($x in @(@{ product = 'pim4entraps' }, @{ kind = 'code' })) {
            $root = New-Install; $zip = New-Release '3.1.0'
            $w = New-World (New-Channel @{ 3 = (New-Entry $zip '3.1.0' 3 5 -Extra $x) }) @{ (Url '3.1.0') = $zip }
            (Run $root $w).Action | Should -Be 'refused'
            $w.Downloads.Count | Should -Be 0
        }
    }
    It 'the channel.json reader on an update-channel branch is gone (retired 2026-10-28)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-CommunityUpdate.ps1'))
        $src | Should -Not -Match 'function Read-SICommunityChannel|function Get-SICommunityRingEntry|raw\.githubusercontent\.com'
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\Publish-SIUpdateChannel.ps1') | Should -BeFalse
    }
}

Describe 'owner 2026-10-28: no update crosses a major version' {
    It 'a release of another major version is refused before anything is downloaded; an unreadable installed version fails closed' {
        $root = New-Install -Version '3.1.0'; $zip = New-Release '4.0.0'
        $w = New-World (New-Channel @{ 3 = (New-Entry $zip '4.0.0' 3 9) }) @{ (Url '4.0.0') = $zip }
        $r = Run $root $w
        $r.Action | Should -Be 'refused'
        $r.Reason | Should -Match 'another major version'
        Test-SICommunityMajorVersion -Installed '2.2.460' -Release '3.0.0' | Should -Match 'another major version'
        Test-SICommunityMajorVersion -Installed '3.0.0.202610261957' -Release '3.2.0' | Should -BeNullOrEmpty
        Test-SICommunityMajorVersion -Installed '' -Release '3.0.0' | Should -Match 'cannot be read'
    }
}

Describe 'scope and no git' {
    It 'an AutomateIT tree (Sync-AutomateIT) and a Pro tree are never updated from the community channel' {
        $top = Join-Path $TestDrive 'ait'; $sol = Join-Path $top 'SOLUTIONS\SecurityInsight'
        New-Item -ItemType Directory -Force -Path (Join-Path $top 'bootstrap'), $sol | Out-Null
        [IO.File]::WriteAllText((Join-Path $top 'bootstrap\Sync-AutomateIT.json'), '{}'); [IO.File]::WriteAllText((Join-Path $sol 'VERSION'), '3.0.0')
        $w = New-World 'unused'
        (Run $sol $w).Action | Should -Be 'not-community'
        # a Pro tree = a file only the Pro package carries (since 2026-10-27, #750: not LICENSE-* / engine\pro-*, which the
        # Community edition ships too)
        foreach ($m in 'setup\_shared\SI-GuidedInstallPro.ps1', 'engine\_shared\SI-InvardiaUpdate.ps1', 'engine\asset-cmdb\Invoke-SICmdb.ps1') {
            $pro = New-Install; $p = Join-Path $pro $m; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; [IO.File]::WriteAllText($p, '# pro')
            (Run $pro $w).Action | Should -Be 'not-community' -Because "$m marks the Pro package"
        }
    }
    It 'a Community v3 tree with LICENSE-PRO and the database folders (engine\pro-settings, engine\pro-data) IS a Community install (#750)' {
        $root = New-Install -Version '3.1.0'
        [IO.File]::WriteAllText((Join-Path $root 'LICENSE-PRO'), 'the paid web pages')
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'engine\pro-settings'), (Join-Path $root 'engine\pro-data') | Out-Null
        Get-SICommunityInstallKind -Root $root | Should -Be 'community'
    }
    It 'the client never runs git (no git command in its code)' {
        foreach ($c in $script:ClientFiles) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $c), [ref]$null, [ref]$null)
            $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '(?i)^git(\.exe)?$' })
            $cmds.Count | Should -Be 0 -Because "$c must not need git"
        }
    }
    It 'Update-SecurityInsight.ps1 runs in a fresh process with NO git on PATH (the manifest read from a local folder; nothing released -> exit 0)' {
        $root = New-Install
        $ch = Join-Path $TestDrive 'manifests-empty'; New-Item -ItemType Directory -Force -Path $ch | Out-Null
        $exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $prev = $env:PATH
        try {
            $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$(Split-Path -Parent $exe)"
            (Get-Command git -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
            $out = & $exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Update-SecurityInsight.ps1') -BaseUrl $ch 2>&1
            $code = $LASTEXITCODE
        } finally { $env:PATH = $prev }
        $code | Should -Be 0
        ($out -join "`n") | Should -Match 'nothing is released to ring 3'
    }
}
