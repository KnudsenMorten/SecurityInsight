#Requires -Version 5.1
<#
    framework SEC-LANE-1 (owner 2026-11-14: "they pull down as today") -- THE SHORT IMAGE-ONLY UPDATE PATH of caj-si-updater
    (container/updater/_shared/SI-UpdaterImageOnly.ps1, wired in _shared/SI-UpdaterInvardia.ps1; the release script's
    setup/Invoke-SIContainerUpdate.ps1 -ImageOnly) and the clean-up switch that clears itself (SI-UpdaterImagePrune.ps1
    Invoke-SIUpdaterPruneSwitchClear).

    What must hold:
      * an image-only release (a fourth version part on what runs + the image patch's What's new + the SAME engine code +
        a script with the image-only mode) takes the short path; anything else takes the full path, unchanged;
      * the short path NEVER asks the run gate, never runs the database / template / size steps (Invoke-SIUpdaterRoll is
        never called), never stops an execution, and swaps the parts in order: engine jobs, web app, record, updater LAST;
      * a part that fails says where and why (the drift reason), records it, and the record of what runs is not written;
      * after a healthy swap the clean-up is asked with healthy = true; after one that is not proven, with false;
      * the release script's -ImageOnly mode pins by digest and runs none of the steps after the roll (its source);
      * SI_UPDATER_IMAGE_PRUNE=off on the updater's own job is taken away by the updater (3.1.14+), read back, once.
    Offline: fake Invardia answers, a fake vault, a fake Pro database, mocked Azure. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:TestBase = 'https://invardia.test'
    $script:PrevBase = $env:SI_UPDATER_INVARDIA_BASE_URL
    $env:SI_UPDATER_INVARDIA_BASE_URL = $script:TestBase
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-GuardStrict.ps1')
    Mock Invoke-WebRequest { throw 'no network in tests' }
    Mock Invoke-RestMethod { throw 'no network in tests' }

    $script:Key = 'inv-' + ('t' * 24)   # a fake install key (built, so no scanner reads it as a secret)
    $script:Licence = '{"licence":"TEST-LICENCE-TEXT"}'
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    function script:ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $pub = $script:Rsa.ExportParameters($false)
    $script:Trusted = @(ConvertFrom-SIInvardiaKeyEntry -Entry ([pscustomobject]@{ keyId = 'test-update-key-1'; jwk = [pscustomobject]@{ kty = 'RSA'; n = (ConvertTo-B64Url $pub.Modulus); e = (ConvertTo-B64Url $pub.Exponent) } }))

    # A release archive: VERSION, an engine file, (optionally) the image patch's What's new and an update script stub that
    # records how it was called (-ImageOnly or not) in $global:IOOrder. Returns @{ Zip; EngineHash }.
    function script:New-IOZip([string]$Version, [string]$WhatsNewType = 'security', [string]$EngineText = 'Write-Host engine', [switch]$NoImageOnlyMode) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-io-src-' + [guid]::NewGuid().ToString('N'))
        $si = Join-Path $src "securityinsight-src-$Version\SOLUTIONS\SecurityInsight"
        foreach ($d in 'setup', 'engine', 'whats-new') { New-Item -ItemType Directory -Force (Join-Path $si $d) | Out-Null }
        Set-Content -LiteralPath (Join-Path $si 'VERSION') -Value $Version -NoNewline
        Set-Content -LiteralPath (Join-Path $si 'engine\Invoke-X.ps1') -Value $EngineText -NoNewline
        if ($WhatsNewType) { Set-Content -LiteralPath (Join-Path $si "whats-new\$Version.json") -Value (('{{"version":"{0}","type":"{1}"}}' -f $Version, $WhatsNewType)) }
        $p = if ($NoImageOnlyMode) { 'param([switch]$Apply, $ResourceGroupName, $AcrName, $SubscriptionId)' } else { 'param([switch]$Apply, [switch]$ImageOnly, $ResourceGroupName, $AcrName, $SubscriptionId)' }
        $io = if ($NoImageOnlyMode) { '$false' } else { '$ImageOnly' }
        Set-Content -LiteralPath (Join-Path $si 'setup\Invoke-SIContainerUpdate.ps1') -Value ($p + "`n" + ('$global:IOOrder.Add("engine imageonly=" + [bool]{0})' -f $io) + "`nexit 0")
        $hash = Get-SIEngineFingerprint -SIRoot $si
        $zip = Join-Path ([IO.Path]::GetTempPath()) ('si-io-' + [guid]::NewGuid().ToString('N') + '.zip')
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        Remove-Item -LiteralPath $src -Recurse -Force
        [pscustomobject]@{ Zip = $zip; EngineHash = $hash }
    }
    function script:New-IOAnswer([string]$Version, [string]$File, [long]$Sequence = 7) {
        $m = [ordered]@{ product = 'securityinsight'; kind = 'code'; ring = 1; sequence = $Sequence; version = $Version; archive = "securityinsight-src-$Version.zip"
                         sha256 = (Get-SIInvardiaFileSha256 -Path $File); size = (Get-Item -LiteralPath $File).Length; image = $null; minFromVersion = $null
                         notes = 'test'; manualStep = $null; releasedAt = '2026-11-14T08:00:00Z' }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $script:Rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $body = ([ordered]@{ manifest = $m; manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key-1'
                             downloadUrl = "$($script:TestBase)/api/updates/securityinsight/code/$Version/archive?t=DLTOKEN" }) | ConvertTo-Json -Compress -Depth 5
        [pscustomobject]@{ Status = 200; Body = $body; RetryAfter = 0; Error = '' }
    }
    # a fake Pro database: the recorded engine fingerprint answers its read; every statement is kept
    function script:New-IOStore([string]$EngineHash) {
        # what the tests read: the cfg.InstallState values written (name -> value) and the schema statements counted --
        # recorded as the statements arrive (plain strings, no parameter object kept)
        $st = @{ Writes = @{}; Schema = 0; Sql = (New-Object System.Collections.Generic.List[string]) }
        $fp = ('{{"hash":"{0}","version":"3.0.1"}}' -f $EngineHash)
        [pscustomobject]@{ State = $st; Name = 'fake'; Server = ''; Database = ''
            Invoke = { param($q, $p, $m)
                       $st.Sql.Add([string]$q)
                       if ("$q" -match '(?i)\bCREATE\s+TABLE|ALTER\s+TABLE') { $st.Schema++ }
                       if ($p -is [System.Collections.IDictionary]) {
                           try {
                               $n = $null; $v = $null
                               foreach ($e in $p.GetEnumerator()) { if ("$($e.Key)" -eq 'Name') { $n = "$($e.Value)" } elseif ("$($e.Key)" -eq 'Value') { $v = "$($e.Value)" } }
                               if ($n -and $null -ne $v) { $st.Writes[$n] = $v }
                           } catch { $st.Writes['__error'] = $_.Exception.Message }
                       }
                       if ($m -eq 'reader' -and "$q" -like "*N'EngineFingerprint'*" -and $fp -notlike '*""*') { return , @(@{ Value = $fp }) }
                       , @() }.GetNewClosure() }
    }
    function script:New-IOWorld($Zip, [string]$Version) {
        $w = @{ Vault = @{ 'SI-Invardia-InstallKey' = $script:Key; 'SI-License' = $script:Licence }; Gate = (New-Object System.Collections.Generic.List[string])
                Sizings = (New-Object System.Collections.Generic.List[string]); PostRolls = (New-Object System.Collections.Generic.List[string]); Prunes = (New-Object System.Collections.Generic.List[object]); Pendings = (New-Object System.Collections.Generic.List[string]) }
        $answer = New-IOAnswer -Version $Version -File $Zip
        $w.Seams = @{
            Http = { param($u, $b, $k, $h) $kind = ($b | ConvertFrom-Json).kind; if ($kind -eq 'code') { $answer } else { [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } } }.GetNewClosure()
            Download = { param($u, $f) Copy-Item -LiteralPath $Zip -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }.GetNewClosure()
            ReadSecret = { param($n) $w.Vault[$n] }.GetNewClosure()
            WriteSecret = { param($n, $v) $w.Vault[$n] = $v }.GetNewClosure()
            TrustedKeys = { $script:Trusted }
            TenantId = { '11111111-2222-3333-4444-555555555555' }
            PreRoll = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = [pscustomobject]@{ LoginServer = 'reg.example.io'; UpdaterId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'; UpdaterImage = 'reg.example.io/si-updater:v3.0.1-build'; Record = $null } } }
            PostRoll = { param($si, $v, $c) $w.PostRolls.Add($v); [pscustomobject]@{ Code = 0; Text = "post-roll $v" } }.GetNewClosure()
            SelfRetry = { $null }
            SizingPass = { param($why) $w.Sizings.Add([string]$why); $true }.GetNewClosure()
            RunGate = { param($holder) $w.Gate.Add('asked'); [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no run is going'; RunId = ''; LockTaken = $false; Holder = '' } }.GetNewClosure()
            ImageOnlyPrune = { param($healthy) $w.Prunes.Add([bool]$healthy) }.GetNewClosure()
            ImageOnlyPendingPrune = { $w.Pendings.Add('checked') }.GetNewClosure()
        }
        $w
    }
    # the value the updater last wrote into cfg.InstallState -Name (Save-SIUpdaterInstallStateValue: @{ Name; Value; By }); ''
    # = none. Only dictionary parameters are looked at (other statements carry other shapes).
    function script:Get-IOStateRow($Store, [string]$Name) {
        $w = $Store.State.Writes
        if ($w.ContainsKey($Name)) { return [string]$w[$Name] }
        ''
    }
    function script:Invoke-IORun($World, $Store, [string]$Deployed = '3.0.1') {
        $e = @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_UPDATER_RING = '1' }
        $World.Seams.Now = { [datetime]'2026-11-14T10:00:00Z' }
        $log = @(Invoke-SIUpdaterFromInvardia -Env $e -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Store $Store -Deployed $Deployed `
                    -SIRoot $script:SIRoot -Seams $World.Seams -Work (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) 6>&1 | ForEach-Object { $_ })
        [pscustomobject]@{ Code = (@($log | Where-Object { $_ -is [int] }) | Select-Object -Last 1); Log = (@($log | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n")
                           State = (ConvertFrom-SIInvardiaUpdateState -Json $World.Vault['SI-Update-State']) }
    }
}
AfterAll {
    $env:SI_UPDATER_INVARDIA_BASE_URL = $script:PrevBase
    if ($script:Rsa) { $script:Rsa.Dispose() }
    Remove-Variable -Name IOOrder -Scope Global -ErrorAction SilentlyContinue
}

Describe 'the image-only decision (Get-SIUpdaterImageOnlyDecision)' {
    BeforeAll { $script:Z = New-IOZip -Version '3.0.1.1'; $script:Root = Join-Path $TestDrive 'rel'
                $null = Expand-SIUpdaterSolution -ZipPath $script:Z.Zip -Destination $script:Root }
    It 'a fourth part on what runs + the What''s new of type security + the same engine code + the script''s mode = image-only' {
        $d = Get-SIUpdaterImageOnlyDecision -SIRoot $script:Root -Version '3.0.1.1' -Deployed '3.0.1' -RecordedHash $script:Z.EngineHash
        $d.ImageOnly | Should -BeTrue
        $d.Why | Should -Match 'image patch of the 3\.0\.1'
    }
    It 'NEGATIVE: a code release, another engine, no record of the engine, another What''s new, an older script = the full update' {
        (Get-SIUpdaterImageOnlyDecision -SIRoot $script:Root -Version '3.0.2' -Deployed '3.0.1' -RecordedHash $script:Z.EngineHash).ImageOnly | Should -BeFalse
        (Get-SIUpdaterImageOnlyDecision -SIRoot $script:Root -Version '3.0.1.1' -Deployed '3.0.1' -RecordedHash ('0' * 64)).Why | Should -Match 'engine code differs'
        (Get-SIUpdaterImageOnlyDecision -SIRoot $script:Root -Version '3.0.1.1' -Deployed '3.0.1' -RecordedHash '').Why | Should -Match 'not recorded'
        $f = New-IOZip -Version '3.0.1.1' -WhatsNewType 'feature'; $r2 = Join-Path $TestDrive 'rel2'; $null = Expand-SIUpdaterSolution -ZipPath $f.Zip -Destination $r2
        (Get-SIUpdaterImageOnlyDecision -SIRoot $r2 -Version '3.0.1.1' -Deployed '3.0.1' -RecordedHash $f.EngineHash).Why | Should -Match "not the image patch's 'security'"
        $o = New-IOZip -Version '3.0.1.1' -NoImageOnlyMode; $r3 = Join-Path $TestDrive 'rel3'; $null = Expand-SIUpdaterSolution -ZipPath $o.Zip -Destination $r3
        (Get-SIUpdaterImageOnlyDecision -SIRoot $r3 -Version '3.0.1.1' -Deployed '3.0.1' -RecordedHash $o.EngineHash).Why | Should -Match 'no image-only mode'
    }
    It 'the recorded engine fingerprint is read from cfg.InstallState ''EngineFingerprint''' {
        Read-SIUpdaterRecordedEngineHash -Store (New-IOStore ('A' * 64)) | Should -Be ('a' * 64)
        Read-SIUpdaterRecordedEngineHash -Store $null | Should -Be ''
    }
}

Describe 'the short path itself (Invoke-SIUpdaterImageOnly against seams)' {
    BeforeEach {
        $script:Order = New-Object System.Collections.Generic.List[string]
        $script:Seams = @{
            EngineSwap = { param($r) $script:Order.Add('engine'); [pscustomobject]@{ Code = 0; Stage = '4. VERIFY'; Failures = @(); Error = '' } }
            AppSwap    = { param($r, $t) $script:Order.Add('web'); [pscustomobject]@{ Code = 0; Text = 'ca-si-management runs src-x (healthy)' } }
            Record     = { param($v, $c) $script:Order.Add("record $v"); $true }
            SelfSwap   = { param($r, $t) $script:Order.Add("updater $t"); [pscustomobject]@{ Action = 'rolled'; Reason = 'moved' } }
        }
        $script:A = @{ SIRoot = $TestDrive; Version = '3.0.1.1'; Commit = ('c' * 40); ResourceGroup = 'rg'; AcrName = 'acr'; SubscriptionId = 'sub' }
    }
    It 'the parts in order: engine jobs, web app, the record, the updater LAST; done' {
        $r = Invoke-SIUpdaterImageOnly @script:A -Seams $script:Seams 6>$null
        $r.Code | Should -Be 0; $r.Result | Should -Be 'done'; $r.Component | Should -Be ''
        @($script:Order) | Should -Be @('engine', 'web', 'record 3.0.1.1', ('updater v3.0.1.1-' + ('c' * 12)))
        @($r.Parts) | Should -Be @('engine jobs', 'web app', 'updater')
    }
    It 'the engine build fails: build-failed at the engine jobs; nothing else is swapped, no record' {
        $script:Seams.EngineSwap = { param($r) $script:Order.Add('engine'); [pscustomobject]@{ Code = 1; Stage = '2. BUILD'; Failures = @(); Error = 'The image build did not succeed (Failed). No job was changed.' } }
        $r = Invoke-SIUpdaterImageOnly @script:A -Seams $script:Seams 6>$null
        $r.Code | Should -Be 1; $r.Result | Should -Be 'build-failed'; $r.Component | Should -Be 'engine jobs'; $r.Why | Should -Match 'image build did not succeed'
        @($script:Order) | Should -Be @('engine')
    }
    It 'the engine swap fails (a job did not read back): swap-failed; the web app and the updater keep their images' {
        $script:Seams.EngineSwap = { param($r) [pscustomobject]@{ Code = 1; Stage = '5. ROLLBACK'; Failures = @([pscustomobject]@{ Step = 'roll'; Code = 'si-upd-0805'; Text = 'caj-si-x reads back the old image' }); Error = '' } }
        $r = Invoke-SIUpdaterImageOnly @script:A -Seams $script:Seams 6>$null
        $r.Result | Should -Be 'swap-failed'; $r.Why | Should -Match 'reads back the old image'
        $script:Order.Count | Should -Be 0
    }
    It 'the web app fails: swap-failed at the web app; the updater is NOT moved and the record is NOT written (the next run retries)' {
        $script:Seams.AppSwap = { param($r, $t) $script:Order.Add('web'); [pscustomobject]@{ Code = 1; Text = 'ca-si-management: not healthy after 10 min' } }
        $r = Invoke-SIUpdaterImageOnly @script:A -Seams $script:Seams 6>$null
        $r.Code | Should -Be 1; $r.Result | Should -Be 'swap-failed'; $r.Component | Should -Be 'web app'
        @($script:Order) | Should -Be @('engine', 'web')
    }
    It 'the updater''s own move fails: the update is installed, the drift reason names the updater' {
        $script:Seams.SelfSwap = { param($r, $t) [pscustomobject]@{ Action = 'failed'; Reason = 'the updater job could not be pointed at it' } }
        $r = Invoke-SIUpdaterImageOnly @script:A -Seams $script:Seams 6>$null
        $r.Code | Should -Be 0; $r.Result | Should -Be 'swap-failed'; $r.Component | Should -Be 'updater'; $r.Why | Should -Match 'could not be pointed'
    }
    It 'the drift record fits cfg.InstallState (400 characters) and names version, result, component and why' {
        $v = ConvertTo-SIUpdaterImageOnlyValue -Result ([pscustomobject]@{ Result = 'swap-failed'; Component = 'web app'; Why = ('x' * 900) }) -Version '3.0.1.1' -From '3.0.1'
        $v.Length | Should -BeLessOrEqual 400
        $o = $v | ConvertFrom-Json
        $o.result | Should -Be 'swap-failed'; $o.component | Should -Be 'web app'; $o.version | Should -Be '3.0.1.1'; $o.from | Should -Be '3.0.1'
    }
}

Describe 'the updater run from Invardia: short path vs full path (Invoke-SIUpdaterFromInvardia)' {
    BeforeEach {
        $global:IOOrder = New-Object System.Collections.Generic.List[string]
        Mock Invoke-SIUpdaterAppRoll { $global:IOOrder.Add('web app images-only=' + [bool]$ImagesOnly); [pscustomobject]@{ Code = 0; Text = 'healthy' } }
        Mock Save-SIUpdaterInstalledRecord { $global:IOOrder.Add("record $Version"); $true }
        Mock Invoke-SIUpdaterSelfRoll { $global:IOOrder.Add('updater'); [pscustomobject]@{ Action = 'rolled'; Image = 'x'; Previous = $CurrentImage; Reason = 'moved' } }
        Mock Invoke-SIUpdaterArm { $global:IOOrder.Add("arm $Method $Path"); $null }
    }
    It 'an IMAGE-ONLY release: no run gate, no database / template / size step, no execution stopped; engine, web app, record, updater LAST' {
        Mock Invoke-SIUpdaterRoll { throw 'the full roll must not run for an image-only release' }
        try {
        $z = New-IOZip -Version '3.0.1.1'
        $w = New-IOWorld -Zip $z.Zip -Version '3.0.1.1'
        $st = New-IOStore $z.EngineHash
        $r = Invoke-IORun -World $w -Store $st
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'image-only: yes, the short image-only update path'
        $w.Gate.Count | Should -Be 0 -Because 'the run gate is never asked'
        $w.Sizings.Count | Should -Be 0 -Because 'no size step'
        $w.PostRolls.Count | Should -Be 0 -Because 'the full post-roll never runs'
        Should -Invoke Invoke-SIUpdaterRoll -Times 0 -Exactly -Scope It
        @($global:IOOrder | Where-Object { $_ -like 'arm POST*' -and $_ -like '*/stop*' }).Count | Should -Be 0 -Because 'a running execution is never stopped'
        @($global:IOOrder | Where-Object { $_ -notlike 'arm *' }) | Should -Be @('engine imageonly=True', 'web app images-only=True', 'record 3.0.1.1', 'updater')
        $w.Prunes.Count | Should -Be 1; [bool]$w.Prunes[0] | Should -BeTrue -Because 'a healthy swap records its pending clean-up'
        $w.Pendings.Count | Should -Be 0 -Because 'the run that swapped never cleans up: a job must succeed on the new image first'
        $r.State.code.appliedVersion | Should -Be '3.0.1.1'
        $row = Get-IOStateRow $st 'ImageOnlyUpdate'
        ($row | ConvertFrom-Json).result | Should -Be 'done'
        $st.State.Schema | Should -Be 0 -Because 'no schema step'
        $st.State.Writes.ContainsKey('__error') | Should -BeFalse
        } catch { throw ('{0} @ {1}' -f $_.Exception.Message, $_.ScriptStackTrace) }
    }
    It 'a web app that fails: exit 1, the drift reason recorded, the clean-up told the swap is NOT proven (nothing deleted)' {
        Mock Invoke-SIUpdaterAppRoll { [pscustomobject]@{ Code = 1; Text = 'ca-si-management: not healthy after 10 min' } }
        try {
        $z = New-IOZip -Version '3.0.1.1'
        $w = New-IOWorld -Zip $z.Zip -Version '3.0.1.1'
        $st = New-IOStore $z.EngineHash
        $r = Invoke-IORun -World $w -Store $st
        $r.Code | Should -Be 1
        $r.State.lastError | Should -Match 'image-only update 3\.0\.1\.1 swap-failed at the web app'
        $w.Prunes.Count | Should -Be 1; [bool]$w.Prunes[0] | Should -BeFalse
        Should -Invoke Save-SIUpdaterInstalledRecord -Times 0 -Exactly -Scope It
        $row = Get-IOStateRow $st 'ImageOnlyUpdate'
        ($row | ConvertFrom-Json).component | Should -Be 'web app'
        } catch { throw ('{0} @ {1}' -f $_.Exception.Message, $_.ScriptStackTrace) }
    }
    It 'a LATER run (the release runs already): the pending clean-up of the earlier swap is checked, nothing is swapped' {
        Mock Invoke-SIUpdaterImageOnly { throw 'nothing to swap' }
        $z = New-IOZip -Version '3.0.1.1'
        $w = New-IOWorld -Zip $z.Zip -Version '3.0.1.1'
        $r = Invoke-IORun -World $w -Store (New-IOStore $z.EngineHash) -Deployed '3.0.1.1'
        $r.Code | Should -Be 0
        $w.Pendings.Count | Should -Be 1
        $w.Prunes.Count | Should -Be 0
        Should -Invoke Invoke-SIUpdaterImageOnly -Times 0 -Exactly -Scope It
    }
    It 'NEGATIVE: a CODE release takes the full path -- the run gate asked, the release script run WITHOUT -ImageOnly' {
        $z = New-IOZip -Version '3.0.2' -WhatsNewType 'feature'
        $w = New-IOWorld -Zip $z.Zip -Version '3.0.2'
        $r = Invoke-IORun -World $w -Store $null
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'image-only: no, the full update'
        $w.Gate.Count | Should -Be 1
        @($global:IOOrder | Where-Object { $_ -like 'engine*' }) | Should -Be @('engine imageonly=False')
        $w.PostRolls.Count | Should -Be 1
        $w.Prunes.Count | Should -Be 0
    }
    It 'NEGATIVE: an image patch whose engine code differs from what runs takes the full path (the run gate, the full roll)' {
        Mock Invoke-SIUpdaterRoll { $global:IOOrder.Add('full roll'); [pscustomobject]@{ Code = 0; Held = $false; Reason = '' } }
        Mock Invoke-SIUpdaterImageOnly { throw 'the short path must not run' }
        $z = New-IOZip -Version '3.0.1.1'
        $w = New-IOWorld -Zip $z.Zip -Version '3.0.1.1'
        $r = Invoke-IORun -World $w -Store (New-IOStore ('f' * 64))
        $r.Log | Should -Match 'engine code differs'
        $w.Gate.Count | Should -Be 1
        @($global:IOOrder | Where-Object { $_ -notlike 'arm *' }) | Should -Be @('full roll')
        Should -Invoke Invoke-SIUpdaterImageOnly -Times 0 -Exactly -Scope It
        $w.Prunes.Count | Should -Be 0
    }
}

Describe 'the release script''s image-only mode (setup\Invoke-SIContainerUpdate.ps1 -ImageOnly, its source)' {
    BeforeAll { $script:Src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1') }
    It 'has the switch, pins every job by the digest the registry gives the built tag, and refuses without one' {
        $script:Src | Should -Match '\[switch\]\$ImageOnly'
        $script:Src | Should -Match ([regex]::Escape("Get-SIAcrManifestDigest -Rest `$rest -LoginServer `$acr.LoginServer -Repo 'si-orchestrator' -Tag `$tag"))
        $script:Src | Should -Match ([regex]::Escape("`$newImage = '{0}@{1}' -f `$newImage, `$dg"))
        $script:Src | Should -Match 'could not be read from the registry -- no job was changed'
    }
    It 'runs none of the steps after the roll and never moves the updater itself (it moves LAST, after the web app)' {
        $i = $script:Src.IndexOf("if (`$ImageOnly) { Info 'image-only update: the engine jobs are done")
        $j = $script:Src.LastIndexOf('exit (Complete-SIUpdate)')
        $i | Should -BeGreaterThan 0; $j | Should -BeGreaterThan $i
        # nothing to roll: the image-only exit comes BEFORE the line that moves the updater and runs the steps after the roll
        $k = $script:Src.IndexOf("if (`$toUpdate.Count -eq 0 -and `$ImageOnly) { Info 'image-only update: every engine job runs this image already -- nothing to roll'; exit 0 }")
        $k | Should -BeGreaterThan 0
        $k | Should -BeLessThan $script:Src.IndexOf("Info 'Every job already runs this tree -- nothing to roll.'; Invoke-SIUpdateSelfMove; exit (Complete-SIUpdate)")
        # every Invoke-SIUpdateSelfMove call after the roll comes after the image-only exit
        $script:Src.LastIndexOf("`nInvoke-SIUpdateSelfMove") | Should -BeGreaterThan $i
    }
    It 'Get-SIAcrManifestDigest: the Docker-Content-Digest of the tag; 404 = ''''; no digest throws' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-AcrBuild.ps1')
        $d = 'sha256:' + ('ab' * 32)
        $rest = { param($m, $u, $b, $res, $h)
                  if ($u -like '*oauth2/exchange') { return [pscustomobject]@{ Status = 200; Body = '{"refresh_token":"r"}'; Headers = @{} } }
                  if ($u -like '*oauth2/token') { return [pscustomobject]@{ Status = 200; Body = '{"access_token":"a"}'; Headers = @{} } }
                  if ($u -like '*/manifests/missing') { return [pscustomobject]@{ Status = 404; Body = ''; Headers = @{} } }
                  if ($u -like '*/manifests/nodigest') { return [pscustomobject]@{ Status = 200; Body = ''; Headers = @{} } }
                  [pscustomobject]@{ Status = 200; Body = ''; Headers = @{ 'Docker-Content-Digest' = $d.ToUpperInvariant().Replace('SHA256', 'sha256') } } }.GetNewClosure()
        $tok = { 'arm-token' }
        Get-SIAcrManifestDigest -Rest $rest -LoginServer 'reg.example.io' -Repo 'si-orchestrator' -Tag 'v1' -Token $tok | Should -Be $d
        Get-SIAcrManifestDigest -Rest $rest -LoginServer 'reg.example.io' -Repo 'si-orchestrator' -Tag 'missing' -Token $tok | Should -Be ''
        { Get-SIAcrManifestDigest -Rest $rest -LoginServer 'reg.example.io' -Repo 'si-orchestrator' -Tag 'nodigest' -Token $tok } | Should -Throw '*no digest*'
    }
    It 'the pre-roll of an image-only release never waits for running jobs (-NoQuietWait), only for a manual deploy' {
        $u = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
        $u | Should -Match ([regex]::Escape('-SIRoot $si -NoQuietWait:$imageOnly'))
        $rs = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRollSteps.ps1')
        $rs | Should -Match ([regex]::Escape("if (`$NoQuietWait) { return [pscustomobject]@{ Go = `$true; Reason = ''; Environment = `$envNow } }"))
    }
}

Describe 'the clean-up switch clears itself (Invoke-SIUpdaterPruneSwitchClear)' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $script:JobEnv = @(@{ name = 'SI_UPDATER_RING'; value = '2' }, @{ name = 'SI_UPDATER_IMAGE_PRUNE'; value = 'off' })
        $script:Arm = { param($Method, $Path, $Body)
            $script:Calls.Add("$Method")
            if ($Method -eq 'PATCH') { $b = $Body | ConvertFrom-Json; $script:JobEnv = @($b.properties.template.containers[0].env | ForEach-Object { @{ name = $_.name; value = $_.value } }); return $null }
            [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'u'; image = 'x'; imageType = 'ContainerImage'; env = @($script:JobEnv | ForEach-Object { [pscustomobject]$_ }) }) } } } }
    }
    It 'off on the job + this updater runs 3.1.14 or later = taken away (one PATCH, read back), nothing else changed, one line' {
        $e = @{ SI_UPDATER_IMAGE_PRUNE = 'off' }
        $r = Invoke-SIUpdaterPruneSwitchClear -Env $e -SubscriptionId 'sub' -ResourceGroup 'rg' -JobName 'caj-si-updater' -Version '3.1.18' -Arm $script:Arm 6>$null
        $r.Action | Should -Be 'cleared'; $r.Line | Should -Match 'taken away from the updater job by itself'
        @($script:Calls) | Should -Be @('GET', 'PATCH', 'GET')
        @($script:JobEnv | ForEach-Object { $_.name }) | Should -Be @('SI_UPDATER_RING')
        $e.ContainsKey('SI_UPDATER_IMAGE_PRUNE') | Should -BeFalse
        # the next run: nothing to do, nothing said
        Invoke-SIUpdaterPruneSwitchClear -SubscriptionId 'sub' -ResourceGroup 'rg' -JobName 'caj-si-updater' -Version '3.1.18' -Arm $script:Arm | Should -BeNullOrEmpty
    }
    It 'NEGATIVE: an updater older than 3.1.14, or a job without the switch off, is never changed' {
        Invoke-SIUpdaterPruneSwitchClear -SubscriptionId 'sub' -ResourceGroup 'rg' -JobName 'caj-si-updater' -Version '3.1.13' -Arm $script:Arm | Should -BeNullOrEmpty
        @($script:Calls) | Should -Be @('GET')
        $script:JobEnv = @(@{ name = 'SI_UPDATER_IMAGE_PRUNE'; value = 'on' })
        Invoke-SIUpdaterPruneSwitchClear -SubscriptionId 'sub' -ResourceGroup 'rg' -JobName 'caj-si-updater' -Version '3.1.18' -Arm $script:Arm | Should -BeNullOrEmpty
        @($script:Calls | Where-Object { $_ -eq 'PATCH' }).Count | Should -Be 0
    }
    It 'a PATCH that does not read back is a WARNING, never a throw' {
        $arm = { param($Method, $Path, $Body) if ($Method -eq 'PATCH') { return $null }
                 [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'u'; image = 'x'; env = @([pscustomobject]@{ name = 'SI_UPDATER_IMAGE_PRUNE'; value = 'off' }) }) } } } }
        $r = Invoke-SIUpdaterPruneSwitchClear -SubscriptionId 'sub' -ResourceGroup 'rg' -JobName 'caj-si-updater' -Version '3.1.18' -Arm $arm 6>$null
        $r.Action | Should -Be 'unconfirmed'; $r.Line | Should -Match '^WARNING'
    }
    It 'is wired into every update run (Start-SIUpdater.ps1, after the Key Vault step, with the version this image carries)' {
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $i = $s.IndexOf('$null = Invoke-SIUpdaterKeyVaultPurgeStep -Env $Env'); $j = $s.IndexOf('$null = Invoke-SIUpdaterPruneSwitchClear -Env $Env')
        $i | Should -BeGreaterThan 0; $j | Should -BeGreaterThan $i
    }
}
