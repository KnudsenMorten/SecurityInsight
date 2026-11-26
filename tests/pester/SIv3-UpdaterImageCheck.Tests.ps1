#Requires -Version 5.1
<#
    SI #1344 (owner IMAGE-30MIN-1, framework SEC-LANE-1 G5) -- THE IMAGE CHECK EVERY 15 MINUTES: the job caj-si-image-check
    (setup\_shared\SI-ImageCheckJob.ps1) runs the updater's image with SI_UPDATER_MODE = image-check
    (container\updater\_shared\SI-UpdaterImageCheck.ps1, wired in Start-SIUpdater.ps1 and _shared\SI-UpdaterInvardia.ps1).

    What must hold:
      * a ring with a newer IMAGE-ONLY release -> applied at once by the image-only path, then every job's digest read back;
      * a CODE release -> not applied (not even downloaded); it stays on the nightly update;
      * nothing new -> ONE INFO line, nothing saved;
      * a running run is never stopped (the check steps aside for a running update; the swap never stops an execution);
      * the install, the release's converge step and every updater run keep the job present with '*/15 * * * *'.
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
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ImageCheckJob.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImageCheck.ps1')
    Mock Invoke-WebRequest { throw 'no network in tests' }
    Mock Invoke-RestMethod { throw 'no network in tests' }

    $script:Key = 'inv-' + ('t' * 24)   # a fake install key (built, so no scanner reads it as a secret)
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    function script:ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $pub = $script:Rsa.ExportParameters($false)
    $script:Trusted = @(ConvertFrom-SIInvardiaKeyEntry -Entry ([pscustomobject]@{ keyId = 'test-update-key-1'; jwk = [pscustomobject]@{ kty = 'RSA'; n = (ConvertTo-B64Url $pub.Modulus); e = (ConvertTo-B64Url $pub.Exponent) } }))

    function script:New-ICZip([string]$Version, [string]$WhatsNewType = 'security', [switch]$NeedsQuiet) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-ic-src-' + [guid]::NewGuid().ToString('N'))
        $si = Join-Path $src "securityinsight-src-$Version\SOLUTIONS\SecurityInsight"
        foreach ($d in 'setup', 'engine', 'whats-new') { New-Item -ItemType Directory -Force (Join-Path $si $d) | Out-Null }
        Set-Content -LiteralPath (Join-Path $si 'VERSION') -Value $Version -NoNewline
        Set-Content -LiteralPath (Join-Path $si 'engine\Invoke-X.ps1') -Value 'Write-Host engine' -NoNewline
        if ($WhatsNewType) { Set-Content -LiteralPath (Join-Path $si "whats-new\$Version.json") -Value (('{{"version":"{0}","type":"{1}"}}' -f $Version, $WhatsNewType)) }
        if ($NeedsQuiet) { Set-Content -LiteralPath (Join-Path $si 'UPDATE-NEEDS-QUIET.txt') -Value 'a change the running jobs cannot run against' }
        Set-Content -LiteralPath (Join-Path $si 'setup\Invoke-SIContainerUpdate.ps1') -Value ('param([switch]$Apply, [switch]$ImageOnly, $ResourceGroupName, $AcrName, $SubscriptionId)' + "`n" + '$global:ICOrder.Add("engine imageonly=" + [bool]$ImageOnly)' + "`nexit 0")
        $hash = Get-SIEngineFingerprint -SIRoot $si
        $zip = Join-Path ([IO.Path]::GetTempPath()) ('si-ic-' + [guid]::NewGuid().ToString('N') + '.zip')
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        Remove-Item -LiteralPath $src -Recurse -Force
        [pscustomobject]@{ Zip = $zip; EngineHash = $hash }
    }
    function script:New-ICAnswer([string]$Version, [string]$File, [long]$Sequence = 7) {
        $m = [ordered]@{ product = 'securityinsight'; kind = 'code'; ring = 1; sequence = $Sequence; version = $Version; archive = "securityinsight-src-$Version.zip"
                         sha256 = (Get-SIInvardiaFileSha256 -Path $File); size = (Get-Item -LiteralPath $File).Length; image = $null; minFromVersion = $null
                         notes = 'test'; manualStep = $null; releasedAt = '2026-11-24T08:00:00Z' }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $script:Rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $body = ([ordered]@{ manifest = $m; manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key-1'
                             downloadUrl = "$($script:TestBase)/api/updates/securityinsight/code/$Version/archive?t=DLTOKEN" }) | ConvertTo-Json -Compress -Depth 5
        [pscustomobject]@{ Status = 200; Body = $body; RetryAfter = 0; Error = '' }
    }
    function script:New-ICStore([string]$EngineHash) {
        $st = @{ Writes = @{} }
        $fp = ('{{"hash":"{0}","version":"3.0.1"}}' -f $EngineHash)
        [pscustomobject]@{ State = $st; Name = 'fake'; Server = ''; Database = ''
            Invoke = { param($q, $p, $m)
                       if ($p -is [System.Collections.IDictionary]) { $n = $null; $v = $null; foreach ($e in $p.GetEnumerator()) { if ("$($e.Key)" -eq 'Name') { $n = "$($e.Value)" } elseif ("$($e.Key)" -eq 'Value') { $v = "$($e.Value)" } }; if ($n -and $null -ne $v) { $st.Writes[$n] = $v } }
                       if ($m -eq 'reader' -and "$q" -like "*N'EngineFingerprint'*") { return , @(@{ Value = $fp }) }
                       , @() }.GetNewClosure() }
    }
    function script:New-ICWorld($Zip, [string]$Version) {
        $w = @{ Vault = @{ 'SI-Invardia-InstallKey' = $script:Key; 'SI-License' = '{"licence":"TEST"}' }; Gate = (New-Object System.Collections.Generic.List[string])
                Sizings = (New-Object System.Collections.Generic.List[string]); Downloads = (New-Object System.Collections.Generic.List[string])
                Proofs = (New-Object System.Collections.Generic.List[string]); JobChecks = (New-Object System.Collections.Generic.List[string]); Busy = @()
                Proof = [pscustomobject]@{ Ok = $true; Checked = 3; Lines = @('caj-si-flow: si-orchestrator:v3.0.1.1-aaaaaaaaaaaa -- OK'); Why = 'every job on an image of 3.0.1.1 (3) runs the digest its build produced -- read back' } }
        $answer = New-ICAnswer -Version $Version -File $Zip
        $w.Seams = @{
            Http = { param($u, $b, $k, $h) $kind = ($b | ConvertFrom-Json).kind; if ($kind -eq 'code') { $answer } else { [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } } }.GetNewClosure()
            Download = { param($u, $f) $w.Downloads.Add($u); Copy-Item -LiteralPath $Zip -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }.GetNewClosure()
            ReadSecret = { param($n) $w.Vault[$n] }.GetNewClosure()
            WriteSecret = { param($n, $v) $w.Vault[$n] = $v }.GetNewClosure()
            TrustedKeys = { $script:Trusted }
            TenantId = { '11111111-2222-3333-4444-555555555555' }
            PreRoll = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = [pscustomobject]@{ LoginServer = 'reg.example.io'; UpdaterId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'; UpdaterImage = 'reg.example.io/si-updater:v3.0.1-build'; Record = $null; JobNames = @('caj-si-flow') } } }
            PostRoll = { param($si, $v, $c) [pscustomobject]@{ Code = 0; Text = "post-roll $v" } }
            SelfRetry = { $null }
            SizingPass = { param($why) $w.Sizings.Add([string]$why); $true }.GetNewClosure()
            RunGate = { param($holder) $w.Gate.Add('asked'); [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no run is going'; RunId = ''; LockTaken = $false; Holder = '' } }.GetNewClosure()
            ImageOnlyPrune = { param($healthy) }
            ImageOnlyPendingPrune = { }
            ReadWaits = { throw 'the image check must never read the nightly update''s wait mark' }
            WriteWaits = { param($v) throw 'the image check must never write the nightly update''s wait mark' }
            ImageCheckJob = { $w.JobChecks.Add('aligned') }.GetNewClosure()
            DigestProof = { param($v) $w.Proofs.Add($v); $w.Proof }.GetNewClosure()
            ImageCheckBusy = { $w.Busy }.GetNewClosure()
        }
        $w
    }
    function script:Invoke-ICRun($World, $Store, [string]$Deployed = '3.0.1') {
        $e = @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_UPDATER_RING = '1'; SI_UPDATER_MODE = 'image-check' }
        $World.Seams.Now = { [datetime]'2026-11-24T10:00:00Z' }
        $out = @(Invoke-SIUpdaterFromInvardia -Env $e -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Store $Store -Deployed $Deployed `
                    -SIRoot $script:SIRoot -Seams $World.Seams -Work (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) 6>&1 | ForEach-Object { $_ })
        $lines = @($out | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" } | Where-Object { $_.Trim() })
        [pscustomobject]@{ Code = (@($out | Where-Object { $_ -is [int] }) | Select-Object -Last 1); Lines = $lines; Log = ($lines -join "`n")
                           State = $(if ($World.Vault['SI-Update-State']) { ConvertFrom-SIInvardiaUpdateState -Json $World.Vault['SI-Update-State'] } else { $null }) }
    }
    # an updater job (ARM GET shape): managed identity, a Key Vault reference, the env the setup writes
    function script:New-ICUpdaterJob([string]$Image = 'reg.example.io/si-updater:v3.0.1-abc', [switch]$PlainSecret) {
        $sec = if ($PlainSecret) { [pscustomobject]@{ name = 'cert-pfx' } } else { [pscustomobject]@{ name = 'cert-pfx'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/cert'; identity = '/subs/uami' } }
        [pscustomobject]@{ name = 'caj-si-updater'; location = 'westeurope'
            identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ '/subs/uami' = [pscustomobject]@{ clientId = 'c1'; principalId = 'p1' } } }
            properties = [pscustomobject]@{ environmentId = '/subs/cae'; provisioningState = 'Succeeded'
                configuration = [pscustomobject]@{ triggerType = 'Schedule'; replicaTimeout = 86400; scheduleTriggerConfig = [pscustomobject]@{ cronExpression = '30 16,17 * * *'; parallelism = 1; replicaCompletionCount = 1 }
                                                   registries = @([pscustomobject]@{ server = 'reg.example.io'; identity = '/subs/uami' }); secrets = @($sec) }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'updater'; image = $Image; resources = [pscustomobject]@{ cpu = 4; memory = '8Gi' }
                    env = @([pscustomobject]@{ name = 'SI_UPDATER_RING'; value = '2' }, [pscustomobject]@{ name = 'SI_UPDATER_JOB_NAME'; value = 'caj-si-updater' }, [pscustomobject]@{ name = 'SI_UPDATER_CERT_PFX_B64'; secretRef = 'cert-pfx' }) }) } } }
    }
    # a fake ARM for the job: GET the updater / the image check job; PUT keeps what was written (made at once)
    function script:New-ICArm($Updater) {
        $a = @{ Updater = $Updater; Job = $null; Calls = (New-Object System.Collections.Generic.List[string]) }
        $a.Arm = { param([string]$Method, [string]$Path, $Body)
            $a.Calls.Add(('{0} {1}' -f $Method, ($Path -split '/')[-1]))
            if ($Method -eq 'PUT') { $j = ($Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json); $j.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force; $a.Job = $j; return $j }
            if ($Path -like '*/caj-si-updater') { return $a.Updater }
            if ($Path -like '*/caj-si-image-check') { return $a.Job }
            $null }.GetNewClosure()
        $a
    }
}
AfterAll {
    $env:SI_UPDATER_INVARDIA_BASE_URL = $script:PrevBase
    if ($script:Rsa) { $script:Rsa.Dispose() }
    Remove-Variable -Name ICOrder, SI_UpdaterQuiet, SI_ImageCheckIdle -Scope Global -ErrorAction SilentlyContinue
}

Describe 'the job caj-si-image-check (Invoke-SIImageCheckJobEnsure): made with ''*/15 * * * *'', kept, its image follows the updater' {
    It 'made from the updater job: the timer, the updater''s image, identity, registry and Key Vault reference, the mode -- read back' {
        $a = New-ICArm (New-ICUpdaterJob)
        $r = Invoke-SIImageCheckJobEnsure -Arm $a.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -Sleep { }
        $r.Ok | Should -BeTrue; $r.Action | Should -Be 'made'; $r.Cron | Should -Be '*/15 * * * *'
        $j = $a.Job
        $j.properties.configuration.triggerType | Should -Be 'Schedule'
        $j.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '*/15 * * * *'
        $j.properties.configuration.replicaRetryLimit | Should -Be 0
        $j.properties.template.containers[0].image | Should -Be 'reg.example.io/si-updater:v3.0.1-abc'
        @($j.identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @('/subs/uami') -Because 'the updater''s identity -- no new one, no new right'
        $j.properties.configuration.secrets[0].keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/cert'
        $env = @{}; foreach ($e in $j.properties.template.containers[0].env) { $env[$e.name] = $(if ($e.PSObject.Properties['secretRef']) { 'ref:' + $e.secretRef } else { $e.value }) }
        $env['SI_UPDATER_MODE'] | Should -Be 'image-check'
        $env['SI_UPDATER_JOB_NAME'] | Should -Be 'caj-si-updater' -Because 'everything the check names is the updater''s'
        $env['SI_UPDATER_RING'] | Should -Be '2'
        $env['SI_UPDATER_CERT_PFX_B64'] | Should -Be 'ref:cert-pfx'
        @($a.Calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 1
    }
    It 'a job that is as it must be is KEPT (no write); a new updater image moves it (updated)' {
        $a = New-ICArm (New-ICUpdaterJob)
        $null = Invoke-SIImageCheckJobEnsure -Arm $a.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -Sleep { }
        $a.Calls.Clear()
        (Invoke-SIImageCheckJobEnsure -Arm $a.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -Sleep { }).Action | Should -Be 'kept'
        @($a.Calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 0
        $a.Updater = New-ICUpdaterJob -Image 'reg.example.io/si-updater:v3.0.1.1-def'
        (Invoke-SIImageCheckJobEnsure -Arm $a.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -Sleep { }).Action | Should -Be 'updated'
        $a.Job.properties.template.containers[0].image | Should -Be 'reg.example.io/si-updater:v3.0.1.1-def'
    }
    It 'NEGATIVE: a secret that is not a Key Vault reference is never copied (not-ready, no write); -WhatIf writes nothing; no updater = not-ready' {
        $a = New-ICArm (New-ICUpdaterJob -PlainSecret)
        $r = Invoke-SIImageCheckJobEnsure -Arm $a.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -Sleep { }
        $r.Action | Should -Be 'not-ready'; $r.Reason | Should -Match 'not a Key Vault reference'
        $b = New-ICArm (New-ICUpdaterJob)
        (Invoke-SIImageCheckJobEnsure -Arm $b.Arm -SubscriptionId 'sub' -ResourceGroup 'rg' -WhatIf).Action | Should -Be 'plan'
        $c = New-ICArm $null
        (Invoke-SIImageCheckJobEnsure -Arm $c.Arm -SubscriptionId 'sub' -ResourceGroup 'rg').Action | Should -Be 'not-ready'
        @($a.Calls + $b.Calls + $c.Calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 0
    }
    It 'the install, the release''s converge step (9n) and every updater run keep it present' {
        $inst = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1')
        $inst | Should -Match ([regex]::Escape('$ic = Invoke-SIImageCheckJobEnsure -Arm $icArm -SubscriptionId $sub -ResourceGroup $ResourceGroupName -UpdaterJob $JobName'))
        $inst.IndexOf('Invoke-SIImageCheckJobEnsure -Arm $icArm') | Should -BeGreaterThan $inst.IndexOf("Step '3. Create or update the job'") -Because 'made from the updater job just written'
        $upd = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')
        $upd | Should -Match ([regex]::Escape('$ic = Invoke-SIImageCheckJobEnsure -Arm $icArm -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -UpdaterJob $name.Trim() -WhatIf:$wi'))
        $upd | Should -Match ([regex]::Escape("`$imageCheckLib = Join-Path `$PSScriptRoot '_shared/SI-ImageCheckJob.ps1'"))
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $s | Should -Match ([regex]::Escape('$null = Invoke-SIUpdaterImageCheckJob -SubscriptionId $sub -ResourceGroup $rg -UpdaterJob (Get-SIUpdaterInstallName -Role updater -Env $Env) -Quiet'))
        (Get-SIImageCheckJobNames).Cron | Should -Be '*/15 * * * *'; (Get-SIImageCheckJobNames).TickMinutes | Should -Be 15 -Because 'the step-aside window follows the tick'
    }
    It 'the image check is its own short run, BEFORE the overlap check (which may stop a dead update) and before every update step' {
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $i = $s.IndexOf('return (Invoke-SIUpdaterImageCheckRun -Env $Env')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $s.IndexOf('$earlier = Get-SIUpdaterEarlierLiveness')
        $i | Should -BeLessThan $s.IndexOf('Invoke-SIUpdaterSecretHandover -Rest')
        $s | Should -Match ([regex]::Escape('$icLine = Wait-SIUpdaterImageCheckEnded -Executions'))
    }
}

Describe 'the pure rules: the candidate, the nightly slot, the digest proof' {
    It 'only an image-only release of what runs goes on; a code release and nothing new are one INFO line' {
        $act = [pscustomobject]@{ Act = $true }; $none = [pscustomobject]@{ Act = $false }
        (Get-SIImageCheckCandidate -Result ([pscustomobject]@{ Action = 'update'; Version = '3.1.43.6'; Reason = '' }) -Decision $act -Deployed '3.1.43.5' -Ring 2).Go | Should -BeTrue
        $c = Get-SIImageCheckCandidate -Result ([pscustomobject]@{ Action = 'update'; Version = '3.1.44'; Reason = '' }) -Decision $act -Deployed '3.1.43.5' -Ring 2
        $c.Go | Should -BeFalse; $c.Line | Should -Match '^image check: ring 2 has 3\.1\.44, not an image-only release .* the nightly update installs it'
        $n = Get-SIImageCheckCandidate -Result ([pscustomobject]@{ Action = 'current'; Version = '3.1.43.5'; Reason = '' }) -Decision $none -Deployed '3.1.43.5' -Ring 2
        $n.Go | Should -BeFalse; $n.Line | Should -Match '^image check: nothing new'
        (Get-SIImageCheckCandidate -Result $null).Go | Should -BeFalse
    }
    It 'the nightly update''s slot: the check steps aside for 15 minutes after each of its starts' {
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T16:30:00Z') -Cron '30 16,17 * * *' | Should -BeTrue
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T17:40:00Z') -Cron '30 16,17 * * *' | Should -BeTrue
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T17:00:00Z') -Cron '30 16,17 * * *' | Should -BeFalse
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T16:30:00Z') -Cron '' | Should -BeFalse
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T16:45:00Z') -Cron '30 16,17 * * *' | Should -BeFalse -Because 'the tick right after the nightly start checks again'
        Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T16:45:40Z') -Cron '30 16,17 * * *' | Should -BeFalse -Because 'a late start of the tick (seconds) does not stretch the window'
    }
    It 'with the 15-minute tick NO check is skipped twice in a row by the slot rule: one tick per nightly start, over a whole day' {
        foreach ($cron in '30 16,17 * * *', '0 21,22 * * *', '7 3 * * *', '45 23 * * *') {
            $starts = @($cron.Split(' ')[1].Split(',')).Count
            $skips = 0; $prev = $false; $twice = 0
            for ($i = 0; $i -lt 96; $i++) {
                $at = Test-SIImageCheckAtUpdaterSlot -NowUtc ([datetime]'2026-11-24T00:00:00Z').AddMinutes(15 * $i) -Cron $cron
                if ($at) { $skips++; if ($prev) { $twice++ } }
                $prev = $at
            }
            $twice | Should -Be 0 -Because "$cron never skips two ticks in a row"
            $skips | Should -Be $starts -Because "$cron skips exactly one tick per nightly start"
        }
    }
    It 'case (h): a job on the release''s build digest passes; another digest under the same tag, an old tag, or no build read FAILS' {
        $d1 = 'sha256:' + ('1' * 64); $d2 = 'sha256:' + ('2' * 64)
        $job = { param($n, $i) [pscustomobject]@{ name = $n; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = $i }) } } } }
        $b = @([pscustomobject]@{ Repository = 'si-orchestrator'; Tag = 'v3.1.43.6-aaaaaaaaaaaa'; Digest = $d1; Run = 'cb1'; Status = 'Succeeded' },
               [pscustomobject]@{ Repository = 'si-updater'; Tag = 'v3.1.43.6-bbbbbbbbbbbb'; Digest = $d2; Run = 'cb2'; Status = 'Succeeded' })
        $ok = Get-SIImageCheckDigestProof -Version '3.1.43.6' -LoginServer 'reg.example.io' -Builds $b -Jobs @(
            (& $job 'caj-si-flow' "reg.example.io/si-orchestrator:v3.1.43.6-aaaaaaaaaaaa@$d1"), (& $job 'caj-si-updater' 'reg.example.io/si-updater:v3.1.43.6-bbbbbbbbbbbb'),
            (& $job 'caj-si-image-check' 'reg.example.io/si-updater:v3.1.43.6-bbbbbbbbbbbb'), (& $job 'caj-other' 'mcr.microsoft.com/x:1'))
        $ok.Ok | Should -BeTrue; $ok.Checked | Should -Be 3
        $bad = Get-SIImageCheckDigestProof -Version '3.1.43.6' -LoginServer 'reg.example.io' -Builds $b -Jobs @((& $job 'caj-si-flow' "reg.example.io/si-orchestrator:v3.1.43.6-aaaaaaaaaaaa@$d2"))
        $bad.Ok | Should -BeFalse; $bad.Why | Should -Match 'another image under the same tag'
        $old = Get-SIImageCheckDigestProof -Version '3.1.43.6' -LoginServer 'reg.example.io' -Builds $b -Jobs @((& $job 'caj-si-flow' 'reg.example.io/si-orchestrator:v3.1.43.5-cccccccccccc'))
        $old.Ok | Should -BeFalse; $old.Why | Should -Match 'not the build of 3\.1\.43\.6'
        (Get-SIImageCheckDigestProof -Version '3.1.43.6' -Builds @() -Jobs @((& $job 'caj-si-flow' 'reg.example.io/si-orchestrator:v3.1.43.6-a'))).Ok | Should -BeFalse
        $runs = ConvertFrom-SIImageCheckRegistryRuns ([pscustomobject]@{ value = @([pscustomobject]@{ properties = [pscustomobject]@{ runId = 'cb1'; status = 'Succeeded'; outputImages = @([pscustomobject]@{ repository = 'si-orchestrator'; tag = 'v1'; digest = $d1 }) } }) })
        $runs[0].Run | Should -Be 'cb1'; $runs[0].Digest | Should -Be $d1
    }
}

Describe 'an image check run against Invardia (Invoke-SIUpdaterFromInvardia, SI_UPDATER_MODE = image-check)' {
    BeforeEach {
        $global:ICOrder = New-Object System.Collections.Generic.List[string]
        $global:SI_UpdaterQuiet = $null; $global:SI_ImageCheckIdle = $null
        Mock Invoke-SIUpdaterAppRoll { $global:ICOrder.Add('web app images-only=' + [bool]$ImagesOnly); [pscustomobject]@{ Code = 0; Text = 'healthy' } }
        Mock Save-SIUpdaterInstalledRecord { $global:ICOrder.Add("record $Version"); $true }
        Mock Invoke-SIUpdaterSelfRoll { $global:ICOrder.Add('updater'); [pscustomobject]@{ Action = 'rolled'; Image = 'x'; Previous = $CurrentImage; Reason = 'moved' } }
        Mock Invoke-SIUpdaterArm { $global:ICOrder.Add("arm $Method $Path"); $null }
        Mock Invoke-SIUpdaterRoll { throw 'the full roll never runs in an image check' }
    }
    It 'a ring with a newer IMAGE-ONLY release: applied at once (engine, web app, record, updater LAST), this job aligned, every digest read back' {
        $z = New-ICZip -Version '3.0.1.1'
        $w = New-ICWorld -Zip $z.Zip -Version '3.0.1.1'
        $r = Invoke-ICRun -World $w -Store (New-ICStore $z.EngineHash)
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'image check: ring 1 has 3\.0\.1\.1, an image-only \(security\) release of the 3\.0\.1 this install runs -- it is installed now'
        @($global:ICOrder | Where-Object { $_ -notlike 'arm *' }) | Should -Be @('engine imageonly=True', 'web app images-only=True', 'record 3.0.1.1', 'updater')
        $w.JobChecks.Count | Should -Be 1 -Because 'the image check job follows the updater''s new image'
        @($w.Proofs) | Should -Be @('3.0.1.1') -Because 'every job''s digest is read back against its build (case (h))'
        $r.Log | Should -Match 'image check: digest read-back -- every job on an image of 3\.0\.1\.1'
        $w.Gate.Count | Should -Be 0 -Because 'no run gate: a running pipeline is never waited for or stopped'
        $w.Sizings.Count | Should -Be 0 -Because 'none of the nightly steps'
        @($global:ICOrder | Where-Object { $_ -like 'arm POST*' }).Count | Should -Be 0 -Because 'nothing is ever stopped'
        $r.State.code.appliedVersion | Should -Be '3.0.1.1'
    }
    It 'a digest read-back that does not prove the swap: the run FAILS and says which job' {
        $z = New-ICZip -Version '3.0.1.1'
        $w = New-ICWorld -Zip $z.Zip -Version '3.0.1.1'
        $w.Proof = [pscustomobject]@{ Ok = $false; Checked = 2; Lines = @('caj-si-flow: si-orchestrator:v3.0.1.1-a -- NOT proven'); Why = '1 of 2 job(s) do not run the digest their build of 3.0.1.1 produced: caj-si-flow' }
        $r = Invoke-ICRun -World $w -Store (New-ICStore $z.EngineHash)
        $r.Code | Should -Be 1
        $r.State.lastError | Should -Match 'digest read-back did not prove it -- 1 of 2 job\(s\)'
    }
    It 'NEGATIVE: a CODE release is NOT applied -- not downloaded, nothing rolled, nothing saved, one INFO line' {
        $z = New-ICZip -Version '3.0.2' -WhatsNewType 'feature'
        $w = New-ICWorld -Zip $z.Zip -Version '3.0.2'
        $r = Invoke-ICRun -World $w -Store (New-ICStore $z.EngineHash)
        $r.Code | Should -Be 0
        $r.Lines.Count | Should -Be 1
        $r.Lines[0] | Should -Match 'image check: ring 1 has 3\.0\.2, not an image-only release .* the nightly update installs it, this check does not'
        $w.Downloads.Count | Should -Be 0
        $global:ICOrder.Count | Should -Be 0
        $w.Vault.ContainsKey('SI-Update-State') | Should -BeFalse -Because 'the nightly update''s state stays as it is'
    }
    It 'nothing new: exactly ONE INFO line, nothing saved, nothing rolled' {
        $z = New-ICZip -Version '3.0.1.1'
        $w = New-ICWorld -Zip $z.Zip -Version '3.0.1.1'
        $r = Invoke-ICRun -World $w -Store (New-ICStore $z.EngineHash) -Deployed '3.0.1.1'
        $r.Code | Should -Be 0
        $r.Lines.Count | Should -Be 1
        $r.Lines[0] | Should -Match '\] image check: nothing new -- this install runs the release of ring 1 \(3\.0\.1\.1\)$'
        $global:ICOrder.Count | Should -Be 0; $w.Vault.ContainsKey('SI-Update-State') | Should -BeFalse
        $global:SI_ImageCheckIdle | Should -BeTrue
    }
    It 'a release that must be installed while nothing runs, while a job runs: it WAITS (one line), the running job is not stopped' {
        $z = New-ICZip -Version '3.0.1.1' -NeedsQuiet
        $w = New-ICWorld -Zip $z.Zip -Version '3.0.1.1'
        $w.Busy = @('caj-si-flow')
        $r = Invoke-ICRun -World $w -Store (New-ICStore $z.EngineHash)
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'must be installed while no SecurityInsight job runs .* caj-si-flow run\(s\) now and are not stopped; it waits'
        @($global:ICOrder | Where-Object { $_ -notlike 'arm *' }).Count | Should -Be 0
        @($global:ICOrder | Where-Object { $_ -like 'arm POST*' }).Count | Should -Be 0
    }
}

Describe 'the image check run itself (Invoke-SIUpdaterImageCheckRun): it steps aside, never stops anything' {
    BeforeEach {
        $global:SI_UpdaterQuiet = $null; $global:SI_ImageCheckIdle = $null
        $script:Arm = New-Object System.Collections.Generic.List[string]
        Mock Invoke-SIUpdaterArm { $script:Arm.Add("$Method $Path"); @() }
        Mock Invoke-SIUpdaterFromInvardia { throw 'Invardia must not be asked' }
        $script:Running = [pscustomobject]@{ name = 'caj-si-updater-x1'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-11-24T09:50:00Z'; endTime = $null } }
    }
    It 'an update of caj-si-updater runs: one INFO line, Invardia not asked, nothing stopped' {
        $out = @(Invoke-SIUpdaterImageCheckRun -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -NowUtc ([datetime]'2026-11-24T10:00:00Z') `
                    -Seams @{ UpdaterCron = { '30 16,17 * * *' }; UpdaterExecutions = { $script:Running }; OwnExecutions = { @() } } 6>&1)
        @($out | Where-Object { $_ -is [int] })[-1] | Should -Be 0
        $l = @($out | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" })
        $l.Count | Should -Be 1; $l[0] | Should -Match 'image check: the update caj-si-updater-x1 runs now -- nothing checked here; it was not stopped'
        @($script:Arm | Where-Object { $_ -like 'POST*' }).Count | Should -Be 0
        Should -Invoke Invoke-SIUpdaterFromInvardia -Times 0 -Exactly -Scope It
    }
    It 'at the nightly update''s own start: one INFO line, nothing asked' {
        $out = @(Invoke-SIUpdaterImageCheckRun -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -NowUtc ([datetime]'2026-11-24T16:30:00Z') `
                    -Seams @{ UpdaterCron = { '30 16,17 * * *' }; UpdaterExecutions = { @() }; OwnExecutions = { @() } } 6>&1)
        @($out | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) | Should -Match 'image check: the nightly update starts now'
        Should -Invoke Invoke-SIUpdaterFromInvardia -Times 0 -Exactly -Scope It
    }
    It 'nothing running: the one update client is asked in its image-check mode' {
        Mock Invoke-SIUpdaterFromInvardia { $global:SI_ICAskedMode = $Env['SI_UPDATER_MODE']; 0 }
        $rc = Invoke-SIUpdaterImageCheckRun -Env @{ SI_UPDATER_MODE = 'image-check' } -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -NowUtc ([datetime]'2026-11-24T10:00:00Z') `
                    -Seams @{ UpdaterCron = { '30 16,17 * * *' }; UpdaterExecutions = { @() }; OwnExecutions = { @() }; Deployed = { '3.0.1' } } 6>$null
        $rc | Should -Be 0
        $global:SI_ICAskedMode | Should -Be 'image-check'
        Should -Invoke Invoke-SIUpdaterFromInvardia -Times 1 -Exactly -Scope It
    }
    It 'a nightly update waits for an image check that runs now (bounded), and never stops it' {
        $n = 0
        $line = Wait-SIUpdaterImageCheckEnded -Executions { if ($script:icPoll++ -lt 1) { $script:Running } else { @() } } -Sleep { } -Now { [datetime]'2026-11-24T10:00:00Z' }
        $line | Should -Match 'has ended -- the update goes on'
        Wait-SIUpdaterImageCheckEnded -Executions { @() } -Sleep { } | Should -Be ''
    }
}
