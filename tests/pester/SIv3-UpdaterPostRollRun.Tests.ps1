#Requires -Version 5.1
<#
    #1262 -- AN UPDATER-SIDE CHANGE ACTS WITHIN ITS OWN UPDATE (the post-roll run).
    The update to a release is carried out by the OLD updater image; the updater moves its own job onto the release's image
    during that run, and the running execution finishes on its old image -- so the post-roll steps (the web app steps, the
    built-in sign-in incl. the MCP standard and the key-ring move; the AI settings) ran in the release's code only on the
    NEXT update. Now an update that moved the updater starts the updater job ONCE more with SI_UPDATER_MODE = post-roll,
    and that run (on the new image) runs the post-roll steps in the release's own code.

    What these tests keep true:
      * the full update and the image-only update both start the post-roll run when the updater moved itself ('rolled'),
        and only then (current / failed / off = no run);
      * the start body carries SI_UPDATER_MODE = post-roll (the image and every other setting of the job kept);
      * the post-roll run (the REAL Start-SIUpdater.ps1 path, Invoke-SIUpdater): runs the AI settings step and the post-roll
        steps (the web app steps, then the built-in sign-in, with -Rc 0) -- and reads no manifest, asks for no licence,
        rolls no image and never starts another run (bounded); it waits for the update that started it, as the second
        update does, and never stops anything;
      * the chain: a post-roll change of release N acts within release N's own update.
    Offline, fakes only; PS 5.1 and 7.
#>

BeforeAll {
    $env:SI_Setup_NewInstallNames = 'false'
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:PrevBase = $env:SI_UPDATER_INVARDIA_BASE_URL
    $script:TestBase = 'https://invardia.test'
    $env:SI_UPDATER_INVARDIA_BASE_URL = $script:TestBase
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterRunGate.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InvardiaUpdate.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UpdaterStart.ps1')
    Mock Invoke-WebRequest { throw 'no network in tests' }
    Mock Invoke-RestMethod { throw 'no network in tests' }

    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-15T10:00:00', 'Utc')
    # ---- Invardia's side, offline: a TEST signing key (made per run), a signed code manifest, a release archive ----
    $script:Key = 'inv-test-' + [guid]::NewGuid().ToString('N')
    $script:Tenant = '11111111-2222-3333-4444-555555555555'
    function script:ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $pub = $script:Rsa.ExportParameters($false)
    $script:Trusted = @(ConvertFrom-SIInvardiaKeyEntry -Entry ([pscustomobject]@{ keyId = 'test-update-key-1'; jwk = [pscustomobject]@{ kty = 'RSA'; n = (ConvertTo-B64Url $pub.Modulus); e = (ConvertTo-B64Url $pub.Exponent) } }))
    $script:Marker = Join-Path ([IO.Path]::GetTempPath()) ('si-postroll-marker-' + [guid]::NewGuid().ToString('N') + '.txt')
    function script:New-CodeZip([string]$Version) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-postroll-src-' + [guid]::NewGuid().ToString('N'))
        $si = Join-Path $src "securityinsight-src-$Version\SOLUTIONS\SecurityInsight"
        New-Item -ItemType Directory -Force (Join-Path $si 'setup') | Out-Null
        Set-Content -LiteralPath (Join-Path $si 'VERSION') -Value $Version -NoNewline
        Set-Content -LiteralPath (Join-Path $si 'setup\Invoke-SIContainerUpdate.ps1') -Value ('param([switch]$Apply, $ResourceGroupName, $AcrName, $SubscriptionId) Set-Content -LiteralPath ''{0}'' -Value ("apply=$Apply"); $global:LASTEXITCODE = 0' -f $script:Marker)
        $zip = Join-Path ([IO.Path]::GetTempPath()) ('si-postroll-' + [guid]::NewGuid().ToString('N') + '.zip')
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        Remove-Item -LiteralPath $src -Recurse -Force
        $zip
    }
    function script:New-Answer([string]$File, [string]$Version = '3.0.1', [long]$Sequence = 7) {
        $m = [ordered]@{ product = 'securityinsight'; kind = 'code'; ring = 1; sequence = $Sequence; version = $Version; archive = "securityinsight-src-$Version.zip"
                         sha256 = (Get-SIInvardiaFileSha256 -Path $File); size = (Get-Item -LiteralPath $File).Length; image = $null; minFromVersion = $null
                         notes = 'test release'; manualStep = $null; releasedAt = '2026-11-15T08:00:00Z' }
        $raw = [Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Compress))
        $sig = $script:Rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $body = ([ordered]@{ manifest = $m; manifestB64 = [Convert]::ToBase64String($raw); signature = [Convert]::ToBase64String($sig); keyId = 'test-update-key-1'
                             downloadUrl = "$($script:TestBase)/api/updates/securityinsight/code/$Version/archive?t=DLTOKEN" }) | ConvertTo-Json -Compress -Depth 5
        [pscustomobject]@{ Status = 200; Body = $body; RetryAfter = 0; Error = '' }
    }
    $script:Z301 = New-CodeZip '3.0.1'

    # ONE world at a time ($script:W): the seams are plain script blocks of this file
    function script:New-World([string]$SelfAction = 'rolled', [switch]$ImageOnly) {
        $script:W = @{ Vault = @{ 'SI-Invardia-InstallKey' = $script:Key; 'SI-License' = '{"licence":"TEST-LICENCE-TEXT"}' }; Code = (New-Answer -File $script:Z301)
                       SelfAction = $SelfAction; Started = (New-Object System.Collections.Generic.List[string]) }
        $script:W.Seams = @{
            Http = { param($u, $b, $k, $h) if (($b | ConvertFrom-Json).kind -eq 'code' -and $script:W.Code) { $script:W.Code } else { [pscustomobject]@{ Status = 204; Body = ''; RetryAfter = 0; Error = '' } } }
            Download = { param($u, $f) Copy-Item -LiteralPath $script:Z301 -Destination $f -Force; [pscustomobject]@{ Status = 200; Error = '' } }
            ReadSecret = { param($n) $script:W.Vault[$n] }
            WriteSecret = { param($n, $v) $script:W.Vault[$n] = $v }
            TrustedKeys = { $script:Trusted }
            TenantId = { $script:Tenant }
            ClaimHttp = { [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = 'no claim' } }
            PreRoll = { [pscustomobject]@{ Go = $true; Reason = ''; Environment = $null } }
            PostRoll = { param($si, $v, $c) [pscustomobject]@{ Code = 0; Text = "post-roll $v"; SelfAction = $script:W.SelfAction } }
            SelfRetry = { $null }
            SizingPass = { param($why) $true }
            RunGate = { param($h) [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no pipeline run is going (test)'; RunId = ''; LockTaken = $false; Holder = '' } }
            Beat = { param($h, $what) $true }
            ExitGate = { param($h) $true }
            ReadWaits = { $null }
            WriteWaits = { param($v) }
            # the post-roll run's start: recorded (the real start body is tested on its own below)
            SecondPass = { $script:W.Started.Add('post-roll'); 'post-roll run: started (test)' }
            Now = { $script:T0 }
        }
        if ($ImageOnly) {
            $script:W.Seams.ImageOnlyDecision = { param($si, $v, $d) [pscustomobject]@{ ImageOnly = $true; Why = 'an image patch (test)' } }
            $script:W.Seams.ImageOnlyRun = { param($si, $v, $c, $e) [pscustomobject]@{ Code = 0; Result = 'done'; Component = ''; Why = 'every part swapped (test)'; Parts = @('engine jobs', 'updater'); SelfAction = $script:W.SelfAction } }
            $script:W.Seams.ImageOnlyPrune = { param($h) $true }
        }
        $script:W
    }
    function script:Invoke-Update($World, [hashtable]$Env = @{}) {
        Remove-Item -LiteralPath $script:Marker -ErrorAction SilentlyContinue
        $global:SI_UpdaterFailures = New-Object System.Collections.Generic.List[object]
        $e = @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_UPDATER_RING = '1'; CONTAINER_APP_JOB_EXECUTION_NAME = 'upd-x1' }
        foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
        $log = @(Invoke-SIUpdaterFromInvardia -Env $e -SubscriptionId 'sub' -ResourceGroup 'rg' -AcrName 'acr' -Store $null -Deployed '3.0.0' `
                    -SIRoot $script:SIRoot -Seams $World.Seams -Work (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) 6>&1 | ForEach-Object { $_ })
        [pscustomobject]@{ Code = (@($log | Where-Object { $_ -is [int] }) | Select-Object -Last 1); Log = (@($log | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n") }
    }

    # ---- the post-roll run on the REAL script path (Invoke-SIUpdater): Azure, the manifest and the roll are fakes ----
    $script:UpdEnv = {
        @{ SI_UPDATER_TENANT_ID = $script:Tenant; SI_UPDATER_CLIENT_ID = 'cid'; SI_UPDATER_SUBSCRIPTION_ID = 'sub'; SI_UPDATER_RESOURCE_GROUP = 'rg'
           SI_UPDATER_ACR = 'acr'; SI_UPDATER_CERT_PFX_B64 = 'pfx'; SI_UPDATER_KEY_VAULT = 'kv'; SI_UPDATER_SOURCE = 'invardia'
           CONTAINER_APP_JOB_EXECUTION_NAME = 'upd-post-1'; CONTAINER_APP_JOB_NAME = 'caj-si-updater' }
    }
    function script:Set-RunMocks {
        $script:Seen = New-Object System.Collections.Generic.List[string]
        $script:Rc = New-Object System.Collections.Generic.List[string]
        Mock Connect-SIUpdaterRest { 'the test identity' }
        Mock Get-SIUpdaterDeployed { '3.0.1' }
        Mock Invoke-SIUpdaterArm { $script:Seen.Add(('arm {0} {1}' -f $(if ($Method) { $Method } else { 'GET' }), $Path)); $null }
        Mock Wait-SIUpdaterPreviousEnded { $script:Seen.Add('wait-previous'); 'second update: no other update runs' }
        Mock Invoke-SIUpdaterFromInvardia { $script:Seen.Add('manifest'); 0 }
        Mock Invoke-SIUpdaterLicenceRequest { $script:Seen.Add('licence'); $null }
        Mock Start-SIUpdaterSecondPass { $script:Seen.Add('start-another'); '' }
        Mock Invoke-SIUpdaterSelfRoll { $script:Seen.Add('self-roll'); $null }
        Mock Set-SIUpdaterImage { $script:Seen.Add('image-roll') }
        Mock Invoke-SIUpdaterSecretHandover { [pscustomobject]@{ Report = @() } }
        Mock Invoke-SIUpdaterWebJobRightsStep { $null }
        Mock Invoke-SIUpdaterAiSettingsStep { $script:Seen.Add('ai-settings'); $null }
        Mock Invoke-SIUpdaterOpenAIRightsStep { $null }
        Mock Invoke-SIUpdaterKeyVaultPurgeStep { $null }
        Mock Invoke-SIUpdaterRecordEndpoints { $null }
        Mock Get-SIUpdaterInstallEdition { 'pro' }
        # the post-roll steps themselves (Invoke-SIUpdaterWebAppStepsAfter is the REAL one): recorded, in order
        Mock Invoke-SIUpdaterWebAppSteps { $script:Seen.Add('web-app-steps'); $null }
        Mock Invoke-SIUpdaterBuiltInAuthStep { $script:Seen.Add('built-in-sign-in'); $script:Rc.Add("$Rc"); $null }
        foreach ($n in 'Invoke-SIUpdaterPruneSwitchClear', 'Register-SIUpdaterExecutionBeat', 'Invoke-SIUpdaterIdentityNamesStep') {
            if (Get-Command -Name $n -ErrorAction SilentlyContinue) { Mock $n { $null } }
        }
    }
}

AfterAll {
    $env:SI_UPDATER_INVARDIA_BASE_URL = $script:PrevBase
    Remove-Item -LiteralPath $script:Marker -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Z301 -ErrorAction SilentlyContinue
    if ($script:Rsa) { $script:Rsa.Dispose() }
}

Describe 'the update that moved the updater starts the post-roll run (#1262)' {
    It 'the full update: the updater moved itself (rolled) -> the post-roll run is started ONCE' {
        $w = New-World -SelfAction 'rolled'
        $r = Invoke-Update $w
        $r.Code | Should -Be 0
        (Test-Path -LiteralPath $script:Marker) | Should -BeTrue
        @($w.Started).Count | Should -Be 1
        $r.Log | Should -Match 'post-roll run: started'
    }
    It 'the full update: the updater did not move (current / failed / off) -> no post-roll run' {
        foreach ($a in 'current', 'failed', 'off', '') {
            $w = New-World -SelfAction $a
            $null = Invoke-Update $w
            @($w.Started).Count | Should -Be 0 -Because "self action '$a'"
        }
    }
    It 'the IMAGE-ONLY update: the updater swapped LAST (rolled) -> the post-roll run is started too (before #1262 it never was)' {
        $w = New-World -SelfAction 'rolled' -ImageOnly
        $r = Invoke-Update $w
        $r.Code | Should -Be 0
        $r.Log | Should -Match 'image-only update 3\.0\.1: done'
        @($w.Started).Count | Should -Be 1
    }
    It 'the image-only update without the updater moved -> no post-roll run' {
        $w = New-World -SelfAction 'current' -ImageOnly
        $null = Invoke-Update $w
        @($w.Started).Count | Should -Be 0
    }
    It 'BOUNDED: a run in post-roll mode never starts another, even if it were to roll' {
        $w = New-World -SelfAction 'rolled'
        $null = Invoke-Update $w -Env @{ SI_UPDATER_MODE = 'post-roll' }
        @($w.Started).Count | Should -Be 0
    }
}

Describe 'the start body of the post-roll run' {
    It 'POSTs the job''s own template with SI_UPDATER_MODE = post-roll (the image and every setting kept) -- and nothing else' {
        $calls = New-Object System.Collections.Generic.List[object]
        $job = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'main'; image = 'acr.azurecr.io/si-updater:3.0.1-abc'
                    env = @([pscustomobject]@{ name = 'SI_KEEP'; value = 'kept' }, [pscustomobject]@{ name = 'SI_SECRET'; secretRef = 'a-secret' }); resources = [pscustomobject]@{ cpu = 4; memory = '8Gi' } }) } } }
        $arm = { param($m, $p, $b) $calls.Add([pscustomobject]@{ M = $m; P = $p; B = $b }); if ($m -eq 'GET') { $job } else { [pscustomobject]@{ name = 'caj-si-updater-post1' } } }.GetNewClosure()
        $line = Start-SIUpdaterSecondPass -ResourceGroup 'rg' -SubscriptionId 'sub' -JobName 'caj-si-updater' -Arm $arm
        $line | Should -Match '^post-roll run: started \(caj-si-updater-post1\)'
        @($calls | ForEach-Object { $_.M }) | Should -Be @('GET', 'POST')
        $calls[1].P | Should -BeLike '*/Microsoft.App/jobs/caj-si-updater/start*'
        $json = $calls[1].B | ConvertTo-Json -Depth 10 -Compress
        $json | Should -Match '"name":"SI_UPDATER_MODE","value":"post-roll"'
        $json | Should -Match 'si-updater:3\.0\.1-abc'
        $json | Should -Match '"name":"SI_KEEP","value":"kept"'
        $json | Should -Match '"secretRef":"a-secret"'
        @($calls | Where-Object { $_.P -match '/stop' }).Count | Should -Be 0
    }
    It 'the older mode is still there for an updater that starts it (second-pass), and nothing else is accepted' {
        $arm = { param($m, $p, $b) if ($m -eq 'GET') { [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'main'; image = 'i'; env = @() }) } } } } else { $script:Body2 = $b; $null } }
        $null = Start-SIUpdaterSecondPass -ResourceGroup 'rg' -SubscriptionId 'sub' -JobName 'caj-si-updater' -Arm $arm -Mode 'second-pass'
        ($script:Body2 | ConvertTo-Json -Depth 10 -Compress) | Should -Match '"value":"second-pass"'
        { Start-SIUpdaterSecondPass -ResourceGroup 'rg' -SubscriptionId 'sub' -JobName 'caj-si-updater' -Arm $arm -Mode 'update-now' } | Should -Throw
    }
    It 'a start that fails is one line, never a throw (the next update runs the post-roll steps)' {
        $arm = { param($m, $p, $b) throw 'HTTP 403' }
        $line = Start-SIUpdaterSecondPass -ResourceGroup 'rg' -SubscriptionId 'sub' -JobName 'caj-si-updater' -Arm $arm
        $line | Should -Match '^post-roll run: could not be started \(HTTP 403\) -- the next update runs'
    }
}

Describe 'the post-roll run on the real script path (Start-SIUpdater.ps1, Invoke-SIUpdater)' {
    BeforeEach { Set-RunMocks }

    It 'ASSERT-WIRING: SI_UPDATER_MODE = post-roll runs the AI settings and the post-roll steps (web app, then the built-in sign-in, -Rc 0) -- no manifest, no licence, no image roll, no further run' {
        $e = & $script:UpdEnv; $e.SI_UPDATER_MODE = 'post-roll'
        $out = @(Invoke-SIUpdater -Env $e 6>&1 | ForEach-Object { $_ })
        @($out | Where-Object { $_ -is [int] })[-1] | Should -Be 0
        $seen = @($script:Seen | Where-Object { $_ -notlike 'arm *' })
        $seen | Should -Contain 'wait-previous'
        $seen | Should -Contain 'ai-settings'
        $seen | Should -Contain 'web-app-steps'
        $seen | Should -Contain 'built-in-sign-in'
        [array]::IndexOf($seen, 'wait-previous') | Should -BeLessThan ([array]::IndexOf($seen, 'ai-settings'))
        [array]::IndexOf($seen, 'web-app-steps') | Should -BeLessThan ([array]::IndexOf($seen, 'built-in-sign-in'))
        @($script:Rc) | Should -Be @('0')
        foreach ($never in 'manifest', 'licence', 'start-another', 'self-roll', 'image-roll') { $seen | Should -Not -Contain $never -Because "a post-roll run never does '$never'" }
        # nothing is stopped or cancelled, and no job is written over ARM by the run itself
        @($script:Seen | Where-Object { $_ -match '^arm (POST|PATCH|PUT|DELETE) ' }).Count | Should -Be 0
        (@($out | Where-Object { $_ -isnot [int] } | ForEach-Object { "$_" }) -join "`n") | Should -Match 'post-roll run: the post-roll steps of .+ in its own code \(no image roll'
    }
    It 'the same script without the mode is an ordinary update (the harness tells the two apart)' {
        $e = & $script:UpdEnv
        $null = @(Invoke-SIUpdater -Env $e 6>&1)
        $script:Seen | Should -Contain 'manifest'
        $script:Seen | Should -Not -Contain 'wait-previous'
    }
    It 'safe on a Community install (no settings database): the post-roll run still ends well and still rolls nothing' {
        Mock Get-SIUpdaterInstallEdition { 'community' }
        $e = & $script:UpdEnv; $e.SI_UPDATER_MODE = 'post-roll'; $e.SI_UPDATER_SOURCE = 'community'
        $out = @(Invoke-SIUpdater -Env $e 6>&1 | ForEach-Object { $_ })
        @($out | Where-Object { $_ -is [int] })[-1] | Should -Be 0
        $script:Seen | Should -Contain 'built-in-sign-in'
        foreach ($never in 'manifest', 'licence', 'start-another', 'self-roll', 'image-roll') { $script:Seen | Should -Not -Contain $never }
    }
    It 'idempotent: two post-roll runs one after the other do the same steps and start nothing' {
        $e = & $script:UpdEnv; $e.SI_UPDATER_MODE = 'post-roll'
        $null = @(Invoke-SIUpdater -Env $e 6>&1); $first = @($script:Seen | Where-Object { $_ -notlike 'arm *' })
        Set-RunMocks
        $null = @(Invoke-SIUpdater -Env $e 6>&1); $second = @($script:Seen | Where-Object { $_ -notlike 'arm *' })
        $second | Should -Be $first
        $second | Should -Not -Contain 'start-another'
    }
}

Describe 'the chain: a post-roll change of release N acts within release N''s own update' {
    It 'the update rolls (the updater moved), starts the post-roll run with the mode it carries, and that run reaches the post-roll steps' {
        # 1. the update of release N (run by the old updater code): it moves the updater, and starts the post-roll run --
        #    through the REAL start (its ARM is the fake: the job read, the start POST recorded)
        $w = New-World -SelfAction 'rolled'
        $script:ChainBodies = New-Object System.Collections.Generic.List[object]
        $script:ChainJob = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'main'; image = 'acr.azurecr.io/si-updater:N'; env = @() }) } } }
        $script:ChainArm = { param($m, $p, $b) if ($m -eq 'GET') { $script:ChainJob } else { $script:ChainBodies.Add($b); [pscustomobject]@{ name = 'exec-post' } } }
        $w.Seams.SecondPass = { Start-SIUpdaterSecondPass -ResourceGroup 'rg' -SubscriptionId 'sub' -JobName 'caj-si-updater' -Arm $script:ChainArm }
        $r = Invoke-Update $w
        $r.Log | Should -Match 'post-roll run: started \(exec-post\)'
        $script:ChainBodies.Count | Should -Be 1
        $mode = @($script:ChainBodies[0].containers[0].env | Where-Object { $_.name -eq 'SI_UPDATER_MODE' })[0].value
        $mode | Should -Be 'post-roll'
        # 2. the started execution (release N's image, release N's code): exactly that environment -> the post-roll steps
        Set-RunMocks
        $e = & $script:UpdEnv; $e.SI_UPDATER_MODE = $mode
        $null = @(Invoke-SIUpdater -Env $e 6>&1)
        $script:Seen | Should -Contain 'built-in-sign-in'
        $script:Seen | Should -Contain 'ai-settings'
        $script:Seen | Should -Not -Contain 'manifest'
        $script:Seen | Should -Not -Contain 'start-another'
    }
}
