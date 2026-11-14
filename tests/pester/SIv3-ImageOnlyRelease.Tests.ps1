#Requires -Version 5.1
<#
    framework SEC-LANE-1 -- WHAT AN INSTALL CAN TELL OF AN IMAGE-ONLY RELEASE, AND THE IMAGES IT RUNS
    (engine/_shared/SI-ImageOnlyRelease.ps1) + the heartbeat's Update.runningImages (engine/_shared/SI-HeartbeatFields.ps1,
    Invardia's contract 2e20fb60: { component, repo, digest, dotnet, readUtc }, at most 40, soft).

    What must hold: the image patch rule (a fourth part on the release that runs, never a code release, never lower);
    the What's new marker; the three proofs together; image references parsed (pin, tag, both); one component per job and
    per app container; the digest from the pin, else the registry's manifest of the tag (one token per repository, one read
    per tag); the .NET runtime from the image's label, else the base image's DOTNET_VERSION (a multi-platform index: its
    linux/amd64 image); nothing known = null, never a guess; the value checked against the contract; Update carries the key
    as its LAST key, and a bad value leaves the key out, never the rest of Update. Offline: fake ARM, fake registry.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name Test-SIImageOnlyVersion -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-ImageOnlyRelease.ps1') }
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-14T10:00:00', [DateTimeKind]::Utc)
    $script:DA = 'sha256:' + ('a' * 64); $script:DB = 'sha256:' + ('b' * 64); $script:DC = 'sha256:' + ('c' * 64); $script:DX = 'sha256:' + ('d' * 64)
    # a fake registry data plane: every call recorded
    function script:New-FakeReg {
        $w = @{ Calls = (New-Object System.Collections.Generic.List[string]) }
        # (locals: a .GetNewClosure() block does not see the test's script: variables)
        $DA = $script:DA; $DB = $script:DB; $DC = $script:DC; $DX = $script:DX
        $w.Http = {
            param($Method, $Uri, $Headers, $Body)
            $w.Calls.Add("$Method $Uri")
            if ($Uri -like '*/oauth2/exchange') { return [pscustomobject]@{ Status = 200; Body = '{"refresh_token":"r"}'; Headers = @{} } }
            if ($Uri -like '*/oauth2/token') { return [pscustomobject]@{ Status = 200; Body = '{"access_token":"a"}'; Headers = @{} } }
            if ($Method -eq 'HEAD' -and $Uri -like '*/si-orchestrator/manifests/v3.1.17-abc') { return [pscustomobject]@{ Status = 200; Body = ''; Headers = @{ 'Docker-Content-Digest' = $DB } } }
            if ($Method -eq 'HEAD') { return [pscustomobject]@{ Status = 404; Body = ''; Headers = @{} } }
            if ($Uri -like "*/manifests/$DA") { return [pscustomobject]@{ Status = 200; Body = ('{{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"digest":"{0}","platform":{{"os":"linux","architecture":"arm64"}}}},{{"digest":"{1}","platform":{{"os":"linux","architecture":"amd64"}}}}]}}' -f $DX, $DC); Headers = @{} } }
            if ($Uri -like "*/manifests/$DC" -or $Uri -like "*/manifests/$DB") { return [pscustomobject]@{ Status = 200; Body = ('{{"config":{{"digest":"sha256:{0}"}}}}' -f ('e' * 64)); Headers = @{} } }
            if ($Uri -like '*/blobs/*') { return [pscustomobject]@{ Status = 200; Body = '{"config":{"Env":["PATH=/usr/bin","DOTNET_VERSION=10.0.15","ASPNET_VERSION=10.0.15"]}}'; Headers = @{} } }
            [pscustomobject]@{ Status = 404; Body = ''; Headers = @{} }
        }.GetNewClosure()
        $w
    }
}

Describe 'the image patch rule (Test-SIImageOnlyVersion, Test-SIImageOnlyRelease, Get-SIImageOnlyMarker)' {
    It '<V> on <R> -> <Ok>' -ForEach @(
        @{ V = '3.1.17.1'; R = '3.1.17'; Ok = $true }
        @{ V = '3.1.17.2'; R = '3.1.17.1'; Ok = $true }
        @{ V = '3.1.18'; R = '3.1.17'; Ok = $false }
        @{ V = '3.1.17.1'; R = '3.1.17.2'; Ok = $false }
        @{ V = '3.1.17.1'; R = '3.1.17.1'; Ok = $false }
        @{ V = '3.1.17.1'; R = '3.1.16'; Ok = $false }
        @{ V = '3.1.17.1'; R = ''; Ok = $false }
        @{ V = 'v3.1.17.1'; R = '3.1.17'; Ok = $false }
        @{ V = '3.1.17.202611141200'; R = '3.1.17'; Ok = $false }
    ) { (Test-SIImageOnlyVersion -Version $V -Running $R).Ok | Should -Be $Ok }
    It 'the marker is the image patch''s own What''s new, type security' {
        $d = Join-Path $TestDrive 'r'; New-Item -ItemType Directory -Force (Join-Path $d 'whats-new') | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'whats-new\3.1.17.1.json') -Value '{"version":"3.1.17.1","type":"security"}'
        Set-Content -LiteralPath (Join-Path $d 'whats-new\3.1.18.json') -Value '{"version":"3.1.18","type":"feature"}'
        (Get-SIImageOnlyMarker -SIRoot $d -Version '3.1.17.1').Ok | Should -BeTrue
        (Get-SIImageOnlyMarker -SIRoot $d -Version '3.1.18').Ok | Should -BeFalse
        (Get-SIImageOnlyMarker -SIRoot $d -Version '3.1.17.9').Why | Should -Match 'carries no'
    }
    It 'all three proofs and the script''s mode, else not image-only with the reason' {
        $m = [pscustomobject]@{ Ok = $true; Why = 'security' }
        (Test-SIImageOnlyRelease -Version '3.1.17.1' -Running '3.1.17' -Marker $m -RecordedEngineHash 'AB' -ReleaseEngineHash 'ab').ImageOnly | Should -BeTrue
        (Test-SIImageOnlyRelease -Version '3.1.17.1' -Running '3.1.17' -Marker $m -RecordedEngineHash 'ab' -ReleaseEngineHash 'cd').Why | Should -Match 'differs'
        (Test-SIImageOnlyRelease -Version '3.1.17.1' -Running '3.1.17' -Marker $m -RecordedEngineHash '' -ReleaseEngineHash 'ab').Why | Should -Match 'not recorded'
        (Test-SIImageOnlyRelease -Version '3.1.17.1' -Running '3.1.17' -Marker $m -RecordedEngineHash 'ab' -ReleaseEngineHash 'ab' -ScriptReady $false).ImageOnly | Should -BeFalse
        (Test-SIImageOnlyRelease -Version '3.1.17.1' -Running '3.1.17' -Marker ([pscustomobject]@{ Ok = $false; Why = 'no marker' }) -RecordedEngineHash 'ab' -ReleaseEngineHash 'ab').Why | Should -Be 'no marker'
    }
}

Describe 'the running images (Get-SIRunningImageComponents, the registry reader, Get-SIRunningImages)' {
    It 'image references: tag, pin, tag + pin; an image without a registry host is not one of ours' {
        $r = ConvertFrom-SIImageReference "acrsi.azurecr.io/si-orchestrator:v3.1.17-abc@$($script:DA)"
        $r.Registry | Should -Be 'acrsi.azurecr.io'; $r.Repo | Should -Be 'si-orchestrator'; $r.Tag | Should -Be 'v3.1.17-abc'; $r.Digest | Should -Be $script:DA
        (ConvertFrom-SIImageReference 'acrsi.azurecr.io/si-updater:v1').Digest | Should -Be ''
        ConvertFrom-SIImageReference 'nginx:latest' | Should -BeNullOrEmpty
    }
    It 'one component per job, the app''s first container under its name, a further container as <app>.<container>' {
        $jobs = @([pscustomobject]@{ name = 'caj-si-flow'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'c'; image = 'r.azurecr.io/si-orchestrator:t' }) } } })
        $apps = @([pscustomobject]@{ name = 'ca-si-management'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @(
                    [pscustomobject]@{ name = 'app'; image = 'r.azurecr.io/si-management:src-1' }, [pscustomobject]@{ name = 'signin-front'; image = 'r.azurecr.io/signin-front:2.1.2' }) } } })
        $c = @(Get-SIRunningImageComponents -Jobs $jobs -Apps $apps)
        @($c | ForEach-Object { $_.Component }) | Should -Be @('caj-si-flow', 'ca-si-management', 'ca-si-management.signin-front')
    }
    It 'the digest from the pin, else the registry''s manifest of the tag; .NET from the image (index -> linux/amd64 -> its config); unknown = null' {
        $f = New-FakeReg
        $imageReader = New-SIRegistryImageReader -Http $f.Http -ArmToken { 'arm' }
        $comp = @(
            [pscustomobject]@{ Component = 'caj-si-flow'; Image = "acrsi.azurecr.io/si-orchestrator:v3.1.17-abc@$($script:DA)" }
            [pscustomobject]@{ Component = 'caj-si-verification'; Image = 'acrsi.azurecr.io/si-orchestrator:v3.1.17-abc' }
            [pscustomobject]@{ Component = 'caj-si-mail'; Image = 'acrsi.azurecr.io/si-orchestrator:v3.1.17-abc' }
            [pscustomobject]@{ Component = 'caj-si-updater'; Image = 'acrsi.azurecr.io/si-updater:gone' }
            [pscustomobject]@{ Component = 'ca-other'; Image = 'nginx:latest' })
        $ri = @(Get-SIRunningImages -Components $comp -ImageReader $imageReader -NowUtc $script:Now)
        $ri.Count | Should -Be 5
        $ri[0].digest | Should -Be $script:DA; $ri[0].dotnet | Should -Be '10.0.15'; $ri[0].repo | Should -Be 'si-orchestrator'; $ri[0].readUtc | Should -Be '2026-11-14T10:00:00Z'
        $ri[1].digest | Should -Be $script:DB; $ri[1].dotnet | Should -Be '10.0.15'
        $ri[3].digest | Should -BeNullOrEmpty; $ri[3].dotnet | Should -BeNullOrEmpty; $ri[3].repo | Should -Be 'si-updater'
        $ri[4].repo | Should -BeNullOrEmpty; $ri[4].digest | Should -BeNullOrEmpty
        @($ri[0].Keys) | Should -Be @('component', 'repo', 'digest', 'dotnet', 'readUtc')
        # cheap: one token per repository, one HEAD per tag (the same tag twice = one read), never another host
        @($f.Calls | Where-Object { $_ -like 'HEAD *v3.1.17-abc' }).Count | Should -Be 1
        @($f.Calls | Where-Object { $_ -like 'POST *oauth2/exchange' }).Count | Should -Be 2
        @($f.Calls | Where-Object { $_ -notlike '* https://acrsi.azurecr.io/*' }).Count | Should -Be 0
        Test-SIRunningImagesValue -Value $ri | Should -Be ''
    }
    It 'a registry that refuses the token: the pin still counts, the rest is null -- never a throw' {
        $imageReader = New-SIRegistryImageReader -Http { param($m, $u, $h, $b) [pscustomobject]@{ Status = 401; Body = ''; Headers = @{} } } -ArmToken { 'arm' }
        $ri = @(Get-SIRunningImages -Components @([pscustomobject]@{ Component = 'a'; Image = "r.azurecr.io/x:t@$($script:DA)" }, [pscustomobject]@{ Component = 'b'; Image = 'r.azurecr.io/x:t' }) -ImageReader $imageReader -NowUtc $script:Now)
        $ri[0].digest | Should -Be $script:DA; $ri[0].dotnet | Should -BeNullOrEmpty
        $ri[1].digest | Should -BeNullOrEmpty
    }
    It 'the .NET record: the label first, then DOTNET_VERSION; nothing = ''''' {
        Get-SIImageDotnetVersion -Config ([pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'org.securityinsight.dotnet' = '10.0.16' }; Env = @('DOTNET_VERSION=10.0.15') } }) | Should -Be '10.0.16'
        Get-SIImageDotnetVersion -Config ([pscustomobject]@{ config = [pscustomobject]@{ Env = @('DOTNET_VERSION=10.0.15') } }) | Should -Be '10.0.15'
        Get-SIImageDotnetVersion -Config ([pscustomobject]@{ config = [pscustomobject]@{ Env = @('PATH=/x') } }) | Should -Be ''
    }
    It 'the contract check refuses what Invardia refuses (keys, names, digest, version, time, count, duplicates)' {
        $ok = [ordered]@{ component = 'caj-si-flow'; repo = 'si-orchestrator'; digest = $script:DA; dotnet = '10.0.15'; readUtc = '2026-11-14T10:00:00Z' }
        Test-SIRunningImagesValue -Value @($ok) | Should -Be ''
        $bad = { param($k, $v) $x = [ordered]@{}; foreach ($n in $ok.Keys) { $x[$n] = $ok[$n] }; $x[$k] = $v; Test-SIRunningImagesValue -Value @($x) }
        & $bad 'component' 'Not A Name' | Should -Match 'component'
        & $bad 'digest' 'not-a-digest' | Should -Match 'digest'
        & $bad 'dotnet' 'ten' | Should -Match 'dotnet'
        & $bad 'readUtc' 'yesterday' | Should -Match 'readUtc'
        Test-SIRunningImagesValue -Value @($ok, $ok) | Should -Match 'more than once'
        Test-SIRunningImagesValue -Value @(1..41 | ForEach-Object { [ordered]@{ component = "c$_"; repo = $null; digest = $null; dotnet = $null; readUtc = '2026-11-14T10:00:00Z' } }) | Should -Match 'at most 40'
        Test-SIRunningImagesValue -Value @([ordered]@{ component = 'a'; digest = $null }) | Should -Match 'keys'
    }
}

Describe 'the heartbeat: Update.runningImages (SI-HeartbeatFields.ps1)' {
    BeforeAll {
        $script:U = New-SIHeartbeatOrdered -Names (Get-SIHeartbeatFieldsContract).Fields.Update -Values @{ installed = '3.1.17'; lastUpdaterResult = 'succeeded' }
        $script:Img = [ordered]@{ component = 'caj-si-updater'; repo = 'si-updater'; digest = $script:DA; dotnet = '10.0.15'; readUtc = '2026-11-14T10:00:00Z' }
    }
    It 'Update with runningImages as its LAST key passes; the agreed five alone still pass' {
        Test-SIHeartbeatField -Name 'Update' -Value $script:U | Should -Be ''
        $ux = Add-SIHeartbeatUpdateRunningImages -Update $script:U -Images @($script:Img)
        @($ux.PSObject.Properties | ForEach-Object { $_.Name })[-1] | Should -Be 'runningImages'
        Test-SIHeartbeatField -Name 'Update' -Value $ux | Should -Be ''
        ($ux | ConvertTo-Json -Depth 6 -Compress) | Should -Match '"runningImages":\[\{"component":"caj-si-updater","repo":"si-updater","digest":"sha256:a{64}","dotnet":"10.0.15","readUtc":"2026-11-14T10:00:00Z"\}\]'
    }
    It 'no image = the key is left out, never sent empty; a bad entry fails the check' {
        $ux = Add-SIHeartbeatUpdateRunningImages -Update $script:U -Images @()
        @($ux.PSObject.Properties | ForEach-Object { $_.Name }) | Should -Not -Contain 'runningImages'
        $b = [ordered]@{ component = 'x'; repo = 'r'; digest = 'nope'; dotnet = $null; readUtc = '2026-11-14T10:00:00Z' }
        Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateRunningImages -Update $script:U -Images @($b)) | Should -Match 'digest'
    }
    It 'New-SIHeartbeatFields: the images ride on Update; a bad value leaves the key out and keeps the rest of Update' {
        $rows = @([pscustomobject]@{ K = 'state'; Name = 'UpdateState'; S = $null; T1 = $null; T2 = $null; T3 = $null; T4 = $null; N1 = $null; Txt = '{"lastCheckUtc":"2026-11-14T09:00:00Z","code":{"version":"3.1.17","action":"current"},"error":""}'; Txt2 = $null })
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ Update = $true } -CfgRows $rows -Installed '3.1.17' -RunningImages @($script:Img)
        $f['Update'].runningImages[0].component | Should -Be 'caj-si-updater'
        $b = [ordered]@{ component = 'Bad Name'; repo = 'r'; digest = $null; dotnet = $null; readUtc = '2026-11-14T10:00:00Z' }
        $g = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ Update = $true } -CfgRows $rows -Installed '3.1.17' -RunningImages @($b)
        $g['Update'].installed | Should -Be '3.1.17'
        @($g['Update'].PSObject.Properties | ForEach-Object { $_.Name }) | Should -Not -Contain 'runningImages'
    }
    It 'Get-SIHeartbeatRunningImages: ONE job list and ONE app list from ARM, then the reader' {
        $paths = New-Object System.Collections.Generic.List[string]
        $img = "acrsi.azurecr.io/si-updater:v1@$($script:DA)"
        $arm = { param($Path) $paths.Add($Path)
                 if ($Path -like '*/jobs?*') { return [pscustomobject]@{ value = @([pscustomobject]@{ name = 'caj-si-updater'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'u'; image = $img }) } } }) } }
                 [pscustomobject]@{ value = @() } }.GetNewClosure()
        $ri = @(Get-SIHeartbeatRunningImages -Arm $arm -Scope ([pscustomobject]@{ Sub = 's'; Rg = 'rg' }) -NowUtc $script:Now -ImageReader (New-SIRegistryImageReader -Http (New-FakeReg).Http -ArmToken { 'arm' }))
        $paths.Count | Should -Be 2
        $ri[0].component | Should -Be 'caj-si-updater'; $ri[0].digest | Should -Be $script:DA
    }
}
