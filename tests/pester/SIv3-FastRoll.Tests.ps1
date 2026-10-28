#Requires -Version 5.1
<#
    #416 THE FAST ROLL (operator 2026-10-06: "release must comedown to 10 min", "we solved the updater yesterday by the
    changes you made like paralle", "where did those learning go"). setup/_shared/SI-FastRoll.ps1: two-layer images with a
    cached base, builds queued together, every job swapped by ONE ARM PATCH of its template, all at once, verified.
    Offline: a fake ARM behind the REST seam records every call (#521: no az CLI). Runs on Windows PowerShell 5.1 and
    PowerShell 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-FastRoll.ps1')
    function script:New-Job([string]$Name, [string]$Image, [hashtable]$Env = @{ A = '1' }) {
        $e = @($Env.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ name = $_; value = $Env[$_] } })
        [pscustomobject]@{ name = $Name; tags = [pscustomobject]@{ owner = 'si' }
            identity = [pscustomobject]@{ userAssignedIdentities = [pscustomobject]@{ '/x/uami-si' = [pscustomobject]@{} } }
            properties = [pscustomobject]@{ provisioningState = 'Succeeded'
                configuration = [pscustomobject]@{ triggerType = 'Schedule'; scheduleTriggerConfig = [pscustomobject]@{ cronExpression = '0 1 * * *' }
                    secrets = @([pscustomobject]@{ name = 'kv'; keyVaultUrl = 'https://kv/secrets/x'; identity = '/x/uami-si' }) }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'c'; image = $Image; imageType = 'ContainerImage'; env = $e
                    resources = [pscustomobject]@{ cpu = 1; memory = '2Gi'; ephemeralStorage = '4Gi' } }) } } }
    }
    # a fake Azure behind the REST seam: jobs by name, every call recorded as '<METHOD> <url>'; PATCH applies the template;
    # the job list returns the jobs. Like ARM (live 2026-10-06): a PATCH at an api-version before 2024-08 that carries
    # imageType is refused 400; a job busy with another operation answers 409.
    function script:New-FakeAzure([object[]]$Jobs) {
        $w = [pscustomobject]@{ Jobs = @{}; Calls = (New-Object System.Collections.Generic.List[string]); Busy = @{}; Mutate = $null; Bodies = @{} }
        foreach ($j in $Jobs) { $w.Jobs[$j.name] = $j }
        $w
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        if ($Resource -ne 'https://management.azure.com/') { return [pscustomobject]@{ Status = 401; Body = 'wrong audience' } }
        if ($Method -eq 'PATCH') {
            $n = ([regex]::Match($Uri, '/jobs/([^?]+)')).Groups[1].Value
            if ($w.Busy[$n] -gt 0) { $w.Busy[$n]--; return [pscustomobject]@{ Status = 409; Body = ('{"error":{"code":"ContainerAppsJobOperationInProgress","message":"Cannot modify a container apps job ''' + $n + '''"}}') } }
            $bodyText = [string]$Body
            $api = ([regex]::Match($Uri, 'api-version=([0-9-]+)')).Groups[1].Value
            if ($api -lt '2024-08' -and $bodyText -match '"imageType"') { return [pscustomobject]@{ Status = 400; Body = '{"status":400,"errors":{"$[0]":["Unknown properties imageType in ContainerAppContainer are not supported"]}}' } }
            $b = $bodyText | ConvertFrom-Json
            $w.Bodies[$n] = $b
            $w.Jobs[$n].properties.template = $b.properties.template
            if ($w.Mutate -eq $n) { $w.Jobs[$n].properties.configuration.triggerType = 'Manual' }
            return [pscustomobject]@{ Status = 200; Body = '' }
        }
        if ($Method -eq 'GET' -and $Uri -like '*/providers/Microsoft.App/jobs?*') { return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject ([pscustomobject]@{ value = @($w.Jobs.Values) }) -Depth 30) } }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
}

Describe 'two-layer images: the cached base and the thin code layer' {
    It 'the ENGINE Dockerfile (no modules since #305) splits: only the time zone database in the cached base (2026-10-06), the code in the thin layer' {
        $p = New-SIImageLayerPlan -DockerfileText ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Dockerfile'))) -BaseRepo 'si-base' -LoginServer 'reg.io' -FromDigest 'sha256:abc' -Week '2026-W41'
        $p.HasBase | Should -BeTrue
        $p.BaseDockerfile | Should -Match 'tzdata'
        $p.BaseDockerfile | Should -Not -Match 'COPY|Install-Module'
        $p.AppDockerfile | Should -Match 'COPY \. /app/'
        $p.AppDockerfile | Should -Not -Match 'apt-get'
    }
    It 'the UPDATER Dockerfile splits: apt (no Azure CLI since #521) in the base, the code COPY lines in the thin layer on top of it' {
        $p = New-SIImageLayerPlan -DockerfileText ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile'))) -BaseRepo 'si-updater-base' -LoginServer 'reg.io' -FromDigest 'sha256:abc' -Week '2026-W41'
        $p.HasBase | Should -BeTrue
        $p.BaseTag | Should -Match '^[0-9a-f]{16}$'
        $p.BaseDockerfile | Should -Match 'FROM mcr\.microsoft\.com/powershell:lts-ubuntu-22\.04@sha256:abc'
        $p.BaseDockerfile | Should -Match 'apt-get install -y --no-install-recommends ca-certificates'
        $p.BaseDockerfile | Should -Not -Match 'InstallAzureCLIDeb|az extension|azure-cli'
        $p.BaseDockerfile | Should -Not -Match 'COPY'
        $p.AppDockerfile | Should -Match ("FROM reg\.io/si-updater-base:{0}" -f $p.BaseTag)
        $p.AppDockerfile | Should -Match 'COPY container/updater/Start-SIUpdater.ps1'
        $p.AppDockerfile | Should -Match 'ENTRYPOINT'
        $p.AppDockerfile | Should -Not -Match 'apt-get'
    }
    It 'the base hash is stable, and moves with the FROM digest, the base lines, a module version, and the week (only when the base RUNs)' {
        $df = "FROM mcr.microsoft.com/powershell:lts`nRUN apt-get update`nCOPY . /app/`nENTRYPOINT [`"pwsh`"]"
        $a = (New-SIImageLayerPlan -DockerfileText $df -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W1').BaseTag
        (New-SIImageLayerPlan -DockerfileText $df -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W1').BaseTag | Should -Be $a
        (New-SIImageLayerPlan -DockerfileText $df -BaseRepo b -LoginServer r -FromDigest 'sha256:2' -Week 'W1').BaseTag | Should -Not -Be $a
        (New-SIImageLayerPlan -DockerfileText $df -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W2').BaseTag | Should -Not -Be $a
        (New-SIImageLayerPlan -DockerfileText $df -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W1' -Floating 'M=2.0').BaseTag | Should -Not -Be $a
        (New-SIImageLayerPlan -DockerfileText ($df -replace 'apt-get update', 'apt-get update && true') -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W1').BaseTag | Should -Not -Be $a
        # a code change never moves the base
        (New-SIImageLayerPlan -DockerfileText ($df -replace 'COPY \. /app/', 'COPY engine/ /app/') -BaseRepo b -LoginServer r -FromDigest 'sha256:1' -Week 'W1').BaseTag | Should -Be $a
        $env = "FROM x.io/a:1`nENV A=1`nCOPY . /app/"
        (New-SIImageLayerPlan -DockerfileText $env -BaseRepo b -LoginServer r -Week 'W1').BaseTag | Should -Be (New-SIImageLayerPlan -DockerfileText $env -BaseRepo b -LoginServer r -Week 'W2').BaseTag
    }
    It 'what the split cannot map safely is built as it is, never guessed: multi-stage (the web app), COPY --from, a parser directive' {
        $directive = '# syntax=docker/dockerfile:1' + "`n" + ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile')) -replace '(?s)^.*?(?=FROM mcr)', '')
        (New-SIImageLayerPlan -DockerfileText $directive -BaseRepo b -LoginServer r).HasBase | Should -BeFalse
        (New-SIImageLayerPlan -DockerfileText "FROM a.io/b:1 AS build`nRUN x`nCOPY . .`nFROM a.io/c:1`nCOPY --from=build /o /o" -BaseRepo b -LoginServer r).HasBase | Should -BeFalse
        (New-SIImageLayerPlan -DockerfileText "FROM a.io/b:1`nRUN x`nCOPY --from=other /o /o" -BaseRepo b -LoginServer r).HasBase | Should -BeFalse
        (New-SIImageLayerPlan -DockerfileText "FROM a.io/b:1`nRUN x`nEXPOSE 80`nCOPY . ." -BaseRepo b -LoginServer r).HasBase | Should -BeFalse
    }
    It 'the ISO week is computed the ISO way (2026-01-01 is in 2026-W01; 2027-01-01 in 2026-W53)' {
        Get-SIIsoWeek -Date ([datetime]'2026-01-01') | Should -Be '2026-W01'
        Get-SIIsoWeek -Date ([datetime]'2027-01-01') | Should -Be '2026-W53'
        Get-SIIsoWeek -Date ([datetime]'2026-10-06') | Should -Be '2026-W41'
    }
}

Describe 'a tag per source: an image whose sources did not change is not rebuilt' {
    BeforeEach {
        $script:T = Join-Path ([IO.Path]::GetTempPath()) ('si-srch-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $script:T 'app\src\bin'), (Join-Path $script:T 'app\src\obj'), (Join-Path $script:T 'config') | Out-Null
        Set-Content -LiteralPath (Join-Path $script:T 'app\src\a.cs') -Value 'class A {}'
        Set-Content -LiteralPath (Join-Path $script:T 'config\x.locked.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $script:T 'VERSION') -Value '3.0.0'
    }
    AfterEach { Remove-Item -LiteralPath $script:T -Recurse -Force -ErrorAction SilentlyContinue }
    It 'BUILD.json, bin/, obj/ and customer files never change it; a source file, a shipped config file or VERSION does' {
        $paths = @('VERSION', 'config', 'app/src')
        $h = Get-SISourceHash -Root $script:T -Paths $paths
        $h | Should -Match '^[0-9a-f]{64}$'
        Set-Content -LiteralPath (Join-Path $script:T 'BUILD.json') -Value '{"commit":"x"}'
        Set-Content -LiteralPath (Join-Path $script:T 'app\src\bin\a.dll') -Value 'x'
        Set-Content -LiteralPath (Join-Path $script:T 'app\src\obj\a.json') -Value 'x'
        Set-Content -LiteralPath (Join-Path $script:T 'config\SecurityInsight.custom.ps1') -Value 'x'
        Get-SISourceHash -Root $script:T -Paths $paths | Should -Be $h
        Set-Content -LiteralPath (Join-Path $script:T 'app\src\a.cs') -Value 'class A { int x; }'
        $h2 = Get-SISourceHash -Root $script:T -Paths $paths; $h2 | Should -Not -Be $h
        Set-Content -LiteralPath (Join-Path $script:T 'config\x.locked.json') -Value '{"a":1}'
        Get-SISourceHash -Root $script:T -Paths $paths | Should -Not -Be $h2
        Get-SISourceHash -Root $script:T -Paths @('nothing-here') | Should -Be ''
    }
}

Describe 'the job swap: one ARM PATCH of the template per job, all at once, verified' {
    It 'the PATCH body is properties.template ONLY -- never configuration (ARM returns secrets without values; sending them drops them)' {
        $j = New-Job 'caj-si-a' 'reg.io/si-orchestrator:old'
        $b = New-SIJobImagePatchBody -Job $j -Image 'reg.io/si-orchestrator:new' -RepoPrefix 'reg.io/si-orchestrator' | ConvertFrom-Json
        @($b.PSObject.Properties.Name) | Should -Be @('properties')
        @($b.properties.PSObject.Properties.Name) | Should -Be @('template')
        $b.properties.template.containers[0].image | Should -Be 'reg.io/si-orchestrator:new'
        $b.properties.template.containers[0].env[0].name | Should -Be 'A'
        $b.properties.template.containers[0].resources.PSObject.Properties['ephemeralStorage'] | Should -BeNullOrEmpty
        # a sidecar on another image is not touched
        $j.properties.template.containers += [pscustomobject]@{ name = 'side'; image = 'other.io/x:1' }
        $b2 = New-SIJobImagePatchBody -Job $j -Image 'reg.io/si-orchestrator:new' -RepoPrefix 'reg.io/si-orchestrator' | ConvertFrom-Json
        $b2.properties.template.containers[1].image | Should -Be 'other.io/x:1'
        # the job object itself is not changed
        $j.properties.template.containers[0].image | Should -Be 'reg.io/si-orchestrator:old'
    }
    It 'every PATCH goes out BEFORE the first read-back (parallel, not one job after another), and every job is verified' {
        $jobs = @(1..6 | ForEach-Object { New-Job ("caj-si-{0}" -f $_) 'reg.io/si-orchestrator:old' })
        $script:World = New-FakeAzure $jobs
        $t = @($jobs | ForEach-Object { [pscustomobject]@{ Name = $_.name; Image = 'reg.io/si-orchestrator:new' } })
        $r = @(Invoke-SIJobImageRoll -Rest $script:Rest -SubscriptionId 's' -ResourceGroup 'rg' -Targets $t -Jobs $jobs -RepoPrefix 'reg.io/si-orchestrator' -PollSeconds 0 -RetrySeconds 0)
        @($r | Where-Object { $_.Ok }).Count | Should -Be 6
        $calls = @($script:World.Calls)
        # ONE read before (the PATCH's own api-version), six PATCHes back to back, ONE list reads all six back
        $calls[0] | Should -BeLike 'GET *'
        @($calls[1..6] | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 6
        @($calls | Where-Object { $_ -like 'GET *' }).Count | Should -Be 2
        @($calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 0 -Because 'never a PUT (it would drop the secrets)'
        foreach ($c in $calls) { $c | Should -Match ('api-version=' + $script:SIFastRollArmApi) }
        foreach ($c in $calls) { $c | Should -Match '^(GET|PATCH) https://management\.azure\.com/subscriptions/s/resourceGroups/rg/providers/Microsoft\.App/jobs' }
    }
    It 'a job busy with another operation (409) is sent again; the others are not held up' {
        $jobs = @((New-Job 'caj-si-a' 'reg.io/si-orchestrator:old'), (New-Job 'caj-si-b' 'reg.io/si-orchestrator:old'))
        $script:World = New-FakeAzure $jobs; $script:World.Busy['caj-si-b'] = 2
        $t = @($jobs | ForEach-Object { [pscustomobject]@{ Name = $_.name; Image = 'reg.io/si-orchestrator:new' } })
        $r = @(Invoke-SIJobImageRoll -Rest $script:Rest -SubscriptionId 's' -ResourceGroup 'rg' -Targets $t -Jobs $jobs -PollSeconds 0 -RetrySeconds 0)
        @($r | Where-Object { $_.Ok }).Count | Should -Be 2
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *caj-si-b*' }).Count | Should -Be 3
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *caj-si-a*' }).Count | Should -Be 1
    }
    It 'NEGATIVE: a job where anything but the image changed FAILS verification (its trigger moved)' {
        $jobs = @((New-Job 'caj-si-a' 'reg.io/si-orchestrator:old'), (New-Job 'caj-si-b' 'reg.io/si-orchestrator:old'))
        $script:World = New-FakeAzure $jobs; $script:World.Mutate = 'caj-si-b'
        # the roll fingerprints the jobs as ARM returned them (a JSON copy); the fake then moves caj-si-b's trigger
        $t = @($jobs | ForEach-Object { [pscustomobject]@{ Name = $_.name; Image = 'reg.io/si-orchestrator:new' } })
        $r = @(Invoke-SIJobImageRoll -Rest $script:Rest -SubscriptionId 's' -ResourceGroup 'rg' -Targets $t -Jobs $jobs -PollSeconds 0 -RetrySeconds 0)
        ($r | Where-Object { $_.Name -eq 'caj-si-a' }).Error | Should -BeNullOrEmpty
        ($r | Where-Object { $_.Name -eq 'caj-si-a' }).Ok | Should -BeTrue
        $b = $r | Where-Object { $_.Name -eq 'caj-si-b' }
        $b.Ok | Should -BeFalse
        $b.Changed | Should -Contain 'Trigger'
        $b.Error | Should -Match 'more than the image changed'
    }
    It 'NEGATIVE: a refused PATCH (not a 409) is reported with what ARM said, never retried, and the job is not counted as sent' {
        $jobs = @(New-Job 'caj-si-a' 'reg.io/si-orchestrator:old')
        $script:World = New-FakeAzure $jobs
        $bad = { param($Method, $Uri, $Body, $Resource, $Headers) if ($Method -eq 'PATCH') { $script:World.Calls.Add("PATCH $Uri"); return [pscustomobject]@{ Status = 400; Body = '{"error":{"code":"InvalidParameterValue","message":"no"}}' } }; & $script:Rest $Method $Uri $Body $Resource $Headers }
        $r = @(Invoke-SIJobImageRoll -Rest $bad -SubscriptionId 's' -ResourceGroup 'rg' -Targets @([pscustomobject]@{ Name = 'caj-si-a'; Image = 'x' }) -Jobs $jobs -PollSeconds 0 -RetrySeconds 0)
        $r[0].Ok | Should -BeFalse; $r[0].Sent | Should -BeFalse; $r[0].Error | Should -Match 'HTTP 400: InvalidParameterValue: no'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
    }
    It 'LIVE 2026-10-06: a job read in a newer schema (imageType) is still accepted -- read and PATCH share ONE api-version and the PATCH never carries imageType' {
        $jobs = @(1..16 | ForEach-Object { New-Job ("caj-si-{0}" -f $_) 'reg.io/si-orchestrator:old' })
        $script:World = New-FakeAzure $jobs
        $t = @($jobs | ForEach-Object { [pscustomobject]@{ Name = $_.name; Image = 'reg.io/si-orchestrator:new' } })
        $r = @(Invoke-SIJobImageRoll -Rest $script:Rest -SubscriptionId 's' -ResourceGroup 'rg' -Targets $t -Jobs $jobs -RepoPrefix 'reg.io/si-orchestrator' -PollSeconds 0 -RetrySeconds 0)
        @($r | Where-Object { $_.Ok }).Count | Should -Be 16
        $script:World.Bodies.Count | Should -Be 16
        foreach ($b in $script:World.Bodies.Values) { ConvertTo-Json -InputObject $b -Depth 30 | Should -Not -Match 'imageType' }
        # the body builder alone, also initContainers; a non-default imageType is kept, never guessed away
        $j = New-Job 'caj-si-x' 'reg.io/si-orchestrator:old'
        $j.properties.template | Add-Member -NotePropertyName initContainers -NotePropertyValue @([pscustomobject]@{ name = 'i'; image = 'reg.io/si-orchestrator:old'; imageType = 'ContainerImage' })
        New-SIJobImagePatchBody -Job $j -Image 'reg.io/si-orchestrator:new' -RepoPrefix 'reg.io/si-orchestrator' | Should -Not -Match 'imageType'
        $j.properties.template.containers[0].imageType = 'CloudBuild'
        New-SIJobImagePatchBody -Job $j -Image 'n' | Should -Match '"imageType":"CloudBuild"'
        # the api-version is one that knows imageType
        ($script:SIFastRollArmApi -ge '2024-08') | Should -BeTrue
    }
    It 'NEGATIVE (the live failure reproduced): with the OLD api-version an echoed imageType is refused, the job is not sent, and the roll reports ARM''s reason' {
        $jobs = @(New-Job 'caj-si-a' 'reg.io/si-orchestrator:old')
        $script:World = New-FakeAzure $jobs
        # the old roll's body: the template as read in the newer schema (imageType kept), sent at 2024-03-01 -- refused like ARM did live
        $tpl = ConvertTo-Json -InputObject $jobs[0].properties.template -Depth 60 | ConvertFrom-Json
        $tpl.containers[0].image = 'reg.io/si-orchestrator:new'
        $old = ConvertTo-Json -InputObject @{ properties = @{ template = $tpl } } -Depth 60 -Compress
        $u = 'https://management.azure.com/x/jobs/caj-si-a?api-version=2024-03-01'
        (& $script:Rest 'PATCH' $u $old 'https://management.azure.com/' $null).Body | Should -Match 'Unknown properties imageType'
        # the same template through today's body builder at the old api-version is accepted
        (& $script:Rest 'PATCH' $u (New-SIJobImagePatchBody -Job $jobs[0] -Image 'reg.io/si-orchestrator:new') 'https://management.azure.com/' $null).Status | Should -Be 200
        # and a refused PATCH is reported with ARM's reason, not sent (the roll itself)
        $refuse = { param($Method, $Uri, $Body, $Resource, $Headers) if ($Method -eq 'PATCH') { return [pscustomobject]@{ Status = 400; Body = 'Bad Request: Unknown properties imageType in ContainerAppContainer are not supported' } }; & $script:Rest $Method $Uri $Body $Resource $Headers }
        $r = @(Invoke-SIJobImageRoll -Rest $refuse -SubscriptionId 's' -ResourceGroup 'rg' -Targets @([pscustomobject]@{ Name = 'caj-si-a'; Image = 'reg.io/si-orchestrator:new' }) -Jobs $jobs -PollSeconds 0 -RetrySeconds 0)
        $r[0].Ok | Should -BeFalse; $r[0].Sent | Should -BeFalse
        $r[0].Error | Should -Match 'Unknown properties imageType'
    }
    It 'the ARM job list follows nextLink; a failing read falls back to the job list the caller read' {
        $j1 = New-Job 'caj-si-p1' 'i:1'; $j2 = New-Job 'caj-si-p2' 'i:1'
        $paged = { param($Method, $Uri, $Body, $Resource, $Headers)
            if ($Uri -like '*page2*') { [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject ([pscustomobject]@{ value = @($j2) }) -Depth 30) } }
            else { [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject ([pscustomobject]@{ value = @($j1); nextLink = 'https://management.azure.com/page2' }) -Depth 30) } } }
        @(Get-SIArmJobList -Rest $paged -SubscriptionId 's' -ResourceGroup 'rg' | ForEach-Object { $_.name }) | Should -Be @('caj-si-p1', 'caj-si-p2')
        { Get-SIArmJobList -Rest { param($Method, $Uri) [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"AuthorizationFailed","message":"no"}}' } } -SubscriptionId 's' -ResourceGroup 'rg' } | Should -Throw '*HTTP 403: AuthorizationFailed*'
        $jobs = @(New-Job 'caj-si-a' 'reg.io/si-orchestrator:old')
        $script:World = New-FakeAzure $jobs
        $script:GetFailed = $false
        $flaky = { param($Method, $Uri, $Body, $Resource, $Headers) if ($Method -eq 'GET' -and -not $script:GetFailed) { $script:GetFailed = $true; return [pscustomobject]@{ Status = 503; Body = 'transient' } }; & $script:Rest $Method $Uri $Body $Resource $Headers }
        $r = @(Invoke-SIJobImageRoll -Rest $flaky -SubscriptionId 's' -ResourceGroup 'rg' -Targets @([pscustomobject]@{ Name = 'caj-si-a'; Image = 'reg.io/si-orchestrator:new' }) -Jobs $jobs -PollSeconds 0 -RetrySeconds 0)
        $r[0].Ok | Should -BeTrue
        $script:World.Bodies['caj-si-a'] | ConvertTo-Json -Depth 30 | Should -Not -Match 'imageType'
    }
    It 'the fingerprint covers what an image swap must never change' {
        $a = Get-SIJobFingerprint -Job (New-Job 'j' 'i:1')
        $b = Get-SIJobFingerprint -Job (New-Job 'j' 'i:2')
        @(Compare-SIJobFingerprint -Before $a -After $b).Count | Should -Be 0     # the image is NOT part of it
        @(Compare-SIJobFingerprint -Before $a -After (Get-SIJobFingerprint -Job (New-Job 'j' 'i:1' -Env @{ A = '2' }))) | Should -Be @('Env')
        foreach ($k in 'Trigger', 'Schedule', 'Secrets', 'Env', 'Resources', 'Identity', 'Tags', 'Registries', 'Volumes') { $a.Keys | Should -Contain $k }
    }
}

Describe 'builds are queued together and waited for together (the registry''s own build over ARM)' {
    BeforeAll {
        # a fake registry behind the REST seam: the registry list, run states per run id, the upload slot and scheduleRun
        $script:Reg = [pscustomobject]@{ id = '/subscriptions/s/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/acr'; name = 'acr'; properties = [pscustomobject]@{ loginServer = 'acr.azurecr.io'; publicNetworkAccess = 'Enabled' } }
        $script:BuildRest = {
            param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $script:BuildCalls.Add(('{0} {1}' -f $Method, ($Uri -replace '\?.*$', '')))
            $j = { param($o) [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $o -Depth 10 -Compress) } }
            if ($Uri -like '*/providers/Microsoft.ContainerRegistry/registries?api-version=*') { return (& $j ([pscustomobject]@{ value = @($script:Reg) })) }
            if ($Uri -like '*/runs/*/listLogSasUrl*') { return (& $j ([pscustomobject]@{ logLink = 'https://acrlogs.blob.example/log?sig=x' })) }
            if ($Uri -like 'https://acrlogs.blob.example/*') { return [pscustomobject]@{ Status = 200; Body = "Step 1/3`nStep 2/3`nERROR: failed to solve: process did not complete successfully" } }
            if ($Method -eq 'GET' -and $Uri -match '/runs/([A-Za-z0-9]+)\?') {
                $id = $Matches[1]; $q = $script:Runs[$id]; $s = $q[0]; if ($q.Count -gt 1) { $script:Runs[$id] = @($q[1..($q.Count - 1)]) }
                return (& $j ([pscustomobject]@{ properties = [pscustomobject]@{ runId = $id; status = $s } }))
            }
            if ($Method -eq 'GET' -and $Uri -like '*/runs?api-version=*') { return (& $j ([pscustomobject]@{ value = @([pscustomobject]@{ properties = [pscustomobject]@{ runId = 'ca9'; outputImages = @([pscustomobject]@{ repository = 'si-orchestrator'; tag = 'v1' }) } }, [pscustomobject]@{ properties = [pscustomobject]@{ runId = 'ca8'; outputImages = @([pscustomobject]@{ repository = 'x'; tag = 'v1' }) } }) })) }
            if ($Uri -like '*/listBuildSourceUploadUrl*') { return (& $j ([pscustomobject]@{ uploadUrl = 'https://acrtasks.blob.example/src.tar.gz?sig=x'; relativePath = 'source/abc.tar.gz' })) }
            if ($Method -eq 'PUT' -and $Uri -like 'https://acrtasks.blob.example/*') { return [pscustomobject]@{ Status = 201; Body = '' } }
            if ($Uri -like '*/scheduleRun*') { return $script:ScheduleAnswer }
            [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
        }
    }
    BeforeEach { $script:BuildCalls = New-Object System.Collections.Generic.List[string]; $script:SIAcrRegistryCache = @{} }
    It 'Wait-SIAcrBuilds polls every queued run in the same loop until all are done; Queued / Started / Running mean still going' {
        $script:Runs = @{ r1 = @('Running', 'Succeeded'); r2 = @('Queued', 'Started', 'Running', 'Failed') }
        $b = @([pscustomobject]@{ Image = 'a:1'; RunId = 'r1'; Status = 'Queued'; Started = [datetime]::UtcNow }, [pscustomobject]@{ Image = 'b:1'; RunId = 'r2'; Status = 'Queued'; Started = [datetime]::UtcNow })
        $log = New-Object System.Collections.Generic.List[string]
        $r = @(Wait-SIAcrBuilds -Rest $script:BuildRest -SubscriptionId 's' -AcrName 'acr' -Builds $b -PollSeconds 0 -Log { param($m) $log.Add($m) }.GetNewClosure())
        ($r | Where-Object Image -eq 'a:1').Status | Should -Be 'Succeeded'
        ($r | Where-Object Image -eq 'b:1').Status | Should -Be 'Failed'
        # a failed build prints the end of its log
        (($r | Where-Object Image -eq 'b:1').LogTail)[-1] | Should -Match 'failed to solve'
        ($log -join "`n") | Should -Match 'build log of b:1 \(run r2\) ends'
        ($log -join "`n") | Should -Match '\| ERROR: failed to solve'
        @($script:BuildCalls | Where-Object { $_ -like '*listLogSasUrl*' }).Count | Should -Be 1 -Because 'only the failed run''s log is read'
    }
    It 'a queued build takes its run id from the registry''s answer (root or .properties), else from the newest run naming the image' {
        $ctx = Join-Path ([IO.Path]::GetTempPath()) ('si-fr-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path (Join-Path $ctx 'container') | Out-Null
        Set-Content -LiteralPath (Join-Path $ctx 'container\Dockerfile') -Value "FROM x.io/y:1`nCOPY . /app/"
        Push-Location -LiteralPath $ctx
        try {
            $script:ScheduleAnswer = [pscustomobject]@{ Status = 200; Body = '{"runId":"ca7"}' }
            (Start-SIAcrBuild -Rest $script:BuildRest -SubscriptionId 's' -AcrName 'acr' -Image 'si-orchestrator:v1' -File 'container/Dockerfile').RunId | Should -Be 'ca7'
            $script:ScheduleAnswer = [pscustomobject]@{ Status = 200; Body = '{"properties":{"runId":"ca6","status":"Queued"}}' }
            (Start-SIAcrBuild -Rest $script:BuildRest -SubscriptionId 's' -AcrName 'acr' -Image 'si-orchestrator:v1' -File 'container/Dockerfile').RunId | Should -Be 'ca6'
            $script:ScheduleAnswer = [pscustomobject]@{ Status = 202; Body = '' }
            (Start-SIAcrBuild -Rest $script:BuildRest -SubscriptionId 's' -AcrName 'acr' -Image 'si-orchestrator:v1' -File 'container/Dockerfile').RunId | Should -Be 'ca9'
            # an updater image from before #521 passes -Az: accepted and ignored (the release builds over REST itself)
            $script:ScheduleAnswer = [pscustomobject]@{ Status = 200; Body = '{"runId":"ca5"}' }
            (Start-SIAcrBuild -Rest $script:BuildRest -Az { throw 'az must never be called' } -SubscriptionId 's' -AcrName 'acr' -Image 'si-orchestrator:v1' -File 'container/Dockerfile').RunId | Should -Be 'ca5'
        } finally { Pop-Location; Remove-Item -LiteralPath $ctx -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'a build that cannot be queued THROWS with what Azure said (the caller then builds nothing and says why)' {
        $ctx = Join-Path ([IO.Path]::GetTempPath()) ('si-fr-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $ctx | Out-Null
        Set-Content -LiteralPath (Join-Path $ctx 'Dockerfile') -Value 'FROM x.io/y:1'
        Push-Location -LiteralPath $ctx
        try {
            $script:ScheduleAnswer = [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"AuthorizationFailed","message":"no scheduleRun"}}' }
            { Start-SIAcrBuild -Rest $script:BuildRest -SubscriptionId 's' -AcrName 'acr' -Image 'si-x:1' -File 'Dockerfile' } | Should -Throw '*HTTP 403: AuthorizationFailed: no scheduleRun*'
        } finally { Pop-Location; Remove-Item -LiteralPath $ctx -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'WIRING: the product paths use the fast roll' {
    It 'Invoke-SIContainerUpdate.ps1 builds through it and swaps every job with Invoke-SIJobImageRoll (no az job update one by one)' {
        $cu = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')
        $cu | Should -Match '_shared/SI-FastRoll\.ps1'
        $cu | Should -Match 'Invoke-SIJobImageRoll'
        $cu | Should -Match 'Get-SIImageLayerPlan'
        $cu | Should -Not -Match "'containerapp', 'job', 'update'"
    }
    It 'the updater loads its fast roll, queues every other image before the engine roll, and its builds wait for the queued ones' {
        $su = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $su | Should -Match '_shared/SI-UpdaterFastRoll\.ps1'
        $iPre = $su.IndexOf('Start-SIUpdaterPrebuilds -SIRoot'); $iRoll = $su.IndexOf("setup/Invoke-SIContainerUpdate.ps1') -Apply")
        $iPre | Should -BeGreaterThan 0; $iPre | Should -BeLessThan $iRoll
        $iDb = $su.IndexOf('Invoke-SIUpdaterDatabase -SIRoot'); $iDb | Should -BeLessThan $iPre     # #352: the database step stays FIRST
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterSelf.ps1')) | Should -Match 'Invoke-SIUpdaterFastBuild'
    }
}
