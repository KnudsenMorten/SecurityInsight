#Requires -Version 5.1
<#
    #521 THE IMAGE BUILD WITHOUT THE AZURE CLI -- setup/_shared/SI-AcrBuild.ps1, ported from PIM4EntraPS's proven
    engine/_shared/PIM-AcrBuild.ps1: listBuildSourceUploadUrl -> PUT the .tar.gz to the SAS -> scheduleRun -> GET runs/<id>.
    Against a fake registry behind the REST seam (setup/_shared/SI-UpdateRest.ps1). Proves the four traps PIM learned live:
    the upload carries NO bearer token and DOES carry x-ms-blob-type: BlockBlob; image names are registry-relative;
    Queued / Started / Running all mean still going; a registry with public access Disabled needs an agent pool. Also: the
    build context is packed with .NET (no tar.exe), .dockerignore applied before anything leaves; a failed run's log tail is
    printed; the tag check reads the registry's own data plane. Offline. Windows PowerShell 5.1 and PowerShell 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-FastRoll.ps1')   # loads SI-AcrBuild.ps1 and SI-UpdateRest.ps1
    function script:New-Reg([string]$Access = 'Enabled') {
        [pscustomobject]@{ id = '/subscriptions/s1/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/acrsi'; name = 'acrsi'
            properties = [pscustomobject]@{ loginServer = 'acrsi.azurecr.io'; publicNetworkAccess = $Access } }
    }
    # the fake registry: every call recorded with what it carried (method, url, resource = token audience, headers, body)
    function script:New-RegWorld([string]$Access = 'Enabled', [string[]]$States = @('Queued', 'Running', 'Succeeded'), [string[]]$Pools = @(), [string]$Log = '', [int]$ManifestStatus = 200) {
        [pscustomobject]@{ Reg = (New-Reg $Access); States = [System.Collections.Generic.List[string]]$States; Pools = $Pools; Log = $Log; ManifestStatus = $ManifestStatus
            Calls = (New-Object System.Collections.Generic.List[object]); Uploaded = $null; Scheduled = $null }
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:W
        $w.Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Resource = $Resource; Headers = $(if ($Headers) { $Headers.Clone() } else { @{} }); Body = $Body })
        $j = { param($o) [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $o -Depth 10 -Compress) } }
        $arm = ($Resource -eq 'https://management.azure.com/')
        if ($Uri -like 'https://management.azure.com/*' -and -not $arm) { return [pscustomobject]@{ Status = 401; Body = 'ARM needs its token' } }
        if ($Uri -like '*/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/acrsi?api-version=*') { return (& $j $w.Reg) }
        if ($Uri -like '*/resourceGroups/*/providers/Microsoft.ContainerRegistry/registries/acrsi?api-version=*') { return [pscustomobject]@{ Status = 404; Body = '{"error":{"code":"ResourceNotFound","message":"no"}}' } }
        if ($Uri -like '*/providers/Microsoft.ContainerRegistry/registries?api-version=*') { return (& $j ([pscustomobject]@{ value = @($w.Reg) })) }
        if ($Uri -like '*/registries/acrsi/listBuildSourceUploadUrl?api-version=2019-06-01-preview') { return (& $j ([pscustomobject]@{ uploadUrl = 'https://acrtasks.blob.example/ctx.tar.gz?sv=x&sig=y'; relativePath = 'source/20261009/ctx.tar.gz' })) }
        if ($Uri -like 'https://acrtasks.blob.example/*') { $w.Uploaded = $Body; return [pscustomobject]@{ Status = 201; Body = '' } }
        if ($Uri -like '*/registries/acrsi/agentPools?api-version=*') { return (& $j ([pscustomobject]@{ value = @($w.Pools | ForEach-Object { [pscustomobject]@{ name = $_ } }) })) }
        if ($Uri -like '*/registries/acrsi/scheduleRun?api-version=2019-06-01-preview') { $w.Scheduled = ([string]$Body | ConvertFrom-Json); return (& $j ([pscustomobject]@{ properties = [pscustomobject]@{ runId = 'cb1'; status = 'Queued' } })) }
        if ($Uri -like '*/registries/acrsi/runs/cb1/listLogSasUrl?api-version=*') { return (& $j ([pscustomobject]@{ logLink = 'https://acrlogs.blob.example/cb1.log?sig=z' })) }
        if ($Uri -like 'https://acrlogs.blob.example/*') { return [pscustomobject]@{ Status = 200; Body = $w.Log } }
        if ($Uri -like '*/registries/acrsi/runs/cb1?api-version=2019-06-01-preview') {
            $s = $w.States[0]; if ($w.States.Count -gt 1) { $w.States.RemoveAt(0) }
            return (& $j ([pscustomobject]@{ properties = [pscustomobject]@{ runId = 'cb1'; status = $s } }))
        }
        if ($Uri -eq 'https://acrsi.azurecr.io/oauth2/exchange') { return (& $j ([pscustomobject]@{ refresh_token = 'acr-refresh' })) }
        if ($Uri -eq 'https://acrsi.azurecr.io/oauth2/token') { return (& $j ([pscustomobject]@{ access_token = 'acr-access' })) }
        if ($Uri -like 'https://acrsi.azurecr.io/v2/*/manifests/*') { return [pscustomobject]@{ Status = $w.ManifestStatus; Body = '' } }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
    $script:Token = { param($Resource) 'aad-' + $Resource }
    # the entry names of a .tar.gz (ustar, GNU long names and PAX path records understood) -- to read back what was packed
    function script:Get-TgzEntryNames([string]$Path) {
        $fs = [IO.File]::OpenRead($Path)
        try { $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress); $ms = New-Object System.IO.MemoryStream; $gz.CopyTo($ms); $gz.Dispose(); $b = $ms.ToArray() } finally { $fs.Dispose() }
        $names = New-Object System.Collections.Generic.List[string]; $pending = $null; $o = 0
        while ($o + 512 -le $b.Length) {
            $h = [byte[]]$b[$o..($o + 511)]
            if (-not ($h | Where-Object { $_ -ne 0 })) { break }
            $str = { param($s, $n) ([Text.Encoding]::UTF8.GetString($h, $s, $n)).Split([char]0)[0] }
            $name = & $str 0 100; $prefix = & $str 345 155
            $size = [Convert]::ToInt64(((& $str 124 12).Trim()), 8)
            $type = [char]$h[156]
            $data = if ($size) { [Text.Encoding]::UTF8.GetString($b, $o + 512, [int]$size) } else { '' }
            if ($type -eq 'L') { $pending = $data.TrimEnd([char]0) }
            elseif ($type -eq 'x') { foreach ($rec in ($data -split "`n")) { if ($rec -match '^\d+ path=(.*)$') { $pending = $Matches[1] } } }
            elseif ($type -in '0', [char]0) { $names.Add($(if ($pending) { $pending } elseif ($prefix) { $prefix + '/' + $name } else { $name })); $pending = $null }
            $o += 512 + [int]([Math]::Ceiling($size / 512.0) * 512)
        }
        $names.ToArray()
    }
    function script:New-Context {
        $c = Join-Path ([IO.Path]::GetTempPath()) ('si-acr-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        foreach ($d in 'container', 'engine\_shared', 'config', '.git', ('risk-analysis-detection\' + ('deep' * 20))) { New-Item -ItemType Directory -Force -Path (Join-Path $c $d) | Out-Null }
        Set-Content -LiteralPath (Join-Path $c 'container\Dockerfile') -Value "FROM x.io/y:1`nCOPY . /app/"
        Set-Content -LiteralPath (Join-Path $c 'engine\_shared\SI-X.ps1') -Value '1'
        Set-Content -LiteralPath (Join-Path $c 'config\SecurityInsight.custom.ps1') -Value '$secret = 1'
        Set-Content -LiteralPath (Join-Path $c 'config\example.locked.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $c 'engine\_shared\tenant.custom.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $c '.git\HEAD') -Value 'ref'
        Set-Content -LiteralPath (Join-Path $c ('risk-analysis-detection\' + ('deep' * 20) + '\rule-with-a-long-name-to-pass-one-hundred-characters.yaml')) -Value 'x'
        Copy-Item -LiteralPath (Join-Path $script:SIRoot '.dockerignore') -Destination (Join-Path $c '.dockerignore')
        $c
    }
}

Describe 'the build context: packed with .NET, .dockerignore applied before anything leaves' {
    It 'Docker''s rules: a pattern matches the path or a folder above it, ** spans folders, the last match wins, ! keeps' {
        $rules = @(Get-SIDockerIgnoreRules -Text "# c`n**/*.custom.ps1`n**/config/`n!config/*.locked.json`ninternal/`nanalyzer-web/**/bin`n")
        Test-SIDockerIgnored -RelativePath 'config/SecurityInsight.custom.ps1' -Rules $rules | Should -BeTrue
        Test-SIDockerIgnored -RelativePath 'a/b/x.custom.ps1' -Rules $rules | Should -BeTrue
        Test-SIDockerIgnored -RelativePath 'x.custom.ps1' -Rules $rules | Should -BeTrue -Because '**/ matches zero folders too'
        Test-SIDockerIgnored -RelativePath 'config/example.locked.json' -Rules $rules | Should -BeFalse -Because 'the exception after the folder rule keeps it'
        Test-SIDockerIgnored -RelativePath 'sub/config/x.json' -Rules $rules | Should -BeTrue
        Test-SIDockerIgnored -RelativePath 'internal/deep/file.md' -Rules $rules | Should -BeTrue
        Test-SIDockerIgnored -RelativePath 'analyzer-web/src/x/bin/a.dll' -Rules $rules | Should -BeTrue
        Test-SIDockerIgnored -RelativePath 'engine/_shared/SI-AzRest.ps1' -Rules $rules | Should -BeFalse
        Test-SIDockerIgnored -RelativePath 'container/Dockerfile' -Rules $rules | Should -BeFalse
    }
    It 'the real context: customer files and .git never packed, shipped files kept, a Dockerfile outside the context travels as .si-build/<name> -- both writers' {
        $c = New-Context
        $extra = Join-Path ([IO.Path]::GetTempPath()) ('Dockerfile.app-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Set-Content -LiteralPath $extra -Value 'FROM acrsi.azurecr.io/si-base:abc'
        try {
            foreach ($fmt in 'Auto', 'Ustar') {
                $out = Join-Path ([IO.Path]::GetTempPath()) ('si-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.tar.gz')
                try {
                    $p = New-SIBuildContextArchive -Path $c -OutFile $out -Extra @{ '.si-build/Dockerfile.app' = $extra } -Format $fmt
                    $names = @(Get-TgzEntryNames $out)
                    $names | Should -Contain 'container/Dockerfile'
                    $names | Should -Contain 'engine/_shared/SI-X.ps1'
                    $names | Should -Contain 'config/example.locked.json'
                    $names | Should -Contain '.si-build/Dockerfile.app'
                    $names | Should -Contain ('risk-analysis-detection/' + ('deep' * 20) + '/rule-with-a-long-name-to-pass-one-hundred-characters.yaml') -Because 'a name over 100 characters survives'
                    $names | Should -Not -Contain 'config/SecurityInsight.custom.ps1'
                    $names | Should -Not -Contain 'engine/_shared/tenant.custom.json'
                    @($names | Where-Object { $_ -like '.git/*' }) | Should -BeNullOrEmpty
                    @($p.Files).Count | Should -Be $names.Count
                    if ($fmt -eq 'Ustar') { $p.Writer | Should -Be 'ustar' }
                    elseif ('System.Formats.Tar.TarWriter' -as [type]) { $p.Writer | Should -Be 'System.Formats.Tar' }
                } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
            }
        } finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $extra -Force -ErrorAction SilentlyContinue }
    }
    It 'the Dockerfile the build names is always packed, even when .dockerignore would leave it out' {
        $c = Join-Path ([IO.Path]::GetTempPath()) ('si-acr-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path (Join-Path $c 'webapp') | Out-Null
        Set-Content -LiteralPath (Join-Path $c 'webapp\Dockerfile') -Value 'FROM x'
        Set-Content -LiteralPath (Join-Path $c '.dockerignore') -Value "**/Dockerfile"
        try { @(Get-SIBuildContextFiles -Path $c -Keep @('webapp/Dockerfile') | ForEach-Object { $_.Rel }) | Should -Contain 'webapp/Dockerfile' }
        finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'the four calls (PIM''s proven REST build)' {
    BeforeEach { $script:SIAcrRegistryCache = @{} }
    It 'upload slot -> PUT to the SAS WITHOUT a bearer token and WITH x-ms-blob-type: BlockBlob -> scheduleRun -> the run id' {
        $script:W = New-RegWorld
        $c = New-Context
        try { $q = Invoke-SIAcrQueueBuild -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -ResourceGroup 'rg-acr' -ContextPath $c -Image 'si-orchestrator:v3.0.1-abc' -DockerfilePath 'container/Dockerfile' }
        finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue }
        $q.RunId | Should -Be 'cb1' -Because 'the run id under .properties is read'
        $up = @($script:W.Calls | Where-Object { $_.Uri -like 'https://acrtasks.blob.example/*' })
        $up.Count | Should -Be 1
        $up[0].Method | Should -Be 'PUT'
        $up[0].Resource | Should -Be '' -Because 'the SAS is the credential: no ARM token may be attached'
        $up[0].Headers.ContainsKey('Authorization') | Should -BeFalse
        $up[0].Headers['x-ms-blob-type'] | Should -Be 'BlockBlob'
        ($script:W.Uploaded -is [byte[]]) | Should -BeTrue
        $script:W.Uploaded[0] | Should -Be 0x1f -Because 'a gzip stream'
        # ARM: the slot, then the run -- the tasks api-version pinned, ARM's own token
        $order = @($script:W.Calls | ForEach-Object { ($_.Uri -replace '\?.*$', '') -replace '^.*/', '' })
        $order.IndexOf('listBuildSourceUploadUrl') | Should -BeLessThan $order.IndexOf('ctx.tar.gz')
        $order.IndexOf('ctx.tar.gz') | Should -BeLessThan $order.IndexOf('scheduleRun')
        foreach ($a in @($script:W.Calls | Where-Object { $_.Uri -like '*listBuildSourceUploadUrl*' -or $_.Uri -like '*scheduleRun*' })) { $a.Resource | Should -Be 'https://management.azure.com/'; $a.Uri | Should -Match 'api-version=2019-06-01-preview$' }
    }
    It 'the DockerBuildRequest: registry-RELATIVE image (a login-server prefix is taken off), Linux / amd64, push on, the slot''s relative path, the Dockerfile in the context' {
        $script:W = New-RegWorld
        $c = New-Context
        try { $null = Invoke-SIAcrQueueBuild -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -ResourceGroup 'rg-acr' -ContextPath $c -Image 'acrsi.azurecr.io/si-orchestrator:v3.0.1-abc' -DockerfilePath 'container/Dockerfile' }
        finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue }
        $s = $script:W.Scheduled
        $s.type | Should -Be 'DockerBuildRequest'
        @($s.imageNames) | Should -Be @('si-orchestrator:v3.0.1-abc')
        @($s.imageNames)[0] | Should -Not -Match 'azurecr\.io'
        $s.platform.os | Should -Be 'Linux'; $s.platform.architecture | Should -Be 'amd64'
        $s.isPushEnabled | Should -BeTrue
        $s.sourceLocation | Should -Be 'source/20261009/ctx.tar.gz'
        $s.dockerFilePath | Should -Be 'container/Dockerfile'
        $s.PSObject.Properties['agentPoolName'] | Should -BeNullOrEmpty -Because 'a public registry builds on the shared agents'
        ConvertTo-SIAcrRelativeImage -Image 'si-x:1' | Should -Be 'si-x:1'
        ConvertTo-SIAcrRelativeImage -Image 'other.azurecr.io/si-x:1' | Should -Be 'si-x:1'
    }
    It 'a Dockerfile outside the context is packed and named .si-build/<name>' {
        $script:W = New-RegWorld
        $c = New-Context
        $df = Join-Path ([IO.Path]::GetTempPath()) ('Dockerfile.base')
        Set-Content -LiteralPath $df -Value 'FROM mcr.microsoft.com/powershell:lts'
        try { $null = Invoke-SIAcrQueueBuild -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -ResourceGroup 'rg-acr' -ContextPath $c -Image 'si-updater-base:abc' -DockerfilePath $df }
        finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $df -Force -ErrorAction SilentlyContinue }
        $script:W.Scheduled.dockerFilePath | Should -Be '.si-build/Dockerfile.base'
    }
    It 'a registry with public access Disabled builds on its agent pool (the shared agents are refused there); a set pool wins' {
        $script:W = New-RegWorld -Access 'Disabled' -Pools @('pool-vnet')
        $c = New-Context
        try { $null = Invoke-SIAcrQueueBuild -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -ResourceGroup 'rg-acr' -ContextPath $c -Image 'si-x:1' -DockerfilePath 'container/Dockerfile' }
        finally { Remove-Item -LiteralPath $c -Recurse -Force -ErrorAction SilentlyContinue }
        $script:W.Scheduled.agentPoolName | Should -Be 'pool-vnet'
        $prev = [Environment]::GetEnvironmentVariable('SI_UPDATER_ACR_AGENT_POOL')
        [Environment]::SetEnvironmentVariable('SI_UPDATER_ACR_AGENT_POOL', 'pool-set')
        try { Resolve-SIAcrAgentPool -Rest $script:Rest -Registry ([pscustomobject]@{ Id = 'x'; PublicNetworkAccess = 'Enabled' }) | Should -Be 'pool-set' }
        finally { [Environment]::SetEnvironmentVariable('SI_UPDATER_ACR_AGENT_POOL', $prev) }
    }
    It 'the registry is found in its resource group, else among every registry of the subscription (as az acr show --name did)' {
        $script:W = New-RegWorld
        (Get-SIAcrRegistry -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -ResourceGroup 'rg-jobs').LoginServer | Should -Be 'acrsi.azurecr.io'
        $script:SIAcrRegistryCache = @{}
        $r = Get-SIAcrRegistry -Rest $script:Rest -SubscriptionId 's1' -AcrName 'ACRSI'
        $r.ResourceGroup | Should -Be 'rg-acr'
        $script:SIAcrRegistryCache = @{}
        { Get-SIAcrRegistry -Rest $script:Rest -SubscriptionId 's1' -AcrName 'nope' } | Should -Throw '*was not found*'
    }
}

Describe 'following the run: Queued / Started / Running are still going; a failure prints the end of its log' {
    BeforeEach { $script:SIAcrRegistryCache = @{} }
    It 'polls through every running state to Succeeded' {
        $script:W = New-RegWorld -States @('Queued', 'Started', 'Running', 'Running', 'Succeeded')
        $b = @([pscustomobject]@{ Image = 'si-x:1'; RunId = 'cb1'; Status = 'Queued'; Started = [datetime]::UtcNow })
        $r = @(Wait-SIAcrBuilds -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Builds $b -PollSeconds 0)
        $r[0].Status | Should -Be 'Succeeded'
        @($script:W.Calls | Where-Object { $_.Uri -like '*/runs/cb1?*' }).Count | Should -Be 5
        @($script:W.Calls | Where-Object { $_.Uri -like '*listLogSasUrl*' }).Count | Should -Be 0
    }
    It 'a failed run: the log link is asked for, the log read WITHOUT a token, its tail printed and kept' {
        $log = (1..50 | ForEach-Object { "step line $_" }) -join "`n"
        $script:W = New-RegWorld -States @('Running', 'Failed') -Log ($log + "`nERROR: failed to solve: process `"/bin/sh -c apt-get`" did not complete successfully: exit code: 100")
        $lines = New-Object System.Collections.Generic.List[string]
        $b = @([pscustomobject]@{ Image = 'si-x:1'; RunId = 'cb1'; Status = 'Queued'; Started = [datetime]::UtcNow })
        $r = @(Wait-SIAcrBuilds -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Builds $b -PollSeconds 0 -Log { param($m) $lines.Add($m) }.GetNewClosure())
        $r[0].Status | Should -Be 'Failed'
        @($r[0].LogTail).Count | Should -Be 30
        @($r[0].LogTail)[-1] | Should -Match 'exit code: 100'
        ($lines -join "`n") | Should -Match 'build si-x:1: Failed'
        ($lines -join "`n") | Should -Match '\| ERROR: failed to solve'
        $sas = @($script:W.Calls | Where-Object { $_.Uri -like 'https://acrlogs.blob.example/*' })
        $sas.Count | Should -Be 1
        $sas[0].Resource | Should -Be ''
        @($script:W.Calls | Where-Object { $_.Uri -like '*listLogSasUrl*' })[0].Method | Should -Be 'POST'
    }
    It 'a run still going at the deadline is a Timeout, never a success' {
        $script:W = New-RegWorld -States @('Running')
        $b = @([pscustomobject]@{ Image = 'si-x:1'; RunId = 'cb1'; Status = 'Queued'; Started = [datetime]::UtcNow })
        (@(Wait-SIAcrBuilds -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Builds $b -PollSeconds 0 -TimeoutMinutes 0))[0].Status | Should -Be 'Timeout'
    }
}

Describe 'the tag check reads the registry itself (was az acr repository show-tags)' {
    BeforeEach { $script:SIAcrRegistryCache = @{} }
    It 'ARM token -> registry refresh token -> pull token for that repository -> HEAD of the manifest' {
        $script:W = New-RegWorld -ManifestStatus 200
        Test-SIAcrTag -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Repo 'si-orchestrator' -Tag 'v1' -Token $script:Token | Should -BeTrue
        $ex = @($script:W.Calls | Where-Object { $_.Uri -like '*/oauth2/exchange' })[0]
        $ex.Resource | Should -Be ''; [string]$ex.Body | Should -Match 'grant_type=access_token&service=acrsi\.azurecr\.io&access_token=aad-https'
        $ex.Headers['Content-Type'] | Should -Be 'application/x-www-form-urlencoded'
        [string](@($script:W.Calls | Where-Object { $_.Uri -like '*/oauth2/token' })[0].Body) | Should -Match ([regex]::Escape('scope=repository%3Asi-orchestrator%3Apull'))
        $h = @($script:W.Calls | Where-Object { $_.Method -eq 'HEAD' })[0]
        $h.Uri | Should -Be 'https://acrsi.azurecr.io/v2/si-orchestrator/manifests/v1'
        $h.Headers['Authorization'] | Should -Be 'Bearer acr-access'
        $h.Resource | Should -Be '' -Because 'the registry token is the credential, not an ARM token'
    }
    It '404 = not there (the image is built); any other answer = not known = $false, never a throw' {
        $script:W = New-RegWorld -ManifestStatus 404
        Test-SIAcrTag -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Repo 'si-orchestrator' -Tag 'v1' -Token $script:Token | Should -BeFalse
        $script:W = New-RegWorld -ManifestStatus 401
        { Test-SIAcrManifest -Rest $script:Rest -LoginServer 'acrsi.azurecr.io' -Repo 'si-x' -Tag '1' -Token $script:Token } | Should -Throw '*HTTP 401*'
        Test-SIAcrTag -Rest $script:Rest -SubscriptionId 's1' -AcrName 'acrsi' -Repo 'si-x' -Tag '1' -Token $script:Token | Should -BeFalse
    }
}

Describe 'the REST seam of an update (setup/_shared/SI-UpdateRest.ps1)' {
    It 'the updater job''s identity: managed identity, certificate, or the run''s own sign-in -- an unknown mode is refused' {
        (Get-SIUpdateRestSignIn -Env @{ SI_UPDATER_CLIENT_ID = 'c1'; SI_UPDATER_AUTH = 'ManagedIdentity' }).Mode | Should -Be 'ManagedIdentity'
        $c = Get-SIUpdateRestSignIn -Env @{ SI_UPDATER_CLIENT_ID = 'c1'; SI_UPDATER_TENANT_ID = 't1'; SI_UPDATER_CERT_PFX_B64 = 'AAAA'; SI_UPDATER_CERT_PASSWORD = 'pw' }
        $c.Mode | Should -Be 'Certificate'; $c.TenantId | Should -Be 't1'
        { Get-SIUpdateRestSignIn -Env @{ SI_UPDATER_CLIENT_ID = 'c1'; SI_UPDATER_AUTH = 'Certificate' } } | Should -Throw '*SI_UPDATER_CERT_PFX_B64*'
        { Get-SIUpdateRestSignIn -Env @{ SI_UPDATER_CLIENT_ID = 'c1'; SI_UPDATER_AUTH = 'AzCli' } } | Should -Throw "*must be 'ManagedIdentity' or 'Certificate'*"
        $prev = [Environment]::GetEnvironmentVariable('SI_UPDATER_CLIENT_ID'); [Environment]::SetEnvironmentVariable('SI_UPDATER_CLIENT_ID', $null)
        try { (Get-SIUpdateRestSignIn -Env @{}).Mode | Should -Be 'Config' } finally { [Environment]::SetEnvironmentVariable('SI_UPDATER_CLIENT_ID', $prev) }
    }
    It 'the token audience follows the resource; '''' = no token at all' {
        Get-SIUpdateRestAudience -Resource 'https://management.azure.com/' | Should -Be 'Arm'
        Get-SIUpdateRestAudience -Resource 'https://storage.azure.com/' | Should -Be 'Storage'
        Get-SIUpdateRestAudience -Resource 'https://graph.microsoft.com/' | Should -Be 'Graph'
        Get-SIUpdateRestAudience -Resource 'https://vault.azure.net/' | Should -Be 'KeyVault'
        Get-SIUpdateRestAudience -Resource '' | Should -Be ''
    }
    It 'a call without a token goes to the HTTP seam with NO Authorization header; an ARM call through the token client' {
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 201; Content = ''; Headers = @{}; RetryAfter = '' } }
        $r = Invoke-SIUpdateRestCall -Method PUT -Uri 'https://x.blob.example/c?sig=1' -Body ([byte[]](1, 2)) -Resource '' -Headers @{ 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/octet-stream' }
        $r.Status | Should -Be 201
        Should -Invoke Invoke-SIAzRestHttp -Times 1 -Exactly -ParameterFilter { -not $Headers.ContainsKey('Authorization') -and $Headers['x-ms-blob-type'] -eq 'BlockBlob' -and $ContentType -eq 'application/octet-stream' }
        Mock Invoke-SIAzRestRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"a":1}'; Headers = @{} } }
        (Invoke-SIUpdateRestCall -Method GET -Uri 'https://management.azure.com/x' -Resource 'https://management.azure.com/').Body | Should -Be '{"a":1}'
        Should -Invoke Invoke-SIAzRestRequest -Times 1 -Exactly -ParameterFilter { $Audience -eq 'Arm' -and ($AllowStatus -contains 409) -and ($AllowStatus -notcontains 401) }
    }
    It 'Invoke-SIRestJson: a success is parsed, 404 with -AllowNotFound is $null, anything else throws with what Azure said' {
        $ok = { param($Method, $Uri) [pscustomobject]@{ Status = 200; Body = '{"x":1}' } }
        (Invoke-SIRestJson -Rest $ok -Uri 'https://management.azure.com/a').x | Should -Be 1
        $nf = { param($Method, $Uri) [pscustomobject]@{ Status = 404; Body = '' } }
        Invoke-SIRestJson -Rest $nf -Uri 'https://management.azure.com/a' -AllowNotFound | Should -BeNullOrEmpty
        $bad = { param($Method, $Uri) [pscustomobject]@{ Status = 409; Body = '{"error":{"code":"ContainerAppsJobOperationInProgress","message":"busy"}}' } }
        { Invoke-SIRestJson -Rest $bad -Uri 'https://management.azure.com/a' -What 'the job' } | Should -Throw 'the job failed: HTTP 409: ContainerAppsJobOperationInProgress: busy'
    }
    It 'the one-container image PATCH body (the updater''s own job, the web app): the whole template, only the first image changed' {
        $res = [pscustomobject]@{ properties = [pscustomobject]@{ configuration = [pscustomobject]@{ secrets = @([pscustomobject]@{ name = 's' }) }
            template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'u'; image = 'acrsi.azurecr.io/si-updater:old'; imageType = 'ContainerImage'; env = @([pscustomobject]@{ name = 'A'; value = '1' }); resources = [pscustomobject]@{ cpu = 0.5; memory = '1Gi'; ephemeralStorage = '2Gi' } }) } } }
        $b = New-SITemplateImagePatchBody -Resource $res -Image 'acrsi.azurecr.io/si-updater:new' | ConvertFrom-Json
        @($b.properties.PSObject.Properties.Name) | Should -Be @('template')
        $b.properties.template.containers[0].image | Should -Be 'acrsi.azurecr.io/si-updater:new'
        $b.properties.template.containers[0].env[0].name | Should -Be 'A'
        $b.properties.template.containers[0].PSObject.Properties['imageType'] | Should -BeNullOrEmpty
        $res.properties.template.containers[0].image | Should -Be 'acrsi.azurecr.io/si-updater:old'
    }
}
