#Requires -Version 5.1
<#
    #350 (c) -- caj-si-updater UPDATES ITSELF, LAST (PIM4EntraPS's ca-pim-update: "3. ITSELF, last").

    After the engine jobs, the web app and the MCP server are rolled and healthy, the run builds the updater image from the
    SAME verified release (container/updater/Dockerfile) and points its OWN job at it -- the last change of the run. The running
    execution finishes on the image it started with (a Container Apps job's template is read when an execution starts). A
    failed self-roll never fails the update: the job is marked (si-updater-pending), UpdateState says so, the next run retries.

    And the Windows long-path build problem (#350): `az acr build` from a deep folder cannot read paths over 260 characters,
    so a deep build context is copied to a short stage first (setup/_shared/SI-BuildStage.ps1) -- in the product path.

    Offline: a fake ARM behind the updater's one ARM seam (#521: no az). Runs on PS 5.1 and pwsh 7. (The run that calls it -- after a roll from Invardia, or to retry an owed self-update -- is tested in SIv3-InvardiaUpdate.Tests.ps1.)
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuildStage.ps1')

    $script:Login  = 'reg.example.io'
    $script:C42 = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'
    $script:C40 = 'ffff0000eeee1111dddd2222cccc3333bbbb4444'
    $script:Tag42 = 'v3.0.0-rc.42-a1b2c3d4e5f6'

    # A release archive: SOLUTIONS/SecurityInsight with VERSION, BUILD.json and (optionally) the updater's Dockerfile.
    function script:New-ReleaseZip([string]$OutFile, [string]$Display, [string]$Commit, [bool]$WithDockerfile = $true) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-self-src-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $si = Join-Path $src "r\SOLUTIONS\SecurityInsight"
        New-Item -ItemType Directory -Force (Join-Path $si 'setup') | Out-Null
        Set-Content -LiteralPath (Join-Path $si 'VERSION') -Value (($Display -split '-')[0]) -NoNewline
        Set-Content -LiteralPath (Join-Path $si 'BUILD.json') -Value (@{ version = ($Display -split '-')[0]; display = $Display; commit = $Commit } | ConvertTo-Json)
        if ($WithDockerfile) {
            New-Item -ItemType Directory -Force (Join-Path $si 'container\updater') | Out-Null
            Set-Content -LiteralPath (Join-Path $si 'container\updater\Dockerfile') -Value 'FROM x'
        }
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $OutFile)
        Remove-Item -LiteralPath $src -Recurse -Force
    }
    function script:Set-Scenario([hashtable]$Record, [string]$UpdaterImage = 'reg.example.io/si-updater:v3.0.0', [string]$Pending = '', [string[]]$RegistryTags = @(),
                                 [int]$JobUpdateConflicts = 0, [switch]$JobUpdateFails, [switch]$BuildFails, [bool]$WithDockerfile = $true) {
        $script:Record = $Record; $script:UpdaterImage = $UpdaterImage; $script:Pending = $Pending; $script:RegistryTags = $RegistryTags
        $script:Conflicts = $JobUpdateConflicts; $script:JobUpdateFails = [bool]$JobUpdateFails; $script:BuildFails = [bool]$BuildFails
        $script:WithDockerfile = $WithDockerfile
        $script:Az = New-Object System.Collections.Generic.List[string]
        $script:Fetched = New-Object System.Collections.Generic.List[string]
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $script:LastZip = $null
    }
    # A fake Pro database: records every statement and its parameters (the UpdateState row is what the header reads).
    $script:Store = [pscustomobject]@{ Name = 'fake'; Invoke = { param($sql, $p, $mode) $script:Sql.Add([pscustomobject]@{ Sql = $sql; P = $p }) } }
    function script:Get-UpdateState { $r = @($script:Sql | Where-Object { $_.Sql -like "*N'UpdateState'*" } | Select-Object -Last 1); if ($r.Count) { $r[0].P['Value'] | ConvertFrom-Json } }
}

Describe 'the self-update decisions (pure)' {
    It 'the image tag is the build: version + 12 characters of the commit' {
        New-SIUpdaterBuildTag -Version '3.0.0-rc.42' -Commit $script:C42 | Should -Be $script:Tag42
        New-SIUpdaterBuildTag -Version '3.0.0' -Commit '' | Should -Be 'v3.0.0-build'
    }
    It 'SI_UPDATER_SELF_UPDATE = 0 / false / off / no switches it off; unset or anything else = on' {
        foreach ($v in '0', 'false', 'OFF', 'no') { Test-SIUpdaterSelfDisabled $v | Should -BeTrue }
        foreach ($v in '', $null, '1', 'on', 'yes') { Test-SIUpdaterSelfDisabled $v | Should -BeFalse }
    }
    It 'off / current / roll (in the registry) / build / skipped (nothing to build it from)' {
        $t = 'reg.example.io/si-updater:' + $script:Tag42
        (Get-SIUpdaterSelfDecision -CurrentImage 'x' -TargetImage $t -InRegistry $true -HasDockerfile $true -Disabled $true).Action | Should -Be 'off'
        (Get-SIUpdaterSelfDecision -CurrentImage $t -TargetImage $t -InRegistry $false -HasDockerfile $true -Disabled $false).Action | Should -Be 'current'
        $r = Get-SIUpdaterSelfDecision -CurrentImage 'reg.example.io/si-updater:v3.0.0' -TargetImage $t -InRegistry $true -HasDockerfile $false -Disabled $false
        $r.Action | Should -Be 'roll'; $r.Build | Should -BeFalse; $r.Act | Should -BeTrue
        $b = Get-SIUpdaterSelfDecision -CurrentImage 'reg.example.io/si-updater:v3.0.0' -TargetImage $t -InRegistry $false -HasDockerfile $true -Disabled $false
        $b.Action | Should -Be 'build'; $b.Build | Should -BeTrue
        $s = Get-SIUpdaterSelfDecision -CurrentImage 'reg.example.io/si-updater:v3.0.0' -TargetImage $t -InRegistry $false -HasDockerfile $false -Disabled $false
        $s.Act | Should -BeFalse; $s.Action | Should -Be 'skipped'; $s.Reason | Should -Match 'keeps si-updater:v3.0.0'
    }
}

Describe 'a deep build context is built from a short copy (Windows long paths)' {
    It 'decides by the longest full path: over the limit = stage; unreadable (-1) = stage; short = as it is; Linux never stages' {
        (Get-SIBuildStageDecision -ContextPath ('C:\' + ('d' * 120)) -LongestRelative 142 -IsWindowsHost $true).Stage | Should -BeTrue
        (Get-SIBuildStageDecision -ContextPath 'C:\deep' -LongestRelative -1 -IsWindowsHost $true).Stage | Should -BeTrue
        (Get-SIBuildStageDecision -ContextPath 'C:\AutomateIT\SOLUTIONS\SecurityInsight' -LongestRelative 142 -IsWindowsHost $true).Stage | Should -BeFalse
        (Get-SIBuildStageDecision -ContextPath ('/' + ('d' * 300)) -LongestRelative 142 -IsWindowsHost $false).Stage | Should -BeFalse
    }
    It 'runs the build in a short stage when the folder is too deep, and removes the stage afterwards' {
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-self-ctx-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force (Join-Path $src 'container\updater') | Out-Null
        Set-Content -LiteralPath (Join-Path $src 'container\updater\Dockerfile') -Value 'FROM x'
        try {
            $script:Seen = $null; $script:SeenFile = $false
            Invoke-SIInBuildContext -Path $src -IsWindowsHost $true -Limit 10 -Copy { param($from, $to) New-Item -ItemType Directory -Force (Join-Path $to 'container\updater') | Out-Null; Copy-Item -LiteralPath (Join-Path $from 'container\updater\Dockerfile') -Destination (Join-Path $to 'container\updater\Dockerfile') } `
                -Action { $script:Seen = (Get-Location).Path; $script:SeenFile = Test-Path -LiteralPath 'container/updater/Dockerfile' }
            $script:Seen | Should -Not -Be $src
            (Split-Path -Leaf $script:Seen) | Should -Match '^sib-[0-9a-f]{8}$'
            $script:SeenFile | Should -BeTrue
            Test-Path -LiteralPath $script:Seen | Should -BeFalse
            # short enough: the folder itself
            Invoke-SIInBuildContext -Path $src -IsWindowsHost $true -Copy { throw 'must not copy' } -Action { $script:Seen = (Get-Location).Path }
            $script:Seen | Should -Be ([IO.Path]::GetFullPath($src).TrimEnd('\'))
            # not Windows: never staged, whatever the length
            Invoke-SIInBuildContext -Path $src -IsWindowsHost $false -Limit 10 -Copy { throw 'must not copy' } -Action { $script:Seen = (Get-Location).Path }
            $script:Seen | Should -Be ([IO.Path]::GetFullPath($src).TrimEnd('\'))
        } finally { Remove-Item -LiteralPath $src -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'the copy (robocopy) carries a path longer than 260 characters and leaves out .git, bin and obj' -Skip:(-not ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows)) {
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-self-long-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $deep = $src
        while ($deep.Length -lt 250) { $deep = Join-Path $deep ('segment' + ('x' * 20)) }
        $null = & robocopy ([IO.Path]::GetTempPath()) ([IO.Path]::GetTempPath()) /L /NFL /NDL /NJH /NJS 2>&1; $global:LASTEXITCODE = 0
        try {
            # create the deep file through the extended-length prefix (Windows PowerShell cannot write it directly)
            $null = [IO.Directory]::CreateDirectory('\\?\' + $deep)
            [IO.File]::WriteAllText('\\?\' + (Join-Path $deep 'rule.custom.sample.yaml'), 'x')
            New-Item -ItemType Directory -Force (Join-Path $src 'bin'), (Join-Path $src 'engine') | Out-Null
            Set-Content -LiteralPath (Join-Path $src 'bin\junk.dll') -Value 'x'
            Set-Content -LiteralPath (Join-Path $src 'engine\a.ps1') -Value 'x'
            (Get-SIBuildStageDecision -ContextPath $src -LongestRelative (Get-SIBuildContextLongestPath -Path $src) -IsWindowsHost $true).Stage | Should -BeTrue
            $stage = Get-SIBuildStageRoot
            try {
                New-SIBuildStageCopy -Source $src -Destination $stage
                Test-Path -LiteralPath (Join-Path $stage 'engine\a.ps1') | Should -BeTrue
                Test-Path -LiteralPath (Join-Path $stage 'bin') | Should -BeFalse
                $rel = $deep.Substring($src.Length + 1)
                [IO.File]::Exists('\\?\' + (Join-Path (Join-Path $stage $rel) 'rule.custom.sample.yaml')) | Should -BeTrue
            } finally { $null = & robocopy $src $stage /PURGE /NFL /NDL /NJH /NJS 2>&1; $global:LASTEXITCODE = 0; [IO.Directory]::Delete('\\?\' + $stage, $true) }
        } finally { if ([IO.Directory]::Exists('\\?\' + $src)) { [IO.Directory]::Delete('\\?\' + $src, $true) } }
    }
    It 'the product build paths use it: the engine image, the updater image, and the updater''s own builds' {
        $cu = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')
        # #416: the engine build is queued through the fast roll's Start-SIAcrBuild, in the same short context; #521: the
        # registry builds it over ARM (SI-AcrBuild.ps1), no az
        $cu | Should -Match "(?s)Invoke-SIInBuildContext -Path \`$solRoot.*Start-SIAcrBuild.*si-orchestrator"
        $fr = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-FastRoll.ps1')
        $fr | Should -Match 'Invoke-SIAcrQueueBuild'
        $fr | Should -Not -Match "'acr', 'build'"
        $cu | Should -Not -Match 'Push-Location -LiteralPath \$solRoot'
        $ij = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1')
        # #521: the updater image builds over REST too (setup\_shared\SI-AcrBuild.ps1: no az, no short copy needed)
        $ij | Should -Match "(?s)Invoke-SIAcrRestBuild -SubscriptionId \`$sub -ResourceGroup \`$ResourceGroupName -RegistryName \`$AcrName -SourcePath \`$solRoot.*si-updater:v\`$version.*container/updater/Dockerfile"
        $ij | Should -Not -Match "'acr', 'build'"
        $bs = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        # #521: Bootstrap builds over REST (setup\_shared\SI-AcrBuild.ps1 packs the context in .NET -- long paths need no short copy)
        $bs | Should -Match "(?s)Invoke-SIAcrRestBuild -SubscriptionId \`$subId -ResourceGroup \`$ResourceGroupName -RegistryName \`$AcrName -SourcePath \`$PSScriptRoot.*si-orchestrator"
        # Pro: the web app roll builds through the same helper (the Community copy has no web app -- checked where it exists)
        $waPath = Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1'
        if (Test-Path -LiteralPath $waPath) {
            $wa = Get-Content -Raw -LiteralPath $waPath
            $wa | Should -Match 'Invoke-SIUpdaterAcrBuild'
            $wa | Should -Not -Match "'acr', 'build'"
        }
    }
}

Describe 'the updater rolls ITSELF (Invoke-SIUpdaterSelfRoll), against a fake ARM (#521: no az)' {
    BeforeAll {
        # the verified release the run extracted (SOLUTIONS/SecurityInsight with the updater's Dockerfile, or without it)
        function script:New-ReleaseRoot([bool]$WithDockerfile = $true) {
            $zip = Join-Path $TestDrive ('rel-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.zip')
            New-ReleaseZip -OutFile $zip -Display '3.0.0-rc.42' -Commit $script:C42 -WithDockerfile $WithDockerfile
            $dst = Join-Path $TestDrive ('si-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            $null = Expand-SIUpdaterSolution -ZipPath $zip -Destination $dst
            $dst
        }
        $script:Self = {
            param([string]$SIRoot, [switch]$Disabled)
            Invoke-SIUpdaterSelfRoll -SIRoot $SIRoot -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -LoginServer $script:Login -Tag $script:Tag42 `
                -JobName 'caj-si-updater' -JobId '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater' -CurrentImage $script:UpdaterImage -Disabled:$Disabled -Waits @(0, 1, 1, 1) 6>$null
        }
    }
    BeforeEach {
        Mock Start-Sleep { }
        Mock Invoke-SIUpdaterAcrBuild { $script:Az.Add(("build --image {0} --file {1}" -f $Image, $File)); if ($script:BuildFails) { throw 'the build service said no' } }
        Mock Test-SIUpdaterImageTag { $script:Az.Add(('tag? {0}:{1}' -f $Repo, $Tag)); @($script:RegistryTags) -contains $Tag }
        # the updater's ONE ARM seam: its own job (read, read-modify-write PATCH of the template) and the tag merge
        Mock Invoke-SIUpdaterArm {
            $script:Az.Add(('{0} {1}' -f $Method, $Path))
            if ($Path -eq '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater') {
                if ($Method -eq 'PATCH') {
                    if ($script:Conflicts -gt 0) { $script:Conflicts--; throw 'the job failed: HTTP 409: ContainerAppsJobOperationInProgress: Cannot modify a container apps job' }
                    if ($script:JobUpdateFails) { throw 'the job failed: HTTP 403: AuthorizationFailed: no rights' }
                    $script:SelfPatch = [string]$Body
                    $script:UpdaterImage = [string](([string]$Body | ConvertFrom-Json).properties.template.containers[0].image); return $null
                }
                return [pscustomobject]@{ properties = [pscustomobject]@{ configuration = [pscustomobject]@{ triggerType = 'Schedule'; secrets = @([pscustomobject]@{ name = 'cert-pfx'; keyVaultUrl = 'https://kv/secrets/x' }) }
                    template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'caj-si-updater'; image = $script:UpdaterImage; env = @([pscustomobject]@{ name = 'SI_UPDATER_ACR'; value = 'acr' }) }) } } }
            }
            if ($Method -eq 'PATCH' -and $Path -like '*/providers/Microsoft.Resources/tags/default') {
                $t = ([string]$Body | ConvertFrom-Json).properties.tags
                $script:Az.Add(('tags ' + ((@($t.PSObject.Properties | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })) -join ' ')))
                return $null
            }
            return $null
        }
    }
    It 'builds the updater image from the verified release, then moves its OWN job -- ONE PATCH of its template, in subscription sub, recorded' {
        Set-Scenario -Record @{ Version = '3.0.0-rc.40'; Commit = $script:C40 }
        $r = & $script:Self (New-ReleaseRoot)
        $r.Action | Should -Be 'rolled'
        $script:UpdaterImage | Should -Be ('reg.example.io/si-updater:' + $script:Tag42)
        $order = @($script:Az)
        $iBuild = [array]::FindIndex([string[]]$order, [Predicate[string]]{ param($x) $x -like ('build --image si-updater:{0} --file container/updater/Dockerfile' -f $script:Tag42) })
        $iSelf  = [array]::FindIndex([string[]]$order, [Predicate[string]]{ param($x) $x -eq 'PATCH /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater' })
        $iBuild | Should -BeGreaterThan -1; $iSelf | Should -BeGreaterThan $iBuild
        @($order | Where-Object { $_ -eq 'PATCH /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater' }).Count | Should -Be 1
        @($order | Where-Object { $_ -match '/(stop|start)$' }).Count | Should -Be 0
        @($order | Where-Object { $_ -match '^(GET|PATCH) ' -and $_ -notmatch '^(GET|PATCH) /subscriptions/sub/' }).Count | Should -Be 0
        # the read-modify-write: the template only, the job's own container and env kept -- never the configuration (its secrets)
        $p = $script:SelfPatch | ConvertFrom-Json
        @($p.properties.PSObject.Properties.Name) | Should -Be @('template')
        $p.properties.template.containers[0].env[0].name | Should -Be 'SI_UPDATER_ACR'
        $rec = @($order | Where-Object { $_ -like 'tags *si-updater-image=*' })
        $rec.Count | Should -Be 1
        $rec[0] | Should -Match ('si-updater-image={0}' -f [regex]::Escape($script:Tag42))
        $rec[0] | Should -Match 'si-updater-previous=v3\.0\.0( |$)'
    }
    It 'an operation still in flight (409) is waited out, not reported as a failure' {
        Set-Scenario -Record @{} -JobUpdateConflicts 2
        (& $script:Self (New-ReleaseRoot)).Action | Should -Be 'rolled'
        $script:UpdaterImage | Should -Be ('reg.example.io/si-updater:' + $script:Tag42)
    }
    It 'the image already in the registry is not rebuilt' {
        Set-Scenario -Record @{} -RegistryTags @($script:Tag42)
        (& $script:Self (New-ReleaseRoot)).Action | Should -Be 'rolled'
        @($script:Az | Where-Object { $_ -like 'build*si-updater*' }).Count | Should -Be 0
    }
    It 'a FAILED self-roll never fails the update: Action failed, the job marked pending, the reason says SecurityInsight IS updated' {
        Set-Scenario -Record @{} -JobUpdateFails
        $r = & $script:Self (New-ReleaseRoot)
        $r.Action | Should -Be 'failed'; $r.Reason | Should -Match 'SecurityInsight IS updated'
        $script:UpdaterImage | Should -Be 'reg.example.io/si-updater:v3.0.0'
        @($script:Az | Where-Object { $_ -like ('tags *si-updater-pending={0}*' -f $script:Tag42) }).Count | Should -Be 1
        @($script:Az | Where-Object { $_ -eq 'PATCH /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater' }).Count | Should -Be 1     # no endless retry of a real failure
    }
    It 'a failed image BUILD is the same: the updater job untouched, pending for the next run' {
        Set-Scenario -Record @{} -BuildFails
        $r = & $script:Self (New-ReleaseRoot)
        $r.Action | Should -Be 'failed'; $r.Reason | Should -Match 'could not be built'
        @($script:Az | Where-Object { $_ -like 'PATCH */jobs/caj-si-updater' }).Count | Should -Be 0
    }
    It 'switched off (SI_UPDATER_SELF_UPDATE=0): nothing built or moved' {
        Set-Scenario -Record @{}
        (& $script:Self (New-ReleaseRoot) -Disabled).Action | Should -Be 'off'
        @($script:Az | Where-Object { $_ -like 'PATCH */jobs/*' -or $_ -like 'build*' }).Count | Should -Be 0
    }
    It 'a release without the updater''s Dockerfile (an older build) is skipped, not failed' {
        Set-Scenario -Record @{}
        (& $script:Self (New-ReleaseRoot -WithDockerfile $false)).Action | Should -Be 'skipped'
        @($script:Az | Where-Object { $_ -like 'tags *si-updater-pending*' }).Count | Should -Be 0
    }
    It 'a retry with no release folder (a later run that rolled nothing) uses the registry image only' {
        Set-Scenario -Record @{} -RegistryTags @($script:Tag42)
        (& $script:Self '').Action | Should -Be 'rolled'
        @($script:Az | Where-Object { $_ -like 'build*' }).Count | Should -Be 0
    }
}

Describe 'the updater image carries the self-update in BOTH editions' {
    It 'Start-SIUpdater loads SI-UpdaterSelf.ps1 unconditionally, and the Dockerfile copies the whole _shared folder' {
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')
        $s | Should -Match "(?m)^\. \(Join-Path \`$PSScriptRoot '_shared/SI-UpdaterSelf\.ps1'\)"
        Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Dockerfile') | Should -Match 'COPY container/updater/_shared/ \./_shared/'
    }
    It 'neither file is kept out of the Community copy' -Tag 'PrivateRepo' {
        $pub = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json')
        $pub | Should -Not -Match 'SI-UpdaterSelf\.ps1'
        $pub | Should -Not -Match 'SI-BuildStage\.ps1'
    }
}
