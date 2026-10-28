#Requires -Version 5.1
# SI-TestScope: PrivateRepo
#   the updater's only source is Invardia, whose client ships with Pro only -- a public (Community) copy has nothing to run
<#
    caj-si-updater -- ONE SOURCE: INVARDIA (#240, framework UPDATE-1.7). SecurityInsight's OWN update feed (a storage
    container with a read-only link, the ring map + channel.json in it, Publish-SISourceArchive / Update-SISourceAccess /
    Publish-SITemplatePack) is RETIRED (operator 2026-10-06: "we are not having separate platforms like a si storage account
    for si updates. one solution: invardia").

    These tests prove that NO feed path is reachable any more: an updater still configured for the feed changes nothing
    (no sign-in, no az call, no HTTP), the feed readers are gone from the updater, the vendor's feed scripts are gone, and
    Install-SIUpdaterJob refuses the feed and removes a leftover feed link. The Invardia path itself is the contract test
    SIv3-InvardiaUpdate.Tests.ps1.
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $script:SIRoot)
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')

    $script:Tenant   = '11111111-2222-3333-4444-555555555555'   # any tenant -- never a real one (publish sanitization)
    $script:Source   = 'https://feedacct.blob.core.windows.net/si-src?sv=2024-01-01&si=srcread&sr=c&sig=TOPSECRETSIG'

    # A release archive's shape: one wrapping folder, SOLUTIONS/SecurityInsight/ with VERSION.
    function script:New-ReleaseZip([string]$OutFile, [string]$Version) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $src = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-src-' + [guid]::NewGuid().ToString('N'))
        $si = Join-Path $src "securityinsight-src-$Version\SOLUTIONS\SecurityInsight"
        New-Item -ItemType Directory -Force (Join-Path $si 'setup') | Out-Null
        Set-Content -LiteralPath (Join-Path $si 'VERSION') -Value $Version -NoNewline
        Set-Content -LiteralPath (Join-Path $si 'setup\Invoke-SIContainerUpdate.ps1') -Value 'exit 0'
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $OutFile)
        Remove-Item -LiteralPath $src -Recurse -Force
    }
    $script:Env = {
        @{ SI_UPDATER_TENANT_ID = $script:Tenant; SI_UPDATER_CLIENT_ID = 'cid'; SI_UPDATER_SUBSCRIPTION_ID = 'sub'
           SI_UPDATER_RESOURCE_GROUP = 'rg'; SI_UPDATER_ACR = 'acr'; SI_UPDATER_CERT_PFX_B64 = 'pfx'; SI_UPDATER_KEY_VAULT = 'kv-test' }
    }
    # The names of the retired feed / ring-channel functions (2026-10-06). None may exist in the updater any more.
    $script:RetiredFunctions = @('Get-SIUpdaterFeedFile', 'Save-SIUpdaterFeedArchive', 'Get-SIUpdaterFeedChecksum', 'Invoke-SIUpdaterTemplateChannel',
        'Invoke-SIUpdaterFromChannel', 'Invoke-SIUpdaterSelfRetry', 'Get-SIUpdaterChannelRelease', 'Save-SIUpdaterChannelState',
        'Get-SIUpdaterChannelDecision', 'Get-SIRingVersion', 'Set-SIUpdateChannelEntry', 'Get-SIFeedChannelName', 'Get-SIUpdaterFeedDecision',
        'Get-SIFeedBlobUrl', 'Get-SIFeedContainerName', 'Get-SIFeedDecisionFiles', 'Test-SIFeedArchiveChecksum', 'Get-SIUpdaterTemplateDecision',
        'Get-SIFeedTemplateRingsName', 'Get-SIFeedTemplateRingKey', 'ConvertFrom-SIFeedChecksum', 'Get-SIFeedChecksumName', 'Hide-SIFeedSecret',
        'ConvertFrom-SIFeedContent', 'Get-SIFeedArchiveName')
}

Describe 'the decisions (pure)' {
    It 'reads the running version from the jobs'' image tags -- highest wins, foreign images ignored' {
        $jobs = @([pscustomobject]@{ Name = 'a'; Image = 'reg.example.io/si-orchestrator:v2.2.460-0123456789ab' }
                  [pscustomobject]@{ Name = 'b'; Image = 'reg.example.io/si-orchestrator:v3.0.0-abcdefabcdef' }
                  [pscustomobject]@{ Name = 'c'; Image = 'reg.example.io/other:v9.9.9-abcdefabcdef' }
                  [pscustomobject]@{ Name = 'd'; Image = 'reg.example.io/si-orchestrator:latest' })
        Get-SIDeployedVersionFromJobs -Jobs $jobs -LoginServer 'reg.example.io' | Should -Be '3.0.0'
        Get-SIDeployedVersionFromJobs -Jobs @() -LoginServer 'reg.example.io' | Should -Be ''
    }
    It 'the from-version is the RELEASE the updater recorded, the content-tagged image only the fallback (never "3.0.0" for a later build)' {
        $jobs = @([pscustomobject]@{ Name = 'b'; Image = 'reg.example.io/si-orchestrator:v3.0.0-abcdefabcdef' })
        Get-SIDeployedVersionFromJobs -Jobs $jobs -LoginServer 'reg.example.io' -Recorded '3.0.0.202610142040' | Should -Be '3.0.0.202610142040'
        Get-SIDeployedVersionFromJobs -Jobs $jobs -LoginServer 'reg.example.io' -Recorded '' | Should -Be '3.0.0' -Because 'no record: the image tag'
        Get-SIDeployedVersionFromJobs -Jobs $jobs -LoginServer 'reg.example.io' -Recorded '2.9.9.1' | Should -Be '3.0.0' -Because 'a record older than the images never moves the guard backward'
        Get-SIDeployedVersionFromJobs -Jobs $jobs -LoginServer 'reg.example.io' -Recorded 'rc.981' | Should -Be '3.0.0' -Because 'not a version'
        Get-SIDeployedVersionFromJobs -Jobs @() -LoginServer 'reg.example.io' -Recorded '3.0.0.202610142040' | Should -Be '3.0.0.202610142040'
        # the applied record of this updater: only a BUILD OF what the jobs say they run
        Resolve-SIUpdaterRunningRelease -Deployed '3.0.0' -AppliedVersion '3.0.0.202610142040' | Should -Be '3.0.0.202610142040'
        Resolve-SIUpdaterRunningRelease -Deployed '3.0.0.202610150144' -AppliedVersion '3.0.0.202610142040' | Should -Be '3.0.0.202610150144'
        Resolve-SIUpdaterRunningRelease -Deployed '3.0.1' -AppliedVersion '3.0.0.202610142040' | Should -Be '3.0.1'
        Resolve-SIUpdaterRunningRelease -Deployed '' -AppliedVersion '3.0.0.202610142040' | Should -Be '' -Because 'nothing read = the guard stays off, as before'
        # the forward-only guard still works on the resolved release
        (Compare-SIUpdaterVersionText '3.0.0.202610151701' '3.0.0.202610142040') | Should -Be 1
        (Compare-SIUpdaterVersionText '3.0.0' '3.0.0.202610142040') | Should -Be -1
    }
    It 'the source: invardia by default; feed only names the RETIRED configuration; anything else is refused' {
        Get-SIUpdaterSourceKind -Source '' -SourceUrl '' | Should -Be 'invardia'
        Get-SIUpdaterSourceKind -Source 'invardia' -SourceUrl $script:Source | Should -Be 'invardia'
        Get-SIUpdaterSourceKind -Source '' -SourceUrl $script:Source | Should -Be 'feed'
        Get-SIUpdaterFeedRetiredReason -Source 'invardia' -SourceUrl $script:Source | Should -BeNullOrEmpty
        Get-SIUpdaterFeedRetiredReason -Source 'feed' -SourceUrl '' | Should -Match 'RETIRED'
        { Get-SIUpdaterSourceKind -Source 'github' -SourceUrl '' } | Should -Throw "*must be 'invardia' or 'feed'*"
    }
}

Describe 'the release archive helpers (pure)' {
    It 'the archive shape is checked: one wrapping folder, SecurityInsight files, a VERSION' {
        $ok = Join-Path ([IO.Path]::GetTempPath()) ('si-shape-' + [guid]::NewGuid().ToString('N') + '.zip')
        try {
            New-ReleaseZip -OutFile $ok -Version '3.0.1'
            $s = Test-SIFeedArchiveShape -Path $ok
            "$($s.Ok)|$($s.Version)" | Should -Be 'True|3.0.1'
        } finally { Remove-Item -LiteralPath $ok -Force -ErrorAction SilentlyContinue }
    }
    It 'the sha256sum line a template pack is staged with' {
        Format-SIFeedChecksum -Hash ('AB' * 32) -ArchiveName 'si-templates-3.0.1.1.json' | Should -BeExactly (('ab' * 32) + '  si-templates-3.0.1.1.json' + "`n")
        { Format-SIFeedChecksum -Hash 'abc' -ArchiveName 'x.zip' } | Should -Throw
    }
}

Describe 'the feed is RETIRED: no feed path is reachable (operator 2026-10-06, "one solution: invardia")' {
    BeforeEach {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        Mock Connect-SIUpdaterRest { $script:Calls.Add('signin'); 'the test identity' }
        Mock Invoke-SIUpdaterArm { $script:Calls.Add('arm ' + $Method + ' ' + $Path) }
        Mock Invoke-WebRequest { $script:Calls.Add('http ' + $Uri); throw 'no network in tests' }
        Mock Invoke-RestMethod { $script:Calls.Add('http ' + $Uri); throw 'no network in tests' }
        Mock Invoke-SIUpdaterLicenceRequest { $script:Calls.Add('licence') }
    }
    It 'SI_UPDATER_SOURCE = feed: exit 0, NOTHING done -- no sign-in, no Azure call, no HTTP -- and the log says how to move' {
        $e = & $script:Env; $e.SI_UPDATER_SOURCE = 'feed'; $e.SI_UPDATER_SOURCE_URL = $script:Source
        $out = @(Invoke-SIUpdater -Env $e 6>&1 | ForEach-Object { "$_" })
        $rc = @($out | Where-Object { $_ -match '^\d+$' }) | Select-Object -Last 1
        $rc | Should -Be '0'
        $script:Calls.Count | Should -Be 0
        ($out -join "`n") | Should -Match 'own update feed is RETIRED'
        ($out -join "`n") | Should -Match 'Install-SIUpdaterJob\.ps1 -Source invardia'
        ($out -join "`n") | Should -Not -Match 'TOPSECRETSIG'
    }
    It 'a feed link without SI_UPDATER_SOURCE (an old job): the same -- nothing done' {
        $e = & $script:Env; $e.SI_UPDATER_SOURCE_URL = $script:Source
        $null = Invoke-SIUpdater -Env $e 6>$null
        $script:Calls.Count | Should -Be 0
    }
    It 'SI_UPDATER_SOURCE = invardia with a leftover feed link: the Invardia path runs, the link is never read' {
        Mock Invoke-SIUpdaterFromInvardia { $script:Calls.Add('invardia'); 0 }
        Mock Get-SIUpdaterDeployed { '3.0.0' }
        Mock Get-SIUpdaterAutoSwitches { $null }
        $e = & $script:Env; $e.SI_UPDATER_SOURCE = 'invardia'; $e.SI_UPDATER_SOURCE_URL = $script:Source
        (Invoke-SIUpdater -Env $e 6>$null) | Should -Be 0
        $script:Calls | Should -Contain 'invardia'
        @($script:Calls | Where-Object { $_ -like 'http *' }).Count | Should -Be 0
    }
    It 'missing configuration is refused, not guessed; an unknown source is refused' {
        $e = & $script:Env; $e.Remove('SI_UPDATER_KEY_VAULT')
        { Invoke-SIUpdater -Env $e } | Should -Throw '*SI_UPDATER_KEY_VAULT*'
        $e = & $script:Env; $e.SI_UPDATER_SOURCE = 'github'
        { Invoke-SIUpdater -Env $e } | Should -Throw "*must be 'invardia' or 'feed'*"
    }
    It 'no feed reader or ring-channel function exists in the updater any more' {
        foreach ($n in $script:RetiredFunctions) { Get-Command -Name $n -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$n read or decided from SI's retired feed" }
    }
    It 'no product file names a retired function, a feed blob, the ring map or channel.json in code (comments do not count)' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'container\updater') -Recurse -Filter *.ps1) +
                 @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'setup') -Recurse -Filter *.ps1)
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in $files) {
            # code only: every comment token (line and block) removed
            $tokens = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$null)
            $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text })) -join ' '
            foreach ($n in $script:RetiredFunctions) { if ($code -match ('\b' + [regex]::Escape($n) + '\b')) { $hits.Add("$($f.Name) -> $n") } }
            # a private install's DNS zone suffix for the storage private endpoint (SI-PrivateNetwork.ps1: Suffix = 'blob.core.windows.net')
            # names the Azure service, not a feed -- that one use is taken out before the check
            $feedCode = $code -replace "Suffix\s*=\s*'blob\.core\.windows\.net'", ''
            if ($feedCode -match 'blob\.core\.windows\.net|release-map\.json|si-src-internal') { $hits.Add("$($f.Name) -> a feed location") }
            # channel.json: retired everywhere (2026-10-28: the Community channel is Invardia's route); the updater reads none
            if ($f.FullName -like '*\container\updater\*' -and $code -match 'channel\.json') { $hits.Add("$($f.Name) -> channel.json") }
        }
        $hits | Should -BeNullOrEmpty
    }
    It 'the vendor''s feed scripts are gone: no publish to the feed, no feed access link, no feed template channel' {
        foreach ($s in 'Publish-SISourceArchive.ps1', 'Update-SISourceAccess.ps1', 'Publish-SITemplatePack.ps1') {
            Test-Path -LiteralPath (Join-Path $script:SIRoot "setup\$s") | Should -BeFalse -Because "$s published to / opened SI's retired feed"
        }
    }
    It 'NO repository credential is left anywhere in the updater (#171)' {
        foreach ($f in 'container\updater\Start-SIUpdater.ps1', 'container\updater\_shared\SI-UpdaterCore.ps1', 'container\updater\_shared\SI-UpdateFeed.ps1') {
            $code = ((Get-Content -LiteralPath (Join-Path $script:SIRoot $f)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match 'api\.github\.com' -Because $f
            $code | Should -Not -Match 'GITHUB_TOKEN|GitHubToken|gh-token' -Because $f
        }
        ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" |
            Should -Not -Match 'api\.github\.com'
    }
}

Describe 'Install-SIUpdaterJob (setup), against a recording fake Azure over REST (no az CLI)' {
    BeforeAll {
        $script:Installer = Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1'
        . (Join-Path $script:SIRoot 'tests\fixtures\SIUpdaterJobRestWorld.ps1')
        Enable-SIUpdaterJobRestWorld
        $script:InstArgs = @{ SubscriptionId = 'sub-1'; ResourceGroupName = 'rg'; AcrName = 'acr'; EnvName = 'cae'; KeyVaultName = 'kv'
                              CertSecretName = 'spn-pfx'; SpnClientId = 'app-1'; TenantId = 'ten-1' }
        function script:Calls([string]$Fn) { @($global:SIUJ.Calls | Where-Object { $_.Fn -eq $Fn }) }
        function script:At($c) { [array]::IndexOf($global:SIUJ.Calls.ToArray(), $c) }
    }
    AfterAll { Disable-SIUpdaterJobRestWorld }
    BeforeEach { Reset-SIUpdaterJobRestWorld @{} }

    It 'calls no az CLI: the registry, the build, the identity, the vault, the roles and the job all go through the REST layer' {
        $code = ((Get-Content -LiteralPath $script:Installer) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match '&\s*az\b|Invoke-SIInstallAz'
        foreach ($fn in 'Get-SIContainerRegistry', 'Invoke-SIAcrRestBuild', 'Get-SIUserAssignedIdentity', 'Get-SIKeyVaultArm', 'New-SIRoleAssignment', 'Get-SIContainerAppJob', 'New-SIContainerAppJobFromArgs', 'Update-SIContainerAppJob') {
            $code | Should -Match ([regex]::Escape($fn))
        }
    }
    It 'an updater found WITHOUT its timer (an earlier switch to the pipeline) is put back on 03:00 UTC -- a PATCH of the trigger, before the update (#393)' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true; $global:SIUJ.Manual = $true
        & $script:Installer @script:InstArgs -Apply *> $null
        $patch = @(Calls 'Invoke-SIArm' | Where-Object { $_.Args.Method -eq 'PATCH' })
        $patch.Count | Should -Be 1
        $patch[0].Text | Should -Match 'jobs/caj-si-updater\?api-version='
        $patch[0].Args.Path | Should -Match '^/subscriptions/sub-1/'
        $patch[0].Text | Should -Not -Match 'secrets' -Because 'only the trigger and the tags are patched'
        $upd = @(Calls 'Update-SIContainerAppJob')[0]
        $upd.Args.Cron | Should -Be '30 16,17 * * *'
        (At $patch[0]) | Should -BeLessThan (At $upd) -Because 'the update sets a cron only on a Schedule job'
    }
    It 'an updater on its timer gets no PATCH' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true
        & $script:Installer @script:InstArgs -Apply *> $null
        @(Calls 'Invoke-SIArm' | Where-Object { $_.Args.Method -eq 'PATCH' }).Count | Should -Be 0
    }

    It 'upgrading an updater installed before 3.0.0 REMOVES the GitHub token -- env vars and the secret in the SAME whole-job write' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true; $global:SIUJ.Legacy = $true
        & $script:Installer @script:InstArgs -Apply *> $null
        $upd = @(Calls 'Update-SIContainerAppJob')
        $upd.Count | Should -Be 1 -Because 'one read-modify-write: a referenced secret is never left behind or removed first'
        foreach ($n in 'SI_UPDATER_GITHUB_TOKEN', 'SI_UPDATER_REPO', 'SI_UPDATER_SOURCE_REF') { @($upd[0].Args.RemoveEnv) | Should -Contain $n }
        @($upd[0].Args.RemoveEnv) | Should -Not -Contain 'SI_UPDATER_ACR'
        @($upd[0].Args.RemoveSecrets) | Should -Be @('gh-token')
    }
    It 'a job without the legacy settings gets no removal' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true
        & $script:Installer @script:InstArgs -Apply *> $null
        $upd = @(Calls 'Update-SIContainerAppJob')[0]
        @($upd.Args.RemoveEnv).Count | Should -Be 0
        @($upd.Args.RemoveSecrets).Count | Should -Be 0
    }

    It 'without -Apply it changes nothing (and signs nothing in)' {
        & $script:Installer @script:InstArgs *> $null
        $global:SIUJ.Calls.Count | Should -Be 0
    }
    It 'the feed is refused BEFORE anything is called: -Source feed, or a feed link secret' {
        { & $script:Installer @script:InstArgs -Source feed -Apply *> $null } | Should -Throw '*own update feed is retired*'
        { & $script:Installer @script:InstArgs -SourceUrlSecretName 'SI-UpdateFeed-Url' -Apply *> $null } | Should -Throw '*own update feed is retired*'
        $global:SIUJ.Calls.Count | Should -Be 0
    }
    It 'a job that still carries the feed link (ring 1 before the switch) has the env var AND the secret removed in the update' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true; $global:SIUJ.FeedJob = $true
        & $script:Installer @script:InstArgs -UpdateRing 1 -Apply *> $null
        $upd = @(Calls 'Update-SIContainerAppJob')
        $upd.Count | Should -Be 1
        @($upd[0].Args.RemoveEnv) | Should -Contain 'SI_UPDATER_SOURCE_URL'
        @($upd[0].Args.RemoveSecrets) | Should -Contain 'src-url'
        $env = @($upd[0].Args.SetEnv) -join ' '
        $env | Should -Match 'SI_UPDATER_SOURCE=invardia'; $env | Should -Match 'SI_UPDATER_RING=1'
        $env | Should -Not -Match 'src-url|SI_UPDATER_SOURCE_URL'
    }
    It '-Apply creates the job: schedule, a Key Vault REFERENCE for the certificate, source invardia, the subscription on every call' {
        & $script:Installer @script:InstArgs -Apply *> $null
        $create = @(Calls 'New-SIContainerAppJobFromArgs')
        $create.Count | Should -Be 1
        $t = $create[0].Text
        $t | Should -Match '--trigger-type Schedule --cron-expression 30 16,17 \* \* \*'   # 18:30 local time: the two UTC ticks (owner 2026-10-21)
        $t | Should -Not -Match 'SI_UPDATER_RING|SI_UPDATER_PRO_SQL'   # not asked for = not set
        $t | Should -Match 'cert-pfx=keyvaultref:https://kv\.vault\.azure\.net/secrets/spn-pfx,identityref:/sub/uami'
        $t | Should -Not -Match 'src-url|SI_UPDATER_SOURCE_URL'
        $t | Should -Match 'SI_UPDATER_SOURCE=invardia'
        $t | Should -Match 'SI_UPDATER_CERT_PFX_B64=secretref:cert-pfx'
        $t | Should -Not -Match 'SI_UPDATER_REPO|SI_UPDATER_GITHUB_TOKEN|SI_UPDATER_SOURCE_REF'
        $t | Should -Not -Match '--subscription|--output' -Because 'ConvertFrom-SIJobCreateArgs refuses a flag it does not know'
        $create[0].Args.EnvironmentId | Should -Be '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae'
        $create[0].Args.Location | Should -Be 'westeurope'
        @($global:SIUJ.Calls | Where-Object { $_.Args.ContainsKey('SubscriptionId') -and $_.Args.SubscriptionId -ne 'sub-1' }).Count | Should -Be 0
        @(Calls 'Invoke-SIAcrRestBuild')[0].Args.DockerFilePath | Should -Be 'container/updater/Dockerfile'
        @(Calls 'New-SIRoleAssignment' | Where-Object { $_.Args.ObjectId -like 'oid-of-app-1' }).Count | Should -Be 0   # SPN roles are opt-in
        @(Calls 'New-SIRoleAssignment' | ForEach-Object { $_.Args.Role }) | Should -Be @('Key Vault Secrets User', 'AcrPull')
    }
    It 'a re-run updates the existing job in place (secrets + image + env), and never reads a secret value' {
        $global:SIUJ.HasJob = $true; $global:SIUJ.HasUami = $true
        & $script:Installer @script:InstArgs -Apply *> $null
        @(Calls 'New-SIContainerAppJobFromArgs').Count | Should -Be 0
        $upd = @(Calls 'Update-SIContainerAppJob')
        $upd.Count | Should -Be 1
        @($upd[0].Args.SetSecrets) -join ' ' | Should -Match '^cert-pfx=keyvaultref:'
        $upd[0].Args.Image | Should -Match '^reg\.example\.io/si-updater:v'
        @(Calls 'Get-SIKeyVaultSecretValue').Count | Should -Be 0
    }
    It 'an existing updater on the image it rolled itself to KEEPS it (no build, no downgrade) and keeps its 4 CPU / 8 GiB (internal ring 1 2026-10-10)' {
        $rolled = 'reg.example.io/si-updater:v3.0.0.202610102024-2e0582308f82'
        $global:SIUJ.HasUami = $true
        $global:SIUJ.Job = [pscustomobject]@{ name = 'caj-si-updater'; id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'; tags = [pscustomobject]@{ 'si-updater-image' = $rolled }
            properties = [pscustomobject]@{ configuration = [pscustomobject]@{ triggerType = 'Schedule' }; template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = $rolled; resources = [pscustomobject]@{ cpu = '4.0'; memory = '8Gi' } }) } } }
        & $script:Installer @script:InstArgs -Apply *> $null
        $upd = @(Calls 'Update-SIContainerAppJob')
        $upd.Count | Should -Be 1
        $upd[0].Args.Image | Should -Be $rolled
        [string]$upd[0].Args.Cpu | Should -BeNullOrEmpty -Because 'a job at 4 CPU / 8 GiB keeps its size'
        @(Calls 'Invoke-SIAcrRestBuild').Count | Should -Be 0 -Because 'the job keeps its image -- nothing to build'
    }
    It 'a failed image build stops the run before the identity or the job is touched' {
        $global:SIUJ.BuildFails = $true
        { & $script:Installer @script:InstArgs -Apply *> $null } | Should -Throw '*image build did not succeed*'
        # (the job is READ first -- an existing one keeps its image; nothing is created or changed)
        @(Calls 'New-SIContainerAppJobFromArgs').Count + @(Calls 'Update-SIContainerAppJob').Count | Should -Be 0
    }
    It '#350: -UpdateRing and the Pro database become the job''s SI_UPDATER_RING and SI_UPDATER_PRO_SQL_* settings' {
        & $script:Installer @script:InstArgs -UpdateRing 1 -ProSqlServer 'sql.example.net' -ProSqlDatabase 'sqldb-si-pro' -Apply *> $null
        $t = @(Calls 'New-SIContainerAppJobFromArgs')[0].Text
        $t | Should -Match 'SI_UPDATER_RING=1'
        $t | Should -Match 'SI_UPDATER_PRO_SQL_SERVER=sql\.example\.net'
        $t | Should -Match 'SI_UPDATER_PRO_SQL_DATABASE=sqldb-si-pro'
    }
    It '#350: -UseManagedIdentity -- the job signs in as its own identity: no certificate secret, SI_UPDATER_AUTH + the identity''s client id' {
        $a = $script:InstArgs.Clone(); $a.Remove('CertSecretName'); $a.Remove('SpnClientId')
        & $script:Installer @a -UseManagedIdentity -GrantSpnRoles -Apply *> $null
        $t = @(Calls 'New-SIContainerAppJobFromArgs')[0].Text
        $t | Should -Not -Match 'cert-pfx|SI_UPDATER_CERT_PFX_B64'
        $t | Should -Match 'SI_UPDATER_AUTH=ManagedIdentity'
        $t | Should -Match 'SI_UPDATER_CLIENT_ID=0c1d2e3f-1111-4222-8333-0000000c1d00'
        $t | Should -Not -Match 'src-url'
        @(Calls 'New-SIUserAssignedIdentity').Count | Should -Be 1 -Because 'the identity did not exist yet'
        @(Calls 'New-SIRoleAssignment' | Where-Object { $_.Args.ObjectId -eq 'pid' -and $_.Args.Role -eq 'Contributor' }).Count | Should -Be 2
        @(Calls 'New-SIRoleAssignment' | Where-Object { $_.Args.ObjectId -eq 'pid' -and $_.Args.Role -eq 'Key Vault Secrets Officer' }).Count | Should -Be 1
        @(Calls 'Resolve-SIPrincipalObjectId').Count | Should -Be 0 -Because 'no SPN is named'
    }
    It 'sign-in by certificate without the certificate secret or the SPN is refused' {
        $a = $script:InstArgs.Clone(); $a.Remove('CertSecretName')
        { & $script:Installer @a -Apply *> $null } | Should -Throw '*-CertSecretName and -SpnClientId*'
    }
    It 'the updater''s sign-in mode: Certificate by default, ManagedIdentity on request, anything else refused' {
        Get-SIUpdaterAuthMode -Auth '' | Should -Be 'Certificate'
        Get-SIUpdaterAuthMode -Auth 'managedidentity' | Should -Be 'ManagedIdentity'
        { Get-SIUpdaterAuthMode -Auth 'Secret' } | Should -Throw
    }
    It '-GrantSpnRoles assigns the SPN (found by its app id) Contributor on the registry and the resource group, and Key Vault Secrets Officer' {
        & $script:Installer @script:InstArgs -Apply -GrantSpnRoles *> $null
        @(Calls 'Resolve-SIPrincipalObjectId' | Where-Object { $_.Args.Id -eq 'app-1' }).Count | Should -Be 1
        @(Calls 'New-SIRoleAssignment' | Where-Object { $_.Args.ObjectId -eq 'oid-of-app-1' -and $_.Args.Role -eq 'Contributor' } | ForEach-Object { $_.Args.Scope }) | Should -Be @('/sub/acr', '/sub/rg')
        @(Calls 'New-SIRoleAssignment' | Where-Object { $_.Args.ObjectId -eq 'oid-of-app-1' -and $_.Args.Role -eq 'Key Vault Secrets Officer' }).Count | Should -Be 1
    }
}
Describe 'the updater identity reads the directory (owner 2026-10-17: the tenant size sizes the jobs)' {
    BeforeAll {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        . ([scriptblock]::Create(($ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-SIUpdaterDirectoryRead' }, $true)).Extent.Text))
        $script:InstallSrc = $src
    }
    It 'asks the grant step for Directory.Read.All ONLY, for the updater identity; present = one line' {
        $seen = New-Object System.Collections.Generic.List[object]
        $r = Invoke-SIUpdaterDirectoryRead -PrincipalId 'p-1' -SubscriptionId 's-1' -Grant { param($p, $s) $seen.Add(@($p, $s)); 0 }.GetNewClosure()
        $r | Should -Match 'Directory\.Read\.All.*present'
        $seen[0][0] | Should -Be 'p-1'
        # the real grant: the jobs' own grant step, only that one permission, applied
        $script:InstallSrc | Should -Match ([regex]::Escape("`$a = @{ PrincipalId = `$p; Only = @('Directory.Read.All'); Apply = `$true }"))
        $script:InstallSrc | Should -Match ([regex]::Escape("'Grant-SIIdentity.ps1'"))
    }
    It 'NEVER stops the setup: a grant this sign-in cannot make is one plain line with the command for an administrator' {
        $r = Invoke-SIUpdaterDirectoryRead -PrincipalId 'p-1' -Grant { 1 }
        $r | Should -Match 'could NOT be given'
        $r | Should -Match 'sizes the jobs for a large tenant'
        $r | Should -Match ([regex]::Escape('.\setup\Grant-SIIdentity.ps1 -PrincipalId p-1 -Only Directory.Read.All -Apply'))
        { Invoke-SIUpdaterDirectoryRead -PrincipalId 'p-1' -Grant { throw 'Graph refused' } } | Should -Not -Throw
        Invoke-SIUpdaterDirectoryRead -PrincipalId 'p-1' -Grant { throw 'Graph refused' } | Should -Match 'Graph refused'
    }
    It 'runs only where the setup grants the managed identity its roles, and is never counted as a missing updater right' {
        $i = $script:InstallSrc.IndexOf('$dirRead = Invoke-SIUpdaterDirectoryRead -PrincipalId ([string]$uami.PrincipalId) -SubscriptionId $sub')
        $i | Should -BeGreaterThan $script:InstallSrc.IndexOf('if ($GrantSpnRoles -and $UseManagedIdentity) {')
        $i | Should -BeLessThan $script:InstallSrc.IndexOf('} elseif ($GrantSpnRoles) {')
        $fn = [regex]::Match($script:InstallSrc, '(?s)function Invoke-SIUpdaterDirectoryRead \{.*?\n\}').Value
        $fn | Should -Not -Match 'SIUpdaterGrantsFailed'
    }
}
