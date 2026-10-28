#Requires -Version 5.1
# SI-TestScope: PrivateRepo
#   checks the publish manifest and LICENSE-PRO, which a public copy does not carry (see _SITestScope.ps1)
<#
    ONE CODEBASE, TWO PAYLOADS (framework PUB-6, operator 2026-09-30).

    The public mirror is the Community edition. The paid ENGINES of SecurityInsight Pro -- the ServiceNow and CMDB
    connectors, the close-loop and governance mails -- reach paying customers only through the private sync, so every
    such path is listed in solution.publish.json `excludePaths` and removed at publish. (Cross-engine correlation and
    the full asset properties are Community since 2026-10-27; the web app ships with its paid pages gated by the licence.)

    Two ways this breaks silently, and both are what these tests are for:
      1. A FREE file loads a Pro file. The public copy then fails at runtime for ~6,000 installs,
         while every test here, run on the full tree, stays green. Found twice while building this:
         the Defender recommendations stage published through a helper that lived in the correlation
         folder, and the trend engine dot-sourced a correlation file it never used.
      2. A new Pro file is added outside the listed paths and quietly ships to the public mirror.
#>

BeforeDiscovery {
    $script:DiscRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
}

BeforeAll {
    # CR5 (#655): new installs get the new names by default (SI_Setup_NewInstallNames ON since 2026-10-18). This suite's fake
    # installs pin TODAY's names; the default itself is proven in SIv3-GuidedInstall (CR5 step 2) and SIv3-InstallNames.
    $env:SI_Setup_NewInstallNames = 'false'
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Publish = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json
    $script:Exclude = @($script:Publish.excludePaths | ForEach-Object { "$_".Replace('\', '/').Trim('/') })
    # Excluded because RETIRED, not because Pro (#194). The SI Analyzer was the only such entry; it is DELETED from the
    # repository (its history is in git only), so nothing is excluded for being retired any more.
    $script:Retired = @()
    $script:ProExclude = @($script:Exclude | Where-Object { $script:Retired -notcontains $_ })

    function script:Test-SIExcluded([string]$Rel) {
        $r = $Rel.Replace('\', '/').Trim('/')
        foreach ($e in $script:Exclude) { if ($r -ieq $e -or $r.StartsWith("$e/", [StringComparison]::OrdinalIgnoreCase)) { return $true } }
        $false
    }
}

Describe 'every Pro component is excluded from the public payload' {

    It '<_> is in excludePaths' -ForEach @(
        'launcher/asset-cmdb',
        'engine/asset-cmdb/Invoke-SICmdb.ps1', 'engine/asset-cmdb/Invoke-SIVulnLoop.ps1', 'engine/asset-cmdb/Invoke-SICloseLoopMail.ps1',
        'engine/asset-cmdb/Invoke-SICmdbSql.ps1', 'engine/asset-cmdb/Invoke-SICmdbImport.ps1', 'engine/asset-cmdb/_shared/SI-ServiceNowClient.ps1',
        'engine/pro-data/Invoke-SIDepartmentReport.ps1', 'engine/pro-data/Invoke-SIGovernanceMail.ps1', 'engine/pro-data/Invoke-SITaskDigest.ps1',
        'setup/Set-SIServiceNowCredential.ps1', 'setup/_shared/SI-GuidedInstallPro.ps1',
        'engine/_shared/SI-InvardiaUpdate.ps1', 'engine/_shared/SI-InvardiaUpdateKeys.json', 'container/updater/_shared/SI-UpdaterInvardia.ps1'
    ) {
        $script:Exclude | Should -Contain $_
    }

    It 'every file under engine/asset-cmdb is listed, except the four helpers the free data sync needs -- a NEW file there never ships by default' {
        # engine/asset-cmdb is listed file by file since 2026-10-18 (the data sync and the database setup need three of its
        # helpers in the free version: the completeness verdict, the release store, the vulnerability target's SQL seam and the close guards they load); a folder entry would have kept a new file out by itself, so this does it now.
        $shared = @('engine/asset-cmdb/_shared/SI-VulnDesired.ps1', 'engine/asset-cmdb/_shared/SI-VulnRelease.ps1', 'engine/asset-cmdb/_shared/SI-VulnTarget.ps1', 'engine/asset-cmdb/_shared/SI-ReconcileGuards.ps1')
        $root = Join-Path $script:SIRoot 'engine\asset-cmdb'
        $unlisted = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object { 'engine/asset-cmdb/' + $_.FullName.Substring($root.Length + 1).Replace('\', '/') } |
            Where-Object { $shared -notcontains $_ -and -not (Test-SIExcluded $_) })
        $unlisted | Should -BeNullOrEmpty -Because 'a Pro file under engine/asset-cmdb must be in excludePaths (or be named a shared helper here, on purpose)'
        foreach ($s in $shared) { Test-SIExcluded $s | Should -BeFalse -Because "$s is loaded by the free data sync / database setup" }
    }
    It 'every excludePaths entry still exists -- a renamed Pro folder would otherwise ship' {
        $missing = @($script:Exclude | Where-Object { -not (Test-Path -LiteralPath (Join-Path $script:SIRoot $_)) })
        $missing | Should -BeNullOrEmpty -Because 'an entry that names nothing protects nothing'
    }

    It 'every file that declares a Pro feature gate lives under an excluded path' {
        # A new Pro engine gates itself with Assert-SIFeatureOrSkip. If it sits outside the list, it ships.
        $gated = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.Name -ne 'SI-FeatureCatalog.ps1' } |
            Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match "(Assert-SIFeatureOrSkip|Test-SIFeatureAvailable)\s+-Feature\s+'(servicenow-connector|governance|cmdb-connectors)'" } |
            ForEach-Object { $_.FullName.Substring($script:SIRoot.Length + 1) })
        $gated | Should -Not -BeNullOrEmpty
        # SHIPPED on purpose, each with its reason: verification (Community since 2026-10-27, #750 (8)) asks the gate only to
        # SKIP its ServiceNow output check (after Test-Path finds the Pro helper) -- it gates nothing of its own
        $shippedGateCallers = @('engine\verification\Invoke-SIVerification.ps1')
        @($gated | Where-Object { -not (Test-SIExcluded $_) -and $shippedGateCallers -notcontains $_ }) | Should -BeNullOrEmpty
    }
}

Describe 'the free version has the database and the web app (owner 2026-10-18, #750 (a))' {

    It '<_> ships in the public payload' -ForEach @(
        'pro-management', 'pro-management/deploy/Deploy-SIManagement.ps1', 'pro-management/deploy/New-SIManagementAppRegistration.ps1',
        'pro-management/src/SI.Management.Web/Licensing/ProFeatures.cs',
        'sql/si-data-schema.sql', 'sql/si-identity-schema.sql', 'sql/si-pro-settings.sql', 'sql/si-vulnerability-target.sql', 'sql/si-cmdbsync-schema.sql',
        'engine/pro-settings', 'engine/pro-data/Invoke-SIDataSync.ps1', 'engine/pro-data/_shared/SI-DataSync.ps1', 'engine/data-model',
        'engine/asset-cmdb/_shared/SI-VulnDesired.ps1',
        'setup/_shared/SI-GuidedInstallData.ps1', 'setup/Initialize-SIDataSql.ps1', 'setup/Initialize-SIVulnTargetSql.ps1', 'setup/Import-SIProSettings.ps1',
        'setup/Publish-SITemplates.ps1', 'setup/Install-SIUpdaterJob.ps1',
        'config/settings.catalog.locked.json', 'config/audit-actions.locked.json', 'config/config-entities.locked.json',
        # the owner's decisions of 2026-10-27 (#750): correlation and the full asset properties, the schema-update scripts,
        # verification and data health, the licence terms of the paid web pages -- all in the Community edition
        'engine/asset-correlation', 'engine/asset-properties', 'launcher/asset-correlation', 'config/correlation-decisions.custom.sample.yaml',
        'container/updater/_shared/SI-UpdaterDatabase.ps1', 'setup/Grant-SIUpdaterDatabase.ps1', 'container/updater/_shared/SI-UpdaterWebApp.ps1',
        'engine/verification', 'config/verification-checks.locked.json', 'engine/data-health/Invoke-SIDataHealth.ps1',
        'engine/asset-tagging', 'LICENSE-PRO'
    ) {
        Test-Path -LiteralPath (Join-Path $script:SIRoot $_) | Should -BeTrue -Because "$_ must exist"
        Test-SIExcluded $_ | Should -BeFalse -Because "$_ is part of the database and the web app, which the free version has"
    }

    It 'every product script the free install''s database and web app steps run ships in the public payload' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1')
        $rel = @([regex]::Matches($src, "-RelativePath '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $rel.Count | Should -BeGreaterThan 5
        foreach ($r in $rel) {
            Test-Path -LiteralPath (Join-Path $script:SIRoot $r) | Should -BeTrue -Because "$r is run by a free install step"
            Test-SIExcluded $r | Should -BeFalse -Because "$r is run by a free install step"
        }
        # ...and every engine / sql file the step bodies dot-source or read
        $loads = @([regex]::Matches($src, "Combine\(\`$ctx\.SIRoot((?:, '[^']+')+)\)") | ForEach-Object { ([regex]::Matches($_.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }) -join '/' } | Sort-Object -Unique)
        $loads.Count | Should -BeGreaterThan 2
        foreach ($l in $loads) { Test-SIExcluded $l | Should -BeFalse -Because "$l is loaded by a free install step" }
    }

    It 'the guided install''s plan without a licence has the database and the web app steps, and no paid step' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $ids = @(Get-SIInstallStepPlan -Edition 'community' | ForEach-Object Id)
        foreach ($s in 'preflight-sql-region', 'pro-sql', 'pro-schema', 'pro-templates', 'pro-settings', 'web-app', 'updater-job') { $ids | Should -Contain $s }
        $ids | Should -Not -Contain 'pro-cmdb'
        $script:SIInstallCommunityEngines | Should -Contain 'asset-datasync' -Because 'the data sync loads Risk Analysis into the database in both versions'
        # owner 2026-10-27 (#750 (1), (2)): the CI build (correlation) and asset tagging are Community edition jobs
        foreach ($e in 'asset-correlation', 'asset-tagging') { $script:SIInstallCommunityEngines | Should -Contain $e }
    }

    It 'the solution file stays out of the public copy (it names the test projects the copy leaves out) and nothing shipped needs it (2026-10-28)' {
        Test-SIExcluded 'pro-management/SI.Management.sln' | Should -BeTrue
        foreach ($p in 'pro-management/tests') { Test-SIExcluded $p | Should -BeTrue }
        # the images build their projects directly (the Dockerfiles), never the solution
        foreach ($d in 'pro-management/Dockerfile', 'pro-management/Dockerfile.mcp') { (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $d)) | Should -Not -Match '\.sln' -Because $d }
        # (-Include is ignored next to -LiteralPath: filter on the extension)
        $needs = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.csproj', '.json', '.yml' } |
            Where-Object { $_.FullName -notmatch '[\\/](bin|obj|INTERNAL)[\\/]' } |
            ForEach-Object { $_.FullName.Substring($script:SIRoot.Length + 1).Replace('\', '/') } |
            Where-Object { -not (Test-SIExcluded $_) -and $_ -notlike 'tests/*' } |
            Where-Object { (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $_)) -match 'SI\.Management\.sln' })
        # (only the probe project's comment says it is NOT part of the solution)
        # (solution.publish.json names it in its exclude list, and is itself stripped at publish)
        @($needs | Where-Object { $_ -notin 'pro-management/deploy/probe/SI.Management.LiveProbe.csproj', 'solution.publish.json' }) | Should -BeNullOrEmpty
    }

    It 'the Community edition logo files ship, unchanged, and the web app names them (owner 2026-10-28)' {
        $dir = 'pro-management/src/SI.Management.Web/wwwroot/brand/community'
        foreach ($f in 'invardia-securityinsight-community-horizontal-reversed.svg', 'invardia-securityinsight-community-horizontal-colour.svg',
                       'invardia-securityinsight-community-stacked-colour.svg', 'favicon.ico', 'invardia-icon.svg',
                       'invardia-app-tile-180.png', 'invardia-app-tile-192.png', 'invardia-app-tile-512.png') {
            Test-Path -LiteralPath (Join-Path $script:SIRoot "$dir/$f") | Should -BeTrue -Because "$f is the Community edition's brand"
            Test-SIExcluded "$dir/$f" | Should -BeFalse -Because "$f must ship in the Community edition"
        }
        # the same files as the brand pack the README uses (Invardia's brand/products/securityinsight/community, byte for byte)
        foreach ($v in 'colour', 'reversed') {
            $a = Join-Path $script:SIRoot "$dir/invardia-securityinsight-community-horizontal-$v.svg"
            $b = Join-Path $script:SIRoot "docs/images/brand/invardia-securityinsight-community-horizontal-$v.svg"
            (Get-FileHash -LiteralPath $a).Hash | Should -Be (Get-FileHash -LiteralPath $b).Hash -Because "the $v logo is never redrawn"
        }
        $cs = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'pro-management/src/SI.Management.Web/Licensing/EditionBrand.cs')
        foreach ($p in @([regex]::Matches($cs, '"(/brand/community/[^"]+)"') | ForEach-Object { $_.Groups[1].Value })) {
            Test-Path -LiteralPath (Join-Path $script:SIRoot ('pro-management/src/SI.Management.Web/wwwroot' + $p)) | Should -BeTrue -Because "$p is named by EditionBrand.cs"
        }
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'README.md')) | Should -Match 'invardia-securityinsight-community-horizontal-colour\.svg'
    }

    It 'correlation, the full asset properties, asset tagging, verification and data health carry no licence gate (#750)' {
        . (Join-Path $script:SIRoot 'engine\SI-FeatureCatalog.ps1')
        Test-SIFeatureIsPaid -Feature 'correlation' | Should -BeFalse
        foreach ($d in 'engine\asset-correlation', 'engine\asset-properties', 'engine\asset-tagging', 'engine\verification', 'engine\data-health') {
            $gated = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot $d) -Recurse -File -Filter '*.ps1' |
                Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match "(Assert-SIFeatureOrSkip|Test-SIFeatureAvailable)\s+-Feature\s+'(correlation|asset-tagging|verification|data-health)'" })
            $gated | Should -BeNullOrEmpty -Because "$d is in the Community edition"
        }
    }

}

Describe 'no free file loads a Pro file' {

    It 'no PowerShell file outside the Pro paths references one in code (comments do not count)' {
        # Terms: a Pro FILE by its file name; a Pro FOLDER by its name when that name is distinctive
        # (asset-correlation, ...). A folder named with a plain word -- container/updater -- is matched by its
        # last TWO segments, both separators: the bare word "updater" is in banner text and comments all
        # over the free code (2026-09-30), and matching it would bury the real signal.
        # Docs are skipped -- a dangling doc link cannot break a run.
        $terms = @($script:ProExclude | Where-Object { $_ -notlike '*.md' } | ForEach-Object {
            $leaf = Split-Path -Leaf $_
            if ($leaf -match '[-.]') { $leaf }
            else {
                $parts = @($_ -split '[\\/]' | Where-Object { $_ })
                # a top-level folder with a plain name (release) is matched as a path: 'release/' or 'release\'
                $two = if ($parts.Count -ge 2) { $parts[-2] + '/' + $parts[-1] } else { $leaf + '/' }
                $two; $two.Replace('/', '\')
            }
        } | Sort-Object -Unique)
        $skipDirs = '[\\/](internal|logs|output|staging|bin|obj|node_modules)[\\/]'
        # Free TESTS that check a Pro file only where it exists (Test-Path, then skip). Named one by one:
        # a free ENGINE is never allowed here -- it would have to run without the file.
        $guarded = @(
            'tests\pester\SIv3-LegacyAliasContract.Tests.ps1|asset-correlation'
            # the job size (#509) names the Pro job caj-si-asset-cmdb-sql to size it when it exists -- a JOB name, never a load of the folder
            'setup\_shared\SI-JobSizing.ps1|asset-cmdb'
            # #685: the update creates the Pro jobs a newer version needs (caj-si-verification) through the Pro worker, loaded
            # only after Test-Path finds it -- the Community copy has neither the worker nor the jobs
            'setup\Invoke-SIContainerUpdate.ps1|SI-MissingJobs.ps1'
            # #903: the update's ServiceNow data-out step reads a connector row with the engine's own rule (SI-Connector.ps1), loaded
            # only after Test-Path finds it -- the Community copy has no connectors and the step returns before it
            'setup\Invoke-SIContainerUpdate.ps1|asset-cmdb'
            # #681: the private-networking cut-over loads the Support app's database access only after it finds the file (Pro)
            'setup\Set-SIPrivateNetworking.ps1|SI-SupportAppDatabase.ps1'
            # #681: the private-networking option's no-module check reads the Pro support SQL job files only where they exist
            'tests\pester\SIv3-PrivateNetwork.Tests.ps1|SI-SupportSqlJob.ps1'
            'tests\pester\SIv3-PrivateNetwork.Tests.ps1|Invoke-SISupportSqlAccessJob.ps1'
            'tests\pester\SIv3-JobSizing.Tests.ps1|asset-cmdb'
            # #756: the size settings' catalog entries are checked only after Test-Path finds the Pro settings catalog (skipped without it)
            'tests\pester\SIv3-JobSizing.Tests.ps1|settings.catalog.locked.json'
            'tests\pester\SIv3-SqlTier.Tests.ps1|settings.catalog.locked.json'
            'tests\pester\SIv3-ShippedHelpersContract.Tests.ps1|Measure-SICmdbMatchRate.ps1'
            'tests\pester\SIv3-IngestTargetPin.Tests.ps1|asset-properties'
            'tests\pester\SIv3-LogIngestRest.Tests.ps1|asset-properties'   # the wiring check reads the Pro ingest file only after Test-Path finds it
            'tests\pester\SIv3-DataFixes.Tests.ps1|asset-properties'       # the parts hand-over tests load the Pro publisher only after Test-Path finds it (skipped without it)
            # #692: the report-structure block loads the report certification only after Test-Path finds it (skipped, saying why, without it)
            'tests\pester\SIv3-ReportOutputContract.Tests.ps1|report-certification'
            'tests\pester\SIv3-SocAttackPaths.Tests.ps1|report-certification'   # the spec case runs only after Test-Path finds the folder (skipped without it)
            'tests\pester\SIv3-SqlTier.Tests.ps1|SI-UpdaterInvardia.ps1'        # #756: the Invardia update path is read only after Test-Path finds it (skipped without it)
            'tests\pester\SIv3-StepFailureCause.Tests.ps1|asset-correlation'     # a job NAME in fixture log lines -- a label, never loaded
            'tests\pester\SIv3-NoScriptSigningClaims.Tests.ps1|release\'         # the published product pages are read only after Test-Path finds the folder
            # the data sync's step NAME 'view-context' (a label in its step list) -- the Pro test fixture folder tests\fixtures\view-context is never loaded
            'engine\pro-data\_shared\SI-DataSync.ps1|view-context'
            # The container parity test NAMES Pro engines only to assert they have no launcher config of their own.
            'tests\pester\SIv3-ContainerParity.Tests.ps1|asset-correlation'
            'tests\pester\SIv3-ContainerParity.Tests.ps1|asset-cmdb'
            # #350: the updater loads the Pro web app roll only after Test-Path finds it (the Community image has no web app)
            'container\updater\Start-SIUpdater.ps1|SI-UpdaterWebApp.ps1'
            # #350 (c): the self-update test checks that the Pro web app roll builds through the build-context helper only
            # after Test-Path finds it
            'tests\pester\SIv3-UpdaterSelf.Tests.ps1|SI-UpdaterWebApp.ps1'
            # #352: the updater loads its Pro database step only after Test-Path finds it, and its installer offers the Pro
            # database rights (Grant-SIUpdaterDatabase.ps1) only after Test-Path finds that script -- the Community copy has neither.
            'container\updater\Start-SIUpdater.ps1|SI-UpdaterDatabase.ps1'
            'setup\Install-SIUpdaterJob.ps1|Grant-SIUpdaterDatabase.ps1'
            # the secret hand-over (Pro web app -> updater): the updater and its installer load it only after Test-Path finds it
            'container\updater\Start-SIUpdater.ps1|SI-UpdaterSecretHandover.ps1'
            'setup\Install-SIUpdaterJob.ps1|SI-UpdaterSecretHandover.ps1'
            # #429: the asset tagging job records its run as a connector only after Test-Path finds the Pro connector helper
            'engine\asset-tagging\Invoke-SIAssetTaggingJob.ps1|asset-cmdb'
            # V3-DATA-MODEL 2.12: the data-out writer (free: the CI build writes the CI workbook through it) records its runs as
            # a connector, and sends a ServiceNow hand-off, only after Test-Path finds the Pro connector / ServiceNow helpers
            'engine\data-out\SI-DataOut.ps1|asset-cmdb'
            # ...and NAMES the Pro script setup\Set-SIServiceNowCredential.ps1 only in the reason it returns on that Pro-only path
            # (reached only after Test-Path found the Pro ServiceNow helpers) -- a text for the admin, never loaded.
            'engine\data-out\SI-DataOut.ps1|Set-SIServiceNowCredential.ps1'
            # the CI graph (free) reads the service model from the CMDB engine only after File.Exists finds it -- an install
            # without that engine gives no model (said once, never fatal)
            'engine\data-model\SI-CiGraph.ps1|asset-cmdb'
            # the fast-gate suite checks the Pro CI build suite's scale tag only where Test-Path finds that suite
            'tests\pester\SIv3-FastGate.Tests.ps1|SIv3-CiBuildSql.Tests.ps1'
        )
        # Container hosting (#170) NAMES the Pro engines to host them where they exist -- it never loads one.
        # Bootstrap adds a Pro job only after Test-Path finds the engine folder, and the entrypoint dispatches
        # only a job that exists; in the Community copy neither ever happens. Infrastructure, not an engine.
        foreach ($f in 'Bootstrap-ContainerAppJob.ps1', 'container\Start-SIInContainer.ps1', 'container\_shared\SI-ContainerConfig.ps1', 'tests\pester\SIv3-ContainerConfig.Tests.ps1') {
            foreach ($e in 'asset-correlation', 'asset-properties', 'asset-cmdb') { $guarded += "$f|$e" }
            # the verification service (V3-DATA-MODEL 2.11): the dispatch NAMES its script; the entrypoint hosts only a job that exists
            $guarded += "$f|engine/verification"
            # #718: the hourly status report job -- the same: named to host it where it exists, added only after Test-Path
            $guarded += "$f|engine/heartbeat"
        }
        # The licence setter (#173) is Pro tooling. Unattended setup calls it only after Test-Path finds it and
        # says so when it does not; the free licence test checks it only where it exists.
        # The missing-table test (#221) checks the Pro readers' wiring only where they exist (Test-Path, then skip).
        foreach ($e in 'asset-correlation', 'asset-cmdb') { $guarded += "tests\pester\SIv3-KqlError.Tests.ps1|$e" }
        $guarded += 'Setup-SecurityInsight-Unattended.ps1|Set-SILicense.ps1'
        # #509: the update's job sizing NAMES the CI build job (caj-si-asset-correlation) to size it where it exists -- it
        # sizes only jobs the install has, and never loads the engine; its test names it the same way.
        $guarded += 'setup\_shared\SI-JobSizing.ps1|asset-correlation'
        $guarded += 'tests\pester\SIv3-JobSizing.Tests.ps1|asset-correlation'
        # the run-limit test NAMES a job that is no step of the pipeline, to show it is left alone (a label, never loaded)
        $guarded += 'tests\pester\SIv3-JobSizing.Tests.ps1|asset-properties'
        # #269: the daily job flow is FREE; the flow test NAMES Pro jobs as steps (labels, never loaded). The RUNNER is no
        # longer allowed here (env 4 Community install, 2026-10-28): it opens the database through the settings layer both
        # editions ship -- a Pro file named in it would put a Community install's runs, lock and queue back on the blob store.
        foreach ($e in 'asset-correlation', 'asset-properties', 'asset-cmdb') { $guarded += "tests\pester\SIv3-JobFlow.Tests.ps1|$e" }
        # the self-healing test NAMES Pro jobs as steps of the pipeline and as jobs whose run limit is raised (labels, never loaded)
        foreach ($e in 'asset-correlation', 'asset-cmdb') { $guarded += "tests\pester\SIv3-RunLimitSelfHeal.Tests.ps1|$e" }
        # #306: the pipeline test NAMES Pro jobs as steps of the Correlate / Deliver stages (labels, never loaded)
        foreach ($e in 'asset-correlation', 'asset-properties', 'asset-cmdb') { $guarded += "tests\pester\SIv3-Pipeline.Tests.ps1|$e" }
        # #528: the stages test NAMES Pro jobs as pipeline steps (labels, never loaded) and reads the web app's JobFlow.cs as
        # text to prove it carries the same default layout (never loaded)
        foreach ($e in 'asset-correlation', 'asset-cmdb') { $guarded += "tests\pester\SIv3-PipelineStages.Tests.ps1|$e" }
        # the flow switch test's fake job list NAMES a Pro job (caj-si-asset-correlation) -- a label, never loaded
        $guarded += 'tests\pester\SIv3-JobFlowSetup.Tests.ps1|asset-correlation'
        # v3: the Risk Analysis CI-context test NAMES the CI-building job as a pipeline step (a label in test data, never loaded)
        $guarded += 'tests\pester\SIv3-RaCiContext.Tests.ps1|asset-correlation'
        # The guided install loads its Pro steps only after Test-Path finds them.
        # the free install's updater step asks only whether the package carries the update client (Test-Path, never loaded)
        $guarded += 'setup\_shared\SI-GuidedInstallData.ps1|SI-UpdaterInvardia.ps1'
        $guarded += 'setup\Install-SecurityInsight.ps1|SI-GuidedInstallPro.ps1'
        # #412: the profilers' full asset-metadata level loads the Pro publisher only after Test-Path finds it (and the Pro
        # licence allows it); the Community copy stays at the security level -- the source queries unchanged -- and says so.
        $guarded += 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1|asset-properties'
        # ...and the job flow NAMES the retired asset-properties job (a step a stored pipeline loses) -- a label, never loaded.
        $guarded += 'engine\_shared\SI-JobFlow.ps1|asset-properties'
        # the retired-job test checks the guided install's Pro job list only after Test-Path finds it
        $guarded += 'tests\pester\SIv3-JobFlow.Tests.ps1|SI-GuidedInstallPro.ps1'
        # The telemetry contract NAMES every job id, the Pro ones included ('si-asset-properties') -- a label in a
        # closed list, never a path that is loaded.
        $guarded += 'engine\_shared\SI-Telemetry.ps1|asset-properties'
        $guarded += 'tests\pester\SIv3-ErrorClass.Tests.ps1|asset-properties'
        # The telemetry sender maps an engine NAME to its job id ('asset-cmdb' -> 'si-cmdb') -- labels, never a path loaded.
        foreach ($e in 'asset-correlation', 'asset-properties', 'asset-cmdb') { $guarded += "engine\_shared\SI-TelemetrySend.ps1|$e" }
        $guarded += 'tests\pester\SIv3-LicenseInstall.Tests.ps1|Set-SILicense.ps1'
        # #239: the licence request client installs through Set-SILicense.ps1 only after Test-Path finds it (a Community copy
        # reports that it cannot install), and names Request-SILicense.ps1 only in what it tells the admin to run.
        $guarded += 'engine\_shared\SI-LicenceRequest.ps1|Set-SILicense.ps1'
        $guarded += 'engine\_shared\SI-LicenceRequest.ps1|Request-SILicense.ps1'
        $guarded += 'diagnostics\_SIInstallDiagnostics.ps1|Request-SILicense.ps1'
        $guarded += 'tests\pester\SIv3-LicenceRequest.Tests.ps1|Set-SILicense.ps1'
        # ...and NAMES Request-SILicense.ps1 in a Describe title (the nested-script case it reproduces) -- a label, never loaded.
        $guarded += 'tests\pester\SIv3-LicenceRequest.Tests.ps1|Request-SILicense.ps1'
        # The rule-override test's SQL CMDB connector block runs only where Test-Path finds the Pro connector (skipped in a
        # Community copy); the free precedence blocks run everywhere.
        foreach ($e in 'asset-cmdb') { $guarded += "tests\pester\SIv3-CmdbRuleOverride.Tests.ps1|$e" }
        # The storage test checks the Pro guided install only where Test-Path finds it.
        $guarded += 'tests\pester\SIv3-StorageSharedKeyOff.Tests.ps1|SI-GuidedInstallPro.ps1'
        # #681 / #683: the option tests load the Pro install steps / read them only after Test-Path finds them
        $guarded += 'tests\pester\SIv3-PrivateNetwork.Tests.ps1|SI-GuidedInstallPro.ps1'
        $guarded += 'tests\pester\SIv3-CustomerKeys.Tests.ps1|SI-GuidedInstallPro.ps1'
        # The upgrade test names SI's retired feed tools only to assert they are gone (2026-10-06).
        $guarded += 'tests\pester\SIv3-ProUpgrade.Tests.ps1|Publish-SISourceArchive.ps1'
        $guarded += 'tests\pester\SIv3-ProUpgrade.Tests.ps1|Update-SISourceAccess.ps1'
        # #240: updates from Invardia are Pro. The updater loads its Invardia hook only after Test-Path finds it (and only when
        # SI_UPDATER_SOURCE is invardia), its installer refuses -Source invardia when Test-Path does not find it, and the
        # health check reads the update state only after Test-Path finds the client.
        $guarded += 'container\updater\Start-SIUpdater.ps1|SI-UpdaterInvardia.ps1'
        $guarded += 'setup\Install-SIUpdaterJob.ps1|SI-UpdaterInvardia.ps1'
        $guarded += 'diagnostics\_SIInstallDiagnostics.ps1|SI-InvardiaUpdate.ps1'
        # 2026-10-06 (SI's own feed retired, Invardia is the only Pro update source): the updater suites test the Invardia hook;
        # they are PrivateRepo-scoped (# SI-TestScope: PrivateRepo -- never run in a Community copy), and the own-schedule
        # wiring check that reads the hook is tagged PrivateRepo.
        $guarded += 'tests\pester\SIv3-Updater.Tests.ps1|SI-UpdaterInvardia.ps1'
        $guarded += 'tests\pester\SIv3-UpdateChannel.Tests.ps1|SI-UpdaterInvardia.ps1'
        $guarded += 'tests\pester\SIv3-UpdaterOwnSchedule.Tests.ps1|SI-UpdaterInvardia.ps1'
        # #275 R2: the CMDB refresh loads the Pro CMDB reader only for source 'pro-cmdb' (a Pro database is configured), and
        # only after Test-Path finds it -- a Community copy says it is not the Pro package. Never reached without a Pro database.
        $guarded += 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1|asset-cmdb'
        # ...and names the Pro migration script only in the warning it gives on that Pro-only path.
        $guarded += 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1|Import-SICmdbCsv.ps1'
        # #643: the report-scope suite checks the Pro vulnerability loop's tier reader only after Test-Path finds it
        $guarded += 'tests\pester\SIv3-ReportScopeHonest.Tests.ps1|asset-cmdb'
        # #724 (2): the portal-link suite checks the Pro close-loop and exemption mails only where Test-Path finds them
        $guarded += 'tests\pester\SIv3-InvardiaPortalLink.Tests.ps1|asset-cmdb'
        # #725: the workbook-export suite checks the Pro missing-jobs worker and the Pro settings catalog only where Test-Path finds them
        $guarded += 'tests\pester\SIv3-RaWorkbookExport.Tests.ps1|SI-MissingJobs.ps1'
        # #755: the retired-v2-scripts suite asserts a retired Pro doc (release\script-docs) is ABSENT, and reads the web app's
        $guarded += 'tests\pester\SIv3-RetiredV2SetupScripts.Tests.ps1|release\'
        # ---- 2026-10-18 (#915): engine/asset-cmdb and the governance engines are listed FILE BY FILE (the free data sync
        # needs four of asset-cmdb's helpers), so each Pro file is a term of its own. The infrastructure and the tests that
        # name them were already allowed under the folder term; each is named again under the file it names, same reason.
        foreach ($f in 'Bootstrap-ContainerAppJob.ps1', 'container\_shared\SI-ContainerConfig.ps1', 'tests\pester\SIv3-ContainerConfig.Tests.ps1') {
            foreach ($e in 'Invoke-SICmdb.ps1', 'Invoke-SIVulnLoop.ps1', 'Invoke-SICmdbSql.ps1', 'Invoke-SICloseLoopMail.ps1') { $guarded += "$f|$e" }
        }
        $guarded += 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1|SI-CmdbHome.ps1'
        $guarded += 'engine\asset-tagging\Invoke-SIAssetTaggingJob.ps1|SI-Connector.ps1'
        $guarded += 'engine\data-model\SI-CiGraph.ps1|SI-ServiceModel.ps1'
        # #903: ...and the ServiceNow output check (SI-SnowVerify.ps1), loaded the same way, only after Test-Path finds it
        foreach ($e in 'SI-Connector.ps1', 'SI-SnowImportSet.ps1', 'SI-ServiceNowClient.ps1', 'SI-SnowVerify.ps1') { $guarded += "engine\data-out\SI-DataOut.ps1|$e" }
        foreach ($e in 'SI-CmdbSqlSync.ps1') { $guarded += "tests\pester\SIv3-CmdbRuleOverride.Tests.ps1|$e" }
        foreach ($e in 'SI-CloseLoopMail.ps1', 'SI-ExemptionMail.ps1', 'Invoke-SICloseLoopMail.ps1') { $guarded += "tests\pester\SIv3-InvardiaPortalLink.Tests.ps1|$e" }
        $guarded += 'tests\pester\SIv3-KqlError.Tests.ps1|Invoke-SIVulnLoop.ps1'
        # The four close-loop helpers the free data sync and the database setup load SHIP (engine\asset-cmdb\_shared\
        # SI-VulnDesired / SI-VulnRelease / SI-VulnTarget / SI-ReconcileGuards); their folder's name is still a Pro term
        # (launcher/asset-cmdb), so the shipped files that load them by path are named here.
        $guarded += 'engine\pro-data\Invoke-SIDataSync.ps1|asset-cmdb'
        $guarded += 'engine\pro-data\_shared\SI-DataCiLifecycle.ps1|asset-cmdb'
        # #829: the CI build's run-health check loads the shipped helper SI-VulnDesired.ps1 by its path
        $guarded += 'engine\pro-data\_shared\SI-DataCi.ps1|asset-cmdb'
        # #903: the update's ServiceNow data-out step loads the Pro connector rule only after Test-Path finds it (file-by-file term)
        $guarded += 'setup\Invoke-SIContainerUpdate.ps1|SI-Connector.ps1'
        $guarded += 'setup\Initialize-SIVulnTargetSql.ps1|asset-cmdb'
        # ...a held release's audit target is the text 'release/<run id>', never the release kit folder
        $guarded += 'engine\asset-cmdb\_shared\SI-VulnRelease.ps1|release/'
        # The database layer and its setup NAME Pro things without loading them: the settings layer maps container job
        # names to engine folders (labels) and materialises the CMDB ownership map / service model under their file names
        # (read only where they exist); the grant catalog lists the Pro files the engine role covers (labels); the data
        # quality figures label their step 'asset-correlation' (the CI build job's name); the settings import runs the v2.2
        # CMDB migration and the connector store only after Test-Path finds them; the data tables' setup checks the SQL
        # CMDB connector's tables only after Test-Path finds its helper.
        foreach ($e in 'asset-cmdb') { $guarded += "engine\pro-settings\SI-ProSettings.ps1|$e" }
        foreach ($e in 'cmdb-source-ownership.locked.json', 'service-model.locked.json') { $guarded += "engine\pro-settings\SI-ProConfig.ps1|$e" }
        foreach ($e in 'asset-cmdb', 'SI-SnowTestPack.ps1', 'New-SIServiceNowTestPack.ps1', 'SI-Connector.ps1') { $guarded += "engine\pro-settings\SI-EngineGrants.ps1|$e" }
        $guarded += 'engine\pro-data\_shared\SI-DataQuality.ps1|asset-correlation'
        # 2026-10-27 (#750): the full asset properties (now Community) hold a large change through the SHIPPED release store
        # engine\asset-cmdb\_shared\SI-VulnRelease.ps1 -- loaded by its path; the folder name is still a Pro term (launcher/asset-cmdb)
        $guarded += 'engine\asset-properties\_shared\SI-AssetPropertiesProfiler.ps1|asset-cmdb'
        $guarded += 'engine\asset-properties\Invoke-SIAssetProperties.ps1|asset-cmdb'
        # ...and verification (now Community) runs the ServiceNow output check only after Test-Path finds it AND the licence
        # allows 'servicenow-connector' -- the Community copy has neither file
        foreach ($e in 'asset-cmdb', 'SI-SnowVerify.ps1', 'SI-Connector.ps1') { $guarded += "engine\verification\Invoke-SIVerification.ps1|$e" }
        # #750 (b): the Community update client tells the Pro package from the Community copy by Pro-only files -- Test-Path on
        # their names, never loaded (LICENSE-PRO and engine\pro-* ship in both since 2026-10-27, so they no longer tell them apart);
        # its test builds such trees in TestDrive
        foreach ($f in 'engine\_shared\SI-CommunityUpdate.ps1', 'tests\pester\SI-UpdateChannelClient.Tests.ps1') {
            foreach ($e in 'SI-GuidedInstallPro.ps1', 'SI-InvardiaUpdate.ps1', 'Invoke-SICmdb.ps1', 'asset-cmdb') { $guarded += "$f|$e" }
        }
        # ...the Community updater suite proves the Community path never loads the Pro Invardia hook (named, Test-Path only)
        $guarded += 'tests\pester\SIv3-UpdaterCommunity.Tests.ps1|SI-UpdaterInvardia.ps1'
        # ...and the Community edition suite runs its licence-record cases only where Test-Path finds the Pro install file
        $guarded += 'tests\pester\SIv3-CommunityEdition.Tests.ps1|SI-GuidedInstallPro.ps1'
        # ...and asserts the retired 2.2 hand-over folder (release\handover-2.2.x) is GONE -- named, never loaded
        $guarded += 'tests\pester\SIv3-CommunityEdition.Tests.ps1|release\'
        foreach ($e in 'asset-cmdb', 'SI-Connector.ps1', 'Import-SICmdbCsv.ps1') { $guarded += "setup\Import-SIProSettings.ps1|$e" }
        foreach ($e in 'asset-cmdb', 'SI-CmdbSqlSync.ps1') { $guarded += "setup\Initialize-SIDataSql.ps1|$e" }
        $offenders = New-Object System.Collections.Generic.List[string]
        # -Include is silently ignored next to -LiteralPath on PS 5.1, so filter on the extension.
        Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } | ForEach-Object {
            $rel = $_.FullName.Substring($script:SIRoot.Length + 1)
            if (Test-SIExcluded $rel) { return }
            if ($_.FullName -match $skipDirs) { return }
            if ($rel -ieq 'tests\pester\SI-CommunityPayload.Tests.ps1') { return }
            $tokens = $null; $errs = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errs)
            foreach ($t in $tokens) {
                if ($t.Kind -eq 'Comment') { continue }
                if ($t.Kind -notin 'StringLiteral', 'StringExpandable', 'HereStringLiteral', 'HereStringExpandable', 'Generic') { continue }
                foreach ($term in $terms) {
                    if ($t.Text.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and "$rel|$term" -notin $guarded) {
                        $offenders.Add(('{0}:{1} -> {2}' -f $rel, $t.Extent.StartLineNumber, $term))
                    }
                }
            }
        }
        # joined on one line, so the message names every offender (an array's message shows only the first ten)
        (@($offenders) -join ' ;; ') | Should -BeNullOrEmpty -Because 'the Community edition does not contain these files'
    }
}

Describe 'every free engine can actually be STARTED in the public copy (#167)' {

    It 'every launcher folder that is not a Pro path has a launcher.community-vm.ps1' {
        # Publish strips launcher.internal-*, so a free engine whose only launcher is internal-vm ships as
        # an engine nobody can start. That is how "Trend" came to be advertised for Community with no way
        # to run it (2026-09-30). Derived from the tree, not a hand-kept list, so the next engine counts.
        # Internal-only BY DECISION, each with the reason -- an entry here is a choice, not a gap:
        # (asset-tagging was the one exemption until #188 gave it a Community launcher, 2026-09-30.)
        # v3 (2026-10-08): the Community edition is container-hosted -- the CI build runs as the container job
        # caj-si-asset-correlation (Start-SIInContainer); the asset-properties job is retired (#412: the profilers publish
        # the full asset metadata themselves). Neither has a VM launcher to ship.
        $internalOnly = @{ 'asset-correlation' = 'container job caj-si-asset-correlation'; 'asset-properties' = 'retired (#412)' }
        $missing = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'launcher') -Directory |
            Where-Object { $_.Name -notlike '_*' } |
            Where-Object { -not (Test-SIExcluded ('launcher/' + $_.Name)) } |
            Where-Object { -not $internalOnly.ContainsKey($_.Name) } |
            Where-Object { -not (Test-Path -LiteralPath (Join-Path $_.FullName 'launcher.community-vm.ps1')) } |
            ForEach-Object { $_.Name })
        $missing | Should -BeNullOrEmpty -Because "free engines with no Community launcher: $($missing -join ', ')"
    }
}

Describe 'the licence files match the edition split' {

    It 'publishes under PolyForm Shield 1.0.0 with the official terms and a Required Notice' {
        $script:Publish.license | Should -Be 'PolyForm-Shield-1.0.0'
        $lic = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'LICENSE')
        # \r?$: a Windows checkout (core.autocrlf) has CRLF, and (?m)$ does not match before \r.
        $lic | Should -Match '(?m)^# PolyForm Shield License 1\.0\.0\r?$'
        $lic | Should -Match '(?m)^Required Notice: Copyright'
        $lic | Should -Match 'Any purpose is a permitted purpose, except for providing any product that competes with the software'
        $lic | Should -Match '(?s)Pro components .* are NOT licensed under these terms'
    }

    It 'LICENSE-PRO ships and names every paid web page, every paid finding action and the MCP server that ship in the Community edition (owner 2026-10-27, #750 (5))' {
        Test-SIExcluded 'LICENSE-PRO' | Should -BeFalse -Because 'the public copy carries Pro components (the paid web pages), so it carries their terms'
        $pro = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'LICENSE-PRO')
        $part1 = ($pro -split 'PART 2')[0]
        $cs = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Licensing\ProFeatures.cs')
        $pagesBlock = [regex]::Match($cs, '(?s)Pages\s*=\s*new Dictionary.*?\};').Value
        $actionsBlock = [regex]::Match($cs, '(?s)Actions\s*=\s*new Dictionary.*?\};').Value
        $pages = @([regex]::Matches($pagesBlock, '\["(/[^"]+)"\]') | ForEach-Object { $_.Groups[1].Value })
        $actions = @([regex]::Matches($actionsBlock, '\["([a-z-]+)"\]') | ForEach-Object { $_.Groups[1].Value })
        $pages.Count | Should -BeGreaterThan 10
        $actions.Count | Should -BeGreaterThan 3
        foreach ($p in $pages) { $part1 | Should -Match ('(?m)^\s+' + [regex]::Escape($p) + '\s*$') -Because "the paid page $p ships in the Community edition" }
        foreach ($a in $actions) { $part1 | Should -Match ('\b' + [regex]::Escape($a) + '\b') -Because "the paid action $a ships in the Community edition" }
        $part1 | Should -Match 'SI\.Management\.Mcp'
    }

    It 'LICENSE-PRO names every excluded Pro code/config path' {
        $pro = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'LICENSE-PRO')
        # a path is named by itself, or by the folder it is in (engine/asset-cmdb: listed file by file in excludePaths, named
        # once in LICENSE-PRO with the three shared helpers it does not cover)
        $named = { param([string]$Path) $parts = $Path -split '/'; for ($i = $parts.Count; $i -ge [Math]::Min(2, $parts.Count); $i--) { if ($pro.IndexOf(($parts[0..($i - 1)] -join '/'), [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }; $false }
        $missing = @($script:ProExclude | Where-Object { $_ -notlike 'docs/*' -and $_ -notlike 'tests/*' -and $_ -ne 'LICENSE-PRO' -and $_ -notin 'pro-management/tests', 'pro-management/SI.Management.sln', 'pro-management/docs-screens', 'pro-management/deploy/internal' } |
            Where-Object { -not (& $named $_) })
        $missing | Should -BeNullOrEmpty
    }
}
