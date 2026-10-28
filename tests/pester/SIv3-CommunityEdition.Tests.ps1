#Requires -Version 5.1
<#
    THE COMMUNITY EDITION BUILD (SI #750, owner decisions 2026-10-27; branch si-v3-scale/community-build). What these tests hold:
      (1) (2) cross-engine correlation (the CI build, asset-correlation) and asset tagging are jobs of EVERY install, not Pro
              additions; nothing a person reads calls asset tagging Pro, and its write answer is on a page both editions show;
      (6)     the database NAMES are the same in both editions (sqldb-si-pro / sqldb-si-identity) -- only the resource group and
              the server carry the edition;
      (7)     a Pro install's guided install VERIFIES AND RECORDS THE LICENCE itself (cfg.InstallState 'Licence', the record the
              web app's licence gate and the MCP server read), so its paid pages are on at once;
      (11)    side by side in ONE tenant: a NEW Community edition install gets tenant-wide names of its own (the sign-in app,
              the engine app, the SQL admin group) and never finds a Pro install's objects -- nor a Pro install the Community
              one's;
      (b)     a Community edition install records its update ring on the Community channel, ring 2 or 3 only.
    The licence-record cases need the Pro package's install file (setup\_shared\SI-GuidedInstallPro.ps1) and are skipped in a
    Community copy, saying so.
#>

BeforeDiscovery {
    $script:DiscRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:HasProInstall = Test-Path -LiteralPath (Join-Path $script:DiscRoot 'setup\_shared\SI-GuidedInstallPro.ps1')
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SavedNewNames = $env:SI_Setup_NewInstallNames
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-DisplayNames.ps1')
    $script:ProInstallFile = Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallPro.ps1'
    if (Test-Path -LiteralPath $script:ProInstallFile) { . $script:ProInstallFile }
    function script:Read-SI([string]$Rel) { [IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }
}

AfterAll { $env:SI_Setup_NewInstallNames = $script:SavedNewNames }

Describe '(1) (2) correlation and asset tagging are Community edition jobs' {
    It 'every install gets the CI build and asset tagging; the Pro package does not add them again' {
        $script:SIInstallCommunityEngines | Should -Contain 'asset-correlation'
        $script:SIInstallCommunityEngines | Should -Contain 'asset-tagging'
        if (Get-Command -Name Get-SIInstallProEngines -ErrorAction SilentlyContinue) {
            $pro = @(Get-SIInstallProEngines -Values @{})
            $pro | Should -Not -Contain 'asset-correlation'
            $pro | Should -Not -Contain 'asset-tagging'
        }
    }
    It 'the asset tagging write answer is on a page both editions show (features), never on the Pro page' {
        $p = (Read-SI 'setup\install-parameters.json') | ConvertFrom-Json
        @($p.parameters | Where-Object { $_.key -eq 'assetTaggingWrites' })[0].page | Should -Be 'features'
    }
    It 'nothing a person reads calls asset tagging Pro (the settings catalog, the reference config, the product docs)' {
        foreach ($f in 'config\settings.catalog.locked.json', 'config\SecurityInsight.custom.reference.ps1', 'pro-management\src\SI.Management.Web\ProductDocs\community-scripts.md') {
            (Read-SI $f) | Should -Not -Match 'Asset tagging \(Pro\)' -Because $f
            (Read-SI $f) | Should -Not -Match '(?i)asset tagging as a container job is part of Pro' -Because $f
        }
        (Read-SI 'pro-management\src\SI.Management.Web\Licensing\ProFeatures.cs') | Should -Not -Match '(?i)"/AssetTagging"' -Because 'the asset tagging pages are in both editions'
    }
}

Describe '(6) the database names are the same in both editions; the server and resource group carry the edition' {
    It 'the install''s databases are sqldb-si-pro and sqldb-si-identity, whatever the edition' {
        $script:SIInstallProDatabase | Should -BeExactly 'sqldb-si-pro'
        $script:SIInstallLedgerDatabase | Should -BeExactly 'sqldb-si-identity'
    }
    It 'the Community edition''s server and resource group carry its own names; nothing ships a Community database name' {
        $c = Get-SISetupResourceNames -Ring prod -Edition community -Hosting ca -SubscriptionId '00000000-0000-0000-0000-000000000001'
        $p = Get-SISetupResourceNames -Ring prod -Edition pro -Hosting ca -SubscriptionId '00000000-0000-0000-0000-000000000001'
        $c.ResourceGroup | Should -BeExactly 'rg-si-prod-community-ca'
        $c.SqlServer | Should -Match '^sql-si-prod-community-ca'
        $c.SqlServer | Should -Not -Be $p.SqlServer
        foreach ($d in 'engine', 'setup', 'container', 'pro-management\src', 'pro-management\deploy') {
            $hit = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot $d) -Recurse -File -Include '*.ps1', '*.cs', '*.json' |
                Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' } | Select-String -Pattern 'sqldb-si-community' -SimpleMatch)
            $hit | Should -BeNullOrEmpty -Because "$d names one database per role in both editions"
        }
    }
    It 'the web app, the MCP server and the updater are given the install''s database names, never an edition-specific one' {
        $src = Read-SI 'setup\_shared\SI-GuidedInstallData.ps1'
        $src | Should -Match '\$script:SIInstallProDatabase\s*=\s*''sqldb-si-pro'''
        $src | Should -Not -Match "(?i)Database\s*=\s*'sqldb-si-(?!pro'|identity'|vulntarget')"
    }
}

Describe '(11) side by side in one tenant: a new Community edition install has tenant-wide names of its own' {
    It 'its sign-in app, engine app and SQL admin group are named apart from a Pro install''s' {
        $c = Get-SISetupDisplayNames -New -Edition community
        $p = Get-SISetupDisplayNames -New -Edition pro
        foreach ($k in 'SpnDisplayName', 'WebAppDisplayName', 'SqlAdminGroupDisplayName', 'SqlAdminGroupName') {
            [string]$c[$k] | Should -Not -BeExactly ([string]$p[$k]) -Because $k
            [string]$c[$k] | Should -Match '(?i)community' -Because $k
        }
        $c.SqlAdminGroupName | Should -BeExactly 'grp-si-community-sql-admins'
        $p.SqlAdminGroupName | Should -BeExactly 'grp-si-sql-admins'
    }
    It 'an existing install (today''s names, no -New) keeps exactly today''s names in both editions' {
        foreach ($e in 'community', 'pro') {
            $d = Get-SISetupDisplayNames -Edition $e
            $d.WebAppDisplayName | Should -BeExactly 'SecurityInsight Management'
            $d.SpnDisplayName | Should -BeExactly 'SecurityInsight'
            $d.SqlAdminGroupDisplayName | Should -BeExactly 'grp-si-sql-admins'
        }
    }
    It 'the admin group lookups never cross: the Community group''s filter names only its own names, the Pro filter never the Community ones' {
        $cf = Get-SISqlAdminGroupFilter -GroupName 'grp-si-community-sql-admins'
        $cf | Should -Match "displayName eq 'grp-si-community-sql-admins'"
        $cf | Should -Match "displayName eq 'SecurityInsight Community SQL admins'"
        $cf | Should -Match "mailNickname eq 'grpsicommunitysqladmins'"
        $cf | Should -Not -Match "'grp-si-sql-admins'|'SecurityInsight SQL admins'|'grpsisqladmins'"
        (Get-SISqlAdminGroupFilter -GroupName 'SecurityInsight Community SQL admins') | Should -BeExactly $cf
        $pf = Get-SISqlAdminGroupFilter -GroupName 'grp-si-sql-admins'
        $pf | Should -Not -Match '(?i)community'
    }
    It 'the install creates the Community group under its own name and display name (both database steps)' {
        $names = [ordered]@{ SqlServer = 'sql-si-prod-community-ca-abc123'; ResourceGroup = 'rg-si-prod-community-ca'
                             SqlAdminGroupDisplayName = 'SecurityInsight Community SQL admins'; SqlAdminGroupName = 'grp-si-community-sql-admins' }
        $ctx = [pscustomobject]@{ Values = [ordered]@{ subscriptionId = '00000000-0000-0000-0000-000000000001' }; Names = $names; Facts = [ordered]@{ userObjectId = '11111111-1111-1111-1111-111111111111' } }
        $ga = Get-SIInstallSqlAdminGroupArgs -Ctx $ctx
        $ga.GroupName | Should -BeExactly 'grp-si-community-sql-admins'
        $ga.DisplayName | Should -BeExactly 'SecurityInsight Community SQL admins'
        # a Pro install with the new names: today's lookup name, the new display name (unchanged behaviour)
        $ctx.Names = [ordered]@{ SqlServer = 's'; ResourceGroup = 'r'; SqlAdminGroupDisplayName = 'SecurityInsight SQL admins'; SqlAdminGroupName = 'grp-si-sql-admins' }
        $gp = Get-SIInstallSqlAdminGroupArgs -Ctx $ctx
        $gp.Contains('GroupName') | Should -BeFalse
        $gp.DisplayName | Should -BeExactly 'SecurityInsight SQL admins'
        # the server step (pro-sql) passes the same names
        $src = Read-SI 'setup\_shared\SI-GuidedInstallData.ps1'
        $src | Should -Match 'Get-SIInstallSqlAdminGroupName -Names \$n'
        Get-SIInstallSqlAdminGroupName -Names $names | Should -BeExactly 'grp-si-community-sql-admins'
        Get-SIInstallSqlAdminGroupName -Names ([ordered]@{}) | Should -BeExactly 'grp-si-sql-admins'
    }
    It 'a resume keeps the group name the first run recorded' {
        $src = Read-SI 'setup\_shared\SI-GuidedInstall.ps1'
        $src | Should -Match "'WebAppDisplayName' \+ 'SqlAdminGroupDisplayName' \+ 'SqlAdminGroupName'"
    }
}

Describe 'owner 2026-10-28: SecurityInsight 3 is published to its own branch; 2.2''s public main stays frozen' {
    It 'the public stable branch is v3 and the preview branch is v3''s own -- never main or the 2.2 preview branch' {
        $pub = (Read-SI 'solution.publish.json') | ConvertFrom-Json
        $pub.stableBranch | Should -BeExactly 'v3'
        $pub.previewBranch | Should -Not -BeIn @('main', 'preview')
        $pub.previewBranch | Should -Match '^v3'
    }
    It 'the 2.2.461 hand-over is retired: no hand-over change set, no hand-over suites, no excludePaths entry for them' {
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'release\handover-2.2.x') | Should -BeFalse
        foreach ($t in 'SIv3-UpdateHandover.Tests.ps1', 'SIv3-HandoverReleaseOrder.Tests.ps1') { Test-Path -LiteralPath (Join-Path $script:SIRoot "tests\pester\$t") | Should -BeFalse }
        (Read-SI 'solution.publish.json') | Should -Not -Match 'UpdateHandover|HandoverReleaseOrder|handover-2\.2'
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\Publish-SIUpdateChannel.ps1') | Should -BeFalse -Because 'the channel.json tool is retired (2026-10-28)'
    }
}

Describe '2026-10-28: the public copy has no BUILD.json -- the web app image still builds' {
    It 'a folder without BUILD.json gets one from its VERSION; one with it is left as it is; no VERSION = not a release' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-BuildInfo.ps1')
        $d = Join-Path $TestDrive 'pub'; New-Item -ItemType Directory -Force -Path $d | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'VERSION'), '3.0.5')
        Initialize-SIBuildInfoFile -SolutionRoot $d -Channel community -Ring 3 | Should -Be 'written'
        $j = Get-Content -Raw -LiteralPath (Join-Path $d 'BUILD.json') | ConvertFrom-Json
        $j.version | Should -Be '3.0.5'; $j.channel | Should -Be 'community'; $j.ring | Should -Be 3
        [IO.File]::WriteAllText((Join-Path $d 'BUILD.json'), '{"version":"3.0.5","display":"kept"}')
        Initialize-SIBuildInfoFile -SolutionRoot $d | Should -Be 'present'
        (Get-Content -Raw -LiteralPath (Join-Path $d 'BUILD.json')) | Should -Match 'kept'
        $e = Join-Path $TestDrive 'empty'; New-Item -ItemType Directory -Force -Path $e | Out-Null
        { Initialize-SIBuildInfoFile -SolutionRoot $e } | Should -Throw '*VERSION*'
    }
    It 'the Community updater stamps it before anything is built; the guided install''s web deploy stamps its own stage' {
        $u = Read-SI 'container\updater\_shared\SI-UpdaterCommunity.ps1'
        $u.IndexOf('Initialize-SIBuildInfoFile') | Should -BeGreaterThan 0
        $u.IndexOf('Initialize-SIBuildInfoFile') | Should -BeLessThan $u.IndexOf('Invoke-SIUpdaterRoll -SIRoot')
        (Read-SI 'pro-management\deploy\Deploy-SIManagement.ps1') | Should -Match "Write-SIBuildInfo -Info \`$info -Path \(Join-Path \`$Stage 'BUILD.json'\)"
    }
}

Describe '(b) a Community edition install records its update ring on the Community channel, ring 2 or 3' {
    It 'the settings step records channel community and clamps any other ring to 3' {
        $src = Read-SI 'setup\_shared\SI-GuidedInstallData.ps1'
        $src | Should -Match "if \(-not \`$ctx\.Pro -and \`$a\.Ring -notin '2', '3'\) \{ \`$a\.Ring = '3' \}"
        $src | Should -Match "\`$a\.Channel = \`$\(if \(\`$ctx\.Pro\) \{ 'invardia' \} else \{ 'community' \}\)"
    }
}

Describe '(7) the guided install verifies and records the licence itself' {
    It 'the settings step records it for a Pro install, after the settings import (cfg.InstallState exists)' {
        $src = Read-SI 'setup\_shared\SI-GuidedInstallData.ps1'
        $step = [regex]::Match($src, "(?s)\`$t\['pro-settings'\] = \{.*?\n    \}\r?\n").Value
        $step | Should -Not -BeNullOrEmpty
        $step.IndexOf('Save-SIInstallLicenceRecord') | Should -BeGreaterThan $step.IndexOf('setup/Import-SIProSettings.ps1')
        $step | Should -Match 'if \(\$ctx\.Pro -and \(Get-Command -Name Save-SIInstallLicenceRecord'
    }
    It 'writes the SAME row the updater writes (cfg.InstallState Licence), the value as a safe literal, within 400 characters' -Skip:(-not $script:HasProInstall) {
        $q = Get-SIInstallLicenceRecordSql -Json '{"status":"Valid","customer":"O''Brien Ltd","sku":"Pro"}'
        $q | Should -Match "Name = N'Licence'"
        $q | Should -Match ([regex]::Escape('N''{"status":"Valid","customer":"O''''Brien Ltd","sku":"Pro"}'''))
        $q | Should -Match "UpdatedBy = N'guided install'"
        $long = [ordered]@{ status = 'Valid'; sku = 'Pro'; features = ('f' * 150); reason = ('r' * 300) } | ConvertTo-Json -Compress
        $q2 = Get-SIInstallLicenceRecordSql -Json $long
        $lit = [regex]::Match($q2, "N'(\{.*?\})'").Groups[1].Value.Replace("''", "'")
        $lit.Length | Should -BeLessOrEqual 400
        ($lit | ConvertFrom-Json).reason | Should -BeNullOrEmpty
    }
    It 'verifies the licence, writes its summary through the install''s SQL seam and says so; a failure is a line, never a stop' -Skip:(-not $script:HasProInstall) {
        $script:Sent = New-Object System.Collections.Generic.List[string]
        Mock Use-SIInstallUserSqlToken { & $Action }
        Mock Get-SIInstallSqlFqdn { '<server>.database.windows.net' }
        Mock Invoke-SIInstallSql { $script:Sent.Add($Query); $null }
        $lic = [pscustomobject]@{ Status = 'Valid'; LicenseId = 'L-1'; Customer = 'Contoso'; Sku = 'Pro'; Features = @(); TenantIds = @('22222222-2222-2222-2222-222222222222')
                                  ValidFrom = [datetime]'2026-01-01'; ValidTo = [datetime]'2027-01-01'; GraceUntil = $null; Reason = '' }
        $ctx = [pscustomobject]@{ SIRoot = $script:SIRoot; LicencePath = ''; Values = [ordered]@{ tenantId = '22222222-2222-2222-2222-222222222222' }
                                  Facts = [ordered]@{}; Seams = @{ Now = { [datetime]'2026-10-27T12:00:00Z' } } }
        $r = Save-SIInstallLicenceRecord -Ctx $ctx -License $lic
        $r.Ok | Should -BeTrue
        $r.Status | Should -Be 'Valid'
        $ctx.Facts['licenceRecorded'] | Should -Be 'Valid'
        $script:Sent.Count | Should -Be 1
        $script:Sent[0] | Should -Match "N'Licence'"
        $script:Sent[0] | Should -Match '"tenantOk":true'
        Mock Invoke-SIInstallSql { throw 'Login failed for user' }
        $r2 = Save-SIInstallLicenceRecord -Ctx $ctx -License $lic
        $r2.Ok | Should -BeFalse
        $r2.Text | Should -Match 'the updater records it on its first run'
        # no licence file and no licence = nothing to record
        (Save-SIInstallLicenceRecord -Ctx $ctx).Ok | Should -BeFalse
    }
}
