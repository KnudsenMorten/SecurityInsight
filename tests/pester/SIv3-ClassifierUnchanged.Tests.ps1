#Requires -Version 5.1
<#
    THE PRIVILEGE TIER CLASSIFIER SKIPS ITS AI PASS WHEN NOTHING IT READS CHANGED (#528).

    Measured 2026-10-09 (internal): ptc took 15 of the pipeline's ~90 minutes, every day, for a catalog that moves on the
    order of weeks. Its inputs -- the Entra role definitions, the API permission catalog of 14 well-known service
    principals, the Azure role definitions -- cost seconds to read; the minutes are the AI pass. So every run reads the
    inputs, fingerprints them (plus the engine's own code, the AI switch and the AI deployment) and keeps the catalog --
    'skipped: unchanged since <date>', a successful run -- when the fingerprint equals the last COMPLETE catalog's and that
    catalog is younger than SI_PrivilegeTierClassifier_RefreshDays (default 7, so it is still rebuilt weekly).
    Rule 4: a catalog an AI failure left open (untiered items, items kept from an older catalog) is never kept as whole.
    Engine functions are lifted by AST. No network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:EnginePath = [IO.Path]::Combine($script:SIRoot, 'engine', 'privilege-tier-classifier', 'Invoke-PrivilegeTierClassifier.ps1')
    $script:EngineSrc = [IO.File]::ReadAllText($script:EnginePath)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
    $script:Lifted = @()
    foreach ($name in 'Get-PTCInputFingerprint', 'Get-PTCCatalogState', 'Get-PTCUnchangedDecision', 'Get-PTCOpenItemCount', 'Get-PTCRefreshDays', 'Get-PTCDryRunPath', 'Export-TieredJSON') {
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
        if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)); $script:Lifted += $name }
    }
    function script:Write-Log { param($Message, $Level) }
    $script:Entra = @([pscustomobject]@{ Id = 'r1'; DisplayName = 'Global Administrator'; Description = 'all'; IsBuiltIn = $true; Permissions = @('microsoft.directory/allEntities/allProperties/allTasks') },
                      [pscustomobject]@{ Id = 'r2'; DisplayName = 'Reports Reader'; Description = 'reports'; IsBuiltIn = $true; Permissions = @('microsoft.directory/auditLogs/allProperties/read', 'microsoft.directory/signInReports/allProperties/read') })
    $script:Api = @([pscustomobject]@{ ServicePrincipal = 'Microsoft Graph'; AppId = '00000003-0000-0000-c000-000000000000'; PermissionType = 'Application'; Id = 'p1'; Value = 'Directory.ReadWrite.All'; DisplayName = 'x'; Description = 'y' })
    $script:Azure = @([pscustomobject]@{ Id = 'a1'; Name = 'Owner'; Description = 'o'; IsCustom = $false; Actions = @('*'); NotActions = @(); DataActions = @() })
    $script:Groups = @('Domain Admins', 'Enterprise Admins')
    function script:Fp { param($E = $script:Entra, $P = $script:Api, $A = $script:Azure, $G = $script:Groups, [string]$Engine = 'h1', [string]$RunAI = 'True', [string]$Dep = 'gpt')
        Get-PTCInputFingerprint -EntraRoles $E -APIPermissions $P -AzureRoles $A -ADGroups $G -EngineHash $Engine -RunAI $RunAI -AIDeployment $Dep }
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-10T22:00:00', 'Utc')
}

Describe 'the functions exist' {
    It 'all were lifted from the engine' { $script:Lifted.Count | Should -Be 7 -Because ($script:Lifted -join ',') }
}

Describe 'the input fingerprint' {
    It 'is stable, and independent of the order Graph / ARM return the items and their permissions in' {
        $a = Fp
        $a | Should -Match '^sha256:[0-9a-f]{64}$'
        (Fp) | Should -Be $a
        $shuffled = @($script:Entra[1], $script:Entra[0])
        $permsReversed = @([pscustomobject]@{ Id = 'r2'; DisplayName = 'Reports Reader'; Description = 'reports'; IsBuiltIn = $true; Permissions = @('microsoft.directory/signInReports/allProperties/read', 'microsoft.directory/auditLogs/allProperties/read') }, $script:Entra[0])
        (Fp -E $shuffled) | Should -Be $a
        (Fp -E $permsReversed) | Should -Be $a
        (Fp -G @('Enterprise Admins', 'Domain Admins', 'Domain Admins')) | Should -Be $a
    }
    It 'changes with a role, a permission, an Azure action, a new custom role, the engine, the AI switch or the deployment' {
        $a = Fp
        $renamed = @([pscustomobject]@{ Id = 'r1'; DisplayName = 'Global Administrator'; Description = 'all'; IsBuiltIn = $true; Permissions = @('microsoft.directory/allEntities/allProperties/allTasks', 'new/action') }, $script:Entra[1])
        (Fp -E $renamed) | Should -Not -Be $a
        (Fp -E ($script:Entra + @([pscustomobject]@{ Id = 'c1'; DisplayName = 'Org Tier0 Custom'; Description = ''; IsBuiltIn = $false; Permissions = @() }))) | Should -Not -Be $a
        (Fp -P @([pscustomobject]@{ ServicePrincipal = 'Microsoft Graph'; AppId = '00000003-0000-0000-c000-000000000000'; PermissionType = 'Application'; Id = 'p1'; Value = 'Directory.ReadWrite.All'; DisplayName = 'x'; Description = 'changed' })) | Should -Not -Be $a
        (Fp -A @([pscustomobject]@{ Id = 'a1'; Name = 'Owner'; Description = 'o'; IsCustom = $false; Actions = @('*'); NotActions = @('Microsoft.Authorization/*/Delete'); DataActions = @() })) | Should -Not -Be $a
        (Fp -Engine 'h2') | Should -Not -Be $a -Because 'a release that changes the prompts or the hardcoded lists rebuilds'
        (Fp -RunAI 'False') | Should -Not -Be $a
        (Fp -Dep 'gpt-new') | Should -Not -Be $a
    }
}

Describe 'the skip decision' {
    BeforeAll { $script:Fp1 = Fp; $script:Prior = { param($Fp = $script:Fp1, [double]$AgeDays = 1, [bool]$Complete = $true) [pscustomobject]@{ Fingerprint = $Fp; GeneratedUtc = $script:Now.AddDays(-$AgeDays); Complete = $Complete } } }
    It 'unchanged, complete and younger than the setting: skipped, and the line says since when' {
        $d = Get-PTCUnchangedDecision -Prior (& $script:Prior) -Fingerprint $script:Fp1 -NowUtc $script:Now -MaxAgeDays 7
        $d.Skip | Should -BeTrue
        $d.Reason | Should -Match '^skipped: unchanged since 2026-10-09 22:00 UTC'
    }
    It 'rebuilt when the inputs changed' { (Get-PTCUnchangedDecision -Prior (& $script:Prior) -Fingerprint (Fp -Engine 'h9') -NowUtc $script:Now).Skip | Should -BeFalse }
    It 'rebuilt at least every N days, whatever the fingerprint says' {
        (Get-PTCUnchangedDecision -Prior (& $script:Prior -AgeDays 7) -Fingerprint $script:Fp1 -NowUtc $script:Now -MaxAgeDays 7).Reason | Should -Match 'days old'
        (Get-PTCUnchangedDecision -Prior (& $script:Prior -AgeDays 6.9) -Fingerprint $script:Fp1 -NowUtc $script:Now -MaxAgeDays 7).Skip | Should -BeTrue
        (Get-PTCUnchangedDecision -Prior (& $script:Prior -AgeDays 2) -Fingerprint $script:Fp1 -NowUtc $script:Now -MaxAgeDays 1).Skip | Should -BeFalse
    }
    It 'rule 4: a previous catalog that left items open is tiered again, never kept as whole' {
        $d = Get-PTCUnchangedDecision -Prior (& $script:Prior -Complete $false) -Fingerprint $script:Fp1 -NowUtc $script:Now
        $d.Skip | Should -BeFalse; $d.Reason | Should -Match 'untiered'
    }
    It 'rebuilt when this run could not collect every input' { (Get-PTCUnchangedDecision -Prior (& $script:Prior) -Fingerprint $script:Fp1 -NowUtc $script:Now -CollectionOk $false).Skip | Should -BeFalse }
    It 'rebuilt with no previous catalog, a catalog without a fingerprint, a forced rebuild, or the setting at 0' {
        (Get-PTCUnchangedDecision -Prior $null -Fingerprint $script:Fp1 -NowUtc $script:Now).Skip | Should -BeFalse
        (Get-PTCUnchangedDecision -Prior (& $script:Prior -Fp '') -Fingerprint $script:Fp1 -NowUtc $script:Now).Reason | Should -Match 'no input fingerprint'
        (Get-PTCUnchangedDecision -Prior (& $script:Prior) -Fingerprint $script:Fp1 -NowUtc $script:Now -Force $true).Skip | Should -BeFalse
        (Get-PTCUnchangedDecision -Prior (& $script:Prior) -Fingerprint $script:Fp1 -NowUtc $script:Now -MaxAgeDays 0).Skip | Should -BeFalse
    }
    It 'the setting: 0-365 taken as it is, anything else is 7' {
        Get-PTCRefreshDays -Value $null | Should -Be 7
        Get-PTCRefreshDays -Value '' | Should -Be 7
        Get-PTCRefreshDays -Value 0 | Should -Be 0
        Get-PTCRefreshDays -Value '14' | Should -Be 14
        Get-PTCRefreshDays -Value -1 | Should -Be 7
        Get-PTCRefreshDays -Value 'weekly' | Should -Be 7
    }
    It 'an open item is one still at Tier 99' {
        Get-PTCOpenItemCount -Tiered @{ ADGroups = @([pscustomobject]@{ Tier = 0 }); EntraRoles = @([pscustomobject]@{ Tier = 99 }, [pscustomobject]@{ Tier = 1 }); APIPerms = @(); AzureRoles = @([pscustomobject]@{ Tier = 99 }) } | Should -Be 2
        Get-PTCOpenItemCount -Tiered @{ ADGroups = @(); EntraRoles = @(); APIPerms = @(); AzureRoles = @() } | Should -Be 0
    }
}

Describe 'the catalog records what the next run compares with' {
    BeforeEach {
        $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ('si-ptc-' + [guid]::NewGuid().ToString('n').Substring(0, 8))
        $null = New-Item -ItemType Directory -Path $script:Dir -Force
        $script:OutputFolder = $script:Dir; $OutputFolder = $script:Dir
        $script:OutputFile = Join-Path $script:Dir 'privilege-tier-catalog.custom.json'; $OutputFile = $script:OutputFile
        $script:PtcWhatIf = $true; $script:PtcAICallsUsed = 3
    }
    AfterEach { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    It 'the written metadata carries the fingerprint, the UTC time and whether it is complete -- and reads back as the state' {
        $tier = [pscustomobject]@{ Name = 'Domain Admins'; Tier = 0; Reason = 'r' }
        $path = Export-TieredJSON -TieredADGroups @($tier) -TieredEntraRoles @() -TieredAPIPerms @() -TieredAzureRoles @() -RawAPIPermissions @() -RawAzureRoles @() -InputFingerprint 'sha256:abc' -Complete $true
        $j = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $j.Metadata.InputFingerprint | Should -Be 'sha256:abc'
        $j.Metadata.Complete | Should -BeTrue
        $st = Get-PTCCatalogState -Path $path
        $st.Fingerprint | Should -Be 'sha256:abc'; $st.Complete | Should -BeTrue
        ([datetime]::UtcNow - $st.GeneratedUtc).TotalMinutes | Should -BeLessThan 5
    }
    It 'a catalog written before fingerprints reads as "no fingerprint", aged by its file time' {
        '{"Metadata":{"GeneratedAt":"2026-10-01 10:00:00"},"AD_BuiltInPermissionGroups_Tier0":[]}' | Set-Content -LiteralPath $script:OutputFile -Encoding UTF8
        $st = Get-PTCCatalogState -Path $script:OutputFile
        $st.Fingerprint | Should -Be ''; $st.Complete | Should -BeFalse
        (Get-PTCCatalogState -Path (Join-Path $script:Dir 'missing.json')) | Should -BeNullOrEmpty
    }
}

Describe 'wiring in the engine' {
    It 'collects, decides, and only then runs the AI pass; a skip ends the run as a success with its line in run health' {
        $main = $script:EngineSrc.Substring($script:EngineSrc.IndexOf('function Main {'))
        $iCollect = $main.IndexOf('$azureRoles     = Get-AzureRoleDefinitions')
        $iDecide = $main.IndexOf('Get-PTCUnchangedDecision')
        $iAi = $main.IndexOf('Invoke-AllAITiering')
        $iCollect | Should -BeGreaterThan 0
        $iDecide | Should -BeGreaterThan $iCollect
        $iAi | Should -BeGreaterThan $iDecide
        $main | Should -Match 'if \(\$_unchanged\.Skip\) \{[^}]*\$_phRH_Err = \$_unchanged\.Reason[^}]*return'
        $main | Should -Match 'if \(-not \$script:PtcWhatIf\) \{\s*\$_unchanged' -Because 'a dry run always shows the rebuild'
        $main | Should -Match '-InputFingerprint\s+\$_fingerprint'
        $main | Should -Match '-Complete\s+\(\$_collectionOk -and \$keptFromPrior -eq 0 -and \(Get-PTCOpenItemCount -Tiered \$tiered\) -eq 0\)'
        $main | Should -Match 'Get-PTCRefreshDays'
    }
    It 'the setting is shipped with its default (7) and documented in the reference' {
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'launcher', 'privilege-tier-classifier', 'LauncherConfig.defaults.ps1')) | Should -Match 'SI_PrivilegeTierClassifier_RefreshDays = 7'
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'SecurityInsight.custom.reference.ps1')) | Should -Match '# \$global:SI_PrivilegeTierClassifier_RefreshDays = 7'
    }
}
