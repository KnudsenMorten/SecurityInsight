#Requires -Version 5.1
<#
    THE PRIVILEGE TIER CATALOG: BUILT HERE WITH AI, OR THE DAILY CLASSIFIED CATALOG DOWNLOADED (#1194, framework
    TIER-CATALOG-1).

    With AI off the classifier kept the tiers of its previous catalog, and the shipped catalog was months old: a role or
    permission Microsoft added since fell to the default tier. One setting (SI_PrivilegeTierCatalog_Source: auto |
    invardia | ai) now chooses the source; the download is CHECKED (manifest schema, byte count, SHA-256, the file's own
    version, every tier section present and non-empty) before it replaces the local copy, only a NEWER version replaces
    it, and a failed download or check keeps the last good copy and says how old it is -- never failing the run. The
    download replaces the BUILT-IN sections only: the shipped and the tenant's custom roles stay, and the custom catalog
    still wins on top.

    OFFLINE. The one network seam (Invoke-SITierCatalogHttpGet, and below it Invoke-SIAzRestHttp) is mocked; fixtures are
    written to TestDrive. Script-scope stubs only. Engine functions of the classifier are lifted by AST.
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Shared = [IO.Path]::Combine($script:SIRoot, 'engine', '_shared')
    # the shared HTTP seam exists (a stub), so the download file does not load the whole REST layer
    function script:Invoke-SIAzRestHttp { param($Method, $Uri, [switch]$AsBytes, $TimeoutSec, $Headers) throw 'not mocked' }
    function script:Write-SIInfo { param($Message) }
    function script:Write-Log { param($Message, $Level) }
    . ([IO.Path]::Combine($script:Shared, 'SI-TierCatalogDownload.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'shared', 'IdentityCatalogTierComputer.ps1'))

    $script:EnginePath = [IO.Path]::Combine($script:SIRoot, 'engine', 'privilege-tier-classifier', 'Invoke-PrivilegeTierClassifier.ps1')
    $script:EngineSrc = [IO.File]::ReadAllText($script:EnginePath)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
    $script:Lifted = @()
    foreach ($name in 'Get-PTCDownloadedTierMaps', 'Test-PTCIsBuiltInItem', 'Get-PTCItemKey', 'Set-PTCTiersFromDownloaded',
                      'Get-PTCCatalogSourceNote', 'Test-PTCCatalogSourceMoved', 'Get-PTCInputFingerprint', 'Get-PTCCatalogState',
                      'Get-PTCFirstRunSkip', 'Get-PTCFailureOutcome') {
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
        if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)); $script:Lifted += $name }
    }

    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-11T06:00:00', 'Utc')

    # A catalog in SI's schema: every built-in tier section with one generic row, plus the named rows the merge tests read.
    function script:New-CatalogObject {
        param([string]$Version = '2026.11.10', [string[]]$Drop = @(), [string[]]$Empty = @(), [switch]$NoVersion, [string]$FileVersion)
        $c = [ordered]@{ Metadata = [ordered]@{ GeneratedAt = '2026-11-10 02:00:00'; GeneratedBy = 'daily build' } }
        if (-not $NoVersion) { $c.Metadata['version'] = $(if ($FileVersion) { $FileVersion } else { $Version }) }
        foreach ($t in 0..3) {
            $c["AD_BuiltInPermissionGroups_Tier$t"] = @([ordered]@{ Name = "ADG-T$t"; Tier = $t; Reason = 'r' })
            $c["EntraID_BuiltInRoles_Tier$t"]      = @([ordered]@{ DisplayName = "Role-T$t"; IsBuiltIn = $true; Tier = $t; Reason = 'r' })
            $c["EntraID_APIPermissions_Tier$t"]    = @([ordered]@{ Value = "Perm.T$t"; PermissionType = 'Application'; Tier = $t; Reason = 'r' })
            $c["Azure_BuiltInRoles_Tier$t"]        = @([ordered]@{ Name = "AzRole-T$t"; IsCustom = $false; Tier = $t; Reason = 'r' })
        }
        $c['EntraID_BuiltInRoles_Tier0'] = @($c['EntraID_BuiltInRoles_Tier0'] + [ordered]@{ DisplayName = 'Fresh Role'; IsBuiltIn = $true; Tier = 0; Reason = 'new since the shipped catalog' })
        $c['EntraID_BuiltInRoles_Tier1'] = @($c['EntraID_BuiltInRoles_Tier1'] + [ordered]@{ DisplayName = 'Moved Role'; IsBuiltIn = $true; Tier = 1; Reason = 're-tiered' })
        # a custom-role section in the download is NEVER taken
        $c['EntraID_CustomRoles_Tier0'] = @([ordered]@{ DisplayName = 'Download Custom Role'; IsBuiltIn = $false; Tier = 0; Reason = 'x' })
        $c['EntraID_APIPermissions_Catalog'] = @()
        $c['Azure_Roles_Catalog'] = @()
        foreach ($d in $Drop) { $c.Remove($d) }
        foreach ($e in $Empty) { $c[$e] = @() }
        [pscustomobject]$c
    }
    function script:ConvertTo-Bytes { param($Object) ,([System.Text.Encoding]::UTF8.GetBytes(($Object | ConvertTo-Json -Depth 8))) }
    function script:New-ManifestBytes {
        param([byte[]]$FileBytes, [string]$Version = '2026.11.10', [string]$Schema = 'si-privilege-tier-catalog/2', $ByteCount, [string]$Sha)
        $m = [ordered]@{ schema = $Schema; version = $Version; builtUtc = '2026-11-10T02:00:00Z'
                         sha256 = $(if ($Sha) { $Sha } else { Get-SITierCatalogSha256 $FileBytes })
                         bytes = $(if ($null -ne $ByteCount) { $ByteCount } else { $FileBytes.Length })
                         counts = [ordered]@{ EntraID_BuiltInRoles_Tier0 = 2 }; changes = @() }
        ,([System.Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Depth 5)))
    }
    # the network: the manifest and the version file, from these two variables
    function script:Set-Published { param([byte[]]$Manifest, [byte[]]$File) $script:PubManifest = $Manifest; $script:PubFile = $File }
    $script:HttpBody = { if ($Uri -like '*/manifest.json') { ,$script:PubManifest } else { ,$script:PubFile } }
}

Describe 'the functions exist' {
    It 'the classifier''s catalog-source functions were lifted from the engine' { $script:Lifted.Count | Should -Be 10 -Because ($script:Lifted -join ',') }
}

Describe 'the setting: which source this run uses (owner 2026-11-11: download by default, AI an opt-in)' {
    It 'the default is the download -- empty and the old ''auto'' too, also with AI usable (an opt-in that costs money is never inferred)' {
        foreach ($v in @($null, '', 'auto', 'AUTO ')) {
            foreach ($ai in $true, $false) {
                $r = Resolve-SITierCatalogSource -Value $v -AIAvailable $ai
                $r.Source | Should -Be 'invardia' -Because "value '$v', AI usable $ai"
                $r.Warning | Should -BeNullOrEmpty
            }
        }
        (Resolve-SITierCatalogSource -Value '' -AIAvailable $true).Setting | Should -Be 'invardia'
    }
    It 'invardia = downloaded, also with AI usable' {
        (Resolve-SITierCatalogSource -Value 'invardia' -AIAvailable $true).Source | Should -Be 'invardia'
        (Resolve-SITierCatalogSource -Value 'Invardia ' -AIAvailable $false).Source | Should -Be 'invardia'
    }
    It "ai = the opt-in: built here when AI can be used; 'ai' with AI not usable falls back to the download and warns" {
        (Resolve-SITierCatalogSource -Value 'ai' -AIAvailable $true).Source | Should -Be 'ai'
        $r = Resolve-SITierCatalogSource -Value 'ai' -AIAvailable $false
        $r.Source | Should -Be 'invardia'
        $r.Warning | Should -Match 'downloaded instead'
    }
    It 'an unknown value is the download, with a warning' {
        $r = Resolve-SITierCatalogSource -Value 'github' -AIAvailable $true
        $r.Source | Should -Be 'invardia'
        $r.Warning | Should -Match "unknown value 'github'"
    }
    It 'AI can be used only with AI integration on, the classifier''s switch on and the Azure OpenAI settings set -- the classifier''s switch alone never makes it AI' {
        Test-SITierCatalogAIAvailable -AIIntegration $true -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k' | Should -BeTrue
        Test-SITierCatalogAIAvailable -AIIntegration 'true' -RunAI $null -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k' | Should -BeTrue
        Test-SITierCatalogAIAvailable -AIIntegration $null -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k' | Should -BeFalse -Because 'AI integration is off by default'
        Test-SITierCatalogAIAvailable -AIIntegration $false -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k' | Should -BeFalse
        Test-SITierCatalogAIAvailable -AIIntegration $true -RunAI $false -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k' | Should -BeFalse
        Test-SITierCatalogAIAvailable -AIIntegration $true -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey '' | Should -BeFalse
        # an install that never chose 'ai': whatever its AI settings, the download
        (Resolve-SITierCatalogSource -Value 'invardia' -AIAvailable (Test-SITierCatalogAIAvailable -AIIntegration $true -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey 'k')).Source | Should -Be 'invardia'
    }
    It 'ships with invardia for every install (the classifier''s defaults, the Community reference, the settings catalog: invardia | ai)' {
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'launcher', 'privilege-tier-classifier', 'LauncherConfig.defaults.ps1')) | Should -Match "SI_PrivilegeTierCatalog_Source = 'invardia'"
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'SecurityInsight.custom.reference.ps1')) | Should -Match "# \`$global:SI_PrivilegeTierCatalog_Source = 'invardia'"
        $cat = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'settings.catalog.locked.json')) | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_PrivilegeTierCatalog_Source' })
        $s.Count | Should -Be 1
        $s[0].type | Should -Be 'enum'
        @($s[0].values) | Should -Be @('invardia', 'ai')
        $s[0].default | Should -Be 'invardia'
        $s[0].edition | Should -Be 'community' -Because 'Pro AND Community'
    }
}
Describe 'the download: only a checked, newer catalog replaces the local copy' {
    BeforeEach {
        $script:Local = Join-Path $TestDrive ('dl-{0}\privilege-tier-catalog.downloaded.custom.json' -f [guid]::NewGuid().ToString('N'))
        $script:GoodFile = ConvertTo-Bytes (New-CatalogObject -Version '2026.11.10')
        Set-Published -Manifest (New-ManifestBytes -FileBytes $script:GoodFile) -File $script:GoodFile
        Mock Invoke-SITierCatalogHttpGet $script:HttpBody
    }
    It 'a good download with no local copy is saved byte for byte and reported' {
        $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now -BaseUrl 'https://example.test/catalog/privilege-tier'
        $r.Status | Should -Be 'downloaded'
        $r.Updated | Should -BeTrue
        $r.Version | Should -Be '2026.11.10'
        $r.Warning | Should -BeNullOrEmpty
        [IO.File]::ReadAllBytes($script:Local) | Should -Be $script:GoodFile
        Should -Invoke Invoke-SITierCatalogHttpGet -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://example.test/catalog/privilege-tier/manifest.json' }
        Should -Invoke Invoke-SITierCatalogHttpGet -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://example.test/catalog/privilege-tier/2026.11.10.json' }
    }
    It 'a newer version replaces an older local copy' {
        $old = ConvertTo-Bytes (New-CatalogObject -Version '2026.11.01')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:Local) | Out-Null
        [IO.File]::WriteAllBytes($script:Local, $old)
        $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
        $r.Status | Should -Be 'downloaded'
        (Get-SITierCatalogDownloadState -Path $script:Local).Version | Should -Be '2026.11.10'
    }
    It 'the same version is current: the file is not downloaded again' {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:Local) | Out-Null
        [IO.File]::WriteAllBytes($script:Local, $script:GoodFile)
        $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
        $r.Status | Should -Be 'current'
        $r.Updated | Should -BeFalse
        $r.Warning | Should -BeNullOrEmpty
        Should -Invoke Invoke-SITierCatalogHttpGet -Times 1 -Exactly
    }
    It 'an OLDER published version keeps the local copy and says so' {
        $newer = ConvertTo-Bytes (New-CatalogObject -Version '2026.11.12')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:Local) | Out-Null
        [IO.File]::WriteAllBytes($script:Local, $newer)
        $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
        $r.Status | Should -Be 'current'
        $r.Version | Should -Be '2026.11.12'
        $r.Warning | Should -Match 'older than the local copy'
        [IO.File]::ReadAllBytes($script:Local) | Should -Be $newer
    }
    Context 'a failed check keeps the last good copy and says how old it is' {
        BeforeEach {
            $script:Old = ConvertTo-Bytes (New-CatalogObject -Version '2026.11.01')
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:Local) | Out-Null
            [IO.File]::WriteAllBytes($script:Local, $script:Old)
        }
        It '<Case>' -TestCases @(
            @{ Case = 'a wrong SHA-256'; Make = { Set-Published -Manifest (New-ManifestBytes -FileBytes $script:GoodFile -Sha ('0' * 64)) -File $script:GoodFile }; Why = 'SHA-256' }
            @{ Case = 'a short file (fewer bytes than the manifest says)'; Make = { $short = [byte[]]$script:GoodFile[0..($script:GoodFile.Length - 40)]; Set-Published -Manifest (New-ManifestBytes -FileBytes $script:GoodFile) -File $short }; Why = 'bytes' }
            @{ Case = 'a missing tier section'; Make = { $f = ConvertTo-Bytes (New-CatalogObject -Drop 'Azure_BuiltInRoles_Tier2'); Set-Published -Manifest (New-ManifestBytes -FileBytes $f) -File $f }; Why = 'Azure_BuiltInRoles_Tier2 is missing' }
            @{ Case = 'an empty tier section'; Make = { $f = ConvertTo-Bytes (New-CatalogObject -Empty 'EntraID_APIPermissions_Tier0'); Set-Published -Manifest (New-ManifestBytes -FileBytes $f) -File $f }; Why = 'EntraID_APIPermissions_Tier0 is empty' }
            @{ Case = 'a manifest of another schema'; Make = { Set-Published -Manifest (New-ManifestBytes -FileBytes $script:GoodFile -Schema 'si-privilege-tier-catalog/1') -File $script:GoodFile }; Why = 'schema' }
            @{ Case = 'a manifest without a version'; Make = { Set-Published -Manifest (New-ManifestBytes -FileBytes $script:GoodFile -Version 'latest') -File $script:GoodFile }; Why = 'no valid version' }
            @{ Case = 'a file that names another version than its manifest'; Make = { $f = ConvertTo-Bytes (New-CatalogObject -Version '2026.11.10' -FileVersion '2026.11.09'); Set-Published -Manifest (New-ManifestBytes -FileBytes $f) -File $f }; Why = 'says version 2026.11.09' }
            @{ Case = 'a file that is not JSON'; Make = { $f = [System.Text.Encoding]::UTF8.GetBytes('<html>maintenance</html>'); Set-Published -Manifest (New-ManifestBytes -FileBytes $f) -File $f }; Why = 'not valid JSON' }
        ) {
            param($Case, $Make, $Why)
            & $Make
            $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
            $r.Status | Should -Be 'kept'
            $r.Updated | Should -BeFalse
            $r.Version | Should -Be '2026.11.01'
            $r.Warning | Should -Match ([regex]::Escape($Why))
            $r.Warning | Should -Match 'last good copy is kept: version 2026\.11\.01, 10 days old'
            [IO.File]::ReadAllBytes($script:Local) | Should -Be $script:Old -Because 'the last good copy is never touched'
            @(Get-ChildItem -LiteralPath (Split-Path -Parent $script:Local) -Force -Filter '*.tmp').Count | Should -Be 0
        }
        It 'a network failure keeps the last good copy, warns, and never throws' {
            Mock Invoke-SITierCatalogHttpGet { throw 'https://invardia.com/catalog/privilege-tier/manifest.json answered no answer: The remote name could not be resolved' }
            { $script:R = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now } | Should -Not -Throw
            $script:R.Status | Should -Be 'kept'
            $script:R.Warning | Should -Match 'manifest could not be read'
            $script:R.Warning | Should -Match '10 days old'
            [IO.File]::ReadAllBytes($script:Local) | Should -Be $script:Old
        }
        It 'the version file failing to download keeps the last good copy' {
            Mock Invoke-SITierCatalogHttpGet { if ($Uri -like '*/manifest.json') { ,$script:PubManifest } else { throw 'HTTP 404' } }
            $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
            $r.Status | Should -Be 'kept'
            $r.Warning | Should -Match 'version 2026\.11\.10 could not be downloaded'
        }
    }
    It 'a failure with no downloaded copy at all says the shipped catalog is used' {
        Mock Invoke-SITierCatalogHttpGet { throw 'no answer' }
        $r = Update-SITierCatalogDownload -LocalPath $script:Local -NowUtc $script:Now
        $r.Status | Should -Be 'none'
        $r.Version | Should -BeNullOrEmpty
        $r.Warning | Should -Match 'catalog shipped with SecurityInsight is used'
        Test-Path -LiteralPath $script:Local | Should -BeFalse
    }
}

Describe 'the one network call goes through the shared seam and retries transient answers' {
    BeforeEach { Mock Start-Sleep { } }
    It 'retries a 503 and returns the bytes of the 200' {
        $script:Calls = 0
        Mock Invoke-SIAzRestHttp {
            $script:Calls++
            if ($script:Calls -eq 1) { return [pscustomobject]@{ StatusCode = 503; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = '2' } }
            [pscustomobject]@{ StatusCode = 200; Content = ''; Bytes = [byte[]](1, 2, 3); Headers = @{}; RetryAfter = '' }
        }
        $b = Invoke-SITierCatalogHttpGet -Uri 'https://example.test/manifest.json'
        $b.GetType().Name | Should -Be 'Byte[]'
        $b | Should -Be ([byte[]](1, 2, 3))
        Should -Invoke Invoke-SIAzRestHttp -Times 2 -Exactly -ParameterFilter { $AsBytes -and -not $Headers.ContainsKey('Authorization') }
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 2 }
    }
    It 'a 404 throws at once (not retried)' {
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 404; Content = 'nf'; Bytes = $null; Headers = @{}; RetryAfter = '' } }
        { Invoke-SITierCatalogHttpGet -Uri 'https://example.test/x.json' } | Should -Throw '*HTTP 404*'
        Should -Invoke Invoke-SIAzRestHttp -Times 1 -Exactly
    }
    It 'the download file makes no direct web call (the raw-call ratchet holds)' {
        $path = [IO.Path]::Combine($script:Shared, 'SI-TierCatalogDownload.ps1')
        $tokens = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errs)
        $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text })) -join ' '
        $code | Should -Not -Match '(?i)\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|HttpClient|WebRequest\]::Create'
        $code | Should -Match 'Invoke-SIAzRestHttp'
    }
}

Describe 'the merge: the download replaces the BUILT-IN sections; custom roles and the custom catalog still win' {
    BeforeAll {
        $dir = Join-Path $TestDrive 'merge'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        # the shipped catalog: old tiers, a role the download no longer lists, and one shipped custom role
        $shipped = [ordered]@{ Metadata = [ordered]@{ GeneratedAt = '2026-05-03 00:08:22' } }
        foreach ($t in 0..3) {
            $shipped["AD_BuiltInPermissionGroups_Tier$t"] = @([ordered]@{ Name = "ADG-T$t"; Tier = $t; Reason = 'old' })
            $shipped["EntraID_BuiltInRoles_Tier$t"] = @([ordered]@{ DisplayName = "Role-T$t"; IsBuiltIn = $true; Tier = $t; Reason = 'old' })
            $shipped["EntraID_CustomRoles_Tier$t"] = @()
            $shipped["EntraID_APIPermissions_Tier$t"] = @([ordered]@{ Value = "Perm.T$t"; Tier = $t; Reason = 'old' })
            $shipped["Azure_BuiltInRoles_Tier$t"] = @([ordered]@{ Name = "AzRole-T$t"; IsCustom = $false; Tier = $t; Reason = 'old' })
            $shipped["Azure_CustomRoles_Tier$t"] = @()
        }
        $shipped['EntraID_BuiltInRoles_Tier3'] = @($shipped['EntraID_BuiltInRoles_Tier3'] + [ordered]@{ DisplayName = 'Moved Role'; IsBuiltIn = $true; Tier = 3; Reason = 'old' })
        $shipped['EntraID_BuiltInRoles_Tier2'] = @($shipped['EntraID_BuiltInRoles_Tier2'] + [ordered]@{ DisplayName = 'Shipped Only Role'; IsBuiltIn = $true; Tier = 2; Reason = 'old' })
        $shipped['EntraID_CustomRoles_Tier3'] = @([ordered]@{ DisplayName = 'Shipped Custom Role'; IsBuiltIn = $false; Tier = 3; Reason = 'old' })
        $script:ShippedPath = Join-Path $dir 'privilege-tier-catalog.locked.json'
        [IO.File]::WriteAllText($script:ShippedPath, ($shipped | ConvertTo-Json -Depth 8))
        $script:DlPath = Join-Path $dir 'privilege-tier-catalog.downloaded.custom.json'
        [IO.File]::WriteAllBytes($script:DlPath, (ConvertTo-Bytes (New-CatalogObject -Version '2026.11.10')))
        function script:Write-Custom { param([string]$Source)
            $c = [ordered]@{ Metadata = [ordered]@{ GeneratedAtUtc = '2026-11-11T01:00:00Z'; CatalogSource = $Source; CatalogVersion = '2026.11.10' }
                             EntraID_CustomRoles_Tier0 = @([ordered]@{ DisplayName = 'Tenant Custom Role'; IsBuiltIn = $false; Tier = 0; Reason = 'tenant' })
                             EntraID_APIPermissions_Tier0 = @([ordered]@{ Value = 'Perm.T3'; Tier = 0; Reason = 'the customer raised it' }) }
            $p = Join-Path $TestDrive ('custom-{0}.json' -f [guid]::NewGuid().ToString('N'))
            [IO.File]::WriteAllText($p, ($c | ConvertTo-Json -Depth 6)); $p }
    }
    It 'Merge-SITierCatalogBuiltIns takes the built-in sections, keeps the shipped custom roles, never takes a downloaded custom role' {
        $s = Get-Content -LiteralPath $script:ShippedPath -Raw | ConvertFrom-Json
        $m = Merge-SITierCatalogBuiltIns -Shipped $s -Downloaded (New-CatalogObject)
        @($m.EntraID_BuiltInRoles_Tier0 | ForEach-Object DisplayName) | Should -Contain 'Fresh Role'
        @($m.EntraID_BuiltInRoles_Tier3 | ForEach-Object DisplayName) | Should -Not -Contain 'Moved Role'
        @($m.EntraID_CustomRoles_Tier3 | ForEach-Object DisplayName) | Should -Be @('Shipped Custom Role')
        @($m.EntraID_CustomRoles_Tier0 | Where-Object { $_ }).Count | Should -Be 0
        $m.Metadata.GeneratedAt | Should -Be '2026-05-03 00:08:22' -Because 'the shipped metadata is not replaced'
        @($s.EntraID_BuiltInRoles_Tier3 | ForEach-Object DisplayName) | Should -Contain 'Moved Role' -Because 'the input is not changed'
    }
    It 'the identity engine tiers from the download when the classifier built the catalog from it' {
        $info = Initialize-SIIdentityCatalog -Path $script:ShippedPath -CustomPath (Write-Custom 'invardia') -DownloadedPath $script:DlPath -Force
        Get-SITierFromEntraRoles -Roles @('Fresh Role') | Should -Be 0 -Because 'a role only the new catalog lists gets its tier, not the default'
        Get-SITierFromEntraRoles -Roles @('Moved Role') | Should -Be 1 -Because 'the download replaces the shipped tier'
        @(Get-SIEntraRoleMatches -Roles @('Shipped Only Role')).Count | Should -Be 0 -Because 'the built-in sections are replaced, not merged'
        Get-SITierFromEntraRoles -Roles @('Shipped Custom Role') | Should -Be 3 -Because 'shipped custom roles stay'
        Get-SITierFromEntraRoles -Roles @('Tenant Custom Role') | Should -Be 0 -Because 'the tenant''s custom roles stay'
        @(Get-SIEntraRoleMatches -Roles @('Download Custom Role')).Count | Should -Be 0 -Because 'a custom-role section of the download is never taken'
        Get-SITierFromEntraAPIPerms -Perms @('Perm.T3') | Should -Be 0 -Because 'the custom catalog still wins'
        Get-SITierFromAzureRoles -Roles @('AzRole-T1') | Should -Be 1
        $info.CatalogSource | Should -Be 'invardia'
        $info.CatalogVersion | Should -Be '2026.11.10'
        $info.Label | Should -Match 'daily classified catalog version 2026\.11\.10, built 2026-11-10'
        Get-SIIdentityCatalogLabel | Should -Be $info.Label -Because 'every identity row records it'
    }
    It 'an install building with AI ignores a downloaded copy' {
        $info = Initialize-SIIdentityCatalog -Path $script:ShippedPath -CustomPath (Write-Custom 'ai') -DownloadedPath $script:DlPath -Force
        @(Get-SIEntraRoleMatches -Roles @('Fresh Role')).Count | Should -Be 0
        Get-SITierFromEntraRoles -Roles @('Moved Role') | Should -Be 3
        $info.CatalogSource | Should -Be 'ai'
        $info.Label | Should -Match 'built here with AI on 2026-11-11'
    }
    It 'the download selected but missing: the shipped sections are used, with a warning and a label that says so' {
        $info = Initialize-SIIdentityCatalog -Path $script:ShippedPath -CustomPath (Write-Custom 'invardia') -DownloadedPath (Join-Path $TestDrive 'none.json') -Force -WarningVariable w 3>$null
        Get-SITierFromEntraRoles -Roles @('Moved Role') | Should -Be 3
        ($w -join ' ') | Should -Match 'no downloaded copy is available'
        $info.Label | Should -Match 'not downloaded yet'
    }
    It 'a downloaded copy with an empty tier is not used' {
        $bad = Join-Path $TestDrive 'bad-download.json'
        [IO.File]::WriteAllBytes($bad, (ConvertTo-Bytes (New-CatalogObject -Empty 'AD_BuiltInPermissionGroups_Tier1')))
        $null = Initialize-SIIdentityCatalog -Path $script:ShippedPath -CustomPath (Write-Custom 'invardia') -DownloadedPath $bad -Force -WarningVariable w 3>$null
        Get-SITierFromEntraRoles -Roles @('Moved Role') | Should -Be 3
        ($w -join ' ') | Should -Match 'AD_BuiltInPermissionGroups_Tier1 is empty'
    }
}

Describe 'tier classification wins: the tenant''s classified catalog places every built-in entry it lists (AI mode too)' {
    BeforeAll {
        $dir = Join-Path $TestDrive 'classified'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $shipped = [ordered]@{ Metadata = [ordered]@{ GeneratedAt = '2026-05-03 00:08:22' } }
        foreach ($t in 0..3) {
            $shipped["AD_BuiltInPermissionGroups_Tier$t"] = @([ordered]@{ Name = "ADG-T$t"; Tier = $t; Reason = 'shipped' })
            $shipped["EntraID_BuiltInRoles_Tier$t"] = @([ordered]@{ DisplayName = "Role-T$t"; IsBuiltIn = $true; Tier = $t; Reason = 'shipped' })
            $shipped["EntraID_CustomRoles_Tier$t"] = @()
            $shipped["EntraID_APIPermissions_Tier$t"] = @([ordered]@{ Value = "Perm.T$t"; Tier = $t; Reason = 'shipped' })
            $shipped["Azure_BuiltInRoles_Tier$t"] = @([ordered]@{ Name = "AzRole-T$t"; IsCustom = $false; Tier = $t; Reason = 'shipped' })
            $shipped["Azure_CustomRoles_Tier$t"] = @()
        }
        $script:ClsShipped = Join-Path $dir 'privilege-tier-catalog.locked.json'
        [IO.File]::WriteAllText($script:ClsShipped, ($shipped | ConvertTo-Json -Depth 8))
        # the classifier's AI-built catalog: four entries placed at another tier than the shipped file; Role-T2 not listed
        $cls = [ordered]@{
            Metadata = [ordered]@{ GeneratedAtUtc = '2026-11-11T01:00:00Z'; CatalogSource = 'ai'; CatalogVersion = '' }
            EntraID_BuiltInRoles_Tier1 = @([ordered]@{ DisplayName = 'Role-T3'; IsBuiltIn = $true; Tier = 1; Reason = 'classified' })
            EntraID_BuiltInRoles_Tier3 = @([ordered]@{ DisplayName = 'Role-T0'; IsBuiltIn = $true; Tier = 3; Reason = 'classified' })
            Azure_BuiltInRoles_Tier0 = @([ordered]@{ Name = 'AzRole-T3'; IsCustom = $false; Tier = 0; Reason = 'classified' })
            EntraID_APIPermissions_Tier3 = @([ordered]@{ Value = 'Perm.T1'; Tier = 3; Reason = 'classified' })
            AD_BuiltInPermissionGroups_Tier2 = @([ordered]@{ Name = 'ADG-T0'; Tier = 2; Reason = 'classified' })
            EntraID_CustomRoles_Tier0 = @([ordered]@{ DisplayName = 'Role-T1'; IsBuiltIn = $false; Tier = 0; Reason = 'the customer''s own entry' })
        }
        $script:ClsCustom = Join-Path $dir 'privilege-tier-catalog.custom.json'
        [IO.File]::WriteAllText($script:ClsCustom, ($cls | ConvertTo-Json -Depth 8))
        $script:ClsInfo = Initialize-SIIdentityCatalog -Path $script:ClsShipped -CustomPath $script:ClsCustom -DownloadedPath (Join-Path $dir 'none.json') -Force
    }
    It 'a role the classified catalog places at another tier takes the classified tier (Entra and Azure built-in roles)' {
        Get-SITierFromEntraRoles -Roles @('Role-T3') | Should -Be 1 -Because 'shipped Tier 3, classified Tier 1'
        @(Get-SIEntraRoleMatches -Roles @('Role-T0'))[0].CatalogTier | Should -Be 3 -Because 'shipped Tier 0, classified Tier 3: classification wins, also downwards'
        Get-SITierFromAzureRoles -Roles @('AzRole-T3') | Should -Be 0
    }
    It 'an API permission and an AD group move per entry, not per tier (the more privileged shipped tier no longer stays)' {
        Get-SITierFromEntraAPIPerms -Perms @('Perm.T1') | Should -Be 3
        Get-SITierFromADGroups -Groups @('ADG-T0') | Should -Be 2
    }
    It 'a role the classified catalog does not list keeps the shipped tier' {
        @(Get-SIEntraRoleMatches -Roles @('Role-T2'))[0].CatalogTier | Should -Be 2
        Get-SITierFromAzureRoles -Roles @('AzRole-T1') | Should -Be 1
    }
    It 'the custom catalog''s own entries still win on top (MIN)' {
        Get-SITierFromEntraRoles -Roles @('Role-T1') | Should -Be 0 -Because 'the custom-role entry places it at Tier 0'
    }
    It 'the source is recorded' {
        $script:ClsInfo.CatalogSource | Should -Be 'ai'
        $script:ClsInfo.Label | Should -Match 'built here with AI on 2026-11-11 \(an entry it does not list: the shipped catalog dated 2026-05-03'
    }
    It 'Merge-SIClassifiedBuiltIns changes neither input and counts the classified entries' {
        $s = Get-Content -LiteralPath $script:ClsShipped -Raw | ConvertFrom-Json
        $c = Get-Content -LiteralPath $script:ClsCustom -Raw | ConvertFrom-Json
        $r = Merge-SIClassifiedBuiltIns -Base $s -Classified $c
        $r.Entries | Should -Be 5
        @($r.Catalog.EntraID_BuiltInRoles_Tier3 | ForEach-Object DisplayName) | Should -Be @('Role-T0')
        @($s.EntraID_BuiltInRoles_Tier3 | ForEach-Object DisplayName) | Should -Be @('Role-T3')
        (Merge-SIClassifiedBuiltIns -Base $s -Classified $null).Entries | Should -Be 0
    }
}

Describe 'the classifier: built-in items take the downloaded tier; custom roles are tiered here' {
    BeforeAll { $script:Maps = Get-PTCDownloadedTierMaps -Catalog (New-CatalogObject) }
    It 'the maps hold the built-in sections by the consumer''s keys, never a custom-role section' {
        $script:Maps.EntraRoles.ContainsKey('fresh role') | Should -BeTrue -Because 'case-insensitive'
        $script:Maps.EntraRoles.ContainsKey('Download Custom Role') | Should -BeFalse
        $script:Maps.APIPerms['Perm.T2'].Tier | Should -Be 2
        $script:Maps.ADGroups['ADG-T0'].Tier | Should -Be 0
        $script:Maps.AzureRoles['AzRole-T3'].Tier | Should -Be 3
    }
    It 'a built-in item gets the downloaded tier over the AI''s; a custom role and an unlisted item are left as they were' {
        $tiered = @{
            ADGroups   = @([pscustomobject]@{ Name = 'ADG-T0'; Tier = 3; Reason = 'ai' })
            EntraRoles = @([pscustomobject]@{ DisplayName = 'Moved Role'; IsBuiltIn = $true; Tier = 3; Reason = 'ai' },
                           [pscustomobject]@{ DisplayName = 'Role-T1'; IsBuiltIn = $false; Tier = 2; Reason = 'tenant custom of the same name' },
                           [pscustomobject]@{ DisplayName = 'Unlisted Role'; IsBuiltIn = $true; Tier = 99; Reason = 'open' })
            APIPerms   = @([pscustomobject]@{ Value = 'Perm.T1'; Tier = 99; Reason = 'open' })
            AzureRoles = @([pscustomobject]@{ Name = 'AzRole-T0'; IsCustom = $false; Tier = 2; Reason = 'ai' },
                           [pscustomobject]@{ Name = 'AzRole-T1'; IsCustom = $true; Tier = 3; Reason = 'custom' })
        }
        Set-PTCTiersFromDownloaded -Tiered $tiered -Maps $script:Maps | Should -Be 4
        $tiered.ADGroups[0].Tier | Should -Be 0
        $tiered.EntraRoles[0].Tier | Should -Be 1
        $tiered.EntraRoles[0].Reason | Should -Be 're-tiered'
        $tiered.EntraRoles[1].Tier | Should -Be 2 -Because 'a custom role is never touched'
        $tiered.EntraRoles[2].Tier | Should -Be 99 -Because 'not in the download: the previous catalog / AI decide'
        $tiered.APIPerms[0].Tier | Should -Be 1
        $tiered.AzureRoles[0].Tier | Should -Be 0
        $tiered.AzureRoles[1].Tier | Should -Be 3
        Set-PTCTiersFromDownloaded -Tiered $tiered -Maps $null | Should -Be 0
    }
    It 'a new source or a new downloaded version rebuilds at once; the same one does not' {
        $cat = [pscustomobject]@{ Source = 'invardia'; Version = '2026.11.10' }
        Test-PTCCatalogSourceMoved -Prior ([pscustomobject]@{ CatalogSource = 'invardia'; CatalogVersion = '2026.11.10' }) -Catalog $cat | Should -BeFalse
        Test-PTCCatalogSourceMoved -Prior ([pscustomobject]@{ CatalogSource = 'invardia'; CatalogVersion = '2026.11.09' }) -Catalog $cat | Should -BeTrue
        Test-PTCCatalogSourceMoved -Prior ([pscustomobject]@{ CatalogSource = 'ai'; CatalogVersion = '' }) -Catalog $cat | Should -BeTrue
        Test-PTCCatalogSourceMoved -Prior ([pscustomobject]@{ CatalogSource = ''; CatalogVersion = '' }) -Catalog $cat | Should -BeTrue -Because 'a catalog from before records no source: rebuilt once'
        Test-PTCCatalogSourceMoved -Prior ([pscustomobject]@{ CatalogSource = 'ai'; CatalogVersion = '' }) -Catalog ([pscustomobject]@{ Source = 'ai'; Version = '' }) | Should -BeFalse
    }
    It 'the fingerprint changes with the source and the downloaded version, and is unchanged without one' {
        $base = @{ EntraRoles = @([pscustomobject]@{ Id = 'r1'; DisplayName = 'Global Administrator'; Description = 'all'; IsBuiltIn = $true; Permissions = @('a') }); ADGroups = @('Domain Admins'); EngineHash = 'h'; RunAI = 'True'; AIDeployment = 'gpt' }
        $a = Get-PTCInputFingerprint @base
        (Get-PTCInputFingerprint @base -CatalogSource '') | Should -Be $a -Because 'a caller that passes none keeps its fingerprint'
        $v1 = Get-PTCInputFingerprint @base -CatalogSource 'invardia:2026.11.10'
        $v1 | Should -Not -Be $a
        (Get-PTCInputFingerprint @base -CatalogSource 'invardia:2026.11.11') | Should -Not -Be $v1
        (Get-PTCInputFingerprint @base -CatalogSource 'ai:') | Should -Not -Be $v1
    }
    It 'the run records the source, the version and the date in one line' {
        Get-PTCCatalogSourceNote -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = '2026.11.10'; BuiltUtc = [datetime]'2026-11-10T02:00:00Z' }) | Should -Be 'privilege tier catalog: downloaded version 2026.11.10 (built 2026-11-10)'
        Get-PTCCatalogSourceNote -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = ''; BuiltUtc = $null }) | Should -Match 'could not be downloaded yet; the shipped catalog is used'
        Get-PTCCatalogSourceNote -Catalog ([pscustomobject]@{ Source = 'ai'; Version = ''; BuiltUtc = $null }) | Should -Be 'privilege tier catalog: built here with AI'
    }
    It 'the previous catalog''s source and version are read back' {
        $p = Join-Path $TestDrive 'prior.json'
        [IO.File]::WriteAllText($p, (@{ Metadata = @{ GeneratedAtUtc = '2026-11-10T01:00:00Z'; InputFingerprint = 'sha256:x'; Complete = $true; CatalogSource = 'invardia'; CatalogVersion = '2026.11.10' } } | ConvertTo-Json -Depth 4))
        $s = Get-PTCCatalogState -Path $p
        $s.CatalogSource | Should -Be 'invardia'
        $s.CatalogVersion | Should -Be '2026.11.10'
    }
}

Describe 'the downloaded copy is shared through storage under its own name (a container keeps its last good copy)' {
    BeforeAll { . ([IO.Path]::Combine($script:Shared, 'SI-CatalogBlob.ps1')) }
    It 'publish and refresh take -BlobName; without it they still use the custom catalog''s blob' {
        $local = Join-Path $TestDrive 'blob\privilege-tier-catalog.downloaded.custom.json'
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $local) | Out-Null
        [IO.File]::WriteAllBytes($local, (ConvertTo-Bytes (New-CatalogObject)))
        Mock New-SIAzStorageContext { 'ctx' }
        Mock Get-SIAzStorageContainer -RemoveParameterType Context { 'exists' }
        Mock Set-SIAzStorageBlobContent -RemoveParameterType Context { }
        Publish-SICatalogToBlob -LocalPath $local -AccountName 'acct' -BlobName 'privilege-tier-catalog.downloaded.custom.json' | Should -BeTrue
        Should -Invoke Set-SIAzStorageBlobContent -Times 1 -Exactly -ParameterFilter { $Container -eq 'sicatalog' -and $Blob -eq 'privilege-tier-catalog.downloaded.custom.json' }
        Publish-SICatalogToBlob -LocalPath $local -AccountName 'acct' | Should -BeTrue
        Should -Invoke Set-SIAzStorageBlobContent -Times 1 -Exactly -ParameterFilter { $Blob -eq 'privilege-tier-catalog.custom.json' }
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { $null }
        Update-SICatalogFromBlob -LocalPath $local -AccountName 'acct' -BlobName 'privilege-tier-catalog.downloaded.custom.json' | Should -Be 'local'
        Should -Invoke Get-SIAzStorageBlob -Times 1 -Exactly -ParameterFilter { $Blob -eq 'privilege-tier-catalog.downloaded.custom.json' }
    }
}

Describe 'wiring (the classifier source)' {
    It 'the source is resolved and the download refreshed BEFORE the age checks, and a moved source skips the 24h skip' {
        $iSource = $script:EngineSrc.IndexOf('$script:PtcCatalog = Invoke-PTCCatalogSource')
        $iAge = $script:EngineSrc.IndexOf('if (-not $_forceRebuild -and -not $_sourceMoved -and (Test-Path -LiteralPath $OutputFile))')
        $iSource | Should -BeGreaterThan 0
        $iAge | Should -BeGreaterThan $iSource
    }
    It 'built-in items it knows are not sent to the AI, take the downloaded tier, and the export records the source' {
        $script:EngineSrc | Should -Match '-Known\s+\$script:PtcCatalog\.Maps'
        $script:EngineSrc | Should -Match 'Write-PTCDownloadedTiers -Tiered \$tiered -Catalog \$script:PtcCatalog'
        $script:EngineSrc | Should -Match 'Set-PTCTiersFromDownloaded -Tiered \$Tiered -Maps \$Catalog\.Maps'
        $script:EngineSrc | Should -Match '-CatalogSource\s+\(\[string\]\$script:PtcCatalog\.Source\)'
        $script:EngineSrc | Should -Match "-CatalogSource \('\{0\}:\{1\}' -f \`$script:PtcCatalog\.Source, \`$script:PtcCatalog\.Version\)"
        $script:EngineSrc | Should -Match '\$_phRH_Err = \$script:PtcCatalog\.Note'
    }
    It 'the download is shared through the storage account under its own name, like the custom catalog' {
        $script:EngineSrc | Should -Match 'Publish-SICatalogToBlob -LocalPath \$DownloadPath -BlobName \$script:SITierCatalogFileName'
        $script:EngineSrc | Should -Match 'Update-SICatalogFromBlob -LocalPath \$DownloadPath -BlobName \$script:SITierCatalogFileName'
        $script:SITierCatalogFileName | Should -Match '\.custom\.json$' -Because 'the gitignore / dockerignore keep *.custom.json out of the repository and the image'
    }
}

Describe 'the classifier never fails a night (owner 2026-11-11)' {
    BeforeAll { . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Pipeline.ps1')) }
    It 'first run, the download failed and no catalog of its own: the step is skipped with one plain line' {
        $s = Get-PTCFirstRunSkip -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = '' }) -HaveOwnCatalog $false
        $s.Skip | Should -BeTrue
        $s.Line | Should -Match 'step is skipped -- the collections use the catalog shipped with SecurityInsight, and the next run tries again'
        (Get-PTCFirstRunSkip -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = '' }) -HaveOwnCatalog $true).Skip | Should -BeFalse -Because 'a normal run keeps its last known classification'
        (Get-PTCFirstRunSkip -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = '2026.11.10' }) -HaveOwnCatalog $false).Skip | Should -BeFalse
        (Get-PTCFirstRunSkip -Catalog ([pscustomobject]@{ Source = 'ai'; Version = '' }) -HaveOwnCatalog $false).Skip | Should -BeFalse -Because 'AI builds it'
    }
    It 'a failed rebuild on a normal run ends OK on the last known classification -- its date, version and age said; with none it is skipped' {
        $prior = [pscustomobject]@{ GeneratedUtc = [datetime]'2026-11-08T01:00:00Z'; CatalogVersion = '2026.11.07'; CatalogSource = 'invardia' }
        $k = Get-PTCFailureOutcome -ErrorText 'Graph 503' -Prior $prior -NowUtc $script:Now
        $k.ExitReason | Should -Be 'success'
        $k.Line | Should -Match 'could not be rebuilt \(Graph 503\)\. The last known classification is kept: built 2026-11-08 \(the daily catalog version 2026\.11\.07\), 3 days old'
        $n = Get-PTCFailureOutcome -ErrorText 'no sign-in' -Prior $null -NowUtc $script:Now
        $n.ExitReason | Should -Be 'skipped'
        $n.Line | Should -Match 'step is skipped'
    }
    It 'WIRING -- the engine: no AI request with the download, the first-run skip before any rebuild, and a failure never rethrown' {
        $script:EngineSrc | Should -Match '\$script:PtcNoAI = \(\$script:PtcCatalog\.Source -ne ''ai''\)'
        $script:EngineSrc | Should -Match 'if \(\$script:PtcNoAI\) \{'
        $script:EngineSrc | Should -Match '\$_phRH_Exit = ''skipped''; \$_phRH_Err = \$_skip\.Line'
        $script:EngineSrc | Should -Match '\$kept = Get-PTCFailureOutcome'
        $eng = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
        $main = $eng.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Main' }, $true)[0].Extent.Text
        $script:EngineSrc | Should -Not -Match '(?m)^\s*if \(\$script:PtcSkipped\) \{ exit' -Because 'a skipped run ends its execution successfully: the runner reads the skip from the step''s run log'
        $main | Should -Not -Match '(?m)^\s*throw\s*$' -Because 'the classifier never fails the run'
    }
    It 'the runner: a failed / timed-out / ended-at-its-limit classifier step is SKIPPED, never failed; a stop on purpose stays; any other step is untouched' {
        foreach ($state in 'Failed', 'TimedOut') {
            $st = [pscustomobject]@{ Job = 'ptc'; State = $state; ErrorClass = 'job-failed'; Error = 'the execution ended failed' }
            (Set-SIPipelineClassifierSkipped -Step $st) | Should -Match 'never failed'
            $st.State | Should -Be 'Skipped'; $st.ErrorClass | Should -Be 'classifier-skipped'
            $st.Error | Should -Match '\(the execution ended failed\)'
        }
        $stop = [pscustomobject]@{ Job = 'caj-si-ptc'; State = 'Interrupted'; ErrorClass = 'stopped'; Error = 'x' }
        (Set-SIPipelineClassifierSkipped -Step $stop) | Should -BeNullOrEmpty
        $stop.State | Should -Be 'Interrupted'
        $other = [pscustomobject]@{ Job = 'identity'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'x' }
        (Set-SIPipelineClassifierSkipped -Step $other) | Should -BeNullOrEmpty
        $other.State | Should -Be 'Failed'
        $ok = [pscustomobject]@{ Job = 'ptc'; State = 'Success'; ErrorClass = ''; Error = '' }
        (Set-SIPipelineClassifierSkipped -Step $ok) | Should -BeNullOrEmpty
        (Set-SIPipelineClassifierSkipped -Step $ok -EndReason 'skipped') | Should -Match 'could not be downloaded'
        $sk = [pscustomobject]@{ Job = 'ptc'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'the execution ended failed' }
        (Set-SIPipelineClassifierSkipped -Step $sk -EndReason 'skipped') | Should -Match '^the tier classifier skipped this run: there is no tier catalog of this install''s own yet'
        $sk.State | Should -Be 'Skipped'
        Test-SIPipelineClassifierSkipLog -Lines @('[2026-11-11 01:00:05] [WARN] The daily classified tier catalog could not be downloaded, and this install has no tier catalog of its own yet: the step is skipped -- the collections use the catalog shipped with SecurityInsight, and the next run tries again.') | Should -BeTrue
        Test-SIPipelineClassifierSkipLog -Lines @('[INFO] catalog built', '[WARN] the last known classification is kept') | Should -BeFalse
        Test-SIPipelineClassifierSkipLog -Lines @() | Should -BeFalse
        # the engine's own skip sentences are the ones the runner reads
        (Get-PTCFirstRunSkip -Catalog ([pscustomobject]@{ Source = 'invardia'; Version = '' }) -HaveOwnCatalog $false).Line | ForEach-Object { Test-SIPipelineClassifierSkipLog -Lines @($_) } | Should -BeTrue
        (Get-PTCFailureOutcome -ErrorText 'x' -Prior $null).Line | ForEach-Object { Test-SIPipelineClassifierSkipLog -Lines @($_) } | Should -BeTrue
        $ok.State | Should -Be 'Skipped'
    }
    It 'the stage and the Collect verdict count a skipped classifier as fine' {
        $st = { param([hashtable]$s) [pscustomobject]@{ Steps = @($s.Keys | ForEach-Object { [pscustomobject]@{ Job = $_; Stage = 'collect'; State = $s[$_][0]; ErrorClass = $s[$_][1] } }) } }
        Get-SIPipelineStageOutcome -State (& $st @{ ptc = @('Skipped', 'classifier-skipped'); identity = @('Success', '') }) -Stage 'collect' | Should -Be 'Succeeded'
        Get-SIPipelineStageOutcome -State (& $st @{ ptc = @('Skipped', 'needs-failed'); identity = @('Success', '') }) -Stage 'collect' | Should -Be 'Failed'
        Get-SIPipelineStageOutcome -State (& $st @{ ptc = @('Success', ''); identity = @('Failed', 'job-failed') }) -Stage 'collect' | Should -Be 'Failed' -Because 'any other step is judged as before'
    }
    It 'the start record query tells a skipped END apart (EndOther leaves it out)' {
        $jf = [System.Management.Automation.Language.Parser]::ParseFile([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'), [ref]$null, [ref]$null)
        . ([scriptblock]::Create($jf.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SIJobFlowStartRecordQuery' }, $true)[0].Extent.Text))
        $q = Get-SIJobFlowStartRecordQuery -Execution 'caj-si-ptc-e1' -StartedUtc ([datetime]'2026-11-11T01:00:00Z') -Engine 'privilege-tier-classifier'
        $q | Should -Match "Skipped = countif\(.*tostring\(ExitReason\) == 'skipped'\)"
        $q | Should -Match "!in \('throttled', 'success', 'skipped'\)"
    }
}