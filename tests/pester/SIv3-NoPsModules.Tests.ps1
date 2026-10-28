#Requires -Version 5.1
<#
    SECURITYINSIGHT RUNS WITH NO POWERSHELL MODULES (#305) -- native REST, ARM and .NET only.

    A guard over every shipped RUNTIME script: engine/**, launcher/**, container/**, auth/**. (setup/**, diagnostics/**
    and tests/** are not runtime and are guarded by their own lanes.) It fails on:
      * ANY module load or install, whatever the module (#524, owner 2026-10-09 "we dont do ps modules"): Import-Module /
        ipmo, `using module`, dot-sourcing or invoking a .psm1, Install-Module / Update-Module / Save-Module /
        Find-Module / *-PSResource / Get-InstalledModule / Remove-Module, Add-Type -Path / -LiteralPath or a .dll, and
        [Reflection.Assembly]::LoadFrom / LoadFile;
      * Get-Module, except the bare test probe `Get-Module -Name Pester` (never -ListAvailable: that is module gating);
      * #Requires -Modules naming ANY module;
      * a call to a command from those modules: any Az cmdlet (verb-noun with an 'Az' noun prefix, case-sensitive, so
        SecurityInsight's own *-SIAz* wrappers and *-Azure* names are not matched), the AzLogDcrIngestPS functions, the
        Microsoft Graph SDK cmdlets and the platform framework's sign-in / secret functions;
      * a FUNCTION DEFINED with the exact name of one of those commands (a shim would hide the dependency);
    and on a container Dockerfile that installs a PowerShell module.
    A function SecurityInsight defines itself whose name merely looks like an Az cmdlet (Connect-AzWithSPN,
    Set-AzContextFromResourceId) is not a module command.

    OFFLINE. AST only: comments and strings never count; a command name in a string that is INVOKED (& 'Get-AzX') does.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RuntimeDirs = 'engine', 'launcher', 'container', 'auth'

    $script:ModuleRx = '(?i)^(Az(\..+)?|AzLogDcrIngestPS|MicrosoftGraphPS|Microsoft\.Graph(\..+)?|AutomateITPS)$'
    $script:ModuleTextRx = '(?i)(\bAz\.[A-Za-z]+|\bAzLogDcrIngestPS\b|\bMicrosoftGraphPS\b|\bMicrosoft\.Graph\b|\bAutomateITPS\b)'
    $script:ModuleVerbs = 'Import-Module', 'Install-Module', 'Update-Module', 'Save-Module', 'Find-Module', 'Install-PSResource', 'Update-PSResource', 'Save-PSResource', 'Find-PSResource', 'Get-Module', 'Get-InstalledModule', 'Remove-Module'
    $script:InstallVerbs = 'Install-Module', 'Update-Module', 'Save-Module', 'Install-PSResource', 'Update-PSResource', 'Save-PSResource'
    # #524: these are a module use WHATEVER they name (the runtime loads, installs and probes no module at all)
    $script:AnyModuleVerbs = @($script:InstallVerbs) + @('Import-Module', 'ipmo', 'Find-Module', 'Find-PSResource', 'Get-InstalledModule', 'Get-InstalledPSResource', 'Remove-Module', 'rmo')

    # the commands of the modules SecurityInsight no longer uses that are NOT caught by the Az verb-noun rule
    $script:NamedCommands = @(
        # AzLogDcrIngestPS
        'CheckCreateUpdate-TableDcr-Structure', 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output', 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce',
        'Add-CollectionTimeToAllEntriesInArray', 'Add-ColumnDataToAllEntriesInArray', 'ValidateFix-AzLogAnalyticsTableSchemaColumnNames',
        'Build-DataArrayToAlignWithSchema', 'Get-ObjectSchemaAsArray', 'Get-ObjectSchemaAsHash', 'Convert-PSArrayToObjectFixStructure',
        'CreateUpdate-AzLogAnalyticsCustomLogTableDcr', 'CreateUpdate-AzDataCollectionRuleLogIngestCustomLog',
        'Get-AzLogAnalyticsTableAzDataCollectionRuleStatus', 'Get-AzDceListAll', 'Get-AzDcrListAll', 'Get-AzDcrDceDetails',
        'Get-AzAccessTokenManagement', 'Get-AzTokenForResource', 'Delete-AzDataCollectionRules', 'Delete-AzLogAnalyticsCustomLogTables',
        # Microsoft Graph SDK / MicrosoftGraphPS
        'Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest', 'Select-MgProfile', 'Get-MgUser', 'Get-MgGroup',
        'Get-MgServicePrincipal', 'Get-MgApplication', 'Get-MgDirectoryRole', 'Get-MgRoleManagementDirectoryRoleDefinition',
        'Get-MgRoleManagementDirectoryRoleAssignment', 'Get-MgDevice', 'Invoke-MgGraphRequestPS',
        # the platform framework's module (AutomateITPS)
        'Connect-Platform', 'Connect-PlatformBootstrap', 'Connect-PlatformModern', 'Initialize-PlatformAutomationFramework',
        'Get-PlatformSecret', 'Get-PlatformSecretKeyVault', 'New-PlatformContext', 'Get-AutomateITAzureToken',
        # the old per-engine module installer
        'Ensure-SecurityInsightModules', 'Ensure-Module',
        # #524: the Az session commands are flagged even when a runtime file defines a function of that name (a shim
        # would hide the dependency, and the Own rule below would otherwise excuse the call)
        'Get-AzContext', 'Set-AzContext', 'Get-AzAccessToken', 'Connect-AzAccount', 'Disconnect-AzAccount', 'Get-AzSubscription', 'Invoke-AzRestMethod'
    )

    $script:Files = @(foreach ($d in $script:RuntimeDirs) {
        $p = Join-Path $script:SIRoot $d
        if (Test-Path -LiteralPath $p) { Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } }
    })

    # functions SecurityInsight defines itself anywhere in the runtime (Connect-AzWithSPN, Set-AzContextFromResourceId...)
    $script:Own = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $script:Asts = @{}
    foreach ($f in $script:Files) {
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
        $script:Asts[$f.FullName] = $ast
        foreach ($fd in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            [void]$script:Own.Add(($fd.Name -replace '^(global|script|local):', ''))
        }
    }

    function script:Test-SIModuleCommandName {
        <# PURE. Is -Name a command of a module SecurityInsight must not use? #>
        param([string]$Name, [System.Collections.Generic.HashSet[string]]$Own)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
        $n = $Name -replace '^.*\\', ''   # Module\Command
        if ($script:NamedCommands -contains $n) { return $true }
        if ($n -cmatch '^[A-Za-z]+-Az[A-Z][A-Za-z0-9]*$' -and $n -cnotmatch '-SIAz') {
            if ($Own -and $Own.Contains($n)) { return $false }
            return $true
        }
        if ($n -cmatch '^[A-Za-z]+-Mg[A-Z][A-Za-z0-9]*$' -and -not ($Own -and $Own.Contains($n))) { return $true }
        return $false
    }

    function script:Find-SIModuleUse {
        <# Every module use in one parsed script: '<line> <what>'. -Own: functions defined in the runtime. #>
        param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast, [System.Collections.Generic.HashSet[string]]$Own)
        $hits = New-Object System.Collections.Generic.List[string]
        if ($Ast -is [System.Management.Automation.Language.ScriptBlockAst] -and $Ast.ScriptRequirements) {
            foreach ($m in @($Ast.ScriptRequirements.RequiredModules)) { [void]$hits.Add(('{0} #Requires -Modules {1}' -f 1, $m.Name)) }
        }
        # `using module X` (#524)
        foreach ($sb in @($Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ScriptBlockAst] }, $true)) + @($Ast)) {
            foreach ($u in @($sb.UsingStatements)) {
                if ($u -and [string]$u.UsingStatementKind -eq 'Module') { [void]$hits.Add(('{0} using module {1}' -f $u.Extent.StartLineNumber, $u.Name)) }
            }
        }
        # [Reflection.Assembly]::LoadFrom / LoadFile / UnsafeLoadFrom -- a module's assembly loaded by hand (#524)
        foreach ($m in $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $args[0].Static -and
                                     ([string]$args[0].Member.Value) -in 'LoadFrom', 'LoadFile', 'UnsafeLoadFrom' }, $true)) {
            [void]$hits.Add(('{0} {1}' -f $m.Extent.StartLineNumber, $m.Extent.Text))
        }
        foreach ($c in $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $line = $c.Extent.StartLineNumber
            $first = if ($c.CommandElements.Count) { $c.CommandElements[0].Extent.Text } else { '' }
            # dot-sourcing or invoking a module file (. ./x.psm1, & 'x.psm1') loads a module without Import-Module (#524)
            if ($first -match '(?i)\.psm1\b') { [void]$hits.Add(('{0} loads {1}' -f $line, $first)); continue }
            $name = $c.GetCommandName()
            if (-not $name) { continue }
            $argText = @($c.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join ' '
            if ($script:AnyModuleVerbs -contains $name) { [void]$hits.Add(('{0} {1} {2}' -f $line, $name, $argText).TrimEnd()); continue }
            if ($name -in 'Get-Module', 'gmo') {
                # the one allowed shape: the test-session probe `Get-Module -Name Pester` (no -ListAvailable, nothing else)
                if ($argText -notmatch '^(?i)(-Name\s+)?[''"]?Pester[''"]?$') { [void]$hits.Add(('{0} {1} {2}' -f $line, $name, $argText).TrimEnd()) }
                continue
            }
            # Add-Type -AssemblyName <a .NET assembly> is .NET, not a module; a file (-Path / -LiteralPath, a .dll) is not
            if ($name -eq 'Add-Type' -and $argText -match '(?i)(^|\s)-(Path|LiteralPath)\b|\.dll\b') { [void]$hits.Add(('{0} Add-Type {1}' -f $line, $argText)); continue }
            if ($script:ModuleVerbs -contains $name) {
                if ($argText -match $script:ModuleTextRx) { [void]$hits.Add(('{0} {1} {2}' -f $line, $name, $argText)) }
                continue
            }
            if (Test-SIModuleCommandName -Name $name -Own $Own) { [void]$hits.Add(('{0} {1}' -f $line, $name)) }
        }
        foreach ($fd in $Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $fn = ($fd.Name -replace '^(global|script|local):', '')
            # a shim with a module command's exact name would hide the dependency -- the one exception is the
            # framework-compatible Get-PlatformSecret the platform sign-in publishes for configuration files
            if ($script:NamedCommands -contains $fn -and $fn -ne 'Get-PlatformSecret') { [void]$hits.Add(('{0} defines {1}' -f $fd.Extent.StartLineNumber, $fn)) }
        }
        return $hits.ToArray()
    }
}

Describe 'SecurityInsight runs with no PowerShell modules (runtime: engine, launcher, container, auth)' {

    It 'scans a real runtime (sanity: the runtime folders hold scripts)' {
        $script:Files.Count | Should -BeGreaterThan 100
        foreach ($d in $script:RuntimeDirs) { @($script:Files | Where-Object { $_.FullName -like ('*\' + $d + '\*') }).Count | Should -BeGreaterThan 0 -Because $d }
    }

    It 'every runtime script parses' {
        $bad = @(foreach ($f in $script:Files) {
            $tok = $null; $err = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            if ($err) { '{0}: {1}' -f $f.FullName.Substring($script:SIRoot.Length + 1), $err[0].Message }
        })
        $bad | Should -BeNullOrEmpty
    }

    It 'no runtime script loads, installs, probes or requires a module, or calls a module command' {
        # NO EXEMPTION (#524): the sign-in mode "AzContext" adapter (engine/_shared/SI-AzSession.ps1) used to call an Az
        # PowerShell session's Get-AzContext / Get-AzAccessToken; that mode and the file are gone (one connect path: SI's own
        # REST token client), and no file is allowed any Az / Graph / framework command.
        # ONE assembly exception, and only for assemblies (never a module, never a module command): the mail PDF (#574)
        # loads the pinned MIT PDF library (engine/_shared/pdf/SI.Pdf.packages.json, DLLs only) and compiles its own
        # builder source -- in engine\_shared\SI-MailPdf.ps1 and nowhere else. The next It pins what that file may load.
        $assemblyOnly = @{ 'engine\_shared\SI-MailPdf.ps1' = '(?i)^\d+ (\[Reflection\.Assembly\]::LoadFrom\(\[string\]\$lib\.Files\[\$n\]\)|Add-Type -Path \$src -ReferencedAssemblies \$refs\b.*)$' }
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in $script:Files) {
            $rel = $f.FullName.Substring($script:SIRoot.Length + 1).Replace('/', '\')
            foreach ($h in @(Find-SIModuleUse -Ast $script:Asts[$f.FullName] -Own $script:Own)) {
                if ($assemblyOnly.ContainsKey($rel) -and $h -match $assemblyOnly[$rel]) { continue }
                [void]$hits.Add(('{0}:{1}' -f $rel, $h))
            }
        }
        $hits | Should -BeNullOrEmpty
    }

    It 'the one assembly exception loads only the pinned PDF library and SecurityInsight''s own builder source' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-MailPdf.ps1'))
        # the DLLs come only from Find-SIPdfLibrary (the names in the pinned manifest), the source is SIMailPdf.cs
        $t | Should -Match '\$lib = Find-SIPdfLibrary'
        $t | Should -Match "\`$src = \[IO\.Path\]::Combine\(\`$PSScriptRoot, 'pdf', 'SIMailPdf\.cs'\)"
        $t | Should -Match "Get-Content -Raw -LiteralPath \(\[IO\.Path\]::Combine\(\`$PSScriptRoot, 'pdf', 'SI\.Pdf\.packages\.json'\)\)"
        $t | Should -Not -Match '(?i)\.psd1|\.psm1|Import-Module'
        $m = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\pdf\SI.Pdf.packages.json') | ConvertFrom-Json
        foreach ($p in @($m.packages)) {
            $p.license | Should -Be 'MIT'
            @($p.dlls | Where-Object { $_ -notmatch '^[A-Za-z][A-Za-z0-9.]*\.dll$' -or $_ -match '(?i)^(Az|Microsoft\.Graph|Microsoft\.Identity|AzLogDcrIngestPS)' }) | Should -BeNullOrEmpty
        }
        # and no other runtime file loads an assembly
        $others = @($script:Files | Where-Object { $_.FullName -notlike '*\engine\_shared\SI-MailPdf.ps1' } | Where-Object {
            @($script:Asts[$_.FullName].FindAll({ $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $args[0].Static -and
                ([string]$args[0].Member.Value) -in 'LoadFrom', 'LoadFile', 'UnsafeLoadFrom' }, $true)).Count })
        $others | Should -BeNullOrEmpty
    }

    It 'the container images install no PowerShell module' {
        $docker = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'container') -Recurse -File -Filter 'Dockerfile*')
        $docker.Count | Should -BeGreaterThan 0
        foreach ($d in $docker) {
            $lines = @(Get-Content -LiteralPath $d.FullName | Where-Object { $_ -notmatch '^\s*#' })
            ($lines -join "`n") | Should -Not -Match '(?i)Install-Module|Install-PSResource|Save-Module|PSGallery' -Because $d.FullName
            # the image's own build guard (owner 2026-10-10, SIv3-ImageNoAzNoModules) names the modules it REFUSES and
            # fails the build when one is present -- that line installs nothing, every other line is still checked
            $install = @($lines | Where-Object { $_ -notmatch 'Get-Module -ListAvailable -Name .*exit 1' })
            ($install -join "`n") | Should -Not -Match $script:ModuleTextRx -Because $d.FullName
        }
    }

    It 'the retired module tooling is gone: no engine Ensure-Module copy, no container module sync' {
        @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Filter 'Ensure-Module.ps1').Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'container\Sync-ContainerModules.ps1') | Should -BeFalse
    }

    It 'there is no module switch any more: the Azure and log-ingest paths are REST only' {
        foreach ($f in $script:Files) {
            foreach ($fd in $script:Asts[$f.FullName].FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                $fd.Name | Should -Not -BeIn @('Get-SIAzureAccessMode', 'Test-SIAzureRestMode', 'Test-SIAzCommand', 'Get-SILogIngestEngine') -Because $f.Name
            }
        }
    }
}

Describe 'the guard itself catches what it must (negative proof)' {
    It 'flags <What>' -TestCases @(
        @{ What = 'Import-Module of an Az module';            Code = 'Import-Module Az.Accounts -ErrorAction Stop' }
        @{ What = 'Import-Module of the ingest module';       Code = 'Import-Module -Name AzLogDcrIngestPS -Force' }
        @{ What = 'Import-Module of the framework by path';   Code = 'Import-Module (Join-Path $r ''FUNCTIONS\AutomateITPS\AutomateITPS.psd1'') -Global' }
        @{ What = 'Install-Module of anything';               Code = 'Install-Module Pester -Scope CurrentUser' }
        @{ What = 'a module probe';                           Code = 'if (Get-Module -ListAvailable -Name Az.KeyVault) { }' }
        @{ What = '#Requires -Modules';                       Code = "#Requires -Modules Az.Accounts`nWrite-Output 1" }
        @{ What = 'an Az cmdlet';                             Code = 'Connect-AzAccount -Identity' }
        @{ What = 'an Az cmdlet invoked by name';             Code = '& ''Get-AzKeyVaultSecret'' -VaultName kv -Name n' }
        @{ What = 'a module-qualified Az cmdlet';             Code = 'Az.Accounts\Get-AzContext' }
        @{ What = 'an ingest-module function';                Code = 'CheckCreateUpdate-TableDcr-Structure -Data $d' }
        @{ What = 'a Graph SDK cmdlet';                       Code = 'Connect-MgGraph -Identity' }
        @{ What = 'the framework sign-in';                    Code = 'Connect-Platform -ErrorAction Stop' }
        @{ What = 'the framework secret function';            Code = 'Get-PlatformSecret -Context $c -Name x' }
        @{ What = 'a shim named like a module command';       Code = 'function Get-AzDceListAll { }' }
        # #524
        @{ What = 'Import-Module of ANY module (even SI''s own)'; Code = 'Import-Module ./setup/Install-SecurityInsight.psd1' }
        @{ What = 'ipmo by alias';                            Code = 'ipmo Something' }
        @{ What = 'Import-Module of a computed path';         Code = 'Import-Module (Join-Path $r ''x.psd1'') -Global' }
        @{ What = 'using module';                             Code = "using module Az.Accounts`nWrite-Output 1" }
        @{ What = 'dot-sourcing a .psm1';                     Code = '. (Join-Path $PSScriptRoot ''Helpers.psm1'')' }
        @{ What = 'Get-Module -ListAvailable gating';         Code = 'if (Get-Module -ListAvailable -Name Pester) { }' }
        @{ What = 'Get-Module of anything but Pester';        Code = 'Get-Module -Name Whatever' }
        @{ What = 'Add-Type of a dll';                        Code = 'Add-Type -Path (Join-Path $d ''Microsoft.Identity.Client.dll'')' }
        @{ What = 'an assembly loaded by hand';               Code = '[Reflection.Assembly]::LoadFrom(''x.dll'')' }
        @{ What = '#Requires -Modules of any module';         Code = "#Requires -Modules Pester`nWrite-Output 1" }
        @{ What = 'the framework back-compat sign-in';        Code = 'Initialize-PlatformAutomationFramework -IgnoreMissingSecrets' }
        @{ What = 'an Az session call even with a same-named function'; Code = 'function Get-AzContext { }; Get-AzContext' }
    ) {
        param($What, $Code)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$null, [ref]$null)
        @(Find-SIModuleUse -Ast $ast -Own (New-Object 'System.Collections.Generic.HashSet[string]')).Count | Should -BeGreaterThan 0
    }
    It 'does not flag <What>' -TestCases @(
        @{ What = 'an SI wrapper';                            Code = 'Connect-SIAzAccount -Identity; Search-SIAzGraph -Query q' }
        @{ What = 'an *-Azure* name';                         Code = 'Add-AzureResourceTag -ResourceId x' }
        @{ What = 'a comment or a string';                    Code = "# Import-Module Az.Accounts`n`$x = 'Connect-AzAccount'" }
        @{ What = 'a repo-root marker path';                  Code = 'Test-Path (Join-Path $cur ''FUNCTIONS\AutomateITPS\AutomateITPS.psd1'')' }
        @{ What = 'an SI-defined Az-looking function';        Code = 'function Connect-AzWithSPN { }; Connect-AzWithSPN' }
        @{ What = 'the test-session probe Get-Module -Name Pester'; Code = 'if (Get-Module -Name Pester) { }' }
        @{ What = 'Add-Type of a .NET assembly by name';      Code = 'Add-Type -AssemblyName System.Net.Http' }
        @{ What = 'the SI platform sign-in';                  Code = 'Connect-SIPlatform' }
        @{ What = 'the Invardia support token source (#524)'; Code = 'Get-InvardiaSupportToken -Resource https://management.azure.com' }
    ) {
        param($What, $Code)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$null, [ref]$null)
        $own = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($fd in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$own.Add($fd.Name) }
        @(Find-SIModuleUse -Ast $ast -Own $own) | Should -BeNullOrEmpty
    }
}
