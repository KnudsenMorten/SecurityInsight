#Requires -Version 5.1
<#
    SecurityInsight v3 runs with NO PowerShell modules (REQUIREMENTS #305) -- the SETUP half of the guard.

    Every setup / install / bootstrap / wizard / validate / grant script -- setup\** (incl. ConfigWizard\backend and
    _shared), and the solution-root Bootstrap-*.ps1 and Setup-*.ps1 -- must run on native REST, ARM and .NET only:
      * no #Requires -Modules
      * no module load or install of ANY module (#524, owner 2026-10-09 "we dont do ps modules"): no Import-Module / ipmo
        (a literal name, a computed path such as the framework's FUNCTIONS\AutomateITPS\AutomateITPS.psd1, or SI's own),
        no `using module`, no dot-sourcing of a .psm1, no Install-/Update-/Save-/Find-Module or *-PSResource, no
        Add-Type -Path / a .dll, no [Reflection.Assembly]::LoadFrom; Get-Module only as the test probe `-Name Pester`
      * no call to the platform framework module's sign-in (Connect-Platform, Initialize-PlatformAutomationFramework ...)
        nor to SI's runtime port of it (Connect-SIPlatform): the setup flavour that used them is retired (#524, owner
        2026-10-09 "we dont use that legacy code"); setup signs in through SI's own REST client only
      * no call to an Az / Microsoft Graph SDK cmdlet (Verb-Az* / Verb-Mg*), directly or as a command NAME in a string
        handed to a seam ('Get-AzContext' through & $Command)
      * no customer advice to install a module or to run Connect-AzAccount / Connect-MgGraph -- in the scripts and in
        the wizard's own page and script
      * nothing loads the retired module helpers (Ensure-Module.ps1, Ensure-SecurityInsightModules)
    Comments may still mention the old cmdlets (history); code and strings may not.

    The runtime half (engines, launchers, container) is SIv3-NoPsModules.Tests.ps1.
#>

BeforeDiscovery {
    $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $files = @()
    $files += @(Get-ChildItem -LiteralPath $root -File -Filter 'Bootstrap-*.ps1')
    $files += @(Get-ChildItem -LiteralPath $root -File -Filter 'Setup-*.ps1')
    # filter on .Extension: Windows PowerShell 5.1 ignores -Include together with -LiteralPath
    $files += @(Get-ChildItem -LiteralPath (Join-Path $root 'setup') -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' })
    $script:SetupScripts = @($files | Sort-Object FullName -Unique | ForEach-Object {
        @{ Rel = $_.FullName.Substring($root.Length + 1); Path = $_.FullName }
    })
    $script:WizardPages = @(Get-ChildItem -LiteralPath (Join-Path $root 'setup\ConfigWizard') -File -Recurse | Where-Object { $_.Extension -in '.html', '.js' } | ForEach-Object {
        @{ Rel = $_.FullName.Substring($root.Length + 1); Path = $_.FullName }
    })
}

BeforeAll {
    $script:ModuleNames = '^(Az(\..+)?|AzLogDcrIngestPS|Microsoft\.Graph(\..+)?|MicrosoftGraphPS)$'
    # the platform framework module's (FUNCTIONS\AutomateITPS) sign-in commands and SI's runtime port of it -- setup uses
    # neither (#524). Get-PlatformSecret is not listed: SI publishes a compatible REST function of that name, and the
    # generated configuration file still calls it.
    $script:FrameworkCommands = 'Connect-Platform', 'Connect-PlatformBootstrap', 'Connect-PlatformModern', 'Disconnect-Platform',
                                'Initialize-PlatformAutomationFramework', 'Initialize-PlatformIdentity', 'Get-PlatformSecretKeyVault',
                                'New-PlatformContext', 'Get-AutomateITAzureToken', 'Connect-SIPlatform'
    $script:CmdletRx    ='\b(Get|Set|New|Remove|Update|Connect|Disconnect|Invoke|Register|Unregister|Search|Test|Add|Start|Stop|Enable|Disable|Clear|Select|Save|Import|Export|Grant|Revoke|Restore|Backup|Resolve|Move|Rename|Reset|Publish|Find|Use|Wait)-(Az|Mg)[A-Z][A-Za-z]+\b'

    function script:Get-SINoModuleFindings {
        param([string]$Path)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $out = New-Object System.Collections.Generic.List[string]
        if ($ast.ScriptRequirements -and @($ast.ScriptRequirements.RequiredModules).Count) {
            $out.Add(('#Requires -Modules {0}' -f (@($ast.ScriptRequirements.RequiredModules | ForEach-Object { $_.Name }) -join ', ')))
        }
        # `using module X` (#524)
        foreach ($sb in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockAst] }, $true)) + @($ast)) {
            foreach ($u in @($sb.UsingStatements)) {
                if ($u -and [string]$u.UsingStatementKind -eq 'Module') { $out.Add(('line {0}: using module {1}' -f $u.Extent.StartLineNumber, $u.Name)) }
            }
        }
        # [Reflection.Assembly]::LoadFrom / LoadFile / UnsafeLoadFrom (#524)
        foreach ($m in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and ([string]$n.Member.Value) -in 'LoadFrom', 'LoadFile', 'UnsafeLoadFrom' }, $true))) {
            $out.Add(('line {0}: loads an assembly {1}' -f $m.Extent.StartLineNumber, $m.Extent.Text))
        }
        foreach ($c in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) {
            $line = $c.Extent.StartLineNumber
            $first = if ($c.CommandElements.Count) { $c.CommandElements[0].Extent.Text } else { '' }
            if ($first -match '(?i)\.psm1\b') { $out.Add(('line {0}: loads {1}' -f $line, $first)); continue }   # . ./x.psm1 / & x.psm1
            $name = $c.GetCommandName()
            if (-not $name) { continue }
            $argText = @($c.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join ' '
            if ($name -match $script:CmdletRx) { $out.Add(('line {0}: calls {1}' -f $line, $name)); continue }
            if ($name -match '^(Install-Module|Install-PSResource|Update-Module|Update-PSResource|Save-Module|Save-PSResource|Find-Module|Find-PSResource|Get-InstalledModule|Remove-Module|rmo)$') { $out.Add(('line {0}: {1}' -f $line, $name)); continue }
            # #524: ANY Import-Module, whatever it names -- a literal, a computed path (Join-Path ... AutomateITPS.psd1), SI's own
            if ($name -match '^(Import-Module|ipmo)$') { $out.Add(('line {0}: {1} {2}' -f $line, $name, $argText)); continue }
            # Get-Module: only the bare test-session probe `Get-Module -Name Pester` (never -ListAvailable gating)
            if ($name -match '^(Get-Module|gmo)$') {
                if ($argText -notmatch '^(?i)(-Name\s+)?[''"]?Pester[''"]?$') { $out.Add(('line {0}: {1} {2}' -f $line, $name, $argText)) }
                continue
            }
            if ($name -eq 'Add-Type' -and $argText -match '(?i)(^|\s)-(Path|LiteralPath)\b|\.dll\b') { $out.Add(('line {0}: Add-Type {1}' -f $line, $argText)); continue }
            if ($script:FrameworkCommands -contains $name) { $out.Add(('line {0}: calls the framework module''s {1}' -f $line, $name)); continue }
            if ($name -match '^(Ensure-Module|Ensure-SecurityInsightModules)$') { $out.Add(('line {0}: {1}' -f $line, $name)) }
        }
        foreach ($s in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))) {
            $v = [string]$s.Value
            if ($v -match $script:CmdletRx) { $out.Add(('line {0}: names {1} in a string' -f $s.Extent.StartLineNumber, $Matches[0])) }
            elseif ($v -match 'Install-Module|Ensure-Module\.ps1|Ensure-SecurityInsightModules') { $out.Add(('line {0}: string mentions {1}' -f $s.Extent.StartLineNumber, $Matches[0])) }
        }
        return @($out | Select-Object -Unique)
    }
}

Describe 'Setup runs with no PowerShell modules (#305)' {

    It '<Rel> loads, requires and calls no Az / Microsoft Graph module' -ForEach $script:SetupScripts {
        $f = @(Get-SINoModuleFindings -Path $Path)
        ($f -join "`n") | Should -BeNullOrEmpty -Because 'setup must run on native REST, ARM and .NET only'
    }

    It 'the wizard page <Rel> tells nobody to install a module or to run Connect-AzAccount' -ForEach $script:WizardPages {
        $t = [IO.File]::ReadAllText($Path)
        $bad = @([regex]::Matches($t, ('Install-Module|' + $script:CmdletRx)) | ForEach-Object { $_.Value } | Select-Object -Unique)
        ($bad -join ', ') | Should -BeNullOrEmpty
    }

    It '<Rel> reads none of the retired platform globals (AutomationFramework, HighPriv_*, KV_HighPriv_*) (#524)' -ForEach $script:SetupScripts {
        # owner 2026-10-09: "we dont use that legacy code" -- the AutomateIT platform module's sign-in fed these; setup has
        # one sign-in (SI's own REST client). Comments and strings may still name them (history, messages).
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $vars = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and
                                 $n.VariablePath.UserPath -match '^(?i)(global:)?(AutomationFramework|HighPriv_.*|KV_HighPriv_.*)$' }, $true) |
                  ForEach-Object { 'line {0}: {1}' -f $_.Extent.StartLineNumber, $_.Extent.Text } | Select-Object -Unique)
        ($vars -join "`n") | Should -BeNullOrEmpty
    }

    It 'the retired module helpers are gone from setup' {
        $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        foreach ($rel in 'setup\_shared\Ensure-Module.ps1', 'setup\_shared\Ensure-SecurityInsightInfra.ps1', 'setup\_shared\Send-SecurityInsightExportFile.ps1') {
            Test-Path -LiteralPath (Join-Path $root $rel) | Should -BeFalse -Because "$rel is not used by setup"
        }
    }

    It 'the guard itself catches what it must (negative check)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-nomod-guard-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        try {
            Set-Content -LiteralPath $tmp -Encoding UTF8 -Value @(
                '#Requires -Modules Az.Accounts'
                '# Get-AzContext in a comment is fine'
                'Import-Module AzLogDcrIngestPS'
                '$c = Get-AzContext'
                '& $seam ''New-AzRoleAssignment'' @{}'
                'Write-Host "Run Install-Module Az first"'
                'Connect-MgGraph -Scopes x'
                '$ok = Get-SIAzContext'
                'Import-Module (Join-Path $r ''FUNCTIONS\AutomateITPS\AutomateITPS.psd1'') -Global -Force'
                '$null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets'
                'ipmo ./setup/Install-SecurityInsight.psd1'
                'if (Get-Module -ListAvailable -Name Az.Accounts) { }'
                '. (Join-Path $PSScriptRoot ''Helper.psm1'')'
                'Add-Type -Path ./Microsoft.Identity.Client.dll'
                '[Reflection.Assembly]::LoadFrom(''x.dll'')'
                'if (Get-Module -Name Pester) { }'
                'Add-Type -AssemblyName System.Net.Http'
                '$null = Connect-SIPlatform'
            )
            $f = @(Get-SINoModuleFindings -Path $tmp)
            ($f -join "`n") | Should -Match 'line 9: Import-Module \(Join-Path'
            ($f -join "`n") | Should -Match 'line 10: calls the framework module''s Initialize-PlatformAutomationFramework'
            ($f -join "`n") | Should -Match 'line 11: ipmo'
            ($f -join "`n") | Should -Match 'line 12: Get-Module -ListAvailable'
            ($f -join "`n") | Should -Match 'line 13: loads'
            ($f -join "`n") | Should -Match 'line 14: Add-Type'
            ($f -join "`n") | Should -Match 'line 15: loads an assembly'
            ($f -join "`n") | Should -Match 'line 18: calls the framework module''s Connect-SIPlatform'
            ($f -join "`n") | Should -Not -Match 'line 1[67]:' -Because 'the Pester probe and a .NET assembly by name are no module'
            ($f -join "`n") | Should -Match '#Requires -Modules Az.Accounts'
            ($f -join "`n") | Should -Match 'Import-Module AzLogDcrIngestPS'
            ($f -join "`n") | Should -Match 'calls Get-AzContext'
            ($f -join "`n") | Should -Match 'names New-AzRoleAssignment in a string'
            ($f -join "`n") | Should -Match 'Install-Module'
            ($f -join "`n") | Should -Match 'calls Connect-MgGraph'
            ($f -join "`n") | Should -Not -Match 'SIAz'
            ($f -join "`n") | Should -Not -Match 'line 2:'
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
