#Requires -Version 5.1
<#
    THE SETUP WIZARD: VALUES STAY VALUES, ONLY ITS OWN PAGE CAN DRIVE IT, AND A RE-RUN BREAKS NOTHING (#141).

      * Write-SICustomConfig pasted every value between single quotes unescaped -- a ' in an SMTP password
        broke every launcher, and  x'; <code>; '  became code in a file launchers dot-source as SYSTEM;
      * /api/apply accepted any POST, so any page open in the operator's browser could drive it;
      * cert mode: a re-run uploaded a new certificate, which REPLACES the app's key list;
      * UI keys the backend never read (dceResourceGroup, storageResourceGroup, MaxSpendPerRun, the
        existing-SPN app id); Secret+Key Vault mode emitted names nothing resolved; consent was judged
        before the MDE/MTP permissions were counted; -SkipPhase1 could never succeed.
    The config writer is RUN for real into TestDrive and its output is checked by AST -- never executed.
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Wiz     = Join-Path $script:SIRoot 'setup\ConfigWizard'
    $script:Writer  = Join-Path $script:Wiz 'backend\Write-SICustomConfig.ps1'
    $script:Server  = Join-Path $script:Wiz 'Start-SetupWizard.ps1'
    $script:NewSpn  = Join-Path $script:Wiz 'backend\New-SISpn.ps1'

    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Server, [ref]$null, [ref]$null)
    $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SIWizardRequestAllowed' }, $true) | Select-Object -First 1
    if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)) }

    # Value of `$global:<Name> = <literal>` in a generated file, read from its AST (not by running it).
    function script:Get-AssignedLiteral($FileAst, [string]$Name) {
        $a = $FileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$global:' + $Name) }, $true) | Select-Object -First 1
        if (-not $a) { return $null }
        $c = $a.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ConstantExpressionAst] }, $true) | Select-Object -First 1
        if ($c) { $c.Value } else { $a.Right.Extent.Text }
    }
    $script:Hostile = "x'; `$global:SI_PWNED = 1; '"
    $script:Curly   = "pa" + [char]0x2019 + "ss; `$global:SI_PWNED = 2; " + [char]0x2018
}

Describe 'Write-SICustomConfig: every value stays a value' {
    BeforeAll {
        $script:Out = Join-Path $TestDrive 'SecurityInsight.custom.ps1'
        $spn   = [pscustomobject]@{ AppId = 'app'; TenantId = 'tid'; ObjectId = 'oid'; CredKind = 'Secret'; CredValue = $script:Hostile; KvName = $null }
        $infra = [pscustomobject]@{ Location = 'westeurope'; SubscriptionId = 'sub'; WorkspaceName = "ws'x"; ResourceGroupName = 'rg'; WorkspaceResourceId = '/x'; DceName = 'dce'; DceIngestionUri = 'https://d'; DcrResourceGroupName = 'rg'; StorageAccountName = 'st'; StorageResourceGroupName = 'rg' }
        $smtp  = @{ Server = 'smtp.example.com'; Port = 587; User = 'u'; Password = $script:Curly; From = 'a@b.c'; MailTo = @("o'brien@example.com") }
        $oai   = @{ Endpoint = 'https://o'; Deployment = 'd'; ApiKey = 'k'; MaxSpendPerRun = 2.5 }
        & $script:Writer -OutputPath $script:Out -Spn $spn -Infra $infra -Smtp $smtp -OpenAi $oai *> $null
        $errs = $null
        $script:FileAst = [System.Management.Automation.Language.Parser]::ParseFile($script:Out, [ref]$null, [ref]$errs)
        $script:ParseErrs = @($errs).Count
        $script:Text = Get-Content -LiteralPath $script:Out -Raw
    }
    It 'the generated file parses' { $script:ParseErrs | Should -Be 0 }
    It 'a hostile secret is stored verbatim, not executed' {
        Get-AssignedLiteral $script:FileAst 'SI_SPN_Secret' | Should -Be $script:Hostile
        Get-AssignedLiteral $script:FileAst 'SMTPPassword'  | Should -Be $script:Curly
        Get-AssignedLiteral $script:FileAst 'SI_WorkspaceName' | Should -Be "ws'x"
    }
    It 'no injected assignment exists anywhere in the file' {
        @($script:FileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$global:SI_PWNED' }, $true)).Count | Should -Be 0
    }
    It 'a recipient list item with a quote survives' {
        $script:Text | Should -Match ([regex]::Escape("'o''brien@example.com'"))
    }
    It 'recipients typed as plain text are written (every one was dropped)' {
        $script:Text | Should -Match '\$global:MailTo\s+=\s+@\('
    }
    It 'the file carries a UTF-8 BOM, so PS 5.1 reads non-ASCII values correctly' {
        $b = [IO.File]::ReadAllBytes($script:Out)
        ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) | Should -BeTrue
        $out2 = Join-Path $TestDrive 'dk.custom.ps1'
        $pw = 'r' + [char]0x00F8 + 'dgr' + [char]0x00F8 + 'd-' + [char]0x00E6 + [char]0x00E5
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Secret'; CredValue = $pw }
        $infra = [pscustomobject]@{ Location = 'l'; SubscriptionId = 's'; WorkspaceName = 'w'; ResourceGroupName = 'r'; WorkspaceResourceId = '/x'; DceName = 'd'; DceIngestionUri = 'u'; DcrResourceGroupName = 'r'; StorageAccountName = 'st'; StorageResourceGroupName = 'r' }
        & $script:Writer -OutputPath $out2 -Spn $spn -Infra $infra *> $null
        $fa = [System.Management.Automation.Language.Parser]::ParseFile($out2, [ref]$null, [ref]$null)
        Get-AssignedLiteral $fa 'SI_SPN_Secret' | Should -Be $pw
    }
    It 'the wizard''s MaxSpendPerRun reaches the file, decimals and all (it became 4)' {
        $script:Text | Should -Match '\$global:MaxAiSpendPerRun\s+=\s+2\.5\b'
    }
}

Describe 'Write-SICustomConfig: Secret + Key Vault mode resolves the secret' {
    It 'names alone are no longer emitted -- the secret is read from the vault on load' {
        $out = Join-Path $TestDrive 'kv.custom.ps1'
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Secret'; CredValue = $null; KvName = 'kv-x'; KvSecretName = 'SI-SPN-Secret' }
        $infra = [pscustomobject]@{ Location = 'l'; SubscriptionId = 's'; WorkspaceName = 'w'; ResourceGroupName = 'r'; WorkspaceResourceId = '/x'; DceName = 'd'; DceIngestionUri = 'u'; DcrResourceGroupName = 'r'; StorageAccountName = 'st'; StorageResourceGroupName = 'r' }
        & $script:Writer -OutputPath $out -Spn $spn -Infra $infra *> $null
        $t = Get-Content -LiteralPath $out -Raw
        $t | Should -Match 'Get-SIKvSecret -VaultName \$global:SI_KeyVaultName -SecretName \$global:SI_SPN_KvSecretName'
        $t | Should -Match '\$global:SpnKeyVaultName\s+=\s+\$global:SI_KeyVaultName'
    }
}

Describe 'only the wizard''s own page can call /api/*' {
    It 'its own page is allowed (GET, and POST as application/json)' {
        Test-SIWizardRequestAllowed -HostHeader 'localhost:7777' -Origin $null -Method GET -ContentType $null -Port 7777 | Should -BeNullOrEmpty
        Test-SIWizardRequestAllowed -HostHeader 'localhost:7777' -Origin 'http://localhost:7777' -Method POST -ContentType 'application/json' -Port 7777 | Should -BeNullOrEmpty
    }
    It 'another origin is refused' {
        Test-SIWizardRequestAllowed -HostHeader 'localhost:7777' -Origin 'https://evil.example' -Method POST -ContentType 'application/json' -Port 7777 | Should -Match 'cross-origin'
    }
    It 'a text/plain simple request is refused (no preflight would stop it)' {
        Test-SIWizardRequestAllowed -HostHeader 'localhost:7777' -Origin $null -Method POST -ContentType 'text/plain' -Port 7777 | Should -Match 'application/json'
    }
    It 'a DNS-rebinding host is refused' {
        Test-SIWizardRequestAllowed -HostHeader 'evil.example:7777' -Origin $null -Method GET -ContentType $null -Port 7777 | Should -Match 'not this wizard'
    }
    It 'WIRING -- the guard runs before routing for every /api/ path' {
        $src = Get-Content -LiteralPath $script:Server -Raw
        $src | Should -Match '(?s)if \(\$url -like ''/api/\*''\) \{\s*\$refusal = Test-SIWizardRequestAllowed.{0,600}Status 403.{0,80}continue.{0,120}switch -Regex \(\$url\)'
    }
}

Describe 'cert mode: a re-run never revokes a working credential' {
    BeforeAll { $script:SpnSrc = Get-Content -LiteralPath $script:NewSpn -Raw }
    It 'the key list is only ever replaced on the mint branch, which is off when certificates exist and no opt-in' {
        $a = [System.Management.Automation.Language.Parser]::ParseFile($script:NewSpn, [ref]$null, [ref]$null)
        $upd = $a.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Set-SIGraphApplicationCertificate' }, $true)
        @($upd).Count | Should -Be 1
        $clause = $upd[0].Parent
        while ($clause -and -not ($clause -is [System.Management.Automation.Language.IfStatementAst])) { $clause = $clause.Parent }
        ($clause.Clauses | Where-Object { $_.Item2.Extent.StartOffset -le $upd[0].Extent.StartOffset -and $_.Item2.Extent.EndOffset -ge $upd[0].Extent.EndOffset }).Item1.Extent.Text | Should -Be '$mintCert'
        $script:SpnSrc | Should -Match '(?s)if \(-not \$reuseCert -and \$existingKeys\.Count -gt 0 -and -not \$ReplaceKeyCredentials\) \{\s*throw'
        $script:SpnSrc | Should -Match '\$mintCert = -not \$reuseCert'
    }
    It 'consent is judged over every permission, counted safely on PS 5.1' {
        $script:SpnSrc | Should -Match '(?s)\$pendingCount = @\(\$permResults \| Where-Object \{ \$_\.Status -in @\(''pending'',''skipped''\) \}\)\.Count\s*\r?\n\s*\$consentStatus = if'
    }
}


Describe 'WIRING -- the fields the operator filled in reach the backend' {
    It 'resource groups, existing SPN and the spend ceiling' {
        $srv = Get-Content -LiteralPath $script:Server -Raw
        $srv | Should -Match '\$st\.infra\.dceResourceGroup'
        $srv | Should -Match '\$st\.infra\.storageResourceGroup\b'
        $srv | Should -Match '\$spnArgs\.UseExistingAppId\s+=\s+\$true'
        (Get-Content -LiteralPath (Join-Path $script:Wiz 'app.js') -Raw) | Should -Match 'existingAppId:\s+d\.spnMode === ''useExisting'''
    }
    It '-SkipPhase1 resolves the existing SPN instead of leaving it empty' {
        $u = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Setup-SecurityInsight-Unattended.ps1') -Raw
        $u | Should -Match '(?s)if \(\$SkipPhase1\) \{.{0,2500}Get-SIAzADServicePrincipal -ApplicationId \$skipAppId.{0,1500}ObjectId\s+=\s+\[string\]@\(\$skipSp\)\[0\]\.Id'
    }
}

Describe 'Community is simple: the wizard is first-time setup ONLY -- no day-2 GUI (operator, 2026-10-03)' {
    # The GUI is SecurityInsight Pro only; Community changes settings in its files and views data in the Azure Workbook.
    BeforeAll {
        $script:Srv  = Get-Content -Raw -LiteralPath (Join-Path $script:Wiz 'Start-SetupWizard.ps1')
        $script:Html = Get-Content -Raw -LiteralPath (Join-Path $script:Wiz 'Setup-SecurityInsight.html')
    }
    It 'no Settings mode, no settings routes, no settings page or script' {
        $script:Srv  | Should -Not -Match "ValidateSet\('Setup', 'Settings'\)"
        $script:Srv  | Should -Not -Match "/api/settings"
        $script:Srv  | Should -Not -Match "SI-Settings\.ps1|SI-TierDryRun\.ps1"
        $script:Html | Should -Not -Match 'settings\.js|data-spage='
        Test-Path -LiteralPath (Join-Path $script:Wiz 'settings.js') | Should -BeFalse
    }
    It 'the local viewer and the Power BI deployment are gone; the Azure Workbook stays' {
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'viewer') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\Deploy-SIPowerBI.ps1') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'preview\PowerBI') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'preview\AzureWorkbook\SecurityInsight-RiskAnalysis.workbook.json') | Should -BeTrue
        Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') | Should -Not -Match 'SendToPowerBI'
    }
}

Describe 'least privilege: one engine permission list, no broad setup scopes (#223)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        function script:Get-QuotedPerms([string]$Text) { @([regex]::Matches($Text, "'([A-Za-z]+\.[A-Za-z.]+)'") | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match '\.Read' } | Sort-Object -Unique) }
        $script:GraphPlan = @(($script:SIContainerIdentityAppRoles | Where-Object { $_.Resource -eq 'Microsoft Graph' }).Roles | Sort-Object -Unique)
    }
    It 'the wizard (New-SISpn) grants exactly the container grant plan''s Graph permissions' {
        $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\New-SISpn.ps1')
        $i = $t.IndexOf('$GraphPermissions = @('); $j = $t.IndexOf(')', $t.IndexOf("'RoleManagement.Read.Directory'", $i))
        $spn = Get-QuotedPerms $t.Substring($i, $j - $i)
        Compare-Object $script:GraphPlan $spn | Should -BeNullOrEmpty
    }
    It 'no setup path asks for Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory' {
        foreach ($f in 'setup\ConfigWizard\backend\New-SISpn.ps1', 'setup\ConfigWizard\Start-SetupWizard.ps1') {
            # the scope-equivalence table may NAME a broader grant as satisfying a read requirement; it never requests it
            $code = ((Get-Content -LiteralPath (Join-Path $script:SIRoot $f)) | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch "^\s*'Directory\.Read\.All'\s*=\s*@\(" }) -join "`n"
            $code | Should -Not -Match "'(Directory\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory)'" -Because $f
        }
    }
    It 'a service principal with Application.ReadWrite.OwnedBy satisfies the wizard''s scope check' {
        $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\New-SISpn.ps1')
        $t | Should -Match "'Application.ReadWrite.All' = @\('Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy'\)"
    }
}

Describe 'setup runs with rights on the SI resource group only -- outside it is a customer task (#223)' {
    BeforeAll {
        $script:Boot  = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $script:Infra = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1')
    }
    It 'provider registration that is refused warns with the customer command and continues' {
        # #521: over ARM (Register-SIResourceProvider); a refusal is caught, never a failed setup
        $script:Boot | Should -Match '(?s)try \{\s*\$null = Register-SIResourceProvider -ProviderNamespace \$rp -SubscriptionId \$subId.*?\} catch \{ \$registered = \$false \}'
        $script:Boot | Should -Match 'CUSTOMER TASK, once: register the resource provider'
    }
    It 'a grant setup cannot make becomes a ready-to-run customer task, marked inside / OUTSIDE the SI resource group' {
        $script:Boot | Should -Match 'SICustomerTasks'
        $script:Boot | Should -Match 'OUTSIDE the SI resource group'
        # #564: the customer task is an Azure portal path (a customer has no az CLI) -- was an az role assignment command
        $script:Boot | Should -Match ([regex]::Escape('# Azure role "{1}" on "{2}" for the managed identity {0} -- Azure portal: open the scope > Access control (IAM) > Add > Add role assignment'))
        $script:Boot | Should -Not -Match 'az role assignment create'
        $script:Boot | Should -Match 'CUSTOMER TASKS -- one-time'
    }
    It 'a missing resource group that cannot be created says what the customer does once' {
        # #564: an Azure portal path (was an az group create command)
        $script:Infra | Should -Match ([regex]::Escape('CUSTOMER TASK, once: an Owner of subscription {2} creates it in {1} (Azure portal: Resource groups > Create)'))
        $script:Infra | Should -Not -Match 'az group create'
    }
}
