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
    foreach ($fn in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Test-SIWizardRequestAllowed', 'Test-SIWizardSessionSecret', 'Add-SIWizardSessionSecretToPage' }, $true))) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $spnAst = [System.Management.Automation.Language.Parser]::ParseFile($script:NewSpn, [ref]$null, [ref]$null)
    foreach ($fn in @($spnAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SISpnCertKeyExportPolicy' }, $true))) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }

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
        $spn   = [pscustomobject]@{ AppId = 'app'; TenantId = 'tid'; ObjectId = 'oid'; CredKind = 'Cert'; CertThumbprint = $script:Hostile; KvName = $null }
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
    It 'a hostile value is stored verbatim, not executed' {
        Get-AssignedLiteral $script:FileAst 'SI_SPN_CertThumbprint' | Should -Be $script:Hostile
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
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Cert'; CertThumbprint = $pw }
        $infra = [pscustomobject]@{ Location = 'l'; SubscriptionId = 's'; WorkspaceName = 'w'; ResourceGroupName = 'r'; WorkspaceResourceId = '/x'; DceName = 'd'; DceIngestionUri = 'u'; DcrResourceGroupName = 'r'; StorageAccountName = 'st'; StorageResourceGroupName = 'r' }
        & $script:Writer -OutputPath $out2 -Spn $spn -Infra $infra *> $null
        $fa = [System.Management.Automation.Language.Parser]::ParseFile($out2, [ref]$null, [ref]$null)
        Get-AssignedLiteral $fa 'SI_SPN_CertThumbprint' | Should -Be $pw
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

Describe 'NEGATIVE (2026-10-31): a client secret is never written into the configuration file' {
    BeforeAll { $script:Inf = [pscustomobject]@{ Location = 'l'; SubscriptionId = 's'; WorkspaceName = 'w'; ResourceGroupName = 'r'; WorkspaceResourceId = '/x'; DceName = 'd'; DceIngestionUri = 'u'; DcrResourceGroupName = 'r'; StorageAccountName = 'st'; StorageResourceGroupName = 'r' } }
    It 'a secret with no Key Vault is refused -- no file carries it' {
        $out = Join-Path $TestDrive 'inline.custom.ps1'
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Secret'; CredValue = 'S3CRET-VALUE-1'; KvName = $null }
        { & $script:Writer -OutputPath $out -Spn $spn -Infra $script:Inf *> $null } | Should -Throw '*never written into the configuration file*'
        if (Test-Path -LiteralPath $out) { Get-Content -LiteralPath $out -Raw | Should -Not -Match 'S3CRET-VALUE-1' }
    }
    It 'a secret that also sits in Key Vault: only the vault and secret NAMES are written, never the value' {
        $out = Join-Path $TestDrive 'kvval.custom.ps1'
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Secret'; CredValue = 'S3CRET-VALUE-2'; KvName = 'kv-x'; KvSecretName = 'SI-SPN-Secret' }
        & $script:Writer -OutputPath $out -Spn $spn -Infra $script:Inf *> $null
        $t = Get-Content -LiteralPath $out -Raw
        $t | Should -Not -Match 'S3CRET-VALUE-2'
        $t | Should -Match 'Get-SIKvSecret -VaultName \$global:SI_KeyVaultName -SecretName \$global:SI_SPN_KvSecretName'
    }
    It 'the wizard keeps a secret in Key Vault by default, refuses inline storage, and never sends the value back to the page' {
        $srv = Get-Content -LiteralPath $script:Server -Raw
        $srv | Should -Match "elseif \(\`$signIn\.CredKind -eq 'Cert'\) \{ 'LocalCertStore' \} else \{ 'KeyVault' \}"
        $srv | Should -Match "if \(\`$spnArgs\.CredStorage -eq 'Inline'\) \{\s+throw"
        $srv | Should -Match ([regex]::Escape('$spnOut = & $cmdletNewSISpn @spnArgs') + '\s+' + [regex]::Escape("if (`$spnOut -and `$spnOut.PSObject.Properties['CredValue']) { `$spnOut.CredValue = `$null }"))
    }
}

Describe 'NEGATIVE (2026-10-31): only THIS wizard session can drive the local API -- not another program on the machine' {
    It 'the session secret: equal = allowed; wrong, empty, missing or a prefix = refused' {
        $s = 'a' * 64
        Test-SIWizardSessionSecret -Presented $s -Expected $s | Should -BeTrue
        Test-SIWizardSessionSecret -Presented ('b' * 64) -Expected $s | Should -BeFalse
        Test-SIWizardSessionSecret -Presented '' -Expected $s | Should -BeFalse
        Test-SIWizardSessionSecret -Presented $null -Expected $s | Should -BeFalse
        Test-SIWizardSessionSecret -Presented ('a' * 63) -Expected $s | Should -BeFalse
        Test-SIWizardSessionSecret -Presented ($s + 'a') -Expected $s | Should -BeFalse
        Test-SIWizardSessionSecret -Presented '' -Expected '' | Should -BeFalse -Because 'no secret is never a match'
    }
    It 'the page carries the secret for its own calls (a meta tag in <head>)' {
        $h = Add-SIWizardSessionSecretToPage -Html '<html><head><title>x</title></head><body></body></html>' -Secret 'abc123'
        $h | Should -Match '<meta name="si-wizard-session" content="abc123">\s*</head>'
    }
    It 'WIRING: every /api/* call needs the X-SI-Wizard-Session header; the page is served only to the ?k= link; the page''s calls send it' {
        $src = Get-Content -LiteralPath $script:Server -Raw
        $src | Should -Match ([regex]::Escape("if (-not `$refusal -and -not (Test-SIWizardSessionSecret -Presented `$req.Headers['X-SI-Wizard-Session'] -Expected `$script:SIWizardSecret))"))
        $src | Should -Match ([regex]::Escape("if (-not (Test-SIWizardSessionSecret -Presented `$req.QueryString['k'] -Expected `$script:SIWizardSecret))"))
        $src | Should -Match ([regex]::Escape('$sessionRng.GetBytes($sessionBytes)'))
        $src | Should -Match 'New-Object byte\[\] 32'
        $src | Should -Match ([regex]::Escape('Start-Process $sessionUrl'))
        $js = Get-Content -LiteralPath (Join-Path $script:Wiz 'app.js') -Raw
        $js | Should -Match "h\['X-SI-Wizard-Session'\] = m\.content"
        $js | Should -Match "fetch\('/api/state', \{ method: 'GET', headers: wizardApiHeaders\(\) \}\)"
        $js | Should -Match "headers: wizardApiHeaders\(\{ 'Content-Type': 'application/json' \}\)"
    }
}

Describe 'NEGATIVE (2026-10-31): the engine identity gets no role on the whole subscription; a host-only certificate key is not exportable' {
    It 'New-SISpn assigns no Contributor (and no other role) at the subscription scope' {
        $a = [System.Management.Automation.Language.Parser]::ParseFile($script:NewSpn, [ref]$null, [ref]$null)
        $grants = @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-SIRoleAssignment' }, $true))
        foreach ($g in $grants) {
            $g.Extent.Text | Should -Not -Match "'Contributor'"
            $g.Extent.Text | Should -Not -Match '-Scope \$subScope'
        }
    }
    It 'the certificate key: NonExportable unless a copy goes to Key Vault; the PFX is exported only then' {
        Get-SISpnCertKeyExportPolicy -CredStorage 'LocalCertStore' | Should -Be 'NonExportable'
        Get-SISpnCertKeyExportPolicy -CredStorage '' | Should -Be 'NonExportable'
        Get-SISpnCertKeyExportPolicy -CredStorage 'KeyVault' | Should -Be 'Exportable'
        $t = Get-Content -LiteralPath $script:NewSpn -Raw
        $t | Should -Match '-KeySpec Signature -KeyExportPolicy \$keyExport'
        $t | Should -Not -Match '-KeyExportPolicy Exportable'
        $t | Should -Match "(?s)if \(\`$keyExport -eq 'Exportable'\) \{\s+\`$pfxPwd\s+=.{0,80}\`$pfxBytes = \`$cert\.Export"
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
        $u | Should -Match '(?s)if \(\$SkipPhase1\) \{.{0,2500}Get-SIAzADServicePrincipal -ApplicationId \$skipAppId.{0,3500}ObjectId\s+=\s+\[string\]@\(\$skipSp\)\[0\]\.Id'
    }
}

Describe 'NEGATIVE (2026-11-01): the unattended setup stops BEFORE it creates anything when the credential could not end in a working configuration' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-ServerSignIn.ps1')
        $script:Unatt = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Setup-SecurityInsight-Unattended.ps1') -Raw
        $script:Inf2 = [pscustomobject]@{ Location = 'l'; SubscriptionId = 's'; WorkspaceName = 'w'; ResourceGroupName = 'r'; WorkspaceResourceId = '/x'; DceName = 'd'; DceIngestionUri = 'u'; DcrResourceGroupName = 'r'; StorageAccountName = 'st'; StorageResourceGroupName = 'r' }
    }
    It 'a client secret written into the file (Inline) is refused; so is a Key Vault store with no vault named' {
        Test-SIUnattendedCredentialPlan -CredKind Secret -CredStorage Inline -KeyVaultName 'kv-x' | Should -Match 'never written into the configuration file.*nothing was created'
        Test-SIUnattendedCredentialPlan -CredKind Secret -CredStorage KeyVault -KeyVaultName '' | Should -Match 'needs Auth_Community\.KeyVaultName.*client secret'
        Test-SIUnattendedCredentialPlan -CredKind Cert -CredStorage KeyVault -KeyVaultName $null | Should -Match 'needs Auth_Community\.KeyVaultName.*certificate'
        # what works stays allowed
        Test-SIUnattendedCredentialPlan -CredKind Secret -CredStorage KeyVault -KeyVaultName 'kv-x' | Should -BeNullOrEmpty
        Test-SIUnattendedCredentialPlan -CredKind Cert -CredStorage LocalCertStore | Should -BeNullOrEmpty
        Test-SIUnattendedCredentialPlan -CredKind ManagedIdentity | Should -BeNullOrEmpty
        # the JSON's own Inline reaches the check (Resolve keeps what the JSON says)
        $r = Resolve-SIUnattendedSignIn -CredKind Secret -CredStorage Inline -HostKind AzureVm
        Test-SIUnattendedCredentialPlan -CredKind $r.CredKind -CredStorage $r.CredStorage -KeyVaultName '' | Should -Not -BeNullOrEmpty
    }
    It 'WIRING: the check runs right after the sign-in is resolved, before Phase 1 creates an app or a secret' {
        $script:Unatt | Should -Match '(?s)\$commSignIn = Resolve-SIUnattendedSignIn.{0,900}\$credWhy = Test-SIUnattendedCredentialPlan -CredKind \$commSignIn\.CredKind -CredStorage \$commSignIn\.CredStorage -KeyVaultName.{0,200}if \(\$credWhy\) \{ _Err \$credWhy; throw \$credWhy \}'
        $script:Unatt.IndexOf('$credWhy = Test-SIUnattendedCredentialPlan') | Should -BeLessThan $script:Unatt.IndexOf('$spnOut = & $cmdletNewSISpn @spnArgs')
    }
    It '-SkipPhase1 for a client-secret install: the vault reference, or the existing file''s sign-in kept -- refused before Phase 2 when neither' {
        $r = Get-SIUnattendedExistingSecretRef -KeyVaultName 'kv-x' -KvSecretName ''
        $r.Ok | Should -BeTrue; $r.KvName | Should -Be 'kv-x'; $r.KvSecretName | Should -Be 'SI-SPN-Secret'
        (Get-SIUnattendedExistingSecretRef -KeyVaultName 'kv-x' -KvSecretName 'Own-Name').KvSecretName | Should -Be 'Own-Name'
        $k = Get-SIUnattendedExistingSecretRef -ExistingConfig $true
        $k.Ok | Should -BeTrue; $k.KeepExisting | Should -BeTrue
        $n = Get-SIUnattendedExistingSecretRef
        $n.Ok | Should -BeFalse; $n.Reason | Should -Match 'never written into the configuration file\. Nothing was changed'
        $script:Unatt | Should -Match '(?s)if \(\$SkipPhase1\) \{.{0,3000}\$skipRef = Get-SIUnattendedExistingSecretRef.{0,400}if \(-not \$skipRef\.Ok\) \{ _Err \$skipRef\.Reason; throw \$skipRef\.Reason \}'
        $script:Unatt | Should -Match 'CredValue\s+=\s+\$null'
        $script:Unatt.IndexOf('$skipRef = Get-SIUnattendedExistingSecretRef') | Should -BeLessThan $script:Unatt.IndexOf('$infraOut = & $cmdletInitInfra @infraArgs')
    }
    It 'the config step keeps the sign-in an existing file has (a re-run with -SkipPhase1), and writes no secret' {
        $out = Join-Path $TestDrive 'keep.custom.ps1'
        [IO.File]::WriteAllText($out, "`$global:SI_SPN_AppId = 'a'`r`n`$global:SI_SPN_Secret = 'OLD-INSTALL-SECRET'`r`n")
        $spn = [pscustomobject]@{ AppId = 'a'; TenantId = 't'; ObjectId = 'o'; CredKind = 'Secret'; CredValue = $null; KvName = $null; KeepExistingSignIn = $true }
        & $script:Writer -OutputPath $out -Spn $spn -Infra $script:Inf2 -Merge *> $null
        $t = Get-Content -LiteralPath $out -Raw
        $t | Should -Match ([regex]::Escape("`$global:SI_SPN_Secret = 'OLD-INSTALL-SECRET'")) -Because 'the existing install keeps working'
        @([regex]::Matches($t, '\$global:SI_SPN_Secret\s*=')).Count | Should -Be 1 -Because 'nothing new about the secret is written'
        # without an existing file (or with -Force) the same object is refused
        { & $script:Writer -OutputPath (Join-Path $TestDrive 'nofile.custom.ps1') -Spn $spn -Infra $script:Inf2 -Merge *> $null } | Should -Throw '*never written into the configuration file*'
        { & $script:Writer -OutputPath $out -Spn $spn -Infra $script:Inf2 -Force *> $null } | Should -Throw '*never written into the configuration file*'
    }
}

Describe 'NEGATIVE (2026-11-01): the wizard page offers no way to write a client secret into the file' {
    BeforeAll {
        $script:AppJs = Get-Content -LiteralPath (Join-Path $script:Wiz 'app.js') -Raw
        $script:Page  = Get-Content -LiteralPath (Join-Path $script:Wiz 'Setup-SecurityInsight.html') -Raw
    }
    It 'no Inline storage option on the page or in its rules; a secret is kept in Key Vault only' {
        $script:Page | Should -Not -Match 'value="Inline"'
        $script:AppJs | Should -Not -Match "'Inline'"
        $script:AppJs | Should -Match "kvSecret:\s+\['KeyVault'\]"
        $script:AppJs | Should -Match "win:\s+\['LocalCertStore'\]"
    }
    It 'a server outside Azure that picks a client secret is moved to a certificate (no identity there could read Key Vault), and the page says why' {
        $script:AppJs | Should -Match "(?s)function snapCredStorage\(\).{0,900}state\.data\.credType = 'certThumb'"
        $script:Page | Should -Match 'data-host-type-block="win"[^>]*>[^<]*(outside Azure|a certificate)'
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
