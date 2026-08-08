#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- the SIA environment installer (audit #40).

.DESCRIPTION
    #40: the AutomateIT sync can UPDATE SecurityInsight Analyzer but could never INSTALL it.
    `sync/_SyncDeploy.ps1` runs a solution's declared Deploy.Script unattended on content
    change, but that script (`Deploy-SIAnalyzer.ps1`) is an updater -- it assumes the resource
    group, registry, Container Apps environment, app, storage account and Entra app
    registration already exist. `solution.deploy.json` lists them under `requires` as
    PRECONDITIONS, and nothing created them. `Install-SIAnalyzerEnvironment.ps1` is that
    missing half.

    What these cases pin, and why each one is here rather than trusted:

      * THE BIRTH SETTINGS. Every setting the installer creates the app WITH is one the
        deploy script can only ASSERT afterwards -- target-port (#12), plain-HTTP refusal
        (#13), internal ingress (#3a.3), private environment (#3a part 3). Creating the app
        wrong does not produce a warning, it produces an app that has to be migrated out of,
        which is exactly what #3b already is. So the create arguments are asserted literally.

      * THE ShouldProcess CONTRACT. An installer whose -WhatIf still mutates Azure is worse
        than one with no -WhatIf at all. Every MUTATING az call is required to sit inside a
        ShouldProcess branch, checked structurally through the AST rather than by reading.

      * THE DIVISION OF LABOUR with the updater. The data-plane grants (Log Analytics Reader,
        OpenAI User, Storage Table Data Contributor) belong to Deploy-SIAnalyzer.ps1, which
        re-applies them on every sync. If they leak into the installer they run once, drift,
        and nobody notices. Asserted by absence.

      * RULE 8. SI work touches SI only. The installer must not reach into the shared,
        framework-owned sync/ tree, which was the explicit constraint on #40.

    These are STATIC checks on the script. Whether a real install succeeds is a hosted-gate
    question, answered by running it -- which is how the -WhatIf preference defect below was
    found in the first place.
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> solution root (3 levels up)
    $_root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SiRoot      = $_root
    $script:InstallPath = Join-Path $_root 'analyzer-web\deploy\Install-SIAnalyzerEnvironment.ps1'
    $script:DeployPath  = Join-Path $_root 'analyzer-web\deploy\Deploy-SIAnalyzer.ps1'
    $script:DockerPath  = Join-Path $_root 'analyzer-web\deploy\Dockerfile'

    $script:Install = if (Test-Path $script:InstallPath) { Get-Content -Raw -LiteralPath $script:InstallPath } else { '' }
    $script:Deploy  = if (Test-Path $script:DeployPath)  { Get-Content -Raw -LiteralPath $script:DeployPath }  else { '' }
    $script:Docker  = if (Test-Path $script:DockerPath)  { Get-Content -Raw -LiteralPath $script:DockerPath }  else { '' }

    $script:InstallAst = $null
    $script:ParseErrors = @()
    $script:InstallCode = ''
    if ($script:Install) {
        $errs = $null
        $toks = $null
        $script:InstallAst = [System.Management.Automation.Language.Parser]::ParseInput($script:Install, [ref]$toks, [ref]$errs)
        $script:ParseErrors = @($errs)

        # CODE ONLY -- the script text with every comment token blanked out.
        #
        # This distinction is not pedantry, it is the difference between a test that works and
        # one that cannot: the installer's own documentation NAMES the things it deliberately
        # does not do ("the data-plane grants ... Log Analytics Reader ... stay in
        # Deploy-SIAnalyzer.ps1", "sync/_SyncDeploy.ps1 runs a solution's Deploy.Script").
        # Asserting absence over the raw text therefore fails on the very comments that
        # explain the property being asserted -- and the only way to make it pass would be to
        # delete the explanation. Match the code; let the prose say what it likes.
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append($script:Install)
        foreach ($t in @($toks | Where-Object { $_.Kind -eq 'Comment' })) {
            $start = $t.Extent.StartOffset
            $len   = $t.Extent.EndOffset - $start
            if ($len -gt 0) { [void]$sb.Remove($start, $len); [void]$sb.Insert($start, (' ' * $len)) }
        }
        $script:InstallCode = $sb.ToString()
    }

    # Every Invoke-Az call in the script, paired with its flattened argument list. Used by the
    # ShouldProcess cases below. Extracted from the AST so a reformat cannot change the answer.
    function Get-InvokeAzCalls {
        param($Ast)
        if (-not $Ast) { return @() }
        $calls = $Ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -eq 'Invoke-Az'
        }, $true)
        $out = @()
        foreach ($c in $calls) { $out += [pscustomobject]@{ Ast = $c; Text = $c.Extent.Text } }
        return $out
    }

    # Walk up the AST until an `if` whose condition mentions ShouldProcess is found.
    function Test-GuardedByShouldProcess {
        param($Node)
        $cur = $Node
        while ($cur) {
            if ($cur -is [System.Management.Automation.Language.IfStatementAst]) {
                foreach ($clause in $cur.Clauses) {
                    if ($clause.Item1.Extent.Text -match 'ShouldProcess') { return $true }
                }
            }
            $cur = $cur.Parent
        }
        return $false
    }

    # The az subcommands that CHANGE Azure. Existence probes ('show', 'list', 'exists') are
    # deliberately absent -- they must run under -WhatIf or the preview cannot be accurate.
    $script:MutatingVerbs = @('create', 'update', 'add-record', 'set-mode', 'delete', 'assign')
}

# ============================================================================
Describe 'Install-SIAnalyzerEnvironment exists and parses (audit #40)' {
# ============================================================================

    It 'the installer exists beside the deploy script it complements' {
        Test-Path $script:InstallPath | Should -BeTrue
    }

    It 'parses with no errors on the PowerShell 5.1 grammar' {
        # SI engines run on Windows PowerShell 5.1. A PS7-only construct here would parse
        # cleanly in a dev shell and die on the customer.
        $script:ParseErrors.Count | Should -Be 0
    }

    It 'declares #Requires -Version 5.1' {
        $script:Install | Should -Match '(?m)^#Requires -Version 5\.1'
    }

    It 'supports -WhatIf' {
        $script:Install | Should -Match 'CmdletBinding\(SupportsShouldProcess'
    }
}

# ============================================================================
Describe 'the app is BORN with the settings the deploy can only assert' {
# ============================================================================

    It 'creates the container app with an explicit --target-port' {
        $script:Install | Should -Match "'--target-port'"
    }

    It 'the installer, the deploy gate and the Dockerfile agree on ONE listen port' {
        # A three-way contract now: the image binds it, the installer creates the ingress with
        # it, the deploy asserts the live ingress against it. Nothing injects a port into the
        # container, so two of the three agreeing is not enough.
        #
        # Captures come from [regex]::Match, not from Should -Match: Pester's assertion does
        # not publish $Matches into the test's scope, so reading it there indexes a null array
        # -- which fails as a RuntimeException and looks like a broken test rather than a
        # drifted port.
        $installMatch = [regex]::Match($script:InstallCode, '\$ContainerListenPort\s*=\s*(\d+)')
        $deployMatch  = [regex]::Match($script:Deploy,      '\$ContainerListenPort\s*=\s*(\d+)')
        $dockerMatch  = [regex]::Match($script:Docker,      'ASPNETCORE_URLS=http://\+:(\d+)')

        $installMatch.Success | Should -BeTrue
        $deployMatch.Success  | Should -BeTrue
        $dockerMatch.Success  | Should -BeTrue

        $installMatch.Groups[1].Value | Should -Be $deployMatch.Groups[1].Value
        $installMatch.Groups[1].Value | Should -Be $dockerMatch.Groups[1].Value
    }

    It 'creates the app with INTERNAL ingress, never external (#3a.3)' {
        $script:Install | Should -Match "'--ingress','internal'"
        $script:Install | Should -Not -Match "'--ingress','external'"
    }

    It 'creates the app with a system-assigned managed identity' {
        # The whole data plane is MI-based (Log Analytics, OpenAI, table storage). An app
        # created without one has nothing for the deploy's grants to attach to.
        $script:Install | Should -Match "'--system-assigned'"
    }

    It 'turns plain HTTP off at the ingress (#13)' {
        $script:Install | Should -Match "'--allow-insecure','false'"
    }

    It 'puts the app in multiple-revision mode so the first update is already blue/green' {
        $script:Install | Should -Match "'--mode','multiple'"
    }
}

# ============================================================================
Describe 'the environment is PRIVATE by default (#3a part 3)' {
# ============================================================================

    It 'defaults public network access to Disabled' {
        $script:Install | Should -Match "\`$pna\s*=\s*'Disabled'"
    }

    It 'only enables public access behind the explicit -AllowPublicIngress switch' {
        $script:Install | Should -Match '\[switch\]\$AllowPublicIngress'
        # The ONLY assignment of 'Enabled' must sit inside the AllowPublicIngress branch.
        $enabledAssignments = [regex]::Matches($script:Install, "\`$pna\s*=\s*'Enabled'")
        $enabledAssignments.Count | Should -Be 1
        $script:Install | Should -Match "(?s)if \(\`$AllowPublicIngress\).*?\`$pna\s*=\s*'Enabled'"
    }

    It 'passes --public-network-access at CREATE time, not as a follow-up update' {
        # A window between "environment exists" and "environment is private" is the exposure
        # #3a.3 is about. It must never be opened.
        $script:Install | Should -Match "'containerapp','env','create'[^)]*'--public-network-access'"
    }

    It 'warns when a private environment has no way in' {
        $script:Install | Should -Match 'UNREACHABLE'
    }

    It 'does not cry wolf when the environment already has a private endpoint' {
        # A warning that fires when nothing is wrong stops being read.
        $script:InstallCode | Should -Match 'privateEndpointConnections'
    }

    It 'never passes a JMESPath function call to az, because cmd.exe eats the parentheses' {
        # REGRESSION PIN, and this one shipped: `--query length(properties.privateEndpointConnections)`
        # looked correct and IS correct JMESPath, but `az` on Windows is a BATCH FILE, so
        # cmd.exe parses the argument list before az ever sees it and the '(' terminates it.
        # The call died with "-o was unexpected at this time" and exit 255 -- which the caller
        # read as "no private endpoint" and warned about an environment that had one.
        # Failing CLOSED on a parse error is what made it look like a real finding.
        #
        # The rule this pins: project a list with [] and measure it in PowerShell, never call
        # a JMESPath function. Applies to every az --query in this script.
        $queryArgs = [regex]::Matches($script:InstallCode, "'--query'\s*,\s*'(?<q>[^']*)'")
        @($queryArgs).Count | Should -BeGreaterThan 0
        $withParens = @($queryArgs | Where-Object { $_.Groups['q'].Value -match '\(' } |
                        ForEach-Object { $_.Groups['q'].Value })
        $withParens -join ' || ' | Should -BeNullOrEmpty
    }
}

# ============================================================================
Describe 'the -WhatIf contract: preview never mutates, and preview can still read' {
# ============================================================================

    It 'every MUTATING az call sits inside a ShouldProcess branch' {
        $calls = Get-InvokeAzCalls -Ast $script:InstallAst
        @($calls).Count | Should -BeGreaterThan 0

        $unguarded = @()
        foreach ($c in $calls) {
            $isMutating = $false
            foreach ($v in $script:MutatingVerbs) {
                # Match the verb as a quoted az argument, e.g. 'create' -- not as a substring
                # of a resource name.
                if ($c.Text -match "'$v'") { $isMutating = $true; break }
            }
            if (-not $isMutating) { continue }
            if (-not (Test-GuardedByShouldProcess -Node $c.Ast)) {
                $unguarded += $c.Text.Substring(0, [Math]::Min(110, $c.Text.Length))
            }
        }
        # 'role assignment list --role AcrPull' contains no mutating verb; 'role assignment
        # create' does and must be guarded.
        $unguarded -join " || " | Should -BeNullOrEmpty
    }

    It 'Invoke-Az disables WhatIfPreference locally so probes still read under -WhatIf' {
        # REGRESSION PIN, and this was a real defect found by running the script: -WhatIf sets
        # $WhatIfPreference for the whole scope, and STREAM REDIRECTION honours it, so
        # `2>$errFile` became "What if: Output to File" and captured nothing. A -WhatIf run
        # that cannot read the live environment reports creating resources that already exist.
        $script:Install | Should -Match '(?s)function Invoke-Az.*?\$WhatIfPreference\s*=\s*\$false'
    }

    It 'existence probes are quiet, so an expected absence is not printed as an error' {
        # Printing ResourceNotFound in red on every clean install trains the operator to
        # ignore red, which is how a real failure gets missed.
        $script:Install | Should -Match 'Invoke-Az \$AzArgs -Quiet'
        $script:Install | Should -Match '\[switch\]\$Quiet'
    }
}

# ============================================================================
Describe 'division of labour with Deploy-SIAnalyzer.ps1' {
# ============================================================================

    It 'grants exactly ONE role, and it is AcrPull' {
        # If the data-plane grants leak into the installer they run once, drift, and nobody
        # notices; Deploy-SIAnalyzer.ps1 re-applies them on every sync, which is where they
        # stay correct.
        #
        # Asserted as "which roles does it GRANT", not "which role names appear", and that
        # distinction is load-bearing twice over. The names appear in the .DESCRIPTION (which
        # explains what the installer deliberately does NOT do) and again in a WARNING STRING
        # telling the operator which role their own identity is missing -- neither is a grant,
        # and neither should have to be deleted to make a test pass. So: pull the --role
        # arguments out of the role-assignment-create calls and check that set.
        $roleGrants = [regex]::Matches($script:InstallCode, "'role','assignment','create'.*?'--role',\s*'(?<r>[^']+)'")
        $granted = @($roleGrants | ForEach-Object { $_.Groups['r'].Value } | Sort-Object -Unique)

        $granted.Count | Should -Be 1
        $granted[0] | Should -Be 'AcrPull'
    }

    It 'grants AcrPull itself, because without it the app can never start' {
        # The one grant that genuinely belongs to install: an app that cannot pull its image
        # never runs, so there is nothing for the updater to update.
        $script:Install | Should -Match "'AcrPull'"
    }

    It 'creates the Entra app registration but does not enable Easy Auth' {
        # Creating a directory object needs Graph permissions the deploy identity may lack;
        # enabling Easy Auth is an ARM operation on an app it already owns.
        $script:Install | Should -Match "'ad','app','create'"
        $script:Install | Should -Not -Match "'auth','microsoft','update'"
    }

    It 'hands the caller the exact deploy command for what it just installed' {
        $script:Install | Should -Match 'DeployCommand'
    }
}

# ============================================================================
Describe 'least privilege and containment' {
# ============================================================================

    It 'creates the registry with the admin user disabled' {
        # A shared username/password pair would have to be stored somewhere. The app pulls
        # with its managed identity instead.
        $script:Install | Should -Match "'--admin-enabled','false'"
    }

    It 'creates storage with shared-key auth disabled and a TLS floor' {
        $script:Install | Should -Match "'--allow-shared-key-access','false'"
        $script:Install | Should -Match "'--min-tls-version','TLS1_2'"
        $script:Install | Should -Match "'--allow-blob-public-access','false'"
    }

    It 'gives SIA its own storage account rather than the engines'' one' {
        # Table Data Contributor is granted at ACCOUNT scope, so sharing the engines' account
        # would hand the web app write access to the CMDB and fingerprint tables.
        $script:Install | Should -Match 'least-privilege'
    }

    It 'guards the resource group the same way the deploy does (#3b)' {
        $script:Install | Should -Match 'AllowResourceGroupMismatch'
        $script:Install | Should -Match "/resourceGroups/\(\?<rg>\[\^/\]\+\)/"
    }

    It 'does not reach into the framework-owned sync/ tree (SI CLAUDE.md rule 8)' {
        # #40's explicit constraint: the install belongs to SI; the update path already works.
        # Over CODE again -- the .DESCRIPTION has to explain what sync/_SyncDeploy.ps1 does and
        # why it is deliberately untouched, and saying so is not reaching into it.
        $script:InstallCode | Should -Not -Match '(?m)[''"][^''"]*[\\/]sync[\\/][^''"]*[''"]'
        $script:InstallCode | Should -Not -Match '_SyncDeploy'
    }
}

# ============================================================================
Describe 'negative verification -- these cases can actually fail' {
# ============================================================================

    # A green suite proves only what it asserts. Each case below breaks the property in a
    # COPY of the script text and requires the corresponding assertion to notice.

    It 'the port-agreement case fails when the installer port drifts from the Dockerfile' {
        $mutated = $script:InstallCode -replace '\$ContainerListenPort = 8080', '$ContainerListenPort = 9090'
        $m = [regex]::Match($mutated, '\$ContainerListenPort\s*=\s*(\d+)')
        $m.Success | Should -BeTrue
        $dockerMatch = [regex]::Match($script:Docker, 'ASPNETCORE_URLS=http://\+:(\d+)')
        $m.Groups[1].Value | Should -Not -Be $dockerMatch.Groups[1].Value
    }

    It 'the comment-stripper really removes comments, so the containment cases mean something' {
        # If this stripper silently did nothing, three cases above would be asserting over the
        # raw text and would have failed -- but a future edit could weaken it into a no-op that
        # makes them pass vacuously instead. Pin both directions.
        $script:Install     | Should -Match 'Log Analytics Reader'   # the prose does name it
        $script:InstallCode | Should -Not -Match 'Log Analytics Reader'
        # Stripping must preserve offsets, so code either side of a comment is untouched.
        $script:InstallCode.Length | Should -Be $script:Install.Length
        $script:InstallCode | Should -Match '\$ErrorActionPreference'
    }

    It 'the internal-ingress case fails when the app is created external' {
        $mutated = $script:Install -replace "'--ingress','internal'", "'--ingress','external'"
        $mutated | Should -Not -Match "'--ingress','internal'"
    }

    It 'the private-by-default case fails when the environment defaults to public' {
        $mutated = $script:Install -replace "\`$pna = 'Disabled'", "`$pna = 'Enabled'"
        ([regex]::Matches($mutated, "\`$pna\s*=\s*'Enabled'")).Count | Should -BeGreaterThan 1
    }

    It 'the ShouldProcess case finds an unguarded mutating call when one is introduced' {
        $mutated = $script:Install + "`n[void](Invoke-Az @('group','create','-n','rogue'))`n"
        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($mutated, [ref]$null, [ref]$errs)
        $calls = Get-InvokeAzCalls -Ast $ast
        $rogue = @($calls | Where-Object { $_.Text -match "'rogue'" })
        $rogue.Count | Should -Be 1
        Test-GuardedByShouldProcess -Node $rogue[0].Ast | Should -BeFalse
    }

    It 'the one-role case notices a data-plane grant being added to the installer' {
        $mutated = $script:InstallCode + "`n[void](Invoke-Az @('role','assignment','create','--assignee-object-id',`$x,'--role','Log Analytics Reader','--scope',`$y))`n"
        $granted = @([regex]::Matches($mutated, "'role','assignment','create'.*?'--role',\s*'(?<r>[^']+)'") |
                     ForEach-Object { $_.Groups['r'].Value } | Sort-Object -Unique)
        $granted.Count | Should -Be 2
        $granted | Should -Contain 'Log Analytics Reader'
    }

    It 'the shared-key case fails when storage is created with shared keys enabled' {
        $mutated = $script:Install -replace "'--allow-shared-key-access','false'", "'--allow-shared-key-access','true'"
        $mutated | Should -Not -Match "'--allow-shared-key-access','false'"
    }
}
