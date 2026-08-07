#Requires -Version 5.1
<#
.SYNOPSIS
    AUDIT #35 -- every implemented detect kind is REGISTERED, and an unregistered
    one is reported instead of silently dropped.
    AUDIT #36 -- a rule that loads with zero detections is reported, not inert in
    silence.
.DESCRIPTION
    #35: `Test-SIKind_nameMatches` was implemented and its registry entry was not.
    0412976e added the entry under the comment
    `# Implemented in preview.66 (asset-row reads only):`; the v2.2.0 flatten
    (536e1405) stripped the version framing from that comment and JOINED the two
    lines, leaving

        # Implemented in 'nameMatches'                   = 'Test-SIKind_nameMatches'

    -- a live registry entry turned into part of a comment. Invoke-SIDetect then
    treated `nameMatches` as unknown: Write-Verbose (prints for nobody) and skip.
    Measured on the real tree: 95 detections across 93 rule files lost their
    name-pattern arm, for the entire v2.2 lifetime, on every customer. Nothing
    failed; assets whose role is only recognisable from their hostname simply
    stopped being recognised.

    The first test below is the one that matters: it does not check a list of
    names, it checks that EVERY Test-SIKind_* handler in the file is reachable
    through the registry. A hand-maintained list would have been just as easy to
    silently un-maintain.
#>

BeforeAll {
    Import-Module powershell-yaml -Force
    $script:SiRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SharedDir = Join-Path $script:SiRoot 'engine\asset-profiling\shared'
    . (Join-Path $script:SharedDir 'Get-SIRuleSet.ps1')
    . (Join-Path $script:SharedDir 'RuleEval.ps1')
    $script:Registry = Get-SIKindRegistry

    # Handlers as DECLARED IN SOURCE, read by AST rather than by Get-Command, so
    # the test measures the file and not whatever happens to be in the session.
    $ruleEvalPath = Join-Path $script:SharedDir 'RuleEval.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ruleEvalPath, [ref]$null, [ref]$null)
    $script:HandlerNames = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { $_.Name } | Where-Object { $_ -like 'Test-SIKind_*' })
}

Describe 'RuleKindRegistry (#35)' {

    It 'found the Test-SIKind_* handlers in RuleEval.ps1 (control)' {
        $script:HandlerNames.Count | Should -BeGreaterThan 5
    }

    It 'every implemented Test-SIKind_* handler is reachable through the registry' {
        # The exact defect: handler present, registration absent.
        $registered = @($script:Registry.Values)
        $orphans    = @($script:HandlerNames | Where-Object { $registered -notcontains $_ })
        $orphans | Should -BeNullOrEmpty -Because "implemented but unregistered = silently never called: $($orphans -join ', ')"
    }

    It 'every registry entry points at a handler that exists' {
        foreach ($kind in $script:Registry.Keys) {
            $script:HandlerNames | Should -Contain $script:Registry[$kind] -Because "kind '$kind' maps to a missing handler"
        }
    }

    It 'nameMatches specifically is registered (the entry the flatten swallowed)' {
        $script:Registry.ContainsKey('nameMatches') | Should -BeTrue
    }

    It 'nameMatches actually EVALUATES -- registry membership is not the same as working' {
        $detect = @{ any = @( @{ kind = 'nameMatches'; namePatterns = @('(?i)^dc\d') } ) }
        Invoke-SIDetect -Asset ([pscustomobject]@{ Name = 'DC01';  Hostname = 'DC01'  }) -Detect $detect | Should -BeTrue
        Invoke-SIDetect -Asset ([pscustomobject]@{ Name = 'WEB01'; Hostname = 'WEB01' }) -Detect $detect | Should -BeFalse
    }

    It 'no entry inside the registry body is commented out (negative verification -- pins the exact corruption shape)' {
        # Guards the MECHANISM, not just this one entry: any future bulk comment
        # rewrite that swallows a registration leaves exactly this shape behind.
        # Scoped to the hashtable body -- prose elsewhere in the file may legitimately
        # quote the corrupted line (the comment above the registry does).
        $src  = Get-Content -Raw (Join-Path $script:SharedDir 'RuleEval.ps1')
        $body = [regex]::Match($src, '(?s)\$script:SIKindRegistry\s*=\s*@\{(.*?)^\}', 'Multiline').Groups[1].Value
        $body | Should -Not -BeNullOrEmpty -Because 'the registry body must be locatable for this check to mean anything'
        $body | Should -Not -Match "(?m)^\s*#.*'\w+'\s*=\s*'Test-SIKind_"
    }

    It 'that negative check actually catches the corruption (verified against the real shape)' {
        # Proves the assertion above is not vacuous: feed it the line as 536e1405
        # left it and it must match.
        $corrupted = "    # Implemented in 'nameMatches'                   = 'Test-SIKind_nameMatches'"
        $corrupted | Should -Match "(?m)^\s*#.*'\w+'\s*=\s*'Test-SIKind_"
    }
}

Describe 'RuleLoadDiagnostics (#35 / #36)' {

    BeforeAll {
        $script:Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('si-ruleset-' + [guid]::NewGuid().ToString('N'))
        $endpointDir = Join-Path $script:Scratch 'asset-profiling-enrichment\endpoint'
        New-Item -ItemType Directory -Path $endpointDir -Force | Out-Null

        # A rule whose detect kind does not exist.
        Set-Content -LiteralPath (Join-Path $endpointDir 'UnknownKindRule.locked.yaml') -Encoding ASCII -Value @'
id: UnknownKindRule
appliesTo: endpoint
mode: locked
purpose: test
category: test
detections:
  - id: UnknownKindRule
    detect:
      any:
        - kind: thisKindDoesNotExist
          patterns:
            - '(?i)^x'
    set:
      Tier: 1
'@

        # A rule that parses, loads, and has nothing to match on.
        Set-Content -LiteralPath (Join-Path $endpointDir 'EmptyDetections.locked.yaml') -Encoding ASCII -Value @'
id: EmptyDetections
appliesTo: endpoint
mode: locked
purpose: test
category: test
detections:
'@

        # A rule that is legitimately empty: the customer suppressed it.
        Set-Content -LiteralPath (Join-Path $endpointDir 'SuppressedRule.custom.yaml') -Encoding ASCII -Value @'
id: SuppressedRule
appliesTo: endpoint
mode: disable
'@

        # A well-formed rule, so the healthy path is exercised in the same tree.
        Set-Content -LiteralPath (Join-Path $endpointDir 'GoodRule.locked.yaml') -Encoding ASCII -Value @'
id: GoodRule
appliesTo: endpoint
mode: locked
purpose: test
category: test
detections:
  - id: GoodRule
    detect:
      any:
        - kind: nameMatches
          namePatterns:
            - '(?i)^dc\d'
    set:
      Tier: 0
'@
        $script:Warnings = @()
        $null = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:Scratch -WarningVariable +wv -WarningAction SilentlyContinue
        $script:Warnings = @($wv | ForEach-Object { [string]$_ })
    }

    AfterAll {
        Remove-Item $script:Scratch -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'warns that an unknown detect kind will be skipped, and names it (#35)' {
        ($script:Warnings -join "`n") | Should -Match 'NOT in the RuleEval registry'
        ($script:Warnings -join "`n") | Should -Match 'thisKindDoesNotExist'
    }

    It 'warns that a rule loaded with zero detections, and names the file (#36)' {
        ($script:Warnings -join "`n") | Should -Match 'ZERO detections'
        ($script:Warnings -join "`n") | Should -Match 'EmptyDetections'
    }

    It 'does NOT flag mode: disable as a zero-detection rule (suppression is deliberate)' {
        $zeroWarn = @($script:Warnings | Where-Object { $_ -match 'ZERO detections' })
        ($zeroWarn -join "`n") | Should -Not -Match 'SuppressedRule'
    }

    It 'stays QUIET on a healthy rule tree -- a warning that always fires gets ignored like the last one did' {
        $healthy = Join-Path ([System.IO.Path]::GetTempPath()) ('si-ruleset-ok-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $healthy 'asset-profiling-enrichment\endpoint'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Copy-Item (Join-Path $script:Scratch 'asset-profiling-enrichment\endpoint\GoodRule.locked.yaml') $dir
            $wv2 = @()
            $null = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $healthy -WarningVariable +wv2 -WarningAction SilentlyContinue
            @($wv2) | Should -BeNullOrEmpty
        } finally {
            Remove-Item $healthy -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
