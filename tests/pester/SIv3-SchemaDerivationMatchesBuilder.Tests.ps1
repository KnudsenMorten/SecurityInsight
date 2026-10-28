#Requires -Version 5.1
<#
    THE SCHEMA'S derivation.algorithm MUST DESCRIBE THE CHAIN THE BUILDER ACTUALLY WALKS.

    🔴 THE GAP THIS CLOSES (V3-HANDOFF task 6). Each schema field carries a prose
    `derivation.algorithm` -- and nothing tested it. The dead-candidate guard proves a candidate CAN
    be populated; it says nothing about whether the builder implements what the schema DECLARES. So
    the two drift, silently, in the direction of whoever edited last.

    🪤 AND THIS FILE EXISTS BECAUSE THE DRIFT HAPPENED WHILE CLOSING THE PREVIOUS TASK. On 2026-08-28
    four dead candidates were removed from the endpoint and identity chains. Every test stayed green
    and the schemas went on describing the OLD chains for hours:

        endpoint schema still said:  ... > AD_DnsHostName > AD_Name > ...
        identity schema still said:  ... > AD_DisplayName > AD_SamAccountName > ... > ENTRA_AppId

    Both were corrected in the same change as this guard. The lesson is not that someone was careless
    -- it is that PROSE NOBODY EXECUTES CANNOT STAY TRUE, so it has to be executed.

    🔑 WHAT IS ASSERTED, AND WHAT DELIBERATELY IS NOT. The algorithm text is prose and will stay prose;
    testing its English is neither possible nor useful. What IS machine-checkable is the set of
    METADATA KEYS it names -- `ENTRA_DisplayName`, `MDE_DeviceName`, `AZ_Name`, ... -- against the keys
    the builder actually reads for that field. That is precisely the part that drifted, and precisely
    the part a reader trusts when deciding where a value comes from.

    📌 SCOPED TO SI_AssetName ON PURPOSE. It is the field with a real multi-source chain, the one whose
    drift produced 59 blank names, and the one four engines share. Widening this to every field would
    need every algorithm rewritten into a parseable form first -- a different and much larger job, and
    one that should not be started by a guard.
#>

# 🪤 DEFINED AT CONTAINER SCOPE, NOT IN BeforeAll. Pester evaluates -ForEach during DISCOVERY, which
# runs before any BeforeAll body, so a $script: variable set in BeforeAll is still empty and every
# case is skipped -- or, in Pester 6, the whole container fails on a null ForEach. Caught on this
# file's first run.
# engine key -> (builder file, schema file). publicip is excluded: its SI_AssetName takes a single
# value carried by discovery (IP_AssetName), not a multi-source chain, so there is no key list to
# compare. Its behaviour is pinned by SIv3-PublicIpOwnerAttribution.Tests.ps1 instead.
$script:Pairs = @(
    @{ Engine = 'endpoint'; Builder = 'Build-EndpointProfileRow.ps1'; Schema = 'endpoint.schema.locked.json' }
    @{ Engine = 'identity'; Builder = 'Build-IdentityProfileRow.ps1'; Schema = 'identity.schema.locked.json' }
)

BeforeAll {
    $script:SIRoot    = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:SIRootDir = Split-Path -Parent $script:SIRoot
    $script:Shared    = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'
    $script:SchemaDir = Join-Path $script:SIRootDir 'asset-profiling-schema'

    # Keys the BUILDER reads inside the SI_AssetName candidate list.
    function script:Get-BuilderChainKeys {
        param([string]$BuilderFile)
        $raw = Get-Content (Join-Path $script:Shared $BuilderFile) -Raw

        # TWO SHAPES, because the endpoint builder moved to the PAIRED resolver.
        #   * `$candidates = @( & $get $meta 'KEY' ... )`   -- identity / publicip / azure, unchanged
        #   * `$chain = @( @{ NameKeys = 'KEY'; IdType = ... } ... )` -- endpoint, since 2026-08-28,
        #     where SI_AssetName and SI_AssetId are resolved TOGETHER from one source so the id cannot
        #     be chosen apart from the name (operator: "name drives id as id can change").
        # 🔑 The KEY SET and its ORDER are the contract this guard exists to protect, and both are
        # unchanged by that move -- only where they are written changed. Reading just one shape would
        # have made the guard throw rather than compare, which is a guard failing OPEN.
        $m = [regex]::Match($raw, '(?s)\$candidates\s*=\s*@\((?<body>.*?)\r?\n\s*\)')
        $pattern = "\`$get\s+\`$meta\s+'([A-Za-z0-9_]+)'"
        if (-not $m.Success) {
            $m = [regex]::Match($raw, '(?s)\$chain\s*=\s*@\((?<body>.*?)\r?\n\s*\)')
            $pattern = "NameKeys\s*=\s*'([A-Za-z0-9_;\s]+)'"
        }
        if (-not $m.Success) { throw "neither a `$candidates nor a `$chain block was found in $BuilderFile" }
        $body = $m.Groups['body'].Value
        # drop full-line comments -- the block documents the keys it REMOVED, and counting those would
        # make the guard assert the very drift it exists to catch.
        $code = ($body -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $keys = New-Object System.Collections.ArrayList
        foreach ($k in [regex]::Matches($code, $pattern)) {
            # NameKeys may hold several keys for one source, separated by ';'
            foreach ($one in ($k.Groups[1].Value -split ';')) {
                $t = $one.Trim()
                if ($t) { [void]$keys.Add($t) }
            }
        }
        @($keys)
    }

    # Metadata keys the SCHEMA's algorithm prose names.
    function script:Get-SchemaChainKeys {
        param([string]$SchemaFile)
        $j = Get-Content (Join-Path $script:SchemaDir $SchemaFile) -Raw | ConvertFrom-Json
        $fld = $j.fields | Where-Object { $_.name -eq 'SI_AssetName' }
        if (-not $fld) { throw "SI_AssetName not declared in $SchemaFile" }
        $algo = [string]$fld.derivation.algorithm
        $keys = New-Object System.Collections.ArrayList
        foreach ($k in [regex]::Matches($algo, '(?<![A-Za-z_])(AD_[A-Za-z0-9]+|ENTRA_[A-Za-z0-9]+|MDE_[A-Za-z0-9]+|AZ_[A-Za-z0-9]+|EG_[A-Za-z0-9]+)(?![A-Za-z0-9_])')) {
            [void]$keys.Add($k.Groups[1].Value)
        }
        @($keys)
    }
}

Describe 'SI_AssetName -- the declared chain equals the implemented chain' {

    It '<Engine>: every key the schema names is one the builder reads' -ForEach $script:Pairs {
        $builderKeys = @(script:Get-BuilderChainKeys -BuilderFile $_.Builder)
        $schemaKeys  = @(script:Get-SchemaChainKeys  -SchemaFile  $_.Schema)
        $orphans = @($schemaKeys | Where-Object { $_ -cnotin $builderKeys })
        $orphans.Count | Should -Be 0 -Because "the schema promises $($orphans -join ', ') but the builder never reads it -- that is the drift"
    }

    It '<Engine>: every key the builder reads is one the schema names' -ForEach $script:Pairs {
        # The other direction matters just as much: an UNDOCUMENTED candidate means a reader cannot
        # tell where a value came from, which is how a dead terminal candidate survived unnoticed.
        $builderKeys = @(script:Get-BuilderChainKeys -BuilderFile $_.Builder)
        $schemaKeys  = @(script:Get-SchemaChainKeys  -SchemaFile  $_.Schema)
        $undocumented = @($builderKeys | Where-Object { $_ -cnotin $schemaKeys })
        $undocumented.Count | Should -Be 0 -Because "the builder reads $($undocumented -join ', ') and the schema never mentions it"
    }

    It '<Engine>: the declared ORDER is the implemented order' -ForEach $script:Pairs {
        # Priority is the whole point of a candidate chain -- the same keys in a different order is a
        # different rule. Compared as sequences, not sets.
        $builderKeys = @(script:Get-BuilderChainKeys -BuilderFile $_.Builder)
        $schemaKeys  = @(script:Get-SchemaChainKeys  -SchemaFile  $_.Schema)
        ($schemaKeys -join ' > ') | Should -BeExactly ($builderKeys -join ' > ')
    }

    It '<Engine>: the chain is not empty -- the guard must fail loudly if parsing breaks' -ForEach $script:Pairs {
        # 🪤 Without this, a regex that silently matches nothing makes every assertion above pass by
        # comparing two empty lists. A guard that cannot fail is worse than no guard.
        @(script:Get-BuilderChainKeys -BuilderFile $_.Builder).Count | Should -BeGreaterThan 2
        @(script:Get-SchemaChainKeys  -SchemaFile  $_.Schema).Count  | Should -BeGreaterThan 2
    }
}
