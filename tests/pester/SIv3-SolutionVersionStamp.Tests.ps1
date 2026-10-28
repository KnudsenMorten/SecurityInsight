#Requires -Version 5.1
<#
    EVERY PROFILE ROW CARRIES THE RELEASE THAT PRODUCED IT.

    🔴 WHY (V3-HANDOFF task V3-6). `si-v3` and `main`/prod write the **same Log Analytics workspace and
    the same four profile tables**, and the nightly runs the RELEASED code. Risk Analysis has stamped
    `SolutionVersion` since v2.1, and that stamp is what exposed the two trees interleaving — 2.2.460 at
    13:58, then 2.2.457 at 23:22, **the version running BACKWARDS as time runs forwards.**

    🪤 The profile tables had no stamp, so the identical contamination was undetectable there. Every
    profile measurement taken before 2026-08-28 — the four-engine coverage tables, the `SI_AssetName` /
    `SI_AssetId` percentages — used `max(CollectionTime)` with no way to know which tree wrote the rows.
    They happened to be right. **"Happened to be right" is not attributable**, and the RA tables prove
    the contamination is real rather than theoretical.

    🔑 WHAT IS ASSERTED. Not that the value equals some literal — that would pin the test to today's
    release and fail on every bump. What must hold is that **the column is declared, resolves, and
    equals the VERSION file the tree actually ships**. That is the property an operator relies on when
    they run `| distinct SolutionVersion` to answer "which tree wrote this?".

    ⚠️ A PARSE CHECK IS NOT ENOUGH, so these run the builder in a real PS 5.1 child process. Earlier the
    same day, a here-string missing its trailing newline put a new `case` INSIDE a comment: the file
    parsed clean and the case did not exist.
#>

# 🪤 Container scope — Pester evaluates -ForEach at DISCOVERY, before any BeforeAll body runs.
$script:SwitchBuilders = @(
    @{ Engine = 'endpoint'; Builder = 'Build-EndpointProfileRow.ps1' }
    @{ Engine = 'identity'; Builder = 'Build-IdentityProfileRow.ps1' }
    @{ Engine = 'publicip'; Builder = 'Build-PublicIpProfileRow.ps1' }
)
$script:Schemas = @(
    @{ Engine = 'endpoint'; Schema = 'endpoint.schema.locked.json'  }
    @{ Engine = 'identity'; Schema = 'identity.schema.locked.json'  }
    @{ Engine = 'azure';    Schema = 'azure.schema.locked.json'     }
    @{ Engine = 'publicip'; Schema = 'public-ip.schema.locked.json' }
)

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Shared    = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'
    $script:SchemaDir = Join-Path $script:SIRootDir 'asset-profiling-schema'
    $script:Expected  = (Get-Content (Join-Path $script:SIRootDir 'VERSION') -Raw).Trim()

    function script:Resolve-InChild {
        param([string]$BuilderFile, [string]$FieldName)
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$(Join-Path $script:Shared $BuilderFile)'
`$ctx = @{ Record = [pscustomobject]@{ Metadata = @{} }; PrimaryEntityId = 'PROBE'
           Verdict = `$null; EntityIds = @(); EgNodeId = ''
           RunContext = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z' } }
`$v = Get-SIDerivedValue -Field ([pscustomobject]@{ name = '$FieldName' }) -Context `$ctx
'<R>' + `$(if (`$null -eq `$v) { '<NULL>' } else { "`$v" })
"@
        $out  = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd 2>&1
        $line = @($out) | Where-Object { "$_" -like '<R>*' } | Select-Object -Last 1
        if (-not $line) { throw ("child produced nothing; tail: " + (($out | Select-Object -Last 5) -join ' | ')) }
        ([string]$line) -replace '^<R>',''
    }
}

Describe 'the version stamp is declared on every profile table' {

    It '<Engine>: schema declares SolutionVersion' -ForEach $script:Schemas {
        $j = Get-Content (Join-Path $script:SchemaDir $_.Schema) -Raw | ConvertFrom-Json
        @($j.fields.name) | Should -Contain 'SolutionVersion' -Because 'without it a profile row cannot be attributed to the tree that wrote it (V3-6)'
        $f = @($j.fields | Where-Object { $_.name -ceq 'SolutionVersion' })
        $f.Count     | Should -Be 1
        $f[0].source | Should -Be 'derived'
    }
}

Describe 'and it RESOLVES to the version this tree actually ships' {

    It '<Engine>: SolutionVersion is the VERSION file plus this tree''s edition marker' -ForEach $script:SwitchBuilders {
        # Deliberately derived from the VERSION file rather than a literal: pinning the literal would
        # make this fail on every release bump, which trains people to edit the test.
        #
        # 🔴 THE ASSERTION CHANGED ON 2026-08-31, AND THE OLD ONE WAS THE PROBLEM. It required the
        # stamp to EQUAL the VERSION file -- which is exactly what made this column unable to do its
        # own job. `si-v3` and `main` both ship VERSION 2.2.460, so both stamped "2.2.460" and the
        # tree that wrote a row became unknowable again precisely when the branch is closest to
        # shipping. The header's own evidence (2.2.460 at 13:58, 2.2.457 at 23:22) only works while
        # the two trees differ.
        # The v3 tree now stamps "<version>+v3". The VERSION file itself does NOT move -- it is the
        # customer-sync contract -- so what is asserted is the file's value PLUS the marker.
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SolutionVersion') |
            Should -BeExactly ('{0}+v3' -f $script:Expected)
    }

    It '<Engine>: the marker does not swallow the release number' -ForEach $script:SwitchBuilders {
        # The point of the stamp is still "which RELEASE produced this row". A marker that replaced
        # the version, rather than extending it, would trade one blindness for another.
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SolutionVersion') |
            Should -BeLike ('{0}*' -f $script:Expected)
    }

    It 'the VERSION file itself stays a bare release number' {
        # 🔒 The sync contract. Customers pull on a VERSION check, so a marker written INTO the file
        # would ship v3 to ~30 customers on their next nightly sync. The marker belongs in the
        # stamped value only.
        $script:Expected | Should -Not -Match '\+v3'
        $script:Expected | Should -Match '^\d+\.\d+\.\d+$'
    }

    It '<Engine>: it is never the (dev) sentinel in this tree' -ForEach $script:SwitchBuilders {
        # '(dev)' is the legitimate answer when no VERSION file exists. In THIS repo one does, so the
        # sentinel here means the walk-up broke -- and a table full of '(dev)' is exactly as unusable
        # as no stamp at all.
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SolutionVersion') |
            Should -Not -Be '(dev)'
    }
}

Describe 'azure stamps it inline, because it does not use the field switch' {

    It 'assigns SolutionVersion from the shared helper' {
        # Azure builds its row inline. A hand-rolled version read here would drift from the other three
        # the first time the resolution rule changed -- which is the whole reason the helper exists.
        $raw = Get-Content (Join-Path $script:Shared 'Build-AzureProfileRow.ps1') -Raw
        $raw | Should -Match "\`$row\['SolutionVersion'\]\s*=\s*Get-SISolutionVersion"
    }
}

Describe 'the resolver prefers the per-solution VERSION over the repo-root label' {

    It 'rejects the bootstrap compound sync label' {
        # 🪤 The repo-root VERSION.txt is stamped with e.g.
        #   "AutomateIT-internal-main-<sha> (solutions: ... SecurityInsight-v2.2.221) @ 2026-05-13..."
        # That leaked into RA's stamp once and confused operators who wanted "2.2.225". The helper must
        # skip it, or the profile tables inherit the same defect RA already paid for.
        $raw = Get-Content (Join-Path $script:Shared 'SI-SolutionVersion.ps1') -Raw
        $raw | Should -Match "notmatch\s+'\^AutomateIT-'"
        $raw | Should -Match "VERSION'\s*,\s*'VERSION\.txt'"
    }
}
