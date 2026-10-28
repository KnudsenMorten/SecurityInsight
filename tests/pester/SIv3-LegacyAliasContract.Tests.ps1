#Requires -Version 5.1
<#
    ONE NAME FOR ONE THING IN THE DATA STRUCTURE -- SI_AssetName / SI_AssetId, and no second spelling.

    🔑 THE RULE, AND WHERE IT APPLIES. There are two layers and they have different contracts:

      * PROFILE TABLES (the four SI_*_Profile_CL). Exactly ONE asset-name column and ONE asset-id
        column, both SI_-prefixed. No `AssetName`, no `AssetId`.
      * RA REPORT OUTPUT (what a customer opens). Exactly the OLD names, `AssetName` / `AssetId`,
        filled from the SI_ columns. This is a hard external contract -- ~6000 customers have reports,
        workbooks and saved queries bound to those headers, so the output layer must never rename and
        must never emit an SI_-prefixed column alongside.

    Both halves are asserted here, because "one name" is only true if BOTH hold. Dropping the legacy
    pair from the tables while letting an SI_ name leak into a report header would trade one
    inconsistency for a worse one.

    🔴 WHAT WAS WRONG BEFORE 2026-08-28. The profile schemas carried BOTH spellings, and the second one
    did not even work. All four declared `AssetId` with source `derived`; no builder implemented it --
    not one, on any engine, since inception. Azure had removed it deliberately ("always ==
    PrimaryEntityId, redundant") while its schema went on declaring it. So the field was promised
    everywhere and written nowhere.

    🪤 WHY THAT WAS INVISIBLE FROM BOTH ENDS. Log Analytics never creates a column that has no value on
    any row, so `AssetId` was not empty in the table -- it was ABSENT, and `column_ifexists("AssetId","")`
    in the RA catalog returned "" forever, with no error and no missing-column complaint. Downstream it
    surfaced as "only 38 of 431 Summary rows carry an id", which reads like sparse data rather than a
    field that cannot work. The same 38 explained the empty `ImpactedAssetIds`: nothing was broken in
    the ingest, the value simply was not there to send.

    📌 THE FIX WAS TO MOVE THE DEPENDENCIES, NOT TO KEEP A MIRROR. The legacy column had real readers --
    the correlation ingest projection, the Shodan owner enrichment's two Profile_CL projections, and the
    RA DeviceKey fallback chain. All four are our own code, so they were repointed at SI_AssetName and
    the duplicate was deleted rather than propped up.

    ⚠️ A PARSE CHECK WOULD NOT HAVE CAUGHT THE ORIGINAL DEFECT. While the mirror was briefly being
    ADDED (before the decision to delete instead), a here-string missing its trailing newline appended
    the new case onto the end of a COMMENT line. The file parsed clean and the case did not exist. That
    is why the resolution tests below run the builder in a real PS 5.1 child process rather than
    inspecting source text.
#>

# 🪤 Container scope, not BeforeAll: Pester evaluates -ForEach during DISCOVERY, before any BeforeAll
# body runs, so a $script: variable set there is still empty and every case silently vanishes.
$script:SwitchEngines = @(
    @{ Engine = 'endpoint'; Builder = 'Build-EndpointProfileRow.ps1'; NameKey = 'MDE_DeviceName';    Expect = 'probe-host'  }
    @{ Engine = 'identity'; Builder = 'Build-IdentityProfileRow.ps1'; NameKey = 'ENTRA_DisplayName'; Expect = 'probe-user'  }
    @{ Engine = 'publicip'; Builder = 'Build-PublicIpProfileRow.ps1'; NameKey = 'IP_AssetName';      Expect = 'probe-owner' }
)
$script:AllSchemas = @(
    @{ Engine = 'endpoint'; Schema = 'endpoint.schema.locked.json'  }
    @{ Engine = 'identity'; Schema = 'identity.schema.locked.json'  }
    @{ Engine = 'azure';    Schema = 'azure.schema.locked.json'     }
    @{ Engine = 'publicip'; Schema = 'public-ip.schema.locked.json' }
)

BeforeAll {
    # <SI>/tests/pester/<file> -> up THREE levels to the solution root.
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Shared    = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'
    $script:SchemaDir = Join-Path $script:SIRootDir 'asset-profiling-schema'

    function script:Resolve-InChild {
        param([string]$BuilderFile, [string]$FieldName, [string]$ProbeId = 'PROBE-ID-42', [hashtable]$Meta = @{})
        $builder = Join-Path $script:Shared $BuilderFile
        $metaLit = ($Meta.GetEnumerator() | ForEach-Object { "'{0}'='{1}'" -f $_.Key, $_.Value }) -join '; '
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$builder'
`$ctx = @{ Record = [pscustomobject]@{ Metadata = @{ $metaLit } }; PrimaryEntityId = '$ProbeId'
           Verdict = `$null; EgNodeId = ''
           # 🔴 WAS EntityIds = @(), and that emptiness was a FIXTURE BLIND SPOT. SI_AssetName and
           # SI_AssetId are now resolved as a PAIR from one source, so a name is only usable when that
           # same source's identifier is present. A real endpoint row always carries these; this
           # fixture did not, because the old separate name-chain never read them.
           EntityIds = @(@{type='MdeDeviceId';id='$ProbeId'},@{type='AadDeviceId';id='aad-fx'},@{type='AzureResourceId';id='az-fx'},@{type='EgNodeId';id='eg-fx'})
           RunContext = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z' } }
`$v = Get-SIDerivedValue -Field ([pscustomobject]@{ name = '$FieldName' }) -Context `$ctx
'<R>' + `$(if (`$null -eq `$v -or "`$v" -eq '') { '<EMPTY>' } else { "`$v" })
"@
        $out  = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd 2>&1
        $line = @($out) | Where-Object { "$_" -like '<R>*' } | Select-Object -Last 1
        if (-not $line) { throw ("child produced nothing; tail: " + (($out | Select-Object -Last 5) -join ' | ')) }
        ([string]$line) -replace '^<R>',''
    }
}

Describe 'the profile schemas carry ONE asset-name and ONE asset-id column' {

    It '<Engine>: declares the SI_ pair and neither legacy spelling' -ForEach $script:AllSchemas {
        $j = Get-Content (Join-Path $script:SchemaDir $_.Schema) -Raw | ConvertFrom-Json
        $names = @($j.fields.name)
        $names | Should -Contain 'SI_AssetName'
        $names | Should -Contain 'SI_AssetId'
        # -cnotcontains: the comparison must be case-SENSITIVE, or 'assetname' would satisfy it.
        $names | Should -Not -Contain 'AssetName' -Because 'the legacy mirror was removed 2026-08-28; one name for one thing'
        $names | Should -Not -Contain 'AssetId'   -Because 'declared on all four engines and built by none -- deleted, not repaired'
    }
}

Describe 'the SI_ columns actually resolve -- absence of the mirror must not mean absence of a value' {

    It '<Engine>: SI_AssetName resolves from its own source' -ForEach $script:SwitchEngines {
        $meta = @{ $_.NameKey = $_.Expect }
        $v = script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SI_AssetName' -Meta $meta
        $v | Should -BeExactly $_.Expect
    }

    It '<Engine>: SI_AssetId resolves and TRACKS its source' -ForEach $script:SwitchEngines {
        # A case returning a constant would pass a mere non-empty check. Vary the input and require the
        # output to follow -- that is what a mirror of PrimaryEntityId must do.
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SI_AssetId' -ProbeId 'PROBE-A') | Should -BeExactly 'PROBE-A'
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'SI_AssetId' -ProbeId 'PROBE-B') | Should -BeExactly 'PROBE-B'
    }

    It '<Engine>: the legacy spelling resolves to NOTHING' -ForEach $script:SwitchEngines {
        # If a builder still answered for the old name, the column would quietly reappear in the table
        # the moment any row carried a value -- and the duplication would be back.
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'AssetName' -Meta @{ 'MDE_DeviceName' = 'x' }) | Should -Be '<EMPTY>'
        (script:Resolve-InChild -BuilderFile $_.Builder -FieldName 'AssetId') | Should -Be '<EMPTY>'
    }
}

Describe 'no builder writes a legacy row column' {

    It 'no Build-*ProfileRow.ps1 assigns $row[AssetName] or $row[AssetId]' {
        # Azure builds its row inline rather than through the field switch, so the switch tests above
        # cannot see it. Its synthetic-name fallback used to fill $row['AssetName']; it now fills
        # $row['SI_AssetName'], and its key map resolves SI_AssetName from AZ_Name directly.
        $offenders = @()
        foreach ($f in Get-ChildItem -Path $script:Shared -Filter 'Build-*ProfileRow.ps1') {
            foreach ($m in [regex]::Matches((Get-Content $f.FullName -Raw), '(?m)^(?<line>.*\$row\[.(?:AssetName|AssetId).\]\s*=.*)$')) {
                $offenders += ('{0}: {1}' -f $f.Name, $m.Groups['line'].Value.Trim())
            }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'the azure key map resolves SI_AssetName, not the legacy name' {
        # Azure resolves only fields the SCHEMA declares. With the legacy field deleted, a map entry
        # still keyed 'AssetName' would resolve nothing at all and SI_AssetName would ship empty --
        # a silent regression that looks identical to "this estate has no names".
        $raw = Get-Content (Join-Path $script:Shared 'Build-AzureProfileRow.ps1') -Raw
        $raw | Should -Match "'SI_AssetName'\s*=\s*@\('AZ_Name'\)"
        $raw | Should -Not -Match "(?m)^\s*'AssetName'\s*=\s*@\("
    }
}

Describe 'the readers were MOVED to the SI_ column, not left pointing at a deleted one' {

    It 'the correlation ingest projection reads SI_AssetName' {
        # Correlation is a Pro engine: absent from the Community edition, checked where it exists.
        $corrIngest = Join-Path $script:SIRootDir 'engine\asset-correlation\_shared\SI-CorrelationIngest.ps1'
        if (-not (Test-Path -LiteralPath $corrIngest)) { Set-ItResult -Skipped -Because 'SecurityInsight Pro is not in this copy'; return }
        $raw = Get-Content $corrIngest -Raw
        $raw | Should -Match 'column_ifexists\("SI_AssetName", ""\)'
    }

    It 'both Shodan owner-enrichment projections read SI_AssetName' {
        # Two projections -- one over SI_Endpoint_Profile_CL, one over SI_Azure_Profile_CL. Assert BOTH:
        # this enrichment is what supplies the publicip owner name, and it had already failed silently
        # once when its source stopped being populated.
        $raw = Get-Content (Join-Path $script:SIRootDir 'engine\asset-profiling\discovery\Get-DiscoveryFromShodan.ps1') -Raw
        @([regex]::Matches($raw, 'AssetName = coalesce\(tostring\(column_ifexists\("SI_AssetName", ""\)\)')).Count |
            Should -Be 2
    }

    It 'the RA DeviceKey fallback chain prefers SI_AssetName' {
        $raw = Get-Content (Join-Path $script:SIRootDir 'engine\risk-analysis\_shared\RA-BucketFilters.ps1') -Raw
        $raw | Should -Match "column_ifexists\('SI_AssetName',''\)"
    }
}

Describe 'the customer-facing report contract is UNCHANGED' {

    It 'the RA catalog outputs the old names only -- never an SI_ one' {
        # This is the half that protects ~6000 customers. Renaming a report header, or adding a second
        # asset-name column beside it, breaks saved workbooks and queries that we do not control.
        $yaml = Get-Content (Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') -Raw
        @([regex]::Matches($yaml, "(?m)^\s+- SI_AssetName\s*$")).Count | Should -Be 0
        @([regex]::Matches($yaml, "(?m)^\s+- SI_AssetId\s*$")).Count   | Should -Be 0
        @([regex]::Matches($yaml, "(?m)^\s+- AssetName\s*$")).Count    | Should -BeGreaterThan 50
        @([regex]::Matches($yaml, "(?m)^\s+- AssetId\s*$")).Count      | Should -BeGreaterThan 50
    }

    It 'the catalog reads the CI''s asset fields to fill those old headers' {
        # The bridge between the two layers. If these reads disappeared, the headers would survive and
        # silently go empty -- which is exactly the failure this whole change fixes.
        # #505 -- the reports fill them from the CI (si_asset_name / si_ci_id, SI_CI_CL) instead of the profile
        # tables' SI_AssetName / SI_AssetId. Counted outside the canonical CI blocks, which project those fields.
        $yaml = Get-Content (Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') -Raw
        $outside = [regex]::Replace($yaml, '(?s)//__SI_CI_(LINK|ASSET)_BEGIN__.*?//__SI_CI_\1_END__', '')
        @([regex]::Matches($outside, '(?m)\bAssetName\s*=[^\r\n]*\bsi_asset_name\b')).Count | Should -BeGreaterThan 50
        @([regex]::Matches($outside, '(?m)\bAssetId\s*=[^\r\n]*\bsi_ci_id\b')).Count         | Should -BeGreaterThan 50
    }
}
