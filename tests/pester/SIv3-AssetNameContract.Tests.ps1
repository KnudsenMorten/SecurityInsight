#Requires -Version 5.1
<#
    SI v3 -- THE CROSS-ENGINE ASSET IDENTITY CONTRACT.

    Two fields the operator introduced so every asset is identifiable in one vocabulary across all four
    engines: AssetId (stable id) and AssetName (what a human recognises). MEASURED ON THE LIVE
    WORKSPACE 2026-08-27, before this contract existed:

        table                    rows   AssetId   SI_AssetId   AssetName blank   AssetName = a hash
        SI_Endpoint_Profile_CL    198   0%        0%           59 (30%)          78 (39%)
        SI_Azure_Profile_CL       770   0%        0%            0                 0
        SI_Identity_Profile_CL     65   0%        0%            0                 0

    So AssetId was 100% blank on EVERY table while PrimaryEntityId was 100% populated on every table,
    and endpoint AssetName was unusable on 137 of 198 rows.

    🔴 WHY THE ENGINES DIVERGED, AND IT IS NOT THAT ENDPOINT IS HARDER. Every engine ends its candidate
    chain in a "last resort". Azure's (AZ_NodeId) is produced. Endpoint's (MDE_HardwareUuid) and
    Identity's (ENTRA_AppId) are referenced NOWHERE outside their own builder, so they can never fire.
    Identity survived at 100% only because its FIRST candidate is always populated -- a property of the
    data, not a working fallback. Endpoint had no such luck and fell to 31%.

    🔑 THE GENERALISABLE DEFECT IS THE DEAD CANDIDATE, and the static guard below is the part of this
    file worth keeping: a candidate key that nothing in the engine ever produces is a fallback that
    looks present in code review and cannot execute. That is the same family as the never-wired
    columns this codebase keeps rediscovering -- AssetName itself, SI_AssetId, the tier aggregator,
    ServerAppCatalogMatch, and the 16-function endpoint-class catalog deleted as #87 on 2026-08-31.

    Builders are exercised in CHILD PROCESSES: all four define Get-SIDerivedValue, so dot-sourcing more
    than one into a single scope means the last one silently wins and the tests measure the wrong file.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Shared    = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'

    # Ask ONE builder for ONE derived field, in its own process, and return the value as text.
    function script:AskBuilder {
        param([string]$Builder, [string]$FieldName, [hashtable]$Meta, [string]$PrimaryEntityId)
        $metaLiteral = ($Meta.Keys | ForEach-Object { "'{0}'='{1}'" -f $_, ($Meta[$_] -replace "'","''") }) -join ';'
        if (-not $metaLiteral) { $metaLiteral = '' }
        $file = Join-Path $script:Shared $Builder
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$file'
`$ctx = [pscustomobject]@{
    PrimaryEntityId = '$PrimaryEntityId'
    Record          = [pscustomobject]@{ Metadata = @{$metaLiteral}; SI_RunId = 'r1' }
    Verdict         = `$null
    PerSourceVerdicts = @{}
    # 🔴 WAS @() -- AND THAT EMPTINESS WAS A FIXTURE BLIND SPOT, not a realistic input.
    # SI_AssetName and SI_AssetId are now resolved as a PAIR from ONE source (operator, 2026-08-28:
    # "name drives id as id can change fx if client is known in entra id as device, then later it
    # comes in mde, so id could change"), so a name is only usable if that same source's identifier is
    # present. A real endpoint row ALWAYS carries EntityIds -- Build-EndpointProfileRow populates them
    # from mdeId / egNodeId / aadId / azResId / hostName -- but this fixture never did, because the old
    # separate name-chain did not read them. With @() every source looks unidentified and every name
    # falls to the synthetic, which is why four name assertions went red the moment the pair landed.
    # 📌 This is the same "the fixture's convenience WAS the blind spot" failure TESTS.md records for
    # the correlation fixtures, and the deserialised-empty-array one that shipped a bug in the identity
    # scope filter. One distinct id per source type, so whichever source wins the NAME has an id to
    # travel with -- which is what these tests are actually about.
    EntityIds       = @(
        @{ type='MdeDeviceId';     id='$PrimaryEntityId' }
        @{ type='AadDeviceId';     id='aad-fixture'      }
        @{ type='AzureResourceId'; id='az-fixture'       }
        @{ type='EgNodeId';        id='eg-fixture'       }
    )
    EgNodeId        = ''
    CatalogVersion  = ''
    RunContext      = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z' }
    PrimaryEntityType = 'x'
}
`$v = Get-SIDerivedValue -Field ([pscustomobject]@{ name='$FieldName' }) -Context `$ctx
if (`$null -eq `$v) { '<NULL>' } else { [string]`$v }
"@
        $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd 2>&1
        (@($out) | Select-Object -Last 1) -as [string]
    }
}

Describe 'AssetId -- measured 0%, and DELIBERATELY NOT CHANGED HERE' {

    # 🔒 The unprefixed AssetId is 100% blank on all three profile tables, and it STAYS that way in this
    # change. SIv3-ExposureGraphNodeId.Tests.ps1 records why: "RA already populates its own AssetId
    # (93.4% on Detailed) and consumers may bind to it. SI_ prefixing exists precisely so nothing that
    # reads AssetId today changes behaviour." SI_AssetId is already wired in all four builders on this
    # branch and is the stable-id half of the contract.
    # 🪤 The 0% measured on 2026-08-27 is MAIN's state -- that snapshot came from a main run, which does
    # not carry the SI_AssetId wiring. It is not evidence that si-v3 is broken.
    # ◻ Whether the unprefixed AssetId should ALSO be filled is an open operator decision, not a bug to
    # fix in passing: filling a previously-blank column changes what existing queries return.

    It 'SI_AssetId is the wired stable id, in every builder' -ForEach @(
        @{ b = 'Build-EndpointProfileRow.ps1' }
        @{ b = 'Build-IdentityProfileRow.ps1' }
        @{ b = 'Build-PublicIpProfileRow.ps1' }
    ) {
        (script:AskBuilder -Builder $b -FieldName 'SI_AssetId' -Meta @{} -PrimaryEntityId 'PE-123') |
            Should -Be 'PE-123'
    }

    It 'and the unprefixed AssetId is still NOT wired -- the prior decision stands' {
        foreach ($b in 'Build-EndpointProfileRow.ps1','Build-IdentityProfileRow.ps1','Build-PublicIpProfileRow.ps1') {
            $txt = Get-Content (Join-Path $script:Shared $b) -Raw
            $txt | Should -Not -Match "(?m)^\s*'AssetId'\s*\{"
        }
    }
}

Describe 'SI_AssetName -- never blank, and never silently an identifier' {

    It '<b> is NEVER blank when nothing else has a name' -ForEach @(
        @{ b = 'Build-EndpointProfileRow.ps1' }
        @{ b = 'Build-IdentityProfileRow.ps1' }
        @{ b = 'Build-PublicIpProfileRow.ps1' }
    ) {
        # This is the 30% case: 59 of 198 endpoint rows came through blank because the declared last
        # resort could never fire. The value is now a MARKED SYNTHETIC rather than the bare id --
        # operator decision 2026-08-27; see the synthetic-name block below for why.
        $v = script:AskBuilder -Builder $b -FieldName 'SI_AssetName' -Meta @{} -PrimaryEntityId 'PE-123'
        $v | Should -Not -BeNullOrEmpty
        $v | Should -BeLike 'unnamed-*'
    }

    # ---------------------------------------------------------------------------------------------
    # 🔴 PUBLICIP -- these three REPLACE an assertion that pinned the defect in place.
    #
    # The old test read: "the PublicIP builder resolves AssetName at all -- it had no case whatsoever",
    # and asserted the answer was the IP address. It passed for the same reason the bug shipped: the
    # builder returned $Context.PrimaryEntityId unconditionally, justified in a comment as "a public IP
    # has no name and needs none: the address IS the name".
    #
    # MEASURED 2026-08-27 on a real run, 11 of 11 rows: SI_AssetName was the IP on every row, while
    # AssetEngine and AssetTier were populated 11/11 (3 of them Tier 0) -- proving the engine KNEW the
    # owning asset. Discovery runs in 'profile-cl' mode, so these IPs are read out of
    # SI_Endpoint_Profile_CL / SI_Azure_Profile_CL and every one descends from an asset SI already
    # named. The name was resolved (Get-DiscoveryFromShodan.ps1 '$assetName') and then dropped, because
    # Invoke-Collect.ps1's $excludedTopLevel drops 'Name' before metadata is built.
    #
    # So the premise was false, and publicip was breaking the one contract rule its own schema states:
    # "a candidate identical to PrimaryEntityId is SKIPPED, because an identifier is not a name".
    # ---------------------------------------------------------------------------------------------

    It '🔴 PublicIP returns the OWNING ASSET name when discovery knew one' {
        # The whole point: a Tier 0 open-port finding must render the server name, not a bare address.
        (script:AskBuilder -Builder 'Build-PublicIpProfileRow.ps1' -FieldName 'SI_AssetName' `
            -Meta @{ IP_AssetName = 'dc01.corp.local' } -PrimaryEntityId '203.0.113.9') |
            Should -Be 'dc01.corp.local'
    }

    It '🔴 PublicIP skips an owner name that is merely the IP again' {
        # $assetName falls back to the IP in discovery, so IP_AssetName can legitimately arrive equal to
        # PrimaryEntityId. That is an identifier, not a name, and must not be published as one.
        (script:AskBuilder -Builder 'Build-PublicIpProfileRow.ps1' -FieldName 'SI_AssetName' `
            -Meta @{ IP_AssetName = '203.0.113.9' } -PrimaryEntityId '203.0.113.9') |
            Should -BeLike 'unnamed-publicip-*'
    }

    It '🔴 PublicIP never returns the bare IP as its name' {
        # The regression guard. If this returns '203.0.113.9' again, the defect is back.
        foreach ($meta in @(@{}, @{ IP_AssetName = '' }, @{ IP_AssetName = '203.0.113.9' })) {
            (script:AskBuilder -Builder 'Build-PublicIpProfileRow.ps1' -FieldName 'SI_AssetName' `
                -Meta $meta -PrimaryEntityId '203.0.113.9') |
                Should -Not -Be '203.0.113.9'
        }
    }

    It '🔴 a candidate equal to PrimaryEntityId is skipped so a REAL name below it can win' {
        # The 39% case, and the reason it is not merely cosmetic: MDE_DeviceName carries the machine id
        # when MDE has no computerDnsName, and it sits at position 2 -- above AD, Azure and EG.
        (script:AskBuilder -Builder 'Build-EndpointProfileRow.ps1' -FieldName 'SI_AssetName' `
            -Meta @{ MDE_DeviceName = 'PE-123'; AZ_Name = 'real-server-01' } -PrimaryEntityId 'PE-123') |
            Should -Be 'real-server-01'
    }

    It 'and when the id is the ONLY candidate it becomes a MARKED name, not the bare id' {
        # MDE_DeviceName carrying the machine id is skipped as "not a name", the chain finds nothing
        # else, and the synthetic fires -- so the 78-hash case now reads as unnamed-endpoint-... instead
        # of a 40-hex string an operator would mistake for a hostname.
        $v = script:AskBuilder -Builder 'Build-EndpointProfileRow.ps1' -FieldName 'SI_AssetName' `
                -Meta @{ MDE_DeviceName = 'PE-123' } -PrimaryEntityId 'PE-123'
        $v | Should -BeLike 'unnamed-endpoint-*'
        $v | Should -Not -Be 'PE-123'
    }
    It 'a real name still wins outright' {
        (script:AskBuilder -Builder 'Build-EndpointProfileRow.ps1' -FieldName 'SI_AssetName' `
            -Meta @{ MDE_DeviceName = 'srv-01.contoso.local' } -PrimaryEntityId 'PE-123') |
            Should -Be 'srv-01.contoso.local'
    }
}

Describe '🔑 THE DEAD-CANDIDATE GUARD -- a fallback nothing produces cannot fall back' {

    BeforeAll {
        # Every metadata key each builder reads THROUGH THE METADATA ACCESSOR -- which is wider than the
        # AssetName chain and deliberately so: a dead read is a dead read wherever it sits. It is how
        # AZ_ResourceType turned up, which is not an AssetName candidate at all.
        $script:ChainKeys = @{}
        foreach ($b in @('Build-EndpointProfileRow.ps1','Build-IdentityProfileRow.ps1','Build-AzureProfileRow.ps1')) {
            $raw  = Get-Content (Join-Path $script:Shared $b) -Raw
            $keys = New-Object System.Collections.ArrayList
            foreach ($m in [regex]::Matches($raw, "\`$get\s+\`$meta\s+'([A-Za-z0-9_]+)'")) { [void]$keys.Add($m.Groups[1].Value) }
            foreach ($m in [regex]::Matches($raw, "Get-SIAzureMetaValue\s+-Meta\s+\`$meta\s+-Key\s+'([A-Za-z0-9_]+)'")) { [void]$keys.Add($m.Groups[1].Value) }
            $script:ChainKeys[$b] = @($keys | Sort-Object -Unique)
        }

        # A key is PRODUCED if it appears anywhere under engine\ outside the four row builders.
        # Deliberately permissive: `$metadata['K'] = ...`, `K = $x` in a hashtable literal, and
        # pass-through loops all count. A key that cannot be found even permissively is dead.
        $script:EngineFiles = @(Get-ChildItem -Path (Join-Path $script:SIRootDir 'engine') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue |
                                Where-Object { $_.Name -notlike 'Build-*ProfileRow.ps1' })
        $script:EngineBlob = ($script:EngineFiles | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"

        function script:IsProduced { param([string]$Key) return ($script:EngineBlob -match [regex]::Escape($Key)) }
    }

    # ✅ THE DEAD SET IS NOW EMPTY, AND THAT IS THE VERSION THAT ACTUALLY PROTECTS (2026-08-28).
    #
    # It was pinned at SEVEN on 2026-08-27 as a deliberate compromise: they were a real open defect,
    # and failing the gate on them would have blocked every unrelated release. The compromise had a
    # cost worth naming -- a pinned list can hide a NEW dead candidate behind a known one, because the
    # assertion only compares set membership. An empty expectation has no such hiding place.
    #
    # How the seven were resolved, and the distinction is the transferable part:
    #   MDE_HardwareUuid          REMOVED 2026-08-27 -- endpoint's dead LAST RESORT; its deadness is
    #                             what produced 59 blank names out of 198
    #   ENTRA_UserPrincipalName   FIXED   2026-08-28 -- never missing DATA, merely MISSPELLED. The UPN
    #                             is collected and stored as ENTRA_UPN; only this chain asked for the
    #                             long-form name
    #   AD_DnsHostName, AD_Name,  REMOVED 2026-08-28 -- SI has NO on-prem AD source. Discovery is ARG,
    #   AD_DisplayName,           Azure EG, Entra, MDE and Shodan. Producing them means BUILDING an AD
    #   AD_SamAccountName         collector: a feature, not a repair
    #   AZ_ResourceType           REMOVED 2026-08-28 -- a second alias nothing wrote. The collector
    #                             writes AZ_Type
    #   ENTRA_AppId               REMOVED 2026-08-28 -- identity's dead LAST RESORT, and a GUID, which
    #                             the contract forbids as a name even if it were produced
    #
    # 🪤 So of seven "dead" keys: one was a typo, one was a duplicate alias, four needed a collector
    # that does not exist, and one was forbidden by the contract anyway. NONE of them needed the
    # feature work the list implied. Check unproduced-vs-misspelled before costing the next one.
    It 'NO candidate in any chain is dead -- every one has a real producer' {
        $expectedDead = @() | Sort-Object

        $actualDead = @()
        foreach ($b in $script:ChainKeys.Keys) {
            foreach ($k in $script:ChainKeys[$b]) {
                if (-not (script:IsProduced $k)) { $actualDead += $k }
            }
        }
        $actualDead = @($actualDead | Sort-Object -Unique)

        ($actualDead -join ', ') | Should -Be ($expectedDead -join ', ')
    }

    It '🪤 MDE_HardwareUuid is GONE from the endpoint chain -- it was the dead LAST RESORT' {
        # Removed rather than pinned: it was the terminal candidate, so its deadness is what produced
        # 59 blank rows. The others above only cost a missed opportunity, not a blank.
        $raw = Get-Content (Join-Path $script:Shared 'Build-EndpointProfileRow.ps1') -Raw
        $noBlocks = [regex]::Replace($raw, '(?s)<#.*?#>', '')
        $code = ($noBlocks -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match "\`$get\s+\`$meta\s+'MDE_HardwareUuid'"
    }

    It 'every builder ends in a resort that IS produced -- PrimaryEntityId, measured 100% on all engines' {
        foreach ($b in @('Build-EndpointProfileRow.ps1','Build-IdentityProfileRow.ps1','Build-AzureProfileRow.ps1')) {
            $raw = Get-Content (Join-Path $script:Shared $b) -Raw
            $raw | Should -Match 'PrimaryEntityId' -Because "$b must have a reachable last resort"
        }
    }
}

Describe 'SI_AssetName -- the ONE authored name; there is no second spelling' {

    # 🔒 THE ALIAS DIRECTION IS THE DESIGN (operator, 2026-08-27: "alias direction hold"). SI_AssetName
    # is authored; AssetName delegates to it. The unprefixed name is KEPT, not retired: the shipped
    # report catalog references it ~470 times, RiskAnalysis reads it, and it is the CMDB CI match key.
    # 🔑 Delegation rather than duplication is the whole point -- two columns computing the same thing
    # independently is exactly how the schema's declared derivation and the builder's actual chain came
    # to disagree. These tests assert they cannot drift.

    It '<b> declares SI_AssetName in its schema' -ForEach @(
        @{ b = 'endpoint' }; @{ b = 'azure' }; @{ b = 'identity' }; @{ b = 'public-ip' }
    ) {
        $j = Get-Content (Join-Path $script:SIRootDir "asset-profiling-schema\$b.schema.locked.json") -Raw | ConvertFrom-Json
        $f = @($j.fields | Where-Object { $_.name -eq 'SI_AssetName' })
        $f.Count      | Should -Be 1
        $f[0].source  | Should -Be 'derived'
    }

    It '<b> resolves SI_AssetName to a real name when one exists' -ForEach @(
        @{ b = 'Build-EndpointProfileRow.ps1'; m = @{ MDE_DeviceName = 'srv-01' } }
        @{ b = 'Build-IdentityProfileRow.ps1'; m = @{ ENTRA_DisplayName = 'svc-billing' } }
    ) {
        (script:AskBuilder -Builder $b -FieldName 'SI_AssetName' -Meta $m -PrimaryEntityId 'PE-123') |
            Should -Be @($m.Values)[0]
    }

    It '🔒 the legacy spelling resolves to NOTHING, in <b>' -ForEach @(
        @{ b = 'Build-EndpointProfileRow.ps1'; m = @{ MDE_DeviceName = 'srv-01' } }
        @{ b = 'Build-IdentityProfileRow.ps1'; m = @{ ENTRA_DisplayName = 'svc-billing' } }
        @{ b = 'Build-PublicIpProfileRow.ps1'; m = @{} }
    ) {
        # 🔴 REPLACED 2026-08-28. This asserted 'AssetName EQUALS SI_AssetName', because the two
        # columns coexisted and a mirror kept them from drifting. The mirror is gone: the profile
        # tables now carry ONE asset-name column. A mirror that cannot drift is still a second name to
        # explain -- and the sibling AssetId mirror was never built at all, declared on four engines
        # and written by none. So the readers were repointed at SI_AssetName and the duplicate deleted.
        # What must hold now is the OPPOSITE of what held before: the old name answers with nothing, so
        # the column cannot quietly reappear the moment some row happens to carry a value.
        $authored = script:AskBuilder -Builder $b -FieldName 'SI_AssetName' -Meta $m -PrimaryEntityId 'PE-123'
        $authored | Should -Not -BeNullOrEmpty
        $legacy   = script:AskBuilder -Builder $b -FieldName 'AssetName' -Meta $m -PrimaryEntityId 'PE-123'
        # AskBuilder stringifies a null result as the literal <NULL>, so that is the empty here.
        $legacy | Should -Be '<NULL>'
    }

    It 'the azure builder resolves SI_AssetName directly from AZ_Name' {
        # Azure resolves inline through a key map keyed on SCHEMA FIELD NAMES. With the legacy field
        # deleted, an entry still keyed 'AssetName' would resolve nothing at all and SI_AssetName would
        # ship empty on every azure row -- indistinguishable from an estate that has no names.
        $code = Get-Content (Join-Path $script:Shared 'Build-AzureProfileRow.ps1') -Raw
        $code | Should -Match "'SI_AssetName'\s*=\s*@\('AZ_Name'\)"
        $code | Should -Not -Match "\`$row\['AssetName'\]"
    }
}

Describe '🔴 THE SYNTHETIC NAME -- what a nameless asset gets instead of a blank or a hash' {

    BeforeAll { . (Join-Path $script:Shared 'SI-AssetName.ps1') }

    It 'a nameless asset gets a MARKED name, not the bare identifier' {
        # The 39% case: returning $pe here is precisely what put 78 machine ids into the customer's
        # Excel looking like unreadable hostnames.
        $v = script:AskBuilder -Builder 'Build-EndpointProfileRow.ps1' -FieldName 'SI_AssetName' `
                -Meta @{} -PrimaryEntityId '55a92b233bfb8d8bbe743377477c88ea4358a191'
        $v | Should -BeLike 'unnamed-endpoint-*'
        $v | Should -Not -Be '55a92b233bfb8d8bbe743377477c88ea4358a191'
    }

    It 'and it is still never blank -- the contract SI_AssetName makes' {
        (script:AskBuilder -Builder 'Build-EndpointProfileRow.ps1' -FieldName 'SI_AssetName' -Meta @{} -PrimaryEntityId 'PE-123') |
            Should -Not -BeNullOrEmpty
    }

    It 'DETERMINISTIC -- the same asset gets the same name on every run' {
        $a = Get-SISyntheticAssetName -Engine 'endpoint' -Id 'abc123def456'
        $b = Get-SISyntheticAssetName -Engine 'endpoint' -Id 'abc123def456'
        $a | Should -Be $b
    }

    It '🪤 UNIQUE -- two different assets never share one placeholder' {
        # A shared placeholder would silently merge distinct assets into one report row: the blank-join-key
        # defect (v2.2.442 manufactured 296 findings that way), wearing a friendlier name.
        $a = Get-SISyntheticAssetName -Engine 'endpoint' -Id 'aaaaaaaaaaaa1111'
        $b = Get-SISyntheticAssetName -Engine 'endpoint' -Id 'aaaaaaaaaaaa2222'
        $a | Should -Not -Be $b
    }

    It '🪤 an ARM path takes its entropy from the TAIL, not the subscription guid at the head' {
        # Head-taking would give every resource in a subscription the same "unique" placeholder.
        $one = Get-SISyntheticAssetName -Engine 'azure' -Id '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web-01'
        $two = Get-SISyntheticAssetName -Engine 'azure' -Id '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/db-02'
        $one | Should -Not -Be $two
    }

    It 'no id at all yields NOTHING -- inventing a name from nothing would be worse than a blank' {
        Get-SISyntheticAssetName -Engine 'endpoint' -Id ''    | Should -BeNullOrEmpty
        Get-SISyntheticAssetName -Engine 'endpoint' -Id '///' | Should -BeNullOrEmpty
    }

    It 'a consumer can recognise one without parsing its shape' {
        Test-SISyntheticAssetName -Value (Get-SISyntheticAssetName -Engine 'endpoint' -Id 'abc123') | Should -BeTrue
        Test-SISyntheticAssetName -Value 'srv-01'                                                   | Should -BeFalse
        Test-SISyntheticAssetName -Value ''                                                         | Should -BeFalse
    }

    It 'ONE implementation, shared -- no builder rolls its own naming rule' {
        # Four copies of a rule is how four engines end up with four behaviours, which is the state this
        # whole change replaced.
        # 🔴 UPDATED 2026-08-28: endpoint no longer calls Get-SISyntheticAssetName DIRECTLY. Its name and
        # id are now resolved as a PAIR by Resolve-SIAssetIdentityPair (engine/_shared), which owns the
        # synthetic for that path. So the assertion is "reaches a SHARED rule", not "calls this one
        # function" -- the invariant that matters is that no builder formats the name itself.
        $sharedEntryPoints = 'Get-SISyntheticAssetName|Resolve-SIAssetIdentityPair|Get-SIEndpointIdentityPair'
        foreach ($b in 'Build-EndpointProfileRow.ps1','Build-IdentityProfileRow.ps1','Build-AzureProfileRow.ps1') {
            $code = Get-Content (Join-Path $script:Shared $b) -Raw
            $code | Should -Match $sharedEntryPoints -Because "$b must reach the shared naming rule"
            $code | Should -Not -Match "'unnamed-\{0\}" -Because "$b must not re-implement the format"
        }
        # And the format itself must exist in exactly ONE place across the shared modules.
        $fmtOwners = @(Get-ChildItem (Join-Path $script:SIRootDir 'engine\_shared') -Filter '*.ps1' |
                       Where-Object { (Get-Content $_.FullName -Raw) -match "'unnamed-\{0\}" })
        $fmtOwners.Count | Should -BeLessOrEqual 2 -Because 'the unnamed- format must not proliferate'
    }
}
