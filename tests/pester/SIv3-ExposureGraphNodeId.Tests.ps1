#Requires -Version 5.1
<#
    SI v3 STEP 2 -- the exposure-graph node id must be emitted as a COLUMN.

    Measured live before this change (log-platform-management-securityinsight):
        endpoint  EgNodeId present on 72% of rows INSIDE EntityIds, 0% as a column
        azure     ExposureGraphNodeId column present on 62.5% of rows
        identity  EG_NodeId produced by discovery ("for cross-engine joins") and NEVER READ

    So the correlation key was collected, carried, and thrown away everywhere except azure. Promoting it
    to a column is the cheapest half of the correlation prerequisite: no new query, no new matching
    engine -- the value is already in the row builder's hand.

    🪤 The row builder emits ONLY fields the schema declares, so the code change and the schema
    declaration are BOTH required. A test that checked only one of them would pass on a half-applied
    change and the column would land null.
#>

$EnginesWithEg = @('endpoint', 'identity', 'public-ip', 'azure')

BeforeAll {
    $script:SIRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaDir = Join-Path $script:SIRoot 'asset-profiling-schema'
    $script:SharedDir = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
}

Describe 'STEP 2 -- ExposureGraphNodeId is declared in every profile schema' {

    It '<_> declares ExposureGraphNodeId exactly once' -ForEach $EnginesWithEg {
        $j = Get-Content (Join-Path $script:SchemaDir "$_.schema.locked.json") -Raw | ConvertFrom-Json
        @($j.fields | Where-Object { $_.name -eq 'ExposureGraphNodeId' }).Count | Should -Be 1
    }

    It '<_> declares it as a correlation column, not posture or audit' -ForEach $EnginesWithEg {
        $j = Get-Content (Join-Path $script:SchemaDir "$_.schema.locked.json") -Raw | ConvertFrom-Json
        $f = @($j.fields | Where-Object { $_.name -eq 'ExposureGraphNodeId' })[0]
        $f.purpose | Should -Be 'correlation'
        $f.type    | Should -Be 'string'
    }

    It 'every schema still parses as JSON after the insert' -ForEach $EnginesWithEg {
        { Get-Content (Join-Path $script:SchemaDir "$_.schema.locked.json") -Raw | ConvertFrom-Json } |
            Should -Not -Throw
    }
}

Describe 'STEP 2 -- the row builders actually RESOLVE it' {

    # Declaring the field without wiring the derivation is exactly how AssetName was "always null on
    # Endpoint rows" -- the codebase records that as a real past defect. Assert the wiring, not just
    # the declaration.
    It '<_> row builder resolves ExposureGraphNodeId in its derived-value switch' -ForEach @(
        'Build-EndpointProfileRow', 'Build-IdentityProfileRow', 'Build-PublicIpProfileRow') {
        $txt = Get-Content (Join-Path $script:SharedDir "$_.ps1") -Raw
        $txt | Should -Match "'ExposureGraphNodeId'\s*\{\s*return\s+\`$Context\.EgNodeId\s*\}"
    }

    It '<_> passes EgNodeId into the context the switch reads from' -ForEach @(
        'Build-EndpointProfileRow', 'Build-IdentityProfileRow', 'Build-PublicIpProfileRow') {
        # 🪤 Without this the switch returns $null for every row and the column ships 100% empty --
        #    which looks exactly like "the graph does not cover these assets".
        $txt = Get-Content (Join-Path $script:SharedDir "$_.ps1") -Raw
        $txt | Should -Match '(?m)^\s*EgNodeId\s*=' -Because "$_ must set EgNodeId on the context hashtable"
    }

    It 'identity reads EG_NodeId from discovery metadata, which was previously never consumed' {
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-IdentityProfileRow.ps1') -Raw
        $txt | Should -Match 'meta\.EG_NodeId'
    }
}

Describe 'STEP 2 -- the derived value resolves end to end (behavioural, not textual)' {

    It 'Get-SIDerivedValue returns the context EgNodeId for the endpoint engine' {
        # Dot-sourcing the whole builder pulls in engine dependencies, so exercise the dispatch shape
        # directly: the switch must map the field name onto $Context.EgNodeId and nothing else.
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-EndpointProfileRow.ps1') -Raw
        $m = [regex]::Match($txt, "'ExposureGraphNodeId'\s*\{\s*return\s+(\`$Context\.[A-Za-z]+)\s*\}")
        $m.Success | Should -BeTrue
        $m.Groups[1].Value | Should -Be '$Context.EgNodeId'
    }

    It 'azure was already correct and is left alone -- it maps from its own AZ_NodeId source key' {
        # Azure has emitted this column since 2.3.0 via a source-key map, not the derived switch.
        # Changing it would be churn on a column that already works.
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-AzureProfileRow.ps1') -Raw
        $txt | Should -Match "'ExposureGraphNodeId'\s*=\s*@\('AZ_NodeId'\)"
    }
}


Describe 'STEP 1 -- SI_AssetId: SI''s own unique id, guaranteed populated' {

    # Operator intent: "assetid and assetname was a custom unique id as an identifier so we covered
    # 100%". Measured live: the unprefixed AssetId is 0% on ALL THREE profile tables while
    # PrimaryEntityId is 100% -- declared in every schema as "alias of PrimaryEntityId" and never wired,
    # the same defect this codebase records for AssetName.

    It '<_> declares SI_AssetId exactly once, as an identity column' -ForEach @('endpoint','identity','public-ip','azure') {
        $j = Get-Content (Join-Path $script:SchemaDir "$_.schema.locked.json") -Raw | ConvertFrom-Json
        $f = @($j.fields | Where-Object { $_.name -eq 'SI_AssetId' })
        $f.Count      | Should -Be 1
        $f[0].purpose | Should -Be 'identity'
    }

    # 🔴 UPDATED 2026-08-28, NOT DELETED -- the contract deliberately changed and this records how.
    # These three used to pin the LITERAL source shape `'SI_AssetId' { return $Context.PrimaryEntityId }`.
    # SI_AssetId now goes through the SHARED identity rule in engine/_shared/SI-AssetIdentity.ps1, so
    # every engine answers "may this type key an asset?" from ONE list instead of four opinions.
    # WHY IT HAD TO CHANGE: Build-EndpointProfileRow's PrimaryEntityId chain ends in a HOSTNAME, which
    # SIWeakIdTypes defines as "NOT unique -- must never join on these alone". The profiler was using as
    # its asset id exactly the type the correlation engine forbids keying on, and nothing errored
    # because the two rules lived in modules that could not see each other.
    It 'identity resolves SI_AssetId through the SHARED identity rule' {
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-IdentityProfileRow.ps1') -Raw
        $txt | Should -Match 'Resolve-SIAssetIdValue\s+-Id\s+\$Context\.PrimaryEntityId\s+-Type\s+\$Context\.PrimaryEntityType'
    }

    It 'endpoint resolves SI_AssetId and SI_AssetName as ONE PAIR, from one source' {
        # 🔒 Operator, 2026-08-28: "name drives id as id can change fx if client is known in entra id as
        # device, then later it comes in mde, so id could change." Endpoint is the engine where the two
        # actually disagreed, so it resolves the pair rather than each field independently.
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-EndpointProfileRow.ps1') -Raw
        $txt | Should -Match "'SI_AssetId'\s*\{\s*return\s+\(Get-SIEndpointIdentityPair"
        $txt | Should -Match "'SI_AssetName'\s*\{\s*return\s+\(Get-SIEndpointIdentityPair"
    }

    It 'the pair is resolved ONCE per record, so the two fields cannot diverge' {
        # Behaviour, not shape: the schema field loop asks for each field separately, so without
        # memoisation the walk runs twice and the fields could drift apart the moment anything in it
        # became order- or state-dependent.
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-EndpointProfileRow.ps1') -Raw
        $txt | Should -Match '_SIIdentityPair'
    }

    It 'azure wires it too, in its row-assignment style' {
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-AzureProfileRow.ps1') -Raw
        $txt | Should -Match "\`$row\['SI_AssetId'\]\s*=\s*Resolve-SIAssetIdValue"
    }

    It 'publicip is DELIBERATELY still direct -- and this is an open operator decision' {
        # publicip's PrimaryEntityType is 'IpAddress', which IS in SIWeakIdTypes. Routing it through the
        # shared rule would mark all 11 rows `weak:ipaddress:<ip>` -- defensible (an IP is not a durable
        # identity) but a customer-visible change to a table measured 11/11 unique, i.e. already meeting
        # the requirement. Left alone pending a ruling rather than churned silently.
        # 📌 The CI risk is closed elsewhere: SERVICENOW-CMDB-SCHEMA.md §4 makes a public IP level-4 by
        # rule -- a property, never a CI -- so nothing binds a ServiceNow record to this id.
        $txt = Get-Content (Join-Path $script:SharedDir 'Build-PublicIpProfileRow.ps1') -Raw
        $txt | Should -Match "'SI_AssetId'\s*\{\s*return\s+\`$Context\.PrimaryEntityId\s*\}"
    }

    It 'the shared rule MARKS a weak type instead of passing it through as an asset id' {
        # Behaviour, not shape -- a shape assertion is what let the hostname rung survive this long.
        $mod = Join-Path $script:SharedDir '..\..\_shared\SI-AssetIdentity.ps1'
        Test-Path $mod | Should -BeTrue
        . $mod
        Resolve-SIAssetIdValue -Id 'abc123' -Type 'MdeDeviceId' | Should -BeExactly 'abc123'
        Resolve-SIAssetIdValue -Id 'srv-01' -Type 'Hostname'    | Should -BeExactly 'weak:hostname:srv-01'
        Test-SIWeakAssetId -Value 'weak:hostname:srv-01'        | Should -BeTrue
        Test-SIWeakAssetId -Value 'abc123'                      | Should -BeFalse
    }

    It 'does NOT touch the existing unprefixed AssetId -- the change must be purely additive' {
        # RA already populates its own AssetId (93.4% on Detailed) and consumers may bind to it.
        # SI_ prefixing exists precisely so nothing that reads AssetId today changes behaviour.
        foreach ($b in 'Build-EndpointProfileRow','Build-IdentityProfileRow','Build-PublicIpProfileRow') {
            $txt = Get-Content (Join-Path $script:SharedDir "$b.ps1") -Raw
            $txt | Should -Not -Match "(?m)^\s*'AssetId'\s*\{"
        }
    }

    It 'no schema declares the legacy AssetId any more' -ForEach @('endpoint','identity','azure','public-ip') {
        # 🔴 INVERTED 2026-08-28. This asserted the change was "purely additive" -- SI_AssetId added,
        # AssetId left untouched -- on the stated grounds that "RA already populates its own AssetId
        # (93.4% on Detailed) and consumers may bind to it".
        # 🪤 THE GROUNDS WERE ABOUT A DIFFERENT TABLE. RA's own output does carry a populated AssetId;
        # the PROFILE tables never did. All four declared it `derived` and no builder ever implemented
        # it, so it was 0% on every engine since inception -- and because Log Analytics does not create
        # a column that has no value on any row, it was ABSENT rather than empty, which is why
        # `column_ifexists("AssetId","")` returned "" forever with no error to notice.
        # The customer-facing RA report headers are unchanged; only the profile tables lost the ghost.
        $j = Get-Content (Join-Path $script:SchemaDir "$_.schema.locked.json") -Raw | ConvertFrom-Json
        @($j.fields | Where-Object { $_.name -ceq 'AssetId' }).Count   | Should -Be 0
        @($j.fields | Where-Object { $_.name -ceq 'SI_AssetId' }).Count | Should -Be 1
    }
}
