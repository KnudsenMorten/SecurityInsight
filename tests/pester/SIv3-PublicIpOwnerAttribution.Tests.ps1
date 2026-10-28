#Requires -Version 5.1
<#
    SI v3 -- PUBLICIP MUST PUBLISH THE OWNING ASSET'S ATTRIBUTES, NOT ITS OWN.

    A public IP is not an asset anyone cares about on its own. It matters because of what it is
    ATTACHED to, and the default discovery mode ('profile-cl') finds these IPs by reading them OUT of
    SI_Endpoint_Profile_CL / SI_Azure_Profile_CL -- so the owning asset is always known.

    Discovery collects three facts about that owner and promotes them to the top level of the discovery
    row for exactly one stated reason (Get-DiscoveryFromShodan.ps1): "promoted to top-level so the row
    builder can emit them as flat SI_PublicIP_Profile_CL columns matching what the RA YAML queries
    expect". The three are AssetEngine, AssetTier and the owner's name.

    🔴 ALL THREE WERE DROPPED OR OVERWRITTEN AT DIFFERENT TIMES, AND EACH FAILURE LOOKED FINE:

      AssetName   the row's top-level 'Name' is stripped by Invoke-Collect.ps1's $excludedTopLevel, so
                  SI_AssetName had nothing to read and returned the IP -- a 100%-populated column full
                  of identifiers. Fixed 2026-08-28; guarded in SIv3-AssetNameContract.Tests.ps1.
      the tier    collected correctly, then OVERWRITTEN one line later with the IP's own tier.
                  THIS FILE. Measured 2026-08-27: metadata carried AssetTier=0 for the three
                  endpoint-owned IPs (MGMT1, dc1.2linkit.local, dc3.2linkit.local) while every row
                  in Log Analytics read 3.
      AssetEngine reads $meta correctly. It is the CONTROL: the siblings were handled inconsistently
                  one line apart, which is the whole tell.

    ⚠️ WHY THE TIER IS NOT COSMETIC -- it sets a PUBLISHED SEVERITY. The shipped RA reports do
    `CriticalityTier = toint(coalesce(Tier, 99))` and then map that to SecuritySeverity and the
    Tier0Asset probability token. With the tier forced to the IP's own value, a public IP on a Tier 0
    asset published as "Low" -- in reports whose descriptions read "Public IPs attached to Tier 0/1
    assets". The severity labels in those queries were revised TWICE (v2.2.322 notes "PublicIP always
    showed Critical=0 + Low=0") while the INPUT column was wrong the whole time.

    🔑 THE RESOLUTION (operator, 2026-08-28 -- "as the others"): `Tier` on this table now means what it
    means on the other three profile tables -- THE CRITICALITY TIER OF THE ASSET. RA reads
    `CriticalityTier` from `Tier` in ~76 reports and read `AssetTier` in exactly 4 (the publicip ones),
    so publicip was the outlier and publicip moved. `AssetTier` remains as a plain alias of `Tier`, so
    the two can never disagree again.

    🪤 The earlier version of this file asserted the OPPOSITE -- that `Tier` must be left alone because
    changing it would corrupt the IP's own classification. That premise was false: publicip has no
    classification to corrupt. See the reversed assertion below for the evidence.

    Builders run in a CHILD PROCESS: all four define Get-SIDerivedValue, so dot-sourcing more than one
    into a single scope means the last silently wins and the suite measures the wrong file.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Builder   = Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-PublicIpProfileRow.ps1'

    # Build a REAL row in its own process -- ONCE per distinct input (#416: twelve tests built the same three rows twelve
    # times, a Windows PowerShell child process each, ~5 s apiece). The child returns every column NAME (case kept: KQL
    # column names are case-sensitive) and every value as text; the tests read them from the memo.
    # Behavioural on purpose: a shape assertion ("the code reads $meta") would have passed against the
    # broken version too, because the broken version also read $meta -- just for the wrong sibling.
    $script:RowMemo = @{}
    function script:BuildRow {
        param([Parameter(Mandatory)][hashtable]$Meta, $VerdictTier = 3)
        $metaLiteral = (@($Meta.Keys | Sort-Object) | ForEach-Object { "'{0}'='{1}'" -f $_, ([string]$Meta[$_] -replace "'","''") }) -join ';'
        $verdictExpr = if ($null -eq $VerdictTier) { '$null' } else { "[pscustomobject]@{ SI_Tier = $VerdictTier }" }
        $key = $metaLiteral + '|' + $verdictExpr
        if ($script:RowMemo.ContainsKey($key)) { return $script:RowMemo[$key] }
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$($script:Builder)'
`$rec = [pscustomobject]@{
    AssetId  = 'ip:203.0.113.9'
    Metadata = @{$metaLiteral}
    Verdict  = $verdictExpr
    SI_RunId = 'r1'
    TimeGenerated = '2026-01-01T00:00:00Z'
}
`$rc  = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z'; Engine = 'publicip'; RunId = 'r1' }
`$row = Build-SIPublicIpProfileRow -Record `$rec -RunContext `$rc
# The builder returns a PSCustomObject, not the ordered hashtable it assembles internally -- so this reads properties.
'<NAMES>' + ((`$row.PSObject.Properties.Name) -join ';')
foreach (`$p in `$row.PSObject.Properties) { '<VAL>' + `$p.Name + '=' + ([string]`$p.Value -replace '\r?\n', ' ') }
"@
        $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd 2>&1
        $nl = @($out) | Where-Object { "$_" -like '<NAMES>*' } | Select-Object -Last 1
        if (-not $nl) { throw ("builder produced no row; output was: {0}" -f (($out | Select-Object -Last 5) -join ' | ')) }
        $vals = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
        foreach ($l in @($out | Where-Object { "$_" -like '<VAL>*' })) { $kv = ([string]$l).Substring(5); $i = $kv.IndexOf('='); $vals[$kv.Substring(0, $i)] = $kv.Substring($i + 1) }
        $r = [pscustomobject]@{ Names = (([string]$nl) -replace '^<NAMES>', ''); Values = $vals }
        $script:RowMemo[$key] = $r
        $r
    }

    # one column's value as text, '<MISSING>' when the row has no such column (looked up the way PowerShell reads a property)
    function script:BuildRowField {
        param([Parameter(Mandatory)][hashtable]$Meta, [Parameter(Mandatory)][string]$Column, $VerdictTier = 3)
        $r = BuildRow -Meta $Meta -VerdictTier $VerdictTier
        $hit = @($r.Values.Keys | Where-Object { $_ -eq $Column }) | Select-Object -First 1
        if ($null -eq $hit) { return '<MISSING>' }
        $r.Values[$hit]
    }

    # Every column the builder actually emits, semicolon-joined, so a test can compare names
    # CASE-SENSITIVELY. Needed because PowerShell property access is not.
    function script:BuildRowColumnNames {
        param([Parameter(Mandatory)][hashtable]$Meta, $VerdictTier = 3)
        (BuildRow -Meta $Meta -VerdictTier $VerdictTier).Names
    }
}

Describe 'PublicIP -- the OWNING asset''s tier reaches the row' {

    # The measured case, reduced: an endpoint-owned public IP whose owner is Tier 0, while the publicip
    # classification verdict says 3. Tier must report the OWNER.
    It 'Tier is the owning asset''s criticality, not the IP''s own verdict' {
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint' } `
            -Column 'Tier' -VerdictTier 3 |
            Should -Be '0' -Because 'RA derives CriticalityTier from Tier in ~76 reports; publicip must mean the same thing'
    }

    # 🔄 THIS ASSERTION REVERSED, and the reason is worth keeping. An earlier version of this file
    # asserted "Tier is UNTOUCHED -- it is the IP object's own classification", on the reasoning that
    # bending Tier would corrupt a classification to repair a report column. That reasoning was wrong
    # on its premise: publicip has NO classification to corrupt. There are no publicip tiering rules
    # (no asset-profiling-enrichment/publicip), Classify returns SI_Tier = null with the proof "Tier
    # left null for Stage Profile to compute via MIN-of-SIRules", and zero SIRules match -- so every
    # row fell to a hardcoded 3. It was a constant wearing a classification's name.
    # Operator ruling 2026-08-28, on being shown that ~76 reports read Tier and 4 read AssetTier --
    # "as the others". publicip was the outlier, so publicip moved.
    # 🔒 The five legacy alias columns are GONE (operator, 2026-08-28: "i dont see purpose of
    # assettier. we dont use that name in the other 3. consistence is very importsant"). Each
    # duplicated a DECLARED column under the retired standalone scanner's name, and not one of the
    # five was declared in any of the four engine schemas:
    #     HasShodanRecord -> InShodan     Org  -> OrgName     ISP -> Isp
    #     LastShodanUpdate -> ShodanLastSeen                  AssetTier -> Tier
    # The RA queries moved to the declared names in the same change.
    # 🪤 ASSERTED ON THE EMITTED NAMES, CASE-SENSITIVELY, and that detail is the whole test.
    # A per-column lookup cannot express this: PowerShell property access is CASE-INSENSITIVE, so
    # asking the row for 'ISP' cheerfully returns the declared 'Isp' and the alias looks absent when
    # it is present -- or present when it is absent. (The same case-insensitivity made an earlier
    # `-contains` check report 'ISP' as a declared schema field when only 'Isp' is.) KQL column names
    # ARE case-sensitive, so 'ISP' and 'Isp' are two different columns and only -cne can tell them
    # apart.
    It 'emits no undeclared legacy alias column <_>' -ForEach @(
        'AssetTier', 'HasShodanRecord', 'Org', 'ISP', 'LastShodanUpdate'
    ) {
        $names = (script:BuildRowColumnNames -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint' } -VerdictTier 3) -split ';'
        $alias = $_
        @($names | Where-Object { $_ -ceq $alias }).Count |
            Should -Be 0 -Because "$alias duplicated a declared column under a retired name"
    }

    It 'still emits the DECLARED column each alias duplicated -- <_>' -ForEach @(
        'Tier', 'InShodan'
    ) {
        # The point is that the data did not go away with the alias.
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint' } `
            -Column $_ -VerdictTier 3 |
            Should -Not -Be '<MISSING>'
    }

    It 'AssetEngine survives -- it is the one row column carrying a fact no declared column had' {
        # Kept, and DECLARED in public-ip.schema.locked.json so it is not itself an undeclared column.
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint' } `
            -Column 'AssetEngine' -VerdictTier 3 |
            Should -Be 'endpoint'
    }

    It 'AssetEngine already came from discovery -- the sibling that was always right' {
        # The control. If this ever fails, the two are broken together and the diagnosis differs.
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint' } `
            -Column 'AssetEngine' -VerdictTier 3 |
            Should -Be 'endpoint'
    }

    It 'falls back to the classification verdict when discovery knew no owner tier' {
        # arg-eg / extras discovery can find an IP with no Profile_CL match. A metadata bag without the
        # key at all must not produce a blank severity input.
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetEngine = 'eg' } `
            -Column 'Tier' -VerdictTier 3 |
            Should -Be '3'
    }

    It 'an explicit unranked owner (99) is preserved, not silently replaced' {
        # 99 is discovery's "no tier known" marker and it is MEANINGFUL: the RA queries map a missing
        # tier to 99 too. Replacing it would invent criticality that no source claimed -- the inverse
        # of the bug, and just as wrong.
        script:BuildRowField -Meta @{ IP_Address = '203.0.113.9'; AssetTier = '99'; AssetEngine = 'extra' } `
            -Column 'Tier' -VerdictTier 3 |
            Should -Be '99'
    }
}
