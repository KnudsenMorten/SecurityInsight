#Requires -Version 5.1
<#
    SI v3 -- #101. THE ENDPOINT `DisplayName` COLUMN MUST NOT PUBLISH THE ASSET'S OWN IDENTIFIER.

    🔴 WHAT THIS GUARDS, AND WHY IT IS NOT A NEW DEFECT. It is the SAME defect, in the column next
    door, still shipping five days after it was found and fixed once.
    `Resolve-SIAssetIdentityPair` records the original in its own doc block: "MEASURED 2026-08-27: 78
    of 198 endpoint rows carried a 40-hex MDE machine id in the name column, because
    Get-DiscoveryFromMDE substitutes $m.id when MDE has no computerDnsName -- and it reached a
    customer's Excel reading like a hostname." That guard was written for `SI_AssetName` only.

    MEASURED ON THE SAME LIVE ESTATE 2026-09-01, latest populated snapshot, 197 endpoint rows:
        SI_AssetName carrying a raw hex id ......   0   (the 2026-08-27 guard works)
        DisplayName  carrying a raw 40-hex id ...  78
        DisplayName  == PrimaryEntityId .........  78   (the identifier verbatim, not a lookalike)
        DisplayName  empty ......................  59
        DisplayName  a real name ................  60
    Same estate, same rows, same count as the 2026-08-27 measurement.

    🔑 SO THE RULE NOW HAS ONE HOME -- `Test-SINameIsIdentifier` in engine/_shared/SI-AssetIdentity.ps1
    -- and both name chains call it. A third chain added later inherits the rule instead of
    re-deciding it, which is the whole argument that file was created to make.

    📌 SCOPE. `DisplayName` is a display column: nothing keys, joins, tiers or correlates on it, so
    this cannot move an `SI_AssetId`. That distinction is deliberate -- the sibling finding (#100)
    CAN move one and is therefore not applied here.

    Builders run in CHILD `powershell.exe` (PS 5.1) processes: all four builders define
    Get-SIDerivedValue, so dot-sourcing more than one into a single scope means the last one silently
    wins and the tests measure the wrong file. 5.1 is also the shipped runtime.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Shared    = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'
    $script:IdFile    = Join-Path $script:SIRootDir 'engine\_shared\SI-AssetIdentity.ps1'

    # The real 40-hex MDE machine id shape, and the shape the 78 live rows carry.
    $script:Hex40 = 'aa11e0a75cf3d8215ca2d87eb807df64336c66ff'

    # Ask the endpoint builder for one derived field in its own PS 5.1 process.
    #
    # 🪤 THE METADATA SHAPE IS A PARAMETER, NOT A CONVENIENCE. This codebase has already shipped a bug
    # whose unit tests passed HASHTABLES while the engine passed DESERIALISED JSON (PSCustomObject) --
    # recorded on Get-SIRowValue. `Get-SIEgValue` and the DisplayName chain both branch on the shape,
    # so a fixture that only ever builds one of them tests half the code.
    function script:AskDisplayName {
        param(
            [hashtable]$Meta,
            [string]$PrimaryEntityId,
            [ValidateSet('Hashtable', 'Deserialised')][string]$Shape = 'Hashtable'
        )
        $json = ($Meta | ConvertTo-Json -Depth 8 -Compress) -replace "'", "''"
        $file = Join-Path $script:Shared 'Build-EndpointProfileRow.ps1'
        $cmd = @"
`$ErrorActionPreference='Stop'
. '$file'
`$obj = '$json' | ConvertFrom-Json
`$meta = `$obj
if ('$Shape' -eq 'Hashtable') {
    `$meta = @{}
    foreach (`$p in `$obj.PSObject.Properties) { `$meta[`$p.Name] = `$p.Value }
}
`$ctx = [pscustomobject]@{
    PrimaryEntityId   = '$PrimaryEntityId'
    PrimaryEntityType = 'MdeDeviceId'
    Record            = [pscustomobject]@{ Metadata = `$meta; SI_RunId = 'r1' }
    Verdict           = `$null
    PerSourceVerdicts = @{}
    EntityIds         = @(@{ type='MdeDeviceId'; id='$PrimaryEntityId' })
    EgNodeId          = ''
    CatalogVersion    = ''
    RunContext        = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z' }
}
`$v = Get-SIDerivedValue -Field ([pscustomobject]@{ name='DisplayName' }) -Context `$ctx
if (`$null -eq `$v -or '' -eq [string]`$v) { '<NULL>' } else { [string]`$v }
"@
        # 🪤 -EncodedCommand, NOT -Command, AND THAT IS THE POINT OF THIS COMMENT.
        # The fixture is JSON, so it contains DOUBLE QUOTES -- and Windows PowerShell strips embedded
        # double quotes when it hands a string to a native process. The child then received
        # `{MDE_DeviceName:dc1.contoso.local}`, ConvertFrom-Json threw `Invalid JSON primitive`, and the
        # harness returned the last line of an ERROR RECORD. Every assertion went red for a reason that
        # had nothing to do with the code under test -- and the one assertion phrased as `Should -Not`
        # went GREEN on that same garbage, which is the part worth remembering: a negative assertion
        # passes on a broken fixture. Base64 removes quoting from the transport entirely.
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -EncodedCommand $enc 2>&1
        (@($out) | Select-Object -Last 1) -as [string]
    }
}

Describe '🔑 Test-SINameIsIdentifier -- the rule itself, in its one home' {

    BeforeAll { . $script:IdFile }

    It 'refuses a candidate identical to the id' {
        Test-SINameIsIdentifier -Name $script:Hex40 -Id $script:Hex40 | Should -BeTrue
    }
    It 'refuses it case-insensitively -- a hex id differing only in case is the same id' {
        Test-SINameIsIdentifier -Name $script:Hex40.ToUpperInvariant() -Id $script:Hex40 | Should -BeTrue
    }
    It '🪤 refuses it through a token prefix -- the 2026-08-31 azure case, 123 of 123 rows' {
        Test-SINameIsIdentifier -Name 'abc123' -Id 'eg:az:abc123' | Should -BeTrue
    }
    It 'accepts a real name' {
        Test-SINameIsIdentifier -Name 'srv-01' -Id $script:Hex40 | Should -BeFalse
    }
    It 'is false when either side is blank -- absence is not a match' {
        Test-SINameIsIdentifier -Name ''       -Id $script:Hex40 | Should -BeFalse
        Test-SINameIsIdentifier -Name 'srv-01' -Id ''            | Should -BeFalse
    }
}

Describe '🔴 DisplayName never publishes the identifier -- <shape> metadata' -ForEach @(
    @{ shape = 'Hashtable' }
    @{ shape = 'Deserialised' }
) {

    It 'the 78-row case: MDE substituted the machine id, and it is REFUSED' {
        # This is the exact live shape -- Get-DiscoveryFromMDE writes $m.id into MDE_DeviceName when
        # MDE has no computerDnsName, and PrimaryEntityId is that same MdeDeviceId.
        script:AskDisplayName -Meta @{ MDE_DeviceName = $script:Hex40 } -PrimaryEntityId $script:Hex40 -Shape $shape |
            Should -Be '<NULL>'
    }

    It 'and a REAL name below it still wins -- refusing is not the same as giving up' {
        script:AskDisplayName -Meta @{ MDE_DeviceName = $script:Hex40; EG_RawData = @{ deviceName = 'srv-01' } } `
            -PrimaryEntityId $script:Hex40 -Shape $shape | Should -Be 'srv-01'
    }

    It 'a real MDE name is unaffected, and is still shortened at the first dot' {
        script:AskDisplayName -Meta @{ MDE_DeviceName = 'dc1.contoso.local' } -PrimaryEntityId $script:Hex40 -Shape $shape |
            Should -Be 'dc1'
    }

    It 'Entra still outranks MDE' {
        script:AskDisplayName -Meta @{ ENTRA_DisplayName = 'STRV-MOK-DT-03'; MDE_DeviceName = 'strv-mok-dt-03.contoso.local' } `
            -PrimaryEntityId $script:Hex40 -Shape $shape | Should -Be 'STRV-MOK-DT-03'
    }

    It 'but an Entra name that is merely the id again is refused too -- every rung is guarded' {
        script:AskDisplayName -Meta @{ ENTRA_DisplayName = $script:Hex40; MDE_DeviceName = 'srv-02.contoso.local' } `
            -PrimaryEntityId $script:Hex40 -Shape $shape | Should -Be 'srv-02'
    }

    It '🔒 THE REGRESSION GUARD -- never the bare identifier, whatever the candidates say' {
        foreach ($m in @(
                @{ MDE_DeviceName = $script:Hex40 },
                @{ ENTRA_DisplayName = $script:Hex40 },
                @{ ENTRA_DisplayName = $script:Hex40; MDE_DeviceName = $script:Hex40 },
                @{ EG_RawData = @{ deviceName = $script:Hex40 } }
            )) {
            script:AskDisplayName -Meta $m -PrimaryEntityId $script:Hex40 -Shape $shape |
                Should -Not -Be $script:Hex40
        }
    }
}

Describe '🔒 NOTHING GROUPS ON THE ENDPOINT DisplayName -- which is WHY returning null is safe' {

    # 🪤 THE FIRST VERSION OF THIS CHECK WAS RUN AGAINST THE WRONG DIRECTORY AND FOUND NOTHING.
    # The shipped report catalog is `risk-analysis-detection/`, NOT `engine/risk-analysis/` (which
    # holds only the engine). A grep of the second returns zero hits and reads exactly like "no
    # consumer" -- the same shape as the `grep -o "SI_[A-Za-z]*_CL"` miss the last handoff records.
    # The catalog in fact references `DisplayName` 207 times.
    #
    # 🔑 WHY THIS MATTERS AT ALL. Turning 78 distinct hex values into null MERGES them wherever a
    # query groups by the column -- the FUSING failure `SIWeakIdTypes` calls the worse of the two, and
    # `DisplayName` is on that list by name. So the safety of this change rests on a property of the
    # catalog, and a property nothing asserts is a property that changes.

    BeforeAll {
        $script:Catalog = Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
        $raw = [System.IO.File]::ReadAllText($script:Catalog)
        # Each report starts at `    - ReportName:` -- 4-space indent under the `Reports:` root.
        $script:ReportBlocks = @([regex]::Split($raw, '(?m)^    - ReportName:') | Select-Object -Skip 1)
        # #505 -- the reports read their devices from the CI (SI_CI_CL, class "device") instead of
        # SI_Endpoint_Profile_CL. A report reads devices when its CI block's class filter names "device"; it is checked
        # with the block itself removed (the canonical block projects si_display_name for every class).
        $script:DeviceReports = @(foreach ($b in $script:ReportBlocks) {
            $cls = [regex]::Match($b, 'where tostring\(si_class\) in \(([^)]*)\)').Groups[1].Value
            if ($cls -notmatch '"device"') { continue }
            [pscustomobject]@{
                Name         = (($b -split "`n")[0]).Trim()
                DeviceOnly   = ($cls -notmatch '"identity"')
                Body         = [regex]::Replace($b, '(?s)//__SI_CI_(LINK|ASSET)_BEGIN__.*?//__SI_CI_\1_END__', '')
            }
        })
    }

    It 'the catalog actually parsed -- or the two assertions below prove nothing' {
        # A source-splitting test that matches nothing passes vacuously. If the catalog is ever
        # restructured, this fails LOUDLY instead of turning the rest of this block into a no-op.
        $script:ReportBlocks.Count | Should -BeGreaterThan 100
        @($script:DeviceReports).Count | Should -BeGreaterThan 10 -Because 'the device reports must be found (#505)'
        @($script:DeviceReports | Where-Object DeviceOnly).Count | Should -BeGreaterThan 5
    }

    It 'NO report that reads only devices references a display name at all' {
        # Measured 2026-09-01: 0 of the 126 reports read the endpoint profile's DisplayName. #505: the device-only CI
        # reports (class filter without "identity") read neither DisplayName nor the CI's si_display_name. The
        # identity-and-device reports (admin logon to a device) read the USER's display name, from the identity side.
        $offenders = @($script:DeviceReports | Where-Object { $_.DeviceOnly -and $_.Body -match 'DisplayName|si_display_name' } | ForEach-Object Name)
        ($offenders -join ', ') | Should -Be ''
    }

    It '🔴 and no device report GROUPS BY one -- the assertion that would catch a fused row' {
        $offenders = @()
        foreach ($r in $script:DeviceReports) {
            foreach ($m in [regex]::Matches($r.Body, '(?m)^\s*(\|\s*)?(summarize[^\r\n]*)?by\s+([^\r\n]*)$')) {
                if ($m.Groups[3].Value -match '\b(DisplayName|si_display_name)\b') { $offenders += "$($r.Name) :: $($m.Value.Trim())" }
            }
        }
        ($offenders -join ' | ') | Should -Be ''
    }
}

Describe '🔬 THE TESTS ABOVE GUARD SOMETHING REAL -- the pre-fix chain is run and fails them' {

    # 🔑 A test that would pass against the OLD code guards nothing. The pre-fix DisplayName chain is
    # reproduced verbatim here and asserted to produce exactly the defect, so if someone reverts the
    # guard these assertions are what changes -- not merely a comment.
    BeforeAll {
        function script:PreFixDisplayName {
            param([hashtable]$Meta)
            if ($Meta.ContainsKey('ENTRA_DisplayName') -and -not [string]::IsNullOrWhiteSpace([string]$Meta['ENTRA_DisplayName'])) {
                return [string]$Meta['ENTRA_DisplayName']
            }
            if ($Meta.ContainsKey('MDE_DeviceName') -and -not [string]::IsNullOrWhiteSpace([string]$Meta['MDE_DeviceName'])) {
                $s = [string]$Meta['MDE_DeviceName']
                if ($s.Contains('.')) { return $s.Substring(0, $s.IndexOf('.')) }
                return $s
            }
            return $null
        }
    }

    It 'the old chain publishes the machine id -- which is the 78 rows' {
        script:PreFixDisplayName -Meta @{ MDE_DeviceName = $script:Hex40 } | Should -Be $script:Hex40
    }

    It 'the old chain also hides a real name behind it' {
        # EG carried 'srv-01' all along; the old chain returned at rung 2 and never asked.
        script:PreFixDisplayName -Meta @{ MDE_DeviceName = $script:Hex40 } | Should -Not -Be 'srv-01'
    }
}
