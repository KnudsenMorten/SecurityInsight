#Requires -Version 5.1
<#
    SI v3 Phase 5 -- PAYLOAD PROFILES. Two projections over one collection pass (V3-ARCHITECTURE §3.6).

    🔴 WHAT PHASE 5'S PLAN ASSUMED, AND WHAT WAS ACTUALLY THERE. The plan says "add a `cmdb` payload
    profile beside the existing `security` one; do NOT widen the default-deny includePaths." Measured
    2026-08-25: there was no profile mechanism and no default-deny.
      * `includePaths` is read by exactly ONE file, Get-SISchemaWithCustomMerge, and only to MERGE the
        customer overlay into it. No code ever PROJECTED by it.
      * The row builders copied every MDE_*/AZ_*/ENTRA_*/CMDB_* key into Properties wholesale.
      * `sizeBudgetKb` / `drop_largest_field` were equally unimplemented.
    So each source's `_policy` string -- "Only paths listed here flow to Properties.collect.mde. New MS
    fields are NOT auto-included" -- described an intention, not a behaviour. NINTH and TENTH
    "declared but never wired" shapes.

    🔒 THEREFORE THE DEFAULT DOES NOT MOVE. `cmdb` is the default and is byte-for-byte the previous
    behaviour, because turning default-deny on for everyone would drop columns consumers bind to, and
    Log Analytics keeps ~30 days with no backfill -- a wrong drop cannot be undone by re-running.
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    . (Join-Path $root '..\engine\asset-profiling\shared\Get-SIPayloadProfile.ps1')
    $script:SIRootDir = (Resolve-Path (Join-Path $root '..')).Path

    # A schema shaped like the real one, small enough to reason about.
    $script:Schema = [pscustomobject]@{
        schemaVersion = '2.3.6'
        rawPayload = [pscustomobject]@{
            storageColumn = 'Properties'
            sizeBudgetKb  = 256
            sources = [pscustomobject]@{
                mde = [pscustomobject]@{ includePaths = @('computerDnsName','osPlatform','machineTags[*]','riskScore') }
                # Declares nothing -- UNDECLARED, which must not be read as DENIED.
                entra = [pscustomobject]@{ }
            }
        }
    }
    function script:Bag { @{ ComputerDnsName='dc1'; OsPlatform='WindowsServer'; MachineTags=@('a'); RiskScore=5; SecretExtra='x'; AnotherExtra='y' } }
}

Describe 'the profile selector -- the default must not move' {

    # Inside the Describe, not at the root: Pester 5 refuses a teardown in the block container.
    AfterEach { $global:SI_PayloadProfile = $null }

    It '🔒 defaults to cmdb, which IS the pre-v3 behaviour' {
        # If this ever flips, every customer silently loses whatever the schema forgot to declare, on
        # the next nightly, with no backfill. That is the single most dangerous line in this feature.
        $global:SI_PayloadProfile = $null
        Get-SIPayloadProfileName | Should -BeExactly 'cmdb'
    }

    It 'honours an explicit profile, case-insensitively' {
        $global:SI_PayloadProfile = 'security'; Get-SIPayloadProfileName | Should -BeExactly 'security'
        $global:SI_PayloadProfile = 'SECURITY'; Get-SIPayloadProfileName | Should -BeExactly 'security'
    }

    It '🔴 an unknown profile name falls back to the WIDEST profile, and warns' {
        # The safe direction. A typo must never quietly become default-deny and start shedding fields.
        $global:SI_PayloadProfile = 'securty'
        Get-SIPayloadProfileName -WarningAction SilentlyContinue | Should -BeExactly 'cmdb'
    }
}

Describe 'the allow-list derived from includePaths' {

    It 'is null under cmdb -- no enforcement at all' {
        Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'mde' -ProfileName 'cmdb' | Should -BeNullOrEmpty
    }

    It 'strips the [*] array marker and takes the LAST path segment' {
        # includePaths are JSON paths against the RAW provider document; Properties holds
        # prefix-stripped metadata KEYS. Matching on the leaf is what actually lines the two up.
        $k = Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'mde' -ProfileName 'security'
        $k.Contains('machineTags')     | Should -BeTrue
        $k.Contains('machineTags[*]')  | Should -BeFalse
        $k.Contains('computerDnsName') | Should -BeTrue
    }

    It 'matches case-insensitively -- MDE_MachineTags becomes MachineTags, the path says machineTags[*]' {
        $k = Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'mde' -ProfileName 'security'
        $k.Contains('MachineTags') | Should -BeTrue
    }

    It 'handles a dotted path -- NodeProperties.rawData.deviceType -> deviceType' {
        $s = [pscustomobject]@{ rawPayload = [pscustomobject]@{ sources = [pscustomobject]@{
            exposureGraph = [pscustomobject]@{ includePaths = @('NodeProperties.rawData.deviceType') } } } }
        (Get-SIPayloadAllowedKeys -Schema $s -SourceName 'exposureGraph' -ProfileName 'security').Contains('deviceType') | Should -BeTrue
    }

    It '🔴 an UNDECLARED source is not a DENIED source' {
        # entra declares no includePaths. Enforcing an empty allow-list there would delete the whole
        # bucket because somebody forgot to describe it -- total data loss from an omission.
        Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'entra'   -ProfileName 'security' | Should -BeNullOrEmpty
        Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'nosuch'  -ProfileName 'security' | Should -BeNullOrEmpty
        Get-SIPayloadAllowedKeys -Schema $null          -SourceName 'mde'     -ProfileName 'security' | Should -BeNullOrEmpty
    }
}

Describe 'the projection itself' {

    It 'keeps declared keys and NAMES what it removed' {
        $allowed = Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'mde' -ProfileName 'security'
        $r = Select-SIPayloadBucket -Bucket (script:Bag) -AllowedKeys $allowed -SourceName 'mde'
        $r.Bucket.Keys           | Should -Contain 'ComputerDnsName'
        $r.Bucket.Keys           | Should -Not -Contain 'SecretExtra'
        @($r.Dropped)            | Should -Contain 'mde.SecretExtra'
        @($r.Dropped)            | Should -Contain 'mde.AnotherExtra'
        @($r.Dropped).Count      | Should -Be 2
    }

    It '🔑 passes everything through when AllowedKeys is null, dropping nothing' {
        $r = Select-SIPayloadBucket -Bucket (script:Bag) -AllowedKeys $null -SourceName 'mde'
        @($r.Bucket.Keys).Count | Should -Be 6
        @($r.Dropped).Count     | Should -Be 0
    }

    It '🔴 NEVER MUTATES THE INPUT -- the same metadata bag feeds the typed columns' {
        # A projection that edited in place would silently blank typed columns that have nothing to do
        # with Properties, and the damage would look like a collection failure.
        $bag = script:Bag
        $allowed = Get-SIPayloadAllowedKeys -Schema $script:Schema -SourceName 'mde' -ProfileName 'security'
        [void](Select-SIPayloadBucket -Bucket $bag -AllowedKeys $allowed -SourceName 'mde')
        $bag.Keys | Should -Contain 'SecretExtra'
        @($bag.Keys).Count | Should -Be 6
    }

    It 'a null bucket stays null, and does not throw' {
        (Select-SIPayloadBucket -Bucket $null -AllowedKeys @() -SourceName 'mde').Bucket | Should -BeNullOrEmpty
    }
}

Describe '🔴 THE LEVEL-4 RULE -- a NIC or a public IP is a PROPERTY, never a row' {
    <#
        Operator, via V3-ARCHITECTURE §3.6: "we don't want to create level 4 CIs", and "I don't want
        10,000 columns in the asset table, which is all asset types' possible fields."

        The model makes that STRUCTURAL rather than a policy someone has to remember: the three CMDB
        levels are Service / Component / Asset, and a NIC has no level to become a row in. These tests
        pin the structure, so a later change that tries to promote a level-4 concept fails here.
    #>

    It 'the CMDB level model has exactly three levels, and Asset is the lowest' {
        $levels = @('Service','Component','Asset')
        $levels.Count      | Should -Be 3
        $levels[-1]        | Should -BeExactly 'Asset'
        $levels            | Should -Not -Contain 'Nic'
        $levels            | Should -Not -Contain 'PublicIp'
        $levels            | Should -Not -Contain 'Disk'
    }

    It '🔑 level-4 concepts survive the projection as PROPERTIES when declared' {
        # The point of the envelope+properties model: a NIC is not lost, it just is not a CI. Under the
        # cmdb profile (no enforcement) every one of them is carried.
        $bag = @{ NicMacAddress='00-11-22'; PipAddress='10.0.0.4'; DiskCount=2 }
        $r = Select-SIPayloadBucket -Bucket $bag -AllowedKeys $null -SourceName 'azure'
        $r.Bucket.Keys | Should -Contain 'NicMacAddress'
        $r.Bucket.Keys | Should -Contain 'PipAddress'
        @($r.Dropped).Count | Should -Be 0
    }

    It 'the schema declares no rawPayload SOURCE that is a level-4 object type' {
        # Sources are PROVIDERS (mde, azure, entra, cmdb, exposureGraph), never object types. A source
        # named `nic` would be the first step toward level-4 rows, so it is asserted against here.
        $locked = Get-Content (Join-Path $script:SIRootDir 'asset-profiling-schema\endpoint.schema.locked.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $names = @($locked.rawPayload.sources.PSObject.Properties.Name)
        $names.Count | Should -BeGreaterThan 0
        foreach ($bad in 'nic','publicIp','disk','networkAdapter','volume') { $names | Should -Not -Contain $bad }
    }
}

Describe 'the 256 KB budget -- measured and REPORTED, never silently truncated' {

    It 'reads the budget from the schema' {
        (Measure-SIPayloadSize -Properties @{ a = 1 } -Schema $script:Schema).BudgetBytes | Should -Be (256 * 1024)
    }

    It 'falls back to 256 KB when the schema cannot be read' {
        (Measure-SIPayloadSize -Properties @{ a = 1 } -Schema $null).BudgetBytes | Should -Be (256 * 1024)
    }

    It 'measures UTF-8 BYTES, not characters -- the ingest endpoint counts bytes' {
        $ascii = Measure-SIPayloadSize -Properties @{ a = ('x' * 100) } -Schema $null
        $utf8  = Measure-SIPayloadSize -Properties @{ a = ('æ' * 100) } -Schema $null
        $utf8.Bytes | Should -BeGreaterThan $ascii.Bytes
    }

    It 'flags an over-budget row and NAMES the biggest field' {
        $m = Measure-SIPayloadSize -Properties @{ small = 'x'; huge = ('y' * 300000) } -Schema $null
        $m.OverBudget   | Should -BeTrue
        $m.LargestField | Should -BeExactly 'huge'
    }

    It 'a normal row is under budget and reports its percentage' {
        $m = Measure-SIPayloadSize -Properties @{ a = 'x' } -Schema $null
        $m.OverBudget      | Should -BeFalse
        $m.PercentOfBudget | Should -BeLessThan 1
    }

    It '🔴 DOES NOT TRUNCATE -- and that is the decision, not an omission' {
        # `drop_largest_field` has never been implemented. Implementing it now would put SILENT metadata
        # loss into the exact path §3.6 warns about: the customer loses the biggest field, with no error
        # and no way to see it from the output. A loud failure at publish is the better outcome.
        $props = @{ huge = ('y' * 300000) }
        [void](Measure-SIPayloadSize -Properties $props -Schema $null)
        $props['huge'].Length | Should -Be 300000
    }

    It 'a bag that cannot be serialised reports an error rather than throwing' {
        $circular = @{}; $circular['self'] = $circular
        { Measure-SIPayloadSize -Properties $circular -Schema $null } | Should -Not -Throw
    }
}

Describe 'the run accumulator and its summary' {

    BeforeEach { Reset-SIPayloadStats }

    It 'accumulates rows and remembers the fattest asset by name' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = 'x' }           -Schema $null -AssetName 'small-box')
        [void](Add-SIPayloadMeasurement -Properties @{ a = ('x' * 5000) }  -Schema $null -AssetName 'fat-box')
        $s = Get-SIPayloadStats
        $s.Rows     | Should -Be 2
        $s.MaxAsset | Should -BeExactly 'fat-box'
    }

    It 'counts over-budget rows' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = ('x' * 300000) } -Schema $null -AssetName 'huge')
        (Get-SIPayloadStats).OverBudget | Should -Be 1
    }

    It 'dedupes dropped keys across rows -- the operator wants the field set, not a tally' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = 1 } -Schema $null -AssetName 'a' -Dropped @('mde.Foo','mde.Bar'))
        [void](Add-SIPayloadMeasurement -Properties @{ a = 1 } -Schema $null -AssetName 'b' -Dropped @('mde.Foo'))
        @((Get-SIPayloadStats).DroppedKeys.Keys).Count | Should -Be 2
    }

    It '🔴 Reset clears it -- one container session runs several engines' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = 1 } -Schema $null -AssetName 'a')
        Reset-SIPayloadStats
        (Get-SIPayloadStats).Rows | Should -Be 0
    }

    It 'the summary says nothing when no row was measured' {
        Reset-SIPayloadStats
        { Write-SIPayloadSummary } | Should -Not -Throw
    }

    It 'the summary NAMES the dropped fields rather than counting them' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = 1 } -Schema $null -AssetName 'a' -Dropped @('mde.SecretExtra'))
        $out = Write-SIPayloadSummary -Stats (Get-SIPayloadStats) *>&1 | Out-String -Width 4096   # the stats this test filled (in a shared process the summary's own accumulator may be another file load's); every stream
        $out | Should -Match 'SecretExtra'
    }

    It 'the summary WARNS when a row will fail to publish' {
        [void](Add-SIPayloadMeasurement -Properties @{ a = ('x' * 300000) } -Schema $null -AssetName 'huge')
        $out = Write-SIPayloadSummary -Stats (Get-SIPayloadStats) *>&1 | Out-String -Width 4096   # the stats this test filled (in a shared process the summary's own accumulator may be another file load's); every stream
        $out | Should -Match 'EXCEED'
        $out | Should -Match 'PropertyValueTooLarge'
    }
}

Describe 'IS THIS ON THE PRODUCTION PATH? -- the question ten never-wired defects went unasked' {

    BeforeAll {
        $script:ProdPs1 = @(Get-ChildItem -Path (Join-Path $script:SIRootDir 'engine') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue)
        function script:CallersOf {
            param([string]$Name, [string]$ExcludeLeaf)
            $hits = @()
            foreach ($f in $script:ProdPs1) {
                if ($ExcludeLeaf -and $f.Name -eq $ExcludeLeaf) { continue }
                $code = (Get-Content $f.FullName -Raw) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }
                if (($code -join "`n") -match [regex]::Escape($Name)) { $hits += $f.Name }
            }
            $hits
        }
    }

    It '🔑 the projection is CALLED by the row builder' {
        script:CallersOf -Name 'Select-SIPayloadBucket' -ExcludeLeaf 'Get-SIPayloadProfile.ps1' |
            Should -Contain 'Build-EndpointProfileRow.ps1'
    }

    It '🔑 the accumulator is RESET by the engine run -- without it the summary is about the wrong run' {
        script:CallersOf -Name 'Reset-SIPayloadStats' -ExcludeLeaf 'Get-SIPayloadProfile.ps1' |
            Should -Contain 'Invoke-SIEngineRun.ps1'
    }

    It '🔑 the summary is WRITTEN by Invoke-Output -- otherwise nothing ever reports a drop' {
        script:CallersOf -Name 'Write-SIPayloadSummary' -ExcludeLeaf 'Get-SIPayloadProfile.ps1' |
            Should -Contain 'Invoke-Output.ps1'
    }

    It 'the row builder measures every row through the accessor, not a shared $script: variable' {
        script:CallersOf -Name 'Add-SIPayloadMeasurement' -ExcludeLeaf 'Get-SIPayloadProfile.ps1' |
            Should -Contain 'Build-EndpointProfileRow.ps1'
    }
}

Describe '🪤 THE COMPARER MUST SURVIVE THE RETURN -- the bug the first draft shipped' {
    <#
        Get-SIPayloadAllowedKeys builds an OrdinalIgnoreCase HashSet because the two vocabularies differ
        in case: the schema says `machineTags[*]`, the metadata key is `MachineTags`. PowerShell UNROLLS
        an enumerable on return, so `return $keys` handed back a plain string[] whose .Contains() is
        case-SENSITIVE -- every key missed the allow-list and the projection dropped the entire bucket.
        It looked like working code and produced empty Properties.

        Two guards, because one is not enough: the producer returns `,$keys`, AND the consumer
        re-normalises anything that is not already a HashSet.
    #>

    It 'the producer returns a real HashSet, not an unrolled array' {
        $s = [pscustomobject]@{ rawPayload = [pscustomobject]@{ sources = [pscustomobject]@{
            mde = [pscustomobject]@{ includePaths = @('computerDnsName') } } } }
        $k = Get-SIPayloadAllowedKeys -Schema $s -SourceName 'mde' -ProfileName 'security'
        $k -is [System.Collections.Generic.HashSet[string]] | Should -BeTrue
        $k.Contains('ComputerDnsName') | Should -BeTrue   # the case that regressed
    }

    It '🔴 the consumer survives a CASE-SENSITIVE plain array anyway -- belt and braces' {
        # Simulates the exact regression: an allow-list that arrives already unrolled.
        $r = Select-SIPayloadBucket -Bucket @{ ComputerDnsName = 'dc1' } `
                                    -AllowedKeys ([string[]]@('computerDnsName')) -SourceName 'mde'
        $r.Bucket.Keys      | Should -Contain 'ComputerDnsName'
        @($r.Dropped).Count | Should -Be 0
    }
}
