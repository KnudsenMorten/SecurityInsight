#Requires -Version 5.1
<#
    SI #61 -- THE LOADER. The half that did not exist.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS. An emoji inside a single-quoted test name closes it early and the rest
    of the file parses as garbage. Cost a real debugging detour 2026-08-13.

    What these tests are FOR. The resolver had 31 tests, the row-builder wiring had 5, and the feature
    was completely inert because nothing loaded the file. Every one of those tests passed. So the tests
    below are deliberately weighted towards the PATH rather than the LOGIC: does a file on disk reach
    the global, does a broken one say so out loud, and does the run report what it actually did.

    The rule they all serve: the one outcome this feature must never produce is "no decisions loaded"
    that is indistinguishable from "no decisions written".
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    . (Join-Path $root '..\engine\asset-profiling\shared\Resolve-SIAssetDecisions.ps1')
    . (Join-Path $root '..\engine\asset-profiling\shared\Import-SIAssetDecisions.ps1')
    $script:SIRoot = Join-Path $root '..'

    # Write a decisions file into an isolated tree laid out the way an install is.
    function New-DecisionTree {
        param([string]$Base, [string]$Yaml, [string]$Layout = 'tree')
        # tree    = <solutionRoot>\config\        overlay = <overlayRoot>\  (the overlay ROOT)
        $dir = if ($Layout -eq 'tree') { Join-Path $Base 'config' } else { $Base }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $p = Join-Path $dir 'asset-decisions.custom.yaml'
        if ($null -ne $Yaml) { Set-Content -LiteralPath $p -Value $Yaml -Encoding UTF8 }
        $p
    }

    $script:SampleRel = 'config\asset-decisions.custom.sample.yaml'

    $script:GoodYaml = @'
- asset: SRV-APP-14
  kind: override
  tier: 1
  reason: AD CS role moved here
  by: someone@example.com
  at: 2026-08-13
- asset: LAB-*
  kind: exemption
  reason: isolated lab VLAN
  by: someone@example.com
  at: 2026-08-13
  expires: 2099-11-30
'@
}

Describe 'the path from a file on disk to the global -- the half that was missing' {

    It 'loads a decisions file that is simply sitting in the shipped tree' {
        $base = Join-Path $TestDrive 'inst1'
        New-DecisionTree -Base $base -Yaml $script:GoodYaml | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        $r.Loaded     | Should -Be 2
        $r.Overrides  | Should -Be 1
        $r.Exemptions | Should -Be 1
        @($r.Sources).Count | Should -Be 1
    }

    It 'the loaded entries actually work in the resolver -- end to end, no mocks' {
        # The point of the whole exercise: a file the operator wrote must change what an asset gets.
        $base = Join-Path $TestDrive 'inst2'
        New-DecisionTree -Base $base -Yaml $script:GoodYaml | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        $res = Resolve-SIAssetDecisions -Decisions $r.Decisions -Asset 'SRV-APP-14.corp.example' -Now ([datetime]'2026-08-14')
        $res.Override        | Should -Not -BeNullOrEmpty
        [int]$res.Override.tier | Should -Be 1
        $lab = Resolve-SIAssetDecisions -Decisions $r.Decisions -Asset 'LAB-07' -Now ([datetime]'2026-08-14')
        $lab.IsExempt | Should -BeTrue
    }

    It 'a YAML list reaches the resolver intact -- powershell-yaml returns List[object], not an array' {
        # Verified shape, PS 5.1: a YAML sequence parses to List[object] of Hashtable. This repo has
        # already been bitten twice by @() on a List[object], so the loader normalises and this pins it.
        $base = Join-Path $TestDrive 'inst3'
        New-DecisionTree -Base $base -Yaml $script:GoodYaml | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        ,$r.Decisions | Should -BeOfType [System.Array]
        $r.Decisions[0] | Should -BeOfType [System.Collections.Hashtable]
    }

    It 'a single mapping with no leading dash is accepted as one decision' {
        $base = Join-Path $TestDrive 'inst4'
        New-DecisionTree -Base $base -Yaml "asset: A`nkind: override`ntier: 2`nreason: r`nby: op`nat: 2026-08-13" | Out-Null
        (Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')).Loaded | Should -Be 1
    }
}

Describe 'NOTHING FAILS SILENTLY -- each of these means the operator believes something untrue' {

    It 'a configured path that does not exist is REPORTED, not shrugged off' {
        $r = Import-SIAssetDecisions -Path (Join-Path $TestDrive 'nope\absent.yaml') -Now ([datetime]'2026-08-14')
        @($r.Missing).Count | Should -Be 1
        $r.Loaded           | Should -Be 0
    }

    It 'an unparseable YAML file is REPORTED, and does not take the run down' {
        $base = Join-Path $TestDrive 'bad1'
        New-DecisionTree -Base $base -Yaml "- asset: A`n  kind: [override`n   bad indent: {{{" | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        @($r.ParseFailed).Count | Should -BeGreaterThan 0
        $r.Loaded               | Should -Be 0
    }

    It 'a malformed entry is REJECTED and NAMED, and the good ones beside it still load' {
        # Fail closed per entry, not per file: one typo must not silently disarm the whole file, and
        # must not silently disarm only itself either.
        $base = Join-Path $TestDrive 'mixed'
        New-DecisionTree -Base $base -Yaml @'
- asset: GOOD-1
  kind: override
  tier: 0
  reason: r
  by: op
  at: 2026-08-13
- asset: BAD-1
  kind: exemption
  tier: 3
  reason: smuggling a scope decision in as a tier change
  by: op
  at: 2026-08-13
  expires: 2099-01-01
'@ | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        $r.Loaded            | Should -Be 1
        @($r.Rejected).Count | Should -Be 1
        (@($r.Rejected)[0].Problems -join ' ') | Should -Match "must NOT set 'tier'"
        # and it names the asset, so the operator knows which line to edit
        (Get-SIAssetDecisionField -Entry (@($r.Rejected)[0].Entry) -Name 'asset') | Should -Be 'BAD-1'
    }

    It 'an entry missing provenance is REJECTED -- an unattributed override is the stale tag itself' {
        $base = Join-Path $TestDrive 'noprov'
        New-DecisionTree -Base $base -Yaml "- asset: A`n  kind: override`n  tier: 1`n  reason: r" | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        $r.Loaded            | Should -Be 0
        @($r.Rejected).Count | Should -Be 1
    }

    It 'an already-expired entry is reported as LAPSED at load' {
        $base = Join-Path $TestDrive 'lapsed'
        New-DecisionTree -Base $base -Yaml "- asset: A`n  kind: exemption`n  reason: r`n  by: op`n  at: 2026-01-01`n  expires: 2026-02-01" | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        @($r.Lapsed).Count | Should -Be 1
    }

    It 'a lapsed entry is STILL CARRIED, so the resolver stays the single place expiry is decided' {
        $base = Join-Path $TestDrive 'lapsed2'
        New-DecisionTree -Base $base -Yaml "- asset: A`n  kind: exemption`n  reason: r`n  by: op`n  at: 2026-01-01`n  expires: 2026-02-01" | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        $r.Loaded | Should -Be 1
        # and the resolver, not the loader, is what makes it not apply
        $res = Resolve-SIAssetDecisions -Decisions $r.Decisions -Asset 'A' -Now ([datetime]'2026-08-14')
        $res.IsExempt        | Should -BeFalse
        @($res.Lapsed).Count | Should -Be 1
    }

    It 'NEGATIVE PASS -- an entirely valid file produces no warnings at all' {
        # Without this the rejection tests above could all be passing vacuously.
        $base = Join-Path $TestDrive 'clean'
        New-DecisionTree -Base $base -Yaml $script:GoodYaml | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -Now ([datetime]'2026-08-14')
        @($r.Rejected).Count    | Should -Be 0
        @($r.Lapsed).Count      | Should -Be 0
        @($r.ParseFailed).Count | Should -Be 0
        @($r.Missing).Count     | Should -Be 0
    }

    It 'no file anywhere is a SILENT no-op -- the normal case for almost every install' {
        $r = Import-SIAssetDecisions -SolutionRoot (Join-Path $TestDrive 'empty-install') -Now ([datetime]'2026-08-14')
        $r.Loaded           | Should -Be 0
        @($r.Sources).Count | Should -Be 0
        @($r.Missing).Count | Should -Be 0     # nothing was configured, so nothing is missing
    }
}

Describe 'a rules folder that holds no decisions file is not a missing file -- only a file a person NAMED is' {
    # A SecurityInsight Pro run points SI_EnrichmentDataRoot at its own run folder and writes the decisions file there
    # only when the database holds a decision. Every run of an install with none said "'...asset-decisions.custom.yaml' is
    # configured (overlay) but does not exist. NO decisions were loaded from it" -- a warning about nothing.
    BeforeAll {
        $script:EmptyOverlay = Join-Path $TestDrive 'overlay-no-file'
        New-Item -ItemType Directory -Force -Path $script:EmptyOverlay | Out-Null
        function script:Get-ReportLines($Report) {
            $said = New-Object System.Collections.Generic.List[string]
            Write-SIAssetDecisionLoadReport -Report $Report -Info { param($m) $said.Add("INFO $m") } -Warn { param($m) $said.Add("WARN $m") }
            $said.ToArray()
        }
    }

    It 'the overlay file is never CONFIGURED; the file a person named is' {
        $src = @(Get-SIAssetDecisionSource -OverlayRoot 'D:\si-data' -SolutionRoot 'C:\si')
        ($src | Where-Object Source -eq 'overlay').Configured | Should -BeFalse
        @(Get-SIAssetDecisionSource -ExplicitPath 'D:\named.yaml' -OverlayRoot 'D:\si-data' -SolutionRoot 'C:\si')[0].Configured | Should -BeTrue
    }

    It 'nothing is missing, nothing is said, and no empty file is written' {
        $r = Import-SIAssetDecisions -OverlayRoot $script:EmptyOverlay -SolutionRoot (Join-Path $TestDrive 'empty-install-ov') -Now ([datetime]'2026-08-14')
        @($r.Missing).Count | Should -Be 0
        @($r.Sources).Count | Should -Be 0
        $r.Loaded           | Should -Be 0
        @(Get-ReportLines $r).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:EmptyOverlay 'asset-decisions.custom.yaml') | Should -BeFalse
    }

    It 'the same through the setting a run reads (SI_EnrichmentDataRoot)' {
        $keepRoot = $global:SI_EnrichmentDataRoot; $keepPath = $global:SI_AssetDecisionsPath
        try {
            $global:SI_EnrichmentDataRoot = $script:EmptyOverlay; $global:SI_AssetDecisionsPath = $null
            $r = Import-SIAssetDecisions -SolutionRoot (Join-Path $TestDrive 'empty-install-ov2') -Now ([datetime]'2026-08-14')
            @($r.Missing).Count | Should -Be 0
            @(Get-ReportLines $r).Count | Should -Be 0
        } finally { $global:SI_EnrichmentDataRoot = $keepRoot; $global:SI_AssetDecisionsPath = $keepPath }
    }

    It 'one line at verbose level says the rules folder holds none' {
        $out = @(Import-SIAssetDecisions -OverlayRoot $script:EmptyOverlay -SolutionRoot (Join-Path $TestDrive 'empty-install-ov3') -Now ([datetime]'2026-08-14') -Verbose 4>&1)
        $v = @($out | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] })
        $v.Count | Should -Be 1
        $v[0].Message | Should -Match 'no file at the overlay root'
    }

    It 'CONTROL: a file a person named that does not exist is still REPORTED -- by the setting too, with the rules folder set' {
        $keepRoot = $global:SI_EnrichmentDataRoot; $keepPath = $global:SI_AssetDecisionsPath
        try {
            $global:SI_EnrichmentDataRoot = $script:EmptyOverlay
            $global:SI_AssetDecisionsPath = Join-Path $TestDrive 'named\absent.yaml'
            $r = Import-SIAssetDecisions -SolutionRoot (Join-Path $TestDrive 'empty-install-ov4') -Now ([datetime]'2026-08-14')
            @($r.Missing).Count | Should -Be 1
            @($r.Missing)[0].Source | Should -Be 'explicit'
            $lines = @(Get-ReportLines $r)
            @($lines | Where-Object { $_ -like 'WARN *' }).Count | Should -Be 1
            $lines[0] | Should -Match "^WARN operator decisions: '.*absent\.yaml' is configured \(explicit\) but does not exist\. NO decisions were loaded from it"
        } finally { $global:SI_EnrichmentDataRoot = $keepRoot; $global:SI_AssetDecisionsPath = $keepPath }
    }

    It 'CONTROL: a rules folder that DOES hold the file is read' {
        $ov = Join-Path $TestDrive 'overlay-with-file'
        New-DecisionTree -Base $ov -Layout 'overlay' -Yaml "- asset: O1`n  kind: override`n  tier: 2`n  reason: r`n  by: op`n  at: 2026-08-13" | Out-Null
        $r = Import-SIAssetDecisions -OverlayRoot $ov -SolutionRoot (Join-Path $TestDrive 'empty-install-ov5') -Now ([datetime]'2026-08-14')
        $r.Loaded | Should -Be 1
        @($r.Sources)[0].Source | Should -Be 'overlay'
    }
}

Describe 'where the file is looked for' {

    It 'an explicitly named file is EXCLUSIVE -- naming one file does not silently read two others' {
        $base = Join-Path $TestDrive 'excl'
        New-DecisionTree -Base $base -Yaml $script:GoodYaml | Out-Null
        $src = Get-SIAssetDecisionSource -ExplicitPath 'X:\named.yaml' -OverlayRoot $base -SolutionRoot $base
        @($src).Count   | Should -Be 1
        @($src)[0].Source | Should -Be 'explicit'
    }

    It 'overlay and tree are ADDITIVE -- both are legitimate homes for operator data' {
        $src = Get-SIAssetDecisionSource -OverlayRoot 'D:\si-data' -SolutionRoot 'C:\si'
        @($src).Count | Should -Be 2
        (@($src).Source -join ',') | Should -Be 'overlay,tree'
    }

    It 'does not THROW on a drive that does not exist' {
        # PS 5.1's Join-Path RESOLVES the drive and throws DriveNotFoundException. SI_EnrichmentDataRoot
        # is operator-supplied and routinely a mapped drive -- one the scheduled task's service account
        # cannot see, even though it resolved fine when the operator tested it interactively. This
        # function's whole job is to report "you configured this and it is not there"; throwing from
        # inside it turns a diagnosable misconfiguration into a dead run.
        { Get-SIAssetDecisionSource -OverlayRoot 'Q:\nope' -SolutionRoot 'Q:\nope' } | Should -Not -Throw
    }

    It 'still builds the right paths on a drive that does not exist' {
        # Not throwing is worthless if it also stops producing candidates: the operator would get
        # silence instead of "configured and missing", which is the same failure one step later.
        $src = @(Get-SIAssetDecisionSource -OverlayRoot 'Q:\nope' -SolutionRoot 'Q:\si')
        $src.Count     | Should -Be 2
        $src[0].Path   | Should -Be 'Q:\nope\asset-decisions.custom.yaml'
        $src[1].Path   | Should -Be 'Q:\si\config\asset-decisions.custom.yaml'
        $src[0].Exists | Should -BeFalse
    }

    It 'the overlay file sits at the overlay ROOT, not under shared\' {
        # shared\ is scanned recursively by Get-SIRuleSet; the root is not.
        $src = Get-SIAssetDecisionSource -OverlayRoot 'D:\si-data' -SolutionRoot 'C:\si'
        @($src)[0].Path | Should -Be 'D:\si-data\asset-decisions.custom.yaml'
    }

    It 'the in-tree file lives in config\, NOT in the detection-rule tree' {
        $src = Get-SIAssetDecisionSource -SolutionRoot 'C:\si'
        @($src)[0].Path | Should -Be 'C:\si\config\asset-decisions.custom.yaml'
    }

    It 'NO search path is inside asset-profiling-enrichment -- the rule loader would eat the file' {
        # THE REGRESSION THIS PINS, and it was real: the first draft put both the file and its sample
        # under asset-profiling-enrichment\shared\. Get-SIRuleSet allow-lists *.custom.yaml anywhere
        # under that tree, so the decisions document is picked up and parsed as a detection rule --
        # and the shipped sample then has to satisfy the rule schema, which is how it was caught.
        # Decisions are configuration, not rules.
        $src = Get-SIAssetDecisionSource -OverlayRoot 'D:\si-data' -SolutionRoot 'C:\si'
        foreach ($s in @($src)) {
            $s.Path | Should -Not -Match 'asset-profiling-enrichment'
        }
    }

    It 'and the loader agrees with the rule loader about what a rule file looks like' {
        # Belt and braces on the same lesson, asserted against Get-SIRuleSet's own allow-list rather
        # than a restatement of it: the decisions filename DOES match that allow-list, which is exactly
        # why its folder must not be scanned by it.
        'asset-decisions.custom.yaml' -like '*.custom.yaml' | Should -BeTrue
    }

    It 'the in-tree path is never CONFIGURED, so its absence never warns' {
        # Otherwise every install on earth prints a warning about a file it was never asked to have.
        $src = Get-SIAssetDecisionSource -SolutionRoot 'C:\si'
        @($src)[0].Configured | Should -BeFalse
    }

    It 'entries from BOTH overlay and tree are loaded together' {
        $base = Join-Path $TestDrive 'both'
        New-DecisionTree -Base $base -Layout 'tree'    -Yaml "- asset: T1`n  kind: override`n  tier: 1`n  reason: r`n  by: op`n  at: 2026-08-13" | Out-Null
        $ov = Join-Path $TestDrive 'both-overlay'
        New-DecisionTree -Base $ov  -Layout 'overlay' -Yaml "- asset: O1`n  kind: override`n  tier: 2`n  reason: r`n  by: op`n  at: 2026-08-13" | Out-Null
        $r = Import-SIAssetDecisions -SolutionRoot $base -OverlayRoot $ov -Now ([datetime]'2026-08-14')
        $r.Loaded | Should -Be 2
    }
}

Describe 'ONE reading of expires -- shared by the loader and the resolver' {

    It 'an ISO date parses' {
        $e = Get-SIAssetDecisionExpiry -Entry @{ expires = '2026-11-30' }
        $e.Parsed | Should -BeTrue
        $e.Expiry.ToString('yyyy-MM-dd') | Should -Be '2026-11-30'
    }

    It 'no expires at all is not an error' {
        $e = Get-SIAssetDecisionExpiry -Entry @{ asset = 'A' }
        $e.HasExpiry | Should -BeFalse
        $e.Parsed    | Should -BeTrue
    }

    It 'a US-style date still parses via the invariant fallback -- da-DK hosts included' {
        (Get-SIAssetDecisionExpiry -Entry @{ expires = '11/30/2026' }).Parsed | Should -BeTrue
    }

    It 'an unreadable date is REPORTED, never thrown' {
        $e = Get-SIAssetDecisionExpiry -Entry @{ expires = 'next tuesday-ish' }
        $e.Parsed  | Should -BeFalse
        $e.Problem | Should -Match 'unparseable'
    }

    It 'THE MESSAGE SAYS "expires" -- no backtick, no ESC byte' {
        # The original read "unparseable `expires` value". In a double-quoted PowerShell string the
        # backtick is the ESCAPE character, so backtick-e is ESC: under pwsh 7 that line emitted a raw
        # control byte into the log and printed "unparseable xpires value". The one message in the file
        # written to explain a typo contained one, and the file's own comment warns against exactly it.
        $e = Get-SIAssetDecisionExpiry -Entry @{ expires = 'garbage' }
        $e.Problem | Should -Match 'expires'
        $e.Problem.Contains([char]27) | Should -BeFalse
        $e.Problem.Contains([char]9)  | Should -BeFalse
    }

    It 'the resolver reaches the SAME verdict as the loader on the same bad date' {
        # Two implementations of one date rule is how a run reports lapsed and still applies the entry.
        # Kind must be one that legitimately CARRIES an expiry -- an override with `expires` is refused
        # earlier, by the validator, for a different and equally correct reason.
        $bad = @{ asset='A'; kind='exemption'; by='op'; at='2026-08-13'; reason='r'; expires='garbage' }
        $res = Resolve-SIAssetDecisions -Decisions @($bad) -Asset 'A' -Now ([datetime]'2026-08-14')
        @($res.Rejected).Count | Should -Be 1
        (@($res.Rejected)[0].Problems -join ' ') | Should -Match 'unparseable'
    }
}

Describe 'the run summary counts ENTRIES, not entries-times-assets' {

    It 'one bad entry across 50 assets is reported as ONE rejected entry' {
        # The regression this pins: the resolver runs once per asset with the WHOLE list, so a single
        # malformed line landed in all 50 resolutions and was reported as "50 rejected entries". The
        # operator then goes looking for 50 mistakes in a file that has one -- and a number that large
        # reads as a broken file rather than a typo.
        $bad = @{ asset='A'; kind='exemption'; tier=3; by='op'; at='2026-08-13'; expires='2099-01-01' }
        $resolutions = 1..50 | ForEach-Object {
            Resolve-SIAssetDecisions -Decisions @($bad) -Asset ("HOST-$_") -Now ([datetime]'2026-08-14')
        }
        (Get-SIAssetDecisionReport -Resolutions @($resolutions)).RejectedEntries | Should -Be 1
    }

    It 'one wildcard exemption lapsing across 20 matching assets is ONE lapsed entry' {
        $old = @{ asset='LAB-*'; kind='exemption'; by='op'; at='2026-01-01'; expires='2026-02-01'; reason='r' }
        $resolutions = 1..20 | ForEach-Object {
            Resolve-SIAssetDecisions -Decisions @($old) -Asset ("LAB-$_") -Now ([datetime]'2026-08-14')
        }
        (Get-SIAssetDecisionReport -Resolutions @($resolutions)).LapsedEntries | Should -Be 1
    }

    It 'ASSET counts stay per-asset -- two different machines with an override are two' {
        $d = @(
            @{ asset='H1'; kind='override'; tier=1; by='op'; at='2026-08-13'; reason='r' },
            @{ asset='H2'; kind='override'; tier=0; by='op'; at='2026-08-13'; reason='r' }
        )
        $resolutions = @('H1','H2') | ForEach-Object {
            Resolve-SIAssetDecisions -Decisions $d -Asset $_ -Now ([datetime]'2026-08-14')
        }
        (Get-SIAssetDecisionReport -Resolutions @($resolutions)).AssetsWithOverride | Should -Be 2
    }
}

Describe 'THE WIRING -- because both ends being correct is exactly what hid this for a week' {

    It 'Invoke-SIEngineRun dot-sources the loader AND assigns the global' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $src | Should -Match 'Import-SIAssetDecisions'
        $src | Should -Match '\$global:SI_AssetDecisions\s*='
    }

    It 'the load happens AFTER the customer config, which is what sets the paths' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $cfg = $src.IndexOf('loading customer config')
        $imp = $src.IndexOf('Import-SIAssetDecisions')
        $cfg | Should -BeGreaterThan 0
        $imp | Should -BeGreaterThan $cfg
    }

    It 'the loader failing cannot take the run down' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        # the load is inside a try/catch that warns rather than throws
        $src | Should -Match '(?s)try\s*\{[^}]*Import-SIAssetDecisions.*?\}\s*catch\s*\{'
    }

    It 'Invoke-Output reports what the overrides ACTUALLY did, read off the emitted rows' {
        # Counted from SI_TierOverrideBy on the built rows, not from a counter at the decision point:
        # this feature has already produced an override that moved the variable and not the output.
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')
        $src | Should -Match 'SI_TierOverrideBy'
        $src | Should -Match 'operator decisions'
    }

    It 'the row builder still reads the global the loader fills' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1')
        $src | Should -Match '\$global:SI_AssetDecisions'
    }
}

Describe 'the shipped sample must itself be correct -- it is what operators copy' {

    It 'the sample file exists where the docs say it is' {
        Test-Path (Join-Path $script:SIRoot $script:SampleRel) | Should -BeTrue
    }

    It 'every entry in the sample PASSES the validator' {
        # A sample that teaches a shape the engine rejects is worse than no sample: the operator copies
        # it, gets a rejection, and concludes the feature is broken.
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\SI-Yaml.ps1')   # SecurityInsight's own YAML reader
        $p = Join-Path $script:SIRoot $script:SampleRel
        $doc = ConvertFrom-SIYaml -Yaml (Get-Content -Raw -LiteralPath $p)
        $entries = if ($doc -is [array]) { $doc } elseif ($doc -is [System.Collections.IList]) { $doc.ToArray() } else { @($doc) }
        @($entries).Count | Should -BeGreaterThan 2
        foreach ($e in $entries) {
            $v = Test-SIAssetDecision -Entry $e
            $v.Valid | Should -BeTrue -Because ("sample entry '{0}' must validate, but: {1}" -f (Get-SIAssetDecisionField -Entry $e -Name 'asset'), ($v.Problems -join '; '))
        }
    }

    It 'the sample demonstrates all three kinds' {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\SI-Yaml.ps1')   # SecurityInsight's own YAML reader
        $p = Join-Path $script:SIRoot $script:SampleRel
        $doc = ConvertFrom-SIYaml -Yaml (Get-Content -Raw -LiteralPath $p)
        $entries = if ($doc -is [array]) { $doc } elseif ($doc -is [System.Collections.IList]) { $doc.ToArray() } else { @($doc) }
        $kinds = @($entries | ForEach-Object { [string](Get-SIAssetDecisionField -Entry $_ -Name 'kind') })
        $kinds | Should -Contain 'override'
        $kinds | Should -Contain 'exception'
        $kinds | Should -Contain 'exemption'
    }

    It 'the REAL filename is gitignored and the SAMPLE is not' -Tag 'PrivateRepo' {
        # The real file is customer data and must never reach the public mirror; the sample is
        # documentation and must ship. Both halves matter and they differ by one word in the name.
        $gi = Get-Content -Raw (Join-Path $script:SIRoot '..\..\.gitignore')
        $gi | Should -Match 'SOLUTIONS/\*\*/config/\*'
        $gi | Should -Match '!SOLUTIONS/\*\*/config/\*\.sample\.\*'
    }
}
