#Requires -Version 5.1
<#
    AUDIT #59.3 / N3 + N4 -- every DECLARED table name must be a table SI actually writes.

    Found by the naming pass, 2026-08-11. Two declarations named tables that exist nowhere:

      N3  analyzer-web SiTables.cs declared "SI_PublicIP_Profile_CL" while the engine wrote
          SI_VulnerabilityPIP_CL, so every PublicIP query the Analyzer issued failed to resolve.
          Nothing caught it because the SIA hosted live-verify gate has never run.
      N4  azure.schema.locked.json declared "Azure_Profile_CL"; the real table is SI_Azure_Profile_CL.
          Not a live defect -- nothing reads the schema's `table` field at runtime -- but it is the
          file a connector author or frontend developer consults, and it named a table that does not
          exist. The same bare-name bug sat in 10 places in the PUBLIC DESIGN.md, including a
          copy-pasteable KQL example and the doc's own table inventory.

    🔑 THE ROOT CAUSE WAS ONE ASSUMPTION: that every engine's table follows SI_<Engine>_Profile_CL.
    Three did and publicip did not, so anything deriving the name from the pattern was silently wrong
    for publicip -- and, as N3 shows, anything ASSUMING the pattern was wrong in the other direction.

    ✅ RESOLVED AT THE ROOT, not per-caller (operator ruling): publicip was renamed
    SI_VulnerabilityPIP_CL -> SI_PublicIP_Profile_CL, so THE ASSUMPTION IS NOW TRUE for all four
    engines and N3's original declaration became the correct one. The legacy name is retired; it
    survives only in RELEASENOTES history and in old run logs.

    ⚠️ WHAT THESE TESTS GUARD NOW IS THE OPPOSITE OF WHAT THEY GUARDED BEFORE. The risk is no longer
    "someone applies the pattern to publicip" -- it is a PARTIAL REVERT: a table rename is only safe
    as one atomic edit across the schema, the launcher default, the correlation map, the RA catalog
    and the SIA constants, so these assert every one of those surfaces agrees, and that the retired
    name is gone from all of them.

    🪤 CASING IS LOAD-BEARING. KQL table names are case-sensitive and the `SI_{0}_Profile` pattern
    title-cases the engine key to `SI_Publicip_Profile` -- lowercase `ip`, a DIFFERENT table from the
    declared `SI_PublicIP_Profile`. That is why the launcher still ships an explicit name rather than
    letting the pattern derive it, and why the assertions below match case-sensitively.

    These tests assert the DECLARATIONS agree with the ENGINE. They deliberately do not contact Azure.
#>

BeforeAll {
    $script:SIRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaDir  = Join-Path $script:SIRoot 'asset-profiling-schema'

    # The authority: what the engine actually ingests to. All four now share ONE rule,
    # SI_<Engine>_Profile_CL.
    #   - endpoint/identity/azure come from the SI_<Engine>_Profile pattern in
    #     engine/asset-profiling/stages/Invoke-Output.ps1 (module appends _CL)
    #   - publicip names the SAME shape explicitly via $global:SI_PublicIp_TableName in
    #     launcher/publicip/LauncherConfig.defaults.ps1, because the pattern would
    #     title-case it to the wrongly-cased 'SI_Publicip_Profile'.
    $script:RealTables = @{
        endpoint = 'SI_Endpoint_Profile_CL'
        identity = 'SI_Identity_Profile_CL'
        azure    = 'SI_Azure_Profile_CL'
        publicip = 'SI_PublicIP_Profile_CL'
    }

    # The retired name. No LIVE code may reference it.
    $script:RetiredPublicIpTable = 'SI_VulnerabilityPIP'

    # Comments may name the retired table -- explaining why it was dropped is how the next reader
    # avoids restoring it, and the .cs assertion below has always worked this way. What must never
    # come back is an executable reference, so match on code lines only.
    function script:Get-CodeLines {
        param([string]$Path)
        $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        $commentPrefix = if ($ext -in @('.cs')) { '//' } else { '#' }
        # JSON/YAML have no comment syntax we honour here: '#' covers yaml, and json keys such as
        # "_comment" are deliberately NOT exempt -- a declared name in data is a live declaration.
        Get-Content $Path | Where-Object { -not $_.TrimStart().StartsWith($commentPrefix) }
    }
}

Describe 'Declared table names resolve to real tables -- audit #59.3 N3/N4' {

    Context 'the publicip name is genuinely shipped (the premise of every assertion below)' {

        It 'ships SI_PublicIp_TableName in the publicip launcher defaults' {
            # If this stops being shipped, publicip falls back to the pattern-derived
            # SI_Publicip_Profile_CL -- lowercase 'ip', a DIFFERENT table in case-sensitive KQL.
            # The symptom is the worst kind: the run reports LA=OK while a second, near-identically
            # named table quietly appears and every declared query keeps reading the empty one.
            $defaults = Join-Path $script:SIRoot 'launcher\publicip\LauncherConfig.defaults.ps1'
            $defaults | Should -Exist
            $txt = Get-Content $defaults -Raw
            $txt | Should -Match '\$global:SI_PublicIp_TableName\s*=\s*[''"]SI_PublicIP_Profile[''"]'
        }

        It 'ships the matching DCR name, since a table is only created by its DCR' {
            $defaults = Join-Path $script:SIRoot 'launcher\publicip\LauncherConfig.defaults.ps1'
            $txt = Get-Content $defaults -Raw
            $txt | Should -Match '\$global:SI_PublicIp_DcrName\s*=\s*[''"]dcr-si-publicip-profile[''"]'
        }

        It 'no longer falls back to the retired Shodan-era globals in Invoke-Output' {
            # The legacy fallbacks ($global:SI_Shodan_DcrName / _TableName) are what silently pinned
            # this engine to the old table. A customer custom.ps1 still carrying SI_Shodan_DcrName
            # must NOT be able to drag the engine back off the shared naming rule.
            $out = Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'
            $out | Should -Exist
            $code = (script:Get-CodeLines -Path $out) -join "`n"
            $code | Should -Not -Match '\$global:SI_Shodan_DcrName'
            $code | Should -Not -Match '\$global:SI_Shodan_TableName'
        }
    }

    Context 'the profile schemas' {

        # publicip's schema FILE is hyphenated ('public-ip') while its engine key is not, so the
        # filename cannot be derived from the engine key.
        It 'declares a <_> table matching what the engine writes' -ForEach @('endpoint', 'identity', 'azure', 'publicip') {
            $engine = $_
            $file   = if ($engine -eq 'publicip') { 'public-ip.schema.locked.json' } else { "$engine.schema.locked.json" }
            $path   = Join-Path $script:SchemaDir $file
            $path | Should -Exist
            $json = Get-Content $path -Raw | ConvertFrom-Json
            $json.table | Should -BeExactly $script:RealTables[$engine] `
                -Because "$file is where a connector author looks up the table name"
        }

        It 'declares the publicip table with the SAME rule as the other three, and the right CASING' {
            # -BeExactly, not -Be: 'SI_Publicip_Profile_CL' would pass a case-insensitive compare and
            # is a different table in KQL. This is the assertion that catches a pattern-derived revert.
            $json = Get-Content (Join-Path $script:SchemaDir 'public-ip.schema.locked.json') -Raw | ConvertFrom-Json
            $json.table | Should -BeExactly 'SI_PublicIP_Profile_CL'
            $json.dcrName | Should -BeExactly 'dcr-si-publicip-profile'
        }

        It 'all four profile schemas now satisfy the ONE naming rule' {
            # The assumption that N3 got wrong is now true, and this is what keeps it true.
            foreach ($engine in @('endpoint', 'identity', 'azure', 'publicip')) {
                $script:RealTables[$engine] | Should -Match '^SI_[A-Za-z]+_Profile_CL$' `
                    -Because "$engine must follow SI_<Engine>_Profile_CL like its three siblings"
            }
        }

        It 'never declares a bare <Engine>_Profile_CL name in any schema `table` field' {
            foreach ($f in Get-ChildItem $script:SchemaDir -Filter '*.locked.json') {
                $json = Get-Content $f.FullName -Raw | ConvertFrom-Json
                if (-not $json.table) { continue }
                $json.table | Should -Match '^SI_' -Because "$($f.Name) declares '$($json.table)'"
            }
        }
    }

    Context 'the SCHEMA.locked.json engine registry' {

        It 'names every engine table correctly' {
            $reg = (Get-Content (Join-Path $script:SchemaDir 'SCHEMA.locked.json') -Raw | ConvertFrom-Json).vocabularies.engines
            foreach ($e in $reg) {
                $script:RealTables.ContainsKey($e.name) | Should -BeTrue -Because "registry lists engine '$($e.name)'"
                $e.table | Should -Be $script:RealTables[$e.name]
            }
        }
    }

    # ⚠️ SIA / analyzer-web is NOT part of the new architecture (operator, 2026-08-11: "we dont use
    # analyzer in current design ... from the new architecture"). The repo-root DOCS/REQUIREMENTS.md v3
    # design never specifies it -- RING-1 carries an OPTIONAL `web-frontend` capability and states SIA
    # is "an extension of SI, not the main program", with engine-only SI a supported topology.
    # The SI Analyzer was then RETIRED and DELETED from the tree in every edition (3ba7a2310 "delete the retired
    # SI Analyzer") -- it is not an edition-optional part that one install has and another lacks. So these checks
    # exist only while its code is in the tree: decided at DISCOVERY, so an absent analyzer creates no test at all
    # instead of two SKIPPED ones (owner 2026-10-25: the gate counts a skip as NOT a pass). The retired table name
    # stays guarded in every shipped .cs file by 'the retired name is gone from everything that SHIPS' below.
    if (Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'analyzer-web\src')) {
    Context 'the SIA Analyzer (analyzer-web) -- retired; checked only while its code is in the tree' {

        It 'binds each profile table to the name the engine actually writes' {
            $cs = Join-Path $script:SIRoot 'analyzer-web\src\SIAnalyzer.Core\Kql\SiTables.cs'
            # the analyzer's code IS in the tree (discovery found it): its table file must be there -- a fail, never a skip
            Test-Path $cs | Should -BeTrue -Because 'analyzer-web\src is present, so its SiTables.cs must be'
            $txt = Get-Content $cs -Raw

            $expect = @{
                EndpointProfile = $script:RealTables['endpoint']
                IdentityProfile = $script:RealTables['identity']
                AzureProfile    = $script:RealTables['azure']
                PublicIpProfile = $script:RealTables['publicip']
            }
            foreach ($const in $expect.Keys) {
                $m = [regex]::Match($txt, ('(?m)^\s*public\s+const\s+string\s+{0}\s*=\s*"([^"]+)"' -f $const))
                $m.Success | Should -BeTrue -Because "SiTables.cs must declare $const"
                $m.Groups[1].Value | Should -Be $expect[$const] `
                    -Because "SIA queries $const; a wrong name fails at runtime, not at build"
            }
        }

        It 'never uses the RETIRED SI_VulnerabilityPIP_CL in CODE' {
            # 🔄 THIS ASSERTION REVERSED when publicip was renamed. It used to forbid
            # SI_PublicIP_Profile_CL, which is now the correct name; what must never come back is the
            # retired one. Comment lines are allowed to name it, so the history stays readable.
            $src = Join-Path $script:SIRoot 'analyzer-web\src'
            $bad = @()
            foreach ($f in Get-ChildItem $src -Recurse -File -Include '*.cs') {
                $n = 0
                foreach ($line in (Get-Content $f.FullName)) {
                    $n++
                    if ($line.TrimStart().StartsWith('//')) { continue }
                    if ($line -match $script:RetiredPublicIpTable) { $bad += "$($f.Name):$n" }
                }
            }
            $bad.Count | Should -Be 0 -Because "that table is retired; found at: $($bad -join ', ')"
        }
    }
    }

    Context 'the retired name is gone from everything that SHIPS' {

        # A table rename is only safe as ONE atomic edit. This is the assertion that fails on a
        # partial revert -- the failure mode where the engine writes the new table while some caller
        # still queries the old one and silently returns nothing.
        It 'no shipped file still references SI_VulnerabilityPIP' {
            # 'tests' is excluded because THIS file names the retired string in order to assert its
            # absence, and so would fail itself. Test files ship nothing at runtime.
            $skipDirs = @('logs', 'output', 'staging', 'preview', 'demo', '.git', 'tests')
            $bad = @()
            foreach ($f in Get-ChildItem $script:SIRoot -Recurse -File -Include '*.ps1','*.psm1','*.json','*.yaml','*.yml','*.cs') {
                $rel = $f.FullName.Substring($script:SIRoot.Length).TrimStart('\')
                if ($skipDirs | Where-Object { $rel -like "$_\*" }) { continue }
                # HISTORY, named one by one: the 2.2.460 defaults the first 3.0 run compares a customer's settings with
                # (#276). It records what 2.2 set -- the retired name included -- and is never loaded as configuration.
                if ($rel -eq 'launcher\_lib\v2.2-engine-defaults.locked.json') {
                    (Get-Content -Raw $f.FullName | ConvertFrom-Json).about | Should -Match 'never loaded as configuration'
                    continue
                }
                $code = (script:Get-CodeLines -Path $f.FullName) -join "`n"
                if ($code -match $script:RetiredPublicIpTable) { $bad += $rel }
            }
            # RELEASENOTES.md and old run logs keep the name as HISTORY and are not scanned here --
            # they ship nothing and describe what was true at the time.
            $bad.Count | Should -Be 0 -Because "partial rename left the retired table in: $($bad -join ', ')"
        }
    }

    Context 'the PUBLIC docs -- customers copy KQL straight out of these' {

        It 'uses no bare <Engine>_Profile_CL in <_>' -ForEach @('README.md', 'docs\DESIGN.md', 'docs\FEATURES.md') {
            $path = Join-Path $script:SIRoot $_
            if (-not (Test-Path $path)) { Set-ItResult -Skipped -Because "$_ not present"; return }
            $txt = Get-Content $path -Raw
            # (?<![A-Za-z_]) so SI_Endpoint_Profile_CL does not match its own tail.
            $bad = [regex]::Matches($txt, '(?<![A-Za-z_])(Endpoint|Identity|Azure|PublicIP)_Profile_CL')
            $bad.Count | Should -Be 0 -Because "a bare name in a published example is a query that returns nothing"
        }
    }
}
