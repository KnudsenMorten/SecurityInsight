#Requires -Version 5.1
<#
    AUDIT #59.3 / N3 + N4 -- every DECLARED table name must be a table SI actually writes.

    Found by the naming pass, 2026-08-11. Two declarations named tables that exist nowhere:

      N3  analyzer-web SiTables.cs declared "SI_PublicIP_Profile_CL" -- a string occurring exactly
          ONCE in the whole solution, in that file. The real publicip table is SI_VulnerabilityPIP_CL.
          Every PublicIP query the Analyzer issued would have failed to resolve. Nothing caught it
          because the SIA hosted live-verify gate has never run.
      N4  azure.schema.locked.json declared "Azure_Profile_CL"; the real table is SI_Azure_Profile_CL.
          Not a live defect -- nothing reads the schema's `table` field at runtime -- but it is the
          file a connector author or frontend developer consults, and it named a table that does not
          exist. The same bare-name bug sat in 10 places in the PUBLIC DESIGN.md, including a
          copy-pasteable KQL example and the doc's own table inventory.

    🔑 THE ROOT CAUSE IS ONE ASSUMPTION: that every engine's table follows SI_<Engine>_Profile_CL.
    THREE DO. PUBLICIP DOES NOT -- it keeps the legacy SI_VulnerabilityPIP_CL for continuity with the
    standalone Invoke-PublicIpScanner.ps1 era, applied as a per-engine override. Anything that derives
    a table name from the pattern instead of reading the override is wrong for publicip, silently.

    These tests assert the DECLARATIONS agree with the ENGINE. They deliberately do not contact Azure.
#>

BeforeAll {
    $script:SIRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaDir  = Join-Path $script:SIRoot 'asset-profiling-schema'

    # The authority: what the engine actually ingests to.
    #   - endpoint/identity/azure come from the SI_<Engine>_Profile pattern in
    #     engine/asset-profiling/stages/Invoke-Output.ps1 (module appends _CL)
    #   - publicip is overridden by $global:SI_PublicIp_TableName, shipped in
    #     launcher/publicip/LauncherConfig.defaults.ps1
    $script:RealTables = @{
        endpoint = 'SI_Endpoint_Profile_CL'
        identity = 'SI_Identity_Profile_CL'
        azure    = 'SI_Azure_Profile_CL'
        publicip = 'SI_VulnerabilityPIP_CL'
    }
}

Describe 'Declared table names resolve to real tables -- audit #59.3 N3/N4' {

    Context 'the publicip override is genuinely shipped (the premise of every assertion below)' {

        It 'ships SI_PublicIp_TableName in the publicip launcher defaults' {
            # If this ever stops being shipped, publicip silently falls back to the pattern-derived
            # SI_Publicip_Profile_CL and starts writing to a DIFFERENT table -- customers would see
            # their existing table stop growing while a new one appears. Assert the override exists.
            $defaults = Join-Path $script:SIRoot 'launcher\publicip\LauncherConfig.defaults.ps1'
            $defaults | Should -Exist
            $txt = Get-Content $defaults -Raw
            $txt | Should -Match '\$global:SI_PublicIp_TableName\s*=\s*[''"]SI_VulnerabilityPIP[''"]'
        }
    }

    Context 'the profile schemas' {

        It 'declares a <_> table matching what the engine writes' -ForEach @('endpoint', 'identity', 'azure') {
            $engine = $_
            $path   = Join-Path $script:SchemaDir "$engine.schema.locked.json"
            $path | Should -Exist
            $json = Get-Content $path -Raw | ConvertFrom-Json
            $json.table | Should -Be $script:RealTables[$engine] `
                -Because "$engine.schema.locked.json is where a connector author looks up the table name"
        }

        It 'declares the publicip table as the LEGACY name, not the pattern-derived one' {
            $json = Get-Content (Join-Path $script:SchemaDir 'public-ip.schema.locked.json') -Raw | ConvertFrom-Json
            $json.table | Should -Be 'SI_VulnerabilityPIP_CL'
            $json.table | Should -Not -Be 'SI_PublicIP_Profile_CL'
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
    # These checks therefore SKIP when analyzer-web is absent rather than failing, so this suite
    # survives the component being archived or removed. The constant is still worth keeping correct
    # while the code is in the tree, but nothing here treats it as load-bearing.
    Context 'the SIA Analyzer (analyzer-web) -- N3, optional component' {

        It 'binds each profile table to the name the engine actually writes' {
            $cs = Join-Path $script:SIRoot 'analyzer-web\src\SIAnalyzer.Core\Kql\SiTables.cs'
            if (-not (Test-Path $cs)) {
                Set-ItResult -Skipped -Because 'analyzer-web is not present; it is an optional capability'
                return
            }
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

        It 'never uses the non-existent SI_PublicIP_Profile_CL in CODE' {
            # Comment lines are allowed to name it -- SiTables.cs deliberately records the dead name
            # so the next reader knows why the pattern must not be applied to publicip. What must
            # never come back is a live reference.
            $src = Join-Path $script:SIRoot 'analyzer-web\src'
            if (-not (Test-Path $src)) {
                Set-ItResult -Skipped -Because 'analyzer-web is not present; it is an optional capability'
                return
            }
            $bad = @()
            foreach ($f in Get-ChildItem $src -Recurse -File -Include '*.cs') {
                $n = 0
                foreach ($line in (Get-Content $f.FullName)) {
                    $n++
                    if ($line.TrimStart().StartsWith('//')) { continue }
                    if ($line -match 'SI_PublicIP_Profile_CL') { $bad += "$($f.Name):$n" }
                }
            }
            $bad.Count | Should -Be 0 -Because "that table exists nowhere in the product; found at: $($bad -join ', ')"
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
