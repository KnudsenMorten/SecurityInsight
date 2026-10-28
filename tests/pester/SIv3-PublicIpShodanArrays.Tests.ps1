#Requires -Version 5.1
<#
    EVERY source=shodan FIELD MUST ACTUALLY RESOLVE -- measured 2026-08-28 as 0 of 7.

    🔴 THE DEFECT. Given a Shodan payload containing every value they ask for, ALL SEVEN
    `source: shodan` fields in the publicip profile resolved EMPTY -- OpenPortServices, Hostnames,
    Asn, Isp, OrgName, Country, ShodanLastSeen. Not a subset, not a data condition: none of them had
    ever worked, for any customer. Three independent causes, each fatal on its own:

      1. THE ROOT PREFIX. Paths were authored 'shodan.isp', but the object handed to the walker IS the
         parsed Shodan payload, so it looked for a property literally named 'shodan'.
      2. PROSE IN THE PATH. 'country_code (ISO 3166-1 alpha-2)' and 'data[*] -- per-port {...}' carry
         their explanation in the same string, which becomes part of the segment name.
      3. THE PS 5.1 SINGLE-ELEMENT UNWRAP. `hostnames: ["one.host"]` returns from the dotted-path
         walker as a STRING, and the caller's `-is [string]` guard -- which exists so a scalar is not
         iterated character by character -- then discards it. TWO hostnames worked; ONE vanished.

    🪤 WHY IT SURVIVED SO LONG: the failure is silent. No exception, no warning, just an empty field.
    And the neighbouring COUNT fields (OpenPortCount, VulnCount) have their own working
    implementations, so a row shipped `OpenPortCount = 3` beside `OpenPorts = []` and read as
    "nothing found" rather than "nothing worked". The RA reports mv-expand the ARRAY, so they returned
    zero rows for an internet-facing asset while the count said three ports were open.

    ⚠️ IT ALSO INVALIDATED A CONCLUSION. "This estate has no CVEs" was never a measurement -- `Vulns`
    could not have been populated whatever Shodan returned. Absence was not evidence of absence.

    🔑 SO THE TESTS BELOW ASSERT RESOLUTION AND AGREEMENT, not non-emptiness of live data. A count
    computed independently of the thing it counts will drift again; agreement is the property neither
    side can fake alone.
#>

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:Shared    = Join-Path (Split-Path -Parent $script:SIRootDir) 'engine\asset-profiling\shared'
    $script:Builder   = Join-Path $script:Shared 'Build-PublicIpProfileRow.ps1'
    $script:SchemaFile= Join-Path (Split-Path -Parent $script:SIRootDir) 'asset-profiling-schema\public-ip.schema.locked.json'

    # 🪤 The payload goes to a FILE, not into the child's command line. Embedding JSON in a here-string
    # inside a -Command mangles the quoting and produced a payload the child parsed differently from
    # the parent -- which briefly looked like a code defect and was not.
    function script:RunInChild {
        param([Parameter(Mandatory)][string]$Body, [Parameter(Mandatory)][hashtable]$Payload)
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ("shodan-" + [guid]::NewGuid().ToString('N') + ".json")
        ($Payload | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $file -Encoding UTF8
        try {
            $cmd = @"
`$ErrorActionPreference='Stop'
. '$($script:Builder)'
`$json = Get-Content -LiteralPath '$file' -Raw
`$rec  = [pscustomobject]@{ Metadata = @{ 'SHODAN_RawJson' = `$json; 'IP_Address' = '1.2.3.4' } }
`$ctx  = @{ Record = `$rec; PrimaryEntityId = '1.2.3.4'; Verdict = `$null; EntityIds = @(); EgNodeId = '';
            RunContext = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z' } }
$Body
"@
            $out  = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd 2>&1
            $line = @($out) | Where-Object { "$_" -like '<R>*' } | Select-Object -Last 1
            if (-not $line) { throw ("child produced nothing; output: " + (($out | Select-Object -Last 6) -join ' | ')) }
            ([string]$line) -replace '^<R>',''
        } finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    }

    $script:Full = @{
        ip_str='1.2.3.4'; ports=@(22,80,443); vulns=@('CVE-2021-1234')
        hostnames=@('one.example.com'); country_code='DK'; org='ExampleOrg'; isp='ExampleISP'
        last_update='2026-08-01T00:00:00'; asn='AS12345'
        data=@(@{ port=22; transport='tcp'; product='OpenSSH'; vulns=@{ 'CVE-2022-9999'=@{ cvss=9.8 } } })
    }
}

Describe 'every source=shodan field resolves' {

    It 'all of them -- it was 0 of 7' {
        $body = @'
$schema = Get-SIPublicIpSchema
$dead = @()
foreach ($f in @($schema.fields | Where-Object { $_.source -eq 'shodan' })) {
    $v = Resolve-SISourceValue -Field $f -Record $rec
    $n = if ($null -eq $v) { 0 } else { @($v).Count }
    if ($n -eq 0) { $dead += $f.name }
}
'<R>' + $(if ($dead.Count) { $dead -join ',' } else { 'ALL-RESOLVE' })
'@
        script:RunInChild -Body $body -Payload $script:Full | Should -Be 'ALL-RESOLVE'
    }

    It 'a ONE-element array survives -- the PS 5.1 unwrap that made two work and one vanish' {
        $one = @{ ip_str='1.2.3.4'; hostnames=@('only.example.com') }
        $body = @'
$schema = Get-SIPublicIpSchema
$f = $schema.fields | Where-Object { $_.name -ceq 'Hostnames' }
$v = Resolve-SISourceValue -Field $f -Record $rec
'<R>' + @($v).Count
'@
        script:RunInChild -Body $body -Payload $one | Should -Be '1'
    }
}

Describe 'the array and its count come from one code path' {

    It 'OpenPorts / OpenPortCount agree, and Vulns / VulnCount agree' {
        $body = @'
$o  = Get-SIDerivedValue -Field ([pscustomobject]@{ name='OpenPorts' }) -Context $ctx
$oc = Get-SIDerivedValue     -Field ([pscustomobject]@{ name='OpenPortCount' }) -Context $ctx
$v  = Get-SIDerivedValue -Field ([pscustomobject]@{ name='Vulns' }) -Context $ctx
$vc = Get-SIDerivedValue     -Field ([pscustomobject]@{ name='VulnCount' })     -Context $ctx
'<R>{0}|{1}|{2}|{3}' -f @($o).Count, $oc, @($v).Count, $vc
'@
        $r = (script:RunInChild -Body $body -Payload $script:Full) -split '\|'
        $r[0] | Should -Be '3'   # ports 22,80,443
        $r[1] | Should -Be $r[0] -Because 'the schema defines OpenPortCount AS array_length(OpenPorts)'
        $r[2] | Should -Be '2'   # top-level vulns[] UNION data[].vulns keys
        $r[3] | Should -Be $r[2] -Because 'VulnCount must count the array it ships beside'
    }

    It 'an empty payload agrees at zero -- so "none" stays distinguishable from "broken"' {
        $body = @'
$o  = Get-SIDerivedValue -Field ([pscustomobject]@{ name='OpenPorts' }) -Context $ctx
$oc = Get-SIDerivedValue     -Field ([pscustomobject]@{ name='OpenPortCount' }) -Context $ctx
'<R>{0}|{1}' -f @($o).Count, $oc
'@
        $r = (script:RunInChild -Body $body -Payload @{ ip_str='1.2.3.4' }) -split '\|'
        $r[0] | Should -Be '0'
        $r[1] | Should -Be '0'
    }
}

Describe 'the resolver tolerates the authoring slip that caused this' {

    It 'a sourcePath keeps working even if a root prefix or prose is reintroduced' {
        # The schema paths are correct now; this pins the NORMALISER, so the same slip cannot silently
        # cost a field again. Both forms below are what the schema actually shipped.
        $body = @'
$a = _NormalizeSourcePath -Path 'shodan.country_code (ISO 3166-1 alpha-2)' -Root 'shodan'
$b = _NormalizeSourcePath -Path 'shodan.data[*] -- per-port {port}'        -Root 'shodan'
$c = _NormalizeSourcePath -Path 'isp'                                       -Root 'shodan'
'<R>{0}|{1}|{2}' -f $a, $b, $c
'@
        $r = (script:RunInChild -Body $body -Payload $script:Full) -split '\|'
        $r[0] | Should -Be 'country_code'
        $r[1] | Should -Be 'data[*]'
        $r[2] | Should -Be 'isp' -Because 'an already-correct path must pass through untouched'
    }
}
