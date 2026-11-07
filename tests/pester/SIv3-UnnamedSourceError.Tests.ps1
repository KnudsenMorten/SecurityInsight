#Requires -Version 5.1
<#
    A MISSING DEFENDER TABLE THAT ADVANCED HUNTING DOES NOT NAME IS STILL A MISSING TABLE, NOT A QUERY DEFECT (SUP-2026-00425,
    REQUIREMENTS #1125).

    Measured 2026-11-05, read-only, at a tenant without Defender vulnerability management (no DeviceTvm* tables, DeviceInfo
    present): Device_EndOfSupport_Software_Detailed failed both slices with
      "Operator source expression should be table or column. Fix semantic errors in your query."
    and was reported as a QUERY DEFECT (si-ra-0903), 1 of 69 reports not complete. Reproduced with four small queries there:
      let _src = DeviceTvmSoftwareInventory | ...; let D = DeviceInfo | ...; _src | join (D) ...          -> "Failed to resolve
          table or column expression named 'DeviceTvmSoftwareInventory'"   (the engine's "not applicable here")
      the same with D = union isfuzzy=true (datatable(...)[]), (DeviceInfo) | ...                         -> "Operator source
          expression should be table or column"                             (no table named -> read as a query defect)
    The fuzzy DeviceInfo read came with #1104 (3.0.48); before it the report was "not applicable" there, run after run.

    The engine now asks for each Defender table the query needs on its own when the service gives the unnamed form, and
    says the missing one by name, so it is classified exactly as before. A real defect (every table answers) still fails on
    attempt 1 as a query defect. OFFLINE; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')

    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }
    function script:Add-DynamicGroupKeyCasts { param($Query) $Query }
    function script:Reset-SupersededAttempts { }
    function script:Add-SupersededAttempt { param($Path, $Message) }
    function script:Resolve-SupersededOnSuccess { param($WinningPath) }
    function script:Flush-SupersededAttempts { }
    function script:Save-RARenderedQuery { param($Query, $Tag) }
    function script:Ensure-GraphAuth { param($MaxAgeMinutes) }
    function script:Start-Sleep { param($Seconds, $Milliseconds) }
    function script:Get-DefenderTableOwner { param($TableName) 'owner' }

    # the measured answers (request ids dropped)
    $script:Unnamed = '400 Bad Request -- {"error":{"code":"BadRequest","message":"Operator source expression should be table or column. Fix semantic errors in your query."}}'
    $script:NamedEos = '400 Bad Request -- {"error":{"code":"BadRequest","message":"''take'' operator: Failed to resolve table or column expression named ''DeviceTvmSoftwareInventory''. Fix semantic errors in your query."}}'

    # the shipped report query, as the catalog carries it
    $y = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml'))
    $m = [regex]::Match($y, '(?s)- ReportName: Device_EndOfSupport_Software_Detailed\r?\n.*?ReportQuery:\r?\n\s*- \|-\r?\n(.*?)//__SI_OUT_BEGIN__')
    $script:EosQuery = $m.Groups[1].Value
    # the hunting path without the SI-table hand-off (that part is not what this answer is about)
    $script:EosAh = $script:EosQuery -replace '\bSI_CI_CL\b', 'SiCiLookup'

    # ADVANCED HUNTING at that tenant: the vulnerability tables are not there, DeviceInfo is
    $script:Missing = @('DeviceTvmSoftwareInventory')
    function script:Invoke-SIHuntingQueryRest {
        param($Query, $Token, $TimeoutSec, [switch]$AsResult)
        [void]$script:Sent.Add([string]$Query)
        $p = [regex]::Match([string]$Query, '^\s*([A-Za-z]+) \| take 0\s*$')
        if ($p.Success) {
            $t = $p.Groups[1].Value
            if ($script:Throttled -contains $t) { return [pscustomobject]@{ Ok = $false; Error = '429 Too Many Requests' } }
            if ($script:Missing -contains $t) { return [pscustomobject]@{ Ok = $false; Error = ($script:NamedEos -replace 'DeviceTvmSoftwareInventory', $t) } }
            return [pscustomobject]@{ Ok = $true; Error = $null }
        }
        throw $script:Unnamed
    }
    function script:Reset-Probe {
        $script:_RAHuntingTableAnswer = $null
        $script:Sent = New-Object System.Collections.Generic.List[string]
        $script:Warned = @()
        $script:Throttled = @()
        $script:Missing = @('DeviceTvmSoftwareInventory')
    }
}

Describe 'the measured defect: the unnamed answer alone reads as a query defect' {
    BeforeEach { Reset-Probe }
    It 'the catalog still carries the report and its fuzzy DeviceInfo read (the test would prove nothing otherwise)' {
        $script:EosQuery | Should -Match 'DeviceTvmSoftwareInventory'
        $script:EosQuery | Should -Match 'union isfuzzy=true \(datatable\([^)]*\)\[\]\), \(DeviceInfo\)'
    }
    It 'the raw answer is not "no data source" -- this is what turned the report into a query defect' {
        Test-RANoDataSource -Message $script:Unnamed | Should -BeFalse
        Test-RAUnnamedSourceError -Message $script:Unnamed | Should -BeTrue
        Test-RANoDataSource -Message $script:NamedEos | Should -BeTrue
    }
}

Describe 'the tables a query needs (Get-RAHuntingSourceTables)' {
    BeforeEach { Reset-Probe }
    It 'the end-of-support query needs DeviceTvmSoftwareInventory; DeviceInfo (a fuzzy union leg), its let names and its columns are not listed' {
        $t = @(Get-RAHuntingSourceTables -Query $script:EosQuery)
        $t | Should -Contain 'DeviceTvmSoftwareInventory'
        $t | Should -Not -Contain 'DeviceInfo'
        $t | Should -Not -Contain 'DeviceInfoLatest'
        $t | Should -Not -Contain 'DeviceId'
    }
    It 'a plain (not fuzzy) DeviceInfo read is needed; comments and string literals are not' {
        $q = "// DeviceTvmCertificateInfo in a comment`nlet x = DeviceInfo | where DeviceName == ""DeviceEvents"";`nx | join kind=leftouter (DeviceTvmSoftwareVulnerabilities) on DeviceId"
        $t = @(Get-RAHuntingSourceTables -Query $q)
        ($t -join ',') | Should -Be 'DeviceInfo,DeviceTvmSoftwareVulnerabilities'
    }
}

Describe 'Resolve-RAUnnamedSourceError' {
    BeforeEach { Reset-Probe }
    It 'names the missing table in the service''s own form, so it is "not applicable here"' {
        $r = Resolve-RAUnnamedSourceError -Query $script:EosAh -Message $script:Unnamed
        $r | Should -Match "Failed to resolve table or column expression named 'DeviceTvmSoftwareInventory'"
        Test-RANoDataSource -Message $r | Should -BeTrue
    }
    It 'every table answers: nothing is named and the message stays a query defect' {
        $script:Missing = @()
        Resolve-RAUnnamedSourceError -Query $script:EosAh -Message $script:Unnamed | Should -BeNullOrEmpty
    }
    It 'a probe that is throttled is not taken as missing and is not remembered' {
        $script:Throttled = @('DeviceTvmSoftwareInventory')
        Resolve-RAUnnamedSourceError -Query $script:EosAh -Message $script:Unnamed | Should -BeNullOrEmpty
        $script:_RAHuntingTableAnswer.ContainsKey('DeviceTvmSoftwareInventory') | Should -BeFalse
    }
    It 'any other message is left alone and asks nothing' {
        Resolve-RAUnnamedSourceError -Query $script:EosAh -Message 'case(): return types are not compatible. Fix semantic errors in your query.' | Should -BeNullOrEmpty
        $script:Sent.Count | Should -Be 0
    }
    It 'a table is asked for once per run' {
        [void](Resolve-RAUnnamedSourceError -Query $script:EosAh -Message $script:Unnamed)
        [void](Resolve-RAUnnamedSourceError -Query $script:EosAh -Message $script:Unnamed)
        @($script:Sent | Where-Object { $_ -match '^DeviceTvmSoftwareInventory \| take 0' }).Count | Should -Be 1
    }
}

Describe 'through the hunting call: the report is "not applicable", not a query defect' {
    BeforeEach { Reset-Probe }
    It 'the end-of-support query at a tenant without vulnerability management throws the NAMED answer on attempt 1' {
        $err = $null
        try { [void](Invoke-GraphHuntingQuery -Query $script:EosAh -MaxRetries 4) } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match "named 'DeviceTvmSoftwareInventory'"
        # the bucket loop's and the report's classifier
        Test-RANoDataSource -Message $err.Exception.Message | Should -BeTrue
        @($script:Sent | Where-Object { $_ -notmatch '\| take 0\s*$' }).Count | Should -Be 1 -Because 'a missing table is never retried'
        @($script:Warned | Where-Object { $_ -match 'KQL semantic error' }).Count | Should -Be 0
    }
    It 'when every table is there the same answer is still a query defect on attempt 1' {
        $script:Missing = @()
        $err = $null
        try { [void](Invoke-GraphHuntingQuery -Query $script:EosAh -MaxRetries 4) } catch { $err = $_ }
        $err.Exception.Message | Should -Match 'Operator source expression should be table or column'
        Test-RANoDataSource -Message $err.Exception.Message | Should -BeFalse
        @($script:Sent | Where-Object { $_ -notmatch '\| take 0\s*$' }).Count | Should -Be 1
        @($script:Warned | Where-Object { $_ -match 'KQL semantic error' }).Count | Should -Be 1
    }
}
