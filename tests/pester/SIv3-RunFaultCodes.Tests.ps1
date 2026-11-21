#Requires -Version 5.1
<#
    2026-11-20 -- EVERY RUN FAULT SECURITYINSIGHT WORDS ITSELF CARRIES A STABLE CODE AND A KNOWN ERROR CLASS (Invardia
    run-monitor alignment gaps DD1CE0D5, 1B60BEDE, 48774ED3, 76E31E82, D38A715D, 83EC46B2, A52FD36A, 523D91A7, B6142C3C;
    framework 8.16: "every product warning needs a stable code and a known error class"). Invardia's run monitor
    (faultCodeOf) takes a fault's code from the first si-<area>-<nnnn> in the run's text, else the ONE code its Reports[]
    items carry; a class 'unknown' or no code opens an alignment gap.
    What must hold (OFFLINE: no network, the sender's transport is a stub):
      * Resolve-SIRunFaultCode: each fault text of those runs -> its catalogue code; an unknown text -> '' (never a guess);
      * every code the rules can give is in the catalogue (both copies), of a CauseClass of the closed list;
      * the run record of such a run: ErrorClass is not 'unknown', the code leads the identified text, and a Reports[] item
        carries it -- once, also beside other items' codes; anonymous: the item, no text;
      * a run whose code is already known (RunContext.FailureCode) keeps it: the rules add nothing.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SavedEndpointEnv = $env:SI_TELEMETRY_ENDPOINT
    $env:SI_TELEMETRY_ENDPOINT = 'https://127.0.0.1:9/api/uplink/v1/report'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    $script:Catalogue = @(Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\errors.locked.json') -Raw | ConvertFrom-Json)
    $script:Posts = New-Object System.Collections.Generic.List[object]
    $script:StubOk = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $script:Posts.Add(($Record | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json)); [pscustomobject]@{ Status = 'ok'; Reason = 'accepted' } }
    function script:New-Ctx([string]$Mode = 'identified', [string]$Dir) {
        [pscustomobject]@{ Mode = $Mode; Endpoint = 'https://stub.example.test/report'
                           AccessCode = $(if ($Mode -eq 'anonymous') { 'invardia-community-telemetry-v1' } else { 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz' })
                           Edition = $(if ($Mode -eq 'anonymous') { 'community' } else { 'pro' }); LicenceState = $(if ($Mode -eq 'anonymous') { 'none' } else { 'valid' })
                           Version = '3.0.0.202610151900'; Hosting = 'container'; RuntimeIdentity = 'mi-container'
                           InstallId = $(if ($Mode -eq 'anonymous') { '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f' } else { '' })
                           TenantId = $(if ($Mode -eq 'anonymous') { '' } else { '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6' }); StateDirectory = $Dir; Endpoints = @() }
    }
    function script:Send-Fault([string]$Engine, [string]$Text, [string]$Mode = 'identified', [hashtable]$More = @{}) {
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_Telemetry_Enabled = $null
        $global:ReportTemplate = 'RiskAnalysis_Detailed'; $global:SI_RunNoteCodes = $null
        $rc = [pscustomobject]@{ RunId = 'run-1'; Engine = $Engine; ShardIndex = 0; StartedAt = [datetime]'2026-11-20T06:00:00Z'; FailedStep = 'run' }
        foreach ($k in $More.Keys) { $rc | Add-Member -NotePropertyName $k -NotePropertyValue $More[$k] -Force }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage $Text -AssetCount 10 `
            -Context (New-Ctx -Mode $Mode -Dir $TestDrive) -Transport $script:StubOk -Now ([datetime]'2026-11-20T07:00:00Z') -NoHeartbeat
        @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0]
    }
    $script:Texts = @{
        RaUpstream  = "built on incomplete profile data: the newest endpoint profile run ended 'success-partial' -- findings missing from this run are unknown, not resolved"
        CmdbPartial = "partial snapshot -- endpoint: the endpoint run that produced the snapshot ended 'success-partial'. The CIs in the snapshot were created and updated; none of its CIs was counted absent or retired this run (a CI missing from a snapshot that is not complete is unknown, never absent). No action needed: the next complete snapshot counts absences again."
        NotStored   = "SI_Endpoint_Profile_CL: the data collection rule was changed in this run and Azure was not yet storing every column when the rows arrived: this run's values for PrivilegedLogonStatus, Computer are missing. The rows are there; the next run stores these columns."
        CorrWait    = "correlation: Log Analytics has not finished adding the new column 'PrivilegedLogonEvidence' to SI_Endpoint_Profile_CL after 600 s: every read of the table is refused while it names that column. Correlation does not use the column; the next run reads the table again. The service said: Failed to resolve scalar expression named 'PrivilegedLogonEvidence'"
        Settings    = 'SecurityInsight Pro: the settings database srv/db could not be read -- the run stops rather than use other settings. A connection was successfully established with the server, but then an error occurred during the pre-login handshake.'
        TokenExp    = "the prepared view columns failed: Exception calling ""Open"" with ""0"" argument(s): ""Login failed for user '<token-identified principal>'. Token is expired."""
        LaServer    = 'PS>TerminatingError(): "{"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"message":"Partial query failure: 0x80131500 (message: ExecuteRemoteSubQuery failure ===> Status(StatusCode=\"Unavailable\"'
    }
}

AfterAll {
    $env:SI_TELEMETRY_ENDPOINT = $script:SavedEndpointEnv
    $global:SI_TelemetryHalted = $null; $global:SI_TelemetryContext = $null; $global:SI_Telemetry_Enabled = $null; $global:SI_RunNoteCodes = $null
}

Describe 'the run-fault rules: each fault text -> its catalogue code' {
    It '<Key> -> <Code>' -ForEach @(
        @{ Key = 'RaUpstream'; Code = 'si-ra-0915' }
        @{ Key = 'CmdbPartial'; Code = 'si-cmdb-0703' }
        @{ Key = 'NotStored'; Code = 'si-col-0506' }
        @{ Key = 'CorrWait'; Code = 'si-col-0506' }
        @{ Key = 'Settings'; Code = 'si-set-0401' }
        @{ Key = 'TokenExp'; Code = 'si-data-1406' }
        @{ Key = 'LaServer'; Code = 'si-la-1701' }
    ) {
        Resolve-SIRunFaultCode -Text $script:Texts[$Key] | Should -Be $Code
        Get-SIErrorClass -Message $script:Texts[$Key] | Should -Not -Be 'unknown'
    }
    It 'a text no rule knows gives no code (never a guess); nothing gives nothing' {
        Resolve-SIRunFaultCode -Text 'something nobody has seen before' | Should -Be ''
        Resolve-SIRunFaultCode -Text '' | Should -Be ''
        Resolve-SIRunFaultCode -Text $null | Should -Be ''
    }
    It 'every code the rules can give is in the catalogue, with a CauseClass of the closed list; the two catalogue copies are the same' {
        $c = Get-SIUplinkCausesContract
        foreach ($r in @(Get-SIRunFaultRules)) {
            $e = @($script:Catalogue | Where-Object code -eq $r.Code)
            $e.Count | Should -Be 1 -Because "$($r.Code) must be in data-model\errors.locked.json, else its item is dropped"
            $c.CauseClasses | Should -Contain $e[0].causeClass
        }
        @(Get-SIRunFaultRules).Count | Should -BeGreaterOrEqual 6 -Because 'the rules were read, or this test checks nothing'
        (Get-FileHash (Join-Path $script:SIRoot 'data-model\errors.locked.json')).Hash | Should -Be (Get-FileHash (Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\errors.locked.json')).Hash
    }
}

Describe 'the run record of a fault SecurityInsight words itself' {
    It 'DD1CE0D5: Risk Analysis built on a partial profile run -> class upstream-partial, the code first in the text, one item' {
        $r = Send-Fault -Engine 'risk-analysis' -Text $script:Texts.RaUpstream
        $r.Outcome | Should -Be 'warning'
        $r.ErrorClass | Should -Be 'upstream-partial'
        $r.ErrorText | Should -Match '^si-ra-0915: built on incomplete profile data'
        @($r.Reports | Where-Object { $_.Code -eq 'si-ra-0915' }).Count | Should -Be 1
        ($r.Reports | Where-Object { $_.Code -eq 'si-ra-0915' }).Action | Should -Be 'none'
    }
    It '1B60BEDE / A52FD36A: the CMDB sync on a partial snapshot and the endpoint''s columns not stored -> their own class and code' {
        $c = Send-Fault -Engine 'endpoint' -Text $script:Texts.CmdbPartial
        $c.ErrorClass | Should -Be 'upstream-partial'
        $c.ErrorText | Should -Match '^si-cmdb-0703: partial snapshot -- '
        $r = Send-Fault -Engine 'endpoint' -Text $script:Texts.NotStored
        $r.ErrorClass | Should -Be 'column-not-ready'
        $r.ErrorText | Should -Match '^si-col-0506: '
        @($r.Reports | ForEach-Object Code) | Should -Contain 'si-col-0506'
    }
    It 'a run whose items already carry other codes still has ONE stable code: its own, first in the text' {
        # a scoped note of another code on the same run (#1227)
        $global:SI_RunNoteCodes = New-Object System.Collections.Generic.List[object]
        $global:SI_RunNoteCodes.Add([pscustomobject]@{ Code = 'si-col-0505'; Text = 'some sign-ins could not be read'; Step = 'privileged-logons' })
        $script:Posts.Clear(); $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_Telemetry_Enabled = $null
        $rc = [pscustomobject]@{ RunId = 'run-2'; Engine = 'endpoint'; ShardIndex = 0; StartedAt = [datetime]'2026-11-20T06:00:00Z'; FailedStep = 'run' }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'success-partial' -ErrorMessage $script:Texts.NotStored -AssetCount 10 `
            -Context (New-Ctx -Dir $TestDrive) -Transport $script:StubOk -Now ([datetime]'2026-11-20T07:00:00Z') -NoHeartbeat
        $r = @($script:Posts | Where-Object { "$($_.Kind)" -eq 'run' })[0]
        $global:SI_RunNoteCodes = $null
        @($r.Reports | ForEach-Object Code | Sort-Object) | Should -Be @('si-col-0505', 'si-col-0506')
        ([regex]::Match([string]$r.ErrorText, '\bsi-[a-z]+-[0-9]{4}\b')).Value | Should -Be 'si-col-0506' -Because 'Invardia takes the first code in the text'
    }
    It 'D38A715D / 83EC46B2 / B6142C3C: the settings database, an expired token, Log Analytics'' own failure' {
        (Send-Fault -Engine 'endpoint' -Text $script:Texts.Settings).ErrorText | Should -Match '^si-set-0401: '
        $t = Send-Fault -Engine 'endpoint' -Text $script:Texts.TokenExp
        $t.ErrorClass | Should -Be 'sql-login'; $t.ErrorText | Should -Match '^si-data-1406: '
        $l = Send-Fault -Engine 'endpoint' -Text $script:Texts.LaServer
        $l.ErrorClass | Should -Be 'platform-5xx'; @($l.Reports | ForEach-Object Code) | Should -Contain 'si-la-1701'
    }
    It 'a run whose code is already known (FailureCode) keeps it: the rules add no code and no item' {
        $r = Send-Fault -Engine 'endpoint' -Text $script:Texts.NotStored -More @{ FailureCode = 'si-col-0505' }
        @($r.Reports | ForEach-Object Code) | Should -Be @('si-col-0505')
        $r.ErrorText | Should -Not -Match '^si-col-0506'
    }
    It 'a text no rule knows is sent as before: no code put in front, no item' {
        $r = Send-Fault -Engine 'endpoint' -Text 'something nobody has seen before'
        $r.ErrorText | Should -Be 'something nobody has seen before'
        @($r.Reports | Where-Object { $_ }).Count | Should -Be 0
    }
    It 'anonymous (Community): the item goes, no text ever' {
        $r = Send-Fault -Engine 'endpoint' -Text $script:Texts.NotStored -Mode 'anonymous'
        $r.PSObject.Properties['ErrorText'] | Should -BeNullOrEmpty
        $r.ErrorClass | Should -Be 'column-not-ready'
    }
}
