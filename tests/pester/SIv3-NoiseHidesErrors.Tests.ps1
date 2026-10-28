#Requires -Version 5.1
<#
    NOISE THAT HID REAL ERRORS (live 2026-10-23).

      * THE CAPABILITY PROBE (engine\_shared\SI-UplinkCauses.ps1 Get-SICapabilityProbeLaQuery) asks for SecurityIncident and
        SecurityAlert. In a workspace without Sentinel Log Analytics answers HTTP 200 + a partial error "Failed to resolve
        table or column expression named 'SecurityIncident'" beside the other legs' rows -- the whole result. The verdict
        (engine\_shared\SI-AzRest.ps1 Get-SILaPartialVerdict) allowed only SI tables to be missing, so the whole answer was
        refused and the status report left out the Sentinel, CMDB and CI-column details. Now the probe names the tables
        that may be missing (-MayBeMissing); any other unresolved table is still refused.
      * THE RECORDS MARKER POLL: the pipeline read records.json every 30 s through Get-SIBlobContent, which raised (and
        logged) a TerminatingError 404 every time the marker was not there yet. Get-SIBlobContent -AllowMissing hands the
        404 to Invoke-SIStorageRequest -AllowNotFound and returns $null; the state store's Read uses it.
      * THE STATE STORE'S BLOCKS carry the blob functions as values (${function:...}), never names looked up when called.

    NO EMOJI IN THIS FILE (no BOM; Windows PowerShell 5.1 would decode it as Windows-1252).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UplinkCauses.ps1')
    # the storage request (the one below Get-SIBlobContent), in the SAME scope the blob functions were loaded in -- it
    # replaces theirs: a missing records marker is a 404, -AllowNotFound turns it into $null (as Invoke-SIAzRestRequest does)
    $script:Calls = New-Object System.Collections.Generic.List[object]
    function Invoke-SIStorageRequest {
        param([string]$Method = 'GET', [string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers, [switch]$AllowNotFound, [int[]]$AllowStatus = @(), [switch]$AsBytes, [string]$What)
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; AllowNotFound = [bool]$AllowNotFound })
        if ($Uri -match 'records\.json$') {
            if ($AllowNotFound) { return $null }
            throw "Download blob 'sistate/collect/identity/r1/records.json' -> 404 BlobNotFound"
        }
        return [pscustomobject]@{ Bytes = [Text.Encoding]::UTF8.GetBytes('{"ok":true}'); Headers = @{} }
    }
    function script:New-Unresolved([string[]]$Tables) {
        [pscustomobject]@{ code = 'PartialError'; message = 'There were some errors when processing your query.'
            details = @($Tables | ForEach-Object { [pscustomobject]@{ code = 'EngineError'; message = 'Something went wrong processing your query on the server.'
                innererror = [pscustomobject]@{ code = 'SEM0100'; message = ("'union' operator: Failed to resolve table expression named '{0}'" -f $_); severity = 2 } } }) }
    }
}

Describe 'the capability probe in a workspace without Sentinel' {
    It 'reproduces the live refusal: without the probe''s list the answer is refused as not whole' {
        $v = Test-SILaAnswerWhole -ErrorObject (New-Unresolved @('SecurityIncident', 'SecurityAlert')) -Rows 3
        $v.Whole | Should -BeFalse
        $v.Kind | Should -Be 'Other'
    }
    It 'with the tables the probe names, the answer is whole (the missing tables have no rows)' {
        $may = @(Get-SICapabilityProbeLaMayBeMissing)
        $may | Should -Contain 'SecurityIncident'; $may | Should -Contain 'SecurityAlert'
        $v = Test-SILaAnswerWhole -ErrorObject (New-Unresolved @('SecurityIncident', 'SecurityAlert')) -Rows 3 -MayBeMissing $may
        $v.Whole | Should -BeTrue
        $v.Kind | Should -Be 'Unresolved'
        (Test-SILaAnswerWhole -ErrorObject (New-Unresolved @('SI_CI_CL', 'SecurityAlert')) -Rows 3 -MayBeMissing $may).Whole | Should -BeTrue
    }
    It 'NEGATIVE: a table the caller did not name is still refused; SI tables stay allowed as before' {
        (Test-SILaAnswerWhole -ErrorObject (New-Unresolved @('DeviceInfo')) -Rows 3 -MayBeMissing @(Get-SICapabilityProbeLaMayBeMissing)).Whole | Should -BeFalse
        (Test-SILaAnswerWhole -ErrorObject (New-Unresolved @('SI_CI_CL')) -Rows 3).Whole | Should -BeTrue
        $limit = [pscustomobject]@{ code = 'PartialError'; message = 'Query execution has exceeded the allowed limits' }
        (Test-SILaAnswerWhole -ErrorObject $limit -Rows 3 -MayBeMissing @(Get-SICapabilityProbeLaMayBeMissing)).Kind | Should -Be 'Limit'
    }
    It 'the probe''s own reader passes its list (the default seam)' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-UplinkCauses.ps1')
        $src | Should -Match ([regex]::Escape('Invoke-SITelemetryLaQuery -Query $Kql -MayBeMissing @(Get-SICapabilityProbeLaMayBeMissing)'))
        $tc = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetryCounts.ps1')
        $tc | Should -Match ([regex]::Escape('Test-SILaAnswerWhole -ErrorObject $parsed.Error -Rows 0 -MayBeMissing $MayBeMissing'))
    }
}

Describe 'a marker that is not there yet is not an error (Get-SIBlobContent -AllowMissing, the state store''s Read)' {
    BeforeEach { $script:Calls.Clear() }
    It 'reproduces the live noise: without -AllowMissing a missing marker throws a 404' {
        { Get-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'collect/identity/r1/records.json' } | Should -Throw '*404*'
    }
    It '-AllowMissing: $null, and the 404 is handed to the storage request (no error raised)' {
        $b = Get-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'collect/identity/r1/records.json' -AllowMissing
        $null -eq $b | Should -BeTrue
        $script:Calls[0].AllowNotFound | Should -BeTrue
    }
    It 'a blob that is there is read as before, with or without -AllowMissing' {
        [Text.Encoding]::UTF8.GetString((Get-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'collect/identity/r1/manifest.json' -AllowMissing)) | Should -Be '{"ok":true}'
        [Text.Encoding]::UTF8.GetString((Get-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'collect/identity/r1/manifest.json')) | Should -Be '{"ok":true}'
    }
    It 'the state store reads a missing marker as $null without an error, and a present one as its text' {
        $s = New-SICollectBlobStore -Account 'st'
        $Error.Clear()
        $null -eq (& $s.Read 'collect/identity/r1/records.json') | Should -BeTrue
        $script:Calls[0].AllowNotFound | Should -BeTrue -Because 'the poll asks for a missing blob without an error'
        $Error.Count | Should -Be 0 -Because 'no TerminatingError is raised (and logged) on every poll'
        & $s.Read 'collect/identity/r1/manifest.json' | Should -Be '{"ok":true}'
    }
    It 'the store carries the blob functions as values, and names a missing one in a plain throw' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
        $body = [regex]::Match($src, '(?s)function New-SICollectBlobStore \{.*?\n\}').Value
        $body | Should -Match ([regex]::Escape('${function:Get-SIBlobContent}'))
        $body | Should -Match ([regex]::Escape('& $getFn -Account $acc -Container $con -Blob $Path -AllowMissing'))
        $body | Should -Not -Match '\{ param\(\$Path\) try \{ \$b = Get-SIBlobContent'
        $body | Should -Match 'not loaded from engine\\_shared\\SI-AzRest\.ps1'
    }
}
