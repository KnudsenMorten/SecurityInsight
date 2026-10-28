#Requires -Version 5.1
<#
    A RUN-HEALTH RECORD THAT CANNOT BE SAVED IS SAID OUT LOUD (#198).

    Measured 2026-10-01: SI_RunHealth_CL held 0 rows in 30 days. The run-health rule was bound to a data
    collection endpoint in another subscription (three endpoints share the name dce-securityinsight), the
    pre-flight saw the mismatch and skipped every post -- with Write-Verbose, so no run ever showed it. Crash
    detection and "was this run complete" both read that table, and the vulnerability close-loop (#195) cannot
    close anything without the second.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
}

Describe 'the run-health pre-flight' {
    BeforeEach { $global:SI_RunHealthMismatchWarned = $null }
    AfterAll   { $global:SI_RunHealthMismatchWarned = $null }

    It 'a rule bound to ANOTHER endpoint: skipped, and said once -- not once per heartbeat' {
        Mock Invoke-SIAzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ dataCollectionEndpointId = '/subscriptions/other/resourceGroups/rg-x/providers/Microsoft.Insights/dataCollectionEndpoints/dce-securityinsight' } } | ConvertTo-Json -Depth 4) }
        }
        $args1 = @{ SubscriptionId = 'mine'; DcrResourceGroup = 'rg-si'; DcrName = 'dcr-si-run-health'; DceResourceGroup = 'rg-si'; DceName = 'dce-securityinsight' }
        $w = @()
        $a = Test-SIRunHealthDcrReachable @args1 -WarningVariable +w -WarningAction SilentlyContinue
        $b = Test-SIRunHealthDcrReachable @args1 -WarningVariable +w -WarningAction SilentlyContinue
        $a | Should -BeFalse
        $b | Should -BeFalse
        @($w).Count | Should -Be 1 -Because 'Start and End both check; the operator needs the message once'
        [string]$w[0] | Should -Match 'not being saved'
        [string]$w[0] | Should -Match 'SI_RunHealth_DcrName'
    }

    It 'a rule bound to THIS endpoint posts, and says nothing' {
        Mock Invoke-SIAzRestMethod {
            [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ dataCollectionEndpointId = '/subscriptions/mine/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-securityinsight' } } | ConvertTo-Json -Depth 4) }
        }
        $w = @()
        Test-SIRunHealthDcrReachable -SubscriptionId 'mine' -DcrResourceGroup 'rg-si' -DcrName 'd' -DceResourceGroup 'rg-si' -DceName 'dce-securityinsight' -WarningVariable +w -WarningAction SilentlyContinue | Should -BeTrue
        @($w).Count | Should -Be 0
    }

    It 'no rule yet: posts (creation happens on the post), and says nothing' {
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 404; Content = '' } }
        Test-SIRunHealthDcrReachable -SubscriptionId 'mine' -DcrResourceGroup 'rg-si' -DcrName 'd' -DceResourceGroup 'rg-si' -DceName 'x' | Should -BeTrue
    }
}

Describe 'the run-health row types match the table (#198)' {
    It 'every counter is posted as [long] -- the table''s columns are long, and an [int] made the rule invalid' {
        # Measured 2026-10-01: "InvalidTransformOutput ... AssetCount [produced:'Int', output:'Long']" for AssetCount,
        # DurationSec, PeakWorkingSetMB, ShardCount -- the rule could not be created, and the post never happened.
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        foreach ($c in 'ShardIndex', 'ShardCount', 'AssetCount', 'PeakWorkingSetMB', 'DurationSec') {
            $src | Should -Match ('{0}\s+=\s+\[long\]' -f $c) -Because "$c must be long"
        }
    }
    It 'a failed post is warned about once per run, not swallowed' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $src | Should -Match "Write-Warning \('Run-health record could not be saved"
        $src | Should -Not -Match "Write-Verbose \('Send-SIRunHealthRow: heartbeat failed"
    }
}

Describe 'missing ingest settings (#198)' {
    BeforeEach { $global:SI_RunHealthFailWarned = $null; $script:saved = @($global:SI_WorkspaceResourceId, $global:SI_DceName, $global:SI_DcrResourceGroup) }
    AfterEach  {
        $global:SI_RunHealthFailWarned = $null
        $global:SI_WorkspaceResourceId, $global:SI_DceName, $global:SI_DcrResourceGroup = $script:saved
    }
    It 'a workspace with no endpoint settings: warned once' {
        $global:SI_WorkspaceResourceId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z'
        $global:SI_DceName = $null; $global:SI_DcrResourceGroup = $null
        $ctx = [pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r'; Engine = 'e'; ShardIndex = 0; ShardCount = 1; StartTime = [datetime]::UtcNow }
        $w = @()
        Send-SIRunHealthRow -RunContext $ctx -Phase Start -WarningVariable +w -WarningAction SilentlyContinue
        Send-SIRunHealthRow -RunContext $ctx -Phase End   -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match 'not saved'
    }
    It 'no workspace at all (file-only setup): silent' {
        $global:SI_WorkspaceResourceId = $null; $global:SI_DceName = $null; $global:SI_DcrResourceGroup = $null
        $ctx = [pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r'; Engine = 'e'; ShardIndex = 0; ShardCount = 1; StartTime = [datetime]::UtcNow }
        $w = @()
        Send-SIRunHealthRow -RunContext $ctx -Phase Start -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 0
    }
}

Describe 'the endpoint is pinned before the module sees it (#198)' {
    # Measured 2026-10-01: three endpoints named dce-securityinsight in two subscriptions. AzLogDcrIngestPS picks the
    # FIRST by name, and CheckCreateUpdate-TableDcr-Structure re-bound a freshly created, correctly bound rule to the
    # other subscription's endpoint one minute later (activity log, caller = the engine identity).
    BeforeEach {
        $script:dceSaved = $global:AzDceDetails; $script:dcrSaved = $global:AzDcrDetails
        $global:AzDceDetails = @(
            [pscustomobject]@{ name = 'dce-si'; id = '/subscriptions/other/resourceGroups/rg-dce/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si' },
            [pscustomobject]@{ name = 'dce-si'; id = '/subscriptions/mine/resourceGroups/rg-other/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si' },
            [pscustomobject]@{ name = 'dce-si'; id = '/subscriptions/mine/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si' }
        )
        $global:AzDcrDetails = @(
            [pscustomobject]@{ name = 'dcr-rh'; id = '/subscriptions/other/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-rh' },
            [pscustomobject]@{ name = 'dcr-rh'; id = '/subscriptions/mine/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-rh' }
        )
    }
    AfterEach { $global:AzDceDetails = $script:dceSaved; $global:AzDcrDetails = $script:dcrSaved }

    It 'only this subscription + resource group survives -- the first name match is NOT taken' {
        Select-SIRunHealthIngestTarget -SubscriptionId 'mine' -DceResourceGroup 'rg-si' -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-rh' | Should -BeTrue
        @($global:AzDceDetails).Count | Should -Be 1
        $global:AzDceDetails[0].id | Should -Match '/subscriptions/mine/resourceGroups/rg-si/'
        @($global:AzDcrDetails).Count | Should -Be 1
        $global:AzDcrDetails[0].id | Should -Match '/subscriptions/mine/'
    }
    It 'not in the cache: false, and the cache is left alone (the caller rebuilds it or refuses)' {
        Select-SIRunHealthIngestTarget -SubscriptionId 'nowhere' -DceResourceGroup 'rg-si' -DceName 'dce-si' | Should -BeFalse
        @($global:AzDceDetails).Count | Should -Be 3
    }
    It '🔴 the run-health rule missing from a cache another publisher narrowed: false, so the sender rebuilds (live 2026-10-02: every azure run lost its End row)' {
        # What SI-LogIngest's Select-SIIngestTarget leaves behind after the azure engine's Defender for Cloud publish.
        $global:AzDcrDetails = @([pscustomobject]@{ name = 'dcr-si-azurerecommendation'; id = '/subscriptions/mine/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-si-azurerecommendation' })
        Select-SIRunHealthIngestTarget -SubscriptionId 'mine' -DceResourceGroup 'rg-si' -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-rh' | Should -BeFalse
        # a rule that does not exist YET (first run) is accepted only when the caller says so -- the create step makes it
        Select-SIRunHealthIngestTarget -SubscriptionId 'mine' -DceResourceGroup 'rg-si' -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-rh' -AllowMissingDcr | Should -BeTrue
    }
    It 'WIRING -- after create/update the sender re-reads the rules when its rule is still not in the cache, and never posts without it' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $body = $src.Substring($src.IndexOf('function Send-SIRunHealthRow'))
        $after = $body.Substring($body.IndexOf('$null = Update-SILogTableSchema'))
        $after.IndexOf('Get-SIDcrList') | Should -BeGreaterThan 0
        $after.IndexOf('Get-SIDcrList') | Should -BeLessThan $after.IndexOf('$data = @($row)')
        $after | Should -Match 'data collection rule .\{0\}. was not found'
    }
    It 'the pin runs BEFORE the table + rule update (Update-SILogTableSchema) in the sender' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $body = $src.Substring($src.IndexOf('function Send-SIRunHealthRow'))
        $pin = $body.IndexOf('Select-SIRunHealthIngestTarget')
        $pin | Should -BeGreaterThan 0
        $pin | Should -BeLessThan $body.IndexOf('$null = Update-SILogTableSchema')
    }
}

Describe 'run-health: one endpoint of that name elsewhere is unambiguous (#199)' {
    BeforeEach { $script:dceSaved = $global:AzDceDetails }
    AfterEach  { $global:AzDceDetails = $script:dceSaved }
    It 'a single same-named endpoint outside the configured resource group is used' {
        $global:AzDceDetails = @([pscustomobject]@{ name = 'dce-si'; id = '/subscriptions/mine/resourceGroups/rg-dce/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si' })
        Select-SIRunHealthIngestTarget -SubscriptionId 'mine' -DceResourceGroup 'rg-si' -DceName 'dce-si' | Should -BeTrue
    }
}

Describe 'the run-health CollectionTime is UTC, on any host time zone (#203)' {
    # Measured 2026-10-02 on a UTC+2 host: risk-analysis records were stamped exactly 2 h before TimeGenerated, the
    # endpoint profiler's were not. RA and the tier classifier hand over an un-zoned UTC string; a plain [datetime]
    # cast makes it kind Unspecified, which the serializer reads as LOCAL time and shifts again.
    It 'an un-zoned string is read as UTC, not as local time' {
        $t = ConvertTo-SIRunHealthUtc '2026-10-01 21:33:28'
        $t.Kind | Should -Be ([DateTimeKind]::Utc)
        $t.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2026-10-01 21:33:28'
    }

    It 'a UTC [datetime] passes through unchanged, and a local one is converted' {
        $u = [datetime]::new(2026, 10, 1, 21, 33, 28, [DateTimeKind]::Utc)
        (ConvertTo-SIRunHealthUtc $u) | Should -Be $u
        (ConvertTo-SIRunHealthUtc $u.ToLocalTime()).Kind | Should -Be ([DateTimeKind]::Utc)
        (ConvertTo-SIRunHealthUtc $u.ToLocalTime()) | Should -Be $u
    }

    It 'the serialized value is the same instant -- what the ingest module posts' {
        $t = ConvertTo-SIRunHealthUtc '2026-10-01 21:33:28'
        $back = ([pscustomobject]@{ CollectionTime = $t } | ConvertTo-Json | ConvertFrom-Json).CollectionTime
        if ($back -isnot [datetime]) { $back = [datetime]::Parse([string]$back, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) }
        $back.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2026-10-01 21:33:28'
    }

    It 'the row is built through the conversion, not a bare cast' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1')
        $src | Should -Match 'CollectionTime\s+=\s+ConvertTo-SIRunHealthUtc\s+\$RunContext\.CollectionTime'
        $src | Should -Not -Match 'CollectionTime\s+=\s+\[datetime\]\$RunContext\.CollectionTime'
    }
}