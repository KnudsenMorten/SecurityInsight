#Requires -Version 5.1
<#
    EVERY INGEST PATH PINS ITS ENDPOINT BEFORE THE MODULE TOUCHES THE RULE (#199).

    AzLogDcrIngestPS resolves the data collection endpoint by NAME ONLY, inside CheckCreateUpdate-TableDcr-Structure
    as well as inside Post-*. Measured 2026-10-01 (#198): three endpoints named dce-securityinsight in two
    subscriptions, and a correctly bound rule was re-bound to the other subscription's endpoint by the engine's own
    post one minute after it was created. Pinning only before the POST is too late.
#>

BeforeDiscovery {
    # asset-properties is SecurityInsight Pro and is not in the Community copy: its cases run only where it exists.
    $proIngest = Test-Path (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'engine\asset-properties\_shared\SI-AssetPropertiesIngest.ps1')
    $script:PinFns = @(@{ Fn = 'Select-SIIngestTarget' }) + @(if ($proIngest) { @{ Fn = 'Select-SIAssetPropertiesIngestTarget' } })
    $script:PinFiles = @(
        @{ File = 'engine\_shared\SI-LogIngest.ps1';                              Pin = 'Select-SIIngestTarget -AuthParams' },
        @{ File = 'engine\asset-trend\Invoke-SITrend.ps1';                        Pin = 'Select-SIIngestTarget -AuthParams' }
    ) + @(if ($proIngest) { @{ File = 'engine\asset-properties\_shared\SI-AssetPropertiesIngest.ps1'; Pin = 'Select-SIAssetPropertiesIngestTarget -AuthParams' } })
}
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    $proIngest = Join-Path $script:SIRoot 'engine\asset-properties\_shared\SI-AssetPropertiesIngest.ps1'
    if (Test-Path $proIngest) { . $proIngest }
    function script:Dce([string]$sub, [string]$rg, [string]$n = 'dce-si') { [pscustomobject]@{ name = $n; id = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/$n" } }
    function script:Dcr([string]$sub, [string]$rg, [string]$n = 'dcr-x') { [pscustomobject]@{ name = $n; id = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/$n" } }
}

Describe 'the ingest pin helpers' -ForEach $script:PinFns {
    BeforeEach {
        $script:keep = @{}
        foreach ($v in 'SI_AzSubscriptionId','SI_DceName','SI_DceResourceGroup','SI_DcrResourceGroup','AzDceDetails','AzDcrDetails') {
            $script:keep[$v] = Get-Variable -Scope Global -Name $v -ValueOnly -ErrorAction SilentlyContinue
        }
        $global:SI_AzSubscriptionId = 'mine'; $global:SI_DceName = 'dce-si'; $global:SI_DceResourceGroup = 'rg-si'; $global:SI_DcrResourceGroup = 'rg-si'
        $script:RebuiltDce = $null; $script:RebuiltDcr = $null
        # the endpoint / rule lists a rebuild reads (no network)
        Mock Get-SIDceList { $script:RebuiltDce }
        Mock Get-SIDcrList { $script:RebuiltDcr }
    }
    AfterEach { foreach ($v in $script:keep.Keys) { Set-Variable -Scope Global -Name $v -Value $script:keep[$v] } }

    It '<Fn> -- three same-named endpoints, only this subscription + resource group survives, and the rule too' {
        $global:AzDceDetails = @((Dce 'other' 'rg-dce'), (Dce 'mine' 'rg-other'), (Dce 'mine' 'rg-si'))
        $global:AzDcrDetails = @((Dcr 'other' 'rg-si'), (Dcr 'mine' 'rg-si'))
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        @($global:AzDceDetails).Count | Should -Be 1
        $global:AzDceDetails[0].id | Should -Match '/subscriptions/mine/resourceGroups/rg-si/'
        @($global:AzDcrDetails).Count | Should -Be 1
        $global:AzDcrDetails[0].id | Should -Match '/subscriptions/mine/'
    }
    It '<Fn> -- no such rule here yet, so same-named rules elsewhere are dropped and the module creates it HERE' {
        $global:AzDceDetails = @((Dce 'mine' 'rg-si'))
        $global:AzDcrDetails = @((Dcr 'other' 'rg-si'), (Dcr 'mine' 'rg-si' 'dcr-unrelated'))
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        @($global:AzDcrDetails | Where-Object name -eq 'dcr-x').Count | Should -Be 0
        @($global:AzDcrDetails | Where-Object name -eq 'dcr-unrelated').Count | Should -Be 1
    }
    It '<Fn> -- an empty cache is built first, so the module never runs its tenant-wide lookup' {
        $global:AzDceDetails = $null; $global:AzDcrDetails = $null
        $script:RebuiltDce = @((Dce 'other' 'rg-dce'), (Dce 'mine' 'rg-si')); $script:RebuiltDcr = @((Dcr 'mine' 'rg-si'))
        & $Fn -AuthParams @{ AzAppId = 'a' } -DcrName 'dcr-x'
        @($global:AzDceDetails).Count | Should -Be 1
        $global:AzDceDetails[0].id | Should -Match '/subscriptions/mine/'
    }
    It '<Fn> -- ONE endpoint of that name, in another resource group, is unambiguous and used' {
        $global:AzDceDetails = @((Dce 'mine' 'rg-dce-elsewhere'))
        $script:RebuiltDce = $global:AzDceDetails
        { & $Fn -AuthParams @{ AzAppId = 'a' } -DcrName 'dcr-x' } | Should -Not -Throw
        $global:AzDceDetails[0].id | Should -Match 'rg-dce-elsewhere'
    }
    It '<Fn> -- several of that name and none here, refuses and nothing is posted' {
        $global:AzDceDetails = @((Dce 'other' 'rg-a'), (Dce 'other2' 'rg-b'))
        $script:RebuiltDce = $global:AzDceDetails
        { & $Fn -AuthParams @{ AzAppId = 'a' } -DcrName 'dcr-x' } | Should -Throw '*nothing was posted*'
    }
    It '<Fn> -- an EXISTING rule bound to another same-named endpoint posts through THAT endpoint, and is not moved' {
        # Measured 2026-10-01: ingestion accepts a post only through the rule's own endpoint (HTTP 403 "not associated"
        # otherwise), and a rule moved to this install's endpoint was still refused more than 10 minutes later.
        $other = Dce 'other' 'rg-dce'; $here = Dce 'mine' 'rg-si'
        $global:AzDceDetails = @($other, $here)
        $mis = Dcr 'mine' 'rg-si'; $mis | Add-Member -NotePropertyName properties -NotePropertyValue ([pscustomobject]@{ dataCollectionEndpointId = $other.id })
        $global:AzDcrDetails = @($mis)
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        @($global:AzDceDetails).Count | Should -Be 1
        $global:AzDceDetails[0].id | Should -Be $other.id
        $global:AzDcrDetails[0].id | Should -Be $mis.id
    }
    It '<Fn> -- the bound endpoint missing from a cache narrowed by an earlier refresh is looked up again' {
        $other = Dce 'other' 'rg-dce'; $here = Dce 'mine' 'rg-si'
        $mis = Dcr 'mine' 'rg-si'; $mis | Add-Member -NotePropertyName properties -NotePropertyValue ([pscustomobject]@{ dataCollectionEndpointId = $other.id })
        $global:AzDceDetails = @($here); $global:AzDcrDetails = @($mis)
        $script:RebuiltDce = @($other, $here); $script:RebuiltDcr = @($mis)
        & $Fn -AuthParams @{ AzAppId = 'a' } -DcrName 'dcr-x'
        $global:AzDceDetails[0].id | Should -Be $other.id
    }
    It '<Fn> -- a rule bound HERE (any letter case) keeps this install''s endpoint; a differently named binding is not followed' {
        $here = Dce 'mine' 'rg-si'
        $ok = Dcr 'mine' 'rg-si'; $ok | Add-Member -NotePropertyName properties -NotePropertyValue ([pscustomobject]@{ dataCollectionEndpointId = $here.id.ToUpper() })
        $global:AzDceDetails = @($here); $global:AzDcrDetails = @($ok)
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        $global:AzDceDetails[0].id | Should -Be $here.id

        $foreign = Dce 'other' 'rg-x' 'dce-another-name'
        $odd = Dcr 'mine' 'rg-si'; $odd | Add-Member -NotePropertyName properties -NotePropertyValue ([pscustomobject]@{ dataCollectionEndpointId = $foreign.id })
        $global:AzDceDetails = @($here, $foreign); $global:AzDcrDetails = @($odd)
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        $global:AzDceDetails[0].id | Should -Be $here.id -Because 'Post-* looks the endpoint up by the configured name'
    }
    It '<Fn> -- no subscription known, nothing to pin to, the cache is left alone' {
        $global:SI_AzSubscriptionId = $null
        $global:AzDceDetails = @((Dce 'other' 'rg-a'), (Dce 'mine' 'rg-si'))
        & $Fn -AuthParams $null -DcrName 'dcr-x'
        @($global:AzDceDetails).Count | Should -Be 2
    }
}

Describe 'the pin runs BEFORE the table + rule update, Update-SILogTableSchema (#199)' -ForEach $script:PinFiles {
    It '<File>' {
        $src  = Get-Content -Raw (Join-Path $script:SIRoot $File)
        $call = $src.IndexOf('$null = Update-SILogTableSchema')
        $pin  = $src.IndexOf($Pin)
        $call | Should -BeGreaterThan 0
        $pin  | Should -BeGreaterThan 0
        $pin  | Should -BeLessThan $call
    }
}

Describe 'no engine path creates a rule without pinning first' {
    It 'every Update-SILogTableSchema call in engine\ has a pin before it in its file' {
        $files = Get-ChildItem (Join-Path $script:SIRoot 'engine') -Recurse -Filter *.ps1 |
            Where-Object { (Get-Content -Raw $_.FullName) -match '\$null = Update-SILogTableSchema' }
        @($files).Count | Should -BeGreaterThan 3
        foreach ($f in $files) {
            $src = Get-Content -Raw $f.FullName
            $pre = $src.Substring(0, $src.IndexOf('$null = Update-SILogTableSchema'))
            $pre | Should -Match 'Select-SI\w*IngestTarget -|Apply-SIDcrScopeFilter -Scope|\$global:AzDceDetails = @\(\$_picked\)' -Because "$($f.Name) must pin before it creates"
        }
    }
}

Describe 'the pin runs AGAIN right before the post (#199)' -ForEach $script:PinFiles {
    It '<File> -- after the cache refresh, before Post-*' {
        $src  = Get-Content -Raw (Join-Path $script:SIRoot $File)
        # the LAST post: Send-SIObjectMapRows also posts earlier for a table already made ready in this run (#475), with
        # the endpoint and rule this full path pinned (SIv3-RecordPublishPerf checks that restore)
        $post = $src.LastIndexOf('$null = Send-SILogData')
        $last = $src.LastIndexOf($Pin)
        $last | Should -BeGreaterThan $src.IndexOf('Ensure-SecurityInsightAzDceDcrCache')
        $last | Should -BeLessThan $post
    }
}
