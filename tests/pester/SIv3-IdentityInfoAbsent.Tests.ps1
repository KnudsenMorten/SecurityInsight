#Requires -Version 5.1
<#
    A WORKSPACE WITHOUT THE IdentityInfo TABLE (#759, fix-request triage 2026-10-18: 4 installs, rings 1-2).

    Where the source that fills IdentityInfo (Defender for Identity / the Defender XDR connector) is not connected, Log
    Analytics answers SEM0100 "Failed to resolve table or column expression named 'IdentityInfo'". That is a fact about the
    tenant, not a failed read. What these tests keep true:
      * no warning: one plain INFO line, said once per run (a second call is a cache hit, no second query);
      * the state carries its own code 'source-not-present' and no error text, and the Defender for Identity pull is
        recorded with that code (Set-SIRecordPull -Code) -- not as a failed read;
      * a table that EXISTS and fails stays a failure (a warning and the error text).
    Offline: the workspace and the query are stubs.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function script:Write-SIInfo { param([string]$Message) }
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    $script:Sem0100 = "BadArgumentError: 'where' operator: Failed to resolve table or column expression named 'IdentityInfo' (SEM0100)"
}

Describe 'Test-SIIdentityInfoTableAbsent' {
    It 'SEM0100 on IdentityInfo = absent; any other failure = not absent' {
        Test-SIIdentityInfoTableAbsent -Message $script:Sem0100 | Should -BeTrue
        Test-SIIdentityInfoTableAbsent -Message 'Response status code does not indicate success: 403 (Forbidden)' | Should -BeFalse
        Test-SIIdentityInfoTableAbsent -Message "Failed to resolve table or column expression named 'DeviceInfo'" | Should -BeFalse
        Test-SIIdentityInfoTableAbsent -Message '' | Should -BeFalse
    }
}

Describe 'Get-SIIdentityInfoByObjectId on a workspace without the table' {
    BeforeEach {
        $script:_SICache = @{}
        Mock Resolve-SIWorkspaceFromResourceId { [pscustomobject]@{ CustomerId = [guid]'11111111-2222-3333-4444-555555555555' } }
    }
    It 'no warning, one plain line, the coded state, and no second query' {
        Mock Invoke-SIAzOperationalInsightsQuery { throw $script:Sem0100 }
        Mock Write-SIInfo { }
        $r = Get-SIIdentityInfoByObjectId -WorkspaceResourceId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w' -WarningVariable wv -WarningAction SilentlyContinue
        @($wv).Count | Should -Be 0
        $r.Count | Should -Be 0
        $st = $script:_SICache['IdentityInfoState']
        $st.Code | Should -Be 'source-not-present'
        $st.Error | Should -BeNullOrEmpty
        $st.Complete | Should -BeFalse
        Should -Invoke Write-SIInfo -Times 1 -Exactly -ParameterFilter { "$Message" -match 'no IdentityInfo table' -and "$Message" -match 'not an error' }
        $null = Get-SIIdentityInfoByObjectId -WorkspaceResourceId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
        Should -Invoke Invoke-SIAzOperationalInsightsQuery -Times 1 -Exactly
        Should -Invoke Write-SIInfo -Times 1 -Exactly -ParameterFilter { "$Message" -match 'no IdentityInfo table' }
    }
    It 'a table that exists and fails stays a failure: a warning and the error text' {
        Mock Invoke-SIAzOperationalInsightsQuery { throw 'Response status code does not indicate success: 403 (Forbidden).' }
        $null = Get-SIIdentityInfoByObjectId -WorkspaceResourceId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w' -WarningVariable wv -WarningAction SilentlyContinue
        @($wv).Count | Should -Be 1
        $st = $script:_SICache['IdentityInfoState']
        $st.Complete | Should -BeFalse
        $st.Error | Should -Match '403'
        $st.PSObject.Properties['Code'] | Should -BeNullOrEmpty
    }
}

Describe 'the Defender for Identity pull keeps the code' {
    It 'Set-SIRecordPull -Code source-not-present is kept, and survives a second call without a code' {
        $null = Reset-SIRecordCapture
        Set-SIRecordPull -Provider 'mdi' -Complete $false -ErrorText '' -Code 'source-not-present'
        $global:SIRecordCaptureState.Pulls['mdi'].Code | Should -Be 'source-not-present'
        $global:SIRecordCaptureState.Pulls['mdi'].Error | Should -BeNullOrEmpty
        Set-SIRecordPull -Provider 'mdi' -Complete $false
        $global:SIRecordCaptureState.Pulls['mdi'].Code | Should -Be 'source-not-present'
        $global:SIRecordCaptureState = $null
    }
    It 'the discovery hands the state''s code to the pull (wiring)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $src | Should -Match ([regex]::Escape("Set-SIRecordPull -Provider 'mdi' -Complete `$iiOk -ErrorText `$iiErr -Code `$iiCode"))
    }
}
