#Requires -Version 5.1
<#
    SI #1268 (the owner's approved rights list, 2026-11-15) -- the web app holds NO Reader on the install resource group: the
    UPDATER reads the environment report's Azure facts with its own rights on every run and writes them to the Pro database
    (cfg.EnvironmentFacts 'install'), read back (container/updater/_shared/SI-UpdaterEnvFacts.ps1); the web reads them from SQL
    only (pro-management EnvReport/AzureFacts.cs SqlAzureFactsReader -- its own xUnit tests).
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'container/updater/_shared/SI-UpdaterEnvFacts.ps1')
    $script:Rg = '/subscriptions/s/resourceGroups/rg-si'
    function script:New-Arm([switch]$RolesFail, [switch]$ListFail) {
        $calls = New-Object System.Collections.Generic.List[string]
        $f = [pscustomobject]@{ RolesFail = [bool]$RolesFail; ListFail = [bool]$ListFail }
        $rg = $script:Rg
        $arm = {
            param([string]$Path, [string]$ApiVersion, [switch]$List)
            $calls.Add(('{0} {1}{2}' -f $(if ($List) { 'LIST' } else { 'GET' }), $Path, $(if ($ApiVersion) { '@' + $ApiVersion } else { '' })))
            if ($List -and $Path -eq "$rg/resources") {
                if ($f.ListFail) { throw 'HTTP 403 AuthorizationFailed' }
                return @(
                    [pscustomobject]@{ id = "$rg/providers/Microsoft.KeyVault/vaults/vault-a"; name = 'vault-a'; type = 'Microsoft.KeyVault/vaults'; location = 'westeurope' }
                    [pscustomobject]@{ id = "$rg/providers/Microsoft.App/containerApps/ca-si-management"; name = 'ca-si-management'; type = 'Microsoft.App/containerApps'; location = 'westeurope' }
                    [pscustomobject]@{ id = "$rg/providers/Microsoft.Insights/dataCollectionRules/dcr1"; name = 'dcr1'; type = 'Microsoft.Insights/dataCollectionRules' })
            }
            if ($Path -like '*/vaults/vault-a') { return [pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Enabled'; networkAcls = [pscustomobject]@{ defaultAction = 'Allow' }; secretValue = 'do-not-take'; accessPolicies = @([pscustomobject]@{ x = 1 }) } } }
            if ($Path -like '*/containerApps/ca-si-management') {
                return [pscustomobject]@{ identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web" = [pscustomobject]@{} } }
                    properties = [pscustomobject]@{ configuration = [pscustomobject]@{ ingress = [pscustomobject]@{ external = $true }; secrets = @([pscustomobject]@{ name = 's'; value = 'do-not-take' }) } } }
            }
            if ($List -and $Path -like '*/roleAssignments?$filter=atScope()') {
                if ($f.RolesFail) { throw 'HTTP 403' }
                return @([pscustomobject]@{ properties = [pscustomobject]@{ principalId = 'p1'; principalType = 'ServicePrincipal'; roleDefinitionId = '/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/b24988ac'; scope = $rg } },
                         [pscustomobject]@{ properties = [pscustomobject]@{ principalId = 'p2'; principalType = 'ServicePrincipal'; roleDefinitionId = '/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/b24988ac'; scope = $rg } })
            }
            if ($Path -like '*/roleDefinitions/b24988ac') { return [pscustomobject]@{ properties = [pscustomobject]@{ roleName = 'Contributor' } } }
            throw "unexpected $Path"
        }.GetNewClosure()
        [pscustomobject]@{ Arm = $arm; Calls = $calls }
    }
    function script:New-Store([switch]$NoTable) {
        $st = [pscustomobject]@{ Writes = (New-Object System.Collections.Generic.List[object]); NoTable = [bool]$NoTable }
        $inv = { param([string]$sql, $p, [string]$mode)
            $st.Writes.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode })
            if ($st.NoTable) { return , @() }
            , @(@{ ReadUtc = ([string]$p.ReadUtc).Replace(' ', 'T'); Chars = ([string]$p.Facts).Length })
        }.GetNewClosure()
        [pscustomobject]@{ Name = 'fake'; Invoke = $inv; State = $st }
    }
}

Describe 'the updater reads the environment report''s Azure facts (Read-SIUpdaterEnvFacts)' {
    It 'the resources with their NAMED facts only, a GET only for the report''s types, the role assignments atScope with each role named once' {
        $a = New-Arm
        $f = Read-SIUpdaterEnvFacts -Arm $a.Arm -SubscriptionId 's' -ResourceGroup 'rg-si' -NowUtc ([datetime]'2026-11-15T18:30:00Z').ToUniversalTime()
        $f.readUtc | Should -Be '2026-11-15T18:30:00Z'
        $f.error | Should -BeNullOrEmpty
        @($f.resources).Count | Should -Be 3
        $kv = @($f.resources | Where-Object { $_.name -eq 'vault-a' })[0]
        @($kv.network | ForEach-Object { '{0}={1}' -f $_.fact, $_.value }) | Should -Be @('public network access=Enabled', 'default network rule=Allow')
        $ca = @($f.resources | Where-Object { $_.name -eq 'ca-si-management' })[0]
        @($ca.network | ForEach-Object { '{0}={1}' -f $_.fact, $_.value }) | Should -Be @('external ingress=true', 'IP restrictions=0')
        @($ca.userAssigned) | Should -Be @('id-si-web')
        (ConvertTo-Json -InputObject $f -Depth 12 -Compress) | Should -Not -Match 'do-not-take' -Because 'no key, secret or setting value is ever taken from an answer'
        @($a.Calls | Where-Object { $_ -like '*dcr1*' }) | Should -BeNullOrEmpty -Because 'no GET of a type the report does not show'
        @($f.roles | ForEach-Object role) | Should -Be @('Contributor', 'Contributor')
        @($a.Calls | Where-Object { $_ -like '*roleDefinitions/b24988ac*' }).Count | Should -Be 1 -Because 'each role name is looked up once'
    }
    It 'a part that cannot be read is said; the other part is still kept' {
        $f = Read-SIUpdaterEnvFacts -Arm (New-Arm -RolesFail).Arm -SubscriptionId 's' -ResourceGroup 'rg-si'
        @($f.resources).Count | Should -Be 3; $f.error | Should -Match 'the role assignments could not be read'
        $g = Read-SIUpdaterEnvFacts -Arm (New-Arm -ListFail).Arm -SubscriptionId 's' -ResourceGroup 'rg-si'
        @($g.roles).Count | Should -Be 2; $g.error | Should -Match 'the resources could not be read: HTTP 403'
    }
}

Describe 'the step writes them to the Pro database and reads them back (Invoke-SIUpdaterEnvFactsStep)' {
    It 'one write of cfg.EnvironmentFacts ''install'' with the JSON and its read time, read back' {
        $s = New-Store
        $r = Invoke-SIUpdaterEnvFactsStep -Store $s -SubscriptionId 's' -ResourceGroup 'rg-si' -Arm (New-Arm).Arm -NowUtc ([datetime]'2026-11-15T18:30:00Z').ToUniversalTime()
        $r.Ok | Should -BeTrue -Because $r.Line
        $r.Line | Should -Be 'System Documentation facts recorded: 3 resource(s), 2 role assignment(s) at the resource group (read back)'
        $s.State.Writes.Count | Should -Be 1; $w0 = $s.State.Writes[0]
        $w0.Sql | Should -Match "cfg\.EnvironmentFacts"; $w0.Sql | Should -Match "Name = N'install'"; $w0.Mode | Should -Be 'reader'
        [string]$w0.P['ReadUtc'] | Should -Be '2026-11-15 18:30:00'
        ([string]$w0.P['Facts'] | ConvertFrom-Json).resourceGroup | Should -Be 'rg-si'
    }
    It 'no row read back (a schema without the table): a warning, never a failure of the update; no Pro database: nothing' {
        $r = Invoke-SIUpdaterEnvFactsStep -Store (New-Store -NoTable) -SubscriptionId 's' -ResourceGroup 'rg-si' -Arm (New-Arm).Arm
        $r.Ok | Should -BeFalse; $r.Line | Should -Match '^WARNING: System Documentation facts: written, but the row does not read back'
        (Invoke-SIUpdaterEnvFactsStep -Store $null -SubscriptionId 's' -ResourceGroup 'rg-si').Line | Should -Match 'no Pro database'
        { Invoke-SIUpdaterEnvFactsStep -Store (New-Store) -SubscriptionId 's' -ResourceGroup 'rg-si' -Arm { throw 'boom' } } | Should -Not -Throw
    }
    It 'ASSERT-WIRING: the updater loads the step and runs it on every run with a Pro database; the schema has the table; the image carries the file' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container/updater/Start-SIUpdater.ps1'))
        $u | Should -Match "Join-Path \`$PSScriptRoot '_shared/SI-UpdaterEnvFacts\.ps1'"
        $u | Should -Match '\$ef = Invoke-SIUpdaterEnvFactsStep -Store \$proStore -SubscriptionId \$sub -ResourceGroup \$rg'
        # it runs on the path every run takes (after the endpoints step, before the update decision)
        $u.IndexOf('Invoke-SIUpdaterEnvFactsStep -Store') | Should -BeGreaterThan $u.IndexOf('$null = Invoke-SIUpdaterRecordEndpoints')
        $u.IndexOf('Invoke-SIUpdaterEnvFactsStep -Store') | Should -BeLessThan $u.IndexOf("if (`$updMode -eq 'post-roll') { return (Invoke-SIUpdaterPostRollRun")
        (Get-Content -Raw (Join-Path $script:SIRoot 'sql/si-pro-settings.sql')) | Should -Match "IF OBJECT_ID\('cfg\.EnvironmentFacts'\) IS NULL\s+CREATE TABLE cfg\.EnvironmentFacts"
        (Get-Content -Raw (Join-Path $script:SIRoot 'container/updater/Dockerfile')) | Should -Match 'COPY container/updater/_shared/ \./_shared/'
    }
}
