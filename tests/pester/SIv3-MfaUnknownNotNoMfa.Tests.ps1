#Requires -Version 5.1
<#
    #522 MFA THAT COULD NOT BE READ IS UNKNOWN -- NEVER "NO MFA" (SI rule 4: UNKNOWN is never reported as a finding).

    customer H 2026-10-09: "Identity_NoMFA_Detailed" (all enabled users with no MFA registration) flagged 8,836 of ~8,994
    identities. Cause in the code: the identity discovery reads MFA registration in ONE bulk call
    (/reports/authenticationMethods/userRegistrationDetails); when that call failed (licence / permission / throttling past
    the retries on a large tenant -- a failure part-way also threw away the pages already read) the map came back EMPTY, and
    every user then defaulted to ENTRA_MfaIsRegistered = $false -- which the report reads as "no MFA".

    What these keep true:
      1. a failed read: no user is "no MFA" (all $null), and the run prints ONE plain line saying MFA data is missing
      2. a read that stops part-way: the users read keep their real value, the rest are unknown, one plain line
      3. a full read: the real values, no line
      4. the reports filter the CI field `si_mfa_registered == false`, which a null never matches -- so unknown never becomes a row
    OFFLINE: Graph is a fake; no tenant is touched.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    foreach ($n in 'Write-SIInfo', 'Write-SIProgress', 'Reset-SIProgress', 'Write-SIWarn') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:global:{0}" -f $n) -Value { param($Message) } }
    }
    . (Join-Path $script:Shared 'Invoke-SIPagedRest.ps1')
    . (Join-Path $script:Shared 'IdentityRoleFetcher.ps1')
    . (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1')

    $script:U1 = 'u0000000-0000-0000-0000-000000000001'
    $script:U2 = 'u0000000-0000-0000-0000-000000000002'
    function script:RegRow([string]$Id, [bool]$Mfa) {
        [pscustomobject]@{ id = $Id; isMfaRegistered = $Mfa; isMfaCapable = $Mfa; methodsRegistered = @($(if ($Mfa) { 'microsoftAuthenticatorPush' }), 'password') }
    }
    $script:YamlLines = [IO.File]::ReadAllLines((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportText([string]$Name) {
        $start = -1
        for ($i = 0; $i -lt $script:YamlLines.Count; $i++) { if ($script:YamlLines[$i] -match ('^\s*- ReportName:\s*' + [regex]::Escape($Name) + '\s*$')) { $start = $i; break } }
        if ($start -lt 0) { return $null }
        $end = $script:YamlLines.Count
        for ($i = $start + 1; $i -lt $script:YamlLines.Count; $i++) { if ($script:YamlLines[$i] -match '^\s*- ReportName:') { $end = $i; break } }
        ($script:YamlLines[$start..($end - 1)] -join "`n")
    }
}

Describe 'the MFA registration read records what it could and could not read' {
    BeforeEach {
        Reset-SIIdentityFetcherCache
        $script:Warned = New-Object System.Collections.Generic.List[string]
        Mock Write-SIWarn { $script:Warned.Add([string]$Message) }
    }

    It 'a refused read (licence / permission): empty map, state not complete, ONE plain line saying MFA data is missing' {
        $map = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch { param($Url, $Token) [pscustomobject]@{ Rows = @(); Complete = $false; Count = 0; Pages = 0; Error = 'MFA registration: page 1 failed after 1 attempt(s) -- HTTP 403 Forbidden' } }
        $map.Count | Should -Be 0
        (Get-SIEntraMfaRegistrationState).Complete | Should -BeFalse
        $script:Warned.Count | Should -Be 1
        $script:Warned[0] | Should -Match '^MFA registration data is missing for this run'
        $script:Warned[0] | Should -Match 'No user is reported as having no MFA'
        $script:Warned[0] | Should -Match 'P1 or P2'
    }

    It 'a fetch that throws is treated as a failed read (never as "every user has no MFA")' {
        $map = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch { param($Url, $Token) throw 'network down' }
        $map.Count | Should -Be 0
        (Get-SIEntraMfaRegistrationState).Complete | Should -BeFalse
        $script:Warned.Count | Should -Be 1
        $script:Warned[0] | Should -Match 'network down'
    }

    It 'a read that stops part-way keeps the users it read, and says the data is incomplete' {
        $map = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch { param($Url, $Token) [pscustomobject]@{ Rows = @((RegRow $script:U1 $true)); Complete = $false; Count = 1; Pages = 1; Error = 'MFA registration: page 2 failed after 6 attempt(s) -- HTTP 429 TooManyRequests' } }
        $map.Count | Should -Be 1
        $map[$script:U1].IsMfaRegistered | Should -BeTrue
        $script:Warned.Count | Should -Be 1
        $script:Warned[0] | Should -Match '^MFA registration data is incomplete for this run: it was read for 1 users'
        $script:Warned[0] | Should -Match 'slow down'
    }

    It 'a complete read: the real values, no warning line' {
        $map = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch { param($Url, $Token) [pscustomobject]@{ Rows = @((RegRow $script:U1 $true), (RegRow $script:U2 $false)); Complete = $true; Count = 2; Pages = 1; Error = $null } }
        $map[$script:U1].IsMfaRegistered | Should -BeTrue
        $map[$script:U2].IsMfaRegistered | Should -BeFalse
        $map[$script:U2].MfaMethodCount | Should -Be 0 -Because 'a password alone is not MFA'
        (Get-SIEntraMfaRegistrationState).Complete | Should -BeTrue
        $script:Warned.Count | Should -Be 0
    }

    It 'the real read uses the pager that keeps collected pages (never the throwing one)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:Shared 'IdentityRoleFetcher.ps1'))
        $fn = [regex]::Match($src, '(?s)function Get-SIEntraMfaRegistrationByPrincipal \{.*?\nfunction ').Value
        $fn | Should -Match 'Invoke-SIPagedRest -Url \$regUrl'
        $fn | Should -Not -Match 'Invoke-SIGraphPaged'
    }
}

Describe 'a user without MFA data is UNKNOWN on the discovery record, never "no MFA"' {
    It 'no entry: every MFA value is $null' {
        $f = ConvertTo-SIUserMfaFields -Entry $null
        $f.ContainsKey('ENTRA_MfaIsRegistered') | Should -BeTrue
        $null -eq $f.ENTRA_MfaIsRegistered | Should -BeTrue
        $null -eq $f.ENTRA_MfaMethodCount | Should -BeTrue
    }
    It 'an entry: the values are carried as read (false stays false -- a real "no MFA")' {
        Reset-SIIdentityFetcherCache
        $map = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch { param($Url, $Token) [pscustomobject]@{ Rows = @((RegRow $script:U2 $false)); Complete = $true; Count = 1; Pages = 1; Error = $null } }
        $f = ConvertTo-SIUserMfaFields -Entry $map[$script:U2]
        $f.ENTRA_MfaIsRegistered | Should -BeFalse
        $null -eq $f.ENTRA_MfaIsRegistered | Should -BeFalse
    }

    Context 'the whole Entra users discovery over a fake tenant' {
        BeforeAll {
            . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')
            . (Join-Path $script:Shared 'SI-FullAssetProperties.ps1')
            . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1')
            $script:SavedWs = $global:SI_WorkspaceResourceId
            $global:SI_WorkspaceResourceId = '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            $script:SavedStream = $global:SI_DiscoverStream; $global:SI_DiscoverStream = $null
            function script:FakeUser([string]$Id) {
                [pscustomobject]@{ id = $Id; displayName = $Id; userPrincipalName = "$Id@contoso.test"; accountEnabled = $true; createdDateTime = '2025-01-01T00:00:00Z'
                                   userType = 'Member'; onPremisesSyncEnabled = $null; assignedLicenses = @(); signInActivity = $null; customSecurityAttributes = $null }
            }
        }
        AfterAll { $global:SI_WorkspaceResourceId = $script:SavedWs; $global:SI_DiscoverStream = $script:SavedStream }
        BeforeEach {
            Mock Get-SIGraphToken { 'tok' }
            Mock Invoke-SIPagedRest {
                $rows = if ($Url -match '/users\?' -and $Url -notmatch 'deletedItems') { @((FakeUser $script:U1), (FakeUser $script:U2)) } else { @() }
                [pscustomobject]@{ Rows = $rows; Complete = $true; Pages = 1; Retries = 0; Count = $rows.Count; Error = $null }
            }
            foreach ($c in 'Get-SIEntraRoleDefinitionMap', 'Get-SIEntraRoleAssignmentsByPrincipal', 'Get-SIEntraPIMEligibleByPrincipal',
                           'Get-SIRoleAssignedGroups', 'Get-SIIdentityInfoByObjectId', 'Get-SIExposureGraphIdentities', 'Get-SIAzureDelegationsByPrincipal') { Mock $c { @{} } }
            Mock Get-SIInheritedRolesForPrincipal { [pscustomobject]@{ Permanent = @(); Eligible = @() } }
            # #549 the sign-in methods read is not what this suite tests (SIv3-PasswordlessOnly) -- no Graph call
            Mock Get-SIEntraPasswordlessByUser { @{} }
        }

        It 'MFA read failed: no record says "no MFA" (all unknown)' {
            Mock Get-SIEntraMfaRegistrationByPrincipal { @{} }
            $recs = @(Get-DiscoveryFromEntraUsers)
            $recs.Count | Should -Be 2
            @($recs | Where-Object { $_.ENTRA_MfaIsRegistered -eq $false }).Count | Should -Be 0
            @($recs | Where-Object { $null -eq $_.ENTRA_MfaIsRegistered }).Count | Should -Be 2
        }

        It 'MFA read succeeded: the user without MFA is "no MFA", the user with MFA is not' {
            Mock Get-SIEntraMfaRegistrationByPrincipal {
                @{ $script:U1 = [pscustomobject]@{ IsMfaRegistered = $true; MfaMethods = @('fido2'); MfaMethodCount = 1 }
                   $script:U2 = [pscustomobject]@{ IsMfaRegistered = $false; MfaMethods = @(); MfaMethodCount = 0 } }
            }
            $recs = @(Get-DiscoveryFromEntraUsers)
            ($recs | Where-Object { $_.ENTRA_UserId -eq $script:U1 }).ENTRA_MfaIsRegistered | Should -BeTrue
            $r2 = $recs | Where-Object { $_.ENTRA_UserId -eq $script:U2 }
            $r2.ENTRA_MfaIsRegistered | Should -BeFalse
            $null -eq $r2.ENTRA_MfaIsRegistered | Should -BeFalse
        }
    }
}

Describe 'the "no MFA" reports never turn an unknown into a row' {
    # the reports read the CI (SI_CI_CL): the filter is on the CI field si_mfa_registered (MfaIsRegistered is only its
    # output column); the rule is the same -- an equality with false, which a null never matches, and never a negation
    It '<_> filters si_mfa_registered == false (a null never matches) and never negates it' -ForEach @('Identity_NoMFA_Summary', 'Identity_NoMFA_Detailed') {
        $t = Get-ReportText $_
        $null -ne $t | Should -BeTrue
        $t | Should -Match '\| where si_mfa_registered == false'
        foreach ($c in 'si_mfa_registered', 'MfaIsRegistered') {
            $t | Should -Not -Match ($c + '\s*!=\s*true')
            $t | Should -Not -Match ('not\(\s*' + $c)
            $t | Should -Not -Match ('coalesce\(\s*' + $c + '\s*,\s*false')
        }
    }
}
