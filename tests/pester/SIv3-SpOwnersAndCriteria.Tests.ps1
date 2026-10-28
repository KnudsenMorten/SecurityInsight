#Requires -Version 5.1
<#
    SERVICE-PRINCIPAL OWNERS IN THE PROFILE, AND FACTOR CRITERIA (#541 (7)).

    1. ORPHANED SERVICE PRINCIPALS. The identity profile's IsOrphanSPN read an 'Owner' value no collector set, so EVERY service
       principal came out orphaned. It now reads ENTRA_OwnerCount, which the service-principal discovery takes from ONE owners
       read before it lists the principals (Get-SISpOwnerCounts): 0 owners = orphaned, owners = not, NOT READ = unknown ($null),
       never orphaned. The read pages at $top=100 (Graph caps the page size with $expand on directory objects) and follows
       nextLink; an owners list that may be truncated counts as "has owners", never 0.
    2. CRITERIA. A factor's criteria block (what the web app's wizard edits) is validated by Test-SIRiskFactorCriteria, and the
       data-model validation runs it, so a customer override is held to it: kind list | threshold | range, an SI field (never
       si_tier), a source, a list the condition reads, a threshold leaf whose value is inside [min, max].
    Offline; PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRiskFactors.ps1')
    $script:Model = Get-SIDataModel
    # not 'Sp': that is PowerShell's alias of Set-ItemProperty, and an alias wins over a function
    function script:SpProfile([hashtable]$Meta) { [pscustomobject]@{ IsServicePrincipal = $true; Upn = ''; Metadata = $Meta } }
}
Describe 'the owners read' {
    AfterEach { $global:SISpOwnerState = $null }
    It 'pages at $top=100 with owners expanded, and counts each principal''s owners' {
        $script:U = $null
        $s = Get-SISpOwnerCounts -Fetch { param($u) $script:U = $u; @([pscustomobject]@{ id = 'A'; owners = @() }, [pscustomobject]@{ id = 'b'; owners = @([pscustomobject]@{ id = 'u1' }, [pscustomobject]@{ id = 'u2' }) }) } -Refresh
        $script:U | Should -Match '\$expand=owners\(\$select=id,displayName,userPrincipalName\)'
        $script:U | Should -Match '\$top=100'
        $script:U | Should -Not -Match '\$top=999'
        $s.Read | Should -BeTrue
        Get-SISpOwnerCount -Id 'a' | Should -Be 0
        Get-SISpOwnerCount -Id 'B' | Should -Be 2
        Get-SISpOwnerCount -Id 'not-read' | Should -BeNullOrEmpty
    }
    It 'an owners list that may be truncated counts as "has owners", never 0' {
        $row = [pscustomobject]@{ id = 'c'; owners = @() }
        $row | Add-Member -NotePropertyName 'owners@odata.nextLink' -NotePropertyValue 'https://graph.microsoft.com/next'
        $null = Get-SISpOwnerCounts -Fetch { param($u) @($row, [pscustomobject]@{ id = 'd'; owners = @(1..20 | ForEach-Object { [pscustomobject]@{ id = "u$_" } }) }) } -Refresh
        Get-SISpOwnerCount -Id 'c' | Should -BeGreaterThan 0
        Get-SISpOwnerCount -Id 'd' | Should -Be 20
    }
    It 'a failed read leaves every count unknown' {
        $s = Get-SISpOwnerCounts -Fetch { param($u) throw 'Forbidden' } -Refresh -WarningAction SilentlyContinue
        $s.Read | Should -BeFalse
        Get-SISpOwnerCount -Id 'a' | Should -BeNullOrEmpty
    }
    It 'pages through Invoke-SIPagedRest (which follows @odata.nextLink) when no test fetch is given' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1'))
        $t | Should -Match "Invoke-SIPagedRest -Url \`$url -Token \`$Token -SourceLabel 'EntraServicePrincipals owners'"
    }
}

Describe 'IsOrphanSPN in the identity profile' {
    AfterEach { $global:SISpOwnerState = $null }
    It 'no owners = orphaned; owners = not orphaned' {
        (Get-SIIdentityRiskFactors -Record (SpProfile @{ ENTRA_OwnerCount = 0 })).IsOrphanSPN | Should -BeTrue
        (Get-SIIdentityRiskFactors -Record (SpProfile @{ ENTRA_OwnerCount = 3 })).IsOrphanSPN | Should -BeFalse
    }
    It 'owners NOT read = unknown ($null), never orphaned' {
        $r = Get-SIIdentityRiskFactors -Record (SpProfile @{})
        $r.Contains('IsOrphanSPN') | Should -BeTrue
        $r.IsOrphanSPN | Should -BeNullOrEmpty
        $r.IsOrphanSPN | Should -Not -BeTrue
    }
    It 'a user is never an orphaned service principal' {
        (Get-SIIdentityRiskFactors -Record ([pscustomobject]@{ IsServicePrincipal = $false; Upn = 'a@b.c'; Metadata = @{ ENTRA_OwnerCount = 0 } })).IsOrphanSPN | Should -BeFalse
    }
    It 'is wired: the discovery reads the owners before the principals and every record carries ENTRA_OwnerCount' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraServicePrincipals.ps1'))
        $t | Should -Match 'ENTRA_OwnerCount\s+= \(Get-SISpOwnerCount -Id \(\[string\]\$sp\.id\) -AppOwners '
        $read = $t.IndexOf('Get-SISpOwnerCounts -Token $token -Refresh')
        $read | Should -BeGreaterThan 0
        $read | Should -BeLessThan $t.IndexOf('# #475 STREAMING')
        $read | Should -BeLessThan $t.LastIndexOf('Invoke-SIPagedRest -Url $url -Token $token')
    }
    It 'the record part comes from the same read (no second Graph call)' {
        $null = Reset-SIRecordCapture -Engine t -Clear
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key 'x1' -Part sp -Object ([pscustomobject]@{ id = 'x1' })
        $global:SISpOwnerState = @{ Read = $true; Complete = $true; Counts = @{ x1 = 0 } }
        $script:Called = 0
        Invoke-SISpOwnerCapture -Token 't' | Should -Be 1
        $global:SIRecordCaptureState.Records['entra|service_principal|x1'].Parts.Contains('owners') | Should -BeTrue
    }
}

Describe 'factor criteria (what the wizard edits)' {
    AfterEach { $global:SISpOwnerState = $null }
    BeforeAll {
        function script:F([string]$Id) { (@($script:Model['risk-factors'].factors | Where-Object { $_.id -eq $Id })[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
        $script:Lists = Get-SIDataModelListContext $script:Model
    }
    It 'the shipped criteria are valid: unsupported_os is a list of collected OS values; the stale / age factors are thresholds' {
        foreach ($f in @($script:Model['risk-factors'].factors | Where-Object { $_.PSObject.Properties['criteria'] })) { @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -BeNullOrEmpty -Because $f.id }
        (F 'unsupported_os').criteria.kind | Should -Be 'list'
        (F 'unsupported_os').criteria.list | Should -Be 'unsupported_os'
        (F 'unsupported_os').criteria.source | Should -Be 'collected'
        # #559: one stale factor (very_stale_sign_in folded into stale_sign_in -- its days are the criteria); old_vuln is new
        foreach ($id in 'stale_sign_in', 'old_password', 'old_account', 'old_vuln') { (F $id).criteria.kind | Should -Be 'threshold' -Because $id }
        @($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'very_stale_sign_in' }).Count | Should -Be 0
    }
    It 'refuses a threshold outside its range, a tier field, an unknown kind or source, a list the condition does not read' {
        $f = F 'stale_sign_in'; $f.criteria.max = 50
        @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -Match 'outside the criteria range'
        $f = F 'stale_sign_in'; $f.criteria.field = 'si_tier'
        @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -Match 'never si_tier'
        $f = F 'stale_sign_in'; $f.criteria.kind = 'freetext'
        @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -Match "criteria kind 'freetext'"
        $f = F 'unsupported_os'; $f.criteria.list = 'high_risk_ports'
        @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -Match 'does not read the criteria list'
        $f = F 'unsupported_os'; $f.criteria.source = 'kql'
        @(Test-SIRiskFactorCriteria -Factor $f -Lists $script:Lists) | Should -Match "criteria source 'kql'"
    }
    It 'the data-model validation runs it (a customer override is held to it)' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RiskFactorCatalog.ps1')) | Should -Match 'foreach \(\$x in \(Test-SIRiskFactorCriteria -Factor \$f -Lists \$lists\)\) \{ \$p\.Add\(\$x\) \}'
    }
}
