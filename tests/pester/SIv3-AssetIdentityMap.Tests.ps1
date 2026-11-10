#Requires -Version 5.1
<#
    THE ONE ASSET-IDENTITY RESOLVER -- EXECUTED, not asserted from source text.

    🔴 WHY IT EXISTS. Measured 2026-08-30: **84 reports resolve an asset identity across NINE
    different hand-written chain variants** in the locked catalog, and this session added a tenth.
    Every identity fix had to be applied to "these four sites but not those six", and twice it was
    applied to a report that did not have the columns. Nine dialects cannot be kept in step across
    ~6,000 customer estates -- they drift silently, exactly the way `AssetId` and `AssetType` drifted
    into declared-but-never-built.

    🔑 WHAT MAKES IT GENERIC: the chain is keyed on identity SOURCE PRIORITY, never on resource type.
    Nothing in it hard-codes a resource type, a naming convention or a tenant, which is what lets it
    hold for an estate this code has never seen.

    🪤 AND IT SHIPPED BROKEN FOR ONE RUN, WHICH IS WHY THESE TESTS EXECUTE IT. The first version
    wrapped the query call in `@()`. `Invoke-LogAnalyticsKqlQuery` returns its rows comma-protected,
    so `@(call)` re-wraps them into a single element and the map built with "Endpoint=1 Azure=1
    Identity=1" instead of 237/770/1593 -- while logging success. The trap is documented at
    RA-GraphHunting.ps1:351 and a source-shape assertion would not have caught it.
#>

BeforeAll {
    $script:SIRoot   = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:MapPath  = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AssetIdentityMap.ps1'
    . $script:MapPath
}

Describe 'the asset-identity resolver -- key derivation' {

    It 'derives the short key by stripping the DNS suffix' {
        # EG names a device by FQDN, the endpoint profile stores the MDE short name. Measured: a
        # full-name key resolved 3 of 4 device probes and missed exactly the FQDN one.
        Get-SIIdentityShortKey -Name 'host1.contoso.local' | Should -BeExactly 'host1'
        Get-SIIdentityShortKey -Name 'HOST1'               | Should -BeExactly 'host1'
        Get-SIIdentityShortKey -Name 'STRV-MOK-LT-06'      | Should -BeExactly 'strv-mok-lt-06'
    }

    It 'returns empty for a blank name rather than throwing' {
        Get-SIIdentityShortKey -Name ''    | Should -BeExactly ''
        Get-SIIdentityShortKey -Name $null | Should -BeExactly ''
    }

    It 'derives the ARM parent/child key generically, not just for SQL' {
        # The pair ExposureGraph puts in its parentheses. Written over the last two <type>/<name>
        # segments so any child-resource type resolves the same way.
        Get-SIIdentityPathKey -AssetId 'az:/subscriptions/x/resourcegroups/rg/providers/microsoft.sql/servers/sql-ait-mfnpr/databases/master' |
            Should -BeExactly 'sql-ait-mfnpr/master'
        Get-SIIdentityPathKey -AssetId 'az:/subscriptions/x/resourcegroups/rg/providers/microsoft.web/sites/mysite/slots/staging' |
            Should -BeExactly 'mysite/staging'
    }

    It 'returns empty for an id with no parent/child pair -- a top-level resource has none' {
        # 🪤 THIS CASE CAUGHT A REAL BUG. The first pattern just took the last four segments, so a
        # bare resource-group id produced the key "x/rg" -- a resource GROUP posing as a parent/child
        # pair, free to false-match an unrelated asset. Anchoring on /providers/ fixed it.
        Get-SIIdentityPathKey -AssetId 'az:/subscriptions/x/resourcegroups/rg' | Should -BeExactly ''
        Get-SIIdentityPathKey -AssetId ''                                     | Should -BeExactly ''
        # a TOP-LEVEL resource has a provider but no parent/child pair
        Get-SIIdentityPathKey -AssetId 'az:/subscriptions/x/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv-x' |
            Should -BeExactly ''
    }
}

Describe 'the asset-identity resolver -- lookup priority' {

    BeforeAll {
        # Drive the resolver's own dictionaries directly: this is about priority, not about LA.
        $mod = Get-Module -All | Where-Object { $_.Path -eq $script:MapPath } | Select-Object -First 1
        $exact = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $short = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $path  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $exact['SRV-A']              = [pscustomobject]@{ Id='id-exact'; Name='SRV-A'; Type='Endpoint'; Table='SI_Endpoint_Profile_CL' }
        $short['srv-b']              = [pscustomobject]@{ Id='id-short'; Name='SRV-B'; Type='Endpoint'; Table='SI_Endpoint_Profile_CL' }
        $path['sql-x/master']        = [pscustomobject]@{ Id='id-path';  Name='master'; Type='microsoft.sql/servers/databases'; Table='SI_Azure_Profile_CL' }
        Set-Variable -Scope Script -Name _SIIdentityExact -Value $exact
        Set-Variable -Scope Script -Name _SIIdentityShort -Value $short
        Set-Variable -Scope Script -Name _SIIdentityPath  -Value $path
    }

    It 'matches an exact name first, and case-insensitively' {
        # MDE, ARM and EG disagree about case constantly -- measured, a case-sensitive key resolved
        # 2 of 21 device names where a case-insensitive one resolved 14.
        (Resolve-SIAssetIdentity -Name 'SRV-A').Id | Should -BeExactly 'id-exact'
        (Resolve-SIAssetIdentity -Name 'srv-a').Id | Should -BeExactly 'id-exact'
    }

    It 'falls back to the short name for an FQDN' {
        (Resolve-SIAssetIdentity -Name 'srv-b.contoso.local').Id | Should -BeExactly 'id-short'
    }

    It 'falls back to the ARM parent/child pair in an EG-style label' {
        (Resolve-SIAssetIdentity -Name 'master (sql-x/master)').Id | Should -BeExactly 'id-path'
    }

    It 'returns NULL when nothing matches -- an empty id is a real answer' {
        # An ExposureGraph subscription node has no identity anywhere and SHOULD report no id rather
        # than borrow one. Returning a wrong id is worse than returning none.
        Resolve-SIAssetIdentity -Name 'sg-visualstudio 2 (DEMO) - USD150 month' | Should -BeNullOrEmpty
        Resolve-SIAssetIdentity -Name ''                                        | Should -BeNullOrEmpty
    }
}

Describe 'a table the map could not read is never taken as no assets' {
    BeforeAll {
        function script:Write-Info { param($m) }
        function script:Write-Warn2 { param($m) $script:Warned.Add([string]$m) }
        function script:Test-RANoDataSource { param($Message) [string]$Message -match 'Failed to resolve table' }
        function script:Invoke-LogAnalyticsKqlQueryParted {
            param($WorkspaceResourceId, $Query, $What)
            $script:Asked.Add([string]$What)
            foreach ($t in @($script:Fail.Keys)) { if ($Query -match $t) { throw $script:Fail[$t] } }
            $k = if ($Query -match 'SI_Endpoint') { 'e' } elseif ($Query -match 'SI_Azure') { 'a' } else { 'i' }
            , @([pscustomobject]@{ SI_AssetName = "host-$k"; SI_AssetId = "id-$k"; Seen = '2026-11-01T00:00:00Z'; AssetType = 'x'; AzureResourceId = ''; EgNodeId = '' })
        }
        $script:Ws = '/subscriptions/x/workspaces/w'
    }
    BeforeEach {
        $script:Warned = New-Object System.Collections.Generic.List[string]
        $script:Asked = New-Object System.Collections.Generic.List[string]
        $script:Fail = @{}
    }
    It 'a table that timed out: the other tables are mapped, a summary report ends not complete' {
        $script:Fail['SI_Azure'] = 'Request timed out'
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        (Resolve-SIAssetIdentity -Name 'host-e').Id | Should -Be 'id-e'
        $err = $null; try { Assert-SIAssetIdentityMapRead -ReportName 'X_Summary' -WorkspaceResourceId '' } catch { $err = $_ }
        $err.Exception.Data['SIRALookupUnavailable'] | Should -BeTrue
        $err.Exception.Message | Should -Match 'a lookup this report needs could not be read'
    }
    It 'a table too large for any number of parts is the same' {
        $tooLarge = New-Object System.InvalidOperationException('the asset identities are more than Log Analytics can answer')
        $tooLarge.Data['SIRALookupTooLarge'] = $true
        $script:Fail['SI_Identity'] = $tooLarge
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        { Assert-SIAssetIdentityMapRead -ReportName 'X_Summary_Y' -WorkspaceResourceId '' } | Should -Throw '*could not be read*'
    }
    It 'a detailed report is not held for it and asks nothing' {
        $script:Fail['SI_Azure'] = 'Request timed out'
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        $script:Asked.Clear()
        { Assert-SIAssetIdentityMapRead -ReportName 'X_Detailed_Y' -WorkspaceResourceId $script:Ws } | Should -Not -Throw
        $script:Asked.Count | Should -Be 0
    }
    It 'the next report asks only the unread table again; once it reads, the map is whole and nothing more is asked' {
        $script:Fail['SI_Azure'] = 'Request timed out'
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        $script:Fail.Clear(); $script:Asked.Clear()
        { Assert-SIAssetIdentityMapRead -ReportName 'X_Summary' -WorkspaceResourceId $script:Ws } | Should -Not -Throw
        @($script:Asked) | Should -Be @('the asset identities of SI_Azure_Profile_CL')
        (Resolve-SIAssetIdentity -Name 'host-a').Id | Should -Be 'id-a'
        (Resolve-SIAssetIdentity -Name 'host-e').Id | Should -Be 'id-e'
        $script:Asked.Clear()
        Assert-SIAssetIdentityMapRead -ReportName 'X_Summary' -WorkspaceResourceId $script:Ws
        $script:Asked.Count | Should -Be 0
    }
    It 'still unread on the next report: asked again, never remembered as no assets' {
        $script:Fail['SI_Azure'] = 'Request timed out'
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        $script:Asked.Clear()
        { Assert-SIAssetIdentityMapRead -ReportName 'X_Summary' -WorkspaceResourceId $script:Ws } | Should -Throw '*could not be read*'
        @($script:Asked) | Should -Be @('the asset identities of SI_Azure_Profile_CL')
    }
    It 'a table that does not exist has no assets: no report is held and it is not asked again (control)' {
        $script:Fail['SI_Azure'] = "Failed to resolve table or column expression named 'SI_Azure_Profile_CL'"
        Initialize-SIAssetIdentityMap -WorkspaceResourceId $script:Ws -Force
        $script:Asked.Clear()
        { Assert-SIAssetIdentityMapRead -ReportName 'X_Summary' -WorkspaceResourceId $script:Ws } | Should -Not -Throw
        $script:Asked.Count | Should -Be 0
    }
    It 'which reports need the map: the summary names only' {
        Test-SIAssetIdentityMapNeeded -ReportName 'A_Summary' | Should -BeTrue
        Test-SIAssetIdentityMapNeeded -ReportName 'A_Summary_B' | Should -BeTrue
        Test-SIAssetIdentityMapNeeded -ReportName 'A_Detailed_B' | Should -BeFalse
    }
    It 'the report loop checks it after the report''s stream start, so a failure removes only that report''s rows (source)' {
        $eng = Get-Content -Raw -Encoding UTF8 (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $start = $eng.IndexOf('$null = Start-RAStreamReport -Stream $script:RAStream -ReportName')
        $start | Should -BeGreaterThan 0
        $eng.IndexOf('Assert-SIAssetIdentityMapRead -ReportName') | Should -BeGreaterThan $start
    }
}

Describe 'the resolver is wired into the engine, not merely present' {

    It 'is dot-sourced by the risk-analysis engine' {
        # A resolver nothing calls is the defect family this whole session kept finding.
        $eng = Get-Content -Raw -Encoding UTF8 (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $eng | Should -Match 'RA-AssetIdentityMap\.ps1'
        $eng | Should -Match 'Initialize-SIAssetIdentityMap'
    }

    It 'is actually consulted when an id is still blank' {
        $rs = Get-Content -Raw -Encoding UTF8 (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        $rs | Should -Match 'Resolve-SIAssetIdentity'
    }

    It 'never wraps the LA call in @() -- the trap that made the map build with 1 row per table' {
        $txt = Get-Content -Raw -Encoding UTF8 $script:MapPath
        $txt | Should -Not -Match '@\(Invoke-LogAnalyticsKqlQuery'
    }

    It 'reports short-name collisions instead of resolving them silently' {
        # 31 collisions on this estate. A large customer will have more, and a wrong id is worse than
        # none -- so the count must reach the operator.
        $txt = Get-Content -Raw -Encoding UTF8 $script:MapPath
        $txt | Should -Match 'short-name collision'
    }
}
