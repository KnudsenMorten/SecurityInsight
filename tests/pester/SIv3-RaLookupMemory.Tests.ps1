#Requires -Version 5.1
<#
    #711 -- RISK ANALYSIS RAN OUT OF MEMORY READING ONE REPORT'S LOOKUPS (the large ring-1 install, 2026-10-15 23:27Z,
    Identity_Admin_LogonTo_InternetExposedDevice_Summary: "a lookup this report needs could not be read from Log Analytics
    (its lookups) ... OutOfMemoryException", two hours into the run).

    The cause: every lookup a report read from Log Analytics (its let-bindings over SI_CI_CL / SI_*_Profile_CL -- ~100,000
    rows each at that install) was cached for the WHOLE run -- rows, inline text, per-slice groups, key index -- and never
    let go, so the process grew report by report. Now a lookup is kept only while the current or the previous report uses
    it (Start-RALookupCacheReport at the top of every report), nothing is cut (a lookup let go is read again, whole), an
    out-of-memory lets go of every cached lookup and is its own cause (si-ra-0303, class out-of-memory, support, a ticket),
    and the run health END says "out of memory" -- which raises the Risk Analysis job one size band at the next update,
    also for a Risk Analysis job whose run health names the engine 'risk-analysis' (matched on its own execution).

    OFFLINE: Log Analytics is a stub that counts its reads; no network, no tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-UplinkCauses.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    $script:Catalogue = @(Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\errors.locked.json') -Raw | ConvertFrom-Json)

    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Err2  { param($m) $script:Errs += , [string]$m }
    function script:Write-Warn2 { param($m) }

    # Log Analytics: every lookup body answers -RowsPer rows of the _ciPeer shape; every read is counted per body
    $script:RowsPer = 2000
    # (the stub is the reader under the real parted read -- a stub of the parted read itself would be shadowed by the
    # function the dot-sourced files define)
    function script:Invoke-LogAnalyticsKqlQuery {
        param($WorkspaceResourceId, $Query, $TimeoutSec)
        $script:Reads.Add([string]$Query)
        $script:SeenFlag = $global:SI_LaCompactRows
        $tag = [regex]::Match([string]$Query, 'lookup-(\w+)').Groups[1].Value
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $script:RowsPer; $i++) {
            $rows.Add([pscustomobject]@{ _peerKey = ('{0}-{1:x8}' -f $tag, $i); peer_ci_id = ('ci-{0}-{1}' -f $tag, $i); peer_tier = ($i % 4); peer_cmdb_id = ''; peer_rf_p = '["internet_exposed"]' })
        }
        $global:RA_LastLaQueryColumnTypes = @{ _peerKey = 'string'; peer_ci_id = 'string'; peer_tier = 'int'; peer_cmdb_id = 'string'; peer_rf_p = 'dynamic' }
        return , $rows.ToArray()
    }
    function script:Reset-State {
        foreach ($n in 'Rows', 'Snapshot', 'ColumnTypes', 'BucketGroups', 'BucketGroupsWhole', 'KeyIndex') { Set-Variable -Scope Script -Name ('_Hybrid{0}Cache' -f $n) -Value @{} }
        $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridCacheLastUse = @{}; $script:_HybridCacheReport = 0
        $script:_CrossDomainBucketCoalesce = @()
        $script:Reads = New-Object System.Collections.Generic.List[string]
        $script:Errs = @()
    }
    function script:Use-Lookup([string]$Name) {
        # what a report does with its lookup: read it (cached), index it for a slice's keys, keep its inline text
        $r = Get-SIHybridLetRows -VarName '_ciPeer' -BodyKql ("SI_CI_CL | where tag == 'lookup-{0}' | project _peerKey" -f $Name) -WorkspaceResourceId '/ws'
        $null = Get-RALookupRowsForKeys -CacheKey $r.CacheKey -AllRows @($r.Rows) -Column '_peerKey' -Keys @(('{0}-{1:x8}' -f $Name, 1))
        $script:_HybridSnapshotCache[$r.CacheKey] = ('datatable text of ' + $Name)
        $script:_HybridBucketGroupsCache[('{0}::8' -f $r.CacheKey)] = @{ 0 = @($r.Rows) }
        return $r
    }
    function script:Get-CachedLookups { @($script:_HybridRowsCache.Keys).Count }
    $script:LmhText = "a lookup this report needs could not be read from Log Analytics (its lookups) -- the report is not run without it, because it would then list findings twice or without their CI and CMDB values: Exception of type 'System.OutOfMemoryException' was thrown."
}

Describe 'a lookup is kept for the reports that use it, never for the whole run' {
    BeforeEach { Reset-State }

    It 'REPRODUCED: without the per-report release every report''s own lookup stays in memory to the end of the run' {
        # the run as it was: reports one after the other, each with a lookup of its own, nothing ever let go
        foreach ($i in 1..12) { $null = Use-Lookup ('r{0}' -f $i) }
        Get-CachedLookups | Should -Be 12 -Because 'this is what grew report by report until the process ran out of memory'
    }

    It 'with the release at the top of every report, at most the current and the previous report''s lookups are held -- however long the run' {
        $max = 0
        foreach ($i in 1..30) {
            $null = Start-RALookupCacheReport
            $null = Use-Lookup ('r{0}' -f $i)
            $max = [Math]::Max($max, (Get-CachedLookups))
        }
        $max | Should -BeLessOrEqual 2
        $script:_HybridSnapshotCache.Count | Should -BeLessOrEqual 2
        $script:_HybridBucketGroupsCache.Count | Should -BeLessOrEqual 2
        $script:_HybridKeyIndexCache.Count | Should -BeLessOrEqual 2
        $script:_HybridColumnTypesCache.Count | Should -BeLessOrEqual 2
    }

    It 'a lookup shared by reports in a row is read ONCE; one the previous report did not use is let go with everything built from it' {
        $null = Start-RALookupCacheReport          # report 1: A + B
        $a = Use-Lookup 'A'; $null = Use-Lookup 'B'
        $null = Start-RALookupCacheReport          # report 2: B + C -- A and B kept (report 1 used both), B not read again
        $null = Use-Lookup 'B'; $null = Use-Lookup 'C'
        @($script:Reads | Where-Object { $_ -match 'lookup-B' }).Count | Should -Be 1
        $script:_HybridRowsCache.ContainsKey($a.CacheKey) | Should -BeTrue
        $s = Start-RALookupCacheReport             # report 3: A was not used by report 2 -> let go
        $s.Released | Should -Be 1
        $s.Kept | Should -Be 2
        $script:_HybridRowsCache.ContainsKey($a.CacheKey) | Should -BeFalse
        $script:_HybridSnapshotCache.ContainsKey($a.CacheKey) | Should -BeFalse
        $script:_HybridColumnTypesCache.ContainsKey($a.CacheKey) | Should -BeFalse
        @($script:_HybridBucketGroupsCache.Keys | Where-Object { ([string]$_).StartsWith($a.CacheKey + '::') }).Count | Should -Be 0
        @($script:_HybridKeyIndexCache.Keys | Where-Object { ([string]$_).StartsWith($a.CacheKey + '::') }).Count | Should -Be 0
    }

    It 'NOTHING IS CUT: a lookup let go is read again, whole, by the next report that needs it' {
        $null = Start-RALookupCacheReport; $null = Use-Lookup 'A'
        $null = Start-RALookupCacheReport; $null = Use-Lookup 'B'
        $null = Start-RALookupCacheReport          # A let go here
        $again = Use-Lookup 'A'
        @($script:Reads | Where-Object { $_ -match 'lookup-A' }).Count | Should -Be 2
        @($again.Rows).Count | Should -Be $script:RowsPer
        (Get-RALookupRowsForKeys -CacheKey $again.CacheKey -AllRows @($again.Rows) -Column '_peerKey' -Keys @('A-00000005', 'A-000007cf')).Count | Should -Be 2
    }

    It 'the report loop lets go of the previous report''s lookups at the TOP of every report (the wiring)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        # (#742: the reports of a pass -- the template's in one job, one work item's on a queue worker)
        $loop = $src.IndexOf('foreach ($includeItem in $script:RALoopList) {')
        $loop | Should -BeGreaterThan 0
        $call = $src.IndexOf('Start-RALookupCacheReport', $loop)
        $call | Should -BeGreaterThan $loop
        $call | Should -BeLessThan $src.IndexOf('$inc = Resolve-ReportInclude -Item $includeItem', $loop) -Because 'before the report reads anything'
    }
}

Describe 'a kept lookup is held as compact rows: the same columns and values, a fraction of the memory' {
    BeforeAll {
        $script:Answer = [System.Text.Encoding]::UTF8.GetBytes('{"tables":[{"name":"PrimaryResult","columns":[{"name":"_peerKey","type":"string"},{"name":"peer_tier","type":"int"},{"name":"peer_rf_p","type":"dynamic"},{"name":"peer_in_scope","type":"bool"},{"name":"peer_cmdb_id","type":"string"},{"name":"class","type":"string"}],"rows":[["k1",0,"[\"internet_exposed\"]",true,null,"device"],["k2",3,"[]",false,"",null],["k3",1,"[\"a\",\"b\"]",true,"C-1"]]}]}')
    }
    AfterEach { $global:SI_LaCompactRows = $null }
    It 'asked for compact rows: one small object per row, the same values as the PSCustomObject rows (null stays null, a short row filled with null)' {
        $global:SI_LaCompactRows = $null
        $plain = (ConvertFrom-SILaQueryRows -Bytes $script:Answer).Rows
        $global:SI_LaCompactRows = $true
        $compact = (ConvertFrom-SILaQueryRows -Bytes $script:Answer).Rows
        $plain[0] | Should -BeOfType [System.Management.Automation.PSCustomObject]
        $compact[0].GetType().Namespace | Should -Be 'SecurityInsight.LaRows'
        $compact.Count | Should -Be 3
        @($compact[0].PSObject.Properties.Name) | Should -Be @($plain[0].PSObject.Properties.Name)
        for ($r = 0; $r -lt 3; $r++) {
            foreach ($n in @($plain[0].PSObject.Properties.Name)) {
                $a = $plain[$r].PSObject.Properties[$n].Value; $b = $compact[$r].PSObject.Properties[$n].Value
                if ($null -eq $a) { $b | Should -BeNullOrEmpty -Because "$n row $r" ; ($null -eq $b) | Should -BeTrue -Because "$n row $r stays null" }
                else { $b | Should -BeExactly $a -Because "$n row $r" }
            }
        }
        $compact[0].peer_tier | Should -Be '0'; $compact[0].peer_in_scope | Should -Be 'true'; $compact[0].class | Should -Be 'device'
    }
    It 'the inline text of a lookup is byte for byte the same from compact rows' {
        $global:SI_LaCompactRows = $null
        $plain = (ConvertFrom-SILaQueryRows -Bytes $script:Answer).Rows
        $global:SI_LaCompactRows = $true
        $compact = (ConvertFrom-SILaQueryRows -Bytes $script:Answer).Rows
        $types = @{ _peerKey = 'string'; peer_tier = 'int'; peer_rf_p = 'dynamic'; peer_in_scope = 'bool'; peer_cmdb_id = 'string'; class = 'string' }
        (Convert-RowsToKqlDatatable -LetVarName '_ciPeer' -Rows $compact -ColumnTypes $types) | Should -BeExactly (Convert-RowsToKqlDatatable -LetVarName '_ciPeer' -Rows $plain -ColumnTypes $types)
        $k = Get-RALookupRowsForKeys -CacheKey 'compact|x' -AllRows $compact -Column '_peerKey' -Keys @('k2', 'k9')
        $k.Count | Should -Be 1; $k[0].peer_tier | Should -Be '3'
    }
    It 'GUARD: the per-row readers of a lookup use plain member access -- $row.PSObject per row keeps a wrapper per row alive (~4 KB, measured)' {
        foreach ($fn in 'Convert-RowsToKqlDatatable', 'Get-SICLBucketKey', 'Get-RALookupRowsForKeys') {
            $body = (Get-Command -Name $fn).ScriptBlock.ToString()
            $body | Should -Not -Match '\$(r|row|Row)\.PSObject\.Properties' -Because $fn
        }
    }
    It 'a column the row does not have reads as nothing, as before (bucket key, key index)' {
        $script:_CrossDomainBucketCoalesce = @()
        Get-SICLBucketKey -Row ([pscustomobject]@{ Other = 'x'; DeviceId = 'dev-1' }) | Should -Be 'dev-1'
        Get-SICLBucketKey -Row ([pscustomobject]@{ Other = 'x' }) | Should -Be ''
        (Get-RALookupRowsForKeys -CacheKey 'missing|x' -AllRows @([pscustomobject]@{ a = 1 }) -Column 'nope' -Keys @('')).Count | Should -Be 1
    }
    It 'a column name that cannot be a property keeps the PSCustomObject rows; so does a read that did not ask' {
        Get-SILaCompactRowType -Names @('a-b', 'c') | Should -BeNullOrEmpty
        Get-SILaCompactRowType -Names @('Name', 'name') | Should -BeNullOrEmpty -Because 'PowerShell reads properties without case'
        $global:SI_LaCompactRows = $null
        (ConvertFrom-SILaQueryRows -Bytes $script:Answer).Rows[0] | Should -BeOfType [System.Management.Automation.PSCustomObject]
    }
    It 'the lookup read asks for compact rows only while it reads, and puts the setting back' {
        Reset-State
        $global:SI_LaCompactRows = 'before'
        $script:SeenFlag = $null
        $null = Get-SIHybridLetRows -VarName '_ciPeer' -BodyKql 'SI_CI_CL | project _peerKey' -WorkspaceResourceId '/ws'
        $script:SeenFlag | Should -BeTrue
        $global:SI_LaCompactRows | Should -Be 'before'
    }
}

Describe 'an out-of-memory reading a lookup is its own cause (si-ra-0303) and frees the memory' {
    BeforeEach { Reset-State }

    It 'the error says out of memory and carries si-ra-0303; the report ends at once, not complete; every cached lookup is let go' {
        $null = Use-Lookup 'A'; $null = Use-Lookup 'B'
        $oom = New-Object System.OutOfMemoryException
        $e = ConvertTo-RALookupUnavailableError -What 'its lookups' -Err $oom
        $e | Should -Not -BeNullOrEmpty
        $e.Message | Should -Match 'out of memory'
        $e.Message | Should -Match 'si-ra-0303'
        $e.Message | Should -Match 'a lookup this report needs could not be read'
        $e.Data['SIRACode'] | Should -Be 'si-ra-0303'
        Test-RALookupUnavailableError -Err $e | Should -BeTrue
        Test-RAReportCannotRunError -Err $e | Should -BeTrue -Because 'no retry, re-size or sub-slice is spent on it: the report is not complete, its findings unknown'
        Get-CachedLookups | Should -Be 0
        $script:_HybridSnapshotCache.Count | Should -Be 0
    }

    It 'a wrapped out-of-memory ("Exception calling ...: Exception of type ''System.OutOfMemoryException'' was thrown") is recognised too' {
        $inner = New-Object System.OutOfMemoryException
        $wrapped = New-Object System.Management.Automation.MethodInvocationException("Exception calling `"ToArray`" with `"0`" argument(s): `"Exception of type 'System.OutOfMemoryException' was thrown.`"", $inner)
        (ConvertTo-RALookupUnavailableError -What 'its lookups' -Err $wrapped).Data['SIRACode'] | Should -Be 'si-ra-0303'
        Test-RAOutOfMemoryError -Err "Exception of type 'System.OutOfMemoryException' was thrown." | Should -BeTrue
    }

    It 'converted once only: the si-ra-0303 error passed on again is not wrapped a second time' {
        $e = ConvertTo-RALookupUnavailableError -What 'its lookups' -Err (New-Object System.OutOfMemoryException)
        ConvertTo-RALookupUnavailableError -What 'its lookups' -Err $e | Should -BeNullOrEmpty
    }

    It 'NEGATIVE: any other failed read stays "lookup unavailable" without the code; a table that does not exist stays no data source' {
        $other = ConvertTo-RALookupUnavailableError -What 'its lookups' -Err (New-Object System.InvalidOperationException('Response status code does not indicate success: 503'))
        $other.Message | Should -Not -Match 'si-ra-0303|out of memory'
        $other.Data.Contains('SIRACode') | Should -BeFalse
        ConvertTo-RALookupUnavailableError -What 'its lookups' -Err "Failed to resolve table or column expression named 'SI_CI_CL'" | Should -BeNullOrEmpty
    }

    It 'Invoke-RAResolveLookups throws the si-ra-0303 error when the lookups ran out of memory' {
        $thrown = $null
        try { $null = Invoke-RAResolveLookups -Query 'let _ciPeer = SI_CI_CL | project a; T' -WorkspaceResourceId '/ws' -Resolve { param($q) throw (New-Object System.OutOfMemoryException) } -Shadow { param($q) $q } }
        catch { $thrown = $_ }
        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Data['SIRACode'] | Should -Be 'si-ra-0303'
        $thrown.Exception.Message | Should -Match '\(its lookups\): Risk Analysis ran out of memory'
    }
}

Describe 'the run record and the catalogue: out-of-memory is si-ra-0303 (support, a ticket)' {
    It 'the large install''s own text maps to out-of-memory / si-ra-0303 (it was read as too-large before)' {
        $c = Get-SIReportCause -State 'NotComplete' -Text $script:LmhText
        $c.CauseClass | Should -Be 'out-of-memory'
        Resolve-SIReportCauseCode -Cause $c | Should -Be 'si-ra-0303'
    }
    It 'the new text maps to it too, and the item carries it' {
        $e = New-RALookupOutOfMemoryError -What 'its lookups' -Line 'Exception of type ''System.OutOfMemoryException'' was thrown.'
        $i = @(ConvertTo-SIUplinkReports -Facts @([pscustomobject]@{ Report = 'Identity_Admin_LogonTo_InternetExposedDevice_Summary'; State = 'NotComplete'; Why = $e.Message }) -Version '3.0.0.202610160900' -Catalogue $script:Catalogue)[0]
        $i.Code | Should -Be 'si-ra-0303'
        $i.CauseClass | Should -Be 'out-of-memory'
        $i.Action | Should -Be 'support'
    }
    It 'the catalogue entry: class out-of-memory, support acts, a ticket' {
        $e = $script:Catalogue | Where-Object code -eq 'si-ra-0303'
        $e | Should -Not -BeNullOrEmpty
        $e.causeClass | Should -Be 'out-of-memory'
        $e.action | Should -Be 'support'
        $e.whoActs | Should -Be 'support'
        $e.opensTicket | Should -BeTrue
        $e.customerText | Should -Not -Match '#\d'
        (Get-SIUplinkCausesContract).CauseClasses | Should -Contain 'out-of-memory'
    }
    It 'NEGATIVE: a result over the size limit is still too-large, not out of memory' {
        (Get-SIReportCause -State 'Failed' -Text 'it failed: Query execution has exceeded the allowed limits').CauseClass | Should -Be 'too-large'
    }
}

Describe 'the Risk Analysis job goes up one size band after a report ran out of memory' {
    BeforeAll {
        $script:T0 = [datetime]::new(2026, 10, 15, 21, 35, 0, [DateTimeKind]::Utc)
        function script:New-Exec([string]$Name, [string]$Status, [datetime]$Start, [int]$Seconds) {
            [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $Start.ToString('o'); endTime = $Start.AddSeconds($Seconds).ToString('o') } }
        }
        $script:OomEnd = 'success-partial'
        $script:OomMsg = '1 report(s) incomplete -- their findings are unknown, not remediated: Identity_Admin_LogonTo_InternetExposedDevice_Summary (' + (New-RALookupOutOfMemoryError -What 'its lookups' -Line 'x').Message + ')'
    }
    It 'the Risk Analysis job (its run health says risk-analysis): the run ended without an error, its END says out of memory -> one band up' {
        $e = @(New-Exec 'caj-si-risk-analysis-q1' 'Succeeded' $script:T0 7300)
        $rh = @([pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'End'; ExitReason = $script:OomEnd; ErrorMessage = $script:OomMsg; Execution = 'caj-si-risk-analysis-q1'; TimeGenerated = $script:T0.AddSeconds(7290).ToString('o') })
        $s = Get-SIJobFailureSignal -JobName 'caj-si-risk-analysis' -Engine 'risk-analysis' -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh
        $s.Kind | Should -Be 'oom'
        $cur = [pscustomobject]@{ Cpu = [double]2.0; Memory = '4.0Gi'; MemoryGi = [double]4.0; ReplicaTimeout = 604800 }
        $c = Get-SIJobSizeChange -JobName 'caj-si-risk-analysis' -Engine 'risk-analysis' -Current $cur -Failure $s
        $c.Action | Should -Be 'raise'; $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'
    }
    It 'REPRODUCED -> FIXED: the Detailed job records its run health as risk-analysis; matched on its own execution it is raised too' {
        $e = @(New-Exec 'caj-si-risk-analysis-detailed-d1' 'Succeeded' $script:T0 7300)
        $rh = @([pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'End'; ExitReason = $script:OomEnd; ErrorMessage = $script:OomMsg; Execution = 'caj-si-risk-analysis-detailed-d1'; TimeGenerated = $script:T0.AddSeconds(7290).ToString('o') })
        (Get-SIJobFailureSignal -JobName 'caj-si-risk-analysis-detailed' -Engine 'risk-analysis-detailed' -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh).Kind | Should -Be 'oom'
    }
    It 'NEGATIVE: another execution''s out-of-memory record is not this Detailed job''s, and a partial run for another reason is no signal' {
        $e = @(New-Exec 'caj-si-risk-analysis-detailed-d1' 'Succeeded' $script:T0 7300)
        $other = @([pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'End'; ExitReason = $script:OomEnd; ErrorMessage = $script:OomMsg; Execution = 'caj-si-risk-analysis-q1'; TimeGenerated = $script:T0.AddSeconds(7290).ToString('o') })
        Get-SIJobFailureSignal -JobName 'caj-si-risk-analysis-detailed' -Engine 'risk-analysis-detailed' -ReplicaTimeout 604800 -Executions $e -RunHealthRows $other | Should -BeNullOrEmpty
        $plain = @([pscustomobject]@{ Engine = 'risk-analysis'; Phase = 'End'; ExitReason = 'success-partial'; ErrorMessage = '1 report(s) incomplete: x (its query failed: 503)'; Execution = 'caj-si-risk-analysis-detailed-d1'; TimeGenerated = $script:T0.AddSeconds(7290).ToString('o') })
        Get-SIJobFailureSignal -JobName 'caj-si-risk-analysis-detailed' -Engine 'risk-analysis-detailed' -ReplicaTimeout 604800 -Executions $e -RunHealthRows $plain | Should -BeNullOrEmpty
    }
    It 'the update reads the execution of every run health row' {
        Get-SIJobSizingKql -Kind RunHealthRows | Should -Match "Execution = tostring\(column_ifexists\('Execution', ''\)\)"
    }
}

# On demand only (owner rule: the 100,000-record measurements carry the tag Scale and no gate runs them).
Describe 'MEASURED: a run of reports each with its own ~100,000-row lookup' -Tag 'Scale' {
    It 'the memory held after 20 reports stays at about two lookups' {
        Reset-State
        $script:RowsPer = 100000
        foreach ($i in 1..20) { $null = Start-RALookupCacheReport; $null = Use-Lookup ('m{0}' -f $i) }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
        Get-CachedLookups | Should -BeLessOrEqual 2
        Write-Host ('managed memory after 20 reports: {0:N0} MB' -f ([GC]::GetTotalMemory($true) / 1MB))
        $script:RowsPer = 2000
    }
}
