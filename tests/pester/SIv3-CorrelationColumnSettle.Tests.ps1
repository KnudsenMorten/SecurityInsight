#Requires -Version 5.1
<#
    A PROFILE TABLE TAKING A NEW COLUMN DOES NOT STOP THE CORRELATION STEP (live 2026-11-13, ring 2, release 3.1.16).
    The asset-correlation step failed on attempt 1 with
        'project' operator: Failed to resolve scalar expression named '["PrivilegedLogonEvidence"]'
    and Risk Analysis, the CMDB step, vulnerabilities and close-loop mail were skipped. The correlation read never names
    that column: every profile column is read through column_ifexists. The name came from Log Analytics' own expansion of
    the endpoint table, which the endpoint step had just extended with the new column in the same run; until the service
    has finished adding a column it refuses reads of the table naming it.

      * THE QUERY: the snapshot and count queries name every profile column only through column_ifexists (no bare
        reference, no ["..."] reference) -- a table without any of the columns still answers.
      * THE WAIT: a read refused for a column the query does not name bare is read again (the stage's freshness wait),
        said once; a name the query writes itself is a fault of the query and fails at once; every other failure is
        thrown unchanged, at once.
      * WIRING: every correlation read (paged, freshness, whole snapshot) goes through it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationCore.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationIngest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationPaged.ps1')
    $script:T = [datetime]::SpecifyKind([datetime]'2026-11-13T18:21:00', [DateTimeKind]::Utc)
    # the service's answer, as the step's log carried it
    $script:Live = 'Operation returned an invalid status code ''BadRequest'' -- SemanticError/SEM0100: ''project'' operator: Failed to resolve scalar expression named ''["PrivilegedLogonEvidence"]'''
    $script:Columns = @()
    foreach ($e in 'endpoint', 'identity', 'azure', 'public-ip') {
        $s = Get-Content -Raw (Join-Path $script:SIRoot ('asset-profiling-schema\{0}.schema.locked.json' -f $e)) | ConvertFrom-Json
        $script:Columns += @($s.fields | ForEach-Object { [string]$_.name } | Where-Object { $_ })
    }
    $script:Columns = @($script:Columns | Select-Object -Unique)
    # the query with every column_ifexists("<name>" taken out: what is left is what the query names bare
    function script:Bare([string]$Q) { [regex]::Replace($Q, '(?i)column_ifexists\(\s*"[^"]*"', 'column_ifexists(') }
    # the right-hand sides of the project list (the alias on the left is the result column's name, not a read)
    function script:ProjectReads([string]$Q) {
        $i = $Q.IndexOf('| project'); if ($i -lt 0) { return '' }
        (@(($Q.Substring($i + 9) -split "`n") | ForEach-Object { $p = $_.IndexOf('='); if ($p -ge 0) { $_.Substring($p + 1) } else { $_ } }) -join "`n")
    }
}

Describe 'The correlation query names every profile column only through column_ifexists' {
    It 'the snapshot query (whole and a part), and the count query: no bare and no ["..."] column reference' {
        $schemaCols = @($script:Columns | Where-Object { $_ -ne 'CollectionTime' })
        $schemaCols.Count | Should -BeGreaterThan 50 -Because 'the four profile schemas were read'
        $schemaCols | Should -Contain 'PrivilegedLogonEvidence'
        foreach ($q in @(
            (Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL'),
            (Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL' -SnapshotTime $script:T -Part 1 -Parts 4),
            (Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL' -RowLimit 10),
            (Get-SICorrelationCountKql -TableName 'SI_Endpoint_Profile_CL'))) {
            $q | Should -Not -Match '\[\s*["''][A-Za-z_]'
            $reads = Bare (ProjectReads $q)
            $where = Bare (($q -split "`n" | Where-Object { $_ -notmatch '^\s*\| project' -and $_ -match '\bwhere\b|let ' }) -join "`n")
            foreach ($c in $schemaCols) {
                $rx = '(?<![A-Za-z0-9_"])' + [regex]::Escape($c) + '(?![A-Za-z0-9_"])'
                $reads | Should -Not -Match $rx -Because ("'{0}' must be read through column_ifexists" -f $c)
                $where | Should -Not -Match $rx -Because ("'{0}' must be read through column_ifexists" -f $c)
            }
        }
    }
    It 'every column it reads keeps its result name and type: tostring(column_ifexists(name, "")), EntityIds dynamic' {
        $q = Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL'
        foreach ($c in (Get-SICorrelationProjection)) { $q | Should -Match ([regex]::Escape(('{0} = tostring(column_ifexists("{0}", ""))' -f $c))) }
        $q | Should -Match ([regex]::Escape('EntityIds = column_ifexists("EntityIds", dynamic(null))'))
        $q | Should -Match ([regex]::Escape('AssetName = coalesce(tostring(column_ifexists("SI_AssetName", "")), tostring(column_ifexists("AssetName", "")))'))
    }
    It 'a fake table that lacks the new columns still answers the query (every name it reads is a column the table has or a column_ifexists)' {
        # a fake table: only what every profile table has had since v3 began -- no PrivilegedLogon* column, no EgNodeId
        $fake = @('TimeGenerated', 'CollectionTime', 'SI_AssetId', 'SI_AssetName', 'MdeDeviceId')
        $q = Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL' -SnapshotTime $script:T -Part 0 -Parts 2
        $bareNames = @([regex]::Matches((Bare $q), '(?<![A-Za-z0-9_"])([A-Z][A-Za-z0-9_]+)(?![A-Za-z0-9_"(])') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $aliases = @((Get-SICorrelationProjection) + @('EntityIds', 'AssetName', 'SnapshotTime', 'SI_Endpoint_Profile_CL'))
        foreach ($n in $bareNames) {
            (($fake -contains $n) -or ($aliases -contains $n)) | Should -BeTrue -Because ("'{0}' is named bare and is not a column of the fake table" -f $n)
        }
    }
}

Describe 'A read refused while the table is taking a new column' {
    It 'names the column only when the query does not name it bare (the service''s ["..."] form and the plain form)' {
        $q = Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL'
        Get-SICorrelationSettlingColumn -Message $script:Live -Query $q | Should -Be 'PrivilegedLogonEvidence'
        Get-SICorrelationSettlingColumn -Message "'project' operator: Failed to resolve scalar expression named 'PrivilegedLogonStatus'" -Query $q | Should -Be 'PrivilegedLogonStatus'
        # a column the query reads only through column_ifexists is not the query's own bare reference either
        Get-SICorrelationSettlingColumn -Message "Failed to resolve scalar expression named 'MdeDeviceId'" -Query 'T | project x = tostring(column_ifexists("MdeDeviceId", ""))' | Should -Be 'MdeDeviceId'
        # the query's own names: a fault of the query, never waited for
        Get-SICorrelationSettlingColumn -Message "'where' operator: Failed to resolve scalar expression named 'CollectionTime'" -Query $q | Should -Be ''
        Get-SICorrelationSettlingColumn -Message "Failed to resolve scalar expression named 'snap'" -Query $q | Should -Be ''
        # other failures
        Get-SICorrelationSettlingColumn -Message "'where' operator: Failed to resolve table or column expression named 'SI_Endpoint_Profile_CL'" -Query $q | Should -Be ''
        Get-SICorrelationSettlingColumn -Message 'Forbidden' -Query $q | Should -Be ''
        Get-SICorrelationSettlingColumn -Message '' -Query $q | Should -Be ''
    }
    It 'reads again until the service answers, says it once, and hands back the rows' {
        $script:Calls = 0; $script:Slept = New-Object System.Collections.Generic.List[int]
        $read = { param($Query) $script:Calls++; if ($script:Calls -le 2) { throw $script:Live }; @([pscustomobject]@{ SI_AssetId = 'a' }, [pscustomobject]@{ SI_AssetId = 'b' }) }
        $w = $null
        $rows = @(Invoke-SICorrelationSettledRead -Read $read -Query (Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL') -MaxWaitSeconds 600 -PollSeconds 30 -Sleep { param($s) $script:Slept.Add($s) } -WarningVariable w 3>$null)
        $rows.Count | Should -Be 2
        $script:Calls | Should -Be 3
        @($script:Slept) | Should -Be @(30, 30)
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match "still adding the new column 'PrivilegedLogonEvidence' to SI_Endpoint_Profile_CL"
    }
    It 'a fault of the query and every other failure: thrown unchanged at the first attempt, nothing waited' {
        $q = Get-SICorrelationSnapshotKql -TableName 'SI_Endpoint_Profile_CL'
        foreach ($m in @("'where' operator: Failed to resolve scalar expression named 'CollectionTime'", "Failed to resolve table or column expression named 'SI_Endpoint_Profile_CL'", 'Forbidden', '429 Too Many Requests')) {
            $script:Calls = 0; $script:Slept = 0
            $err = $null
            try { $null = Invoke-SICorrelationSettledRead -Read { param($Query) $script:Calls++; throw $m } -Query $q -MaxWaitSeconds 600 -Sleep { param($s) $script:Slept++ } 3>$null } catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Be $m
            $script:Calls | Should -Be 1 -Because $m
            $script:Slept | Should -Be 0 -Because $m
        }
    }
    It 'still refused at the end of the wait: thrown, saying what it is, and never read as a cut answer' {
        $err = $null
        try { $null = Invoke-SICorrelationSettledRead -Read { param($Query) throw $script:Live } -Query (Get-SICorrelationCountKql -TableName 'SI_Endpoint_Profile_CL') -MaxWaitSeconds 0 -Sleep { } 3>$null } catch { $err = $_ }
        $err.Exception.Message | Should -Match "has not finished adding the new column 'PrivilegedLogonEvidence' to SI_Endpoint_Profile_CL"
        $err.Exception.Message | Should -Match 'the next run reads the table again'
        Test-SICorrelationCutAnswer -Message $err.Exception.Message | Should -BeFalse -Because 'a cut answer is read again in two parts; this is not one'
    }
}

Describe 'WIRING -- every correlation read goes through the wait' {
    It 'Invoke-SICorrelationKql waits through the service''s refusal and answers the rows' {
        function Resolve-SICorrelationWorkspaceId { param($WorkspaceResourceId) 'ws' }
        $script:LaCalls = 0
        function Invoke-SIAzOperationalInsightsQuery { param($WorkspaceId, $Query, $Wait) $script:LaCalls++; if ($script:LaCalls -eq 1) { throw $script:Live }; [pscustomobject]@{ Results = @([pscustomobject]@{ Rows = 7; SnapshotTime = $script:T }) } }
        function Start-Sleep { param([int]$Seconds) }
        $r = @(Invoke-SICorrelationKql -WorkspaceResourceId '/x' -Query (Get-SICorrelationCountKql -TableName 'SI_Endpoint_Profile_CL') 3>$null)
        $script:LaCalls | Should -Be 2
        $r.Count | Should -Be 1
        $r[0].Rows | Should -Be 7
    }
    It 'the paged reader, the freshness wait and the whole-snapshot reader all read through Invoke-SICorrelationKql' {
        $paged = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationPaged.ps1'))
        ([regex]::Matches($paged, [regex]::Escape('{ param($Query) Invoke-SICorrelationKql -WorkspaceResourceId $WorkspaceResourceId -Query $Query }'))).Count | Should -Be 2
        $ingest = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationIngest.ps1'))
        $ingest | Should -Match ([regex]::Escape('$rows = Invoke-SICorrelationKql -WorkspaceResourceId $WorkspaceResourceId -Query $kql'))
        $ingest | Should -Match ([regex]::Escape('Invoke-SICorrelationSettledRead -Query $Query -Read { param($q) Invoke-SICorrelationKqlOnce'))
    }
}
