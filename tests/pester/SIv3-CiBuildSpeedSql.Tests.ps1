#Requires -Version 7.0
<#
    THE CI BUILD MAKES THE SAME CIs AS BEFORE ITS SPEED-UP -- in the database (real SQL Server): the two real-SQL cases of
    SIv3-CiBuildSpeed.Tests.ps1, in their own file so the Linux runner runs them beside the rest (framework 12.1 rule 10). The
    set-up is the shared _SIv3CiBuildSpeedSetup.ps1. PowerShell 7.
#>

BeforeDiscovery {
    $script:IsPwsh = $PSVersionTable.PSVersion.Major -ge 7
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '_SIv3CiBuildSpeedSetup.ps1')
}

AfterAll { Restore-CiPerfSpeedGlobals }

Describe 'The CI build makes the same CIs as before its speed-up, in the database (real SQL Server)' -Skip:(-not $script:IsPwsh) {
    It 'the database holds the same CIs after the whole build, CI for CI (real SQL Server)' -Skip:(-not $script:HasSql) {
        $dbs = @()
        try {
            $digests = @{}
            foreach ($which in 'now', 'before') {
                $db = New-CiPerfDatabase -SIRoot $script:SIRoot -Prefix 'si_test_cispeed_'
                $dbs += $db
                $w = Write-CiPerfTenant -Scale 0.002 -Invoke $db.Seam -Model $script:Model -T $script:T
                $w.Failed | Should -Be 0
                $posted = New-Object System.Collections.Generic.List[object]
                $lc = & $db.NewEngineConn
                $bargs = @{ SqlInvoke = $db.Seam; LockOpen = $db.NewEngineConn; LedgerProvider = ([pscustomobject]@{ Kind = 'sql'; Connection = $lc }); Rules = $script:Rules; CmdbIndex = (New-SICiCmdbIndex)
                    Post = { param($Rows) foreach ($x in $Rows) { if ([string]$x.si_row_kind -eq 'full') { $posted.Add($x) } }; @($Rows).Count }.GetNewClosure(); LookbackDays = 30; WorkbookMaxCis = 0; RunId = 'speed'; BuildTime = $script:Now; Log = { param($l, $m) } }
                if ($which -eq 'now') { $r = Invoke-SICiBuild @bargs } else { $r = Invoke-BeforeSICiBuild @bargs }
                $r.Failed | Should -BeFalse -Because ([string]$r.Reason)
                $d = Get-CiPerfCiDigest -Invoke $db.Seam -Epoch $script:T -Volatile @('si_collection_time', 'si_run_id', 'si_ci_built', 'si_last_build', 'si_lifecycle_since', 'si_lifecycle_reason', 'si_not_seen_days')
                $rows = @(foreach ($p in ($posted | Sort-Object { [string]$_.si_ci_id })) { Canon $p })
                $digests[$which] = @{ Cis = $d; Posted = $rows; Count = $r.CiCount }
            }
            $digests['now'].Count | Should -Be $digests['before'].Count
            $cmp = Compare-CiPerfDigest -Before $digests['before'].Cis -After $digests['now'].Cis
            Write-Host ('    {0:N0} CIs compared in the database: {1} different, {2} only before, {3} only now' -f $cmp.Cis, $cmp.Different, $cmp.OnlyBefore, $cmp.OnlyAfter)
            foreach ($x in $cmp.Examples) { Write-Host ('    {0}: before {1} / now {2}' -f $x.CiId, $x.Before, $x.After) }
            $cmp.Same | Should -BeTrue
            ($digests['now'].Posted -join "`n") | Should -BeExactly ($digests['before'].Posted -join "`n")
        } finally { foreach ($db in $dbs) { Remove-CiPerfDatabase -Db $db } }
    }

    It 'the correlation job''s ledger write lands the same rows in one statement (real SQL Server)' -Skip:(-not $script:HasSql) {
        $groups = Groups
        $idy = Resolve-SIObjectIdentity -Groups $groups -Ledger @{} -Now $script:Now
        # a duplicate anchor (the last id written wins) and supersessions (the first new id written wins)
        $dec = @($idy.Decisions) + @([pscustomobject]@{ CorrelationId = 'dup'; NewIdentifiers = @([pscustomobject]@{ Type = 'AadObjectId'; Value = 'dup-1'; CorrelationId = 'first' }, [pscustomobject]@{ Type = 'AadObjectId'; Value = 'dup-1'; CorrelationId = 'second' }) })
        $sup = @([pscustomobject]@{ OldId = 'old-1'; NewId = 'new-a' }, [pscustomobject]@{ OldId = 'old-1'; NewId = 'new-b' }, [pscustomobject]@{ OldId = 'old-2'; NewId = 'new-c' })
        $dbs = @(); $content = @{}; $counts = @{}
        try {
            foreach ($which in 'now', 'before') {
                $db = New-CiPerfDatabase -SIRoot $script:SIRoot -Prefix 'si_test_cispeed_'
                $dbs += $db
                $cn = & $db.NewEngineConn
                if ($which -eq 'now') { $w = Save-SIObjectLedger -Connection $cn -Decisions $dec -Superseded $sup -Now $script:Now }
                else { $w = Save-BeforeSIObjectLedger -Connection $cn -Decisions $dec -Superseded $sup -Now $script:Now }
                $counts[$which] = '{0}/{1}' -f $w.AnchorsWritten, $w.SupersededWritten
                $rows = @(& $db.Seam 'SELECT IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen, LastSeen FROM si.ObjectIdentity ORDER BY IdentifierType, IdentifierValue' @{} 'rows')
                $s = @(& $db.Seam 'SELECT OldId, NewId, SupersededAt, Reason FROM si.ObjectIdentitySuperseded ORDER BY OldId' @{} 'rows')
                $content[$which] = (@($rows | ForEach-Object { '{0}|{1}|{2}|{3:o}|{4:o}' -f $_.IdentifierType, $_.IdentifierValue, $_.SI_CorrelationId, $_.FirstSeen, $_.LastSeen }) + @($s | ForEach-Object { 'SUP {0}|{1}|{2:o}|{3}' -f $_.OldId, $_.NewId, $_.SupersededAt, $_.Reason })) -join "`n"
            }
            $counts['now'] | Should -Be $counts['before']
            $content['now'] | Should -BeExactly $content['before']
            $content['now'] | Should -Match 'aadobjectid\|dup-1\|second|AadObjectId\|dup-1\|second'
            $content['now'] | Should -Match 'SUP old-1\|new-a'
        } finally { foreach ($db in $dbs) { Remove-CiPerfDatabase -Db $db } }
    }
}
