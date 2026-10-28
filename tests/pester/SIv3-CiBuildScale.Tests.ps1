#Requires -Version 5.1
<#
    #639 THE CI BUILD AT MILLIONS OF ASSETS (engine/data-model/SI-CiBuildRun.ps1 + SI-CiBuildSql.ps1, sidata.CiBuildStage).
    Owner 2026-10-21: "memory issues must not be a problem in any step. env must work in millions of assets env".

      * THE SAME CIs: a build with the stage (the CMDB staged a page at a time and looked up per batch, the CMDB key hashes
        staged in chunks and compared in SQL, the identity CIs looked up per batch, the unchanged CIs' seen rows read and
        posted a page at a time) writes and posts EXACTLY what the whole-set build of before does -- a full and an
        incremental build, CMDB values and identity links included (the whole-set path runs on a database without the stage).
      * MEMORY: the seen rows are held one page at a time (SeenHeldMax <= the page), the CMDB one page + one chunk, the stage
        writer one chunk; the CI workbook reads every CI of the build back a page at a time -- no 50,000 limit.
      * NO GREEN FAILURE: a CMDB that cannot be read is a build issue and its keys are neither compared nor saved (an empty
        CMDB would strip every CI's CMDB values); relations not updated are a build issue.
    The real-SQL tests run against the local SQL Server Express of the test VM and skip, saying so, where there is none.
#>

BeforeDiscovery {
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
    # the real-SQL block builds its database from the Pro schemas: Test-Path first -- a Community copy skips that block
    $discRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:HasProSchema = (Test-Path -LiteralPath (Join-Path $discRoot 'sql\si-data-schema.sql')) -and (Test-Path -LiteralPath (Join-Path $discRoot 'sql\si-identity-schema.sql'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . (Join-Path $script:SIRoot 'engine\data-out\SI-DataOut.ps1')
    $script:T = [datetime]::SpecifyKind([datetime]'2026-10-21T03:00:00', [DateTimeKind]::Utc)
    $script:SnRec = [pscustomobject]@{ si_cmdb_id = 'CI0012'; si_cmdb_name = 'Payroll VM'; si_cmdb_criticality = 'high'; azure_resource_id = @('/subscriptions/s/vm1', '/subscriptions/s/VM2'); entra_object_id = 'E-1'; si_fqdn = 'payroll.corp'; unrelated = 'x' }
}

Describe 'The owning CMDB staged and looked up per batch' {
    It 'a staged item carries the hash the whole index gave its key, and the batch index finds what the whole index finds' {
        $rows = @(ConvertTo-SICiCmdbStageItem -Item $script:SnRec -Kind record)
        @($rows | ForEach-Object { $_.K }) | Should -Be @('svc|ci0012', 'arm|/subscriptions/s/vm1', 'arm|/subscriptions/s/vm2', 'entra|e-1', 'fqdn|payroll.corp')
        foreach ($r in $rows) { $r.H | Should -Be (Get-SICiCmdbItemHash -Item $script:SnRec) }
        $whole = New-SICiCmdbIndexFromRecords -Records @($script:SnRec)
        $batch = ConvertTo-SICiCmdbBatchIndex -Rows @($rows | ForEach-Object { [pscustomobject]@{ K = $_.K; V = $_.V } }) -Total 99
        $batch.Count | Should -Be 99
        foreach ($ci0 in @(@{ si_link_azure = '/subscriptions/s/VM1' }, @{ si_link_entra = 'e-1' }, @{ si_fqdn = 'PAYROLL.corp' }, @{ si_cmdb_id = 'ci0012' })) {
            $a = [ordered]@{ si_ci_id = 'c' }; $b = [ordered]@{ si_ci_id = 'c' }
            foreach ($k in $ci0.Keys) { $a[$k] = $ci0[$k]; $b[$k] = $ci0[$k] }
            $null = Set-SICiCmdb -Ci $a -Index $whole -CmdbOwner 'servicenow'
            $null = Set-SICiCmdb -Ci $b -Index $batch -CmdbOwner 'servicenow'
            ($b | ConvertTo-Json -Compress) | Should -Be ($a | ConvertTo-Json -Compress)
            $b['si_cmdb_name'] | Should -Be 'Payroll VM'
        }
        # the CMDB key hashes of the staged items are the whole index's (an unchanged CMDB dirties nothing after the change)
        $wk = @{}; foreach ($x in (Get-SICiCmdbKeyHashes -Index $whole)) { $wk[$x.k] = $x.h }
        foreach ($r in $rows) { $wk[$r.K] | Should -Be $r.H }
    }
    It 'a batch looks up the keys its CIs carry and the ids the rules and overrides can set' {
        $keys = Get-SICiCmdbLookupKeys -Docs @([ordered]@{ si_cmdb_id = 'X1'; si_link_azure = '/A'; si_link_entra = 'E'; si_fqdn = 'h.corp' }) -ExtraIds @('RULE-1')
        @($keys) | Sort-Object | Should -Be @('arm|/a', 'entra|e', 'fqdn|h.corp', 'svc|rule-1', 'svc|x1')
        $ov = ConvertTo-SICiOverrideIndex -Rows @([pscustomobject]@{ CiId = 'c1'; Field = 'si_cmdb_id'; Value = 'OV-9' })
        $ids = Get-SICiRuleCmdbIds -Rules @([pscustomobject]@{ set = [ordered]@{ si_cmdb_id = 'R-1' } }, [pscustomobject]@{ set = [ordered]@{ si_tier = 1 } }) -Overrides $ov
        @($ids) | Sort-Object | Should -Be @('OV-9', 'R-1')
    }
    It 'the stage writer holds one chunk, writes a key once (the last item wins) and writes the rest on flush' {
        $script:Stmts = New-Object System.Collections.Generic.List[object]
        $w = New-SICiStageWriter -Sql { param($Sql, $Params, $Mode) $script:Stmts.Add(@(ConvertFrom-Json $Params.j)) } -Kind 'ck' -ChunkBytes 200
        for ($i = 0; $i -lt 40; $i++) { $w.Add(('k{0}' -f ($i % 30)), ('h{0}' -f $i), $null) }
        $w.Flush()
        $all = @($script:Stmts | ForEach-Object { $_ })
        $script:Stmts.Count | Should -BeGreaterOrEqual 3
        $w.MaxHeld | Should -BeLessThan 30 -Because 'a chunk is written when it reaches its size'
        ($all | Where-Object { $_.k -eq 'k5' } | Select-Object -Last 1).h | Should -Be 'h35' -Because 'the last item of a key wins'
        @($all | ForEach-Object { $_.k } | Select-Object -Unique).Count | Should -Be 30
    }
    It 'a CMDB that cannot be read is NOT an empty one: Ok false with the reason (the build makes it an issue)' {
        $w = New-SICiStageWriter -Sql { param($Sql, $Params, $Mode) } -Kind 'ck'
        $r = Import-SICiCmdbStage -Sql { param($Sql, $Params, $Mode) throw 'Timeout expired' } -Writer $w -Owner 'servicenow' -Log { param($l, $m) }
        $r.Ok | Should -BeFalse
        $r.Why | Should -Match 'Timeout expired'
    }
    It 'the owning CMDB records are read a page at a time (keyset on the record key)' {
        $script:Pages = 0
        $recs = @(for ($i = 0; $i -lt 7; $i++) { [pscustomobject]@{ RecordKey = ('servicenow|cmdb_ci|{0:D2}' -f $i); DocJson = (ConvertTo-Json -Compress -InputObject ([ordered]@{ si_cmdb_id = "C$i"; si_fqdn = "h$i.corp" })) } })
        $w = New-SICiStageWriter -Sql { param($Sql, $Params, $Mode) } -Kind 'ck'
        $r = Import-SICiCmdbStage -Sql { param($Sql, $Params, $Mode) $script:Pages++; @($recs | Where-Object { [string]::CompareOrdinal($_.RecordKey, [string]$Params.after) -gt 0 } | Select-Object -First ([int]$Params.n)) } -Writer $w -Owner 'servicenow' -PageSize 3 -Log { param($l, $m) }
        $r.Ok | Should -BeTrue
        $r.Items | Should -Be 7
        $r.Keys | Should -Be 14
        $script:Pages | Should -Be 3
    }
}

Describe 'The statements' {
    It 'the dirty statement compares the staged CMDB keys in SQL; without the stage it reads @ck as before' {
        $s = Get-SICiDirtySql -CmdbStaged
        $s | Should -Match ([regex]::Escape("FROM (SELECT K, H FROM sidata.CiBuildStage WHERE Kind = N'ck') c FULL OUTER JOIN sidata.CiCmdbKey s"))
        $s | Should -Not -Match 'OPENJSON\(@ck\)'
        Get-SICiDirtySql | Should -Match 'OPENJSON\(@ck\)'
        Get-SICiCmdbKeySaveSql -FromStage | Should -Match "FROM sidata\.CiBuildStage c WHERE c\.Kind = N'ck'"
        Get-SICiCmdbKeySaveSql -FromStage | Should -Not -Match '@ck'
    }
    It 'the unchanged CIs are staged and read a page at a time; the seen statement with -Stage answers only its summary' {
        $s = Get-SICiSeenSql -Stage
        $s | Should -Match "INSERT sidata\.CiBuildStage \(Kind, K\)"
        $s | Should -Match "SELECT N'summary' AS Kind, @touched AS Touched, @daily AS Daily"
        $s | Should -Not -Match "SELECT N'seen', t\.CiId" -Because 'never every clean CI in one answer'
        Get-SICiSeenPageSql | Should -Match 'TOP \(CONVERT\(INT, @n\)\).*\s+FROM sidata\.CiBuildStage s JOIN sidata\.Ci t'
        Get-SICiSeenPageSql | Should -Match 'ORDER BY s\.K'
    }
    It 'the build keeps no CI for the workbook and no CI for Risk Analysis (only the -ReturnCis test seam does)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $t | Should -Not -Match '\$wbDocs'
        $t | Should -Match 'Write-SICiWorkbook -Sql \$sql -Now \$now'
        $t | Should -Match "New-SIDataOutItemCursor -Grain 'ci' -PageSize \`$st\.PageSize -Source"
    }
    It 'every parameter the engine hands the data-out writer is one the writer has (live 2026-10-22: -ReadPages, never written)' {
        # the build's call passed -ReadPages after the writer had moved to -Cursor: every run "the CI workbook was not
        # written". A wiring test that matched the call's TEXT stayed green -- here every call is checked against the writer.
        $root = Join-Path $script:SIRoot 'engine'
        $wAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'data-out\SI-DataOut.ps1'), [ref]$null, [ref]$null)
        $wFn = $wAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-SIDataOutWriter' }, $true)
        $have = @($wFn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) + @('WhatIf', 'Verbose', 'ErrorAction')
        $calls = 0
        foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1') {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-SIDataOutWriter' }, $true)) {
                $calls++
                foreach ($p in @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] })) {
                    $have -contains $p.ParameterName | Should -BeTrue -Because ('{0}:{1} passes -{2} to Invoke-SIDataOutWriter' -f $f.Name, $c.Extent.StartLineNumber, $p.ParameterName)
                }
            }
        }
        $calls | Should -BeGreaterOrEqual 2
        # the CI build's writer call is splatted: its keys are the writer's too
        $bAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'data-model\SI-CiBuildRun.ps1'), [ref]$null, [ref]$null)
        $wa = $bAst.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$wa' }, $true)
        $keys = @($wa.Right.Expression.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text }) + @('OutputDir', 'Edition')
        $keys | Should -Contain 'Cursor'
        foreach ($k in $keys) { $have -contains $k | Should -BeTrue -Because "Write-SICiWorkbook hands -$k to the writer" }
        # and the writer refuses what the live call passed (so this test catches it)
        $have | Should -Not -Contain 'ReadPages'
    }
}

Describe 'The staged build equals the whole-set build (real SQL Server)' -Skip:(-not ($script:HasSql -and $script:HasProSchema)) {
    BeforeAll {
        function script:New-Db([switch]$NoStage) {
            $name = 'si_test_ciscale_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "CREATE DATABASE [$name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $a = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30"); $a.Open()
            foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $a.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
            # a database from before the stage: the build keeps the whole-set path of before
            if ($NoStage) { $c = $a.CreateCommand(); $c.CommandText = 'DROP TABLE sidata.CiBuildStage'; [void]$c.ExecuteNonQuery() }
            $c = $a.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
            $script:Conns[$name] = EngineConn $a.ConnectionString
            $db = [pscustomobject]@{ Name = $name; Admin = $a; ConnStr = $a.ConnectionString }
            # (built from text, not a closure: it finds Invoke-TestSeam and the production reader where it is called)
            $db | Add-Member -MemberType ScriptMethod -Name Seam -Value { [scriptblock]::Create(("param(`$Sql, `$Params, `$Mode) Invoke-TestSeam -Name '{0}' -Sql `$Sql -Params `$Params -Mode `$Mode" -f $this.Name)) }
            $db
        }
        function script:EngineConn([string]$ConnStr) {
            # NOT pooled: a connection closed while impersonating goes back to the pool unreverted
            $e = New-Object System.Data.SqlClient.SqlConnection ($ConnStr + ';Pooling=false'); $e.Open()
            $c = $e.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
            $e
        }
        function script:Invoke-TestSeam([string]$Name, $Sql, $Params, $Mode) {
            $c = $script:Conns[$Name].CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            $c.ExecuteNonQuery()
        }
        $script:Conns = @{}
        function script:Drop-Db($Db) {
            foreach ($x in $script:Conns[$Db.Name], $Db.Admin) { try { $x.Dispose() } catch { } }
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($Db.Name)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($Db.Name)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        }
        function script:Rec([string]$p, [string]$rt, [string]$cls, [string]$key, [hashtable]$f, [datetime]$coll) {
            $o = [ordered]@{ si_provider = $p; si_record_type = $rt; si_class = $cls; si_record_key = "${p}|${rt}|$key"; si_collection_time = $coll; si_source_last_seen = $coll.AddHours(-1); si_collection_complete = $true }
            foreach ($k in $f.Keys) { $o[$k] = $f[$k] }
            [pscustomobject]$o
        }
        # devices (Defender + Entra device + every 5th an Azure VM), their users (each device names its user as owner),
        # and the owning external CMDB's records (every 4th VM, by its Azure resource id; every 7th device by its name)
        function script:Estate([int]$N, [datetime]$Coll, [int]$Bump = -1) {
            $r = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt $N; $i++) {
                $j = "z$i"
                $os = 'windows'; if ($i -eq $Bump) { $os = 'linux' }
                $r.Add((Rec mde device device "m$j" @{ mde_device_id = "m$j"; entra_device_id = "a$j"; si_hostname = "host$j"; si_fqdn = "host$j.corp"; si_os_platform = $os; si_owner = "u$j" } $Coll))
                $r.Add((Rec entra device device "a$j" @{ entra_device_id = "a$j"; si_hostname = "host$j" } $Coll))
                $r.Add((Rec entra user identity "u$j" @{ entra_object_id = "u$j"; si_upn = "user$j@corp"; si_asset_name = "user$j" } $Coll))
                if ($i % 5 -eq 0) { $r.Add((Rec azure azure_resource cloud_resource "vm$j" @{ azure_resource_id = "/subscriptions/s/vm$j"; azure_vm_id = "vmid$j" } $Coll)) }
                if ($i % 20 -eq 0) { $r.Add((Rec servicenow cmdb_ci device "sn$j" @{ si_cmdb_id = "SN-$j"; si_cmdb_name = "App $j"; si_cmdb_criticality = 'high'; azure_resource_id = "/subscriptions/s/vm$j" } $Coll)) }
                if ($i % 7 -eq 0) { $r.Add((Rec servicenow cmdb_ci device "snf$j" @{ si_cmdb_id = "SNF-$j"; si_cmdb_name = "Host $j"; si_fqdn = "host$j.corp" } $Coll)) }
            }
            $r.ToArray()
        }
        function script:Write-Recs($Db, $Records, [datetime]$Now) {
            $all = @($Records); $seam = $Db.Seam()
            for ($i = 0; $i -lt $all.Count; $i += 500) { $w = Write-SIRecordsToSql -Rows @($all[$i..([Math]::Min($i + 500, $all.Count) - 1)]) -Invoke $seam -Now $Now; if ($w.Failed) { throw "records could not be written ($($w.Failed))" } }
        }
        function script:Build($Db, [datetime]$At) {
            $posted = New-Object System.Collections.Generic.List[object]
            # the ledger on a connection of its own (the build closes it at its end)
            $r = Invoke-SICiBuild -SqlInvoke ($Db.Seam()) -LedgerProvider ([pscustomobject]@{ Kind = 'sql'; Connection = (EngineConn $Db.ConnStr) }) -Rules @() -BuildTime $At `
                -Post { param($Rows) foreach ($x in $Rows) { $posted.Add($x) }; @($Rows).Count }.GetNewClosure() -BatchCis 40 -PageRows 25 -LookbackDays 30 -WorkbookMaxCis 0 -RunId 'scale' -Log { param($l, $m) }
            [pscustomobject]@{ Result = $r; Posted = $posted.ToArray() }
        }
        function script:RowText($Rows) {
            $t = @(foreach ($x in $Rows) { $o = [ordered]@{}; foreach ($n in ([string[]]@($x.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object)) { if ($n -ne 'si_collection_time') { $o[$n] = $x.$n } }; ConvertTo-Json -InputObject $o -Compress -Depth 8 })
            [string[]]$a = $t; [Array]::Sort($a, [StringComparer]::Ordinal); $a
        }
        function script:CiText($Db) {
            $t = @(& ($Db.Seam()) 'SELECT CiId, DocJson, Lifecycle FROM sidata.Ci ORDER BY CiId' @{} 'rows' | ForEach-Object { '{0}|{1}|{2}' -f $_.CiId, $_.Lifecycle, $_.DocJson })
            [string[]]$a = $t; [Array]::Sort($a, [StringComparer]::Ordinal); $a
        }
        $script:SavedOwner = $global:SIWeb_CmdbSource
        $global:SIWeb_CmdbSource = 'servicenow'
        $script:A = New-Db; $script:B = New-Db -NoStage
        foreach ($db in $script:A, $script:B) { Write-Recs $db (Estate 120 $script:T) $script:T }
        $script:A1 = Build $script:A $script:T; $script:B1 = Build $script:B $script:T
        # a second build: one device changed -- incremental, every other CI only seen (a page at a time on A)
        $t2 = $script:T.AddHours(1)
        foreach ($db in $script:A, $script:B) { Write-Recs $db (Estate 120 $t2 7) $t2 }
        $script:A2 = Build $script:A $t2; $script:B2 = Build $script:B $t2
    }
    AfterAll {
        $global:SIWeb_CmdbSource = $script:SavedOwner
        foreach ($db in $script:A, $script:B) { if ($db) { Drop-Db $db } }
    }
    It 'the stage is used on the updated database and the whole-set path (said) on the other' {
        $script:A1.Result.Failed | Should -BeFalse -Because ([string]$script:A1.Result.Reason)
        $script:B1.Result.Failed | Should -BeFalse -Because ([string]$script:B1.Result.Reason)
        $script:A1.Result.Staged | Should -BeTrue
        $script:B1.Result.Staged | Should -BeFalse
        @($script:B1.Result.Issues | Where-Object { $_.Text -match 'sidata\.CiBuildStage is missing' }).Count | Should -Be 1
        @($script:A1.Result.Issues).Count | Should -Be 0
    }
    It 'a full build: the same CIs in SQL and the same rows posted to SI_CI_CL -- CMDB values and identity links included' {
        (CiText $script:A) | Should -Be (CiText $script:B)
        (RowText $script:A1.Posted) | Should -Be (RowText $script:B1.Posted)
        $docs = @(& ($script:A.Seam()) 'SELECT DocJson FROM sidata.Ci' @{} 'rows' | ForEach-Object { ConvertFrom-Json $_.DocJson })
        @($docs | Where-Object { $_.si_cmdb_name }).Count | Should -BeGreaterThan 0 -Because 'the owning CMDB was looked up per batch and found'
        @($docs | Where-Object { $_.si_owner_ci_id }).Count | Should -BeGreaterThan 0 -Because 'the identity CIs were looked up per batch and linked'
    }
    It 'an incremental build: the same result, the unchanged CIs seen a page at a time (one page held)' {
        $script:A2.Result.BuildMode | Should -Be 'incremental'
        (CiText $script:A) | Should -Be (CiText $script:B)
        (RowText $script:A2.Posted) | Should -Be (RowText $script:B2.Posted)
        $script:A2.Result.SkippedCis | Should -BeGreaterThan 50
        $script:A2.Result.SkippedCis | Should -Be $script:B2.Result.SkippedCis
        $script:A2.Result.SeenPages | Should -BeGreaterThan 1
        $script:A2.Result.SeenHeldMax | Should -BeLessOrEqual 25
    }
    It 'the CMDB keys this build saw are saved from the stage (the next build compares with them)' {
        $a = @(& ($script:A.Seam()) 'SELECT RefKey, Hash FROM sidata.CiCmdbKey ORDER BY RefKey' @{} 'rows' | ForEach-Object { '{0}={1}' -f $_.RefKey, $_.Hash })
        $b = @(& ($script:B.Seam()) 'SELECT RefKey, Hash FROM sidata.CiCmdbKey ORDER BY RefKey' @{} 'rows' | ForEach-Object { '{0}={1}' -f $_.RefKey, $_.Hash })
        $a.Count | Should -BeGreaterThan 0
        $a | Should -Be $b
    }
    It 'the CI workbook reads every CI of the build back a page at a time -- no limit' {
        $script:WbPages = New-Object System.Collections.Generic.List[int]
        $cur = New-SICiWorkbookCursor -Sql ($script:A.Seam()) -Now $script:T.AddHours(1) -PageSize 30
        while ($null -ne ($pg = Get-SIDataOutNextPage -Cursor $cur)) { $script:WbPages.Add(@($pg.Items).Count + @($pg.Frozen).Count) }
        $n = $cur.Rows
        $want = @(& ($script:A.Seam()) 'SELECT COUNT(*) AS N FROM sidata.Ci WHERE DocJson IS NOT NULL AND CollectionTime = CONVERT(DATETIME2(3), @t, 127)' @{ t = $script:T.AddHours(1).ToString('o') } 'rows')[0].N
        $n | Should -Be $want
        $want | Should -BeGreaterThan 60
        $script:WbPages.Count | Should -BeGreaterThan 1
        ($script:WbPages | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 30
    }
}
