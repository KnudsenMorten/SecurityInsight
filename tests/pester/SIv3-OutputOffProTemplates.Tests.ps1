#Requires -Version 5.1
<#
    A COLUMN SHIPPED SWITCHED OFF STAYS OFF THROUGH THE PRO SETTINGS DATABASE (release blocker if not: every new ServiceNow
    column would be SENT at every Pro install with nothing switched on).

    Pro does not read data-model\outputs\*.locked.json at run time: the release's templates are stored in cfg.Template (one
    row per output column, Get-SITemplateRows -> Invoke-SITemplatePublish), read back (Read-SIProTemplates), merged with the
    customer's overrides (Merge-SIProItems), written to the run folder (Export-SIProConfig) and only THEN read as the output
    map (Get-SIDataModel, which leaves a column with "off": true out). What is proven here:
      * every column a map ships "off": true carries "off": true in its template row;
      * through the round trip -- in memory, and STORED IN AND READ BACK FROM A REAL SQL SERVER (the test runner's) -- every
        such column stays off, and every output's map (its columns and the rows it produces for the same items) EQUALS the
        file-based map (Community / the shipped files).
    The real-SQL part skips, saying so, without SI_TEST_LOCALSQL. PS 5.1 and 7.
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL) -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type])
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\pro-settings\SI-ProSettings.ps1')
    if (-not (Get-Command -Name Get-SITemplateRows -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\pro-settings\SI-ProConfig.ps1') }
    . (Join-Path $script:SIRoot 'engine\data-model\SI-OutputMapper.ps1')
    $script:Ctx = Get-SIProConfigContext -SIRoot $script:SIRoot
    $script:Rows = @((Get-SITemplateRows -SIRoot $script:SIRoot -Families @('datamodel')).Rows)
    # the shipped maps and their columns shipped off
    $script:OutDir = Join-Path $script:SIRoot 'data-model\outputs'
    $script:Shipped = [ordered]@{}
    foreach ($f in Get-ChildItem -LiteralPath $script:OutDir -Filter '*.locked.json' | Sort-Object Name) {
        $id = $f.Name -replace '\.locked\.json$', ''
        $script:Shipped[$id] = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($f.FullName))
    }
    $script:SoftCols = @(foreach ($id in $script:Shipped.Keys) { foreach ($c in @($script:Shipped[$id].columns)) { if ($c.PSObject.Properties['soft'] -and $c.soft -eq $true) { [pscustomobject]@{ Output = $id; Target = [string]$c.target } } } })
    $script:OffCols = @(foreach ($id in $script:Shipped.Keys) { foreach ($c in @($script:Shipped[$id].columns)) { if ($c.PSObject.Properties['off'] -and $c.off -eq $true) { [pscustomobject]@{ Output = $id; Target = [string]$c.target } } } })
    # the FILE-BASED model (the shipped files, no overlay)
    $script:FileModel = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model') -OverlayRoot (Join-Path $TestDrive 'no-overlay')

    function script:Get-ProModel([object[]]$Templates) {
        $m = Merge-SIProItems -Templates $Templates -Overrides @() -Context $script:Ctx
        $run = Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $x = Export-SIProConfig -Items @($m.Items | Where-Object { $_.Kind -ne 'naming' }) -Families $m.Families -RunFolder $run -Context $script:Ctx
        [pscustomobject]@{ Merge = $m; Model = (Get-SIDataModel -Root $x.DataModelRoot -OverlayRoot (Join-Path $TestDrive 'no-overlay')) }
    }
    # items carrying a value for every field any map reads (top level and extra.<field>), a few shapes
    function script:New-Items {
        $fields = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
        foreach ($id in $script:Shipped.Keys) { foreach ($c in @($script:Shipped[$id].columns)) { $f = [string]$c.from; if ($f -and -not $f.StartsWith('$')) { [void]$fields.Add($f) } } }
        $items = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 4; $i++) {
            $top = [ordered]@{ si_ci_id = "ci-$i"; si_finding_key = "CVE-2026-100$i"; item_key = "ci-$i|CVE-2026-100$i"; si_finding_state = @('open', 'resolved')[$i % 2]; si_severity = @('High', 'Low', 'Critical', 'Medium')[$i] }
            $extra = [ordered]@{}
            foreach ($f in $fields) {
                if ($f.StartsWith('extra.')) { $extra[$f.Substring(6)] = ('{0}-{1}' -f $f.Substring(6), $i) }
                elseif (-not $top.Contains($f) -and $f -notmatch '\.') { $top[$f] = ('{0}-{1}' -f $f, $i) }
            }
            $top['extra'] = [pscustomobject]$extra
            $items.Add([pscustomobject]$top)
        }
        , $items.ToArray()
    }
    $script:Items = New-Items
    function script:Get-RowsJson($model, [string]$id) {
        $map = $model.Outputs[$id]
        $at = [datetime]::new(2026, 11, 17, 8, 0, 0, [DateTimeKind]::Utc)
        try { $rows = @(Invoke-SIOutputMap -Map $map -Items $script:Items -ValueMaps $model['value-maps'].maps -Context @{ RunId = 'r1'; RunTime = $at }); ConvertTo-Json -InputObject $rows -Depth 20 -Compress }
        catch { 'THROWS: ' + $_.Exception.Message }
    }
    function script:Assert-SameAsFiles($proModel, [string]$how) {
        foreach ($id in $script:Shipped.Keys) {
            $fm = $script:FileModel.Outputs[$id]; $pm = $proModel.Outputs[$id]
            $pm | Should -Not -BeNullOrEmpty -Because "$id is in the $how model"
            @($pm.columns | ForEach-Object { [string]$_.target }) | Should -Be @($fm.columns | ForEach-Object { [string]$_.target }) -Because "$id columns ($how)"
            (ConvertTo-Json -InputObject @($pm.columns) -Depth 20 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject @($fm.columns) -Depth 20 -Compress) -Because "$id column bodies ($how)"
            (Get-RowsJson $proModel $id) | Should -BeExactly (Get-RowsJson $script:FileModel $id) -Because "$id rows ($how)"
        }
        foreach ($o in $script:OffCols) {
            @($proModel.Outputs[$o.Output].columns | ForEach-Object { [string]$_.target }) | Should -Not -Contain $o.Target -Because "$($o.Output) $($o.Target) is shipped off ($how)"
        }
    }
}

Describe 'the template rows carry "off": true' {
    It 'there are columns shipped off or on by default (the proof is not empty), ServiceNow among them' {
        # owner 2026-11-17: the new ServiceNow columns are ON BY DEFAULT ("soft": true) -- none may be shipped off any more
        ($script:OffCols.Count + $script:SoftCols.Count) | Should -BeGreaterThan 0
        @(@($script:OffCols) + @($script:SoftCols) | Where-Object { $_.Output -like 'servicenow-*' }).Count | Should -BeGreaterThan 0
    }
    It 'every column on by default has a template row whose body says "soft": true, and it IS in the map (file-based and Pro) -- sent' {
        foreach ($o in $script:SoftCols) {
            $key = Get-SIDataModelProItemKey -Name ('outputs/' + $o.Output) -ItemKey $o.Target
            $row = @($script:Rows | Where-Object { $_.ItemKey -eq $key })
            $row.Count | Should -Be 1 -Because "the template row of $key"
            (ConvertFrom-Json -InputObject ([string]$row[0].BodyJson)).soft | Should -BeTrue -Because "$key keeps its soft flag in the stored body"
            @($script:FileModel.Outputs[$o.Output].columns | ForEach-Object { [string]$_.target }) | Should -Contain $o.Target
        }
        @(Get-SIOutputSoftColumns -Map $script:FileModel.Outputs['servicenow-vulnerable-item']).Count | Should -Be @($script:SoftCols | Where-Object { $_.Output -eq 'servicenow-vulnerable-item' }).Count
    }
    It 'every column shipped off has a template row whose body says "off": true' {
        foreach ($o in $script:OffCols) {
            $key = Get-SIDataModelProItemKey -Name ('outputs/' + $o.Output) -ItemKey $o.Target
            $row = @($script:Rows | Where-Object { $_.ItemKey -eq $key })
            $row.Count | Should -Be 1 -Because "the template row of $key"
            $b = ConvertFrom-Json -InputObject ([string]$row[0].BodyJson)
            $b.off | Should -BeTrue -Because "$key keeps its off flag in the stored body"
        }
    }
    It 'the file-based map leaves them out (the reference)' {
        foreach ($o in $script:OffCols) { @($script:FileModel.Outputs[$o.Output].columns | ForEach-Object { [string]$_.target }) | Should -Not -Contain $o.Target }
    }
}

Describe 'the Pro round trip in memory: merge -> run folder -> output map = the files' {
    It 'every output''s columns and rows equal the file-based ones; every column shipped off stays off' {
        $x = Get-ProModel $script:Rows
        @($x.Merge.Refused | Where-Object { $_.Name -like 'datamodel/outputs/*' }) | Should -BeNullOrEmpty
        Assert-SameAsFiles $x.Model 'in memory'
    }
}

Describe 'STORED IN AND READ BACK FROM SQL SERVER: the same maps, the same rows' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_outoff_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open()
        try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "CREATE DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $sql = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-pro-settings.sql'))
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
        try { foreach ($b in ($sql -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() }) { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $b; [void]$c.ExecuteNonQuery() } }
        finally { $cn.Dispose() }
        $cs = $script:Cs
        $script:Store = [pscustomobject]@{
            Name = 'local'
            Invoke = { param([string]$s, $p, [string]$mode)
                $k = New-Object System.Data.SqlClient.SqlConnection $cs; $k.Open()
                try {
                    $cmd = $k.CreateCommand(); $cmd.CommandTimeout = 300; $cmd.CommandText = $s
                    if ($p) { foreach ($n in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $n, $(if ($null -eq $p[$n]) { [DBNull]::Value } else { $p[$n] })) } }
                    if ($mode -eq 'reader') {
                        $rd = $cmd.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                        try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $v = $rd.GetValue($i); $o[$rd.GetName($i)] = $(if ($v -is [DBNull]) { $null } else { $v }) }; $out.Add([pscustomobject]$o) } } finally { $rd.Close() }
                        , $out.ToArray()
                    } else { [void]$cmd.ExecuteNonQuery() }
                } finally { $k.Dispose() } }.GetNewClosure()
        }
        $null = Invoke-SITemplatePublish -Store $script:Store -Plan @(Get-SITemplatePublishPlan -Rows $script:Rows -Existing @()) -ChangedBy 'tester' -BatchSize 200
        $script:Back = @(Read-SIProTemplates -Store $script:Store | Where-Object { $_ })
    }
    AfterAll {
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
    }
    It 'every output template row is stored and read back; the off flag is in the stored body' {
        $outRows = @($script:Rows | Where-Object { $_.Kind -eq 'datamodel' -and [string]$_.ItemKey -like 'outputs/*' })
        @($script:Back | Where-Object { $_.Kind -eq 'datamodel' -and [string]$_.ItemKey -like 'outputs/*' }).Count | Should -Be $outRows.Count
        foreach ($o in $script:OffCols) {
            $key = Get-SIDataModelProItemKey -Name ('outputs/' + $o.Output) -ItemKey $o.Target
            $r = @($script:Back | Where-Object { $_.Kind -eq 'datamodel' -and $_.ItemKey -eq $key })
            $r.Count | Should -Be 1 -Because $key
            (ConvertFrom-Json -InputObject ([string]$r[0].BodyJson)).off | Should -BeTrue -Because "$key read back from SQL"
        }
    }
    It 'the run''s maps from the rows read back = the files: columns, bodies, rows; every column shipped off stays off' {
        $x = Get-ProModel @($script:Back | Where-Object { $_.Kind -eq 'datamodel' })
        @($x.Merge.Refused | Where-Object { $_.Name -like 'datamodel/*' }) | Should -BeNullOrEmpty -Because 'every stored row passes its hash check'
        Assert-SameAsFiles $x.Model 'SQL round trip'
    }
}
