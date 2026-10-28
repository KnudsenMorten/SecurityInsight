#Requires -Version 5.1
<#
    SecurityInsight -- #865 (owner 2026-10-21: "turn off test mode, my mistake" / "for the sql it should be on always"):
    SI'S OWN SQL CLOSE-LOOP TARGET IS ALWAYS ON.

    The connector of kind sql, direction vulnerability (`vulnerability-sql`) is SecurityInsight's own record of every
    vulnerability's lifecycle -- the source of Changes & trends > Vulnerabilities over time and Vulnerabilities per
    collection. The import created it with Mode 'whatif', AllowCreate 0, AllowClose 0, so it recorded nothing and both pages
    stayed empty. New installs / the import now create it apply + create + close (Get-SIConnectorImportPlan); the web app
    saves it so (ConnectorRepository.AlwaysOn).

    EXISTING INSTALLS reach that state through the update (Invoke-SIContainerUpdate.ps1 step 9k), on EVERY update -- the
    rule is "always on", not a one-time default, so there is no marker:
      * every cfg.Connector row of kind sql + direction vulnerability that is not apply / create / close is set to
        Mode 'apply', AllowCreate 1, AllowClose 1 -- ONE transaction per connector with its cfg.ChangeLog row
        (Name 'connector/<name>', Scope 'connector', Kind 'connector'; the Connectors page's history shows it), only while
        the row is still off (a row a person changed meanwhile is left);
      * READ BACK afterwards: a row that did not reach apply / create / close is said, as a warning;
      * a connector to a CUSTOMER system (servicenow, rest) and the SQL CMDB hand-off (sql + cmdb) are never touched --
        the statements name kind 'sql' AND direction 'vulnerability';
      * Enabled is left as it is (switching a connector on or off stays the customer's); a switched-off one is said.
    Pro only (the Pro database). Never throws (Invoke-SIOwnSqlConnectorOn); -WhatIf (-DetectOnly) plans only.
    PURE planning (Get-SIOwnSqlConnectorPlan) over a SQL seam.
#>

$script:SIOwnSqlConnector = @{
    By     = 'SecurityInsight update'
    Reason = 'SecurityInsight''s own SQL vulnerability target is always on (apply, create and close): in test mode it records nothing and Changes & trends stays empty (owner decision 2026-10-21)'
}

function Test-SIOwnSqlConnectorOn {
    <# PURE. Is the row on: Mode apply, AllowCreate and AllowClose set (bit, int, bool or text). #>
    param([Parameter(Mandatory)]$Row)
    $g = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $bit = { param($v) if ($v -is [bool]) { $v } else { [string]$v -match '^(?i)(1|true)$' } }
    ([string](& $g $Row 'Mode')).Trim().ToLowerInvariant() -eq 'apply' -and (& $bit (& $g $Row 'AllowCreate')) -and (& $bit (& $g $Row 'AllowClose'))
}

function Get-SIOwnSqlConnectorPlan {
    <#
        PURE. -Rows: the cfg.Connector rows (Name, Kind, Direction, Enabled, Mode, AllowCreate, AllowClose). Only kind sql +
        direction vulnerability are looked at. Returns @{ Change = @(names); Same = @(names); Off = @(switched-off names); Lines }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $g = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $change = New-Object System.Collections.Generic.List[string]; $same = New-Object System.Collections.Generic.List[string]
    $off = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $kind = ([string](& $g $r 'Kind')).Trim().ToLowerInvariant(); $dir = ([string](& $g $r 'Direction')).Trim().ToLowerInvariant()
        if (-not $dir) { $dir = 'vulnerability' }
        if ($kind -ne 'sql' -or $dir -ne 'vulnerability') { continue }
        $name = [string](& $g $r 'Name')
        if (Test-SIOwnSqlConnectorOn -Row $r) { $same.Add($name) } else { $change.Add($name) }
        if (-not ([string](& $g $r 'Enabled') -match '^(?i)(1|true)$')) { $off.Add($name) }
    }
    foreach ($n in $change) {
        $lines.Add(("connectors: SecurityInsight's own SQL vulnerability target '{0}' was in test mode (or could not create / close) -- now apply, create and close, so it records every vulnerability's lifecycle (Changes & trends > Vulnerabilities over time / per collection)" -f $n))
    }
    foreach ($n in $off) {
        $lines.Add(("connectors: SecurityInsight's own SQL vulnerability target '{0}' is switched off -- Changes & trends > Vulnerabilities over time stays empty until it is switched on (Connectors)" -f $n))
    }
    [pscustomobject]@{ Change = $change.ToArray(); Same = $same.ToArray(); Off = $off.ToArray(); Lines = $lines.ToArray() }
}

function Get-SIOwnSqlConnectorSql {
    <#
        The Pro database's statements. 'Read': the connectors (none when the table does not exist). 'Apply' (-Name): ONE
        transaction -- the row set to apply / create / close with its cfg.ChangeLog row, only while it is still off and still
        sql + vulnerability; returns Outcome 'changed' | 'same'. Returns @{ Sql; Params }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Statement, [string]$Name, [string]$By = $script:SIOwnSqlConnector.By)
    if ($Statement -eq 'Read') {
        return [pscustomobject]@{ Params = @{}; Sql = @'
IF OBJECT_ID(N'cfg.Connector') IS NOT NULL
SELECT Name, Kind, Direction, CONVERT(int, Enabled) AS Enabled, Mode, CONVERT(int, AllowCreate) AS AllowCreate, CONVERT(int, AllowClose) AS AllowClose
FROM cfg.Connector ORDER BY Name;
'@ }
    }
    [pscustomobject]@{ Params = [ordered]@{ Name = $Name; By = $By; Reason = $script:SIOwnSqlConnector.Reason }; Sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT c.Name, c.Kind, c.Direction, c.Enabled, c.Mode, c.AllowCreate, c.AllowClose, c.SettingsJson, c.SecretRefsJson, c.MappingJson
    FROM cfg.Connector c WITH (UPDLOCK, HOLDLOCK)
    WHERE c.Name = @Name AND LOWER(c.Kind) = N'sql' AND LOWER(c.Direction) = N'vulnerability' AND (c.Mode <> N'apply' OR c.AllowCreate = 0 OR c.AllowClose = 0)
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
IF @old IS NULL
BEGIN
    COMMIT;
    SELECT N'same' AS Outcome;
    RETURN;
END;
UPDATE cfg.Connector SET Mode = N'apply', AllowCreate = 1, AllowClose = 1, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE Name = @Name AND LOWER(Kind) = N'sql' AND LOWER(Direction) = N'vulnerability';
DECLARE @new nvarchar(max) = (SELECT c.Name, c.Kind, c.Direction, c.Enabled, c.Mode, c.AllowCreate, c.AllowClose, c.SettingsJson, c.SecretRefsJson, c.MappingJson
    FROM cfg.Connector c WHERE c.Name = @Name FOR JSON PATH, WITHOUT_ARRAY_WRAPPER);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (N'connector/' + @Name, N'connector', N'connector', N'Set', @old, @new, @By, @Reason);
COMMIT;
SELECT N'changed' AS Outcome;
'@ }
}

function Invoke-SIOwnSqlConnectorOn {
    <#
        The Pro database's part. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows). Never throws.
        Returns @{ Action = same | changed | plan | failed | none; Changed = @(names); Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    $norm = { param($x) @($x | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
    try {
        $q = Get-SIOwnSqlConnectorSql -Statement Read
        $rows = & $norm (& $Sql $q.Sql $q.Params 'reader')
        $plan = Get-SIOwnSqlConnectorPlan -Rows $rows
        if (-not @($plan.Change).Count -and -not @($plan.Same).Count) { return [pscustomobject]@{ Action = 'none'; Changed = @(); Lines = @() } }
        if (-not @($plan.Change).Count) { return [pscustomobject]@{ Action = 'same'; Changed = @(); Lines = @($plan.Lines) } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Changed = @(); Lines = @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) } }
        $done = New-Object System.Collections.Generic.List[string]
        foreach ($n in @($plan.Change)) {
            $a = Get-SIOwnSqlConnectorSql -Statement Apply -Name $n
            $o = & $norm (& $Sql $a.Sql $a.Params 'reader')
            if (@($o | Where-Object { [string]$_.Outcome -eq 'changed' }).Count) { $done.Add($n) }
        }
        # READ BACK: every own SQL target the plan moved must now be on
        $after = Get-SIOwnSqlConnectorPlan -Rows (& $norm (& $Sql $q.Sql $q.Params 'reader'))
        $still = @($after.Change | Where-Object { $plan.Change -contains $_ })
        if ($still.Count) {
            return [pscustomobject]@{ Action = 'failed'; Changed = $done.ToArray(); Lines = @(('connectors: SecurityInsight''s own SQL vulnerability target {0} is still not apply / create / close after the update set it -- check the Connectors page; the next update tries again' -f (($still | ForEach-Object { "'$_'" }) -join ', '))) }
        }
        [pscustomobject]@{ Action = 'changed'; Changed = $done.ToArray(); Lines = @($plan.Lines) }
    } catch {
        [pscustomobject]@{ Action = 'failed'; Changed = @(); Lines = @(('connectors: SecurityInsight''s own SQL vulnerability target was not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message)) }
    }
}
