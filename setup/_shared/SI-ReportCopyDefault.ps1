#Requires -Version 5.1
<#
    SecurityInsight -- #830 (owner 2026-10-20): THE COPY OF THE RISK ANALYSIS REPORT ROWS TO LOG ANALYTICS IS AN OPTIONAL
    OUTPUT, OFF BY DEFAULT IN EVERY INSTALL ("Copy Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL)",
    the setting SendToLogAnalytics). SecurityInsight reads the Risk Analysis result from its database; the copy is for the
    customer's own workbooks, Sentinel or KQL.

    EXISTING INSTALLS reach the new-install state through the update, ONCE (cfg.InstallState 'ReportRowCopyDefault'), the
    rule "every setup default change needs an updater step". What setup WROTE is moved; what a PERSON chose stays:
      * until now every guided install carried the copy ON without anyone choosing it: the generated config file wrote
        `$global:SendToLogAnalytics = $true` (imported into cfg.Setting with UpdatedBy '<who> (import)'), the Risk Analysis
        jobs were made with SI_RA_SEND_TO_LOG_ANALYTICS=1, and the defaults file said $true;
      * so a stored value that is ON is a SHIPPED value when its row was written by an import, by setup or by an update
        (Test-SIReportCopyShippedWriter) -- it is set to off, with its change-log row; a value ON that a person set on the
        Settings page (UpdatedBy = that person) is KEPT, said in one line;
      * an install with no stored value at all gets the solution-wide value off: the database's value is applied after the
        job's environment (the Pro settings layer), so a job made with SI_RA_SEND_TO_LOG_ANALYTICS=1 follows it -- nothing
        on the jobs is changed;
      * a NEW install writes the marker itself (Get-SIReportCopyInstallMarkerSql), so the step finds nothing to do.
    What cannot be told apart: a value a person once typed into the config file and imported looks exactly like the
    shipped line -- it is turned off too, and the one line says how to turn it on again (the Settings page).
    PURE planning (Get-SIReportCopyPlan) over a SQL seam; never throws (Invoke-SIReportCopyDefault).
#>

$script:SIReportCopy = @{ Marker = 'ReportRowCopyDefault'; By = 'SecurityInsight update'; Name = 'SendToLogAnalytics'; Scope = 'solution' }

function Test-SIReportCopyValueOn {
    <# PURE. A stored value (cfg.Setting.ValueJson) that is ON -- the engine's rule (Test-SIRaReportCopyOn): true / 1 / "on" / "yes". #>
    param([AllowNull()][AllowEmptyString()][string]$ValueJson)
    $v = ([string]$ValueJson).Trim().Trim('"').Trim().ToLowerInvariant()
    $v -in 'true', '1', 'yes', 'on'
}

function Test-SIReportCopyShippedWriter {
    <#
        PURE. Was the row written by SecurityInsight (an import of the generated config file, setup, an update) rather than by
        a person on the Settings page? '<who> (import)', 'guided install', 'setup ...', 'SecurityInsight update' (and an empty
        writer) are SecurityInsight's; anything else is a person.
    #>
    param([AllowNull()][AllowEmptyString()][string]$UpdatedBy)
    $b = ([string]$UpdatedBy).Trim()
    if (-not $b) { return $true }
    ($b -match '\(import\)\s*$') -or ($b -match '^(?i)(guided install|setup\b|securityinsight update|securityinsight setup|install\b)')
}

function Get-SIReportCopyPlan {
    <#
        PURE. -Rows: the stored values of SendToLogAnalytics (Scope, ValueJson, UpdatedBy); -Done: the marker is there.
        Returns @{ Done; Settings (@{ Scope; New; Insert }); Kept (scopes a person set on); Lines }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [bool]$Done = $false)
    $g = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $set = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]
    if ($Done) { return [pscustomobject]@{ Done = $true; Settings = @(); Kept = @(); Lines = @() } }
    $rows = @($Rows | Where-Object { $_ })
    foreach ($r in $rows) {
        $scope = [string](& $g $r 'Scope'); $val = [string](& $g $r 'ValueJson'); $by = [string](& $g $r 'UpdatedBy')
        if (-not (Test-SIReportCopyValueOn $val)) { continue }
        if (Test-SIReportCopyShippedWriter $by) { $set.Add([pscustomobject]@{ Scope = $scope; New = 'false'; Insert = $false }) }
        else { $kept.Add($scope); $lines.Add(('report rows: the copy of the Risk Analysis report rows to Log Analytics stays ON ({0}) -- set by {1} on the Settings page' -f $scope, $by)) }
    }
    if ($rows.Count -eq 0) { $set.Add([pscustomobject]@{ Scope = $script:SIReportCopy.Scope; New = 'false'; Insert = $true }) }
    if ($set.Count) {
        $lines.Add('report rows: the copy of the Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL) is now off, as in a new install -- SecurityInsight reads the results from its database; your own workbooks, Sentinel rules or KQL on that table need it on again (Settings: Copy Risk Analysis report rows to Log Analytics)')
    }
    [pscustomobject]@{ Done = $false; Settings = $set.ToArray(); Kept = $kept.ToArray(); Lines = $lines.ToArray() }
}

function Get-SIReportCopySql {
    <#
        The Pro database's statements. 'Read': the marker and the stored values. 'Apply' (-Plan): ONE transaction -- each value
        written with its cfg.ChangeLog row (the Settings page's history shows it), the marker last; a marker that appeared
        meanwhile = nothing is written. Returns @{ Sql; Params }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Name, $Plan, [string]$By = $script:SIReportCopy.By)
    if ($Name -eq 'Read') {
        return [pscustomobject]@{ Params = @{ Marker = $script:SIReportCopy.Marker; Setting = $script:SIReportCopy.Name }; Sql = @'
SELECT N'marker' AS Kind, CAST(N'' AS nvarchar(64)) AS Scope, Value AS ValueJson, UpdatedBy FROM cfg.InstallState WHERE OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND Name = @Marker
UNION ALL SELECT N'setting', Scope, ValueJson, UpdatedBy FROM cfg.Setting WHERE Name = @Setting;
'@ }
    }
    $p = [ordered]@{ By = $By; Marker = $script:SIReportCopy.Marker; Setting = $script:SIReportCopy.Name; MarkerValue = ''
                     Reason = 'the copy of the Risk Analysis report rows to Log Analytics is an optional output, off by default in every install (owner decision 2026-10-20)' }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('SET XACT_ABORT ON;')
    $null = $sb.AppendLine('BEGIN TRAN;')
    $null = $sb.AppendLine('IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Marker) BEGIN COMMIT; RETURN; END')
    $i = 0
    foreach ($s in @($Plan.Settings)) {
        $i++
        $p["S$i"] = [string]$s.Scope; $p["V$i"] = [string]$s.New
        $null = $sb.AppendLine(("DECLARE @old$i nvarchar(max) = (SELECT ValueJson FROM cfg.Setting WHERE Name = @Setting AND Scope = @S$i);"))
        $null = $sb.AppendLine(("IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @Setting AND Scope = @S$i) UPDATE cfg.Setting SET ValueJson = @V$i, KeyVaultSecretName = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Setting AND Scope = @S$i;"))
        $null = $sb.AppendLine(("ELSE INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@Setting, @S$i, @V$i, NULL, @By);"))
        $null = $sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@Setting, @S$i, N'Set', @old$i, @V$i, @By, @Reason);"))
    }
    $p.MarkerValue = ([ordered]@{ off = @(@($Plan.Settings) | ForEach-Object { [string]$_.Scope }); kept = @($Plan.Kept); by = 'update'; at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
    $null = $sb.AppendLine('INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Marker, @MarkerValue, NULL, @By);')
    $null = $sb.AppendLine('COMMIT;')
    [pscustomobject]@{ Sql = $sb.ToString(); Params = $p }
}

function Get-SIReportCopyInstallMarkerSql {
    <# PURE. A NEW Pro install's marker (the update's one-time step then has nothing to move); only when the table exists and the marker is not there. #>
    param([string]$By = 'guided install')
    $q = { param($s) ([string]$s).Replace("'", "''") }
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'{0}') INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'{0}', N'{1}', NULL, N'{2}');" -f (& $q $script:SIReportCopy.Marker), (& $q '{"off":[],"kept":[],"by":"install"}'), (& $q $By)
}

function Invoke-SIReportCopyDefault {
    <#
        The Pro database's part, once. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows, 'nonquery'). Never throws.
        Returns @{ Action = done | changed | kept | plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    try {
        $q = Get-SIReportCopySql -Name Read
        $rows = @(& $Sql $q.Sql $q.Params 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } })
        $plan = Get-SIReportCopyPlan -Rows @($rows | Where-Object { [string]$_.Kind -eq 'setting' }) -Done ([bool]@($rows | Where-Object { [string]$_.Kind -eq 'marker' }).Count)
        if ($plan.Done) { return [pscustomobject]@{ Action = 'done'; Lines = @() } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) } }
        $a = Get-SIReportCopySql -Name Apply -Plan $plan
        $null = & $Sql $a.Sql $a.Params 'nonquery'
        [pscustomobject]@{ Action = $(if (@($plan.Settings).Count) { 'changed' } else { 'kept' }); Lines = @($plan.Lines) }
    } catch {
        [pscustomobject]@{ Action = 'failed'; Lines = @(('report rows: the copy of the report rows to Log Analytics was not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message)) }
    }
}
