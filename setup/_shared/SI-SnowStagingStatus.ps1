#Requires -Version 5.1
<#
    SecurityInsight -- #912 THE SERVICENOW STAGING STATUS TABLE: existing installs reach the new-install state SAFELY.

    THE NEW-INSTALL STATE: the setting SI_DataOut_ServiceNowStagingStatusTable is not set, so the engine uses the default
    u_si_staging_status (Get-SISnowStagingStatusTable, engine\asset-cmdb\_shared\SI-SnowImportSet.ps1): every push to ServiceNow
    is one batch -- a writing row, u_si_batch_id on every data row, an end row (complete | failed | held) -- and when the table
    cannot be written NOTHING is sent (data trust: never rows without their batch marker).

    WHY AN UPDATE CANNOT SIMPLY TAKE THE DEFAULT: the staging status table lives in the CUSTOMER's ServiceNow instance, and only
    their ServiceNow team can create it. An install that already sends to ServiceNow would stop sending on the night of the
    update. So, ONCE per install, this step writes the setting EMPTY ('') where the install already sends to ServiceNow
    through the Import Set API -- either of SI_DataOut_ServiceNowCiTable, SI_DataOut_ServiceNowVulnTable
    is set (the older push's two tables are retired, #914). Empty = the rows go exactly as before, and the
    run log, the ServiceNow check (Data health, the daily mail) and "For your ServiceNow team" say that the staging status table
    is missing and how to create it. The customer then creates the table and sets the setting (or clears the row to take the
    default).
    An install that does not send to ServiceNow is left alone: when it is set up later, its ServiceNow team follows the guide,
    which includes the staging status table.

    GUARDS: only while the setting has NO row (a value anyone set is never touched); one transaction with its cfg.ChangeLog row
    (By 'SecurityInsight update', the reason in words); read back. Never a delete, never another setting. Pro only (the Pro
    database). Never throws (Invoke-SISnowStagingStatusUpdate); -WhatIf (-DetectOnly) plans only. PURE planning
    (Get-SISnowStagingStatusPlan) over a SQL seam.
#>

$script:SISnowStagingStatusUpdate = @{
    By       = 'SecurityInsight update'
    Setting  = 'SI_DataOut_ServiceNowStagingStatusTable'
    Default  = 'u_si_staging_status'
    # the settings that say this install already sends rows to ServiceNow through the Import Set API
    Pushing  = @('SI_DataOut_ServiceNowCiTable', 'SI_DataOut_ServiceNowVulnTable')   # #914: the older push's tables are retired
}

function Get-SISnowStagingStatusPlan {
    <#
        PURE. -Settings: name -> the stored ValueJson (a name with no row is absent; $null = a row with NULL).
        Returns @{ Action = none | set-empty; Line; Pushing (the table settings that are set) }.
    #>
    param([hashtable]$Settings = @{})
    $c = $script:SISnowStagingStatusUpdate
    $text = {
        param($vj)
        if ($null -eq $vj -or $vj -is [System.DBNull]) { return '' }
        $s = [string]$vj
        try { $o = ConvertFrom-Json -InputObject $s; if ($o -is [array]) { return (($o | ForEach-Object { [string]$_ }) -join ';').Trim() }; return ([string]$o).Trim() } catch { return $s.Trim() }
    }
    if ($Settings.ContainsKey($c.Setting)) { return [pscustomobject]@{ Action = 'none'; Line = ''; Pushing = @() } }
    $pushing = @(foreach ($n in $c.Pushing) { if ($Settings.ContainsKey($n) -and (& $text $Settings[$n])) { $n } })
    if (-not $pushing.Count) { return [pscustomobject]@{ Action = 'none'; Line = ''; Pushing = @() } }
    [pscustomobject]@{ Action = 'set-empty'; Pushing = $pushing
        Line = ('ServiceNow: this install already sends to ServiceNow ({0}), so {1} is set empty: the rows go as before, and the ServiceNow page warns until your ServiceNow team creates the staging status table ({2}) and the setting names it.' -f ($pushing -join ', '), $c.Setting, $c.Default) }
}

function Get-SISnowStagingStatusSql {
    <# PURE. The statements: Read (the settings) and Set (the empty value, only while no row exists, with its cfg.ChangeLog row). #>
    param([ValidateSet('Read', 'Set')][string]$Statement)
    $c = $script:SISnowStagingStatusUpdate
    if ($Statement -eq 'Read') {
        $names = (@($c.Setting) + @($c.Pushing) | ForEach-Object { "N'$_'" }) -join ', '
        return [pscustomobject]@{ Params = @{}; Sql = ("IF OBJECT_ID(N'cfg.Setting') IS NOT NULL`nSELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name IN ({0});" -f $names) }
    }
    [pscustomobject]@{ Params = [ordered]@{ N = $c.Setting; V = '""'; By = $c.By; Reason = 'the staging status table is created by your ServiceNow team first -- until then the rows go as before, with a warning' }; Sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = @N AND Scope = N'solution')
BEGIN
    COMMIT;
    SELECT N'stale' AS Outcome;
    RETURN;
END;
INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@N, N'solution', @V, NULL, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@N, N'solution', N'Set', NULL, @V, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'changed' AS Outcome;
'@ }
}

function Read-SISnowStagingStatusSettings {
    <# The settings through the seam: name -> ValueJson (only names that have a row). #>
    param([Parameter(Mandatory)][scriptblock]$Sql)
    $q = Get-SISnowStagingStatusSql -Statement Read
    $h = @{}
    foreach ($r in @(& $Sql $q.Sql $q.Params 'reader' | ForEach-Object { $_ } | Where-Object { $_ })) {
        $n = if ($r -is [System.Collections.IDictionary]) { [string]$r['Name'] } else { [string]$r.Name }
        $v = if ($r -is [System.Collections.IDictionary]) { $r['ValueJson'] } else { $r.ValueJson }
        if ($v -is [System.DBNull]) { $v = $null }
        if ($n) { $h[$n] = $v }
    }
    $h
}

function Invoke-SISnowStagingStatusUpdate {
    <#
        The Pro database's part. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows). Never throws.
        Returns @{ Action = none | plan | changed | failed; Lines; Warnings }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    $out = { param($a, $l, $w) [pscustomobject]@{ Action = $a; Lines = @($l | Where-Object { $_ }); Warnings = @($w | Where-Object { $_ }) } }
    try {
        $plan = Get-SISnowStagingStatusPlan -Settings (Read-SISnowStagingStatusSettings -Sql $Sql)
        if ($plan.Action -eq 'none') { return (& $out 'none' @() @()) }
        if ($WhatIf) { return (& $out 'plan' @(('{0} (re-run with -Apply)' -f $plan.Line)) @()) }
        $q = Get-SISnowStagingStatusSql -Statement Set
        $o = [string](@(& $Sql $q.Sql $q.Params 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { $_['Outcome'] } else { $_.Outcome } } | Select-Object -First 1)
        if ($o -ne 'changed') { return (& $out 'none' @() @(('ServiceNow: {0} was set by someone while the update read it -- left as it is' -f $script:SISnowStagingStatusUpdate.Setting))) }
        # READ BACK
        $after = Read-SISnowStagingStatusSettings -Sql $Sql
        if (-not $after.ContainsKey($script:SISnowStagingStatusUpdate.Setting)) { return (& $out 'failed' @(('ServiceNow: {0} could not be read back after it was set -- the next update tries again' -f $script:SISnowStagingStatusUpdate.Setting)) @()) }
        & $out 'changed' @($plan.Line) @()
    } catch { & $out 'failed' @(('ServiceNow: the staging status setting was not checked ({0}) -- the update goes on; the next update tries again.' -f $_.Exception.Message)) @() }
}
