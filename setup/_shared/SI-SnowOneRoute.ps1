#Requires -Version 5.1
<#
    SecurityInsight Pro -- UPDATE STEP 9o: ONE ROUTE INTO SERVICENOW (#914, owner 2026-10-27).

    The older ServiceNow push -- the CMDB job's Import Set push and direct write, the vulnerability close-loop's ServiceNow
    connector -- was REMOVED; the ServiceNow data-out connector is the one ServiceNow push. No customer used the older push,
    but an existing install may still hold one of its settings. This step reads them ONCE per install:

      * a setting of the older push that holds a value (SI_ServiceNow_ImportSetTable, SI_ServiceNow_ImportSetMaxRows,
        SI_VulnSync_ServiceNowImportSetTable, SI_ServiceNow_DirectWrite, SI_VulnSync_ServiceNowDirectWrite) is NAMED in ONE
        line of the update log: the code no longer reads it (retired in the settings catalog), the ServiceNow data-out
        connector is the one push;
      * NOTHING is deleted: the setting rows stay in the settings database (never customer data deleted) and are ignored;
      * the step records that it said so (cfg.InstallState 'SnowOneRoute'), so the line is said once, never on every update.

    Never fails the update: a database that cannot be read is one warning, and the next update tries again. -WhatIf: the plan.
    PowerShell 7; parses on 5.1. No modules.
#>

$script:SISnowOneRoute = [pscustomobject]@{
    Marker   = 'SnowOneRoute'
    By       = 'SecurityInsight update'
    Settings = @('SI_ServiceNow_ImportSetTable', 'SI_ServiceNow_ImportSetMaxRows', 'SI_VulnSync_ServiceNowImportSetTable', 'SI_ServiceNow_DirectWrite', 'SI_VulnSync_ServiceNowDirectWrite')
}

function Get-SISnowOneRouteSettings { <# PURE. The older push's settings this step names. #> , @($script:SISnowOneRoute.Settings) }

function Get-SISnowOneRouteReadSql {
    <# The marker and the older push's setting rows (every scope). #>
    @'
SET NOCOUNT ON;
SELECT N'marker' AS Kind, Name, CAST(N'' AS nvarchar(64)) AS Scope, Value AS ValueJson FROM cfg.InstallState WHERE OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND Name = @Marker
UNION ALL
SELECT N'setting', Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN (SELECT value FROM OPENJSON(@names));
'@
}

function Get-SISnowOneRouteMarkSql {
    <# The marker, written once (never overwritten). #>
    "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = @Marker) INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Marker, @Value, NULL, @By);"
}

function Test-SISnowOneRouteValueSet {
    <# PURE. Does a stored value hold something (not empty, not false, not 0)? #>
    param([AllowNull()][AllowEmptyString()][string]$ValueJson)
    $v = ([string]$ValueJson).Trim().Trim('"').Trim()
    if (-not $v) { return $false }
    return (@('false', '0', 'null', 'off', 'no') -notcontains $v.ToLowerInvariant())
}

function Get-SISnowOneRoutePlan {
    <#
        PURE. The step's decision from the rows read (Get-SISnowOneRouteReadSql): @{ Action ('none' | 'say' | 'mark');
        Named (the settings that hold a value); Lines }. Said already (the marker) = none. No setting holds a value = mark
        only (nothing to say, the marker so the step is not read again).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $g = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
    if (@($Rows | Where-Object { [string](& $g $_ 'Kind') -eq 'marker' }).Count) { return [pscustomobject]@{ Action = 'none'; Named = @(); Lines = @() } }
    $named = @(@($Rows | Where-Object { [string](& $g $_ 'Kind') -eq 'setting' -and (Test-SISnowOneRouteValueSet ([string](& $g $_ 'ValueJson'))) } |
               ForEach-Object { [string](& $g $_ 'Name') }) | Select-Object -Unique | Sort-Object)
    if ($named.Count -eq 0) { return [pscustomobject]@{ Action = 'mark'; Named = @(); Lines = @() } }
    $line = ('ServiceNow: the older ServiceNow push was removed -- {0} {1} no longer read (the values stay in the settings database). The ServiceNow data-out connector is the one ServiceNow push: set it up on Configuration > Connectors > Setup (direction data-out).' -f ($named -join ', '), $(if ($named.Count -eq 1) { 'is' } else { 'are' }))
    [pscustomobject]@{ Action = 'say'; Named = $named; Lines = @($line) }
}

function Invoke-SISnowOneRouteUpdate {
    <#
        Update step 9o through -Sql { param($Query, $Params, $Mode) } (the Pro database). Returns @{ Action; Named; Lines;
        Warnings }. -WhatIf: the plan only (nothing marked). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    try {
        $rows = @(& $Sql (Get-SISnowOneRouteReadSql) @{ Marker = $script:SISnowOneRoute.Marker; names = (ConvertTo-Json -InputObject @($script:SISnowOneRoute.Settings) -Compress) } 'reader')
        $plan = Get-SISnowOneRoutePlan -Rows $rows
        if ($plan.Action -eq 'none' -or $WhatIf) { return [pscustomobject]@{ Action = $plan.Action; Named = $plan.Named; Lines = @($plan.Lines); Warnings = @() } }
        $null = & $Sql (Get-SISnowOneRouteMarkSql) @{ Marker = $script:SISnowOneRoute.Marker; Value = ('said: {0}' -f $(if ($plan.Named.Count) { $plan.Named -join ',' } else { 'nothing set' })); By = $script:SISnowOneRoute.By } 'nonquery'
        [pscustomobject]@{ Action = $plan.Action; Named = $plan.Named; Lines = @($plan.Lines); Warnings = @() }
    } catch {
        [pscustomobject]@{ Action = 'failed'; Named = @(); Lines = @(); Warnings = @(('ServiceNow: the older push''s settings could not be read ({0}) -- the update goes on; the next update tries again.' -f $_.Exception.Message)) }
    }
}
