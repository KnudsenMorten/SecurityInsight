<#
.SYNOPSIS
    SecurityInsight Pro -- acknowledge every open guard event (safety check) in the Pro database: a fresh start.

.DESCRIPTION
    Operator 2026-10-07: "clear the safety checks or close all/acknowledge all so i can start a
    fresh". This is the setup-script twin of Operations > Guards (safety checks) > "Acknowledge all": every OPEN guard event
    (one no acknowledgement covers -- its own, or one of exactly the same event: the same guard key and detail) is
    acknowledged with the SAME statement the web app's Acknowledge runs (cfg.GuardAck, one row per event; later repeats
    of exactly it are covered too), by 'setup: <reason>', and the run is written to the audit trail
    (guard.event.acknowledge, actor source 'setup').

    What it NEVER touches: held data. A held close set or a held / refused Risk Analysis collection stays held and is NOT
    loaded or released (cfg.GuardRelease and sidata are not read or written); the next complete nightly run brings fresh
    data. Releases stay one at a time, in the web app, on purpose.

    Plan by default: lists the events it would acknowledge and writes nothing. -Apply writes (-WhatIf with -Apply still
    only plans).

    The database comes from -SqlServer / -Database (else SI_ProSqlServer / SI_ProSqlDatabase) and is reached as the
    engine identity (certificate), like the other setup\*.ps1 Pro tools.

.EXAMPLE
    .\setup\Clear-SIGuardEvents.ps1 -SqlServer <server>.database.windows.net -Database sidb -Reason 'fresh start' -AcknowledgeAll
.EXAMPLE
    .\setup\Clear-SIGuardEvents.ps1 -SqlServer <server>.database.windows.net -Database sidb -Reason 'fresh start' -AcknowledgeAll -Apply

.LINK
    https://invardia.com/docs/si/scripts/Clear-SIGuardEvents/
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SqlServer = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    # Why (required, at least 10 characters): on every acknowledgement and on the audit trail.
    [Parameter(Mandatory)][string]$Reason,
    # Acknowledge every open guard event (the only mode -- named so the command says what it does).
    [switch]$AcknowledgeAll,
    # Write. Without it the script only plans.
    [switch]$Apply,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    [switch]$PassThru
)

#Requires -Version 7.0   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Clear-SIGuardEvents' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the preview: nothing is acknowledged
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot

$why = ([string]$Reason).Trim()
if ($why.Length -lt 10) { throw 'say why every open guard event is acknowledged (-Reason, at least 10 characters)' }
if ($why.Length -gt 1000) { $why = $why.Substring(0, 1000) }
if (-not $AcknowledgeAll) { throw 'nothing to do: give -AcknowledgeAll (every open guard event is acknowledged; held data is never touched)' }

. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-Audit.ps1'))
if (-not $Store) {
    if (-not $SqlServer -or -not $Database) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
    $Store = New-SIProSettingsStore -Server $SqlServer -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
}

# The open events: no acknowledgement covers them -- the web app's rule (SqlGuardEventStore.Source, the OUTER APPLY).
$openSql = @'
IF OBJECT_ID(N'cfg.GuardEvent') IS NULL OR OBJECT_ID(N'cfg.GuardAck') IS NULL
    SELECT CAST(-1 AS bigint) AS Id, CAST(NULL AS datetime2(0)) AS TsUtc, N'' AS GuardId, N'' AS Outcome, N'' AS Severity, N'' AS Subject, N'' AS Detail;
ELSE
    SELECT e.Id, e.TsUtc, e.GuardId, e.Outcome, e.Severity, e.Subject, LEFT(ISNULL(e.Detail, N''), 200) AS Detail
    FROM cfg.GuardEvent AS e
    OUTER APPLY (SELECT TOP (1) a.AckBy FROM cfg.GuardAck AS a
                 WHERE a.EventId = e.Id OR (a.GuardKey = e.GuardKey AND a.DetailHash = HASHBYTES('SHA2_256', ISNULL(e.Detail, N'')))
                 ORDER BY a.AckUtc DESC) AS ak
    WHERE ak.AckBy IS NULL
    ORDER BY e.TsUtc DESC, e.Id DESC;
'@

# THE web app's acknowledgement (SqlGuardEventStore.AckSql) -- the same text; a test compares the two.
$ackSql = @'
IF OBJECT_ID(N'cfg.GuardAck') IS NULL BEGIN SELECT N'NoTable' AS Outcome; RETURN; END;
DECLARE @k nvarchar(500), @h varbinary(32);
SELECT @k = e.GuardKey, @h = HASHBYTES('SHA2_256', ISNULL(e.Detail, N'')) FROM cfg.GuardEvent AS e WHERE e.Id = @EventId;
IF @k IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
IF EXISTS (SELECT 1 FROM cfg.GuardAck AS a WHERE a.EventId = @EventId) BEGIN SELECT N'Already' AS Outcome; RETURN; END;
INSERT cfg.GuardAck (EventId, GuardKey, DetailHash, AckBy, Note) VALUES (@EventId, @k, @h, @By, LEFT(@Note, 1000));
SELECT N'Acknowledged' AS Outcome;
'@

# the reader answers its rows as ONE array -- unrolled here
$rows = @(& $Store.Invoke $openSql @{} 'reader' | ForEach-Object { $_ })
if ($rows.Count -eq 1 -and [long]$rows[0].Id -eq -1) {
    throw 'this database has no guard events or cannot record acknowledgements yet (apply sql\si-pro-settings.sql -- it only adds)'
}
$by = 'setup: ' + $why
if ($by.Length -gt 256) { $by = $by.Substring(0, 256) }

Write-Host ('Open guard events in {0}: {1}' -f $Store.Name, $rows.Count)
foreach ($r in $rows) {
    $when = if ($r.TsUtc) { ([datetime]$r.TsUtc).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { '' }
    Write-Host ('  #{0,-7} {1,-20} {2,-9} {3,-40} {4}' -f $r.Id, $when, $r.Severity, $r.GuardId, $(if ($r.Subject) { $r.Subject } else { '' }))
}
$result = [pscustomobject]@{ Mode = 'plan'; Open = $rows.Count; Acknowledged = 0; Already = 0; Missing = 0; Events = @($rows | ForEach-Object { [long]$_.Id }); By = $by }

$write = $Apply -and $PSCmdlet.ShouldProcess($Store.Name, ('acknowledge {0} open guard event(s) by ''{1}''' -f $rows.Count, $by))
if (-not $write) {
    Write-Host ('[PLAN] {0} open guard event(s) would be acknowledged by ''{1}''. Held data is not touched. Run again with -Apply to write.' -f $rows.Count, $by)
    if ($PassThru) { return $result }
    return
}

$result.Mode = 'applied'
foreach ($r in $rows) {
    $o = @(& $Store.Invoke $ackSql @{ EventId = [long]$r.Id; By = $by; Note = $why } 'reader' | ForEach-Object { $_ })
    switch ([string]$o[0].Outcome) {
        'Acknowledged' { $result.Acknowledged++ }
        'Already'      { $result.Already++ }
        'NoTable'      { throw 'this database cannot record acknowledgements yet (apply sql\si-pro-settings.sql -- it only adds)' }
        default        { $result.Missing++ }
    }
}
[void](Write-SIAuditEvent -Store $Store -Action 'guard.event.acknowledge' -Actor (Get-SIAuditActor) -ActorSource 'setup' -Target '/Admin/Guards/events' -Reason $why `
        -OutcomeText ('Clear-SIGuardEvents: {0} open guard event(s) acknowledged by ''{1}''; held data not touched' -f $result.Acknowledged, $by) `
        -After ([ordered]@{ acknowledgeAll = $true; acknowledged = $result.Acknowledged; already = $result.Already; missing = $result.Missing; events = $result.Events; by = $by }))
Write-Host ('[OK]   {0} guard event(s) acknowledged by ''{1}'' ({2} already, {3} gone). Held data is not touched: the next complete run loads fresh data.' -f $result.Acknowledged, $by, $result.Already, $result.Missing) -ForegroundColor Green
if ($PassThru) { $result }
} finally { Stop-SIScriptRun -Run $siRun }
