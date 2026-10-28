#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- the daily configuration backup (REQUIREMENTS #404, framework CONFIG-1.3).
.DESCRIPTION
    Runs as its own container job (caj-si-config-backup), on its OWN daily timer outside the pipeline (default 18:00 UTC:
    after the working day, before the 23:30 pipeline, never at the 23:00 update; SI_Bootstrap_ScheduleConfigBackup).
    A time-of-day job never overlaps its previous run (SCHED-1.1: the container's execution guard).

    One backup of every customer-made configuration record in force (cfg.vConfigSnapshot -- the configuration set of
    config\config-entities.locked.json) through cfg.ConfigBackupTake: a compressed copy, or "no change" (pointing at the
    backup that holds the content) when nothing changed since the newest backup. Then the retention: backups older than
    SI_Pro_ConfigBackupRetentionDays (default 90) are removed through cfg.ConfigBackupPrune -- never a pinned one, never one
    whose content a kept backup points at -- recorded as config.backup.prune; and, only when SI_Pro_ConfigJournalRetentionDays
    is set (default: the journal is kept), change-journal rows older than that, never shorter than the backups.
    Every step is on the audit trail (config.backup.take / .prune, config.journal.prune). "Back up now" in the web app
    takes the same backup through the same procedure.

    Never in a backup: secrets (a secret setting holds only its Key Vault secret NAME), the audit trail, the change journal,
    caches, telemetry, run logs.
.PARAMETER NoPrune
    Take the backup only; remove nothing.
#>
[CmdletBinding()]
param([switch]$NoPrune)

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
function Write-BackupLog ([string]$level, [string]$msg) {
    $c = switch ($level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'STEP' { 'Cyan' } default { 'Gray' } }
    Write-Host ('[{0}] {1}' -f $level, $msg) -ForegroundColor $c
}

Write-BackupLog 'STEP' 'SecurityInsight -- configuration backup'
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
if (-not (Assert-SIFeatureOrSkip -Feature 'settings-database')) { return }
. (Join-Path $here 'SI-ProSettings.ps1')
. (Join-Path $here 'SI-Audit.ps1')
. (Join-Path $here 'SI-ConfigJournal.ps1')

# Same auth bridge as the other Pro engines: platform names -> SI_SPN_*.
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }
if ([string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlServer) -or [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlDatabase)) {
    Write-BackupLog 'INFO' 'skipped: the Pro database is not configured (SI_ProSqlServer / SI_ProSqlDatabase) -- there is no configuration to back up.'
    return
}

$store = New-SIProSettingsStore -Server ([string]$global:SI_ProSqlServer) -Database ([string]$global:SI_ProSqlDatabase) -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
# a run a person started (SI_AUDIT_CID) records under that request's correlation id; a scheduled run under its own
$cid = if ([string]$env:SI_AUDIT_CID) { [string]$env:SI_AUDIT_CID } else { [guid]::NewGuid().ToString('N') }
$invoke = New-SIConfigInvoke -Invoke $store.Invoke -CorrelationId $cid -ActorSource 'job' -Source 'sync'
$version = try { (Get-Content -LiteralPath (Join-Path $siRoot 'VERSION') -Raw).Trim() } catch { '' }
$log = { param([string]$level, [string]$msg) Write-BackupLog $level $msg }

$r = Invoke-SIConfigBackup -Invoke $invoke -Trigger 'scheduled' -Actor (Get-SIAuditActor -Job 'configuration backup') -CorrelationId $cid -ProductVersion $version `
        -RetentionDays (Get-Variable -Name SI_Pro_ConfigBackupRetentionDays -Scope Global -ValueOnly -ErrorAction SilentlyContinue) `
        -JournalRetentionDays (Get-Variable -Name SI_Pro_ConfigJournalRetentionDays -Scope Global -ValueOnly -ErrorAction SilentlyContinue) `
        -NoPrune:$NoPrune -Log $log
Write-BackupLog 'OK' ("done: backup #{0}{1}; {2} old backup(s) removed" -f $r.BackupId, $(if ($r.NoChange) { ' (no change)' } else { '' }), $r.Pruned)
