#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the users' sign-in methods in full, read in the background (owner 2026-11-05: "same with caching as sep
    job").
.DESCRIPTION
    Runs as its OWN small container job (caj-si-signin-methods) on its own timer -- every 15 minutes ("3,18,33,48 * * * *",
    config\job-flow.locked.json) -- never a step of the pipeline, never the pipeline's or the updater's lock: it touches only
    Microsoft Graph and its own tables (sidata.UserSignInMethods / UserSignInMethodsDetail) and its claim row
    (cfg.InstallState 'SignInMethodsFill'), so it never holds up a collection or an update.
    Each run reads users per user -- every property of every sign-in method and the device of a Windows Hello /
    Microsoft Authenticator method -- for at most SI_Identity_SignInMethodsFillMinutes (default 8), privileged users first,
    then users whose methods changed, then users never read, then the oldest; it stops at its slice and the next run carries
    on (engine\asset-profiling\shared\SI-SignInMethodsChoice.ps1, Invoke-SISignInMethodsFill). One run at a time: the
    container's execution guard ends a run whose previous execution still runs, and the claim row does the same.
    SI_Identity_SignInMethodsPerUser 'off' = the run ends at once, reading nobody. The identity collection takes what was
    saved at its next run. It signs in as the engine (collection) identity, which holds UserAuthenticationMethod.Read.All.
    It never fails: anything that goes wrong is said once and the job ends well (exit 0).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
try { Set-StrictMode -Off } catch { }
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$say = { param([string]$Level, [string]$Message) Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $(if ($Level -eq 'WARN') { 'Yellow' } else { 'Gray' }) }

& $say 'STEP' 'SecurityInsight -- the users'' sign-in methods, read in the background'
try {
    . (Join-Path $siRoot 'engine/asset-profiling/shared/SI-AuthMethodsRead.ps1')
    . (Join-Path $siRoot 'engine/asset-profiling/shared/SI-SignInMethodsChoice.ps1')
} catch {
    & $say 'WARN' ('the background read could not be loaded ({0}) -- nothing is read this run' -f $_.Exception.Message)
    exit 0
}

# the Pro database (the claim row and the stored choice) and the data database (the saved detail) -- as the heartbeat opens them
$proInvoke = $null; $dataInvoke = $null
if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/data-model/SI-RecordSql.ps1') }
        # the database through the record seam (both editions ship it; never a Pro-only file), its rows
        if (Get-Command -Name Invoke-SIRecordSqlDb -ErrorAction SilentlyContinue) {
            $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
            $proInvoke = [scriptblock]::Create(('param($Sql, $Params, $Mode) Invoke-SIRecordSqlDb -Server {0} -Database {1} -Sql $Sql -Params $Params -Mode rows' -f (& $q $global:SI_ProSqlServer), (& $q $global:SI_ProSqlDatabase)))
        }
        $dSrv = if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }
        $dDb = if ([string]$global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }
        $dataInvoke = New-SIRecordSqlInvoke -Server $dSrv -Database $dDb
    } catch { $dataInvoke = $null }
}

$r = Invoke-SISignInMethodsFillTick -DataInvoke $dataInvoke -ProInvoke $proInvoke -SIRoot $siRoot
if ($r -and "$($r.Line)".Trim()) { & $say $(if ($r.Status -eq 'error') { 'WARN' } else { 'INFO' }) $r.Line }
# never a failed execution: what was not read is read by a later run
exit 0
