<#
.SYNOPSIS
    SecurityInsight Pro -- ONE TIME: let asset tagging read its settings from the Pro database.

.DESCRIPTION
    Asset tagging (#236) runs under its OWN identity (default uami-securityinsight-tagging), separate from the read-only
    collection identity, because it is the one engine that may write tags. Like every Pro engine it reads its settings from
    the Pro database at run start, so its identity needs a database user there with db_datareader -- nothing more. Installs
    made before this script lack that user, and their daily asset-tagging run stops at the settings check.

    Shows the statements by default; -Apply runs them AS THE CALLER, who must be the SQL server's Entra admin (or a member
    of its admin group). The identity is found by name or given by -ClientId; its database user is found by SID, so an
    existing user is reused whatever its name. Idempotent.

.EXAMPLE
    .\setup\Grant-SITaggingDatabase.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -SqlServer <server>.database.windows.net -SqlDatabase <db>
    Plan only (prints the T-SQL). Add -Apply to run it as yourself (the server's Entra admin).

.LINK
    https://invardia.com/docs/si/scripts/Grant-SITaggingDatabase/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SqlServer,
    [Parameter(Mandatory)][string]$SqlDatabase,
    [string]$ResourceGroupName,
    [string]$IdentityName = 'uami-securityinsight-tagging',
    [string]$ClientId,
    [string]$UserName,
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Grant-SITaggingDatabase' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: the T-SQL is shown, not run
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSchema.ps1')

function Initialize-SIGrantSignIn {
    # #521: setup's own REST sign-in (an existing one in this process is reused; else a person signs in -- Cloud Shell or the
    # browser; an Invardia support session gives its tokens). Never the az CLI.
    if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
    if (-not (Get-Command -Name Get-SISetupAccessToken -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1')) }
    if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
}

if (-not $ClientId) {
    if (-not $ResourceGroupName) { throw 'pass -ResourceGroupName (to find the identity by name) or -ClientId.' }
    . Initialize-SIGrantSignIn
    $id = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -SubscriptionId $SubscriptionId -ErrorAction Stop
    $ClientId = [string]$id.ClientId
}
if (-not $UserName) { $UserName = $IdentityName }
$sql = Get-SITaggingDatabaseAccessSql -UserName $UserName -ClientId $ClientId
Write-Host ("== Asset tagging's settings access on {0}/{1} (identity {2}, client id {3})" -f $SqlServer, $SqlDatabase, $UserName, $ClientId) -ForegroundColor Cyan
Write-Host (($sql -split "`n" | ForEach-Object { '    ' + $_.TrimEnd() }) -join "`n") -ForegroundColor DarkGray
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply as the SQL server''s Entra admin.' -ForegroundColor Yellow; return }

# a guided install hands its own sign-in in ($global:SI_InstallTokenProvider); otherwise setup's own sign-in (no az CLI)
$tp = Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore
$tok = if ($tp -is [scriptblock]) { ([string](& $tp 'https://database.windows.net/')).Trim() }
       else { . Initialize-SIGrantSignIn; ([string](Get-SISetupAccessToken -Resource 'https://database.windows.net/')).Trim() }
if (-not $tok) { throw 'the sign-in could not issue an Azure SQL token for the caller.' }
$cn = New-Object System.Data.SqlClient.SqlConnection ("Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connect Timeout=30" -f $SqlServer, $SqlDatabase)
$cn.AccessToken = $tok
$cn.Open()
try {
    $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql
    $rd = $cmd.ExecuteReader()
    try {
        if ($rd.Read()) {
            $ok = ([int]$rd['DataReader'] -eq 1)
            Write-Host ("  {0}: db_datareader {1}" -f $rd['UserName'], $rd['DataReader']) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
            if (-not $ok) { throw 'db_datareader was not granted -- run this as the SQL server''s Entra admin.' }
        }
    } finally { $rd.Close() }
} finally { $cn.Dispose() }
Write-Host 'Done: asset tagging can now read its settings; its next run passes the settings check.' -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
