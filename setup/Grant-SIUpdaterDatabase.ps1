<#
.SYNOPSIS
    SecurityInsight Pro -- ONE TIME: let the product updater (caj-si-updater) apply a release's database schema and grants.

.DESCRIPTION
    Since #352 an update applies the release's Pro database schema (additive, gated) and the grants its code needs BEFORE it
    rolls any code -- never new code on an old schema. For that the updater's identity needs, on the Pro database:
      db_datareader + db_datawriter   its state rows and the template gate (most installs already have these)
      db_ddladmin                     the additive schema (CREATE TABLE / VIEW / INDEX, ALTER TABLE ... ADD)
      db_securityadmin                the web app's and MCP server's grants, the audit role, the DENYs
    Until it has them, an update STOPS before rolling anything and says so (Operations > Guards (safety checks): update.schema.failed).

    Shows the statements by default; -Apply runs them AS THE CALLER, who must be the SQL server's Entra admin (or a member
    of its admin group) -- the same way Deploy-SIManagement.ps1 -GrantSql creates the web app's users. The identity is found
    by name (a user-assigned identity, the default uami-si-updater) or given by -ClientId (an SPN); its database user is
    found by SID, so an existing user is reused whatever its name. Idempotent.

.EXAMPLE
    .\setup\Grant-SIUpdaterDatabase.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -SqlServer <server>.database.windows.net -SqlDatabase <db>
    Plan only (prints the T-SQL). Add -Apply to run it as yourself (the server's Entra admin).

.LINK
    https://invardia.com/docs/si/scripts/Grant-SIUpdaterDatabase/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SqlServer,
    [Parameter(Mandatory)][string]$SqlDatabase,
    [string]$ResourceGroupName,
    [string]$IdentityName = 'uami-si-updater',
    # an SPN instead of a managed identity: its app (client) id; -UserName names a NEW database user (default: the identity name)
    [string]$ClientId,
    [string]$UserName,
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Grant-SIUpdaterDatabase' -Quiet:($false)
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the plan: nothing is granted
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSchema.ps1')
# #672 (framework §12.23 P4 / P9): the certificate-signed grant procedure -- REMOVE-ME switch SI_Setup_SignedGrantProcedure,
# OFF by default until a fresh test install has proven it. ON = the full model: the component roles, the signed procedure,
# the updater in si_updater (EXECUTE on it) and NO db_securityadmin. OFF = today's rights.
. (Join-Path $siRoot 'engine\pro-settings\SI-GrantProcedure.ps1')
$signedGrants = Test-SIGrantProcedureSetup

function Initialize-SIGrantSignIn {
    # #521: setup's own REST sign-in (an existing one in this process is reused; else a person signs in -- Cloud Shell or the
    # browser; an Invardia support session gives its tokens). Never the az CLI.
    if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))   # ALWAYS (#616): its API versions are script values of THIS script's scope
    if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
}

if (-not $ClientId) {
    if (-not $ResourceGroupName) { throw 'pass -ResourceGroupName (to find the identity by name) or -ClientId.' }
    . Initialize-SIGrantSignIn
    $id = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -SubscriptionId $SubscriptionId -ErrorAction Stop
    $ClientId = [string]$id.ClientId
}
if (-not $UserName) { $UserName = $IdentityName }
$sql = Get-SIUpdaterDatabaseAccessSql -UserName $UserName -ClientId $ClientId -NoSecurityAdmin:$signedGrants
$procBatches = if ($signedGrants) { @(Get-SIGrantProcedureAdminSql -UpdaterUser $UserName) } else { @() }
Write-Host ("== The updater's database rights on {0}/{1} (identity {2}, client id {3})" -f $SqlServer, $SqlDatabase, $UserName, $ClientId) -ForegroundColor Cyan
Write-Host (($sql -split "`n" | ForEach-Object { '    ' + $_.TrimEnd() }) -join "`n") -ForegroundColor DarkGray
if ($signedGrants) { Write-Host ('  + the signed grant procedure (SI_Setup_SignedGrantProcedure is ON): {0}' -f (($procBatches | ForEach-Object { $_.Step }) -join ', ')) -ForegroundColor DarkGray }
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply as the SQL server''s Entra admin.' -ForegroundColor Yellow; return }

# a guided install hands its own sign-in in ($global:SI_InstallTokenProvider); otherwise setup's own sign-in (no az CLI)
$tp = Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore
if (-not ($tp -is [scriptblock])) { . Initialize-SIGrantSignIn }
# Open-SISqlConnectionRetry reads no script value of its file, so finding it defined is enough
if (-not (Get-Command -Name Open-SISqlConnectionRetry -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1')) }
# opened with a bounded retry on "Login failed" / 40615 only, a new token each time: the server's administrator or its
# firewall rule may have changed a moment ago
$dbUser = $UserName
$cn = Open-SISqlConnectionRetry -Server $SqlServer -Database $SqlDatabase -Token {
    param([bool]$Fresh)
    if ($tp -is [scriptblock]) { ([string](& $tp 'https://database.windows.net/')).Trim() }
    else { ([string](Get-SISetupAccessToken -Resource 'https://database.windows.net/' -ForceRefresh:$Fresh)).Trim() }
}
try {
    $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql
    $rd = $cmd.ExecuteReader()
    try {
        if ($rd.Read()) {
            $ok = ([int]$rd['DdlAdmin'] -eq 1) -and (([int]$rd['SecurityAdmin'] -eq 1) -or $signedGrants) -and ([int]$rd['DataReader'] -eq 1) -and ([int]$rd['DataWriter'] -eq 1)
            $dbUser = [string]$rd['UserName']
            Write-Host ("  {0}: db_ddladmin {1}, db_securityadmin {2}, db_datareader {3}, db_datawriter {4}" -f $rd['UserName'], $rd['DdlAdmin'], $rd['SecurityAdmin'], $rd['DataReader'], $rd['DataWriter']) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
            if (-not $ok) { throw 'the roles were not all granted -- run this as the SQL server''s Entra admin.' }
        }
    } finally { $rd.Close() }
    # the full model: the roles, the procedure, its signature and the updater's EXECUTE (each batch idempotent)
    if ($signedGrants) {
        foreach ($b in @(Get-SIGrantProcedureAdminSql -UpdaterUser $dbUser)) {
            $cmd = $cn.CreateCommand(); $cmd.CommandText = $b.Sql; $cmd.CommandTimeout = 0; [void]$cmd.ExecuteNonQuery()
            Write-Host ("  signed grant procedure: {0}" -f $b.Purpose) -ForegroundColor Green
        }
    }
} finally { $cn.Dispose() }
Write-Host 'Done: the updater can now apply a release''s database schema and grants before it rolls the code.' -ForegroundColor Green
} finally { Stop-SIScriptRun -Run $siRun }
