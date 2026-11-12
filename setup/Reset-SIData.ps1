<#
.SYNOPSIS
    SecurityInsight Pro -- a FRESH START of the data: empty the install's data in place and keep the install itself.

.DESCRIPTION
    For an install whose data should start again from nothing -- for example after a scope mistake collected objects that
    were never wanted -- while the customer does not use SecurityInsight yet. The scheduled pipeline fills the data again
    from the sources; nothing of the old data is kept.

    EMPTIED: every table of the Pro database's data schemas (findings, CIs, collections, their history, the vulnerability
    and CMDB connector state, the ServiceNow staging tables) and four run-history tables that describe that data (the
    connectors' runs and item change log, the data-out items and batches).
    THE IDENTITY LEDGER IS KEPT by default: its ids stay stable, and a ledger row for an object that is out of scope makes
    no CI. -IncludeIdentityLedger (opt-in) empties it too (its schema record is kept).
    KEPT: the databases, every user, role, grant and procedure (SQL access is never lost), the settings, templates and all
    other configuration, the change journal, the audit trail, the install's state (schema version, ring), the support
    consent and grants, the pipeline's run records and the performance measurements. The full list and the reason for
    each table: setup\_shared\SI-DataReset.ps1.

    PLAN BY DEFAULT: per table the rows and MB that would go, and what is kept; nothing is changed. -Apply empties the
    tables (-WhatIf with -Apply still only plans). -Apply refuses while a pipeline run, an update, the clean-up or the
    index build is running, and holds the install's lock for the whole reset so none starts meanwhile. It refuses when
    another system holds SecurityInsight's keys (a live ServiceNow / REST output) unless -AcceptExternalKeysLost. After
    -Apply it reads back: every emptied table has 0 rows, no kept table has fewer rows, and the two identity scope
    settings (SI_Identity_SkipNeverSyncedDisabledAd, SI_Identity_SkipDeletedGroups) are on. A second -Apply on an emptied
    install changes nothing and says so. Recorded on the audit trail (data.store.reset).

    REACHING THE DATABASES: as the install identity (certificate; -SqlServer / -Database, else SI_ProSqlServer /
    SI_ProSqlDatabase), or with -SupportSql through the Invardia Support app's audited Invoke-InvardiaSupportSql (open the
    Support session first). With -IncludeIdentityLedger, the identity ledger database is -IdentityDatabase (else the install's SI_LedgerDatabase setting,
    else sqldb-si-identity) on the same server (else SI_LedgerSqlServer). On a PRIVATE install (public network access off)
    the databases are reached only from inside its network -- framework rule 11e: this script NEVER opens a firewall rule
    or public access. It reads the server's public network access first (-ResourceGroupName) and refuses on a private
    install unless it runs inside the network (-InsideNetwork).

.EXAMPLE
    .\setup\Reset-SIData.ps1 -SqlServer <server>.database.windows.net -Database sqldb-si-pro -ResourceGroupName rg-si -Reason 'fresh start after a scope mistake'
.EXAMPLE
    .\setup\Reset-SIData.ps1 -SqlServer <server>.database.windows.net -Database sqldb-si-pro -ResourceGroupName rg-si -Reason 'fresh start after a scope mistake' -Apply
.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'fresh start of the data'
    .\setup\Reset-SIData.ps1 -SqlServer <server> -Database sqldb-si-pro -ResourceGroupName <rg> -SupportSql -Reason 'fresh start after a scope mistake' -Apply

.LINK
    https://invardia.com/docs/si/scripts/Reset-SIData/
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Why (required, at least 10 characters): on the audit trail.
    [Parameter(Mandatory)][string]$Reason,
    # Empty the tables. Without it the script only plans.
    [switch]$Apply,
    # Go on although a live ServiceNow / REST output holds SecurityInsight's keys (the fresh data gets new keys).
    [switch]$AcceptExternalKeysLost,
    # Opt-in: empty the identity ledger database too (default: kept -- stable ids; an object out of scope makes no CI).
    [switch]$IncludeIdentityLedger,
    [string]$SqlServer = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    # The identity ledger database (default: the install's SI_LedgerDatabase setting, else sqldb-si-identity) and its server.
    [string]$IdentityDatabase,
    [string]$IdentitySqlServer,
    # The install's resource group: its database server's public network access is read first (a private install is refused).
    [string]$ResourceGroupName = [string]$global:SI_Bootstrap_ResourceGroupName,
    [string]$SubscriptionId,
    # This runs INSIDE the install's network (a machine in it, or the install's own job): the private check is not needed.
    [switch]$InsideNetwork,
    # Reach the databases through the Invardia Support app's audited SQL (Invoke-InvardiaSupportSql; open the session first).
    [switch]$SupportSql,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The databases, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    $IdentityStore,
    # TEST SEAM: { } -> the database server's public network access ('Enabled' | 'Disabled' | ...), instead of reading it from Azure.
    [scriptblock]$NetworkAccess,
    # TEST SEAM: { param([int]$ms) } -- the pause between two batches.
    [scriptblock]$Pause,
    [switch]$PassThru
)

#Requires -Version 7.0   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Reset-SIData' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the preview: nothing is changed
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-DataReset.ps1'))

$why = ([string]$Reason).Trim()
if ($why.Length -lt 10) { throw 'say why (-Reason, at least 10 characters): it is kept on the audit trail' }

# ---- THE PRIVATE CHECK (framework rule 11e): read the server's public network access BEFORE any connection -----------
$srvShort = (([string]$SqlServer) -split '\.')[0]
if (-not $InsideNetwork) {
    $pna = $null
    if ($NetworkAccess) { $pna = [string](& $NetworkAccess) }
    elseif (-not $Store) {
        if (-not $ResourceGroupName) { throw 'give -ResourceGroupName (the install''s resource group: its database server is checked for public network access before anything is read), or -InsideNetwork when this runs inside the install''s network' }
        if (-not $srvShort) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
        . ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-SetupAzure.ps1'))
        . ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
        $inSession = [bool]((Get-Variable -Name InvardiaSupportState -Scope Global -ErrorAction SilentlyContinue) -or (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue))
        $ca = @{}
        if ($SubscriptionId) { $ca['SubscriptionId'] = $SubscriptionId }
        if (-not $inSession) {
            if ($TenantId) { $ca['TenantId'] = $TenantId }
            if ($AppId -and $CertThumbprint) { $ca['ApplicationId'] = $AppId; $ca['CertificateThumbprint'] = $CertThumbprint }
        }
        $null = Connect-SISetupAzure @ca
        $shape = Get-SISqlServerNetworkShape -ResourceGroupName $ResourceGroupName -ServerName $srvShort -SubscriptionId $SubscriptionId
        if ($null -eq $shape) { throw ('the database server {0} was not found in {1} -- nothing was read or changed' -f $srvShort, $ResourceGroupName) }
        $pna = [string]$shape.PublicNetworkAccess
    }
    if ($null -ne $pna) {
        $p = $pna.Trim()
        # an empty value is a server made before the setting existed: public
        if (-not ($p -eq '' -or $p -ieq 'Enabled')) {
            throw ('this install is private (public network access {0}): its databases are reached only from inside its network -- framework rule 11e; nothing was opened, read or changed. Run it inside the network (-InsideNetwork, on a machine in the install''s network).' -f $p)
        }
    }
}

# ---- THE DATABASES ---------------------------------------------------------------------------------------------------
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
$open = {
    param([string]$Server, [string]$Db, [string]$What)
    if ($SupportSql) { return (New-SIDataResetSupportStore -Server $Server -Database $Db -Reason ('SecurityInsight fresh start of the data ({0}): {1}' -f $What, $why)) }
    New-SIProSettingsStore -Server $Server -Database $Db -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
}
if (-not $Store) {
    if (-not $SqlServer -or -not $Database) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
    $Store = & $open $SqlServer $Database 'Pro database'
}
if ($IncludeIdentityLedger -and -not $IdentityStore) {
    # where the identity ledger is: the parameters, else the install's own settings, else the shipped name
    $loc = @(Invoke-SIDataResetRows -Invoke $Store.Invoke -Sql (Get-SIDataResetSql -Name Location)) | Select-Object -First 1
    $idDb = if ($IdentityDatabase) { $IdentityDatabase } else { ConvertFrom-SIDataResetSettingText ([string](Get-SIDataResetField $loc 'LedgerDatabase')) }
    if (-not $idDb) { $idDb = 'sqldb-si-identity' }
    $idSrv = if ($IdentitySqlServer) { $IdentitySqlServer } else { ConvertFrom-SIDataResetSettingText ([string](Get-SIDataResetField $loc 'LedgerServer')) }
    if (-not $idSrv) { $idSrv = $SqlServer }
    if (-not $idSrv) { throw 'the identity ledger''s server is not known: give -IdentitySqlServer' }
    $IdentityStore = & $open $idSrv $idDb 'identity ledger'
}

$write = $Apply -and $PSCmdlet.ShouldProcess($Store.Name, 'empty the data tables (a fresh start of the data)')
$ra = @{ Invoke = $Store.Invoke; Reason = $why; Apply = [bool]$write; AcceptExternalKeysLost = [bool]$AcceptExternalKeysLost
    IncludeIdentityLedger = [bool]$IncludeIdentityLedger; StoreName = [string]$Store.Name }
if ($IdentityStore) { $ra['IdentityInvoke'] = $IdentityStore.Invoke; $ra['IdentityStoreName'] = [string]$IdentityStore.Name }
if ($Pause) { $ra['Pause'] = $Pause }
$result = Invoke-SIDataReset @ra
if ($result.Mode -eq 'refused') { throw ('refused: {0} -- nothing was changed' -f $result.Refused) }
if ($result.Mode -eq 'applied' -and -not $result.ReadBack.Ok) { throw 'the reset did not read back as expected (see the lines above) -- run it again' }
if ($PassThru) { $result }
} finally { Stop-SIScriptRun -Run $siRun }
