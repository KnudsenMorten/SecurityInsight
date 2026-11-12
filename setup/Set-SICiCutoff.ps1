<#
.SYNOPSIS
    SecurityInsight Pro -- set (or take back) the ONE-TIME CI CUT-OFF: the CI build ignores records collected before it.

.DESCRIPTION
    #1100 (owner 2026-11-04: "is it possible that we can do a one-time cut-off and then ignore older runs?" / "leave it as
    an hidden feature for customer to run from a script or through support app"). A HIDDEN feature: it is not a setting --
    not in the settings catalog, not on the web Settings page, not over MCP. This script is the way to set it.

    WHY: the CI build groups every record collected within its look-back (SI_ActiveStaleDays, default 30 days). Records an
    old collection left behind -- for example accounts a setting now leaves out, no longer collected -- stay "current" for
    that whole window and are rebuilt into CIs every build.

    WHAT THE CUT-OFF DOES (engine\data-model\SI-CiCutoff.ps1, read by every CI build):
      * the look-back's lower bound becomes MAX(now - look-back, cut-off): a record collected before the cut-off is not
        current -- but only for a source (provider + record type) that has collected again since the cut-off; a source
        that has not keeps its records until it has;
      * a CI built ONLY from records collected before the cut-off is RETIRED at once (never deleted), reason
        "one-time cut-off <date>: <reason>", recorded in the CI's change history. A CI that one record collected after
        the cut-off still builds stays active. Records are never deleted (retention removes them as usual);
      * a retired CI reaches data-out like every retired CI: a CMDB output that is on (ServiceNow ...) gets its retired
        row. The plan below says how many CIs would retire and whether such an output is on -- look before -Apply;
      * once the cut-off is older than the look-back it changes nothing any more (the build says so); the record stays.

    THE STATE: one row in the Pro database, cfg.InstallState 'CiCutoff' = { cutoffUtc, setBy, reason, setUtc }. -Clear
    takes it back by writing cleared = true (the row is kept as the record). Every write is read back and written to the
    audit trail (cibuild.cutoff.set / cibuild.cutoff.clear, actor source setup).

    PLAN BY DEFAULT: reads the state, the look-back, the CIs that would retire (a read-only count) and the data-out
    outputs, and writes nothing. -Apply writes (-WhatIf with -Apply still only plans).

    REACHING THE DATABASE: as the install identity (certificate; -SqlServer / -Database, else SI_ProSqlServer /
    SI_ProSqlDatabase), or with -SupportSql through the Invardia Support app's audited Invoke-InvardiaSupportSql (open the
    Support session first). On a PRIVATE install (public network access off) the database is reached only from inside
    its network -- framework rule 11e: this script NEVER opens a firewall rule or public access. It reads the server's
    public network access first (-ResourceGroupName) and refuses on a private install unless it runs inside the network
    (-InsideNetwork: a machine in the install's network, or the install's own job).

    THE SAME SQL THROUGH THE SUPPORT APP BY HAND (no script): the value is compact JSON, at most 400 characters --
        Invoke-InvardiaSupportSql -Server <server> -Database <db> -Reason '<why>' -Query "DECLARE @Value nvarchar(400) =
          N'{""cutoffUtc"":""2026-11-04T08:00:00Z"",""setBy"":""Invardia support"",""reason"":""<why>"",""setUtc"":""<now>Z""}';
          DECLARE @By nvarchar(256) = N'Invardia support'; <the statement of Get-SICiCutoffWriteSql>"
    The script does exactly this with -SupportSql (and writes the audit row and reads the state back) -- prefer it.

.EXAMPLE
    .\setup\Set-SICiCutoff.ps1 -SqlServer <server>.database.windows.net -Database sidb -ResourceGroupName rg-si -Reason 'old account collection no longer in scope'
.EXAMPLE
    .\setup\Set-SICiCutoff.ps1 -SqlServer <server>.database.windows.net -Database sidb -ResourceGroupName rg-si -CutoffUtc '2026-11-04T03:00:00Z' -Reason 'old account collection no longer in scope' -Apply
.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'one-time CI cut-off'
    .\setup\Set-SICiCutoff.ps1 -SqlServer <server> -Database <db> -ResourceGroupName <rg> -SupportSql -Reason 'old account collection no longer in scope' -Apply
.EXAMPLE
    .\setup\Set-SICiCutoff.ps1 -SqlServer <server>.database.windows.net -Database sidb -InsideNetwork -Clear -Reason 'the cut-off is no longer wanted' -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SICiCutoff/
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # The cut-off (UTC; a time without a zone is taken as UTC). Default: now. Never in the future, never older than the look-back.
    [datetime]$CutoffUtc,
    # Why (required, at least 10 characters): in the state row, on every CI it retires and on the audit trail.
    [Parameter(Mandatory)][string]$Reason,
    # Take the cut-off back (the row is kept, marked cleared).
    [switch]$Clear,
    # Write. Without it the script only plans.
    [switch]$Apply,
    [string]$SqlServer = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    # The install's resource group: its database server's public network access is read first (a private install is refused).
    [string]$ResourceGroupName = [string]$global:SI_Bootstrap_ResourceGroupName,
    [string]$SubscriptionId,
    # This runs INSIDE the install's network (a machine in it, or the install's own job): the private check is not needed.
    [switch]$InsideNetwork,
    # Reach the database through the Invardia Support app's audited SQL (Invoke-InvardiaSupportSql; open the session first).
    [switch]$SupportSql,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    # TEST SEAM: { } -> the database server's public network access ('Enabled' | 'Disabled' | ...), instead of reading it from Azure.
    [scriptblock]$NetworkAccess,
    [switch]$PassThru
)

#Requires -Version 7.0   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SICiCutoff' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
if ($WhatIfPreference) { $Apply = $false }   # -WhatIf = the preview: nothing is written
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'engine', 'data-model', 'SI-CiCutoff.ps1'))

$why = ([string]$Reason).Trim()
if ($why.Length -lt 10) { throw 'say why (-Reason, at least 10 characters): it is kept with the cut-off, on every CI it retires and on the audit trail' }
if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
$nowUtc = [datetime]::UtcNow
if ($Clear -and $PSBoundParameters.ContainsKey('CutoffUtc')) { throw '-Clear takes the cut-off back: give no -CutoffUtc with it' }
if ($PSBoundParameters.ContainsKey('CutoffUtc')) {
    $cut = switch ($CutoffUtc.Kind) { 'Local' { $CutoffUtc.ToUniversalTime() } 'Utc' { $CutoffUtc } default { [datetime]::SpecifyKind($CutoffUtc, [DateTimeKind]::Utc) } }
} else { $cut = $nowUtc }
$cut = [datetime]::SpecifyKind($cut, [DateTimeKind]::Utc)
if ($cut -gt $nowUtc.AddMinutes(5)) { throw ('the cut-off {0} is in the future: a cut-off says which records are OLD -- give a time that has passed' -f (Format-SICiCutoffTime $cut)) }

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
        if ($null -eq $shape) { throw ('the database server {0} was not found in {1} -- nothing was read or written' -f $srvShort, $ResourceGroupName) }
        $pna = [string]$shape.PublicNetworkAccess
    }
    if ($null -ne $pna) {
        $p = $pna.Trim()
        # an empty value is a server made before the setting existed: public
        if (-not ($p -eq '' -or $p -ieq 'Enabled')) {
            throw ('this install is private (public network access {0}): its database {1} is reached only from inside its network -- framework rule 11e; nothing was opened, read or written. Run it inside the network (-InsideNetwork, on a machine in the install''s network) or through the install''s job.' -f $p, $(if ($srvShort) { $srvShort } else { 'server' }))
        }
    }
}

# ---- THE DATABASE --------------------------------------------------------------------------------------------------
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-Audit.ps1'))
if (-not $Store) {
    if (-not $SqlServer -or -not $Database) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
    if ($SupportSql) {
        if (-not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) { throw '-SupportSql needs the Invardia Support session (Connect-InvardiaSupport.ps1) open in this shell: Invoke-InvardiaSupportSql was not found' }
        $sqlArgs = @{ Server = $(if ($SqlServer -match '\.') { $SqlServer } else { $SqlServer + '.database.windows.net' }); Database = $Database; Reason = ('SecurityInsight one-time CI cut-off: ' + $why) }
        # Invoke-InvardiaSupportSql takes no parameters: each one is DECLAREd before the statement, as a literal. The
        # statements are the same text as on the direct path.
        $supInvoke = {
            param([string]$sql, $params, [string]$mode)
            $decl = New-Object System.Text.StringBuilder
            if ($params) {
                foreach ($k in @($params.Keys)) {
                    $v = $params[$k]
                    if ($k -notmatch '^[A-Za-z][A-Za-z0-9_]{0,63}$') { throw "not a parameter name: $k" }
                    if ($null -eq $v) { [void]$decl.AppendLine("DECLARE @$k NVARCHAR(MAX) = NULL;") }
                    elseif ($v -is [bool]) { [void]$decl.AppendLine(("DECLARE @{0} BIT = {1};" -f $k, [int]$v)) }
                    elseif ($v -is [int] -or $v -is [long]) { [void]$decl.AppendLine(("DECLARE @{0} BIGINT = {1};" -f $k, [long]$v)) }
                    else { [void]$decl.AppendLine(("DECLARE @{0} NVARCHAR(MAX) = N'{1}';" -f $k, ([string]$v).Replace("'", "''"))) }
                }
            }
            $res = Invoke-InvardiaSupportSql @sqlArgs -Query ($decl.ToString() + $sql)
            $rows = @(@(if ($null -ne $res -and $res.PSObject.Properties['Rows']) { $res.Rows } else { $res }) | Where-Object { $null -ne $_ })
            if ($mode -eq 'scalar') {
                if (-not $rows.Count) { return $null }
                $r0 = $rows[0]
                if ($r0 -is [System.Data.DataRow]) { return $r0.ItemArray[0] }
                return @($r0.PSObject.Properties)[0].Value
            }
            , @($rows)
        }.GetNewClosure()
        $Store = [pscustomobject]@{ Name = ('{0}/{1} (Invardia Support app)' -f $sqlArgs.Server, $Database); Invoke = $supInvoke }
    } else {
        $Store = New-SIProSettingsStore -Server $SqlServer -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
    }
}
$rowsOf = { param([string]$sql, $p) @(& $Store.Invoke $sql $(if ($p) { $p } else { @{} }) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
$valOf = { param($row, [string]$name) if ($null -eq $row) { $null } elseif ($row -is [System.Collections.IDictionary]) { $row[$name] } elseif ($row.PSObject.Properties[$name]) { $row.$name } else { $null } }

# ---- WHAT IS THERE: the state, the look-back, the data-out outputs ----------------------------------------------------
$stRows = @(& $rowsOf (Get-SICiCutoffReadSql))
$oldValue = if ($stRows.Count) { [string](& $valOf $stRows[0] 'Value') } else { $null }
$old = ConvertFrom-SICiCutoffValue -Value $oldValue
$setRows = & $rowsOf @'
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL
    SELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name IN (N'SI_ActiveStaleDays', N'SI_DataOut_Outputs');
'@
$settings = @{}; foreach ($s in $setRows) { $settings[[string](& $valOf $s 'Name')] = [string](& $valOf $s 'ValueJson') }
$lookback = 30
$lbText = [string]$settings['SI_ActiveStaleDays']
if ($lbText) { $n = 0; if ([int]::TryParse($lbText.Trim().Trim('"'), [ref]$n) -and $n -gt 0) { $lookback = $n } }
if (-not $Clear -and $cut -le $nowUtc.AddDays(-$lookback)) { throw ('the cut-off {0} is older than the look-back ({1} day(s)): it would change nothing' -f (Format-SICiCutoffTime $cut), $lookback) }

# data-out: the outputs that write somewhere else than a file (a CMDB / ServiceNow ...) and are on at this install
$dataOut = @()
try {
    $cat = @(([IO.File]::ReadAllText([IO.Path]::Combine($siRoot, 'config', 'data-out.locked.json')) | ConvertFrom-Json).outputs)
    $chosen = @()
    $dv = [string]$settings['SI_DataOut_Outputs']
    if ($dv) {
        $parsed = $null; try { $parsed = $dv | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $dv }
        $chosen = @(@($parsed) | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
    foreach ($e in $cat) {
        if ([string]$e.kind -in 'excel', 'fixed') { continue }
        if (@($e.editions) -notcontains 'pro') { continue }
        $on = [bool]$e.default -or (@($e.PSObject.Properties['defaultEditions'] | ForEach-Object { $_.Value }) -contains 'pro')
        if ($chosen.Count) { $on = $chosen -contains [string]$e.output }
        if ($on) { $dataOut += [string]$e.output }
    }
} catch { Write-Host ('[WARN] the data-out outputs could not be read ({0}) -- check Configuration > Connectors before -Apply.' -f $_.Exception.Message) -ForegroundColor Yellow; $dataOut = $null }

$result = [pscustomobject]@{ Mode = 'plan'; Clear = [bool]$Clear; CutoffUtc = $cut; LookbackDays = $lookback; WouldRetire = $null; UpperBound = $null; RecordsIgnored = $null
    FeedsWaiting = $null; DataOut = $dataOut; DataOutOn = [bool]($dataOut -and @($dataOut).Count); Previous = $old; Value = $null; ReadBack = $null; Audited = $false }

Write-Host ('One-time CI cut-off at {0}' -f $Store.Name)
if ($old) {
    Write-Host ('  now set   : {0} by {1} -- {2}{3}' -f (Format-SICiCutoffTime $old.CutoffUtc), $old.SetBy, $old.Reason, $(if ($old.Cleared) { ' (CLEARED)' } else { '' }))
} else { Write-Host '  now set   : none' }
Write-Host ('  look-back : {0} day(s) (SI_ActiveStaleDays)' -f $lookback)
if ($null -eq $dataOut) { Write-Host '  data-out  : could not be read' }
elseif (@($dataOut).Count) { Write-Host ('  data-out  : ON at this install ({0}) -- every CI the cut-off retires is sent there as a retired row' -f (@($dataOut) -join ', ')) -ForegroundColor Yellow }
else { Write-Host '  data-out  : no CMDB / ServiceNow output is on at this install -- a retired CI stays in SecurityInsight only' }

if ($Clear) {
    if (-not $old -or $old.Cleared) {
        Write-Host '[INFO] there is no cut-off to take back -- nothing to do.'
        $result.Mode = 'nothing'
        if ($PassThru) { return $result }
        return
    }
    Write-Host '[PLAN] the cut-off would be taken back (the row stays, marked cleared). A CI it already retired stays retired until a source records it again.'
    $newValue = ConvertTo-SICiCutoffValue -CutoffUtc $old.CutoffUtc -Reason $why -SetBy (Get-SIAuditActor) -SetUtc $nowUtc -Cleared
} else {
    # the CIs that would retire: the build's own rule, read only
    try {
        $pl = @(& $rowsOf (Get-SICiCutoffRetireSql -CutoffUtc $cut -LookbackDays $lookback -PlanOnly)) | Select-Object -First 1
        $result.WouldRetire = [int](& $valOf $pl 'Retired'); $result.UpperBound = [int](& $valOf $pl 'UpperBound')
        $result.RecordsIgnored = [int](& $valOf $pl 'RecordsIgnored'); $result.FeedsWaiting = [int](& $valOf $pl 'FeedsWaiting')
        Write-Host ('[PLAN] cut-off {0} ({1}): {2} record(s) before it would be ignored; {3} CI(s) would retire at the next CI build{4}.' -f `
            (Format-SICiCutoffTime $cut), $why, $result.RecordsIgnored, $result.WouldRetire, $(if ($result.UpperBound -gt $result.WouldRetire) {
                ('; up to {0} once the {1} source(s) not collected since the cut-off have collected again' -f $result.UpperBound, $result.FeedsWaiting) } else { '' }))
    } catch {
        Write-Host ('[WARN] the CIs that would retire could not be counted ({0}) -- the CMDB impact is not known.' -f $_.Exception.Message) -ForegroundColor Yellow
    }
    $newValue = ConvertTo-SICiCutoffValue -CutoffUtc $cut -Reason $why -SetBy (Get-SIAuditActor) -SetUtc $nowUtc
}
$result.Value = $newValue

$write = $Apply -and $PSCmdlet.ShouldProcess($Store.Name, $(if ($Clear) { 'take back the one-time CI cut-off' } else { 'set the one-time CI cut-off ' + (Format-SICiCutoffTime $cut) }))
if (-not $write) {
    Write-Host '[PLAN] nothing was written. Run again with -Apply to write.'
    if ($PassThru) { return $result }
    return
}

# ---- WRITE, READ BACK, AUDIT ------------------------------------------------------------------------------------------
$by = Get-SIAuditActor
$w = @(& $rowsOf (Get-SICiCutoffWriteSql) @{ Value = $newValue; By = ('setup: ' + $by) }) | Select-Object -First 1
$outcome = [string](& $valOf $w 'Outcome')
if ($outcome -eq 'NoTable') { throw 'this database has no cfg.InstallState yet (apply sql\si-pro-settings.sql -- it only adds)' }
$back = [string](& $valOf $w 'Value')
# read back once more on its own (the write's answer and the stored row must agree)
$again = @(& $rowsOf (Get-SICiCutoffReadSql))   # @(): one row back is ONE hashtable, and [0] on it reads key 0 (found live 2026-11-04)
$stored = if ($again.Count) { [string](& $valOf $again[0] 'Value') } else { '' }
if ($outcome -ne 'Written' -or $back -ne $newValue -or $stored -ne $newValue) {
    throw ('the cut-off was NOT read back as written (answer {0}; stored {1}) -- check cfg.InstallState ''CiCutoff''' -f $outcome, $(if ($stored) { $stored } else { 'nothing' }))
}
$result.ReadBack = $stored
$result.Mode = 'applied'
$action = if ($Clear) { 'cibuild.cutoff.clear' } else { 'cibuild.cutoff.set' }
$result.Audited = [bool](Write-SIAuditEvent -Store $Store -Action $action -Actor $by -ActorSource 'setup' -Target '/cfg/InstallState/CiCutoff' -Reason $why `
        -OutcomeText ('Set-SICiCutoff: {0}' -f $(if ($Clear) { 'the one-time CI cut-off taken back' } else { ('one-time CI cut-off {0}; {1} CI(s) counted to retire; data-out {2}' -f (Format-SICiCutoffTime $cut), $(if ($null -ne $result.WouldRetire) { $result.WouldRetire } else { 'not' }), $(if ($result.DataOutOn) { 'on: ' + (@($dataOut) -join ', ') } else { 'off' })) })) `
        -Before $(if ($oldValue) { [ordered]@{ value = $oldValue } } else { $null }) -After ([ordered]@{ value = $newValue; wouldRetire = $result.WouldRetire; dataOut = @($dataOut) }))
if ($Clear) { Write-Host '[OK]   the one-time CI cut-off is taken back (read back; the row is kept, marked cleared).' -ForegroundColor Green }
else { Write-Host ('[OK]   one-time CI cut-off {0} written and read back. The next CI build applies it and says so in its log.' -f (Format-SICiCutoffTime $cut)) -ForegroundColor Green }
if (-not $result.Audited) { Write-Host '[WARN] the audit trail row could not be written (see the warning above) -- the cut-off itself is stored.' -ForegroundColor Yellow }
if ($PassThru) { $result }
} finally { Stop-SIScriptRun -Run $siRun }
