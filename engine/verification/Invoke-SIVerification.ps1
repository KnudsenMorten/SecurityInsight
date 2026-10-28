#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- the VERIFICATION SERVICE: finds the settings and plans SecurityInsight's data depends on that
    are NOT enabled in the Microsoft estate (docs/V3-DATA-MODEL.md 2.11).
.DESCRIPTION
    The checks (config\verification-checks.locked.json): Defender for Cloud plans off per subscription, Azure VMs and
    active Entra devices without a Defender for Endpoint sensor, sensors not reporting, operating systems out of support,
    no AWS / GCP connector, empty Advanced Hunting tables, sign-in / audit logs not reaching the security workspace,
    SecurityInsight collectors that did not complete. Each finding can be IGNORED or ACCEPTED in the web app
    (Operations > Verification (data gaps)) with who, when and why, and is due for review after 180 days.

    🔒 READ-ONLY toward Defender for Endpoint, Defender for Cloud, Entra and Azure: it only reads, with the permissions the
    collection identity already has (Resource Graph = Reader; /api/machines = Machine.Read.All; /devices =
    Device.Read.All; Advanced Hunting = ThreatHunting.Read.All; Log Analytics = Log Analytics Reader). It writes only its
    own tables in the Pro database (cfg.Verification*).

    A source that cannot be read makes the checks that need it NOT CHECKED with the reason (run health:
    success-partial) -- never 'no gaps', and the findings it found before stay as they were.

    Settings (config, or the Pro settings database):
        SI_ProSqlServer / SI_ProSqlDatabase      the Pro database (SI_Pro_DataSqlServer / ...Database win when set)
        SI_DefenderWorkspaceResourceId           the security workspace with the sign-in logs (else SI_WorkspaceResourceId)
        SI_WorkspaceResourceId                   SecurityInsight's workspace (run health)
        SI_ActiveStaleDays                       a device not seen for this many days is stale, not a gap (default 30)
.PARAMETER DryRun
    Run the checks and print the gaps; store nothing.
#>
[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
Write-Host '[STEP] SecurityInsight -- verification: data-collection gaps' -ForegroundColor Cyan
# THE LICENCE GATE COMES FIRST: the verification service is part of the Pro data backend.
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
if (-not (Assert-SIFeatureOrSkip -Feature 'data-backend')) { return }

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Resolve-SIV3WorkspaceId -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-V3Snapshot.ps1') }
if (-not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataSql.ps1') }
if (-not (Get-Command -Name Invoke-SIHuntingQuery -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1') }
if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1') }
if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
. (Join-Path $here '_shared\SI-Verification.ps1')
. (Join-Path $here '_shared\SI-VerificationStore.ps1')
. (Join-Path $here '_shared\SI-VerificationRun.ps1')

if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

$log = {
    param([string]$level, [string]$msg)
    switch ($level) { 'OK' { Write-Host "[OK]   $msg" -ForegroundColor Green } 'WARN' { Write-Host "[WARN] $msg" -ForegroundColor Yellow } default { Write-Host "[INFO] $msg" -ForegroundColor Gray } }
}
$catalog = Get-SIVerificationCatalog -Path (Join-Path $siRoot 'config\verification-checks.locked.json')
$stale = 30
if ("$($global:SI_ActiveStaleDays)" -match '^\d+$' -and [int]$global:SI_ActiveStaleDays -gt 0) { $stale = [int]$global:SI_ActiveStaleDays }

$server = ''; $database = ''
foreach ($pair in @(@('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'), @('SI_ProSqlServer', 'SI_ProSqlDatabase'))) {
    $s = "$(Get-Variable -Name $pair[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
    $d = "$(Get-Variable -Name $pair[1] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
    if ($s -and $d) { $server = $s; $database = $d; break }
}
$invoke = $null
if ($server -and $database) { $invoke = New-SIDataSqlInvoke -Server $server -Database $database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint }
else { & $log 'WARN' 'No Pro database (SI_ProSqlServer / SI_ProSqlDatabase) -- the gaps are printed, not stored.' }

# ---- THE READS (each one source; read-only) ----
$sources = @{
    Subscriptions = { Search-SIResourceGraph -Query "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name, state = tostring(properties.state)" }
    Pricings      = { Search-SIResourceGraph -Query "securityresources | where type =~ 'microsoft.security/pricings' | project subscriptionId, name, tier = tostring(properties.pricingTier)" }
    Vms           = { Search-SIResourceGraph -Query "resources | where type =~ 'microsoft.compute/virtualmachines' | project id, name, vmId = tostring(properties.vmId), powerState = tostring(properties.extended.instanceView.powerState.code)" }
    Connectors    = { Search-SIResourceGraph -Query "resources | where type =~ 'microsoft.security/securityconnectors' | project id, name, cloud = tostring(properties.environmentName)" }
    Machines      = {
        $r = Invoke-SIPagedRest -Url 'https://api.securitycenter.microsoft.com/api/machines' -Token (Get-SIGraphToken -Resource Defender) -SourceLabel 'MDE /api/machines'
        # a PARTIAL machine list would report every machine it missed as not onboarded -- so partial = not read
        if (-not $r.Complete) { throw $r.Error }
        $r.Rows
    }
    Devices       = {
        $r = Invoke-SIPagedRest -Url 'https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,accountEnabled,approximateLastSignInDateTime&$top=999' -Token (Get-SIGraphToken -Resource Graph) -SourceLabel 'Entra /devices'
        if (-not $r.Complete) { throw $r.Error }
        $r.Rows
    }
    HuntingCount  = {
        param([string]$table)
        # one row on success ('count' always answers); nothing = the read failed (or the table does not exist): unknown
        $rows = @(Invoke-SIHuntingQuery -Query ('{0} | take 1 | count' -f $table) -QueryEngine DefenderGraph)
        if ($rows.Count -eq 0) { return $null }
        $v = $rows[0].Count; if ($null -eq $v) { $v = $rows[0].count }
        [long]$v
    }
}
$secWs = [string]$global:SI_DefenderWorkspaceResourceId
if (-not $secWs) { $secWs = [string]$global:SI_WorkspaceResourceId }
$secWsName = 'the security workspace'
if ($secWs) {
    $secWsName = ('the security workspace {0}' -f ($secWs -split '/')[-1])
    $sources['SignInCounts'] = {
        $parts = @($catalog.signInTables | ForEach-Object { "($_ | where TimeGenerated > ago(1d) | summarize C = count() | extend T = '$_')" })
        $kql = 'union isfuzzy=true ' + ($parts -join ', ') + ' | project T, C'
        $rows = @((Invoke-SIAzOperationalInsightsQuery -WorkspaceId (Resolve-SIV3WorkspaceId -WorkspaceResourceId $secWs) -Query $kql -Wait 300 -ErrorAction Stop).Results)
        $counts = @{}
        foreach ($t in @($catalog.signInTables)) { $counts[[string]$t] = [long]0 }   # isfuzzy: a table that does not exist answers nothing = no rows
        foreach ($r in $rows) { if ($r.T) { $counts[[string]$r.T] = [long]$r.C } }
        $counts
    }
}
if ([string]$global:SI_WorkspaceResourceId) {
    $sources['RunHealth'] = {
        $kql = "SI_RunHealth_CL | where TimeGenerated > ago(26h) | where Phase == 'End' | project TimeGenerated, Engine, ExitReason, ErrorMessage"
        @((Invoke-SIAzOperationalInsightsQuery -WorkspaceId (Resolve-SIV3WorkspaceId -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId)) -Query $kql -Wait 300 -ErrorAction Stop).Results)
    }
}

# ---- run health (SI_RunHealth_CL): START now, END once in the finally ----
$runContext = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'verification'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
$healthFile = Join-Path $siRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'
if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $healthFile)) { try { . $healthFile } catch { & $log 'WARN' ("run health is not recorded: {0}" -f $_.Exception.Message) } }
$sendHealth = {
    param([string]$phase, [string]$exit, [string]$err)
    if ($DryRun -or -not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { return }
    try { Send-SIRunHealthRow -RunContext $runContext -Phase $phase -ExitReason $exit -ErrorMessage $err -NoTelemetry } catch { }
}
$rhEnd = @{ Exit = 'failed'; Message = '' }
& $sendHealth 'Start' '' ''
try {
    $res = Invoke-SIVerificationCore -Catalog $catalog -Sources $sources -Invoke $invoke -StaleDays $stale -WorkspaceName $secWsName -DryRun:$DryRun -Log $log
    $rhEnd = $res.Outcome
    # the hook for the setup telemetry's controls (#491): counts per check, never the customer's object names
    $global:SI_VerificationControls = @($res.Controls)
    $gaps = 0; foreach ($s in @($res.Summary)) { $gaps += [int]$s.Open }
    & $log 'OK' ("done: {0} check(s), {1} open gap(s), {2} not checked{3}" -f @($res.Summary).Count, $gaps, @($res.Summary | Where-Object { $_.State -eq 'not-checked' }).Count, $(if ($res.Written) { " -- stored as run $($res.RunId)" } elseif ($DryRun) { ' (DRY RUN -- nothing stored)' } else { '' }))
    $global:SI_VerificationResult = $res
} catch {
    $rhEnd = @{ Exit = 'failed'; Message = [string]$_.Exception.Message }
    throw
} finally {
    & $sendHealth 'End' ([string]$rhEnd.Exit) ([string]$rhEnd.Message)
    # CR2 (#656): the daily DATA HEALTH check runs in this job, after the verification checks, with its own run-health
    # records (engine 'data-health'). It never fails this job, and this job's result never stops it.
    # DOT-SOURCED, not started with `&`: the shared code this script loaded (the Graph / Defender token, the paged reads,
    # the telemetry sender and the uplink client, through Send-SIRunHealthRow.ps1) keeps its file-level state in THIS
    # script's scope. A script started with `&` gets a scope of its own: it still SEES those functions (so it does not
    # load them again) but not their state -- the first live run (2026-10-15) read no Entra users, apps or Defender
    # devices ("You cannot call a method on a null-valued expression") and reported to Invardia without the install key.
    $dhScript = Join-Path $siRoot 'engine\data-health\Invoke-SIDataHealth.ps1'
    if (Test-Path -LiteralPath $dhScript) {
        try { . $dhScript -DryRun:$DryRun }
        catch { & $log 'WARN' ('The data health check could not finish: {0} -- the verification results above are not affected.' -f $_.Exception.Message) }
    }
    # THE DAILY SERVICENOW CHECK (owner 2026-10-20: "verify table schema matches + get alerts"): every ServiceNow output with an
    # Import Set table -- the connection, the table, its columns against the columns sent, the column mapping -- recorded for
    # the web app's data health page, the heartbeat and the daily mail (engine\asset-cmdb\_shared\SI-SnowVerify.ps1). Reads
    # only; it never fails this job.
    $snowCheck = Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-SnowVerify.ps1'
    if (-not $DryRun -and (Test-Path -LiteralPath $snowCheck) -and (Test-SIFeatureAvailable -Feature 'servicenow-connector').Allowed) {
        try {
            if (-not (Get-Command -Name Read-SIConnectorRows -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-Connector.ps1') }
            . $snowCheck
            $null = Invoke-SISnowChecks -Store (New-SIConnectorRegistryStore) -Trigger daily -Log $log
        } catch { & $log 'WARN' ('The ServiceNow check could not finish: {0} -- the verification results above are not affected.' -f $_.Exception.Message) }
    }
}
