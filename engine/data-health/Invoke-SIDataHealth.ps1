#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- the daily DATA HEALTH check (CR2, REQUIREMENTS #656): is SecurityInsight's own data whole and
    right? SecurityInsight only.
.DESCRIPTION
    (a) Per source -- Entra users, Entra apps and service principals, Defender devices, Azure resources, Defender for Cloud
        recommendations -- 10 % of the source's records (at least 50, all when fewer), picked at random every day, are read
        from the source and looked up in SecurityInsight's newest collection: is the record there, and do its key fields
        match?
    (b) 10 % of the devices that hold vulnerability findings (at least 50, random) are asked again from Defender for
        Endpoint and compared with the stored findings, per Risk Analysis report; the same answers give the
        'vulnerabilities' source of (a).
    A source or report is anomalous when more records differ than its margin (Settings: SI_DataHealth_Margin_*). Three
    anomalous days in a row make the data Unhealthy; one good day makes it Healthy again. While Unhealthy every data-out
    channel plans and reports only (engine\_shared\SI-DataHealthHold.ps1); a SuperAdmin may let one channel through with a
    reason on Configuration > Connectors > Data-health hold, until the data is Healthy again.

    🔒 READ-ONLY toward Entra, Defender and Azure, with the rights the collection identity already has (Graph User.Read.All /
    Application.Read.All; Defender Machine.Read.All + Vulnerability.Read.All; Azure Reader). It writes only its own tables
    in the Pro database (cfg.DataHealth*). A source that cannot be read is NOT CHECKED with the reason -- never "ok".

    Runs inside the verification job (caj-si-verification), after the verification checks; its own run-health records
    (engine 'data-health'). Settings: SI_DataHealth_Enabled (default on), SI_DataHealth_Margin_* / _MarginMinimum,
    SI_Telemetry_SendHealth (the health record to Invardia; on by default, $false turns it off, framework §12.22).
.PARAMETER DryRun
    Run the checks and print the result; store nothing, send nothing.
#>
[CmdletBinding()]
param([switch]$DryRun, [AllowNull()]$Seed)
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
Write-Host '[STEP] SecurityInsight -- data health: is the newest collection whole and right?' -ForegroundColor Cyan
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
if (-not (Assert-SIFeatureOrSkip -Feature 'data-backend')) { return }

. (Join-Path $here '_shared\SI-DataHealth.ps1')
. (Join-Path $here '_shared\SI-DataHealthStore.ps1')
. (Join-Path $here '_shared\SI-DataHealthRun.ps1')
if (-not (Test-SIDataHealthEnabled)) { Write-Host '[INFO] The data health check is switched off (SI_DataHealth_Enabled) -- nothing is checked, nothing is held.'; return }

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-AzRest.ps1') }
if (-not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataSql.ps1') }
if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1') }
if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
if (-not (Get-Command -Name Resolve-SIAzurePlacement -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\data-model\SI-AzureChildren.ps1') }

if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

$log = {
    param([string]$level, [string]$msg)
    switch ($level) { 'OK' { Write-Host "[OK]   $msg" -ForegroundColor Green } 'WARN' { Write-Host "[WARN] $msg" -ForegroundColor Yellow } default { Write-Host "[INFO] $msg" -ForegroundColor Gray } }
}

$server = ''; $database = ''
foreach ($pair in @(@('SI_ProSqlServer', 'SI_ProSqlDatabase'), @('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'))) {
    $s = "$(Get-Variable -Name $pair[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
    $d = "$(Get-Variable -Name $pair[1] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
    if ($s -and $d) { $server = $s; $database = $d; break }
}
$invoke = $null
if ($server -and $database) { $invoke = New-SIDataSqlInvoke -Server $server -Database $database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint }
else { & $log 'WARN' 'No Pro database (SI_ProSqlServer / SI_ProSqlDatabase) -- the newest collection cannot be read; nothing is checked.' }

# ---- THE READS (each one source; read-only). A partial read is NOT a read: it would show every record it missed as missing ----
$paged = {
    param([string]$url, [string]$resource, [string]$label)
    $r = Invoke-SIPagedRest -Url $url -Token (Get-SIGraphToken -Resource $resource) -SourceLabel $label
    if (-not $r.Complete) { throw $r.Error }
    @($r.Rows)
}
$firstParty = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
$includeFirstParty = $true; if ($null -ne $global:SI_IncludeFirstPartySpns) { $includeFirstParty = [bool]$global:SI_IncludeFirstPartySpns }
$sources = @{
    'entra-users' = {
        foreach ($u in (& $paged 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled,createdDateTime&$top=999' 'Graph' 'Entra /users')) {
            [pscustomobject]@{ Key = 'entra:' + ([string]$u.id).ToLowerInvariant(); Name = [string]$u.userPrincipalName; Created = $u.createdDateTime
                               Values = @{ userPrincipalName = $u.userPrincipalName; accountEnabled = $u.accountEnabled } }
        }
    }
    'entra-apps' = {
        foreach ($sp in (& $paged 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,createdDateTime&$top=999' 'Graph' 'Entra /servicePrincipals')) {
            # the same scope as the collection: Microsoft's own service principals only when SI_IncludeFirstPartySpns is on
            if (-not $includeFirstParty -and [string]$sp.appOwnerOrganizationId -eq $firstParty) { continue }
            [pscustomobject]@{ Key = 'entra:' + ([string]$sp.id).ToLowerInvariant(); Name = [string]$sp.displayName; Created = $sp.createdDateTime
                               Values = @{ appId = $sp.appId; accountEnabled = $sp.accountEnabled } }
        }
    }
    'devices' = {
        foreach ($m in (& $paged 'https://api.securitycenter.microsoft.com/api/machines' 'Defender' 'Defender /api/machines')) {
            [pscustomobject]@{ Key = 'mde:' + ([string]$m.id).ToLowerInvariant(); Name = [string]$m.computerDnsName; Created = $m.firstSeen
                               Values = @{ aadDeviceId = $m.aadDeviceId } }
        }
    }
    'azure' = {
        # the same scope as the collection: only the Azure types that become CIs (collection-scope; a child resource is a
        # part of its parent's record, never a record of its own)
        $scope = Get-SIAzureCiScope
        foreach ($r in @(Search-SIResourceGraph -Query 'resources | project id = tolower(id), name, type = tolower(type), location = tolower(location), created = todatetime(properties.timeCreated)')) {
            $pl = Resolve-SIAzurePlacement -Id ([string]$r.id) -Type ([string]$r.type) -Object $r -Scope $scope
            if ($pl.Action -ne 'record') { continue }
            [pscustomobject]@{ Key = 'azure:' + [string]$r.id; Name = [string]$r.name; Created = $r.created; Values = @{ type = $r.type; location = $r.location } }
        }
    }
    'mdc' = {
        $scope = Get-SIAzureCiScope
        # Changed (#747): the newest status change of the resource's assessments -- a count that differs because an assessment
        # changed after the collection is drift, not a defect
        $q = "securityresources | where type =~ 'microsoft.security/assessments' | extend ResourceId = tolower(tostring(properties.resourceDetails.Id)), Status = tostring(properties.status.code), StatusChanged = todatetime(properties.status.statusChangeDate) | where isnotempty(ResourceId) | summarize Unhealthy = countif(Status =~ 'Unhealthy'), Changed = max(StatusChanged) by ResourceId"
        foreach ($r in @(Search-SIResourceGraph -Query $q)) {
            $pl = Resolve-SIAzurePlacement -Id ([string]$r.ResourceId) -Type '' -Object $null -Scope $scope
            if ($pl.Action -ne 'record') { continue }
            [pscustomobject]@{ Key = 'mdc:' + [string]$r.ResourceId; Name = ([string]$r.ResourceId -split '/')[-1]; Created = $null; Modified = $r.Changed; Values = @{ unhealthy = $r.Unhealthy } }
        }
    }
}
# (b): one read per sampled device -- its vulnerabilities as Defender reports them now ($null = the read failed: left out)
$defender = {
    param([string[]]$MdeIds)
    $out = @{}
    $tok = Get-SIGraphToken -Resource Defender
    foreach ($id in @($MdeIds)) {
        try {
            $r = Invoke-SIPagedRest -Url ('https://api.securitycenter.microsoft.com/api/machines/{0}/vulnerabilities' -f $id) -Token $tok -SourceLabel 'Defender machine vulnerabilities'
            # the CVE, the date the report's minimum age is judged by (the vulnerability's last update, else its publication),
            # and its publication (#747: published after the stored collection = it did not exist then -- drift, not a miss)
            $out[$id] = $(if ($r.Complete) { , @($r.Rows | Where-Object { $_ -and [string]$_.id } | ForEach-Object { [pscustomobject]@{ Cve = [string]$_.id; LastModified = $(if ($_.updatedOn) { $_.updatedOn } else { $_.publishedOn }); Published = $_.publishedOn } }) } else { $null })
        } catch { $out[$id] = $null }
    }
    $out
}

# ---- (b) like with like: each report's OWN exclusions (excluded CVEs, the CVE minimum age, excluded configuration ids) through
#      Risk Analysis's one scope reader -- RA-ScopePreamble.ps1 Get-RAReportActiveScope + Test-RAInScopeFinding, never a copy.
#      Exclusions that cannot be read = every CVE is expected (said once; nothing is hidden from the check).
$inScope = $null
try {
    foreach ($dep in 'engine\_shared\SI-Yaml.ps1', 'engine\data-model\SI-DataModelTemplates.ps1', 'engine\_shared\SI-DisabledAssets.ps1') {
        $p = Join-Path $siRoot $dep; if (Test-Path -LiteralPath $p) { . $p }
    }
    if (-not (Get-Command -Name Get-SIItemValue -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\data-model\SI-Conditions.ps1') }
    . (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')
    if (-not (Get-Command -Name Write-Info -ErrorAction SilentlyContinue)) { function Write-Info ($msg) { } }
    if (-not (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue)) { function Write-Warn2 ($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow } }
    . (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-ExcludeLists.ps1')
    # the report exclusion files live beside the Risk Analysis catalog (a Pro install's database copy, SI_ProRaSettingsPath, wins)
    if ([string]::IsNullOrWhiteSpace([string]$global:SettingsPath) -or -not (Test-Path -LiteralPath (Join-Path ([string]$global:SettingsPath) 'RiskAnalysis_Queries_Locked.yaml'))) {
        $global:SI_DataHealthRaSettingsPath = Join-Path $siRoot 'risk-analysis-detection'
    }
    $scopeCache = @{}
    $inScope = {
        param([string]$Report, [string]$Cve, $LastModified)
        if (-not $scopeCache.ContainsKey($Report)) {
            $saved = $global:SettingsPath
            try {
                if ($global:SI_DataHealthRaSettingsPath) { $global:SettingsPath = $global:SI_DataHealthRaSettingsPath }
                $scopeCache[$Report] = Get-RAReportActiveScope -ReportName $Report
            } catch {
                & $log 'INFO' ('the exclusions of {0} could not be read ({1}) -- every vulnerability of it is expected' -f $Report, $_.Exception.Message)
                $scopeCache[$Report] = $null
            } finally { $global:SettingsPath = $saved }
        }
        $a = $scopeCache[$Report]
        if ($null -eq $a) { return $true }
        Test-RAInScopeFinding -Active $a -Cve $Cve -ConfigurationId $Cve -LastModified $LastModified
    }
} catch { & $log 'INFO' ('the reports'' exclusions could not be loaded ({0}) -- every vulnerability is expected' -f $_.Exception.Message); $inScope = $null }

# ---- the health record for Invardia (counts only; behind SI_Telemetry_SendHealth, ON by default -- framework §12.22) ----
# Every way the record does NOT go out is said in one line (Get-SIDataHealthSendSkipReason): the switch off, telemetry off,
# a dry run, or an install that is not identified -- with what it lacks (Get-SITelemetryContext's AnonymousReason).
$tctx = $null; $send = $null; $tskip = ''
$sendOn = [bool](Test-SIDataHealthSendEnabled)
if ($DryRun -or -not $sendOn) { $tskip = Get-SIDataHealthSendSkipReason -SendEnabled $sendOn -DryRun:$DryRun }
else {
    try {
        if (-not (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-TelemetrySend.ps1') }
        # Started with `&` from a script that loaded the uplink client, this script would see its functions but not its
        # address and codes (file-level state of THAT script) -- load it here then. (The verification engine dot-sources
        # this script, so there the state is already in scope.)
        if (-not (Get-Variable -Name AitUplinkInvardiaEndpoint -Scope Script -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\AitUplink.ps1') }
        if ((Test-SITelemetryEnabled)) {
            $tctx = Get-SITelemetryContext
            $send = { param($Record) Send-SITelemetryUplink -Record $Record -Endpoint $tctx.Endpoint -AccessCode $tctx.AccessCode -TimeoutSec 5 }
        } else { $tskip = Get-SIDataHealthSendSkipReason -SendEnabled $true -TelemetryEnabled $false }
    } catch { $tctx = $null; $send = $null; $tskip = Get-SIDataHealthSendSkipReason -SendEnabled $true -ContextError $_.Exception.Message }
}

# ---- run health (SI_RunHealth_CL): START now, END once in the finally ----
$runContext = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'data-health'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
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
    $res = Invoke-SIDataHealthCycle -Sources $sources -Defender $defender -Invoke $invoke -InScope $inScope -DryRun:$DryRun -Seed $Seed -TelemetryContext $tctx -SendTelemetry $send -TelemetrySkipReason $tskip -Log $log
    $rhEnd = Get-SIDataHealthOutcome -Result $res
    & $log $(if ($res.Coverage) { 'WARN' } else { 'OK' }) ('data health done: {0}{1}{2}{3}' -f $res.State.State, $(if ($res.Coverage) { " -- $($res.Coverage)" } else { '' }), $(if ($res.Written) { " -- stored as cycle $($res.CycleId)" } elseif ($DryRun) { ' (DRY RUN -- nothing stored)' } else { '' }),
        $(if ($res.Telemetry -ne 'not-sent') { " -- health record to Invardia: $($res.Telemetry)" } else { '' }))
    $global:SI_DataHealthResult = $res
} catch {
    $rhEnd = @{ Exit = 'failed'; Message = [string]$_.Exception.Message }
    throw
} finally {
    & $sendHealth 'End' ([string]$rhEnd.Exit) ([string]$rhEnd.Message)
}
