#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- THE MAIL JOB (both editions): the mails every install sends (the mail check, the safety-check mails,
    the outbox the web app fills) and, where the licence covers it, the vulnerability close-loop's DAILY MAIL: what was
    opened, closed and reopened in the last 24 hours, what is open now by severity and asset tier, the mean time to fix,
    and the items themselves.
.DESCRIPTION
    Reads the close-loop's own record in SQL (vuln.VulnerabilityItem / vuln.VulnerabilityEvent, plus the Pro data
    backend's asset tiers and daily statistics when they exist) and sends one HTML mail in the Risk Analysis mail's
    style, through the Risk Analysis SMTP transports. A day without change sends a short "nothing changed" mail.

    Settings (config, or the Pro settings database -- edited on the web app's e-mail settings page):
        Mail_CloseLoop_Daily_SendMail     $true to send (off by default)
        Mail_CloseLoop_Daily_To           the recipients
        Mail_CloseLoop_Daily_SendTimeUtc  HH:mm, UTC -- when the container job runs (default 10:45, after the
                                          close-loop at 10:00); a changed time takes effect when setup is re-run
        SmtpServer / SMTPPort / SMTP_UseSSL / SMTPFrom / SMTPUser / SMTPPassword / Mail_SendAnonymous -- the same
                                          relay settings as the Risk Analysis mail
        SI_VulnSync_SqlServer / SI_VulnSync_SqlDatabase -- the close-loop's database
        SIWeb_PublicBaseUrl               the web app's address, for the link to its close-loop page (read from
                                          the Pro settings when it is not in the config)
    Sign-in to SQL: the container job's managed identity, else the engine SPN by certificate (read only:
    db_datareader in the close-loop's database).

    The same job then sends the EXEMPTION MAILS (#252, engine\asset-cmdb\_shared\SI-ExemptionMail.ps1): the outbox the
    web app fills (requests, decisions), the expiry warnings and the monthly review to each security domain's owners.
    It needs SI_ProSqlServer / SI_ProSqlDatabase and writes only cfg.ExemptionMail.

    Off, or no recipients: one line saying so, and the run ends successfully. A mail that cannot be sent FAILS the run
    with the relay's error.
.PARAMETER Top
    How many newly opened and closed items the mail lists (most severe first). Default 15.
.PARAMETER DryRun
    Build the mail and save it to a file; do not send it.
#>
[CmdletBinding()]
param(
    [int]$Top = 15,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

function Write-MailStep ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-MailInfo ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-MailOk   ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-MailWarn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)

Write-MailStep 'SecurityInsight -- the mail job'
# THE ONE MAIL JOB OF EVERY INSTALL (framework PRO-COMMUNITY-SAME, owner 2026-11-11): the same job in both editions. It sends
# the mails every install sends -- the mail check (SI_MAIL_VERIFY), the safety-check mails (the guard outbox), the outbox the
# web app fills (the Get Started reminder, sign-ins, report mails, the test mail, exemption requests and decisions) -- and,
# ONLY where the licence covers them, the paid kinds: the vulnerability close-loop's daily mail and the ServiceNow checks
# ('servicenow-connector'), the exemption expiry warnings and monthly reviews, the department reports, the governance mails
# and the task digest ('governance'). Each paid kind asks the licence at run time; an unlicensed kind is one line, never a
# failed run.
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
$outboxOnlyRun = ("$env:SI_EXEMPTION_MAIL_ONLY".Trim() -eq '1')
# The business owners' monthly report (#254), the governance mails (#254 phases 2 + 3) and the daily task digest (#265): each
# has its own licence gate and its own rule; they run at the end, after the mails above them. Paid files that this package
# does not carry are simply not due.
$deptReport = Join-Path $siRoot 'engine\pro-data\Invoke-SIDepartmentReport.ps1'
$deptReportDue = (-not $outboxOnlyRun) -and (Test-Path -LiteralPath $deptReport)
$govMail = Join-Path $siRoot 'engine\pro-data\Invoke-SIGovernanceMail.ps1'
$govMailDue = Test-Path -LiteralPath $govMail
$govOutboxOnly = $outboxOnlyRun
$taskDigest = Join-Path $siRoot 'engine\pro-data\Invoke-SITaskDigest.ps1'
$taskDigestDue = (-not $govOutboxOnly) -and (Test-Path -LiteralPath $taskDigest)
# the paid kinds, asked once per run (the free mails below never ask)
$closeLoopLicensed = [bool](Test-SIFeatureAvailable -Feature 'servicenow-connector').Allowed
$governanceLicensed = [bool](Test-SIFeatureAvailable -Feature 'governance').Allowed

. (Join-Path $here '_shared\SI-CloseLoopMail.ps1')
# #252: the exemption mails ride on this job (the outbox, expiry warnings, the monthly review).
. (Join-Path $here '_shared\SI-ExemptionMail.ps1')
# MAIL-1: the one mail transport (Send-SIMail: the shared mailbox over Microsoft Graph, or SMTP through the Risk Analysis
# transports Send-MailAnonymous / Send-MailSecure -- reused, not copied).
. (Join-Path $siRoot 'engine\_shared\SI-MailTransport.ps1')
. (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-Mail.ps1')
# The SQL seam of the data backend: managed identity in a container, else the engine SPN's certificate.
. (Join-Path $siRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
# The tenant in the subject: '<primary domain> (<tenant id>)' (#243). The domain may be read from Microsoft Graph
# (/organization) as the job's identity, so the token helper and the Graph client are loaded; a failure to load them
# only means the subject shows the tenant id.
try {
    if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
    if (-not (Get-Command -Name Invoke-SIGraphRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-GraphRest.ps1') }
} catch { Write-Verbose ("Microsoft Graph helpers not loaded: {0}" -f $_.Exception.Message) }

# Same auth bridge as the other Pro engines: platform names -> SI_SPN_*.
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

$globalsNow = @{}
foreach ($v in (Get-Variable -Scope Global)) { $globalsNow[$v.Name] = $v.Value }

$version = ''
try { $version = (Get-Content -LiteralPath (Join-Path $siRoot 'VERSION') -Raw).Trim() } catch { }
$newInvoke = {
    param([string]$server, [string]$database)
    New-SIDataSqlInvoke -Server $server -Database $database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
}

# THE SERVICENOW CHECKS (owner 2026-10-20: "verify connection. verify table schema matches + get alerts"). The web app's
# "Verify" starts one execution of this job with SI_SNOW_VERIFY=<output | all> (SI_SNOW_VERIFY_BY = who asked, and the
# outbox-only switch, so nothing else is sent): it runs only the ServiceNow checks -- the connection, the Import Set table,
# its columns and its column mapping -- with THIS job's identity, which reads the connector's secrets from the install's Key
# Vault (the web app holds no Key Vault right), records each result (cfg.ServiceNowCheck) for the page, and ends. Every daily
# mail carries a line per ServiceNow output whose newest check is not ok (engine\asset-cmdb\_shared\SI-SnowVerify.ps1).
$snowLog = { param([string]$level, [string]$msg) switch ($level) { 'OK' { Write-MailOk $msg } 'WARN' { Write-MailWarn $msg } default { Write-MailInfo $msg } } }
$snowVerify = "$env:SI_SNOW_VERIFY".Trim()
$snowStore = $null
$snowLines = @()
# the ServiceNow checks are part of the licensed ServiceNow connector: asked only where the licence covers it and this package
# carries the connector's files
$snowConnector = Join-Path $here '_shared\SI-Connector.ps1'
$snowVerifyLib = Join-Path $here '_shared\SI-SnowVerify.ps1'
if ($closeLoopLicensed -and (Test-Path -LiteralPath $snowConnector) -and (Test-Path -LiteralPath $snowVerifyLib)) {
    try {
        if (-not (Get-Command -Name Read-SIConnectorRows -ErrorAction SilentlyContinue)) { . $snowConnector }
        . $snowVerifyLib
        $snowStore = New-SIConnectorRegistryStore
    } catch { Write-MailWarn ("servicenow: the ServiceNow checks are not available here -- {0}" -f $_.Exception.Message) }
}
if ($snowVerify) {
    if (-not $closeLoopLicensed) { $null = Assert-SIFeatureOrSkip -Feature 'servicenow-connector'; return }
    if ($snowVerify -notmatch '^(all|servicenow-ci|servicenow-vulnerable-item)$') { Write-MailWarn ("servicenow: '{0}' is not a ServiceNow output -- nothing was checked." -f $snowVerify); return }
    if (-not $snowStore) { Write-MailWarn 'servicenow: no Pro settings database -- the check cannot read the connector or record its result.'; return }
    $null = Invoke-SISnowChecks -Store $snowStore -Trigger verify -Only $snowVerify -RequestedBy ("$env:SI_SNOW_VERIFY_BY".Trim()) -Log $snowLog
    Write-MailInfo 'ServiceNow check only (started by the web app''s Verify) -- nothing else runs.'
    return
}
if ($snowStore) {
    try { $snowLines = @(Get-SISnowCheckMailLines -Rows @(& $snowStore.Invoke (Get-SISnowCheckLatestSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) -On (Get-SISnowOutputsOn -FromGlobal)) }
    catch { Write-MailWarn ("servicenow: the newest ServiceNow checks could not be read for the mail -- {0}" -f $_.Exception.Message) }
}

$smtp = Get-SICloseLoopMailSmtp -Globals $globalsNow
# MAIL-1: with the shared mailbox, the restriction is checked here as THIS job's identity (two sendMail calls with no
# recipient: nothing is delivered) and kept in cfg.InstallState 'MailRestriction' for the web app's Mail card and home
# banner. An Exchange administrator's confirmation (cfg.InstallState 'MailRestrictionAttestation') counts when no other
# mailbox can be tested. SI_MAIL_VERIFY=1 (the web app's "Verify" button) runs only this check.
$mailVerifyOnly = ("$env:SI_MAIL_VERIFY".Trim() -eq '1')
if ($smtp.Mode -eq 'sharedMailbox' -and -not @($smtp.Problems).Count -and -not $DryRun) {
    $mdb = $null; $minv = $null
    try { $mdb = Get-SIExemptionMailDatabase -Globals $globalsNow; if ($mdb) { $minv = & $newInvoke $mdb.Server $mdb.Database } } catch { $minv = $null }
    if ($minv -and -not $smtp.Attestation) {
        try { $att = @(& $minv "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'MailRestrictionAttestation'" @{} 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
              if ($att -and $att.Value) { $smtp.Attestation = [string]$att.Value } } catch { }
    }
    $mr = Get-SIMailRestriction -Settings $smtp -Force
    $lvl = if ($mr.AllowsSend) { 'OK' } else { 'WARN' }
    & { param($l, $m) switch ($l) { 'OK' { Write-MailOk $m } default { Write-MailWarn $m } } } $lvl ("mail      : shared mailbox {0} -- {1}: {2}" -f $smtp.SharedMailbox, $mr.State, $mr.Detail)
    if ($minv) { if (-not (Write-SIMailRestrictionState -Invoke $minv -Restriction $mr -By 'close-loop mail job')) { Write-MailWarn 'mail      : the restriction status could not be saved for the web app' } }
}
if ($mailVerifyOnly) { Write-MailInfo 'mail check only (started by the web app''s Verify) -- nothing else runs.'; return }
$send = {
    param([string[]]$to, [string]$subject, [string]$html)
    if ($smtp.Mode -eq 'sharedMailbox') { Write-MailInfo ("mail      : shared mailbox {0} (Microsoft Graph, this job's identity)" -f $smtp.SharedMailbox) }
    else { Write-MailInfo ("relay     : {0}:{1} (ssl {2}, {3}) from {4}" -f $smtp.Server, $smtp.Port, $smtp.UseSsl, $(if ($smtp.Anonymous) { 'anonymous' } else { 'authenticated as ' + $smtp.User }), $smtp.From) }
    [void](Send-SICloseLoopMail -Smtp $smtp -To $to -Subject $subject -BodyHtml $html)
}
$log = {
    param([string]$level, [string]$msg)
    switch ($level) { 'OK' { Write-MailOk $msg } 'WARN' { Write-MailWarn $msg } default { Write-MailInfo $msg } }
}

# The web app starts one execution with SI_EXEMPTION_MAIL_ONLY=1 right after it queues an exemption request or decision
# mail (#252): that execution sends the exemption outbox only -- the daily close-loop mail goes at its own time.
$outboxOnly = ("$env:SI_EXEMPTION_MAIL_ONLY".Trim() -eq '1')
$res = $null
$closeLoopError = $null
if ($outboxOnly) {
    Write-MailInfo 'exemption outbox only (started by the web app) -- the daily close-loop mail is not part of this run.'
} elseif (-not (Assert-SIFeatureOrSkip -Feature 'servicenow-connector')) {
    # the close-loop daily mail is a licensed kind: one line (above), the free mails below still go
} else {
    try {
        $res = Invoke-SICloseLoopMailCore -Globals $globalsNow -NewInvoke $newInvoke -Send $send -Top $Top -Version $version -DryRun:$DryRun -Log $log -Warnings $snowLines
        if ($DryRun -and $res.Html) {
            $out = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('SI-CloseLoopMail-{0}.html' -f ([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))))
            [IO.File]::WriteAllText($out, $res.Html, (New-Object System.Text.UTF8Encoding($false)))
            Write-MailInfo ("saved     : {0}" -f $out)
        }
    } catch { $closeLoopError = $_ }
}
$global:SI_CloseLoopMailResult = $res

# #252: THE EXEMPTION MAILS -- the outbox (requests to approvers, decisions to requesters), the expiry warnings and the
# monthly review to each domain's owners; through the same Risk Analysis transports (Send-SICloseLoopMail). It runs
# even when the close-loop mail failed or is off; a failed close-loop mail still fails the run afterwards.
Write-MailStep 'SecurityInsight -- exemption mails'
$exSend = {
    # the management summary outbox passes its file (the management presentation) as the 5th argument
    param([string[]]$to, [string]$subject, [string]$html, [bool]$noPdf = $false, [string[]]$attachments = @())
    [void](Send-SICloseLoopMail -Smtp $smtp -To $to -Subject $subject -BodyHtml $html -NoPdf:$noPdf -Attachments $attachments)
}
$exRes = Invoke-SIExemptionMailCore -Globals $globalsNow -NewInvoke $newInvoke -Send $exSend -SmtpReady ((@($smtp.Problems).Count -eq 0) -and -not $smtp.Off) `
    -OutboxOnly:$outboxOnly -NoPlan:(-not $governanceLicensed) -DryRun:$DryRun -Log $log
$global:SI_ExemptionMailResult = $exRes
# #277: the guard events the web app wrote (cfg.GuardEvent, mail / telemetry 'pending') -- the same relay, never fails the job
try {
    . (Join-Path $siRoot 'engine\_shared\SI-Guard.ps1')
    if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
        # the relay is the same one (the Risk Analysis mail settings, read from the same globals)
        $global:SI_GuardOutboxResult = Invoke-SIGuardOutbox -Invoke (& $newInvoke ([string]$global:SI_ProSqlServer) ([string]$global:SI_ProSqlDatabase)) -DryRun:$DryRun -Log $log
    }
} catch { Write-MailWarn ("guards    : the guard outbox could not be sent -- {0}" -f $_.Exception.Message) }

# #254: the business owners' monthly report (its own licence gate and once-a-month rule); a failure fails the run afterwards,
# like the mails above, but never stops them.
$deptReportError = $null
if ($deptReportDue) { try { & $deptReport -DryRun:$DryRun } catch { $deptReportError = $_ } }
$govMailError = $null
if ($govMailDue) { try { & $govMail -OutboxOnly:$govOutboxOnly -DryRun:$DryRun } catch { $govMailError = $_ } }
$taskDigestError = $null
if ($taskDigestDue) { try { & $taskDigest -DryRun:$DryRun } catch { $taskDigestError = $_ } }
# Framework TRUST-1 point 3 (live 2026-11-13): a mail HELD only because its send right could not be checked (Microsoft
# answered nothing usable) is not a proven refusal -- said as a warning with its catalogue code, and the step is not failed
# for it: every mail stays held (none is recorded as sent) and the next run checks again. Any other failure fails as before.
$heldMail = { param($kind, $e) if (Test-SIMailHeldUnreadable -Failure $e) { Write-MailWarn ('{0}: held this run -- the mail send right could not be checked ({1}); nothing was sent and nothing is lost, the next run checks again' -f $kind, $(if ($e -is [System.Management.Automation.ErrorRecord]) { $e.Exception.Message } else { [string]$e })); Add-SIMailHeldNote; $true } else { $false } }
if ($closeLoopError -and (& $heldMail 'close-loop mail' $closeLoopError)) { $closeLoopError = $null }
if ($deptReportError -and (& $heldMail 'business owners'' report' $deptReportError)) { $deptReportError = $null }
if ($govMailError -and (& $heldMail 'governance mail' $govMailError)) { $govMailError = $null }
if ($taskDigestError -and (& $heldMail 'task digest' $taskDigestError)) { $taskDigestError = $null }
if ($closeLoopError) { throw $closeLoopError }
if ($exRes.Failed -gt 0) {
    $exErr = @($exRes.Errors | Where-Object { "$_".Trim() })
    if ($exErr.Count -and @($exErr | Where-Object { -not (Test-SIMailHeldUnreadable -Failure ([string]$_)) }).Count -eq 0) {
        $null = & $heldMail ('{0} exemption mail(s)' -f $exRes.Failed) ([string]$exErr[0])
    } else { throw ('{0} exemption mail(s) were not sent: {1}' -f $exRes.Failed, ($exRes.Errors -join ' | ')) }
}
if ($deptReportError) { throw $deptReportError }
if ($govMailError) { throw $govMailError }
if ($taskDigestError) { throw $taskDigestError }
