#Requires -Version 5.1
<#
.SYNOPSIS
    Platform-wide health-check engine. Runs a configurable battery of checks
    against an Entra tenant / Azure subscription / Key Vault / Function App /
    internet connectivity, collects the results, and sends an email alert if
    anything failed.

.DESCRIPTION
    Every check is individually switchable via $global:* booleans (set by the
    launcher's LauncherConfig.ps1 or passed as parameters). The script runs
    the enabled checks, collects a structured result per check, and on any
    failure sends an SMTP alert email.

    The alert body always includes:
      * Tenant ID
      * Customer / environment name
      * Timestamp (UTC)
      * Machine the check ran on
      * Per-check status + details
      * Any stack trace for checks that threw

    For internal tenants the default recipient is mok@2linkit.net so Morten
    can cross-reference alerts against customer inventory. Community users
    override $global:AlertEmailTo to their own mailbox.

.PARAMETER CheckSecretExpiry
    Enumerate all Entra app registrations owned by -TenantId, flag any where
    at least one client secret OR certificate expires within -DaysBeforeExpiry
    days (default 14) or is already expired.

.PARAMETER DaysBeforeExpiry
    Default: 14.

.PARAMETER CheckKeyVaultConnectivity
    Try to list secrets in -KeyVaultName. Fails if the caller lacks 'Secrets
    User' or if the KV is unreachable.

.PARAMETER KeyVaultName
    Name of the Key Vault to probe (short name, not URI).

.PARAMETER CheckAzureConnectivity
    Query the Azure Resource Manager endpoint via Get-AzContext + Get-AzSubscription.

.PARAMETER CheckGraphConnectivity
    Requires Microsoft.Graph.Authentication. Calls Get-MgOrganization -- fails
    if the SPN lacks any Graph read permissions or Graph endpoint is blocked.

.PARAMETER CheckFunctionAppAccess
    HTTP GET to -FunctionAppHealthUrl (expecting 200). Useful if the solution
    is hosted in a Function App and you want to detect platform outages.

.PARAMETER FunctionAppHealthUrl
    e.g. https://fn-securityinsight-prod.azurewebsites.net/api/health.

.PARAMETER CheckInternetConnectivity
    Simple web probe to https://login.microsoftonline.com -- catches basic
    outbound internet / proxy issues before other checks fail mysteriously.

.PARAMETER TenantId
    Tenant being monitored. Included in every email so you can map alerts back
    to customers.

.PARAMETER CustomerName
    Free-text customer / environment label. Included in the email subject and body.

.PARAMETER AlertEmailTo
    Recipient of the alert email. Default: mok@2linkit.net (internal).
    Community users must override to their own mailbox via LauncherConfig.ps1.

.PARAMETER SmtpServer / SmtpPort / SmtpFrom / SmtpUseSsl / SmtpCredential
    Standard SMTP parameters. If $global:SmtpCredential is set, used for auth;
    otherwise anonymous. Supported: O365 / SendGrid / customer's own relay.

.PARAMETER AlwaysSendHeartbeat
    If set, the script sends an email on every run (green or red) -- useful
    to detect the check SCRIPT itself silently failing. Default: only-on-fail.

.EXAMPLE
    # Hourly health check for a customer tenant, email Morten if anything fails:
    .\Invoke-PlatformHealthCheck.ps1 `
        -CheckSecretExpiry -DaysBeforeExpiry 21 `
        -CheckAzureConnectivity -CheckGraphConnectivity `
        -CheckKeyVaultConnectivity -KeyVaultName kv-securityinsight-prod `
        -TenantId c806957b-41a4-496c-9bbb-6e4e5b00ec9b `
        -CustomerName 'Contoso' `
        -SmtpServer smtp.office365.com -SmtpPort 587 -SmtpFrom 'alerts@contoso.com' -SmtpUseSsl
#>
[CmdletBinding()]
param(
    # ---- Check toggles ----
    [switch]$CheckSecretExpiry,
    [int]   $DaysBeforeExpiry = 14,

    [switch]$CheckKeyVaultConnectivity,
    [string]$KeyVaultName,

    [switch]$CheckAzureConnectivity,
    [switch]$CheckGraphConnectivity,

    [switch]$CheckFunctionAppAccess,
    [string]$FunctionAppHealthUrl,

    [switch]$CheckInternetConnectivity,

    # ---- Context ----
    [string]$TenantId,
    [string]$CustomerName,

    # ---- Alerting ----
    [string]$AlertEmailTo   = 'mok@2linkit.net',
    [string]$SmtpServer,
    [int]   $SmtpPort       = 587,
    [string]$SmtpFrom,
    [switch]$SmtpUseSsl,
    [switch]$AlwaysSendHeartbeat
)
$ErrorActionPreference = 'Stop'

# ---- v2 bootstrap: accept params OR global fallbacks ----
if (-not $TenantId -and $global:SpnTenantId) { $TenantId = $global:SpnTenantId }
if (-not $CustomerName -and $global:CustomerName) { $CustomerName = [string]$global:CustomerName }
if (-not $SmtpServer -and $global:SmtpServer) { $SmtpServer = [string]$global:SmtpServer }
if (-not $SmtpFrom   -and $global:SmtpFrom)   { $SmtpFrom   = [string]$global:SmtpFrom }
if (-not $AlertEmailTo -or $AlertEmailTo -eq 'mok@2linkit.net') {
    if ($global:AlertEmailTo) { $AlertEmailTo = [string]$global:AlertEmailTo }
}

if (-not $TenantId)     { throw "Invoke-PlatformHealthCheck: -TenantId is required (or set `$global:SpnTenantId)." }
if (-not $CustomerName) { $CustomerName = $env:COMPUTERNAME }

function Write-Step  ($m) { Write-Host "[CHECK] $m" -ForegroundColor Cyan }
function Write-Ok    ($m) { Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Fail  ($m) { Write-Host "[FAIL]  $m" -ForegroundColor Red   }
function Write-Info  ($m) { Write-Host "[INFO]  $m" -ForegroundColor Gray  }

$results = New-Object System.Collections.Generic.List[object]
function Record {
    param([string]$Name, [bool]$Passed, [string]$Detail, [object]$Exception = $null)
    $results.Add([pscustomobject]@{
        Name      = $Name
        Passed    = $Passed
        Detail    = $Detail
        Exception = if ($Exception) { $Exception.ToString() } else { $null }
        Timestamp = [datetime]::UtcNow.ToString('o')
    })
    if ($Passed) { Write-Ok ("{0} :: {1}" -f $Name, $Detail) } else { Write-Fail ("{0} :: {1}" -f $Name, $Detail) }
}

# ------------------ CHECKS ------------------

if ($CheckInternetConnectivity) {
    Write-Step 'Internet connectivity (login.microsoftonline.com)'
    try {
        $r = Invoke-WebRequest -Uri 'https://login.microsoftonline.com' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        Record 'InternetConnectivity' $true "HTTP $($r.StatusCode)"
    } catch { Record 'InternetConnectivity' $false "unreachable: $($_.Exception.Message)" $_.Exception }
}

if ($CheckAzureConnectivity) {
    Write-Step 'Azure Resource Manager connectivity'
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if (-not $ctx -or -not $ctx.Subscription) { throw 'No Azure context; launcher must authenticate first.' }
        $subs = Get-AzSubscription -ErrorAction Stop | Select-Object -First 1
        Record 'AzureConnectivity' $true ("subscription={0}" -f $subs.Name)
    } catch { Record 'AzureConnectivity' $false $_.Exception.Message $_.Exception }
}

if ($CheckGraphConnectivity) {
    Write-Step 'Microsoft Graph connectivity'
    try {
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
            throw 'Microsoft.Graph.Authentication module not installed.'
        }
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
        if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
            throw 'No Microsoft Graph context; launcher must Connect-MgGraph first.'
        }
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop -WarningAction SilentlyContinue
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        Record 'GraphConnectivity' $true ("tenant={0}" -f $org.DisplayName)
    } catch { Record 'GraphConnectivity' $false $_.Exception.Message $_.Exception }
}

if ($CheckKeyVaultConnectivity) {
    Write-Step ("Key Vault connectivity ({0})" -f $KeyVaultName)
    try {
        if (-not $KeyVaultName) { throw '-KeyVaultName is required when -CheckKeyVaultConnectivity is on.' }
        if (-not (Get-Module -ListAvailable -Name 'Az.KeyVault')) { throw 'Az.KeyVault module not installed.' }
        Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
        $secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName -ErrorAction Stop
        $sw.Stop()
        Record 'KeyVaultConnectivity' $true ("vault={0} secrets={1} latency={2}ms" -f $kv.VaultName, @($secrets).Count, $sw.ElapsedMilliseconds)
    } catch { Record 'KeyVaultConnectivity' $false $_.Exception.Message $_.Exception }
}

if ($CheckSecretExpiry) {
    Write-Step ("Entra app secret / certificate expiry (threshold: {0} days)" -f $DaysBeforeExpiry)
    try {
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop -WarningAction SilentlyContinue
        $apps = Get-MgApplication -All -ErrorAction Stop
        $now       = [datetime]::UtcNow
        $threshold = $now.AddDays($DaysBeforeExpiry)
        $aboutToExpire = @()
        foreach ($a in $apps) {
            foreach ($p in ($a.PasswordCredentials | Where-Object { $_ })) {
                if ($p.EndDateTime -lt $threshold) {
                    $aboutToExpire += [pscustomobject]@{
                        AppDisplayName = $a.DisplayName
                        AppId          = $a.AppId
                        CredentialType = 'Secret'
                        KeyId          = $p.KeyId
                        Expires        = $p.EndDateTime
                        DaysLeft       = [int]($p.EndDateTime - $now).TotalDays
                    }
                }
            }
            foreach ($c in ($a.KeyCredentials | Where-Object { $_ })) {
                if ($c.EndDateTime -lt $threshold) {
                    $aboutToExpire += [pscustomobject]@{
                        AppDisplayName = $a.DisplayName
                        AppId          = $a.AppId
                        CredentialType = 'Certificate'
                        KeyId          = $c.KeyId
                        Expires        = $c.EndDateTime
                        DaysLeft       = [int]($c.EndDateTime - $now).TotalDays
                    }
                }
            }
        }
        if ($aboutToExpire.Count -gt 0) {
            $detail = ($aboutToExpire | ForEach-Object { "{0} ({1}) {2} expires {3:yyyy-MM-dd} ({4}d)" -f $_.AppDisplayName, $_.AppId, $_.CredentialType, $_.Expires, $_.DaysLeft }) -join "`n"
            Record 'SecretExpiry' $false ("{0} credential(s) within threshold`n{1}" -f $aboutToExpire.Count, $detail)
        } else {
            Record 'SecretExpiry' $true ("no secrets/certs expiring within {0} days" -f $DaysBeforeExpiry)
        }
    } catch { Record 'SecretExpiry' $false $_.Exception.Message $_.Exception }
}

if ($CheckFunctionAppAccess) {
    Write-Step ("Function App health URL ({0})" -f $FunctionAppHealthUrl)
    try {
        if (-not $FunctionAppHealthUrl) { throw '-FunctionAppHealthUrl is required when -CheckFunctionAppAccess is on.' }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-WebRequest -Uri $FunctionAppHealthUrl -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $sw.Stop()
        if ($r.StatusCode -ne 200) { throw "HTTP $($r.StatusCode)" }
        Record 'FunctionAppAccess' $true ("200 OK latency={0}ms" -f $sw.ElapsedMilliseconds)
    } catch { Record 'FunctionAppAccess' $false $_.Exception.Message $_.Exception }
}

# ------------------ SUMMARY + EMAIL ------------------

$anyFailed  = @($results | Where-Object { -not $_.Passed }).Count -gt 0
$passed     = @($results | Where-Object { $_.Passed }).Count
$failed     = @($results | Where-Object { -not $_.Passed }).Count
$summaryClr = if ($anyFailed) { 'Red' } else { 'Green' }
$status     = if ($anyFailed) { 'FAIL' } else { 'OK' }

Write-Host ""
Write-Host ("Summary: {0} passed, {1} failed ({2} checks total)" -f $passed, $failed, $results.Count) -ForegroundColor $summaryClr

if (-not ($anyFailed -or $AlwaysSendHeartbeat)) {
    Write-Ok 'No failures and heartbeat disabled -- no email sent.'
    return
}

if (-not $SmtpServer) {
    Write-Fail 'Email alert needed but -SmtpServer / $global:SmtpServer not set. Skipping email.'
    return
}
if (-not $SmtpFrom) { $SmtpFrom = $AlertEmailTo }

$subject = "[{0}] PlatformHealthCheck {1} -- {2} ({3})" -f `
    $status, $CustomerName, $TenantId, ([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))

$bodyLines = @(
    "PlatformHealthCheck report",
    "",
    "Customer / Environment : $CustomerName",
    "TenantId               : $TenantId",
    "Ran on host            : $env:COMPUTERNAME",
    "Timestamp (UTC)        : $([datetime]::UtcNow.ToString('o'))",
    "Total checks           : $($results.Count)",
    "Passed                 : $passed",
    "Failed                 : $failed",
    ""
)
foreach ($r in $results) {
    $perStatus = if ($r.Passed) { 'PASS' } else { 'FAIL' }
    $bodyLines += "[$perStatus] $($r.Name)"
    $bodyLines += "        $($r.Detail)"
    if ($r.Exception) { $bodyLines += "        EXCEPTION: $($r.Exception)" }
    $bodyLines += ""
}
$bodyLines += "Developed by Morten Knudsen, Microsoft MVP  |  https://mortenknudsen.net  |  mok@mortenknudsen.net"
$body = $bodyLines -join "`r`n"

try {
    Write-Step ("Sending alert to {0} via {1}:{2}" -f $AlertEmailTo, $SmtpServer, $SmtpPort)
    $mailParams = @{
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
        From       = $SmtpFrom
        To         = $AlertEmailTo
        Subject    = $subject
        Body       = $body
        ErrorAction = 'Stop'
    }
    if ($SmtpUseSsl -or [bool]$global:SmtpUseSsl) { $mailParams.UseSsl = $true }
    if ($global:SmtpCredential -is [System.Management.Automation.PSCredential]) {
        $mailParams.Credential = $global:SmtpCredential
    }
    Send-MailMessage @mailParams
    Write-Ok 'Email alert sent.'
} catch {
    Write-Fail "Failed to send alert email: $($_.Exception.Message)"
    throw
}

if ($anyFailed) { exit 1 } else { exit 0 }
