#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight PublicIP Scanner -- collects every public IP attached to a
    Tier 0/1 asset, queries Shodan REST for each, and ingests one row per IP
    into SI_VulnerabilityPIP_CL.

.DESCRIPTION
    Pipeline (per run):
      1. Read SI_Endpoint_Profile_CL + SI_Azure_Profile_CL latest snapshot
         from Log Analytics; project assets where Tier <= 1 and the asset has
         at least one public IP.
      2. For each unique public IP, call https://api.shodan.io/shodan/host/{ip}
         (Shodan REST). Throttle = 1 call/second by default (Shodan free tier).
      3. Build one row per IP carrying AssetName + AssetEngine + AssetTier +
         IpAddress + ScanTime + OpenPorts[] + Vulns[] + Country + Org + ISP
         + Hostnames[] + LastShodanUpdate.
      4. Ingest to SI_VulnerabilityPIP_CL via AzLogDcrIngestPS.

    Risk Analysis side (separate -- see risk-analysis-detection YAML):
      - PublicIP_OpenPorts_Summary / _Detailed       : flag any open admin port
      - PublicIP_Vulnerabilities_Summary / _Detailed : flag any CVE in vulns[]

.NOTES
    Solution       : SecurityInsight
    File           : Invoke-PublicIpScanner.ps1
    Engine         : publicip
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net   (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>

# ----------------------------------------------------------------------
#  Module dependencies
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules

# v2.2.233 -- SPN name bridge (defensive copy of Initialize-LauncherConfig).
# Mirrors $global:SI_SPN_* (v2.3 Setup Wizard output) onto the legacy
# $global:Spn* names this engine still reads, so the engine works when invoked
# outside the standard launcher path.
if ($global:SI_SPN_TenantId        -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
if ($global:SI_SPN_AppId           -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
if ($global:SI_SPN_Secret          -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
if ($global:SI_SPN_ObjectId        -and -not $global:SpnObjectId)              { $global:SpnObjectId              = [string]$global:SI_SPN_ObjectId }
if ($global:SI_SPN_CertThumbprint  -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }
# v2.2.278 -- bridge from internal-AutomateIT framework's HighPriv_Modern_*_Azure
# globals (set by Connect-Platform). SI_SPN_* > HighPriv_* precedence.
if ($global:HighPriv_Modern_TenantID                       -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:HighPriv_Modern_TenantID }
if ($global:HighPriv_Modern_ApplicationID_Azure            -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if ($global:HighPriv_Modern_ApplicationSecret_Azure        -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:HighPriv_Modern_ApplicationSecret_Azure }
if ($global:HighPriv_Modern_CertificateThumbprint_Azure    -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

# ============================================================
# CONFIGURATION (v2: launcher is source of truth)
# ============================================================

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }

# Knobs (silent defaults so the per-call loop doesn't WARN every iteration).
if (-not $global:SI_Shodan_ThrottleMs)         { $global:SI_Shodan_ThrottleMs         = 1100 }   # 1 call/sec + headroom
if (-not $global:SI_Shodan_TimeoutSec)         { $global:SI_Shodan_TimeoutSec         = 15 }
if (-not $global:SI_Shodan_TierMax)            { $global:SI_Shodan_TierMax            = 3 }     # default scan all tiers (T0-T3); tighten via custom for cost control
if (-not $global:SI_Shodan_AssetLimit)         { $global:SI_Shodan_AssetLimit         = 0 }     # 0 = no cap
if ($null -eq $global:SI_Shodan_LookbackDays)  { $global:SI_Shodan_LookbackDays       = 8 }     # how far back to look in Profile_CL
if ($null -eq $global:SI_Shodan_SkipLA_Ingest) { $global:SI_Shodan_SkipLA_Ingest      = $false }
if ($null -eq $global:SI_Shodan_DcrName)       { $global:SI_Shodan_DcrName            = 'dcr-si-publicip-profile' }
if ($null -eq $global:SI_Shodan_TableName)     { $global:SI_Shodan_TableName          = 'SI_VulnerabilityPIP_CL' }
# Hybrid fresh-scan knobs. Off by default; opt-in via LauncherConfig.custom.ps1.
if ($null -eq $global:SI_Shodan_ForceFreshScan)        { $global:SI_Shodan_ForceFreshScan       = $false }
if ($null -eq $global:SI_Shodan_ScanWaitMaxSec)        { $global:SI_Shodan_ScanWaitMaxSec       = 300 }   # 5 min sync deadline
if ($null -eq $global:SI_Shodan_ScanPollIntervalSec)   { $global:SI_Shodan_ScanPollIntervalSec  = 30 }
if ($null -eq $global:SI_Shodan_PendingScansPath)      {
    $_dataDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data'
    $global:SI_Shodan_PendingScansPath = Join-Path $_dataDir 'shodan-pending-scans.json'
}
# Skip-if-recent guard. Once a fresh scan completes successfully its
# completion time is persisted; subsequent runs within this window will
# skip submitting a NEW scan (still proceed to read host info from cache).
# Default 20h fits a daily 02:00 + 03:00 + 04:00 belt-and-braces schedule.
if ($null -eq $global:SI_Shodan_FreshScanIntervalHours) { $global:SI_Shodan_FreshScanIntervalHours = 20 }
if ($null -eq $global:SI_Shodan_LastFreshScanPath)     {
    $_dataDir2 = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data'
    $global:SI_Shodan_LastFreshScanPath = Join-Path $_dataDir2 'shodan-last-fresh-scan.json'
}

# Auth required when not in AutomationFramework. v2.2.238 -- accept either
# ClientSecret OR CertificateThumbprint (the bridge in this engine's preamble
# at v2.2.233 mirrors SI_SPN_CertThumbprint -> SpnCertificateThumbprint, and
# the community-vm launcher already supports cert auth via Connect-AzAccount).
if (-not [bool]$global:AutomationFramework) {
    $_hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $_hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
        (-not $_hasSecret -and -not $_hasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Launcher must set them or enable AutomationFramework."
    }
}
# Accept either the canonical SI-prefixed name or the legacy v1 SHODAN_ApiKey
# alias (some sample configs still use the unprefixed form). Whichever is set
# wins; if both are set, SI_Shodan_ApiKey takes precedence.
if ([string]::IsNullOrWhiteSpace([string]$global:SI_Shodan_ApiKey) -and
    -not [string]::IsNullOrWhiteSpace([string]$global:SHODAN_ApiKey)) {
    $global:SI_Shodan_ApiKey = [string]$global:SHODAN_ApiKey
}
if ([string]::IsNullOrWhiteSpace([string]$global:SI_Shodan_ApiKey)) {
    throw "Missing `$global:SI_Shodan_ApiKey -- set it in config/SecurityInsight.custom.ps1 or LauncherConfig.custom.ps1 (legacy `$global:SHODAN_ApiKey is also accepted). Get a key at https://account.shodan.io/."
}
if ([string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
    throw "Missing `$global:SI_WorkspaceResourceId -- the engine reads SI_Endpoint_Profile_CL + SI_Azure_Profile_CL from this workspace."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$script:_StartTime = [datetime]::UtcNow
$script:_CollectionTime = ([datetime]::UtcNow).ToString('yyyy-MM-dd HH:mm:ss')

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $col = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'STEP'    { 'Cyan' }
        default   { 'White' }
    }
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) -ForegroundColor $col
}

# ============================================================
# AUTH
# ============================================================
if ([bool]$global:AutomationFramework) {
    # Bootstrap via AutomateITPS (mirrors privilege-tier-classifier internal-vm path)
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) { throw "AutomationFramework: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1." }
    $global:PathScripts = $repoRoot
    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
    Write-Log "Auth method (bootstrap): SPN + Certificate (Initialize-PlatformAutomationFramework)" "INFO"

    # Map AF globals to v2 contract
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure
}

function Connect-AzWithSPN {
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account.Id -eq $global:SpnClientId -and $ctx.Subscription) {
            Write-Log "Azure already connected as SPN $($global:SpnClientId)" "INFO"
            return
        }
    } catch {}
    $secureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $credential   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secureSecret)
    Connect-AzAccount -ServicePrincipal -TenantId $global:SpnTenantId -Credential $credential -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    Write-Log "Connected to Azure" "SUCCESS"
}

# ============================================================
# STEP 1 : QUERY LA FOR TIER 0/1 PUBLIC IPs
# ============================================================
function Get-PublicIpsFromProfileTables {
    Write-Log "=== STEP 1: Reading Tier 0-$($global:SI_Shodan_TierMax) public IPs from SI_*_Profile_CL ===" "STEP"
    Connect-AzWithSPN

    # Defensive: column names that hold a public IP differ per profile table.
    # Endpoint:  PublicIp / PublicIpAddress / Properties.* (varies by source)
    # Azure   :  IsPubliclyExposed flag + AssetName for IPs / public IP resources
    # Use column_ifexists wrappers so a tenant whose schema lacks one column
    # doesn't fail the whole read.
    $tierMax = [int]$global:SI_Shodan_TierMax
    $lookbackDays = [int]$global:SI_Shodan_LookbackDays
    # union isfuzzy=true silently skips tables that don't exist yet (e.g. fresh
    # workspaces where the Azure or Endpoint engine hasn't ingested its first
    # batch). Without isfuzzy, KQL throws BadRequest at parse time and the
    # whole discovery query fails even if the OTHER table has data.
    $kql = @"
union isfuzzy=true
(
    SI_Endpoint_Profile_CL
    | where TimeGenerated > ago(${lookbackDays}d)
    | summarize arg_max(CollectionTime, *) by PrimaryEntityId
    | where toint(coalesce(Tier, 99)) <= $tierMax
    // Servers only -- workstation PublicIp is the user's current ISP egress NAT
    // (home, coffee shop, cellular). Scanning it = scanning a random consumer
    // ISP, not anything the customer owns. DeviceType == "Server" covers both
    // Windows + Linux server roles in the SI endpoint schema.
    | where tostring(column_ifexists("DeviceType", "")) =~ "Server"
    | extend _ip = tostring(coalesce(
                       column_ifexists("PublicIp", ""),
                       column_ifexists("PublicIpAddress", ""),
                       column_ifexists("ExternalIp", "")))
    | where isnotempty(_ip)
    | project AssetName, AssetEngine = "endpoint", AssetTier = toint(coalesce(Tier, 99)),
              cmdbId              = tostring(column_ifexists("cmdbId", "")),
              cmdbName            = tostring(column_ifexists("cmdbName", "")),
              cmdbCriticality     = tostring(column_ifexists("cmdbCriticality", "")),
              cmdbDataSensitivity = tostring(column_ifexists("cmdbDataSensitivity", "")),
              IpAddress = _ip
),
(
    SI_Azure_Profile_CL
    | where TimeGenerated > ago(${lookbackDays}d)
    | summarize arg_max(CollectionTime, *) by PrimaryEntityId
    | where toint(coalesce(Tier, 99)) <= $tierMax
    // Read PipAddress (the actual SI schema column for microsoft.network/publicipaddresses
    // resources) FIRST, then legacy fallbacks. Do NOT filter on IsPubliclyExposed --
    // PIP resources often have it null/false because they ARE the public IP, not
    // something exposed behind one. The IP-regex filter below gates non-IP values.
    | extend _ip = tostring(coalesce(
                       column_ifexists("PipAddress", ""),
                       column_ifexists("PublicIpAddress", ""),
                       column_ifexists("IpAddress", "")))
    | where isnotempty(_ip)
    | project AssetName, AssetEngine = "azure", AssetTier = toint(coalesce(Tier, 99)),
              cmdbId              = tostring(column_ifexists("cmdbId", "")),
              cmdbName            = tostring(column_ifexists("cmdbName", "")),
              cmdbCriticality     = tostring(column_ifexists("cmdbCriticality", "")),
              cmdbDataSensitivity = tostring(column_ifexists("cmdbDataSensitivity", "")),
              IpAddress = _ip
)
| where IpAddress matches regex @"^(?:\d{1,3}\.){3}\d{1,3}`$"
| summarize arg_min(AssetTier, *) by IpAddress
"@

    Write-Log "Submitting LA discovery query ..." "INFO"
    # Resolve the LA workspace's CustomerId (= GUID used by Invoke-AzOperationalInsightsQuery -WorkspaceId).
    # Get-AzOperationalInsightsWorkspace doesn't accept -ResourceId; parse the ARM id and call with -Name + -ResourceGroupName.
    # The SPN's default Az context may be on a different subscription than the
    # one that owns SI_WorkspaceResourceId (common when the workspace is in a
    # community / lab subscription but the SPN was issued in a different sub).
    # Switch context to the workspace's subscription before the LA query.
    try {
        if ($global:SI_WorkspaceResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
            throw "Invalid LA workspace resource id: $($global:SI_WorkspaceResourceId)"
        }
        $wsSub  = $matches.sub
        $wsRg   = $matches.rg
        $wsName = $matches.name
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or $ctx.Subscription.Id -ne $wsSub) {
            Write-Log "Switching Az context to subscription $wsSub (was $($ctx.Subscription.Id))" "INFO"
            Set-AzContext -SubscriptionId $wsSub -ErrorAction Stop | Out-Null
        }
        $wsCustomerId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $wsRg -Name $wsName -ErrorAction Stop).CustomerId
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $wsCustomerId -Query $kql -ErrorAction Stop
    } catch {
        # Surface the real KQL error body when present ($.ErrorDetails.Message
        # carries the JSON body from Invoke-AzOperationalInsightsQuery on
        # BadRequest / NotFound responses; $.Exception.Message is just the HTTP
        # status). Without this, "Operation returned an invalid status code
        # 'BadRequest'" hides whether the cause was a missing table, a syntax
        # error, or a permissions gap.
        $errBody = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errBody = $_.ErrorDetails.Message }
        Write-Log "LA query failed: $($_.Exception.Message)" "ERROR"
        if ($errBody) { Write-Log "LA error detail: $errBody" "ERROR" }
        Write-Log ("Hint: BadRequest typically means SI_Endpoint_Profile_CL / SI_Azure_Profile_CL don't exist yet in the workspace -- run the endpoint + azure engines first to create the tables.") "INFO"
        return @()
    }
    $rows = @($resp.Results)
    if (-not $rows -or $rows.Count -eq 0) {
        Write-Log "no Tier 0-$tierMax public IPs found in Endpoint+Azure profile tables" "WARN"
        return @()
    }
    Write-Log ("found {0} Tier 0-{1} public IP(s)" -f $rows.Count, $tierMax) "SUCCESS"

    if ([int]$global:SI_Shodan_AssetLimit -gt 0 -and $rows.Count -gt [int]$global:SI_Shodan_AssetLimit) {
        Write-Log ("AssetLimit cap: trimming {0} -> {1}" -f $rows.Count, $global:SI_Shodan_AssetLimit) "WARN"
        $rows = $rows | Select-Object -First ([int]$global:SI_Shodan_AssetLimit)
    }
    return $rows
}

# ============================================================
# STEP 1.5 : OPTIONAL FRESH SCAN  (hybrid wait-or-defer)
#
# Workflow when $global:SI_Shodan_ForceFreshScan = $true:
#   a) If a previous scan is still pending in `shodan-pending-scans.json`,
#      poll its status. If DONE -> proceed straight to Step 2 (read host info).
#      If still PROCESSING -> log + exit (next run picks it up).
#   b) Otherwise POST /shodan/scan with the IP list, save scan_id to state,
#      then sync-poll for up to $global:SI_Shodan_ScanWaitMaxSec seconds.
#      If DONE within deadline -> proceed to Step 2.
#      If still PROCESSING at deadline -> exit (next run picks it up).
# ============================================================

function Submit-ShodanScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Ips)
    $uri  = 'https://api.shodan.io/shodan/scan?key=' + [uri]::EscapeDataString($global:SI_Shodan_ApiKey)
    $body = 'ips=' + [uri]::EscapeDataString(($Ips -join ','))
    Write-Log ("submitting fresh Shodan scan for {0} IP(s) ..." -f $Ips.Count) "INFO"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
                  -ContentType 'application/x-www-form-urlencoded' `
                  -TimeoutSec ([int]$global:SI_Shodan_TimeoutSec) -ErrorAction Stop
        Write-Log ("scan submitted: id={0} count={1} credits_left={2}" -f $resp.id, $resp.count, $resp.credits_left) "SUCCESS"
        return $resp.id
    } catch {
        Write-Log "Shodan scan submit failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-ShodanScanStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId)
    $uri = ('https://api.shodan.io/shodan/scan/{0}?key={1}' -f $ScanId, [uri]::EscapeDataString($global:SI_Shodan_ApiKey))
    try {
        return Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-Log "scan-status fetch failed: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Wait-ShodanScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId)
    $deadline = (Get-Date).AddSeconds([int]$global:SI_Shodan_ScanWaitMaxSec)
    while ((Get-Date) -lt $deadline) {
        $st = Get-ShodanScanStatus -ScanId $ScanId
        if ($null -ne $st) {
            Write-Log ("scan {0} status={1}" -f $ScanId, $st.status) "INFO"
            if ($st.status -eq 'DONE') { return $true }
        }
        Start-Sleep -Seconds ([int]$global:SI_Shodan_ScanPollIntervalSec)
    }
    return $false
}

function Save-PendingScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId, [Parameter(Mandatory)][string[]]$Ips)
    $obj = [pscustomobject]@{
        ScanId       = $ScanId
        SubmittedAt  = ([datetime]::UtcNow).ToString('o')
        Ips          = @($Ips)
    }
    $dir = Split-Path -Parent $global:SI_Shodan_PendingScansPath
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $obj | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $global:SI_Shodan_PendingScansPath -Encoding UTF8 -Force
    Write-Log ("pending scan persisted: {0} ({1} IPs)" -f $ScanId, $Ips.Count) "INFO"
}

function Load-PendingScan {
    if (-not (Test-Path -LiteralPath $global:SI_Shodan_PendingScansPath)) { return $null }
    try { return (Get-Content -LiteralPath $global:SI_Shodan_PendingScansPath -Raw | ConvertFrom-Json) }
    catch { Write-Log "could not parse pending-scans state: $($_.Exception.Message)" "WARN"; return $null }
}

function Clear-PendingScan {
    if (Test-Path -LiteralPath $global:SI_Shodan_PendingScansPath) {
        Remove-Item -LiteralPath $global:SI_Shodan_PendingScansPath -Force -ErrorAction SilentlyContinue
    }
}

function Save-LastFreshScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScanId, [Parameter(Mandatory)][int]$IpCount)
    $obj = [pscustomobject]@{
        ScanId      = $ScanId
        CompletedAt = ([datetime]::UtcNow).ToString('o')
        IpCount     = $IpCount
    }
    $dir = Split-Path -Parent $global:SI_Shodan_LastFreshScanPath
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $obj | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $global:SI_Shodan_LastFreshScanPath -Encoding UTF8 -Force
}

function Test-RecentFreshScan {
    # Returns $true when the last successful fresh-scan completed within the
    # configured interval. Multiple daily runs (02:00 / 03:00 / 04:00) then
    # become safely idempotent: only the first run that finds no recent record
    # actually submits + waits.
    if (-not (Test-Path -LiteralPath $global:SI_Shodan_LastFreshScanPath)) { return $false }
    try {
        $rec = Get-Content -LiteralPath $global:SI_Shodan_LastFreshScanPath -Raw | ConvertFrom-Json
        if (-not $rec.CompletedAt) { return $false }
        # Parse as UTC -- the saved timestamp is ISO 8601 with 'Z' / offset; using
        # [datetime]::Parse silently coerces to local kind and produces negative
        # ages on machines whose local clock is ahead of UTC.
        $completedUtc = ([datetimeoffset]::Parse($rec.CompletedAt)).UtcDateTime
        $age = ([datetime]::UtcNow - $completedUtc).TotalHours
        if ($age -lt [double]$global:SI_Shodan_FreshScanIntervalHours) {
            Write-Log ("recent fresh-scan {0} completed {1:n1}h ago (within {2}h window) -- skipping new submission" -f $rec.ScanId, $age, $global:SI_Shodan_FreshScanIntervalHours) "INFO"
            return $true
        }
        return $false
    } catch {
        Write-Log "could not parse last-fresh-scan state: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Invoke-FreshScanFlow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Targets)

    $ips = @($Targets | ForEach-Object { $_.IpAddress } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ips.Count -eq 0) { return $true }

    # 1. Pending scan from a prior run? Always honor it before considering anything else.
    $pending = Load-PendingScan
    if ($pending -and $pending.ScanId) {
        Write-Log ("found pending scan {0} (submitted {1}); polling ..." -f $pending.ScanId, $pending.SubmittedAt) "STEP"
        $st = Get-ShodanScanStatus -ScanId $pending.ScanId
        if ($null -ne $st -and $st.status -eq 'DONE') {
            Write-Log "pending scan completed -- proceeding to Step 2 read." "SUCCESS"
            Save-LastFreshScan -ScanId $pending.ScanId -IpCount @($pending.Ips).Count
            Clear-PendingScan
            return $true
        }
        Write-Log ("pending scan still processing (status={0}). Exiting; next run will re-poll." -f $st.status) "WARN"
        return $false
    }

    # 2. Skip-if-recent: don't burn scan credits if a fresh scan finished within the window.
    if (Test-RecentFreshScan) {
        Write-Log "skipping fresh-scan submission (recent run still warm); proceeding to Step 2 read." "INFO"
        return $true
    }

    # 3. No pending, no recent -- submit a fresh scan.
    Write-Log "=== STEP 1.5: ForceFreshScan -- submitting Shodan scan ===" "STEP"
    $scanId = Submit-ShodanScan -Ips $ips
    if (-not $scanId) {
        Write-Log "scan submission failed; falling back to read-only host info." "WARN"
        return $true
    }
    Save-PendingScan -ScanId $scanId -Ips $ips

    Write-Log ("waiting up to {0}s for scan to complete (poll every {1}s) ..." -f $global:SI_Shodan_ScanWaitMaxSec, $global:SI_Shodan_ScanPollIntervalSec) "INFO"
    if (Wait-ShodanScan -ScanId $scanId) {
        Write-Log "scan finished within sync deadline -- proceeding to Step 2." "SUCCESS"
        Save-LastFreshScan -ScanId $scanId -IpCount $ips.Count
        Clear-PendingScan
        return $true
    }
    Write-Log "scan deadline reached; exiting. Next run will pick up the pending scan." "WARN"
    return $false
}

# ============================================================
# STEP 2 : QUERY SHODAN PER IP
# ============================================================
function Get-ShodanHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Ip)
    $uri = ('https://api.shodan.io/shodan/host/{0}?key={1}' -f $Ip, [uri]::EscapeDataString($global:SI_Shodan_ApiKey))
    try {
        return Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec ([int]$global:SI_Shodan_TimeoutSec) -ErrorAction Stop
    } catch {
        $resp = $_.Exception.Response
        $status = if ($resp) { [int]$resp.StatusCode } else { 0 }
        # 404 = no scan info on file (legitimate empty result, not an error)
        if ($status -eq 404) { return $null }
        throw
    }
}

function Invoke-ShodanScans {
    param([Parameter(Mandatory)][object[]]$Targets)
    Write-Log "=== STEP 2: Querying Shodan for $($Targets.Count) IP(s) (throttle ${global:SI_Shodan_ThrottleMs}ms/call) ===" "STEP"

    $rows = New-Object System.Collections.Generic.List[object]
    $i = 0
    $progressStep = [Math]::Max(1, [int]($Targets.Count / 20))

    foreach ($t in $Targets) {
        $i++
        if ($i -eq 1 -or ($i % $progressStep -eq 0) -or $i -eq $Targets.Count) {
            Write-Log ("   shodan: {0,4}/{1,-4}  current={2}" -f $i, $Targets.Count, $t.IpAddress) "INFO"
        }

        $shodan = $null
        try { $shodan = Get-ShodanHost -Ip $t.IpAddress }
        catch {
            Write-Log ("Shodan call failed for $($t.IpAddress): $($_.Exception.Message)") "WARN"
        }

        # Build the row regardless (so we keep an audit trail of "scanned but no data")
        $openPorts = @()
        $vulns     = @()
        $country   = ''
        $org       = ''
        $isp       = ''
        $hostnames = @()
        $lastShodanUpdate = ''

        if ($null -ne $shodan) {
            $openPorts = @($shodan.ports | Sort-Object -Unique)
            if ($shodan.vulns) {
                # Shodan returns vulns in TWO shapes depending on the host record:
                #   - newer:  hashtable keyed on CVE: {"CVE-2024-X":{verified:..., cvss:...}}
                #   - older:  flat string array:      ["CVE-2024-X","CVE-2023-Y"]
                # Reading .PSObject.Properties.Name on an Array returns INTRINSIC .NET
                # property names (Count, IsFixedSize, ...) -- not what we want. Distinguish
                # by type before extracting CVE IDs.
                $raw = $shodan.vulns
                if ($raw -is [System.Collections.IDictionary]) {
                    # Hashtable shape: keys ARE the CVE IDs
                    $vulns = @($raw.Keys | ForEach-Object { [string]$_ } | Sort-Object -Unique)
                } elseif ($raw -is [System.Array] -or $raw -is [System.Collections.IList]) {
                    # Array shape: elements ARE the CVE IDs
                    $vulns = @($raw | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
                } else {
                    # PSCustomObject (Shodan keyed object came in via ConvertFrom-Json without -AsHashtable)
                    $vulns = @($raw.PSObject.Properties.Name | Where-Object { $_ -match '^CVE-\d{4}-\d+$' } | Sort-Object -Unique)
                }
            }
            $country   = [string]$shodan.country_name
            $org       = [string]$shodan.org
            $isp       = [string]$shodan.isp
            $hostnames = @($shodan.hostnames)
            $lastShodanUpdate = [string]$shodan.last_update
        }

        $rows.Add([pscustomobject]@{
            CollectionTime    = $script:_CollectionTime
            ScanTime          = ([datetime]::UtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ')
            IpAddress         = $t.IpAddress
            AssetId           = $t.IpAddress
            AssetName         = $t.AssetName
            AssetEngine       = $t.AssetEngine
            AssetType         = 'PublicIP'
            AssetTier         = [string][int]$t.AssetTier   # v2.2.320 -- String to match LA custom-table convention. Pre-v2.2.320 emitted [int] which 400'd against tenants whose DCR was created with String AssetTier ("InvalidTransformOutput: AssetTier produced:'Int', output:'String'"). The [int] cast in the middle still validates the input is numeric before stringifying.
            cmdbId              = $t.cmdbId
            cmdbName            = $t.cmdbName
            cmdbCriticality     = $t.cmdbCriticality
            cmdbDataSensitivity = $t.cmdbDataSensitivity
            HasShodanRecord   = ($null -ne $shodan)
            OpenPortCount     = $openPorts.Count
            OpenPorts         = ($openPorts | ConvertTo-Json -Compress)
            VulnCount         = $vulns.Count
            Vulns             = ($vulns | ConvertTo-Json -Compress)
            Country           = $country
            Org               = $org
            ISP               = $isp
            Hostnames         = ($hostnames | ConvertTo-Json -Compress)
            LastShodanUpdate  = $lastShodanUpdate
        }) | Out-Null

        if ($i -lt $Targets.Count) { Start-Sleep -Milliseconds ([int]$global:SI_Shodan_ThrottleMs) }
    }
    Write-Log ("Shodan: {0} IPs scanned, {1} returned data" -f $rows.Count, ($rows | Where-Object { $_.HasShodanRecord }).Count) "SUCCESS"
    return $rows
}

# ============================================================
# STEP 3 : INGEST INTO SI_VulnerabilityPIP_CL
# ============================================================
function Send-RowsToLogAnalytics {
    param([Parameter(Mandatory)][object[]]$Rows)
    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Log "no rows to ingest" "WARN"
        return
    }
    if ([bool]$global:SI_Shodan_SkipLA_Ingest) {
        Write-Log "SI_Shodan_SkipLA_Ingest=true; skipping ingest (rows kept in $script:_OutputJson)" "WARN"
        return
    }
    Write-Log "=== STEP 3: Ingesting $($Rows.Count) rows to $($global:SI_Shodan_TableName) ===" "STEP"

    # AzLogDcrIngestPS already imported by the launcher's module check; no need
    # to reimport here (and reimporting emits the always-on unapproved-verbs +
    # restricted-chars WARNINGs).

    # AzLogDcrIngestPS reads SPN credentials from globals:
    #   $global:LogIngestAppId / $global:LogIngestAppSecret / $global:TenantId
    # Map our Spn* globals to those if not already set.
    if (-not $global:LogIngestAppId)     { $global:LogIngestAppId     = $global:SpnClientId }
    if (-not $global:LogIngestAppSecret) { $global:LogIngestAppSecret = $global:SpnClientSecret }
    if (-not $global:TenantId)           { $global:TenantId           = $global:SpnTenantId }

    # v2.2.271 -- cert OR secret auth. Build a splat once and reuse at all 4 ingest
    # call sites below. Passing $global:LogIngestAppSecret='' to the module under
    # cert auth triggered ParameterBindingValidationException ("Cannot bind argument
    # to parameter 'AzAppSecret' because it is an empty string").
    $__ingestAuth = @{}
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)) {
        $__ingestAuth['AzAppCertificateThumbprint'] = [string]$global:SpnCertificateThumbprint
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:LogIngestAppSecret)) {
        $__ingestAuth['AzAppSecret'] = [string]$global:LogIngestAppSecret
    }

    # AzLogDcrIngestPS Post-* + CheckCreateUpdate-* resolve DCE/DCR by name on
    # their own (Get-AzDcrListAll scans the SPN's visible scope), so we don't
    # need $global:DceIngestionUri pre-populated AND we don't care which RG
    # the DCE actually lives in -- mirrors how the asset-profiling Output
    # stage behaves. Just validate the name is set.
    if (-not $global:SI_DceName) { throw "Missing `$global:SI_DceName -- set in launcher config." }
    $tableName = $global:SI_Shodan_TableName -replace '_CL$',''

    # ====================================================================
    # CANONICAL AzLogDcrIngestPS PIPELINE (mirrors RA + asset-profiling Output stage)
    # ====================================================================
    # Step 1. Define / update DCR + table from a schema sample (CASING-SAFE).
    #         Without this, the lower-level auto-create path lowercases the table
    #         name (we got 'SI_VulnerabilityPIP_CL' instead of 'SI_VulnerabilityPIP_CL').
    # Step 2. ARM consistency sleep -- newly created DCR's immutableId isn't
    #         discoverable in ARG immediately; Post-* needs it.
    # Step 3. Get-AzDcrListAll -- refresh the DCR cache so Post-* can resolve
    #         DcrName -> immutableId via $global:AzDcrDetails (otherwise the
    #         module's fallback can send a bogus id and the API 404s).
    # Step 4. Add-CollectionTimeToAllEntriesInArray -- safety net (we stamp
    #         CollectionTime upstream too, but the helper handles edge cases).
    # Step 5. Add-ColumnDataToAllEntriesInArray -- host identity (Computer /
    #         ComputerFqdn / UserLoggedOn) for cross-engine consistency.
    # Step 6. ValidateFix-AzLogAnalyticsTableSchemaColumnNames -- normalize
    #         column names to DCR-acceptable form (no spaces, valid chars).
    # Step 7. Build-DataArrayToAlignWithSchema -- pad rows with the columns
    #         the DCR declares but the row may not carry (default-valued).
    # Step 8. Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output -- the actual ingest.
    # ====================================================================

    # Save + silence verbose preference for the duration of the AzLogDcrIngestPS
    # pipeline (the module emits a verbose storm on every call). Restored in finally.
    $_savedVerbosePreference = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'
    try {
        # Step 1. Schema sample (first 100 rows -- larger sample = more reliable
        # column-type inference; matches the RA / asset-profiling pattern).
        $schemaSample = @($Rows | Select-Object -First 100)

        # Build the canonical DCE/DCR caches via the standard helpers BEFORE
        # the collision guard. PublicIP engine doesn't share state with the
        # asset-profiling engine, so the cache may be empty here. The guard
        # below will silently skip if AzDceDetails is null, which is what was
        # happening on greenfield community runs -> module's internal name-only
        # lookup returned BOTH same-named DCEs -> 'Array' bug.
        try {
            $global:AzDceDetails = Get-AzDceListAll -AzAppId $global:LogIngestAppId @__ingestAuth -TenantId $global:TenantId -Verbose:$false 4>$null
            $global:AzDcrDetails = Get-AzDcrListAll -AzAppId $global:LogIngestAppId @__ingestAuth -TenantId $global:TenantId -Verbose:$false 4>$null
        } catch { Write-Log ('Get-AzDceListAll/Get-AzDcrListAll prefetch failed: {0} -- collision guard may not fire' -f $_.Exception.Message) 'WARN' }

        # DCE collision guard (mirrors v2.2.59 in Invoke-Output.ps1). Strict:
        # pin $global:AzDceDetails to ONE entry by name + sub + RG so the
        # AzLogDcrIngestPS line 1575 name-only lookup returns a single record
        # (avoids the LinkedAuthorizationFailed array bug).
        if ($global:AzDceDetails -and $global:SI_DceName -and $global:SI_AzSubscriptionId -and $global:SI_DceResourceGroup) {
            $_picked = @($global:AzDceDetails | Where-Object {
                $_.name -eq $global:SI_DceName -and
                $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DceResourceGroup)/*"
            }) | Select-Object -First 1
            if ($_picked) {
                $global:AzDceDetails = @($_picked)
            } else {
                $_byName = @($global:AzDceDetails | Where-Object { $_.name -eq $global:SI_DceName })
                Write-Log ("DCE collision guard: '{0}' NOT in sub '{1}' / RG '{2}'. {3} same-named DCE(s) visible in other scopes -- module name-only lookup will pick wrong record. Verify SI_DceName / SI_AzSubscriptionId / SI_DceResourceGroup." -f $global:SI_DceName, $global:SI_AzSubscriptionId, $global:SI_DceResourceGroup, $_byName.Count) 'WARN'
            }
        }

        Write-Log 'CheckCreateUpdate-TableDcr-Structure (schema check + auto-provision)' 'STEP'
        try {
            $null = CheckCreateUpdate-TableDcr-Structure `
                        -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                        -AzAppId                                    $global:LogIngestAppId `
                        @__ingestAuth `
                        -TenantId                                   $global:TenantId `
                        -Verbose:$false `
                        -DceName                                    $global:SI_DceName `
                        -DcrName                                    $global:SI_Shodan_DcrName `
                        -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                        -TableName                                  $tableName `
                        -Data                                       $schemaSample `
                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                        -AzLogDcrTableCreateFromAnyMachine          $true `
                        -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null
        } catch {
            # v2.2.320 -- surface full context inline (operator ask: "would be
            # great to include details like dcr name, rg name, sub name, etc").
            # Plus pull the Azure error body out of $_.ErrorDetails / response
            # stream because Invoke-RestMethod 400s often leave the diagnostic
            # there instead of in $_.Exception.Message.
            $_azDetail = $_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $_azDetail = [string]$_.ErrorDetails.Message
            } else {
                try {
                    $_respStream = $_.Exception.Response.GetResponseStream()
                    if ($_respStream) {
                        if ($_respStream.CanSeek) { $_respStream.Position = 0 }
                        $_reader = New-Object System.IO.StreamReader($_respStream)
                        try { $_body = $_reader.ReadToEnd(); if (-not [string]::IsNullOrWhiteSpace($_body)) { $_azDetail = $_body } }
                        finally { $_reader.Close() }
                    }
                } catch { }
            }
            $_azDetail = ($_azDetail -replace "`r?`n", ' ' -replace '\s{2,}', ' ').Trim()
            Write-Log "CheckCreateUpdate-TableDcr-Structure failed: $($_.Exception.Message)" 'ERROR'
            Write-Log '----- target context -----' 'ERROR'
            Write-Log ("  Subscription   : {0}" -f ($global:SI_AzSubscriptionId  | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  Workspace      : {0}" -f ($global:SI_WorkspaceName     | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  Workspace RG   : {0}" -f ($global:SI_WorkspaceResourceGroup | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  DCE            : {0}" -f ($global:SI_DceName           | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  DCE RG         : {0}" -f ($global:SI_DceResourceGroup  | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  DCR            : {0}" -f ($global:SI_Shodan_DcrName    | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  DCR RG         : {0}" -f ($global:SI_DcrResourceGroup  | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log ("  Target table   : {0}" -f $tableName) 'ERROR'
            Write-Log ("  SPN AppId      : {0}" -f ($global:SI_SPN_AppId         | ForEach-Object { if ($_) { $_ } else { '<unset>' } })) 'ERROR'
            Write-Log '----- Azure error body -----' 'ERROR'
            Write-Log ("  {0}" -f $_azDetail) 'ERROR'
            Write-Log '----- common causes -----' 'ERROR'
            Write-Log "  1) Schema drift -- existing DCR/table column type differs from engine's current row shape. Azure body usually says 'InvalidTransformOutput: <col> produced:X, output:Y'. Delete BOTH the DCR ('$($global:SI_Shodan_DcrName)') AND the table ('$tableName') in workspace '$($global:SI_WorkspaceName)' and re-run; engine will recreate with the correct shape." 'ERROR'
            Write-Log "  2) SPN lacks Contributor (or Monitoring Contributor) on DCR resource group '$($global:SI_DcrResourceGroup)' in sub '$($global:SI_AzSubscriptionId)'." 'ERROR'
            Write-Log '  3) Schema sample contains a null/empty value in a required column (engine should have caught this upstream).' 'ERROR'
            throw
        }

        # Step 2. ARM consistency sleep -- newly created DCR's immutableId isn't
        # discoverable in ARG immediately; Post-* needs it.
        Start-Sleep -Seconds 15

        # Step 3. Refresh the DCR cache so Post-* can resolve DcrName -> immutableId
        # via $global:AzDcrDetails (otherwise the module's fallback can send a bogus
        # id and the Log Ingestion API 404s).
        Write-Log 'Get-AzDcrListAll (refresh DCE/DCR cache)' 'STEP'
        try {
            $global:AzDcrDetails = Get-AzDcrListAll `
                                        -AzAppId        $global:LogIngestAppId `
                                        @__ingestAuth `
                                        -TenantId       $global:TenantId `
                                        -Verbose:$false 4>$null
        } catch {
            Write-Log "Get-AzDcrListAll failed: $($_.Exception.Message) -- continuing; Post-* will fall back to ARG." 'WARN'
        }

        # Step 4. CollectionTime safety net (already stamped upstream).
        $DataVariable = @($Rows)
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable -Verbose:$false 4>$null

        # Step 5. Host identity columns (Computer / ComputerFqdn / UserLoggedOn).
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                                    -Column1Name Computer     -Column1Data $env:ComputerName `
                                    -Column2Name ComputerFqdn -Column2Data ([System.Net.Dns]::GetHostEntry($env:ComputerName)).HostName `
                                    -Column3Name UserLoggedOn -Column3Data $env:USERNAME `
                                    -Verbose:$false 4>$null

        # Step 6. Normalise column names to DCR-acceptable form.
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$false 4>$null

        # Step 7. Align data structure with the declared DCR schema.
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable -Verbose:$false 4>$null

        # Step 8. Ingest.
        $global:EnableCompressionDefault = $true
        Write-Log ('Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output (rows={0})' -f $DataVariable.Count) 'STEP'
        $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                            -DceName     $global:SI_DceName `
                            -DcrName     $global:SI_Shodan_DcrName `
                            -Data        $DataVariable `
                            -TableName   $tableName `
                            -AzAppId     $global:LogIngestAppId `
                            @__ingestAuth `
                            -TenantId    $global:TenantId `
                            -Verbose:$false 4>$null
    } finally {
        $global:VerbosePreference = $_savedVerbosePreference
    }

    Write-Log "ingest completed" "SUCCESS"
}

# ============================================================
# EXTRA IPs (manual list -- non-Azure / non-MDE assets like physical
# firewalls, branch-office gateways, partner endpoints). Configured in
# asset-profiling-schema/public-ip.schema.custom.json under "extraIPs.entries".
# Each entry: ipAddress (required), assetName (required), tier (0..3),
# cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity (optional).
# Falls back to $global:SI_Shodan_ExtraIPs (PowerShell hashtable list) if set.
# ============================================================
function Get-PublicIpsFromExtraList {
    [CmdletBinding()]
    param()

    $entries = New-Object System.Collections.Generic.List[object]

    # Source 1: customer schema overlay JSON (preferred -- config-as-data)
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $customSchema = Join-Path $repoRoot 'asset-profiling-schema/public-ip.schema.custom.json'
    if (Test-Path -LiteralPath $customSchema) {
        try {
            $body = Get-Content -LiteralPath $customSchema -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($body.PSObject.Properties['extraIPs'] -and $body.extraIPs.PSObject.Properties['entries']) {
                foreach ($e in @($body.extraIPs.entries)) { [void]$entries.Add($e) }
            }
        } catch {
            Write-Log ("Failed to parse {0}: {1}" -f $customSchema, $_.Exception.Message) "WARN"
        }
    }

    # Source 2: legacy global override (PowerShell hashtable list)
    if ($global:SI_Shodan_ExtraIPs) {
        foreach ($e in @($global:SI_Shodan_ExtraIPs)) { [void]$entries.Add($e) }
    }

    if ($entries.Count -eq 0) { return @() }

    # Case-insensitive scalar getter -- inline, no closure (closures over loop
    # variables collapsed all 3 entries into one row of array-IpAddress in v2.2).
    function _GetExtraField {
        param($Entry, [string]$Key)
        if ($null -eq $Entry) { return $null }
        if ($Entry -is [hashtable]) {
            foreach ($k in $Entry.Keys) {
                if ([string]::Equals([string]$k, $Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $Entry[$k] }
            }
            return $null
        }
        foreach ($p in $Entry.PSObject.Properties) {
            if ([string]::Equals($p.Name, $Key, [System.StringComparison]::OrdinalIgnoreCase)) { return $p.Value }
        }
        return $null
    }

    $ipRx = '^(?:\d{1,3}\.){3}\d{1,3}$'
    $out  = New-Object System.Collections.Generic.List[object]
    foreach ($e in $entries) {
        $ipRaw = _GetExtraField -Entry $e -Key 'IpAddress'
        $ip    = if ($null -eq $ipRaw) { '' } else { [string]$ipRaw }
        $name  = [string](_GetExtraField -Entry $e -Key 'AssetName')
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -notmatch $ipRx) {
            Write-Log ("ExtraIPs entry skipped -- IpAddress missing or not IPv4: '{0}'" -f $ip) "WARN"
            continue
        }
        if ([string]::IsNullOrWhiteSpace($name)) {
            Write-Log ("ExtraIPs entry skipped -- AssetName required for '{0}'" -f $ip) "WARN"
            continue
        }
        $tier = _GetExtraField -Entry $e -Key 'Tier'
        if ($null -eq $tier -or [string]::IsNullOrWhiteSpace([string]$tier)) { $tier = 99 }
        [void]$out.Add([pscustomobject]@{
            IpAddress           = $ip
            AssetName           = $name
            AssetEngine         = 'extra'
            AssetTier           = [int]$tier
            cmdbId              = [string](_GetExtraField -Entry $e -Key 'cmdbId')
            cmdbName            = [string](_GetExtraField -Entry $e -Key 'cmdbName')
            cmdbCriticality     = [string](_GetExtraField -Entry $e -Key 'cmdbCriticality')
            cmdbDataSensitivity = [string](_GetExtraField -Entry $e -Key 'cmdbDataSensitivity')
        })
    }
    if ($out.Count -gt 0) {
        Write-Log ("ExtraIPs loaded: {0} manual target(s)" -f $out.Count) "SUCCESS"
    }
    # NOTE: do NOT use ',$out.ToArray()' (comma-protector). For 1-element results it
    # would protect against unwrap, but for N>1 it creates a NESTED array that the
    # caller's `@(Get-...)` cannot flatten -- result: foreach iterates ONCE with
    # $r = [array of N]. Plain return + caller @(...) handles both cases correctly.
    return $out.ToArray()
}

# ============================================================
# MAIN
# ============================================================

# Per-run heartbeat -> SI_RunHealth_CL. Same shape as the asset-profiling
# pipeline; lets a single KQL detect crashed/missing engine runs across the
# whole stack regardless of which engine wrote the row.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine/asset-profiling/shared/Send-SIRunHealthRow.ps1')
$script:_RunHealthCtx = [pscustomobject]@{
    RunId          = [guid]::NewGuid().ToString()
    Engine         = 'publicip-scanner'
    ShardIndex     = 0
    ShardCount     = 1
    StartedAt      = $script:_StartTime
    CollectionTime = $script:_CollectionTime
}
try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {}

$_phRunHealth_ExitReason = 'success'
$_phRunHealth_ErrorMsg   = ''
$_phRunHealth_AssetCount = -1
try {
    Write-Log "=== SecurityInsight PublicIP Scanner (Shodan) -- $script:_CollectionTime ===" "STEP"
    $discovered = @(Get-PublicIpsFromProfileTables)
    $extras     = @(Get-PublicIpsFromExtraList)

    # Merge: discovered IPs win on duplicate (they carry richer profile context);
    # extras only contribute IPs the discovery query didn't already find.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $discovered) { [void]$seen.Add(([string]$r.IpAddress)) }
    $newExtras = @($extras | Where-Object { $seen.Add(([string]$_.IpAddress)) })
    if ($newExtras.Count -lt $extras.Count) {
        Write-Log ("ExtraIPs: {0} duplicate of discovered IP(s) skipped" -f ($extras.Count - $newExtras.Count)) "INFO"
    }
    $targets = @($discovered + $newExtras)
    if (-not $targets -or $targets.Count -eq 0) { Write-Log "nothing to do; exiting" "INFO"; return }

    # Optional fresh-scan flow. Returns $false if a scan is still in flight
    # at the deadline -- in that case we exit and let the next run pick it up.
    if ([bool]$global:SI_Shodan_ForceFreshScan) {
        $proceed = Invoke-FreshScanFlow -Targets $targets
        if (-not $proceed) {
            Write-Log "deferring read until scan completes (state file persisted). Exiting cleanly." "INFO"
            return
        }
    }

    $rows = Invoke-ShodanScans -Targets $targets
    $_phRunHealth_AssetCount = @($rows).Count

    # JSON sidecar (for offline review / SIEM forwarding)
    $outDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data'
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
    $script:_OutputJson = Join-Path $outDir 'SecurityInsight_PublicIpScan.json'
    $rows | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $script:_OutputJson -Encoding UTF8 -Force
    Write-Log "JSON sidecar: $script:_OutputJson" "SUCCESS"

    Send-RowsToLogAnalytics -Rows $rows

    $elapsed = ([datetime]::UtcNow - $script:_StartTime).TotalSeconds
    Write-Log ("=== PublicIP Scanner completed in {0:n1}s ===" -f $elapsed) "SUCCESS"
} catch {
    $_phRunHealth_ExitReason = 'failure'
    $_phRunHealth_ErrorMsg   = $_.Exception.Message
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    throw
} finally {
    try {
        Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'End' `
                            -AssetCount $_phRunHealth_AssetCount `
                            -ExitReason $_phRunHealth_ExitReason `
                            -ErrorMessage $_phRunHealth_ErrorMsg
    } catch {}
}
