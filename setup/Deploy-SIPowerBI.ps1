#Requires -Version 5.1
<#
.SYNOPSIS
    Step 4 -- deploy (or refresh the deployment of) the SecurityInsight
    management dashboard into the customer's Power BI tenant via REST API.

.DESCRIPTION
    One-time onboarding step per customer. Mirrors the Step 3 / Step 4 shape:
    read config from LauncherConfig.defaults/.custom.ps1, authenticate to
    Power BI, and make the target state happen (idempotent).

    What this script does:
      1. Authenticates to the Power BI REST API (v1.0 + v2023-10-01) using
         a service principal. Same 4 auth methods as the rest of
         SecurityInsight (Interactive / ManagedIdentity / SpnSecret /
         SpnCertificate). The SPN needs Power BI API permissions and must
         be allowed to use the APIs via the admin tenant setting.
      2. Resolves / creates the target Power BI workspace (a.k.a. group).
      3. Uploads the solution-shipped .pbix via POST /groups/{id}/imports
         with nameConflict=CreateOrOverwrite so re-runs update in place.
      4. Rebinds the dataset's Power BI parameters (LA_WorkspaceId,
         LA_TenantId, StalenessDays, TopNFindings) via
         POST /groups/{id}/datasets/{id}/Default.UpdateParameters.
      5. Grants the deploying SPN dataset owner rights and (optionally)
         adds an access group as workspace Viewer/Member/Admin so the
         real humans can see the dashboard.
      6. Triggers an initial dataset refresh so the dashboard has data on
         first open (optional; controlled by -TriggerInitialRefresh).

    This script runs ONCE per customer + again whenever you rev the .pbix
    (new tiles, new pages). Per-run data freshness is handled by the
    RiskAnalysis engine's SendToPowerBI flag, which only triggers a
    dataset refresh -- no .pbix upload.

.PARAMETER PbixPath
    Path to the .pbix to deploy. Defaults to the solution-shipped copy
    at preview/PowerBI/SecurityInsight-RiskAnalysis.pbix. Override only if
    you have a customer-specific variant.

.PARAMETER PowerBIWorkspaceName
    Display name of the target Power BI workspace. Created if missing.
    Default: 'SecurityInsight-Reports'.

.PARAMETER ReportName
    Display name of the report inside that workspace. The .pbix upload
    uses this as the 'datasetDisplayName' parameter -- so it's also the
    name of the underlying dataset. Default: 'SecurityInsight - Risk Analysis'.

.PARAMETER LAWorkspaceId
    GUID-only Log Analytics Workspace ID (NOT the full Resource ID).
    Injected into the .pbix parameter 'LA_WorkspaceId' so the Power BI
    queries know which LA workspace to hit. Defaults to
    $global:WorkspaceId if set, otherwise derived from
    $global:WorkspaceResourceId.

.PARAMETER LATenantId
    GUID tenant ID of the LA workspace's home tenant. Defaults to
    $global:SpnTenantId.

.PARAMETER StalenessDays
    Default value for the StalenessDays parameter in the dashboard (the
    "open for at least N days" threshold on the stale-findings page).
    Default: 30.

.PARAMETER TopNFindings
    Default value for the TopNFindings parameter in the dashboard
    (the "top N by RiskScore" size on the operational page). Default: 25.

.PARAMETER AccessGroupObjectId
    Optional. Azure AD group objectId. If set, the script adds this group
    as a Viewer on the workspace so members can open the dashboard. Skip
    to manage access manually in the Power BI portal.

.PARAMETER AccessGroupRole
    Role granted to -AccessGroupObjectId. One of Viewer, Member, Contributor,
    Admin. Default: Viewer.

.PARAMETER TriggerInitialRefresh
    Switch. If set, the script queues an initial dataset refresh after
    parameter rebind so the dashboard has data on first open. Default:
    $true.

.PARAMETER AuthMethod
    How to authenticate to Power BI. One of:
      Interactive     - device code / browser sign-in (ops laptop)
      ManagedIdentity - Azure host's MI (only works if tenant setting
                        allows SPN APIs)
      SpnSecret       - Power BI SPN + plaintext secret
      SpnCertificate  - Power BI SPN + cert thumbprint

.PARAMETER AuthTenantId / AuthClientId / AuthClientSecret / AuthCertificateThumbprint
    Standard SecurityInsight auth parameters. Same semantics as Step 2/3/4.

.PARAMETER WhatIfMode
    Dry-run preview. Walks the catalogue, calls GET endpoints to check
    current state, but does NOT create workspaces, upload pbix, or rebind
    parameters.

.NOTES
    Solution     : SecurityInsight
    File         : Step4_Deploy-SecurityInsight-PowerBI-Dashboard.ps1
    Developed by : Morten Knudsen, Microsoft MVP
    Prereqs      : See DOCS/PowerBI-Prerequisites.md for the one-time
                   tenant setup (Power BI SPN, API permissions, admin
                   tenant setting, workspace admin rights).
#>
[CmdletBinding()]
param(
    [string]$PbixPath,
    [string]$PowerBIWorkspaceName = 'SecurityInsight-Reports',
    [string]$ReportName           = 'SecurityInsight - Risk Analysis',

    [string]$LAWorkspaceId,
    [string]$LATenantId,

    [int]$StalenessDays = 30,
    [int]$TopNFindings  = 25,

    [string]$AccessGroupObjectId,
    [ValidateSet('Viewer','Member','Contributor','Admin')]
    [string]$AccessGroupRole = 'Viewer',

    [switch]$TriggerInitialRefresh,

    [switch]$WhatIfMode,

    # ---- Auth selection (same pattern as Step 2/3/4) ----
    [ValidateSet('Interactive','ManagedIdentity','SpnSecret','SpnCertificate')]
    [string]$AuthMethod = 'SpnSecret',
    [string]$AuthTenantId,
    [string]$AuthClientId,
    [string]$AuthClientSecret,
    [string]$AuthCertificateThumbprint
)

$ErrorActionPreference = 'Stop'

#region Logging helpers
function Write-Step ([string]$m) { Write-Host "[STEP]    $m" -ForegroundColor Cyan }
function Write-Info ([string]$m) { Write-Host "[INFO]    $m" -ForegroundColor White }
function Write-Ok   ([string]$m) { Write-Host "[OK]      $m" -ForegroundColor Green }
function Write-Add  ([string]$m) { Write-Host "[APPLIED] $m" -ForegroundColor Yellow }
function Write-Skip ([string]$m) { Write-Host "[SKIP]    $m" -ForegroundColor DarkYellow }
function Write-Err2 ([string]$m) { Write-Host "[FAIL]    $m" -ForegroundColor Red }
function Write-Sep         { Write-Host ("-" * 88) -ForegroundColor White }
#endregion

# ---------------------------------------------------------------------------
# Resolve pbix path
# ---------------------------------------------------------------------------
if (-not $PbixPath) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\preview\PowerBI\SecurityInsight-RiskAnalysis.pbix')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { $PbixPath = (Resolve-Path -LiteralPath $c).Path; break }
    }
}
if (-not $PbixPath -or -not (Test-Path -LiteralPath $PbixPath)) {
    throw @"
Power BI .pbix not found. Expected at:
  preview/PowerBI/SecurityInsight-RiskAnalysis.pbix

If you haven't authored the .pbix yet, follow docs/PowerBI-dashboard-spec.md
in Power BI Desktop, save the result as SecurityInsight-RiskAnalysis.pbix in
that folder, and re-run this script.

Or pass -PbixPath '<path>' to use a custom location.
"@
}
$pbixFileName = [IO.Path]::GetFileName($PbixPath)
$pbixSizeMB   = [math]::Round((Get-Item $PbixPath).Length / 1MB, 2)

# ---------------------------------------------------------------------------
# Resolve LA workspace id + tenant id
# ---------------------------------------------------------------------------
if (-not $LAWorkspaceId) {
    if ($global:WorkspaceId) {
        $LAWorkspaceId = [string]$global:WorkspaceId
    } elseif ($global:WorkspaceResourceId -match '/workspaces/([^/]+)$') {
        # best-effort: Resource ID ends with /workspaces/<NAME>, but we need the
        # customerId GUID, not the name. If they only gave us the resource id
        # we can't safely derive it -- force-fail with a clear message.
        throw "LAWorkspaceId not supplied and can't be inferred. Pass -LAWorkspaceId '<GUID>' (Log Analytics blade -> Properties -> Workspace ID)."
    } else {
        throw "LAWorkspaceId not supplied. Pass -LAWorkspaceId '<GUID>' or set `$global:WorkspaceId."
    }
}
if (-not $LATenantId) {
    $LATenantId = if ($AuthTenantId) { $AuthTenantId } else { $global:SpnTenantId }
    if (-not $LATenantId) { throw "LATenantId not supplied. Pass -LATenantId or set `$global:SpnTenantId." }
}

Write-Host ""
Write-Host "========================================================================================" -ForegroundColor Cyan
Write-Host "  SecurityInsight -- Step 4: Deploy management dashboard to Power BI"                   -ForegroundColor Cyan
Write-Host "  pbix           : $pbixFileName ($pbixSizeMB MB)"                                        -ForegroundColor White
Write-Host "  Workspace      : $PowerBIWorkspaceName"                                                 -ForegroundColor White
Write-Host "  Report         : $ReportName"                                                           -ForegroundColor White
Write-Host "  LA workspace   : $LAWorkspaceId"                                                        -ForegroundColor White
Write-Host "  LA tenant      : $LATenantId"                                                           -ForegroundColor White
Write-Host "  Auth method    : $AuthMethod"                                                           -ForegroundColor White
Write-Host "  WhatIfMode     : $([bool]$WhatIfMode)"                                                  -ForegroundColor White
Write-Host "========================================================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Acquire Power BI token (resource scope: https://analysis.windows.net/powerbi/api/.default)
# ---------------------------------------------------------------------------
$pbiResource = 'https://analysis.windows.net/powerbi/api/.default'

function Get-PowerBIToken {
    param(
        [Parameter(Mandatory)][string]$Method,
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint
    )
    if (-not $TenantId) { throw "TenantId required for Power BI auth." }

    switch ($Method) {
        'SpnSecret' {
            if (-not $ClientId -or -not $ClientSecret) { throw "SpnSecret requires -AuthClientId + -AuthClientSecret." }
            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = $pbiResource
            }
            $resp = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body $body -ContentType 'application/x-www-form-urlencoded'
            return $resp.access_token
        }
        'SpnCertificate' {
            if (-not $ClientId -or -not $CertificateThumbprint) { throw "SpnCertificate requires -AuthClientId + -AuthCertificateThumbprint." }
            # Cert-based OAuth2 client assertion flow. Cert must be installed in
            # CurrentUser\My or LocalMachine\My.
            $cert = Get-ChildItem "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) { $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue }
            if (-not $cert) { throw "Cert '$CertificateThumbprint' not found in CurrentUser\My or LocalMachine\My." }

            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $jwtHeader = @{ alg='RS256'; typ='JWT'; x5t=[Convert]::ToBase64String($cert.GetCertHash()) } | ConvertTo-Json -Compress
            $jwtPayload = @{
                aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
                iss = $ClientId
                sub = $ClientId
                jti = [guid]::NewGuid().ToString()
                nbf = $now
                exp = $now + 600
            } | ConvertTo-Json -Compress
            $enc1 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtHeader)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $enc2 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jwtPayload)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $toSign = "$enc1.$enc2"
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($toSign), 'SHA256', 'Pkcs1')
            $enc3 = [Convert]::ToBase64String($sig).TrimEnd('=').Replace('+','-').Replace('/','_')
            $assertion = "$toSign.$enc3"

            $body = @{
                grant_type            = 'client_credentials'
                client_id             = $ClientId
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = $assertion
                scope                 = $pbiResource
            }
            $resp = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body $body -ContentType 'application/x-www-form-urlencoded'
            return $resp.access_token
        }
        'ManagedIdentity' {
            # IMDS endpoint -- only works on Azure-hosted runtime (VM / Function / App Service / Runbook worker)
            $imdsUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://analysis.windows.net/powerbi/api"
            if ($ClientId) { $imdsUri += "&client_id=$ClientId" }
            $resp = Invoke-RestMethod -Method GET -Uri $imdsUri -Headers @{ Metadata = 'true' }
            return $resp.access_token
        }
        'Interactive' {
            # Device code flow -- simplest path that works in any terminal.
            $appId = if ($ClientId) { $ClientId } else { '1950a258-227b-4e31-a9cf-717495945fc2' }  # well-known Azure PowerShell client id
            $deviceBody = @{
                client_id = $appId
                scope     = $pbiResource
            }
            $dev = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
                -Body $deviceBody -ContentType 'application/x-www-form-urlencoded'
            Write-Host ""
            Write-Host "  Device code auth:" -ForegroundColor Yellow
            Write-Host "    Open $($dev.verification_uri)" -ForegroundColor Yellow
            Write-Host "    and enter code: $($dev.user_code)" -ForegroundColor Yellow
            Write-Host ""
            $deadline = (Get-Date).AddSeconds($dev.expires_in)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds ([math]::Max(5, $dev.interval))
                try {
                    $pollBody = @{
                        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                        client_id   = $appId
                        device_code = $dev.device_code
                    }
                    $resp = Invoke-RestMethod -Method POST `
                        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                        -Body $pollBody -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                    if ($resp.access_token) { return $resp.access_token }
                } catch {
                    # 'authorization_pending' is expected while the user is still signing in
                    $errBody = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($errBody.error -ne 'authorization_pending') { throw }
                }
            }
            throw "Device code auth timed out after $($dev.expires_in) seconds."
        }
        default { throw "Unsupported AuthMethod '$Method'." }
    }
}

Write-Sep
Write-Step "Acquiring Power BI access token (AuthMethod=$AuthMethod)"
try {
    $token = Get-PowerBIToken -Method $AuthMethod -TenantId $AuthTenantId `
        -ClientId $AuthClientId -ClientSecret $AuthClientSecret `
        -CertificateThumbprint $AuthCertificateThumbprint
    Write-Ok ("token acquired ({0} chars)" -f $token.Length)
} catch {
    throw "Failed to acquire Power BI token: $($_.Exception.Message)"
}

$pbiHeaders = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'
}
$pbiBase = 'https://api.powerbi.com/v1.0/myorg'

# ---------------------------------------------------------------------------
# 2. Resolve / create the workspace (group)
# ---------------------------------------------------------------------------
Write-Sep
Write-Step "Resolving Power BI workspace: $PowerBIWorkspaceName"
$groups = Invoke-RestMethod -Method GET -Uri "$pbiBase/groups?`$filter=name eq '$PowerBIWorkspaceName'" -Headers $pbiHeaders
$targetGroup = $groups.value | Select-Object -First 1

if (-not $targetGroup) {
    if ($WhatIfMode) {
        Write-Skip "workspace '$PowerBIWorkspaceName' not found -- WOULD create (WhatIfMode)"
    } else {
        Write-Step "workspace '$PowerBIWorkspaceName' not found -- creating"
        $createBody = @{ name = $PowerBIWorkspaceName } | ConvertTo-Json -Compress
        $targetGroup = Invoke-RestMethod -Method POST -Uri "$pbiBase/groups?workspaceV2=true" -Headers $pbiHeaders -Body $createBody
        Write-Add ("created workspace  id={0}" -f $targetGroup.id)
    }
} else {
    Write-Ok ("workspace found  id={0}" -f $targetGroup.id)
}

if (-not $targetGroup) {
    # WhatIfMode without an existing workspace -- can't continue any further
    Write-Skip "WhatIfMode + no existing workspace -- cannot evaluate downstream state. Exiting."
    return
}
$groupId = $targetGroup.id

# ---------------------------------------------------------------------------
# 3. Upload the .pbix (create or overwrite)
# ---------------------------------------------------------------------------
Write-Sep
Write-Step "Uploading $pbixFileName to workspace"
if ($WhatIfMode) {
    Write-Skip "WOULD upload $pbixFileName to group $groupId (WhatIfMode)"
} else {
    # Power BI Import API requires multipart/form-data with the pbix as a file part.
    $importUri = "$pbiBase/groups/$groupId/imports?datasetDisplayName=$([uri]::EscapeDataString($ReportName))&nameConflict=CreateOrOverwrite"
    $boundary = "----SI-" + [guid]::NewGuid().ToString('N')
    $bytes = [System.IO.File]::ReadAllBytes($PbixPath)
    $LF = "`r`n"
    $preamble = "--$boundary$LF" +
                "Content-Disposition: form-data; name=""file""; filename=""$pbixFileName""$LF" +
                "Content-Type: application/octet-stream$LF$LF"
    $postamble = "$LF--$boundary--$LF"
    $preambleBytes  = [Text.Encoding]::UTF8.GetBytes($preamble)
    $postambleBytes = [Text.Encoding]::UTF8.GetBytes($postamble)
    $body = New-Object byte[] ($preambleBytes.Length + $bytes.Length + $postambleBytes.Length)
    [Array]::Copy($preambleBytes, 0, $body, 0, $preambleBytes.Length)
    [Array]::Copy($bytes,         0, $body, $preambleBytes.Length, $bytes.Length)
    [Array]::Copy($postambleBytes, 0, $body, $preambleBytes.Length + $bytes.Length, $postambleBytes.Length)

    $importHeaders = @{
        Authorization = "Bearer $token"
        'Content-Type' = "multipart/form-data; boundary=$boundary"
    }
    $importResp = Invoke-RestMethod -Method POST -Uri $importUri -Headers $importHeaders -Body $body
    $importId = $importResp.id

    # Poll import status
    Write-Info "polling import status..."
    $deadline = (Get-Date).AddMinutes(5)
    $import = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $import = Invoke-RestMethod -Method GET -Uri "$pbiBase/groups/$groupId/imports/$importId" -Headers $pbiHeaders
        if ($import.importState -eq 'Succeeded') { break }
        if ($import.importState -eq 'Failed')    { throw "Power BI import failed: $($import | ConvertTo-Json -Depth 5)" }
    }
    if ($import.importState -ne 'Succeeded') { throw "Power BI import timed out (state=$($import.importState))." }
    Write-Add ("imported  state={0}  reports={1}  datasets={2}" -f $import.importState, @($import.reports).Count, @($import.datasets).Count)

    $datasetId = $import.datasets[0].id
    $reportId  = $import.reports[0].id
    Write-Info ("datasetId: $datasetId")
    Write-Info ("reportId : $reportId")
}

# ---------------------------------------------------------------------------
# 4. Rebind parameters (LA_WorkspaceId / LA_TenantId / StalenessDays / TopNFindings)
# ---------------------------------------------------------------------------
if (-not $WhatIfMode) {
    Write-Sep
    Write-Step "Rebinding dataset parameters"
    $paramBody = @{
        updateDetails = @(
            @{ name = 'LA_WorkspaceId'; newValue = $LAWorkspaceId },
            @{ name = 'LA_TenantId';    newValue = $LATenantId },
            @{ name = 'StalenessDays';  newValue = [string]$StalenessDays },
            @{ name = 'TopNFindings';   newValue = [string]$TopNFindings }
        )
    } | ConvertTo-Json -Depth 5 -Compress
    try {
        Invoke-RestMethod -Method POST `
            -Uri "$pbiBase/groups/$groupId/datasets/$datasetId/Default.UpdateParameters" `
            -Headers $pbiHeaders -Body $paramBody | Out-Null
        Write-Add "parameters rebound"
    } catch {
        # If the pbix doesn't define some of these parameters, UpdateParameters returns 400.
        # Surface the error but continue -- the report still works with whatever was baked in.
        Write-Err2 ("UpdateParameters failed: {0}" -f $_.Exception.Message)
        Write-Info "Continuing -- verify the .pbix defines LA_WorkspaceId / LA_TenantId / StalenessDays / TopNFindings parameters."
    }

    # Rebind the dataset's credentials (LA is OAuth2, signed in as the SPN/user)
    # is intentionally LEFT to the customer's Power BI admin UX -- datasets
    # deployed to Power BI via Import always require a one-time "Take over"
    # and "Sign in" in the dataset settings pane for the gateway/cloud
    # connection. There is no supported REST endpoint for OAuth2 credential
    # plumbing that works with Log Analytics today. See PowerBI-Prerequisites.md.
}

# ---------------------------------------------------------------------------
# 5. Grant access group
# ---------------------------------------------------------------------------
if ($AccessGroupObjectId -and -not $WhatIfMode) {
    Write-Sep
    Write-Step ("Granting {0} {1} on workspace to AAD group {2}" -f $AccessGroupObjectId, $AccessGroupRole, $PowerBIWorkspaceName)
    $accessBody = @{
        identifier             = $AccessGroupObjectId
        principalType          = 'Group'
        groupUserAccessRight   = $AccessGroupRole
    } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Method POST -Uri "$pbiBase/groups/$groupId/users" -Headers $pbiHeaders -Body $accessBody | Out-Null
        Write-Add "access group granted"
    } catch {
        # Already a member? 409 conflict. Soft-warn and continue.
        Write-Skip ("group already has access or grant failed: {0}" -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# 6. Trigger initial refresh
# ---------------------------------------------------------------------------
if ($TriggerInitialRefresh -and -not $WhatIfMode) {
    Write-Sep
    Write-Step "Triggering initial dataset refresh"
    try {
        Invoke-RestMethod -Method POST `
            -Uri "$pbiBase/groups/$groupId/datasets/$datasetId/refreshes" `
            -Headers $pbiHeaders -Body '{"notifyOption":"NoNotification"}' | Out-Null
        Write-Add "refresh queued"
    } catch {
        Write-Err2 ("initial refresh failed: {0}" -f $_.Exception.Message)
        Write-Info "This usually means the dataset's LA credentials aren't bound yet. See PowerBI-Prerequisites.md for the one-time 'Take over + Sign in' step."
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Sep
Write-Host ""
if ($WhatIfMode) {
    Write-Host "  ========= Step 4 dry-run summary (no changes made) =========" -ForegroundColor Cyan
} else {
    Write-Host "  ========= Step 4 deployment summary =========" -ForegroundColor Cyan
    Write-Host ("  Workspace  : {0}  (id={1})"  -f $PowerBIWorkspaceName, $groupId)   -ForegroundColor White
    if ($reportId)  { Write-Host ("  Report     : {0}  (id={1})"  -f $ReportName, $reportId)  -ForegroundColor White }
    if ($datasetId) { Write-Host ("  Dataset    : id={0}"         -f $datasetId)              -ForegroundColor White }
    Write-Host ("  Portal URL : https://app.powerbi.com/groups/{0}/reports/{1}" -f $groupId, $reportId) -ForegroundColor White
}
Write-Host ""
Write-Host "  One-time post-deploy step in the Power BI portal (can't be automated today):" -ForegroundColor Yellow
Write-Host "    1. Open https://app.powerbi.com/groups/$groupId/settings/datasets/$datasetId" -ForegroundColor Yellow
Write-Host "    2. Dataset settings -> 'Take over' if prompted" -ForegroundColor Yellow
Write-Host "    3. Data source credentials -> sign in to 'Azure Monitor Logs'" -ForegroundColor Yellow
Write-Host "    4. (optional) Scheduled refresh -> set to 8x/day or match your RiskAnalysis cadence" -ForegroundColor Yellow
Write-Host ""
Write-Sep
