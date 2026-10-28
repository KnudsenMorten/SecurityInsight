<#
.SYNOPSIS
    CriticalAssetTagging - engine script in the SecurityInsight solution.

.NOTES
    Solution       : SecurityInsight
    File           : CriticalAssetTagging.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

    REPORT ONLY BY DEFAULT (operator 2026-10-07). Started directly, without a launcher, a run writes tags only when asked:
      -Apply on the run, or $global:SI_AssetTagging_Apply = $true in the configuration.
    -WhatIfMode (report only) wins over -Apply; a $global:WhatIfMode = $true still means report only, and a
    $global:WhatIfMode = $false is NOT a request to write (it was the old default, copied into many configurations).
    The launchers and the container job decide the mode themselves and pass it as -RunMode report|write.
    One decision for every entry point: Resolve-SIAssetTaggingRunMode (AssetTagging.Resolve.ps1).
#>
param(
  # Write the tags. Without it (and without $global:SI_AssetTagging_Apply = $true) the run only reports what it would write.
  [switch]$Apply,
  # Report only -- the default; kept for scripts that pass it. Wins over -Apply.
  [switch]$WhatIfMode,
  # Set by a launcher or the container job, which have already decided: 'report' or 'write'. Not for direct use.
  [ValidateSet('', 'report', 'write')][string]$RunMode = ''
)
# The run mode is decided once, below, before anything reads WhatIfMode (the parameter names are reused later on).
$script:ATApplySwitch  = [bool]$Apply
$script:ATWhatIfSwitch = [bool]$WhatIfMode
$script:ATHostRunMode  = [string]$RunMode
Remove-Variable -Name Apply, WhatIfMode, RunMode -ErrorAction SilentlyContinue
# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }

Write-host "***********************************************************************************************"
Write-host "Critical Asset Tagging using YAML-file"
Write-host ""
Write-host "Support: https://github.com/KnudsenMorten/SecurityInsight/issues   (Pro: https://portal.invardia.com/ > Support)"
Write-host "***********************************************************************************************"

# No PowerShell modules: Azure, Graph and Defender are reached over plain REST.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-Yaml.ps1')   # SecurityInsight's own YAML reader (no powershell-yaml module)
# Microsoft Graph and the Defender API over plain REST -- no Microsoft.Graph SDK, no MicrosoftGraphPS.
# This was the last engine on the SDK; it now signs in and calls Graph itself (_shared/AT-GraphRest.ps1).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-GraphRest.ps1')
. (Join-Path $PSScriptRoot '_shared/AT-GraphRest.ps1')
# #236: every planned and executed write is a row in the asset-tag activity table.
. (Join-Path $PSScriptRoot '_shared/AT-Activity.ps1')
# #236: the managed identity sign-in helper is loaded by the HOST -- the container entry point, or the launcher's config
# loader on a VM -- never by the engine; the engine only follows $global:SI_UseManagedIdentity.

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

# -------------------------------------------------------------------------------------------------
# GLOBAL-ONLY CONFIG (launcher is source of truth)
# -------------------------------------------------------------------------------------------------

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
  $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

# KustoCL engine globals (set by launcher, optional - only required when KustoCL rules exist)
if ($null -eq $global:KustoWorkspaceId)  { $global:KustoWorkspaceId  = $null }
if ($null -eq $global:KustoTable)        { $global:KustoTable         = 'SI_IdentityAssets_CL' }
if ($null -eq $global:CsaAttributeSet)   { $global:CsaAttributeSet   = 'SecurityInsight' }

try {
  $global:SettingsPath = (Resolve-Path -LiteralPath $global:SettingsPath).Path
} catch {
  throw "SettingsPath does not exist or cannot be resolved: $($global:SettingsPath)"
}

if (-not [bool]$global:AutomationFramework -and -not [bool]$global:SI_UseManagedIdentity) {
  # #236: a managed-identity run has no SPN at all -- its tokens come from the identity endpoint.
  # v2.2.238 -- accept Secret OR CertThumbprint. The bridge in this engine's
  # preamble at v2.2.233 mirrors SI_SPN_CertThumbprint -> SpnCertificateThumbprint.
  $_hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
  $_hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
  if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
      (-not $_hasSecret -and -not $_hasCert)) {
    throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Launcher must set them or enable AutomationFramework."
  }
}

$SettingsPath        = $global:SettingsPath
$AutomationFramework = [bool]$global:AutomationFramework
$Scope               = @($global:Scope)

# REPORT ONLY unless told to write (see the help above). A host (launcher / container job) passes its decision as -RunMode;
# a direct run resolves it here with the same rules the launchers use.
if (-not (Get-Command -Name Resolve-SIAssetTaggingRunMode -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AssetTagging.Resolve.ps1') }
if ($script:ATHostRunMode) {
  $script:ATRunMode = [pscustomobject]@{ Apply = ($script:ATHostRunMode -eq 'write'); WhatIfMode = ($script:ATHostRunMode -ne 'write'); Source = 'host' }
} else {
  if ($script:ATApplySwitch -and $script:ATWhatIfSwitch) { Write-Host '[WARN] -Apply and -WhatIfMode were both given: -WhatIfMode wins, nothing is changed.' -ForegroundColor Yellow }
  $script:ATRunMode = Resolve-SIAssetTaggingRunMode -ApplySwitch $script:ATApplySwitch -WhatIfSwitch $script:ATWhatIfSwitch `
      -ApplySetting $global:SI_AssetTagging_Apply -ConfigWhatIf $global:WhatIfMode -EnabledSetting $global:SI_AssetTagging_Enabled
  if ($script:ATRunMode.Apply) { Write-Host ('[WARN] ' + (Get-SIAssetTaggingRunModeLine -Mode $script:ATRunMode)) -ForegroundColor Yellow }
  else { Write-Host ('[INFO] ' + (Get-SIAssetTaggingRunModeLine -Mode $script:ATRunMode)) }
}
$global:WhatIfMode = [bool]$script:ATRunMode.WhatIfMode
$WhatIfMode = [bool]$global:WhatIfMode

if ($null -eq $global:SuppressErrors) { $global:SuppressErrors = $false }
$SuppressErrors = [bool]$global:SuppressErrors

if ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }
$SuppressWarnings = [bool]$global:SuppressWarnings

$script:SuppressErrors   = $SuppressErrors
$script:SuppressWarnings = $SuppressWarnings
$script:WhatIfMode       = $WhatIfMode

#######################################################################################################
# FUNCTIONS
#######################################################################################################

function Write-Step  ($m){ Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-Info  ($m){ Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-Ok    ($m){ Write-Host "[OK]   $m" -ForegroundColor Green }

function Write-Warn2 {
  param($m)
  if (-not $script:SuppressWarnings) {
    Write-Host "[WARN] $m" -ForegroundColor Yellow
  }
}

function Write-Err2 {
  param($m)
  if (-not $script:SuppressErrors) {
    Write-Host "[ERR]  $m" -ForegroundColor Red
  }
}

function Write-Sep {
  param(
    [string]$Char = '-',
    [int]$Width = 110
  )
  Write-Host ($Char * $Width) -ForegroundColor DarkGray
}

function Write-BlockFields {
  param(
    [hashtable]$Fields,
    [ValidateSet('Info','Ok','Warn','Err')]
    [string]$Level = 'Info',
    [string]$Indent = ""
  )

  if (-not $Fields -or $Fields.Count -eq 0) { return }

  $color = switch ($Level) {
    'Ok'   { 'Green' }
    'Warn' { 'Yellow' }
    'Err'  { 'Red' }
    default { 'Gray' }
  }

  $keys = @($Fields.Keys)

  $preferredOrder = @(
    'Rule','Engine','Mode','Chunk','Count','Machines',
    'Name','Type','Tag','TagKey','TagValue',
    'Reason','TargetSub','ContextSub','Id',
    'ResourceId','Error'
  )

  $orderedKeys = @()
  foreach ($k in $preferredOrder) {
    if ($keys -contains $k) { $orderedKeys += $k }
  }
  foreach ($k in $keys) {
    if ($orderedKeys -notcontains $k) { $orderedKeys += $k }
  }

  foreach ($k in $orderedKeys) {
    $v = if ($null -eq $Fields[$k]) { "" } else { [string]$Fields[$k] }

    if ($k -in @('ResourceId','Error')) {
      Write-Host ("{0}{1,-12}:" -f $Indent, $k) -ForegroundColor $color
      foreach ($line in ($v -split "`r?`n")) {
        Write-Host $line -ForegroundColor $color
      }
    }
    else {
      Write-Host ("{0}{1,-12}: {2}" -f $Indent, $k, $v) -ForegroundColor $color
    }
  }
}

function Write-InfoBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($SeparatorBefore) { Write-Sep }
  Write-Info $Title
  Write-BlockFields -Fields $Fields -Level Info
  if ($SeparatorAfter) { Write-Sep }
}

function Write-OkBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($SeparatorBefore) { Write-Sep }
  Write-Ok $Title
  Write-BlockFields -Fields $Fields -Level Ok
  if ($SeparatorAfter) { Write-Sep }
}

function Write-WarnBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($script:SuppressWarnings) { return }

  if ($SeparatorBefore) { Write-Sep }
  Write-Warn2 $Title
  Write-BlockFields -Fields $Fields -Level Warn
  if ($SeparatorAfter) { Write-Sep }
}

function Write-ErrBlock {
  param(
    [Parameter(Mandatory)][string]$Title,
    [hashtable]$Fields = @{},
    [switch]$SeparatorBefore,
    [switch]$SeparatorAfter
  )

  if ($script:SuppressErrors) { return }

  if ($SeparatorBefore) { Write-Sep }
  Write-Err2 $Title
  Write-BlockFields -Fields $Fields -Level Err
  if ($SeparatorAfter) { Write-Sep }
}

function Tick {
  param([string]$Label="")
  if($script:_sw){
    $script:_sw.Stop()
    Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds)
    $script:_sw=$null
  }
}

function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Connect-GraphHighPriv {
  [CmdletBinding()]
  param()

  # CERTIFICATE FIRST, then the secret, and a loud refusal when neither is set -- an interactive
  # prompt on an unattended automation host reads as a hang, which is how the old secret-only
  # connect reached a live internal customer on v2.2.422. The token is for the same identity the
  # SDK connect used ($global:SpnClientId); Get-ATSpnAccessToken applies the same order.
  # #236: the managed identity first, when the run's sign-in switch is on -- the SPN order below is unchanged.
  if ([bool]$global:SI_UseManagedIdentity) {
    Write-Info ("Connecting to Microsoft Graph (managed identity{0})..." -f $(if ($global:SI_UAMI_ClientId) { ", client id $($global:SI_UAMI_ClientId)" } else { '' }))
  }
  elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)) {
    Write-Info ("Connecting to Microsoft Graph (app+certificate, thumbprint {0})..." -f $global:SpnCertificateThumbprint)
  }
  elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
    Write-Info "Connecting to Microsoft Graph (app+secret)..."
  }
  $script:ATGraphToken = Get-ATAccessToken -Resource 'https://graph.microsoft.com'

  $script:GraphLastConnectUtc = [datetime]::UtcNow
  Write-Ok ("Graph connected at {0:u}" -f $script:GraphLastConnectUtc)
  Write-Info "Graph requests: timeout 900s, up to 6 attempts on throttling or service errors"
}

function Get-RuleMode {
  param([AllowNull()][object]$Mode)
  if ($null -eq $Mode) { return 'PROD' }
  $m = ([string]$Mode).Trim()
  if ([string]::IsNullOrWhiteSpace($m)) { return 'PROD' }
  $m.ToUpperInvariant()
}

function Get-QueryEngine {
  param([AllowNull()][object]$QueryEngine)
  if ($null -eq $QueryEngine) { return 'DEFENDERGRAPH' }
  $qe = ([string]$QueryEngine).Trim()
  if ([string]::IsNullOrWhiteSpace($qe)) { return 'DEFENDERGRAPH' }
  $qe.ToUpperInvariant()
}

# ==========================================================================================
# KUSTOCL ENGINE - Log Analytics query + Entra CSA write-back
# ==========================================================================================

function Invoke-KustoCLQuery {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WorkspaceId,
    [Parameter(Mandatory)][string]$Query
  )

  # #639 lane 4: a rule's query can match millions of objects -- read in parts when one Log Analytics answer cannot carry
  # it (Read-SILaParts; a cut answer is refused, never tagged from). A part that fails fails the rule's read (it throws).
  if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-LaParts.ps1') }
  $result = Read-SILaParts -WorkspaceId $WorkspaceId -Query $Query -What 'the rule''s Log Analytics query' -Log { param($l, $m) Write-Info $m }

  $rows = @($result.Rows)
  if ($rows.Count -eq 0) {
    return [pscustomobject]@{ Data = @(); Count = 0 }
  }
  return [pscustomobject]@{ Data = $rows; Count = $rows.Count }
}

function Get-EntraObjectIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('ObjectId','objectId','ObjectId_s','objectId_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-EntraObjectTypeFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('ObjectType','objectType','ObjectType_s','objectType_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-EntraDisplayNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($n in @('DisplayName','displayName','DisplayName_s','displayName_s')) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return '<unknown>'
}

function Get-EntraEndpointFromObjectType {
  param([Parameter(Mandatory)][string]$ObjectType)
  switch ($ObjectType.ToLowerInvariant()) {
    'user'              { return 'users' }
    'serviceprincipal'  { return 'servicePrincipals' }
    'managedidentity'   { return 'servicePrincipals' }
    default             { return $null }
  }
}

function Get-EntraCurrentCSATags {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Endpoint,
    [Parameter(Mandatory)][string]$ObjectId,
    [Parameter(Mandatory)][string]$AttributeSet
  )

  try {
    $resp = Invoke-ATGraphRequest -Method Get `
      -Uri "https://graph.microsoft.com/v1.0/$Endpoint/$ObjectId`?`$select=customSecurityAttributes"

    $csaBlock = $resp.customSecurityAttributes
    if (-not $csaBlock) { return @() }

    $setBlock = $csaBlock.$AttributeSet
    if (-not $setBlock) { return @() }

    $raw = $setBlock.AssetTags
    if (-not $raw) { return @() }

    # AssetTags is a string collection - may come back as array or single string
    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
      return @($raw | ForEach-Object { [string]$_ } | Where-Object { $_ })
    }
    return @([string]$raw)
  }
  catch {
    # A READ FAILURE IS NOT "NO TAGS" (#136). An object with no CSA yet is already answered above -- the
    # GET succeeds and returns no block. Reaching here means the GET itself FAILED (403, throttle, token),
    # so the current tags are UNKNOWN. Returning @() made Set-EntraCSATag PATCH the whole multi-value
    # attribute as "@() + the new tag", erasing every tag the identity already had (a tier-0 tag among
    # them) on a transient error. Throw instead: the caller skips this identity (-SuppressErrors) or
    # stops, and never writes over state it could not read.
    throw ("could not read the current custom security attributes of {0}/{1} -- refusing to write over unknown tags: {2}" -f $Endpoint, $ObjectId, $_.Exception.Message)
  }
}

function Set-EntraCSATag {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Endpoint,
    [Parameter(Mandatory)][string]$ObjectId,
    [Parameter(Mandatory)][string]$AttributeSet,
    [Parameter(Mandatory)][string]$AssetTagName,
    [Parameter(Mandatory)][string[]]$CurrentTags,
    [string]$DisplayName    = '<unknown>',
    [bool]$WhatIfMode       = $script:WhatIfMode,
    [bool]$SuppressErrors   = $script:SuppressErrors
  )

  $result = [pscustomobject]@{
    Success        = $false
    Suppressed     = $false
    AlreadyPresent = $false
    WhatIf         = $false
    Changed        = $false
    ErrorMessage   = $null
    ObjectId       = $ObjectId
    DisplayName    = $DisplayName
    AssetTagName   = $AssetTagName
  }

  # Skip if already tagged
  if ($CurrentTags -contains $AssetTagName) {
    $result.Success        = $true
    $result.AlreadyPresent = $true
    return $result
  }

  if ($WhatIfMode) {
    $result.Success = $true
    $result.WhatIf  = $true
    $result.Changed = $true
    return $result
  }

  # Merge new tag into existing collection
  $newTags = @($CurrentTags) + @($AssetTagName) | Select-Object -Unique

  $body = @{
    customSecurityAttributes = @{
      $AttributeSet = @{
        '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'
        'AssetTags@odata.type' = '#Collection(String)'
        AssetTags     = @($newTags)
      }
    }
  }

  try {
    Invoke-ATGraphRequest -Method Patch `
      -Uri  "https://graph.microsoft.com/v1.0/$Endpoint/$ObjectId" `
      -Body $body | Out-Null

    $result.Success = $true
    $result.Changed = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message
    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }
    throw
  }
}

function Ensure-GraphAuth {
  if ($script:GraphLastConnectUtc -eq [datetime]::MinValue -or
      (([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes -ge 45)) {
    Connect-GraphHighPriv
  }
}

function Invoke-DefenderGraphQuery {
  param([Parameter(Mandatory)][string]$Query)
  # v2.2.394: drop Start-MgSecurityHuntingQuery (Microsoft.Graph.Security)
  # and hit the Graph REST endpoint directly. PS 5.1 sessions routinely
  # hit "Assembly with same name is already loaded" when Microsoft.Graph.*
  # modules get loaded by different upstream callers (Connect-MgGraph,
  # Az.Accounts, the profiling engine, etc.) and their bundled
  # Microsoft.Graph.Authentication versions disagree. REST avoids the
  # entire module-version graph and uses the same Get-SIGraphToken /
  # /security/runHuntingQuery approach as Invoke-SIHuntingQuery in the
  # profiling engine.
  $siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
  . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1')
  $token = Get-SIGraphToken -Resource Graph
  try {
    $resp = Invoke-RestMethod -Method Post `
      -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
      -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
      -Body (@{ Query = $Query } | ConvertTo-Json -Compress)
  } catch {
    $msg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
      $msg = $_.ErrorDetails.Message
    } elseif ($_.Exception.Response) {
      $stream = $null; $reader = $null
      try {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()
        if ($body) { $msg = ('{0} | body: {1}' -f $msg, $body) }
      } catch {
      } finally {
        if ($reader) { try { $reader.Dispose() } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
      }
    }
    throw ('Defender hunting query failed: {0}' -f $msg)
  }
  $rawRows = @()
  if     ($resp.results) { $rawRows = @($resp.results) }
  elseif ($resp.Results) { $rawRows = @($resp.Results) }
  # Drop any *@odata.* property pairs row-by-row so the downstream
  # field-getter logic doesn't trip on metadata noise.
  return @($rawRows | ForEach-Object { ConvertTo-PSObjectDeep $_ -StripOData })
}

function Invoke-AzureResourceGraphQuery {
  param([Parameter(Mandatory)][string]$Query)

  $pageSize = 1000
  $skip     = 0
  $allRows  = @()

  while ($true) {
    if ($skip -eq 0) { $res = Search-SIAzGraph -Query $Query -First $pageSize }
    else            { $res = Search-SIAzGraph -Query $Query -First $pageSize -Skip $skip }

    $rows = @()
    if ($res) {
      if ($res.PSObject.Properties.Name -contains 'Data') { $rows = @($res.Data) }
      else                                               { $rows = @($res) }
    }

    if (-not $rows -or $rows.Count -eq 0) { break }
    $allRows += $rows
    if ($rows.Count -lt $pageSize) { break }
    $skip += $pageSize
  }

  [pscustomobject]@{
    Data  = $allRows
    Count = $allRows.Count
  }
}

function Get-DefenderAccessHeaders {
  <#
      SECRET FIRST HERE, unlike Graph -- and that asymmetry is deliberate, not an oversight.

      The secret branch used to be MicrosoftGraphPS' Connect-MicrosoftRestApiEndpointPS, which had NO
      certificate parameter; it is now a plain client_credentials POST (Get-ATDefenderHeaders -SecretOnly,
      _shared/AT-GraphRest.ps1) for the same identity, kept secret-first so nothing changes for a customer.
      Operator ruling 2026-08-12: "if mde doesn't support certificate, then fallback to secret, which
      exists for this customer."

      The cert branch below covers the cert-ONLY customer, who otherwise had no route: it mints the
      token via SI's own helper, which falls through to the Az context -- and on an AutomationFramework
      host that context was established with the certificate. Headers are built to match the module's
      shape exactly (Content-Type / Accept / Authorization) so every downstream Invoke-DefenderRest
      caller is unaffected by which branch produced them.
  #>
  # #236: a managed-identity run has neither a secret nor a certificate -- its Defender token comes from the identity
  # endpoint. Checked FIRST, so a leftover SPN secret in the config can never be used instead of the chosen identity.
  if ([bool]$global:SI_UseManagedIdentity) {
    $h = Get-ATDefenderHeaders
    $script:DefenderHeadersAt = [datetime]::UtcNow
    return $h
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
    $h = Get-ATDefenderHeaders -SecretOnly
    $script:DefenderHeadersAt = [datetime]::UtcNow
    return $h
  }

  Write-Info "Defender API: no secret available -- acquiring a token via the certificate-backed Az context."
  $tokenHelper = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth\Get-SIGraphToken.ps1'
  if (-not (Test-Path -LiteralPath $tokenHelper)) {
    throw ("Defender API needs either `$global:SpnClientSecret or the token helper at '{0}', and neither is present." -f $tokenHelper)
  }
  . $tokenHelper
  $tok = Get-SIGraphToken -Resource Defender
  if ([string]::IsNullOrWhiteSpace([string]$tok)) {
    throw "Defender API token acquisition returned an empty token. Check that the SPN holds Machine.Read.All / Machine.ReadWrite.All on WindowsDefenderATP."
  }
  $script:DefenderHeadersAt = [datetime]::UtcNow
  return @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $tok"
  }
}

function ConvertTo-PSObjectDeep {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    $InputObject,
    [switch] $StripOData,
    [switch] $CastPrimitiveArrays,
    [switch] $ConvertArraysToString,
    [string] $ArrayJoinChar = ', ',
    [switch] $PreserveRootArray = $true
  )
  function _IsPrimitive([object]$x) {
    if ($null -eq $x) { return $true }
    $t = $x.GetType()
    return ($t.IsPrimitive -or $t.FullName -in @('System.String','System.Decimal','System.DateTime','System.Guid','System.TimeSpan'))
  }
  function _Convert([object]$obj, [bool]$isRoot = $false) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [pscustomobject]) {
      $ordered = [ordered]@{}
      foreach ($p in $obj.PSObject.Properties) {
        if ($StripOData -and ($p.Name -like '*@odata*')) { continue }
        $ordered[$p.Name] = _Convert $p.Value $false
      }
      return [pscustomobject]$ordered
    }
    if ($obj -is [System.Collections.IDictionary]) {
      $ordered = [ordered]@{}
      foreach ($k in $obj.Keys) {
        if ($StripOData -and ($k -is [string]) -and ($k -like '*@odata*')) { continue }
        $ordered[$k] = _Convert $obj[$k] $false
      }
      return [pscustomobject]$ordered
    }
    if (($obj -is [System.Collections.IEnumerable]) -and -not ($obj -is [string])) {
      $items = @()
      foreach ($item in $obj) { $items += ,(_Convert $item $false) }
      if ($ConvertArraysToString -and -not ($isRoot -and $PreserveRootArray)) {
        $pieces = foreach ($e in $items) { if (_IsPrimitive $e) { $e } else { ($e | ConvertTo-Json -Compress -Depth 12) } }
        return ($pieces -join $ArrayJoinChar)
      }
      if ($CastPrimitiveArrays -and -not $ConvertArraysToString -and $items.Count -gt 0) {
        $nonNull   = $items | Where-Object { $_ -ne $null }
        $typeNames = $nonNull | ForEach-Object { $_.GetType().FullName } | Select-Object -Unique
        $allPrim   = ($nonNull | ForEach-Object { _IsPrimitive $_ } | Where-Object { -not $_ } | Measure-Object).Count -eq 0
        if ($allPrim -and $typeNames.Count -eq 1) {
          switch ($typeNames[0]) {
            'System.String'  { return [string[]]  $items }
            'System.Int32'   { return [int[]]     $items }
            'System.Int64'   { return [long[]]    $items }
            'System.Double'  { return [double[]]  $items }
            'System.Boolean' { return [bool[]]    $items }
          }
        }
      }
      return @($items)
    }
    return $obj
  }
  $rootIsArray = (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]))
  if ($rootIsArray -and $PreserveRootArray) {
    $out = @()
    foreach ($i in $InputObject) { $out += ,(_Convert $i $false) }
    return @($out)
  }
  return (_Convert $InputObject $true)
}

# ==========================================================================================
# DEFENDER REST INVOKER WITH THROTTLING + RETRY
# ==========================================================================================
$script:DefenderMinDelayMs = 750
$script:DefenderLastCall   = [datetime]::MinValue

function Invoke-DefenderRest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','PUT','DELETE')]
    [string]$Method,
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][hashtable]$Headers,
    [object]$BodyObj = $null,
    [int]$MaxAttempts = 8
  )

  $attempt = 0
  $delaySeconds = 2
  $tokenRefreshed = $false

  # TOKEN LIFETIME (#136). The headers were built ONCE per run, while every device gets its own
  # sequential call spaced >= 750 ms apart: ~5,000 devices outlive a one-hour token, and every call
  # after that came back 401 -- the run aborted part-way, or with -SuppressErrors the remaining
  # devices were silently counted "not found" and left untagged. Refreshed proactively at 45 minutes,
  # and once on a 401. The caller's hashtable is updated IN PLACE, so its later calls use the new token.
  $refreshHeaders = {
    param($h)
    $fresh = Get-DefenderAccessHeaders
    foreach ($k in @($fresh.Keys)) { $h[$k] = $fresh[$k] }
  }

  while ($true) {
    $attempt++

    if ($script:DefenderHeadersAt -and ([datetime]::UtcNow - $script:DefenderHeadersAt).TotalMinutes -gt 45) {
      Write-Info "Defender API token is over 45 minutes old -- refreshing before the next call."
      & $refreshHeaders $Headers
    }

    if ($script:DefenderLastCall -ne [datetime]::MinValue) {
      $elapsedMs = ([datetime]::UtcNow - $script:DefenderLastCall).TotalMilliseconds
      if ($elapsedMs -lt $script:DefenderMinDelayMs) {
        Start-Sleep -Milliseconds ([int]($script:DefenderMinDelayMs - $elapsedMs))
      }
    }

    try {
      $script:DefenderLastCall = [datetime]::UtcNow

      if ($null -ne $BodyObj) {
        $json = $BodyObj | ConvertTo-Json -Depth 6
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $json
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers
      }
    }
    catch {
      $ex = $_.Exception
      $resp = $ex.Response

      $statusCode = $null
      $retryAfter = $null

      if ($resp) {
        try { $statusCode = [int]$resp.StatusCode } catch {}
        # pwsh 7's HttpResponseMessage has no header indexer -- read the typed value first.
        try {
          if ($resp.Headers.PSObject.Properties['RetryAfter'] -and $resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
            $retryAfter = [string][int]$resp.Headers.RetryAfter.Delta.TotalSeconds
          } else { $retryAfter = $resp.Headers['Retry-After'] }
        } catch {}
      }

      if ($statusCode -eq 401 -and -not $tokenRefreshed) {
        # Expired token: refresh once and retry THIS call. A second 401 is a real authorisation failure.
        $tokenRefreshed = $true
        Write-Info "Defender API returned 401 -- refreshing the token once and retrying."
        & $refreshHeaders $Headers
        continue
      }

      if ($statusCode -eq 429) {
        $sleep = $null
        if ($retryAfter -and ($retryAfter -match '^\d+$')) { $sleep = [int]$retryAfter }
        if (-not $sleep) { $sleep = $delaySeconds }

        Write-Info ("429 throttled. Sleeping {0}s (attempt {1}/{2})" -f $sleep, $attempt, $MaxAttempts)
        Start-Sleep -Seconds $sleep
        $delaySeconds = [math]::Min($delaySeconds * 2, 60)

        if ($attempt -lt $MaxAttempts) { continue }
      }

      if ($statusCode -ge 500 -and $statusCode -le 599 -and $attempt -lt $MaxAttempts) {
        Write-Info ("{0} server error. Sleeping {1}s (attempt {2}/{3})" -f $statusCode, $delaySeconds, $attempt, $MaxAttempts)
        Start-Sleep -Seconds $delaySeconds
        $delaySeconds = [math]::Min($delaySeconds * 2, 60)
        continue
      }

      throw
    }
  }
}

# ==========================================================================================
# Helpers: name + SenseDeviceId extraction (NO DNS RESOLUTION)
# ==========================================================================================
function Get-FirstNonEmptyPropertyValue {
  param(
    [Parameter(Mandatory)][psobject]$Row,
    [Parameter(Mandatory)][string[]]$Names
  )
  foreach ($n in $Names) {
    $p = $Row.PSObject.Properties[$n]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }
  return $null
}

function Get-DeviceNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  $n = Get-FirstNonEmptyPropertyValue -Row $Row -Names @(
    'DeviceName','deviceName',
    'NodeName','nodeName',
    'ComputerDnsName','computerDnsName',
    'HostName','hostName',
    'DnsName','dnsName',
    'NetBiosName','netBiosName',
    'AadDeviceName','aadDeviceName',
    'MachineName','machineName',
    'Name','name'
  )

  if (-not [string]::IsNullOrWhiteSpace($n)) {
    return $n.Trim()
  }

  $id = Get-SenseDeviceIdFromRow -Row $Row
  if (-not [string]::IsNullOrWhiteSpace($id)) {
    return "<unknown:$id>"
  }

  return "<unknown>"
}

function Get-SenseDeviceIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  $id = Get-FirstNonEmptyPropertyValue -Row $Row -Names @('SenseDeviceId','senseDeviceId')
  if ([string]::IsNullOrWhiteSpace($id)) { return $null }
  return $id.Trim()
}

function Test-DefenderMachineExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$MachineId,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  if ([string]::IsNullOrWhiteSpace($MachineId)) { return $false }

  $uri = "https://api.securitycenter.microsoft.com/api/machines/$MachineId"
  try {
    Invoke-DefenderRest -Method GET -Uri $uri -Headers $AccessHeaders -BodyObj $null -MaxAttempts 3 | Out-Null
    return $true
  }
  catch {
    $ex = $_.Exception
    $resp = $ex.Response
    $statusCode = $null
    if ($resp) { try { $statusCode = [int]$resp.StatusCode } catch {} }
    if ($statusCode -eq 404) { return $false }

    if ($SuppressErrors) {
      Write-WarnBlock -Title "Suppressed Defender machine existence check error" -Fields ([ordered]@{
        MachineId = $MachineId
        Error     = $_.Exception.Message
      }) -SeparatorBefore
      return $false
    }

    throw
  }
}

# ==========================================================================================
# DEFENDER TAGGING FUNCTIONS
# ==========================================================================================
function AddTagForMultipleMachines {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string[]]$MachineIds,
    [Parameter(Mandatory)][string]$Tag,
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines"
  $bodyObj = @{
    Value      = $Tag
    Action     = "Add"
    MachineIds = @($MachineIds)
  }

  $result = [pscustomobject]@{
    Success      = $false
    Suppressed   = $false
    WhatIf       = $false
    ErrorMessage = $null
    Count        = @($MachineIds).Count
    Tag          = $Tag
    Uri          = $uri
  }

  if ($WhatIfMode) {
    Write-WarnBlock -Title "[WHATIF] Would bulk-tag Defender machines" -Fields ([ordered]@{
      Count = $MachineIds.Count
      Tag   = $Tag
      Uri   = $uri
    }) -SeparatorBefore
    $result.Success = $true
    $result.WhatIf  = $true
    return $result
  }

  try {
    Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj | Out-Null
    $result.Success = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message
    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }
    throw
  }
}

function Add-DefenderTag {
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][string]$MachineId,
    [Parameter(Mandatory)][string]$Tag,
    [string]$DeviceName = "<unknown>",
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $uri  = "https://api.securitycenter.microsoft.com/api/machines/$MachineId/tags"
  $bodyObj = @{
    Value  = $Tag
    Action = "Add"
  }

  $result = [pscustomobject]@{
    Success      = $false
    Suppressed   = $false
    WhatIf       = $false
    ErrorMessage = $null
    MachineId    = $MachineId
    DeviceName   = $DeviceName
    Tag          = $Tag
    Uri          = $uri
  }

  if ($WhatIfMode) {
    Write-WarnBlock -Title "[WHATIF] Would tag Defender machine" -Fields ([ordered]@{
      DeviceName = $DeviceName
      MachineId  = $MachineId
      Tag        = $Tag
      Uri        = $uri
    }) -SeparatorBefore
    $result.Success = $true
    $result.WhatIf  = $true
    return $result
  }

  try {
    Invoke-DefenderRest -Method POST -Uri $uri -Headers $AccessHeaders -BodyObj $bodyObj | Out-Null
    $result.Success = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message
    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }
    throw
  }
}

# ==========================================================================================
# BULK APPLY WITH SPLIT-AND-RETRY + NAME LOGGING
# ==========================================================================================
function Apply-TagBulkWithSplit {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$AccessHeaders,
    [Parameter(Mandatory)][pscustomobject[]]$Devices,
    [Parameter(Mandatory)][string]$Tag,
    [int]$MaxSplitDepth = 10,
    [bool]$SuppressErrors = $script:SuppressErrors,
    # #236: the rule the devices came from, for the activity log
    [string]$Rule,
    [string]$RuleMode
  )

  if (-not $Devices -or $Devices.Count -eq 0) { return }

  # #236: one activity row per device, planned (WouldApply) or executed (Applied / Failed).
  $logDevices = {
    param([object[]]$Items, [string]$Status, [string]$Err)
    foreach ($it in @($Items)) {
      Add-ATActivity -Target 'Defender' -Status $Status -Rule $Rule -RuleMode $RuleMode -QueryEngine 'DefenderGraph' `
        -TargetId ([string]$it.Id) -TargetName ([string]$it.Name) -AssetTag $Tag -AssetTagType 'MachineTag' `
        -ErrorMessage $Err -WhatIf ([bool]$script:WhatIfMode)
    }
  }

  $stack = New-Object System.Collections.Stack
  $stack.Push([pscustomobject]@{ Items = @($Devices); Depth = 0 })

  while ($stack.Count -gt 0) {
    $work  = $stack.Pop()
    $items = @($work.Items)
    $depth = [int]$work.Depth

    $ids = @($items | ForEach-Object { $_.Id })

    try {
      $bulkResult = AddTagForMultipleMachines -AccessHeaders $AccessHeaders -MachineIds $ids -Tag $Tag -SuppressErrors $SuppressErrors

      if ($bulkResult.Suppressed) {
        & $logDevices $items 'Failed' ([string]$bulkResult.ErrorMessage)
        Write-WarnBlock -Title "Suppressed Defender bulk tagging error" -Fields ([ordered]@{
          Count = $ids.Count
          Depth = $depth
          Tag   = $Tag
          Error = $bulkResult.ErrorMessage
        }) -SeparatorBefore
      }
      elseif ($bulkResult.WhatIf) {
        & $logDevices $items 'WouldApply' ''
      }
      else {
        & $logDevices $items 'Applied' ''
        Write-OkBlock -Title "Defender bulk tag applied" -Fields ([ordered]@{
          Count = $ids.Count
          Tag   = $Tag
          Depth = $depth
        }) -SeparatorBefore
      }

      continue
    }
    catch {
      Write-ErrBlock -Title "Defender bulk tagging failed" -Fields ([ordered]@{
        Count = $ids.Count
        Depth = $depth
        Error = $_.Exception.Message
      }) -SeparatorBefore

      if ($items.Count -le 1 -or $depth -ge $MaxSplitDepth) {
        $one = $items[0]
        try {
          $singleResult = Add-DefenderTag -AccessHeaders $AccessHeaders -MachineId $one.Id -Tag $Tag -DeviceName $one.Name -SuppressErrors $SuppressErrors
          if ($singleResult.Suppressed) { & $logDevices @($one) 'Failed' ([string]$singleResult.ErrorMessage) }
          elseif ($singleResult.WhatIf) { & $logDevices @($one) 'WouldApply' '' }
          else { & $logDevices @($one) 'Applied' '' }
          if ($singleResult.Suppressed) {
            Write-WarnBlock -Title "Suppressed Defender single-machine tagging error" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Tag   = $Tag
              Error = $singleResult.ErrorMessage
            }) -SeparatorBefore
          }
          else {
            Write-OkBlock -Title "Defender single-machine tag applied" -Fields ([ordered]@{
              Name = $one.Name
              Id   = $one.Id
              Tag  = $Tag
            }) -SeparatorBefore
          }
        }
        catch {
          & $logDevices @($one) 'Failed' ([string]$_.Exception.Message)
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed unprocessable Defender machine error" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Error = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            Write-ErrBlock -Title "Unprocessable Defender machine" -Fields ([ordered]@{
              Name  = $one.Name
              Id    = $one.Id
              Error = $_.Exception.Message
            }) -SeparatorBefore
          }
        }
        continue
      }

      $mid = [math]::Floor($items.Count / 2)
      if ($mid -lt 1) { $mid = 1 }

      $left  = @($items[0..($mid-1)])
      $right = @($items[$mid..($items.Count-1)])

      $stack.Push([pscustomobject]@{ Items = $right; Depth = ($depth + 1) })
      $stack.Push([pscustomobject]@{ Items = $left;  Depth = ($depth + 1) })
    }
  }
}

# ==========================================================================================
# Azure tagging helpers
# ==========================================================================================
function Get-ArgResourceIdFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($name in @('ResourceId','resourceId','id','Id')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }
  return $null
}

function Get-ArgResourceNameFromRow {
  param([Parameter(Mandatory)][psobject]$Row)

  foreach ($name in @('name','Name','resourceName','ResourceName','displayName','DisplayName')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
  }

  $rid = Get-ArgResourceIdFromRow -Row $Row
  if (-not [string]::IsNullOrWhiteSpace($rid)) {
    if ($rid -match '^/subscriptions/([0-9a-fA-F-]{36})$') {
      return $matches[1]
    }
    if ($rid -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/([^/]+)$') {
      return $matches[1]
    }

    $segments = @($rid.Trim('/') -split '/')
    if ($segments.Count -gt 0) {
      return $segments[-1]
    }
  }

  return $null
}

function Get-ArgAssetTagTypeFromRow {
  param([Parameter(Mandatory)][psobject]$Row)
  foreach ($name in @('AssetTagType','assettagtype','TagKey','tagKey')) {
    $p = $Row.PSObject.Properties[$name]
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  }
  return $null
}

function Get-TagValueFromRow {
  param(
    [Parameter(Mandatory)][psobject]$Row,
    [Parameter(Mandatory)][string]$ColumnName
  )
  if ([string]::IsNullOrWhiteSpace($ColumnName)) { return $null }
  $p = $Row.PSObject.Properties[$ColumnName]
  if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return ([string]$p.Value).Trim() }
  return $null
}

function Get-SubscriptionIdFromResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }

  if ($ResourceId -match '^/subscriptions/([0-9a-fA-F-]{36})(/|$)') {
    return $matches[1].ToLowerInvariant()
  }

  return $null
}

function Test-SubscriptionScopeId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}$')
}

function Test-ResourceGroupScopeId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+$')
}

function Get-ResourceTypeFromResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }

  if (Test-SubscriptionScopeId -ResourceId $ResourceId) {
    return 'microsoft.resources/subscriptions'
  }

  if (Test-ResourceGroupScopeId -ResourceId $ResourceId) {
    return 'microsoft.resources/resourcegroups'
  }

  $m = [regex]::Match($ResourceId, '/providers/([^/]+/[^/]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }

  return $null
}

function Test-ArmResourceId {
  param([Parameter(Mandatory)][string]$ResourceId)

  if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }

  if (Test-SubscriptionScopeId -ResourceId $ResourceId) { return $true }
  if (Test-ResourceGroupScopeId -ResourceId $ResourceId) { return $true }

  return ($ResourceId -match '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/[^/]+/.+')
}

function Set-AzContextFromResourceId {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ResourceId)

  $subId = Get-SubscriptionIdFromResourceId -ResourceId $ResourceId
  if ([string]::IsNullOrWhiteSpace($subId)) {
    throw "Could not extract subscription id from ResourceId: $ResourceId"
  }

  $ctx = Get-SIAzContext -ErrorAction SilentlyContinue
  $currentSub = $null
  if ($ctx -and $ctx.Subscription) { $currentSub = [string]$ctx.Subscription.Id }

  if ($currentSub -ne $subId) {
    Set-SIAzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
  }

  return $subId
}

function Test-SkipAzureTaggingForType {
  param([Parameter(Mandatory)][string]$ResourceType)

  # Types that cannot be tagged via Update-AzTag / PATCH on the resource id.
  # These are either provider-scope-only resources (no /tags endpoint on ARM),
  # internal Microsoft service objects, or types where PATCH is not supported.
  $skipTypes = @(
    # Already skipped - query rules have no tags endpoint
    'microsoft.insights/scheduledqueryrules',

    # Role assignments - PATCH not supported at any roleAssignment scope
    # (neither subscription-provider, resourceGroup, nor MG scope)
    'microsoft.authorization/roleassignments',

    # Policy assignments at subscription-provider scope have no tags endpoint.
    # (RG-scoped assignments are taggable, but ARG queries should already
    # filter to isnotempty(resourceGroup) so provider-scope ones never appear)
    'microsoft.authorization/policyassignments',

    # Defender for Cloud / security pricing plans - subscription-provider scope,
    # no /tags endpoint (microsoft.security/pricings/{PlanName})
    'microsoft.security/pricings',

    # Internal Microsoft Sentinel platform service - not a customer-manageable resource
    'microsoft.sentinelplatformservices/sentinelplatformservices'
  )

  return ($skipTypes -contains $ResourceType.ToLowerInvariant())
}

function Add-AzureResourceTag {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ResourceId,
    [Parameter(Mandatory)][string]$AssetTagName,
    [Parameter(Mandatory)][string]$TagKey,
    [bool]$WhatIfMode = $script:WhatIfMode,
    [bool]$SuppressErrors = $script:SuppressErrors
  )

  $rid = if ($null -ne $ResourceId) { $ResourceId.Trim() } else { $null }

  $result = [pscustomobject]@{
    Success          = $false
    Suppressed       = $false
    Changed          = $false
    AlreadyPresent   = $false
    Skipped          = $false
    SkipReason       = $null
    WhatIf           = $false
    ResourceId       = $rid
    ResourceType     = $null
    SubscriptionId   = $null
    TagKey           = $TagKey
    TagValue         = $AssetTagName
    ErrorMessage     = $null
  }

  try {
    if ([string]::IsNullOrWhiteSpace($rid))          { throw "ResourceId is empty" }
    if ([string]::IsNullOrWhiteSpace($TagKey))       { throw "TagKey is empty" }
    if ([string]::IsNullOrWhiteSpace($AssetTagName)) { throw "AssetTagName is empty" }
    # Provider-scope resources (e.g. /subscriptions/{id}/providers/...) are not taggable
    # via ARM tags � they have no /tags endpoint. Detect them before the strict ARM id check
    # and return a clean skip rather than throwing.
    if (-not [string]::IsNullOrWhiteSpace($rid)) {
      $rt = Get-ResourceTypeFromResourceId -ResourceId $rid
      if (-not [string]::IsNullOrWhiteSpace($rt) -and
          (Test-SkipAzureTaggingForType -ResourceType $rt)) {
        $result.Skipped    = $true
        $result.SkipReason = "Tagging skipped for resource type: $rt"
        return $result
      }
    }

    if (-not (Test-ArmResourceId -ResourceId $rid))  { throw "Invalid ARM ResourceId: $rid" }

    $resourceType        = Get-ResourceTypeFromResourceId -ResourceId $rid
    $subId               = Get-SubscriptionIdFromResourceId -ResourceId $rid
    $isSubscriptionScope = Test-SubscriptionScopeId -ResourceId $rid
    $isResourceGroup     = Test-ResourceGroupScopeId -ResourceId $rid

    $result.ResourceType   = $resourceType
    $result.SubscriptionId = $subId

    if (-not [string]::IsNullOrWhiteSpace($resourceType) -and
        -not $isSubscriptionScope -and
        -not $isResourceGroup -and
        (Test-SkipAzureTaggingForType -ResourceType $resourceType)) {
      $result.Skipped    = $true
      $result.SkipReason = "Tagging skipped for resource type: $resourceType"
      return $result
    }

    Set-AzContextFromResourceId -ResourceId $rid | Out-Null

    $existing = $null
    try {
      $existing = (Get-SIAzTag -ResourceId $rid -ErrorAction Stop).Properties.TagsProperty
    }
    catch {
      $existing = $null
    }

    $already = $false
    if ($existing -and $existing.ContainsKey($TagKey) -and ([string]$existing[$TagKey]) -eq $AssetTagName) {
      $already = $true
    }

    if ($already) {
      $result.Success        = $true
      $result.AlreadyPresent = $true
      $result.Changed        = $false
      if ($WhatIfMode) { $result.WhatIf = $true }
      return $result
    }

    if ($WhatIfMode) {
      $result.Success = $true
      $result.WhatIf  = $true
      $result.Changed = $true
      return $result
    }

    Update-SIAzTag -ResourceId $rid -Tag @{ $TagKey = $AssetTagName } -Operation Merge -ErrorAction Stop | Out-Null

    $result.Success = $true
    $result.Changed = $true
    return $result
  }
  catch {
    $result.ErrorMessage = $_.Exception.Message

    if ($SuppressErrors) {
      $result.Suppressed = $true
      return $result
    }

    throw
  }
}

# RUN HEALTH: a START and END record like every other engine (the END also sends the telemetry run report). Recorded in
# report-only mode too: that mode changes nothing in the estate but still writes the activity table. The run body below
# is inside the try; END is in its finally, so a failed run is recorded as one.
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-RunHealthScope.ps1')
$rhTag = Start-SIRunHealth -Engine 'asset-tagging' -RecordInReportMode
$rhTagExit = 'success'; $rhTagMsg = ''; $rhTagCount = -1
try {
Write-Step "initializing"
Write-Info ("WhatIfMode: {0}" -f $WhatIfMode)
Write-Info ("SuppressErrors: {0}" -f $SuppressErrors)
Write-Info ("SuppressWarnings: {0}" -f $SuppressWarnings)

# #236: the run's id and sign-in, stamped on every activity row -- the same id as the run's health record.
$global:SI_AssetTaggingRunId = if ($rhTag) { [string]$rhTag.RunId } else { [guid]::NewGuid().ToString() }
$script:ATAuth = Get-ATAuthMode
$global:SI_AssetTaggingAuthMode = [string]$script:ATAuth.Mode
Clear-ATActivity
Write-Info ("Sign-in: {0}" -f $script:ATAuth.Reason)

#####################################################################################################
# CONNECTION
#####################################################################################################

if ($script:ATAuth.Mode -eq 'ManagedIdentity') {

  # #236 -- the MANAGED IDENTITY: a Pro container job's own user-assigned identity (caj-si-asset-tagging), or an Azure
  # VM's / Azure Arc server's identity. Azure Resource Manager (Resource Graph, tag reads and writes), Microsoft Graph
  # (hunting, custom security attributes) and Defender for Endpoint (machine tags) all take their tokens from the
  # identity endpoint. No secret and no certificate exist on this path.
  Write-Step "connecting to Azure (managed identity)"
  Tock
  try {
    $miArgs = @{ Identity = $true; WarningAction = 'SilentlyContinue' }
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_UAMI_ClientId)) { $miArgs['AccountId'] = [string]$global:SI_UAMI_ClientId }
    Connect-SIAzAccount @miArgs | Out-Null
    Write-Ok "azure connection step done"
  } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
  Tick "azure connect"

  $script:GraphLastConnectUtc = [datetime]::MinValue

  Write-Step "connecting to Microsoft Graph (initial)"
  Tock
  try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
  Tick "graph connect"

  Write-Step "acquiring Defender API auth headers"
  $AccessHeaders = Get-DefenderAccessHeaders

} elseif ($AutomationFramework) {

  # The platform identity of an internal install, signed in by SecurityInsight itself over plain REST (no
  # PowerShell module): bootstrap\platform-config.json -> the platform Key Vault -> the platform identity, and the
  # framework's $global:HighPriv_* / $global:AzureTenantId names populated.
  . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/SI-PlatformConnect.ps1')
  $__platformCfg = Find-SIPlatformConfigPath -Start $PSScriptRoot
  if ($__platformCfg) {
      $global:PathScripts = Split-Path -Parent (Split-Path -Parent $__platformCfg)
      Write-Output ""
      Write-Output "Repo root          -> $($global:PathScripts)"
  }
  # Idempotent: skip when the launcher's configuration (layer 1) already signed the platform identity in.
  if (-not $global:Context -or -not $global:AzureTenantId -or -not $global:HighPriv_Modern_ApplicationID_Azure) {
      $null = Connect-SIPlatform -Start $PSScriptRoot
  }
  $global:SpnTenantId     = $global:AzureTenantId
  $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure

  # THE ROOT CAUSE of the interactive-prompt bug: this block set the secret and NOTHING ELSE, so on a
  # cert-authenticated internal customer SpnCertificateThumbprint stayed empty no matter what
  # the platform sign-in had resolved, and the Graph connect fell through to a prompt.
  # Two further traps, both live here:
  #   1. It read $global:HighPriv_Modern_Secret_Azure while this engine's own preamble bridge (line ~39)
  #      reads $global:HighPriv_Modern_ApplicationSecret_Azure. One fact, two spellings -- so the
  #      unconditional assignment below could also CLOBBER a secret the preamble had already resolved,
  #      by overwriting it with the empty other name.
  #   2. The SPN-globals pre-flight that accepts "secret OR cert" is guarded by
  #      `if (-not $global:AutomationFramework)`, so on THIS path nothing ever checked that a usable
  #      credential existed at all.
  # Assign only what is actually populated, and accept either spelling of the secret.
  $_afSecret = if (-not [string]::IsNullOrWhiteSpace([string]$global:HighPriv_Modern_Secret_Azure)) {
                   [string]$global:HighPriv_Modern_Secret_Azure
               } else {
                   [string]$global:HighPriv_Modern_ApplicationSecret_Azure
               }
  if (-not [string]::IsNullOrWhiteSpace($_afSecret)) { $global:SpnClientSecret = $_afSecret }
  if (-not [string]::IsNullOrWhiteSpace([string]$global:HighPriv_Modern_CertificateThumbprint_Azure)) {
      $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure
  }

  # Say which credential this run will actually use, before using it. The failure being fixed here was
  # invisible until the module put a prompt on screen; the run must state its own auth mode up front.
  Write-Info ("AutomationFramework auth: AppId={0} cert={1} secret={2}" -f `
      $global:SpnClientId,
      $(if ($global:SpnCertificateThumbprint) { 'yes' } else { 'no' }),
      $(if ($global:SpnClientSecret)          { 'yes' } else { 'no' }))
  if ([string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint) -and
      [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
      throw (("AutomationFramework resolved no usable credential for AppId '{0}' (tenant '{1}'): neither " +
              "HighPriv_Modern_CertificateThumbprint_Azure nor HighPriv_Modern_[Application]Secret_Azure is set. " +
              "Check the Key Vault this platform config points at.") -f $global:SpnClientId, $global:SpnTenantId)
  }

  $script:GraphLastConnectUtc = [datetime]::MinValue

  Write-Step "connecting to Microsoft Graph (initial)"
  Tock
  try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
  Tick "graph connect"

  Write-Step "acquiring Defender API auth headers"
  $AccessHeaders = Get-DefenderAccessHeaders

} else {

  # The SAME defect as the AutomationFramework branch, in the branch nobody reported: the pre-flight
  # above explicitly accepts "SpnClientSecret OR SpnCertificateThumbprint" (v2.2.238), and then this
  # code could only ever use the secret. A cert-only community customer passed validation and died here
  # on a null secret. Prefer cert, keep secret as the fallback -- same order as everywhere else in SI.
  $_useCert = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
  Write-Host ("Connect using ServicePrincipal with AppId & {0}" -f $(if ($_useCert) { 'Certificate' } else { 'Secret' }))

  Write-Step "connecting to Azure"
  Tock
  try {
    if ($_useCert) {
      Connect-SIAzAccount -ServicePrincipal -ApplicationId $global:SpnClientId `
                        -CertificateThumbprint $global:SpnCertificateThumbprint `
                        -Tenant $global:SpnTenantId -WarningAction SilentlyContinue
    } else {
      $SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
      $Credential = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $SecureSecret)
      Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $Credential -WarningAction SilentlyContinue
    }
    Write-Ok "azure connection step done"
  } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
  Tick "azure connect"

  $script:GraphLastConnectUtc = [datetime]::MinValue

  Write-Step "connecting to Microsoft Graph (initial)"
  Tock
  try { Connect-GraphHighPriv } catch { Write-Err2 "initial graph connect failed: $($_.Exception.Message)"; throw }
  Tick "graph connect"

  Write-Step "acquiring Defender API auth headers"
  $AccessHeaders = Get-DefenderAccessHeaders
}

#####################################################################################################
# INITIALIZATION
#####################################################################################################

$Scope = @(
  $Scope |
  ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } |
  Where-Object { $_ } |
  Select-Object -Unique
)

if ($null -eq $Scope -or @($Scope).Count -eq 0) { $Scope = @('PROD') }

Write-Step "execution scope initialized"
Write-Info ("Active Scope(s): {0}" -f ($Scope -join ', '))

# -------------------------------------------------------------------------------------------------
# YAML SOURCES (Locked + Custom)
# -------------------------------------------------------------------------------------------------

function Import-AssetTaggingYaml {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return @()
  }

  $y = Get-Content -Raw -LiteralPath $Path | ConvertFrom-SIYaml -SourceName $Path
  if (-not $y) { return @() }
  if (-not $y.ContainsKey('AssetTagging')) {
    throw "YAML file is missing AssetTagging root: $Path"
  }
  if ($null -eq $y.AssetTagging) { return @() }

  return @($y.AssetTagging)
}

# Which files to read: ONE resolution (AssetTagging.Resolve.ps1), shared with the launchers and the Pro importer, so an
# upgrade imports exactly the files a run reads (#275). The rules are unchanged from 2.2:
#   * the YAML names: the configured ones, else SecurityInsight_CriticalAssetTagging_Locked/Custom.yaml, legacy CriticalAssetTagging.yaml;
#   * SecurityInsight Pro (Phase C): when the settings layer materialised the tagging rules from the database (templates +
#     the customer's overrides, already merged), they are the WHOLE rule set -- the rules folder's files are not read;
#   * v2.2.393 back-compat: customers who pulled v2.2.390/391 before the v2.2.392 rename have
#     'AssetTagging.AutoExclude.locked.yaml' on disk -- used when the configured locked file does not exist.
. (Join-Path $PSScriptRoot 'AssetTagging.Resolve.ps1')
$__tagFiles = Resolve-SIAssetTaggingFiles -SettingsPath $SettingsPath -SIRoot (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) `
  -LockedYamlFile ([string]$global:LockedYamlFile) -CustomYamlFile ([string]$global:CustomYamlFile) -LegacyYamlFile ([string]$global:LegacyYamlFile) `
  -ProAssetTaggingPath ([string]$global:SI_ProAssetTaggingPath) -ProConfigRoot ([string]$global:SI_ProConfigRoot)
$taggingRulesDir = $__tagFiles.RulesDir
$LockedYamlFile  = $__tagFiles.LockedYamlFile
$CustomYamlFile  = $__tagFiles.CustomYamlFile
$LegacyYamlFile  = $__tagFiles.LegacyYamlFile
$lockedPath = $__tagFiles.LockedPath; $customPath = $__tagFiles.CustomPath; $legacyPath = $__tagFiles.LegacyPath
$lockedExists = $__tagFiles.LockedExists; $customExists = $__tagFiles.CustomExists; $legacyExists = $__tagFiles.LegacyExists
if ($__tagFiles.FromPro) { Write-Info ("Asset-tagging rules from the SecurityInsight settings database: {0}" -f $taggingRulesDir) }
if ($__tagFiles.PreRenamed) { Write-Warn2 ("Locked YAML '{0}' not found; falling back to pre-v2.2.392 filename 'AssetTagging.AutoExclude.locked.yaml'." -f $__tagFiles.ConfiguredLockedYamlFile) }

$rulesLocked = @()
$rulesCustom = @()

if ($lockedExists -or $customExists) {

  Write-Step ("loading Locked YAML: {0}" -f $LockedYamlFile)
  $rulesLocked = Import-AssetTaggingYaml -Path $lockedPath

  Write-Step ("loading Custom YAML: {0}" -f $CustomYamlFile)
  $rulesCustom = Import-AssetTaggingYaml -Path $customPath

} elseif ($legacyExists) {

  Write-Warn2 ("Locked/Custom YAML not found. Falling back to legacy YAML: {0}" -f $LegacyYamlFile)
  $rulesLocked = Import-AssetTaggingYaml -Path $legacyPath

} else {

  throw "No YAML found. Expected either Locked+Custom or legacy file in SettingsPath: $SettingsPath"

}

# Merge: Custom wins on duplicate AssetTagName STEM (case-insensitive).
#
# Rule identity = everything BEFORE '--tier<N>--SI' (or '--excluded--SI'),
# combined with the '--SI' suffix. The tier number / 'excluded' marker between
# is treated as an OVERRIDABLE data field, not part of the identity. This lets
# a customer change just the tier (e.g. promote 'BackupOperators--tier1--SI'
# to 'BackupOperators--tier0--SI') by dropping a same-stem entry into
# Custom.yaml -- no need to rewrite the Locked query or disable it.
#
#   Locked : 'BackupOperators--tier1--SI'   -> key 'BACKUPOPERATORS--SI'
#   Custom : 'BackupOperators--tier0--SI'   -> key 'BACKUPOPERATORS--SI'
#   Merge result: Custom wins -> Backup Operators now tagged at tier 0.
#
# Two valid shapes for AssetTagName:
#   <stem>--tier<N>--SI      -- standard tiering (N = 0|1|2|3)
#   <stem>--excluded--SI     -- explicit exclusion marker. Used to tag
#                               assets that should show up as "Excluded"
#                               in the Defender portal filter -- typically
#                               renamed / pre-decommission machines that
#                               still linger in inventory. Treated as a
#                               parallel identity class: an 'excluded'
#                               entry shares its stem with any tier entry,
#                               so Custom can still override Locked.
#
# Malformed names throw with a clear error pointing at the offending entry
# (no silent fallback; that path was explicitly rejected for being ambiguous).
function Get-AssetTagStemKey {
    param([string]$Name, [string]$Source)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $trim = $Name.Trim()
    $m = [regex]::Match($trim, '^(?<stem>.+?)--(?:tier(?<tier>\d+)|excluded)--SI$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $m.Success) {
        throw ("AssetTagName '{0}' in {1} does not match the required '<stem>--tier<N>--SI' or '<stem>--excluded--SI' convention. Fix the YAML entry -- malformed tag names cannot participate in the Locked/Custom merge." -f $trim, $Source)
    }
    return ($m.Groups['stem'].Value + '--SI').ToUpperInvariant()
}

$ruleMap = [ordered]@{}
foreach ($r in @($rulesLocked)) {
  $k = Get-AssetTagStemKey -Name ([string]$r.AssetTagName) -Source 'Locked.yaml'
  if (-not $k) { continue }
  $ruleMap[$k] = $r
}
foreach ($r in @($rulesCustom)) {
  $k = Get-AssetTagStemKey -Name ([string]$r.AssetTagName) -Source 'Custom.yaml'
  if (-not $k) { continue }
  $ruleMap[$k] = $r
}

$mergedRules = @($ruleMap.Values)

$Yaml = [pscustomobject]@{ AssetTagging = $mergedRules }

Write-Info ("AssetTagging rules loaded: Locked={0}, Custom={1}, Effective={2}" -f (@($rulesLocked).Count), (@($rulesCustom).Count), (@($mergedRules).Count))

#####################################################################################################
# MAIN LOOP
#####################################################################################################

Write-Step "starting asset tag enforcement"

# 2026-06-11: load optional asset-tagging.config.json. Canonical location
# is 'config/asset-tagging.config.json' under the SI solution root (sibling
# of SecurityInsight.custom.ps1). For back-compat we also probe
# $SettingsPath. Used to gate per-rule execution via the YAML field
# 'EnabledByConfigFlag:' (dotted path under root, e.g.
# 'AutoExcludeRules.ExcludeCanBeOnboarded'). When the file is missing
# we treat every flag as false -- meaning gated rules silently skip.
$assetTaggingConfig = $null
try {
  # The candidates, in order (AssetTagging.Resolve.ps1): SecurityInsight Pro's copy materialised from the settings
  # database (SI_ProConfigRoot), then config\ under the SI root, then SettingsPath.
  $candidateConfigPaths = @($__tagFiles.ConfigCandidates)
  $taggingConfigPath = $__tagFiles.ConfigPath
  if ($taggingConfigPath) {
    $assetTaggingConfig = Get-Content -Raw -LiteralPath $taggingConfigPath | ConvertFrom-Json
    Write-Info "Loaded asset-tagging config from $taggingConfigPath"
  } else {
    Write-Info ("No asset-tagging.config.json found -- gated rules will skip. Looked in: {0}" -f (@($candidateConfigPaths | Where-Object { $_ }) -join '; '))
  }
} catch {
  Write-Warning ("Failed to load asset-tagging.config.json -- treating every EnabledByConfigFlag as false: {0}" -f $_.Exception.Message)
  $assetTaggingConfig = $null
}

# Tiny helper: resolve a dotted-path expression like
# 'AutoExcludeRules.ExcludeCanBeOnboarded' against the loaded JSON and
# return a boolean. Missing path / null config / non-boolean leaf all
# resolve to $false (fail closed -- a typo never accidentally enables
# auto-tagging).
function Test-TaggingConfigFlag {
  param([string]$DottedPath)
  if (-not $assetTaggingConfig) { return $false }
  if ([string]::IsNullOrWhiteSpace($DottedPath)) { return $false }
  $node = $assetTaggingConfig
  foreach ($seg in $DottedPath.Split('.')) {
    if ($null -eq $node) { return $false }
    $node = $node.$seg
  }
  if ($node -is [bool]) { return [bool]$node }
  if ($node -is [string]) { return ($node -eq 'true' -or $node -eq '1') }
  return $false
}

# Resolves DeviceNamePatterns.* from the JSON config and tests whether
# a given device name matches ANY entry across StartsWith / Contains /
# MatchesRegex (OR semantics). Used by the ApplyDeviceNamePatterns:
# post-KQL row filter.
# FAILS CLOSED (#136): with no patterns (all three arrays empty, or the
# block missing) NOTHING matches. It used to match EVERYTHING -- and the
# only rule that uses this filter is Auto-NamePattern--Excluded--SI, so
# enabling that rule before filling in a pattern tagged every onboarded
# device as Excluded and removed the whole estate from Risk Analysis.
function Test-DeviceNameMatchesConfigPatterns {
  param(
    [string]$DeviceName,
    [string]$OrNodeName   # secondary -- many DefenderGraph queries project NodeName instead of DeviceName
  )
  $name = if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $DeviceName } else { $OrNodeName }
  if ([string]::IsNullOrWhiteSpace($name)) { return $false }

  if (-not $assetTaggingConfig -or -not $assetTaggingConfig.DeviceNamePatterns) { return $false }
  $p = $assetTaggingConfig.DeviceNamePatterns

  $startsWith   = @($p.StartsWith   | Where-Object { $_ })
  $contains     = @($p.Contains     | Where-Object { $_ })
  $matchesRegex = @($p.MatchesRegex | Where-Object { $_ })

  # No patterns == nothing named == nothing matches (fail closed, see above).
  if ($startsWith.Count -eq 0 -and $contains.Count -eq 0 -and $matchesRegex.Count -eq 0) { return $false }

  $lc = $name.ToLowerInvariant()
  foreach ($pat in $startsWith) {
    if ($lc.StartsWith(([string]$pat).ToLowerInvariant())) { return $true }
  }
  foreach ($pat in $contains) {
    if ($lc.Contains(([string]$pat).ToLowerInvariant())) { return $true }
  }
  foreach ($pat in $matchesRegex) {
    try {
      if ([System.Text.RegularExpressions.Regex]::IsMatch(
            $name,
            [string]$pat,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        return $true
      }
    } catch {
      Write-Warning ("DeviceNamePatterns.MatchesRegex entry '{0}' is invalid regex; skipping: {1}" -f $pat, $_.Exception.Message)
    }
  }
  return $false
}

foreach ($rule in @($Yaml.AssetTagging)) {

  $ruleMode    = Get-RuleMode $rule.Mode
  $queryEngine = Get-QueryEngine $rule.QueryEngine

  if ($Scope -notcontains $ruleMode) {
    Write-Info ("Skipping rule '{0}' (Mode={1}) due to Scope filter" -f $rule.AssetTagName, $ruleMode)
    continue
  }

  # EnabledByConfigFlag gate: a rule with this field only runs when the
  # boolean at the named JSON path is true. Rules without the field always
  # run (back-compat -- this is purely additive).
  if ($rule.EnabledByConfigFlag) {
    if (-not (Test-TaggingConfigFlag -DottedPath $rule.EnabledByConfigFlag)) {
      Write-Info ("Skipping rule '{0}' -- EnabledByConfigFlag '{1}' is false (or missing) in asset-tagging.config.json" -f $rule.AssetTagName, $rule.EnabledByConfigFlag)
      continue
    }
    Write-Info ("Rule '{0}' enabled via config flag '{1}'" -f $rule.AssetTagName, $rule.EnabledByConfigFlag)
  }

  # ApplyDeviceNamePatterns: opt-in flag on the rule (boolean, default
  # false). When true, the engine -- AFTER receiving rows from KQL --
  # filters them against DeviceNamePatterns.* in the JSON config. Lives
  # in config (not KQL) so a customer never has to edit a KQL `where`
  # clause to change their device-name scope.
  $ruleApplyDeviceNamePatterns = ($rule.ApplyDeviceNamePatterns -eq $true)

  if (-not $rule.Query) { continue }

  foreach ($queryItem in @($rule.Query)) {

    $query = [string]$queryItem
    if ([string]::IsNullOrWhiteSpace($query)) { continue }

    Write-Sep
    Write-Info ("Processing: {0} (Mode={1}, Engine={2})" -f $rule.AssetTagName, $ruleMode, $queryEngine)

    if ($queryEngine -eq 'DEFENDERGRAPH') {

      Write-Info "running hunting query against engine: DEFENDERGRAPH .... Please wait !"
      # v2.2.394: Invoke-DefenderGraphQuery now returns a flat array of
      # PSCustomObject rows (REST shape); no more .Results.AdditionalProperties
      # SDK-style indirection.
      $rows = @(Invoke-DefenderGraphQuery -Query $query)
      if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results"; continue }

      # ApplyDeviceNamePatterns: row-level filter applied here, AFTER
      # KQL execution. Reads DeviceNamePatterns.* (StartsWith / Contains
      # / MatchesRegex) from the JSON config and drops rows whose
      # DeviceName / NodeName doesn't match any entry. With NO patterns the
      # rule tags nothing and says so (#136) -- it used to tag every row.
      if ($ruleApplyDeviceNamePatterns) {
        $np = if ($assetTaggingConfig) { $assetTaggingConfig.DeviceNamePatterns } else { $null }
        $npCount = 0
        if ($np) { $npCount = @($np.StartsWith | Where-Object { $_ }).Count + @($np.Contains | Where-Object { $_ }).Count + @($np.MatchesRegex | Where-Object { $_ }).Count }
        if ($npCount -eq 0) {
          Write-Warn2 ("rule '{0}' is enabled and scoped by device-name patterns, but DeviceNamePatterns has no entries -- tagging NOTHING. Add StartsWith / Contains / MatchesRegex entries to asset-tagging.config.json to use it." -f $rule.AssetTagName)
          continue
        }
        $before = $rows.Count
        $rows = @($rows | Where-Object { Test-DeviceNameMatchesConfigPatterns -DeviceName ([string]$_.DeviceName) -OrNodeName ([string]$_.NodeName) })
        Write-Info ("ApplyDeviceNamePatterns: {0} -> {1} row(s) after DeviceNamePatterns.* filter" -f $before, $rows.Count)
        if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results after name-pattern filter"; continue }
      }

      $assetTagName = [string]($rows | Select-Object -First 1).AssetTagName
      if ([string]::IsNullOrWhiteSpace($assetTagName)) { Write-Warn2 "query returned rows but AssetTagName is empty; skipping"; continue }

      $devices = @()
      $skippedNoSenseId = 0
      $skippedNotFound  = 0

      foreach ($r in $rows) {
        $name = Get-DeviceNameFromRow -Row $r
        $id   = Get-SenseDeviceIdFromRow -Row $r

        # v2.2.398: drop the per-row "Skipping Defender row -- Missing
        # SenseDeviceId" + "Skipping Defender device -- Not found"
        # warnings. These fired hundreds of times per rule for
        # un-onboarded devices (CanBeOnboarded / InsufficientInfo /
        # Unsupported buckets are full of switches / APs / IoT that
        # never had an MDE machine record). The aggregate "Skipped
        # Defender rows -- Count" summary below still tells the
        # operator how many rows were dropped and why.
        if ([string]::IsNullOrWhiteSpace($id)) {
          $skippedNoSenseId++
          continue
        }

        $exists = $true
        try {
          $exists = Test-DefenderMachineExists -AccessHeaders $AccessHeaders -MachineId $id -SuppressErrors $SuppressErrors
        }
        catch {
          if ($SuppressErrors) {
            $exists = $false
          }
          else {
            throw
          }
        }

        if (-not $exists) {
          $skippedNotFound++
          continue
        }

        $devices += [pscustomobject]@{ Id = $id; Name = $name }
      }

      if ($skippedNoSenseId -gt 0) {
        Write-WarnBlock -Title "Skipped Defender rows" -Fields ([ordered]@{
          Reason = "Missing SenseDeviceId"
          Count  = $skippedNoSenseId
        }) -SeparatorBefore
      }

      if ($skippedNotFound -gt 0) {
        Write-WarnBlock -Title "Skipped Defender rows" -Fields ([ordered]@{
          Reason = "SenseDeviceId not found in Defender or inaccessible"
          Count  = $skippedNotFound
        }) -SeparatorBefore
      }

      $devices = @($devices | Group-Object Id | ForEach-Object { $_.Group | Select-Object -First 1 })

      if (-not $devices -or $devices.Count -eq 0) {
        Write-Warn2 "no taggable devices found; skipping"
        continue
      }

      $chunkSize   = 500
      $totalChunks = [math]::Ceiling($devices.Count / $chunkSize)

      for ($i = 0; $i -lt $devices.Count; $i += $chunkSize) {

        $currentChunk = [math]::Floor($i / $chunkSize) + 1
        $endIndex     = [math]::Min($i + $chunkSize - 1, $devices.Count - 1)
        $chunk        = @($devices[$i..$endIndex])

        $namesPreview = @(
          $chunk | Select-Object -First 5 | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_.Name) -or $_.Name -like '<unknown*') {
              $_.Id
            }
            else {
              "{0} ({1})" -f $_.Name, $_.Id
            }
          }
        ) -join ', '

        if ($chunk.Count -gt 5) { $namesPreview = "$namesPreview, ..." }

        Write-InfoBlock -Title "Defender tagging batch" -Fields ([ordered]@{
          Rule     = $rule.AssetTagName
          Tag      = $assetTagName
          Chunk    = "$currentChunk/$totalChunks"
          Count    = $chunk.Count
          Machines = $namesPreview
        }) -SeparatorBefore

        # v2.2.395: per-device verbose so operators can see EXACTLY which
        # machines are getting which tag (Apply-TagBulkWithSplit hits the
        # bulk MDE endpoint and only logs a count). The bulk OK line still
        # follows below; this is purely additive visibility.
        foreach ($d in $chunk) {
          if ([string]::IsNullOrWhiteSpace($d.Name) -or $d.Name -like '<unknown*') {
            Write-Info ("Tagging device {0} with tag '{1}'" -f $d.Id, $assetTagName)
          } else {
            Write-Info ("Tagging device {0} ({1}) with tag '{2}'" -f $d.Name, $d.Id, $assetTagName)
          }
        }

        try {
          Apply-TagBulkWithSplit -AccessHeaders $AccessHeaders -Devices $chunk -Tag $assetTagName -SuppressErrors $SuppressErrors `
            -Rule ([string]$rule.AssetTagName) -RuleMode $ruleMode
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed Defender chunk tagging error" -Fields ([ordered]@{
              Tag   = $assetTagName
              Chunk = "$currentChunk/$totalChunks"
              Error = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            throw
          }
        }
      }
    }
    elseif ($queryEngine -eq 'AZURERESOURCEGRAPH') {

      Write-Info "running hunting query against engine: AZURERESOURCEGRAPH .... Please wait !"
      $arg = Invoke-AzureResourceGraphQuery -Query $query

      $rows = @()
      if ($arg -and ($arg.PSObject.Properties.Name -contains 'Data')) {
        $rows = @($arg.Data)
      } elseif ($arg) {
        $rows = @($arg)
      }
      $rows = @($rows)

      if (-not $rows -or $rows.Count -eq 0) { Write-Info "no results"; continue }

      $fallbackTagValue = $null
      if ($rule.PSObject.Properties.Name -contains 'AssetTagName' -and -not [string]::IsNullOrWhiteSpace([string]$rule.AssetTagName)) {
        $fallbackTagValue = [string]$rule.AssetTagName
      }

      $resourceIds = @(
        foreach ($r in $rows) {
          $rid = Get-ArgResourceIdFromRow -Row $r
          if (-not [string]::IsNullOrWhiteSpace($rid)) { $rid }
        }
      )
      $resourceIds = @($resourceIds | Select-Object -Unique)

      if (-not $resourceIds -or $resourceIds.Count -eq 0) {
        Write-Warn2 "ARG results did not include a resource id column (expected id/Id/ResourceId); skipping"
        continue
      }

      Write-InfoBlock -Title "Azure tagging batch" -Fields ([ordered]@{
        Rule   = $rule.AssetTagName
        Engine = $queryEngine
        Mode   = $ruleMode
        Count  = $resourceIds.Count
      }) -SeparatorBefore

      foreach ($rid in $resourceIds) {

        $match = $rows | Where-Object {
          ($_.PSObject.Properties.Name -contains 'id' -and ([string]$_.id) -eq $rid) -or
          ($_.PSObject.Properties.Name -contains 'Id' -and ([string]$_.Id) -eq $rid) -or
          ($_.PSObject.Properties.Name -contains 'ResourceId' -and ([string]$_.ResourceId) -eq $rid)
        } | Select-Object -First 1

        $nameHint = if ($match) { Get-ArgResourceNameFromRow -Row $match } else { $null }
        if ([string]::IsNullOrWhiteSpace($nameHint)) { $nameHint = "<resource>" }

        $tagKey = $null
        if ($match) { $tagKey = Get-ArgAssetTagTypeFromRow -Row $match }
        if ([string]::IsNullOrWhiteSpace($tagKey)) {
          Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
            Name       = $nameHint
            Reason     = "Missing AssetTagType"
            ResourceId = $rid
          }) -SeparatorBefore
          continue
        }

        $tagValue = $null
        if ($match) { $tagValue = Get-TagValueFromRow -Row $match -ColumnName 'AssetTagName' }
        if ([string]::IsNullOrWhiteSpace($tagValue)) { $tagValue = $fallbackTagValue }

        if ([string]::IsNullOrWhiteSpace($tagValue)) {
          Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
            Name       = $nameHint
            Reason     = "Missing AssetTagName"
            ResourceId = $rid
          }) -SeparatorBefore
          continue
        }

        $resourceType = $null
        $targetSub    = $null
        try {
          if (-not [string]::IsNullOrWhiteSpace($rid)) {
            $resourceType = Get-ResourceTypeFromResourceId -ResourceId $rid
            $targetSub    = Get-SubscriptionIdFromResourceId -ResourceId $rid
          }
        } catch {}

        try {
          $result = Add-AzureResourceTag `
            -ResourceId $rid `
            -AssetTagName $tagValue `
            -TagKey $tagKey `
            -WhatIfMode $WhatIfMode `
            -SuppressErrors $SuppressErrors

          # #236: the activity row for this resource -- planned, executed, already there, refused or failed.
          $azStatus = if ($result.Skipped) { 'Skipped' } elseif ($result.Suppressed) { 'Failed' }
                      elseif ($result.AlreadyPresent) { 'AlreadyPresent' } elseif ($result.WhatIf -and $result.Changed) { 'WouldApply' }
                      elseif ($result.Changed) { 'Applied' } else { $null }
          if ($azStatus) {
            Add-ATActivity -Target 'Azure' -Status $azStatus -Rule ([string]$rule.AssetTagName) -RuleMode $ruleMode -QueryEngine 'AzureResourceGraph' `
              -TargetId $rid -TargetName $nameHint -AssetTag $tagValue -AssetTagType $tagKey `
              -ErrorMessage $(if ($result.Skipped) { [string]$result.SkipReason } else { [string]$result.ErrorMessage }) -WhatIf $WhatIfMode
          }

          if ($result.Skipped) {
            Write-WarnBlock -Title "Skipping Azure tag" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $result.ResourceType
              Reason     = $result.SkipReason
              ResourceId = $rid
            }) -SeparatorBefore
          }
          elseif ($result.Suppressed) {
            Write-WarnBlock -Title "Suppressed Azure tagging error" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ResourceId = $rid
              Error      = $result.ErrorMessage
            }) -SeparatorBefore
          }
          elseif ($result.WhatIf -and $result.Changed) {
            Write-WarnBlock -Title "[WHATIF] Would set Azure tag" -Fields ([ordered]@{
              Name       = $nameHint
              TagKey     = $tagKey
              TagValue   = $tagValue
              Type       = $result.ResourceType
              ResourceId = $rid
            }) -SeparatorBefore
          }
          elseif ($result.AlreadyPresent) {
            Write-InfoBlock -Title "Azure tag already present" -Fields ([ordered]@{
              Name     = $nameHint
              TagKey   = $tagKey
              TagValue = $tagValue
              Type     = $result.ResourceType
            }) -SeparatorBefore
          }
          elseif ($result.Changed) {
            Write-OkBlock -Title "Azure tag set" -Fields ([ordered]@{
              Name     = $nameHint
              TagKey   = $tagKey
              TagValue = $tagValue
              Type     = $result.ResourceType
            }) -SeparatorBefore
          }
          else {
            Write-WarnBlock -Title "Azure tag returned no-change/unknown state" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              ResourceId = $rid
            }) -SeparatorBefore
          }
        }
        catch {
          Add-ATActivity -Target 'Azure' -Status 'Failed' -Rule ([string]$rule.AssetTagName) -RuleMode $ruleMode -QueryEngine 'AzureResourceGraph' `
            -TargetId $rid -TargetName $nameHint -AssetTag $tagValue -AssetTagType $tagKey -ErrorMessage ([string]$_.Exception.Message) -WhatIf $WhatIfMode
          $currentSub = $null
          try { $currentSub = (Get-SIAzContext).Subscription.Id } catch {}

          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed Azure tagging failure" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ContextSub = $currentSub
              ResourceId = $rid
              Error      = $_.Exception.Message
            }) -SeparatorBefore
          }
          else {
            Write-ErrBlock -Title "Azure tagging failed" -Fields ([ordered]@{
              Name       = $nameHint
              Type       = $resourceType
              TargetSub  = $targetSub
              ContextSub = $currentSub
              ResourceId = $rid
              Error      = $_.Exception.Message
            }) -SeparatorBefore
          }
        }
      }
    }
    elseif ($queryEngine -eq 'KUSTOCL') {

      # -----------------------------------------------------------------------
      # KustoCL engine - query Log Analytics custom table, write CSA on Entra
      # -----------------------------------------------------------------------

      if ([string]::IsNullOrWhiteSpace([string]$global:KustoWorkspaceId)) {
        Write-WarnBlock -Title "Skipping KustoCL rule" -Fields ([ordered]@{
          Rule   = $rule.AssetTagName
          Reason = "KustoWorkspaceId global is not set - add it to your launcher"
        }) -SeparatorBefore
        continue
      }

      # Substitute {{TABLE}} placeholder with the configured table name
      $kustoTable = if (-not [string]::IsNullOrWhiteSpace([string]$global:KustoTable)) {
        [string]$global:KustoTable
      } else { 'SI_IdentityAssets_CL' }

      $resolvedQuery = $query -replace '\{\{TABLE\}\}', $kustoTable

      Write-Info "running hunting query against engine: KUSTOCL .... Please wait !"

      $kResult = $null
      try {
        $kResult = Invoke-KustoCLQuery -WorkspaceId $global:KustoWorkspaceId -Query $resolvedQuery
      }
      catch {
        if ($SuppressErrors) {
          Write-WarnBlock -Title "Suppressed KustoCL query error" -Fields ([ordered]@{
            Rule  = $rule.AssetTagName
            Error = $_.Exception.Message
          }) -SeparatorBefore
          continue
        }
        throw
      }

      if (-not $kResult -or $kResult.Count -eq 0) { Write-Info "no results"; continue }

      $rows = @($kResult.Data)

      # Read AssetTagName from first row (same contract as DefenderGraph)
      $assetTagName = [string]($rows | Select-Object -First 1).AssetTagName
      if ([string]::IsNullOrWhiteSpace($assetTagName)) {
        Write-Warn2 "KustoCL query returned rows but AssetTagName column is empty; skipping"
        continue
      }

      # Resolve AttributeSet - from rule property, then global, then default
      $attributeSet = if ($rule.PSObject.Properties.Name -contains 'AttributeSet' -and
                          -not [string]::IsNullOrWhiteSpace([string]$rule.AttributeSet)) {
        [string]$rule.AttributeSet
      } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:CsaAttributeSet)) {
        [string]$global:CsaAttributeSet
      } else { 'SecurityInsight' }

      Write-InfoBlock -Title "KustoCL identity tagging batch" -Fields ([ordered]@{
        Rule         = $rule.AssetTagName
        Engine       = $queryEngine
        Mode         = $ruleMode
        Count        = $rows.Count
        AttributeSet = $attributeSet
      }) -SeparatorBefore

      $tagged   = 0
      $skipped  = 0
      $alreadyP = 0
      $failed   = 0

      foreach ($r in $rows) {

        $objectId   = Get-EntraObjectIdFromRow   -Row $r
        $objectType = Get-EntraObjectTypeFromRow  -Row $r
        $displayName= Get-EntraDisplayNameFromRow -Row $r

        if ([string]::IsNullOrWhiteSpace($objectId)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Missing ObjectId column"
            DisplayName = $displayName
          }) -SeparatorBefore
          $skipped++
          continue
        }

        if ([string]::IsNullOrWhiteSpace($objectType)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Missing ObjectType column"
            DisplayName = $displayName
            ObjectId    = $objectId
          }) -SeparatorBefore
          $skipped++
          continue
        }

        $endpoint = Get-EntraEndpointFromObjectType -ObjectType $objectType
        if ([string]::IsNullOrWhiteSpace($endpoint)) {
          Write-WarnBlock -Title "Skipping KustoCL row" -Fields ([ordered]@{
            Reason      = "Unrecognised ObjectType: $objectType"
            DisplayName = $displayName
            ObjectId    = $objectId
          }) -SeparatorBefore
          $skipped++
          continue
        }

        # Read current CSA tags - used for skip/already-present check
        $currentTags = @()
        try {
          $currentTags = Get-EntraCurrentCSATags `
            -Endpoint     $endpoint `
            -ObjectId     $objectId `
            -AttributeSet $attributeSet
        }
        catch {
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed CSA read error" -Fields ([ordered]@{
              DisplayName = $displayName
              ObjectId    = $objectId
              Error       = $_.Exception.Message
            }) -SeparatorBefore
            $skipped++
            continue
          }
          throw
        }

        try {
          $result = Set-EntraCSATag `
            -Endpoint     $endpoint `
            -ObjectId     $objectId `
            -AttributeSet $attributeSet `
            -AssetTagName $assetTagName `
            -CurrentTags  $currentTags `
            -DisplayName  $displayName `
            -WhatIfMode   $WhatIfMode `
            -SuppressErrors $SuppressErrors

          # #236: the activity row for this identity.
          $csaStatus = if ($result.Suppressed) { 'Failed' } elseif ($result.AlreadyPresent) { 'AlreadyPresent' }
                       elseif ($result.WhatIf -and $result.Changed) { 'WouldApply' } elseif ($result.Changed) { 'Applied' } else { $null }
          if ($csaStatus) {
            Add-ATActivity -Target 'Entra' -Status $csaStatus -Rule ([string]$rule.AssetTagName) -RuleMode $ruleMode -QueryEngine 'KustoCL' `
              -TargetId $objectId -TargetName $displayName -AssetTag $assetTagName -AssetTagType $attributeSet `
              -ErrorMessage ([string]$result.ErrorMessage) -WhatIf $WhatIfMode
          }

          if ($result.Suppressed) {
            Write-WarnBlock -Title "Suppressed CSA tagging error" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              AssetTagName = $assetTagName
              Error        = $result.ErrorMessage
            }) -SeparatorBefore
            $failed++
          }
          elseif ($result.WhatIf -and $result.Changed) {
            Write-WarnBlock -Title "[WHATIF] Would set CSA tag" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              ObjectType   = $objectType
              AttributeSet = $attributeSet
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $tagged++
          }
          elseif ($result.AlreadyPresent) {
            Write-InfoBlock -Title "CSA tag already present" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $alreadyP++
          }
          elseif ($result.Changed) {
            Write-OkBlock -Title "CSA tag set" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              ObjectType   = $objectType
              AttributeSet = $attributeSet
              AssetTagName = $assetTagName
            }) -SeparatorBefore
            $tagged++
          }
        }
        catch {
          Add-ATActivity -Target 'Entra' -Status 'Failed' -Rule ([string]$rule.AssetTagName) -RuleMode $ruleMode -QueryEngine 'KustoCL' `
            -TargetId $objectId -TargetName $displayName -AssetTag $assetTagName -AssetTagType $attributeSet `
            -ErrorMessage ([string]$_.Exception.Message) -WhatIf $WhatIfMode
          if ($SuppressErrors) {
            Write-WarnBlock -Title "Suppressed CSA tagging failure" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              Error        = $_.Exception.Message
            }) -SeparatorBefore
            $failed++
          }
          else {
            Write-ErrBlock -Title "CSA tagging failed" -Fields ([ordered]@{
              DisplayName  = $displayName
              ObjectId     = $objectId
              Error        = $_.Exception.Message
            }) -SeparatorBefore
          }
        }
      }

      Write-InfoBlock -Title "KustoCL batch complete" -Fields ([ordered]@{
        Rule      = $rule.AssetTagName
        Tagged    = $tagged
        AlreadyOk = $alreadyP
        Skipped   = $skipped
        Failed    = $failed
      }) -SeparatorBefore
    }
    else {
      Write-Warn2 ("Unknown QueryEngine '{0}' for rule '{1}'. Use DefenderGraph, AzureResourceGraph or KustoCL." -f $queryEngine, $rule.AssetTagName)
      continue
    }
  }
}

Write-Step "asset tag enforcement completed"

# #236: every planned and executed write, to the asset-tag activity table -- what a report-only run WOULD change, and
# what a writing run DID change, are both visible in Log Analytics and the web app, not only in this transcript.
$atRows = @(Get-ATActivity)
$atSum = Get-ATActivitySummary -Rows $atRows
Write-InfoBlock -Title ("Asset tagging activity ({0})" -f $(if ($WhatIfMode) { 'report only -- nothing was changed' } else { 'writes ON' })) -Fields ([ordered]@{
  WouldApply     = $atSum.WouldApply
  Applied        = $atSum.Applied
  AlreadyPresent = $atSum.AlreadyPresent
  Failed         = $atSum.Failed
  Skipped        = $atSum.Skipped
}) -SeparatorBefore
$atPub = Publish-ATActivity -Rows $atRows
if ($atPub.Published) { Write-Ok ("activity log: {0} row(s) sent to {1}_CL" -f $atPub.Rows, $atPub.Table) }
elseif ($atPub.Rows -gt 0) { Write-Warn2 ("activity log NOT sent ({0} row(s)): {1}" -f $atPub.Rows, $atPub.Reason) }
else { Write-Info ("activity log: {0}" -f $atPub.Reason) }

# A run where some tags failed, or whose activity rows could not be sent, did only part of its job: its health record says so.
$rhTagWhy = @()
if ([int]$atSum.Failed -gt 0) { $rhTagWhy += ('{0} tag write(s) failed' -f [int]$atSum.Failed) }
if (-not $atPub.Published -and [int]$atPub.Rows -gt 0) { $rhTagWhy += 'the activity log could not be sent' }
if ($rhTagWhy.Count -gt 0) { $rhTagExit = 'success-partial'; $rhTagMsg = ($rhTagWhy -join '; ') }
} catch {
  $rhTagExit = 'error'; $rhTagMsg = $_.Exception.Message
  throw
} finally {
  Stop-SIRunHealth -Context $rhTag -ExitReason $rhTagExit -ErrorMessage $rhTagMsg -AssetCount $rhTagCount
}
