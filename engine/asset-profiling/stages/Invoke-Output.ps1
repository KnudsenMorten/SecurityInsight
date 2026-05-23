#Requires -Version 5.1
<#
    Output stage.

    Sinks: LA (default), JSON file dump, Excel summary, optional Microsoft
    Fabric Eventhouse (lands in preview.E). LA path uses AzLogDcrIngestPS;
    JSON path drops a flat snapshot file; Excel path generates the operator
    summary.

    For the LA + Eventhouse paths are stubs; JSON + Excel write
    real files so the pipeline produces verifiable artifacts.
#>

function Apply-SIDcrScopeFilter {
    # v2.2.245 -- always-on cache-scope filter. AzLogDcrIngestPS resolves
    # DCE/DCR by NAME-ONLY Where-Object lookup against $global:AzDceDetails /
    # $global:AzDcrDetails. When same-named records exist in OTHER subs/RGs
    # (legacy installs, sibling subscriptions, other tenants the SPN can see),
    # the lookup returns an ARRAY and downstream id/immutableId becomes an
    # array -> ingest 400/404 ('Array' type or wrong-region immutableId
    # like 'westeurope'). Pre-filtering the caches to ONLY records in the
    # customer's configured sub + RG means the module physically cannot see
    # cross-scope rows -- name-only lookups are safe.
    param(
        [string]$Scope = 'pre-create',
        [string]$DcrName,
        [string]$DceName,
        [string]$SubscriptionId,
        [string]$DceResourceGroup,
        [string]$DcrResourceGroup
    )
    if (-not $SubscriptionId) { return }

    # v2.2.264 -- silent. Filter does its work without per-call logging.
    # The wait-loop's "waiting for DCR ... immutableId in ARG" messages and
    # v2.2.250's captured CheckCreateUpdate output cover the diagnostic case
    # if something actually fails. Successful runs were emitting 30+ noise
    # lines (pre-create + post-create + every 15s wait-loop iteration).
    if ($global:AzDceDetails -and $DceResourceGroup) {
        $global:AzDceDetails = @($global:AzDceDetails | Where-Object {
            $_.id -like "*/subscriptions/$SubscriptionId/resourceGroups/$DceResourceGroup/*"
        })
    }
    if ($global:AzDcrDetails -and $DcrResourceGroup) {
        $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object {
            $_.id -like "*/subscriptions/$SubscriptionId/resourceGroups/$DcrResourceGroup/*"
        })
    }
}

function Persist-SIDcrAutoRename {
    # v2.2.249 -- persist auto-renamed DCR name back into the customer's
    # SecurityInsight.custom.ps1 so the next run reads it from the override
    # path (Step 1a's "per-engine DCR name override") instead of having to
    # re-detect the collision + re-derive the suffix every run.
    #
    # Why bother since the suffix is deterministic from $global:SI_DcrResourceGroup?
    # Two reasons: (1) the customer can SEE the binding in their config file --
    # no surprise "where did this DCR name come from"; (2) if they ever change
    # SI_DcrResourceGroup, the DCR name won't silently move with it -- it stays
    # pinned to whatever was first written. The persisted value is the source
    # of truth from run 2 onward.
    #
    # Best-effort: file might not exist (community / no-custom-file mode),
    # might be read-only, or path resolution from $PSScriptRoot might fail.
    # Any failure is logged + ignored -- never blocks the engine.
    param(
        [Parameter(Mandatory)][string]$Engine,        # 'endpoint' / 'identity' / 'azure' / 'publicip'
        [Parameter(Mandatory)][string]$DcrName        # the auto-renamed value
    )

    try {
        # Walk up from this stage file (engine/asset-profiling/stages/) until
        # we find the SI repo root (the dir containing VERSION). config/ lives
        # next to it.
        $cur = $PSScriptRoot
        while ($cur -and -not (Test-Path -LiteralPath (Join-Path $cur 'VERSION'))) {
            $parent = Split-Path -Parent $cur
            if (-not $parent -or $parent -eq $cur) { $cur = $null; break }
            $cur = $parent
        }
        if (-not $cur) {
            Write-Warning "DCR auto-rename: could not locate SI repo root from script path -- skipping persist."
            return
        }
        $customPath = Join-Path $cur 'config\SecurityInsight.custom.ps1'
        if (-not (Test-Path -LiteralPath $customPath)) {
            Write-Warning ("DCR auto-rename: '{0}' not found -- skipping persist. Next run will re-derive the same name." -f $customPath)
            return
        }

        $engineCap = (Get-Culture).TextInfo.ToTitleCase($Engine.ToLowerInvariant())
        # Normalize 'Publicip' -> 'PublicIp' to match the override naming convention.
        if ($engineCap -eq 'Publicip') { $engineCap = 'PublicIp' }
        $varName  = ('SI_{0}_DcrName' -f $engineCap)
        $varToken = ('\$global:' + $varName)

        $content = Get-Content -LiteralPath $customPath -Raw -ErrorAction Stop
        $line    = ('$global:{0} = ''{1}''' -f $varName, $DcrName)

        # If the variable already exists in the file, leave it alone -- customer
        # may have set it intentionally; auto-rename only fires when it's empty,
        # so the only way this branch hits is a race with a manual edit.
        if ($content -match $varToken) {
            Write-Warning ("DCR auto-rename: `$global:{0} already present in {1} -- not overwriting." -f $varName, $customPath)
            return
        }

        $block = @"

# ----------------------------------------------------------------------------
# Added by SecurityInsight engine v2.2.249 -- $((Get-Date).ToUniversalTime().ToString('u'))
# DCR auto-rename: cross-scope name collision detected for the default DCR
# name. The engine auto-renamed this install's DCR to a unique target-RG-derived
# value to avoid the AzLogDcrIngestPS module's name-only-lookup hijack.
# Edit / remove this line to override; engine will re-detect on next run if absent.
# ----------------------------------------------------------------------------
$line

"@
        Add-Content -LiteralPath $customPath -Value $block -Encoding UTF8 -ErrorAction Stop
        Write-SIInfo ("DCR auto-rename persisted: appended `$global:{0} = '{1}' to {2}" -f $varName, $DcrName, $customPath)
    } catch {
        Write-Warning ("DCR auto-rename persist FAILED ({0}) -- next run will re-derive the same name from the target RG, so this is non-fatal." -f $_.Exception.Message)
    }
}

function Write-SIClassificationToLogAnalytics {
    # NO [CmdletBinding()]. Mirrors v2.1 RA / IAC pattern --
    # those engines are plain script bodies (no advanced-function wrappers)
    # so AzLogDcrIngestPS verbose flows naturally. Adding [CmdletBinding()]
    # here was breaking inheritance for some module functions. Verbose is
    # now forced explicitly per-call via -Verbose on each AzLogDcrIngestPS
    # invocation, matching how the user expects the engines to look.
    param(
        $RunContext,
        $Records
    )

    # No required-infra-globals check anymore -- the prestage block below
    # supplies defaults for everything (workspace, DCE, DCR, RGs, location).
    # Only auth is hard-required.
    # Auth: SI_SPN_* primary (Secret OR CertThumbprint), SI_LogIngest_* fallback,
    # UAMI when $global:SI_PreferUami + $global:SI_UAMI_ClientId set.
    # v2.2.237 -- accept cert as well as secret. AzLogDcrIngestPS module supports
    # both via -AzAppCertificateThumbprint / -AzAppSecret. SPN+cert customers
    # were previously gate-failed at this check even though Bootstrap-Auth had
    # successfully authenticated them.
    $haveSpnSecret = $global:SI_SPN_AppId  -and $global:SI_SPN_Secret         -and $global:SI_SPN_TenantId -and $global:SI_SPN_ObjectId
    $haveSpnCert   = $global:SI_SPN_AppId  -and $global:SI_SPN_CertThumbprint -and $global:SI_SPN_TenantId -and $global:SI_SPN_ObjectId
    $haveSpn       = $haveSpnSecret -or $haveSpnCert
    $haveLi        = $global:SI_LogIngest_AppId -and $global:SI_LogIngest_Secret -and $global:SI_LogIngest_TenantId -and $global:SI_LogIngest_ObjectId
    $haveUami      = $global:SI_PreferUami -and $global:SI_UAMI_ClientId
    if (-not ($haveSpn -or $haveLi -or $haveUami)) {
        return 'SKIPPED -- no auth configured. Set $global:SI_SPN_AppId + (Secret OR CertThumbprint) + TenantId + ObjectId in custom.ps1, or run Bootstrap-Auth.ps1.'
    }

    if (-not (Get-Module -Name AzLogDcrIngestPS)) {
        Import-Module AzLogDcrIngestPS -Force -ErrorAction Stop
    }

    # Per-engine schema-driven row-builder dispatch. Adding a new engine = add an
    # entry to $engineDispatch + drop a Build-SI<Engine>ProfileRow.ps1 in shared/.
    $engineDispatch = @{
        'identity' = @{
            Script    = 'Build-IdentityProfileRow.ps1'
            Function  = 'Build-SIIdentityProfileRow'
            AuditCols = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType',
                          'IdentityType','SecurityPrincipalType','Tier','DisplayName',
                          'Upn','Mail','AccountEnabled','EntraRoles_Permanent','LastSignInDateTime','IsEnabledActive')
            AlwaysOn  = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType','IdentityType','Tier')
        }
        'endpoint' = @{
            Script    = 'Build-EndpointProfileRow.ps1'
            Function  = 'Build-SIEndpointProfileRow'
            # ExposureScore wasn't in the endpoint schema -- audit always
            # reported [EMPTY]. Replaced with ExposureLevel (the schema column that
            # maps to MDE_ExposureScore via the keymap fix in this preview).
            AuditCols = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType',
                          'Hostname','DisplayName','OsPlatform','OsVersion','DeviceCategory','DeviceType','Tier',
                          'SensorHealthState','OnboardingStatus','MachineGroup','LastSeen','ExposureLevel','IsEnabledActive')
            AlwaysOn  = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType','Tier')
        }
        'publicip' = @{
            Script    = 'Build-PublicIpProfileRow.ps1'
            Function  = 'Build-SIPublicIpProfileRow'
            AuditCols = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType',
                          'IpAddress','InShodan','OpenPortCount','VulnCount','MaxCvssScore','Tier','AssetType','IsEnabledActive')
            # IpAddress dropped from AlwaysOn -- not every Azure publicIPAddresses
            # resource has an IP assigned (dynamic-allocation IPs that haven't been
            # bound, recently-deleted, or pre-provisioning state). Engine should
            # still ingest the row so downstream Hygiene reports can flag the gap.
            AlwaysOn  = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType','Tier')
        }
        'azure' = @{
            Script    = 'Build-AzureProfileRow.ps1'
            Function  = 'Build-SIAzureProfileRow'
            # dropped AssetId from row builder (== PrimaryEntityId) and
            # renamed SubscriptionId/ResourceGroup -> AzSubscriptionId/AzResourceGroup.
            # AuditCols + AlwaysOn now reflect the actual emitted columns.
            AuditCols = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType',
                          'AzureResourceId','ResourceType','AzSubscriptionId','AzResourceGroup',
                          'Name','Location','Tier','ServiceType','ServiceName','IsEnabledActive','Properties')
            AlwaysOn  = @('TimeGenerated','CollectionTime','RunId','PrimaryEntityId','PrimaryEntityType','Tier')
        }
    }

    $cfg = $engineDispatch[$RunContext.Engine]
    if (-not $cfg) {
        return ('FAILED: no engineDispatch entry for engine "{0}" -- add Build-SI<Engine>ProfileRow.ps1 + register in $engineDispatch.' -f $RunContext.Engine)
    }
    $rowBuilderPath = Join-Path $PSScriptRoot ('..\shared\' + $cfg.Script)
    if (-not (Test-Path $rowBuilderPath)) {
        return ('FAILED: row builder not found for engine "{0}": {1}' -f $RunContext.Engine, $rowBuilderPath)
    }

    . $rowBuilderPath
    $_rowTotal = @($Records).Count
    Write-SIInfo ('row builder: {0} (profiles schema) -- building {1} row(s) ...' -f $cfg.Function, $_rowTotal)
    # Per-row progress every 5% (or every 100 rows on small runs). Identity tenants
    # with 5K-50K records were silent for 30s-5min on this loop; the periodic
    # heartbeat keeps the operator aware that work is happening.
    $_rowStart = [datetime]::UtcNow
    $_rowI = 0
    $_rowStep = if ($_rowTotal -ge 2000) { [int]([Math]::Max(1, [Math]::Floor($_rowTotal / 20))) } else { [int]([Math]::Max(1, [Math]::Min(100, $_rowTotal))) }
    $flat = @(foreach ($r in $Records) {
        $_rowI++
        if ($_rowI -eq 1 -or ($_rowStep -gt 0 -and ($_rowI % $_rowStep -eq 0)) -or $_rowI -eq $_rowTotal) {
            $_pct = if ($_rowTotal -gt 0) { [int](100 * $_rowI / $_rowTotal) } else { 100 }
            $_el  = ([datetime]::UtcNow - $_rowStart).TotalSeconds
            Write-SIInfo ('   row builder: {0,5}/{1,5} ({2,3}%)  elapsed={3,5:n1}s' -f $_rowI, $_rowTotal, $_pct, $_el)
        }
        try { & $cfg.Function -Record $r -RunContext $RunContext }
        catch {
            $line = if ($_.InvocationInfo) { $_.InvocationInfo.ScriptLineNumber } else { '?' }
            $stmt = if ($_.InvocationInfo) { ($_.InvocationInfo.Line -replace '\s+',' ').Trim() } else { '' }
            Write-Warning ('       row build failed for AssetId={0} -- {1} [line {2}: {3}]' -f $r.AssetId, $_.Exception.Message, $line, $stmt)
        }
    })
    Write-SIInfo ('row builder: built {0} row(s) in {1:n1}s' -f $flat.Count, ([datetime]::UtcNow - $_rowStart).TotalSeconds)

    # Pre-ingest population audit. Per-engine sentinel column list (see $engineDispatch).
    # 0% on an always-on column halts before LA ingest -- catches data-flow regressions
    # before they ship a stale snapshot that overwrites yesterday's good one.
    if ($flat.Count -gt 0) {
        $stats = foreach ($col in $cfg.AuditCols) {
            $populated = 0
            foreach ($row in $flat) {
                if ($row.PSObject.Properties[$col]) {
                    $v = $row.$col
                    if ($null -ne $v -and "$v" -ne '' -and "$v" -ne '{}' -and "$v" -ne '[]') { $populated++ }
                }
            }
            $pct = if ($flat.Count -gt 0) { [int](100 * $populated / $flat.Count) } else { 0 }
            [pscustomobject]@{ Column = $col; Populated = $populated; Total = $flat.Count; Pct = $pct }
        }
        Write-Host ''
        Write-SIStep 'pre-ingest population audit:'
        foreach ($s in $stats) {
            # color the row by health: red 0%, yellow <25% (when AlwaysOn), gray otherwise
            $marker = ''; $col = 'Gray'
            if ($s.Pct -eq 0)                                                 { $marker = ' [EMPTY]'; $col = 'Red' }
            elseif ($s.Pct -lt 25 -and $s.Column -in $cfg.AlwaysOn)           { $marker = ' [LOW]';   $col = 'Yellow' }
            # Tabular row (column-aligned audit) -- needs raw Write-Host with dynamic color.
            # converter REGRESSION: my mechanical converter swapped Write-Host ->
            # Write-SIInfo here but couldn't strip `-ForegroundColor $col` (variable, not
            # literal Gray/DarkGray), so PS bound it as an unknown param to Write-SIInfo and
            # the whole Output stage threw. Restored to Write-Host with leading 1-space margin.
            Write-Host (' {0,-30} {1,5} / {2} = {3,3}%{4}' -f $s.Column, $s.Populated, $s.Total, $s.Pct, $marker) -ForegroundColor $col
        }
        # extended audit -- count populated cells across ALL emitted
        # columns so the user can see the schema-driven coverage. Lists the top
        # 20 most-populated and any non-trivially-empty ones too.
        $allCols = $flat | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique
        $colStats = foreach ($col in $allCols) {
            $populated = 0
            foreach ($row in $flat) {
                if ($row.PSObject.Properties[$col]) {
                    $v = $row.$col
                    if ($null -ne $v -and "$v" -ne '' -and "$v" -ne '{}' -and "$v" -ne '[]') { $populated++ }
                }
            }
            [pscustomobject]@{ Column = $col; Populated = $populated; Pct = [int](100 * $populated / $flat.Count) }
        }
        $populatedCount = @($colStats | Where-Object { $_.Populated -gt 0 }).Count
        Write-SIInfo ('schema-coverage: {0} of {1} emitted columns have at least one non-empty value' -f $populatedCount, $allCols.Count)
        $deadCritical = @($stats | Where-Object { $_.Column -in $cfg.AlwaysOn -and $_.Pct -eq 0 })
        if ($deadCritical.Count -gt 0) {
            Write-Warning ('       {0} CRITICAL column(s) at 0%% population -- run halted before LA ingest. Columns: {1}' -f `
                $deadCritical.Count, (($deadCritical.Column) -join ', '))
            return 'FAILED: critical schema columns empty -- LA ingest skipped to prevent stale data.'
        }
    }

    # Naming patterns are customer-tunable via custom.ps1 globals
    # (Layer 3 in the v2.1 config-stack model). Defaults follow the
    # SI_<Engine>_Profile + dcr-si-<engine>-profile pattern.
    # The "_Profile" suffix replaced "_Classification" because the row
    # content is broader than just a tier verdict -- it carries metadata
    # snapshot, posture proofs, EG enrichment, signal-map criticality,
    # app-group identity, and cross-engine references.
    # AzLogDcrIngestPS appends _CL on ingest.
    $engineCap = (Get-Culture).TextInfo.ToTitleCase($RunContext.Engine)
    $tablePattern = if ($global:SI_TableNamePattern) { $global:SI_TableNamePattern } else { 'SI_{0}_Profile' }
    $dcrPattern   = if ($global:SI_DcrNamePattern)   { $global:SI_DcrNamePattern }   else { 'dcr-si-{0}-profile' }
    $tableName = $tablePattern -f $engineCap
    $dcrName   = $dcrPattern   -f $RunContext.Engine.ToLowerInvariant()

    # v2.2.245 -- per-engine DCR name override (Layer 4: custom-file global beats
    # pattern). When the customer-set $global:SI_<Engine>_DcrName is non-empty,
    # it wins over the pattern-derived default. Lets each profiler engine point
    # at a fully-qualified unique DCR name to avoid collisions with same-named
    # DCRs from previous installs / sibling subscriptions / other tenants the
    # SPN can see (which would make the module's name-only DCR lookup return
    # the wrong record and 4xx the ingest).
    $_perEngineDcrName = switch ($RunContext.Engine.ToLowerInvariant()) {
        'endpoint' { [string]$global:SI_Endpoint_DcrName }
        'identity' { [string]$global:SI_Identity_DcrName }
        'azure'    { [string]$global:SI_Azure_DcrName }
        # v2.2.349 -- publicip falls back to the LEGACY $global:SI_Shodan_DcrName
        # if SI_PublicIp_DcrName isn't set. Customers who installed under the
        # standalone Invoke-PublicIpScanner.ps1 era already have SI_Shodan_DcrName
        # in their custom.ps1 pointing at their existing DCR; honour it so the
        # pipeline writes to the SAME DCR + table they're already using.
        'publicip' {
            if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_PublicIp_DcrName)) { [string]$global:SI_PublicIp_DcrName }
            else { [string]$global:SI_Shodan_DcrName }
        }
        default    { '' }
    }
    if (-not [string]::IsNullOrWhiteSpace($_perEngineDcrName)) {
        Write-SIInfo ("DCR override: '{0}' -> '{1}' (from `$global:SI_{2}_DcrName)" -f $dcrName, $_perEngineDcrName, $engineCap)
        $dcrName = $_perEngineDcrName
    }

    # v2.2.349 -- per-engine table-name override (mirrors the DCR override above).
    # Lets each engine point at a fully-qualified table name distinct from the
    # SI_<Engine>_Profile pattern. Critical for publicip migration: legacy
    # Invoke-PublicIpScanner.ps1 wrote SI_VulnerabilityPIP_CL (hardcoded), not
    # the pattern-derived SI_Publicip_Profile_CL -- preserves continuity for
    # the existing table + RA YAML queries.
    $_perEngineTableName = switch ($RunContext.Engine.ToLowerInvariant()) {
        'endpoint' { [string]$global:SI_Endpoint_TableName }
        'identity' { [string]$global:SI_Identity_TableName }
        'azure'    { [string]$global:SI_Azure_TableName }
        'publicip' {
            if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_PublicIp_TableName)) { [string]$global:SI_PublicIp_TableName }
            else { [string]$global:SI_Shodan_TableName }
        }
        default    { '' }
    }
    if (-not [string]::IsNullOrWhiteSpace($_perEngineTableName)) {
        # Module appends _CL on ingest; strip a trailing _CL on customer-set value
        # so the canonical "SI_VulnerabilityPIP_CL" config-value works as well as
        # the bare "SI_VulnerabilityPIP".
        $_perEngineTableName = $_perEngineTableName -replace '_CL$',''
        Write-SIInfo ("Table override: '{0}' -> '{1}' (from `$global:SI_{2}_TableName)" -f $tableName, $_perEngineTableName, $engineCap)
        $tableName = $_perEngineTableName
    }

    try {
        # Silence Az SDK + AzLogDcrIngestPS verbose stream for the ingest block.
        # The module reads $global:VerbosePreference internally, so $env / per-call
        # -Verbose:$false isn't enough. Restored in finally.
        $_savedVerbosePreference = $global:VerbosePreference
        $global:VerbosePreference = 'SilentlyContinue'

        # Auth: SPN primary (SI_SPN_* unified globals from Bootstrap-Auth.ps1),
        # SI_LogIngest_* legacy fallback. UAMI opt-in via $global:SI_PreferUami.
        # v2.2.237 -- cert path. AzLogDcrIngestPS module accepts cert directly via
        # -AzAppCertificateThumbprint / -AzAppCertificateStoreLocation. Route the
        # right credential into $authParams based on which globals are set:
        #   1. $global:SI_PreferUami           -> managed identity
        #   2. $global:SI_SPN_CertThumbprint   -> SPN + certificate
        #   3. $global:SI_SPN_Secret           -> SPN + secret (legacy)
        $spnAppId      = if ($global:SI_SPN_AppId)           { $global:SI_SPN_AppId }           else { $global:SI_LogIngest_AppId }
        $spnSecret     = if ($global:SI_SPN_Secret)          { $global:SI_SPN_Secret }          else { $global:SI_LogIngest_Secret }
        $spnTenantId   = if ($global:SI_SPN_TenantId)        { $global:SI_SPN_TenantId }        else { $global:SI_LogIngest_TenantId }
        $spnCertThumb  = [string]$global:SI_SPN_CertThumbprint
        # v2.2.243 -- auto-detect cert store. Connect-AzAccount probes both
        # stores; AzLogDcrIngestPS only looks in the one we pass. When the
        # cert lives in CurrentUser\My (common dev setup), the default
        # 'LocalMachine' would make LA ingest fail with
        # "Certificate ... not found in Cert:\LocalMachine\My". Customer
        # $global:SI_SPN_CertStoreLocation always wins.
        $spnCertStore  = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
                         elseif ($spnCertThumb) {
                             $_clean = $spnCertThumb -replace '\s',''
                             $_resolved = 'LocalMachine'
                             foreach ($_s in 'LocalMachine','CurrentUser') {
                                 $_c = Get-ChildItem "Cert:\$_s\My" -ErrorAction SilentlyContinue |
                                       Where-Object { $_.Thumbprint -eq $_clean -and $_.HasPrivateKey } |
                                       Select-Object -First 1
                                 if ($_c) { $_resolved = $_s; break }
                             }
                             $_resolved
                         } else { 'LocalMachine' }

        # v2.2.349 -- DEFINITIVE auth-type detection via JWT decode. Get an ARM
        # access token from the active Az session, decode the JWT payload, and
        # read the `appidacr` claim. Per Microsoft Identity docs:
        #   appidacr = 0  -> password (client secret) auth
        #   appidacr = 1  -> certificate auth (private_key_jwt)
        #   appidacr = 2  -> certificate auth (tls_client_auth)
        # This is the ground truth -- doesn't matter what's in HighPriv_* / SI_SPN_* /
        # AzContext.ExtendedProperties. The token issuer tells us what they validated.
        $jwtAuthType = $null    # 'cert' / 'secret' / $null (couldn't determine)
        try {
            $tok = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
            $tokStr = if ($tok.Token -is [System.Security.SecureString]) {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok.Token)
                try { [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            } else { [string]$tok.Token }
            $parts = $tokStr -split '\.'
            if ($parts.Length -eq 3) {
                $payload = $parts[1]
                $pad = $payload.Length % 4
                if ($pad -gt 0) { $payload = $payload + ('=' * (4 - $pad)) }
                $payload = $payload.Replace('-','+').Replace('_','/')
                $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
                $appidacr = [string]$claims.appidacr
                $jwtAuthType = switch ($appidacr) {
                    '0' { 'secret' }
                    '1' { 'cert' }
                    '2' { 'cert' }
                    default { $null }
                }
            }
        } catch { }

        $useMi   = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
        $useCert = -not $useMi -and -not [string]::IsNullOrWhiteSpace($spnCertThumb)
        $useSecret = -not $useMi -and -not $useCert -and -not [string]::IsNullOrWhiteSpace($spnSecret)

        $authParams = if ($useMi) {
            @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
        } elseif ($useCert) {
            @{
                AzAppId                       = $spnAppId
                AzAppCertificateThumbprint    = $spnCertThumb
                AzAppCertificateStoreLocation = $spnCertStore
                TenantId                      = $spnTenantId
            }
        } else {
            @{ AzAppId = $spnAppId; AzAppSecret = $spnSecret; TenantId = $spnTenantId }
        }

        # v2.2.349 -- label comes from the JWT's appidacr claim (the token issuer
        # tells us what it actually validated), not from inferring which globals
        # are populated. Falls back to explicit creds when JWT didn't decode.
        $authNote = if ($useMi)                  { 'UAMI' }
                    elseif ($jwtAuthType -eq 'cert')   { 'SPN+Cert' }
                    elseif ($jwtAuthType -eq 'secret') { 'SPN+Secret' }
                    elseif ($useCert)                  { 'SPN+Cert' }
                    elseif ($useSecret)                { 'SPN+Secret' }
                    else { 'SPN+Session' }

        # AzLogDcrIngestPS reads tokens from the active Az session cache rather
        # than doing a clean client_credentials call internally. Refresh the
        # session here so the cache holds a token the module can use. Idempotent.
        # v2.2.237 -- branch on cert vs secret so SPN+cert customers don't fall
        # through to the secret path and hit AADSTS7000215 "Invalid client secret".
        if (-not $useMi -and $spnAppId -and $spnTenantId) {
            try {
                if ($useCert) {
                    $null = Connect-AzAccount -ServicePrincipal `
                                              -Tenant                 $spnTenantId `
                                              -ApplicationId          $spnAppId `
                                              -CertificateThumbprint  $spnCertThumb `
                                              -ErrorAction Stop -WarningAction SilentlyContinue
                } elseif ($spnSecret) {
                    $secCred = [pscredential]::new($spnAppId, (ConvertTo-SecureString $spnSecret -AsPlainText -Force))
                    $null = Connect-AzAccount -ServicePrincipal `
                                              -Tenant $spnTenantId `
                                              -Credential $secCred `
                                              -ErrorAction Stop -WarningAction SilentlyContinue
                }
            } catch {
                Write-Warning ("LA ingest: SPN session refresh failed -- AzLogDcrIngestPS may 401: {0}" -f $_.Exception.Message)
            }
        }

        Write-Host ''
        Write-SIInfo ('table : {0}_CL' -f $tableName)
        Write-SIInfo ('DCR   : {0}  (rg={1})' -f $dcrName, $global:SI_DcrResourceGroup)
        Write-SIInfo ('DCE   : {0}' -f $global:SI_DceName)
        Write-SIInfo ('auth  : {0}' -f $authNote)
        Write-SIInfo ('rows  : {0}' -f $flat.Count)

        # Prestage moved to Invoke-SIEngineRun.ps1 entry (v2.2.55) so the storage
        # account exists + SI_StorageKey is backfilled BEFORE the entry-time
        # storage validation. By the time we get here, all infra is in place.

        # ---- canonical AzLogDcrIngestPS pattern (mirrors RA engine line 5914+) ----
        # Step 1: build full DCE + DCR caches via the standard helpers. Everything
        # downstream (CheckCreateUpdate, Post-*) reads these caches to resolve
        # name -> id / immutableId. Always rebuild fresh per ingest.
        $global:AzDceDetails = Get-AzDceListAll @authParams -Verbose:$false 4>$null
        $global:AzDcrDetails = Get-AzDcrListAll @authParams -Verbose:$false 4>$null

        # Step 1a: Auto-rename on cross-scope name collision (v2.2.249).
        #
        # Customer-tenant reality: the SPN has reader rights on dozens of subs.
        # Get-AzDcrListAll returns 80-100+ DCRs across them. Many share generic
        # names like 'dcr-si-endpoint' from previous installs. CheckCreateUpdate
        # internally re-fetches the cache (defeating our scope filter at Step 1b)
        # and decides "a DCR by that name exists, skip create". The wait loop
        # then never finds the DCR in target sub/RG -> 120s timeout -> 404 on
        # Post-*. Net result with v2.2.245's scope filter alone:
        #   "DCR scope filter [wait-loop-120s]: 82 cached -> 0 in target / 404"
        #
        # Real-world fix: give THIS install a unique DCR name so the cross-scope
        # records can never collide. v2.2.245 added $global:SI_<Engine>_DcrName
        # for that, but it requires customer editing custom.ps1 -- which they
        # only know after the first run fails. Auto-rename closes the loop: the
        # engine detects the collision, mints a unique suffix (-<rg> normalized),
        # and uses that. Customer-set override always still wins.
        if ([string]::IsNullOrWhiteSpace($_perEngineDcrName) -and $global:AzDcrDetails -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
            $_crossScope = @($global:AzDcrDetails | Where-Object {
                $_.name -eq $dcrName -and
                $_.id   -notlike "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
            })
            if ($_crossScope.Count -gt 0) {
                $_inScope = @($global:AzDcrDetails | Where-Object {
                    $_.name -eq $dcrName -and
                    $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
                })
                if ($_inScope.Count -eq 0) {
                    # No DCR by this name in target scope, but N cross-scope namesakes
                    # exist. Module's name-only lookup will hijack -- auto-rename to
                    # avoid the collision entirely. Suffix is the target RG name
                    # normalized to DCR-name-safe chars.
                    #
                    # v2.2.251 -- length guard. Azure Microsoft.Insights resources
                    # (DCR included) allow 1-260 chars per ARM, but practical limits
                    # (portal display, RBAC scope strings, ARG queries) cap useful
                    # names at ~60-64. If the full RG name pushes the combined name
                    # over 60 chars, fall back to an 8-char SHA1 hash of the RG
                    # name -- deterministic across runs (same RG -> same hash) so
                    # subsequent runs read the same persisted name from custom.ps1.
                    $_rgClean = ($global:SI_DcrResourceGroup -replace '[^a-zA-Z0-9-]','-').ToLowerInvariant().Trim('-')
                    $_uniqueName = "$dcrName-$_rgClean"
                    if ($_uniqueName.Length -gt 60) {
                        $_sha = [System.Security.Cryptography.SHA1]::Create()
                        try {
                            $_hashBytes = $_sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($global:SI_DcrResourceGroup.ToLowerInvariant()))
                        } finally { $_sha.Dispose() }
                        $_hashSuffix = ([BitConverter]::ToString($_hashBytes) -replace '-','').Substring(0,8).ToLowerInvariant()
                        $_uniqueName = "$dcrName-$_hashSuffix"
                        Write-SIInfo ("DCR auto-rename length guard: full-RG suffix would produce a {0}-char name (>60); replaced with 8-char SHA1 hash of RG '{1}' -> '{2}'" -f ($dcrName.Length + 1 + $_rgClean.Length), $global:SI_DcrResourceGroup, $_uniqueName)
                    }
                    Write-SIInfo ("DCR auto-rename: '{0}' -> '{1}' to avoid {2} cross-scope same-named DCR(s). Persisting to SecurityInsight.custom.ps1 so next run reads it as a normal override." -f $dcrName, $_uniqueName, $_crossScope.Count)
                    $dcrName = $_uniqueName
                    Persist-SIDcrAutoRename -Engine $RunContext.Engine -DcrName $_uniqueName
                }
                # If $_inScope.Count -gt 0, target scope HAS the DCR -- scope filter
                # at Step 1b will isolate it, no rename needed.
            }
        }

        # Step 1b: Scope filter (v2.2.245). AzLogDcrIngestPS resolves DCE/DCR by
        # NAME-ONLY Where-Object lookup against the global caches (module lines
        # 1575 / 3548 / 5457). When same-named records exist in other subs/RGs
        # (legacy installs, sibling subscriptions, cross-tenant the SPN can see),
        # the lookup returns ARRAY -> id becomes string[] -> ingest 400/404 with
        # invalid 'Array' type or wrong-region immutableId ('westeurope').
        # Fix: pre-filter BOTH caches to ONLY records that live in the customer's
        # configured sub + RG. Cross-scope records are dropped entirely so the
        # module physically cannot see them. Applied here (pre-create) and again
        # after Step 4's cache re-sync.
        Apply-SIDcrScopeFilter -Scope 'pre-create' -DcrName $dcrName -DceName $global:SI_DceName `
                               -SubscriptionId $global:SI_AzSubscriptionId `
                               -DceResourceGroup $global:SI_DceResourceGroup `
                               -DcrResourceGroup $global:SI_DcrResourceGroup

        # Step 1c: Active auth + RBAC probe (v2.2.256). Operator: "can we
        # verify that auth is working as expected with cert".
        # ---------------------------------------------------------------
        # Two questions to answer in <5s, before we burn 240s waiting:
        #   1. Does the cert-based SPN authentication produce a usable ARM
        #      token RIGHT NOW? (separate from the earlier Get-AzDcrListAll
        #      success -- that might be from a cached token; this proves
        #      the current session can mint a fresh one)
        #   2. Does the SPN hold a role that allows CREATING a DCR in the
        #      target RG? Reader is enough for listing (which is why the
        #      scope filter sees 83 cross-scope DCRs) but not for write.
        #      Need "Monitoring Contributor" or higher.
        # If either check fails, log loud + actionable but DO NOT abort
        # (the engine still runs the JSON + Excel sinks; LA fails predictably).
        # v2.2.266 -- token-mint probe only. RBAC visibility line dropped --
        # informational at best (the SPN only sees its own assignments at
        # scopes where it has roleAssignments/read, so partial view is the
        # norm and the line never told us anything actionable). True write-
        # capability test = Step 3's DCR create.
        try {
            $_ctx = Get-AzContext -ErrorAction SilentlyContinue
            if ($_ctx) {
                try {
                    $null = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
                    Write-SIInfo ('auth probe : ARM token OK ({0}, {1})' -f $_ctx.Account.Type, $_ctx.Account.Id)
                } catch {
                    Write-Warning ('auth probe : ARM token MINT FAILED -- {0}' -f $_.Exception.Message)
                }
            } else {
                Write-Warning 'auth probe : NO Az context (Connect-AzAccount not run this session).'
            }
        } catch { }

        # Step 2: schema sample (full dataset for type inference) + CollectionTime stamp.
        $schemaSample = @($flat | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $RunContext.CollectionTime -Force -PassThru
        })

        # v2.2.321 -- always print where data is being sent. Shared helper so
        # publicip/RA/profile engines all emit the same 6-line format.
        Write-SIIngestTarget -DcrName $dcrName -TableName $tableName

        # Step 3: provision/update DCR + LA table.
        # v2.2.258 -- AzLogDcrIngestPS v1.6.3 BUG WORKAROUND for cert auth.
        # CheckCreateUpdate-TableDcr-Structure has this gate at line 910:
        #     If ( ($AzAppId) -and ($AzAppSecret) ) { ...create logic... }
        # When the SPN authenticates with a certificate (SI v2.2.243+ default
        # for cert-based installs), $AzAppSecret is empty -- the entire create
        # block is skipped, function returns silently, no DCR is ever created.
        # Wait loop then times out and Post-* fails with "DcrImmutableId is
        # empty string". Module owner needs to publish v1.6.4 with the gate
        # changed to: ($AzAppId) -and ( ($AzAppSecret) -or ($AzAppCertThumb) ).
        #
        # Workaround until v1.6.4 lands: when $useCert is true, skip
        # CheckCreateUpdate and call its three inner functions directly
        # (Get-AzLogAnalyticsTableAzDataCollectionRuleStatus +
        # CreateUpdate-AzLogAnalyticsCustomLogTableDcr +
        # CreateUpdate-AzDataCollectionRuleLogIngestCustomLog). All three
        # already accept -AzAppCertificateThumbprint correctly.
        $_createOutput = $null
        try {
            $_createOutput = & {
                $VerbosePreference = 'Continue'
                $WarningPreference = 'Continue'
                $ErrorActionPreference = 'Continue'
                if ($useCert) {
                    Write-Output "v2.2.258 cert workaround: bypassing CheckCreateUpdate-TableDcr-Structure (module v1.6.3 gate skips cert path); calling inner Create/Update helpers directly."
                    # Step 3a -- check if table+DCR already exist with the same schema.
                    $_schemaArr = Get-ObjectSchemaAsArray -Data $schemaSample
                    $_needsCreate = $true
                    try {
                        $_needsCreate = [bool](Get-AzLogAnalyticsTableAzDataCollectionRuleStatus `
                            -AzLogWorkspaceResourceId  $global:SI_WorkspaceResourceId `
                            -TableName                 $tableName `
                            -DcrName                   $dcrName `
                            -SchemaSourceObject        $_schemaArr `
                            @authParams)
                    } catch {
                        Write-Warning ("StructureCheck threw -- assuming create needed. Reason: {0}" -f $_.Exception.Message)
                        $_needsCreate = $true
                    }
                    if ($_needsCreate) {
                        # Step 3b -- create/update LA table.
                        $_tableSchema = Get-ObjectSchemaAsHash -Data $schemaSample -ReturnType Table
                        $null = CreateUpdate-AzLogAnalyticsCustomLogTableDcr `
                            -AzLogWorkspaceResourceId  $global:SI_WorkspaceResourceId `
                            -SchemaSourceObject        $_tableSchema `
                            -TableName                 $tableName `
                            @authParams
                        # Step 3c -- create/update DCR.
                        $_dcrSchema = Get-ObjectSchemaAsHash -Data $schemaSample -ReturnType DCR
                        $null = CreateUpdate-AzDataCollectionRuleLogIngestCustomLog `
                            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                            -SchemaSourceObject                         $_dcrSchema `
                            -DceName                                    $global:SI_DceName `
                            -DcrName                                    $dcrName `
                            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                            -TableName                                  $tableName `
                            -LogIngestServicePricipleObjectId           $global:SI_LogIngest_ObjectId `
                            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                            @authParams
                    } else {
                        Write-Output "Existing table+DCR already match schema -- no create/update needed."
                    }
                } else {
                    # Secret or MI path -- use the canonical combined function.
                    CheckCreateUpdate-TableDcr-Structure `
                        -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                        @authParams `
                        -DceName                                    $global:SI_DceName `
                        -DcrName                                    $dcrName `
                        -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                        -TableName                                  $tableName `
                        -Data                                       $schemaSample `
                        -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                        -AzLogDcrTableCreateFromAnyMachine          $true `
                        -AzLogDcrTableCreateFromReferenceMachine    @()
                }
            } 4>&1 3>&1 2>&1 | Out-String
        } catch {
            $_createOutput = ("Step 3 threw a terminating exception: {0}" -f $_.Exception.Message)
        }

        # Step 4: re-sync caches after DCR provisioning. Newly-created DCR's
        # immutableId needs to land in ARG before Post-* can resolve it.
        # v2.2.250 -- bumped wait from 120s -> 240s. New-tenant scenarios (RG
        # was just created, ARG cold-start) routinely take 90-180s to index a
        # brand-new DCR. 120s was burning customer cycles on what's actually
        # just ARG eventual consistency.
        $_dcrReady = $false
        $_waitTotal = 0
        $_waitMax   = 240
        $_waitStep  = 15
        while ($_waitTotal -lt $_waitMax) {
            Start-Sleep -Seconds $_waitStep
            $_waitTotal += $_waitStep
            $global:AzDceDetails = Get-AzDceListAll @authParams -Verbose:$false 4>$null
            $global:AzDcrDetails = Get-AzDcrListAll @authParams -Verbose:$false 4>$null
            # Filter to target sub/RG so the name-only lookup below can't pick
            # a cross-scope DCR's immutableId (which would be in another region).
            Apply-SIDcrScopeFilter -Scope ('wait-loop-' + $_waitTotal + 's') -DcrName $dcrName -DceName $global:SI_DceName `
                                   -SubscriptionId $global:SI_AzSubscriptionId `
                                   -DceResourceGroup $global:SI_DceResourceGroup `
                                   -DcrResourceGroup $global:SI_DcrResourceGroup
            $_dcrRow = @($global:AzDcrDetails | Where-Object { $_.name -eq $dcrName } | Select-Object -First 1)[0]
            $_immId  = if ($_dcrRow) {
                if ($_dcrRow.properties -and $_dcrRow.properties.immutableId) { [string]$_dcrRow.properties.immutableId }
                elseif ($_dcrRow.immutableId)                                  { [string]$_dcrRow.immutableId }
                else                                                            { '' }
            } else { '' }
            if ($_immId -and $_immId -notlike '*location*' -and $_immId -ne $global:SI_Location) {
                Write-SIInfo ("DCR immutableId resolved after {0}s: {1}" -f $_waitTotal, $_immId)
                $_dcrReady = $true
                break
            }
            Write-SIInfo ("waiting for DCR '{0}' immutableId in ARG ({1}s/{2}s) ..." -f $dcrName, $_waitTotal, $_waitMax)
        }
        if (-not $_dcrReady) {
            Write-Warning ("DCR '{0}' immutableId not in ARG after {1}s -- ingest will likely 404." -f $dcrName, $_waitMax)
            # v2.2.250 -- dump CheckCreateUpdate-TableDcr-Structure's captured
            # verbose/warning/error stream so the operator can see WHY the DCR
            # didn't land. Three classes of failure show up in this dump:
            #   1. Module says "DCR already exists in different RG -- skipping
            #      create" -- collision detection didn't catch it (file a bug).
            #   2. Module says "creating DCR..." followed by an ARM PUT 403/401
            #      -- SPN missing Monitoring Contributor on target RG.
            #   3. Module says "creating DCR..." with no error -- DCR was created
            #      and this is genuine ARG eventual consistency lag (wait + re-run).
            if ($_createOutput) {
                Write-Warning  "===== CheckCreateUpdate-TableDcr-Structure output (captured for diagnosis) ====="
                $_createOutput -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object {
                    Write-Warning ("  | {0}" -f $_)
                }
                Write-Warning  "===== end module output ====="
            } else {
                Write-Warning "(no module output captured -- CheckCreateUpdate returned silently)"
            }
            Write-Warning "Likely root causes:"
            Write-Warning "  - ARG eventual consistency on new RG (re-run in 5 min)"
            Write-Warning "  - SPN missing 'Monitoring Contributor' on target sub or RG"
            Write-Warning "  - Module hit a same-named DCR via its internal ARM lookup that"
            Write-Warning "    bypasses our cache filter (file a bug + paste the module output above)"
            # v2.2.258 -- abort the LA sink cleanly. Without this, the engine
            # proceeds to Build-DataArrayToAlignWithSchema + Post-* which then
            # throws "Cannot bind argument to parameter 'DcrImmutableId' because
            # it is an empty string" (the new DCR doesn't exist so the cache
            # lookup returns null). Confusing for the operator; the real cause
            # is right above this line.
            return ('FAILED: DCR ''{0}'' not created in target RG after {1}s -- see module output / RBAC probe above for root cause. LA sink skipped to prevent confusing "DcrImmutableId empty" downstream error.' -f $dcrName, $_waitMax)
        }

        # Re-apply scope filter after Step 4's cache re-sync -- Get-Az*ListAll
        # repopulated the caches with the full cross-sub view; drop cross-scope
        # entries again so the upcoming Post-* call resolves names within the
        # customer's target sub/RG only.
        Apply-SIDcrScopeFilter -Scope 'post-create' -DcrName $dcrName -DceName $global:SI_DceName `
                               -SubscriptionId $global:SI_AzSubscriptionId `
                               -DceResourceGroup $global:SI_DceResourceGroup `
                               -DcrResourceGroup $global:SI_DcrResourceGroup

        # Step 5: standard 4-step prep pipeline (mirrors RA engine).
        $DataVariable = @($flat)

        # 5a. CollectionTime - shared across all rows in this run (cross-shard
        # latest-snapshot queries depend on it). Pre-stamped on $flat upstream;
        # also call the module helper as belt-and-suspenders for any row that slipped through.
        foreach ($entry in $DataVariable) {
            $entry | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $RunContext.CollectionTime -Force | Out-Null
        }

        # 5b. Host identity columns (Computer / ComputerFqdn / UserLoggedOn).
        $hostName = $env:COMPUTERNAME
        if (-not $hostName) { $hostName = [System.Net.Dns]::GetHostName() }
        $hostFqdn = $hostName
        try { $hostFqdn = [System.Net.Dns]::GetHostEntry([string]::Empty).HostName } catch { }
        $hostUser = $env:USERNAME
        if (-not $hostUser) { $hostUser = $env:USER }
        if (-not $hostUser) { $hostUser = 'container' }
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                            -Column1Name Computer     -Column1Data $hostName `
                            -Column2Name ComputerFqdn -Column2Data $hostFqdn `
                            -Column3Name UserLoggedOn -Column3Data $hostUser `
                            -Verbose:$false 4>$null

        # 5c. Validate + normalize column names + align data structure with DCR schema.
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$false 4>$null
        $DataVariable = Build-DataArrayToAlignWithSchema                 -Data $DataVariable -Verbose:$false 4>$null

        # Step 6: POST.
        $global:EnableCompressionDefault = $true
        $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                    -DceName     $global:SI_DceName `
                    -DcrName     $dcrName `
                    -Data        $DataVariable `
                    -TableName   $tableName `
                    @authParams `
                    -Verbose:$false 4>$null

        return ('OK -- {0} rows -> {1}_CL via {2}  ({3} auth, CollectionTime={4:o})' -f $DataVariable.Count, $tableName, $dcrName, $authNote, $RunContext.CollectionTime)
    }
    catch {
        # v2.2.358 -- surface the full failure with same shape as the RA-engine
        # LA-ingest catch: error body (ErrorDetails or response-stream fallback),
        # error code parsed out of the JSON body for the headline, full target
        # context (matches Write-SIIngestTarget pre-ingest block so operator can
        # correlate), and a common-cause checklist so the operator has a path
        # forward instead of just a generic 400 / 401 / 403.
        $msg = $_.Exception.Message
        $body = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $body = [string]$_.ErrorDetails.Message
        } else {
            try {
                $_respStream = $_.Exception.Response.GetResponseStream()
                if ($_respStream) {
                    if ($_respStream.CanSeek) { $_respStream.Position = 0 }
                    $_reader = New-Object System.IO.StreamReader($_respStream)
                    try { $_b = $_reader.ReadToEnd(); if (-not [string]::IsNullOrWhiteSpace($_b)) { $body = $_b } }
                    finally { $_reader.Close() }
                }
            } catch { }
        }
        $azCode = $null
        if ($body) {
            try {
                $azObj = $body | ConvertFrom-Json -ErrorAction Stop
                if ($azObj -and $azObj.error -and $azObj.error.code) { $azCode = [string]$azObj.error.code }
            } catch { }
        }
        $codeSuffix = if ($azCode) { " [code: $azCode]" } else { '' }

        Write-Host ''
        Write-SIErr '=== LA INGEST FAILED ==='
        Write-SIErr ('Exception : {0}{1}' -f $msg, $codeSuffix)
        Write-SIErr ('At        : {0}:{1}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber)
        Write-SIErr '----- ingest target context -----'
        Write-SIErr ('  Engine           : {0}' -f $RunContext.Engine)
        Write-SIErr ('  DCR              : {0}  (rg={1})' -f $dcrName, $global:SI_DcrResourceGroup)
        Write-SIErr ('  DCE              : {0}' -f $global:SI_DceName)
        Write-SIErr ('  Table            : {0}' -f $tableName)
        Write-SIErr ('  Workspace        : {0}  (rg={1})' -f $global:SI_WorkspaceName, $global:SI_WorkspaceResourceGroup)
        Write-SIErr ('  Subscription     : {0}' -f $global:SI_AzSubscriptionId)
        Write-SIErr ('  SPN AppId        : {0}' -f $spnAppId)
        Write-SIErr ('  Rows attempted   : {0}' -f @($DataVariable).Count)
        Write-SIErr ('  Auth method      : {0}' -f $authNote)
        Write-SIErr '----- raw Azure error body -----'
        if ($body) {
            foreach ($_line in ($body -split "`r?`n")) {
                if (-not [string]::IsNullOrWhiteSpace($_line)) { Write-SIErr ('  {0}' -f $_line.Trim()) }
            }
        } else {
            Write-SIErr '  (no Azure response body captured; SDK swallowed it -- re-run with -Verbose for the full HTTP trace)'
        }
        Write-SIErr '----- common causes -----'
        Write-SIErr "  - LinkedAuthorizationFailed 'Array' for dataCollectionEndpointId: the DCR has BOTH a stale + the current DCE attached (Azure portal -> DCR -> Properties shows both). Delete the stale entry, or re-create the DCR clean."
        Write-SIErr "  - Schema drift: existing DCR/table column types differ from the engine's current row shape ('InvalidTransformOutput: <col> produced:X, output:Y'). Delete the DCR ('$dcrName') AND the table ('$tableName') in workspace '$($global:SI_WorkspaceName)' -- engine will recreate with the correct shape."
        Write-SIErr "  - SPN missing 'Monitoring Metrics Publisher' on DCR RG '$($global:SI_DcrResourceGroup)' in sub '$($global:SI_AzSubscriptionId)' -- the only role required for log ingest."
        Write-SIErr "  - Body size > nginx 1 MB cap on the Log Ingestion endpoint -- if Rows attempted is high (>5K wide-schema), split into smaller batches."
        Write-Host ''
        return ('FAILED: {0}{1}' -f $msg, $codeSuffix)
    }
    finally {
        # Restore caller's verbose preference even on exception path.
        if ($null -ne $_savedVerbosePreference) { $global:VerbosePreference = $_savedVerbosePreference }
    }
}

function Invoke-SIOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    # @() forces an array even when the shard is empty (no records flowed
    # through Classify because Collect skipped everything). Without this,
    # $records is $null and downstream calls bind-error on the Mandatory
    # parameter.
    $records = @(Read-SIStageShards -Context $RunContext.StorageContext `
                                     -ContainerName $RunContext.StagingContainer `
                                     -RunId $RunContext.RunId `
                                     -Stage 'Classify' `
                                     -ReplicaIndex ([int]$RunContext.ShardIndex))

    # ---- ENDPOINT engine: "active devices only" filter ----
    # Stale Entra device registrations, offboarded MDE boxes, decommissioned
    # servers still on the EG node list -- all noise for most customers
    # tracking the live managed fleet.
    #
    # v2.2.39 flipped back to MIXED default (MDE + EG + Entra freshness).
    # Strict MDE-only (v2.2.38 brief default) dropped real Azure VMs visible only
    # in ARG/EG and lost cross-source correlation enrichment for non-MDE devices.
    # Mixed keeps the broad surface; opt-in to strict with SI_RequireMdeActive_Endpoint.
    #
    # PRECEDENCE (top wins):
    #   1. $global:SI_IncludeInactive_Endpoint = $true
    #      Disable filter entirely. Emit every asset including stale
    #      registrations + offboarded devices. Use when stale-asset cleanup
    #      IS the use-case (SOC needs to find ghosts to delete).
    #   2. $global:SI_RequireMdeActive_Endpoint = $true
    #      Strict MDE-only. Keep if NOT MDE-offboarded AND (MDE Active OR
    #      MDE_LastSeen<staleDays). Drops EG-only and Entra-only devices.
    #      Matches MDE portal "Sensor health state: Active" filter exactly.
    #   3. DEFAULT (no globals set)
    #      Mixed-source. Keep if NOT MDE-offboarded AND any of:
    #      MDE Active, MDE_LastSeen<staleDays, EG.lastSeen<staleDays,
    #      ENTRA_ApproximateLastSignInDateTime<staleDays. Preserves visibility
    #      into BYOD / IoT / Azure-VM / non-MDE-onboarded devices.
    #
    # Filter runs BEFORE all sinks (LA + JSON + Excel see same set).
    if ($RunContext.Engine -ieq 'endpoint') {
        $includeInactive  = [bool](Get-Variable -Name 'SI_IncludeInactive_Endpoint'   -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        $requireMdeActive = [bool](Get-Variable -Name 'SI_RequireMdeActive_Endpoint'  -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        # Backwards-compat: v2.2.38 introduced SI_AllowNonMdeDevices_Endpoint as
        # opt-in to mixed mode. Mixed is now the default again; the old global
        # is ignored (still mixed either way) but we don't error on it.
        $staleDays   = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
        $staleCutoff = (Get-Date).ToUniversalTime().AddDays(-$staleDays)

        if (-not $includeInactive) {
            $beforeCount = $records.Count
            $records = @($records | Where-Object {
                $m = $_.Metadata
                if (-not $m) { return $true }   # no metadata -> can't decide, keep it
                if ([string]$m.MDE_OnboardingStatus -eq 'Offboarded') { return $false }
                $sensorActive = ([string]$m.MDE_SensorHealthState -in @('Active','ImpairedCommunication'))
                if ($sensorActive) { return $true }
                # Build the freshness candidate list. Default (mixed) accepts
                # MDE / EG / Entra freshness signals. SI_RequireMdeActive_Endpoint
                # narrows to MDE_LastSeen only.
                $candidates = if ($requireMdeActive) { @('MDE_LastSeen') } else { @('MDE_LastSeen','EG_LastSeen','ENTRA_ApproximateLastSignInDateTime') }
                foreach ($prop in $candidates) {
                    $p = $m.PSObject.Properties[$prop]
                    if ($p -and $p.Value) {
                        # PS 5.1 can't bind [datetime]::TryParse(string,[ref]$ts) when $ts
                        # is initialized as $null (the [ref] doesn't match `out DateTime`
                        # because PowerShell sees [ref][object]). Use try/catch + Parse
                        # instead -- works on PS 5.1 + 7+, no typed-ref dance.
                        $ts = $null
                        try { $ts = [datetime]::Parse([string]$p.Value) } catch { $ts = $null }
                        if ($ts -and $ts.ToUniversalTime() -ge $staleCutoff) { return $true }
                    }
                }
                return $false
            })
            $dropped = $beforeCount - $records.Count
            $modeLabel = if ($requireMdeActive) { 'Strict (MDE-only)' } else { 'Mixed (MDE+EG+Entra, DEFAULT)' }
            Write-SIInfo ('asset filter [{0}, {1}d]: {2} -> {3} (dropped {4} inactive). Tighten with $global:SI_RequireMdeActive_Endpoint=$true; disable with $global:SI_IncludeInactive_Endpoint=$true.' -f $modeLabel, $staleDays, $beforeCount, $records.Count, $dropped)
        } else {
            Write-SIInfo 'asset filter: DISABLED ($global:SI_IncludeInactive_Endpoint = $true) -- emitting all assets including stale registrations'
        }
    }

    # ---- IDENTITY engine: "active identities only" filter (DEFAULT ON) ----
    # Mirrors the endpoint flip in v2.2.32: filter out disabled accounts and
    # ghost accounts (never signed in OR signed in > $global:SI_ActiveStaleDays
    # ago). Same logic as Build-IdentityProfileRow.ps1's IsEnabledActive.
    #   DEFAULT: ENTRA_Enabled=$true AND 0 <= ENTRA_LastSignInDays <= staleDays
    #   OPT-OUT: $global:SI_IncludeInactive_Identity = $true
    if ($RunContext.Engine -ieq 'identity') {
        $includeInactiveId = [bool](Get-Variable -Name 'SI_IncludeInactive_Identity' -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        $staleDaysId       = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
        if (-not $includeInactiveId) {
            $beforeCountId = $records.Count
            $records = @($records | Where-Object {
                $m = $_.Metadata
                if (-not $m) { return $true }
                if ($m.PSObject.Properties['ENTRA_Enabled'] -and $m.ENTRA_Enabled -ne $true) { return $false }
                if ($null -eq $m.ENTRA_LastSignInDays) { return $false }
                $days = $null
                try { $days = [int]$m.ENTRA_LastSignInDays } catch { return $false }
                if ($days -lt 0) { return $false }
                return ($days -le $staleDaysId)
            })
            $droppedId = $beforeCountId - $records.Count
            Write-SIInfo ('asset filter [ExcludeInactive (Identity), {0}d]: {1} -> {2} (dropped {3} disabled/stale). Set $global:SI_IncludeInactive_Identity=$true to disable.' -f $staleDaysId, $beforeCountId, $records.Count, $droppedId)
        } else {
            Write-SIInfo 'asset filter: DISABLED ($global:SI_IncludeInactive_Identity = $true) -- emitting all identities including disabled/ghost accounts'
        }
    }

    $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ('si-out-' + $RunContext.RunId)
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory | Out-Null }

    $sinkResults = @{}

    if ($RunContext.Sinks -contains 'JSON') {
        $jsonPath = Join-Path $outDir ('{0}_Classification.json' -f $RunContext.Engine)
        $records | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
        $sinkResults['JSON'] = $jsonPath
    }

    if ($RunContext.Sinks -contains 'Excel') {
        $csvPath = Join-Path $outDir ('{0}_Classification.csv' -f $RunContext.Engine)
        $flat = @(foreach ($r in $records) {
            [pscustomobject]@{
                AssetId        = $r.AssetId
                TimeGenerated  = $r.TimeGenerated
                SI_RunId       = $r.SI_RunId
                SI_Classify_Status = $r.SI_Classify_Status
                SI_Tier        = $r.Verdict.SI_Tier
                SI_ServiceType = $r.Verdict.SI_ServiceType
                SI_ServiceName = $r.Verdict.SI_ServiceName
                SI_Group       = $r.Verdict.SI_Group
                SI_FP_Meta     = $r.SI_FP_Meta
                SI_FP_Enrich   = $r.SI_FP_Enrich
            }
        })
        $flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $sinkResults['Excel'] = $csvPath
    }

    if ($RunContext.Sinks -contains 'LA') {
        if ($records.Count -gt 0) {
            $sinkResults['LA'] = Write-SIClassificationToLogAnalytics -RunContext $RunContext -Records $records
        } else {
            $sinkResults['LA'] = 'skipped (no records to write)'
        }
    }

    if ($RunContext.Sinks -contains 'Eventhouse') {
        $sinkResults['Eventhouse'] = '<stub: Fabric Eventhouse write lands in preview.E>'
    }

    # Build an honest summary that distinguishes OK from SKIPPED/FAILED per sink.
    # Emit the actual SKIP/FAIL reason as a Write-Warning so the operator can see
    # WHICH global / auth piece is missing without having to grep SinkResults.
    $sinkLabels = foreach ($k in $sinkResults.Keys) {
        $v = [string]$sinkResults[$k]
        if ($v -like 'SKIPPED*') {
            Write-Warning ('Sink {0}: {1}' -f $k, $v)
            '{0}=SKIP' -f $k
        }
        elseif ($v -like 'FAILED:*') {
            Write-Warning ('Sink {0}: {1}' -f $k, $v)
            '{0}=FAIL' -f $k
        }
        else { '{0}=OK' -f $k }
    }
    $okCount = @($sinkLabels | Where-Object { $_ -like '*=OK' }).Count

    [pscustomobject]@{
        Stage       = 'Output'
        Count       = $records.Count
        SinkResults = $sinkResults
        Summary     = ('{0} rows -> {1}/{2} sink(s) OK [{3}]' -f $records.Count, $okCount, $sinkResults.Count, ($sinkLabels -join ' '))
    }
}
