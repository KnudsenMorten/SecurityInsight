#Requires -Version 5.1
<#
    Classify stage.

    AI is the work-horse: ServiceName, ServiceType, effective tier + tier
    proofs, external-risk severity tags, grouping (subnet | rg | sub |
    servername-pattern). Respects $global:MaxAiSpendPerRun -- when reached,
    Output writes partial classification with SI_Classify_Status='budget-capped'.

    Real-Azure mode: calls the Azure OpenAI deployment configured in
    $global:OpenAI_endpoint / OpenAI_deployment / OpenAI_apiKey /
    OpenAI_apiVersion. One asset per call (batch optimisation lands later).
    JSON-mode response, deterministic temperature.

    Mock mode: deterministic rule-based stand-in (Exchange -> T1, DC -> T0,
    default -> Workstation/T2).
#>

# Per-call cost estimate -- crude but bounded. GPT-4-class deployments at
# Azure prices are ~$0.005-0.015 per asset. Customer can override in
# .custom.ps1 via $global:SI_AI_CostPerCallEstimate (recommended after
# observing actual cost from a few real runs).
function Get-SIAiCostPerCallEstimate {
    if ($global:SI_AI_CostPerCallEstimate -gt 0) {
        return [double]$global:SI_AI_CostPerCallEstimate
    }
    return 0.01    # conservative ship default
}

# Default system prompts shipped with the engine. Customer can override
# either prompt in custom.ps1 by setting $global:SI_SystemPrompt_endpoint
# or $global:SI_SystemPrompt_identity to a multi-line string.
$script:SI_SystemPrompt_endpoint_default = @'
You classify enterprise endpoint assets (servers, workstations, IoT). Return
ONLY valid JSON (no commentary, no markdown fences) with exactly these keys:

  SI_Tier           INTEGER 0..3
                    0 = critical infra (AD/ADCS/ADFS, DCs, identity providers, KV holding tenant root creds)
                    1 = production servers (line-of-business, customer-facing apps, prod databases)
                    2 = workstations / general endpoints
                    3 = LOWEST tier -- test / dev / pre-prod / external /
                        unmanaged / shadow IT / kiosk / IoT-untrusted.
                        Catch-all for anything that isn't actively used by
                        tier 0-2 personnel or doesn't host tier 0-2 workloads.
  SI_ServiceType    short categorical (Workstation, ExchangeServer, FileServer, WebApp,
                    DomainController, SqlServer, JumpHost, BuildAgent, IoT, Unknown, ...)
  SI_ServiceName    short human label, e.g. "Corp Exchange Frontend" or "<DeviceName>"
                    when no clearer name can be inferred
  SI_Group          coarse grouping key from subnet / rg / naming pattern
                    (e.g. "subnet:10.0.1.0/24" or "rg:rg-prod-web" or "name-prefix:dc-")
  SI_Tier_Proofs    ARRAY of {Source, ProofLabel, ProofWeight, Reason}
                    explaining the tier choice. Each posture-rule hit MUST appear
                    here. Reason is one short sentence.

PROPERTIES JSON SOURCE:
  When EG has ingested the device, Properties carries Microsoft's curated
  device posture view (rawData): onboardingStatus, sensorHealthState,
  antivirusEnabled, asrRules, lastSeenTime, exposureScore, criticality,
  businessApplicationName, deviceCategory, osPlatform, osVersion, etc.
  Treat onboardingStatus != "Onboarded" as a T3 hint; antivirusEnabled
  = false on a server is a T1+ red flag.

CROSS-ENGINE / SIGNAL-MAP SIGNALS:
  XENG_AppGroup / XENG_AppType / XENG_AppGroupConfidence  -- AI cluster name
                              (e.g. "DCFleet-EU" / DomainControllerCluster).
                              Use as SI_Group = "group:<XENG_AppGroup>" when
                              Confidence >= 0.4.
  XENG_CriticalityScore     -- AI signal-map composite score. Use as a tier
                              anchor: >=80 push T0/T1; 40-79 consider T1/T2;
                              <40 baseline T2/T3; <0 trust-dominant.
  XENG_ActiveSignals        -- {Path, Weight, Reason, Value}. Cite the
                              highest-weight contributors in
                              SI_Tier_Proofs.Reason.
'@

$script:SI_SystemPrompt_identity_default = @'
You classify enterprise IDENTITIES (Entra users + service principals).
Return ONLY valid JSON (no commentary, no markdown fences) with exactly:

  SI_Tier           INTEGER 0..3
                    0 = tenant admins (Global Admin, Privileged Role Admin, breakglass)
                         OR service principals with tenant-root permissions
                         (RoleManagement.ReadWrite.Directory, etc.)
                    1 = privileged role holders (User Admin, Security Admin, App Admin, Eligible PIM)
                         OR multi-tenant SPs / SPs with high write-scope perms
                    2 = regular users (employees with no admin roles)
                    3 = LOWEST tier -- catch-all for: service accounts /
                         on-prem-synced automation users / shared mailboxes /
                         managed identities scoped to one workload / external
                         B2B guests / federated partners / shadow IT.
  SI_ServiceType    short categorical:
                      Users:  HumanUser, ServiceAccount, BreakGlass, Guest, Admin
                      SPs:    ManagedIdentity, FirstPartySP, MultiTenantSP,
                              AppRegistrationSP, LegacySP
  SI_ServiceName    short human label -- usually the displayName or UPN
  SI_Group          grouping key (department, on-prem-sync source, license bundle,
                    SP publisher, or a sensible default like "sp:multi-tenant")
  SI_Tier_Proofs    ARRAY of {Source, ProofLabel, ProofWeight, Reason} explaining tier.
                    For identity, each role assignment / sensitive group / privileged
                    group membership / SP credential anomaly MUST appear here.
                    Reason is one short sentence.

CROSS-ENGINE SIGNALS (when XENG_* fields present in the payload):
  XENG_T0DevicesAccessed > 0 -- user signs in interactively to T0 endpoints
                                (DCs, ADCS, identity infra). This is a
                                strong T0 signal even without admin roles.
  XENG_T1DevicesAccessed > 0 -- production server access. Strong T1 signal.
  XENG_HighTierDeviceDetails  -- the specific devices touched. Cite at least
                                 one in SI_Tier_Proofs.Reason.
  XENG_AppGroup / XENG_AppType / XENG_AppGroupConfidence  -- AI cluster name
                                 (e.g. "Finance-Helsinki" / Department).
                                 Use as SI_Group = "group:<XENG_AppGroup>"
                                 when Confidence >= 0.4.

EG CREDENTIAL SIGNALS:
  ENTRA_HasAdLeakedCredentials = true   -- on-prem AD password hash leaked
                                           publicly. T1+ regardless of role;
                                           paired with admin role => T0.
  ENTRA_HasLeakedCredentials   = true   -- Entra password leaked. Same.
  ENTRA_IsActive               = false  -- inactive 30+ days. Tier may be
                                           lowered (T2->T3) if no admin role.
  ENTRA_HasServicePrincipalName = true on a User -- legacy SPN-bearing user
                                           (constrained-delegation risk).

AI-DISCOVERED SIGNAL MAP:
  XENG_CriticalityScore         -- INTEGER. Sum of per-field weights from
                                    an AI metaprofile run on this engine
                                    (signal-map cache). Use as a tier ANCHOR:
                                       >= 80   -> push T0/T1
                                       40..79  -> consider T1/T2
                                       0..39   -> baseline T2/T3
                                       < 0     -> trust signals dominate; T2/T3
                                    Posture rules + cross-engine still
                                    override; this is a tie-breaker + sanity
                                    check, not the only input.
  XENG_ActiveSignals            -- ARRAY of {Path, Weight, Reason, Value}
                                    explaining which fields contributed.
                                    Cite the highest-weight ones in
                                    SI_Tier_Proofs.Reason.

SERVICE-PRINCIPAL POSTURE LABELS (when ENTRA_AssetType = ServicePrincipal):
  SPState=Orphan                   -- enabled SP with zero credentials.
                                      Hygiene flag (T2/T3 unless paired with
                                      role grants). Cite the empty cred state
                                      in the proof reason.
  SPAudience=MultiTenant           -- accepts cross-tenant tokens. Push to
                                      T1 when paired with high consent or
                                      privileged role assignments. T2 alone.
  SPState=ExpiredCredentialsActive -- can't authenticate today, but role
                                      assignments persist. Note this in the
                                      reason; don't ignore the SP.
  SPState=UnverifiedPublisher      -- missing publisher attestation. Hygiene
                                      flag; T3 alone, escalate when paired
                                      with broad consent.
  SPState=CredentialExpiringSoon   -- advisory only. Do NOT use to determine
                                      tier; reflect in reason text only.
'@

$script:SI_SystemPrompt_azure_default = @'
You classify Azure RESOURCES (data stores, identity stores, network edge,
compute platforms). Return ONLY valid JSON (no commentary, no markdown
fences) with exactly:

  SI_Tier           INTEGER 0..3
                    0 = tenant-root infra: Key Vaults that store the SPN/UAMI
                        credentials for tenant-wide automation, root-management-
                        group-scoped resources, identity infrastructure.
                    1 = production data stores + customer-facing platforms:
                        prod SQL, prod Cosmos, prod Storage with sensitive data,
                        prod App Services serving customers, prod KV holding
                        per-app secrets, prod AKS clusters running prod workloads.
                    2 = shared / non-prod platform: dev/qa data stores, shared
                        monitoring, internal-only App Services, lab clusters.
                    3 = LOWEST tier -- sandbox / experimental / single-developer
                        resources, public-facing-without-intent (storage with
                        allowBlobPublicAccess, services with no
                        publicNetworkAccess restriction in non-prod), resources
                        without an Owner tag, untagged shadow IT.
  SI_ServiceType    short categorical (KeyVault, StorageAccount, SqlServer,
                    SqlManagedInstance, CosmosDb, MySqlFlexible,
                    PostgreSqlFlexible, AksCluster, AppService,
                    ApplicationGateway, LoadBalancer, NetworkSecurityGroup,
                    RedisCache, EventHub, ServiceBus, Other)
  SI_ServiceName    short human label -- displayName / resource short name
  SI_Group          grouping key. PREFER "app:<XENG_AppGroup>" when the
                    payload contains XENG_AppGroup with Confidence >= 0.4
                    (means AI clustering identified an application). Else
                    prefer "rg:<resourceGroup>", "sub:<subscriptionShortName>",
                    or "env:<EnvTag>" when an environment tag is present.
  SI_Tier_Proofs    ARRAY of {Source, ProofLabel, ProofWeight, Reason}
                    explaining tier. Each posture-rule hit MUST appear here.
                    For Azure resources, also cite tag-based signals
                    (Environment=Production, DataClassification=Confidential)
                    when present. Reason is one short sentence.

KEY POSTURE LABELS (when present in payload):
  AzPosture=KeyVaultPublicNetwork  -- KV reachable from public internet.
                                      Push to T1+ even if Production tag absent.
  AzPosture=StoragePublicAccess    -- Storage allows blob public access.
                                      Strong TE signal unless intentional CDN.
  AzPosture=SqlPublicEndpoint      -- SQL server publicly reachable. T1 + flag.
  AzPosture=NoEnvironmentTag       -- Resource has no Owner / Environment tag.
                                      Hygiene flag; do NOT use to set tier alone.
  AzPosture=ProductionTagged       -- Resource explicitly tagged Production.
                                      Strong T1 signal; T0 only if also identity-
                                      infra type (KV holding root creds).
  AzPosture=NoSoftDelete           -- KV with SoftDelete disabled (irrecoverable).
                                      T1 hygiene flag.
  AzPosture=NoRbacAuth             -- KV using legacy access policies. T2 flag.

CROSS-ENGINE SIGNALS (when XENG_* fields present in the payload):
  XENG_AccessedByT0Count > 0  -- T0-tier identities (Global Admins, breakglass)
                                 have access edges into this resource per
                                 Defender Exposure Graph. Treat as strong T1
                                 signal at minimum; resource type may push T0
                                 (KV holding tenant root creds + accessed by
                                 multiple GAs = T0).
  XENG_AccessedByT1Count > 0  -- privileged identities have access. T1+ signal.
  XENG_HighTierAccessorDetails -- specific identities + their access edge type.
                                  Cite at least ONE in SI_Tier_Proofs.Reason
                                  when XENG_AccessedByT0Count or T1Count > 0.
  XENG_AppGroup               -- AI-derived application/workload name from
                                 same-RG cluster analysis. Use as SI_Group
                                 ("app:<XENG_AppGroup>") when Confidence >= 0.4.
  XENG_AppType                -- WebApplication / Database / ApiBackend /
                                 ContainerWorkload / SecretsVault / etc. Use
                                 as a hint when AZ_Posture properties are
                                 sparse -- a resource in a "Database" cluster
                                 with sensitive data tags should escalate.

PROPERTY SOURCE NOTE:
  AZ_Posture is a hashtable of dot-paths chosen per-type by an AI metaprofile
  pass. These are the SECURITY-RELEVANT properties for THIS resource type.
  AZ_FpMeta is the broader stable-config set; you may use it for context but
  AZ_Posture is your primary tier-driver. AZ_Posture being sparse means the
  type genuinely has few security-relevant properties (e.g. a public IP
  resource); look at tags + cross-engine signals + naming for tier.

EG ENRICHMENT:
  EG_ExposureScore / EG_Criticality / EG_BusinessApp / EG_HandlesSensitiveData
       -- Defender's own inferred signals. Treat EG_Criticality='Critical'
          as a strong T1+ signal; EG_HandlesSensitiveData=true escalates
          data stores to T1+. Cite in SI_Tier_Proofs.Reason.
  XENG_CriticalityScore -- precomputed signal-map sum (see general note in
                           the endpoint/identity prompts).
  XENG_AppGroup         -- AI-clustered application name. Use as SI_Group.

PROPERTIES JSON SOURCE:
  Properties is the verbatim EG NodeProperties.rawData blob -- Microsoft's
  curated security view for THIS Azure resource type. It carries fields
  like publicNetworkAccess, allowSharedKeyAccess, encryption.*, networkAcls.*,
  enablePurgeProtection, etc. -- specific to the type (NodeLabel).
  Look at the actual fields present in Properties to drive your tier
  decision. This replaces the per-type AI metaprofile call
  for resources EG has ingested. ARG-fallback assets still use the
  AZ_Posture / AZ_FpMeta projections from the metaprofile cache.
'@

function Get-SISystemPromptForEngine {
    param([Parameter(Mandatory)][string]$Engine)
    if ($Engine -eq 'identity') {
        if ($global:SI_SystemPrompt_identity) { return $global:SI_SystemPrompt_identity }
        return $script:SI_SystemPrompt_identity_default
    }
    if ($Engine -eq 'azure') {
        if ($global:SI_SystemPrompt_azure) { return $global:SI_SystemPrompt_azure }
        return $script:SI_SystemPrompt_azure_default
    }
    if ($global:SI_SystemPrompt_endpoint) { return $global:SI_SystemPrompt_endpoint }
    return $script:SI_SystemPrompt_endpoint_default
}

function Invoke-SIOpenAIClassify {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AssetPayload,
        [Parameter()][ValidateSet('endpoint','identity','azure')][string]$Engine = 'endpoint'
    )

    $sys = Get-SISystemPromptForEngine -Engine $Engine

    $userJson = $AssetPayload | ConvertTo-Json -Depth 8 -Compress

    # Token-limit guard: AOAI rejects with 400 when prompt > deployment's
    # context window. EG payloads can be 100KB+ when an asset has many
    # related vulnerabilities/recommendations attached. ~3 chars/token rule
    # of thumb -> 200KB user prompt = ~67k tokens, blows past gpt-4-32k.
    # Cap at 60KB user content (≈20k tokens) and log when we trim.
    $maxUserChars = 60000
    if ($userJson.Length -gt $maxUserChars) {
        Write-Warning ('  AOAI payload {0:N0} chars > {1:N0} cap -- trimming Metadata + PostureHits' -f $userJson.Length, $maxUserChars)
        # Trim the two heaviest fields first; keep AssetId/Engine/Hint/Sources intact.
        $trimmed = @{
            Engine       = $AssetPayload.Engine
            AssetId      = $AssetPayload.AssetId
            Sources      = $AssetPayload.Sources
            Hint         = $AssetPayload.Hint
            Metadata     = '<trimmed: payload exceeded token budget>'
            PostureHits  = @($AssetPayload.PostureHits | Select-Object -First 20)
        }
        $userJson = $trimmed | ConvertTo-Json -Depth 8 -Compress
    }

    $body = @{
        messages = @(
            @{ role = 'system'; content = $sys },
            @{ role = 'user';   content = $userJson }
        )
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
    } | ConvertTo-Json -Depth 6 -Compress

    # opt-in AI payload dump for prompt tuning. Set
    # $global:SI_DumpAIPayload=$true (or env SI_DUMP_AI_PAYLOAD=1) and every
    # AI call writes <TEMP>\si-ai-dumps\<engine>-<safe-assetid>.json with the
    # system + user message + AOAI body sent. Prints the full path so operators
    # can open + diff to find irrelevant fields bloating the prompt.
    $dumpEnabled = $global:SI_DumpAIPayload -or `
                   ([Environment]::GetEnvironmentVariable('SI_DUMP_AI_PAYLOAD') -in '1','true','True','yes')
    if ($dumpEnabled) {
        $dumpDir = Join-Path ([System.IO.Path]::GetTempPath()) 'si-ai-dumps'
        if (-not (Test-Path $dumpDir)) { New-Item -ItemType Directory -Path $dumpDir | Out-Null }
        $safeId = ([string]$AssetPayload.AssetId) -replace '[^A-Za-z0-9._-]','_'
        $dumpPath = Join-Path $dumpDir ('{0}-{1}.json' -f $Engine, $safeId)
        $dump = @{
            Engine        = $Engine
            AssetId       = $AssetPayload.AssetId
            UserJsonChars = $userJson.Length
            SystemPrompt  = $sys
            UserPayload   = $AssetPayload
            UserJsonRaw   = $userJson
        } | ConvertTo-Json -Depth 12
        Set-Content -Path $dumpPath -Value $dump -Encoding utf8
        Write-SIInfo ('  AI payload dump -> {0} ({1:N0} chars)' -f $dumpPath, $userJson.Length)
    }

    $url = ('{0}/openai/deployments/{1}/chat/completions?api-version={2}' -f `
            $global:OpenAI_endpoint.TrimEnd('/'),
            $global:OpenAI_deployment,
            $global:OpenAI_apiVersion)

    $resp = Invoke-RestMethod -Method Post -Uri $url `
        -Headers @{ 'api-key' = $global:OpenAI_apiKey; 'Content-Type' = 'application/json' } `
        -Body $body

    $content = $resp.choices[0].message.content
    return ($content | ConvertFrom-Json)
}

function Invoke-SIClassify {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    $records = Read-SIStageShards -Context $RunContext.StorageContext `
                                   -ContainerName $RunContext.StagingContainer `
                                   -RunId $RunContext.RunId `
                                   -Stage 'Enrich' `
                                   -ReplicaIndex ([int]$RunContext.ShardIndex)

    $aiBudget       = if ($global:MaxAiSpendPerRun -gt 0) { [double]$global:MaxAiSpendPerRun } else { [double]::PositiveInfinity }
    $aiCostPerCall  = Get-SIAiCostPerCallEstimate
    $aiSpent        = 0.0

    # AI integration is OFF BY DEFAULT. Customer opts in via:
    #   $global:SI_EnableAI = $true              (tenant-wide for all engines)
    #   $global:SI_EnableAI_<engine> = $true     (per-engine -- identity/endpoint/azure/publicip)
    # Legacy kill-switches still honored:
    #   $global:SI_DisableAI                     (force-off all engines)
    #   $global:SI_DisableAI_<engine> = $true    (force-off one engine)
    # Identity engine is hard-disabled (catalog-driven since 52).
    # When disabled, Stage Classify runs deterministic-only: TargetTier-rule
    # short-circuit + cheap-path shortcuts. Assets with neither produce a
    # 'no-ai' verdict (SI_Tier=2 default + SI_Tier_Proofs explaining why no AI).
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Test-SIAIEnabled.ps1')
    $useAI = ($RunContext.StorageContext.Mode -ne 'Mock') -and (Test-SIAIEnabled -Engine $RunContext.Engine)
    if (-not $useAI) {
        Write-SIInfo ('AI integration DISABLED for engine={0} -- deterministic-only classification (opt in via $global:SI_EnableAI = $true)' -f $RunContext.Engine)
    }

    $classified = New-Object System.Collections.ArrayList
    $aiCalls    = 0
    $reused     = 0
    $errored    = 0
    $capped     = 0
    $deterministic = 0

    # Tier ordering for "highest privilege wins" when multiple v2 TargetTier
    # rules match the same asset. 0 wins over 1 wins over 2 etc.
    # dropped TE; tier 3 is the lowest-trust tier.
    # SI_Tier ships as INT (0-3) not string ("T0"-"T3"). Posture
    # rules YAML still uses "T<N>" strings for operator readability; we coerce
    # at the engine boundary via ConvertTo-SITierInt.
    function ConvertTo-SITierInt {
        param($Value)
        if ($null -eq $Value) { return $null }
        $s = [string]$Value
        if ($s -match '^[Tt]?(\d)$' -and [int]$matches[1] -in 0..3) { return [int]$matches[1] }
        return $null
    }

    # identity engine -- load the deterministic catalog classifier
    # (legacy IAC parity). Identity bypasses AOAI entirely; tier comes from
    # Min(EntraRoles, APIPerms, AzureRoles, ADGroups) catalog match.
    $identityCatalogReady = $false
    if ($RunContext.Engine -eq 'identity') {
        $catModule = Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\IdentityCatalogTierComputer.ps1'
        if (Test-Path $catModule) {
            try {
                . $catModule
                $catInfo = Initialize-SIIdentityCatalog
                # detailed per-tier breakdown so operators can see the
                # catalog's current shape (helps spot stale catalogs, missing tiers).
                Write-SIInfo ('identity catalog loaded -- dated {0}' -f $catInfo.GeneratedAt)
                Write-SIInfo ('  Entra roles    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}' -f $catInfo.EntraRoleCounts.T0, $catInfo.EntraRoleCounts.T1, $catInfo.EntraRoleCounts.T2, $catInfo.EntraRoleCounts.T3)
                Write-SIInfo ('  Graph perms    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}' -f $catInfo.APIPermCounts.T0,   $catInfo.APIPermCounts.T1,   $catInfo.APIPermCounts.T2,   $catInfo.APIPermCounts.T3)
                Write-SIInfo ('  AD groups      total       : {0,3}' -f $catInfo.ADGroupCount)
                Write-SIInfo ('  Azure roles    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}' -f $catInfo.AzureRoleCounts.T0, $catInfo.AzureRoleCounts.T1, $catInfo.AzureRoleCounts.T2, $catInfo.AzureRoleCounts.T3)
                Write-SIInfo (' identity engine = catalog-driven (no AI calls); -DisableAI is a no-op here')
                Write-SIInfo (' schema authority: v2.2/asset-profiling-schema/identity.schema.locked.json')
                $identityCatalogReady = $true
            } catch {
                Write-Warning ('Identity catalog init failed -- {0}; falling back to existing classification path' -f $_.Exception.Message)
            }
        }
    }

    # Progress: emit a heartbeat every N assets + on every error.
    # AI calls are 1-2s each, so a 100-asset run sits silent for 2-3 minutes
    # without this. Cadence-aware: print every 5 for small runs, every 25 for
    # large ones so the line count stays sane.
    $totalToClassify = $records.Count
    $progressEvery = if ($totalToClassify -lt 30) { 5 } elseif ($totalToClassify -lt 200) { 25 } else { 50 }
    $progressIdx = 0
    $stageStart  = [datetime]::UtcNow

    foreach ($r in $records) {
        $progressIdx++
        if ($progressIdx -eq 1 -or $progressIdx % $progressEvery -eq 0 -or $progressIdx -eq $totalToClassify) {
            $elapsed = ([datetime]::UtcNow - $stageStart).TotalSeconds
            Write-SIInfo ('[{0,4}/{1}] elapsed={2,5:N1}s  AI={3} det={4} reused={5} err={6} cap={7}  ~${8:N2}' -f `
                $progressIdx, $totalToClassify, $elapsed, $aiCalls, $deterministic, $reused, $errored, $capped, $aiSpent)
        }

        $verdict = $null
        $status  = 'classified'

        # ---- identity engine -- catalog-driven, no AI ----------
        # Per-asset Min(EntraRoles, APIPerms, AzureRoles, ADGroups) catalog
        # match. Identity does not need AI -- the catalog itself was AI-curated
        # once and applies to every asset deterministically. Mirrors legacy
        # IAC's tier-compute loop.
        if ($identityCatalogReady -and $RunContext.Engine -eq 'identity') {
            $entraRoles = @()
            if ($r.Metadata.ENTRA_DirectoryRolesPermanent) { $entraRoles += @($r.Metadata.ENTRA_DirectoryRolesPermanent) }
            if ($r.Metadata.ENTRA_DirectoryRolesEligible) { $entraRoles += @($r.Metadata.ENTRA_DirectoryRolesEligible) }
            $entraRoles = @($entraRoles | Where-Object { $_ } | Select-Object -Unique)

            $appPerms = @()
            if ($r.Metadata.ENTRA_AppPermissions_Application) { $appPerms += @($r.Metadata.ENTRA_AppPermissions_Application) }
            if ($r.Metadata.ENTRA_AppPermissions_Delegated)   { $appPerms += @($r.Metadata.ENTRA_AppPermissions_Delegated) }
            $appPerms = @($appPerms | Where-Object { $_ } | Select-Object -Unique)

            $entraRoleTier = Get-SITierFromEntraRoles    -Roles $entraRoles
            $apiPermTier   = Get-SITierFromEntraAPIPerms -Perms $appPerms

            # Azure RBAC delegations (EffectiveTier per assignment
            # was precomputed = Max(RoleTier, ScopeLevel) at discovery).
            # CRITICAL: skip entries where EffectiveTier is null/empty -- earlier
            # code did `[int]$e.EffectiveTier` which silently converts null to 0,
            # making EVERY user with any Azure RBAC delegation classify as T0.
            # Source-discovery may emit placeholder objects (no role-name match
            # in the catalog) where EffectiveTier is genuinely absent; those
            # entries carry no tier signal and must NOT contribute.
            $azureTier = $null
            $azDelegs  = @($r.Metadata.ENTRA_AzureDelegations) | Where-Object { $_ }
            foreach ($e in $azDelegs) {
                if (-not $e.PSObject.Properties['EffectiveTier']) { continue }
                $rawTier = $e.EffectiveTier
                if ($null -eq $rawTier -or [string]::IsNullOrWhiteSpace([string]$rawTier)) { continue }
                $t = [int]$rawTier
                if ($t -lt 0 -or $t -gt 3) { continue }
                if ($null -eq $azureTier -or $t -lt $azureTier) { $azureTier = $t }
            }

            # AD verdict source: Exposure Graph rawData.nestedAdGroupNames (NOT IdentityInfo).
            # EG already resolves nested AD group memberships into a flat name list, which is
            # exactly what the catalog matches against. IdentityInfo's GroupMembership column
            # was lossy (truncation, name vs DN inconsistency).
            $adGroups = @()
            $egRaw = $r.Metadata.ENTRA_EgRawData
            if ($egRaw -and $egRaw.PSObject.Properties['nestedAdGroupNames']) {
                $adGroups = @($egRaw.nestedAdGroupNames) | Where-Object { $_ }
            }
            $adTier   = Get-SITierFromADGroups -Groups $adGroups
            # AD users with no high-priv group match still need an EXPLICIT
            # AD verdict. Without this, AdBuiltinGroupsVerdict_Tier was blank in LA for
            # every ordinary on-prem user (Hybrid IdentityType, ENTRA_OnPrem=true).
            # Default to tier 3 + emit a clear proof so the column populates and the
            # tier is justified by something other than the bogus empty Azure RBAC proof.
            $isOnPremUser = ($r.Metadata.ENTRA_OnPrem -eq $true -and $r.Metadata.ENTRA_AssetType -eq 'User')
            if ($null -eq $adTier -and $isOnPremUser) { $adTier = 3 }
            $effective = Get-SIMinTier -Tiers @($entraRoleTier, $apiPermTier, $azureTier, $adTier)

            $proofs = New-Object System.Collections.ArrayList
            foreach ($m in (Get-SIEntraRoleMatches -Roles $entraRoles)) {
                [void]$proofs.Add(@{
                    Source      = 'Catalog:EntraRoles'
                    ProofLabel  = [string]$m.Role
                    ProofWeight = (100 - ([int]$m.CatalogTier * 25))
                    Reason      = ('Entra directory role "{0}" -> catalog tier {1}' -f $m.Role, $m.CatalogTier)
                })
            }
            foreach ($m in (Get-SIEntraPermMatches -Perms $appPerms)) {
                [void]$proofs.Add(@{
                    Source      = 'Catalog:APIPerms'
                    ProofLabel  = [string]$m.Permission
                    ProofWeight = (100 - ([int]$m.CatalogTier * 25))
                    Reason      = ('Graph permission "{0}" -> catalog tier {1}' -f $m.Permission, $m.CatalogTier)
                })
            }
            # Azure delegation proofs (one per assignment).
            # skip placeholder entries with empty RoleName / ScopeLabel /
            # EffectiveTier. Source-discovery sometimes emits objects with all-blank
            # fields when no role-name match in the catalog, which produced bogus
            # 'Azure RBAC "" at  -> effective tier ' proofs (ProofLabel='@') on every
            # ordinary user.
            foreach ($e in $azDelegs) {
                if ([string]::IsNullOrWhiteSpace([string]$e.RoleName)) { continue }
                if ($null -eq $e.EffectiveTier -or [string]::IsNullOrWhiteSpace([string]$e.EffectiveTier)) { continue }
                $inhNote = if ($e.PSObject.Properties['InheritedFromGroup'] -and $e.InheritedFromGroup) { ' (inherited via group)' } else { '' }
                [void]$proofs.Add(@{
                    Source      = 'Catalog:AzureRoles'
                    ProofLabel  = ('{0}@{1}' -f $e.RoleName, $e.ScopeLabel)
                    ProofWeight = (100 - ([int]$e.EffectiveTier * 25))
                    Reason      = ('Azure RBAC "{0}" at {1} -> effective tier {2}{3}' -f $e.RoleName, $e.ScopeLabel, $e.EffectiveTier, $inhNote)
                })
            }
            # AD group proofs (one per matched on-prem group)
            $adGroupMatches = @(Get-SIADGroupMatches -Groups $adGroups)
            foreach ($m in $adGroupMatches) {
                [void]$proofs.Add(@{
                    Source      = 'Catalog:ADGroups'
                    ProofLabel  = [string]$m.Name
                    ProofWeight = (100 - ([int]$m.Tier * 25))
                    Reason      = ('On-prem AD group "{0}" -> catalog tier {1}: {2}' -f $m.Name, $m.Tier, $m.Reason)
                })
            }
            # explicit default for OnPrem AD users with no high-priv group
            # match. Pairs with $adTier=3 default above so AdBuiltinGroupsVerdict_Tier
            # populates instead of leaving the column blank.
            if ($isOnPremUser -and $adGroupMatches.Count -eq 0) {
                $dn = if ($r.Metadata.ENTRA_DisplayName) { [string]$r.Metadata.ENTRA_DisplayName } else { [string]$r.AssetId }
                [void]$proofs.Add(@{
                    Source      = 'Catalog:ADGroups'
                    ProofLabel  = 'OnPremUser-NoBuiltinMatch'
                    ProofWeight = 10
                    Reason      = ('On-prem AD user "{0}" -- no high-privilege AD-builtin-group match -> default tier 3.' -f $dn)
                })
            }
            # Cheap-path: disabled user accounts always T3
            if ($r.Metadata.ENTRA_Enabled -eq $false -and $r.Metadata.ENTRA_AssetType -eq 'User') {
                [void]$proofs.Add(@{
                    Source='Catalog:UserState'; ProofLabel='DisabledUser'; ProofWeight=80
                    Reason='Account disabled -- cannot sign in.'
                })
            }
            if ($proofs.Count -eq 0) {
                [void]$proofs.Add(@{
                    Source='Catalog:NoMatch'; ProofLabel='NoCatalogMatch'; ProofWeight=0
                    Reason='No Entra roles, no API permissions, no privileged signals -- defaulted to tier 3 (low).'
                })
            }

            $serviceType = if ($r.Metadata.ENTRA_AssetType -eq 'User') {
                if ($r.Metadata.ENTRA_Enabled -eq $false) { 'DisabledUser' }
                elseif ($r.Metadata.ENTRA_UserType -eq 'Guest') { 'Guest' }
                else { 'User' }
            } elseif ($r.Metadata.ENTRA_AssetType -eq 'ServicePrincipal') {
                if ($r.Metadata.ENTRA_SPType -eq 'ManagedIdentity') { 'ManagedIdentity' }
                elseif ($r.Metadata.ENTRA_SPAppOwnerTenant -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a') { 'FirstPartySP' }
                elseif ($r.Metadata.ENTRA_SPSignInAudience -in 'AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount') { 'MultiTenantSP' }
                elseif ($r.Metadata.ENTRA_SPType -eq 'Legacy') { 'LegacySP' }
                else { 'AppRegistrationSP' }
            } else { 'Identity' }

            $svcName = if ($r.Metadata.ENTRA_DisplayName) { [string]$r.Metadata.ENTRA_DisplayName }
                       elseif ($r.Metadata.ENTRA_UPN)    { [string]$r.Metadata.ENTRA_UPN }
                       elseif ($r.Name)                  { [string]$r.Name }
                       else                              { $r.AssetId }

            # legacy-IAC output schema parity. Per-provider tier sources +
            # per-asset flags + highest-risk callouts so downstream KQL / dashboards
            # can drop columns instead of parsing SI_Tier_Proofs.

            # TierSources: per-provider {Tier, CatalogMatches[]} JSON
            $tierSources = [ordered]@{
                EntraID_Roles_Permanent = [ordered]@{
                    Tier             = (Get-SITierFromEntraRoles -Roles @($r.Metadata.ENTRA_DirectoryRolesPermanent | Where-Object { $_ }))
                    CatalogMatches   = (Get-SIEntraRoleMatches  -Roles @($r.Metadata.ENTRA_DirectoryRolesPermanent | Where-Object { $_ }))
                    Roles            = @($r.Metadata.ENTRA_DirectoryRolesPermanent | Where-Object { $_ })
                }
                EntraID_Roles_Eligible  = [ordered]@{
                    Tier             = (Get-SITierFromEntraRoles -Roles @($r.Metadata.ENTRA_DirectoryRolesEligible | Where-Object { $_ }))
                    CatalogMatches   = (Get-SIEntraRoleMatches  -Roles @($r.Metadata.ENTRA_DirectoryRolesEligible | Where-Object { $_ }))
                    Roles            = @($r.Metadata.ENTRA_DirectoryRolesEligible | Where-Object { $_ })
                }
                EntraID_APIPermissions = [ordered]@{
                    Tier             = $apiPermTier
                    CatalogMatches   = (Get-SIEntraPermMatches -Perms $appPerms)
                    HighestRisk      = (Get-SIHighestRiskEntraAPIPermission -Perms $appPerms)
                    ApplicationPerms = @($r.Metadata.ENTRA_AppPermissions_Application)
                    DelegatedPerms   = @($r.Metadata.ENTRA_AppPermissions_Delegated)
                }
                AD                     = [ordered]@{
                    Tier             = $adTier
                    CatalogMatches   = (Get-SIADGroupMatches -Groups $adGroups)
                    AllGroups        = $adGroups
                }
                Azure                  = [ordered]@{
                    Tier             = $azureTier
                    Assignments      = @($azDelegs)
                    HighestRisk      = ($azDelegs | Sort-Object EffectiveTier | Select-Object -First 1)
                }
            }

            # Per-asset boolean flags + callouts (precomputed once -> no KQL runtime work)
            $isManagedIdentity = ($r.Metadata.ENTRA_SPType -eq 'ManagedIdentity')
            $isMultiTenant     = ($r.Metadata.ENTRA_SPSignInAudience -in 'AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount')
            $isFirstParty      = ($r.Metadata.ENTRA_SPAppOwnerTenant -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')
            # IsBreakGlass full gate -- GA permanent + display matches
            # break/emergency/glass/bg- + last sign-in > 30 days (or never).
            $lastSignInDays = if ($null -ne $r.Metadata.ENTRA_LastSignInDays) { [int]$r.Metadata.ENTRA_LastSignInDays } else { -1 }
            $isInactive30   = ($lastSignInDays -lt 0 -or $lastSignInDays -gt 30)
            $isBreakGlass   = (
                ($r.Metadata.ENTRA_DirectoryRolesPermanent -contains 'Global Administrator') -and
                ($r.Metadata.ENTRA_DisplayName -and ([string]$r.Metadata.ENTRA_DisplayName) -match '(?i)break|emergency|glass|bg-') -and
                $isInactive30
            )
            # IsActive: sign-in within last 30 days (-1 = unknown -> false)
            $isActive = ($lastSignInDays -ge 0 -and $lastSignInDays -le 30)
            $isHighValueTarget = ($effective -in 0,1)
            $isSensitive       = ($effective -eq 0)
            $highestApiPerm    = Get-SIHighestRiskEntraAPIPermission -Perms $appPerms
            $highestAzScope    = if ($azDelegs.Count -gt 0) {
                $top = $azDelegs | Sort-Object EffectiveTier | Select-Object -First 1
                [string]$top.ScopeLabel
            } else { '' }

            $verdict = @{
                SI_Tier                          = $effective
                SI_ServiceType                   = $serviceType
                SI_ServiceName                   = $svcName
                SI_Group                         = if ($r.Metadata.ENTRA_Department) { [string]$r.Metadata.ENTRA_Department } else { '' }
                SI_Tier_Proofs                   = $proofs.ToArray()
                # schema-parity columns
                TierSources                      = ($tierSources | ConvertTo-Json -Depth 8 -Compress)
                IsSensitive                      = $isSensitive
                IsHighValueTarget                = $isHighValueTarget
                IsBreakGlass                     = $isBreakGlass
                IsManagedIdentity                = $isManagedIdentity
                IsMultiTenant                    = $isMultiTenant
                IsFirstPartySP                   = $isFirstParty
                IsActive                         = $isActive
                HighestRiskEntraAPIPermission    = $highestApiPerm
                HighestRiskAzureScopeLabel       = $highestAzScope
                LastSignInDateTime               = if ($r.Metadata.ENTRA_LastSignInDateTime) { [string]$r.Metadata.ENTRA_LastSignInDateTime } else { '' }
                LastSignInDays                   = $lastSignInDays
                CustomSecurityAttributes         = if ($r.Metadata.ENTRA_CustomSecurityAttributes) { [string]$r.Metadata.ENTRA_CustomSecurityAttributes } else { '{}' }
            }
            $deterministic++
            $status = 'catalog'
        }

        # ---- v2 TargetTier short-circuit -----------------------------------
        # Any posture rule v2 with Mode=Production AND a TargetTier that
        # matched? Skip AI -- the rule is by definition deterministic
        # ("DC detected -> T0", "BreakGlass detected -> T0"). Highest-priv
        # tier wins when multiple rules match.
        $deterministicHit = $null
        $deterministicHitInt = $null
        foreach ($h in @($r.PostureHits)) {
            if ($h.Mode -eq 'Production' -and $h.TargetTier) {
                $candInt = ConvertTo-SITierInt $h.TargetTier
                if ($null -eq $candInt) { continue }
                if ($null -eq $deterministicHit -or $candInt -lt $deterministicHitInt) {
                    $deterministicHit = $h
                    $deterministicHitInt = $candInt
                }
            }
        }

        if (-not $verdict -and $deterministicHit) {
            # guarded with `-not $verdict` so identity catalog branch
            # above wins when it already classified the asset.
            $deterministic++
            $status  = 'deterministic'
            $verdict = @{
                SI_Tier        = $deterministicHitInt
                SI_ServiceType = if ($deterministicHit.Label -match 'ServiceType=(.+)$') { $matches[1] } else { 'Other' }
                SI_ServiceName = $r.AssetId
                SI_Group       = if ($r.Enrichment.XENG_AppGroup) { ('app:{0}' -f $r.Enrichment.XENG_AppGroup) } else { 'deterministic' }
                SI_Tier_Proofs = $r.PostureHits
            }
        }
        # identity engine cheap-path shortcut for disabled users only.
        # ManagedIdentity + FirstParty-MS shortcuts were considered, then dropped
        # because both classes can hold highly-privileged Graph application
        # permissions (Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory,
        # etc.) that make them effectively T0. SP discovery does NOT yet pull
        # appRoleAssignments / oauth2PermissionGrants, so the cheap-path can't
        # safely categorize them. Re-enable when discovery emits those fields
        # and posture rules with TargetTier cover the privileged-perm cases.
        elseif (-not $verdict -and $r.Metadata -and $r.Metadata.ENTRA_Enabled -eq $false -and `
                $r.Metadata.ENTRA_AssetType -eq 'User') {
            # Disabled user accounts -> T3. Disabled = cannot sign in.
            # If a disabled user still holds a sensitive role, that's a posture-rule
            # finding (TargetTier=0/1) which fires above this branch.
            $deterministic++
            $status  = 'deterministic'
            $verdict = @{
                SI_Tier        = 3
                SI_ServiceType = 'DisabledUser'
                SI_ServiceName = if ($r.Metadata.ENTRA_DisplayName) { [string]$r.Metadata.ENTRA_DisplayName } else { $r.AssetId }
                SI_Group       = 'user:disabled'
                SI_Tier_Proofs = @(@{ Source='Cheap-path'; ProofLabel='DisabledUser'; ProofWeight=80; Reason='Account disabled -- cannot sign in.' })
            }
        }
        # dropped revalidated path. Cadence (Stage Collect) is
        # the only skip mechanism; every record reaching Classify gets
        # either the deterministic short-circuit (above) or a fresh AI call.
        elseif ($useAI) {
            if (($aiSpent + $aiCostPerCall) -gt $aiBudget) {
                $capped++
                $status  = 'budget-capped'
                $verdict = @{
                    SI_Tier        = 2
                    SI_ServiceType = 'Unknown'
                    SI_ServiceName = $r.AssetId
                    SI_Group       = 'unknown'
                    SI_Tier_Proofs = @(@{ Source='Budget'; ProofLabel='budget-capped'; ProofWeight=0; Reason='AI spend cap reached for this run' })
                }
            } else {
                $hasExch = ($r.PostureHits | Where-Object { $_.Label -eq 'ServiceType=ExchangeServer' }).Count -gt 0
                $hasDc   = ($r.PostureHits | Where-Object { $_.Label -eq 'ServiceType=DomainController' }).Count -gt 0

                $payload = @{
                    Engine       = $RunContext.Engine
                    AssetId      = $r.AssetId
                    Sources      = $r.Sources
                    Hint         = $r.Hint
                    Metadata     = $r.Metadata
                    PostureHits  = $r.PostureHits
                }
                try {
                    $verdict = Invoke-SIOpenAIClassify -AssetPayload $payload -Engine $RunContext.Engine
                    # Coerce SI_Tier to int -- AI may return "T0" or 0 depending on prompt + temperature.
                    $verdict.SI_Tier = ConvertTo-SITierInt $verdict.SI_Tier
                    if ($null -eq $verdict.SI_Tier) { $verdict.SI_Tier = 2 }   # safety floor
                    $aiCalls++
                    $aiSpent += $aiCostPerCall
                } catch {
                    # Surface the AOAI response body -- 'Bad Request' alone hides the real
                    # cause (token-limit overflow, content-filter trip, schema rejection).
                    $msg  = $_.Exception.Message
                    $body = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
                    Write-Warning ('Classify AI call failed for {0} -- {1}' -f $r.AssetId, $msg)
                    if ($body) { Write-Warning ('  AOAI body: {0}' -f $body) }
                    $errored++
                    $status = 'error'
                    # Cheap fallback so the row still ships
                    $tier = if ($hasDc) { 0 } elseif ($hasExch) { 1 } else { 2 }
                    $svc  = if ($hasDc) { 'DomainController' } elseif ($hasExch) { 'ExchangeServer' } else { 'Workstation' }
                    $verdict = @{
                        SI_Tier        = $tier
                        SI_ServiceType = $svc
                        SI_ServiceName = $r.AssetId
                        SI_Group       = 'fallback'
                        SI_Tier_Proofs = $r.PostureHits
                    }
                }
            }
        }
        elseif (-not $verdict) {
            # No-AI path. Two scenarios:
            #   a) Mock mode (running without real Az / OpenAI -- legacy behaviour,
            #      use synthetic ServiceType heuristics so unit tests get tiered output)
            #   b) DisableAI / SI_DisableAI_<engine>=$true and the asset
            #      didn't match a TargetTier rule or cheap-path. Emit a 'no-ai' verdict
            #      that records WHY this asset has no tier opinion.
            # gate the entire branch on `-not $verdict` so the catalog
            # branch's verdict (identity engine) doesn't get OVERWRITTEN with the
            # no-ai fallback.
            if (-not $useAI) {
                $deterministic++
                $status = 'no-ai'
                # Derive a useful AssetType + Group from what we already know
                # rather than hard-coding "Unknown" / "no-ai" -- AI being off is
                # a configuration choice, not a reason to lose all asset typing.
                $derivedType  = 'Unknown'
                $derivedGroup = 'unclassified'
                $os = if ($r.Metadata.MDE_OSPlatform) { [string]$r.Metadata.MDE_OSPlatform } elseif ($r.Metadata.EG_OS) { [string]$r.Metadata.EG_OS } else { '' }
                $hostname = if ($r.Metadata.MDE_DeviceName) { [string]$r.Metadata.MDE_DeviceName } else { '' }
                if ($RunContext.Engine -eq 'endpoint') {
                    # Endpoint AssetType fallback chain. Rules in Stage Profile
                    # (AssetProfileByApplicationServiceDetection / DeviceType) can OVERRIDE
                    # with a more specific value (ExchangeServer, SQLServer, FileServer, ...);
                    # this just stops endpoints landing in reports as "Unknown" when no
                    # rule matched and AI is off.
                    # Priority order: explicit DC marker > MDE_DeviceCategory > OS family.
                    $mdeCat = ''
                    if ($r.Metadata.MDE_DeviceCategory) { $mdeCat = [string]$r.Metadata.MDE_DeviceCategory }
                    $isDc = $false
                    if ($mdeCat -ieq 'DomainController') { $isDc = $true }
                    elseif ($r.Metadata.EG_isDomainController) { $isDc = [bool]$r.Metadata.EG_isDomainController }
                    if ($isDc) {
                        $derivedType = 'DomainController'
                    } elseif ($mdeCat -and ($mdeCat -ne 'Other') -and ($mdeCat -ne 'Unknown')) {
                        # MDE buckets: Endpoint, Server, Mobile, IoT, NetworkDevice
                        $derivedType = $mdeCat
                    } elseif ($os -match '(?i)Server') {
                        $derivedType = 'Server'
                    } elseif ($os -match '(?i)Windows10|Windows11|Win10|Win11') {
                        $derivedType = 'Workstation'
                    } elseif ($os -match '(?i)iOS|iPadOS|Android') {
                        $derivedType = 'Mobile'
                    } elseif ($os -match '(?i)Linux|Ubuntu|RHEL|CentOS|Debian') {
                        $derivedType = 'Linux'
                    } elseif ($os -match '(?i)macOS|Darwin') {
                        $derivedType = 'macOS'
                    } elseif ($os) {
                        $derivedType = 'Endpoint'   # OS known but family unrecognized
                    }
                    # Group derivation (unchanged)
                    if ($r.Metadata.MDE_MachineGroup) { $derivedGroup = ('rbac:{0}' -f $r.Metadata.MDE_MachineGroup) }
                    elseif ($r.Metadata.ARG_RG)        { $derivedGroup = ('rg:{0}'   -f $r.Metadata.ARG_RG) }
                    elseif ($os)                       { $derivedGroup = ('os:{0}'   -f $os) }
                }
                elseif ($RunContext.Engine -eq 'azure') {
                    if ($r.Metadata.AZ_NodeLabel) { $derivedType = ($r.Metadata.AZ_NodeLabel -split '/' | Select-Object -Last 1) }
                    elseif ($r.Metadata.AZ_Type)  { $derivedType = ($r.Metadata.AZ_Type      -split '/' | Select-Object -Last 1) }
                    if ($r.Metadata.AZ_RG) { $derivedGroup = ('rg:{0}' -f $r.Metadata.AZ_RG) }
                }
                elseif ($RunContext.Engine -eq 'publicip') {
                    if ($r.Metadata.IP_Address) { $derivedType = 'PublicIP' }
                }
                # drop the hardcoded SI_Tier=2 default. Tier is now
                # purely MIN-of-SIRules driven by Stage Profile (catalog matches +
                # virtual logon-graph rule + future cross-engine signals). When no
                # rule fires the asset surfaces SI_Tier=null so operators see the
                # gap and add a rule -- no silent "everything-is-T2" floor.
                $verdict = @{
                    SI_Tier        = $null
                    SI_ServiceType = $derivedType
                    SI_ServiceName = if ($hostname) { $hostname } else { $r.AssetId }
                    SI_Group       = $derivedGroup
                    SI_Tier_Proofs = @(@{ Source='NoAI'; ProofLabel='AIDisabled'; ProofWeight=0; Reason=('AI disabled -- AssetType="{0}" derived from hostname/OS heuristics. Tier left null for Stage Profile to compute via MIN-of-SIRules.' -f $derivedType) }) + @($r.PostureHits)
                }
            } else {
                # Mock / no-OAI-config fallback: deterministic rule-based stand-in.
                $aiCalls++
                $hasExch = ($r.PostureHits | Where-Object { $_.Label -eq 'ServiceType=ExchangeServer' }).Count -gt 0
                $hasDc   = ($r.PostureHits | Where-Object { $_.Label -eq 'ServiceType=DomainController' }).Count -gt 0
                $tier = 2; $serviceType = 'Workstation'
                if ($hasExch) { $tier = 1; $serviceType = 'ExchangeServer' }
                elseif ($hasDc) { $tier = 0; $serviceType = 'DomainController' }
                $verdict = @{
                    SI_Tier        = $tier
                    SI_ServiceType = $serviceType
                    SI_ServiceName = ('{0}-{1}' -f $r.AssetId, $serviceType)
                    SI_Tier_Proofs = $r.PostureHits
                    SI_Group       = ('subnet:{0}' -f $r.Metadata.MDE_Subnet)
                }
            }
        }

        [void]$classified.Add(@{
            AssetId            = $r.AssetId
            TimeGenerated      = ([datetime]::UtcNow.ToString('o'))
            SI_RunId           = $RunContext.RunId
            SI_FP_Meta         = $r.FpMeta
            SI_FP_Enrich       = $r.FpEnrich
            SI_Classify_Status = $status
            Verdict            = $verdict
            # Carry Metadata through to Stage Output. Without it, Build-IdentityProfileRow
            # sees an empty Metadata blob and every ENTRA_*-sourced flat column lands null
            # (DisplayName, Upn, Department, EntraRoles_*, etc.). Identity engine reads it
            # via Resolve-SISourceValue + the _SIEntraKeyMap.
            Metadata           = $r.Metadata
        })

        # cache stores only what cadence + last-known-tier
        # lookup needs. fp_meta + fp_enrich columns dropped (existing rows
        # carry stale values; harmless -- nothing reads them anymore).
        # wrapped in try/catch -- a single fingerprint write failure
        # (Azure Tables 400 from oversized verdict JSON, key with bad chars,
        # transient throttling) was terminating the entire stage and losing
        # all classification work. Now per-asset failures are warnings only.
        #
        # Cache is opt-in via $global:SI_FingerprintCache_Enabled (default
        # $false in shared-defaults.ps1). When disabled, skip the writes
        # entirely -- ForceFullRun tenants never read the cache, so the
        # writes are pure overhead + transcript noise from 400s on identity
        # rows with large role/permission JSON.
        if ($global:SI_FingerprintCache_Enabled -eq $true) {
            try {
                $verdictJson = $verdict | ConvertTo-Json -Compress -Depth 8
                # Azure Tables string-property limit: 32,768 UTF-16 chars
                # (== 64KB). Truncate the verdict to ~30K chars so even if
                # the payload contains non-ASCII surrogates the resulting
                # UTF-16 byte length stays comfortably under the cap.
                # Previous 60000 ceiling was a bug -- it counted UTF-16
                # chars but compared against a byte budget, so SPN rows
                # with heavy TierSources still tripped PropertyValueTooLarge.
                if ($verdictJson.Length -gt 30000) {
                    $verdictJson = '{"truncated":true,"reason":"verdict JSON > 30K UTF-16 chars","SI_Tier":' + $verdict.SI_Tier + '}'
                }
                $_fpProperties = @{
                    si_tier          = $verdict.SI_Tier
                    si_verdict       = $verdictJson
                    last_seen_run_id = $RunContext.RunId
                    last_seen_at     = ([datetime]::UtcNow.ToString('o'))
                }
                if ($RunContext.ForceFullRun) {
                    Set-SIFingerprintRecord -Context $RunContext.StorageContext `
                                             -TableName $RunContext.FingerprintTable `
                                             -AssetId $r.AssetId `
                                             -Properties $_fpProperties `
                                             -ForceOverwrite
                } else {
                    Set-SIFingerprintRecord -Context $RunContext.StorageContext `
                                             -TableName $RunContext.FingerprintTable `
                                             -AssetId $r.AssetId `
                                             -Properties $_fpProperties
                }
            } catch {
                $msg = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
                Write-Warning ('Fingerprint cache write failed for {0} -- {1} (continuing)' -f $r.AssetId, $msg)
            }
        }
    }

    if ($classified.Count -gt 0) {
        Write-SIStageShard -Context $RunContext.StorageContext `
                            -ContainerName $RunContext.StagingContainer `
                            -RunId $RunContext.RunId `
                            -Stage 'Classify' `
                            -ShardIndex 0 `
                            -ReplicaIndex ([int]$RunContext.ShardIndex) `
                            -Records $classified.ToArray() | Out-Null
    }

    [pscustomobject]@{
        Stage         = 'Classify'
        Count         = $classified.Count
        AiCalls       = $aiCalls
        Reused        = $reused
        Errored       = $errored
        Capped        = $capped
        Deterministic = $deterministic
        AiSpent       = ('{0:n2}' -f $aiSpent)
        Summary       = ('{0} classified -- {1} AI, {2} deterministic (rule TargetTier), {3} reused, {4} errored, {5} budget-capped (~${6})' -f $classified.Count, $aiCalls, $deterministic, $reused, $errored, $capped, ('{0:n2}' -f $aiSpent))
    }
}
