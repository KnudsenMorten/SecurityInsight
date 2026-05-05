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

    # Required infra globals (always needed regardless of auth path).
    foreach ($g in @('SI_WorkspaceResourceId','SI_DceName','SI_DcrResourceGroup')) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $g -ValueOnly -Scope Global -ErrorAction SilentlyContinue))) {
            return ('SKIPPED -- $global:{0} not set (run Bootstrap-Auth.ps1)' -f $g)
        }
    }
    # Auth: SI_SPN_* primary, SI_LogIngest_* fallback,
    # UAMI when $global:SI_PreferUami + $global:SI_UAMI_ClientId set.
    $haveSpn  = $global:SI_SPN_AppId   -and $global:SI_SPN_Secret   -and $global:SI_SPN_TenantId   -and $global:SI_SPN_ObjectId
    $haveLi   = $global:SI_LogIngest_AppId -and $global:SI_LogIngest_Secret -and $global:SI_LogIngest_TenantId -and $global:SI_LogIngest_ObjectId
    $haveUami = $global:SI_PreferUami -and $global:SI_UAMI_ClientId
    if (-not ($haveSpn -or $haveLi -or $haveUami)) {
        return 'SKIPPED -- no auth configured. Set $global:SI_SPN_AppId/Secret/TenantId/ObjectId in custom.ps1, or run Bootstrap-Auth.ps1.'
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

    try {
        # UNCONDITIONAL silence of the AzLogDcrIngestPS / Az SDK VERBOSE
        # storm for the duration of the ingest block. The per-call -Verbose:$false
        # flag isn't enough -- the module reads $global:VerbosePreference internally.
        # Az/DCR call traces are never useful for diagnosing AP issues, so silence
        # regardless of operator -Verbose. Restored in the catch/finally below.
        $_savedVerbosePreference = $global:VerbosePreference
        $global:VerbosePreference = 'SilentlyContinue'

        # SPN-secret is the primary auth (single SPN for both
        # Graph reads + LA ingest; SI_SPN_* unified globals). UAMI path
        # remains opt-in via $global:SI_PreferUami for legacy single-tenant
        # deployments.
        # Backwards-compat fallback: SI_LogIngest_* 25 names.
        $spnAppId    = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_LogIngest_AppId }
        $spnSecret   = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_LogIngest_Secret }
        $spnTenantId = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_LogIngest_TenantId }
        $spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }

        $useMi = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)

        $authParams = if ($useMi) {
            @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
        } else {
            @{ AzAppId = $spnAppId; AzAppSecret = $spnSecret; TenantId = $spnTenantId }
        }

        $authNote = if ($useMi) { 'UAMI' } else { 'SPN' }
        Write-Host ''
        Write-SIInfo ('table : {0}_CL' -f $tableName)
        Write-SIInfo ('DCR   : {0}  (rg={1})' -f $dcrName, $global:SI_DcrResourceGroup)
        Write-SIInfo ('DCE   : {0}' -f $global:SI_DceName)
        Write-SIInfo ('auth  : {0}' -f $authNote)
        Write-SIInfo ('rows  : {0}' -f $flat.Count)

        # ---- 1. Provision/update DCR + LA table from a schema sample ----
        # flag set to $false. The $true setting
        # had AzLogDcrIngestPS try to grant Monitoring Metrics Publisher
        # at DCR-scope on every run -- that requires Owner / User Access
        # Administrator on the DCR RG, which the LogIngest SPN typically
        # doesn't have. Match v2.1 RA / IAC pattern: Bootstrap-Auth.ps1
        # grants the role ONCE at $global:SI_DcrResourceGroup scope using
        # the operator's elevated context.
        # Pre-stamp CollectionTime on the schema sample too so the DCR schema
        # declares the column up front -- otherwise the first ingest after
        # provisioning would race the schema-extension on first sight.
        # pass the FULL dataset to CheckCreateUpdate-TableDcr-Structure.
        # The 50-row sample was missing rare/sparse columns whose values are null
        # in early SP rows (UAC flags, MI-specific fields, etc.) -- AzLogDcrIngestPS
        # then skipped them from the DCR/table schema. Full dataset = every column
        # type correctly inferred, no silent drops downstream.
        $schemaSample = @($flat | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $RunContext.CollectionTime -Force -PassThru
        })

        # optional DCR-merge diagnostic. Gated OFF by default --
        # operator opts in via $global:SI_DcrMergeDiagnostic = $true in their
        # custom.ps1 when they want to know WHICH columns are causing AzLog-
        # DcrIngestPS to repeatedly re-merge the DCR. The helper compares the
        # in-memory schema sample against the DCR's existing streamDeclarations.
        # NEVER throws -- diagnostics must not break ingest.
        if ($global:SI_DcrMergeDiagnostic) {
            try {
                . (Join-Path $PSScriptRoot '..\storage\DcrMergeDiagnostic.ps1')
                Invoke-SIDcrMergeDiagnostic -DcrName $dcrName -DcrResourceGroup $global:SI_DcrResourceGroup -SchemaSample $schemaSample
            } catch {
                Write-Warning ('       dcr-merge-diag failed: {0} (diagnostic only, ingest continues)' -f $_.Exception.Message)
            }
        }

        Write-Host ''
        Write-SIStep 'CheckCreateUpdate-TableDcr-Structure (schema check + auto-provision)'
        # Verbose dropped on every AzLogDcrIngestPS call below.
        # also wrap each call in Invoke-SIQuietBlock to silence the
        # `VERBOSE: GET https://management.azure.com/...` / `VERBOSE: Schema
        # mismatch...` storm that the module emits internally regardless of the
        # per-call -Verbose flag. QuietBlock honors -Verbose at the engine entry
        # (Invoke-SIEngineRun.ps1:107-113) -- if the operator opted in, the
        # block is a no-op pass-through.
        # stream redirection 4>$null is the only bulletproof silencer.
        # AzLogDcrIngestPS sets its own $script:VerbosePreference internally, so
        # neither $global:VerbosePreference nor -Verbose:$false stops the storm.
        $null = CheckCreateUpdate-TableDcr-Structure `
            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
            @authParams `
            -DceName                                    $global:SI_DceName `
            -DcrName                                    $dcrName `
            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
            -TableName                                  $tableName `
            -Data                                       $schemaSample `
            -LogIngestServicePricipleObjectId           $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
            -AzLogDcrTableCreateFromAnyMachine          $true `
            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # ---- 2. ARM consistency sleep removed.
        # The 15s sleep was a defence for newly-created DCRs (Post-* needs
        # the immutableId discoverable in ARG before it can resolve DcrName).
        # In steady state (DCR already exists from a prior run) the sleep
        # adds latency for nothing. If a future first-run hits a 404 on the
        # very first ingest after DCR creation, re-add the sleep guarded by
        # 'is the DCR new?' state.

        # ---- 3. Refresh the DCR cache ($global:AzDcrDetails) ----
        # Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output resolves DcrName
        # -> immutableId via $global:AzDcrDetails. A newly created DCR isn't
        # in the cache yet; rebuild it to avoid the bogus-id 404 path
        # documented in v2.1's SecurityInsight_RiskAnalysis.ps1.
        if (-not $useMi) {
            Write-SIStep 'Get-AzDcrListAll (refresh DCE/DCR cache)'
            try {
                $global:AzDcrDetails = Get-AzDcrListAll `
                                            -AzAppId     $spnAppId `
                                            -AzAppSecret $spnSecret `
                                            -TenantId    $spnTenantId 4>$null
            } catch {
                Write-Warning ('Get-AzDcrListAll failed: {0} -- continuing; Post-* will fall back to ARG.' -f $_.Exception.Message)
            }
        }

        # ---- 4. Standard ingest pipeline (mirrors v2.1 RiskAnalysis 4-step) ----
        $DataVariable = @($flat)

        # 4a. Stamp the SHARED CollectionTime onto every row. Mirrors the v2.1
        #     pre-stamp pattern. We do NOT call Add-CollectionTimeToAllEntriesInArray
        #     because that function self-generates [datetime]::Now per call --
        #     each replica would write a DIFFERENT time, breaking cross-shard
        #     "latest dataset" queries.
        foreach ($entry in $DataVariable) {
            $entry | Add-Member -MemberType NoteProperty `
                                -Name  CollectionTime `
                                -Value $RunContext.CollectionTime `
                                -Force | Out-Null
        }

        # 4b. Host identity (Computer / ComputerFqdn / UserLoggedOn) -- in a
        #     container, these are the replica's hostname / N/A / runtime user.
        #     Useful for forensics: which replica wrote a given row.
        $hostName = $env:COMPUTERNAME
        if (-not $hostName) { $hostName = [System.Net.Dns]::GetHostName() }
        $hostFqdn = $hostName
        try { $hostFqdn = [System.Net.Dns]::GetHostEntry([string]::Empty).HostName } catch { }
        $hostUser = $env:USERNAME
        if (-not $hostUser) { $hostUser = $env:USER }
        if (-not $hostUser) { $hostUser = 'container' }

        Write-SIStep 'Add-ColumnDataToAllEntriesInArray (Computer/Fqdn/User)'
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                            -Column1Name Computer     -Column1Data $hostName `
                            -Column2Name ComputerFqdn -Column2Data $hostFqdn `
                            -Column3Name UserLoggedOn -Column3Data $hostUser 4>$null

        # 4c. Validate + normalise column names (DCR schema rules)
        Write-SIStep 'ValidateFix-AzLogAnalyticsTableSchemaColumnNames'
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable 4>$null

        # 4d. Align data structure with the declared DCR schema
        Write-SIStep 'Build-DataArrayToAlignWithSchema'
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable 4>$null

        # ---- 5. POST ----
        # Retry-with-cache-refresh: a freshly auto-created DCR may be missing
        # from $global:AzDcrDetails OR present with an unresolved/empty
        # immutableId; AzLogDcrIngestPS sometimes falls back to the location
        # string ('westeurope') as the URL path, producing
        #   404 NotFound: Data collection rule with immutable Id 'westeurope' not found.
        # Wait + re-call Get-AzDcrListAll between attempts so the DCR's
        # immutableId has time to populate in ARG.
        $global:EnableCompressionDefault = $true
        Write-SIStep ('Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output (compression={0}, rows={1})' -f $global:EnableCompressionDefault, $DataVariable.Count)
        $maxAttempts = 3
        $attempt = 0
        while ($true) {
            $attempt++
            try {
                $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                    -DceName     $global:SI_DceName `
                    -DcrName     $dcrName `
                    -Data        $DataVariable `
                    -TableName   $tableName `
                    @authParams 4>$null
                break  # success
            } catch {
                $msg  = $_.Exception.Message
                $body = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
                $combined = ($msg + ' ' + $body)
                $isTransient = $combined -match '404|NotFound|immutable Id|data collection rule'
                if (-not $isTransient -or $attempt -ge $maxAttempts) {
                    throw  # let outer catch surface the full error
                }
                $sleepSec = 30 * $attempt  # 30, 60s
                Write-SIWarn ('LA ingest attempt {0}/{1} failed (transient DCR-cache issue): {2}. Refreshing DCE/DCR cache and retrying in {3}s ...' -f $attempt, $maxAttempts, $msg, $sleepSec)
                Start-Sleep -Seconds $sleepSec
                if (-not $useMi) {
                    try {
                        $global:AzDcrDetails = Get-AzDcrListAll `
                                                    -AzAppId     $spnAppId `
                                                    -AzAppSecret $spnSecret `
                                                    -TenantId    $spnTenantId 4>$null
                    } catch {
                        Write-SIWarn ('Get-AzDcrListAll refresh failed during retry: {0}' -f $_.Exception.Message)
                    }
                }
            }
        }

        return ('OK -- {0} rows -> {1}_CL via {2}  ({3} auth, CollectionTime={4:o})' -f $DataVariable.Count, $tableName, $dcrName, $authNote, $RunContext.CollectionTime)
    }
    catch {
        # Surface the full failure so operators don't have to guess from a one-line label.
        $msg  = $_.Exception.Message
        $body = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
        Write-Host ''
        Write-SIErr '=== LA INGEST FAILED ==='
        Write-SIErr ('Exception : {0}' -f $msg)
        if ($body) { Write-SIErr ('Body      : {0}' -f $body) }
        Write-SIErr ('At        : {0}:{1}' -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber)
        Write-Host ''
        return ('FAILED: {0}' -f $msg)
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
