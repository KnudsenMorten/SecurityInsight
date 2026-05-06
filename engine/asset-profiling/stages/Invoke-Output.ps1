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
        # Silence Az SDK + AzLogDcrIngestPS verbose stream for the ingest block.
        # The module reads $global:VerbosePreference internally, so $env / per-call
        # -Verbose:$false isn't enough. Restored in finally.
        $_savedVerbosePreference = $global:VerbosePreference
        $global:VerbosePreference = 'SilentlyContinue'

        # Auth: SPN primary (SI_SPN_* unified globals from Bootstrap-Auth.ps1),
        # SI_LogIngest_* legacy fallback. UAMI opt-in via $global:SI_PreferUami.
        $spnAppId    = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_LogIngest_AppId }
        $spnSecret   = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_LogIngest_Secret }
        $spnTenantId = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_LogIngest_TenantId }

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

        # ---- canonical AzLogDcrIngestPS pattern (mirrors RA engine line 5914+) ----
        # Step 1: build full DCE + DCR caches via the standard helpers. Everything
        # downstream (CheckCreateUpdate, Post-*) reads these caches to resolve
        # name -> id / immutableId. Always rebuild fresh per ingest.
        $global:AzDceDetails = Get-AzDceListAll @authParams -Verbose:$false 4>$null
        $global:AzDcrDetails = Get-AzDcrListAll @authParams -Verbose:$false 4>$null

        # Step 2: schema sample (full dataset for type inference) + CollectionTime stamp.
        $schemaSample = @($flat | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $RunContext.CollectionTime -Force -PassThru
        })

        # Step 3: provision/update DCR + LA table.
        $null = CheckCreateUpdate-TableDcr-Structure `
                    -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                    @authParams `
                    -Verbose:$false `
                    -DceName                                    $global:SI_DceName `
                    -DcrName                                    $dcrName `
                    -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                    -TableName                                  $tableName `
                    -Data                                       $schemaSample `
                    -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                    -AzLogDcrTableCreateFromAnyMachine          $true `
                    -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # Step 4: re-sync caches after DCR provisioning. Newly-created DCR's
        # immutableId needs to land in ARG before Post-* can resolve it.
        Start-Sleep -Seconds 15
        $global:AzDceDetails = Get-AzDceListAll @authParams -Verbose:$false 4>$null
        $global:AzDcrDetails = Get-AzDcrListAll @authParams -Verbose:$false 4>$null

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
