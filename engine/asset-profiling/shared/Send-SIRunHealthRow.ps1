#Requires -Version 5.1
<#
    Per-shard heartbeat to LA. Emits one row to SI_RunHealth_CL at the
    Start of every replica run, and a second row at End -- success or
    failure. The MISSING end-row is itself the signal that a replica
    OOM'd / got killed before it could finish (KQL: where Phase=='Start'
    | join kind=leftanti (... where Phase=='End') on RunId, ShardIndex).

    Best-effort: any failure to ship the heartbeat is swallowed (silent),
    because telemetry must NEVER kill the run it's measuring.

    Schema:
      RunId, Engine, ShardIndex, ShardCount, Phase=Start|End,
      AssetCount, PeakWorkingSetMB, DurationSec, ExitReason,
      ErrorMessage, Computer, CollectionTime
#>

function Send-SIRunHealthRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext,
        [Parameter(Mandatory)][ValidateSet('Start','End')][string]$Phase,
        [int]$AssetCount = -1,
        [string]$ExitReason = '',
        [string]$ErrorMessage = ''
    )

    # UNCONDITIONAL silence of the AzLogDcrIngestPS / Az SDK VERBOSE
    # storm for the duration of the heartbeat. Per-call -Verbose:$false isn't
    # enough -- the module reads $global:VerbosePreference internally. Heartbeat
    # call traces are never useful, so silence regardless of operator -Verbose.
    $_savedVerbosePreference = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'

    try {
        # Engine bootstrap may have failed before LA globals were set; bail silently
        # if we don't have what we need to ship.
        if (-not $global:SI_WorkspaceResourceId -or -not $global:SI_DceName -or -not $global:SI_DcrResourceGroup) {
            return
        }

        # Memory: PS 5.1 [System.Diagnostics.Process].WorkingSet64 is current process bytes.
        # Use PeakWorkingSet64 so a brief peak isn't lost between heartbeat reads.
        $peakMb = -1
        try {
            $proc = [System.Diagnostics.Process]::GetCurrentProcess()
            $peakMb = [int]([Math]::Round($proc.PeakWorkingSet64 / 1MB))
        } catch { }

        $duration = if ($RunContext.StartedAt) {
            [int]([datetime]::UtcNow - $RunContext.StartedAt).TotalSeconds
        } else { 0 }

        $hostName = $env:COMPUTERNAME
        if (-not $hostName) { $hostName = [System.Net.Dns]::GetHostName() }

        $row = [pscustomobject]@{
            CollectionTime    = $RunContext.CollectionTime
            RunId             = [string]$RunContext.RunId
            Engine            = [string]$RunContext.Engine
            ShardIndex        = [int]$RunContext.ShardIndex
            ShardCount        = [int]$RunContext.ShardCount
            Phase             = $Phase
            AssetCount        = $AssetCount
            PeakWorkingSetMB  = $peakMb
            DurationSec       = $duration
            ExitReason        = $ExitReason
            ErrorMessage      = $ErrorMessage
            Computer          = $hostName
        }

        # Auth resolution mirrors Invoke-Output.ps1: MI / SPN+Cert / SPN+Secret.
        # v2.2.237 -- cert path added (AzLogDcrIngestPS module accepts cert directly).
        $spnAppId      = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_LogIngest_AppId }
        $spnSecret     = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_LogIngest_Secret }
        $spnTenantId   = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_LogIngest_TenantId }
        $spnObjectId   = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }
        $spnCertThumb  = [string]$global:SI_SPN_CertThumbprint
        $spnCertStore  = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation } else { 'LocalMachine' }

        $useMi   = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
        $useCert = -not $useMi -and -not [string]::IsNullOrWhiteSpace($spnCertThumb)
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

        # Table is workspace-scoped (no cross-sub collision), so the name stays.
        # DCR is name-looked-up across all subs the SPN sees, so it MUST be
        # unique when one SPN spans internal + community tenants.
        $tableName = 'SI_RunHealth'
        $dcrName   = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RunHealth_DcrName)) { [string]$global:SI_RunHealth_DcrName } else { 'dcr-si-run-health' }

        # Provision/update DCR + table from the single-row schema sample. AzLogDcrIngestPS
        # is idempotent so the per-replica overhead after first-run is just a cache hit.
        # 4>$null on each call suppresses the AzLogDcrIngestPS / Az SDK VERBOSE storm
        # (POST/GET URLs + byte counts). Stream-redirect is needed because the Az SDK
        # writes via Write-Verbose internally and ignores the function-scoped preference
        # when called in nested module contexts.
        $null = CheckCreateUpdate-TableDcr-Structure `
            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
            @authParams `
            -DceName                                    $global:SI_DceName `
            -DcrName                                    $dcrName `
            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
            -TableName                                  $tableName `
            -Data                                       @($row) `
            -LogIngestServicePricipleObjectId           $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
            -AzLogDcrTableCreateFromAnyMachine          $true `
            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # Re-sync the DCE/DCR cache so a freshly-created DCR's immutableId is in
        # $global:AzDcrDetails before Post-* runs its name-only lookup. Without
        # this, AzLogDcrIngestPS falls back to the DCE's location field as a
        # bogus immutableId -> 404 'westeurope' from the Log Ingestion API.
        # Same pattern as Invoke-Output.ps1 (v2.2.65) and Invoke-RiskAnalysis.ps1.
        try {
            $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction SilentlyContinue
            if ($ensureFn) {
                & $ensureFn `
                    @authParams `
                    -SubscriptionId   $global:SI_AzSubscriptionId `
                    -DceResourceGroup $global:SI_DceResourceGroup `
                    -DcrResourceGroup $global:SI_DcrResourceGroup `
                    -Force 4>$null
            }
        } catch { }

        # DCR collision guard: when one SPN sees DCRs of the same name in
        # multiple subs/RGs, the module's name-only lookup picks one at random.
        # Filter $global:AzDcrDetails down to the (sub + RG + name) match
        # before Post-* runs its lookup.
        if ($global:AzDcrDetails -and $dcrName -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
            $_picked = @($global:AzDcrDetails | Where-Object {
                $_.name -eq $dcrName -and
                $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
            }) | Select-Object -First 1
            if ($_picked) { $global:AzDcrDetails = @($_picked) }
        }

        $data = @($row)
        $data = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $data 4>$null
        $data = Build-DataArrayToAlignWithSchema -Data $data 4>$null
        $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
            -DceName     $global:SI_DceName `
            -DcrName     $dcrName `
            -Data        $data `
            -TableName   $tableName `
            @authParams 4>$null
    }
    catch {
        # Telemetry must never kill the run. Surface ONLY in verbose.
        Write-Verbose ('Send-SIRunHealthRow: heartbeat failed -- {0}' -f $_.Exception.Message)
    }
    finally {
        # Restore caller's verbose preference even on bail-out / exception.
        if ($null -ne $_savedVerbosePreference) { $global:VerbosePreference = $_savedVerbosePreference }
    }
}
