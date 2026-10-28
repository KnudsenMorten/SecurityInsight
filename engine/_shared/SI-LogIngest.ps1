#Requires -Version 5.1
<#
    SI -- publish rows to a Log Analytics custom table through the normal DCR path.

    Moved here from engine/asset-correlation/_shared/SI-CorrelationIngest.ps1 because a FREE stage uses
    it too: the azure profiler's Defender for Cloud recommendations stage publishes with
    Send-SIObjectMapRows. The correlation engine is part of SecurityInsight Pro and is not in the
    Community edition, so a free engine must never load a file from its folder. The function names are
    unchanged, so every caller and test keeps working.
#>

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }

function Initialize-SIIngestGlobals {
    <#
      Fill the three names the DCR/DCE pinning and the LogIngest role grant need, from what an install
      actually has (#174). The profiling orchestrator backfills them at its entry; the stages and engines that
      publish WITHOUT it (trend, Defender recommendations, the Pro engines) did not -- and the CLI setup wrote
      only the older names -- so pinning was skipped and a new DCR got no LogIngest principal.
        SI_AzSubscriptionId  <- the subscription in SI_WorkspaceResourceId, else the 2.2.x SubscriptionId
        SI_DceResourceGroup  <- the 2.2.x DceResourceGroup, else SI_DcrResourceGroup (same RG by default)
        SI_SPN_ObjectId      <- SpnObjectId, else SI_LogIngest_ObjectId
      Only EMPTY names are filled; a value the customer set always stands. Never throws.
    #>
    if (-not $global:SI_AzSubscriptionId) {
        if ("$($global:SI_WorkspaceResourceId)" -match '/subscriptions/([^/]+)/') { $global:SI_AzSubscriptionId = $Matches[1] }
        elseif ($global:SubscriptionId) { $global:SI_AzSubscriptionId = [string]$global:SubscriptionId }
    }
    if (-not $global:SI_DceResourceGroup) {
        # SI_DcrResourceGroup FIRST: the unprefixed DceResourceGroup is ALWAYS set by the solution-wide shared
        # defaults ('rg-dce-securityinsight'), so after loading it cannot tell a customer value from the default.
        # The DCE normally lives with the DCRs (the sample: "leave unset, same RG as workspace").
        if ($global:SI_DcrResourceGroup) { $global:SI_DceResourceGroup = [string]$global:SI_DcrResourceGroup }
        elseif ($global:DceResourceGroup) { $global:SI_DceResourceGroup = [string]$global:DceResourceGroup }
    }
    if (-not $global:SI_SPN_ObjectId) {
        if ($global:SpnObjectId) { $global:SI_SPN_ObjectId = [string]$global:SpnObjectId }
        elseif ($global:SI_LogIngest_ObjectId) { $global:SI_SPN_ObjectId = [string]$global:SI_LogIngest_ObjectId }
    }
}

function Get-SILogIngestObjectId {
    <#
      The object id that gets the ingest role on a new or updated data collection rule: SI_SPN_ObjectId (what setup
      writes), else the older SI_LogIngest_ObjectId -- the same order Send-SIObjectMapRows, trend, asset properties and
      the run-health row use. Three output stages passed SI_LogIngest_ObjectId alone, so an install with only
      SI_SPN_ObjectId got a rule nobody could post to (#257). Empty when neither is set.
    #>
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_ObjectId)) { return [string]$global:SI_SPN_ObjectId }
    return [string]$global:SI_LogIngest_ObjectId
}

function Select-SIIngestTarget {
    <#
        #199 -- make the endpoint AzLogDcrIngestPS will use the RIGHT one, before it touches the rule and again
        before the post. The module resolves the endpoint by NAME ONLY -- the first match in $global:AzDceDetails,
        or in a tenant-wide Resource Graph query when that cache is empty. Measured 2026-10-01: three endpoints
        named dce-securityinsight in two subscriptions; a rule created on the right one was re-bound to another
        one minute later by the engine's own post (#198); four rules on this tenant were bound to the other
        subscription's endpoint.
        The endpoint is chosen as follows:
          - a rule that EXISTS posts through the endpoint it is bound to, when that endpoint has the configured
            name. Ingestion accepts a post only through the rule's own endpoint, and moving a rule is not an
            option -- measured 2026-10-01, a re-bound rule was still refused (HTTP 403) more than 10 minutes later.
          - otherwise (a new rule) this install's endpoint -- subscription + resource group + name -- so the
            module creates the rule there and not on a same-named endpoint elsewhere.
          - ONE endpoint of that name anywhere is unambiguous and used (an endpoint outside the rules' resource
            group has always worked that way). Several and none here: refused, nothing is posted.
        The DCR cache is narrowed to this install's rule (or, before it exists, cleared of same-named rules
        elsewhere). An empty cache is built first. Without a subscription id there is nothing to pin to.
    #>
    param([hashtable]$AuthParams, [Parameter(Mandatory)][string]$DcrName)
    $sub = [string]$global:SI_AzSubscriptionId
    if (-not $sub -or -not $global:SI_DceName) { return }
    $dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { [string]$global:SI_DcrResourceGroup }
    $dcrRg = [string]$global:SI_DcrResourceGroup
    $rebuilt = $false
    $rebuild = {
        if ($rebuilt -or -not $AuthParams) { return }
        try { $global:AzDceDetails = Get-SIDceList @AuthParams -Verbose:$false 4>$null } catch { }
        try { $global:AzDcrDetails = Get-SIDcrList @AuthParams -Verbose:$false 4>$null } catch { }
        $rebuilt = $true   # dot-sourced: this IS the function's scope
    }
    $findHere = { @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dceRg/*" }) | Select-Object -First 1 }
    $findRule = { if ($dcrRg) { @($global:AzDcrDetails | Where-Object { $_ -and $_.name -eq $DcrName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dcrRg/*" }) | Select-Object -First 1 } }

    if (-not $global:AzDceDetails) { . $rebuild }
    $dce = . $findHere
    $dcr = . $findRule
    if (-not $dce -or ($dcrRg -and -not $dcr)) { . $rebuild; $dce = . $findHere; $dcr = . $findRule }
    if (-not $dce) {
        $same = @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName })
        if ($same.Count -ne 1) {
            throw ("Data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}'. {3} endpoint(s) of that name exist elsewhere, so nothing was posted -- set SI_DceResourceGroup to the one this install uses." -f $global:SI_DceName, $dceRg, $sub, $same.Count)
        }
        $dce = $same[0]
    }
    $bound = if ($dcr -and $dcr.properties) { [string]$dcr.properties.dataCollectionEndpointId } else { '' }
    if ($bound -and $bound -ne [string]$dce.id) {
        $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1
        if (-not $b) { . $rebuild; $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1 }
        if ($b -and $b.name -eq $global:SI_DceName) {
            Write-Verbose ("Data collection rule '{0}' is bound to {1}; posting through it." -f $DcrName, $bound)
            $dce = $b
        }
    }
    $global:AzDceDetails = @($dce)
    if ($dcr) { $global:AzDcrDetails = @($dcr) }
    elseif ($global:AzDcrDetails) { $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { $_ -and $_.name -ne $DcrName }) }
}
function Resolve-SICorrelationAuthParams {
    <#
        MI > SPN+cert > SPN+secret, resolved into the splat AzLogDcrIngestPS wants.
        Mirrors Send-SIRunHealthRow deliberately -- see this file's header for why it is not shared.
    #>
    $spnAppId     = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_LogIngest_AppId }
    $spnSecret    = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_LogIngest_Secret }
    $spnTenantId  = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_LogIngest_TenantId }
    $spnCertThumb = [string]$global:SI_SPN_CertThumbprint

    # Auto-detect which store actually holds the private key. A thumbprint in the wrong store reads as
    # "no cert" and falls through to the secret branch, which then fails on a tenant that has no secret.
    $spnCertStore = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
                    elseif ($spnCertThumb) {
                        $clean = $spnCertThumb -replace '\s',''
                        if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
                            $resolved = 'LocalMachine'
                            foreach ($s in 'LocalMachine','CurrentUser') {
                                $c = Get-ChildItem "Cert:\$s\My" -ErrorAction SilentlyContinue |
                                     Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
                                     Select-Object -First 1
                                if ($c) { $resolved = $s; break }
                            }
                            $resolved
                        } else {
                            # #209: no Cert: drive (a Linux container) -- read the X509Store instead.
                            if (-not (Get-Command Get-SICertStoreLocation -ErrorAction Ignore)) {
                                . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Find-SICertificate.ps1')
                            }
                            Get-SICertStoreLocation -Thumbprint $clean
                        }
                    } else { 'LocalMachine' }

    $useMi   = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
    $useCert = -not $useMi -and -not [string]::IsNullOrWhiteSpace($spnCertThumb)

    if ($useMi) {
        return @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
    }
    if ($useCert) {
        return @{
            AzAppId                       = $spnAppId
            AzAppCertificateThumbprint    = $spnCertThumb
            AzAppCertificateStoreLocation = $spnCertStore
            TenantId                      = $spnTenantId
        }
    }
    @{ AzAppId = $spnAppId; AzAppSecret = $spnSecret; TenantId = $spnTenantId }
}

function Send-SIObjectMapRows {
    <#
        Publish the map to SI_ObjectMap_CL through the normal DCR path.

        SQL COMPUTES AND HOLDS, LA PUBLISHES -- and there is no SQL yet, so today this IS the store.

        🔴 CORRECTED 2026-08-13. This header used to say the deterministic seed means "an object's id is
        recomputed identically every run", and that key-stability memory was "an OPTIMISATION over a
        correctness property the core already has". THAT WAS WRONG, and believing it is what would ship
        duplicate CIs. The property the core has is `same INPUT -> same id`. The property a connector
        needs is `same OBJECT -> same id`. They diverge whenever group membership changes:

          * Measured: adding one member carrying a lower-sorting exposure-graph id moved a group from
            `exposuregraphnodeid:aaa` to `exposuregraphnodeid:000`. The seed is the ordinally-lowest
            value of the highest-priority type PRESENT IN THE GROUP, so any arrival or departure moves
            it.
          * Departures are routine: the same day, EndpointEG returned 0 rows on a timeout and 51 assets
            left the snapshot.
          * Anchors churn independently -- MDE ids rotate, a rebuilt VM gets a new ARM path, a
            re-enrolled device gets a new AadDeviceId.

        So SQL key-stability is a CORRECTNESS PREREQUISITE before the connector may create CIs, not an
        optimisation. Publishing to LA without it is fine -- reading a map is harmless. CREATING a
        ServiceNow CI from an id that can move is not.

        Decided 2026-08-13 (V3-ARCHITECTURE 2.3a): a minted UUIDv5-from-birth-anchor id, stored, with an
        anchor ledger and a superseded table. Until that exists, ids emitted here are PROVISIONAL and a
        connector must not create CIs from them.

        NOT best-effort. Unlike the run-health heartbeat, this IS the output -- a swallowed failure
        would leave consumers reading a stale map while every run reported success.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [string]$TableName = 'SI_ObjectMap',
        [string]$DcrName
    )

    if (@($Rows).Count -eq 0) {
        Write-Warning 'correlation: nothing to publish -- 0 map rows. Not posting.'
        return 0
    }
    if ([string]::IsNullOrWhiteSpace($DcrName)) {
        $DcrName = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ObjectMap_DcrName)) {
            [string]$global:SI_ObjectMap_DcrName
        } else { 'dcr-si-objectmap' }
    }

    $savedVerbose = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'
    $lock = $null
    try {
        $authParams = Resolve-SICorrelationAuthParams
        Initialize-SIIngestGlobals
        $spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }

        # #475 -- A TABLE + RULE ALREADY MADE READY IN THIS PROCESS FOR THESE COLUMNS IS NOT CHECKED AGAIN. The steps below
        # (endpoint + rule selection twice, the table / rule update with its coverage check, the cache refresh) are several
        # Azure calls; they ran for every batch, and a run collected in parts posts its records in dozens of batches
        # (customer H 2026-10-09: 96,551 records). A batch whose columns were all made ready earlier in this process posts
        # through the same pinned endpoint and rule; a batch with a NEW column takes the full path again.
        $readyKey = ('{0}|{1}' -f $TableName, $DcrName).ToLowerInvariant()
        $batchCols = Get-SIObjectMapColumns -Rows @($Rows)
        # in the run cache (global, like the tokens: this file is dot-sourced at different depths, so $script: differs)
        $rcache = Get-SILogIngestRunCache
        if (-not ($rcache.ObjectMapReady -is [hashtable])) { $rcache.ObjectMapReady = @{} }
        $ready = $rcache.ObjectMapReady[$readyKey]
        if ($ready -and (Test-SIObjectMapColumnsReady -Ready $ready.Columns -Columns $batchCols)) {
            $global:AzDceDetails = @($ready.Dce); $global:AzDcrDetails = @($ready.Dcr)
            $data = @($Rows)
            $data = Repair-SILogColumnName -Data $data 4>$null
            $data = Format-SILogRowsToSchema -Data $data 4>$null
            $null = Send-SILogData -DceName $global:SI_DceName -DcrName $DcrName -Data $data -TableName $TableName @authParams 4>$null
            return @($data).Count
        }
        # several processes of one run publish at once (the records of a run collected in parts): the table / rule update
        # is done by one at a time (SI_INGEST_LOCK_FILE), so two never update the same rule over each other
        $lock = Enter-SIIngestLock

        # 🔴 THE WHOLE SET, NOT ONE ROW -- CORRECTED 2026-08-31. `-Data` was
        # `@($Rows | Select-Object -First 1)`. AzLogDcrIngestPS INFERS the table + DCR column set
        # from what it is handed, so one row defined the schema for the entire table: a row lacking
        # an optional field meant that column was never created, and every other row's value for it
        # was DROPPED AT INGEST, silently, for the life of the table.
        # 🪤 Nothing errors. The engine reports rows posted, the table exists, and the field is
        # simply absent -- indistinguishable from "no object had a value".
        # 📌 The four profilers already got this right (Invoke-Output.ps1's `$schemaSample` is the
        # FULL dataset, commented "full dataset for type inference"). Only the engines that publish
        # their own v3 tables carried the shortcut.
        #
        # 🔴 AND THIS COMMENT MUST STAY *ABOVE* THE CALL, NOT INSIDE IT (audit #102, 2026-09-02).
        # It was written between two backtick-continued argument lines, and **a comment TERMINATES a
        # backtick continuation**: everything after it was dropped, including the `-Data @($Rows)` this
        # very comment was added to introduce. Correlation then failed at publish on every run --
        # `missing mandatory parameters: Data AzDcrSetLogIngestApiAppPermissionsDcrLevel
        # AzLogDcrTableCreateFromReferenceMachine`, which is exactly the arguments that follow it here.
        # #199 -- pin BEFORE the create/update, not only before the post.
        Select-SIIngestTarget -AuthParams $authParams -DcrName $DcrName
        $null = Update-SILogTableSchema `
            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
            @authParams `
            -DceName                                    $global:SI_DceName `
            -DcrName                                    $DcrName `
            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
            -TableName                                  $TableName `
            -Data                                       @($Rows) `
            -LogIngestServicePricipleObjectId           $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
            -AzLogDcrTableCreateFromAnyMachine          $true `
            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # Re-sync the DCE/DCR cache so a freshly created DCR's immutableId is known before the
        # name-only lookup inside Post-*. Without it the module falls back to the DCE's location
        # field as a bogus immutableId and the ingestion API answers 404 'westeurope'.
        try {
            $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction Ignore
            if ($ensureFn) {
                & $ensureFn @authParams `
                    -SubscriptionId   $global:SI_AzSubscriptionId `
                    -DceResourceGroup $global:SI_DceResourceGroup `
                    -DcrResourceGroup $global:SI_DcrResourceGroup `
                    -Force 4>$null
            }
        } catch { }

        # 📌 SUPERSEDED 2026-10-01 (#199): Select-SIIngestTarget above now builds and pins the caches BEFORE the
        # create/update -- the module resolves the endpoint by name inside CheckCreateUpdate too, so pinning only
        # here was too late. The history below is kept for the BlockCopy lesson.
        # 🪤 DO NOT PRE-POPULATE THE CACHES HERE. Tried on 2026-08-30, mirroring the profiler's
        # `$global:AzDceDetails = Get-AzDceListAll @authParams`, on the reasoning that filtering a
        # cache that does not exist yet would be a silent no-op. It is not a no-op -- by this point
        # `CheckCreateUpdate-TableDcr-Structure` (called above) has already built both caches, which
        # is why the DCR pin below has always worked. The rebuild is redundant work, nothing more.
        # 📌 It was briefly believed to have CAUSED the "BlockCopy ... Object must be an array of
        # primitives" error that appeared once the 403 was gone. It did not, and the wrong version of
        # this note lived here for an hour. That error was a real defect in AzLogDcrIngestPS 1.7.1 --
        # `return $bytes` enumerates the array, so the caller binds object[] and [Buffer]::BlockCopy
        # rejects it -- which broke the UNCOMPRESSED path for every caller of the module. Fixed
        # upstream in 1.7.2 (SI finding #81). Removing these lines did not make it go away; only the
        # module fix did.

        # DCR name-collision guard. One SPN can see same-named DCRs in several subscriptions -- there
        # are already three DCEs called dce-securityinsight in this tenant -- and the module's name-only
        # lookup then picks one at random. Pin to (sub + RG + name) before posting.
        if ($global:AzDcrDetails -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
            $picked = @($global:AzDcrDetails | Where-Object {
                $_.name -eq $DcrName -and
                $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
            }) | Select-Object -First 1
            if ($picked) { $global:AzDcrDetails = @($picked) }
        }

        # 🔴 AND THE SAME GUARD FOR THE **DCE** -- its absence is why this engine could never publish.
        # The comment above names the hazard exactly ("three DCEs called dce-securityinsight") and then
        # pins only the DCR. `Post-*` resolves the DCE by NAME-ONLY against $global:AzDceDetails, so it
        # could pick an endpoint in a DIFFERENT subscription and post this workspace's DCR immutableId
        # to it -- which the Log Ingestion API answers with **HTTP 403**.
        # MEASURED 2026-08-30: three DCEs named `dce-securityinsight` exist across this tenant (one in
        # the workspace's own subscription, two in a sibling), and every correlation run ended
        # `[ERROR] Engine failed: Log Ingestion API request failed. HTTP Status: 403` AFTER doing all
        # of its real work -- 1296 rows read, 1291 objects correlated, ledger updated, 2228 map rows
        # built -- and losing the lot at the final POST. That is why the handoff records correlation as
        # "built + run on real data, never published": it was never a correlation defect at all.
        # 🔑 THE PROFILER ALREADY SOLVES THIS. `Apply-SIDcrScopeFilter` (asset-profiling/stages/
        # Invoke-Output.ps1) filters BOTH caches to the configured sub + RG, which is exactly why the
        # four profilers ingest happily while this engine 403s on the same credentials. Operator,
        # 2026-08-30: *"it must use same auth as the design is using to send data to la in the
        # profiler"* -- so this mirrors that filter rather than inventing a third variant.
        # 📌 Same auth params, same scope pin. The DCE RG falls back to the DCR RG, matching the
        # profiler's own default of 'rg-securityinsight' when SI_DceResourceGroup is unset.
        $_dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup }
                  else { [string]$global:SI_DcrResourceGroup }
        if ($global:AzDceDetails -and $global:SI_AzSubscriptionId -and $_dceRg) {
            $_pickedDce = @($global:AzDceDetails | Where-Object {
                $_.id -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$_dceRg/*"
            })
            if ($_pickedDce.Count -gt 0) { $global:AzDceDetails = @($_pickedDce) }
        }

        # #199 -- again before the post: the cache refresh above narrowed it to this install's endpoint, which is
        # not the rule's own when the rule is bound elsewhere.
        Select-SIIngestTarget -AuthParams $authParams -DcrName $DcrName
        # ready for these columns in this process (#475): the next batch with no new column posts straight away
        $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        if ($ready) { foreach ($c in $ready.Columns) { [void]$known.Add($c) } }
        foreach ($c in $batchCols) { [void]$known.Add($c) }
        $rcache.ObjectMapReady[$readyKey] = [pscustomobject]@{ Columns = $known; Dce = @($global:AzDceDetails); Dcr = @($global:AzDcrDetails) }
        Exit-SIIngestLock -Lock $lock; $lock = $null
        $data = @($Rows)
        $data = Repair-SILogColumnName -Data $data 4>$null
        $data = Format-SILogRowsToSchema -Data $data 4>$null
        $null = Send-SILogData `
            -DceName   $global:SI_DceName `
            -DcrName   $DcrName `
            -Data      $data `
            -TableName $TableName `
            @authParams 4>$null

        @($data).Count
    }
    finally {
        if ($lock) { Exit-SIIngestLock -Lock $lock }
        if ($null -ne $savedVerbose) { $global:VerbosePreference = $savedVerbose }
    }
}

function Get-SIObjectMapColumns {
    <# PURE. Every column name of a batch of rows (PSObject properties or dictionary keys), once. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { [void]$set.Add([string]$k) } }
        else { foreach ($p in $r.PSObject.Properties) { [void]$set.Add($p.Name) } }
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($c in $set) { $out.Add($c) }
    , $out.ToArray()
}

function Test-SIObjectMapColumnsReady {
    <# PURE. $true when every column of the batch is among the columns already made ready. #>
    param($Ready, [AllowEmptyCollection()][string[]]$Columns = @())
    if ($null -eq $Ready) { return $false }
    foreach ($c in $Columns) { if (-not $Ready.Contains($c)) { return $false } }
    $true
}

function Enter-SIIngestLock {
    <#
        The cross-process lock of the table / rule update (SI_INGEST_LOCK_FILE, set by a parent that runs several publishing
        processes at once). No variable = no lock ($null). Waits up to 20 minutes; then goes on without it, said once -- a
        lock that cannot be taken never stops a publish (the coverage check before every post still guards the rule).
    #>
    param([int]$WaitSeconds = 1200)
    $path = [string][Environment]::GetEnvironmentVariable('SI_INGEST_LOCK_FILE')
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    $until = [datetime]::UtcNow.AddSeconds($WaitSeconds)
    while ([datetime]::UtcNow -lt $until) {
        try { return [System.IO.File]::Open($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
        catch { Start-Sleep -Milliseconds 500 }
    }
    Write-Warning ('the table update lock ({0}) was not free for {1} seconds -- this process goes on without it' -f $path, $WaitSeconds)
    $null
}

function Exit-SIIngestLock {
    param($Lock)
    if ($Lock) { try { $Lock.Dispose() } catch { } }
}

# =====================================================================================================================
#  LOG INGESTION OVER PLAIN REST -- SecurityInsight needs no PowerShell module (no AzLogDcrIngestPS, no Az.*).
# =====================================================================================================================
<#
    Every SI call site calls the SI wrapper of the job; each wrapper does it over plain REST (its *Rest function):

        SI wrapper                  replaces (AzLogDcrIngestPS)                            SI REST function
        Get-SIDceList               Get-AzDceListAll                                       Get-SIDceListRest
        Get-SIDcrList               Get-AzDcrListAll                                       Get-SIDcrListRest
        Update-SILogTableSchema     CheckCreateUpdate-TableDcr-Structure                   Update-SILogTableSchemaRest
        Send-SILogData              Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output     Send-SILogDataRest
        Add-SICollectionTime        Add-CollectionTimeToAllEntriesInArray                  Add-SICollectionTimeRest
        Add-SIColumnData            Add-ColumnDataToAllEntriesInArray                      Add-SIColumnDataRest
        Repair-SILogColumnName      ValidateFix-AzLogAnalyticsTableSchemaColumnNames       Repair-SILogColumnNameRest
        Format-SILogRowsToSchema    Build-DataArrayToAlignWithSchema                       Format-SILogRowsToSchemaRest
        Get-SILogSchemaArray        Get-ObjectSchemaAsArray                                Get-SILogSchemaRest -As Array
        Get-SILogSchemaHash         Get-ObjectSchemaAsHash                                 Get-SILogSchemaRest -As Hash
        Test-SILogTableDcrStatus    Get-AzLogAnalyticsTableAzDataCollectionRuleStatus      Test-SILogTableDcrStatusRest
        Set-SILogTable              CreateUpdate-AzLogAnalyticsCustomLogTableDcr           Set-SILogTableRest
        Set-SILogDcr                CreateUpdate-AzDataCollectionRuleLogIngestCustomLog    Set-SILogDcrRest

    The wrappers keep the parameter names and types the call sites were written against, so no call site changed.

    PS 5.1 safe: no ?. / ??, no RSA.ImportFromPem. Works on pwsh 7 / Linux (no Cert: drive needed). Community + Pro:
    this file never references a Pro path.
#>

function Get-SILogIngestWrapperMap {
    <# The wrapper -> replaced function -> REST function table above, as data (the wiring tests read it). #>
    [ordered]@{
        'Get-SIDceList'            = @{ Replaces = 'Get-AzDceListAll';                                   Rest = 'Get-SIDceListRest' }
        'Get-SIDcrList'            = @{ Replaces = 'Get-AzDcrListAll';                                   Rest = 'Get-SIDcrListRest' }
        'Update-SILogTableSchema'  = @{ Replaces = 'CheckCreateUpdate-TableDcr-Structure';               Rest = 'Update-SILogTableSchemaRest' }
        'Send-SILogData'           = @{ Replaces = 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output'; Rest = 'Send-SILogDataRest' }
        'Add-SICollectionTime'     = @{ Replaces = 'Add-CollectionTimeToAllEntriesInArray';              Rest = 'Add-SICollectionTimeRest' }
        'Add-SIColumnData'         = @{ Replaces = 'Add-ColumnDataToAllEntriesInArray';                  Rest = 'Add-SIColumnDataRest' }
        'Repair-SILogColumnName'   = @{ Replaces = 'ValidateFix-AzLogAnalyticsTableSchemaColumnNames';   Rest = 'Repair-SILogColumnNameRest' }
        'Format-SILogRowsToSchema' = @{ Replaces = 'Build-DataArrayToAlignWithSchema';                   Rest = 'Format-SILogRowsToSchemaRest' }
        'Get-SILogSchemaArray'     = @{ Replaces = 'Get-ObjectSchemaAsArray';                            Rest = 'Get-SILogSchemaRest' }
        'Get-SILogSchemaHash'      = @{ Replaces = 'Get-ObjectSchemaAsHash';                             Rest = 'Get-SILogSchemaRest' }
        'Test-SILogTableDcrStatus' = @{ Replaces = 'Get-AzLogAnalyticsTableAzDataCollectionRuleStatus';  Rest = 'Test-SILogTableDcrStatusRest' }
        'Set-SILogTable'           = @{ Replaces = 'CreateUpdate-AzLogAnalyticsCustomLogTableDcr';       Rest = 'Set-SILogTableRest' }
        'Set-SILogDcr'             = @{ Replaces = 'CreateUpdate-AzDataCollectionRuleLogIngestCustomLog'; Rest = 'Set-SILogDcrRest' }
    }
}

# ---- the wrappers ------------------------------------------------------------------------------------------------
# Each declares the parameters the call sites pass (names + types) and forwards @PSBoundParameters: only what the call
# site bound, with the value it bound, including -Verbose:$false. NOT `@args`: measured 2026-10-03 on PS 5.1 and 7.6,
# `@args` splits `-Name:$value` into a bare switch plus a positional value.

function Get-SIDceList {
    [CmdletBinding()]
    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    return (Get-SIDceListRest @PSBoundParameters)
}

function Get-SIDcrList {
    [CmdletBinding()]
    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    return (Get-SIDcrListRest @PSBoundParameters)
}

function Get-SIDcrCreateRefusal {
    <# PURE. The line of a DCR / table create's captured output in which Azure (or the create itself) REFUSED it -- the
       Microsoft answer to surface, '' when there is none. A refused create never makes the rule appear, so it is not waited for.
       'skipping create' / 'already exists in' (a rule of that name in ANOTHER resource group) is a refusal too: the create did nothing. #>
    param([AllowNull()][AllowEmptyString()][string]$CreateOutput)
    if ([string]::IsNullOrWhiteSpace($CreateOutput)) { return '' }
    $re = '(?i)AuthorizationFailed|LinkedAuthorizationFailed|\(Forbidden\)|\b403\b|\(Unauthorized\)|\b401\b|InvalidPayload|InvalidTemplate|InvalidRequestContent|BadRequest|ResourceGroupNotFound|SubscriptionNotFound|WorkspaceNotFound|Step 3 threw|skipping create|already exists in'
    foreach ($l in ($CreateOutput -split '\r?\n')) { if ($l -match $re) { return $l.Trim() } }
    ''
}

function Wait-SIDcrReady {
    <#
        Fix request 2a40d950 (owner 2026-10-22: no fixed limits on SI's own work): after the table / rule create, WAIT UNTIL
        THE RULE IS READY and read it back -- never a fixed number of seconds that gives up while Azure is still making it
        (it was 240 s). A not-found / no-immutableId answer right after a create means "not yet" (REQUIREMENTS #619). It stops
        only on EVIDENCE that waiting cannot help, and says Microsoft's answer:
          * the create's own output carries a refusal (Get-SIDcrCreateRefusal) -- before any wait;
          * Azure says the rule's provisioning FAILED;
          * reading the rule is refused (401 / 403 -- the identity may not read it);
          * the create has RETURNED and two read-backs in a row, spaced by the progress pace (-MaxPauseSeconds), find NO rule
            at all: the create did nothing, so waiting cannot help (review S1: it polled until the job died). A rule that IS
            there but still provisioning is waited for without a deadline.
        Any other failed read is a transient answer: said, and read again. Progress is said on every read (elapsed, what was
        seen); the first read is at once (a rule that is already there costs no wait); the pause between reads grows from -FirstPauseSeconds to -MaxPauseSeconds (a pace, never a deadline).
        -Probe { } -> @{ ImmutableId; State } of the rule as SI's own lists see it now ($null = not there yet); it throws
        when the read fails. -Sleep { param($s) } / -Log { param($m) } are seams. Returns @{ Ready; ImmutableId; Waited; Why }.
    #>
    param([Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][scriptblock]$Probe, [AllowNull()][AllowEmptyString()][string]$CreateOutput,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log = { param($m) Write-Host $m },
          [int]$FirstPauseSeconds = 15, [int]$MaxPauseSeconds = 60, [AllowEmptyString()][string]$Location = '')
    $refused = Get-SIDcrCreateRefusal -CreateOutput $CreateOutput
    if ($refused) {
        # read back ONCE: a refusal of a later part (the table, a role) can come after the rule itself was made -- then it is used
        $r = $null; try { $r = & $Probe } catch { $r = $null }
        if ($null -ne $r -and [string]$r.ImmutableId -and [string]$r.ImmutableId -notlike '*location*' -and [string]$r.ImmutableId -ne $Location -and [string]$r.State -notmatch '(?i)^failed$') {
            & $Log ("DCR '{0}' is ready although the create reported: {1}" -f $DcrName, $refused)
            return @{ Ready = $true; ImmutableId = [string]$r.ImmutableId; Waited = 0; Why = '' }
        }
        return @{ Ready = $false; ImmutableId = ''; Waited = 0; Why = ("the create of DCR '{0}' was refused -- {1}" -f $DcrName, $refused) }
    }
    $waited = 0; $pause = [Math]::Max(1, $FirstPauseSeconds); $absent = 0
    while ($true) {
        $seen = 'not there yet'
        try {
            $r = & $Probe
            if ($null -ne $r) {
                $imm = [string]$r.ImmutableId; $st = [string]$r.State
                if ($st -match '(?i)^failed$') { return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("Azure reports DCR '{0}' with provisioning state Failed" -f $DcrName) } }
                if ($imm -and $imm -notlike '*location*' -and $imm -ne $Location) { & $Log ("DCR immutableId resolved after {0}s: {1}" -f $waited, $imm); return @{ Ready = $true; ImmutableId = $imm; Waited = $waited; Why = '' } }
                $seen = $(if ($st) { "there, provisioning state $st, no immutableId yet" } else { 'there, no immutableId yet' })
                $absent = 0
            } else {
                $absent++
                if ($absent -ge 2) {
                    $said = @(([string]$CreateOutput) -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $answer = $(if ($said.Count) { $said[-1] } else { 'nothing (the create returned no output)' })
                    return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("the rule was not created; Azure answered: {0} -- DCR '{1}' was not found on two read-backs {2}s apart after the create returned" -f $answer, $DcrName, [Math]::Max(1, $MaxPauseSeconds)) }
                }
            }
        } catch {
            $m = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim()
            if ($m -match '(?i)\b401\b|\b403\b|AuthorizationFailed|Forbidden|Unauthorized') { return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("reading DCR '{0}' was refused -- {1}" -f $DcrName, $m) } }
            $seen = "the read failed ($m) -- read again"
        }
        & $Log ("waiting for DCR '{0}' to be ready ({1}s so far; {2}) ..." -f $DcrName, $waited, $seen)
        # after a read that found no rule at all, the next read is a full progress pace later (the second read-back of the stop rule)
        $nap = $(if ($absent -ge 1) { [Math]::Max($pause, [Math]::Max(1, $MaxPauseSeconds)) } else { $pause })
        & $Sleep $nap
        $waited += $nap
        $pause = [Math]::Min([Math]::Max(1, $MaxPauseSeconds), $pause * 2)
    }
}

function Update-SILogTableSchema {
    [CmdletBinding()]
    param([Array]$Data, [string]$AzLogWorkspaceResourceId, [string]$TableName, [string]$DcrName, [string]$DcrResourceGroup, [string]$DceName,
          [AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel,
          [boolean]$AzLogDcrTableCreateFromAnyMachine, [string]$SchemaMode, [boolean]$EnableUploadViaLogHub,
          [AllowEmptyCollection()][array]$AzLogDcrTableCreateFromReferenceMachine,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    # A rule that already feeds ANOTHER table is never repurposed, and columns this call adds to an existing rule are
    # noted so the post can check that they are stored (Start-SILogDcrWatch / Complete-SILogDcrWatch, below).
    $watch = Start-SILogDcrWatch -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -Bound $PSBoundParameters
    # A NEW rule for a table that already exists is declared from the TABLE (its columns, with their types):
    # Set-SILogDcrRest does this itself.
    $out = Update-SILogTableSchemaRest @PSBoundParameters
    # The rule this install posts through must declare EVERY column of the data -- a column it does not declare is
    # dropped by Azure without an error. Missing ones are added from the table; any still missing refuses the post.
    # Before Complete-SILogDcrWatch, so columns added here are checked after the post like any other new column.
    $null = Assert-SILogDcrCoversData -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -DceName $DceName -Data $Data -Bound $PSBoundParameters
    Complete-SILogDcrWatch -Watch $watch
    $out
}

function Send-SILogData {
    [CmdletBinding()]
    param([array]$Data, [AllowEmptyString()][string]$DcrName, [AllowEmptyString()][string]$DceName, [string]$TableName,
          [string]$BatchAmount, [bool]$EnableUploadViaLogHub, [string]$LogHubPath,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation, [string]$TenantId,
          [Nullable[bool]]$EnableCompression, [Nullable[bool]]$UseManagedIdentity, [string]$ManagedIdentityClientId)
    $out = Send-SILogDataRest @PSBoundParameters
    # Columns added to this rule earlier in the run: check that Log Analytics really stores their values.
    Confirm-SILogNewColumns -DcrName $DcrName -TableName $TableName -Data $Data -Bound $PSBoundParameters
    $out
}

function Add-SICollectionTime {
    [CmdletBinding()]
    param([Array]$Data)
    return (Add-SICollectionTimeRest @PSBoundParameters)
}

function Add-SIColumnData {
    [CmdletBinding()]
    param([Array]$Data, [string]$Column1Name, [string]$Column1Data, [string]$Column2Name, [string]$Column2Data, [string]$Column3Name, [string]$Column3Data)
    return (Add-SIColumnDataRest @PSBoundParameters)
}

function Repair-SILogColumnName {
    [CmdletBinding()]
    param([Array]$Data)
    return (Repair-SILogColumnNameRest @PSBoundParameters)
}

function Format-SILogRowsToSchema {
    [CmdletBinding()]
    param([Array]$Data)
    return (Format-SILogRowsToSchemaRest @PSBoundParameters)
}

function Get-SILogSchemaArray {
    [CmdletBinding()]
    param([Array]$Data, [string[]]$ReturnType)
    return (Get-SILogSchemaRest -As Array @PSBoundParameters)
}

function Get-SILogSchemaHash {
    [CmdletBinding()]
    param([Array]$Data, [string[]]$ReturnType)
    return (Get-SILogSchemaRest -As Hash @PSBoundParameters)
}

function Test-SILogTableDcrStatus {
    [CmdletBinding()]
    param([string]$AzLogWorkspaceResourceId, [string]$TableName, [string]$DcrName, [array]$SchemaSourceObject,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    return (Test-SILogTableDcrStatusRest @PSBoundParameters)
}

function Set-SILogTable {
    [CmdletBinding()]
    param([string]$TableName, [array]$SchemaSourceObject, [string]$AzLogWorkspaceResourceId, [string]$SchemaMode,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    return (Set-SILogTableRest @PSBoundParameters)
}

function Set-SILogDcr {
    [CmdletBinding()]
    param([array]$SchemaSourceObject, [string]$AzLogWorkspaceResourceId, [string]$DceName, [string]$DcrResourceGroup, [string]$DcrName, [string]$TableName,
          [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel, [AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [string]$SchemaMode,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    $watch = Start-SILogDcrWatch -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -Bound $PSBoundParameters
    $out = Set-SILogDcrRest @PSBoundParameters
    Complete-SILogDcrWatch -Watch $watch
    $out
}

# =====================================================================================================================
#  A RULE IS NEVER REPURPOSED, AND NEW COLUMNS ARE CHECKED -- both engines (these run around the wrappers above)
#
#  1. A data collection rule that already feeds ANOTHER table is never changed to feed this one. Measured in the 2.2 ->
#     3.0 upgrade test: a setup-written 2.2 config named its public-IP rule 'dcr-si-publicip-profile' (feeding the 2.2
#     public-IP table); 3.0's own default uses the same name for its new table, and the module REWROTE the rule -- the
#     old flow was gone and the first post failed. Start-SILogDcrWatch refuses before anything is written.
#  2. Columns added to an EXISTING rule land empty for a while: Azure accepts the post, but drops the new columns'
#     values until the change has reached the ingestion pipeline (measured: the first 3.0 run after the upgrade wrote
#     SI_AssetName / SI_AssetId empty on 134 of 134 rows; empty again 4 and 18 minutes after a column was added; filled
#     hours later). The rule shows the new column at once, so the rule itself is no signal. Complete-SILogDcrWatch
#     notes what was added; Confirm-SILogNewColumns, after the post, asks Log Analytics whether this run's values were
#     STORED, and when they were not, the run says so and records it (Get-SILogIngestNotes -> the run's outcome is
#     success-partial, so nothing downstream reads the snapshot as whole).
#  Every read here is best effort: a rule that cannot be read is never a reason to stop a publish -- only a rule that IS
#  read and feeds another table is.
# =====================================================================================================================

function Get-SILogDcrStreams {
    <# PURE. The streams an existing rule writes: each data flow's outputStream, else the flow's streams; a rule with
       no data flows -> its declared streams. #>
    param([AllowNull()]$Dcr)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Dcr -or $null -eq $Dcr.properties) { return @() }
    foreach ($f in @($Dcr.properties.dataFlows)) {
        if ($null -eq $f) { continue }
        $names = if ($f.PSObject.Properties['outputStream'] -and $f.outputStream) { @([string]$f.outputStream) } else { @(@($f.streams) | ForEach-Object { [string]$_ }) }
        foreach ($n in $names) { if ($n -and -not $out.Contains($n)) { [void]$out.Add($n) } }
    }
    if ($out.Count -eq 0 -and $Dcr.properties.streamDeclarations) {
        foreach ($p in $Dcr.properties.streamDeclarations.PSObject.Properties) { [void]$out.Add([string]$p.Name) }
    }
    return $out.ToArray()
}

function Test-SILogDcrFeedsOtherTable {
    <# PURE. $true when the rule exists, writes at least one stream, and none of its streams is this table's. #>
    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName)
    $streams = @(Get-SILogDcrStreams -Dcr $Dcr)
    if ($streams.Count -eq 0) { return $false }
    $t = $TableName -replace '_CL$', ''
    $mine = @(('Custom-' + $t + '_CL'), (Get-SILogStreamName -TableName $t))
    foreach ($s in $streams) { if ($mine -contains $s) { return $false } }
    return $true
}

function Get-SILogDcrStreamColumns {
    <# PURE. The column names the rule declares for this table's stream (empty when it declares none). #>
    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName)
    if ($null -eq $Dcr -or $null -eq $Dcr.properties -or -not $Dcr.properties.streamDeclarations) { return @() }
    $t = $TableName -replace '_CL$', ''
    foreach ($s in @(('Custom-' + $t + '_CL'), (Get-SILogStreamName -TableName $t))) {
        $p = $Dcr.properties.streamDeclarations.PSObject.Properties[$s]
        if ($p) { return @(@($p.Value.columns) | Where-Object { $_ } | ForEach-Object { [string]$_.name }) }
    }
    return @()
}

function Get-SILogAddedColumns {
    <# PURE. Columns in -After that -Before did not have. #>
    param([AllowEmptyCollection()][string[]]$Before = @(), [AllowEmptyCollection()][string[]]$After = @())
    return @(@($After) | Where-Object { $_ -and (@($Before) -notcontains $_) })
}

function Get-SILogAlternateDcrName {
    <# PURE. A distinct, deterministic rule name for this install: '<name>-<resource group>', or '<name>-<8-character
       hash of the resource group>' when that would pass 60 characters -- the rule the profilers' collision rename
       already uses, so every run derives the same name. #>
    param([Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][string]$ResourceGroup)
    $rgClean = ($ResourceGroup -replace '[^a-zA-Z0-9-]', '-').ToLowerInvariant().Trim('-')
    $name = "$DcrName-$rgClean"
    if ($name.Length -gt 60) {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ResourceGroup.ToLowerInvariant())) } finally { $sha.Dispose() }
        $name = "$DcrName-" + (([BitConverter]::ToString($h) -replace '-', '').Substring(0, 8).ToLowerInvariant())
    }
    return $name
}

function Get-SILogDcrRepurposeMessage {
    <# The one sentence a refused rule produces. #>
    param([string]$DcrName, [string]$ResourceGroup, [string[]]$Streams, [string]$TableName)
    $feeds = (@($Streams) | ForEach-Object { $_ -replace '^Custom-', '' }) -join ', '
    ("The data collection rule '{0}' (resource group '{1}') already sends data to {2}. It is left unchanged -- changing it to send {3}_CL would stop the data it carries now. Give {3}_CL a rule of its own: set this table's data collection rule name in config\SecurityInsight.custom.ps1 to a new name (it is created automatically)." -f `
        $DcrName, $ResourceGroup, $feeds, ($TableName -replace '_CL$', ''))
}

function Get-SILogDcrState {
    <#
        The rule as Azure has it NOW (never from the run cache): Known = $false when it cannot be read (no subscription /
        resource group configured, or the read failed); else Dcr = the rule, or $null when it does not exist.
    #>
    param([string]$DcrName, [string]$DcrResourceGroup, [string]$WorkspaceResourceId, $Bound)
    $scope = Get-SILogIngestScope -WorkspaceResourceId $WorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
    if (-not $DcrName -or -not $scope.Subscription -or -not $scope.DcrRg) { return [pscustomobject]@{ Known = $false; Dcr = $null; ResourceGroup = $scope.DcrRg } }
    try {
        $auth = Resolve-SILogIngestAuth -Bound $Bound
        $d = Invoke-SILogArm -Path "/subscriptions/$($scope.Subscription)/resourceGroups/$($scope.DcrRg)/providers/Microsoft.Insights/dataCollectionRules/$DcrName" `
                 -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -AllowNotFound -NoCache
        return [pscustomobject]@{ Known = $true; Dcr = $d; ResourceGroup = $scope.DcrRg }
    } catch {
        Write-Verbose ("data collection rule '{0}' could not be read before the update: {1}" -f $DcrName, $_.Exception.Message)
        return [pscustomobject]@{ Known = $false; Dcr = $null; ResourceGroup = $scope.DcrRg }
    }
}

function Resolve-SILogDcrNameForTable {
    <#
        The rule name this table should post through: -DcrName, unless that rule exists and feeds ANOTHER table -- then
        Get-SILogAlternateDcrName (when that one is free or already this table's). When the alternate is taken too, the
        original name is returned and the wrapper refuses it with a clear message. Unknown (cannot be read) -> unchanged.
        Returns Name + Reason (empty when unchanged).
    #>
    param([Parameter(Mandatory)][string]$DcrName, [string]$DcrResourceGroup, [Parameter(Mandatory)][string]$TableName, [string]$WorkspaceResourceId, $Bound)
    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $Bound
    if (-not $st.Known -or -not $st.Dcr -or -not (Test-SILogDcrFeedsOtherTable -Dcr $st.Dcr -TableName $TableName)) {
        return [pscustomobject]@{ Name = $DcrName; Reason = '' }
    }
    $alt = Get-SILogAlternateDcrName -DcrName $DcrName -ResourceGroup ([string]$st.ResourceGroup)
    $st2 = Get-SILogDcrState -DcrName $alt -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $Bound
    if ($st2.Known -and $st2.Dcr -and (Test-SILogDcrFeedsOtherTable -Dcr $st2.Dcr -TableName $TableName)) {
        return [pscustomobject]@{ Name = $DcrName; Reason = '' }
    }
    $feeds = (@(Get-SILogDcrStreams -Dcr $st.Dcr) | ForEach-Object { $_ -replace '^Custom-', '' }) -join ', '
    [pscustomobject]@{
        Name   = $alt
        Reason = ("the data collection rule '{0}' already sends data to {1} and is left unchanged; {2}_CL uses its own rule '{3}'." -f $DcrName, $feeds, ($TableName -replace '_CL$', ''), $alt)
    }
}

function Start-SILogDcrWatch {
    <# Before a rule is created / updated: refuse a rule that feeds another table; remember the columns it declares. #>
    param([string]$DcrName, [string]$DcrResourceGroup, [string]$TableName, [string]$WorkspaceResourceId, $Bound)
    if (-not $DcrName -or -not $TableName) { return $null }
    $b = @{}; if ($Bound) { foreach ($k in @($Bound.Keys)) { if ($k -notin 'Data', 'SchemaSourceObject') { $b[$k] = $Bound[$k] } } }
    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
    if (-not $st.Known) { return $null }
    if ($st.Dcr -and (Test-SILogDcrFeedsOtherTable -Dcr $st.Dcr -TableName $TableName)) {
        throw (Get-SILogDcrRepurposeMessage -DcrName $DcrName -ResourceGroup ([string]$st.ResourceGroup) -Streams @(Get-SILogDcrStreams -Dcr $st.Dcr) -TableName $TableName)
    }
    [pscustomobject]@{
        DcrName = $DcrName; DcrResourceGroup = $DcrResourceGroup; TableName = ($TableName -replace '_CL$', ''); WorkspaceResourceId = $WorkspaceResourceId
        Bound = $b; Existed = [bool]$st.Dcr; Before = @(Get-SILogDcrStreamColumns -Dcr $st.Dcr -TableName $TableName)
    }
}

function Complete-SILogDcrWatch {
    <# After the update: columns an EXISTING rule gained are noted for Confirm-SILogNewColumns. Never throws. #>
    param($Watch)
    if (-not $Watch -or -not $Watch.Existed) { return }
    # The run-health record does not check itself: it is the record a check would report into.
    if ($Watch.TableName -ieq 'SI_RunHealth') { return }
    try {
        $st = Get-SILogDcrState -DcrName $Watch.DcrName -DcrResourceGroup $Watch.DcrResourceGroup -WorkspaceResourceId $Watch.WorkspaceResourceId -Bound $Watch.Bound
        if (-not $st.Known -or -not $st.Dcr) { return }
        $added = @(Get-SILogAddedColumns -Before $Watch.Before -After @(Get-SILogDcrStreamColumns -Dcr $st.Dcr -TableName $Watch.TableName))
        if ($added.Count -eq 0) { return }
        if (-not ($global:SI_LogIngestNewColumns -is [hashtable])) { $global:SI_LogIngestNewColumns = @{} }
        $key = $Watch.DcrName.ToLowerInvariant()
        $ws = if ($Watch.WorkspaceResourceId) { $Watch.WorkspaceResourceId } else { [string]$global:SI_WorkspaceResourceId }
        if ($global:SI_LogIngestNewColumns.ContainsKey($key)) {
            $prev = $global:SI_LogIngestNewColumns[$key]
            $added = @(@($prev.Columns) + @($added) | Select-Object -Unique)
        }
        $global:SI_LogIngestNewColumns[$key] = [pscustomobject]@{ Table = $Watch.TableName; Columns = $added; WorkspaceResourceId = $ws; AddedAt = [datetime]::UtcNow }
    } catch { Write-Verbose ("new-column check skipped: {0}" -f $_.Exception.Message) }
}

function Get-SILogColumnsWithValues {
    <# PURE. Of -Columns, those holding a non-empty value in at least one row (only those can be checked). #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][string[]]$Columns = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Columns)) {
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            $v = if ($r -is [System.Collections.IDictionary]) { $r[$c] } elseif ($r.PSObject.Properties[$c]) { $r.$c } else { $null }
            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { [void]$out.Add($c); break }
        }
    }
    return $out.ToArray()
}

function Get-SILogRowColumnNames {
    <# PURE. Every column name the rows carry (first-seen order, TimeGenerated left out: Azure sets it). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys | ForEach-Object { [string]$_ }) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($n in $names) { if ($n -and $n -ne 'TimeGenerated' -and $seen.Add($n)) { [void]$out.Add($n) } }
    }
    return $out.ToArray()
}

function Get-SILogRowsCollectionTime {
    <# PURE. The run's CollectionTime from the first row that carries one, as UTC; $null when no row does. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $v = if ($r -is [System.Collections.IDictionary]) { $r['CollectionTime'] } elseif ($r.PSObject.Properties['CollectionTime']) { $r.CollectionTime } else { $null }
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
        if ($v -is [datetime]) { if ($v.Kind -eq [DateTimeKind]::Local) { return $v.ToUniversalTime() }; return [datetime]::SpecifyKind($v, [DateTimeKind]::Utc) }
        $d = [datetime]::MinValue
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse([string]$v, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    }
    return $null
}

function Get-SILogColumnCheckKql {
    <# PURE. Rows of this run in the table, and how many carry a value in each new column (C0, C1, ... in -Columns order). #>
    param([Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string[]]$Columns, [AllowNull()]$CollectionTime, [AllowNull()]$PostedSince)
    $t = ($TableName -replace '_CL$', '') -replace '[^A-Za-z0-9_]', ''
    $agg = for ($i = 0; $i -lt $Columns.Count; $i++) {
        'C{0} = countif(isnotempty(tostring(column_ifexists("{1}", ""))))' -f $i, ($Columns[$i] -replace '[^A-Za-z0-9_]', '')
    }
    $filter = if ($CollectionTime) {
        $ct = ([datetime]$CollectionTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        "| where TimeGenerated > ago(2d)`n| where CollectionTime between (datetime($ct) - 2s .. datetime($ct) + 2s)"
    } else {
        $since = ([datetime]$PostedSince).ToUniversalTime().AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        "| where TimeGenerated >= datetime($since)"
    }
    "{0}_CL`n{1}`n| summarize Rows = count(), {2}" -f $t, $filter, ($agg -join ', ')
}

function Get-SILogColumnCheckVerdict {
    <#
        PURE. One result row of Get-SILogColumnCheckKql -> Verdict:
          stored      -- rows arrived and every new column holds values
          not-stored  -- rows arrived and a new column is empty on all of them (Missing names which)
          not-landed  -- no row of this run is queryable yet
    #>
    param([AllowNull()]$Result, [Parameter(Mandatory)][string[]]$Columns)
    $get = { param($n) if ($null -eq $Result) { 0 } elseif ($Result -is [System.Collections.IDictionary]) { [long]$Result[$n] } elseif ($Result.PSObject.Properties[$n]) { [long]$Result.$n } else { 0 } }
    $rows = & $get 'Rows'
    if ($rows -le 0) { return [pscustomobject]@{ Verdict = 'not-landed'; Rows = 0; Missing = @($Columns) } }
    $missing = @(for ($i = 0; $i -lt $Columns.Count; $i++) { if ((& $get ('C' + $i)) -le 0) { $Columns[$i] } })
    if ($missing.Count -gt 0) { return [pscustomobject]@{ Verdict = 'not-stored'; Rows = $rows; Missing = $missing } }
    [pscustomobject]@{ Verdict = 'stored'; Rows = $rows; Missing = @() }
}

function Invoke-SILogLaQuery {
    <# One Log Analytics query as the run's identity (the workspace's id read through ARM). Returns the first table's
       rows as objects. Throws on failure. #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$Query, $Bound)
    $auth = Resolve-SILogIngestAuth -Bound $Bound
    $ws = Invoke-SILogArm -Path $WorkspaceResourceId -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth
    $cid = if ($ws -and $ws.properties) { [string]$ws.properties.customerId } else { '' }
    if (-not $cid) { throw 'the Log Analytics workspace id could not be read' }
    $r = Invoke-SILogIngestRequest -Method POST -Uri ('https://api.loganalytics.io/v1/workspaces/{0}/query' -f $cid) -Body (@{ query = $Query } | ConvertTo-Json -Compress) `
             -Resource 'https://api.loganalytics.io/' -Auth $auth -MaxAttempts 3 -What 'Log Analytics query'
    $j = $r.Content | ConvertFrom-Json
    $tbl = @($j.tables)[0]
    if (-not $tbl) { return @() }
    $names = @(@($tbl.columns) | ForEach-Object { [string]$_.name })
    foreach ($row in @($tbl.rows)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = @($row)[$i] }
        [pscustomobject]$o
    }
}

function Wait-SILogColumnsStored {
    <#
        Asks Log Analytics, until this run's rows have arrived, whether the new columns hold their values. Polls at 30 s,
        then 60 s, then every 120 s; stops as soon as the answer is known (stored, or every row arrived with a column
        empty) or after -WindowSec (default 900: Azure's ingestion delay is normally seconds to a few minutes, so rows
        that are still missing after 15 minutes are reported, not waited for). A query that fails ends the check.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string[]]$Columns,
          [AllowNull()]$CollectionTime, [AllowNull()]$PostedSince, [int]$ExpectedRows = 1, $Bound, [int]$WindowSec = 0)
    if ($WindowSec -le 0) { $WindowSec = 900; $o = 0; if ([int]::TryParse([string]$global:SI_LogIngest_NewColumnCheckSec, [ref]$o) -and $o -gt 0) { $WindowSec = $o } }
    $kql = Get-SILogColumnCheckKql -TableName $TableName -Columns $Columns -CollectionTime $CollectionTime -PostedSince $PostedSince
    $waited = 0; $step = 30
    $last = [pscustomobject]@{ Verdict = 'not-landed'; Rows = 0; Missing = @($Columns) }
    while ($true) {
        Start-Sleep -Seconds $step
        $waited += $step
        try {
            $res = @(Invoke-SILogLaQuery -WorkspaceResourceId $WorkspaceResourceId -Query $kql -Bound $Bound)
            $last = Get-SILogColumnCheckVerdict -Result $(if ($res.Count) { $res[0] } else { $null }) -Columns $Columns
        } catch {
            $last = [pscustomobject]@{ Verdict = 'unverified'; Rows = 0; Missing = @($Columns); Detail = $_.Exception.Message }
            break
        }
        if ($last.Verdict -eq 'stored') { break }
        if ($last.Verdict -eq 'not-stored' -and $last.Rows -ge $ExpectedRows) { break }
        if ($waited -ge $WindowSec) { break }
        $step = [Math]::Min(120, $step * 2)
    }
    $last | Add-Member -NotePropertyName WaitedSec -NotePropertyValue $waited -Force
    return $last
}

function Add-SILogIngestNote {
    <# Something a publish could not deliver in full, for the run's outcome (Get-SIRunOutcome). #>
    # -Kind 'column-lag' (#414): only NEW, non-key columns were not stored yet (Azure's propagation delay) -- the rows and
    # their key columns are there, so a Risk Analysis run says it as a warning and is NOT partial for it.
    param([Parameter(Mandatory)][string]$Table, [string[]]$Columns = @(), [Parameter(Mandatory)][string]$Message, [string]$Kind = 'incomplete')
    if (-not ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]])) { $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object] }
    [void]$global:SI_LogIngestNotes.Add([pscustomobject]@{ Table = $Table; Columns = @($Columns); Message = $Message; Kind = $Kind })
}

function Get-SILogIngestNoteKind {
    <#
        PURE. 'column-lag' when a 'not-stored' verdict misses only non-key columns; else 'incomplete'.
        #414 / #294: the KEY columns are the ones a row cannot be placed or read without. A new key column that was not
        stored is a real loss (the data sync refuses such rows); any other new column not stored yet is propagation lag.
    #>
    param([string]$Verdict, [string[]]$Missing = @())
    $keys = @('CollectionTime', 'ConfigurationId', 'AssetId', 'AssetName', 'ReportName', 'SecuritySeverity', 'CriticalityTier', 'RiskScoreTotal', 'SolutionVersion')
    if ($Verdict -ne 'not-stored' -or -not @($Missing).Count) { return 'incomplete' }
    foreach ($m in @($Missing)) { if ($keys -contains ([string]$m).Trim()) { return 'incomplete' } }
    'column-lag'
}

function Get-SILogIngestNotes {
    if ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]]) { return $global:SI_LogIngestNotes.ToArray() }
    return @()
}

function Reset-SILogIngestNotes {
    <# At the start of a run: notes and pending column checks belong to ONE run. #>
    $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object]
    $global:SI_LogIngestNewColumns = @{}
}

function Confirm-SILogNewColumns {
    <#
        After a post through a rule that gained columns earlier in this run: were this run's values for them STORED?
        Not stored (or not confirmable) -> one warning that says what is missing and that the next run fills it, and a
        note that makes the run's outcome success-partial. Never throws: the rows themselves were posted.
    #>
    param([string]$DcrName, [string]$TableName, [AllowNull()][array]$Data, $Bound)
    if (-not $DcrName -or -not ($global:SI_LogIngestNewColumns -is [hashtable])) { return }
    $key = $DcrName.ToLowerInvariant()
    if (-not $global:SI_LogIngestNewColumns.ContainsKey($key)) { return }
    $chg = $global:SI_LogIngestNewColumns[$key]
    $global:SI_LogIngestNewColumns.Remove($key)
    $table = if ($TableName) { $TableName -replace '_CL$', '' } else { [string]$chg.Table }
    try {
        $rows = @($Data)
        $newCols = @(Get-SILogColumnsWithValues -Rows $rows -Columns @($chg.Columns))
        # ring 1, 2026-10-11 -- a rule CHANGED right before the post can drop values of columns it had already (added by an
        # earlier run or job inside Azure's propagation window), not only of the columns this run added. So once this run
        # changed the rule, EVERY column that carries a value in the posted rows is checked; the new ones first.
        $cols = @(Get-SILogColumnsWithValues -Rows $rows -Columns @(@($newCols) + @(Get-SILogRowColumnNames -Rows $rows) | Select-Object -Unique))
        if ($newCols.Count -eq 0 -or $cols.Count -eq 0) { return }
        # #475: the wait (half a minute or more) is spent ONCE per table per process -- a run that posts its records in
        # dozens of batches gained new columns batch after batch and waited every time (customer H 2026-10-09)
        $rcache = Get-SILogIngestRunCache
        if (-not ($rcache.ConfirmedTables -is [hashtable])) { $rcache.ConfirmedTables = @{} }
        $tk = $table.ToLowerInvariant()
        if ($rcache.ConfirmedTables.ContainsKey($tk)) {
            Write-Host (" [INFO] {0}_CL gained {1} more new column(s) ({2}); this run checked the table's new columns once already, so these are not waited for -- the next run stores them in any case." -f $table, $newCols.Count, ($newCols -join ', '))
            return
        }
        $rcache.ConfirmedTables[$tk] = $true
        $b = @{}; if ($Bound) { foreach ($k in @($Bound.Keys)) { if ($k -ne 'Data') { $b[$k] = $Bound[$k] } } }
        Write-Host (" [INFO] {0}_CL gained {1} new column(s) in this run ({2}). Azure takes a while to start storing a new column, so this run checks that the values of every column it posted ({3}) arrived ..." -f $table, $newCols.Count, ($newCols -join ', '), $cols.Count)
        $res = Wait-SILogColumnsStored -WorkspaceResourceId ([string]$chg.WorkspaceResourceId) -TableName $table -Columns $cols `
                   -CollectionTime (Get-SILogRowsCollectionTime -Rows $rows) -PostedSince ([datetime]::UtcNow.AddSeconds(-60)) -ExpectedRows $rows.Count -Bound $b
        if ($res.Verdict -eq 'stored') {
            Write-Host (" [OK]   {0}_CL: the new column(s) hold this run's values." -f $table)
            return
        }
        $msg = switch ($res.Verdict) {
            'not-stored' { "{0}_CL: the data collection rule was changed in this run and Azure was not yet storing every column when the rows arrived: this run's values for {1} are missing. The rows are there; the next run stores these columns." -f $table, (@($res.Missing) -join ', ') }
            'not-landed' { "{0}_CL gained new column(s) in this run ({1}) and this run's rows were not queryable within {2} minutes, so it is not known whether those columns were stored." -f $table, ($cols -join ', '), [int]($res.WaitedSec / 60) }
            default      { "{0}_CL gained new column(s) in this run ({1}) and it could not be checked whether this run's values were stored ({2})." -f $table, ($cols -join ', '), $res.Detail }
        }
        Write-Warning $msg
        # the run's outcome is judged on the columns this run ADDED (as before); a column the rule already had that read
        # back empty is said (the warning above) but only ever counts as propagation lag
        $missNew = @(@($res.Missing) | Where-Object { $newCols -contains $_ })
        $kind = 'column-lag'
        if ([string]$res.Verdict -ne 'not-stored') { $kind = 'incomplete' }
        elseif ($missNew.Count -gt 0) { $kind = Get-SILogIngestNoteKind -Verdict 'not-stored' -Missing $missNew }
        Add-SILogIngestNote -Table $table -Columns $cols -Message $msg -Kind $kind
    } catch {
        $msg = ("{0}_CL gained new column(s) in this run and it could not be checked whether this run's values were stored ({1})." -f $table, $_.Exception.Message)
        Write-Warning $msg
        Add-SILogIngestNote -Table $table -Message $msg
    }
}

# =====================================================================================================================
#  THE RULE MUST DECLARE EVERY COLUMN OF THE DATA -- both engines (#294)
#
#  Azure stores only the columns a data collection rule DECLARES: every other value of a posted row is dropped, and the
#  post still answers 204. Found live 2026-10-05 on ring 1: a Risk Analysis Detailed run posted 14,624 rows and only
#  AssetName, AssetId, the report name and 8 more columns arrived -- CollectionTime, ConfigurationId, SecuritySeverity,
#  CriticalityTier, RiskScoreTotal and SolutionVersion were EMPTY on every row, and the run logged SUCCESS. The chain:
#    1. the run used the default rule name (its configuration had not reached the job), a rule that did not exist yet;
#    2. AzLogDcrIngestPS creates a new rule in two steps -- first with the data's FIRST 11 columns, then with all of
#       them. The second step was refused (InvalidTransformOutput: a column the data reads as an object, the existing
#       table holds as text), so the rule was left with 11 columns;
#    3. on the next run the module looked the rule up BY NAME across the tenant, found another install's same-named
#       rule with every column, concluded nothing was missing, and the rows went through the 11-column rule.
#  Set-SILogDcrRest stops step 2 (a new rule for an existing table is declared from the TABLE, with its
#  types); Assert-SILogDcrCoversData stops step 3 for good: after every table/rule update it reads THE rule this install
#  posts through (in the configured scope, never by name across the tenant), adds from the table any column of the data
#  the rule does not declare, and REFUSES the post when a column of the data still is not declared.
# =====================================================================================================================

function Get-SILogBoundAuth {
    <# The sign-in arguments of a wrapper call (what Set-SILogDcrRest / Resolve-SILogIngestAuth take), nothing else. #>
    param($Bound)
    $b = @{}
    if ($null -eq $Bound) { return $b }
    foreach ($k in 'AzAppId', 'AzAppSecret', 'AzAppCertificateThumbprint', 'AzAppCertificateStoreLocation', 'UseManagedIdentity', 'ManagedIdentityClientId', 'TenantId') {
        if ($Bound.ContainsKey($k) -and $null -ne $Bound[$k] -and "$($Bound[$k])" -ne '') { $b[$k] = $Bound[$k] }
    }
    $b
}

function Get-SILogDataColumnNames {
    <#
        PURE. The columns a set of rows carries: the union over EVERY row (first-seen order, names compared without
        letter case), without TimeGenerated and Log Analytics' own standard columns, and only names a Log Analytics
        column can have (a name the ingest path drops before posting is not a column of the posted data).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows = @())
    $std = @('TimeGenerated', 'TenantId', 'Type', '_ResourceId', '_SubscriptionId', 'SourceSystem', 'MG', 'ManagementGroupName', '_BilledSize', '_IsBillable', '_ItemId', '_TimeReceived')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($n in $names) {
            $s = [string]$n
            if (-not $s -or $s -notmatch '^[A-Za-z][A-Za-z0-9_]*$' -or ($std -contains $s)) { continue }
            if ($s.Length -gt 45) { $s = $s.Substring(0, 45) }   # the column name repair cuts a longer name to 45
            if ($seen.Add($s)) { [void]$out.Add($s) }
        }
    }
    return $out.ToArray()
}

function Get-SILogNewRuleColumns {
    <#
        PURE. The stream declaration of a NEW rule: the table's columns with the table's types when the table exists (then
        each column of -SchemaSourceObject the table does not have, with its own type); else -SchemaSourceObject.
        TimeGenerated is never declared (the rule's transform sets it).
    #>
    param([AllowNull()]$Table, [AllowNull()][AllowEmptyCollection()][object[]]$SchemaSourceObject = @())
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $add = { param($n, $t) $s = [string]$n; if ($s -and $s -ne 'TimeGenerated' -and $seen.Add($s)) { [void]$out.Add([ordered]@{ name = $s; type = [string]$t }) } }
    if ($null -ne $Table -and $Table.properties -and $Table.properties.schema) {
        foreach ($c in @($Table.properties.schema.columns)) { if ($c) { & $add $c.name $c.type } }
    }
    foreach ($c in @($SchemaSourceObject)) { if ($c) { & $add $c.name $c.type } }
    return $out.ToArray()
}

function Get-SILogDcrCoverageGap {
    <#
        PURE. Which of -Columns the rule does NOT declare for this table's stream: Missing (all of them), InTable (those
        the table has -- the rule can be given them from the table) and NotInTable (those the table does not have).
    #>
    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName, [AllowEmptyCollection()][string[]]$Columns = @(), [AllowNull()]$Table)
    $declared = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @(Get-SILogDcrStreamColumns -Dcr $Dcr -TableName $TableName)) { [void]$declared.Add([string]$n) }
    $inTable = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $Table -and $Table.properties -and $Table.properties.schema) {
        foreach ($c in @($Table.properties.schema.columns)) { if ($c) { [void]$inTable.Add([string]$c.name) } }
    }
    $missing = @(@($Columns) | Where-Object { $_ -and -not $declared.Contains([string]$_) })
    [pscustomobject]@{
        Missing    = $missing
        InTable    = @($missing | Where-Object { $inTable.Contains([string]$_) })
        NotInTable = @($missing | Where-Object { -not $inTable.Contains([string]$_) })
    }
}

function Assert-SILogDcrCoversData {
    <#
        After a table/rule update: THE rule this install posts through (read in the configured scope) must declare every
        column of -Data. Columns it lacks that the table has are added from the table (Set-SILogDcrRest, additive); a
        column still not declared after that REFUSES the post -- throws System.IO.InvalidDataException, because Azure
        would store the rows without it and answer success. Columns the TABLE does not have either are said and noted
        (the run is partial), not refused: the table update is what failed there, and it says so itself.
        Nothing is checked when schema management is off for this machine (the same rule the module applies) or the
        rule cannot be read (said with -Verbose; Known = $false). Returns @{ Verdict; Added; Missing }.
    #>
    param([string]$DcrName, [string]$DcrResourceGroup, [string]$TableName, [string]$WorkspaceResourceId, [string]$DceName, [AllowNull()][array]$Data, $Bound)
    $res = [pscustomobject]@{ Verdict = 'skipped'; Added = @(); Missing = @() }
    if (-not $DcrName -or -not $TableName) { return $res }
    if ($Bound) {
        if ($Bound.ContainsKey('EnableUploadViaLogHub') -and [bool]$Bound['EnableUploadViaLogHub']) { return $res }
        if ($Bound.ContainsKey('AzLogDcrTableCreateFromAnyMachine') -and -not [bool]$Bound['AzLogDcrTableCreateFromAnyMachine']) {
            $ref = if ($Bound.ContainsKey('AzLogDcrTableCreateFromReferenceMachine')) { @($Bound['AzLogDcrTableCreateFromReferenceMachine']) } else { @() }
            if (-not ($env:COMPUTERNAME -and ($ref -contains $env:COMPUTERNAME))) { return $res }
        }
    }
    $cols = @(Get-SILogDataColumnNames -Rows @($Data))
    if (-not $cols.Count) { return $res }
    $t = $TableName -replace '_CL$', ''
    $b = Get-SILogBoundAuth -Bound $Bound
    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
    if (-not $st.Known) { $res.Verdict = 'unknown'; Write-Verbose ("data collection rule '{0}' could not be read -- its columns are not checked" -f $DcrName); return $res }
    if (-not $st.Dcr) {
        throw (New-Object System.IO.InvalidDataException(("The data collection rule '{0}' does not exist in resource group '{1}' after the table and rule update, so nothing is posted to {2}_CL." -f $DcrName, $st.ResourceGroup, $t)))
    }
    $auth = Resolve-SILogIngestAuth -Bound $b
    $readTable = { try { Get-SILogTableRest -WorkspaceResourceId $WorkspaceResourceId -TableName $t -Auth $auth -NoCache } catch { $null } }
    $table = & $readTable
    $gap = Get-SILogDcrCoverageGap -Dcr $st.Dcr -TableName $t -Columns $cols -Table $table
    if (-not @($gap.Missing).Count) { $res.Verdict = 'covered'; return $res }
    if (@($gap.InTable).Count) {
        Write-Host (" [WARN] the data collection rule '{0}' does not declare {1} column(s) of {2}_CL that this data carries ({3}) -- Azure would drop their values. Adding them to the rule from the table." -f `
            $DcrName, @($gap.InTable).Count, $t, ((@($gap.InTable) | Select-Object -First 12) -join ', ')) -ForegroundColor Yellow
        $null = Set-SILogDcrRest -SchemaSourceObject @(@($gap.InTable) | ForEach-Object { @{ name = [string]$_; type = 'string' } }) -AzLogWorkspaceResourceId $WorkspaceResourceId `
                    -DceName $DceName -DcrResourceGroup ([string]$st.ResourceGroup) -DcrName $DcrName -TableName $t @b
        $res.Added = @($gap.InTable)
        $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
        $gap = Get-SILogDcrCoverageGap -Dcr $st.Dcr -TableName $t -Columns $cols -Table $table
    }
    $res.Missing = @($gap.Missing)
    if (@($gap.InTable).Count) {
        throw (New-Object System.IO.InvalidDataException(("The data collection rule '{0}' does not declare {1} column(s) of {2}_CL that this data carries ({3}) and they could not be added to it. Posting through it would store the rows WITHOUT those values, so nothing is posted." -f `
            $DcrName, @($gap.InTable).Count, $t, ((@($gap.InTable) | Select-Object -First 20) -join ', '))))
    }
    if (@($gap.NotInTable).Count) {
        $msg = ("{0}_CL does not have {1} column(s) this data carries ({2}), so their values are not stored by this run." -f $t, @($gap.NotInTable).Count, ((@($gap.NotInTable) | Select-Object -First 20) -join ', '))
        Write-Warning $msg
        Add-SILogIngestNote -Table $t -Columns @($gap.NotInTable) -Message $msg
        $res.Verdict = 'partial'
        return $res
    }
    $res.Verdict = 'repaired'
    return $res
}

# =====================================================================================================================
#  REST: run cache, HTTP seam, tokens
# =====================================================================================================================

function Get-SILogIngestRunCache {
    <# Per-run (per-process) cache: tokens, ARM reads, DCR ids. Global because this file is dot-sourced at different
       depths by different engines, and `$script:` would then be a different scope per caller. #>
    if (-not ($global:SI_LogIngestRunCache -is [hashtable])) {
        $global:SI_LogIngestRunCache = @{ Tokens = @{}; Arm = @{}; DcrIds = @{} }
    }
    return $global:SI_LogIngestRunCache
}

function Reset-SILogIngestArmCache {
    <# After any create/update: the next read must see what was just written. #>
    $c = Get-SILogIngestRunCache
    $c.Arm = @{}
}

function Invoke-SILogIngestHttp {
    <#
        THE ONE HTTP SEAM. Every REST call in this file goes through here (tests Mock it). Never throws on an HTTP status:
        returns @{ StatusCode; Content; RetryAfter }. A network failure (no response at all) is StatusCode 0.
        HttpWebRequest, not Invoke-WebRequest: its error shape is the same on PS 5.1 and pwsh 7, so the body of a 4xx
        and the Retry-After of a 429 are read the same way on both.
    #>
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        $Body,
        [string]$ContentType,
        [int]$TimeoutSec = 300
    )
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 on an older .NET Framework may not offer TLS 1.2 by default; Azure requires it.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = $Method.ToUpperInvariant()
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.Accept = 'application/json'
    if ($Headers) {
        foreach ($k in $Headers.Keys) {
            if ($k -eq 'Content-Type') { $req.ContentType = [string]$Headers[$k] }
            elseif ($k -eq 'Accept')   { $req.Accept = [string]$Headers[$k] }
            else { $req.Headers[$k] = [string]$Headers[$k] }
        }
    }
    if ($ContentType) { $req.ContentType = $ContentType }
    if ($null -ne $Body) {
        # statements, never `= if (...) { $Body }`: an if-expression enumerates a byte array into object[]
        [byte[]]$bytes = $null
        if ($Body -is [byte[]]) { $bytes = $Body } else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body) }
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream()
        try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Close() }
    } elseif ($req.Method -in 'POST', 'PUT', 'PATCH') {
        $req.ContentLength = 0
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch {
        $we = $_.Exception
        while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
        if ($we -and $we.Response) {
            $resp = $we.Response
            # An HTTP status is an answer returned to the caller, not an error of this process: take the caught record
            # back out of $Error (setup shows every new entry -- each probe printed "(404) Not Found", 2026-10-06).
            if ($global:Error.Count -gt 0 -and [object]::ReferenceEquals($global:Error[0], $_)) { $global:Error.RemoveAt(0) }
        }
        else { return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; RetryAfter = $null } }
    }
    try {
        $text = ''
        $rs = $resp.GetResponseStream()
        if ($rs) { $sr = New-Object System.IO.StreamReader($rs); try { $text = $sr.ReadToEnd() } finally { $sr.Close() } }
        return [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Content = $text; RetryAfter = [string]$resp.Headers['Retry-After'] }
    } finally { $resp.Close() }
}

function Initialize-SILogIngestAuthHelpers {
    <# The managed-identity and certificate token helpers live in auth/. Loaded on first need, never at file load. #>
    # Only what is MISSING is loaded, and only that is published to the global scope (it was dot-sourced inside this
    # function, so it would vanish on return). Something already visible -- the engine's own copy, a test's mock -- is
    # never replaced.
    $authDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth'
    # The managed-identity helper is NOT loaded here: the run's entry point loads it (the launcher config on a VM / Arc
    # server, the container entry in a job) -- an engine never does (SIv3-ContainerIdentity). Get-SILogIngestToken
    # says so when it is missing.
    $want = @(
        @{ File = 'Find-SICertificate.ps1'; Fns = @('Get-SICertificateClientToken', 'Get-SICertificateFromStore', 'Test-SICertDriveAvailable') }
    )
    foreach ($w in $want) {
        $missing = @($w.Fns | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
        if ($missing.Count -eq 0) { continue }
        $p = Join-Path $authDir $w.File
        if (-not (Test-Path -LiteralPath $p)) { continue }
        . $p
        foreach ($n in $missing) {
            $f = Get-Command -Name $n -CommandType Function -ErrorAction Ignore
            if ($f) { Set-Item -Path ("function:global:{0}" -f $n) -Value $f.ScriptBlock }
        }
    }
}

function Resolve-SILogIngestAuth {
    <#
        The sign-in the call site handed over (the same splat AzLogDcrIngestPS takes), as one decision:
          ManagedIdentity -- UseManagedIdentity = $true
          Certificate     -- AzAppId + AzAppCertificateThumbprint + TenantId
          Secret          -- AzAppId + AzAppSecret + TenantId
          then the run's own decision: $global:SI_UseManagedIdentity (#222) -> ManagedIdentity, else the run's own
          sign-in (Resolve-SIAzRestAuth: what Connect-SIAzAccount recorded, else the configured identity).
        Same precedence as the module: managed identity, then certificate, then secret.
    #>
    param($Bound = @{})   # a hashtable or $PSBoundParameters
    if ($null -eq $Bound) { $Bound = @{} }
    $g = { param($k) if ($Bound.ContainsKey($k)) { $Bound[$k] } else { $null } }
    $mi = & $g 'UseManagedIdentity'
    if ($null -eq $mi -and $null -ne (Get-Variable -Scope Global -Name UseManagedIdentityDefault -ValueOnly -ErrorAction Ignore)) { $mi = (Get-Variable -Scope Global -Name UseManagedIdentityDefault -ValueOnly -ErrorAction Ignore) }
    $app = [string](& $g 'AzAppId'); $tid = [string](& $g 'TenantId')
    $thumb = [string](& $g 'AzAppCertificateThumbprint'); $sec = [string](& $g 'AzAppSecret')
    if ([bool]$mi) {
        $cid = [string](& $g 'ManagedIdentityClientId'); if (-not $cid) { $cid = [string](Get-Variable -Scope Global -Name SI_UAMI_ClientId -ValueOnly -ErrorAction Ignore) }
        return @{ Mode = 'ManagedIdentity'; ClientId = $cid }
    }
    if ($app -and $thumb -and $tid) { return @{ Mode = 'Certificate'; AppId = $app; TenantId = $tid; Thumbprint = ($thumb -replace '\s', '') } }
    if ($app -and $sec -and $tid)   { return @{ Mode = 'Secret'; AppId = $app; TenantId = $tid; Secret = $sec } }
    if ((Get-Variable -Scope Global -Name SI_UseManagedIdentity -ValueOnly -ErrorAction Ignore) -eq $true) { return @{ Mode = 'ManagedIdentity'; ClientId = [string](Get-Variable -Scope Global -Name SI_UAMI_ClientId -ValueOnly -ErrorAction Ignore) } }
    return @{ Mode = 'Run' }
}

function Get-SILogIngestToken {
    <#
        A bearer token for -Resource (https://monitor.azure.com/ for ingestion, https://management.azure.com/ for ARM),
        as the identity -Auth (Resolve-SILogIngestAuth) names:
          ManagedIdentity -- Get-SIManagedIdentityToken (container / Azure VM / Azure Arc endpoint; its own cache)
          Certificate     -- Get-SICertificateClientToken (JWT client assertion signed from the X509Store; no Cert: drive)
          Secret          -- client_credentials with the secret
          Support         -- the Invardia support session's Get-InvardiaSupportToken (#524; SI-AzRest.ps1 Get-SISupportToken)
          Run             -- the run's own sign-in (Resolve-SIAzRestAuth, over REST; #524: never an Azure session)
        Cached per identity + resource until 5 minutes before expiry.
    #>
    param([Parameter(Mandatory)][string]$Resource, [hashtable]$Auth, [switch]$ForceRefresh)
    # the supported token hook (see SI-AzRest.ps1): consulted first when set and no explicit sign-in was handed over
    if (-not $Auth) {
        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
        $Auth = Resolve-SILogIngestAuth
    }
    $res = $Resource.TrimEnd('/') + '/'
    # #524: the Invardia support session's tokens (Resolve-SIAzRestAuth's Mode 'Support') -- Invardia caches them; the
    # tenant of each is checked against the one SI works in
    if ($Auth.Mode -eq 'Support') { return (Get-SISupportToken -Resource $res -TenantId ([string]$Auth.TenantId) -ForceRefresh:$ForceRefresh) }
    $cache = (Get-SILogIngestRunCache).Tokens
    $who = switch ($Auth.Mode) { 'Certificate' { $Auth.AppId } 'Secret' { $Auth.AppId } 'ManagedIdentity' { $Auth.ClientId } default { '' } }
    $key = '{0}|{1}|{2}' -f $Auth.Mode, $who, $res
    if (-not $ForceRefresh -and $cache.ContainsKey($key) -and $cache[$key].ExpiresAt -gt [datetime]::UtcNow) { return $cache[$key].Token }

    $token = $null; $expiresAt = [datetime]::UtcNow.AddMinutes(45)
    # A TRANSIENT failure of the token endpoint (the managed-identity endpoint of a container, Entra) is waited out and asked
    # again, a bounded number of times -- Microsoft's errors (Get-SITransientKind: throttled / timeout / unavailable). Any
    # other answer (a refused sign-in, a missing certificate) fails at once, as before. The sweep of 2026-10-22: one
    # IDENTITY_ENDPOINT blip threw through every helper's retry and failed the run.
    if (-not (Get-Command -Name Get-SITransientKind -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot 'SI-ErrorClass.ps1') }
    $tokenAttempts = 4
    for ($tokenTry = 1; $tokenTry -le $tokenAttempts; $tokenTry++) {
    try {
    switch ($Auth.Mode) {
        'ManagedIdentity' {
            if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction Ignore)) {
                throw 'Sign-in as a managed identity was asked for, but the managed-identity sign-in helper is not loaded in this run (its entry point loads it: the launcher configuration or the container entry).'
            }
            $token = Get-SIManagedIdentityToken -Resource $res -ClientId ([string]$Auth.ClientId) -ForceRefresh:$ForceRefresh
        }
        'Certificate' {
            Initialize-SILogIngestAuthHelpers
            $token = Get-SICertificateClientToken -TenantId $Auth.TenantId -ClientId $Auth.AppId -Thumbprint $Auth.Thumbprint -Resource $res
        }
        'Secret' {
            $body = 'client_id={0}&scope={1}&client_secret={2}&grant_type=client_credentials' -f `
                [uri]::EscapeDataString($Auth.AppId), [uri]::EscapeDataString($res.TrimEnd('/') + '/.default'), [uri]::EscapeDataString($Auth.Secret)
            $r = Invoke-SILogIngestHttp -Method POST -Uri ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $Auth.TenantId) `
                     -Body $body -ContentType 'application/x-www-form-urlencoded'
            if ([int]$r.StatusCode -lt 200 -or [int]$r.StatusCode -ge 300) {
                throw ("Sign-in with the client secret failed for {0}. HTTP Status: {1} Response: {2}" -f $res, $r.StatusCode, $r.Content)
            }
            $j = $r.Content | ConvertFrom-Json
            $token = [string]$j.access_token
            $secs = 0
            if ([int]::TryParse([string]$j.expires_in, [ref]$secs) -and $secs -gt 600) { $expiresAt = [datetime]::UtcNow.AddSeconds($secs - 300) }
        }
        default {
            $t = Get-SIAzAccessToken -ResourceUrl $res -ErrorAction Stop
            $token = if ($t.Token -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $t.Token).Password } else { [string]$t.Token }
            try { if ($t.ExpiresOn) { $e = ([DateTimeOffset]$t.ExpiresOn).UtcDateTime.AddMinutes(-5); if ($e -lt $expiresAt) { $expiresAt = $e } } } catch { }
        }
    }
    break
    } catch {
        $kind = Get-SITransientKind -Message ([string]$_.Exception.Message)
        if ($kind -eq 'error' -or $tokenTry -ge $tokenAttempts) { throw }
        $wait = Get-SILogIngestRetryDelay -RetryAfter '' -Attempt $tokenTry
        Write-Verbose ("The token for {0} ({1} sign-in) was not issued ({2}: {3}) -- asked again in {4} s ({5}/{6})." -f $res, $Auth.Mode, $kind, $_.Exception.Message, $wait, $tokenTry, $tokenAttempts)
        Start-Sleep -Seconds $wait
    }
    }
    if ([string]::IsNullOrWhiteSpace($token)) { throw ("No access token for {0} ({1} sign-in)." -f $res, $Auth.Mode) }
    $cache[$key] = @{ Token = $token; ExpiresAt = $expiresAt }
    return $token
}

function Get-SILogIngestRetryDelay {
    <# Seconds to wait before retry -Attempt: the server's Retry-After (seconds or an HTTP date) when it sent one,
       else exponential (2, 4, 8 ... capped at 60). Never more than 10 minutes: a wait the server asks for had no upper
       limit, and a run that waits says nothing meanwhile (the retry after it either works or is the answer). #>
    param([string]$RetryAfter, [int]$Attempt)
    $s = 0
    if ($RetryAfter) {
        if ([int]::TryParse($RetryAfter.Trim(), [ref]$s)) { return [Math]::Min(600, [Math]::Max(1, $s)) }
        $d = [datetime]::MinValue
        if ([datetime]::TryParse($RetryAfter, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
            return [int][Math]::Min(600, [Math]::Max(1, [Math]::Ceiling(($d - [datetime]::UtcNow).TotalSeconds)))
        }
    }
    return [int][Math]::Min(60, [Math]::Pow(2, $Attempt))
}

function Invoke-SILogIngestRequest {
    <#
        One authenticated REST call with the retry rule (CLAUDE.md working rule 4):
          429 / 408 / 5xx / no response -> PLATFORM: wait (Retry-After when sent) and retry in-run
          401 once                      -> the token is refreshed and the call repeated once
          404 with -AllowNotFound       -> $null (a lookup that found nothing)
          any other 4xx                 -> FAIL FAST, the response body in the error: re-sending an invalid request
                                           burns time and fails identically
        Returns the response object (StatusCode / Content).
    #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers,
        [string]$Resource = 'https://management.azure.com/',
        [hashtable]$Auth,
        [switch]$AllowNotFound,
        [int]$MaxAttempts = 6,
        [string]$What = 'Azure Resource Manager request'
    )
    $refreshed = $false; $forceNext = $false
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $token = Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$forceNext
        $forceNext = $false
        $h = @{ 'Authorization' = ('Bearer ' + $token) }
        if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
        $r = Invoke-SILogIngestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType
        $code = [int]$r.StatusCode
        if ($code -ge 200 -and $code -lt 300) { return $r }
        if ($code -eq 404 -and $AllowNotFound) { return $null }
        if ($code -eq 401 -and -not $refreshed) { $refreshed = $true; $forceNext = $true; continue }
        $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
        if ($transient -and $attempt -lt $MaxAttempts) {
            $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
            Write-Verbose ("{0}: HTTP {1}, retrying in {2}s (attempt {3}/{4})" -f $What, $code, $wait, $attempt, $MaxAttempts)
            # SAID, not only in the verbose stream (which the publish path switches off): a call that got no answer can
            # have taken 5 minutes already, and six of them in a row were half an hour without one line in the run log
            if ($code -eq 0 -or $wait -ge 30) {
                Write-Host (" [INFO] {0}: {1} -- trying again in {2} second(s) (attempt {3} of {4})" -f $What, $(if ($code -eq 0) { 'no answer from Azure' } else { 'Azure answered HTTP {0}' -f $code }), $wait, $attempt, $MaxAttempts)
            }
            Start-Sleep -Seconds $wait
            continue
        }
        throw ("{0} failed. HTTP Status: {1} Response: {2}" -f $What, $code, $r.Content)
    }
    throw ("{0} failed after {1} attempts." -f $What, $MaxAttempts)
}

# =====================================================================================================================
#  REST: ARM reads/writes, scoped lookups
# =====================================================================================================================

function Get-SILogArmApiVersion {
    <# ARM api-versions this file uses (a function, not a variable: the file is dot-sourced at different depths). #>
    param([Parameter(Mandatory)][ValidateSet('Dce', 'Dcr', 'Table', 'Role')][string]$Kind)
    switch ($Kind) { 'Dce' { '2022-06-01' } 'Dcr' { '2022-06-01' } 'Table' { '2022-10-01' } 'Role' { '2022-04-01' } }
}

function Invoke-SILogArm {
    <# ARM call -> parsed JSON (or $null for a 404 with -AllowNotFound). GETs are cached per run; any write clears it. #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, $Body, [hashtable]$Auth, [switch]$AllowNotFound, [switch]$NoCache)
    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path + $(if ($Path -match '\?') { '&' } else { '?' }) + 'api-version=' + $ApiVersion }
    $cache = (Get-SILogIngestRunCache).Arm
    if ($Method -eq 'GET' -and -not $NoCache -and $cache.ContainsKey($uri)) { return $cache[$uri] }
    $json = if ($null -ne $Body -and -not ($Body -is [string])) { $Body | ConvertTo-Json -Depth 50 -Compress } else { $Body }
    $r = Invoke-SILogIngestRequest -Method $Method -Uri $uri -Body $json -Auth $Auth -AllowNotFound:$AllowNotFound -What ('Azure Resource Manager {0} {1}' -f $Method, ($uri -replace '\?.*$', ''))
    $obj = $null
    if ($r -and -not [string]::IsNullOrWhiteSpace([string]$r.Content)) { $obj = $r.Content | ConvertFrom-Json }
    if ($Method -eq 'GET') { if (-not $NoCache) { $cache[$uri] = $obj } } else { Reset-SILogIngestArmCache }
    return $obj
}

function Get-SILogArmList {
    <# Every item of an ARM list, following nextLink. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [hashtable]$Auth)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $page = Invoke-SILogArm -Path $Path -ApiVersion $ApiVersion -Auth $Auth
    while ($page) {
        foreach ($v in @($page.value)) { if ($null -ne $v) { [void]$items.Add($v) } }
        if ([string]::IsNullOrWhiteSpace([string]$page.nextLink)) { break }
        $page = Invoke-SILogArm -Path ([string]$page.nextLink) -ApiVersion $ApiVersion -Auth $Auth
    }
    foreach ($i in $items) {
        # the Resource Graph shape callers already read (subscriptionId / resourceGroup) -- ARM omits them
        if ([string]$i.id -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/') {
            if (-not $i.PSObject.Properties['subscriptionId']) { $i | Add-Member -NotePropertyName subscriptionId -NotePropertyValue $Matches[1] }
            if (-not $i.PSObject.Properties['resourceGroup'])  { $i | Add-Member -NotePropertyName resourceGroup -NotePropertyValue $Matches[2] }
        }
    }
    return $items.ToArray()   # enumerated, like the module's list; callers wrap in @()
}

function Get-SILogIngestScope {
    <#
        WHERE this install's endpoint and rules live: subscription + resource groups. Lookups are by NAME within this
        scope, never tenant-wide -- the same name exists in other environments (measured 2026-10-01: three endpoints
        named dce-securityinsight in two subscriptions).
          Subscription  -SubscriptionId, else -WorkspaceResourceId's, else SI_AzSubscriptionId, else SI_WorkspaceResourceId's,
                        else the 2.2.x SubscriptionId (a new rule is created in the workspace's subscription, as the
                        module did; SI_AzSubscriptionId is filled from the workspace by Initialize-SIIngestGlobals)
          DcrRg         -DcrResourceGroup, else SI_DcrResourceGroup
          DceRg         -DceResourceGroup, else SI_DceResourceGroup, else the DCR resource group
    #>
    param([string]$SubscriptionId, [string]$WorkspaceResourceId, [string]$DcrResourceGroup, [string]$DceResourceGroup)
    $sub = $SubscriptionId
    if (-not $sub -and $WorkspaceResourceId -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
    if (-not $sub) { $sub = [string]$global:SI_AzSubscriptionId }
    if (-not $sub -and "$($global:SI_WorkspaceResourceId)" -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
    if (-not $sub) { $sub = [string]$global:SubscriptionId }
    $dcrRg = if ($DcrResourceGroup) { $DcrResourceGroup } else { [string]$global:SI_DcrResourceGroup }
    $dceRg = if ($DceResourceGroup) { $DceResourceGroup } elseif ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { $dcrRg }
    [pscustomobject]@{ Subscription = $sub; DcrRg = $dcrRg; DceRg = $dceRg }
}

function Get-SILogScopedList {
    param([ValidateSet('Dce', 'Dcr')][string]$Kind, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth)
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        throw ("No subscription is configured for the data collection {0} lookup (SI_AzSubscriptionId / SI_WorkspaceResourceId). It is never read tenant-wide, because the same name exists in other environments." -f $(if ($Kind -eq 'Dce') { 'endpoint' } else { 'rule' }))
    }
    $type = if ($Kind -eq 'Dce') { 'dataCollectionEndpoints' } else { 'dataCollectionRules' }
    $path = if ($ResourceGroup) { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/$type" }
            else { "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/$type" }
    return (Get-SILogArmList -Path $path -ApiVersion (Get-SILogArmApiVersion $Kind) -Auth $Auth)
}

function Get-SIDceListRest {
    <# REST twin of Get-AzDceListAll -- but SCOPED: the configured subscription only (never tenant-wide). Same auth
       arguments as the module; -SubscriptionId / -ResourceGroup narrow further. #>
    [CmdletBinding()]
    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup)
    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId
    return (Get-SILogScopedList -Kind Dce -SubscriptionId $scope.Subscription -ResourceGroup $ResourceGroup -Auth $auth)
}

function Get-SIDcrListRest {
    <# REST twin of Get-AzDcrListAll -- scoped to the configured subscription, like Get-SIDceListRest. #>
    [CmdletBinding()]
    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup)
    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId
    return (Get-SILogScopedList -Kind Dcr -SubscriptionId $scope.Subscription -ResourceGroup $ResourceGroup -Auth $auth)
}

function Find-SILogResourceByName {
    <#
        A DCR or DCE by NAME in the configured scope:
          resource group known  -> exactly that resource (GET by its id); nothing else is considered
          resource group absent -> the subscription's list; one match is used, several refuse (the name is ambiguous)
        -AnyResourceGroupWhenMissing (endpoints only): not in the resource group, but exactly ONE of that name in the
        subscription -> that one (an endpoint outside the rules' resource group has always worked); several refuse.
        Returns $null when there is none.
    #>
    param([ValidateSet('Dce', 'Dcr')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth, [switch]$AnyResourceGroupWhenMissing)
    $label = if ($Kind -eq 'Dce') { 'data collection endpoint' } else { 'data collection rule' }
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { throw ("No subscription is configured to look up {0} '{1}' in (SI_AzSubscriptionId / SI_WorkspaceResourceId)." -f $label, $Name) }
    $type = if ($Kind -eq 'Dce') { 'dataCollectionEndpoints' } else { 'dataCollectionRules' }
    if ($ResourceGroup) {
        $hit = Invoke-SILogArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/$type/$Name" -ApiVersion (Get-SILogArmApiVersion $Kind) -Auth $Auth -AllowNotFound
        if ($hit -or -not $AnyResourceGroupWhenMissing) { return $hit }
    }
    $same = @(Get-SILogScopedList -Kind $Kind -SubscriptionId $SubscriptionId -Auth $Auth | Where-Object { $_ -and $_.name -eq $Name })
    if ($same.Count -eq 1) { return $same[0] }
    if ($same.Count -gt 1) {
        throw ("{0} '{1}' exists {2} times in subscription '{3}'{4}, so nothing was posted -- set the resource group this install uses ({5})." -f `
            $label, $Name, $same.Count, $SubscriptionId, $(if ($ResourceGroup) { " (none in resource group '$ResourceGroup')" } else { '' }),
            $(if ($Kind -eq 'Dce') { 'SI_DceResourceGroup' } else { 'SI_DcrResourceGroup' }))
    }
    return $null
}

# =====================================================================================================================
#  REST: data shape -- exact twins of the module's pre-processing (so 'Rest' declares and posts the same columns)
# =====================================================================================================================

function Add-SICollectionTimeRest {
    <#
        CollectionTime on every row, IDENTICAL across all shards and batches of one run:
          * a row that already carries a CollectionTime keeps it -- the engines stamp the run's own value upstream
            ($RunContext.CollectionTime / $global:RA_CollectionTime), and that is the value every shard shares;
          * a row without one gets this process's run value, minted once and reused by every later call.
        Same value format as the module ([datetime] from "yyyy-MM-ddTHH:mm:ssK", UTC).
        DIFFERS FROM THE MODULE ON PURPOSE: Add-CollectionTimeToAllEntriesInArray overwrites every row with the time
        of THAT call, so a "safety net" call after the upstream stamp replaced the shared run value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data)
    if (-not ($global:SI_LogIngestRunCollectionTime -is [datetime])) {
        [datetime]$ct = (Get-Date ([datetime]::Now.ToUniversalTime()) -Format 'yyyy-MM-ddTHH:mm:ssK')
        $global:SI_LogIngestRunCollectionTime = $ct
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in $Data) {
        $p = $e.PSObject.Properties['CollectionTime']
        if (-not $p -or $null -eq $p.Value -or [string]::IsNullOrWhiteSpace([string]$p.Value)) {
            $e | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $global:SI_LogIngestRunCollectionTime -Force | Out-Null
        }
        [void]$out.Add($e)
    }
    return [array]$out.ToArray()
}

function Add-SIColumnDataRest {
    <# Twin of Add-ColumnDataToAllEntriesInArray: up to three columns with one value each, on every row. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data, [Parameter(Mandatory)][string]$Column1Name, [Parameter(Mandatory)][AllowEmptyString()][string]$Column1Data,
          [string]$Column2Name, [string]$Column2Data, [string]$Column3Name, [string]$Column3Data)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in $Data) {
        if ($Column1Name) { $e | Add-Member -MemberType NoteProperty -Name $Column1Name -Value $Column1Data -Force }
        if ($Column2Name) { $e | Add-Member -MemberType NoteProperty -Name $Column2Name -Value $Column2Data -Force }
        if ($Column3Name) { $e | Add-Member -MemberType NoteProperty -Name $Column3Name -Value $Column3Data -Force }
        [void]$out.Add($e)
    }
    return [array]$out.ToArray()
}

function Repair-SILogColumnNameRest {
    <# Twin of ValidateFix-AzLogAnalyticsTableSchemaColumnNames (1.7.x): prohibited names get '_', ':' '-' '.' are
       removed, leading '_' trimmed, leading whitespace trimmed, >45 characters cut; renamed columns move to the end
       of the row with their own values. Rows are rebuilt only when a name needs fixing. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data)
    $prohibited = @('_ResourceId', 'id', '_ResourceId', '_SubscriptionId', 'TenantId', 'Type', 'UniqueId', 'Title', 'Date')
    $checked = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $rename = @{}
    foreach ($e in $Data) {
        foreach ($p in $e.PSObject.Properties) {
            $n = $p.Name
            if (-not $checked.Add($n)) { continue }
            if ($n -in $prohibited)     { $rename[$n] = $n + '_' }
            elseif ($n -like '*:*')     { $rename[$n] = $n.Replace(':', '') }
            elseif ($n -like '*-*')     { $rename[$n] = $n.Replace('-', '') }
            elseif ($n -like '*.*')     { $rename[$n] = $n.Replace('.', '') }
            elseif ($n -like '_*')      { $rename[$n] = $n.TrimStart('_') }
            elseif ($n -like '* *')     { $rename[$n] = $n.TrimStart() }
            elseif ($n.Length -gt 45)   { $rename[$n] = $n.Substring(0, 45) }
        }
    }
    if ($rename.Count -eq 0) { return [array]$Data }
    # #639: only a row that CARRIES a name to fix is rebuilt (a copy of that row); every other row is passed on as it is --
    # never a copy of the whole post. (Not in place: the caller may still read the row by its own names.)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $Data) {
        $needs = $false
        foreach ($p in $row.PSObject.Properties) { if ($rename.ContainsKey($p.Name)) { $needs = $true; break } }
        if (-not $needs) { [void]$out.Add($row); continue }
        $rebuilt = [ordered]@{}
        $moved = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in $row.PSObject.Properties) {
            if ($rename.ContainsKey($p.Name)) { [void]$moved.Add($p) } else { $rebuilt[$p.Name] = $p.Value }
        }
        foreach ($p in $moved) { $rebuilt[[string]$rename[$p.Name]] = $p.Value }
        [void]$out.Add([pscustomobject]$rebuilt)
    }
    return [array]$out.ToArray()
}

function Get-SILogSchemaRest {
    <#
        Twin of Get-ObjectSchemaAsArray (-As Array) and Get-ObjectSchemaAsHash (-As Hash): the column list of the
        WHOLE set, each column's type from the first row that carries it, read the way the module reads it -- the row
        is round-tripped through JSON and the type taken from Get-Member's definition:
            int* / real* -> int    long* -> long    guid* -> dynamic    string* -> string    datetime* -> datetime
            bool* -> boolean       object* / PSCustomObject -> dynamic
        DIFFERENCES FROM THE MODULE (2026-10-11, both made Log Analytics discard values):
          * a fractional number is `real` -- the module matched none of its patterns and INHERITED the type of the column
            read just before it (alphabetically), which is how LastSignInDays became datetime;
          * an empty (null) value does not decide the type: the first row with a value does, 'dynamic' if none has one.
        KNOWN TRAP KEPT:
          * 'int' vs 'long' follows the value's size in the first row that has the column.
        -ReturnType Table adds TimeGenerated (datetime) first and a description per column; DCR (the default for Array)
        has name + type only. -As Hash returns hashtables and, like the module, nothing without -ReturnType.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data, [ValidateSet('Array', 'Hash')][string]$As = 'Array', [ValidateSet('Table', 'DCR')][string[]]$ReturnType)
    $table = New-Object 'System.Collections.Generic.List[object]'
    $dcr   = New-Object 'System.Collections.Generic.List[object]'
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [void]$seen.Add('TimeGenerated')
    # the module's shapes: Array -> PSCustomObject, Hash -> plain hashtable
    $mk = { param($n, $t, [switch]$Desc)
        if ($As -eq 'Hash') { if ($Desc) { @{ name = $n; type = $t; description = '' } } else { @{ name = $n; type = $t } } }
        elseif ($Desc) { [pscustomobject]@{ name = $n; type = $t; description = '' } }
        else { [pscustomobject]@{ name = $n; type = $t } }
    }
    [void]$table.Add((& $mk 'TimeGenerated' 'datetime' -Desc))
    # columns seen so far only EMPTY (null): typed from the first row that has a value, 'dynamic' when none has
    $nullOnly = New-Object 'System.Collections.Generic.List[string]'
    $nullSet  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Data) {
        $hasNew = $false
        foreach ($p in $entry.PSObject.Properties) { if (-not $seen.Contains($p.Name) -and ($null -ne $p.Value -or -not $nullSet.Contains($p.Name))) { $hasNew = $true; break } }
        if (-not $hasNew) { continue }
        $cols = $entry | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Get-Member -MemberType NoteProperty
        foreach ($c in $cols) {
            if ($seen.Contains($c.Name)) { continue }
            $d = [string]$c.Definition
            # ring 1, 2026-10-11 -- THE TYPE IS DECIDED PER COLUMN, NEVER INHERITED. The module's mapping kept the previous
            # column's type for a definition it did not know (a double), and Get-Member lists the columns alphabetically,
            # so LastSignInDays (a double) was declared after LastSignInDateTime: datetime -- and every value of it was then
            # discarded by Log Analytics. A fractional number is `real`; an empty value waits for a row that has one.
            $objType = $null
            if ($d -match '^(?i)(System\.)?Object\s') {   # a null value round-trips as "object <name>=null"
                if ($nullSet.Add($c.Name)) { [void]$nullOnly.Add($c.Name) }
                continue
            }
            if     ($d -like 'int*')      { $objType = 'int' }
            elseif ($d -like 'real*')     { $objType = 'int' }
            elseif ($d -like 'long*')     { $objType = 'long' }
            elseif ($d -like 'double*' -or $d -like 'decimal*' -or $d -like 'float*' -or $d -like 'single*') { $objType = 'real' }
            elseif ($d -like 'guid*')     { $objType = 'dynamic' }
            elseif ($d -like 'string*')   { $objType = 'string' }
            elseif ($d -like 'datetime*') { $objType = 'datetime' }
            elseif ($d -like 'bool*')     { $objType = 'boolean' }
            elseif ($d -like 'object*')   { $objType = 'dynamic' }
            elseif ($d -like 'System.Management.Automation.PSCustomObject*') { $objType = 'dynamic' }
            else { $objType = 'dynamic' }
            [void]$seen.Add($c.Name)
            [void]$table.Add((& $mk $c.Name $objType -Desc))
            [void]$dcr.Add((& $mk $c.Name $objType))
        }
    }
    foreach ($n in $nullOnly) {
        if ($seen.Contains($n)) { continue }
        [void]$seen.Add($n)
        [void]$table.Add((& $mk $n 'dynamic' -Desc))
        [void]$dcr.Add((& $mk $n 'dynamic'))
    }
    if ($ReturnType -eq 'Table') { return $table.ToArray() }
    if ($ReturnType -eq 'DCR' -or $As -eq 'Array') { return $dcr.ToArray() }
}

function Format-SILogRowsToSchemaRest {
    <# Twin of Build-DataArrayToAlignWithSchema (1.7.x): every row gets every schema column (missing = $null), in
       schema order; a property the schema does not list (a literal TimeGenerated) is kept, after them.
       #639: IN PLACE, never a padded copy of the whole post. A PSCustomObject row is aligned on itself (its properties
       re-ordered, the missing ones added as $null) -- the same row, the same JSON as the copy made before; a row of another
       kind (a hashtable, a compact .NET row) is replaced in the array by its aligned copy, one row at a time. The post
       then serialises a batch at a time (Send-SILogDataRest), so nothing of the post is ever held twice. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data)
    $schema = Get-SILogSchemaRest -Data $Data -As Array
    if (@($Data).Count -eq 0) { return $Data }
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $schema) { [void]$names.Add([string]$c.name) }
    $nm = $names.ToArray()
    for ($i = 0; $i -lt $Data.Count; $i++) { $Data[$i] = Format-SILogRowToNamesInPlace -Row $Data[$i] -Names $nm }
    return $Data
}

function Format-SILogRowToNamesInPlace {
    <# ONE row aligned to -Names (missing = $null, in that order, the other properties after them) -- the row itself when
       it is a PSCustomObject (its properties re-ordered in place; nothing done when it already is aligned), else its
       aligned copy (Format-SILogRowsToNames). The JSON of the result equals the JSON of Format-SILogRowsToNames. #>
    param($Row, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
    if ($null -eq $Row) { return $Row }
    if ($Row.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
        return @(Format-SILogRowsToNames -Data @($Row) -Names $Names)[0]
    }
    $props = $Row.PSObject.Properties
    # already aligned: the names first, in order, every one present -- nothing to do
    $all = @($props)
    $aligned = ($all.Count -ge $Names.Count)
    if ($aligned) { for ($k = 0; $k -lt $Names.Count; $k++) { if ($all[$k].Name -cne $Names[$k] -or $all[$k] -isnot [System.Management.Automation.PSNoteProperty]) { $aligned = $false; break } } }
    if ($aligned) { return $Row }
    foreach ($p in $all) { if ($p -isnot [System.Management.Automation.PSNoteProperty]) { return @(Format-SILogRowsToNames -Data @($Row) -Names $Names)[0] } }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $Names) { [void]$set.Add($n) }
    # the values, then the properties rebuilt on the same object: the names in order, then the others as they were
    $vals = @{}
    $rest = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $all) {
        if ($set.Contains($p.Name)) { if (-not $vals.ContainsKey($p.Name)) { $vals[$p.Name] = $p } }
        else { $rest.Add($p) }
    }
    foreach ($p in $all) { $props.Remove($p.Name) }
    foreach ($n in $Names) {
        $v = $null; if ($vals.ContainsKey($n)) { $v = $vals[$n].Value }
        $props.Add([System.Management.Automation.PSNoteProperty]::new($n, $v))
    }
    foreach ($p in $rest) { $props.Add([System.Management.Automation.PSNoteProperty]::new($p.Name, $p.Value)) }
    return $Row
}

function Format-SILogRowsToNames {
    <# PURE. Format-SILogRowsToSchemaRest's second half: every row gets every column of -Names (missing = $null), in that
       order; a property not in -Names is kept, after them. Each row on its own -- the names are the whole set's schema, read
       before (Risk Analysis prepares the rows of one chunk on several cores with it, #744). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][Array]$Data, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $Data) {
        $props = $row.PSObject.Properties
        $a = [ordered]@{}
        foreach ($n in $Names) { $p = $props[$n]; if ($null -ne $p) { $a[$n] = $p.Value } else { $a[$n] = $null } }
        foreach ($p in $props) { if (-not $a.Contains($p.Name)) { $a[$p.Name] = $p.Value } }
        [void]$out.Add([pscustomobject]$a)
    }
    return $out.ToArray()
}

# =====================================================================================================================
#  REST: table + DCR create / update -- ADDITIVE only
# =====================================================================================================================

function Get-SILogStreamName {
    <# 'Custom-<table>_CL', cut to 52 characters (the stream name limit) -- the module's rule. #>
    param([Parameter(Mandatory)][string]$TableName)
    $s = 'Custom-' + $TableName + '_CL'
    if ($s.Length -gt 52) { $s = $s.Substring(0, 52) }
    return $s
}

function Get-SILogTableRest {
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [hashtable]$Auth, [switch]$NoCache)
    return (Invoke-SILogArm -Path ($WorkspaceResourceId + '/tables/' + $TableName + '_CL') -ApiVersion (Get-SILogArmApiVersion Table) -Auth $Auth -AllowNotFound -NoCache:$NoCache)
}

function Resolve-SILogDcrForTable {
    <# The rule this install posts through: the one recorded this run when it was created/updated, else by name in the
       configured scope (Find-SILogResourceByName). #>
    param([Parameter(Mandatory)][string]$DcrName, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth)
    $ids = (Get-SILogIngestRunCache).DcrIds
    $key = $DcrName.ToLowerInvariant()   # the rule created / updated / found THIS run, wherever the caller put it
    if ($ids.ContainsKey($key)) {
        $hit = Invoke-SILogArm -Path $ids[$key] -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $Auth -AllowNotFound
        if ($hit) { return $hit }
    }
    return (Find-SILogResourceByName -Kind Dcr -Name $DcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Auth $Auth)
}

function Test-SILogTableDcrStatusRest {
    <# Twin of Get-AzLogAnalyticsTableAzDataCollectionRuleStatus: $true when the table or the rule must be created or
       given columns. The rule is looked up in the configured scope, not by name across the tenant. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string]$DcrName,
          [Parameter(Mandatory)][array]$SchemaSourceObject, [string]$DcrResourceGroup,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
    $scope = Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
    $needs = $false
    $t = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
    $cols = @(); $std = @()
    if (-not $t) { $needs = $true }
    else {
        $cols = @($t.properties.schema.columns); $std = @($t.properties.schema.standardColumns)
        foreach ($e in $SchemaSourceObject) {
            if (-not ($cols | Where-Object { $_.name -eq $e.name }) -and -not ($std | Where-Object { $_.name -eq $e.name })) { $needs = $true }
        }
    }
    $dcr = Resolve-SILogDcrForTable -DcrName $DcrName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DcrRg -Auth $auth
    if (-not $dcr) { return $true }
    (Get-SILogIngestRunCache).DcrIds[$DcrName.ToLowerInvariant()] = [string]$dcr.id   # the post uses THIS rule
    $stream = Get-SILogStreamName -TableName $TableName
    $dcrCols = @()
    if ($dcr.properties.streamDeclarations -and $dcr.properties.streamDeclarations.PSObject.Properties[$stream]) { $dcrCols = @($dcr.properties.streamDeclarations.$stream.columns) }
    $tableCols = @($cols | Where-Object { $_.name -ne 'TimeGenerated' })
    if ($dcrCols.Count -lt $tableCols.Count) { return $true }
    foreach ($c in $tableCols) { if (-not ($dcrCols | Where-Object { $_.name -eq $c.name })) { $needs = $true } }
    return $needs
}

function Set-SILogTableRest {
    <#
        Twin of CreateUpdate-AzLogAnalyticsCustomLogTableDcr, ADDITIVE ONLY:
          no table   -> PUT it with the schema of the data (TimeGenerated + every column)
          table      -> the columns it does not have yet are added (PATCH: retention and plan are left as they are); an
                        existing column is never changed or removed, whatever type the data now suggests
        A refused write FAILS with Azure's answer. The module's fallback -- DELETE the table and re-create it -- is not
        copied: it discards data.
        -SchemaSourceObject: the Table-format schema (Get-SILogSchemaRest -ReturnType Table / Get-ObjectSchemaAsHash).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][array]$SchemaSourceObject, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId,
          [string]$SchemaMode = 'Merge',
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
    $table = $TableName + '_CL'
    if ($table.Length -gt 45) { Write-Error ("ERROR - Reduce length of tablename, as it has a maximum of 45 characters (current length: {0})" -f $table.Length) }
    $path = $AzLogWorkspaceResourceId + '/tables/' + $table
    $cur = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
    $toCol = { param($c) [ordered]@{ name = [string]$c.name; type = [string]$c.type; description = '' } }
    if (-not $cur) {
        $columns = @($SchemaSourceObject | ForEach-Object { & $toCol $_ })
        $null = Invoke-SILogArm -Method PUT -Path $path -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth -Body @{ properties = @{ schema = @{ name = $table; columns = $columns } } }
        Write-Output ("table {0}: created with {1} column(s)" -f $table, $columns.Count)
        return
    }
    $std = @($cur.properties.schema.standardColumns | ForEach-Object { [string]$_.name })
    $merged = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in @($cur.properties.schema.columns)) { if ($c -and ([string]$c.name -notin $std)) { [void]$merged.Add((& $toCol $c)) } }
    $added = New-Object 'System.Collections.Generic.List[string]'
    foreach ($s in $SchemaSourceObject) {
        if ([string]$s.name -in $std) { continue }
        if (@($merged | Where-Object { $_.name -eq [string]$s.name }).Count) { continue }
        [void]$merged.Add((& $toCol $s)); [void]$added.Add([string]$s.name)
    }
    if ($added.Count -eq 0) { Write-Output ("table {0}: has every column" -f $table); return }
    $null = Invoke-SILogArm -Method PATCH -Path $path -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth -Body @{ properties = @{ schema = @{ name = $table; columns = @($merged.ToArray()) } } }
    Write-Output ("table {0}: {1} column(s) added ({2})" -f $table, $added.Count, ($added -join ', '))
}

function Resolve-SILogEndpointForNewRule {
    <# This install's endpoint, for a NEW rule: by name in SI_DceResourceGroup (else the rules' group) of the
       subscription; one of that name elsewhere in the subscription is unambiguous; several refuse. #>
    param([Parameter(Mandatory)][string]$DceName, $Scope, [hashtable]$Auth)
    $dce = Find-SILogResourceByName -Kind Dce -Name $DceName -SubscriptionId $Scope.Subscription -ResourceGroup $Scope.DceRg -Auth $Auth -AnyResourceGroupWhenMissing
    if (-not $dce) {
        throw ("Data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}', so nothing was created or posted." -f $DceName, $Scope.DceRg, $Scope.Subscription)
    }
    return $dce
}

function Set-SILogDcrRest {
    <#
        Twin of CreateUpdate-AzDataCollectionRuleLogIngestCustomLog, ADDITIVE ONLY:
          no rule -> PUT one in the configured subscription + resource group, bound to THIS install's endpoint, with the
                     stream declaration (the data's columns), the workspace destination and the default transform
          rule    -> the columns the table has and the stream does not are ADDED to the stream declaration; everything
                     else the rule carries (its endpoint, transform, destinations, other streams) is kept as it is. The
                     module rebuilt the whole rule instead, re-binding it to the endpoint it found by name (#198).
        A new rule waits 15 seconds for Azure to settle, as the module did.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$SchemaSourceObject, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [string]$DceName,
          [Parameter(Mandatory)][string]$DcrResourceGroup, [Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][string]$TableName,
          [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel = $false, [AllowEmptyString()][string]$LogIngestServicePricipleObjectId, [string]$SchemaMode = 'Merge',
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
    $scope = Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
    $stream = Get-SILogStreamName -TableName $TableName
    $wsName = ($AzLogWorkspaceResourceId -split '/')[-1]
    $dcrPath = "/subscriptions/$($scope.Subscription)/resourceGroups/$DcrResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DcrName"
    $ids = (Get-SILogIngestRunCache).DcrIds
    $key = $DcrName.ToLowerInvariant()
    $dcr = Invoke-SILogArm -Path $dcrPath -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -AllowNotFound -NoCache
    $toCol = { param($c) [ordered]@{ name = [string]$c.name; type = [string]$c.type } }

    if (-not $dcr) {
        $dce = Resolve-SILogEndpointForNewRule -DceName $DceName -Scope $scope -Auth $auth
        # #294: a new rule for a table that EXISTS declares the table's columns with the TABLE's types (then any column of
        # the data the table does not have yet). Declared from the data instead, a type that differs from the table's
        # (a column the data reads as an object, the table holds as text) makes Azure refuse the rule.
        $tNew = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
        $cols = @(Get-SILogNewRuleColumns -Table $tNew -SchemaSourceObject $SchemaSourceObject)
        $body = [ordered]@{
            location   = [string]$dce.location
            properties = [ordered]@{
                dataCollectionEndpointId = [string]$dce.id
                streamDeclarations       = @{ $stream = @{ columns = $cols } }
                destinations             = @{ logAnalytics = @(@{ workspaceResourceId = $AzLogWorkspaceResourceId; name = $wsName }) }
                dataFlows                = @(@{ streams = @($stream); destinations = @($wsName); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream })
            }
        }
        $created = Invoke-SILogArm -Method PUT -Path $dcrPath -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -Body $body
        $ids[$key] = $dcrPath
        Write-Output ("data collection rule {0}: created on endpoint {1} with {2} column(s)" -f $DcrName, $dce.id, $cols.Count)
        if ($AzDcrSetLogIngestApiAppPermissionsDcrLevel -and $LogIngestServicePricipleObjectId) {
            $roleDef = "/subscriptions/$($scope.Subscription)/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb"
            try {
                $null = Invoke-SILogArm -Method PUT -Path ($dcrPath + '/providers/Microsoft.Authorization/roleAssignments/' + [guid]::NewGuid().ToString()) -ApiVersion (Get-SILogArmApiVersion Role) -Auth $auth `
                    -Body @{ properties = @{ roleDefinitionId = $roleDef; principalId = $LogIngestServicePricipleObjectId; principalType = 'ServicePrincipal' } }
            } catch { Write-Warning ("Monitoring Metrics Publisher on {0} was not granted: {1}" -f $DcrName, $_.Exception.Message) }
        }
        Start-Sleep -Seconds 15
        return
    }

    $ids[$key] = [string]$dcr.id
    # the columns the stream must carry: the table's (after Set-SILogTableRest), plus Computer/RawData when they are
    # standard columns of a table migrated from v1 -- the module's rule
    $t = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
    $want = New-Object 'System.Collections.Generic.List[object]'
    if ($t) {
        foreach ($c in @($t.properties.schema.columns)) { if ($c -and $c.name -ne 'TimeGenerated') { [void]$want.Add((& $toCol $c)) } }
        foreach ($n in 'Computer', 'RawData') {
            if (-not @($want | Where-Object { $_.name -eq $n }).Count -and @($t.properties.schema.standardColumns | Where-Object { $_.name -eq $n }).Count) { [void]$want.Add([ordered]@{ name = $n; type = 'string' }) }
        }
    } else {
        foreach ($c in $SchemaSourceObject) { if ($c.name -ne 'TimeGenerated') { [void]$want.Add((& $toCol $c)) } }
    }
    $p = $dcr.properties
    if (-not $p.streamDeclarations) { $p | Add-Member -NotePropertyName streamDeclarations -NotePropertyValue ([pscustomobject]@{}) -Force }
    $hasStream = [bool]$p.streamDeclarations.PSObject.Properties[$stream]
    $have = if ($hasStream) { @($p.streamDeclarations.$stream.columns) } else { @() }
    $merged = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $have) { if ($c) { [void]$merged.Add((& $toCol $c)) } }
    $added = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $want) { if (-not @($merged | Where-Object { $_.name -eq $c.name }).Count) { [void]$merged.Add($c); [void]$added.Add([string]$c.name) } }
    if ($added.Count -eq 0) { Write-Output ("data collection rule {0}: has every column" -f $DcrName); return }

    if ($hasStream) { $p.streamDeclarations.$stream.columns = @($merged.ToArray()) }
    else {
        $p.streamDeclarations | Add-Member -NotePropertyName $stream -NotePropertyValue ([pscustomobject]@{ columns = @($merged.ToArray()) })
        $flows = @($p.dataFlows)
        if (-not @($flows | Where-Object { @($_.streams) -contains $stream }).Count) {
            $dest = @($p.destinations.logAnalytics)[0]
            $p.dataFlows = @($flows) + @([pscustomobject]@{ streams = @($stream); destinations = @([string]$dest.name); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream })
        }
    }
    $props = [ordered]@{}
    foreach ($q in $p.PSObject.Properties) { if ($q.Name -notin 'immutableId', 'provisioningState', 'endpoints', 'metadata') { $props[$q.Name] = $q.Value } }
    $body = [ordered]@{ location = [string]$dcr.location; properties = $props }
    if ($dcr.PSObject.Properties['kind'] -and $dcr.kind) { $body['kind'] = $dcr.kind }
    if ($dcr.PSObject.Properties['tags'] -and $dcr.tags) { $body['tags'] = $dcr.tags }
    $null = Invoke-SILogArm -Method PUT -Path ([string]$dcr.id) -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -Body $body
    Write-Output ("data collection rule {0}: {1} column(s) added to {2} ({3})" -f $DcrName, $added.Count, $stream, ($added -join ', '))
}

function Update-SILogTableSchemaRest {
    <#
        Twin of CheckCreateUpdate-TableDcr-Structure: the table and the rule carry every column of the data (the WHOLE
        set decides the schema). Same arguments as the module. Additive only (Set-SILogTableRest / Set-SILogDcrRest).
        A table name with '_' first, '-', ':', '.' or a space is refused as the module refuses it (nothing is done).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Array]$Data, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [Parameter(Mandatory)][string]$TableName,
          [Parameter(Mandatory)][string]$DcrName, [string]$DcrResourceGroup, [string]$DceName,
          [AllowEmptyString()][AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel = $false,
          [boolean]$AzLogDcrTableCreateFromAnyMachine, [string]$SchemaMode = 'Merge', [boolean]$EnableUploadViaLogHub = $false,
          [AllowEmptyCollection()][array]$AzLogDcrTableCreateFromReferenceMachine,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
    if ($TableName -like '_*' -or $TableName -like '*-*' -or $TableName -like '*:*' -or $TableName -like '*.*' -or $TableName -like '* *') {
        Write-Verbose ("ISSUE - Table name [ {0} ] is not a valid Log Analytics table name" -f $TableName)
        return
    }
    if ($EnableUploadViaLogHub) { return }
    if (-not ($AzLogDcrTableCreateFromAnyMachine -or ($env:COMPUTERNAME -and $env:COMPUTERNAME -in @($AzLogDcrTableCreateFromReferenceMachine)))) { return }
    if (-not $DcrResourceGroup) { $DcrResourceGroup = (Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId).DcrRg }
    $authArgs = @{}
    foreach ($k in 'AzAppId', 'AzAppSecret', 'AzAppCertificateThumbprint', 'AzAppCertificateStoreLocation', 'UseManagedIdentity', 'ManagedIdentityClientId', 'TenantId') {
        if ($PSBoundParameters.ContainsKey($k)) { $authArgs[$k] = $PSBoundParameters[$k] }
    }
    $schema = Get-SILogSchemaRest -Data $Data -As Array
    $needs = Test-SILogTableDcrStatusRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $schema -DcrResourceGroup $DcrResourceGroup @authArgs
    if (-not $needs) { Write-Output ("table {0}_CL and rule {1}: every column is declared" -f $TableName, $DcrName); return }
    Set-SILogTableRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -SchemaSourceObject (Get-SILogSchemaRest -Data $Data -As Hash -ReturnType Table) -SchemaMode $SchemaMode @authArgs
    Set-SILogDcrRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -SchemaSourceObject (Get-SILogSchemaRest -Data $Data -As Hash -ReturnType DCR) `
        -DceName $DceName -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -SchemaMode $SchemaMode `
        -LogIngestServicePricipleObjectId $LogIngestServicePricipleObjectId -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel @authArgs
}

# =====================================================================================================================
#  REST: upload
# =====================================================================================================================

function ConvertTo-SILogGzip {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $ms = New-Object System.IO.MemoryStream
    try {
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
        try { $gz.Write($Bytes, 0, $Bytes.Length) } finally { $gz.Dispose() }
        return , $ms.ToArray()
    } finally { $ms.Dispose() }
}

function Send-SILogIngestBatch {
    <# Posts rows [List of row JSON bytes] as one JSON array. Measured: when the payload (compressed when -State says
       so) exceeds the limit, the batch is split in two and each half measured again. #>
    param([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)][hashtable]$State)
    $raw = New-Object System.IO.MemoryStream
    try {
        $raw.WriteByte(0x5B)
        for ($i = 0; $i -lt $Rows.Count; $i++) { if ($i -gt 0) { $raw.WriteByte(0x2C) }; $b = $Rows[$i]; $raw.Write($b, 0, $b.Length) }
        $raw.WriteByte(0x5D)
        $rawBytes = $raw.ToArray()
    } finally { $raw.Dispose() }
    $payload = if ($State.Compress) { ConvertTo-SILogGzip -Bytes $rawBytes } else { $rawBytes }
    if ($payload.Length -gt $State.MaxBytes) {
        if ($Rows.Count -eq 1) { throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f $payload.Length, $State.MaxBytes) }
        $half = [int][Math]::Floor($Rows.Count / 2)
        $a = New-Object 'System.Collections.Generic.List[byte[]]'; $z = New-Object 'System.Collections.Generic.List[byte[]]'
        for ($i = 0; $i -lt $Rows.Count; $i++) { if ($i -lt $half) { [void]$a.Add($Rows[$i]) } else { [void]$z.Add($Rows[$i]) } }
        Send-SILogIngestBatch -Rows $a -State $State
        Send-SILogIngestBatch -Rows $z -State $State
        return
    }
    if ($State.Compress -and $rawBytes.Length -gt 0) { $State.Ratio = [Math]::Max(0.01, $payload.Length / $rawBytes.Length) }
    $from = $State.Posted + 1; $to = $State.Posted + $Rows.Count
    Write-Host ''
    Write-Host ("  Posting data to LogAnalytics table [ {0}_CL ]" -f $State.Table)
    Write-Host ("    Rows       : {0}..{1} / {2}" -f $from, $to, $State.Total)
    Write-Host ("    {0} | {1}" -f $(if ($State.Compress) { 'Compression=ON' } else { 'Compression=OFF' }), $State.AuthText)
    Write-Host ''
    $h = @{}
    if ($State.Compress) { $h['Content-Encoding'] = 'gzip' }
    $null = Invoke-SILogIngestRequest -Method POST -Uri $State.Uri -Body ([byte[]]$payload) -ContentType 'application/json' -Headers $h `
        -Resource 'https://monitor.azure.com/' -Auth $State.Auth -What 'Log Ingestion API request'
    $State.Posted += $Rows.Count
    $State.Bytes += [long]$rawBytes.Length
    $State.Batches++
    Write-Host '  SUCCESS - data uploaded to LogAnalytics' -ForegroundColor Green
}

# =====================================================================================================================
#  REST: the PARALLEL SENDER (#738) -- for a caller that posts one large result in many calls (Risk Analysis)
#
#  A large install, 2026-10-17: 1,138,554 Risk Analysis rows reached Log Analytics at ~2,200 rows a minute (~8.5 hours). Every post
#  was made, and waited for, in line with the work that builds the rows: the page read, the preparation, the JSON, then one
#  POST at a time, each ~half full (the batch split in two whenever the compressed size went over the limit).
#  A sender changes only HOW the rows travel, never WHICH rows or their JSON (the rows are serialised exactly as before, by
#  Send-SILogDataRest, in the order given):
#    * each POST is filled close to the API's limit: the rows are compressed, the compressed size MEASURED, and a batch that
#      comes out over the limit gives back its last rows to the next batch (no half batches); the compression ratio adapts
#      from every measurement; a 413 from the service lowers the limit and the batch is split and sent again;
#    * up to -Degree POSTs are in flight at once (a small fixed number, 4), each on its own worker; a 429 / 408 / 5xx / no
#      answer is retried by its worker after the service's Retry-After, and a 429 holds EVERY worker until then;
#    * the endpoint, the rule and the token are resolved once per sender (the token from the run's cache, refreshed on 401);
#    * the rows confirmed by the service (2xx) are COUNTED; Complete-SILogIngestSender throws when they are fewer than the
#      rows handed over -- the same verdict as before. A failed post stops the next hand-over at once (the error is the
#      same text as a failed synchronous post).
#  Started by the caller (Start-SILogIngestSender -TableName), then every Send-SILogData for that table goes through it;
#  any other table, and every caller that never starts one, posts synchronously exactly as before.
# =====================================================================================================================

function Get-SILogIngestSenderWorkerScript {
    <# The worker: one POST with the retry rule (working rule 4), holding while the service asked every worker to wait. #>
    @'
param([string]$Uri, [byte[]]$Body, [hashtable]$Headers, [int]$MaxAttempts, $Gate)
$notes = New-Object 'System.Collections.Generic.List[string]'
for ($attempt = 1; ; $attempt++) {
    while ($true) {
        $until = [long]$Gate['PauseUntil']; $now = [datetime]::UtcNow.Ticks
        if ($until -le $now) { break }
        Start-Sleep -Milliseconds ([int][Math]::Min(60000, [Math]::Ceiling(($until - $now) / 10000.0)) + 1)
    }
    $r = Invoke-SILogIngestHttp -Method POST -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json'
    $code = [int]$r.StatusCode
    if ($code -ge 200 -and $code -lt 300) { return @{ Code = $code; Attempts = $attempt; Content = ''; Notes = $notes.ToArray() } }
    $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
    if (-not $transient -or $attempt -ge $MaxAttempts) { return @{ Code = $code; Attempts = $attempt; Content = [string]$r.Content; Notes = $notes.ToArray() } }
    $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
    if ($code -eq 429) {
        [System.Threading.Monitor]::Enter($Gate.SyncRoot)
        try { $t = [datetime]::UtcNow.AddSeconds($wait).Ticks; if ($t -gt [long]$Gate['PauseUntil']) { $Gate['PauseUntil'] = $t } } finally { [System.Threading.Monitor]::Exit($Gate.SyncRoot) }
    }
    if ($code -eq 0 -or $wait -ge 30) {
        $notes.Add((" [INFO] Log Ingestion API request: {0} -- trying again in {1} second(s) (attempt {2} of {3})" -f $(if ($code -eq 0) { 'no answer from Azure' } else { 'Azure answered HTTP {0}' -f $code }), $wait, $attempt, $MaxAttempts))
    }
    [System.Threading.Monitor]::Enter($Gate.SyncRoot)
    try { $Gate['Retries'] = 1 + [int]$Gate['Retries'] } finally { [System.Threading.Monitor]::Exit($Gate.SyncRoot) }
    Start-Sleep -Seconds $wait
}
'@
}

function Get-SILogIngestSender {
    <# The sender started for -TableName in this run ($null when none). #>
    param([Parameter(Mandatory)][string]$TableName)
    $c = Get-SILogIngestRunCache
    if (-not ($c.Senders -is [hashtable])) { return $null }
    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
    if ($c.Senders.ContainsKey($k)) { return $c.Senders[$k] }
    $null
}

function Get-SILogIngestPostDegree {
    <# PURE over the setting. POSTs in flight at once: 4 (a small fixed number). SI_LogIngest_ParallelPosts (global) or the
       environment variable SI_LOGINGEST_PARALLELPOSTS: 1 / 0 / off = one at a time; a number = that many, at most 8. #>
    param($Setting = $(Get-Variable -Scope Global -Name SI_LogIngest_ParallelPosts -ValueOnly -ErrorAction Ignore), [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_LOGINGEST_PARALLELPOSTS)
    $s = if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '') { ([string]$Setting).Trim() } elseif ($EnvValue) { $EnvValue.Trim() } else { '' }
    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
    $n = 0
    if ($s -ne '' -and [int]::TryParse($s, [ref]$n)) { if ($n -le 1) { return 1 }; return [Math]::Min(8, $n) }
    4
}

function Start-SILogIngestSender {
    <# Starts the sender for -TableName (see the block above). -Degree: POSTs in flight at once (Get-SILogIngestPostDegree).
       -MaxPayloadBytes: the API's limit per call; each POST is filled to -Fill of it (measured after compression). #>
    param([Parameter(Mandatory)][string]$TableName, [int]$Degree = 0, [long]$MaxPayloadBytes = 1MB, [double]$Fill = 0.95, [int]$MaxAttempts = 6)
    if ($Degree -le 0) { $Degree = Get-SILogIngestPostDegree }
    $c = Get-SILogIngestRunCache
    if (-not ($c.Senders -is [hashtable])) { $c.Senders = @{} }
    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
    if ($c.Senders.ContainsKey($k)) { Stop-SILogIngestSender -TableName $TableName }
    $s = @{
        Table = ($TableName -replace '_CL$', ''); Degree = $Degree; MaxBytes = [long]$MaxPayloadBytes; Fill = $Fill; MaxAttempts = $MaxAttempts
        Uri = $null; Auth = $null; AuthText = ''; Compress = $true; Ratio = 1.0
        Pending = (New-Object 'System.Collections.Generic.List[byte[]]'); PendingBytes = 2L
        InFlight = (New-Object 'System.Collections.Generic.List[object]')
        Accepted = 0L; Dispatched = 0L; Confirmed = 0L; Bytes = 0L; SentBytes = 0L; Posts = 0; Split413 = 0; MaxSent = 0L
        Failed = $null; Pool = $null; Gate = [hashtable]::Synchronized(@{ PauseUntil = 0L; Retries = 0 }); Script = (Get-SILogIngestSenderWorkerScript)
    }
    if ($Degree -gt 1) {
        # the worker's environment: the HTTP seam and the retry delay AS THEY ARE in this run (a test's fake service
        # included), and $SILogSeam (the test seam's shared state, $null in a real run). Never a script block of this
        # runspace: a worker runs only text it was given.
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        foreach ($fn in 'Invoke-SILogIngestHttp', 'Get-SILogIngestRetryDelay') {
            $def = (Get-Command -Name $fn -CommandType Function -ErrorAction Stop).Definition
            $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def)))
        }
        $seam = Get-Variable -Scope Global -Name SILogSeam -ValueOnly -ErrorAction Ignore
        $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('SILogSeam', $seam, '')))
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Degree, $iss, $Host)
        $pool.Open()
        $s.Pool = $pool
    }
    $c.Senders[$k] = $s
    $s
}

function Send-SILogIngestSenderBatch {
    <# Hands one payload to a worker (or posts it here when the sender has no workers), waiting first while -Degree are in flight. #>
    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][byte[]]$Payload, [Parameter(Mandatory)][hashtable]$Batch)
    while ($Sender.InFlight.Count -ge [Math]::Max(1, $Sender.Degree)) { Receive-SILogIngestSenderResults -Sender $Sender -WaitOne }
    # once a post has failed, nothing more goes out (the run fails; the rows not posted are counted as not confirmed)
    if ($Sender.Failed) { return }
    $token = Get-SILogIngestToken -Resource 'https://monitor.azure.com/' -Auth $Sender.Auth -ForceRefresh:([bool]$Batch.Refresh)
    $h = @{ 'Authorization' = ('Bearer ' + $token) }
    if ($Sender.Compress) { $h['Content-Encoding'] = 'gzip' }
    $Batch.Payload = $Payload
    $Sender.Posts++
    if ($null -eq $Sender.Pool) {
        $res = & ([scriptblock]::Create($Sender.Script)) $Sender.Uri $Payload $h $Sender.MaxAttempts $Sender.Gate
        Complete-SILogIngestSenderBatch -Sender $Sender -Batch $Batch -Result $res
        return
    }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $Sender.Pool
    [void]$ps.AddScript($Sender.Script).AddArgument($Sender.Uri).AddArgument($Payload).AddArgument($h).AddArgument($Sender.MaxAttempts).AddArgument($Sender.Gate)
    $Batch.PS = $ps
    $Batch.Handle = $ps.BeginInvoke()
    [void]$Sender.InFlight.Add($Batch)
}

function Complete-SILogIngestSenderBatch {
    <# One post's answer: 2xx = its rows confirmed (said as before); 401 = sent once more with a fresh token; 413 = the limit
       is lowered and the batch split and sent again; anything else = the sender has FAILED (same text as a failed post). #>
    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][hashtable]$Batch, $Result)
    $r = $Result
    if ($r -is [System.Collections.IEnumerable] -and -not ($r -is [hashtable])) { $r = @($r | Where-Object { $_ -is [hashtable] }) | Select-Object -Last 1 }
    if (-not ($r -is [hashtable])) { $r = @{ Code = 0; Content = 'the post''s worker returned no answer'; Notes = @() } }
    foreach ($n in @($r.Notes)) { if ($n) { Write-Host $n } }
    $code = [int]$r.Code
    if ($code -ge 200 -and $code -lt 300) {
        $Sender.Confirmed += $Batch.Rows.Count
        $Sender.Bytes += [long]$Batch.Raw
        $Sender.SentBytes += [long]$Batch.Payload.Length
        if ($Batch.Payload.Length -gt $Sender.MaxSent) { $Sender.MaxSent = [long]$Batch.Payload.Length }
        Write-Host ''
        Write-Host ("  Posting data to LogAnalytics table [ {0}_CL ]" -f $Sender.Table)
        Write-Host ("    Rows       : {0}..{1} / {2}" -f $Batch.From, ($Batch.From + $Batch.Rows.Count - 1), $Sender.Accepted)
        Write-Host ("    {0} | {1} | {2:n0} bytes" -f $(if ($Sender.Compress) { 'Compression=ON' } else { 'Compression=OFF' }), $Sender.AuthText, $Batch.Payload.Length)
        Write-Host ''
        Write-Host '  SUCCESS - data uploaded to LogAnalytics' -ForegroundColor Green
        return
    }
    if ($code -eq 401 -and -not $Batch.Refresh -and -not $Sender.Failed) {
        $Batch.Refresh = $true
        Send-SILogIngestSenderBatch -Sender $Sender -Payload $Batch.Payload -Batch $Batch
        return
    }
    if ($code -eq 413 -and $Batch.Rows.Count -gt 1 -and -not $Sender.Failed) {
        # the service's own limit is lower than ours: lower it under this payload and send the rows again in two
        $Sender.MaxBytes = [long][Math]::Max(65536, [Math]::Floor($Batch.Payload.Length * 0.9))
        $Sender.Split413++
        $half = [int][Math]::Floor($Batch.Rows.Count / 2)
        $a = New-Object 'System.Collections.Generic.List[byte[]]'; $z = New-Object 'System.Collections.Generic.List[byte[]]'
        for ($i = 0; $i -lt $Batch.Rows.Count; $i++) { if ($i -lt $half) { [void]$a.Add($Batch.Rows[$i]) } else { [void]$z.Add($Batch.Rows[$i]) } }
        $Sender.Dispatched -= $Batch.Rows.Count
        Send-SILogIngestSenderRows -Sender $Sender -Rows $a -From $Batch.From
        Send-SILogIngestSenderRows -Sender $Sender -Rows $z -From ($Batch.From + $half)
        return
    }
    if (-not $Sender.Failed) { $Sender.Failed = ("Log Ingestion API request failed. HTTP Status: {0} Response: {1}" -f $code, $r.Content) }
}

function Receive-SILogIngestSenderResults {
    <# Collects the answers of the posts that finished; -WaitOne waits for at least one (when any is in flight); -All for all. #>
    param([Parameter(Mandatory)][hashtable]$Sender, [switch]$WaitOne, [switch]$All)
    while ($Sender.InFlight.Count -gt 0) {
        $done = @($Sender.InFlight | Where-Object { $_.Handle.IsCompleted })
        if ($done.Count -eq 0) {
            if (-not $WaitOne -and -not $All) { return }
            $handles = [System.Threading.WaitHandle[]]@($Sender.InFlight | ForEach-Object { $_.Handle.AsyncWaitHandle } | Select-Object -First 64)
            [void][System.Threading.WaitHandle]::WaitAny($handles, 1000)
            continue
        }
        # out of the list first: answering one post can send another (401, 413) and wait for the workers again
        foreach ($b in $done) { [void]$Sender.InFlight.Remove($b) }
        # each answer on its own: one that throws (a token fetch for a 401 resend, a record too large in a 413 split) is the
        # sender's FIRST error -- every other finished post is still counted and its worker disposed
        foreach ($b in $done) {
            $res = $null
            try { $res = @($b.PS.EndInvoke($b.Handle)) | ForEach-Object { $_.psobject.BaseObject } | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1 }
            catch { $res = @{ Code = 0; Content = $_.Exception.Message; Notes = @() } }
            finally { try { $b.PS.Dispose() } catch { }; $b.PS = $null; $b.Handle = $null }
            try { Complete-SILogIngestSenderBatch -Sender $Sender -Batch $b -Result $res }
            catch { if (-not $Sender.Failed) { $Sender.Failed = [string]$_.Exception.Message } }
        }
        if ($WaitOne -and -not $All) { return }
    }
}

function Send-SILogIngestSenderCut {
    <# Makes ONE post from the rows waiting: compressed and MEASURED; over the limit -> the last rows wait for the next post
       (as many as the measurement says), never a half-empty post: a post that measures under 60% of the limit is not
       sent yet (the ratio is learnt from it and the rows keep coming) -- unless -Final (the rows left at the end). #>
    param([Parameter(Mandatory)][hashtable]$Sender, [switch]$Final)
    $rows = $Sender.Pending
    if ($rows.Count -eq 0) { return }
    $take = $rows.Count
    $limit = [long][Math]::Floor($Sender.MaxBytes * $Sender.Fill)
    while ($true) {
        $raw = New-Object System.IO.MemoryStream
        try {
            $raw.WriteByte(0x5B)
            for ($i = 0; $i -lt $take; $i++) { if ($i -gt 0) { $raw.WriteByte(0x2C) }; $b = $rows[$i]; $raw.Write($b, 0, $b.Length) }
            $raw.WriteByte(0x5D)
            $rawBytes = $raw.ToArray()
        } finally { $raw.Dispose() }
        $payload = if ($Sender.Compress) { ConvertTo-SILogGzip -Bytes $rawBytes } else { $rawBytes }
        if ($Sender.Compress -and $rawBytes.Length -gt 0) { $Sender.Ratio = [Math]::Max(0.005, $payload.Length / [double]$rawBytes.Length) }
        if (-not $Final -and $take -eq $rows.Count -and $payload.Length -lt [long]($limit * 0.6)) { return }   # too empty yet: wait for more rows
        if ($payload.Length -le $limit -or ($payload.Length -le $Sender.MaxBytes -and $take -eq 1)) { break }
        if ($take -eq 1) { throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f $payload.Length, $Sender.MaxBytes) }
        # as many rows as the measured bytes per row allow, a little under (the next post takes the rest)
        $take = [int][Math]::Max(1, [Math]::Min($take - 1, [Math]::Floor($take * ($limit * 0.98) / [double]$payload.Length)))
    }
    $batchRows = $rows.GetRange(0, $take)
    $rows.RemoveRange(0, $take)
    $Sender.PendingBytes = 2L; foreach ($b in $rows) { $Sender.PendingBytes += $b.Length + 1 }
    $from = $Sender.Dispatched + 1
    $Sender.Dispatched += $take
    Send-SILogIngestSenderBatch -Sender $Sender -Payload $payload -Batch @{ Rows = $batchRows; Raw = $rawBytes.Length; From = $from; Refresh = $false }
}

function Send-SILogIngestSenderRows {
    <# Adds serialised rows to the sender, in order; a post is made each time the rows waiting reach the measured size of a
       full one. -From: re-sent rows (a 413 split) keep their numbers and go out at once. #>
    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)]$Rows, [long]$From = 0)
    if ($From -gt 0) {
        # a split batch: these rows go out as they are (each half measured again), ahead of the rows waiting
        $keep = $Sender.Pending; $keepBytes = $Sender.PendingBytes
        $Sender.Pending = New-Object 'System.Collections.Generic.List[byte[]]'; foreach ($b in $Rows) { [void]$Sender.Pending.Add($b) }
        $saved = $Sender.Dispatched; $Sender.Dispatched = $From - 1
        while ($Sender.Pending.Count -gt 0) { Send-SILogIngestSenderCut -Sender $Sender -Final }
        $Sender.Dispatched = $saved + $Rows.Count
        $Sender.Pending = $keep; $Sender.PendingBytes = $keepBytes
        return
    }
    foreach ($b in $Rows) {
        if (-not $Sender.Compress -and ($b.Length + 2) -gt $Sender.MaxBytes) {
            throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f ($b.Length + 2), $Sender.MaxBytes)
        }
        # raw-bytes ceiling: the limit itself uncompressed; compressed, the fill level over the measured ratio
        $ceiling = if ($Sender.Compress) { [long][Math]::Min(64MB, [Math]::Floor($Sender.MaxBytes * $Sender.Fill / $Sender.Ratio)) } else { [long][Math]::Floor($Sender.MaxBytes * $Sender.Fill) }
        $add = $b.Length + $(if ($Sender.Pending.Count -gt 0) { 1 } else { 0 })
        if ($Sender.Pending.Count -gt 0 -and ($Sender.PendingBytes + $add) -gt $ceiling) {
            Send-SILogIngestSenderCut -Sender $Sender
            if ($Sender.Failed) { throw $Sender.Failed }
            $add = $b.Length + $(if ($Sender.Pending.Count -gt 0) { 1 } else { 0 })
        }
        [void]$Sender.Pending.Add($b); $Sender.PendingBytes += $add
        $Sender.Accepted++
    }
    Receive-SILogIngestSenderResults -Sender $Sender
    if ($Sender.Failed) { throw $Sender.Failed }
}

function Sync-SILogIngestSender {
    <# Every row handed over is posted and answered (the rows waiting go out now). Throws when a post failed. #>
    param([Parameter(Mandatory)][hashtable]$Sender)
    while ($Sender.Pending.Count -gt 0 -and -not $Sender.Failed) { Send-SILogIngestSenderCut -Sender $Sender -Final }
    Receive-SILogIngestSenderResults -Sender $Sender -All
    if ($Sender.Failed) { throw $Sender.Failed }
}

function Invoke-SILogIngestGuardHeal {
    <#
        #733 (owner 2026-10-17: guards heal themselves): a table whose rows Log Analytics accepted IN FULL clears an earlier
        "rows not accepted" of that table by itself. Once per table per process (the first full post), so the hot path pays one
        state read per table, not one per post. Never throws; nothing when the guard code is not loaded.
    #>
    param([Parameter(Mandatory)][string]$Table)
    try {
        if (-not (Get-Command -Name Invoke-SIGuardHeal -ErrorAction Ignore)) { return }
        if ($null -eq $script:SILogIngestHealed) { $script:SILogIngestHealed = @{} }
        $t = $Table.ToLowerInvariant()
        if ($script:SILogIngestHealed.ContainsKey($t)) { return }
        $script:SILogIngestHealed[$t] = $true
        $null = Invoke-SIGuardHeal -Checked @(@{ GuardId = 'ingest.rows.short-count'; Subject = $Table; Detail = ('Log Analytics accepted every row for {0}.' -f $Table) }) -Complete $true
    } catch { }
}

function Complete-SILogIngestSender {
    <#
        The end of the hand-over: the rows waiting are posted, every post is answered, the workers are closed. The rows the
        service CONFIRMED are counted against the rows handed over -- fewer throws (and is a guard event), as a short
        synchronous post did. Returns @{ RowsPosted; RowsHandedOver; Posts; BytesPosted; BytesSent; MaxBytesSent; Retries; Split413 }.
    #>
    param([Parameter(Mandatory)][string]$TableName)
    $s = Get-SILogIngestSender -TableName $TableName
    if ($null -eq $s) { return $null }
    try { Sync-SILogIngestSender -Sender $s }
    finally { Close-SILogIngestSender -TableName $TableName }
    if ($s.Confirmed -ne $s.Accepted) {
        if (Get-Command -Name Send-SIGuardEvent -ErrorAction Ignore) { $null = Send-SIGuardEvent -GuardId 'ingest.rows.short-count' -Outcome 'refused' -Subject ($s.Table + '_CL') -Detail ("Log Analytics accepted {0} of {1} row(s) for {2}_CL." -f $s.Confirmed, $s.Accepted, $s.Table) -Values @(@{ Name = 'rowsPosted'; Label = 'Rows accepted'; Measured = [long]$s.Confirmed; Limit = [long]$s.Accepted }, @{ Name = 'rowsGiven'; Label = 'Rows sent'; Measured = [long]$s.Accepted }) -HeldCount ([long]$s.Accepted - [long]$s.Confirmed) }
        throw ("Posted {0} of {1} row(s) to {2}_CL -- the other rows are UNKNOWN, not posted." -f $s.Confirmed, $s.Accepted, $s.Table)
    }
    if ([long]$s.Accepted -gt 0) { Invoke-SILogIngestGuardHeal -Table ($s.Table + '_CL') }
    [pscustomobject]@{ RowsPosted = $s.Confirmed; RowsHandedOver = $s.Accepted; Posts = $s.Posts; BytesPosted = $s.Bytes; BytesSent = $s.SentBytes; MaxBytesSent = $s.MaxSent; Retries = [int]$s.Gate['Retries']; Split413 = $s.Split413 }
}

function Send-SILogDataToSender {
    <#
        Send-SILogDataRest's rows through a sender: serialised EXACTLY as the synchronous path does (ConvertTo-Json -Depth 100
        -Compress per row, UTF-8, in the order given) and handed over. Returns the synchronous path's result shape: RowsPosted
        = the rows handed over (the rows CONFIRMED are counted by Complete-SILogIngestSender), BytesPosted = their JSON bytes.
        When this run added columns to the rule and their check is due (Confirm-SILogNewColumns, after this call), every row
        handed over is posted and answered first -- the check reads the rows back from Log Analytics.
    #>
    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][AllowEmptyCollection()][array]$Data, [string]$DcrName)
    # #639: handed over a BATCH at a time -- the rows serialised so far are handed to the sender once they fill a post
    # (its measured size), never the whole post serialised first and held as bytes beside the rows
    $list = New-Object 'System.Collections.Generic.List[byte[]]'
    $bytes = 1L; $count = 0L; $listBytes = 0L
    $fill = 1.0; if ($Sender.ContainsKey('Fill') -and $Sender.Fill) { $fill = [double]$Sender.Fill }
    $ratio = 1.0; if ($Sender.ContainsKey('Ratio') -and $Sender.Ratio) { $ratio = [double]$Sender.Ratio }
    $max = 1MB; if ($Sender.ContainsKey('MaxBytes') -and $Sender.MaxBytes) { $max = [long]$Sender.MaxBytes }
    $handAt = [long][Math]::Max(1, [Math]::Floor($max * $fill))
    if ($Sender.Compress) { $handAt = [long][Math]::Min(64MB, [Math]::Floor($max * $fill / $ratio)) }
    foreach ($row in $Data) {
        $b = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 100 -InputObject $row -Compress))
        [void]$list.Add($b); $bytes += $b.Length + 1; $listBytes += $b.Length + 1; $count++
        if ($listBytes -ge $handAt) {
            Send-SILogIngestSenderRows -Sender $Sender -Rows $list
            $list = New-Object 'System.Collections.Generic.List[byte[]]'; $listBytes = 0L
        }
    }
    if ($list.Count -gt 0) { Send-SILogIngestSenderRows -Sender $Sender -Rows $list }
    $list = $null
    if ($DcrName -and ($global:SI_LogIngestNewColumns -is [hashtable]) -and $global:SI_LogIngestNewColumns.ContainsKey($DcrName.ToLowerInvariant())) {
        Sync-SILogIngestSender -Sender $Sender
    }
    [pscustomobject]@{ StatusCode = 204; RowsPosted = $count; BytesPosted = $bytes; Batches = 0; Table = ($Sender.Table + '_CL'); Stream = '' }
}

function Stop-SILogIngestSender {
    <# After a failure: nothing more is posted; the posts in flight are answered (their rows count), the workers closed.
       Returns the rows the service confirmed (the rows that DID reach Log Analytics). Never throws. #>
    param([Parameter(Mandatory)][string]$TableName)
    $s = Get-SILogIngestSender -TableName $TableName
    if ($null -eq $s) { return 0L }
    try { $s.Pending.Clear(); Receive-SILogIngestSenderResults -Sender $s -All } catch { }
    Close-SILogIngestSender -TableName $TableName
    [long]$s.Confirmed
}

function Close-SILogIngestSender {
    param([Parameter(Mandatory)][string]$TableName)
    $c = Get-SILogIngestRunCache
    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
    if (-not ($c.Senders -is [hashtable]) -or -not $c.Senders.ContainsKey($k)) { return }
    $s = $c.Senders[$k]
    foreach ($b in $s.InFlight.ToArray()) { try { if ($b.PS) { $b.PS.Stop(); $b.PS.Dispose() } } catch { } }
    $s.InFlight.Clear()
    if ($s.Pool) { try { $s.Pool.Close(); $s.Pool.Dispose() } catch { }; $s.Pool = $null }
    $c.Senders.Remove($k)
}

function Send-SILogDataRest {
    <#
        Twin of Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output, over plain REST:
          * the rule is found by NAME in the configured subscription + SI_DcrResourceGroup (or the one created this run);
          * the post goes through the endpoint the RULE is bound to -- ingestion accepts nothing else (#199);
          * POST {endpoint}/dataCollectionRules/{immutableId}/streams/Custom-{table}_CL?api-version=2023-01-01;
          * batches are sized from the MEASURED JSON bytes of the rows (working rule 5: no fixed row counts), each under
            the 1 MB limit -- compressed when $global:EnableCompressionDefault says so, measured after compression and
            split again if over;
          * 429 / 5xx retried in-run with Retry-After; any other 4xx fails at once with the response body;
          * the rows posted are COUNTED against the rows given -- a shortfall throws, it is never reported as done.
        Rows are serialised exactly as the module serialised them (ConvertTo-Json -Depth 100 -Compress per row).
        -BatchAmount is accepted and ignored: a fixed row count is what working rule 5 forbids.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Data, [Parameter(Mandatory)][AllowEmptyString()][string]$DcrName,
          [AllowEmptyString()][string]$DceName, [Parameter(Mandatory)][string]$TableName,
          [string]$BatchAmount, [bool]$EnableUploadViaLogHub = $false, [string]$LogHubPath,
          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine', [string]$TenantId,
          [Nullable[bool]]$EnableCompression = $null, [Nullable[bool]]$UseManagedIdentity = $null, [string]$ManagedIdentityClientId,
          [string]$SubscriptionId, [string]$DcrResourceGroup, [long]$MaxPayloadBytes = 1MB)
    $total = @($Data).Count
    if ($total -eq 0) { return }
    if ($null -eq $EnableCompression) { $EnableCompression = if ($null -ne $global:EnableCompressionDefault) { [bool]$global:EnableCompressionDefault } else { $false } }
    $bound = @{}; foreach ($k in $PSBoundParameters.Keys) { $bound[$k] = $PSBoundParameters[$k] }
    $auth = Resolve-SILogIngestAuth -Bound $bound
    # #738: a sender started for this table takes the rows (in order, serialised exactly as below); its endpoint, rule and
    # sign-in are resolved on its first call and reused
    $sender = Get-SILogIngestSender -TableName $TableName
    if ($sender -and $sender.Uri) {
        if ([bool]$EnableCompression -ne [bool]$sender.Compress) { $sender = $null }   # never mixed in one sender
        else { return (Send-SILogDataToSender -Sender $sender -Data $Data -DcrName $DcrName) }
    }
    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId -DcrResourceGroup $DcrResourceGroup

    $dcr = Resolve-SILogDcrForTable -DcrName $DcrName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DcrRg -Auth $auth
    if (-not $dcr) { throw ("Data collection rule '{0}' was not found in resource group '{1}' of subscription '{2}', so nothing was posted." -f $DcrName, $scope.DcrRg, $scope.Subscription) }
    $immutableId = [string]$dcr.properties.immutableId
    if (-not $immutableId) { throw ("Data collection rule '{0}' has no immutable id yet, so nothing was posted." -f $DcrName) }
    $stream = Get-SILogStreamName -TableName $TableName
    if (-not ($dcr.properties.streamDeclarations -and $dcr.properties.streamDeclarations.PSObject.Properties[$stream])) {
        $first = @(@($dcr.properties.dataFlows)[0].streams)[0]
        if ($first) { $stream = [string]$first }
    }
    $endpoint = $null
    $boundDce = [string]$dcr.properties.dataCollectionEndpointId
    if ($boundDce) {
        $dce = Invoke-SILogArm -Path $boundDce -ApiVersion (Get-SILogArmApiVersion Dce) -Auth $auth -AllowNotFound
        if ($dce) { $endpoint = [string]$dce.properties.logsIngestion.endpoint }
    }
    if (-not $endpoint -and $dcr.properties.endpoints -and $dcr.properties.endpoints.logsIngestion) { $endpoint = [string]$dcr.properties.endpoints.logsIngestion }
    if (-not $endpoint -and $DceName) {
        $dce = Find-SILogResourceByName -Kind Dce -Name $DceName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DceRg -Auth $auth -AnyResourceGroupWhenMissing
        if ($dce) { $endpoint = [string]$dce.properties.logsIngestion.endpoint }
    }
    if (-not $endpoint) { throw ("No ingestion endpoint for data collection rule '{0}' (not bound to an endpoint, and '{1}' was not found), so nothing was posted." -f $DcrName, $DceName) }

    $authText = switch ($auth.Mode) { 'ManagedIdentity' { 'Auth=ManagedIdentity' } 'Certificate' { 'Auth=SPN-Cert' } 'Secret' { 'Auth=SPN' } 'Support' { 'Auth=InvardiaSupport' } default { 'Auth=Run' } }
    $state = @{
        Uri = ('{0}/dataCollectionRules/{1}/streams/{2}?api-version=2023-01-01' -f $endpoint.TrimEnd('/'), $immutableId, $stream)
        Auth = $auth; Compress = [bool]$EnableCompression; MaxBytes = $MaxPayloadBytes; Ratio = 1.0
        Posted = 0; Bytes = 0L; Batches = 0; Total = $total; Table = $TableName; AuthText = $authText
    }
    if ($sender) {
        $sender.Uri = $state.Uri; $sender.Auth = $auth; $sender.AuthText = $authText; $sender.Compress = [bool]$EnableCompression
        $sender.MaxBytes = [long][Math]::Min([double]$sender.MaxBytes, [double]$MaxPayloadBytes)
        return (Send-SILogDataToSender -Sender $sender -Data $Data -DcrName $DcrName)
    }
    $batch = New-Object 'System.Collections.Generic.List[byte[]]'
    $batchBytes = 2
    foreach ($row in $Data) {
        $b = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 100 -InputObject $row -Compress))
        if (-not $state.Compress -and ($b.Length + 2) -gt $MaxPayloadBytes) {
            throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f ($b.Length + 2), $MaxPayloadBytes)
        }
        # raw-bytes ceiling: the limit itself uncompressed; compressed, the limit over the measured ratio (90% margin)
        $ceiling = if ($state.Compress) { [long][Math]::Min(64MB, [Math]::Floor($MaxPayloadBytes / $state.Ratio * 0.9)) } else { $MaxPayloadBytes }
        $add = $b.Length + $(if ($batch.Count -gt 0) { 1 } else { 0 })
        if ($batch.Count -gt 0 -and ($batchBytes + $add) -gt $ceiling) {
            Send-SILogIngestBatch -Rows $batch -State $state
            $batch = New-Object 'System.Collections.Generic.List[byte[]]'; $batchBytes = 2; $add = $b.Length
        }
        [void]$batch.Add($b); $batchBytes += $add
    }
    if ($batch.Count -gt 0) { Send-SILogIngestBatch -Rows $batch -State $state }
    if ($state.Posted -ne $total) {
        # #277: the short count is a guard trip -- mailed and reported (never instead of the throw)
        if (Get-Command -Name Send-SIGuardEvent -ErrorAction Ignore) { $null = Send-SIGuardEvent -GuardId 'ingest.rows.short-count' -Outcome 'refused' -Subject ($TableName + '_CL') -Detail ("Log Analytics accepted {0} of {1} row(s) for {2}_CL." -f $state.Posted, $total, $TableName) -Values @(@{ Name = 'rowsPosted'; Label = 'Rows accepted'; Measured = [long]$state.Posted; Limit = [long]$total }, @{ Name = 'rowsGiven'; Label = 'Rows sent'; Measured = [long]$total }) -HeldCount ([long]$total - [long]$state.Posted) }
        throw ("Posted {0} of {1} row(s) to {2}_CL -- the other rows are UNKNOWN, not posted." -f $state.Posted, $total, $TableName)
    }
    if ([long]$total -gt 0) { Invoke-SILogIngestGuardHeal -Table ($TableName + '_CL') }
    # BytesPosted: the uncompressed JSON bytes of the rows posted -- a caller that posts in parts sizes its next part from it
    return [pscustomobject]@{ StatusCode = 204; RowsPosted = $state.Posted; BytesPosted = $state.Bytes; Batches = $state.Batches; Table = ($TableName + '_CL'); Stream = $stream }
}
