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

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function ConvertTo-SIUtcDateTimeOrNull {
    <#
        A timestamp from collected metadata as UTC, or $null -- on EVERY edition and host culture.

        Why this exists (#123): on pwsh 7, ConvertFrom-Json / Invoke-RestMethod already hand back a
        [datetime]. `[datetime]::Parse([string]$v)` then renders it in the INVARIANT "MM/dd/yyyy" form
        and parses it back in the HOST culture -- on a da-DK host "09/08" becomes 9 August instead of
        8 September, and a day above 12 fails to parse at all. Fresh devices were dropped as inactive.
        A [datetime] is used as-is; a string is parsed invariant (ISO 8601 round-trips).
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt }
    return $null
}

function Test-SIValuePopulated {
    <#
        AUDIT #17 -- "does this cell count as filled in?", extracted so a test can execute
        it. It was inline in the pre-ingest audit below, which meant the rule deciding
        whether a run may reach Log Analytics had NO executing coverage: the Pester gate
        parses the engines but never runs them, and Test-Smoke's SCHEMA-DRIFT check asserts
        something different (declared vs emitted columns).

        Deliberately treats the two EMPTY-CONTAINER serialisations as unpopulated -- a
        column that only ever holds "{}" or "[]" is a data-flow regression wearing a value.
    #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    $s = "$Value"
    return ($s -ne '' -and $s -ne '{}' -and $s -ne '[]')
}

function Get-SIColumnPopulationStats {
    <#
        AUDIT #17 -- per-column fill rate over the built rows. Pure: no I/O, no globals.
        Pct is integer-TRUNCATED, which is why the halt below tests -eq 0 rather than a
        threshold: 1 populated row in 10,000 truncates to 0% but must NOT halt the run.
        There is a test pinning exactly that.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Columns
    )
    $total = @($Rows).Count
    foreach ($col in $Columns) {
        $populated = 0
        foreach ($row in $Rows) {
            if ($row.PSObject.Properties[$col]) {
                if (Test-SIValuePopulated $row.$col) { $populated++ }
            }
        }
        $pct = if ($total -gt 0) { [int](100 * $populated / $total) } else { 0 }
        [pscustomobject]@{ Column = $col; Populated = $populated; Total = $total; Pct = $pct }
    }
}

function Get-SIDeadCriticalColumns {
    <#
        AUDIT #17 -- THE PRE-INGEST HALT DECISION. An always-on column at 0% population
        means the data flow broke upstream, and ingesting anyway would overwrite
        yesterday's good snapshot with a stale/empty one. Audit #5 established this guard
        is the only thing standing between a broken collection and exactly that.

        Only AlwaysOn columns can halt a run: a non-critical column at 0% is shown in the
        audit table but must never stop the ingest.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Stats,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AlwaysOn
    )
    return @($Stats | Where-Object { $_.Column -in $AlwaysOn -and $_.Pct -eq 0 })
}

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

function Test-SIOutputSchemaChangeNeeded {
    <#
        PURE. Did the table / rule step have something to create or extend? It says so itself when it had nothing to
        do ("every column is declared" / "already match schema"); anything else -- a create, an added column, an error,
        no text at all -- counts as "had to", which is when the create roles are worth checking.
    #>
    param([AllowNull()][AllowEmptyString()][string]$CreateOutput)
    return -not ("$CreateOutput" -match 'every column is declared|already match schema')
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
        $Records,
        # A table the caller hands in to get the BUILT ROWS back (Rows, Ready; Held when the rows are not usable). The
        # run's records take their profile part from these rows and go to the database on their own (Invoke-SIOutput),
        # whether or not the post below works. Not given: nobody wants the rows, and the function is as it always was.
        $Built,
        # build the rows and stop: Log Analytics was not asked for (sinks without 'LA'); returns nothing
        [switch]$RowsOnly
    )
    $wantRows = ($Built -is [System.Collections.IDictionary])

    # No required-infra-globals check anymore -- the run's entry (Invoke-SIEngineRun.ps1)
    # resolves the names of everything it sends to (workspace, DCE, DCR, RGs).
    # Only auth is hard-required.
    # Auth: SI_SPN_* primary (Secret OR CertThumbprint), SI_LogIngest_* fallback,
    # UAMI when $global:SI_PreferUami + $global:SI_UAMI_ClientId set.
    # v2.2.237 -- accept cert as well as secret. The ingestion (plain REST) supports
    # both via -AzAppCertificateThumbprint / -AzAppSecret. SPN+cert customers
    # were previously gate-failed at this check even though Bootstrap-Auth had
    # successfully authenticated them.
    $haveSpnSecret = $global:SI_SPN_AppId  -and $global:SI_SPN_Secret         -and $global:SI_SPN_TenantId -and $global:SI_SPN_ObjectId
    $haveSpnCert   = $global:SI_SPN_AppId  -and $global:SI_SPN_CertThumbprint -and $global:SI_SPN_TenantId -and $global:SI_SPN_ObjectId
    $haveSpn       = $haveSpnSecret -or $haveSpnCert
    $haveLi        = $global:SI_LogIngest_AppId -and $global:SI_LogIngest_Secret -and $global:SI_LogIngest_TenantId -and $global:SI_LogIngest_ObjectId
    $haveUami      = $global:SI_PreferUami -and $global:SI_UAMI_ClientId
    $haveAuth      = [bool]($haveSpn -or $haveLi -or $haveUami)
    $noAuthResult  = 'SKIPPED -- no auth configured. Set $global:SI_SPN_AppId + (Secret OR CertThumbprint) + TenantId + ObjectId in custom.ps1, or run Bootstrap-Auth.ps1.'
    # Without a sign-in for Log Analytics only the POST is skipped. When the caller wants the rows (the records go to
    # the database on their own) they are built first and the skip is said after that, further down.
    if (-not $haveAuth -and -not $wantRows -and -not $RowsOnly) { return $noAuthResult }

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

    # ---- v3: SI_AssetName UNIQUENESS -- the snapshot pass a row builder cannot be ----
    # 🔒 OPERATOR, 2026-08-28: "all assets must have a unique name and identifier. 100%", then
    # "qualify only where it collides".
    # 📊 MEASURED that day, per-snapshot and uncontaminated: SI_AssetId is ALREADY 100% populated and
    # 100% unique on all four engines (198/765/769/11). SI_AssetName is 100% populated and NOT unique
    # -- azure 302 distinct names for 769 rows, identity 395 for 765. So only the NAME needs this.
    # 🔑 IT CANNOT LIVE IN THE ROW BUILDER: a collision is a property of the SNAPSHOT, not of a row,
    # and a builder handed one asset cannot know another shares its name. Here $flat is the complete
    # built row set for the run, which is the first point where the question is even answerable.
    # 📌 Discriminators are per engine and PREFERRED over the opaque id tail wherever they separate the
    # group -- 'web-01 (rg-prod)' reads better than 'web-01 (a1b2c3d4)'. Engines with no meaningful
    # discriminator simply fall through to the id tail, which always works because the id is unique.
    if ($flat.Count -gt 0) {
        $__uniqPath = Join-Path $PSScriptRoot '..\..\_shared\SI-AssetNameUniqueness.ps1'
        if (Test-Path $__uniqPath) {
            . $__uniqPath
            # 🪤 NOT a `switch` returning @(). A switch EMITS its branch value into the pipeline, and an
            # EMPTY ARRAY unrolls to NOTHING -- so `default { @() }` assigns $null, which then binds to
            # [string[]] as a ONE-element array containing $null, and the mandatory -Name parameter
            # downstream rejects the empty string. MEASURED: it crashed the identity engine on a real
            # run ("Cannot bind argument to parameter 'Name' because it is an empty string") while
            # azure passed, because azure's branch happens to return a non-empty array.
            # Same family as this codebase's other empty-collection traps: `,$hits.ToArray()` counting 1
            # for zero matches, and `@($json | ConvertFrom-Json).Count` always being 1 on PS 5.1.
            $__disc = @()
            if ([string]$RunContext.Engine -eq 'azure') { $__disc = @('AzResourceGroup','ResourceType') }
            $__shards = if ($RunContext.ShardCount -gt 0) { [int]$RunContext.ShardCount } else { 1 }
            $__u = Resolve-SIAssetNameCollisions -Rows $flat -Discriminators $__disc -ShardCount $__shards
            if ($__u.Groups -gt 0) {
                $__by = ($__u.ByDiscriminator.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join ', '
                Write-SIInfo ('SI_AssetName uniqueness: {0} colliding name(s) over {1} row(s) -- qualified {2} ({3}{4}by id {5}). unique {6} -> {7}' -f `
                    $__u.Groups, $__u.Rows, $__u.Qualified, $__by, $(if($__by){', '}else{''}), $__u.ById, $__u.UniqueBefore, $__u.UniqueAfter)
            } else {
                Write-SIInfo ('SI_AssetName uniqueness: no collisions -- {0} row(s), {1} distinct name(s)' -f $__u.Rows, $__u.UniqueAfter)
            }
            # NOT silence, and not a throw. A row with neither a usable discriminator nor an id cannot
            # be qualified without inventing a value, which is the one thing this must never do. Saying
            # so is what makes it findable.
            if ($__u.Unqualifiable -gt 0) {
                Write-Warning ('SI_AssetName uniqueness: {0} row(s) keep a DUPLICATE name -- no discriminator and no SI_AssetId to qualify from.' -f $__u.Unqualifiable)
            }
            # ⚠️ Sharding makes the guarantee shard-local: a replica holds only its slice (hash mod
            # ShardCount in Invoke-Discover), so it cannot see a collision with a row another replica
            # owns. ShardCount defaults to 1 and no shipped launcher raises it -- but if one ever does,
            # the claim has to shrink out loud rather than quietly become false.
            if ($__u.ShardLocal) {
                Write-Warning ('SI_AssetName uniqueness is SHARD-LOCAL on this run (ShardCount={0}) -- names are unique within this replica only.' -f $__shards)
            }
        } else {
            Write-Warning ('SI_AssetName uniqueness pass SKIPPED -- not found: {0}' -f $__uniqPath)
        }
    }

    # ---- #61: what the operator decisions ACTUALLY DID, counted off the EMITTED rows ----
    # 🔑 Counted from the rows rather than from a counter incremented where the override is applied,
    # and that is deliberate. The bug this feature already produced once was an override that updated
    # $aggTier while the published row kept the computed tier: the variable moved and the OUTPUT did
    # not. A tally taken at the decision point would have reported that run as a success. Reading
    # SI_TierOverrideBy back off the built rows can only report what a customer will actually see.
    if ($flat.Count -gt 0 -and $global:SI_AssetDecisions -and @($global:SI_AssetDecisions).Count -gt 0) {
        $_ovr = @($flat | Where-Object {
            $_.PSObject.Properties['SI_TierOverrideBy'] -and -not [string]::IsNullOrWhiteSpace([string]$_.SI_TierOverrideBy)
        })
        if ($_ovr.Count -gt 0) {
            Write-SIInfo ('operator decisions: {0} override(s) APPLIED to {1} of {2} row(s)' -f $_ovr.Count, $_ovr.Count, $flat.Count)
            foreach ($_o in $_ovr) {
                Write-SIInfo ('   {0}: tier {1} -> {2}  ({3})' -f `
                    $_o.Hostname, [string]$_o.SI_TierBeforeOverride, [string]$_o.Tier, [string]$_o.SI_TierOverrideBy)
            }
        } else {
            # NOT silence. Decisions were loaded and none of them changed a single row -- which is
            # either correct (they are all exceptions/exemptions, which never touch the tier) or a
            # selector that matches nothing. Saying so is what makes the second case findable; a file
            # full of overrides for hostnames that no longer exist otherwise looks exactly like a file
            # that is working.
            Write-SIInfo ('operator decisions: {0} loaded, 0 override(s) changed a row -- check the selectors if you expected a tier to move' -f @($global:SI_AssetDecisions).Count)
        }
    }

    # ---- v3 Phase 5: the payload profile's one run-summary line ----
    # BEFORE the ingest, on purpose. The 256 KB budget is a HARD ingest limit -- over it the publish
    # fails with PropertyValueTooLarge and the row is lost -- so the operator has to hear about it while
    # there is still something to do, not discover it from a 400. And a projection that sheds fields
    # without naming them is the same silent-loss defect this whole area exists to close.
    if (Get-Command -Name Write-SIPayloadSummary -ErrorAction SilentlyContinue) {
        try { Write-SIPayloadSummary } catch {
            Write-Warning ("payload summary could not be written ({0}) -- the rows themselves are unaffected." -f $_.Exception.Message)
        }
    }

    # Pre-ingest population audit. Per-engine sentinel column list (see $engineDispatch).
    # 0% on an always-on column halts before LA ingest -- catches data-flow regressions
    # before they ship a stale snapshot that overwrites yesterday's good one.
    if ($flat.Count -gt 0) {
        # AUDIT #17: same computation, now in a function so it can be executed by a test.
        $stats = @(Get-SIColumnPopulationStats -Rows $flat -Columns @($cfg.AuditCols))
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
        # AUDIT #17: the halt decision, in a function so a test can exercise it.
        $deadCritical = @(Get-SIDeadCriticalColumns -Stats $stats -AlwaysOn @($cfg.AlwaysOn))
        if ($deadCritical.Count -gt 0) {
            Write-Warning ('       {0} CRITICAL column(s) at 0%% population -- run halted before LA ingest. Columns: {1}' -f `
                $deadCritical.Count, (($deadCritical.Column) -join ', '))
            # This halt is a verdict on the ROWS, not on Log Analytics: rows with a dead key column cannot give the
            # records their profile part either, so the database keeps its last good state too (said on its own line).
            if ($wantRows) { $Built['Held'] = ('the profile rows are not usable ({0} critical column(s) empty: {1}) -- the records were not written, so they keep their last good state' -f $deadCritical.Count, (($deadCritical.Column) -join ', ')) }
            return 'FAILED: critical schema columns empty -- LA ingest skipped to prevent stale data.'
        }
    }

    # ---- the rows are whole from here on: handed to the caller -----------------------------------------------------
    # Everything above is the row builder (build, unique names, the decisions and payload lines, the audit). Everything
    # below is the POST to Log Analytics. The caller writes the run's records to the database from these rows whether
    # the post works, fails, is skipped or was never asked for -- the database does not depend on Log Analytics.
    if ($wantRows) { $Built['Rows'] = $flat; $Built['Ready'] = $true }
    if ($RowsOnly) { return $null }
    if (-not $haveAuth) { return $noAuthResult }

    # Naming patterns are customer-tunable via custom.ps1 globals
    # (Layer 3 in the v2.1 config-stack model). Defaults follow the
    # SI_<Engine>_Profile + dcr-si-<engine>-profile pattern.
    # The "_Profile" suffix replaced "_Classification" because the row
    # content is broader than just a tier verdict -- it carries metadata
    # snapshot, posture proofs, EG enrichment, signal-map criticality,
    # app-group identity, and cross-engine references.
    # AzLogDcrIngestPS appends _CL on ingest.
    $engineCap = (Get-Culture).TextInfo.ToTitleCase($RunContext.Engine)
    # publicip's table is SI_PublicIP_Profile (capital IP) everywhere it is declared and read. Title-casing the engine key
    # gives 'Publicip' -- a DIFFERENT table in case-sensitive KQL -- so the casing must not depend on the launcher default
    # (SI_PublicIp_TableName) having been loaded: a run without it (a container, before that default reached one) wrote
    # SI_Publicip_Profile_CL, which nothing reads.
    if ($RunContext.Engine -ieq 'publicip') { $engineCap = 'PublicIP' }
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
        # publicip reads its own global like the other three. The former fallback
        # to the LEGACY $global:SI_Shodan_DcrName is REMOVED along with the legacy
        # table name -- honouring a retired scanner's DCR is what kept this engine
        # off the shared naming rule in the first place.
        'publicip' { [string]$global:SI_PublicIp_DcrName }
        default    { '' }
    }
    if (-not [string]::IsNullOrWhiteSpace($_perEngineDcrName)) {
        Write-SIInfo ("DCR override: '{0}' -> '{1}' (from `$global:SI_{2}_DcrName)" -f $dcrName, $_perEngineDcrName, $engineCap)
        $dcrName = $_perEngineDcrName
    }

    # v2.2.349 -- per-engine table-name override (mirrors the DCR override above).
    # Lets each engine name its table explicitly instead of taking the
    # SI_<Engine>_Profile pattern. publicip needs it for CASING, not for a
    # different name: the pattern title-cases the engine key to `Publicip`,
    # while the product declares `SI_PublicIP_Profile_CL` everywhere. The former
    # fallback to the legacy $global:SI_Shodan_TableName is REMOVED -- all four
    # profile engines now publish SI_<Engine>_Profile_CL and nothing else.
    $_perEngineTableName = switch ($RunContext.Engine.ToLowerInvariant()) {
        'endpoint' { [string]$global:SI_Endpoint_TableName }
        'identity' { [string]$global:SI_Identity_TableName }
        'azure'    { [string]$global:SI_Azure_TableName }
        'publicip' { [string]$global:SI_PublicIp_TableName }
        default    { '' }
    }
    if (-not [string]::IsNullOrWhiteSpace($_perEngineTableName)) {
        # Module appends _CL on ingest; strip a trailing _CL on customer-set value
        # so the canonical "SI_PublicIP_Profile_CL" config-value works as well as
        # the bare "SI_PublicIP_Profile".
        $_perEngineTableName = $_perEngineTableName -replace '_CL$',''
        Write-SIInfo ("Table override: '{0}' -> '{1}' (from `$global:SI_{2}_TableName)" -f $tableName, $_perEngineTableName, $engineCap)
        $tableName = $_perEngineTableName
    }

    # The legacy public-IP names are no longer honoured (3.0.0) -- say so ONCE per run instead of silently
    # starting a new table: an install carrying them would otherwise see its public-IP history "stop" with
    # nothing in any log to explain it.
    if ($RunContext.Engine -ieq 'publicip' -and -not $script:SILegacyPublicIpNamesReported) {
        $legacy = @(@('SI_Shodan_DcrName', 'SI_Shodan_TableName') | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string](Get-Variable -Name $_ -Scope Global -ValueOnly -ErrorAction SilentlyContinue)) })
        if ($legacy.Count) {
            $script:SILegacyPublicIpNamesReported = $true
            # The retired table is named from the customer's OWN legacy setting when there is one -- never
            # hard-coded here (the retired name must not live on in shipped code; RELEASENOTES names it).
            $oldTable = [string](Get-Variable -Name 'SI_Shodan_TableName' -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            $oldWhere = if ($oldTable) { "the previous table ($($oldTable -replace '_CL$','')_CL)" } else { 'the table the retired public-IP scanner wrote to' }
            $legacyMsg = ("{0} is no longer used: public IPs are now published to {1}_CL through DCR '{2}'. " -f ($legacy -join ' / '), $tableName, $dcrName) +
                         "Rows collected before 3.0.0 stay in $oldWhere -- query both for older history. " +
                         'Remove the old setting from config\SecurityInsight.custom.ps1 to silence this line.'
            Write-Warning $legacyMsg
        }
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
                             if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
                                 $_resolved = 'LocalMachine'
                                 foreach ($_s in 'LocalMachine','CurrentUser') {
                                     $_c = Get-ChildItem "Cert:\$_s\My" -ErrorAction SilentlyContinue |
                                           Where-Object { $_.Thumbprint -eq $_clean -and $_.HasPrivateKey } |
                                           Select-Object -First 1
                                     if ($_c) { $_resolved = $_s; break }
                                 }
                                 $_resolved
                             } else {
                                 # #209: no Cert: drive (a Linux container) -- read the X509Store instead.
                                 if (-not (Get-Command Get-SICertStoreLocation -ErrorAction SilentlyContinue)) {
                                     . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Find-SICertificate.ps1')
                                 }
                                 Get-SICertStoreLocation -Thumbprint $_clean
                             }
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
            $tok = Get-SIAzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
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
                if ($useCert -and -not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
                    # #209: a Linux container has no Cert: drive. Its entry point already signed in with the
                    # certificate's PFX (Connect-AzAccount -CertificatePath); a thumbprint re-sign-in here could
                    # only fail. The ingest itself goes through the token bridge.
                } elseif ($useCert) {
                    $null = Connect-SIAzAccount -ServicePrincipal `
                                              -Tenant                 $spnTenantId `
                                              -ApplicationId          $spnAppId `
                                              -CertificateThumbprint  $spnCertThumb `
                                              -ErrorAction Stop -WarningAction SilentlyContinue
                } elseif ($spnSecret) {
                    $secCred = [pscredential]::new($spnAppId, (ConvertTo-SecureString $spnSecret -AsPlainText -Force))
                    $null = Connect-SIAzAccount -ServicePrincipal `
                                              -Tenant $spnTenantId `
                                              -Credential $secCred `
                                              -ErrorAction Stop -WarningAction SilentlyContinue
                }
            } catch {
                Write-Warning ("LA ingest: SPN session refresh failed -- AzLogDcrIngestPS may 401: {0}" -f $_.Exception.Message)
            }
        }

        # A rule of this name that already feeds ANOTHER table is never repurposed (measured in the 2.2 -> 3.0 upgrade:
        # a 2.2 setup named its public-IP rule exactly like 3.0's default, and the update rewrote it -- the old flow was
        # gone and the post failed). This install's table gets a rule of its own, with a name derived from the resource
        # group, so every run picks the same one; nothing is written to the configuration file.
        if (Get-Command -Name Resolve-SILogDcrNameForTable -ErrorAction SilentlyContinue) {
            try {
                $_own = Resolve-SILogDcrNameForTable -DcrName $dcrName -DcrResourceGroup $global:SI_DcrResourceGroup -TableName $tableName `
                            -WorkspaceResourceId $global:SI_WorkspaceResourceId -Bound $authParams
                if ($_own.Reason) {
                    Write-SIInfo ('DCR: {0}' -f $_own.Reason)
                    $dcrName = $_own.Name
                    $_perEngineDcrName = $_own.Name   # a chosen name: the cross-scope rename below must not rename it again
                }
            } catch { Write-Verbose ("DCR ownership check skipped: {0}" -f $_.Exception.Message) }
        }

        Write-Host ''
        Write-SIInfo ('table : {0}_CL' -f $tableName)
        Write-SIInfo ('DCR   : {0}  (rg={1})' -f $dcrName, $global:SI_DcrResourceGroup)
        Write-SIInfo ('DCE   : {0}' -f $global:SI_DceName)
        Write-SIInfo ('auth  : {0}' -f $authNote)
        Write-SIInfo ('rows  : {0}' -f $flat.Count)

        # The workspace, the endpoint, the rules' resource group and the storage account are made by
        # setup, never by a run: the run's entry (Invoke-SIEngineRun.ps1) only checked that they are
        # there and that the identity may send (shared\SI-RunAccessCheck.ps1).

        # ---- canonical AzLogDcrIngestPS pattern (mirrors RA engine line 5914+) ----
        # Step 1: build full DCE + DCR caches via the standard helpers. Everything
        # downstream (CheckCreateUpdate, Post-*) reads these caches to resolve
        # name -> id / immutableId. Always rebuild fresh per ingest.
        $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null
        $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null

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
            $_ctx = Get-SIAzContext -ErrorAction SilentlyContinue
            if ($_ctx) {
                try {
                    $null = Get-SIAzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
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
                    $_schemaArr = Get-SILogSchemaArray -Data $schemaSample
                    $_needsCreate = $true
                    try {
                        $_needsCreate = [bool](Test-SILogTableDcrStatus `
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
                        $_tableSchema = Get-SILogSchemaHash -Data $schemaSample -ReturnType Table
                        $null = Set-SILogTable `
                            -AzLogWorkspaceResourceId  $global:SI_WorkspaceResourceId `
                            -SchemaSourceObject        $_tableSchema `
                            -TableName                 $tableName `
                            @authParams
                        # Step 3c -- create/update DCR.
                        $_dcrSchema = Get-SILogSchemaHash -Data $schemaSample -ReturnType DCR
                        $null = Set-SILogDcr `
                            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                            -SchemaSourceObject                         $_dcrSchema `
                            -DceName                                    $global:SI_DceName `
                            -DcrName                                    $dcrName `
                            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                            -TableName                                  $tableName `
                            -LogIngestServicePricipleObjectId           (Get-SILogIngestObjectId) `
                            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                            @authParams
                    } else {
                        Write-Output "Existing table+DCR already match schema -- no create/update needed."
                    }
                } else {
                    # Secret or MI path -- use the canonical combined function.
                    Update-SILogTableSchema `
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
            # A rule that feeds another table was refused before anything was written: posting through it could only fail.
            if ($_.Exception.Message -match 'already sends data to') { return ('FAILED: {0}' -f $_.Exception.Message) }
        }

        # This run had something to create (a table, a rule or a new column): may its identity do that? Asked only
        # now, read-only, and only then -- a run whose table and rule already carry every column needs no create role
        # and is told nothing. A missing role is ONE line with the setup command; the run goes on as before.
        if (Test-SIOutputSchemaChangeNeeded -CreateOutput $_createOutput) {
            if (-not (Get-Command -Name Write-SIRunAccessNote -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '..\shared\SI-RunAccessCheck.ps1') }
            Write-SIRunAccessNote -Need Create
        }

        # Step 4: re-sync caches after DCR provisioning. Newly-created DCR's
        # immutableId needs to land in ARG before Post-* can resolve it.
        # v2.2.250 -- bumped wait from 120s -> 240s. New-tenant scenarios (RG
        # was just created, ARG cold-start) routinely take 90-180s to index a
        # brand-new DCR. 120s was burning customer cycles on what's actually
        # just ARG eventual consistency.
        # Fix request 2a40d950 (owner 2026-10-22: no fixed limits): no 240 s give-up any more -- the rule is waited for until it
        # is READY and read back, with progress on every read; only a refusal (the create's, Azure's Failed state, or a refused
        # read) ends the wait, and its Microsoft answer is said (Wait-SIDcrReady, SI-LogIngest.ps1).
        $script:_dcrWaitN = 0
        $_probe = {
            $script:_dcrWaitN++
            $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null
            $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null
            # Filter to target sub/RG so the name-only lookup below can't pick
            # a cross-scope DCR's immutableId (which would be in another region).
            Apply-SIDcrScopeFilter -Scope ('wait-read-' + $script:_dcrWaitN) -DcrName $dcrName -DceName $global:SI_DceName `
                                   -SubscriptionId $global:SI_AzSubscriptionId `
                                   -DceResourceGroup $global:SI_DceResourceGroup `
                                   -DcrResourceGroup $global:SI_DcrResourceGroup
            $_dcrRow = @($global:AzDcrDetails | Where-Object { $_.name -eq $dcrName } | Select-Object -First 1)[0]
            if (-not $_dcrRow) { return $null }
            $_immId = if ($_dcrRow.properties -and $_dcrRow.properties.immutableId) { [string]$_dcrRow.properties.immutableId } elseif ($_dcrRow.immutableId) { [string]$_dcrRow.immutableId } else { '' }
            $_state = if ($_dcrRow.properties -and $_dcrRow.properties.provisioningState) { [string]$_dcrRow.properties.provisioningState } else { '' }
            @{ ImmutableId = $_immId; State = $_state }
        }
        $_wait = Wait-SIDcrReady -DcrName $dcrName -Probe $_probe -CreateOutput ([string]$_createOutput) -Location ([string]$global:SI_Location) -Log { param($m) Write-SIInfo $m }
        $_dcrReady = [bool]$_wait.Ready
        if (-not $_dcrReady) {
            Write-Warning ("DCR '{0}' is not ready after {1}s: {2} -- nothing is posted through it this run." -f $dcrName, $_wait.Waited, $_wait.Why)
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
            Write-Warning ("Microsoft's answer: {0}" -f $_wait.Why)
            Write-Warning "  - a 401 / 403: the identity is missing 'Monitoring Contributor' on the target subscription or resource group"
            # v2.2.258 -- abort the LA sink cleanly. Without this, the engine
            # proceeds to Build-DataArrayToAlignWithSchema + Post-* which then
            # throws "Cannot bind argument to parameter 'DcrImmutableId' because
            # it is an empty string" (the new DCR doesn't exist so the cache
            # lookup returns null). Confusing for the operator; the real cause
            # is right above this line.
            return ('FAILED: DCR ''{0}'' is not ready in the target resource group -- {1}. LA sink skipped to prevent confusing "DcrImmutableId empty" downstream error.' -f $dcrName, $_wait.Why)
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
        $DataVariable = Add-SIColumnData -Data $DataVariable `
                            -Column1Name Computer     -Column1Data $hostName `
                            -Column2Name ComputerFqdn -Column2Data $hostFqdn `
                            -Column3Name UserLoggedOn -Column3Data $hostUser `
                            -Verbose:$false 4>$null

        # 5c. Validate + normalize column names + align data structure with DCR schema.
        $DataVariable = Repair-SILogColumnName -Data $DataVariable -Verbose:$false 4>$null
        $DataVariable = Format-SILogRowsToSchema                 -Data $DataVariable -Verbose:$false 4>$null

        # Step 6: POST.
        $global:EnableCompressionDefault = $true
        $null = Send-SILogData `
                    -DceName     $global:SI_DceName `
                    -DcrName     $dcrName `
                    -Data        $DataVariable `
                    -TableName   $tableName `
                    @authParams `
                    -Verbose:$false 4>$null

        # #412 full asset metadata (SecurityInsight Pro, SI_AssetProperties = 'full'): the whole source objects this run
        # read ONCE, resolved to the rows just published and sent to SI_AssetProperties_CL with the SAME CollectionTime.
        # After the profile post on purpose: a profile that was not published gets no metadata either. Never throws -- a
        # failure is said and costs the profile nothing. At the security level this does nothing.
        if (Get-Command -Name Publish-SIFullAssetProperties -ErrorAction SilentlyContinue) { $null = Publish-SIFullAssetProperties -RunContext $RunContext -Rows @($flat) }

        # v3 data model: this run's provider records go to the database from Invoke-SIOutput (Write-SIOutputRecordsToSql),
        # NOT from here -- they used to be written at this line, so a post that failed, was skipped or returned early
        # above meant no records in the database for that run.

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

# =====================================================================================================================
#  THE DATABASE OUTPUT -- the run's records go to SQL on their own, whatever happened to the Log Analytics post
# =====================================================================================================================
# The records of a collection (what each provider returned, with the profile part the rows give them) live in the
# database: the CI build reads them there. They used to be written from INSIDE the Log Analytics function, after the
# profile post -- so a post that failed, was skipped (no sign-in for it), returned early, or was never asked for (sinks
# without 'LA') meant no records in the database for that run. Now the Output stage has two outputs that do not depend
# on each other, each with its own line in the run's result (SinkResults 'LA' and 'SQL'):
#   the post fails / is skipped / is not asked for  -> the records are still written and their collection is closed
#   the database cannot be written                  -> the post is as it was; the collection is NOT closed
# What a run then IS (engine\_shared\SI-RunOutcome.ps1): the post failed and the records are in the database =
# 'success-partial', Log Analytics named in the run-health record, the step ends well. The DATABASE failed = 'error',
# whatever else was written: the run throws, the step fails and the pipeline runs the source on its last good collection.
# The one thing that holds BOTH is the pre-ingest audit: rows with a dead key column are a verdict on the rows.

function Get-SIOutputRecordsSkipReason {
    <#
        PURE. Why this run writes NO records to the database at all ('' = it does): a dry run writes nothing but local
        files, mock data is never kept, a run without the record capture has none, and SI_DataModelRecords = off.
    #>
    param($RunContext, $CaptureState = $global:SIRecordCaptureState, $Setting = $global:SI_DataModelRecords)
    if ($RunContext -and $RunContext.PSObject.Properties['WhatIf'] -and [bool]$RunContext.WhatIf) { return 'a dry run writes nothing' }
    if ($RunContext -and $RunContext.PSObject.Properties['StorageContext'] -and $RunContext.StorageContext -and [string]$RunContext.StorageContext.Mode -eq 'Mock') { return 'mock data is never kept' }
    if ($null -eq $CaptureState) { return 'no records were captured' }
    if ($Setting -and ([string]$Setting).Trim().ToLowerInvariant() -in 'off', 'false', '0') { return 'the record capture is off' }
    ''
}

function Get-SIOutputRecordsResultText {
    <#
        PURE. What the database output reports, from what the record publish filled in (Publish-SIRecords -Outcome):
          'OK -- ...'       every record written and the collection closed -- or, in a part of a run, handed over
          'PARTIAL: ...'    the records are in the database and the collection is closed; only the optional copy to Log
                            Analytics (SI_LaExport) failed
          'FAILED: ...'     records could not be written, or the collection could not be closed: it is NOT complete
          'skipped (...)'   nothing to write here -- no records, or no database (the publish says that one itself)
        'skipped' in lower case is a correct, empty publish for the run's outcome; FAILED and PARTIAL are not.
    #>
    param([System.Collections.IDictionary]$Outcome = @{})
    $n = [int]$Outcome['Seen']
    switch ([string]$Outcome['State']) {
        'failed'      { return ('FAILED: the records could not be written to the database -- {0}. They keep their last good state.' -f [string]$Outcome['Error']) }
        'handed-over' { return ('OK -- {0} record(s) handed over; they are written once, with the rest of the run' -f $n) }
        'off'         { return 'skipped (the record capture is off)' }
        'no-database' { return 'skipped (no database is configured -- the records were not kept)' }
        'written' {
            $bad = [int]$Outcome['SqlFailed']
            if ($bad -gt 0 -or $Outcome['Closed'] -eq $false) {
                $why = if ($bad -gt 0) { '{0} of {1} record(s) could not be written to the database' -f $bad, $n } else { 'the collection could not be closed in the database' }
                return ('FAILED: {0} -- this collection is NOT complete; what it did not reach keeps its last good state' -f $why)
            }
            if ([int]$Outcome['ExportFailed'] -gt 0) {
                return ('PARTIAL: {0} record(s) are in the database and the collection is complete; the copy to Log Analytics (SI_LaExport) failed -- {1}' -f $n, [string]$Outcome['ExportError'])
            }
            return ('OK -- {0} record(s) -> the database ({1} changed), the collection is complete' -f $n, [int]$Outcome['Changed'])
        }
        default       { return 'skipped (no records to write)' }
    }
}

function Write-SIOutputRecordsToSql {
    <#
        THE DATABASE OUTPUT of a collection. Never throws; returns the output's result text (Get-SIOutputRecordsResultText).
        It does not look at what the Log Analytics post did: -Built is what the row builder handed over (Rows + Ready, or
        Held when the rows are not usable), -Why what the builder said when it could not build them.
        -Publish (tests): { param($RunContext, $Rows, $Outcome) } in place of Publish-SIRecords.
    #>
    param([Parameter(Mandatory)]$RunContext, [System.Collections.IDictionary]$Built = @{}, [string]$Why = '', [scriptblock]$Publish)
    try {
        if ([string]$Built['Held']) { return ('FAILED: {0}' -f [string]$Built['Held']) }
        if (-not $Built['Ready']) {
            $because = ($Why -replace '^(FAILED|SKIPPED)\s*[:\-]*\s*', '').Trim()
            return ('FAILED: the profile rows could not be built, so the records were not written{0} -- they keep their last good state' -f $(if ($because) { ' (' + $because + ')' } else { '' }))
        }
        if (-not $Publish -and -not (Get-Command -Name Publish-SIRecords -ErrorAction SilentlyContinue)) { return 'skipped (no records to write)' }
        $flat = @($Built['Rows'])
        $outcome = @{}
        if ($Publish) { $null = & $Publish $RunContext $flat $outcome }
        else { $null = Publish-SIRecords -RunContext $RunContext -ProfileRows @($flat) -Outcome $outcome }
        return (Get-SIOutputRecordsResultText -Outcome $outcome)
    } catch {
        return ('FAILED: the records could not be written to the database -- {0}. They keep their last good state.' -f $_.Exception.Message)
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
    # CIs follow the same scope (owner 2026-10-10): what the scope filters below leave out is marked on its provider records
    # after them (Select-SIRecordScopeMarks / Set-SIRecordScope), so the CI build leaves its CI out too.
    $scopeBefore = @($records)
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
            # ---- INSTRUMENTATION: WHY was each asset dropped? --------------------------------------
            # 🔴 ADDED 2026-08-28. This filter removed 143 of 236 endpoint assets (61%) on a real run
            # and the log could only say HOW MANY, not WHY -- so nothing could distinguish "the estate
            # really is that stale" from "a freshness signal is not reaching the filter". Four hours of
            # triangulating from Log Analytics could not settle it either, because the filter reads
            # METADATA and metadata never reaches LA. Count it where the decision is made.
            #
            # 🪤 AND IT MEASURES A SUSPECTED BUG RATHER THAN ASSUMING IT. The freshness lookup below
            # uses `$m.PSObject.Properties[$prop]`, which on a HASHTABLE finds NOTHING -- a hashtable's
            # PSObject exposes Count/Keys/Values, not its entries -- while the sensor-health check two
            # lines above uses member access, which works on BOTH shapes. Records reaching Output
            # through the staging blob arrive DESERIALISED (PSCustomObject); built in memory they are
            # hashtables. That asymmetry would produce exactly the observed symptom: sensor-active
            # assets survive and the freshness branch matches almost nothing. `_shapeSafe` counts what
            # a shape-tolerant read WOULD have found, so one run proves or kills it.
            $fx = [ordered]@{ NoMeta=0; Offboarded=0; Sensor=0; Fresh=0; DroppedNoSignal=0
                              MetaIsHashtable=0; MetaIsObject=0; ShapeSafeWouldKeep=0 }
            $fxBy = @{}   # which candidate key kept it
            $getMeta = {
                param($meta, $key)
                if ($null -eq $meta) { return $null }
                if ($meta -is [System.Collections.IDictionary]) {
                    if ($meta.Contains($key)) { return $meta[$key] } else { return $null }
                }
                $pp = $meta.PSObject.Properties[$key]
                if ($pp) { return $pp.Value }
                $null
            }
            $records = @($records | Where-Object {
                $m = $_.Metadata
                if (-not $m) { $fx.NoMeta++; return $true }   # no metadata -> can't decide, keep it
                if ($m -is [System.Collections.IDictionary]) { $fx.MetaIsHashtable++ } else { $fx.MetaIsObject++ }
                if ([string]$m.MDE_OnboardingStatus -eq 'Offboarded') { $fx.Offboarded++; return $false }
                $sensorActive = ([string]$m.MDE_SensorHealthState -in @('Active','ImpairedCommunication'))
                if ($sensorActive) { $fx.Sensor++; return $true }
                # Build the freshness candidate list. Default (mixed) accepts
                # MDE / EG / Entra freshness signals. SI_RequireMdeActive_Endpoint
                # narrows to MDE_LastSeen only.
                $candidates = if ($requireMdeActive) { @('MDE_LastSeen') } else { @('MDE_LastSeen','EG_LastSeen','ENTRA_ApproximateLastSignInDateTime') }
                # What a SHAPE-TOLERANT read would have concluded -- measured, never acted on, so this
                # run's published set is byte-identical to an uninstrumented one. If ShapeSafeWouldKeep
                # exceeds Fresh, the PSObject.Properties lookup below is the defect.
                foreach ($prop in $candidates) {
                    $sv = & $getMeta $m $prop
                    if ($sv) {
                        $sts = ConvertTo-SIUtcDateTimeOrNull $sv
                        if ($sts -and $sts -ge $staleCutoff.ToUniversalTime()) { $fx.ShapeSafeWouldKeep++; break }
                    }
                }
                foreach ($prop in $candidates) {
                    $p = $m.PSObject.Properties[$prop]
                    if ($p -and $p.Value) {
                        # Culture- and edition-safe (#123): a [datetime] is used as-is, a string is
                        # parsed invariant. The old [datetime]::Parse([string]$v) swapped day and
                        # month on a da-DK host whenever pwsh 7 had already parsed the value.
                        $ts = ConvertTo-SIUtcDateTimeOrNull $p.Value
                        if ($ts -and $ts -ge $staleCutoff.ToUniversalTime()) {
                            $fx.Fresh++
                            if (-not $fxBy.ContainsKey($prop)) { $fxBy[$prop] = 0 }
                            $fxBy[$prop]++
                            return $true
                        }
                    }
                }
                $fx.DroppedNoSignal++
                return $false
            })
            $dropped = $beforeCount - $records.Count
            $modeLabel = if ($requireMdeActive) { 'Strict (MDE-only)' } else { 'Mixed (MDE+EG+Entra, DEFAULT)' }
            Write-SIInfo ('asset filter [{0}, {1}d]: {2} -> {3} (dropped {4} inactive). Tighten with $global:SI_RequireMdeActive_Endpoint=$true; disable with $global:SI_IncludeInactive_Endpoint=$true.' -f $modeLabel, $staleDays, $beforeCount, $records.Count, $dropped)
            # 🔑 WHY, not just HOW MANY. A filter that can remove most of an estate has to say which
            # branch made the call, or "the estate is stale" and "a signal never reached the filter"
            # look identical from the outside -- and they did, for a whole session.
            $_by = if ($fxBy.Count) { ($fxBy.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join ', ' } else { 'none' }
            Write-SIInfo ('   filter detail: kept sensor-active={0} · kept fresh={1} ({2}) · no-metadata={3} | dropped offboarded={4} · no-signal={5}' -f `
                $fx.Sensor, $fx.Fresh, $_by, $fx.NoMeta, $fx.Offboarded, $fx.DroppedNoSignal)
            Write-SIInfo ('   metadata shape: hashtable={0} · object={1}' -f $fx.MetaIsHashtable, $fx.MetaIsObject)
            # 🔴 THE TRIPWIRE. The freshness lookup uses $m.PSObject.Properties[...], which finds NOTHING
            # on a hashtable (its PSObject exposes Count/Keys/Values, not its entries) while the
            # sensor-health check above uses member access and works on both shapes. If a shape-tolerant
            # read would have kept MORE assets than the real lookup did, that asymmetry is the defect --
            # not the estate being stale.
            if ($fx.ShapeSafeWouldKeep -gt $fx.Fresh) {
                Write-Warning ('asset filter: {0} asset(s) carry a FRESH timestamp that the current lookup cannot see (kept {1}). $m.PSObject.Properties[...] does not read hashtable metadata -- see the note above this filter.' -f $fx.ShapeSafeWouldKeep, $fx.Fresh)
            }

            # 🔴 SAY WHEN THIS FILTER IS DOING MOST OF THE WORK, because the same line reads the same
            # whether the estate really is stale or a DISCOVERY SOURCE FAILED upstream.
            # Measured 2026-08-13: 'EndpointEG' returned 0 rows after 180s (61 in ~12s when healthy).
            # It carries the last-seen activity signal, so 51 assets aged out of the window and this
            # filter dropped them -- 109 -> 20 where the two previous runs both gave 109 -> 71. The run
            # finished GREEN and the only trace was this line, which describes a correct decision.
            # The operator's inventory fell 72% and nothing called it a loss.
            #
            # This is a REPORTING line, not a threshold that changes behaviour: nothing is filtered
            # differently, and the numbers above are unchanged. It fires on a majority drop because
            # that is the point at which "the estate is stale" and "we failed to ask" stop being
            # distinguishable from the output alone -- and the answer is upstream, in the per-source
            # row counts, which is where it points.
            if ($dropped -gt 0 -and $beforeCount -gt 0 -and $dropped -gt ($beforeCount / 2)) {
                Write-SIWarn ('this filter removed MOST of the estate -- {0} of {1} assets ({2:n0}%). That is expected only if the estate really is that stale. Check the per-source row counts in DISCOVER first: a source that returned 0 rows takes its assets'' last-seen dates with it, and they are dropped here as "inactive" rather than reported as missing.' -f $dropped, $beforeCount, (100.0 * $dropped / $beforeCount))
            }
        } else {
            Write-SIInfo 'asset filter: DISABLED ($global:SI_IncludeInactive_Endpoint = $true) -- emitting all assets including stale registrations'
        }
    }

    # ---- IDENTITY engine: "exclude what the customer cannot act on" (DEFAULT ON) ----
    # 🔴 REWRITTEN 2026-08-27 after measuring it against a real tenant. The previous filter kept only
    # identities with a sign-in inside 30 days, and dropped 1548 of 1613. BOTH of its conditions beyond
    # "disabled" were wrong for identities:
    #
    #   1. 🔴 A CORRECTNESS DEFECT -- `if ($null -eq $m.ENTRA_LastSignInDays) { return $false }`.
    #      MEASURED: only 14 of 1613 identities carried ANY sign-in figure. The other 1599 had no
    #      RECORD, because the sign-in logs cover only what is ingested and retained -- which is not the
    #      same as no sign-in. The filter answered "do we hold recent telemetry about this identity?"
    #      and reported it as "is this identity active?". That is SI working rule 4 -- ABSENCE IS NOT
    #      REMEDIATION -- applied to inventory instead of findings: an identity we knew nothing about
    #      was deleted from the customer's view as though we had confirmed it idle.
    #
    #   2. A SCOPE DECISION, reversed by the operator (2026-08-27: "i was wrong before ... fully
    #      support the chg"). Dormancy is the OPPOSITE signal for an identity than for a device. A
    #      DEVICE unseen for 30 days is probably decommissioned. A CREDENTIAL unused for 30 days is
    #      standing privilege nobody is watching -- the orphan SP, the unused app registration holding
    #      consented Graph permissions, the dormant admin account an attacker prefers PRECISELY because
    #      no one looks at it. This engine's own discovery header names those as why SPs matter.
    #
    # 🔒 THE TEST IS ACTIONABILITY, NOT ACTIVITY (operator: "only problem is builtin spns. how can any
    #    customer do anything rgr their permissions"). A customer cannot change Microsoft's own
    #    first-party applications, so publishing 843 of them is noise that buries the real rows.
    #    But a first-party SP the tenant HAS consented permissions to is actionable -- consent can be
    #    revoked -- so the test is "did this tenant grant it anything?", never "who published it".
    #
    # 📌 MEASURED on the tenant this was built against: 1530 SPNs = 843 Microsoft first-party + 687
    #    tenant-owned (497 managed identities + 188 app registrations + 2), 13 disabled, and 47
    #    principals holding Microsoft Graph app-roles of which 46 are the tenant's own.
    # 🪤 MANAGED IDENTITIES ARE KEPT, and deliberately (operator: "a mi can own permissions. why exclude
    #    them"). 6 of those 47 Graph app-role holders are MIs holding 32 grants between them -- and that
    #    is only the GRAPH slice: an MI on a VM or container app typically holds AZURE RBAC instead,
    #    which is why ENTRA_AzureDelegations is one of the signals below.
    # 🪤 "HAS CREDENTIALS" IS DELIBERATELY NOT A SIGNAL. 500 SPNs carry credentials and 494 of them are
    #    managed-identity certificates Azure creates and rotates. It separates almost nothing, and it is
    #    not a customer action by itself.
    #
    # 🔒 OWNER DECISION 2026-10-10 -- "Everything, findings decide": DISABLED ACCOUNTS ARE PUBLISHED. This stage dropped
    #    every disabled account until then; on a large customer tenant that cut ~22,700 Graph users to ~8,940 published
    #    (0 disabled, 1 guest). The decision now lives in shared\SI-IdentityPublishScope.ps1 (pure, tested):
    #   DEFAULT : publish every user (enabled, disabled, guest) and every tenant-owned SP / MI; leave out only
    #             Microsoft first-party SPs this tenant granted nothing
    #   OPT-OUT : $global:SI_IncludeInactive_Identity     = $true  -- publish everything, Microsoft apps too
    #   TIGHTEN : $global:SI_RequireRecentSignIn_Identity = $true  -- restore the old sign-in behaviour
    #             (named to mirror $global:SI_RequireMdeActive_Endpoint above rather than inventing a
    #             second vocabulary for the same idea)
    if ($RunContext.Engine -ieq 'identity') {
        if (-not (Get-Command -Name Select-SIIdentityPublishScope -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-IdentityPublishScope.ps1')
        }
        $includeInactiveId = [bool](Get-Variable -Name 'SI_IncludeInactive_Identity'     -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        $requireSignInId   = [bool](Get-Variable -Name 'SI_RequireRecentSignIn_Identity' -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
        $staleDaysId       = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
        $idScope = Select-SIIdentityPublishScope -Records $records -IncludeAll:$includeInactiveId -RequireRecentSignIn:$requireSignInId -StaleDays $staleDaysId
        $records = @($idScope.Records)
        Write-SIInfo (Format-SIIdentityPublishScopeLine -Scope $idScope -StaleDays $staleDaysId)
    }

    # ---- CIs follow the collection scope: the records of what the scope left out are marked (in scope wins) ----
    # The kept assets' records are marked IN scope every run (no field is written for them) so that, collected in parts, the
    # record hand-over keeps IN SCOPE when another part left the same record out (in scope wins across parts too).
    if (($RunContext.Engine -ieq 'endpoint' -or $RunContext.Engine -ieq 'identity') -and (Get-Command -Name Set-SIRecordScope -ErrorAction SilentlyContinue)) {
        $scopeIn = @(Get-SIRecordScopeInIds -Kept $records)
        $scopeOut = @(); if ($scopeBefore.Count -ne $records.Count) { $scopeOut = @(Select-SIRecordScopeMarks -Before $scopeBefore -Kept $records) }
        $scopeMarked = Set-SIRecordScope -OutOfScopeIds $scopeOut -InScopeIds $scopeIn
        if ($scopeMarked -gt 0) { Write-SIInfo ('{0} collection: {1} provider record(s) of assets the scope settings leave out are marked -- their CIs are left out of the CI build too (kept as last built, findings not closed) until they are in scope again.' -f $RunContext.Engine, $scopeMarked) }
    }

    # ---- #533 (a): DISABLED accounts and devices, by SI_DisabledAssets_Collect (default on = collected) ----
    # Disabled = the directory SAID so (Entra accountEnabled / AD userAccountControl), never inactivity. Read on every run:
    # an account enabled again is collected again. Off = left out of every sink, with one line saying how many.
    if ($RunContext.Engine -ieq 'identity' -or $RunContext.Engine -ieq 'endpoint') {
        if (-not (Get-Command -Name Select-SIDisabledForStage -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-DisabledAssets.ps1')
        }
        $disSel = Select-SIDisabledForStage -Items @($records) -Stage Collect -StateOf { param($r) $r.Metadata } -Where ('{0} collection' -f $RunContext.Engine)
        $records = @($disSel.Kept)
        if ($disSel.Line) { Write-SIInfo $disSel.Line }
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

    # ---- Log Analytics and the database: two outputs, neither waits for the other ----
    # The profile rows are built ONCE (the row builder at the top of the Log Analytics function) and handed to both.
    # 'LA' is reported only when it was asked for; 'SQL' whenever this run keeps records (not a dry run, not mock data).
    $wantLa  = $RunContext.Sinks -contains 'LA'
    $wantSql = -not (Get-SIOutputRecordsSkipReason -RunContext $RunContext)
    if ($wantLa -or $wantSql) {
        if ($records.Count -gt 0) {
            $built = $null
            if ($wantSql) { $built = @{} }
            $laResult = $null
            try {
                $laResult = Write-SIClassificationToLogAnalytics -RunContext $RunContext -Records $records -Built $built -RowsOnly:(-not $wantLa)
            } catch {
                # Before the rows were whole there is nothing either output could write: the stage fails, as it always did.
                # After that it is the POST that failed -- said for Log Analytics, and the records still go to the database.
                if (-not ($built -and $built['Ready'])) { throw }
                $laResult = ('FAILED: {0}' -f $_.Exception.Message)
            }
            if ($wantLa) { $sinkResults['LA'] = $laResult }
            if ($wantSql) { $sinkResults['SQL'] = Write-SIOutputRecordsToSql -RunContext $RunContext -Built $built -Why ([string]$laResult) }
        } else {
            if ($wantLa)  { $sinkResults['LA']  = 'skipped (no records to write)' }
            if ($wantSql) { $sinkResults['SQL'] = 'skipped (no records to write)' }
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
