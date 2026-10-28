#Requires -Version 5.1
<#
    SI v3 Phase 5 -- PAYLOAD PROFILES: two projections over ONE collection pass.

    THE CUSTOMER REQUIREMENT (operator, 2026-08-12): extract ALL asset metadata for the CMDB feed, not
    only the security-relevant subset -- while NOT exploding the asset table into "10,000 columns, which
    is all asset types' possible fields". V3-ARCHITECTURE §3.6's answer is ARM's own model: a fixed typed
    envelope plus a `properties{}` bag. Typed columns for what every asset has; JSON for what only some
    asset types have. The level-4 exclusion (no CIs for NICs, public IPs, disks) then becomes STRUCTURAL
    rather than a policy someone has to remember: a NIC is a property inside the asset's JSON and there
    is no table it could become a row in.

    🔴 WHAT THE PLAN ASSUMED, AND WHAT WAS ACTUALLY THERE. §7's Phase 5 says "add a `cmdb` payload
    profile beside the existing `security` one; do NOT widen the default-deny includePaths." Measured
    2026-08-25: THERE IS NO PROFILE MECHANISM AND THERE IS NO DEFAULT-DENY.
      * `rawPayload.sources.<src>.includePaths` is read by exactly one file -- Get-SISchemaWithCustomMerge
        -- and that file only MERGES the customer overlay into it. No code ever PROJECTS by it.
      * The row builders copy every MDE_*/AZ_*/ENTRA_*/CMDB_* metadata key into Properties wholesale,
        prefix stripped. So `Properties` has always been "everything Collect happened to fetch".
      * The `_policy` string on each source therefore describes an intention, not a behaviour:
        "Only paths listed here flow to Properties.collect.mde. New MS fields are NOT auto-included."
        Both sentences were false.
      * `sizeBudgetKb: 256` and `truncationStrategy: drop_largest_field` are equally unimplemented --
        nothing measures a row and nothing truncates one. The stated risk ("drop_largest_field truncates
        SILENTLY") is inverted in practice: nothing truncates, so an oversized row fails the publish with
        PropertyValueTooLarge instead, which Invoke-Classify and FingerprintCache already have scars from.

    🔑 SO THE `cmdb` PROFILE IS NOT THE NEW THING -- today's behaviour already IS the cmdb profile. The
    new thing is `security`: the lean projection the policy has always claimed to be.

    🔒 AND THAT IS WHY THE DEFAULT DOES NOT CHANGE SILENTLY. Turning default-deny on for real REMOVES
    fields that consumers may bind to today, and Log Analytics keeps ~30 days with no backfill, so a
    wrong drop is not recoverable by re-running. Two rules follow, and neither is negotiable:
      1. The projection REPORTS what it drops, per run, by name. A silent drop here is the same defect
         class as the silent truncation this file exists to replace.
      2. `security` is opt-in until a run has been measured on real data. See Measure-SIPayloadProfiles.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12), and the profiler
    chassis chooses its own.
#>

# The profiles, and what each one MEANS. Kept as data rather than as branches so a third profile is a
# list entry rather than a new code path.
$script:SIPayloadProfiles = @{
    # Everything Collect fetched. This is the pre-2026-08-25 behaviour, unchanged, and it is what the
    # CMDB feed wants: "all asset metadata, not only the security-relevant subset".
    'cmdb'     = @{ Description = 'all collected metadata (CMDB feed -- §3.6)'; Enforce = $false }
    # Only what the schema declares. The default-deny the _policy always claimed.
    'security' = @{ Description = 'schema-declared includePaths only (default-deny)'; Enforce = $true }
}

function Get-SIPayloadProfileName {
    <#
        Which profile this run uses. `cmdb` is the default ON PURPOSE -- it is the CURRENT behaviour, so
        adopting this file changes nothing until someone opts in. Choosing `security` as the default
        would silently drop columns on every customer at once, which is exactly the failure mode the
        rest of this file is written to prevent.
    #>
    param()
    $v = $global:SI_PayloadProfile
    if ([string]::IsNullOrWhiteSpace([string]$v)) { return 'cmdb' }
    $name = ([string]$v).Trim().ToLowerInvariant()
    if (-not $script:SIPayloadProfiles.ContainsKey($name)) {
        # Fail LOUD but do not die: an unknown profile name must never silently become default-deny and
        # start dropping data. Falling back to the widest profile is the safe direction.
        Write-Warning ("SI_PayloadProfile '{0}' is not a known profile ({1}) -- falling back to 'cmdb' (all collected metadata)." -f `
            $v, ((@($script:SIPayloadProfiles.Keys) | Sort-Object) -join ', '))
        return 'cmdb'
    }
    return $name
}

function Get-SIPayloadAllowedKeys {
    <#
        The allowed key set for one source bucket under one profile, derived from the schema's declared
        includePaths.

        Returns $null when the profile does not enforce, and $null is DELIBERATELY DIFFERENT from an
        empty set: "no opinion, pass everything through" vs "this source is declared to carry nothing".
        Collapsing the two would turn a missing schema section into total data loss for that source.

        🪤 THE PATHS AND THE KEYS ARE NOT THE SAME VOCABULARY. includePaths are JSON paths against the
        RAW provider document (`computerDnsName`, `machineTags[*]`, `NodeProperties.rawData.deviceType`).
        The Properties bucket holds PREFIX-STRIPPED METADATA KEYS the discovery layer chose
        (`MDE_MachineTags` -> `MachineTags`). So matching is on the LAST path segment, case-insensitively,
        with the `[*]` array marker stripped -- which is what actually lines the two lists up. Anything
        stricter silently drops everything, and this file's whole job is to not do that.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Schema,
        [Parameter(Mandatory)][string]$SourceName,
        [Parameter()][string]$ProfileName
    )
    if ([string]::IsNullOrWhiteSpace($ProfileName)) { $ProfileName = Get-SIPayloadProfileName }
    $def = $script:SIPayloadProfiles[$ProfileName]
    if (-not $def -or -not $def.Enforce) { return $null }

    $paths = @()
    try {
        if ($Schema -and $Schema.PSObject.Properties['rawPayload'] -and $Schema.rawPayload -and
            $Schema.rawPayload.PSObject.Properties['sources'] -and $Schema.rawPayload.sources -and
            $Schema.rawPayload.sources.PSObject.Properties[$SourceName]) {
            $src = $Schema.rawPayload.sources.$SourceName
            if ($src.PSObject.Properties['includePaths'] -and $src.includePaths) { $paths = @($src.includePaths) }
        }
    } catch { return $null }
    # A source the schema says nothing about is UNDECLARED, not DENIED. Enforcing an empty allow-list
    # here would delete a whole bucket because someone forgot to describe it.
    if ($paths.Count -eq 0) { return $null }

    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $paths) {
        $s = [string]$p
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        $s = $s -replace '\[\*\]', ''
        $leaf = ($s -split '\.')[-1]
        if (-not [string]::IsNullOrWhiteSpace($leaf)) { [void]$keys.Add($leaf.Trim()) }
    }
    # 🪤 `,$keys` NOT `$keys`. PowerShell UNROLLS an enumerable on return, so a bare `return $keys` hands
    # the caller a plain string[] -- and [string[]]::Contains() is CASE-SENSITIVE, while this HashSet was
    # built OrdinalIgnoreCase precisely because the two vocabularies differ in case (`machineTags[*]` in
    # the schema vs `MachineTags` as the metadata key). The comparer survived the constructor and was
    # then thrown away by the return statement, so EVERY key missed the allow-list and the projection
    # silently dropped the WHOLE bucket. Found by the tests, not by reading it.
    return ,$keys
}

function Select-SIPayloadBucket {
    <#
        Project one Properties bucket through the profile. Returns the bucket to emit, and NAMES what it
        removed so the caller can report it.

        Never mutates the input: the same metadata bag feeds the typed columns, and a projection that
        edited it in place would silently blank columns that have nothing to do with Properties.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Bucket,
        [Parameter()][AllowNull()]$AllowedKeys,
        [Parameter()][string]$SourceName = ''
    )
    if ($null -eq $Bucket) { return [pscustomobject]@{ Bucket = $null; Dropped = @() } }
    # $null AllowedKeys = the profile does not enforce for this source. Pass through untouched.
    if ($null -eq $AllowedKeys) { return [pscustomobject]@{ Bucket = $Bucket; Dropped = @() } }
    if ($Bucket -isnot [System.Collections.IDictionary]) {
        return [pscustomobject]@{ Bucket = $Bucket; Dropped = @() }
    }

    # 🔒 RE-NORMALISE TO A CASE-INSENSITIVE SET even though the producer returns one. If an allow-list
    # ever arrives here as a plain array -- one dropped comma on a return statement is all it takes --
    # [string[]]::Contains() is case-SENSITIVE and this function would drop EVERY field in the bucket
    # while looking like it worked. That exact bug shipped in the first draft of this file and only the
    # tests caught it. One allocation per bucket is a cheap price for it never recurring silently.
    if ($AllowedKeys -isnot [System.Collections.Generic.HashSet[string]]) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($a in @($AllowedKeys)) { if ($a) { [void]$set.Add([string]$a) } }
        $AllowedKeys = $set
    }

    $kept    = @{}
    $dropped = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Bucket.Keys)) {
        if ($AllowedKeys.Contains([string]$k)) { $kept[$k] = $Bucket[$k] }
        else { [void]$dropped.Add(('{0}.{1}' -f $SourceName, $k)) }
    }
    [pscustomobject]@{ Bucket = $kept; Dropped = @($dropped.ToArray()) }
}

function Measure-SIPayloadSize {
    <#
        The size of one Properties bag as it will actually be published, against the schema's declared
        budget.

        🔴 THIS ONLY MEASURES AND REPORTS. It does NOT truncate, and that is a decision rather than an
        omission. `truncationStrategy: drop_largest_field` has never been implemented, and implementing
        it now would introduce SILENT metadata loss into the exact path §3.6 warns about -- a customer
        would lose the field that matters most (the biggest one, usually the raw blob) with no error and
        no way to tell from the output. An oversized row failing loudly at publish is the better
        outcome, and it is also today's behaviour, so this changes nothing except that the operator now
        finds out BEFORE the publish rather than from a 400.

        Measured in UTF-8 bytes of the serialised JSON, because that is what the ingest endpoint counts.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Properties,
        [Parameter()][AllowNull()]$Schema,
        [Parameter()][int]$BudgetKb = 0
    )
    if ($BudgetKb -le 0) {
        $BudgetKb = 256
        try {
            if ($Schema -and $Schema.PSObject.Properties['rawPayload'] -and $Schema.rawPayload -and
                $Schema.rawPayload.PSObject.Properties['sizeBudgetKb'] -and $Schema.rawPayload.sizeBudgetKb) {
                $BudgetKb = [int]$Schema.rawPayload.sizeBudgetKb
            }
        } catch { }
    }

    $bytes = 0
    if ($null -ne $Properties) {
        try {
            $json  = ConvertTo-Json -InputObject $Properties -Depth 12 -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetByteCount([string]$json)
        } catch {
            # A bag that cannot even be serialised is a real problem, but not this function's to raise.
            return [pscustomobject]@{ Bytes = -1; BudgetBytes = ($BudgetKb * 1024); OverBudget = $false; PercentOfBudget = 0; LargestField = ''; Error = $_.Exception.Message }
        }
    }
    $budgetBytes = $BudgetKb * 1024

    # Name the biggest top-level contributor. If the row ever does go over, this is the field that would
    # have been dropped -- so saying it now is what makes the budget actionable instead of alarming.
    $largest = ''; $largestBytes = 0
    if ($Properties -is [System.Collections.IDictionary]) {
        foreach ($k in @($Properties.Keys)) {
            try {
                $b = [System.Text.Encoding]::UTF8.GetByteCount([string](ConvertTo-Json -InputObject $Properties[$k] -Depth 12 -Compress))
                if ($b -gt $largestBytes) { $largestBytes = $b; $largest = [string]$k }
            } catch { }
        }
    }

    [pscustomobject]@{
        Bytes           = $bytes
        BudgetBytes     = $budgetBytes
        OverBudget      = ($bytes -gt $budgetBytes)
        PercentOfBudget = if ($budgetBytes -gt 0) { [math]::Round(($bytes / $budgetBytes) * 100, 1) } else { 0 }
        LargestField    = $largest
        LargestBytes    = $largestBytes
        Error           = ''
    }
}

function Reset-SIPayloadStats {
    <#
        Clear the per-run accumulator. Called at the start of a run: without it a long-lived process
        (the container job runs several engines in one session) would report the PREVIOUS engine's
        fattest asset as this one's, which is worse than reporting nothing.
    #>
    param()
    $script:SIPayloadStats = @{
        Rows = 0; MaxBytes = 0; MaxAsset = ''; OverBudget = 0
        BudgetBytes = 0; LargestField = ''; DroppedKeys = @{}
    }
}

function Get-SIPayloadStats { $script:SIPayloadStats }

function Write-SIPayloadSummary {
    <#
        ONE run-summary line, plus a warning when it matters. This is the half that makes the projection
        and the budget honest: v2.2.436's lesson was that a source returning nothing must SAY so, and the
        same applies to a payload silently shedding fields or creeping toward the ingest limit.

        Uses Write-SIInfo / Write-SIWarn when the chassis is loaded and falls back to Write-Host /
        Write-Warning when it is not, so the diagnostics/ scripts can call it without dragging in the chassis.
    #>
    param([Parameter()][AllowNull()]$Stats)
    if ($null -eq $Stats) { $Stats = $script:SIPayloadStats }
    if ($null -eq $Stats -or [int]$Stats.Rows -le 0) { return }

    $info = { param($m) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m } }
    $warn = { param($m) if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $m } else { Write-Warning $m } }

    $prof     = Get-SIPayloadProfileName
    $maxKb    = [math]::Round($Stats.MaxBytes / 1024, 1)
    $budgetKb = [math]::Round($Stats.BudgetBytes / 1024, 1)
    $pct      = if ([int]$Stats.BudgetBytes -gt 0) { [math]::Round(($Stats.MaxBytes / $Stats.BudgetBytes) * 100, 1) } else { 0 }

    & $info ("   [payload] profile '{0}' -- {1} row(s), largest {2} KB of {3} KB budget ({4}%) on '{5}'{6}" -f `
        $prof, $Stats.Rows, $maxKb, $budgetKb, $pct, $Stats.MaxAsset,
        $(if ($Stats.LargestField) { (" -- biggest field: {0}" -f $Stats.LargestField) } else { '' }))

    # NAME the dropped keys. "N fields dropped" is not actionable; a customer needs to know WHICH, and
    # this is the only place that knows. Capped for readability with the count stated, never truncated
    # in silence (house rule: every silent cap says what it dropped).
    $dropped = @($Stats.DroppedKeys.Keys | Sort-Object)
    if ($dropped.Count -gt 0) {
        $shown = @($dropped | Select-Object -First 12)
        & $warn ("   [payload] profile '{0}' DROPPED {1} distinct field(s) from Properties: {2}{3}" -f `
            $prof, $dropped.Count, ($shown -join ', '),
            $(if ($dropped.Count -gt $shown.Count) { (' ... and {0} more (set $global:SI_PayloadProfile = ''cmdb'' to keep everything)' -f ($dropped.Count - $shown.Count)) } else { '' }))
    }

    # 🔴 The budget is a HARD ingest limit, not advice. Over it, the publish fails with
    # PropertyValueTooLarge and the row is lost -- so this must be a warning before the publish, not a
    # discovery afterwards. Nothing truncates: see Measure-SIPayloadSize for why that is deliberate.
    if ([int]$Stats.OverBudget -gt 0) {
        & $warn ("   [payload] {0} row(s) EXCEED the {1} KB budget and WILL FAIL to publish (PropertyValueTooLarge). Nothing truncates them. Largest: '{2}' at {3} KB, biggest field '{4}'." -f `
            $Stats.OverBudget, $budgetKb, $Stats.MaxAsset, $maxKb, $Stats.LargestField)
    } elseif ($pct -ge 80) {
        & $warn ("   [payload] largest row is at {0}% of the {1} KB budget -- headroom is thin; a wider profile or a fatter asset type will break the publish." -f $pct, $budgetKb)
    }
}

function Add-SIPayloadMeasurement {
    <#
        Record one row's payload against the run accumulator.

        🔑 A FUNCTION RATHER THAN A SHARED `$script:` VARIABLE, deliberately. The row builder and this
        file are separate .ps1 files that are sometimes dot-sourced into the same scope (the engine run)
        and sometimes not (Pester dot-sources each file on its own, and the row builder lazily
        dot-sources this one INSIDE a function, which binds to that function's scope). Under the second
        shape a `$script:`-scoped counter written by one file is invisible to the other, so the summary
        would report 0 rows while the projection was demonstrably running -- a silent-zero that looks
        exactly like "the feature is off". Going through the accessor makes the accumulator belong to
        exactly one file no matter how the caller loaded things.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Properties,
        [Parameter()][AllowNull()]$Schema,
        [Parameter()][string]$AssetName = '',
        [Parameter()][string[]]$Dropped = @()
    )
    if ($null -eq $script:SIPayloadStats) { Reset-SIPayloadStats }
    $m = Measure-SIPayloadSize -Properties $Properties -Schema $Schema
    $script:SIPayloadStats.Rows++
    $script:SIPayloadStats.BudgetBytes = $m.BudgetBytes
    if ($m.Bytes -gt $script:SIPayloadStats.MaxBytes) {
        $script:SIPayloadStats.MaxBytes     = $m.Bytes
        $script:SIPayloadStats.MaxAsset     = if ($AssetName) { $AssetName } else { '(unnamed)' }
        $script:SIPayloadStats.LargestField = [string]$m.LargestField
    }
    if ($m.OverBudget) { $script:SIPayloadStats.OverBudget++ }
    foreach ($d in $Dropped) { if ($d) { $script:SIPayloadStats.DroppedKeys[$d] = $true } }
    return $m
}
