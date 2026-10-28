#Requires -Version 5.1
<#
    SI v3 -- FULL ASSET PROPERTIES, the optional wide pull. Core: the mode gate, the narrow baselines,
    the row builder and the size budget.

    DESIGN: docs/V3-ARCHITECTURE.md 3.6b (this add-on) and 4.9 (the two CMDB scenarios that consume it).

    🔑 WHY THIS IS A SEPARATE ADD-ON AND NOT A WIDER PAYLOAD PROFILE. Phase 5's Get-SIPayloadProfile.ps1
    ships two profiles -- `cmdb` (everything Collect fetched) and `security` (schema includePaths only)
    -- and reading the name `cmdb` you would conclude 3.6 is delivered. It is not. A payload profile is
    a PROJECTION over what Collect already fetched, and the pull is decided upstream in the SOURCE
    QUERY, which three of the four engines curate security-first:

        endpoint  17 hand-picked keys out of the MDE machine object   (Get-DiscoveryFromMDE.ps1)
        identity  $select= 9 device / 13 user / 15 service-principal   (Get-DiscoveryFromEntra*.ps1)
        azure     ARG projects `properties` VERBATIM -- already full   (Get-DiscoveryFromAzureResources.ps1)
        publicip  level 4 by 3.6's own rule -- a property, never a CI. EXCLUDED, no exceptions.

    A field the query never asked for cannot be projected back into existence -- so the narrowing has to
    be removed IN the source query.

    🔄 #412 (operator 2026-10-06): "we dont pull in the same data twice (limited and full) ... if we do
    asset full, then it is 100% the same fields as limited - but with the extra metadata." The old rule --
    a separate add-on that read every source a SECOND time so the profiler stayed untouched -- is
    SUPERSEDED. Now:
      security  the source queries and every SI_*_Profile_CL row are EXACTLY as before (the Community
                edition's only level; asserted by SIv3-OnePullSecurityParity).
      full      each profiler reads each source ONCE with the narrowing removed, builds the SAME security
                row from that object (golden tests), and keeps the whole object; this library then turns
                the kept objects into SI_AssetProperties_CL rows (SI-AssetPropertiesProfiler.ps1). Still
                no key in any discovery record, no column in any profile schema -- the table is its own.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# The reserved table. Not a profile table, deliberately: it has no typed columns beyond the envelope,
# so it cannot drift, and nothing reports off it.
$script:SIAssetPropertiesTable = 'SI_AssetProperties'
$script:SIAssetPropertiesDcr   = 'dcr-si-assetproperties'

# 🔑 THE BUDGET, AND IT IS ENFORCED HERE BECAUSE IT IS ENFORCED NOWHERE ELSE. The profile schemas
# declare `sizeBudgetKb: 256` with `truncationStrategy: drop_largest_field`; measured 2026-08-25,
# NOTHING measures a row and NOTHING truncates one. The stated risk (silent truncation) is inverted in
# practice -- an oversized row fails the whole publish with PropertyValueTooLarge, taking the batch
# with it. A wide payload is by definition fatter, so this engine measures every row.
$script:SIAssetPropertiesBudgetBytes = 256KB

# 🪤 THE SERIALISATION DEPTH, AND IT IS A DATA-LOSS SURFACE, NOT A TUNING KNOB. Past this depth
# ConvertTo-Json writes the .NET TYPE NAME in place of the sub-tree -- no error, no omission, just
# `"System.Management.Automation.PSCustomObject"` where a branch used to be. 16 clears every ARM
# `properties{}` shape measured so far with room to spare; Get-SIAssetPropertyMaxDepth reports any row
# that gets close, so the number is checked against reality rather than believed.
$script:SIAssetPropertiesJsonDepth = 16

# The NARROW baseline per source: exactly what the security path asks for today. Held as data so the
# widening report can name the delta rather than print a count -- 3.6b rule 2: a wide pull that
# silently returns the narrow set looks exactly like a wide pull that worked.
$script:SIAssetPropertiesNarrowBaseline = @{
    # Get-DiscoveryFromMDE.ps1's emit block, in source vocabulary (MDE_ prefix stripped).
    # 🔴 CORRECTED 2026-08-31 AGAINST THE LIVE API, and the corrections are the point of this list.
    # Measured across 146 machines, /api/machines returns 30 property names. The baseline used to claim
    # five it does not return: `osVersion` (the field is `version`), plus `publicIp`,
    # `vulnerabilityCount`, `missingKbCount` and `defenderAvStatus`, which are not machine-list
    # properties at all. A baseline that names fields the source never sends makes the widening report
    # cry "the source changed upstream" on every single run -- and an alarm that is always on is an
    # alarm nobody reads, which would have cost the one real catch this check has already made.
    'mde' = @(
        'id','computerDnsName','osPlatform','version','osProcessor','healthStatus','riskScore',
        'exposureLevel','onboardingStatus','rbacGroupName','machineTags','lastSeen','firstSeen',
        'aadDeviceId','managedBy','managedByStatus'
    )
    # Get-DiscoveryFromEntra.ps1:40 -- the device $select.
    'entra-device' = @(
        'id','deviceId','displayName','operatingSystem','deviceCategory','trustType','profileType',
        'registrationDateTime','approximateLastSignInDateTime'
    )
    # Get-DiscoveryFromEntraUsers.ps1:88 -- the user $select.
    'entra-user' = @(
        'id','displayName','userPrincipalName','accountEnabled','createdDateTime','jobTitle',
        'department','onPremisesSyncEnabled','mail','userType','assignedLicenses','signInActivity',
        'customSecurityAttributes'
    )
    # Get-DiscoveryFromEntraServicePrincipals.ps1:94 -- the SPN $select.
    'entra-serviceprincipal' = @(
        'id','displayName','appId','servicePrincipalType','signInAudience','accountEnabled',
        'publisherName','verifiedPublisher','appOwnerOrganizationId','passwordCredentials',
        'keyCredentials','tags','homepage','customSecurityAttributes','createdDateTime'
    )
    # ARG already projects `properties` verbatim, so there is no narrowing to undo. The baseline is the
    # full set and the widening report will correctly show a delta of zero -- which is the honest
    # answer, not a missing measurement.
    'arm' = @()
    # The metadata additions (#301). None of these is pulled by the security path at all, so there is no
    # narrowing to undo: every field they return is new, and the widening report says so by name.
    'arm-vm-extension' = @()
    'ad-computer'      = @()
    'exposure-graph'   = @()
    'intune-device'    = @()
}

function Get-SIAssetPropertiesMode {
    <#
        Which mode this run is in.

        🔒 `security` IS THE DEFAULT AND IT MEANS OFF. Enabling the wide pull costs Log Analytics ingest
        on every asset every run, and 3.6b rule 5 makes that a per-customer decision that must be
        visible before it is paid. An add-on that switched itself on would not be optional.

        An unknown value falls back to `security` -- the NARROW direction. Note this is the opposite
        default to Get-SIPayloadProfileName, and deliberately so: there, falling back to the widest
        profile is safe because the alternative silently DROPS columns customers already read. Here the
        widest option silently ADDS cost and data nobody asked for, so the safe direction reverses.
    #>
    param()
    $v = $global:SI_AssetProperties
    if ([string]::IsNullOrWhiteSpace([string]$v)) { return 'security' }
    $name = ([string]$v).Trim().ToLowerInvariant()
    if ($name -eq 'full' -or $name -eq 'security') { return $name }
    Write-Warning ("SI_AssetProperties '{0}' is not a known mode (full, security) -- falling back to 'security' (the wide pull stays OFF)." -f $v)
    'security'
}

function Test-SIAssetPropertiesEnabled {
    param()
    (Get-SIAssetPropertiesMode) -eq 'full'
}

function Get-SIAssetPropertiesNarrowBaseline {
    <#
        The narrow field list for one source. Returns an EMPTY array for a source with no narrowing
        (arm), and an empty array for an unknown source -- both mean "nothing to subtract", which makes
        the widening report say `+N` rather than silently reporting no widening at all.

        🪤 NO `,@(...)` WRAPPER, AND THAT IS DELIBERATE -- IT WAS WRITTEN WITH ONE AND IT WAS WRONG.
        The comma preserves a single-element array through `return`, but EVERY caller here already
        wraps in `@(...)`, and `@(<array containing an array>)` counts **1**. Measured when this file
        was first run: the widening report saw one element (an object[]), so `Added` was 1 for every
        source, and `$select=id,System.Object[]` reached a live Graph URL. This is the third time this
        trap has been paid for in this codebase. **Return plainly; let the caller's `@()` do the work.**
    #>
    param([Parameter(Mandatory)][string]$SourceSystem)
    $k = $SourceSystem.Trim().ToLowerInvariant()
    if ($script:SIAssetPropertiesNarrowBaseline.ContainsKey($k)) {
        return @($script:SIAssetPropertiesNarrowBaseline[$k])
    }
    @()
}

function Add-SIAssetPropertyLeafPath {
    <#
        The recursive half of the leaf walk. It APPENDS INTO AN ACCUMULATOR rather than returning a
        collection, and that shape is the fix for a real defect rather than a style preference.

        🪤 THE FIRST VERSION RECURSED ON ITS OWN RETURN VALUE, WHICH WAS COMMA-WRAPPED. Each nested
        call handed back an array CONTAINING an array, the parent added that single element, and the
        whole walk collapsed to one object[]: PropertyCount was 1 for every asset and the report said
        `+1 field` for every source. It PARSED, it RAN, and every number it produced was wrong -- the
        same trap the previous session's own guard was defeated by. An accumulator cannot be unrolled,
        so the shape removes the trap instead of documenting it.

        Arrays collapse to `a[]` rather than `a[0]`, `a[1]` -- an estate where one machine has three
        NICs and another has one must not read as schema drift, and PropertyCount is the number 3.6b
        rule 4 leans on to make a genuine upstream change visible.
    #>
    param(
        [Parameter(Mandatory)]$Accumulator,
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [string]$Prefix = '',
        [int]$Depth = 0,
        [int]$MaxDepth = 12
    )
    if ($null -eq $InputObject -or $Depth -gt $MaxDepth) { return }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in @($InputObject.Keys)) {
            $p = if ($Prefix) { "$Prefix.$k" } else { [string]$k }
            Add-SIAssetPropertyLeafPath -Accumulator $Accumulator -InputObject $InputObject[$k] -Prefix $p -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
    } elseif ($InputObject -is [string]) {
        # BEFORE the IEnumerable test. A string enumerates as characters in PowerShell, and treating
        # one as an array turns every string value into a per-character walk.
        if ($Prefix) { [void]$Accumulator.Add($Prefix) }
    } elseif ($InputObject -is [System.Collections.IEnumerable]) {
        $p = if ($Prefix) { "$Prefix[]" } else { '[]' }
        $seen = $false
        foreach ($item in $InputObject) {
            $seen = $true
            Add-SIAssetPropertyLeafPath -Accumulator $Accumulator -InputObject $item -Prefix $p -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
        # An EMPTY array is still a property the source declared. Dropping it would make a machine with
        # no tags look like a machine whose schema lacks tags.
        if (-not $seen -and $p) { [void]$Accumulator.Add($p) }
    } elseif ($InputObject -is [psobject] -and $InputObject.PSObject.Properties.Count -gt 0 -and
              -not ($InputObject -is [ValueType])) {
        foreach ($prop in $InputObject.PSObject.Properties) {
            $p = if ($Prefix) { "$Prefix.$($prop.Name)" } else { [string]$prop.Name }
            Add-SIAssetPropertyLeafPath -Accumulator $Accumulator -InputObject $prop.Value -Prefix $p -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
    } else {
        if ($Prefix) { [void]$Accumulator.Add($Prefix) }
    }
}

function Get-SIAssetPropertyLeafPath {
    <#
        Every leaf path in one object, as `a.b.c`. Depth-capped: a cycle cannot occur in JSON-sourced
        data, but a pathological nesting can, and this runs once per asset per run.

        🔑 DISTINCT PATHS, AND THAT IS THE WHOLE POINT OF THE `a[]` COLLAPSE. Every element of an
        array yields the same path, so a raw walk counts ARRAY LENGTH: a machine with three tags and a
        machine with one would report different PropertyCounts, and the drift signal 3.6b rule 4 rests
        on would fire on ordinary estate variation instead of on an upstream schema change. Caught by
        running it -- the collapse was implemented and the dedupe it implies was not, so the code
        contradicted the comment directly above it.

        Returns plainly. Callers wrap in `@(...)`, which is what preserves a single-leaf result -- see
        the note on Get-SIAssetPropertiesNarrowBaseline for why a `,` wrapper here was actively wrong.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [int]$MaxDepth = 12
    )
    $acc = New-Object System.Collections.ArrayList
    Add-SIAssetPropertyLeafPath -Accumulator $acc -InputObject $InputObject -Prefix '' -Depth 0 -MaxDepth $MaxDepth

    # Order-stable dedupe. Sort-Object -Unique would also dedupe but reorders, and two runs over the
    # same asset should produce a byte-identical path list so a diff means something.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $out  = New-Object System.Collections.ArrayList
    foreach ($p in $acc) { if ($seen.Add([string]$p)) { [void]$out.Add([string]$p) } }
    @($out.ToArray())
}

function Get-SIAssetPropertyTopLevelName {
    <#
        The top-level property names of one source object -- the vocabulary the narrow baselines are
        written in, so the widening delta compares like with like. Leaf paths would not: the baseline
        says `machineTags`, the leaf walk says `machineTags[]`.
    #>
    param([Parameter(Mandatory)][AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Collections.IDictionary]) { return @($InputObject.Keys | ForEach-Object { [string]$_ }) }
    if ($InputObject -is [psobject]) { return @($InputObject.PSObject.Properties.Name) }
    @()
}

function Get-SIAssetPropertyMaxDepth {
    <#
        How deep the object actually nests.

        🔴 THIS EXISTS BECAUSE `ConvertTo-Json -Depth` TRUNCATES SILENTLY AND UGLY. Past the depth
        limit PowerShell does not error and does not omit the branch -- it writes the .NET TYPE NAME as
        a string, so `properties.networkProfile` becomes
        `"System.Management.Automation.PSCustomObject"`. The row publishes, the column is populated,
        the byte count looks healthy, and the sub-tree is gone. An Azure resource's `properties{}` is
        exactly where that bites: ARM nests deeply and unevenly, so it would hit some resource types
        and not others -- the hardest kind of loss to notice.

        So the depth is MEASURED per row and reported when it approaches the serialisation limit,
        rather than trusted.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [int]$Depth = 0,
        [int]$Ceiling = 40
    )
    if ($null -eq $InputObject -or $Depth -ge $Ceiling) { return $Depth }
    $max = $Depth
    if ($InputObject -is [string]) { return $Depth }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in @($InputObject.Keys)) {
            $d = Get-SIAssetPropertyMaxDepth -InputObject $InputObject[$k] -Depth ($Depth + 1) -Ceiling $Ceiling
            if ($d -gt $max) { $max = $d }
        }
    } elseif ($InputObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $InputObject) {
            $d = Get-SIAssetPropertyMaxDepth -InputObject $item -Depth ($Depth + 1) -Ceiling $Ceiling
            if ($d -gt $max) { $max = $d }
        }
    } elseif ($InputObject -is [psobject] -and $InputObject.PSObject.Properties.Count -gt 0 -and -not ($InputObject -is [ValueType])) {
        foreach ($p in $InputObject.PSObject.Properties) {
            $d = Get-SIAssetPropertyMaxDepth -InputObject $p.Value -Depth ($Depth + 1) -Ceiling $Ceiling
            if ($d -gt $max) { $max = $d }
        }
    }
    $max
}

function New-SIAssetPropertyRow {
    <#
        One row of SI_AssetProperties_CL.

        One row per (object, SOURCE SYSTEM) -- 60.5.5b's ruling, not one merged row. A server that is
        both an MDE machine and an ARM resource contributes two rows, and the CMDB feed decides
        precedence with the field map rather than the collector deciding it here by overwriting.

        🔑 `Properties` IS EMITTED AS AN OBJECT, NOT AS A JSON STRING -- so Log Analytics types the
        column **dynamic** and the bag is queried BY PATH, exactly the way ARM is queried:

            SI_AssetProperties_CL
            | where SourceSystem == "arm"
            | extend vmSize = tostring(Properties.hardwareProfile.vmSize)
            | where Properties.storageProfile.osDisk.osType =~ "Windows"

        🔴 AND THAT IS A DELIBERATE DIVERGENCE FROM THE PROFILE TABLES, which store `Properties` as a
        JSON **string** (`Build-AzureProfileRow.ps1:649`) and force every consumer to write
        `todynamic(Properties)` before touching it. That is tolerable for a handful of curated fields
        and wrong for this table, whose entire purpose is a large heterogeneous bag: an Azure resource
        carries dozens to hundreds of properties and no two resource types carry the same ones, so
        path access is the only usable interface. The precedent is already in-tree -- `EntityIds` is
        emitted as a real array and lands `dynamic` without trouble.
        📌 This is §3.6's own answer applied one level further: a fixed typed envelope plus a
        `properties{}` bag, which is ARM's model, which is why it fits an ARM-shaped payload.

        🔴 THE BUDGET IS ENFORCED, AND OVERSIZE IS REPORTED RATHER THAN TRUNCATED. Dropping the largest
        field -- the strategy the profile schemas declare -- removes data without saying which, and the
        consumer cannot tell a machine that has no networkProfile from one whose networkProfile was
        silently sacrificed. So an oversized payload is REPLACED by a named marker, the row still
        publishes (it keeps its identity and its measurements, which is what makes the problem
        findable), and the run reports it. Never a silent drop, and never a failed batch.

        🪤 DEPTH IS MEASURED, NOT ASSUMED -- see Get-SIAssetPropertyMaxDepth. Past `-Depth`,
        ConvertTo-Json writes the .NET type name instead of the sub-tree, so the row looks complete and
        is not.
    #>
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$SourceSystem,
        [Parameter(Mandatory)][AllowNull()]$SourceObject,
        [Parameter()][string]$SI_AssetId    = '',
        [Parameter()][string]$SI_AssetName  = '',
        [Parameter()][string]$SI_CorrelationId = '',
        # `ledger` | `derived-provisional` | '' (the map did not say). Carried verbatim from
        # SI_ObjectMap_CL -- see Get-SIAssetPropertiesCorrelationKql for why dropping it was a defect.
        [Parameter()][string]$SI_IdSource = '',
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter()][string]$SolutionVersion = '',
        [Parameter()][int]$BudgetBytes = 0,
        # #301 -- the hardware identifiers THIS source states for the object ('' when it states none), and for a
        # child row (a VM extension) the parent's resource id and the child's own name. Typed envelope columns,
        # so the CMDB hand-off reads them without walking a source-specific path.
        [Parameter()][string]$SerialNumber = '',
        [Parameter()][string]$MacAddress = '',
        [Parameter()][string]$ParentResourceId = '',
        [Parameter()][string]$ItemName = ''
    )

    if ($BudgetBytes -le 0) { $BudgetBytes = $script:SIAssetPropertiesBudgetBytes }

    # Serialised ONLY to measure. The published value is the object itself, so the column lands
    # dynamic and stays path-queryable.
    $json = ''
    try {
        if ($null -ne $SourceObject) { $json = (ConvertTo-Json -InputObject $SourceObject -Depth $script:SIAssetPropertiesJsonDepth -Compress) }
    } catch {
        $json = ''
    }
    if ($null -eq $json) { $json = '' }

    $bytes    = [System.Text.Encoding]::UTF8.GetByteCount([string]$json)
    $leaves   = @(Get-SIAssetPropertyLeafPath -InputObject $SourceObject)
    $depth    = Get-SIAssetPropertyMaxDepth -InputObject $SourceObject
    $payload  = $SourceObject
    $oversize = $false

    if ($bytes -gt $BudgetBytes) {
        $oversize = $true
        # An OBJECT, matching the shape of the column so the type does not flip between rows -- a
        # string here and an object there is how a dynamic column degrades to unqueryable.
        $payload = [pscustomobject][ordered]@{
            _siPayloadDropped = 'oversize'
            _siPayloadBytes   = $bytes
            _siPayloadBudget  = $BudgetBytes
            _siPayloadLeaves  = $leaves.Count
        }
    }

    [pscustomobject]@{
        SI_CorrelationId = [string]$SI_CorrelationId
        # 🔴 THE COLUMN THAT DECIDES WHETHER A CI MAY BE CREATED FROM THIS ROW. `derived-provisional`
        # ids MOVE when correlation group membership changes, so creating from one manufactures a second
        # CI on the next run -- and a duplicate CI is effectively permanent once incidents point at it.
        # Enriching a CI that already exists is fine either way; creating is not.
        SI_IdSource      = [string]$SI_IdSource
        SI_AssetId       = [string]$SI_AssetId
        SI_AssetName     = [string]$SI_AssetName
        Engine           = [string]$Engine
        SourceSystem     = [string]$SourceSystem
        CollectionTime   = $CollectionTime
        SI_RunId         = [string]$RunId
        SolutionVersion  = [string]$SolutionVersion
        # 🔑 THE OBJECT, not a JSON string. See the header -- this is what makes the bag ARM-queryable.
        Properties       = $payload
        PropertyCount    = [int]$leaves.Count
        PropertiesBytes  = [int]$bytes
        # 🪤 Published so depth truncation is VISIBLE in the data rather than only in a log line
        # somebody has to still have. `PropertyDepth >= <serialisation depth>` is the query that finds
        # every row whose sub-tree may have been replaced by a type name.
        PropertyDepth    = [int]$depth
        PropertiesDropped= [bool]$oversize
        SerialNumber     = [string]$SerialNumber
        MacAddress       = [string]$MacAddress
        ParentResourceId = [string]$ParentResourceId
        ItemName         = [string]$ItemName
        # The collection-change guard (#301): a row re-published for a HELD source carries $true and the run it was
        # carried from (SI-AssetPropertiesGuard.ps1). Always present, so the column exists from the first run.
        SI_HandoffHeld   = $false
        SI_HeldFromRunId = ''
    }
}

function Get-SIAssetPropertiesWideningReport {
    <#
        3.6b rule 2. What the wide pull actually returned, per source, measured against the narrow
        baseline and reported BY NAME.

        🔑 The number that matters is `Added` and it is a LIST, not a count. A wide pull that quietly
        fell back to the narrow set returns Added = 0 and is otherwise indistinguishable from a wide
        pull that worked -- the same shape as findings #80/#81/#86/#78/#88, every one of which looked
        like a check with nothing to report and was a check that had stopped running.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceSystem,
        # 🔴 A COLLECTION, NOT ONE ROW -- and that correction came from a live run. Sampling row [0]
        # reported five MDE fields (`osVersion`, `publicIp`, `vulnerabilityCount`, ...) as ABSENT FROM
        # THE SOURCE when they were merely null on that one machine: REST APIs omit null properties, so
        # any single object is a subset of the schema. The report then accused the upstream source of
        # dropping fields the security path depends on -- a false alarm on exactly the signal that
        # exists to catch a real upstream change, which is the fastest way to teach an operator to
        # ignore it.
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$SampleObject,
        # How many rows to union. The full set would be exact and is not worth the walk on a large
        # estate; 200 is far past the point where a field present on any machine has appeared.
        [Parameter()][int]$SampleSize = 200
    )
    $narrow = @(Get-SIAssetPropertiesNarrowBaseline -SourceSystem $SourceSystem)

    # UNION the property names across the sample. One object cannot describe a schema.
    $samples = @($SampleObject)
    if ($samples.Count -gt $SampleSize) { $samples = @($samples | Select-Object -First $SampleSize) }
    $actualList = New-Object System.Collections.ArrayList
    foreach ($s in $samples) {
        foreach ($n in @(Get-SIAssetPropertyTopLevelName -InputObject $s)) { [void]$actualList.Add($n) }
    }
    $actual = @($actualList.ToArray())

    $narrowSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $narrow) { if ($n) { [void]$narrowSet.Add([string]$n) } }
    $actualSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($a in $actual) { if ($a) { [void]$actualSet.Add([string]$a) } }

    $added = New-Object System.Collections.ArrayList
    foreach ($a in @($actualSet)) { if (-not $narrowSet.Contains($a)) { [void]$added.Add($a) } }
    $missing = New-Object System.Collections.ArrayList
    foreach ($n in @($narrowSet)) { if (-not $actualSet.Contains($n)) { [void]$missing.Add($n) } }

    [pscustomobject]@{
        SourceSystem = $SourceSystem
        NarrowCount  = $narrowSet.Count
        ActualCount  = $actualSet.Count
        # Sorted so two runs are diffable. An unsorted list makes every run look like a change.
        Added        = @($added.ToArray()   | Sort-Object)
        # 🔴 NOT cosmetic. A field in the narrow baseline that the WIDE pull did not return means the
        # source dropped it upstream, and the security path is reading it today. That is a finding
        # about the profiler, surfaced by the add-on.
        Missing      = @($missing.ToArray() | Sort-Object)
    }
}

function Write-SIAssetPropertiesReport {
    <#
        The per-run report. Prints the widening by name, the budget outcome, and the estimated ingest
        cost of leaving the add-on on -- 3.6b rule 5, because the cost is per-customer and must be
        visible before it is paid rather than discovered on an invoice.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter()][AllowEmptyCollection()][object[]]$Widening = @()
    )

    $info = { param($m) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m } }
    $warn = { param($m) if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $m } else { Write-Warning $m } }

    foreach ($w in @($Widening)) {
        if ($null -eq $w) { continue }
        $shown = @($w.Added | Select-Object -First 12)
        $more  = if (@($w.Added).Count -gt $shown.Count) { (' ... and {0} more' -f (@($w.Added).Count - $shown.Count)) } else { '' }
        if (@($w.Added).Count -eq 0) {
            # The honest reading of a zero. For `arm` it is correct -- ARG never narrowed. For any other
            # source it means the wide pull returned the narrow set, which is a DEFECT wearing the
            # costume of a successful run.
            $note = if ($w.SourceSystem -eq 'arm') { ' (expected -- ARG projects properties verbatim, there was never a narrowing to undo)' }
                    else { ' <-- WIDE PULL RETURNED THE NARROW SET. This is not "nothing new"; it is the pull not happening.' }
            & $warn ("   [assetprops] {0,-24} {1} field(s), +0{2}" -f $w.SourceSystem, $w.ActualCount, $note)
        } else {
            & $info ("   [assetprops] {0,-24} {1} field(s), +{2} beyond the security pull: {3}{4}" -f `
                $w.SourceSystem, $w.ActualCount, @($w.Added).Count, ($shown -join ', '), $more)
        }
        if (@($w.Missing).Count -gt 0) {
            & $warn ("   [assetprops] {0}: {1} field(s) the SECURITY path reads are ABSENT from the wide pull -- {2}. The source changed upstream." -f `
                $w.SourceSystem, @($w.Missing).Count, (@($w.Missing) -join ', '))
        }
    }

    $rows = @($Rows)
    if ($rows.Count -eq 0) { & $warn '   [assetprops] 0 rows built -- nothing to publish.'; return }

    $totalBytes = 0
    foreach ($r in $rows) { $totalBytes += [int]$r.PropertiesBytes }
    $dropped = @($rows | Where-Object { $_.PropertiesDropped })
    $avg = [int]($totalBytes / $rows.Count)
    $maxRow = @($rows | Sort-Object PropertiesBytes -Descending | Select-Object -First 1)[0]

    & $info ("   [assetprops] {0} row(s) · {1:N1} MB · avg {2:N0} B/row · largest {3:N0} B ({4})" -f `
        $rows.Count, ($totalBytes / 1MB), $avg, $maxRow.PropertiesBytes, $maxRow.SI_AssetName)

    # 🔴 DEPTH BEFORE SIZE, because depth loss is the one that does NOT announce itself. An oversized
    # row is flagged and counted; a too-deep row publishes a complete-looking payload with a .NET type
    # name where a sub-tree was. On ARM payloads it would hit some resource types and not others.
    $deep = @($rows | Where-Object { [int]$_.PropertyDepth -ge ($script:SIAssetPropertiesJsonDepth - 1) })
    if ($deep.Count -gt 0) {
        & $warn ("   [assetprops] {0} row(s) nest at or near the serialisation depth of {1} -- a deeper sub-tree is written as a TYPE NAME, not omitted, so the row LOOKS complete. Raise the depth or accept the loss knowingly:" -f `
            $deep.Count, $script:SIAssetPropertiesJsonDepth)
        foreach ($d in @($deep | Sort-Object PropertyDepth -Descending | Select-Object -First 5)) {
            & $warn ("      {0} ({1}/{2}) depth {3}" -f $d.SI_AssetName, $d.Engine, $d.SourceSystem, $d.PropertyDepth)
        }
    }

    if ($dropped.Count -gt 0) {
        & $warn ("   [assetprops] {0} row(s) EXCEEDED the {1} KB budget -- payload replaced by a marker, identity and measurements kept. Not truncated, not silently dropped:" -f `
            $dropped.Count, ($script:SIAssetPropertiesBudgetBytes / 1KB))
        foreach ($d in @($dropped | Select-Object -First 5)) {
            & $warn ("      {0} ({1}/{2}) {3:N0} B, {4} leaf paths" -f $d.SI_AssetName, $d.Engine, $d.SourceSystem, $d.PropertiesBytes, $d.PropertyCount)
        }
    }

    # 3.6b rule 5. Daily, because that is the cadence the profilers run at; stated as a range no wider
    # than the measurement justifies.
    $perDayMb = ($totalBytes / 1MB)
    & $info ("   [assetprops] ESTIMATED INGEST if left enabled: ~{0:N1} MB/run, ~{1:N0} MB/month at one run per day. This is the cost of the add-on and it is paid per run." -f `
        $perDayMb, ($perDayMb * 30))
}
