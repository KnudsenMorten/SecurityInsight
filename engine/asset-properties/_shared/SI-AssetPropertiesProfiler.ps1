#Requires -Version 5.1
<#
    SecurityInsight Pro -- FULL ASSET METADATA FROM THE PROFILERS' OWN PULL (REQUIREMENTS #301 / #408 / #412).

    Operator 2026-10-06: "we dont pull in the same data twice (limited and full) ... if we do asset full, then it is 100%
    the same fields as limited - but with the extra metadata." Approved: one pull per source + history.

    This file replaces the second pass. The asset-properties job used to read every source AGAIN after the profilers
    (Get-SIWideAssetPropertiesFromMde / FromGraph / FromArm ...); now each profiler reads each source ONCE at the full
    level (engine\asset-profiling\shared\SI-FullAssetProperties.ps1 -- free code) and this file, loaded by the profiler
    only where the Pro code exists, turns the whole objects it kept into SI_AssetProperties_CL rows:

      Enable-SIFullAssetProperties        the level 'full' (no licence: the Community edition has it, owner 2026-10-27)
      Invoke-SIAssetPropertiesExtraPulls  the sources no security record reads, read once at the full level:
                                            endpoint  intune-device (only where the app may read Intune -- else SKIPPED)
                                            identity  ad-computer   (only where the AD source exists -- else SKIPPED)
      ConvertTo-SIProfilerAssetPropertyRows  PURE. The kept objects -> rows: each resolved to the profile row it
                                          describes through its anchor (in memory -- the rows were just built, so no
                                          Log Analytics read and no correlation post-pass), VM extensions split into
                                          their own rows, serial number / MAC per source and per asset, the 256 KB
                                          budget per row (an oversize object becomes a named marker, never a cut one).
      Publish-SIProfilerAssetProperties   the collection-change guard per (profiler, source) (#301 -- moved here from the
                                          retired job, not lost), carry-forward of a held source, the post, the retention.

    Every row carries the profiler run's CollectionTime and run id: the full metadata of an asset is the object the
    SAME pull built its profile row from. SI_CorrelationId / SI_IdSource stay empty on these rows -- the correlation
    engine runs later; every reader keys on SI_AssetId (the data sync maps it to the CI through the correlation map).

    PS 5.1 + 7. No PowerShell modules (#305). NO Set-StrictMode (it leaks into the caller's scope).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

# The profiler's console style when it is there (a test loads this file on its own: plain lines then).
if (-not (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue)) { function Write-SIInfo { param([string]$Message) Write-Host ('[INFO] ' + $Message) } }
if (-not (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue)) { function Write-SIWarn { param([string]$Message) Write-Warning $Message } }
if (-not (Get-Command -Name Write-SIOk -ErrorAction SilentlyContinue))   { function Write-SIOk   { param([string]$Message) Write-Host ('[OK]   ' + $Message) } }

if (-not (Get-Command -Name New-SIAssetPropertyRow -ErrorAction SilentlyContinue))            { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesCore.ps1') }
if (-not (Get-Command -Name New-SIAssetPropertiesIdentityIndex -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesIdentity.ps1') }
if (-not (Get-Command -Name Send-SIAssetPropertyRows -ErrorAction SilentlyContinue))          { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesIngest.ps1') }
if (-not (Get-Command -Name Split-SIAssetPropertiesArmExtensions -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesMetadata.ps1') }
if (-not (Get-Command -Name Test-SIAssetPropertiesCollectionChange -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesGuard.ps1') }
# a run collected in parts: the parts hand over, the run's last step publishes once (2026-10-11)
if (-not (Get-Command -Name Save-SIAssetPropsHandover -ErrorAction SilentlyContinue))         { . (Join-Path $PSScriptRoot 'SI-AssetPropertiesHandover.ps1') }
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'asset-profiling', 'shared', 'SI-FullAssetProperties.ps1'))
}

function Enable-SIFullAssetProperties {
    <#
        The licence half of the level decision (Initialize-SIFullAssetProperties made the rest). Licensed -> 'full'.
        Refused -> stays 'security' and says why (Assert-SIFeatureOrSkip prints the one plain line).
        -Allowed  test seam: $true / $false instead of the licence check.
    #>
    param([Parameter(Mandatory)][string]$Engine, [scriptblock]$Log, [AllowNull()]$Allowed)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    # The full asset properties are in the Community edition (owner 2026-10-27, SI #750 (1)): no licence is asked. -Allowed
    # stays as a test seam ($false = the security level, said).
    $ok = if ($null -eq $Allowed) { $true } else { [bool]$Allowed }
    if ($ok) {
        Set-SIFullAssetPropertiesLevel -Level full
        return $true
    }
    Set-SIFullAssetPropertiesLevel -Level security -Reason 'full asset metadata is switched off for this run'
    & $Log 'WARN' "SI_AssetProperties = 'full', but full asset metadata is switched off for this run -- the security level runs (the source queries are unchanged)."
    $false
}

function Invoke-SIAssetPropertiesExtraPulls {
    <#
        The sources a profiler reads ONLY for the full asset metadata (no security record reads them), once:
          endpoint  intune-device  Intune managed devices -> resolve on the Entra device id (AadDeviceId)
          identity  ad-computer    AD computer objects    -> resolve on the object GUID (OnPremObjectGuid)
        A source that does not exist here or may not be read is SKIPPED with its reason (recorded, never a failure).
        -Intune { -> pull } / -Ad { -> pull }  test seams (default: the real reads in SI-AssetPropertiesMetadata.ps1).
    #>
    param([Parameter(Mandatory)][string]$Engine, [scriptblock]$Intune, [scriptblock]$Ad)
    if (-not (Test-SIFullAssetPropertiesOn)) { return }
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $pulls = New-Object System.Collections.Generic.List[object]
    switch ($Engine.Trim().ToLowerInvariant()) {
        'endpoint' {
            if (-not $Intune) {
                $Intune = {
                    if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($siRoot, 'auth', 'Get-SIGraphToken.ps1')) }
                    if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($siRoot, 'engine', 'asset-profiling', 'shared', 'Invoke-SIPagedRest.ps1')) }
                    Get-SIWideAssetPropertiesFromIntune -Token (Get-SIGraphToken -Resource Graph)
                }
            }
            # the endpoint discovery already read the Intune devices this run (Invoke-SIIntuneCapture hands every device here
            # and records the pull): one read per source, never a second one
            $done = ($null -ne $global:SIIntuneCapture -and $global:SIIntuneCapture.Read -and -not $PSBoundParameters.ContainsKey('Intune'))
            if (-not $done) { $pulls.Add(@{ Source = 'intune-device'; Anchor = 'AadDeviceId'; Field = 'azureADDeviceId'; Pull = $Intune }) }
        }
        'identity' {
            if (-not $Ad) { $Ad = { Get-SIWideAssetPropertiesFromAd -SearchBase ([string]$global:SI_AssetProperties_AdSearchBase) } }
            $pulls.Add(@{ Source = 'ad-computer'; Anchor = 'OnPremObjectGuid'; Field = 'ObjectGUID'; Pull = $Ad })
        }
    }
    foreach ($p in $pulls) {
        $res = $null
        try { $res = & $p.Pull }
        catch {
            Set-SIFullSourcePull -SourceSystem $p.Source -Complete $false -ErrorText $_.Exception.Message
            Write-Warning ('full asset metadata: {0} could not be read -- {1}. The run continues; the profile is unaffected.' -f $p.Source, $_.Exception.Message)
            continue
        }
        if ($null -eq $res) { continue }
        if ($res.PSObject.Properties['Skipped'] -and [string]$res.Skipped) {
            Set-SIFullSourcePull -SourceSystem $p.Source -Skipped ([string]$res.Skipped)
            Write-Host ('[INFO] full asset metadata: {0} skipped -- {1}' -f $p.Source, $res.Skipped)
            continue
        }
        Set-SIFullSourcePull -SourceSystem $p.Source -Complete ([bool]$res.Complete) -ErrorText ([string]$res.Error)
        $n = 0
        foreach ($o in @($res.Rows)) {
            if ($null -eq $o) { continue }
            $v = ''; $pp = $o.PSObject.Properties[$p.Field]; if ($pp) { $v = [string]$pp.Value }
            Add-SIFullSourceObject -SourceSystem $p.Source -Object $o -AnchorColumn $p.Anchor -AnchorValue $v
            $n++
        }
        Write-Host ('[INFO] full asset metadata: {0} -- {1} object(s) read' -f $p.Source, $n)
    }
}

function Resolve-SIProfilerEntryIdentity {
    <# PURE. One kept object -> its profile row's identity through the object's own anchor (else the source's default). #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][hashtable]$Index)
    $col = [string]$Entry.AnchorColumn; $val = [string]$Entry.AnchorValue
    if ($col -and $val) {
        $key = ('{0}|{1}' -f $col, $val.Trim().ToLowerInvariant())
        if ($Index.ContainsKey($key)) { return $Index[$key] }
        return $null
    }
    Resolve-SIAssetPropertyIdentity -SourceSystem ([string]$Entry.SourceSystem) -SourceObject $Entry.Object -Index $Index
}

function ConvertTo-SIProfilerAssetPropertyRows {
    <#
        PURE. The objects one profiler run kept -> its SI_AssetProperties_CL rows.
          -ProfileRows  the run's built profile rows (SI_AssetId, SI_AssetName and the anchor columns)
          -Entries      Get-SIFullSourceObjects: @{ SourceSystem; Object; AnchorColumn; AnchorValue }
          -Pulls        source -> @{ Complete; Error; Skipped; Narrowed } (Set-SIFullSourcePull)
        Returns @{ Rows; Unresolved (source -> @{ Missed; Total }); Widening; Attempted; Skipped (source -> reason) }.
        Attempted = the sources this run read (a pull record without Skipped, or kept objects) -- what the guard compares.
    #>
    param(
        [Parameter(Mandatory)][string]$Engine,
        [AllowEmptyCollection()][object[]]$ProfileRows = @(),
        [AllowEmptyCollection()][object[]]$Entries = @(),
        [hashtable]$Pulls = @{},
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        [string]$SolutionVersion = '',
        [int]$BudgetBytes = 0
    )
    $index = New-SIAssetPropertiesIdentityIndex -ProfileRows @($ProfileRows | Where-Object { $null -ne $_ })
    $bySource = [ordered]@{}
    foreach ($e in @($Entries)) {
        if ($null -eq $e -or $null -eq $e.Object) { continue }
        $s = [string]$e.SourceSystem
        if (-not $bySource.Contains($s)) { $bySource[$s] = New-Object System.Collections.Generic.List[object] }
        $bySource[$s].Add($e)
    }

    # Azure: the VM extensions become their own rows (keyed to the VM), and the network interfaces give each VM its MAC.
    $nicMacByVmId = @{}
    if ($bySource.Contains('arm')) {
        # .ToArray(), never @(...) around a List[object] taken from a dictionary -- that throws "Argument types do not match"
        $armList = $bySource['arm'].ToArray()
        $split = Split-SIAssetPropertiesArmExtensions -Rows @($armList | ForEach-Object { $_.Object })
        $nicMacByVmId = Get-SIAssetPropertiesNicMacMap -ArmRows @($split.Resources)
        $keepArm = New-Object System.Collections.Generic.List[object]
        $ext = New-Object System.Collections.Generic.List[object]
        foreach ($e in $armList) {
            if ($e.Object.PSObject.Properties['_siParentResourceId']) {
                $ext.Add([pscustomobject]@{ SourceSystem = 'arm-vm-extension'; Object = $e.Object; AnchorColumn = 'AzureResourceId'; AnchorValue = [string]$e.Object._siParentResourceId })
            } else { $keepArm.Add($e) }
        }
        $bySource['arm'] = $keepArm
        if ($ext.Count -gt 0) { $bySource['arm-vm-extension'] = $ext }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $widening = New-Object System.Collections.Generic.List[object]
    $unresolved = [ordered]@{}
    foreach ($src in @($bySource.Keys)) {
        $list = $bySource[$src].ToArray()
        if ($list.Count -gt 0) { $widening.Add((Get-SIAssetPropertiesWideningReport -SourceSystem $src -SampleObject @($list | ForEach-Object { $_.Object }))) }
        $miss = 0
        foreach ($e in $list) {
            $id = Resolve-SIProfilerEntryIdentity -Entry $e -Index $index
            if (-not $id) { $miss++; continue }
            $o = $e.Object
            $hw = Get-SIAssetPropertyHardwareIds -SourceSystem $src -SourceObject $o -NicMacByVmId $nicMacByVmId
            $parentId = ''; $itemName = ''
            if ($src -eq 'arm-vm-extension') { $parentId = [string]$o._siParentResourceId; $itemName = [string]$o._siExtensionName }
            $rows.Add((New-SIAssetPropertyRow -Engine $Engine -SourceSystem $src -SourceObject $o -SI_AssetId $id.SI_AssetId -SI_AssetName $id.SI_AssetName `
                -CollectionTime $CollectionTime -RunId $RunId -SolutionVersion $SolutionVersion -BudgetBytes $BudgetBytes `
                -SerialNumber $hw.SerialNumber -MacAddress $hw.MacAddress -ParentResourceId $parentId -ItemName $itemName))
        }
        $unresolved[$src] = @{ Missed = $miss; Total = $list.Count }
    }
    $null = Set-SIAssetPropertiesHardwarePrecedence -Rows $rows.ToArray()

    $attempted = New-Object System.Collections.Generic.List[string]
    $skipped = [ordered]@{}
    foreach ($k in @($Pulls.Keys | Sort-Object)) {
        $p = $Pulls[$k]
        if ($p -and [string]$p.Skipped) { $skipped[[string]$k] = [string]$p.Skipped; continue }
        if (-not $attempted.Contains([string]$k)) { $attempted.Add([string]$k) }
    }
    foreach ($k in @($bySource.Keys)) { if (-not $skipped.Contains([string]$k) -and -not $attempted.Contains([string]$k)) { $attempted.Add([string]$k) } }
    # the extensions come with the ARM pull: attempted whenever ARM was (an estate without extensions is compared as 0)
    if ($attempted.Contains('arm') -and -not $attempted.Contains('arm-vm-extension')) { $attempted.Add('arm-vm-extension') }

    [pscustomobject]@{ Rows = $rows.ToArray(); Unresolved = $unresolved; Widening = $widening.ToArray(); Attempted = @($attempted.ToArray() | Sort-Object); Skipped = $skipped }
}

function Publish-SIProfilerAssetProperties {
    <#
        The profiler's full-metadata publish (called by the Output stage after the profile rows were posted):
          1. the rows (ConvertTo-SIProfilerAssetPropertyRows) and the report (widening, budget, cost, unresolved)
          2. the collection-change guard (#301), per source of THIS profiler: this run's collection against the newest
             snapshot of the same (profiler, source) already in SI_AssetProperties_CL. More than
             SI_AssetProperties_ChangeGuardPercent (default 10) = that source's hand-off is HELD: its previous rows are
             published again (SI_HandoffHeld) instead of the new ones, a guard event is raised, and an Admin may release it
             once (applied by this profiler's next run). Skipped on a SHARDED run (a replica holds only its slice).
          3. the post (SI_AssetProperties_CL), then the table's retention (SI_AssetProperties_RetentionDays).
        Seams for tests: -Query { param($Kql) -> rows }, -Send { param($Rows) -> count }, -Store, -Retention, -GuardCalls.
        Returns @{ Status; Rows; Posted; Held; Verdicts; Unresolved }. Throws only on a failed post (the caller says it).
    #>
    param(
        [Parameter(Mandatory)]$RunContext,
        [AllowEmptyCollection()][object[]]$ProfileRows = @(),
        [AllowEmptyCollection()][object[]]$Entries = @(),
        [hashtable]$Pulls = @{},
        [scriptblock]$Query,
        [scriptblock]$Send,
        $Store,
        [scriptblock]$Retention,
        [scriptblock]$GuardCalls,
        [switch]$DryRun
    )
    $engine = ([string]$RunContext.Engine).Trim().ToLowerInvariant()
    $runId = [string]$RunContext.RunId
    $ct = [datetime]$RunContext.CollectionTime
    $sharded = ($RunContext.PSObject.Properties['ShardCount'] -and [int]$RunContext.ShardCount -gt 1)
    $ver = ''
    try {
        $vf = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'VERSION')
        if (Test-Path -LiteralPath $vf) { $ver = ([IO.File]::ReadAllText($vf)).Trim() }
    } catch { }
    # #639 lane 4: the previous collection carried forward for a held source can be every asset's wide payload -- read in parts
    # when one Log Analytics answer cannot carry it (Read-SILaParts; a cut answer is refused, never carried forward as whole)
    if (-not $Query) {
        if (-not (Get-Command -Name Read-SILaParts -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-LaParts.ps1')) }
        $Query = { param($Kql) @((Read-SILaParts -WorkspaceId (Resolve-SIAssetPropertiesWorkspaceId) -Query $Kql -What 'SI_AssetProperties_CL' -Log { param($l, $m) Write-SIInfo ('   [assetprops] ' + $m) }).Rows) }
    }
    if (-not $Send) { $Send = { param($Rows) Send-SIAssetPropertyRows -Rows $Rows } }
    if (-not $Retention) { $Retention = { Set-SIAssetPropertiesTableRetention -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) } }

    Write-SIInfo ('full asset metadata: {0} object(s) kept by this {1} run -- resolving them to the profile rows' -f @($Entries).Count, $engine)
    $built = ConvertTo-SIProfilerAssetPropertyRows -Engine $engine -ProfileRows $ProfileRows -Entries $Entries -Pulls $Pulls -CollectionTime $ct -RunId $runId -SolutionVersion $ver
    foreach ($k in @($built.Unresolved.Keys)) {
        $u = $built.Unresolved[$k]
        $msg = ('   [assetprops] {0,-24} {1,6} object(s), {2} resolved, {3} unresolved' -f $k, $u.Total, ($u.Total - $u.Missed), $u.Missed)
        if ($u.Total -gt 0 -and $u.Missed -eq $u.Total -and -not $sharded) {
            Write-SIWarn ($msg + ' -- NONE resolved: that points at the anchor mapping, not the estate')
        } else { Write-SIInfo $msg }
    }
    foreach ($k in @($built.Skipped.Keys)) { Write-SIInfo ('   [assetprops] {0,-24} skipped -- {1}' -f $k, $built.Skipped[$k]) }
    foreach ($k in @($Pulls.Keys)) {
        $p = $Pulls[$k]
        if ($p -and -not [string]$p.Skipped -and -not [bool]$p.Complete) { Write-SIWarn ('   [assetprops] {0}: the pull was INCOMPLETE ({1}) -- the objects collected are kept' -f $k, $p.Error) }
        if ($p -and [bool]$p.Narrowed) { Write-SIWarn ('   [assetprops] {0}: read with the security property list only this run (Graph refused the full list)' -f $k) }
    }
    Write-SIAssetPropertiesReport -Rows @($built.Rows) -Widening @($built.Widening)

    $rows = @($built.Rows)
    $result = [ordered]@{ Status = 'published'; Rows = $rows.Count; Posted = 0; Held = @(); Verdicts = @(); Unresolved = $built.Unresolved }

    # ---- the collection-change guard (#301), per (profiler, source) ----
    $verdicts = @()
    $held = @()
    if ($sharded) {
        Write-SIInfo ('   [assetprops] collection-change guard not applied: this run is replica {0} of {1} and holds only its slice of each source' -f ([int]$RunContext.ShardIndex + 1), [int]$RunContext.ShardCount)
    } else {
        $prev = @()
        try {
            $prev = @(@(& $Query (Get-SIAssetPropertiesPreviousCountsKql -Engine $engine)) | Where-Object { $_ -and [string]$_.SourceSystem } |
                ForEach-Object { [pscustomobject]@{ SourceSystem = [string]$_.SourceSystem; Rows = [long]$_.Rows; Dropped = [long]$_.Dropped; RunId = [string]$_.RunId } })
        } catch {
            if ("$($_.Exception.Message)" -notmatch '(?i)resolve table|SI_AssetProperties_CL') { Write-SIWarn ('   [assetprops] the previous collection could not be read -- {0}. This run is recorded as the baseline.' -f $_.Exception.Message) }
        }
        $verdicts = @(Test-SIAssetPropertiesCollectionChange -Previous $prev -Current (Measure-SIAssetPropertiesCollection -Rows $rows) -Attempted @($built.Attempted) -Percent (Get-SIAssetPropertiesChangeGuardPercent))
        if ($null -eq $Store) {
            try {
                if (-not (Get-Command -Name New-SIVulnReleaseStore -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'asset-cmdb', '_shared', 'SI-VulnRelease.ps1')) }
                if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-Guard.ps1')) }
                $proInvoke = $null
                if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { $proInvoke = Get-SIGuardProInvoke }
                $Store = if ($proInvoke) { New-SIVulnReleaseStore -Invoke $proInvoke } else { New-SIVulnReleaseStore -Folder ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'state', 'asset-properties-held')) }
            } catch { Write-SIWarn ('   [assetprops] holds cannot be released from this run -- {0}' -f $_.Exception.Message) }
        }
        $log = { param($l, $m) if ($l -eq 'WARN') { Write-SIWarn ('   ' + $m) } else { Write-SIInfo ('   ' + $m) } }
        # #414: the guard switched off (Settings > Guards) -- a large change is handed over like any other
        if ((Get-Command -Name Test-SIGuardOn -ErrorAction SilentlyContinue) -and @($verdicts | Where-Object { $_ -and [bool]$_.Trip }).Count -and -not (Test-SIGuardOn -GuardId 'asset.properties.collection-change' -Log $log)) {
            foreach ($v in @($verdicts)) { if ($v -and [bool]$v.Trip) { $v.Trip = $false; $v.Reason = ('{0} -- handed over: the guard is off (setting)' -f [string]$v.Reason) } }
        }
        $verdicts = @(Resolve-SIAssetPropertiesGuard -Verdicts $verdicts -Store $Store -RunId $runId -Engine $engine -DryRun:$DryRun -Log $log)
        foreach ($v in $verdicts) {
            if (Test-SIAssetPropertiesSourceHeld -SourceSystem $v.SourceSystem -Verdicts @($v)) { Write-SIWarn ('   [assetprops] HELD -- {0}. The previous collection of this source stays in the hand-off.' -f $v.Reason) }
            else { Write-SIInfo ('   [assetprops] {0}' -f $v.Reason) }
        }
        $held = @($verdicts | Where-Object { Test-SIAssetPropertiesSourceHeld -SourceSystem $_.SourceSystem -Verdicts @($_) } | ForEach-Object { [string]$_.SourceSystem })
    }
    $result.Verdicts = $verdicts
    $result.Held = $held

    if ($DryRun) {
        $result.Status = 'dry-run'
        Write-SIInfo ('   [assetprops] dry run -- {0} row(s) would be published to SI_AssetProperties_CL' -f $rows.Count)
        return [pscustomobject]$result
    }

    $publish = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) { if ($held -notcontains [string]$r.SourceSystem) { $publish.Add($r) } }
    foreach ($hs in $held) {
        try {
            $carried = @(@(& $Query (Get-SIAssetPropertiesCarryForwardKql -SourceSystem $hs -Engine $engine)) | Where-Object { $_ } | ForEach-Object { ConvertTo-SIAssetPropertiesCarriedRow -Row $_ -CollectionTime $ct -RunId $runId })
            foreach ($c in $carried) { $publish.Add($c) }
            Write-SIInfo ('   [assetprops] {0}: {1} row(s) of the previous collection carried forward' -f $hs, $carried.Count)
        } catch {
            Write-SIWarn ('   [assetprops] {0}: the previous collection could not be read back -- {1}. Neither the new nor the old rows of this source are published this run.' -f $hs, $_.Exception.Message)
        }
    }
    $calls = @(Get-SIGuardCallsForAssetPropertiesChange -Verdicts $verdicts -RunId $runId -Engine $engine)
    # owner 2026-10-17: every source judged this run is a check -- one back within the limit clears its earlier hold by itself
    $checkedSources = @(@($verdicts) | Where-Object { $_ -and [string]$_.SourceSystem -and $held -notcontains [string]$_.SourceSystem } | ForEach-Object {
        @{ GuardId = 'asset.properties.collection-change'; Subject = [string]$_.SourceSystem } })
    if ($calls.Count -or $checkedSources.Count) {
        if ($GuardCalls) { if ($calls.Count) { & $GuardCalls $calls } }
        elseif (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) {
            $gc = @{ Engine = $engine; RunId = $runId; Invoke = $(if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { Get-SIGuardProInvoke } else { $null }) }
            if ($engine) { $gc['Job'] = 'si-' + $engine.Trim().ToLowerInvariant() }
            $null = Invoke-SIGuardCalls -Calls $calls -Common $gc -Checked $checkedSources -Complete $true
        }
    }

    if ($publish.Count -eq 0) {
        $result.Status = 'empty'
        Write-SIWarn '   [assetprops] nothing to publish to SI_AssetProperties_CL this run.'
        return [pscustomobject]$result
    }
    # The profile engine's own ingest caches are put back afterwards: this post narrows them to its own rule, and a later
    # stage of the same run (tagging, recommendations) posts to its own.
    $savedDce = $global:AzDceDetails; $savedDcr = $global:AzDcrDetails
    try { $result.Posted = [int](& $Send $publish.ToArray()) }
    finally { $global:AzDceDetails = $savedDce; $global:AzDcrDetails = $savedDcr }
    Write-SIOk ('full asset metadata: {0} row(s) posted to SI_AssetProperties_CL (CollectionTime {1:o}, the same as the profile rows)' -f $result.Posted, $ct)
    try {
        $ret = & $Retention
        if ($ret) { Write-SIInfo ('   [assetprops] ' + (Get-SIAssetPropertiesRetentionText -Result $ret)) }
    } catch { Write-SIInfo ('   [assetprops] the table retention could not be checked -- {0}' -f $_.Exception.Message) }
    [pscustomobject]$result
}
