#Requires -Version 5.1
<#
    THE ONE ASSET-IDENTITY RESOLVER. Built once per run, used by every report.

    🔴 WHY THIS EXISTS, measured 2026-08-30: **84 reports resolve an asset identity, across NINE
    different hand-written chain variants** in the locked catalog, and this session added a tenth.
    That is nine dialects of one idea. Every fix to the identity chain this session had to be applied
    to "these four sites but not those six", and twice it was applied to a report that did not have
    the columns. Nine dialects cannot be kept in step across ~6,000 customer estates -- they will
    drift, silently, exactly the way `AssetId` and `AssetType` drifted into declared-but-never-built.

    🔑 SO THE CHAIN LIVES HERE, ONCE, AND IS KEYED ON IDENTITY SOURCE PRIORITY -- NOT ON RESOURCE
    TYPE. Nothing below hard-codes a resource type, a naming convention or a tenant, which is what
    makes it hold for an estate this code has never seen:

        1. exact  SI_AssetName            (100% populated on every profile table, by construction)
        2. short  SI_AssetName            (FQDN vs MDE short name -- see the trap note below)
        3. ARM    <parent>/<child> pair   (any child resource, not just SQL databases)

    🔒 IDENTITY COMES FROM ARM / MDE / ENTRA, NEVER FROM EXPOSUREGRAPH. Operator, 2026-08-30:
    *"dont rely purely on eg .. the other sources have updated info. eg gets data with up to 24 hr
    delay. mde, arm, entra et. are near realtime"* and *"why not just ask azure. not all az ress exist
    in eg"*. Three independent measurements agree:
      * EG carries no ARM resourceId for Azure nodes -- `Get-DiscoveryFromAzureViaEG.ps1:182` falls
        back to NodeId, and every EG-discovered id in the table is `eg:az:<hex node id>`;
      * EG and ARM disagree about names -- EG says `master (sql-ait-mfnpr/master)`, ARM-derived
        profiling says `master (rg-sql-2linkit)`;
      * EG mixes device nodes into Azure findings, and those devices are not Azure assets at all.
    The profile tables are built from ARM / MDE / Entra, so this map is both the correct source and
    the fresher one.

    🪤 KEYED ON SI_AssetName, NEVER ON A VENDOR ID. Measured live: 95 endpoint rows carry
    SI_AssetName/SI_AssetId 95/95 while AadDeviceId reaches 15 and MdeDeviceId 74 -- 21 devices have
    NEITHER. Servers and mobiles never reach Entra (operator), so no vendor id is universal and only
    the SI identity is.

    🪤 AND THE SNAPSHOT MUST BE THE v3 ONE. Both editions write these tables and v2.2 emits none of
    the SI_ columns, so `arg_max(CollectionTime, *)` alone hands back a v2.2 row and the identity
    comes out EMPTY. Every query below filters to rows that actually carry an identity BEFORE the
    arg_max.
#>

# name -> [pscustomobject]{ Id; Name; Type; Table } ; ordinal-insensitive because MDE, ARM and EG
# disagree about case constantly (measured: a case-sensitive key resolved 2 of 21 device names, a
# case-insensitive one resolved 14).
$script:_SIIdentityExact = $null
$script:_SIIdentityShort = $null
$script:_SIIdentityPath  = $null
$script:_SIIdentityStats = $null
# Every SI_AssetId this run knows about, so an id can be recognised as SI-authored rather than
# merely guessed at from its shape. Feeds Get-SIAssetIdSource -- see the note above that function.
$script:_SIIdentityIds   = $null

function Get-SIIdentityShortKey {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim()
    $dot = $n.IndexOf('.')
    if ($dot -gt 0) { $n = $n.Substring(0, $dot) }
    $n.ToLowerInvariant()
}

function Get-SIIdentityPathKey {
    <# `<parent>/<child>` from an ARM id -- the pair ExposureGraph puts in its parentheses.
       Generic over the last two <type>/<name> segments, so it is not SQL-specific. #>
    param([string]$AssetId)
    if ([string]::IsNullOrWhiteSpace($AssetId)) { return '' }
    # 🪤 ANCHOR ON /providers/, DO NOT JUST TAKE THE LAST FOUR SEGMENTS. A bare
    # `az:/subscriptions/x/resourcegroups/rg` has four trailing segments too, and the naive pattern
    # turned it into the key "x/rg" -- a resource GROUP masquerading as a parent/child pair, free to
    # false-match some unrelated asset. Caught by the guard, not by review.
    # The shape required is: /providers/<namespace>/<parentType>/<parent>/<childType>/<child>, so a
    # TOP-LEVEL resource (only <type>/<name> after the namespace) correctly yields no key at all.
    $m = [regex]::Match($AssetId, '/providers/[^/]+/[^/]+/([^/]+)/[^/]+/([^/]+)$')
    if (-not $m.Success) { return '' }
    ('{0}/{1}' -f $m.Groups[1].Value, $m.Groups[2].Value).ToLowerInvariant()
}

function ConvertTo-SIIdentitySeen {
    <# The snapshot time a row came from, as UTC; MinValue when absent or unreadable (an older claim never wins on it). #>
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
    [datetime]::MinValue
}

function Add-SIIdentityClaim {
    <#
        One device claims a VM id / graph node. The NEWEST snapshot wins: when discovery merges two records of one
        machine, the record that disappears keeps its last row inside the map's 8-day window and still claims the
        graph node the merged row now carries (measured 2026-10-02: the hybrid worker's nameless twin stayed in the
        Top 50 under its own name). Two DIFFERENT devices claiming it in the same snapshot is a real conflict: the id
        links to nothing (no fusion), unless a newer snapshot settles it.
    #>
    param($Map, $Collisions, [string]$Key, $Entry)
    if (-not $Map.ContainsKey($Key)) { $Map[$Key] = $Entry; return }
    $cur = $Map[$Key]
    if ($cur.Id -eq $Entry.Id) { if ($Entry.Seen -gt $cur.Seen) { $Map[$Key] = $Entry }; return }
    if ($Entry.Seen -gt $cur.Seen) { $Map[$Key] = $Entry; [void]$Collisions.Remove($Key) }
    elseif ($Entry.Seen -eq $cur.Seen) { [void]$Collisions.Add($Key) }
}

function Initialize-SIAssetIdentityMap {
    <#
        Builds the map from the profile tables. ONE query per table per run.
        Safe to call repeatedly -- it builds once and is then a no-op.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [string[]]$Tables = @('SI_Endpoint_Profile_CL','SI_Azure_Profile_CL','SI_Identity_Profile_CL'),
        [switch]$Force
    )
    if ($script:_SIIdentityExact -and -not $Force) { return }

    $ids   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $exact = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $short = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $path  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $shortCollisions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    # id -> asset (first table wins, same priority as names) and Azure VM resource id -> the DEVICE that carries it (#204):
    # the endpoint profile records a VM's ARM id from Defender, so a report row naming the VM can be the device's row.
    $byId  = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $byArm = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $armCollisions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    # ExposureGraph node id -> the device that carries it: an azure-engine shell 'eg:az:<node>' for a VM is that device
    # (correlation joins them on the same node id).
    $byEg = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
    $egCollisions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $stats = [ordered]@{}

    foreach ($tbl in $Tables) {
        # 🔒 v3-identity filter BEFORE the arg_max -- see the header note.
        $q = @"
$tbl
| where TimeGenerated > ago(8d)
| extend _n = tostring(column_ifexists("SI_AssetName",""))
| extend _i = tostring(column_ifexists("SI_AssetId",""))
| where isnotempty(_n) and isnotempty(_i)
| summarize arg_max(CollectionTime, *) by PrimaryEntityId
| project SI_AssetName = _n, SI_AssetId = _i, Seen = CollectionTime, AssetType = tostring(column_ifexists("AssetType","")), AzureResourceId = tolower(tostring(column_ifexists("AzureResourceId",""))), EgNodeId = tolower(tostring(column_ifexists("ExposureGraphNodeId","")))
"@
        # 🔴 NO @() WRAP ON THIS CALL. Invoke-LogAnalyticsKqlQuery returns the rows array via
        # `,@($resp.Results)` -- comma-protected so PowerShell emits it as ONE value -- so `@(call)`
        # re-wraps it into an Object[1] holding the inner array, and every consumer then sees exactly
        # ONE "row" whose properties are System.Array's own (Count/Length/SyncRoot). The trap is
        # documented at RA-GraphHunting.ps1:351 and I walked straight into it: the map built with
        # "Endpoint=1 Azure=1 Identity=1" instead of 95/424/765, and reported success while doing so.
        # Plain assignment captures the array; wrap AFTERWARDS if a count is needed.
        $rows = $null
        # #639 lane 4: one row per asset of the table (millions at a large install) -- read in parts when one answer cannot
        # carry it (Invoke-LogAnalyticsKqlQueryParted, RA-LaPartedRead.ps1); a cut answer is refused, never taken as every asset
        if (-not (Get-Command -Name Invoke-LogAnalyticsKqlQueryParted -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'RA-LaPartedRead.ps1'))) { . (Join-Path $PSScriptRoot 'RA-LaPartedRead.ps1') }
        try {
            if (Get-Command -Name Invoke-LogAnalyticsKqlQueryParted -ErrorAction SilentlyContinue) { $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $WorkspaceResourceId -Query $q -What ('the asset identities of {0}' -f $tbl) }
            else { $rows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $q }
        }
        catch {
            # A table that does not exist on this install is normal (publicip is optional; a
            # customer may not run every engine). Never fail the run for it.
            Write-Warn2 ("[identity] {0}: unavailable -- {1}" -f $tbl, $_.Exception.Message)
            $stats[$tbl] = 0
            continue
        }
        $stats[$tbl] = @($rows).Count
        foreach ($r in $rows) {
            $nm = [string]$r.SI_AssetName
            $id = [string]$r.SI_AssetId
            if ([string]::IsNullOrWhiteSpace($nm) -or [string]::IsNullOrWhiteSpace($id)) { continue }
            $seen = ConvertTo-SIIdentitySeen $(if ($r.PSObject.Properties['Seen']) { $r.Seen })
            $entry = [pscustomobject]@{ Id = $id; Name = $nm; Type = [string]$r.AssetType; Table = $tbl; Seen = $seen }
            # 📌 EVERY id, before any first-wins or collision rule below. Those rules pick which
            # asset a NAME means; this set only answers "is this id one we authored", and an id
            # dropped for name ambiguity is still one of ours.
            [void]$ids.Add($id)
            if (-not $byId.ContainsKey($id)) { $byId[$id] = $entry }
            $arm = if ($r.PSObject.Properties['AzureResourceId']) { ([string]$r.AzureResourceId).Trim().ToLowerInvariant() } else { '' }
            if ($tbl -eq 'SI_Endpoint_Profile_CL' -and $arm -like '/subscriptions/*') {
                # Two devices claiming one VM cannot both be it -- an ambiguous VM id links to nothing (no fusion).
                Add-SIIdentityClaim -Map $byArm -Collisions $armCollisions -Key $arm -Entry $entry
            }
            $eg = if ($r.PSObject.Properties['EgNodeId']) { ([string]$r.EgNodeId).Trim().ToLowerInvariant() } else { '' }
            if ($tbl -eq 'SI_Endpoint_Profile_CL' -and $eg -match '^[0-9a-f]{32}$') {
                Add-SIIdentityClaim -Map $byEg -Collisions $egCollisions -Key $eg -Entry $entry
            }

            # 📌 FIRST TABLE WINS, and the order is the priority order. An endpoint row is a stronger
            # claim for a device name than an azure row that happens to share it.
            if (-not $exact.ContainsKey($nm)) { $exact[$nm] = $entry }

            $sk = Get-SIIdentityShortKey -Name $nm
            if ($sk) {
                if ($short.ContainsKey($sk)) {
                    # 🪤 TWO ASSETS SHARING A SHORT NAME ACROSS DOMAINS -- e.g. srv01.contoso.local and
                    # srv01.fabrikam.local. Measured: 31 such keys on this estate; a large customer will
                    # have many more.
                    if ($short[$sk].Id -ne $id) { [void]$shortCollisions.Add($sk) }
                } else { $short[$sk] = $entry }
            }

            $pk = Get-SIIdentityPathKey -AssetId $id
            if ($pk -and -not $path.ContainsKey($pk)) { $path[$pk] = $entry }
        }
    }

    # 🔒 AN AMBIGUOUS SHORT NAME RESOLVES TO NOTHING (finding #76). The short-name link exists because
    # ExposureGraph names a device by FQDN while the endpoint profile stores the MDE short name, so a
    # full-name key misses. But when two assets share a short name the link cannot say WHICH one, and
    # handing back an arbitrary id would be a silent mis-attribution -- the operator would have no way
    # to tell a correct id from a coin toss. So the colliding keys are DROPPED: those names fall
    # through to the exact-name and ARM-path links, and report an empty id if neither answers.
    # 📌 This is the same rule applied everywhere else in this work: an empty id is a fact an operator
    # can act on; a wrong id is not.
    foreach ($ck in $shortCollisions) { [void]$short.Remove($ck) }
    foreach ($ak in $armCollisions) { [void]$byArm.Remove($ak) }
    foreach ($ek in $egCollisions) { [void]$byEg.Remove($ek) }

    $script:_SIIdentityExact = $exact
    $script:_SIIdentityShort = $short
    $script:_SIIdentityPath  = $path
    $script:_SIIdentityIds   = $ids
    $script:_SIIdentityById  = $byId
    $script:_SIIdentityByArm = $byArm
    $script:_SIIdentityByEg  = $byEg
    $script:_SIIdentityStats = [pscustomobject]@{
        Tables          = $stats
        Exact           = $exact.Count
        Short           = $short.Count
        Path            = $path.Count
        Ids             = $ids.Count
        ShortCollisions = $shortCollisions.Count
        VmToDevice      = $byArm.Count
        EgToDevice      = $byEg.Count
    }

    $per = ($stats.GetEnumerator() | ForEach-Object { '{0}={1}' -f ($_.Key -replace '^SI_|_Profile_CL$',''), $_.Value }) -join ' '
    Write-Info ("[identity] asset-identity map built -- {0}; keys: exact={1} short={2} path={3}; Azure VMs linked to their device: {4}" -f $per, $exact.Count, $short.Count, $path.Count, $byArm.Count)
    if ($shortCollisions.Count -gt 0) {
        # Silence here would mean an operator could never tell a correct id from an arbitrary one.
        Write-Warn2 ("[identity] {0} short-name collision(s) DROPPED -- two or more assets share each of these short names, so the short-name link cannot say which is meant and resolves to NO id rather than an arbitrary one. Exact-name and ARM-path matches are unaffected." -f $shortCollisions.Count)
    }
}

function Resolve-SIAssetIdentity {
    <#
        Name -> identity, by SOURCE PRIORITY. Returns $null when nothing matches, which is a real
        answer: an asset with no identity anywhere (an ExposureGraph subscription node, say) SHOULD
        report an empty id rather than borrow one.
    #>
    [CmdletBinding()]
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or -not $script:_SIIdentityExact) { return $null }
    $n = $Name.Trim()

    $hit = $null
    if ($script:_SIIdentityExact.TryGetValue($n, [ref]$hit)) { return $hit }

    # EG names a device by FQDN, the endpoint profile stores the MDE short name -- measured, a
    # full-name key resolved 3 of 4 device probes and missed exactly the FQDN one.
    $sk = Get-SIIdentityShortKey -Name $n
    if ($sk -and $script:_SIIdentityShort.TryGetValue($sk, [ref]$hit)) { return $hit }

    # EG labels a child resource "<child> (<parent>/<child>)"; ARM-derived profiling names it after
    # its resource group. The parenthetical is the ARM <parent>/<child> pair.
    $m = [regex]::Match($n, '\(([^)]+)\)\s*$')
    if ($m.Success) {
        $pk = $m.Groups[1].Value.ToLowerInvariant()
        if ($script:_SIIdentityPath.TryGetValue($pk, [ref]$hit)) { return $hit }
    }
    $null
}

function Get-SIAssetIdentityStats { $script:_SIIdentityStats }

# ================================================================================================
# WHERE DID THIS ID COME FROM?  (operator, 2026-09-01: "so i know where it came from")
# ================================================================================================
# 🔴 THE ID COLUMN CARRIES FOUR NAMESPACES AND SAYS SO NOWHERE. Measured over the 1000 distinct
# impacted-asset ids on one live snapshot: 978 are SI-authored asset ids, 19 are ExposureGraph node
# ids (32 hex characters, NO dashes), 3 are ARM resource ids carrying an `az:` prefix, and 3 are raw
# IPv4 addresses -- the last correctly so, because for a public-IP report the address IS the asset.
#
# 🪤 AN SI ASSET ID AND AN EXPOSUREGRAPH NODE ID BOTH LOOK LIKE HEX. Nothing about the VALUE
# distinguishes them reliably, and they resolve in different systems. So the first question asked is
# not "what shape is this" but "did we author it" -- answered against the identity map this run
# already built, not guessed. Shape rules only ever run on ids the map does not know.
#
# 📌 An `az:` prefix already exists on ONE path, i.e. somebody hit this before and solved it by
# mangling the VALUE. That breaks joins -- an `az:`-prefixed id matches nothing in the profile
# tables -- which is why the answer is a separate column and not a prefix convention.
#
# 🔒 The returned wording is CUSTOMER-FACING and names a system an operator can go and look in. No
# column names, no internal jargon: the reader wants to know where to resolve the id, not which
# branch of which coalesce produced it.
# A report on SI_CI_CL publishes the CI's own id as AssetId (si_ci_id). The engine labels those rows with this value
# (the findings are keyed on the CI through it -- RA-Findings.ps1 Get-SIFindingCiId).
$script:SIAssetIdSourceCi = 'SecurityInsight CI'

function Get-SIAssetIdSource {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$AssetId)

    if ([string]::IsNullOrWhiteSpace($AssetId)) { return '' }
    $id = $AssetId.Trim()

    # 1. Did we author it? Authoritative, and it covers ~98% of real ids.
    # 🪤 The map is built once per run and may legitimately be absent -- a run that never needed it,
    # or a table that does not exist on this install. Absent is NOT "no", so fall through to shape
    # rather than claiming the id is foreign.
    if ($script:_SIIdentityIds -and $script:_SIIdentityIds.Contains($id)) { return 'SecurityInsight asset id' }

    # 2. Shape, in the order that cannot be ambiguous.
    if ($id -match '^az:' -or $id -match '^/subscriptions/') { return 'Azure resource id' }

    $parsedIp = [System.Net.IPAddress]::None
    if ([System.Net.IPAddress]::TryParse($id, [ref]$parsedIp)) { return 'IP address' }

    # A GUID has dashes; an ExposureGraph node id is 32 bare hex characters. Both are "hex", so the
    # DASHES are the whole distinction -- test the node shape first, then the guid.
    if ($id -match '^[0-9a-fA-F]{32}$') { return 'Exposure Graph node id' }
    $parsedGuid = [guid]::Empty
    if ([guid]::TryParse($id, [ref]$parsedGuid)) { return 'Directory object id' }

    # 3. 📌 Named, not blanked. "Unrecognized" is a fact an operator can act on; a blank reads as a
    # missing value and invites the reader to assume the id is fine.
    return 'Unrecognized id format'
}

# ================================================================================================
# ONE ASSET, ONE IDENTITY  (operator, 2026-10-02: "i dont like correlation is not working" / "this is same device")
# ================================================================================================
# 🔴 Measured 2026-10-02: the Top 50 listed one server twice -- MGMT1 (153 findings) and mgmt1.2linkit.local (35).
# The device reports already carried the RIGHT asset id (the profile's), only under ExposureGraph's name; the Azure
# reports carried the VM's ARM id, which -- since #204 -- the endpoint profile records on that same device. Every
# later step (the Top 50, the AI rollup, the published tables) groups by name, so the identity was resolved and then
# thrown away. This turns a resolved (name, id) into THE asset: the device that carries a VM id, else the profile
# asset with that id -- its own id and its own profile name. Anything not in the map is returned unchanged.
function Test-SIAssetNameIsId {
    <# PURE. A "name" that is really an id -- a 32/40-hex node or device id, a GUID, an ARM path -- is never shown in place of a real name. #>
    param([AllowEmptyString()][string]$Name)
    $n = ([string]$Name).Trim()
    ($n -eq '') -or ($n -match '^[0-9a-fA-F]{32}$') -or ($n -match '^[0-9a-fA-F]{40}$') -or ($n -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') -or ($n -match '^(az:)?/subscriptions/')
}

function Resolve-SICanonicalAsset {
    param([AllowEmptyString()][string]$Name, [AllowEmptyString()][string]$Id)
    $hit = $null
    if (-not [string]::IsNullOrWhiteSpace($Id)) {
        $raw = $Id.Trim()
        $arm = ($raw -replace '^az:', '').ToLowerInvariant()
        # an ExposureGraph node, prefixed by the azure engine (eg:az:<node>) or bare as the attack-path reports carry it --
        # measured 2026-10-02: dc1 / dc3 appeared a second time in the Top 50 under their bare node id. 32 hex only: an MDE
        # device id is 40, an SI id is a GUID, and the lookup holds only devices' own graph nodes.
        $egn = if ($raw -match '^(eg:az:)?([0-9a-fA-F]{32})$') { $Matches[2].ToLowerInvariant() } else { '' }
        if ($script:_SIIdentityByArm -and $arm -like '/subscriptions/*' -and $script:_SIIdentityByArm.TryGetValue($arm, [ref]$hit)) { }
        elseif ($script:_SIIdentityByEg -and $egn -and $script:_SIIdentityByEg.TryGetValue($egn, [ref]$hit)) { }
        elseif ($script:_SIIdentityById -and $script:_SIIdentityById.TryGetValue($raw, [ref]$hit)) { }
        else { $hit = $null }
        if ($hit) {
            # the asset's own profile name -- unless that "name" is only an id and the row has a real one
            $nm = if ((Test-SIAssetNameIsId $hit.Name) -and -not (Test-SIAssetNameIsId $Name)) { $Name } else { $hit.Name }
            return [pscustomobject]@{ Name = $nm; Id = $hit.Id; Changed = ($nm -cne $Name -or $hit.Id -cne $Id) }
        }
    }
    [pscustomobject]@{ Name = $Name; Id = $Id; Changed = $false }
}
function ConvertTo-SICanonicalAssetPairs {
    <# Aligned name / id lists -> the canonical assets, one entry per asset (by id, or by name when there is no id), sorted by name. #>
    param([AllowEmptyCollection()][string[]]$Names, [AllowEmptyCollection()][string[]]$Ids)
    $n = @($Names); $i = @($Ids)
    if ($n.Count -eq 0 -or $n.Count -ne $i.Count) { return [pscustomobject]@{ Names = $n; Ids = $i; Changed = $false } }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $pairs = New-Object System.Collections.Generic.List[object]
    $changed = $false
    for ($k = 0; $k -lt $n.Count; $k++) {
        $c = Resolve-SICanonicalAsset -Name ([string]$n[$k]) -Id ([string]$i[$k])
        if ($c.Changed) { $changed = $true }
        $key = if ([string]::IsNullOrWhiteSpace($c.Id)) { 'name:' + $c.Name } else { 'id:' + $c.Id }
        if (-not $seen.Add($key)) { $changed = $true; continue }
        $pairs.Add($c)
    }
    if (-not $changed) { return [pscustomobject]@{ Names = $n; Ids = $i; Changed = $false } }
    # ORDINAL, like every other asset list in the engine (Sort-SIOrdinal) -- a culture sort puts kv1 before MGMT1.
    $arr = $pairs.ToArray(); $keys = [string[]]@($arr | ForEach-Object { [string]$_.Name })
    [Array]::Sort($keys, $arr, [System.StringComparer]::Ordinal)
    $sorted = $arr
    [pscustomobject]@{ Names = [string[]]@($sorted | ForEach-Object { [string]$_.Name }); Ids = [string[]]@($sorted | ForEach-Object { [string]$_.Id }); Changed = $true }
}