#Requires -Version 5.1
<#
    SI v3 -- SI_AssetName UNIQUENESS. The snapshot pass that the row builder cannot be.

    🔒 OPERATOR REQUIREMENT, 2026-08-28: "all assets must have a unique name and identifier. 100%",
    then, once the measurement below was in: "qualify only where it collides".

    📊 MEASURED THE SAME DAY -- per-snapshot, uncontaminated, against the live workspace:
        endpoint  198 rows / 198 unique ids / 196 unique names
        identity  765 rows / 765 unique ids / 395 unique names   <- 370 duplicates
        azure     769 rows / 769 unique ids / 302 unique names   <- 467 duplicates
        publicip   11 rows /  11 unique ids /  11 unique names
    SI_AssetId ALREADY satisfies the requirement outright -- 100% populated and 100% unique on all four
    engines. SI_AssetName is 100% populated and NOT unique, and the azure figure (302) independently
    reproduces the 303 name-keys the RA catalog comment recorded from the other direction.

    🪤 THE MEASUREMENT ONLY MEANS ANYTHING SNAPSHOT-SCOPED. si-v3 and prod write the SAME four tables,
    and prod (v2.2.460) does not emit these columns at all -- zero occurrences in its builders or
    schemas. So a cross-snapshot read mixes rows that structurally cannot carry the field with rows
    that do, and every empty collapses into ONE bucket. That is exactly how "781 rows / 771 distinct"
    was produced and misread as a builder defect. A snapshot comes from exactly one run, so within one
    CollectionTime either every row has the column or none does.

    🔑 WHY THIS IS NOT IN THE ROW BUILDER. A collision is a property of the SNAPSHOT, not of a row: a
    builder handed one asset cannot know that another asset shares its name. A per-row uniqueness
    assertion would be a test that passes because it cannot see the counter-example. This runs once,
    over the COMPLETE built row set, after the build loop and before the ingest.

    This is the profiling half of the split the operator drew: "correlation is to merge all records
    into one, where the profiling is about building the raw data." Profiling guarantees the two fields
    are POPULATED and, here, that they are unique WITHIN one engine's snapshot. Merging the same
    real-world asset across engines stays correlation's job and is not attempted here.

    NO Set-StrictMode -- it leaks into the caller's scope (measured 2026-08-12).
#>

# 🔴 THE ROW/ID PRIMITIVES MOVED to engine/_shared/SI-AssetIdentity.ps1 -- Get-SIIdFragment,
# Get-SIRowValue and Set-SIRowValue -- and are dot-sourced from there. They were declared HERE first,
# and the identity module then called them, which put the dependency the wrong way round: the
# vocabulary module depended on the snapshot-pass module. It PARSED CLEANLY and blew up only when
# Resolve-SIAssetIdentityPair was actually executed ("Get-SIRowValue is not recognized"), which is one
# more instance of this codebase's standing rule -- a parse check cannot prove code runs.
. (Join-Path $PSScriptRoot 'SI-AssetIdentity.ps1')

function Resolve-SIAssetNameCollisions {
    <#
        Qualify SI_AssetName ONLY where it collides, and leave every already-unique name untouched.

        QUALIFIER CHOICE, in order:
          1. each -Discriminators entry, in preference order, IF it actually separates the group --
             a meaningful qualifier ("web-01 (rg-prod)") beats an opaque one wherever one exists;
          2. otherwise the 8-char tail of SI_AssetId -- which usually separates the group, but NOT
             always: an ARM id's tail is the resource name the group shares (#129);
          3. otherwise a short stable SHA-256 of the FULL SI_AssetId (8, then 12/16/64 hex chars),
             which separates any two distinct ids. Used only when 1 and 2 both fail, so names that
             already resolved never change.

        Assignment is ordered by SI_AssetId ORDINALLY -- never Sort-Object's culture compare, which
        makes the same estate produce different names on a Danish host than an English one (the bug
        already recorded for SI_CorrelationId, and SI ships to ~6,000 installs whose locale we do not
        choose). So an asset receives the same qualified name on every run.

        🔴 A QUALIFIED NAME CAN COLLIDE WITH AN UNQUALIFIED ONE. Every candidate is tested against the
        names in use across the WHOLE set, not merely within its own group -- otherwise qualifying
        "web-01" to "web-01 (rg-prod)" would silently fuse with a resource genuinely named that.

        ⚠️ SHARDING. Profiling can be split across replicas (Invoke-Discover, hash mod ShardCount) and a
        replica holds only its slice, so with ShardCount > 1 uniqueness is SHARD-LOCAL. The summary
        says so rather than reporting a guarantee this cannot make. ShardCount defaults to 1 and no
        shipped launcher raises it, so the guarantee holds for the shipped configuration.

        Mutates SI_AssetName in place. Returns a summary object for the run log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter()][string[]]$Discriminators = @(),
        [Parameter()][int]$ShardCount = 1
    )

    $result = [ordered]@{
        Rows            = @($Rows).Count
        Groups          = 0
        Qualified       = 0
        ByDiscriminator = @{}
        ById            = 0
        Unqualifiable   = 0
        UniqueBefore    = 0
        UniqueAfter     = 0
        ShardLocal      = ($ShardCount -gt 1)
    }
    if (@($Rows).Count -eq 0) { return $result }

    # ORDINAL grouping, matching Log Analytics. KQL string comparison is case-sensitive, so two names
    # differing only in case ARE two distinct names in the table; merging them here would report a
    # collision the table does not have.
    # 🪤 A BARE `@{}` CANNOT DO THIS. PowerShell hashtable keys are CASE-INSENSITIVE by default, so
    # 'Server1' and 'server1' land in one bucket and get reported as a collision that Log Analytics
    # does not have -- and one of them would then be needlessly renamed. Caught by a test that failed
    # first; an explicit ordinal comparer is the fix.
    $byName = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.ArrayList]' ([System.StringComparer]::Ordinal)
    foreach ($r in $Rows) {
        $n = Get-SIRowValue -Row $r -Name 'SI_AssetName'
        if (-not $byName.ContainsKey($n)) { $byName[$n] = New-Object System.Collections.ArrayList }
        [void]$byName[$n].Add($r)
    }
    $result.UniqueBefore = $byName.Keys.Count

    $used = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($n in $byName.Keys) { [void]$used.Add([string]$n) }

    foreach ($n in @($byName.Keys)) {
        $group = @($byName[$n])
        if ($group.Count -le 1) { continue }
        $result.Groups++

        # 🔴 ORDINAL sort, NOT Sort-Object. `Sort-Object` compares with the CURRENT CULTURE: this
        # machine runs da-DK, where 'aa' collates as 'å' -- the LAST letter -- so the same estate
        # produces a DIFFERENT member-order, and therefore different qualified names, on a Danish host
        # than an English one. SI ships to ~6,000 installs whose locale we do not choose. This is the
        # identical defect already recorded for SI_CorrelationId's seed, and the first draft of this
        # function reproduced it -- a test caught it, reading correctly and picking the wrong row.
        $ids = New-Object 'System.Collections.Generic.List[string]'
        $byId = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.ArrayList]' ([System.StringComparer]::Ordinal)
        foreach ($row in $group) {
            $rid = [string](Get-SIRowValue -Row $row -Name 'SI_AssetId')
            if (-not $byId.ContainsKey($rid)) { $byId[$rid] = New-Object System.Collections.ArrayList; $ids.Add($rid) }
            [void]$byId[$rid].Add($row)
        }
        $ids.Sort([System.StringComparer]::Ordinal)
        $ordered = @(foreach ($rid in $ids) { foreach ($row in $byId[$rid]) { $row } })

        # The FIRST member keeps the bare name. Qualifying every member would rewrite names that were
        # already readable, and exactly one member of a group can legitimately keep the plain form.
        $first = $true
        foreach ($row in $ordered) {
            if ($first) { $first = $false; continue }

            $assigned = $null
            foreach ($d in @($Discriminators)) {
                # 🔴 A LIBRARY MUST NOT CRASH ON A NULL ELEMENT. `[string[]]$null` binds as a
                # ONE-element array containing $null, so a caller that meant "no discriminators" can
                # hand this loop an empty name -- which is precisely what took the identity engine
                # down on a real run. The caller was fixed too; this is the belt.
                if ([string]::IsNullOrWhiteSpace([string]$d)) { continue }
                $dv = Get-SIRowValue -Row $row -Name ([string]$d)
                if ([string]::IsNullOrWhiteSpace($dv)) { continue }
                $cand = '{0} ({1})' -f $n, $dv
                if (-not $used.Contains($cand)) {
                    $assigned = $cand
                    if (-not $result.ByDiscriminator.ContainsKey($d)) { $result.ByDiscriminator[$d] = 0 }
                    $result.ByDiscriminator[$d]++
                    break
                }
            }
            if (-not $assigned) {
                $fullId = [string](Get-SIRowValue -Row $row -Name 'SI_AssetId')
                $frag = Get-SIIdFragment -Id $fullId
                if ($frag) {
                    $cand = '{0} ({1})' -f $n, $frag
                    if (-not $used.Contains($cand)) { $assigned = $cand; $result.ById++ }
                }
                # LAST RESORT (#129): the tail is NOT always unique. For an ARM id the last 8 alphanumerics
                # are the resource name itself -- exactly what the colliding rows share -- so the 5th
                # 'vnet-hub' in the same resource-group name was left Unqualifiable, and '1.2.3.45' vs
                # '12.3.4.5' share the tail '12345'. A short stable hash of the FULL id separates them.
                # Used ONLY where everything above failed, so every name that already resolved stays
                # byte-identical (names feed the CMDB, and churn there is a real cost).
                if (-not $assigned -and -not [string]::IsNullOrWhiteSpace($fullId)) {
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try { $hex = (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fullId)) | ForEach-Object { $_.ToString('x2') })) }
                    finally { $sha.Dispose() }
                    foreach ($len in 8, 12, 16, 64) {
                        $cand = '{0} ({1})' -f $n, $hex.Substring(0, $len)
                        if (-not $used.Contains($cand)) { $assigned = $cand; $result.ById++; break }
                    }
                }
            }
            # No id and no usable discriminator: leave the name alone rather than invent one. The row
            # keeps a duplicate name and the summary COUNTS it, which is visible to an operator; a
            # fabricated qualifier would not be.
            if (-not $assigned) { $result.Unqualifiable++; continue }

            Set-SIRowValue -Row $row -Name 'SI_AssetName' -Value $assigned
            [void]$used.Add($assigned)
            $result.Qualified++
        }
    }

    $after = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($r in $Rows) { [void]$after.Add([string](Get-SIRowValue -Row $r -Name 'SI_AssetName')) }
    $result.UniqueAfter = $after.Count
    $result
}
