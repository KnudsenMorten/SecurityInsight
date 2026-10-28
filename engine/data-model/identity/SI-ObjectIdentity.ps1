#Requires -Version 5.1
<#
    SI v3 -- THE IDENTITY LEDGER, as pure functions.

    Operator decision 2026-08-13 (V3-ARCHITECTURE 2.3a): a minted, stored SI_CorrelationId plus an
    anchor ledger and a superseded table. ANCHORS ARE HOW WE RECOGNISE AN ASSET; THEY ARE NEVER WHAT WE
    CALL IT.

    🔴 WHY THIS EXISTS, and it is a correctness fix rather than an optimisation.
    Get-SICorrelationId seeds from the ordinally-lowest value of the highest-priority type PRESENT IN
    THE GROUP. That is `same INPUT -> same id`, which is NOT what a connector needs -- it needs
    `same OBJECT -> same id`. The two diverge the moment group membership changes, and membership is not
    stable:

      * MEASURED 2026-08-13: adding one member carrying a lower-sorting exposure-graph id moved a group
        from `exposuregraphnodeid:aaa` to `exposuregraphnodeid:000`.
      * The same day, EndpointEG timed out at 0 rows and 51 assets left the snapshot entirely.
      * Anchors churn regardless: MDE device ids rotate, a rebuilt VM gets a new ARM path, a re-enrolled
        device gets a new AadDeviceId. Editing SISeedPriority would re-key the whole estate at once.

    A ServiceNow CI bound to a key that moves becomes a SECOND CI, and duplicate CIs are effectively
    permanent once incidents point at them.

    🔑 WHY NOT "PICK A DURABLE NATIVE ID AND RE-PICK WHEN IT DIES" -- considered and rejected by the
    operator. Re-picking IS the orphaning event. Their own example proves anchors die while assets live:
    decommission AD sync and the SID goes. Everyone who tried natural-key-as-identity built the alias
    table anyway -- sIDHistory, and Entra Connect keying ms-DS-ConsistencyGuid rather than SID.
    ServiceNow's own answer is correlation_id PLUS the IRE identification rules.

    PURE ON PURPOSE. No SQL, no I/O. The store is a detail; the DECISIONS are the part worth proving,
    and they are provable before a schema exists. Same reasoning as SI-CorrelationCore.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# Namespace for SI's UUIDv5 derivation. Fixed forever: changing it re-keys every asset in every estate,
# which is the one thing this file exists to prevent. Chosen once, never generated at runtime.
$script:SIObjectIdNamespace = [guid]'6b1f4a2e-8c33-5d47-9a10-2f7e5c8d4b91'

# The birth anchor's type priority. The correlation engine (Pro) sets the same list in SI-CorrelationCore.ps1; the CI build
# runs WITHOUT it in Community (Risk Analysis builds the CIs), where this list was missing and every object minted the
# same id. Same values -- one list, set here when the correlation engine has not.
if (-not $script:SISeedPriority) {
    $script:SISeedPriority = @('ExposureGraphNodeId', 'EgNodeId', 'AzureResourceId', 'AadDeviceId', 'AadObjectId', 'MdeDeviceId',
        'ActiveDirectoryObjectGuid', 'SecurityIdentifier', 'OnPremObjectGuid', 'AzureVmId')
}

# #642 THE IDENTIFIER TYPES ONE OBJECT HOLDS EXACTLY ONCE (lower-case canonical type). A service principal has one object id
# and one app id; an Azure resource is its one resource id; an Exposure Graph node and an AD object guid name one object.
# Types that legitimately rotate or come in several on one object (a Defender device id after a re-onboarding, an Entra
# device id after a re-registration, a SID with history) are NOT here -- they never prove two objects apart.
$script:SIOnePerObjectIdTypes = @('aadobjectid', 'aadappid', 'azureresourceid', 'exposuregraphnodeid', 'activedirectoryobjectguid', 'cloudnativeresourceid')

function Test-SILedgerWrongMerge {
    <#
        PURE. #642 IS THIS GROUP PROVABLY ANOTHER OBJECT THAN THE REST OF THE LEDGER ID IT RESOLVED TO?

        Found at a ring 1 install 2026-10-13: one ledger id held 11 different service principals (11 object ids, 11 app ids,
        11 Exposure Graph nodes, all born in ONE run) -- separate per-subscription service principals with the same display
        name. An Exposure Graph node matched BY DISPLAY NAME had given every one of them the same node id (Invoke-Collect.ps1,
        identity EG enrichment), the correlation fused them on it, and the ledger kept the fusion for good: every run after
        that each service principal resolved to the one id again.

        The proof needs no guess about sources that failed (the reason Resolve-SIObjectIdentity never splits on its own): for
        TWO OR MORE identifier types an object holds only once ($script:SIOnePerObjectIdTypes), the id holds a value of the
        group's own type that the group does not carry, and that value was written in the SAME RUN as the group's own value
        (FirstSeen within one second). One object cannot have two object ids AND two app ids born in the same run; an object
        whose id rotated over time (a new value in a later run) is never taken for two objects.

        -Ids: the group's identifiers (Type, Value; canonical, lower-cased). -AnchorKeys: the ledger keys of the id (Get-SILedgerKeysOfId).
        Returns @{ Proven; Types = the conflicting types }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Ids, [Parameter()][AllowNull()][hashtable]$Ledger,
          [Parameter()][AllowEmptyCollection()][string[]]$AnchorKeys = @())
    $none = [pscustomobject]@{ Proven = $false; Types = @() }
    if ($null -eq $Ledger -or @($AnchorKeys).Count -eq 0) { return $none }
    # the group's own anchors under this id, by type: key -> FirstSeen
    $own = @{}; $ownKeys = @{}
    foreach ($id in $Ids) {
        $t = ([string]$id.Type).ToLowerInvariant()
        if ($script:SIOnePerObjectIdTypes -notcontains $t) { continue }
        $k = Get-SILedgerEntryKey -Ledger $Ledger -Type ([string]$id.Type) -Value ([string]$id.Value)
        $ownKeys[(Get-SILedgerKey -Type ([string]$id.Type) -Value ([string]$id.Value))] = $true
        if ($null -eq $k) { continue }
        $ownKeys[$k] = $true
        if (-not $own.ContainsKey($t)) { $own[$t] = New-Object System.Collections.Generic.List[datetime] }
        if ($null -ne $Ledger[$k].FirstSeen) { $own[$t].Add([datetime]$Ledger[$k].FirstSeen) }
    }
    foreach ($x in @($own.Keys)) { if ($own[$x].Count -eq 0) { $own.Remove($x) } }
    if ($own.Count -lt 2) { return $none }
    $types = New-Object System.Collections.Generic.List[string]
    foreach ($ak in $AnchorKeys) {
        if ($ownKeys.ContainsKey($ak)) { continue }
        $cut = ([string]$ak).IndexOf('|'); if ($cut -lt 1) { continue }
        $t = ([string]$ak).Substring(0, $cut)
        if (-not $own.ContainsKey($t) -or $types.Contains($t)) { continue }
        if ($null -eq $Ledger[$ak] -or $null -eq $Ledger[$ak].FirstSeen) { continue }
        $fs = [datetime]$Ledger[$ak].FirstSeen
        foreach ($mine in $own[$t]) { if ([Math]::Abs(($fs - $mine).TotalSeconds) -lt 1) { $types.Add($t); break } }
    }
    [pscustomobject]@{ Proven = ($types.Count -ge 2); Types = $types.ToArray() }
}

function Get-SILedgerIdKeeperKey {
    <#
        PURE. #642 The ledger key of the anchor whose object KEEPS a ledger id when the id is found to hold several objects:
        the anchor the id was minted from (its v5 id is the id itself) -- else the oldest anchor (FirstSeen), ties broken by
        the ordinally lowest key. Decided from the ledger alone, so every batch of a CI build and every engine agree on it.
    #>
    param([Parameter(Mandatory)][string]$CorrelationId, [Parameter()][AllowNull()][hashtable]$Ledger,
          [Parameter()][AllowEmptyCollection()][string[]]$AnchorKeys = @())
    $best = $null; $bestT = $null
    foreach ($ak in $AnchorKeys) {
        if ((New-SIObjectUuidV5 -Name ([string]$ak)).ToString() -eq $CorrelationId) { return [string]$ak }
        $t = [datetime]::MaxValue; if ($null -ne $Ledger[$ak] -and $null -ne $Ledger[$ak].FirstSeen) { $t = [datetime]$Ledger[$ak].FirstSeen }
        if ($null -eq $best -or $t -lt $bestT -or ($t -eq $bestT -and [string]::CompareOrdinal([string]$ak, $best) -lt 0)) { $best = [string]$ak; $bestT = $t }
    }
    $best
}

function New-SIObjectUuidV5 {
    <#
        RFC 4122 v5 (SHA-1, name-based) UUID.

        DETERMINISTIC AT BIRTH, which is the whole point of choosing v5 over a random GUID: if the
        ledger is ever lost, ids can be PARTIALLY rebuilt by re-deriving from the anchors that are still
        present, instead of re-keying the estate and orphaning every CI. A random GUID would have made
        loss unrecoverable.

        🔒 It is derived ONCE, at birth, and then STORED. It is never re-derived at runtime to answer
        "what is this object called" -- that would reintroduce exactly the anchor-dependence this
        design removes. Derivation is for minting and for disaster recovery, nothing else.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][guid]$Namespace = $script:SIObjectIdNamespace
    )

    # Namespace goes in BIG-ENDIAN network order, per RFC 4122. .NET's Guid.ToByteArray() returns the
    # first three fields little-endian, so they must be flipped or the id differs from every other
    # implementation -- and an id that disagrees with the rest of the world is a bug we would only find
    # when someone cross-checked it.
    $nb = $Namespace.ToByteArray()
    [Array]::Reverse($nb, 0, 4)
    [Array]::Reverse($nb, 4, 2)
    [Array]::Reverse($nb, 6, 2)

    # 🪤 NOT `$name` -- PowerShell variable names are CASE-INSENSITIVE, so `$name` IS the `[string]$Name`
    # parameter. Assigning a byte[] into it silently COERCES back to a string, and `.Length` then counts
    # characters instead of bytes: the buffer is sized wrong and Array.Copy dies with "Source array was
    # not long enough". It failed on some inputs and not others, which is what made it look like a data
    # problem rather than a shadowing one.
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
    $buf = New-Object byte[] ($nb.Length + $nameBytes.Length)
    [Array]::Copy($nb, 0, $buf, 0, $nb.Length)
    [Array]::Copy($nameBytes, 0, $buf, $nb.Length, $nameBytes.Length)

    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash($buf) } finally { $sha.Dispose() }

    $out = New-Object byte[] 16
    [Array]::Copy($hash, 0, $out, 0, 16)
    $out[6] = [byte](($out[6] -band 0x0F) -bor 0x50)   # version 5
    $out[8] = [byte](($out[8] -band 0x3F) -bor 0x80)   # RFC 4122 variant

    # Flip back to .NET's little-endian layout so [guid] renders the canonical string.
    [Array]::Reverse($out, 0, 4)
    [Array]::Reverse($out, 4, 2)
    [Array]::Reverse($out, 6, 2)
    [guid][byte[]]$out
}

function Get-SIObjectBirthAnchor {
    <#
        The anchor an object is BORN with: highest-priority identifier type present, and within that
        type the ordinally-lowest value.

        Reuses SISeedPriority so birth and today's seed agree -- but note the difference that matters:
        this is consulted ONCE, at mint. After that the id is stored and the anchor may die freely.

        ORDINAL, never Sort-Object: culture-sensitive sort makes the same object mint a different id on
        a Danish host than an English one (see Sort-SIOrdinal). SI ships to ~6,000 installs whose locale
        we do not choose.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Identifiers)

    $ids = @($Identifiers | Where-Object { $null -ne $_ })
    if ($ids.Count -eq 0) { return $null }

    foreach ($type in $script:SISeedPriority) {
        $vals = @()
        foreach ($id in $ids) { if ($id.Type -ieq $type) { $vals += [string]$id.Value } }
        if ($vals.Count -gt 0) {
            $first = @(Sort-SIOrdinal -Value $vals)[0]
            return [pscustomobject]@{ Type = (Get-SICanonicalIdType -Type $type); Value = [string]$first }
        }
    }
    # 🔴 No type of the priority list (a public IP, an Intune-only device, an app id): the ordinally-lowest ledger key of
    # what the object HAS. Returning nothing here minted every such object from the empty key -- ONE id for all of them
    # (#477, 2026-10-09: found when the CI build ran without the correlation engine, where the list was not even loaded).
    $keys = @(foreach ($id in $ids) { Get-SILedgerKey -Type ([string]$id.Type) -Value ([string]$id.Value) })
    $low = @(Sort-SIOrdinal -Value $keys)[0]
    $cut = $low.IndexOf('|')
    $match = @($ids | Where-Object { (Get-SILedgerKey -Type ([string]$_.Type) -Value ([string]$_.Value)) -ceq $low })[0]
    [pscustomobject]@{ Type = (Get-SICanonicalIdType -Type ([string]$match.Type)); Value = $low.Substring($cut + 1) }
}

function Get-SILedgerKey {
    <# The ledger's lookup key. Canonicalised and lower-cased, so one fact cannot have two spellings. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Type,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    # while Resolve-SIObjectIdentity runs, every key is made once (2026-10-16: five times per identifier of every object --
    # a quarter of the correlation job's ledger step on a large install); the same text, from a table of this call's keys
    $memo = $script:SILedgerKeyMemo
    if ($null -ne $memo) {
        $mk = $Type + [char]1 + $Value
        $hit = $null
        if ($memo.TryGetValue($mk, [ref]$hit)) { return $hit }
        $k = '{0}|{1}' -f (Get-SICanonicalIdType -Type $Type).ToLowerInvariant(), ([string]$Value).ToLowerInvariant()
        $memo[$mk] = $k
        return $k
    }
    '{0}|{1}' -f (Get-SICanonicalIdType -Type $Type).ToLowerInvariant(), ([string]$Value).ToLowerInvariant()
}

# The widest identifier value the ledger's table holds is 256 characters (si.ObjectIdentity.IdentifierValue,
# NVARCHAR(256)). The column is part of the table's primary key, so it cannot simply be made wider: SQL Server limits a
# clustered key to 900 bytes, and the type (64 characters) + 256 characters already take 640 of them.
function ConvertTo-SILedgerStoredValue {
    <#
        PURE. THE ONE RULE for an identifier value that is longer than the ledger's column (an Azure resource id can be
        2,000 characters and more): the value as the ledger's table stores it and looks it up.

          256 characters or fewer -> the value itself, untouched
          longer                  -> '~sha256:' + SHA-256 of the lower-cased value (64 hex) + ':' + its first 160 characters

        The same long value always gives the same short form (so it is found again), two different long values never give
        the same one (the hash decides; the readable start is only there so a person can see what it is). Always 233
        characters or fewer. The id an object is BORN with is still derived from the full value (New-SIObjectUuidV5) --
        this is only what the table holds.

        Found 2026-10-12: a new install's first run wrote 18,820 anchors for 10 minutes and lost all of them, because one
        Azure resource id did not fit the column.

        (The two numbers are written out, not read from the variables above: this function is also called where this
        file's script scope is not the caller's.)
    #>
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value.Length -le 256) { return $Value }
    $low = $Value.ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hex = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($low))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $head = $low.Substring(0, 160)
    # never half of a two-part character at the cut
    if ([char]::IsHighSurrogate($head[$head.Length - 1])) { $head = $head.Substring(0, $head.Length - 1) }
    '~sha256:' + $hex + ':' + $head
}

function Get-SILedgerEntryKey {
    <#
        PURE. The key under which -Ledger holds this identifier, or $null when it does not: the plain key, or -- for a
        value longer than the ledger's column -- the key of its stored short form (what a ledger read from the table
        carries; ConvertTo-SILedgerStoredValue). A ledger kept as a file holds long values whole, so the plain key is
        asked first.
    #>
    param([Parameter()][AllowNull()][hashtable]$Ledger,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Type,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($null -eq $Ledger) { return $null }
    $k = Get-SILedgerKey -Type $Type -Value $Value
    if ($Ledger.ContainsKey($k)) { return $k }
    if ($Value.Length -gt 256) {
        $k2 = Get-SILedgerKey -Type $Type -Value (ConvertTo-SILedgerStoredValue -Value $Value)
        if ($Ledger.ContainsKey($k2)) { return $k2 }
    }
    $null
}

function Get-SILedgerKeysById {
    <#
        PURE. The ledger's keys by the id they point at, for "which anchors does this id hold" without
        reading the whole ledger once per object.

        Returns { LedgerKeys = <every ledger key, in the ledger's own order>; ById = <id -> positions in
        LedgerKeys, ascending>; Other = <positions whose id is not plain text> }.

        🔒 IT MUST FIND EXACTLY WHAT `[string]$Ledger[$k].CorrelationId -eq $cid` FINDS, in the same order.
        `-eq` on strings ignores case by the invariant culture's rules. For PLAIN text (printable ASCII --
        every id SI mints is a GUID) that is the same as an ordinal ignore-case match, which is what the
        lookup uses. An id with any other character is NOT indexed: it is kept in `Other` and compared with
        `-eq` itself (Get-SILedgerKeysOfId), so nothing is matched differently for it.
    #>
    param([Parameter()][AllowNull()][hashtable]$Ledger)
    $byId  = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[int]]' ([StringComparer]::OrdinalIgnoreCase)
    $other = New-Object System.Collections.Generic.List[int]
    $keys  = @()
    if ($null -ne $Ledger) { $keys = @($Ledger.Keys) }
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $c = [string]$Ledger[$keys[$i]].CorrelationId
        # \z, not $: a trailing line break is not plain text
        if ([regex]::IsMatch($c, '^[\x20-\x7E]*\z')) {
            $list = $null
            if (-not $byId.TryGetValue($c, [ref]$list)) { $list = New-Object System.Collections.Generic.List[int]; $byId[$c] = $list }
            [void]$list.Add($i)
        } else { [void]$other.Add($i) }
    }
    [pscustomobject]@{ LedgerKeys = $keys; ById = $byId; Other = $other }
}

function Get-SILedgerKeysOfId {
    <#
        PURE. The ledger keys that point at -CorrelationId, in the ledger's own order -- what a scan of
        every key with `[string]$Ledger[$k].CorrelationId -eq $CorrelationId` answers (Get-SILedgerKeysById).
    #>
    param([Parameter(Mandatory)]$Index, [Parameter()][AllowNull()][hashtable]$Ledger, [Parameter()][AllowNull()][AllowEmptyString()][string]$CorrelationId)
    $keys = $Index.LedgerKeys
    $pos  = New-Object System.Collections.Generic.List[int]
    if ([regex]::IsMatch([string]$CorrelationId, '^[\x20-\x7E]*\z')) {
        $list = $null
        if ($Index.ById.TryGetValue($CorrelationId, [ref]$list)) { foreach ($i in $list) { [void]$pos.Add($i) } }
        # ids that are not plain text: compared exactly as before, and put back in the ledger's order
        if ($Index.Other.Count -gt 0) {
            foreach ($i in $Index.Other) { if ([string]$Ledger[$keys[$i]].CorrelationId -eq $CorrelationId) { [void]$pos.Add($i) } }
            $pos.Sort()
        }
    } else {
        # the id asked for is not plain text: the scan, as before
        for ($i = 0; $i -lt $keys.Count; $i++) { if ([string]$Ledger[$keys[$i]].CorrelationId -eq $CorrelationId) { [void]$pos.Add($i) } }
    }
    foreach ($i in $pos) { $keys[$i] }
}

function Resolve-SIObjectIdentity {
    <#
        Decide each group's SI_CorrelationId against the existing ledger, and say what the ledger must
        become. Returns decisions; it does not write anything.

        Ledger is a hashtable: "type|value" -> @{ CorrelationId; FirstSeen }.
        Absent or empty means a first run, in which case everything mints -- which is correct, and is
        also the disaster-recovery path.

          MINT   no identifier is known         -> derive a v5 id from the birth anchor
          REUSE  all known identifiers agree    -> take the existing id, record any new identifiers
          MERGE  identifiers name 2+ ids        -> keep the OLDEST, supersede the rest, emit old->new

        🔒 THE OLDEST SURVIVES, not the "best". Any other rule (lowest tier, most members, newest) makes
        the surviving id depend on this run's data, which is the exact property being removed. FirstSeen
        decides; an ordinal id compare breaks ties so two hosts never disagree.

        ◻ SPLIT DETECTION IS DEFERRED, AND DELIBERATELY NOT GUESSED. A genuine split -- one object whose
        identifiers stop co-occurring -- cannot be told apart from "a source failed and half the
        identifiers are missing this run" by looking at one run. Getting that wrong RETIRES A LIVE CI,
        which is worse than a late one. It needs either two consecutive runs agreeing or an explicit
        operator action, and that is a separate decision. What this DOES do is report the shrink
        (`ShrunkObjects`) so it is visible rather than silent.
        🔑 THE ONE EXCEPTION, #642: a group that PROVABLY is another object than the rest of its id (Test-SILedgerWrongMerge
        -- two or more types an object holds once, each with another value written in the same run) is split off: a source
        that failed cannot produce that, a fused group can. The object the id was minted from keeps it (Action 'split',
        Splits Kind 'wrong-merge', counted in WrongMergeSplit).

        🔴 -AmbiguousIdKeys (#61.4, added 2026-08-20 after a LIVE failure). Ledger keys carried by more
        than one object this run, which happens only when an operator never-merge kept two groups
        apart. Such a key identifies NEITHER group any more, so it is excluded from three places --
        and ALL THREE are required, or the fix does not survive to the next run:

          1. the `$known` LOOKUP   -- or the shared anchor drags both halves back onto one id
          2. the BIRTH ANCHOR      -- or both halves mint the SAME v5 id from the shared value
          3. the ledger WRITE-BACK -- or the re-minted half claims the shared anchor, and next run the
                                      other half follows it and they MERGE again

        Measured before the fix: `distinct durable ids: 1 for 2 objects`. The derived seed was already
        correct by then, so the published map looked right while the LEDGER re-fused them -- and a
        durable id is exactly the one a connector is permitted to create CIs from.
    #>
    param(
        # AllowNull as well as AllowEmptyCollection: a caller flattening several sources can hand us an
        # array with a null element, and binding must not refuse it. The loop skips nulls itself.
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Groups,
        [Parameter()][hashtable]$Ledger,
        [Parameter()][datetime]$Now = ([datetime]'2000-01-01T00:00:00Z'),
        [Parameter()][AllowNull()][hashtable]$AmbiguousIdKeys
    )

    if ($null -eq $Ledger) { $Ledger = @{} }
    # the ledger keys of this call, each made once (Get-SILedgerKey); dropped at the end of the call
    $script:SILedgerKeyMemo = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $hasAmbiguous = ($null -ne $AmbiguousIdKeys -and $AmbiguousIdKeys.Keys.Count -gt 0)

    $decisions   = New-Object System.Collections.Generic.List[object]
    $superseded  = New-Object System.Collections.Generic.List[object]
    $shrunk      = New-Object System.Collections.Generic.List[object]
    $splits      = New-Object System.Collections.Generic.List[object]
    $unkeyable   = 0
    $keysById    = $null   # the ledger's keys by id, built when the first object that is not new needs it
    $keeperKeys  = @{}      # #642 per ledger id: the key of the anchor whose object keeps the id

    foreach ($g in @($Groups)) {
        if ($null -eq $g) { continue }

        # Every identifier the group carries, across all members, canonicalised.
        $idsAll = New-Object System.Collections.Generic.List[object]
        foreach ($m in @($g.Members)) {
            foreach ($id in (Get-SIMemberIdentifiers -Member $m)) {
                [void]$idsAll.Add([pscustomobject]@{
                    Type  = (Get-SICanonicalIdType -Type ([string]$id.Type))
                    Value = ([string]$id.Value).ToLowerInvariant()
                })
            }
        }

        # Identity is decided on the UNAMBIGUOUS subset. A group whose ONLY anchors are contested falls
        # back to the full set rather than being declared unkeyable -- it still needs an id, and the
        # collision pass below reports what could not be separated.
        $ids = $idsAll
        if ($hasAmbiguous) {
            $filtered = New-Object System.Collections.Generic.List[object]
            foreach ($id in $idsAll) {
                if (-not $AmbiguousIdKeys.ContainsKey((Get-SILedgerKey -Type $id.Type -Value $id.Value))) {
                    [void]$filtered.Add($id)
                }
            }
            if ($filtered.Count -gt 0) { $ids = $filtered }
        }

        if ($ids.Count -eq 0) {
            # No anchor at all -- nothing to remember it by, so it cannot be given a durable identity.
            # Counted, never invented: minting for an unkeyable object would create a new id every run.
            $unkeyable++
            [void]$decisions.Add([pscustomobject]@{
                Group = $g; CorrelationId = $null; Action = 'unkeyable'
                BirthAnchor = $null; NewIdentifiers = @(); PriorIds = @()
            })
            continue
        }

        # Which existing ids do this group's identifiers already point at?
        $known = @{}
        foreach ($id in $ids) {
            # (a value longer than the ledger's column is held under its short form -- Get-SILedgerEntryKey finds both)
            $k = Get-SILedgerEntryKey -Ledger $Ledger -Type $id.Type -Value $id.Value
            if ($null -ne $k) {
                $e = $Ledger[$k]
                $cid = [string]$e.CorrelationId
                if (-not [string]::IsNullOrWhiteSpace($cid) -and -not $known.ContainsKey($cid)) {
                    $known[$cid] = $e.FirstSeen
                }
            }
        }

        $anchor = Get-SIObjectBirthAnchor -Identifiers $ids.ToArray()
        $action = ''
        $cid    = $null
        $priors = @()

        if ($known.Keys.Count -eq 0) {
            $action = 'mint'
            $cid = (New-SIObjectUuidV5 -Name (Get-SILedgerKey -Type $anchor.Type -Value $anchor.Value)).ToString()
        }
        elseif ($known.Keys.Count -eq 1) {
            $action = 'reuse'
            $cid = @($known.Keys)[0]
        }
        else {
            # MERGE. Oldest FirstSeen wins; ordinal id compare breaks a tie deterministically.
            $action = 'merge'
            $ordered = @($known.Keys) | Sort-Object @{ Expression = { $known[$_] } }, @{ Expression = { $_ } }
            $oldest  = $null
            $oldestT = $null
            foreach ($k in @($known.Keys)) {
                $t = $known[$k]
                if ($null -eq $oldestT -or $t -lt $oldestT -or
                    ($t -eq $oldestT -and (@(Sort-SIOrdinal -Value @($k, $oldest))[0]) -eq $k)) {
                    $oldest = $k; $oldestT = $t
                }
            }
            $cid = $oldest
            $priors = @(@($known.Keys) | Where-Object { $_ -ne $cid })
            foreach ($old in $priors) {
                [void]$superseded.Add([pscustomobject]@{ OldId = $old; NewId = $cid; At = $Now })
            }
        }

        # Identifiers this object did not previously have under this id -- the ledger rows to add.
        $newIds = New-Object System.Collections.Generic.List[object]
        foreach ($id in $ids) {
            $k = Get-SILedgerEntryKey -Ledger $Ledger -Type $id.Type -Value $id.Value
            if ($null -eq $k -or [string]$Ledger[$k].CorrelationId -ne $cid) {
                [void]$newIds.Add([pscustomobject]@{ Type = $id.Type; Value = $id.Value; CorrelationId = $cid })
            }
        }

        # #642 A WRONG MERGE IN THE LEDGER: this group resolved to an id that, by proof, also holds ANOTHER object (two or
        # more identifier types an object holds once, each with another value written in the same run -- Test-SILedgerWrongMerge).
        # The object the id was minted from (else the oldest) keeps it; this group becomes its own object, minted from its
        # own birth anchor, and its anchors are re-pointed -- so the next run reuses the new id and nothing splits again.
        # Decided per group from the ledger alone: a CI build batch that holds one of the objects decides exactly what a
        # batch holding all of them would.
        $idKeys = $null
        if ($action -eq 'reuse') {
            if ($null -eq $keysById) { $keysById = Get-SILedgerKeysById -Ledger $Ledger }
            $idKeys = @(Get-SILedgerKeysOfId -Index $keysById -Ledger $Ledger -CorrelationId $cid)
            $wm = Test-SILedgerWrongMerge -Ids $ids.ToArray() -Ledger $Ledger -AnchorKeys $idKeys
            if ($wm.Proven) {
                if (-not $keeperKeys.ContainsKey($cid)) { $keeperKeys[$cid] = Get-SILedgerIdKeeperKey -CorrelationId $cid -Ledger $Ledger -AnchorKeys $idKeys }
                $keeperKey = [string]$keeperKeys[$cid]
                $holdsKeeper = $false
                foreach ($id in $ids) {
                    if ((Get-SILedgerEntryKey -Ledger $Ledger -Type $id.Type -Value $id.Value) -eq $keeperKey) { $holdsKeeper = $true; break }
                }
                $newCid = (New-SIObjectUuidV5 -Name (Get-SILedgerKey -Type $anchor.Type -Value $anchor.Value)).ToString()
                if (-not $holdsKeeper -and $newCid -ne $cid) {
                    $rewritten = New-Object System.Collections.Generic.List[object]
                    foreach ($id in $ids) { [void]$rewritten.Add([pscustomobject]@{ Type = $id.Type; Value = $id.Value; CorrelationId = $newCid }) }
                    [void]$splits.Add([pscustomobject]@{
                        CorrelationId = $cid; NewId = $newCid; Objects = 2; Resolved = $true; Kind = 'wrong-merge'
                        KeptBy = $keeperKey; Types = @($wm.Types)
                        Reason = ('the ledger id held another object as well ({0} differ, written in the same run) -- the object it was minted from keeps the id and this one is its own object' -f (@($wm.Types) -join ', '))
                    })
                    [void]$decisions.Add([pscustomobject]@{
                        Group = $g; CorrelationId = $newCid; Action = 'split'
                        BirthAnchor = $anchor; NewIdentifiers = $rewritten.ToArray(); PriorIds = @($cid)
                        Identifiers = $ids.ToArray()
                    })
                    continue
                }
            }
        }

        # Anchors the ledger holds for this id that did NOT appear this run. Reported, never acted on --
        # see the split note in the docblock.
        if ($action -ne 'mint') {
            $present = @{}
            foreach ($id in $ids) {
                $present[(Get-SILedgerKey -Type $id.Type -Value $id.Value)] = $true
                # a long value is in the ledger under its short form: it appeared this run all the same
                if (([string]$id.Value).Length -gt 256) { $present[(Get-SILedgerKey -Type $id.Type -Value (ConvertTo-SILedgerStoredValue -Value ([string]$id.Value)))] = $true }
            }
            # 🔴 THE LEDGER'S KEYS BY THE ID THEY POINT AT, built once (Get-SILedgerKeysById). This report used to read
            # EVERY ledger key for EVERY object: 28,822 objects against a ledger of well over 100,000 anchors was more
            # than an hour of one correlation run (2026-10-12), and the same again in every batch of the CI build.
            # The same keys are found, in the same order.
            if ($null -eq $keysById) { $keysById = Get-SILedgerKeysById -Ledger $Ledger }
            $missing = New-Object System.Collections.Generic.List[object]
            if ($null -eq $idKeys) { $idKeys = @(Get-SILedgerKeysOfId -Index $keysById -Ledger $Ledger -CorrelationId $cid) }
            foreach ($k in $idKeys) {
                if (-not $present.ContainsKey($k)) { [void]$missing.Add($k) }
            }
            if ($missing.Count -gt 0) {
                [void]$shrunk.Add([pscustomobject]@{ CorrelationId = $cid; MissingAnchors = $missing.ToArray() })
            }
        }

        [void]$decisions.Add([pscustomobject]@{
            Group = $g; CorrelationId = $cid; Action = $action
            BirthAnchor = $anchor; NewIdentifiers = $newIds.ToArray(); PriorIds = $priors
            Identifiers = $ids.ToArray()
        })
    }

    # ---- ONE LEDGER ID CLAIMED BY TWO OBJECTS -------------------------------------------------------
    #
    # 🔴 THIS IS THE OTHER HALF OF THE 2026-08-20 LIVE FAILURE, and excluding the contested anchor above
    # does NOT on its own fix it. Before a split every anchor of the original object points at that
    # object's id, so on the FIRST run after an operator separates it, BOTH halves still resolve to the
    # same id through their own perfectly unambiguous anchors. Measured: `1 distinct id for 2 objects`.
    #
    # 🔑 WHY IT IS SAFE TO ACT HERE AND NOWHERE ELSE. The docblock above refuses to auto-detect splits
    # because one run cannot tell "this object split" from "a source failed". That reasoning is intact:
    # this pass only reassigns when an OPERATOR never-merge produced the separation, which is exactly
    # the missing fact. Two groups that collide WITHOUT one are reported and left alone -- the deferred
    # case, now at least visible instead of silently sharing an id.
    $byId = @{}
    foreach ($d in $decisions) {
        if ([string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) { continue }
        $k = [string]$d.CorrelationId
        if (-not $byId.ContainsKey($k)) { $byId[$k] = New-Object System.Collections.Generic.List[object] }
        [void]$byId[$k].Add($d)
    }

    foreach ($k in @($byId.Keys)) {
        # 🪤 .ToArray(), NOT @(...). On PS 5.1 wrapping a List[object] of PSCustomObjects in @() throws
        # "Argument types do not match" -- and it threw here on the very first call, before any
        # collision existed, so it would have taken down every correlation run.
        $claimants = $byId[$k].ToArray()
        if ($claimants.Count -lt 2) { continue }

        $separated = @($claimants | Where-Object { $_.Group -and $_.Group.PSObject.Properties['SeparatedByDecision'] -and $_.Group.SeparatedByDecision })
        if ($separated.Count -lt 2) {
            # Not operator-separated: the deferred split/reassign case. Report, never act.
            [void]$splits.Add([pscustomobject]@{
                CorrelationId = $k; Objects = $claimants.Count; Resolved = $false; Kind = 'collision'
                Reason = 'two or more objects resolve to one ledger id and no operator decision separated them -- reported, not acted on (see V3-ARCHITECTURE 2.3a)'
            })
            continue
        }

        # WHICH HALF KEEPS THE EXISTING ID. Ordinal compare of each half's own birth-anchor ledger key.
        #
        # 🔑 It is a TIEBREAK, not a claim about which half is "really" the original -- nothing in one
        # run can establish that. What it must be is DETERMINISTIC and STABLE: a rule that flipped
        # between runs would move the CI back and forth, which is worse than either choice. Ordinal
        # (never culture-sensitive) so two hosts cannot disagree.
        # 📌 The operator overrides it with `pin-id`, which is precisely what that kind is for.
        # 🪤 ORDINAL SCAN, not Sort-Object, and NO `u ESCAPE.
        # Two host traps in one line, both found on a LIVE pwsh 7 run while the PS 5.1 Pester suite
        # stayed green (framework finding HOST-1: the suites run on 5.1, the engines on 7):
        #   * "`uffff" is a pwsh 7 escape. On 5.1 it is the literal text "uffff" and parses fine; on
        #     pwsh 7 it is a PARSE ERROR, which took the whole ledger block down to
        #     "identity ledger unavailable -- publishing with DERIVED, PROVISIONAL ids".
        #   * Sort-Object is culture-sensitive, and this choice decides which CI keeps its identity.
        #     A da-DK host must not keep a different half than an en-US one.
        $keeper    = $null
        $keeperKey = $null
        foreach ($d in $claimants) {
            if (-not $d.BirthAnchor) { continue }
            $dk = Get-SILedgerKey -Type $d.BirthAnchor.Type -Value $d.BirthAnchor.Value
            if ($null -eq $keeperKey -or [string]::CompareOrdinal($dk, $keeperKey) -lt 0) {
                $keeper = $d; $keeperKey = $dk
            }
        }
        # Every claimant lacks a birth anchor: nothing to re-mint from, so leave them reported.
        if ($null -eq $keeper) {
            [void]$splits.Add([pscustomobject]@{
                CorrelationId = $k; Objects = $claimants.Count; Resolved = $false; Kind = 'operator'
                Reason = 'operator-separated, but no half carries an unambiguous anchor to mint a new id from -- reported, not acted on'
            })
            continue
        }
        $ranked = $claimants

        foreach ($d in $ranked) {
            if ($d -eq $keeper) { continue }
            if (-not $d.BirthAnchor) { continue }   # nothing of its own to mint from; leave it reported
            $newCid = (New-SIObjectUuidV5 -Name (Get-SILedgerKey -Type $d.BirthAnchor.Type -Value $d.BirthAnchor.Value)).ToString()
            if ($newCid -eq $k) { continue }

            # Re-point this half's OWN anchors at the new id. The contested anchor is already absent
            # from $d.Identifiers, so it stays with the keeper -- which is what stops the two halves
            # merging again on the next run.
            $rewritten = New-Object System.Collections.Generic.List[object]
            foreach ($id in @($d.Identifiers)) {
                [void]$rewritten.Add([pscustomobject]@{ Type = $id.Type; Value = $id.Value; CorrelationId = $newCid })
            }
            $d.NewIdentifiers = $rewritten.ToArray()
            $d.CorrelationId  = $newCid
            $d.Action         = 'split'

            [void]$splits.Add([pscustomobject]@{
                CorrelationId = $k; NewId = $newCid; Objects = $claimants.Count; Resolved = $true
                KeptBy = $keeper.CorrelationId; Kind = 'operator'
                Reason = 'an operator never-merge separated this object; the other half keeps the existing id and this half is a NEW object'
            })
        }
    }

    $script:SILedgerKeyMemo = $null
    # the decisions counted by action in one pass (the same -eq comparison as before, without case)
    $actionCount = @{ mint = 0; reuse = 0; merge = 0; split = 0 }
    foreach ($d in $decisions) { foreach ($a in 'mint', 'reuse', 'merge', 'split') { if ($d.Action -eq $a) { $actionCount[$a]++ } } }
    [pscustomobject]@{
        Decisions     = $decisions.ToArray()
        Superseded    = $superseded.ToArray()
        ShrunkObjects = $shrunk.ToArray()
        Splits        = $splits.ToArray()
        Minted        = $actionCount['mint']
        Reused        = $actionCount['reuse']
        Merged        = $actionCount['merge']
        Split         = $actionCount['split']
        # #642 of them: the objects split off a ledger id that held another object as well (a wrong merge, repaired)
        WrongMergeSplit = @($splits | Where-Object { [string]$_.Kind -eq 'wrong-merge' }).Count
        Unkeyable     = $unkeyable
    }
}
