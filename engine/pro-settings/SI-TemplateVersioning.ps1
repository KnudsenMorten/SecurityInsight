#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- TEMPLATE VERSIONING (REQUIREMENTS §9.3.3 phase C, "align with PIM4EntraPS").

    What a template SAYS, independent of how it is written, and the gate in front of every path that changes it.
    Adopted from PIM4EntraPS's policy templates, with the lessons PIM paid for:

      (a) ITEM IDENTITY = A NORMALISED CONTENT HASH (ContentHash). Comments, key order, `_*` keys and description-only
          fields (description, comment, comments, notes, $schema) do not count, so a documentation edit is not a change.
          BodyHash (the raw body's SHA-256) stays what it was: the integrity check at run start.
      (b) An override whose BaseHash is not the current template's ContentHash is "UPGRADE AVAILABLE", shown with WHAT
          changed (a structured diff of the normalised bodies). Never merged automatically.
      (c) A FINGERPRINT GATE (PIM BUG-55: an image roll silently changed 217 of 325 policies; BUG-223: a path that
          bypassed the gate). Publishing templates compares the template-set fingerprint with the one recorded on the
          install (cfg.InstallState 'TemplateFingerprint'); a moved fingerprint needs -AcceptTemplateChange, otherwise
          the run is a plan. The fingerprint is recorded only AFTER a publish is read back and verified.
      (d) The approver is the identity of the session (Get-SIProSessionActor), never a parameter or a request field
          (PIM BUG-180).
      (e) A conformance view per item and per install: UpToDate / Overridden / Disabled / UpgradeAvailable / Own / Retired.

    Everything here except the store readers / writers is pure (rows in, objects out) and tested directly.
    PS 5.1 safe.
#>

# Keys that describe an item and never change what it does (compared case-insensitively). `_*` keys are dropped too.
$script:SIProDocOnlyKeys = @('description', 'comment', 'comments', 'notes', '$schema')
# The conformance states (the web app's Conformance.States is the same list in the same order).
$script:SIProConformanceStates = @('UpToDate', 'Overridden', 'Disabled', 'UpgradeAvailable', 'Own', 'Retired')
# cfg.InstallState names.
$script:SIProFingerprintName = 'TemplateFingerprint'
# #251 (operator decision 2026-10-04): kinds that WERE templates and are configuration now. Their cfg.Template rows are
# retired by setup (never removed -- history) and count nowhere: not in the fingerprint, not in conformance, not in a pack.
#   naming         the names of tables, DCRs, DCE and workspace are settings (cfg.Setting); the catalog default is the default
#   cmdbownership  the CMDB ownership map is the customer's configuration (cfg.ItemOverride cmdbownership/map)
$script:SIProFormerTemplateKinds = @('naming', 'cmdbownership')

function Get-SIProConformanceStates { $script:SIProConformanceStates }
function Get-SIProFormerTemplateKinds { $script:SIProFormerTemplateKinds }
function Test-SIProFormerTemplateKind {
    <# PURE. Is this kind one that was a template and is configuration now (#251)? #>
    param([AllowEmptyString()][AllowNull()][string]$Kind)
    $script:SIProFormerTemplateKinds -contains [string]$Kind
}

# =====================================================================================================================
#  (a) NORMALISED CONTENT
# =====================================================================================================================
function Test-SIProDocOnlyKey {
    <# PURE. Is this key documentation only? #>
    param([AllowEmptyString()][string]$Key)
    if ($Key.StartsWith('_')) { return $true }
    $script:SIProDocOnlyKeys -contains $Key.ToLowerInvariant()
}

function ConvertTo-SIProContentValue {
    <# PURE. A parsed value with every documentation-only key removed, at any depth (objects -> ordered dictionaries). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    $pairs = $null
    if ($Value -is [System.Collections.IDictionary]) { $pairs = @(foreach ($k in $Value.get_Keys()) { , @([string]$k, $Value[$k]) }) }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) { $pairs = @(foreach ($p in $Value.PSObject.Properties) { , @($p.Name, $p.Value) }) }
    if ($null -ne $pairs) {
        $o = [ordered]@{}
        foreach ($p in $pairs) { if (-not (Test-SIProDocOnlyKey $p[0])) { $o[$p[0]] = ConvertTo-SIProContentValue $p[1] } }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($v in $Value) { $list.Add((ConvertTo-SIProContentValue $v)) }
        return , $list.ToArray()
    }
    $Value
}

function ConvertFrom-SIProBody {
    <# The parsed body (JSON or YAML) -- throws when it does not parse. #>
    param([AllowEmptyString()][string]$Body, [string]$Format = 'json')
    $t = ([string]$Body).TrimStart([char]0xFEFF)
    if ($Format -eq 'yaml') {
        # SecurityInsight's own YAML reader (no powershell-yaml module); -Ordered keeps key order like before.
        if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Yaml.ps1'))
        }
        return (ConvertFrom-SIYaml -Yaml $t -Ordered)
    }
    ConvertFrom-SIProJson $t
}

function Get-SIProContentText {
    <#
        PURE. What an item DOES, as one canonical JSON text: parsed (JSON or YAML -- YAML comments are gone with the
        parse), documentation-only keys dropped at every depth, object keys in ordinal order, compact. A body that does
        not parse falls back to its text with line endings and trailing spaces normalised and comment lines removed --
        so even then a comment edit is not a change.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Body, [string]$Format = 'json')
    if ($null -eq $Body) { $Body = '' }
    try { return (ConvertTo-SIProJson -Value (ConvertTo-SIProContentValue (ConvertFrom-SIProBody -Body $Body -Format $Format)) -Canonical) }
    catch {
        $t = $Body.TrimStart([char]0xFEFF) -replace "`r`n", "`n" -replace "`r", "`n"
        return ((($t -split "`n") | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -notmatch '^\s*(#|//)' -and $_ -ne '' }) -join "`n").Trim()
    }
}

function Get-SIProContentHash {
    <# PURE. SHA-256 (hex) of the normalised content (Get-SIProContentText). #>
    param([AllowEmptyString()][AllowNull()][string]$Body, [string]$Format = 'json')
    Get-SIProTextHash (Get-SIProContentText -Body $Body -Format $Format)
}

function Get-SIProRowContentHash {
    <# A template row's ContentHash: the stored one, else computed from its body (a row published before the column). #>
    param($Row)
    $h = [string](Get-SIProRowValue $Row 'ContentHash')
    if ($h.Trim()) { return $h.Trim() }
    $fmt = [string](Get-SIProRowValue $Row 'Format'); if (-not $fmt) { $fmt = 'json' }
    Get-SIProContentHash -Body ([string](Get-SIProRowValue $Row 'BodyJson')) -Format $fmt
}

# =====================================================================================================================
#  (b) WHAT CHANGED -- a structured diff of two normalised bodies
# =====================================================================================================================
function Get-SIProContentDiff {
    <#
        PURE. The differences between two bodies of one item, after normalisation, as a list of
        @{ Path; Change = added | removed | changed; Old; New } -- Path like 'detections[0].set.Tier', Old / New as compact
        JSON. Objects compare by key (ordinal), lists by position. Identical content = an empty list, however the two are
        written. A body that does not parse is compared as a whole ('(body)').
    #>
    param([AllowEmptyString()][AllowNull()][string]$Old, [AllowEmptyString()][AllowNull()][string]$New, [string]$Format = 'json')
    $out = New-Object System.Collections.Generic.List[object]
    $parse = {
        param([string]$b)
        if ([string]::IsNullOrEmpty($b)) { return @{ Ok = $true; Value = $null } }
        try { @{ Ok = $true; Value = (ConvertTo-SIProContentValue (ConvertFrom-SIProBody -Body $b -Format $Format)) } } catch { @{ Ok = $false; Value = $null } }
    }
    $a = & $parse $Old; $b = & $parse $New
    if (-not $a.Ok -or -not $b.Ok) {
        $x = Get-SIProContentText -Body $Old -Format $Format; $y = Get-SIProContentText -Body $New -Format $Format
        if ($x -cne $y) { $out.Add([pscustomobject]@{ Path = '(body)'; Change = 'changed'; Old = $x; New = $y }) }
        return $out.ToArray()
    }
    $json = { param($v) ConvertTo-SIProJson -Value $v -Canonical }
    $isObj = { param($v) $v -is [System.Collections.IDictionary] }
    $isList = { param($v) ($null -ne $v) -and ($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]) -and -not ($v -is [System.Collections.IDictionary]) }
    $walk = $null
    $walk = {
        param([string]$path, $x, $y)
        if ((& $isObj $x) -and (& $isObj $y)) {
            $keys = New-Object System.Collections.Generic.List[string]
            foreach ($k in $x.get_Keys()) { $keys.Add([string]$k) }
            foreach ($k in $y.get_Keys()) { if (-not $keys.Contains([string]$k)) { $keys.Add([string]$k) } }
            $ka = $keys.ToArray(); [Array]::Sort($ka, [System.StringComparer]::Ordinal)
            foreach ($k in $ka) {
                $p = if ($path) { '{0}.{1}' -f $path, $k } else { $k }
                if (-not $x.Contains($k)) { $out.Add([pscustomobject]@{ Path = $p; Change = 'added'; Old = $null; New = (& $json $y[$k]) }); continue }
                if (-not $y.Contains($k)) { $out.Add([pscustomobject]@{ Path = $p; Change = 'removed'; Old = (& $json $x[$k]); New = $null }); continue }
                & $walk $p $x[$k] $y[$k]
            }
            return
        }
        if ((& $isList $x) -and (& $isList $y)) {
            $xa = @($x); $ya = @($y)
            $n = [Math]::Max($xa.Count, $ya.Count)
            for ($i = 0; $i -lt $n; $i++) {
                $p = '{0}[{1}]' -f $path, $i
                if ($i -ge $xa.Count) { $out.Add([pscustomobject]@{ Path = $p; Change = 'added'; Old = $null; New = (& $json $ya[$i]) }); continue }
                if ($i -ge $ya.Count) { $out.Add([pscustomobject]@{ Path = $p; Change = 'removed'; Old = (& $json $xa[$i]); New = $null }); continue }
                & $walk $p $xa[$i] $ya[$i]
            }
            return
        }
        $jx = & $json $x; $jy = & $json $y
        if ($jx -cne $jy) { $out.Add([pscustomobject]@{ Path = $(if ($path) { $path } else { '(value)' }); Change = 'changed'; Old = $jx; New = $jy }) }
    }
    & $walk '' $a.Value $b.Value
    $out.ToArray()
}

# =====================================================================================================================
#  (b2) ADDITIVE UPGRADE OF AN OVERRIDDEN ITEM (#529, adopted from PIM4EntraPS: "missing blocks / notification rules are
#       added, existing values never touched")
# =====================================================================================================================
function ConvertTo-SIProMutableValue {
    <# PURE. A parsed value as ordered dictionaries and ArrayLists (every key kept, documentation keys too), so additions can
       be put into it. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    $pairs = $null
    if ($Value -is [System.Collections.IDictionary]) { $pairs = @(foreach ($k in $Value.get_Keys()) { , @([string]$k, $Value[$k]) }) }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) { $pairs = @(foreach ($p in $Value.PSObject.Properties) { , @($p.Name, $p.Value) }) }
    if ($null -ne $pairs) {
        $o = [ordered]@{}
        foreach ($p in $pairs) { $o[$p[0]] = ConvertTo-SIProMutableValue $p[1] }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($v in $Value) { [void]$list.Add((ConvertTo-SIProMutableValue $v)) }
        return , $list
    }
    $Value
}

function Get-SIProAdditiveMerge {
    <#
        PURE. Can the new shipped body of an item reach the customer's override WITHOUT touching anything the customer has?
        -Base     the shipped body the override was made against (cfg.TemplateRevision at the override's BaseHash)
        -Current  the shipped body now (cfg.Template)
        -Override the customer's body (cfg.ItemOverride)
        The vendor's change Base -> Current is compared after normalisation (documentation-only keys do not count). It is
        ADDITIVE when it only adds: a new key in an object, new entries in a list (Base's entries all still there, in the
        same order -- new ones may sit anywhere between them). Then every addition is put into the customer's body:
          * a new key the customer's object does not have        -> added (Added)
          * a new key the customer already has (their own value) -> theirs is kept, untouched (Kept)
          * a new list entry the customer's list does not hold   -> appended to their list (Added)
          * a new list entry the customer's list already holds   -> nothing to do (Kept)
          * an addition whose place the customer removed (the parent object / list is gone or is another type) -> the
            upgrade is NOT additive for this override: the customer reviews it (UpgradeAvailable), as before.
        Anything the vendor CHANGED or REMOVED makes the upgrade not additive -- nothing is merged, the item stays
        UpgradeAvailable. Only JSON items are merged (a YAML tier rule keeps its own text, comments and all).
        Returns @{ Additive; Changed (the body differs from the override); Body (the merged JSON, or the override as it
        was); Added; Kept (paths); Reason (why not additive, '' when it is) }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Base, [AllowEmptyString()][AllowNull()][string]$Current,
          [AllowEmptyString()][AllowNull()][string]$Override, [string]$Format = 'json')
    $no = { param([string]$why) [pscustomobject]@{ Additive = $false; Changed = $false; Body = $Override; Added = @(); Kept = @(); Reason = $why } }
    if ($Format -ne 'json') { return (& $no 'a YAML item is never merged automatically -- review the new version') }
    if ([string]::IsNullOrWhiteSpace($Base)) { return (& $no 'the shipped version your change was made on is not known') }
    try {
        $bRaw = ConvertFrom-SIProJson $Base; $cRaw = ConvertFrom-SIProJson $Current; $oRaw = ConvertFrom-SIProJson $Override
    } catch { return (& $no ('a body is not valid JSON: ' + $_.Exception.Message)) }
    $st = @{ Fail = ''; Added = (New-Object System.Collections.Generic.List[string]); Kept = (New-Object System.Collections.Generic.List[string]) }
    $canon = { param($v) ConvertTo-SIProJson -Value (ConvertTo-SIProContentValue $v) -Canonical }
    $isObj = { param($v) $v -is [System.Collections.IDictionary] }
    $isList = { param($v) ($null -ne $v) -and ($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]) -and -not ($v -is [System.Collections.IDictionary]) }
    $b = ConvertTo-SIProContentValue $bRaw
    $c = ConvertTo-SIProContentValue $cRaw
    $cm = ConvertTo-SIProMutableValue $cRaw      # what is added: the shipped entry as shipped (its description too)
    $o = ConvertTo-SIProMutableValue $oRaw
    $walk = $null
    $walk = {
        # x = base (normalised), y = current (normalised), ym = current (mutable, every key), t = the customer's value here
        # ($null when the customer has nothing here: then nothing below may be ADDED, only compared)
        param([string]$path, $x, $y, $ym, $t, [bool]$hasT)
        if ($st.Fail) { return }
        $show = if ($path) { $path } else { '(item)' }
        if ((& $isObj $x) -and (& $isObj $y)) {
            foreach ($k in @($x.get_Keys())) {
                if (-not $y.Contains($k)) { $st.Fail = ("'{0}' was removed from the shipped version" -f $(if ($path) { "$path.$k" } else { $k })); return }
            }
            $tObj = $hasT -and (& $isObj $t)
            foreach ($k in @($y.get_Keys())) {
                $p = if ($path) { '{0}.{1}' -f $path, $k } else { [string]$k }
                $ymk = $ym[$k]
                if ($x.Contains($k)) {
                    $tk = $null; $has = $false
                    if ($tObj -and $t.Contains($k)) { $tk = $t[$k]; $has = $true }
                    & $walk $p $x[$k] $y[$k] $ymk $tk $has
                    if ($st.Fail) { return }
                    continue
                }
                # a key the vendor added
                if (-not $tObj) { $st.Fail = ("the shipped version adds '{0}', but your version has no '{1}' to add it to" -f $p, $show); return }
                if ($t.Contains($k)) { $st.Kept.Add($p) } else { $t[$k] = $ymk; $st.Added.Add($p) }
            }
            return
        }
        if ((& $isList $x) -and (& $isList $y)) {
            $xa = @($x); $ya = @($y); $yma = @($ym)
            $xc = @($xa | ForEach-Object { & $canon $_ }); $yc = @($ya | ForEach-Object { & $canon $_ })
            # Base's entries, in order, inside Current: the rest of Current are the vendor's new entries
            $j = 0; $new = New-Object System.Collections.Generic.List[int]
            for ($i = 0; $i -lt $ya.Count; $i++) { if ($j -lt $xa.Count -and $yc[$i] -ceq $xc[$j]) { $j++ } else { $new.Add($i) } }
            if ($j -eq $xa.Count) {
                if ($new.Count -eq 0) { return }
                if (-not ($hasT -and (& $isList $t))) { $st.Fail = ("the shipped version adds entries to '{0}', but your version has no list there" -f $show); return }
                $tc = New-Object System.Collections.Generic.List[string]; foreach ($e in $t) { $tc.Add((& $canon $e)) }
                foreach ($i in $new) {
                    $p = '{0}[{1}]' -f $path, $i
                    if ($tc.Contains($yc[$i])) { $st.Kept.Add($p) } else { [void]$t.Add($yma[$i]); $tc.Add($yc[$i]); $st.Added.Add($p) }
                }
                return
            }
            # the same entries, changed inside: only additions inside each entry are allowed, and only when the customer's
            # list still lines up with the shipped one (same length) -- else the entry cannot be found safely
            if ($xa.Count -ne $ya.Count) { $st.Fail = ("entries of '{0}' were changed or removed in the shipped version" -f $show); return }
            $tList = $hasT -and (& $isList $t) -and (@($t).Count -eq $xa.Count)
            for ($i = 0; $i -lt $xa.Count; $i++) {
                if ($xc[$i] -ceq $yc[$i]) { continue }
                if (-not $tList) { $st.Fail = ("an entry of '{0}' changed in the shipped version and your list does not line up with it" -f $show); return }
                & $walk ('{0}[{1}]' -f $path, $i) $xa[$i] $ya[$i] $yma[$i] $t[$i] $true
                if ($st.Fail) { return }
            }
            return
        }
        if ((& $canon $x) -cne (& $canon $y)) { $st.Fail = ("'{0}' changed in the shipped version" -f $show) }
    }
    & $walk '' $b $c $cm $o $true
    if ($st.Fail) { return (& $no $st.Fail) }
    $added = $st.Added.ToArray(); $kept = $st.Kept.ToArray()
    $body = if ($added.Count) { ConvertTo-SIProJson -Value $o } else { $Override }
    [pscustomobject]@{ Additive = $true; Changed = ($added.Count -gt 0); Body = $body; Added = $added; Kept = $kept; Reason = '' }
}

function Get-SIProRevisionIndex {
    <# PURE. cfg.TemplateRevision rows indexed by '<kind>/<key>#<hash>' -- by their ContentHash AND by the SHA-256 of their
       body (an override made before content hashes recorded the raw BodyHash as its base). #>
    param([AllowEmptyCollection()][object[]]$Revisions = @())
    $rev = @{}
    foreach ($r in @($Revisions | Where-Object { $_ })) {
        $n = '{0}/{1}' -f (Get-SIProRowValue $r 'Kind'), (Get-SIProRowValue $r 'ItemKey')
        $ch = ([string](Get-SIProRowValue $r 'ContentHash')).Trim()
        if ($ch) { $rev[('{0}#{1}' -f $n, $ch)] = $r }
        $bh = Get-SIProTextHash ([string](Get-SIProRowValue $r 'BodyJson'))
        if (-not $rev.ContainsKey(('{0}#{1}' -f $n, $bh))) { $rev[('{0}#{1}' -f $n, $bh)] = $r }
    }
    $rev
}

function Read-SIProOverrideBaseRevisions {
    <# The cfg.TemplateRevision rows of the items whose override is behind the shipped content -- the bodies an additive
       upgrade compares (only those, never every revision). Empty without the versioning schema. #>
    param([Parameter(Mandatory)]$Store)
    $inner = "SELECT r.Kind, r.ItemKey, r.ContentHash, r.[Version] AS TemplateVersion, r.BodyJson, r.Format FROM cfg.TemplateRevision r JOIN cfg.ItemOverride o ON o.Kind = r.Kind AND o.ItemKey = r.ItemKey JOIN cfg.Template t ON t.Kind = o.Kind AND t.ItemKey = o.ItemKey WHERE o.State = N''override'' AND o.BaseHash IS NOT NULL AND o.BaseHash <> COALESCE(t.ContentHash, N'''') AND o.BaseHash <> t.BodyHash"
    $sql = "IF OBJECT_ID('cfg.TemplateRevision') IS NOT NULL AND OBJECT_ID('cfg.ItemOverride') IS NOT NULL AND COL_LENGTH('cfg.Template', 'ContentHash') IS NOT NULL EXEC (N'$inner')"
    & $Store.Invoke $sql @{} 'reader' | ForEach-Object { $_ }
}

# =====================================================================================================================
#  (c) THE TEMPLATE-SET FINGERPRINT AND THE GATE
# =====================================================================================================================
function Get-SIProTemplateSetFingerprint {
    <#
        PURE. ONE hash for the whole set of templates in force: SHA-256 over '<kind>/<key>=<ContentHash>' of every live
        (not retired) row, ordinal order, newline-joined. '' for an empty set. Only CONTENT counts: a comment, a version
        stamp, a sort order or a source path does not move it.
        #251: rows of a former template kind (naming, cmdbownership) do not count -- they are configuration now. -AllKinds
        counts them as the fingerprint did before (to recognise a fingerprint recorded under the old definition).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [switch]$AllKinds)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        if ($null -ne (Get-SIProRowValue $r 'RetiredAt')) { continue }
        if (-not $AllKinds -and (Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $r 'Kind')))) { continue }
        $lines.Add(('{0}/{1}={2}' -f (Get-SIProRowValue $r 'Kind'), (Get-SIProRowValue $r 'ItemKey'), (Get-SIProRowContentHash $r)))
    }
    if ($lines.Count -eq 0) { return '' }
    $a = $lines.ToArray(); [Array]::Sort($a, [System.StringComparer]::Ordinal)
    Get-SIProTextHash ($a -join "`n")
}

function Get-SIProPlannedTemplateSet {
    <#
        PURE. The live template set AFTER a publish plan is applied to -Existing: existing rows the plan does not touch,
        plus every inserted / updated / revived / unchanged row, minus the retired ones. What the fingerprint gate
        compares with the recorded fingerprint, and what the verification after the write must read back.
    #>
    param([AllowEmptyCollection()][object[]]$Existing = @(), [AllowEmptyCollection()][object[]]$Plan = @())
    $set = [ordered]@{}
    foreach ($e in @($Existing | Where-Object { $_ })) {
        if ($null -ne (Get-SIProRowValue $e 'RetiredAt')) { continue }
        $set[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e
    }
    foreach ($p in @($Plan | Where-Object { $_ })) {
        $name = '{0}/{1}' -f $p.Kind, $p.ItemKey
        if ($p.Action -eq 'retire') { if ($set.Contains($name)) { $set.Remove($name) }; continue }
        if ($p.Row) { $set[$name] = $p.Row }
    }
    @($set.Values)
}

function Get-SIProTemplateChanges {
    <#
        PURE. The items whose CONTENT a publish plan changes (what the operator accepts with -AcceptTemplateChange):
        new, retired, revived, and updated with a different ContentHash. A body edit that only touched comments or
        descriptions is not listed.
    #>
    param([AllowEmptyCollection()][object[]]$Existing = @(), [AllowEmptyCollection()][object[]]$Plan = @())
    $have = @{}; foreach ($e in @($Existing | Where-Object { $_ })) { $have[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e }
    foreach ($p in @($Plan | Where-Object { $_ })) {
        $name = '{0}/{1}' -f $p.Kind, $p.ItemKey
        switch ($p.Action) {
            'insert' { [pscustomobject]@{ Name = $name; Change = 'new'; Kind = $p.Kind; ItemKey = $p.ItemKey } }
            'retire' { [pscustomobject]@{ Name = $name; Change = 'retired'; Kind = $p.Kind; ItemKey = $p.ItemKey } }
            'revive' { [pscustomobject]@{ Name = $name; Change = 'revived'; Kind = $p.Kind; ItemKey = $p.ItemKey } }
            'update' {
                $e = $have[$name]
                if (-not $e -or (Get-SIProRowContentHash $e) -ne (Get-SIProRowContentHash $p.Row)) { [pscustomobject]@{ Name = $name; Change = 'changed'; Kind = $p.Kind; ItemKey = $p.ItemKey } }
            }
        }
    }
}

function Get-SIProTemplateUpgrades {
    <#
        PURE. #529 (3) -- the items a publish plan UPGRADES in place: a live template whose content changes, and which the
        customer follows (no override row, or 'inherit'). One @{ Name; Kind; ItemKey; FromVersion; ToVersion; FromHash;
        ToHash } each. Invoke-SITemplatePublish writes the same rule as SQL (an "upgraded" cfg.ChangeLog row per item, Scope
        'item', in the publish transaction); this is what a plan prints and what the tests hold the writer to.
        An overridden or switched-off item is not listed: it does not follow the template (conformance says what it does).
    #>
    param([AllowEmptyCollection()][object[]]$Existing = @(), [AllowEmptyCollection()][object[]]$Plan = @(), [AllowEmptyCollection()][object[]]$Overrides = @())
    $have = @{}; foreach ($e in @($Existing | Where-Object { $_ })) { $have[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e }
    $own = @{}; foreach ($o in @($Overrides | Where-Object { $_ })) { if ([string](Get-SIProRowValue $o 'State') -in 'override', 'disable') { $own[('{0}/{1}' -f (Get-SIProRowValue $o 'Kind'), (Get-SIProRowValue $o 'ItemKey'))] = $true } }
    foreach ($p in @($Plan | Where-Object { $_ -and $_.Action -eq 'update' -and $_.Row })) {
        $name = '{0}/{1}' -f $p.Kind, $p.ItemKey
        $e = $have[$name]
        if (-not $e -or $null -ne (Get-SIProRowValue $e 'RetiredAt') -or $own.ContainsKey($name)) { continue }
        $from = ([string](Get-SIProRowValue $e 'ContentHash')).Trim()
        if (-not $from) { continue }   # published before content hashes: nothing to compare (the writer skips it too)
        $to = Get-SIProRowContentHash $p.Row
        if ($from -eq $to) { continue }
        [pscustomobject]@{ Name = $name; Kind = $p.Kind; ItemKey = $p.ItemKey
            FromVersion = [string](Get-SIProRowValue $e 'TemplateVersion'); ToVersion = [string](Get-SIProRowValue $p.Row 'TemplateVersion'); FromHash = $from; ToHash = $to }
    }
}

function Get-SIProTemplateGateDecision {
    <#
        PURE. May a publish whose result is -Expected go ahead on an install that recorded -Recorded?
          Initial   nothing recorded and no templates yet -- the first publish of an install; allowed.
          Same      the content in force does not change; allowed (a comment-only refresh writes without acceptance).
          Moved     the content changes: allowed only with -Accept, and when -AcceptFingerprint is given only for
                    exactly that fingerprint (an acceptance names WHAT it accepts -- never a standing blank cheque).
        -Current: the fingerprint of the templates in the database now; it stands in for -Recorded on an install that
        published before the fingerprint was recorded.
    #>
    param([AllowEmptyString()][string]$Recorded, [AllowEmptyString()][string]$Current, [AllowEmptyString()][string]$Expected,
          [switch]$Accept, [AllowEmptyString()][string]$AcceptFingerprint)
    $base = if ($Recorded) { $Recorded } else { $Current }
    $short = { param($f) if ($f) { $f.Substring(0, [Math]::Min(12, $f.Length)) } else { '(none)' } }
    if (-not $base) {
        return [pscustomobject]@{ Allowed = $true; Moved = $false; Initial = $true; Baseline = ''; Expected = $Expected
            Reason = ('first publish on this install -- the template fingerprint {0} becomes the baseline' -f (& $short $Expected)) }
    }
    if ($base -eq $Expected) {
        return [pscustomobject]@{ Allowed = $true; Moved = $false; Initial = $false; Baseline = $base; Expected = $Expected
            Reason = ('the templates in force do not change (fingerprint {0})' -f (& $short $Expected)) }
    }
    $note = if ($Recorded) { 'recorded' } else { 'in the database (nothing recorded yet)' }
    if (-not $Accept) {
        return [pscustomobject]@{ Allowed = $false; Moved = $true; Initial = $false; Baseline = $base; Expected = $Expected
            Reason = ('the templates in force would change: fingerprint {0} {1} -> {2}. Nothing is written without -AcceptTemplateChange.' -f (& $short $base), $note, (& $short $Expected)) }
    }
    if ($AcceptFingerprint -and $AcceptFingerprint.Length -ge 12 -and $Expected.StartsWith($AcceptFingerprint, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Allowed = $true; Moved = $true; Initial = $false; Baseline = $base; Expected = $Expected
            Reason = ('template change accepted for fingerprint {0}' -f (& $short $Expected)) }
    }
    if ($AcceptFingerprint) {
        return [pscustomobject]@{ Allowed = $false; Moved = $true; Initial = $false; Baseline = $base; Expected = $Expected
            Reason = ('the acceptance names fingerprint {0}, but this publish would put {1} in force -- review the new plan and accept that one' -f (& $short $AcceptFingerprint), (& $short $Expected)) }
    }
    [pscustomobject]@{ Allowed = $true; Moved = $true; Initial = $false; Baseline = $base; Expected = $Expected
        Reason = ('template change accepted: fingerprint {0} -> {1}' -f (& $short $base), (& $short $Expected)) }
}

# =====================================================================================================================
#  (d) THE ACTOR IS THE SESSION
# =====================================================================================================================
function Get-SIProSessionActor {
    <#
        The identity this process runs as -- what cfg.ChangeLog records for a publish, an acceptance or an
        acknowledgement. Never taken from a parameter, a file or a request (PIM BUG-180: an approver taken from input is
        whatever the input says). In a container: the managed identity (its client id when the platform says) or the
        engine application; on Windows: the signed-in Windows account; elsewhere: the operating-system user.
    #>
    if ($global:SI_UseManagedIdentity) {
        $cid = [Environment]::GetEnvironmentVariable('AZURE_CLIENT_ID')
        if ($cid) { return ('managed identity {0}' -f $cid) }
        return 'managed identity'
    }
    try {
        if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
            $w = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            if ($w -and $w.Name) { return $w.Name }
        }
    } catch { }
    [System.Environment]::UserName
}

# =====================================================================================================================
#  (e) CONFORMANCE -- per item and per install
# =====================================================================================================================
function Get-SIProConformanceState {
    <#
        PURE. One item's state:
          Own               the customer's item -- no template (or a retired template the customer still overrides)
          Retired           the template is retired and the customer does not override it (the item is not applied)
          Disabled          the customer switched the template item off
          UpToDate          no override (or 'inherit') -- the template as published
          Overridden        the customer's own body, made against the CURRENT template content
          UpgradeAvailable  the customer's own body, made against an OLDER template content (or before the vendor
                            shipped one) -- review what changed, then take the template or keep yours
        BaseHash may be the ContentHash (from now on) or the raw BodyHash (overrides made before content hashes).
    #>
    param([bool]$HasTemplate, [bool]$Retired, [AllowEmptyString()][string]$State, [AllowEmptyString()][string]$BaseHash,
          [AllowEmptyString()][string]$ContentHash, [AllowEmptyString()][string]$BodyHash)
    if (-not $HasTemplate) { return 'Own' }
    if ($Retired) { if ($State -eq 'override') { return 'Own' } else { return 'Retired' } }
    if ($State -eq 'disable') { return 'Disabled' }
    if ($State -ne 'override') { return 'UpToDate' }
    $b = ([string]$BaseHash).Trim()
    if ($b -and ($b -eq ([string]$ContentHash).Trim() -or $b -eq ([string]$BodyHash).Trim())) { return 'Overridden' }
    'UpgradeAvailable'
}

function Get-SIProConformance {
    <#
        PURE. The conformance view. -Templates (cfg.Template rows), -Overrides (cfg.ItemOverride rows), -Revisions
        (cfg.TemplateRevision rows: the template body each BaseHash was made against), -Recorded (the install's recorded
        fingerprint). Returns @{ Items; Summary }:
          Items    one per item: Kind, ItemKey, State, TemplateVersion, BaseVersion, ContentHash, BaseHash, and for
                   UpgradeAvailable: TemplateChanges (base template -> current template) and YourChanges (current
                   template -> your body), each a Get-SIProContentDiff list; BaseKnown says whether the base body was
                   found (an override made before revisions were kept has none -- then only YourChanges is shown).
          Summary  the per-install view: Counts per state (every state present, 0 when none), Total, UpgradeAvailable,
                   Conformant (no upgrade waiting), Fingerprint (of the templates in force) and Recorded.
    #>
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Overrides = @(),
          [AllowEmptyCollection()][object[]]$Revisions = @(), [AllowEmptyString()][string]$Recorded, [switch]$NoDiff)
    # #251: naming and CMDB ownership are configuration, not templates -- they are not part of the conformance view.
    $Templates = @($Templates | Where-Object { $_ -and -not (Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $_ 'Kind'))) })
    $Overrides = @($Overrides | Where-Object { $_ -and -not (Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $_ 'Kind'))) })
    $tpl = @{}; foreach ($t in @($Templates | Where-Object { $_ })) { $tpl[('{0}/{1}' -f (Get-SIProRowValue $t 'Kind'), (Get-SIProRowValue $t 'ItemKey'))] = $t }
    $ovr = @{}; foreach ($o in @($Overrides | Where-Object { $_ })) { $ovr[('{0}/{1}' -f (Get-SIProRowValue $o 'Kind'), (Get-SIProRowValue $o 'ItemKey'))] = $o }
    # #529: by ContentHash and by the raw body hash (an override made before content hashes recorded the BodyHash)
    $rev = Get-SIProRevisionIndex -Revisions @($Revisions)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($k in $tpl.Keys) { $names.Add($k) }
    foreach ($k in $ovr.Keys) { if (-not $tpl.ContainsKey($k)) { $names.Add($k) } }
    $na = $names.ToArray(); [Array]::Sort($na, [System.StringComparer]::Ordinal)
    $counts = [ordered]@{}; foreach ($s in $script:SIProConformanceStates) { $counts[$s] = 0 }
    $items = foreach ($name in $na) {
        $t = $tpl[$name]; $o = $ovr[$name]
        $row = if ($t) { $t } else { $o }
        $kind = [string](Get-SIProRowValue $row 'Kind'); $key = [string](Get-SIProRowValue $row 'ItemKey')
        $fmt = [string](Get-SIProRowValue $row 'Format'); if (-not $fmt) { $fmt = 'json' }
        $ch = if ($t) { Get-SIProRowContentHash $t } else { '' }
        $bh = if ($t) { ([string](Get-SIProRowValue $t 'BodyHash')).Trim() } else { '' }
        $st = if ($o) { [string](Get-SIProRowValue $o 'State') } else { '' }
        $base = if ($o) { ([string](Get-SIProRowValue $o 'BaseHash')).Trim() } else { '' }
        $state = Get-SIProConformanceState -HasTemplate ([bool]$t) -Retired ([bool]($t -and $null -ne (Get-SIProRowValue $t 'RetiredAt'))) -State $st -BaseHash $base -ContentHash $ch -BodyHash $bh
        # #529 (1): an override behind a shipped version that only ADDS is merged at run start (Merge-SIProItems) -- it reads
        # "Overridden -- new shipped additions applied", not "upgrade available". Anything changed or removed stays as before.
        $addApplied = $false; $additions = @(); $notAdditive = ''
        $b = if ($state -eq 'UpgradeAvailable' -and $base) { $rev[('{0}#{1}' -f $name, $base)] } else { $null }
        if ($state -eq 'UpgradeAvailable') {
            if ($b) {
                $am = Get-SIProAdditiveMerge -Base ([string](Get-SIProRowValue $b 'BodyJson')) -Current ([string](Get-SIProRowValue $t 'BodyJson')) -Override ([string](Get-SIProRowValue $o 'BodyJson')) -Format $fmt
                if ($am.Additive) { $state = 'Overridden'; $addApplied = $true; $additions = @($am.Added) } else { $notAdditive = $am.Reason }
            } else { $notAdditive = 'the shipped version your change was made on is not known' }
        }
        $counts[$state]++
        $tc = @(); $yc = @(); $known = $false
        if ($state -eq 'UpgradeAvailable' -and -not $NoDiff) {
            $cur = [string](Get-SIProRowValue $t 'BodyJson')
            if ($b) { $known = $true; $tc = @(Get-SIProContentDiff -Old ([string](Get-SIProRowValue $b 'BodyJson')) -New $cur -Format $fmt) }
            $yc = @(Get-SIProContentDiff -Old $cur -New ([string](Get-SIProRowValue $o 'BodyJson')) -Format $fmt)
        }
        [pscustomobject]@{ Kind = $kind; ItemKey = $key; Name = $name; State = $state; Format = $fmt
            TemplateVersion = $(if ($t) { [string](Get-SIProRowValue $t 'TemplateVersion') } else { '' })
            BaseVersion = $(if ($o) { [string](Get-SIProRowValue $o 'BaseVersion') } else { '' })
            ContentHash = $ch; BaseHash = $base; BaseKnown = $known; TemplateChanges = $tc; YourChanges = $yc
            AdditionsApplied = $addApplied; Additions = $additions; NotAdditiveReason = $notAdditive
            StateText = $(if ($addApplied) { 'Overridden -- new shipped additions applied' } else { $state }) }
    }
    $items = @($items)
    $fp = Get-SIProTemplateSetFingerprint -Rows @($Templates)
    [pscustomobject]@{ Items = $items
        Summary = [pscustomobject]@{ Counts = [pscustomobject]$counts; Total = $items.Count; UpgradeAvailable = $counts['UpgradeAvailable']
            Conformant = ($counts['UpgradeAvailable'] -eq 0); Fingerprint = $fp; Recorded = [string]$Recorded
            FingerprintMatches = (-not $Recorded -or $Recorded -eq $fp) } }
}

# =====================================================================================================================
#  STORE: readers and writers (guarded -- a database without the versioning schema answers "not ready")
# =====================================================================================================================
function Test-SIProVersioningSchema {
    <# What the template-versioning schema still lacks (empty = ready): the ContentHash column, cfg.TemplateRevision,
       cfg.InstallState. #>
    param([Parameter(Mandatory)]$Store)
    $sql = "SELECT CASE WHEN COL_LENGTH('cfg.Template', 'ContentHash') IS NULL THEN 0 ELSE 1 END AS HasContentHash, CASE WHEN OBJECT_ID('cfg.TemplateRevision') IS NULL THEN 0 ELSE 1 END AS HasRevision, CASE WHEN OBJECT_ID('cfg.InstallState') IS NULL THEN 0 ELSE 1 END AS HasInstallState"
    $r = @(& $Store.Invoke $sql @{} 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
    $missing = New-Object System.Collections.Generic.List[string]
    if (-not $r -or [int](Get-SIProRowValue $r 'HasContentHash') -ne 1) { $missing.Add('cfg.Template.ContentHash') }
    if (-not $r -or [int](Get-SIProRowValue $r 'HasRevision') -ne 1) { $missing.Add('cfg.TemplateRevision') }
    if (-not $r -or [int](Get-SIProRowValue $r 'HasInstallState') -ne 1) { $missing.Add('cfg.InstallState') }
    $missing.ToArray()
}

function Read-SIProInstallState {
    <# One cfg.InstallState row (@{ Value; Version; UpdatedAt; UpdatedBy }), or $null (no row, or no table). #>
    param([Parameter(Mandatory)]$Store, [string]$Name = $script:SIProFingerprintName)
    $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Name, Value, [Version], UpdatedAt, UpdatedBy FROM cfg.InstallState WHERE Name = @Name" @{ Name = $Name } 'reader' | ForEach-Object { $_ })
    if ($rows.Count) { return $rows[0] }
    $null
}

function Read-SIProTemplateRevisions {
    <# cfg.TemplateRevision rows (empty without the table). #>
    param([Parameter(Mandatory)]$Store)
    & $Store.Invoke "IF OBJECT_ID('cfg.TemplateRevision') IS NOT NULL SELECT Kind, ItemKey, ContentHash, [Version] AS TemplateVersion, BodyJson, Format FROM cfg.TemplateRevision" @{} 'reader' | ForEach-Object { $_ }
}

function Set-SIProTemplateFingerprint {
    <#
        Record the template-set fingerprint on the install, with its cfg.ChangeLog row, in one transaction. Called ONLY
        after a publish was read back and verified (Publish-SITemplates). The actor is the session (Get-SIProSessionActor).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][AllowEmptyString()][string]$Fingerprint, [string]$Version, [string]$Reason = '')
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name);
IF @old IS NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = @Name)
    INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, @Version, @By);
ELSE
    UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, 'install', 'install', 'Set', @old, CONCAT(@Version, ':', @Value), @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Name = $script:SIProFingerprintName; Value = $Fingerprint; Version = $(if ($Version) { $Version } else { $null }); By = (Get-SIProSessionActor); Reason = $Reason }) 'nonquery'
}

function Get-SIProStoreConformance {
    <# The conformance view read from the database (templates, overrides, revisions, the recorded fingerprint). #>
    param([Parameter(Mandatory)]$Store, [switch]$NoDiff)
    $rec = Read-SIProInstallState -Store $Store
    Get-SIProConformance -Templates @(Read-SIProTemplates -Store $Store) -Overrides @(Read-SIProItemOverrides -Store $Store) `
        -Revisions @(Read-SIProTemplateRevisions -Store $Store) -Recorded $(if ($rec) { [string](Get-SIProRowValue $rec 'Value') } else { '' }) -NoDiff:$NoDiff
}

function Approve-SIProTemplateUpgrade {
    <#
        Resolve "upgrade available" for one item -- the PowerShell twin of the web page's two buttons:
          -Action Take   take the new template: the override goes back to inherit (the row is removed), as Set-SIProItem
          -Action Keep   keep mine and acknowledge: the override's BaseHash / BaseVersion move to the CURRENT template,
                         so it reads Overridden again; the body is not touched
        Each with its cfg.ChangeLog row in one transaction. The actor is the SESSION (Get-SIProSessionActor) -- there is
        deliberately no -ChangedBy. -ExpectedContentHash: the template content the decision was made on; when the
        template moved since, nothing is written.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Key,
          [Parameter(Mandatory)][ValidateSet('Take', 'Keep')][string]$Action, [string]$Reason = '', [string]$ExpectedContentHash)
    $spec = $script:SIProItemKinds[$Kind]
    if (-not $spec -or -not $spec.Templated) { throw ("'{0}' is not a templated configuration kind" -f $Kind) }
    if ($Key -notmatch $spec.Key) { throw ("'{0}' is not a valid {1} key" -f $Key, $Kind) }
    $by = Get-SIProSessionActor
    if ($Action -eq 'Take') {
        Set-SIProItem -Store $Store -Kind $Kind -Key $Key -State inherit -ChangedBy $by -Reason $(if ($Reason) { $Reason } else { 'took the new template' })
        return [pscustomobject]@{ Kind = $Kind; Key = $Key; Action = 'Take'; Outcome = 'Saved'; By = $by }
    }
    $missing = @(Test-SIProVersioningSchema -Store $Store)
    if ($missing.Count) { throw ('nothing written: the Pro database lacks {0} -- run setup\Publish-SITemplates.ps1 -Apply -CreateSchema first' -f ($missing -join ', ')) }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @state nvarchar(16), @oldHash char(64), @newHash char(64), @newVersion nvarchar(32);
SELECT @state = State, @oldHash = BaseHash FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key;
SELECT @newHash = ContentHash, @newVersion = [Version] FROM cfg.Template WHERE Kind = @Kind AND ItemKey = @Key AND RetiredAt IS NULL;
IF @state IS NULL OR @state <> 'override' BEGIN ROLLBACK; SELECT 'NotOverridden' AS Outcome; RETURN; END;
IF @newHash IS NULL BEGIN ROLLBACK; SELECT 'NoTemplate' AS Outcome; RETURN; END;
IF @Expected IS NOT NULL AND @newHash <> @Expected BEGIN ROLLBACK; SELECT 'Stale' AS Outcome; RETURN; END;
UPDATE cfg.ItemOverride SET BaseHash = @newHash, BaseVersion = @newVersion, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, 'item', @Kind, 'Set', CONCAT('base:', COALESCE(@oldHash, '(none)')), CONCAT('base:', @newHash, ' (', @newVersion, ')'), @By, @Reason);
COMMIT;
SELECT 'Saved' AS Outcome;
'@
    $rows = @(& $Store.Invoke $sql ([ordered]@{ Kind = $Kind; Key = $Key; Expected = $(if ($ExpectedContentHash) { $ExpectedContentHash } else { $null }); By = $by
        Reason = $(if ($Reason) { $Reason } else { 'kept my version; acknowledged the new template' }) }) 'reader' | ForEach-Object { $_ })
    $outcome = if ($rows.Count) { [string](Get-SIProRowValue $rows[0] 'Outcome') } else { '' }
    [pscustomobject]@{ Kind = $Kind; Key = $Key; Action = 'Keep'; Outcome = $outcome; By = $by }
}
