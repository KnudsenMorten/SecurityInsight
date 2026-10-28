#Requires -Version 5.1
<#
    THE TIER-RULE DRY RUN for the Settings page: if the staged rule changes were written, which assets would change
    tier? Measured against the LAST PROFILE SNAPSHOT -- SI_<Engine>_Profile_CL where CollectionTime is the newest.
    Nothing is written: no rule, no config, no log. The only sign-in is the snapshot read (see Read-SITierSnapshot.ps1).

    🔒 THE ENGINE'S OWN CODE DECIDES, NOT A COPY OF IT.
      * Rules are compiled by the engine's loader, Get-SIRuleSet (the proposed text goes through it exactly as the
        file would on the next run -- mode disable/overwrite, appliesTo, excludeAssets, osPlatformScope).
      * A rule that must be re-matched is matched by the engine's evaluator, Invoke-SIRuleEval, per asset -- the same
        call Stage Profile makes -- after the same osPlatformScope bucket test (Get-SIAssetOsClass).
      * Every rule that does NOT change keeps the match the engine RECORDED for that asset (the row's SIRules). The
        snapshot is the engine's own decision; the dry run only replaces the matches of the rules being changed.

    WHAT A SNAPSHOT CAN AND CANNOT ANSWER -- said in the result, never guessed:
      * turning a rule off, or an override that changes only what a detection SETS (its tier), is exact: the
        recorded SIRules already say which assets the rule matched and through which detection;
      * a NEW or CHANGED detection must be matched again, and a profile row keeps only some of the inputs. From a
        row: the names (Hostname / DisplayName / SI_AssetName), the OS (OsPlatform), the Defender RBAC group
        (RbacGroupName) and MostFrequentUserTier. A detection that needs anything else -- installed software (the
        TVM inventory), group membership, Azure tags up the parent chain, Exposure Graph roles or a hunting query,
        IP ranges, Entra extension attributes, tags -- is NOT evaluable, and the rule is listed as such;
      * the final tier is MIN(rule tier, the Classify tier) with the engine's default 3, then an operator's tier tag
        (the reducer) and an override decision. The Classify tier is read where the row records it (endpoint: the
        posture claim in SI_TierClaims; identity: the *Verdict_Tier columns). An asset whose recorded tier the rule
        matches and those columns do NOT reproduce is reported as not evaluable -- another input decided it --
        and so is an endpoint with a tier tag (the reducer's arbitration needs the run). An override pins the
        tier: reported, not changed.
      * publicip tiers come from the owning asset, not from rules: a rule change reaches them through the owner on
        the next run, so they are not part of the dry run.
#>

$script:SIDryRunEngines = @('endpoint', 'identity', 'azure')
# The detect kinds a profile ROW can answer -- per engine, because the columns differ. Everything else needs the run.
$script:SIDryRunEvaluableKinds = @{
    endpoint = @('nameMatches', 'osPlatform', 'hasMdeMachineGroupTag', 'mostFrequentUserTier')
    identity = @('nameMatches')
    azure    = @('nameMatches')
}
$script:SIDryRunDefaultTier = 3
$script:SIDryRunIdentityVerdicts = @('EntraRolesPermanentVerdict_Tier', 'EntraRolesEligibleVerdict_Tier', 'EntraApiPermsApplicationVerdict_Tier',
                                     'EntraApiPermsDelegatedVerdict_Tier', 'AdBuiltinGroupsVerdict_Tier', 'AzureRolesVerdict_Tier')

# ---------------------------------------------------------------------------------------------------------------
#  Small pure helpers
# ---------------------------------------------------------------------------------------------------------------
function ConvertTo-SIDryRunInt {
    <# PURE. '' / $null / not a number -> $null; never [int]$null = 0, which would invent a Tier 0. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }
    $null
}

function Get-SIDryRunField {
    <# PURE. A row field as text ('' when absent) -- rows arrive as hashtables (tests) or objects (the query). #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name) -and $null -ne $Row[$Name]) { return [string]$Row[$Name] }; return '' }
    $p = $Row.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return [string]$p.Value }
    ''
}

function ConvertTo-SICanonicalJson {
    <# PURE. A value as JSON with every mapping's keys sorted -- two parses of the same rule compare equal. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-Json -InputObject $Value -Compress) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
    }
    $map = $null
    if ($Value -is [System.Collections.IDictionary]) { $map = @{}; foreach ($k in $Value.get_Keys()) { $map[[string]$k] = $Value[$k] } }
    elseif ($Value -is [pscustomobject]) { $map = @{}; foreach ($p in $Value.PSObject.Properties) { $map[$p.Name] = $p.Value } }
    if ($null -ne $map) {
        # an explicit ordinal sort -- never Sort-Object over nested arrays, whose @() wrapping differs on PS 5.1
        $keys = [string[]]@($map.Keys); [Array]::Sort($keys, [StringComparer]::Ordinal)
        $items = foreach ($k in $keys) { (ConvertTo-Json -InputObject $k -Compress) + ':' + (ConvertTo-SICanonicalJson $map[$k]) }
        return '{' + (@($items) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) { return '[' + (@(foreach ($v in $Value) { ConvertTo-SICanonicalJson $v }) -join ',') + ']' }
    ConvertTo-Json -InputObject ([string]$Value) -Compress
}

function Get-SIDryRunDetectionSignature {
    <# PURE. What decides WHICH assets a compiled rule matches (not what it sets): detections in order + OS scope. #>
    param([Parameter(Mandatory)]$Rule)
    $dets = @(foreach ($d in @($Rule.Detections)) { [ordered]@{ Id = [string]$d.Id; Detect = $d.Detect; ExcludeAssets = @($d.ExcludeAssets) } })
    (ConvertTo-SICanonicalJson $dets) + '|' + (ConvertTo-SICanonicalJson @(@($Rule.osPlatformScope) | ForEach-Object { [string]$_ } | Where-Object { $_ }))
}

function Get-SIDryRunRuleKinds {
    <# PURE. Every detect kind a compiled rule uses. #>
    param([Parameter(Mandatory)]$Rule)
    $k = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($Rule.Detections)) {
        if ($null -eq $d.Detect) { continue }
        $list = if ($d.Detect.any) { @($d.Detect.any) } elseif ($d.Detect.all) { @($d.Detect.all) } else { @() }
        foreach ($s in $list) { $n = [string]$s.kind; if ($n -and -not $k.Contains($n)) { $k.Add($n) } }
    }
    $k.ToArray()
}

function Get-SIDryRunRecordedMatches {
    <#
        PURE. The row's SIRules (the matches Stage Profile recorded) as @{ RuleId; DetectionId; Tier } -- Tier $null when
        the rule set none. Returns $null when the column cannot be read (then nothing about the row is known).
    #>
    param($Row)
    $raw = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('SIRules')) { $raw = $Row['SIRules'] } }
    elseif ($Row.PSObject.Properties['SIRules']) { $raw = $Row.SIRules }
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $raw -or ($raw -is [string] -and $raw.Trim() -eq '')) { return ,$out.ToArray() }
    $items = $raw
    if ($raw -is [string]) {
        # -InputObject, then foreach: on PS 5.1 `@(... | ConvertFrom-Json)` keeps a JSON array as ONE element.
        try { $items = ConvertFrom-Json -InputObject $raw -ErrorAction Stop } catch { return $null }
        if ($null -eq $items) { return ,$out.ToArray() }
    }
    foreach ($m in $items) {
        if ($null -eq $m) { continue }
        $rid = [string](Get-SIDryRunField $m 'RuleId'); if (-not $rid) { continue }
        $out.Add([pscustomobject]@{ RuleId = $rid; DetectionId = [string](Get-SIDryRunField $m 'DetectionId'); Tier = (ConvertTo-SIDryRunInt (Get-SIDryRunField $m 'Tier')) })
    }
    ,$out.ToArray()
}

function Get-SIDryRunRuleTier {
    <# PURE. MIN tier across matches (a match without a tier does not pin the asset) and the first match that sets it. #>
    param([AllowEmptyCollection()][object[]]$Hits)
    $min = $null; $by = $null
    foreach ($m in @($Hits)) {
        if ($null -eq $m -or $null -eq $m.Tier) { continue }
        if ($null -eq $min -or $m.Tier -lt $min) { $min = [int]$m.Tier; $by = $m }
    }
    [pscustomobject]@{ Tier = $min; By = $(if ($by) { if ($by.DetectionId -and $by.DetectionId -ne $by.RuleId) { '{0}/{1}' -f $by.RuleId, $by.DetectionId } else { [string]$by.RuleId } } else { $null }) }
}

function Get-SIDryRunFloor {
    <#
        PURE. The non-rule inputs of the tier that the row RECORDS: the Classify tier (endpoint: the posture claim in
        SI_TierClaims; identity: MIN of the *Verdict_Tier columns), whether an operator tier tag is in play, and whether
        an override decision pinned the tier.
    #>
    param([Parameter(Mandatory)][string]$Engine, $Row)
    $floor = $null; $tag = $null
    if ($Engine -eq 'endpoint') {
        $raw = Get-SIDryRunField $Row 'SI_TierClaims'
        if ($raw -and $raw.Trim() -ne '' -and $raw.Trim() -ne '[]') {
            $claims = $null
            try { $claims = ConvertFrom-Json -InputObject $raw -ErrorAction Stop } catch { $claims = $null }
            foreach ($c in $claims) {
                if ($null -eq $c) { continue }
                $t = ConvertTo-SIDryRunInt (Get-SIDryRunField $c 'Tier')
                if ($null -eq $t) { continue }
                switch ([string](Get-SIDryRunField $c 'SourceKey')) {
                    'PostureRuleTargetTier' { if ($null -eq $floor -or $t -lt $floor) { $floor = $t } }
                    'tenant_si_manual_tag'  { $tag = $t }
                }
            }
        }
    } elseif ($Engine -eq 'identity') {
        foreach ($c in $script:SIDryRunIdentityVerdicts) {
            $t = ConvertTo-SIDryRunInt (Get-SIDryRunField $Row $c)
            if ($null -ne $t -and ($null -eq $floor -or $t -lt $floor)) { $floor = $t }
        }
    }
    $ov = Get-SIDryRunField $Row 'SI_TierBeforeOverride'
    [pscustomobject]@{ Floor = $floor; TagTier = $tag; Overridden = ($ov.Trim() -ne '') }
}

function Get-SIDryRunComposedTier {
    <# PURE. The engine's composition: MIN(rule tier, Classify tier), and the default 3 when neither claimed. #>
    param([AllowNull()]$RuleTier, [AllowNull()]$Floor)
    $t = $null
    foreach ($x in @($RuleTier, $Floor)) { if ($null -ne $x -and ($null -eq $t -or [int]$x -lt $t)) { $t = [int]$x } }
    if ($null -eq $t) { return $script:SIDryRunDefaultTier }
    $t
}

function ConvertTo-SIDryRunAsset {
    <#
        PURE. A profile row in the shape the evaluator reads during Stage Profile -- only the fields a row really keeps:
        the names, the OS, the Defender RBAC group, the most frequent user's tier, the Azure resource id.
    #>
    param([Parameter(Mandatory)][string]$Engine, $Row)
    $name = Get-SIDryRunField $Row 'SI_AssetName'
    $host_ = Get-SIDryRunField $Row 'Hostname'
    $disp = Get-SIDryRunField $Row 'DisplayName'
    $a = @{ Name = $(if ($name) { $name } elseif ($host_) { $host_ } else { $disp }); Hostname = $host_; DisplayName = $disp }
    switch ($Engine) {
        'endpoint' {
            $a['MDE_DeviceName'] = $host_
            $a['MDE_OSPlatform'] = Get-SIDryRunField $Row 'OsPlatform'
            $a['MDE_MachineGroup'] = Get-SIDryRunField $Row 'RbacGroupName'
            $mfu = ConvertTo-SIDryRunInt (Get-SIDryRunField $Row 'MostFrequentUserTier')
            if ($null -ne $mfu) { $a['MostFrequentUserTier'] = $mfu }
        }
        'identity' { $a['ENTRA_DisplayName'] = $disp }
        'azure'    { $a['AZ_Name'] = $(if ($name) { $name } else { $disp }); $a['AZ_ResourceId'] = Get-SIDryRunField $Row 'AzureResourceId' }
    }
    $a
}

function Test-SIDryRunRuleMatch {
    <#
        One rule against one asset, exactly as Stage Profile does it: the osPlatformScope bucket (Get-SIAssetOsClass),
        then the engine's evaluator Invoke-SIRuleEval. Returns @{ RuleId; DetectionId; Tier } or $null.
    #>
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Rule)
    $scope = @(@($Rule.osPlatformScope) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($scope.Count -gt 0) {
        $cls = Get-SIAssetOsClass -Asset $Asset
        if (@($scope | ForEach-Object { [string]$_ }) -notcontains $cls) { return $null }
    }
    $hit = Invoke-SIRuleEval -Asset $Asset -Rule $Rule
    if (-not $hit) { return $null }
    $t = $null; if ($hit.Set) { $t = ConvertTo-SIDryRunInt $hit.Set.Tier }
    [pscustomobject]@{ RuleId = [string]$hit.RuleId; DetectionId = [string]$hit.DetectionId; Tier = $t }
}

# ---------------------------------------------------------------------------------------------------------------
#  THE DIFF -- pure given the rows and the compiled rules
# ---------------------------------------------------------------------------------------------------------------
function Invoke-SITierDryRunDiff {
    <#
        PURE given rows + compiled rules (needs the engine's RuleEval.ps1 loaded for Invoke-SIRuleEval /
        Get-SIAssetOsClass). One engine. A change: @{ Key; Id; Action; Before; After } where Before / After are the
        compiled rule (Get-SIRuleSet shape) in force now / after the change, or $null when the rule is off or absent.

        Per change, how its new matches are found:
          'removed'        -- After is $null: the rule's recorded matches drop;
          'recorded'       -- After decides the same assets as Before (same detections, same OS scope): the recorded
                              matches stand, each takes what After's detection SETS (an override that changes a tier);
          'evaluated'      -- After is matched again on every row (only when every kind it uses is evaluable here);
          'not-evaluable'  -- After needs an input the snapshot does not keep: listed, and NOT counted (its recorded
                              matches are left as they are, so the numbers cover the other changes only).
    #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
          [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes)
    $evaluable = @($script:SIDryRunEvaluableKinds[$Engine])
    $plans = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Changes) {
        $before = $c.Before; $after = $c.After
        $method = $null; $reason = $null; $selfCheck = $null
        if ($null -eq $after) { $method = 'removed'; $reason = 'the rule is off -- its matches drop' }
        elseif ($null -ne $before -and (Get-SIDryRunDetectionSignature $before) -eq (Get-SIDryRunDetectionSignature $after)) {
            $method = 'recorded'; $reason = 'same detections -- the assets the last run matched keep matching; the new tier applies'
        } else {
            $kinds = @(Get-SIDryRunRuleKinds $after)
            $missing = @($kinds | Where-Object { $evaluable -notcontains $_ })
            if ($kinds.Count -eq 0) { $method = 'evaluated'; $reason = 'the rule has no detection -- it matches nothing' }
            elseif ($missing.Count -gt 0) {
                $method = 'not-evaluable'
                $reason = ('it uses {0}, which a profile snapshot does not keep -- its effect shows after the next run' -f ((@($missing) | ForEach-Object { "'$_'" }) -join ', '))
            } else {
                $method = 'evaluated'
                $reason = ('matched again on the snapshot (names, OS, RBAC group{0})' -f $(if ($Engine -eq 'endpoint') { ', most frequent user tier' } else { '' }))
                # Self-check: the rule as it is now, matched on the same row fields, must reproduce what the last run
                # recorded -- where it does not, the row lacks an input and that asset is not evaluable.
                if ($null -ne $before -and @(@(Get-SIDryRunRuleKinds $before) | Where-Object { $evaluable -notcontains $_ }).Count -eq 0) { $selfCheck = $before }
            }
        }
        $plans.Add([pscustomobject]@{ Key = [string]$c.Key; Id = [string]$c.Id; Action = [string]$c.Action; Before = $before; After = $after
            Method = $method; Reason = $reason; SelfCheck = $selfCheck; Mismatch = 0; Note = [string]$c.Note })
    }
    $changedIds = @($plans | Where-Object { $_.Method -ne 'not-evaluable' } | ForEach-Object { $_.Id })

    $changed = New-Object System.Collections.Generic.List[object]
    $pinned = New-Object System.Collections.Generic.List[object]
    $notEval = New-Object System.Collections.Generic.List[object]
    $unchanged = 0; $explained = 0
    foreach ($row in $Rows) {
        $label = Get-SIDryRunField $row 'SI_AssetName'
        if (-not $label) { $label = Get-SIDryRunField $row 'Hostname' }
        if (-not $label) { $label = Get-SIDryRunField $row 'DisplayName' }
        if (-not $label) { $label = Get-SIDryRunField $row 'PrimaryEntityId' }
        $aid = Get-SIDryRunField $row 'SI_AssetId'; if (-not $aid) { $aid = Get-SIDryRunField $row 'PrimaryEntityId' }
        $rec = Get-SIDryRunRecordedMatches $row
        $tier = ConvertTo-SIDryRunInt (Get-SIDryRunField $row 'Tier')
        if ($null -eq $rec -or $null -eq $tier) {
            $notEval.Add([pscustomobject]@{ engine = $Engine; asset = $label; assetId = $aid; reason = $(if ($null -eq $rec) { 'its SIRules column could not be read' } else { 'it has no tier in the snapshot' }) })
            continue
        }
        $asset = $null
        $after = New-Object System.Collections.Generic.List[object]
        foreach ($m in $rec) { if ($changedIds -notcontains $m.RuleId) { $after.Add($m) } }
        $why = $null
        foreach ($p in $plans) {
            switch ($p.Method) {
                'recorded' {
                    foreach ($m in @($rec | Where-Object { $_.RuleId -eq $p.Id })) {
                        $d = @($p.After.Detections | Where-Object { [string]$_.Id -eq $m.DetectionId }) | Select-Object -First 1
                        $t = if ($d -and $d.Set) { ConvertTo-SIDryRunInt $d.Set.Tier } else { $m.Tier }
                        $after.Add([pscustomobject]@{ RuleId = $m.RuleId; DetectionId = $m.DetectionId; Tier = $t })
                    }
                }
                'evaluated' {
                    if ($null -eq $asset) { $asset = ConvertTo-SIDryRunAsset -Engine $Engine -Row $row }
                    if ($p.SelfCheck) {
                        $was = Test-SIDryRunRuleMatch -Asset $asset -Rule $p.SelfCheck
                        $wasRec = @($rec | Where-Object { $_.RuleId -eq $p.Id }) | Select-Object -First 1
                        $same = ($null -eq $was -and $null -eq $wasRec) -or ($null -ne $was -and $null -ne $wasRec -and $was.DetectionId -eq $wasRec.DetectionId)
                        if (-not $same) {
                            $p.Mismatch++
                            if (-not $why) { $why = ("the snapshot's fields do not reproduce the last run's match for {0} -- an input it lacks decided it" -f $p.Id) }
                        }
                    }
                    $hit = Test-SIDryRunRuleMatch -Asset $asset -Rule $p.After
                    if ($hit) { $after.Add($hit) }
                }
            }
        }
        $rb = Get-SIDryRunRuleTier $rec
        $ra = Get-SIDryRunRuleTier $after.ToArray()
        $fl = Get-SIDryRunFloor -Engine $Engine -Row $row
        $explainedHere = ((Get-SIDryRunComposedTier $rb.Tier $fl.Floor) -eq $tier) -and -not $fl.Overridden -and $null -eq $fl.TagTier
        if ($explainedHere) { $explained++ }
        if ($rb.Tier -eq $ra.Tier -and -not $why) { $unchanged++; continue }
        if ($why) { $notEval.Add([pscustomobject]@{ engine = $Engine; asset = $label; assetId = $aid; reason = $why }); continue }
        if ($fl.Overridden) {
            $pinned.Add([pscustomobject]@{ engine = $Engine; asset = $label; assetId = $aid; tier = $tier; reason = 'an override decision sets this tier -- a rule change does not move it' })
            continue
        }
        if ($null -ne $fl.TagTier) {
            $notEval.Add([pscustomobject]@{ engine = $Engine; asset = $label; assetId = $aid; reason = ("an operator tier tag also claims Tier {0} -- the engine's reducer arbitrates it at run time" -f $fl.TagTier) })
            continue
        }
        if (-not $explainedHere) {
            $notEval.Add([pscustomobject]@{ engine = $Engine; asset = $label; assetId = $aid; reason = ("its Tier {0} is not what its recorded rules{1} give -- another input decided it" -f $tier, $(if ($null -ne $fl.Floor) { ' and classification' } else { '' })) })
            continue
        }
        $new = Get-SIDryRunComposedTier $ra.Tier $fl.Floor
        if ($new -eq $tier) { $unchanged++; continue }
        $label2 = { param($rt, $f) if ($null -ne $rt.Tier -and ($null -eq $f -or $rt.Tier -le $f)) { $rt.By } elseif ($null -ne $f) { 'classification' } else { 'engine default (no rule matches)' } }
        $changed.Add([pscustomobject]@{
            engine = $Engine; asset = $label; assetId = $aid; oldTier = $tier; newTier = $new
            direction = $(if ($new -lt $tier) { 'more critical' } else { 'less critical' })
            before = (& $label2 $rb $fl.Floor); after = (& $label2 $ra $fl.Floor)
        })
    }
    [pscustomobject]@{
        engine = $Engine; evaluated = @($Rows).Count; explained = $explained
        changes = @($plans | ForEach-Object { [pscustomobject]@{ key = $_.Key; id = $_.Id; action = $_.Action; method = $_.Method; reason = $_.Reason; selfCheckMismatches = $_.Mismatch; note = $_.Note } })
        changed = $changed.ToArray(); pinned = $pinned.ToArray(); notEvaluable = $notEval.ToArray()
        counts = [pscustomobject]@{
            moreCritical = @($changed | Where-Object { $_.direction -eq 'more critical' }).Count
            lessCritical = @($changed | Where-Object { $_.direction -eq 'less critical' }).Count
            unchanged = $unchanged; pinned = $pinned.Count; notEvaluable = $notEval.Count
        }
    }
}

# ---------------------------------------------------------------------------------------------------------------
#  THE SNAPSHOT QUERY -- pure text; the read itself is a separate seam (Read-SITierSnapshot)
# ---------------------------------------------------------------------------------------------------------------
function Get-SITierSnapshotTable {
    <# The engine's profile table, from its locked schema (the same name the engine writes to). #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure')][string]$Engine)
    $p = Join-Path $SIRoot ('asset-profiling-schema\{0}.schema.locked.json' -f $Engine)
    $t = $null
    if (Test-Path -LiteralPath $p) { try { $t = [string](Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json).table } catch { $t = $null } }
    if (-not $t) { $t = 'SI_{0}{1}_Profile_CL' -f $Engine.Substring(0, 1).ToUpperInvariant(), $Engine.Substring(1) }
    if ($t -notmatch '^[A-Za-z0-9_]+$') { throw "not a table name: $t" }
    $t
}

function Get-SITierSnapshotKql {
    <#
        PURE. The last snapshot of one engine: the rows whose CollectionTime is the NEWEST (every shard of one run carries
        the same CollectionTime), one row per asset, only the columns the dry run reads. column_ifexists, so a column an
        older table never got reads as empty instead of failing the query.

        🔴 -SolutionVersion: the newest run WRITTEN BY THIS INSTALL'S VERSION (the row stamp SolutionVersion). Two installs
        can write one workspace -- measured 2026-10-02 on the internal tenant: the released engine's daily run and the v3
        tree's runs interleave in the same tables, and the bare newest run was the OTHER install's, whose rules are not
        the ones being edited. When this version has no run in the window, the newest run of any version is used and
        every row says which version wrote it (SolutionVersion) next to the newest run in the table (NewestInTable).
    #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure')][string]$Engine, [Parameter(Mandatory)][string]$Table, [int]$LookbackDays = 30,
          [string]$SolutionVersion)
    if ($Table -notmatch '^[A-Za-z0-9_]+$') { throw "not a table name: $Table" }
    if ($SolutionVersion -and $SolutionVersion -notmatch '^[A-Za-z0-9._+()\-]{1,64}$') { throw "not a version: $SolutionVersion" }
    $cols = @('SI_AssetName', 'SI_AssetId', 'Hostname', 'DisplayName', 'SIRules', 'SI_TierBeforeOverride')
    switch ($Engine) {
        'endpoint' { $cols += @('OsPlatform', 'RbacGroupName', 'MostFrequentUserTier', 'SI_TierClaims') }
        'identity' { $cols += $script:SIDryRunIdentityVerdicts }
        'azure'    { $cols += @('AzureResourceId') }
    }
    $proj = @('CollectionTime = tostring(CollectionTime)', 'PrimaryEntityId = tostring(PrimaryEntityId)', 'Tier = tostring(Tier)',
              "SolutionVersion = tostring(column_ifexists('SolutionVersion', ''))", 'NewestInTable = tostring(_newest)') +
            @($cols | ForEach-Object { "{0} = tostring(column_ifexists('{0}', ''))" -f $_ })
    @(
        "let _runs = materialize($Table | where TimeGenerated > ago(${LookbackDays}d) | summarize by CollectionTime, _sv = tostring(column_ifexists('SolutionVersion', '')));"
        'let _newest = toscalar(_runs | summarize max(CollectionTime));'
        $(if ($SolutionVersion) { "let _mine = toscalar(_runs | where _sv == '$SolutionVersion' | summarize max(CollectionTime));" } else { 'let _mine = _newest;' })
        'let _last = iff(isnull(_mine), _newest, _mine);'
        $Table
        "| where TimeGenerated > ago(${LookbackDays}d)"
        '| where CollectionTime == _last'
        '| summarize arg_max(TimeGenerated, *) by PrimaryEntityId'
        ('| project ' + ($proj -join ', '))
    ) -join "`n"
}

function Read-SITierSnapshot {
    <#
        THE SIGN-IN SEAM. Reads the last snapshot of each engine in a SEPARATE Windows PowerShell process
        (Read-SITierSnapshot.ps1): the install's config is loaded and the engines' SPN signs in there, so no credential
        and no config global ever enters the wizard's own process. Returns @{ error; auth; engines = @{ <engine> =
        @{ snapshotTime; rows } } }. -Connection (TenantId, ClientId, CertificateThumbprint, WorkspaceResourceId) signs in
        with that certificate instead of the install's config.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string[]]$Engines, [int]$LookbackDays = 30,
          [string]$SolutionVersion, [hashtable]$Connection, [int]$TimeoutSec = 600)
    $script = Join-Path $PSScriptRoot 'Read-SITierSnapshot.ps1'
    $queries = [ordered]@{}
    foreach ($e in $Engines) { $queries[$e] = Get-SITierSnapshotKql -Engine $e -Table (Get-SITierSnapshotTable -SIRoot $SIRoot -Engine $e) -LookbackDays $LookbackDays -SolutionVersion $SolutionVersion }
    $req = [ordered]@{ installPath = $SIRoot; queries = $queries }
    if ($Connection) { $req['connection'] = $Connection }
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($req | ConvertTo-Json -Depth 6 -Compress)))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Request {1}' -f $script, $b64)
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    # A Windows PowerShell child must not inherit a pwsh 7 module path -- it loses the Cert: drive and the Az modules.
    $psi.EnvironmentVariables['PSModulePath'] = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
    $proc = [System.Diagnostics.Process]::Start($psi)
    $errTask = $proc.StandardError.ReadToEndAsync()
    $out = $proc.StandardOutput.ReadToEnd()
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) { try { $proc.Kill() } catch { }; return [pscustomobject]@{ error = 'the snapshot read did not finish in time' } }
    $m = [regex]::Match($out, '#SI-SNAPSHOT#([A-Za-z0-9+/=]+)#')
    if (-not $m.Success) {
        $tail = (($out + "`n" + $errTask.Result) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' | '
        return [pscustomobject]@{ error = ('the snapshot read failed: {0}' -f $tail) }
    }
    ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.Groups[1].Value)))
}

# ---------------------------------------------------------------------------------------------------------------
#  COMPILE -- the engine's own loader, on the proposed text
# ---------------------------------------------------------------------------------------------------------------
function Import-SIDryRunEngine {
    <# The engine code the dry run calls, from the INSTALL being edited (that is the code that will run): the loader + evaluator. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $style = Join-Path $SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1'
    @(
        $(if (Test-Path -LiteralPath $style) { $style })
        # SecurityInsight's own YAML reader (the rule loader reads YAML; no powershell-yaml module)
        (Join-Path $SIRoot 'engine\_shared\SI-Yaml.ps1')
        (Join-Path $SIRoot 'engine\asset-profiling\shared\RuleEval.ps1')
        (Join-Path $SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
        # the version stamp the install's rows carry (SolutionVersion) -- the engine's own resolution, not a copy
        (Join-Path $SIRoot 'engine\asset-profiling\shared\SI-SolutionVersion.ps1')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
}

function ConvertTo-SICompiledRule {
    <#
        A rule TEXT -> the engine's compiled rule per target engine (Get-SIRuleSet must be loaded). The loader reads files,
        so the text goes to a scratch folder under %TEMP% that is removed before this returns -- nothing is written to the
        install. $null for an engine where the rule does not load or is `mode: disable`.
    #>
    param([Parameter(Mandatory)][string]$RuleFolder, [AllowEmptyString()][string]$RelDir, [Parameter(Mandatory)][string]$Id, [AllowNull()][string]$Text)
    $out = @{}
    $targets = if ($RuleFolder -eq 'shared') { $script:SIDryRunEngines } elseif ($script:SIDryRunEngines -contains $RuleFolder) { @($RuleFolder) } else { @() }
    foreach ($e in $targets) { $out[$e] = $null }
    if ([string]::IsNullOrWhiteSpace($Text) -or $targets.Count -eq 0) { return $out }
    if ($Id -notmatch '^[A-Za-z][A-Za-z0-9_\-]{0,99}$') { throw "not a rule id: $Id" }
    if ($RelDir -and $RelDir -notmatch '^[A-Za-z0-9_\-]+(\\[A-Za-z0-9_\-]+)*$') { throw "not a rule folder: $RelDir" }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('si-dryrun-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    try {
        $dir = Join-Path $tmp ('asset-profiling-enrichment\' + $RuleFolder)
        if ($RelDir) { $dir = Join-Path $dir $RelDir }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $ov = Join-Path $tmp 'no-overlay'; New-Item -ItemType Directory -Path $ov -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $dir ('{0}.custom.yaml' -f $Id)), $Text, (New-Object System.Text.UTF8Encoding($false)))
        foreach ($e in $targets) {
            # the loader returns ONE collection object -- unroll it
            $rules = @(Get-SIRuleSet -Engine $e -SolutionRootOverride $tmp -EnrichmentDataRoot $ov 3>$null 6>$null | ForEach-Object { $_ })
            $r = @($rules | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
            if ($r -and $r.Mode -ne 'disable') { $out[$e] = $r }
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $out
}

function Read-SIRuleEntryText {
    <# The text of one rule file the view lists ('overlay:<rel>' or a path under the install). #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, $Entry)
    if (-not $Entry -or -not $Entry.path) { return $null }
    $p = if ($Entry.path -like 'overlay:*') { Join-Path $OverlayRoot $Entry.path.Substring(8) } else { Join-Path $SIRoot $Entry.path }
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    [System.IO.File]::ReadAllText($p)
}

# ---------------------------------------------------------------------------------------------------------------
#  THE DRY RUN -- plan (validate) -> compile before/after -> read the snapshot -> diff
# ---------------------------------------------------------------------------------------------------------------
function Invoke-SITierDryRun {
    <#
        The staged rule changes (the page's own change objects: @{ action; id; engine; relDir; text }) against the last
        snapshot. Writes nothing. -SnapshotReader is the seam: { param([string[]]$Engines) -> @{ error; engines } }
        (default: Read-SITierSnapshot, which signs in). Returns the per-engine diffs merged, or @{ error } / @{ refused }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes,
          [scriptblock]$SnapshotReader)
    if (@($Changes).Count -eq 0) { return [pscustomobject]@{ error = 'no rule change is staged' } }
    $plan = Invoke-SIRulePlan -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Changes $Changes
    if (@($plan.refused).Count) { return [pscustomobject]@{ refused = $plan.refused; error = 'some changes were refused -- fix them before a dry run' } }
    foreach ($f in (Import-SIDryRunEngine -SIRoot $SIRoot)) { . $f }
    $view = @(Get-SIRuleView -SIRoot $SIRoot -OverlayRoot $OverlayRoot)
    $perEngine = @{}; foreach ($e in $script:SIDryRunEngines) { $perEngine[$e] = New-Object System.Collections.Generic.List[object] }
    $files = @{}
    foreach ($f in $plan.files) {
        $engine = $f.key.Split('/')[0]; $id = $f.key.Substring($engine.Length + 1)
        $row = $view | Where-Object { $_.id -eq $id -and $_.engine -eq $engine } | Select-Object -First 1
        $req = @($Changes | Where-Object { [string]$_.id -eq $id -and ([string]$_.engine).ToLowerInvariant() -eq $engine }) | Select-Object -First 1
        $relDir = if ($row) { [string]$row.relDir } else { [string]$req.relDir }
        $effEntry = if ($row) { if ($row.overlay) { $row.overlay } elseif ($row.custom) { $row.custom } else { $row.locked } } else { $null }
        $beforeText = Read-SIRuleEntryText -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Entry $effEntry
        $afterText = switch ($f.action) {
            'disable' { $null }
            'remove'  {
                # what is in force once the page's own file is gone: an in-tree custom file under an overlay one, else the shipped rule
                if ($row.overlay -and $row.custom) { Read-SIRuleEntryText -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Entry $row.custom }
                elseif ($row.locked) { Read-SIRuleEntryText -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Entry $row.locked }
                else { $null }
            }
            default   { [string]$f.NewText }
        }
        $b = ConvertTo-SICompiledRule -RuleFolder $engine -RelDir $relDir -Id $id -Text $beforeText
        $a = ConvertTo-SICompiledRule -RuleFolder $engine -RelDir $relDir -Id $id -Text $afterText
        $files[$f.key] = $(if ($effEntry) { $p = if ($effEntry.path -like 'overlay:*') { Join-Path $OverlayRoot $effEntry.path.Substring(8) } else { Join-Path $SIRoot $effEntry.path }; $p } else { $null })
        foreach ($e in $script:SIDryRunEngines) {
            if (-not $b.ContainsKey($e)) { continue }
            if ($null -eq $b[$e] -and $null -eq $a[$e]) { continue }
            $perEngine[$e].Add([pscustomobject]@{ Key = $f.key; Id = $id; Action = $f.action; Before = $b[$e]; After = $a[$e]; Note = '' })
        }
    }
    $engines = @($script:SIDryRunEngines | Where-Object { $perEngine[$_].Count -gt 0 })
    if ($engines.Count -eq 0) {
        return [pscustomobject]@{ error = $null; engines = @(); evaluated = 0; changed = @(); pinned = @(); notEvaluable = @(); changes = @()
            counts = [pscustomobject]@{ moreCritical = 0; lessCritical = 0; unchanged = 0; pinned = 0; notEvaluable = 0 }
            notes = @('No staged change affects a tiered engine (endpoint, identity, azure) -- nothing to measure.') }
    }
    $version = $null
    if (Get-Command -Name Get-SISolutionVersion -ErrorAction SilentlyContinue) { $version = [string](Get-SISolutionVersion); if ($version -eq '(dev)') { $version = $null } }
    if (-not $SnapshotReader) { $SnapshotReader = { param([string[]]$Engines, [string]$SolutionVersion) Read-SITierSnapshot -SIRoot $SIRoot -Engines $Engines -SolutionVersion $SolutionVersion } }
    $snap = & $SnapshotReader $engines $version
    if (-not $snap -or $snap.error) { return [pscustomobject]@{ error = $(if ($snap) { [string]$snap.error } else { 'the snapshot read returned nothing' }) } }
    $results = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($snap.notes)) { if ($n) { $notes.Add(('config: {0}' -f $n)) } }
    foreach ($e in $engines) {
        $es = $snap.engines.$e
        $rows = @(); $time = $null
        if ($es) { $rows = @($es.rows | Where-Object { $null -ne $_ }); $time = [string]$es.snapshotTime }
        if ($rows.Count -eq 0) { $notes.Add(("{0}: no profile snapshot in the last 30 days -- nothing to measure" -f $e)); continue }
        $wroteBy = Get-SIDryRunField $rows[0] 'SolutionVersion'
        $newest = Get-SIDryRunField $rows[0] 'NewestInTable'
        if ($version -and $wroteBy -ne $version) {
            $notes.Add(("{0}: no run of this install's version ({1}) in the last 30 days -- measured against the newest run ({2}), written by {3}" -f $e, $version, $time, $(if ($wroteBy) { "version $wroteBy" } else { 'a version that does not stamp its rows' })))
        } elseif ($newest -and $time -and $newest -ne $time) {
            $notes.Add(("{0}: measured against this install's newest run ({1}); a newer run ({2}) in the same table came from another install" -f $e, $time, $newest))
        }
        # A rule changed after the snapshot was taken is not what the snapshot was computed with.
        $chg = $perEngine[$e].ToArray()
        $snapAt = [datetime]::MinValue
        if ($time) { try { $snapAt = [datetime]::Parse($time, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { } }
        foreach ($c in $chg) {
            $fp = $files[$c.Key]
            if ($fp -and (Test-Path -LiteralPath $fp) -and $snapAt -gt [datetime]::MinValue -and (Get-Item -LiteralPath $fp).LastWriteTimeUtc -gt $snapAt) {
                # a file time, not a content check (a copy or checkout also moves it) -- so said as a possibility
                $c.Note = 'its file was modified after this snapshot was taken -- if its content changed, the snapshot reflects the earlier version'
            }
        }
        $d = Invoke-SITierDryRunDiff -Engine $e -Rows $rows -Changes $chg
        $d | Add-Member -NotePropertyName snapshotTime -NotePropertyValue $time -Force
        $results.Add($d)
    }
    $all = $results.ToArray()
    [pscustomobject]@{
        error = $null; auth = $(if ($snap.auth) { [string]$snap.auth } else { $null }); version = $version
        engines = @($all | ForEach-Object { [pscustomobject]@{ engine = $_.engine; snapshotTime = $_.snapshotTime; evaluated = $_.evaluated; explained = $_.explained; counts = $_.counts } })
        evaluated = [int](@($all | ForEach-Object { $_.evaluated }) | Measure-Object -Sum).Sum
        changes = @($all | ForEach-Object { foreach ($c in $_.changes) { $c | Add-Member -NotePropertyName engine -NotePropertyValue $_.engine -Force -PassThru } })
        changed = @($all | ForEach-Object { $_.changed } | Sort-Object engine, oldTier, asset)
        pinned = @($all | ForEach-Object { $_.pinned })
        notEvaluable = @($all | ForEach-Object { $_.notEvaluable })
        counts = [pscustomobject]@{
            moreCritical = [int](@($all | ForEach-Object { $_.counts.moreCritical }) | Measure-Object -Sum).Sum
            lessCritical = [int](@($all | ForEach-Object { $_.counts.lessCritical }) | Measure-Object -Sum).Sum
            unchanged    = [int](@($all | ForEach-Object { $_.counts.unchanged }) | Measure-Object -Sum).Sum
            pinned       = [int](@($all | ForEach-Object { $_.counts.pinned }) | Measure-Object -Sum).Sum
            notEvaluable = [int](@($all | ForEach-Object { $_.counts.notEvaluable }) | Measure-Object -Sum).Sum
        }
        notes = $notes.ToArray()
    }
}
