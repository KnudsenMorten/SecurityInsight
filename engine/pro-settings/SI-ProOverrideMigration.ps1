#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE CUSTOMER'S OVERRIDES FOLLOW THE RISK FACTOR MODEL V2 (CONVERGE-DEFAULTS).

    The risk index was re-keyed from the 2.2 columns to the SI generic fields, and the risk-factor catalog moved to model
    v2 (shortName / group / class / impact 1-5 / state instead of stage). A Pro install keeps the customer's changes as
    cfg.ItemOverride rows keyed by the OLD shape. Left alone they would become orphans: a risk index override under a
    2.2 key matches no template any more (and would come back as an "own" row in the wrong column set), a factor override
    still says `stage` and lacks the v2 fields, and an override of a removed factor (break_glass) would come back as a
    factor of its own. On the next template publish / update (setup\Publish-SITemplates.ps1 with the shipped templates,
    what setup and the updater run) every such row is translated through the SHIPPED translation table
    (risk-analysis-detection\riskscore.index.translation.locked.json) -- the customer's values are kept:

      riskindex  'row/<6 x 2.2 dims>[#n]' -> 'row/<8 x SI dims>[#n]' (si_finding_type | si_category | si_subcategory |
                 si_component | si_finding_key | asset_class | si_severity | si_tier); its body translated column by column
                 (its base values and its place unchanged); a 'disable' moves with its key. When the new key already has
                 an override (the customer redid it), the new one is kept and the old row removed -- said.
      datamodel  'risk-factors:<id>' with a pre-v2 body: stage -> state (not_used / testing = disabled; a built-in factor
                 is never disabled -- it stays enabled and that is said); the v2 fields it lacks come from the shipped
                 factor; a value EQUAL to the 1.0.0 default (riskFactorsV1 in the table: impact 1, the old name) takes the
                 new shipped value, a value the customer changed is kept (impact held to 1..5). A 'disable' of a built-in
                 factor is removed (it cannot be switched off). An override of a REMOVED factor (very_stale_sign_in,
                 break_glass) is removed and said what replaced it.
    Every write goes through Set-SIProItem (validated, ChangeLog), the old key's removal too ('inherit'); an item that does
    not validate after translation is left as it was and reported -- nothing is half-migrated. Running it again changes
    nothing (an already-migrated row is not touched).

    PURE except Invoke-SIProOverrideMigration. PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-SIProOverrideTranslation {
    <# The shipped translation table (the whole JSON document), from -SIRoot. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = [System.IO.Path]::Combine($SIRoot, 'risk-analysis-detection', 'riskscore.index.translation.locked.json')
    return ([System.IO.File]::ReadAllText($p) | ConvertFrom-Json)
}

function ConvertTo-SIProRiskIndexSiKey {
    <# PURE. An old 2.2 risk index item key ('row/<SecurityDomain>|<Category>|<SubCategory>|<ConfigurationId>|<Severity>|<Tier>'
       with an optional '#n') -> the SI key; $null when the key is not a 2.2 key (8 dimensions already, or not a row key). #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][hashtable]$Translation)
    if ($Key -notmatch '^row/') { return $null }
    $suffix = ''; $body = $Key.Substring(4)
    $m = [regex]::Match($body, '#\d+$'); if ($m.Success) { $suffix = $m.Value; $body = $body.Substring(0, $m.Index) }
    $d = $body.Split('|')
    if ($d.Count -ne 6) { return $null }
    $v = { param($c, $x) ConvertTo-SIRiskIndexSiValue -Column $c -Value $x -Translation $Translation }
    $si = @('', (& $v 'si_category' $d[1]), (& $v 'si_subcategory' $d[2]), '', (& $v 'si_finding_key' $d[3]), (& $v 'asset_class' $d[0]), (& $v 'si_severity' $d[4]), (& $v 'si_tier' $d[5]))
    return ('row/' + (($si | ForEach-Object { ([string]$_).Trim() }) -join '|') + $suffix)
}

function ConvertTo-SIProPascalName {
    <# PURE. An id -> a PascalCase short name (old_thing_2 -> OldThing2), for a customer's own factor that has none. #>
    param([string]$Id)
    $s = (@(([string]$Id) -split '[^A-Za-z0-9]+' | Where-Object { $_ } | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) }) -join '')
    if ($s -notmatch '^[A-Z]') { $s = 'F' + $s }
    if ($s.Length -gt 24) { $s = $s.Substring(0, 24) }
    if ($s.Length -lt 2) { $s = $s + 'X' }
    return $s
}

function ConvertTo-SIProFactorV2Body {
    <#
        PURE. One pre-v2 factor override body -> its model v2 body (CONVERGE-DEFAULTS, see the header). -Shipped: the shipped
        v2 factor of that id ($null for the customer's own factor); -V1: the 1.0.0 default of that id ($null when it was not
        shipped). Returns @{ Body (ordered); Notes }.
    #>
    param([Parameter(Mandatory)]$Override, $Shipped, $V1)
    $notes = New-Object System.Collections.Generic.List[string]
    $o = [ordered]@{}
    foreach ($p in $Override.PSObject.Properties) { $o[$p.Name] = $p.Value }
    $id = [string]$o['id']
    $builtin = ($null -ne $Shipped -and [string]$Shipped.class -ne 'optional')
    # stage -> state
    if (-not $o.Contains('state')) {
        $st = 'enabled'
        if ($o.Contains('stage') -and [string]$o['stage'] -in 'not_used', 'testing') { $st = 'disabled' }
        if ($st -eq 'disabled' -and $builtin) { $st = 'enabled'; $notes.Add(("{0} was switched off ({1}); it is built-in now and stays enabled -- lower its impact instead" -f $id, [string]$o['stage'])) }
        $o['state'] = $st
    }
    if ($o.Contains('stage')) { $o.Remove('stage') }
    # the v2 fields it lacks: the shipped factor's (a customer's own factor: derived, optional)
    $fill = @('shortName', 'group', 'class', 'appliesTo', 'axis', 'evaluatedBy', 'providers', 'combine', 'legacyTokens', 'description', 'findingKinds', 'criteria', 'ciColumn')
    foreach ($k in $fill) {
        if ($o.Contains($k)) { continue }
        if ($Shipped -and $Shipped.PSObject.Properties[$k]) { $o[$k] = $Shipped.$k }
    }
    if (-not $o.Contains('shortName')) { $o['shortName'] = ConvertTo-SIProPascalName $id }
    if (-not $o.Contains('class')) { $o['class'] = 'optional' }
    if (-not $o.Contains('group')) { $o['group'] = $(if ([string]$o['appliesTo'] -eq 'finding') { 'Severity' } else { 'Exposure' }) }
    # a value equal to the 1.0.0 default takes the new shipped value; the customer's own value is kept
    $imp = $null; if ($o.Contains('impact')) { $imp = ConvertTo-SINumberOrNull $o['impact'] }
    $v1Imp = $null; if ($V1) { $v1Imp = ConvertTo-SINumberOrNull $V1.impact }
    if ($Shipped -and ($null -eq $imp -or ($null -ne $v1Imp -and $imp -eq $v1Imp))) { $o['impact'] = [int]$Shipped.impact }
    elseif ($null -eq $imp) { $o['impact'] = 1 }
    else {
        $n = [int][Math]::Round($imp); if ($n -lt 1) { $n = 1 }; if ($n -gt 5) { $n = 5 }
        if ($n -ne $imp) { $notes.Add(("{0}: impact {1} held to {2} (1..5)" -f $id, $imp, $n)) }
        $o['impact'] = $n
    }
    if ($Shipped -and $V1 -and [string]$o['name'] -ceq [string]$V1.name) { $o['name'] = [string]$Shipped.name }
    if (-not ([string]$o['name']).Trim()) { if ($Shipped) { $o['name'] = [string]$Shipped.name } else { $o['name'] = $id } }
    return @{ Body = $o; Notes = $notes.ToArray() }
}

function Test-SIProFactorBodyIsV2 {
    <# PURE. $true when a factor body already carries the v2 shape (state, shortName, group, class; no stage). #>
    param($Body)
    if ($null -eq $Body) { return $true }
    foreach ($k in 'state', 'shortName', 'group', 'class') { if (-not $Body.PSObject.Properties[$k]) { return $false } }
    return (-not $Body.PSObject.Properties['stage'])
}

function Get-SIProOverrideMigrationPlan {
    <#
    .SYNOPSIS  PURE. The overrides that need the v2 shape -> the actions: @{ Kind; OldKey; NewKey; State; Body (text or $null);
               Format; BaseHash; BaseVersion; Action = move | rewrite | remove; Reason }. Rows already in the v2 shape give none.
    .PARAMETER Overrides       cfg.ItemOverride rows (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash)
    .PARAMETER Translation     the shipped translation table (Get-SIProOverrideTranslation)
    .PARAMETER ShippedFactors  the shipped v2 factors (data-model\risk-factors.locked.json .factors)
    .PARAMETER TemplateHashes  '<kind>/<key>' -> the shipped template's content hash (the new BaseHash of a moved row)
    #>
    param([AllowEmptyCollection()][object[]]$Overrides = @(), [Parameter(Mandatory)]$Translation, [AllowEmptyCollection()][object[]]$ShippedFactors = @(),
          [hashtable]$TemplateHashes = @{})
    $tr = @{ columns = [ordered]@{}; values = @{} }
    foreach ($p in $Translation.columns.PSObject.Properties) { $tr.columns[$p.Name] = [string]$p.Value }
    foreach ($p in $Translation.values.PSObject.Properties) { $m = @{}; foreach ($q in $p.Value.PSObject.Properties) { $m[$q.Name.ToLowerInvariant()] = [string]$q.Value }; $tr.values[$p.Name] = $m }
    $v1 = @{}; $removed = @{}
    if ($Translation.PSObject.Properties['riskFactorsV1']) {
        foreach ($p in $Translation.riskFactorsV1.factors.PSObject.Properties) { $v1[$p.Name] = $p.Value }
        foreach ($p in $Translation.riskFactorsV1.removed.PSObject.Properties) { $removed[$p.Name] = [string]$p.Value }
    }
    $shipped = @{}; foreach ($f in $ShippedFactors) { if ($f -and $f.id) { $shipped[[string]$f.id] = $f } }
    $have = @{}; foreach ($o in $Overrides) { $have[('{0}/{1}' -f (Get-SIProRowValue $o 'Kind'), (Get-SIProRowValue $o 'ItemKey'))] = $true }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in $Overrides) {
        $kind = [string](Get-SIProRowValue $o 'Kind'); $key = [string](Get-SIProRowValue $o 'ItemKey'); $state = [string](Get-SIProRowValue $o 'State')
        $bodyText = [string](Get-SIProRowValue $o 'BodyJson'); $fmt = [string](Get-SIProRowValue $o 'Format'); if (-not $fmt) { $fmt = 'json' }
        $bv = [string](Get-SIProRowValue $o 'BaseVersion'); $bh = [string](Get-SIProRowValue $o 'BaseHash')
        if ($kind -eq 'riskindex') {
            $nk = ConvertTo-SIProRiskIndexSiKey -Key $key -Translation $tr
            $body = $null; $isOld = $false
            if ($bodyText) { try { $body = $bodyText | ConvertFrom-Json } catch { $body = $null }; if ($body) { $isOld = Test-SIRiskIndexV22Form @($body) } }
            if (-not $nk -and -not $isOld) { continue }
            if (-not $nk) { $nk = $key }
            $newBody = $null
            if ($state -eq 'override' -and $body) {
                $si = ConvertTo-SIRiskIndexSiRow -Row $body -Translation $tr
                # an item keeps its place: Precedence travels as it was stored
                if ($body.PSObject.Properties['Precedence']) { $si['Precedence'] = [string]$body.Precedence }
                $newBody = ConvertTo-Json -InputObject ([pscustomobject]$si) -Compress
                # the key is made of the translated body's dimensions (a repeat keeps its '#n')
                $sfx = ''; $mm = [regex]::Match($key, '#\d+$'); if ($mm.Success) { $sfx = $mm.Value }
                $nk = 'row/' + ((@('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class', 'si_severity', 'si_tier') | ForEach-Object { ([string]$si[$_]).Trim() }) -join '|') + $sfx
            }
            if ($nk -ne $key -and $have.ContainsKey('riskindex/' + $nk)) {
                $out.Add([pscustomobject]@{ Kind = $kind; OldKey = $key; NewKey = $nk; State = 'inherit'; Body = $null; Format = $fmt; BaseHash = $null; BaseVersion = $null; Action = 'remove'
                        Reason = ("the risk index row {0} is already overridden under its new key {1} -- that one is kept, the old row removed" -f $key, $nk) })
                continue
            }
            $nh = $bh; if ($TemplateHashes.ContainsKey('riskindex/' + $nk)) { $nh = [string]$TemplateHashes['riskindex/' + $nk] }
            $out.Add([pscustomobject]@{ Kind = $kind; OldKey = $key; NewKey = $nk; State = $state; Body = $newBody; Format = $fmt; BaseHash = $nh; BaseVersion = $bv
                    Action = $(if ($nk -eq $key) { 'rewrite' } else { 'move' }); Reason = ("risk index row keyed by the SI fields (was {0})" -f $key) })
            continue
        }
        if ($kind -ne 'datamodel' -or $key -notmatch '^risk-factors:(.+)$') { continue }
        $id = $Matches[1]
        if ($removed.ContainsKey($id)) {
            $out.Add([pscustomobject]@{ Kind = $kind; OldKey = $key; NewKey = $key; State = 'inherit'; Body = $null; Format = $fmt; BaseHash = $null; BaseVersion = $null; Action = 'remove'
                    Reason = ("risk factor {0} no longer exists (replaced by {1}) -- your override of it is removed" -f $id, $removed[$id]) })
            continue
        }
        $sf = $null; if ($shipped.ContainsKey($id)) { $sf = $shipped[$id] }
        if ($state -eq 'disable') {
            if ($sf -and [string]$sf.class -ne 'optional') {
                $out.Add([pscustomobject]@{ Kind = $kind; OldKey = $key; NewKey = $key; State = 'inherit'; Body = $null; Format = $fmt; BaseHash = $null; BaseVersion = $null; Action = 'remove'
                        Reason = ("risk factor {0} is built-in and cannot be switched off -- your 'disable' is removed (lower its impact instead)" -f $id) })
            }
            continue
        }
        if ($state -ne 'override' -or -not $bodyText) { continue }
        $body = $null; try { $body = $bodyText | ConvertFrom-Json } catch { continue }
        if (Test-SIProFactorBodyIsV2 $body) { continue }
        $vv = $null; if ($v1.ContainsKey($id)) { $vv = $v1[$id] }
        $c = ConvertTo-SIProFactorV2Body -Override $body -Shipped $sf -V1 $vv
        $nh = $bh; if ($TemplateHashes.ContainsKey('datamodel/' + $key)) { $nh = [string]$TemplateHashes['datamodel/' + $key] }
        $why = 'risk factor override in the model v2 shape (your values kept)'
        if (@($c.Notes).Count) { $why = $why + ' -- ' + (@($c.Notes) -join '; ') }
        $out.Add([pscustomobject]@{ Kind = $kind; OldKey = $key; NewKey = $key; State = 'override'; Body = (ConvertTo-Json -InputObject ([pscustomobject]$c.Body) -Compress -Depth 30); Format = $fmt
                BaseHash = $nh; BaseVersion = $bv; Action = 'rewrite'; Reason = $why })
    }
    return $out.ToArray()
}

function Resolve-SIProRunOverrides {
    <#
    .SYNOPSIS  RUN START: the stored cfg.ItemOverride rows with every row from the PREVIOUS model translated IN MEMORY for this
               run (the same plan the update applies -- Get-SIProOverrideMigrationPlan). Nothing is written: the update's
               Invoke-SIProOverrideMigration stores it. A row the plan removes (a removed factor, a 'disable' of a built-in
               factor, an old risk index row the customer already redid) is left out; a moved / rewritten row takes its new
               key / body. Returns @{ Overrides; Notes (one per item) }. NEVER THROWS: without the translation table the rows
               come back as stored (each then validated as usual -- one that does not validate is left out by the caller).
    #>
    param([AllowEmptyCollection()][object[]]$Overrides = @(), [Parameter(Mandatory)][string]$SIRoot, $Translation, [AllowEmptyCollection()][object[]]$ShippedFactors)
    $rows = @($Overrides | Where-Object { $_ })
    $notes = New-Object System.Collections.Generic.List[string]
    if (-not $rows.Count) { return [pscustomobject]@{ Overrides = @(); Notes = @() } }
    try {
        if (-not $Translation) { $Translation = Get-SIProOverrideTranslation -SIRoot $SIRoot }
        if ($null -eq $ShippedFactors) { $ShippedFactors = @(([System.IO.File]::ReadAllText([System.IO.Path]::Combine($SIRoot, 'data-model', 'risk-factors.locked.json')) | ConvertFrom-Json).factors) }
        $plan = @(Get-SIProOverrideMigrationPlan -Overrides $rows -Translation $Translation -ShippedFactors @($ShippedFactors))
    } catch {
        return [pscustomobject]@{ Overrides = $rows; Notes = @(("your overrides from the previous model could not be translated for this run ({0}) -- they are read as stored" -f $_.Exception.Message)) }
    }
    if (-not $plan.Count) { return [pscustomobject]@{ Overrides = $rows; Notes = @() } }
    $byOld = @{}; foreach ($a in $plan) { $byOld[('{0}/{1}' -f $a.Kind, $a.OldKey)] = $a }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in $rows) {
        $k = '{0}/{1}' -f (Get-SIProRowValue $o 'Kind'), (Get-SIProRowValue $o 'ItemKey')
        if (-not $byOld.ContainsKey($k)) { $out.Add($o); continue }
        $a = $byOld[$k]
        if ($a.Action -eq 'remove') { $notes.Add(("{0}: {1} (for this run; the next update stores it)" -f $k, $a.Reason)); continue }
        $out.Add([pscustomobject]@{ Kind = $a.Kind; ItemKey = $a.NewKey; State = $a.State
                BodyJson = $(if ($null -ne $a.Body) { [string]$a.Body } else { Get-SIProRowValue $o 'BodyJson' }); Format = $a.Format
                BaseVersion = $a.BaseVersion; BaseHash = $a.BaseHash })
        $notes.Add(("{0}: {1} -- translated for this run (the next update stores it)" -f $k, $a.Reason))
    }
    return [pscustomobject]@{ Overrides = $out.ToArray(); Notes = $notes.ToArray() }
}

function Invoke-SIProOverrideMigration {
    <#
    .SYNOPSIS  Applies Get-SIProOverrideMigrationPlan to the install's cfg.ItemOverride rows (see the header). Returns
               @{ Applied = actions written; Refused = @{ Action; Reason } (left as they were); Plan }. -WhatIf: plan only.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [AllowEmptyCollection()][object[]]$Templates = @(), [string]$ChangedBy = 'SecurityInsight update')
    $ov = @(Read-SIProItemOverrides -Store $Store)
    $tr = Get-SIProOverrideTranslation -SIRoot $SIRoot
    $sf = @(([System.IO.File]::ReadAllText([System.IO.Path]::Combine($SIRoot, 'data-model', 'risk-factors.locked.json')) | ConvertFrom-Json).factors)
    $hashes = @{}
    foreach ($t in $Templates) { $k = '{0}/{1}' -f (Get-SIProRowValue $t 'Kind'), (Get-SIProRowValue $t 'ItemKey'); if (-not $hashes.ContainsKey($k)) { try { $hashes[$k] = Get-SIProRowContentHash $t } catch { } } }
    $plan = @(Get-SIProOverrideMigrationPlan -Overrides $ov -Translation $tr -ShippedFactors $sf -TemplateHashes $hashes)
    $applied = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]
    if ($plan.Count -eq 0 -or $WhatIfPreference) { return [pscustomobject]@{ Applied = @(); Refused = @(); Plan = $plan } }
    $ctx = Get-SIProConfigContext -SIRoot $SIRoot
    foreach ($a in $plan) {
        try {
            if ($a.Action -eq 'remove') {
                Set-SIProItem -Store $Store -Kind $a.Kind -Key $a.OldKey -State inherit -ChangedBy $ChangedBy -Reason $a.Reason -Context $ctx
            } else {
                # the new row first (validated -- a refusal leaves the old row as it was), then the old key goes
                Set-SIProItem -Store $Store -Kind $a.Kind -Key $a.NewKey -State $a.State -Body $a.Body -Format $a.Format -BaseVersion $a.BaseVersion -BaseHash $a.BaseHash -ChangedBy $ChangedBy -Reason $a.Reason -Context $ctx
                if ($a.NewKey -ne $a.OldKey) { Set-SIProItem -Store $Store -Kind $a.Kind -Key $a.OldKey -State inherit -ChangedBy $ChangedBy -Reason ('moved to ' + $a.NewKey) -Context $ctx }
            }
            $applied.Add($a)
        } catch { $refused.Add([pscustomobject]@{ Action = $a; Reason = $_.Exception.Message }) }
    }
    return [pscustomobject]@{ Applied = $applied.ToArray(); Refused = $refused.ToArray(); Plan = $plan }
}
