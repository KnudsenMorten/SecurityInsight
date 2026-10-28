#Requires -Version 5.1
<#
    THE "MORE INFO" TEXT OF EVERY SETTING (framework SETTING-INFO-1). Composed by Build-SISettingsCatalog.ps1 into each
    catalog entry as `info`, from ONE source -- the help words in config\settings.descriptions.locked.json:

      what        what it does                          <- help.purpose
      whenOn      on/off settings: what happens ON      <- the "On:" part of help.effect, else effect / defaultText
      whenOff     on/off settings: what happens OFF     <- the "Off:" part of help.effect, else effect / defaultText
      whenChanged other settings: what a change does    <- help.effect
      risk        what can go wrong, reversibility      <- help.<key>.info.risk, else a rule (guards), else the group's risk
      requires    what it needs / depends on            <- help.<key>.info.requires + needs + edition + Key Vault + engines
      default     the default in words                  <- help.defaultText
      recommended the recommendation                    <- help.<key>.info.recommended, else "keep the default" + whenToChange
      docUrl      the long page on invardia.com         <- https://invardia.com/docs/si/settings/<key>/
      confirmWhen 'on' | 'off' | 'lower' | absent       <- the value that is destructive or security-reducing (guards: off)
      confirm     the text shown in the confirmation    <- help.<key>.info.confirm, else whenOn / whenOff / the risk

    PURE functions. PowerShell 5.1: no ?. / ??, no ternary.
#>

$script:SISettingDocBase = 'https://invardia.com/docs/si/settings/'

function Get-SISettingDocUrl {
    param([Parameter(Mandatory)][string]$Name)
    $script:SISettingDocBase + $Name + '/'
}

function Split-SISettingEffect {
    <#
        PURE. An on/off setting's effect text "Off: ... On: ..." (either order) -> @{ On; Off }; a part not present is ''.
        Only a sentence-starting, capitalised "On:" / "Off:" counts (never "on" inside a sentence).
    #>
    param([AllowEmptyString()][string]$Effect)
    $r = @{ On = ''; Off = '' }
    if ([string]::IsNullOrWhiteSpace($Effect)) { return $r }
    $ms = [regex]::Matches($Effect, '(?<![A-Za-z])(On|Off):\s*')
    if ($ms.Count -eq 0) { return $r }
    for ($i = 0; $i -lt $ms.Count; $i++) {
        $m = $ms[$i]
        $start = $m.Index + $m.Length
        $end = if ($i + 1 -lt $ms.Count) { $ms[$i + 1].Index } else { $Effect.Length }
        $text = $Effect.Substring($start, $end - $start).Trim()
        if ($text) { $r[$m.Groups[1].Value] = $text }
    }
    $r
}

function Remove-SISettingStatePrefix {
    <# PURE. "Off: report only" / "Off, unless ..." / "On." -> the words after the state (the state alone -> ''). #>
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    ($Text -replace '^\s*(On|Off|Not set)\s*[:,.;-]?\s*', '').Trim()
}

function Get-SISettingGuardKind {
    <# PURE. 'guard' (a check's on/off), 'guardMail' (a check's mail), 'guardsAll' (every check), 'guardMailAll', or ''. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -eq 'SI_Guards_Enabled') { return 'guardsAll' }
    if ($Name -eq 'SI_GuardMail_Enabled') { return 'guardMailAll' }
    if ($Name -match '^SI_Guard_.+_Enabled$') { return 'guard' }
    if ($Name -match '^SI_Guard_.+_Mail$') { return 'guardMail' }
    ''
}

function Get-SISettingInfo {
    <#
        PURE. One catalog entry (the ordered hashtable the builder writes, or an object with the same fields) -> its info.
        -Authored: help.<key>.info (any of risk, requires, recommended, whenOn, whenOff, whenChanged, confirmWhen, confirm).
        -GroupRisk: group name -> the risk sentence for settings of that group without their own.
        -LabelOf: { param($name) <the label of another setting> } -- for "requires" (the setting it needs).
    #>
    param(
        [Parameter(Mandatory)]$Setting,
        $Authored,
        [hashtable]$GroupRisk = @{},
        [scriptblock]$LabelOf
    )
    $g = { param($o, $k) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return $o[$k] } else { return $null } }; $p = $o.PSObject.Properties[$k]; if ($p) { $p.Value } else { $null } }
    $name = [string](& $g $Setting 'name')
    $type = [string](& $g $Setting 'type')
    $purpose = [string](& $g $Setting 'purpose')
    $effect = [string](& $g $Setting 'effect')
    $defaultText = [string](& $g $Setting 'defaultText')
    $when = [string](& $g $Setting 'whenToChange')
    $group = [string](& $g $Setting 'group')
    $needs = [string](& $g $Setting 'needs')
    $edition = [string](& $g $Setting 'edition')
    $secret = [bool](& $g $Setting 'secret')
    $engines = @(& $g $Setting 'engines' | Where-Object { $_ })
    $a = { param($k) $v = & $g $Authored $k; if ($null -ne $v -and -not ([string]::IsNullOrWhiteSpace([string]$v))) { [string]$v } else { $null } }

    $info = [ordered]@{}
    $info['what'] = $(if ($purpose) { $purpose } else { [string](& $g $Setting 'description') })

    $kind = Get-SISettingGuardKind -Name $name
    if ($type -eq 'bool') {
        $sp = Split-SISettingEffect -Effect $effect
        $on = & $a 'whenOn'; $off = & $a 'whenOff'
        if (-not $on) { $on = $sp.On }
        if (-not $off) { $off = $sp.Off }
        $defState = ''
        if ($defaultText -match '^\s*On\b') { $defState = 'on' } elseif ($defaultText -match '^\s*Off\b') { $defState = 'off' }
        # the default text usually describes the default state; the effect describes changing away from it
        if (-not $on -and $defState -eq 'on') { $on = Remove-SISettingStatePrefix $defaultText }
        if (-not $off -and $defState -eq 'off') { $off = Remove-SISettingStatePrefix $defaultText }
        if (-not $on -and $effect -and ($defState -ne 'on')) { $on = $effect }
        if (-not $off -and $effect -and ($defState -eq 'on')) { $off = $effect }
        # a default that is neither on nor off ("Not set: ... decides") describes the state when it is not switched on
        if (-not $off -and $defState -eq '' -and $defaultText) { $off = $defaultText }
        if (-not $on) {
            $on = switch ($kind) {
                'guardMail' { 'A mail goes to the alert recipients when this check trips (the install-wide guard-mail switch still applies).' }
                'guard' { 'The check works as described on the Guards page: it holds or stops the step when its condition happens, and raises an event.' }
                default { $(if ($defState -eq 'on') { 'On is the default: it works as described under "What it does".' } else { 'It works as described under "What it does".' }) }
            }
        }
        if (-not $off) { $off = $(if ($defState -eq 'off') { 'Off is the default: none of what "On" describes happens.' } else { 'None of what "On" describes happens.' }) }
        $info['whenOn'] = $on
        $info['whenOff'] = $off
    } else {
        $wc = & $a 'whenChanged'
        $info['whenChanged'] = $(if ($wc) { $wc } elseif ($effect) { $effect } else { 'The new value applies from the next run of the jobs that read it.' })
    }

    # risk and the risky value
    $risk = & $a 'risk'
    $confirmWhen = & $a 'confirmWhen'
    switch ($kind) {
        'guard' {
            if (-not $risk) { $risk = 'Turning this check off removes a protection: when its condition happens, nothing holds or stops the step and no event is raised. Reversible at once: switch it back on; it applies from the next run.' }
            if (-not $confirmWhen) { $confirmWhen = 'off' }
        }
        'guardsAll' {
            if (-not $risk) { $risk = 'Turning this off removes EVERY safety check at once: no step is held or stopped to protect your data, whatever happens. Reversible at once: switch it back on; it applies from the next run.' }
            if (-not $confirmWhen) { $confirmWhen = 'off' }
        }
        'guardMail' {
            if (-not $risk) { $risk = 'Low: no data is changed and the check still works; only its mail stops, so a trip is seen only on the Guards page, in run health and in the audit trail. Reversible at once.' }
            if (-not $confirmWhen) { $confirmWhen = 'off' }
        }
        'guardMailAll' {
            if (-not $risk) { $risk = 'No check mails anyone any more: a held or stopped step is seen only on the Guards page, in run health and in the audit trail. Reversible at once.' }
            if (-not $confirmWhen) { $confirmWhen = 'off' }
        }
    }
    if (-not $risk -and $secret) { $risk = 'A credential: kept only in the install''s Key Vault, never shown again after it is saved. A wrong value stops the steps that use it until it is corrected; nothing else is changed.' }
    if (-not $risk -and $GroupRisk.ContainsKey($group)) { $risk = [string]$GroupRisk[$group] }
    if (-not $risk) { $risk = 'Low: it changes how the jobs that read it behave from their next run; nothing already collected or sent is changed. Reversible: change it back.' }
    $info['risk'] = $risk

    # what it needs
    $req = New-Object System.Collections.Generic.List[string]
    $ar = & $a 'requires'; if ($ar) { $req.Add($ar) }
    if ($needs) {
        $neg = $needs.StartsWith('!'); $nn = $needs.TrimStart('!')
        $nl = $nn; if ($LabelOf) { $x = & $LabelOf $nn; if ($x) { $nl = [string]$x } }
        $req.Add($(if ($neg) { 'Works only while "{0}" is off.' -f $nl } else { 'Works only while "{0}" is on.' -f $nl }))
    }
    if ($edition -eq 'pro') { $req.Add('A SecurityInsight Pro licence.') }
    if ($secret) { $req.Add('Kept in the install''s Key Vault.') }
    if ($engines.Count) { $req.Add('Read by: ' + (($engines | ForEach-Object { [string]$_ }) -join ', ') + '.') }
    if ($req.Count -eq 0) { $req.Add('Nothing else.') }
    $info['requires'] = ($req -join ' ')

    $info['default'] = $(if ($defaultText) { $defaultText } else { 'Not set.' })
    $rec = & $a 'recommended'
    if (-not $rec) {
        $rec = 'Keep the default'
        if ($kind -in 'guard', 'guardsAll', 'guardMailAll') { $rec = 'Keep it on' }
        # the guard relief (owner 2026-10-11): a check that is off by default is a warning the customer may switch on
        if ($kind -eq 'guard' -and $defaultText -match '^\s*Off\b') { $rec = 'Keep the default (off) unless you want this check to hold or stop the step' }
        $rec += $(if ($when) { '. Change it when: ' + $when } else { '.' })
    }
    $info['recommended'] = $rec
    $info['docUrl'] = Get-SISettingDocUrl -Name $name

    if ($confirmWhen) {
        $info['confirmWhen'] = $confirmWhen
        $c = & $a 'confirm'
        if (-not $c) {
            $c = switch ($confirmWhen) {
                'on' { $info['whenOn'] }
                'off' { $(if ($info.Contains('whenOff')) { $info['whenOff'] } else { $risk }) }
                default { $risk }
            }
            if ($c -and $risk -and $c -ne $risk) { $c = $c + ' ' + $risk }
        }
        $info['confirm'] = $c
    }
    $info
}

function Get-SISettingInfoGaps {
    <# PURE. The catalog's settings whose info is missing a field (name: fields) -- the test fails on any. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Settings)
    foreach ($s in $Settings) {
        $i = $s.info
        $miss = New-Object System.Collections.Generic.List[string]
        if ($null -eq $i) { '{0}: info' -f $s.name; continue }
        $fields = @('what', 'risk', 'requires', 'default', 'recommended', 'docUrl')
        if ([string]$s.type -eq 'bool') { $fields += 'whenOn', 'whenOff' } else { $fields += 'whenChanged' }
        foreach ($f in $fields) {
            $v = $null
            if ($i -is [System.Collections.IDictionary]) { if ($i.Contains($f)) { $v = $i[$f] } } elseif ($i.PSObject.Properties[$f]) { $v = $i.$f }
            if ([string]::IsNullOrWhiteSpace([string]$v)) { $miss.Add($f) }
        }
        $cw = $null; if ($i -is [System.Collections.IDictionary]) { if ($i.Contains('confirmWhen')) { $cw = $i['confirmWhen'] } } elseif ($i.PSObject.Properties['confirmWhen']) { $cw = $i.confirmWhen }
        if ($cw) {
            $cf = $null; if ($i -is [System.Collections.IDictionary]) { if ($i.Contains('confirm')) { $cf = $i['confirm'] } } elseif ($i.PSObject.Properties['confirm']) { $cf = $i.confirm }
            if ([string]::IsNullOrWhiteSpace([string]$cf)) { $miss.Add('confirm') }
            if ([string]$cw -notin 'on', 'off', 'lower') { $miss.Add('confirmWhen (on/off/lower)') }
        }
        if ($miss.Count) { '{0}: {1}' -f $s.name, ($miss -join ', ') }
    }
}
