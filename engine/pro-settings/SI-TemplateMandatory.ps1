#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- MANDATORY CONTROLS ON TOP OF TEMPLATES (adopted from PIM4EntraPS: engine-enforced defaults applied
    on top of every policy template, whatever the customer's copy says).

    Some parts of a shipped template item are REQUIRED by SecurityInsight's own code -- a risk factor the scoring needs, a
    collection scope without which an engine has nothing to read. A customer may override the item, but never switch such a
    part off or weaken it:
      * the web app's validators (MandatoryControls.cs) and Set-SIProItem refuse such an override with a plain reason;
      * the run (Merge-SIProItems) applies the mandatory value ON TOP of whatever is stored -- an override written before the
        control existed, or by a path that skipped the validator, cannot switch it off either. Each correction is a note.

    The set is data, config\template-mandatory.locked.json (linked next to the web app as catalog\template-mandatory.locked.json),
    and it is a CODE contract: an entry exists only because code in this release depends on it (the entry names that code).
    One control:
      Kind, ItemKey   the template item ('<kind>/<key>' as in cfg.Template)
      Rule            present  -- the item may not be switched off (State 'disable'); the shipped item applies
                      equals   -- the value at Path must be Value
                      atLeast  -- the number at Path must be >= Value
                      above    -- the number at Path must be > Value; the run applies Default when it is not
                      contains -- the list at Path must hold every entry of Value (a list)
      Path            dot-separated object keys inside the JSON body ('' for 'present')
      Value           the required value (the bound, for atLeast / above)
      Default         (above only) the value the run applies when the customer's is not above the bound
      Reason          one plain sentence a person reads when an override is refused
    A switched-off item counts as every part of it switched off: an item with ANY control can not be disabled.

    PURE except Get-SIProMandatoryControls (reads one shipped file). PowerShell 5.1 safe.
#>

$script:SIProMandatoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:SIProMandatoryRules = @('present', 'equals', 'atLeast', 'above', 'contains')
$script:SIProMandatoryCache = @{}

function Get-SIProMandatoryRules { $script:SIProMandatoryRules }

function ConvertFrom-SIProMandatoryCatalog {
    <# PURE. The catalog text -> its controls. Throws on a malformed catalog (it ships with the code: a test reads it). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $doc = ConvertFrom-Json -InputObject $Text
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($doc.Controls)) {
        if ($null -eq $c) { continue }
        $rule = [string]$c.Rule
        if ($script:SIProMandatoryRules -cnotcontains $rule) { throw ("template-mandatory: '{0}' is not a rule ({1})" -f $rule, ($script:SIProMandatoryRules -join ', ')) }
        $kind = [string]$c.Kind; $key = [string]$c.ItemKey
        if (-not $kind -or -not $key) { throw 'template-mandatory: every control names its Kind and ItemKey' }
        $path = if ($c.PSObject.Properties['Path']) { [string]$c.Path } else { '' }
        if ($rule -ne 'present' -and -not $path) { throw ("template-mandatory: {0}/{1} -- rule '{2}' needs a Path" -f $kind, $key, $rule) }
        $val = if ($c.PSObject.Properties['Value']) { $c.Value } else { $null }
        $num = { param($x) $d = 0.0; ($null -ne $x) -and ($x -isnot [bool]) -and [double]::TryParse([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $x), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) }
        if ($rule -in 'atLeast', 'above' -and -not (& $num $val)) { throw ("template-mandatory: {0}/{1} -- {2} needs a number" -f $kind, $key, $rule) }
        $def = if ($c.PSObject.Properties['Default']) { $c.Default } else { $null }
        if ($rule -eq 'above' -and -not ((& $num $def) -and [double]$def -gt [double]$val)) { throw ("template-mandatory: {0}/{1} -- above needs a Default greater than its Value" -f $kind, $key) }
        if ($rule -eq 'contains' -and -not ($val -is [System.Collections.IEnumerable] -and $val -isnot [string])) { throw ("template-mandatory: {0}/{1} -- contains needs a list" -f $kind, $key) }
        $out.Add([pscustomobject]@{ Id = [string]$c.Id; Kind = $kind; ItemKey = $key; Rule = $rule; Path = $path; Value = $val; Default = $def; Reason = [string]$c.Reason; Code = [string]$c.Code })
    }
    # one by one: callers collect with @(...), and a `, $array` return read through @() nests (one element: the array)
    foreach ($o in $out) { $o }
}

function Get-SIProMandatoryControls {
    <# The shipped controls (config\template-mandatory.locked.json), read once per path. No file = no controls. #>
    param([string]$SIRoot = $script:SIProMandatoryRoot)
    $p = [System.IO.Path]::Combine($SIRoot, 'config', 'template-mandatory.locked.json')
    if (-not $script:SIProMandatoryCache.ContainsKey($p)) {
        $c = @()
        if (Test-Path -LiteralPath $p) { $c = @(ConvertFrom-SIProMandatoryCatalog -Text ([System.IO.File]::ReadAllText($p))) }
        $script:SIProMandatoryCache[$p] = $c
    }
    # one by one (callers collect with @(...)); no file = nothing
    foreach ($o in $script:SIProMandatoryCache[$p]) { $o }
}

function Get-SIProMandatoryFor {
    <# PURE. The controls of one item. #>
    param([AllowEmptyCollection()][object[]]$Controls = @(), [AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key)
    @($Controls | Where-Object { $_ -and $_.Kind -ceq $Kind -and $_.ItemKey -ceq $Key })
}

function Get-SIProMandatoryPathValue {
    <# PURE. @{ Found; Value } at a dot path of a parsed body (PSCustomObject or dictionary). #>
    param($Value, [string]$Path)
    $cur = $Value
    foreach ($seg in ($Path -split '\.')) {
        if ($cur -is [System.Collections.IDictionary]) { if (-not $cur.Contains($seg)) { return @{ Found = $false; Value = $null } }; $cur = $cur[$seg]; continue }
        if ($cur -is [System.Management.Automation.PSCustomObject] -and $cur.PSObject.Properties[$seg]) { $cur = $cur.$seg; continue }
        return @{ Found = $false; Value = $null }
    }
    @{ Found = $true; Value = $cur }
}

function Test-SIProMandatoryValue {
    <# PURE. Does a value satisfy one control? (present is about the item's State, not a value: always $true here) #>
    param([Parameter(Mandatory)]$Control, [bool]$Found, $Value)
    switch ($Control.Rule) {
        'present' { return $true }
        'equals' {
            if (-not $Found) { return $false }
            return ((ConvertTo-SIProJson -Value $Value -Canonical) -ceq (ConvertTo-SIProJson -Value $Control.Value -Canonical))
        }
        'atLeast' {
            if (-not $Found -or $null -eq $Value -or $Value -is [bool] -or $Value -is [string]) { return $false }
            $d = 0.0
            if (-not [double]::TryParse([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $false }
            return ($d -ge [double]$Control.Value)
        }
        'above' {
            if (-not $Found -or $null -eq $Value -or $Value -is [bool] -or $Value -is [string]) { return $false }
            $d = 0.0
            if (-not [double]::TryParse([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $false }
            return ($d -gt [double]$Control.Value)
        }
        'contains' {
            if (-not $Found -or $null -eq $Value -or $Value -is [string] -or -not ($Value -is [System.Collections.IEnumerable])) { return $false }
            $have = @(foreach ($v in $Value) { ConvertTo-SIProJson -Value $v -Canonical })
            foreach ($need in @($Control.Value)) { if ($have -cnotcontains (ConvertTo-SIProJson -Value $need -Canonical)) { return $false } }
            return $true
        }
    }
    $false
}

function Get-SIProMandatoryText {
    <# PURE. The plain sentence for one control a customer's change breaks. #>
    param([Parameter(Mandatory)]$Control, [switch]$WhatOnly)
    $v = ConvertTo-SIProJson -Value $Control.Value -Canonical
    $what = switch ($Control.Rule) {
        'present' { 'it cannot be switched off' }
        'equals' { "'{0}' must stay {1}" -f $Control.Path, $v }
        'atLeast' { "'{0}' must be at least {1}" -f $Control.Path, $v }
        'above' { "'{0}' must be more than {1}" -f $Control.Path, $v }
        'contains' { "'{0}' must keep {1}" -f $Control.Path, $v }
    }
    if ($WhatOnly) { return $what }
    $r = if ($Control.Reason) { ' -- ' + $Control.Reason } else { '' }
    ('{0}/{1} is required by SecurityInsight: {2}{3}' -f $Control.Kind, $Control.ItemKey, $what, $r)
}

function Test-SIProMandatoryOverride {
    <#
        PURE. The reasons a customer's state of an item is refused because it switches a mandatory part off or weakens it
        (empty = accepted). -State 'disable' on an item with any control is refused; 'override' is checked per control
        against the body; 'inherit' is always accepted (the shipped item meets every control).
    #>
    param([AllowEmptyCollection()][object[]]$Controls = @(), [AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key,
          [AllowEmptyString()][string]$State, [AllowEmptyString()][AllowNull()][string]$Body)
    $mine = @(Get-SIProMandatoryFor -Controls $Controls -Kind $Kind -Key $Key)
    if ($mine.Count -eq 0 -or $State -eq 'inherit') { return @() }
    if ($State -eq 'disable') {
        $why = New-Object System.Collections.Generic.List[string]
        foreach ($c in $mine) { $why.Add(('{0}/{1} is required by SecurityInsight and cannot be switched off{2}' -f $Kind, $Key, $(if ($c.Reason) { ' -- ' + $c.Reason } else { '' }))) }
        return @($why | Select-Object -Unique)
    }
    $o = $null
    try { $o = ConvertFrom-SIProJson ([string]$Body).TrimStart([char]0xFEFF) } catch { return @() }   # an unreadable body is the item validator's to refuse
    @(foreach ($c in $mine) {
        if ($c.Rule -eq 'present') { continue }
        $pv = Get-SIProMandatoryPathValue -Value $o -Path $c.Path
        if (-not (Test-SIProMandatoryValue -Control $c -Found $pv.Found -Value $pv.Value)) { Get-SIProMandatoryText -Control $c }
    })
}

function Set-SIProMandatoryValues {
    <#
        PURE. The run's side: the mandatory values put ON TOP of an effective JSON body. Returns @{ Body; Changed; Applied
        (one plain line per correction) }. A body that is not JSON (or not an object) is returned as it is.
    #>
    param([AllowEmptyCollection()][object[]]$Controls = @(), [AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key,
          [AllowEmptyString()][AllowNull()][string]$Body)
    $mine = @(Get-SIProMandatoryFor -Controls $Controls -Kind $Kind -Key $Key | Where-Object { $_.Rule -ne 'present' })
    $same = [pscustomobject]@{ Body = $Body; Changed = $false; Applied = @() }
    if ($mine.Count -eq 0) { return $same }
    $o = $null
    try { $o = ConvertTo-SIProMutableValue (ConvertFrom-SIProJson ([string]$Body).TrimStart([char]0xFEFF)) } catch { return $same }
    if ($o -isnot [System.Collections.IDictionary]) { return $same }
    $applied = New-Object System.Collections.Generic.List[string]
    foreach ($c in $mine) {
        $pv = Get-SIProMandatoryPathValue -Value $o -Path $c.Path
        if (Test-SIProMandatoryValue -Control $c -Found $pv.Found -Value $pv.Value) { continue }
        # walk / create the path; the last key receives the value
        $segs = @($c.Path -split '\.'); $cur = $o; $ok = $true
        for ($i = 0; $i -lt $segs.Count - 1; $i++) {
            $s = $segs[$i]
            if (-not $cur.Contains($s) -or $cur[$s] -isnot [System.Collections.IDictionary]) {
                if ($cur.Contains($s) -and $null -ne $cur[$s]) { $ok = $false; break }   # another type sits there: never guessed over
                $cur[$s] = [ordered]@{}
            }
            $cur = $cur[$s]
        }
        if (-not $ok) { continue }
        $last = $segs[$segs.Count - 1]
        if ($c.Rule -eq 'contains') {
            $list = if ($cur.Contains($last) -and $cur[$last] -is [System.Collections.IList]) { $cur[$last] } else { New-Object System.Collections.ArrayList }
            $have = @(foreach ($v in $list) { ConvertTo-SIProJson -Value $v -Canonical })
            foreach ($need in @($c.Value)) { if ($have -cnotcontains (ConvertTo-SIProJson -Value $need -Canonical)) { [void]$list.Add((ConvertTo-SIProMutableValue $need)) } }
            $cur[$last] = $list
        } elseif ($c.Rule -eq 'above') {
            $cur[$last] = $c.Default
        } else {
            $cur[$last] = ConvertTo-SIProMutableValue $c.Value
        }
        $applied.Add(('{0}/{1}: {2} -- the required value is applied' -f $Kind, $Key, (Get-SIProMandatoryText -Control $c -WhatOnly)))
    }
    if ($applied.Count -eq 0) { return $same }
    [pscustomobject]@{ Body = (ConvertTo-SIProJson -Value $o); Changed = $true; Applied = $applied.ToArray() }
}
