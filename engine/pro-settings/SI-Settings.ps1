#Requires -Version 5.1
<#
    The Settings page's backend: read every settings layer, plan a change as a reviewable diff, write it safely.

    🔒 SURGICAL, NEVER REGENERATED. A custom config file is hand-edited by operators and carries code (Key Vault
    pulls, conditionals) next to plain values. A change here replaces ONLY the value of one top-level
    `$global:Name = <literal>` assignment, or appends one line to a marked block. Write-SICustomConfig's
    whole-file render is for first setup and must never be used from this page -- it would drop every hand edit
    it does not model. An assignment that is not a plain literal is refused, never rewritten.

    Everything in this file except Write-SISettingsFile is pure (text in, text out) and tested directly.
#>

$script:SISettingsMarker = '# --- set by the Settings page (SecurityInsight Config Wizard) ---'
function Get-SIPs1Assignments {
    <#
        PURE. Every `$global:Name = ...` assignment in a PowerShell text. Per assignment: Name, Line, TopLevel (not
        inside an if / function / loop), Literal (a plain value: string, number, $true/$false/$null, or an array of
        those), Value (when literal), ValueText, and the offsets needed to edit it.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $found = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -match '^global:[A-Za-z_][A-Za-z0-9_]*$'
    }, $true)
    foreach ($a in $found) {
        $name = ($a.Left.VariablePath.UserPath -replace '^global:', '')
        # Top level = the statement's parent chain reaches the script block without an if / loop / function / try.
        $p = $a.Parent; $top = $true
        while ($p -and -not ($p -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -eq $p.Parent)) {
            if ($p -isnot [System.Management.Automation.Language.NamedBlockAst] -and $p -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $top = $false; break }
            $p = $p.Parent
        }
        $expr = $null
        $right = $a.Right
        if ($right -is [System.Management.Automation.Language.PipelineAst] -and $right.PipelineElements.Count -eq 1 -and
            $right.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $expr = $right.PipelineElements[0].Expression
        } elseif ($right -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $expr = $right.Expression
        }
        $literal = $false; $value = $null
        if ($expr -and $a.Operator -eq [System.Management.Automation.Language.TokenKind]::Equals) {
            $isVar = $expr -is [System.Management.Automation.Language.VariableExpressionAst]
            $okVar = (-not $isVar) -or ($expr.VariablePath.UserPath -in 'true', 'false', 'null')
            $hasVar = @($expr.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -notin 'true', 'false', 'null' }, $true)).Count -gt 0
            $hasCall = @($expr.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -or $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or $n -is [System.Management.Automation.Language.SubExpressionAst] }, $true)).Count -gt 0
            $isHash = @($expr.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] -or $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)).Count -gt 0
            if ($okVar -and -not $hasVar -and -not $hasCall -and -not $isHash) {
                try { $value = $expr.SafeGetValue(); $literal = $true } catch { $literal = $false }
            }
        }
        $vs = if ($expr) { $expr.Extent.StartOffset } else { $right.Extent.StartOffset }
        $ve = if ($expr) { $expr.Extent.EndOffset } else { $right.Extent.EndOffset }
        [pscustomobject]@{
            Name = $name; Line = $a.Extent.StartLineNumber; TopLevel = $top; Literal = $literal
            Value = $value; ValueText = $Text.Substring($vs, $ve - $vs)
            StatementStart = $a.Extent.StartOffset; StatementEnd = $a.Extent.EndOffset; ValueStart = $vs; ValueEnd = $ve
        }
    }
}

function ConvertTo-SIPs1Literal {
    <# PURE. A value as PowerShell source: 'text' (quotes doubled), numbers invariant, $true/$false/$null, @('a', 'b'). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '$null' }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
    }
    if ($Value -is [string]) { return ("'{0}'" -f $Value.Replace("'", "''")) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary]) {
        $items = @(foreach ($v in $Value) {
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { throw 'nested lists are not supported' }
            ConvertTo-SIPs1Literal $v
        })
        return ('@(' + ($items -join ', ') + ')')
    }
    throw ("a value of type {0} cannot be written as a setting" -f $Value.GetType().Name)
}

function Edit-SIPs1Settings {
    <#
        PURE. Apply changes to a custom config text. Each change: @{ Name; Action = 'Set' | 'Reset'; Value }.
          Set   -- the file's top-level literal assignment gets the new value (only its value text changes); with no
                   assignment, one line is appended to the marked block at the end.
          Reset -- the top-level literal assignment's line is removed, so the layer below applies again.
        Refused (and listed, the text untouched for that name): any assignment of the name that is code, inside an
        if / function, or shares its line with other code. Returns @{ Text; Applied; Refused }.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][object[]]$Changes)
    $nl = if ($Text.Contains("`r`n")) { "`r`n" } elseif ($Text.Contains("`n")) { "`n" } else { "`r`n" }
    $assign = @(Get-SIPs1Assignments -Text $Text)
    $edits = New-Object System.Collections.Generic.List[object]     # @{ Start; End; Text }
    $appends = New-Object System.Collections.Generic.List[string]
    $applied = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Changes) {
        $name = [string]$c.Name
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { $refused.Add([pscustomobject]@{ Name = $name; Reason = 'not a valid setting name' }); continue }
        $mine = @($assign | Where-Object { $_.Name -eq $name })
        $bad = @($mine | Where-Object { -not $_.TopLevel -or -not $_.Literal })
        if ($bad.Count -gt 0) {
            $refused.Add([pscustomobject]@{ Name = $name; Reason = ('set by code at line {0} -- edit it in the file' -f $bad[0].Line) }); continue
        }
        if ($c.Action -eq 'Set') {
            try { $lit = ConvertTo-SIPs1Literal $c.Value } catch { $refused.Add([pscustomobject]@{ Name = $name; Reason = $_.Exception.Message }); continue }
            if ($mine.Count -gt 0) {
                # Every literal top-level assignment gets the value -- the last one wins at run time, and leaving an
                # earlier one stale would make the file read one way and run another.
                foreach ($m in $mine) { $edits.Add(@{ Start = $m.ValueStart; End = $m.ValueEnd; Text = $lit }) }
            } else {
                $appends.Add(('$global:{0} = {1}' -f $name, $lit))
            }
            $applied.Add([pscustomobject]@{ Name = $name; Action = 'Set'; Value = $c.Value })
        } elseif ($c.Action -eq 'Reset') {
            if ($mine.Count -eq 0) { continue }    # nothing set here: already the layer below
            $ok = $true; $cuts = @()
            foreach ($m in $mine) {
                $ls = $Text.LastIndexOf("`n", [Math]::Max(0, $m.StatementStart - 1)); $ls = if ($m.StatementStart -eq 0 -or $ls -lt 0) { 0 } else { $ls + 1 }
                $le = $Text.IndexOf("`n", $m.StatementEnd); $le = if ($le -lt 0) { $Text.Length } else { $le + 1 }
                $before = $Text.Substring($ls, $m.StatementStart - $ls)
                $after  = $Text.Substring($m.StatementEnd, $le - $m.StatementEnd).TrimEnd("`r", "`n")
                if ($before.Trim() -ne '' -or ($after.Trim() -ne '' -and -not $after.Trim().StartsWith('#'))) { $ok = $false; break }
                $cuts += @{ Start = $ls; End = $le; Text = '' }
            }
            if (-not $ok) { $refused.Add([pscustomobject]@{ Name = $name; Reason = 'shares its line with other code -- edit it in the file' }); continue }
            foreach ($x in $cuts) { $edits.Add($x) }
            $applied.Add([pscustomobject]@{ Name = $name; Action = 'Reset'; Value = $null })
        } else {
            $refused.Add([pscustomobject]@{ Name = $name; Reason = ('unknown action {0}' -f $c.Action) })
        }
    }
    $out = $Text
    foreach ($e in @($edits | Sort-Object { $_.Start } -Descending)) {
        $out = $out.Substring(0, $e.Start) + $e.Text + $out.Substring($e.End)
    }
    if ($appends.Count -gt 0) {
        $idx = $out.IndexOf($script:SISettingsMarker)
        if ($idx -ge 0) {
            $le = $out.IndexOf("`n", $idx); $le = if ($le -lt 0) { $out.Length } else { $le + 1 }
            $block = ($appends -join $nl) + $nl
            if ($le -eq $out.Length -and -not $out.EndsWith("`n")) { $block = $nl + $block }
            $out = $out.Substring(0, $le) + $block + $out.Substring($le)
        } else {
            $sep = if ($out.Length -eq 0) { '' } elseif ($out.EndsWith("`n")) { $nl } else { $nl + $nl }
            $out = $out + $sep + $script:SISettingsMarker + $nl + ($appends -join $nl) + $nl
        }
    }
    # Self-check: the result parses, and every Set reads back as the value asked for.
    $perr = $null; $tk = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($out, [ref]$tk, [ref]$perr)
    if (@($perr).Count -gt 0) { throw ('the edited file would not parse: {0}' -f $perr[0].Message) }
    $check = @(Get-SIPs1Assignments -Text $out)
    foreach ($a in @($applied | Where-Object { $_.Action -eq 'Set' })) {
        $last = @($check | Where-Object { $_.Name -eq $a.Name -and $_.TopLevel -and $_.Literal }) | Select-Object -Last 1
        if (-not $last -or (ConvertTo-SIPs1Literal $last.Value) -ne (ConvertTo-SIPs1Literal $a.Value)) { throw ('{0} did not read back as the value written' -f $a.Name) }
    }
    [pscustomobject]@{ Text = $out; Applied = $applied.ToArray(); Refused = $refused.ToArray() }
}

function Get-SITextDiff {
    <# PURE. A unified diff (3 lines of context) between two texts; empty when they are equal. #>
    param([AllowEmptyString()][string]$Old, [AllowEmptyString()][string]$New, [string]$Label = 'file', [int]$Context = 3)
    $a = @($Old -split "`r?`n"); $b = @($New -split "`r?`n")
    if ($Old -ceq $New) { return '' }
    $pre = 0; while ($pre -lt $a.Count -and $pre -lt $b.Count -and $a[$pre] -ceq $b[$pre]) { $pre++ }
    $suf = 0; while ($suf -lt ($a.Count - $pre) -and $suf -lt ($b.Count - $pre) -and $a[$a.Count - 1 - $suf] -ceq $b[$b.Count - 1 - $suf]) { $suf++ }
    $am = @(if ($a.Count - $pre - $suf -gt 0) { $a[$pre..($a.Count - $suf - 1)] })
    $bm = @(if ($b.Count - $pre - $suf -gt 0) { $b[$pre..($b.Count - $suf - 1)] })
    # LCS over the changed middle only -- a settings change touches a few lines.
    $n = $am.Count; $m = $bm.Count
    # jagged, not [int[,]]: PS 5.1 cannot parse a computed second index like $L[$i, ($j + 1)]
    $L = New-Object 'object[]' ($n + 1)
    for ($i = 0; $i -le $n; $i++) { $L[$i] = New-Object 'int[]' ($m + 1) }
    for ($i = $n - 1; $i -ge 0; $i--) { $row = $L[$i]; $down = $L[$i + 1]; for ($j = $m - 1; $j -ge 0; $j--) {
        if ($am[$i] -ceq $bm[$j]) { $row[$j] = $down[$j + 1] + 1 } else { $row[$j] = [Math]::Max($down[$j], $row[$j + 1]) } } }
    $body = New-Object System.Collections.Generic.List[string]
    $cs = [Math]::Max(0, $pre - $Context)
    for ($k = $cs; $k -lt $pre; $k++) { $body.Add(' ' + $a[$k]) }
    $i = 0; $j = 0
    while ($i -lt $n -or $j -lt $m) {
        if ($i -lt $n -and $j -lt $m -and $am[$i] -ceq $bm[$j]) { $body.Add(' ' + $am[$i]); $i++; $j++ }
        # on a tie the removed line comes first, so a changed line reads "- old" then "+ new"
        elseif ($j -lt $m -and ($i -ge $n -or $L[$i][$j + 1] -gt $L[$i + 1][$j])) { $body.Add('+' + $bm[$j]); $j++ }
        else { $body.Add('-' + $am[$i]); $i++ }
    }
    $ce = [Math]::Min($a.Count, $a.Count - $suf + $Context)
    for ($k = $a.Count - $suf; $k -lt $ce; $k++) { $body.Add(' ' + $a[$k]) }
    $hdr = '@@ -{0} +{1} @@' -f ($cs + 1), ($cs + 1)
    (@("--- $Label", "+++ $Label", $hdr) + $body.ToArray()) -join "`n"
}

function Get-SISettingsTargets {
    <#
        PURE given a root. The ONLY files the page may write, by key -- the browser names a key, never a path:
        'solution' = config\SecurityInsight.custom.ps1; 'engine:<name>' = launcher\<name>\LauncherConfig.custom.ps1 for
        every engine folder that ships a LauncherConfig.defaults.ps1 or LauncherConfig.custom.sample.ps1.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $t = [ordered]@{ 'solution' = (Join-Path $SIRoot 'config\SecurityInsight.custom.ps1') }
    foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $SIRoot 'launcher') -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        if ($d.Name -eq '_lib') { continue }
        if ((Test-Path -LiteralPath (Join-Path $d.FullName 'LauncherConfig.defaults.ps1')) -or (Test-Path -LiteralPath (Join-Path $d.FullName 'LauncherConfig.custom.sample.ps1'))) {
            $t[('engine:{0}' -f $d.Name)] = (Join-Path $d.FullName 'LauncherConfig.custom.ps1')
        }
    }
    $t
}

function Get-SIFileHash {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([System.IO.File]::ReadAllBytes($Path)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Read-SISettingsText {
    <# The text of a settings file (empty when absent) and whether it carries a UTF-8 BOM. #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Text = ''; Bom = $true; Exists = $false } }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $text = if ($bom) { [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) } else { [System.Text.Encoding]::UTF8.GetString($bytes) }
    [pscustomobject]@{ Text = $text; Bom = $bom; Exists = $true }
}

function Write-SISettingsFile {
    <#
        Write one settings file: refused when it changed since it was read (hash), backed up first
        (<file>.bak.<timestamp>), written to a temp file and swapped in, so it is never half-written. Keeps a BOM the
        file had, and adds one when the text is not plain ASCII (PowerShell 5.1 misreads UTF-8 without it).
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
          [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedHash, [bool]$Bom = $true)
    $now = Get-SIFileHash -Path $Path
    if ($now -ne $ExpectedHash) { throw ('{0} changed since it was read -- reload and review again' -f (Split-Path -Leaf $Path)) }
    $useBom = $Bom -or ($Text -match '[^\x00-\x7F]')
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { throw ('folder not found: {0}' -f $dir) }
    # Short on purpose: PS 5.1 (.NET Framework) refuses paths over 260 characters, and "<long report name>.<guid>.tmp"
    # crossed it in a deep install folder (measured 2026-10-02). Same folder, so the swap below stays one step.
    $tmp = Join-Path $dir ('.si-{0}.tmp' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    [System.IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($useBom)))
    $backup = $null
    if (Test-Path -LiteralPath $Path) {
        $backup = '{0}.bak.{1}' -f $Path, (Get-Date).ToString('yyyyMMdd-HHmmss')
        [System.IO.File]::Replace($tmp, $Path, $backup)
    } else {
        [System.IO.File]::Move($tmp, $Path)
    }
    [pscustomobject]@{ Path = $Path; Backup = $backup; Hash = (Get-SIFileHash -Path $Path) }
}

function Get-SISettingsCatalog {
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = Join-Path $SIRoot 'config\settings.catalog.locked.json'
    if (-not (Test-Path -LiteralPath $p)) { throw "settings catalog not found: $p" }
    (Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json).settings
}

function Get-SISettingsRetiredNames {
    <#
        The settings that no longer exist (the catalog's "retired" list). A value left for one -- in a configuration file
        or a Pro settings row -- is ignored without a message: never imported, never refused, never applied.
    #>
    param([string]$SIRoot)
    # default: the solution root this function's own file ships in (engine\pro-settings\ -> root) -- read from the
    # function itself, so it holds however and from whichever scope this file was loaded
    if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.ScriptBlock.File)) }
    if (-not $SIRoot) { return @() }
    $p = Join-Path $SIRoot 'config\settings.catalog.locked.json'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    $c = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $c.PSObject.Properties['retired']) { return @() }
    @($c.retired | Where-Object { $_ } | ForEach-Object { [string]$_ })
}

function Get-SISettingsView {
    <#
        Every catalog setting with the value each layer gives it, the effective one, and where it comes from.
        Layers, closest last: shared default -> engine default -> solution custom -> engine custom. A secret's value is
        NEVER returned -- only whether it is set, and whether by code. Pro-only settings are left out: this page is the
        Community edition's; Pro keeps its settings in SQL and manages them from its own page (operator, 2026-10-02).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][object[]]$Catalog)
    $targets = Get-SISettingsTargets -SIRoot $SIRoot
    $read = @{}
    function _layer([string]$key, [string]$path) {
        $r = Read-SISettingsText -Path $path
        $read[$key] = [pscustomobject]@{ Path = $path; Exists = $r.Exists; Assign = @(Get-SIPs1Assignments -Text $r.Text); Hash = (Get-SIFileHash -Path $path) }
    }
    _layer 'shared' (Join-Path $SIRoot 'launcher\_lib\SecurityInsight.shared-defaults.ps1')
    foreach ($k in $targets.Keys) {
        _layer $k $targets[$k]
        if ($k -like 'engine:*') { _layer ('default:' + $k.Substring(7)) (Join-Path $SIRoot ('launcher\{0}\LauncherConfig.defaults.ps1' -f $k.Substring(7))) }
    }
    $rows = foreach ($s in $Catalog) {
        if ($s.edition -eq 'pro') { continue }
        $engines = @($s.engines)
        $order = @(@{ Key = 'shared'; Label = 'shared default' })
        foreach ($e in $engines) { $order += @{ Key = "default:$e"; Label = "$e default" } }
        $order += @{ Key = 'solution'; Label = 'solution custom' }
        foreach ($e in $engines) { $order += @{ Key = "engine:$e"; Label = "$e custom" } }
        $layers = foreach ($o in $order) {
            $L = $read[$o.Key]
            if (-not $L) { continue }
            $hits = @($L.Assign | Where-Object { $_.Name -eq $s.name })
            if ($hits.Count -eq 0) { continue }
            $h = $hits[-1]
            $code = -not ($h.Literal -and $h.TopLevel)
            [pscustomobject]@{
                layer = $o.Label; key = $o.Key; line = $h.Line; byCode = $code
                value = if ($s.secret -or $code) { $null } else { $h.Value }
                text  = if ($s.secret) { $(if ($code) { '(set by code)' } else { '(set -- hidden)' }) } elseif ($code) { $h.ValueText } else { $null }
            }
        }
        $layers = @($layers)
        $eff = if ($layers.Count) { $layers[-1] } else { $null }
        [pscustomobject]@{
            name = $s.name; label = $s.label; group = $s.group; type = $s.type; engines = $engines; edition = $s.edition
            secret = [bool]$s.secret; advanced = [bool]$s.advanced; description = $s.description
            purpose = $s.purpose; defaultText = $s.defaultText; effect = $s.effect; whenToChange = $s.whenToChange; unit = $s.unit
            values = $s.values; valueLabels = $s.valueLabels   # a fixed set of choices (type 'enum'): shown as a dropdown
            target = if ($engines.Count -eq 1) { "engine:$($engines[0])" } else { 'solution' }
            layers = $layers; effective = $eff
            editable = (-not $s.secret)
        }
    }
    [pscustomobject]@{
        root = $SIRoot
        files = @(foreach ($k in $read.Keys | Sort-Object) { [pscustomobject]@{ key = $k; path = $read[$k].Path; exists = $read[$k].Exists; hash = $read[$k].Hash; writable = $targets.Contains($k) } })
        settings = @($rows)
    }
}

function ConvertTo-SISettingNumber {
    <#
        PURE. A 'number' setting's value as a finite [double], or $null when it is not one. A real number (any integer or
        decimal type) is taken as is; text is parsed with the INVARIANT culture only -- '0.01' is a number, '0,01' is not,
        whatever the machine's culture -- so the same text means the same value on every host. NaN and infinity are not
        numbers here. Booleans, lists and everything else are refused.
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $d = [double]::NaN
    if ($Value -is [string]) {
        if (-not [double]::TryParse($Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    } elseif ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or
              $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        $d = [double]$Value
    } else { return $null }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
    $d
}

function Test-SISettingValue {
    <# PURE. $null when the value fits the setting's type, else the reason. #>
    param([Parameter(Mandatory)]$Setting, [AllowNull()]$Value)
    switch ([string]$Setting.type) {
        'number' {
            $d = ConvertTo-SISettingNumber $Value
            if ($null -eq $d) { return 'must be a number' }
            $inv = [System.Globalization.CultureInfo]::InvariantCulture
            if ($null -ne $Setting.min -and $d -lt [double]$Setting.min) { return [string]::Format($inv, 'must be at least {0}', [double]$Setting.min) }
            if ($null -ne $Setting.max -and $d -gt [double]$Setting.max) { return [string]::Format($inv, 'must be at most {0}', [double]$Setting.max) }
        }
        'bool'   { if ($Value -isnot [bool]) { return 'must be true or false' } }
        'int'    {
            $n = 0L
            if (-not [long]::TryParse([string]$Value, [ref]$n)) { return 'must be a whole number' }
            if ($null -ne $Setting.min -and $n -lt [long]$Setting.min) { return ('must be at least {0}' -f $Setting.min) }
            if ($null -ne $Setting.max -and $n -gt [long]$Setting.max) { return ('must be at most {0}' -f $Setting.max) }
        }
        'list'   { if ($null -ne $Value -and -not ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string])) { return 'must be a list' } }
        'enum'   { if (@($Setting.values) -notcontains [string]$Value) { return ('must be one of: {0}' -f (@($Setting.values) -join ', ')) } }
        default  { if ($null -ne $Value -and $Value -isnot [string]) { return 'must be text' } }
    }
    if ($Setting.pattern -and $null -ne $Value -and [string]$Value -ne '' -and [string]$Value -notmatch [string]$Setting.pattern) { return ('does not match the expected format ({0})' -f $Setting.patternHint) }
    $null
}

function Invoke-SISettingsPlan {
    <#
        A list of changes -> what each custom file would become, as a diff. Nothing is written. A change:
        @{ name; action = 'Set' | 'Reset'; value }; its file comes from the catalog (one engine -> that engine's
        custom file, else the solution file) -- the browser never names a file. Unknown settings, secrets, Pro settings
        and values of the wrong type are refused with the reason. Returns @{ files; refused } where each file carries
        its key, relative path, current hash, diff and (internal, not for the browser) the new text.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][object[]]$Catalog, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes)
    $targets = Get-SISettingsTargets -SIRoot $SIRoot
    $byName = @{}; foreach ($s in $Catalog) { $byName[[string]$s.name] = $s }
    $refused = New-Object System.Collections.Generic.List[object]
    $perFile = [ordered]@{}
    foreach ($c in $Changes) {
        $name = [string]$c.name; $action = [string]$c.action
        $s = $byName[$name]
        if (-not $s) { $refused.Add([pscustomobject]@{ name = $name; reason = 'not a known setting' }); continue }
        if ($s.secret) { $refused.Add([pscustomobject]@{ name = $name; reason = 'a secret is never set from this page -- keep it in Key Vault' }); continue }
        if ($s.edition -eq 'pro') { $refused.Add([pscustomobject]@{ name = $name; reason = 'a Pro setting is managed from the Pro settings page' }); continue }
        if ($action -notin 'Set', 'Reset') { $refused.Add([pscustomobject]@{ name = $name; reason = "unknown action '$action'" }); continue }
        $value = $c.value
        if ($action -eq 'Set') {
            if ($s.type -eq 'int' -and $value -is [string]) { $n = 0L; if ([long]::TryParse($value, [ref]$n)) { $value = [int]$n } }
            if ($s.type -eq 'list' -and $null -ne $value) { $value = @($value | ForEach-Object { [string]$_ }) }
            $why = Test-SISettingValue -Setting $s -Value $value
            # a number is written as a number literal, invariant ('0.01', never '0,01' or a quoted '0.01'); a [double] also
            # reads back as itself -- a [decimal] from PS 5.1's ConvertFrom-Json would keep '0.010' and fail the read-back
            if (-not $why -and $s.type -eq 'number') { $value = ConvertTo-SISettingNumber $value }
            if ($why) { $refused.Add([pscustomobject]@{ name = $name; reason = $why }); continue }
        }
        $engines = @($s.engines)
        $key = if ($engines.Count -eq 1) { "engine:$($engines[0])" } else { 'solution' }
        if (-not $targets.Contains($key)) { $refused.Add([pscustomobject]@{ name = $name; reason = "no custom file for $key" }); continue }
        if (-not $perFile.Contains($key)) { $perFile[$key] = New-Object System.Collections.Generic.List[object] }
        $perFile[$key].Add(@{ Name = $name; Action = $action; Value = $value })
    }
    $files = foreach ($key in $perFile.Keys) {
        $path = $targets[$key]
        $r = Read-SISettingsText -Path $path
        $ed = Edit-SIPs1Settings -Text $r.Text -Changes $perFile[$key].ToArray()
        foreach ($x in $ed.Refused) { $refused.Add([pscustomobject]@{ name = $x.Name; reason = $x.Reason }) }
        $rel = $path.Substring($SIRoot.Length).TrimStart('\')
        [pscustomobject]@{
            key = $key; path = $rel; exists = $r.Exists; hash = (Get-SIFileHash -Path $path)
            diff = (Get-SITextDiff -Old $r.Text -New $ed.Text -Label $rel)
            applied = @($ed.Applied | ForEach-Object { [pscustomobject]@{ name = $_.Name; action = $_.Action; value = $_.Value } })
            NewText = $ed.Text; Bom = $r.Bom; OldAssign = @(Get-SIPs1Assignments -Text $r.Text)
        }
    }
    [pscustomobject]@{ files = @($files); refused = $refused.ToArray() }
}

function Invoke-SISettingsWrite {
    <#
        Re-plans the same changes on the server (the browser's text is never trusted) and writes each file only when
        its hash is still the one the operator reviewed. Every applied change is logged to logs\settings-changes.log.
        Nothing is written when any change is refused or any file is stale.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][object[]]$Catalog, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes,
          [Parameter(Mandatory)][hashtable]$Hashes, [string]$User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    $plan = Invoke-SISettingsPlan -SIRoot $SIRoot -Catalog $Catalog -Changes $Changes
    if (@($plan.refused).Count -gt 0) { return [pscustomobject]@{ written = @(); refused = $plan.refused; error = 'some changes were refused -- nothing was written' } }
    foreach ($f in $plan.files) {
        if (-not $Hashes.ContainsKey($f.key) -or [string]$Hashes[$f.key] -ne $f.hash) {
            return [pscustomobject]@{ written = @(); refused = @(); error = ('{0} changed since it was reviewed -- review again' -f $f.path) }
        }
    }
    $written = New-Object System.Collections.Generic.List[object]
    $logDir = Join-Path $SIRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir 'settings-changes.log'
    foreach ($f in $plan.files) {
        if (-not $f.diff) { continue }
        $w = Write-SISettingsFile -Path (Join-Path $SIRoot $f.path) -Text $f.NewText -ExpectedHash $f.hash -Bom $f.Bom
        foreach ($a in $f.applied) {
            $old = @($f.OldAssign | Where-Object { $_.Name -eq $a.name }) | Select-Object -Last 1
            $line = [ordered]@{
                time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); user = $User; file = $f.path; setting = $a.name; action = $a.action
                old = $(if ($old) { $old.ValueText } else { $null }); new = $(if ($a.action -eq 'Set') { ConvertTo-SIPs1Literal $a.value } else { $null })
            }
            [System.IO.File]::AppendAllText($log, (($line | ConvertTo-Json -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        }
        $written.Add([pscustomobject]@{ key = $f.key; path = $f.path; backup = $(if ($w.Backup) { $w.Backup.Substring($SIRoot.Length).TrimStart('\') } else { $null }); hash = $w.Hash })
    }
    [pscustomobject]@{ written = $written.ToArray(); refused = @(); error = $null }
}

# =====================================================================================================================
#  PHASE 2 -- the JSON settings: Risk Analysis exclusions and risk weights (risk-analysis-detection\*.custom.json)
#  🔴 Every exclusion value and every weight field / value-map key is pasted into a KQL query by the engine, which
#  escapes only a double quote. A backslash, a quote or a line break could break or change the query, so each value
#  is checked against a strict pattern here -- the page's only way in.
# =====================================================================================================================
$script:SIJsonPatterns = @{
    Cve      = '^CVE-\d{4}-\d{4,7}$'
    ConfigId = '^[A-Za-z0-9._:\-]{1,128}$'
    Tag      = '^[^"\\\r\n]{1,128}$'
    Field    = '^[A-Za-z_][A-Za-z0-9_]{0,63}$'
    MapKey   = '^[^"\\\r\n]{1,64}$'
    IpRange  = '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$'
}
$script:SIWeightEngines = @('endpoint', 'identity', 'azure', 'publicip')

function ConvertTo-SIJsonText {
    <# PURE. Stable, readable JSON (2-space indent). A list is ALWAYS an array -- PS 5.1's ConvertTo-Json writes a one-item list as a bare value. #>
    param([AllowNull()]$Value, [int]$Level = 0)
    $pad = '  ' * $Level; $pad1 = '  ' * ($Level + 1)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
        return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
    }
    if ($Value -is [string]) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in $Value.ToCharArray()) {
            switch ($ch) {
                '"'  { [void]$sb.Append('\"') } '\' { [void]$sb.Append('\\') }
                "`n" { [void]$sb.Append('\n') } "`r" { [void]$sb.Append('\r') } "`t" { [void]$sb.Append('\t') }
                default { if ([int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) } }
            }
        }
        [void]$sb.Append('"'); return $sb.ToString()
    }
    $pairs = $null
    if ($Value -is [System.Collections.IDictionary]) { $pairs = @(foreach ($k in $Value.get_Keys()) { ,@([string]$k, $Value[$k]) }) }
    elseif ($Value -is [pscustomobject]) { $pairs = @(foreach ($p in $Value.PSObject.Properties) { ,@($p.Name, $p.Value) }) }
    if ($null -ne $pairs) {
        if ($pairs.Count -eq 0) { return '{}' }
        $items = foreach ($p in $pairs) { $pad1 + (ConvertTo-SIJsonText $p[0]) + ': ' + (ConvertTo-SIJsonText $p[1] ($Level + 1)) }
        return "{`n" + ($items -join ",`n") + "`n$pad}"
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = @($Value)
        if ($arr.Count -eq 0) { return '[]' }
        $items = foreach ($v in $arr) { $pad1 + (ConvertTo-SIJsonText $v ($Level + 1)) }
        return "[`n" + ($items -join ",`n") + "`n$pad]"
    }
    return (ConvertTo-SIJsonText ([string]$Value) $Level)
}

function Get-SIRaReportNames {
    <# The Risk Analysis report names in the shipped query file -- the only names an exclusion file may be created for. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = Join-Path $SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    @([regex]::Matches([System.IO.File]::ReadAllText($p), '(?m)^\s*-\s*ReportName:\s*([A-Za-z0-9_]+)\s*$') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

function Resolve-SIJsonTarget {
    <# A JSON settings key -> its file, or $null. 'exclusions:global' | 'exclusions:<Report>' (a shipped report) | 'weights'. #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Key, [string[]]$Reports)
    $dir = Join-Path $SIRoot 'risk-analysis-detection'
    if ($Key -eq 'exclusions:global') { return (Join-Path $dir 'RiskAnalysisGlobalExclusions.custom.json') }
    if ($Key -eq 'weights') { return (Join-Path $dir 'riskscore_weighted.schema.custom.json') }
    if ($Key -match '^exclusions:([A-Za-z0-9_]+)$') {
        $r = $Matches[1]
        if (-not $Reports) { $Reports = Get-SIRaReportNames -SIRoot $SIRoot }
        if ($Reports -contains $r) { return (Join-Path $dir ('{0}.exclude.custom.json' -f $r)) }
    }
    $null
}

function Test-SIJsonChange {
    <# PURE. The reasons a change to a JSON settings file is not allowed (empty = allowed). #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Property, [AllowNull()]$Value)
    $why = New-Object System.Collections.Generic.List[string]
    function _list($v, $rx, $what) {
        foreach ($x in @($v)) { if ([string]$x -notmatch $rx) { $why.Add(("'{0}' is not a valid {1}" -f $x, $what)) } }
    }
    if ($Key -eq 'exclusions:global') {
        # #541: the global exclusions -- asset tags, assets (CI ids or names) and address ranges -- reach every report whose
        # scope declares them (data-model/report-scope, the Risk Analysis scope preamble)
        switch ($Property) {
            'ExcludedAssetTags' { _list $Value $script:SIJsonPatterns.Tag 'tag (no quotes, backslashes or line breaks)' }
            'ExcludedAssets'    { _list $Value $script:SIJsonPatterns.Tag 'asset id or name (no quotes, backslashes or line breaks)' }
            'ExcludedIpRanges'  { _list $Value $script:SIJsonPatterns.IpRange 'IPv4 address or range (a.b.c.d/nn)' }
            default             { $why.Add('only ExcludedAssetTags, ExcludedAssets and ExcludedIpRanges can be set globally'); return $why.ToArray() }
        }
    } elseif ($Key -like 'exclusions:*') {
        switch ($Property) {
            'ExcludedCves'             { _list $Value $script:SIJsonPatterns.Cve 'CVE id (CVE-YYYY-NNNN)' }
            'ExcludedConfigurationIds' { _list $Value $script:SIJsonPatterns.ConfigId 'configuration id (letters, digits, . _ : -)' }
            'ExcludedAssetTags'        { _list $Value $script:SIJsonPatterns.Tag 'tag (no quotes, backslashes or line breaks)' }
            'ExcludedAssets'           { _list $Value $script:SIJsonPatterns.Tag 'asset id or name (no quotes, backslashes or line breaks)' }
            'ExcludedIpRanges'         { _list $Value $script:SIJsonPatterns.IpRange 'IPv4 address or range (a.b.c.d/nn)' }
            'CveMinAgeDays'            { $n = 0; if (-not [int]::TryParse([string]$Value, [ref]$n) -or $n -lt 0 -or $n -gt 3650) { $why.Add('CveMinAgeDays must be a whole number from 0 to 3650') } }
            default                    { $why.Add("'$Property' is not an exclusion setting") }
        }
    } elseif ($Key -eq 'weights') {
        if ($script:SIWeightEngines -notcontains $Property) { $why.Add("'$Property' is not an engine (endpoint, identity, azure, publicip)"); return $why.ToArray() }
        if ($null -eq $Value) { return $why.ToArray() }   # null = remove this engine's weights
        # Multipliers are BASIS-100 WHOLE NUMBERS, as the engine reads them (RA-WeightedFactors.ps1 casts each to [int]
        # and divides by 100): 100 = 1.0x, 150 = 1.5x. A decimal like 1.5 would become 2 = 0.02x -- silently no weight --
        # so it is refused rather than accepted. A multiplier is 1..1000 (up to 10x); the cap is 0 (none) .. 10000 (100x,
        # what two fields at 10x can reach). The real weights in use run 100..175.
        function _whole($v, [double]$lo, [double]$hi) {
            $d = 0.0
            if (-not [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $false }
            ($d -eq [Math]::Floor($d)) -and $d -ge $lo -and $d -le $hi
        }
        $combine = [string]$Value.combine
        if ($combine -and $combine -notin 'product', 'max', 'sum-of-deltas') { $why.Add("combine must be product, max or sum-of-deltas") }
        if ($null -ne $Value.maxMultiplier -and -not (_whole $Value.maxMultiplier 0 10000)) { $why.Add('maxMultiplier must be a whole number from 0 to 10000 (100 = 1.0x, 500 = a 5x cap, 0 = no cap)') }
        $fields = @($Value.fields)
        if ($fields.Count -eq 0) { $why.Add('at least one weighted field is needed') }
        foreach ($fl in $fields) {
            if ([string]$fl.field -notmatch $script:SIJsonPatterns.Field) { $why.Add(("'{0}' is not a valid field name" -f $fl.field)); continue }
            $map = $fl.valueMap
            $props = if ($map -is [System.Collections.IDictionary]) { @($map.get_Keys()) } elseif ($map) { @($map.PSObject.Properties.Name) } else { @() }
            if ($props.Count -eq 0) { $why.Add(("{0}: the value map is empty" -f $fl.field)) }
            foreach ($k in $props) {
                if ([string]$k -notmatch $script:SIJsonPatterns.MapKey) { $why.Add(("{0}: '{1}' is not a valid value" -f $fl.field, $k)) }
                $mv = if ($map -is [System.Collections.IDictionary]) { $map[$k] } else { $map.$k }
                if (-not (_whole $mv 1 1000)) { $why.Add(("{0}: the multiplier for '{1}' must be a whole number from 1 to 1000 (100 = 1.0x, 150 = 1.5x)" -f $fl.field, $k)) }
            }
            if ($null -ne $fl.default -and -not (_whole $fl.default 1 1000)) { $why.Add(("{0}: the default multiplier must be a whole number from 1 to 1000 (100 = 1.0x)" -f $fl.field)) }
        }
    } else {
        $why.Add("unknown settings file '$Key'")
    }
    $why.ToArray()
}

function ConvertTo-SIOrderedJson {
    <# PURE. ConvertFrom-Json output -> ordered dictionaries / lists, so a property can be set while every other key keeps its place. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [pscustomobject]) {
        $o = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = ConvertTo-SIOrderedJson $p.Value }; return $o
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}; foreach ($k in $Value.get_Keys()) { $o[[string]$k] = ConvertTo-SIOrderedJson $Value[$k] }; return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return ,@(foreach ($v in $Value) { ConvertTo-SIOrderedJson $v }) }
    $Value
}

function Edit-SIJsonSettings {
    <#
        PURE. Apply property changes to one JSON settings file's text (empty / absent = {}). Every other key -- the
        `_`-prefixed notes included -- keeps its value and place. For 'weights' the property is an engine under
        weightedRiskFactors; $null removes it. For exclusions $null removes the property.
    #>
    param([Parameter(Mandatory)][string]$Key, [AllowEmptyString()][string]$Text, [Parameter(Mandatory)][object[]]$Changes)
    $doc = if ([string]::IsNullOrWhiteSpace($Text)) { [ordered]@{} } else { ConvertTo-SIOrderedJson ($Text | ConvertFrom-Json) }
    if ($doc -isnot [System.Collections.IDictionary]) { throw 'the file is not a JSON object' }
    foreach ($c in $Changes) {
        $prop = [string]$c.property
        $val = ConvertTo-SIOrderedJson $c.value
        if ($Key -eq 'weights') {
            if (-not $doc.Contains('weightedRiskFactors') -or $doc['weightedRiskFactors'] -isnot [System.Collections.IDictionary]) { $doc['weightedRiskFactors'] = [ordered]@{} }
            $w = $doc['weightedRiskFactors']
            if ($null -eq $val) { if ($w.Contains($prop)) { $w.Remove($prop) } } else { $w[$prop] = $val }
        } else {
            if ($null -eq $val) { if ($doc.Contains($prop)) { $doc.Remove($prop) } }
            elseif ($prop -eq 'CveMinAgeDays') { $doc[$prop] = [int]$val }
            else { $doc[$prop] = @(@($val) | ForEach-Object { [string]$_ }) }
        }
    }
    (ConvertTo-SIJsonText $doc) + "`n"
}

function Get-SIJsonSettingsView {
    <# What the Exclusions and Risk weights pages show: the report names, the current global / per-report exclusions, and the current weights per engine. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $reports = @(Get-SIRaReportNames -SIRoot $SIRoot)
    $dir = Join-Path $SIRoot 'risk-analysis-detection'
    function _read([string]$path) {
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        try { Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { [pscustomobject]@{ _unreadable = $_.Exception.Message } }
    }
    $g = _read (Join-Path $dir 'RiskAnalysisGlobalExclusions.custom.json')
    $per = foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.exclude.custom.json' -ErrorAction SilentlyContinue)) {
        $name = $f.Name -replace '\.exclude\.custom\.json$', ''
        $b = _read $f.FullName
        [pscustomobject]@{ report = $name; known = ($reports -contains $name); hash = (Get-SIFileHash -Path $f.FullName)
            ExcludedCves = @($b.ExcludedCves | Where-Object { $_ }); ExcludedConfigurationIds = @($b.ExcludedConfigurationIds | Where-Object { $_ })
            ExcludedAssetTags = @($b.ExcludedAssetTags | Where-Object { $_ }); CveMinAgeDays = $b.CveMinAgeDays }
    }
    $wpath = Join-Path $dir 'riskscore_weighted.schema.custom.json'
    $w = _read $wpath
    $sample = _read (Join-Path $dir 'riskscore_weighted.schema.custom.sample.json')
    $engines = foreach ($e in $script:SIWeightEngines) {
        $sec = if ($w -and $w.weightedRiskFactors -and $w.weightedRiskFactors.PSObject.Properties[$e]) { $w.weightedRiskFactors.$e } else { $null }
        $ex = if ($sample -and $sample.weightedRiskFactors -and $sample.weightedRiskFactors.PSObject.Properties[$e]) { $sample.weightedRiskFactors.$e } else { $null }
        [pscustomobject]@{ engine = $e; current = $sec; example = $ex }
    }
    [pscustomobject]@{
        reports = $reports
        global  = [pscustomobject]@{ ExcludedAssetTags = @($g.ExcludedAssetTags | Where-Object { $_ }); hash = (Get-SIFileHash -Path (Join-Path $dir 'RiskAnalysisGlobalExclusions.custom.json')) }
        perReport = @($per)
        weights = [pscustomobject]@{ engines = @($engines); hash = (Get-SIFileHash -Path $wpath); exists = (Test-Path -LiteralPath $wpath) }
    }
}

function Invoke-SIJsonSettingsPlan {
    <# Changes @{ key; property; value } -> per-file diff + hash, nothing written. Refused changes carry the reasons. #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes)
    $reports = @(Get-SIRaReportNames -SIRoot $SIRoot)
    $refused = New-Object System.Collections.Generic.List[object]
    $perFile = [ordered]@{}
    foreach ($c in $Changes) {
        $key = [string]$c.key; $prop = [string]$c.property
        $path = Resolve-SIJsonTarget -SIRoot $SIRoot -Key $key -Reports $reports
        if (-not $path) { $refused.Add([pscustomobject]@{ name = "$key/$prop"; reason = "'$key' is not a settings file this page may change" }); continue }
        $why = @(Test-SIJsonChange -Key $key -Property $prop -Value $c.value)
        if ($why.Count) { $refused.Add([pscustomobject]@{ name = "$key/$prop"; reason = ($why -join '; ') }); continue }
        if (-not $perFile.Contains($key)) { $perFile[$key] = @{ Path = $path; Changes = New-Object System.Collections.Generic.List[object] } }
        $perFile[$key].Changes.Add(@{ property = $prop; value = $c.value })
    }
    $files = foreach ($key in $perFile.Keys) {
        $path = $perFile[$key].Path
        $r = Read-SISettingsText -Path $path
        try { $new = Edit-SIJsonSettings -Key $key -Text $r.Text -Changes $perFile[$key].Changes.ToArray() }
        catch { $refused.Add([pscustomobject]@{ name = $key; reason = ('the current file could not be read: {0}' -f $_.Exception.Message) }); continue }
        $rel = $path.Substring($SIRoot.Length).TrimStart('\')
        [pscustomobject]@{ key = $key; path = $rel; exists = $r.Exists; hash = (Get-SIFileHash -Path $path)
            diff = (Get-SITextDiff -Old $r.Text -New $new -Label $rel); applied = @($perFile[$key].Changes | ForEach-Object { [pscustomobject]@{ property = $_.property } })
            NewText = $new; OldText = $r.Text }
    }
    [pscustomobject]@{ files = @($files); refused = $refused.ToArray() }
}

function Invoke-SIJsonSettingsWrite {
    <# Re-plans on the server and writes only files whose hash is still the reviewed one; logs each change. Nothing is written when anything is refused or stale. #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes,
          [Parameter(Mandatory)][hashtable]$Hashes, [string]$User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    $plan = Invoke-SIJsonSettingsPlan -SIRoot $SIRoot -Changes $Changes
    if (@($plan.refused).Count) { return [pscustomobject]@{ written = @(); refused = $plan.refused; error = 'some changes were refused -- nothing was written' } }
    foreach ($f in $plan.files) {
        if (-not $Hashes.ContainsKey($f.key) -or [string]$Hashes[$f.key] -ne $f.hash) { return [pscustomobject]@{ written = @(); refused = @(); error = ('{0} changed since it was reviewed -- review again' -f $f.path) } }
    }
    $logDir = Join-Path $SIRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir 'settings-changes.log'
    $written = New-Object System.Collections.Generic.List[object]
    foreach ($f in $plan.files) {
        if (-not $f.diff) { continue }
        $w = Write-SISettingsFile -Path (Join-Path $SIRoot $f.path) -Text $f.NewText -ExpectedHash $f.hash -Bom $false
        foreach ($a in $f.applied) {
            $line = [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); user = $User; file = $f.path; setting = $a.property; action = 'Set' }
            [System.IO.File]::AppendAllText($log, (($line | ConvertTo-Json -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        }
        $written.Add([pscustomobject]@{ key = $f.key; path = $f.path; backup = $(if ($w.Backup) { $w.Backup.Substring($SIRoot.Length).TrimStart('\') } else { $null }); hash = $w.Hash })
    }
    [pscustomobject]@{ written = $written.ToArray(); refused = @(); error = $null }
}

# =====================================================================================================================
#  PHASE 3 -- tier rules (asset-profiling-enrichment\<engine>\...\<id>.custom.yaml)
#  A custom rule with the same id REPLACES the shipped one; `mode: disable` turns it off; a rule in the overlay folder
#  (SI_EnrichmentDataRoot, outside the code tree) wins over both. The page writes only rules it created (marked on the
#  first line) -- a hand-written custom rule is shown read-only, because a YAML round trip would drop its comments.
# =====================================================================================================================
$script:SIRuleMarker = '# Created by the SecurityInsight Settings page'
$script:SIRuleEngines = @('endpoint', 'identity', 'azure', 'shared')

function Get-SIRuleKinds {
    <# The detection kinds the engine evaluates, read from its registry (the page never guesses). #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = Join-Path $SIRoot 'engine\asset-profiling\shared\RuleEval.ps1'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    $t = [System.IO.File]::ReadAllText($p)
    $i = $t.IndexOf('$script:SIKindRegistry = @{'); if ($i -lt 0) { return @() }
    $j = $t.IndexOf("`n}", $i)
    @([regex]::Matches($t.Substring($i, $j - $i), "(?m)^\s*'([A-Za-z]+)'\s*=") | ForEach-Object { $_.Groups[1].Value })
}

function Get-SIRuleHeader {
    <# PURE. The few fields the list shows, read from the text (no YAML round trip): id, mode, purpose, category, tiers set, page-created. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $f = { param($k) $m = [regex]::Match($Text, "(?m)^$k\s*:\s*(.+?)\s*$"); if ($m.Success) { $m.Groups[1].Value.Trim("'", '"', ' ') } else { '' } }
    [pscustomobject]@{
        Id = (& $f 'id'); Mode = (& $f 'mode'); Purpose = (& $f 'purpose'); Category = (& $f 'category')
        Tiers = @([regex]::Matches($Text, '(?m)^\s*Tier\s*:\s*(\d+)') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
        PageCreated = $Text.TrimStart([char]0xFEFF).StartsWith($script:SIRuleMarker)
    }
}

function Get-SIRuleView {
    <#
        Every rule by id: its shipped file, an in-tree custom file, an overlay custom file, which one the engine uses, and
        whether the page may edit it. Paths are relative (to the solution, or to the overlay as 'overlay:...').
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot)
    $tree = Join-Path $SIRoot 'asset-profiling-enrichment'
    $byId = [ordered]@{}
    function _add($file, $base, $where) {
        $rel = $file.FullName.Substring($base.Length).TrimStart('\')
        $parts = $rel -split '\\'
        $engine = $parts[0].ToLowerInvariant()
        if ($script:SIRuleEngines -notcontains $engine) { return }
        $relDir = if ($parts.Count -gt 2) { ($parts[1..($parts.Count - 2)] -join '\') } else { '' }
        $text = [System.IO.File]::ReadAllText($file.FullName)
        $h = Get-SIRuleHeader -Text $text
        $id = if ($h.Id) { $h.Id } else { $file.Name -replace '\.(locked|custom)\.yaml$', '' }
        $key = "$engine|$id"
        if (-not $byId.Contains($key)) { $byId[$key] = [ordered]@{ id = $id; engine = $engine; relDir = $relDir; locked = $null; custom = $null; overlay = $null } }
        $entry = [pscustomobject]@{ path = $(if ($where -eq 'overlay') { 'overlay:' + $rel } else { 'asset-profiling-enrichment\' + $rel }); mode = $h.Mode
            purpose = $h.Purpose; category = $h.Category; tiers = $h.Tiers; pageCreated = $h.PageCreated; hash = (Get-SIFileHash -Path $file.FullName) }
        $byId[$key][$where] = $entry
        if (-not $byId[$key].relDir -and $relDir) { $byId[$key].relDir = $relDir }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter '*.yaml' -ErrorAction SilentlyContinue)) {
        if ($f.Name -like '*.locked.yaml') { _add $f $tree 'locked' } elseif ($f.Name -like '*.custom.yaml') { _add $f $tree 'custom' }
    }
    if ($OverlayRoot -and (Test-Path -LiteralPath $OverlayRoot)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $OverlayRoot -Recurse -File -Filter '*.custom.yaml' -ErrorAction SilentlyContinue)) { _add $f $OverlayRoot 'overlay' }
    }
    $rows = foreach ($k in $byId.Keys) {
        $r = $byId[$k]
        $eff = if ($r.overlay) { $r.overlay } elseif ($r.custom) { $r.custom } else { $r.locked }
        $state = if (-not $r.locked) { 'added' } elseif ($eff -eq $r.locked) { 'shipped' } elseif ($eff.mode -eq 'disable') { 'turned off' } else { 'overridden' }
        $show = if ($eff.mode -eq 'disable' -and $r.locked) { $r.locked } else { $eff }
        [pscustomobject]@{ id = $r.id; engine = $r.engine; relDir = $r.relDir; state = $state
            purpose = $show.purpose; category = $show.category; tiers = $show.tiers
            locked = $r.locked; custom = $r.custom; overlay = $r.overlay; effective = $eff.path
            editable = ($eff -ne $r.locked -and $eff.pageCreated) }
    }
    @($rows | Sort-Object engine, relDir, id)
}

function Get-SIRuleTargetPath {
    <# Where the page writes a custom rule: the overlay when one is set, else beside the shipped rule. Id and folder are checked -- no path from the browser. #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, [Parameter(Mandatory)][string]$Engine, [AllowEmptyString()][string]$RelDir, [Parameter(Mandatory)][string]$Id)
    if ($script:SIRuleEngines -notcontains $Engine) { throw "unknown rule engine '$Engine'" }
    if ($Id -notmatch '^[A-Za-z][A-Za-z0-9_\-]{0,99}$') { throw "'$Id' is not a valid rule id (letters, digits, _ and -)" }
    if ($RelDir -and $RelDir -notmatch '^[A-Za-z0-9_\-]+(\\[A-Za-z0-9_\-]+)*$') { throw "'$RelDir' is not a valid rule folder" }
    $base = if ($OverlayRoot) { $OverlayRoot } else { Join-Path $SIRoot 'asset-profiling-enrichment' }
    $dir = if ($RelDir) { Join-Path (Join-Path $base $Engine) $RelDir } else { Join-Path $base $Engine }
    Join-Path $dir ('{0}.custom.yaml' -f $Id)
}

function New-SIRuleText {
    <# PURE. The text the page writes: turn a shipped rule off, start an override from the shipped text, or a new rule. #>
    param([Parameter(Mandatory)][ValidateSet('disable', 'override', 'add')][string]$Kind, [Parameter(Mandatory)][string]$Id,
          [string]$Engine = 'endpoint', [AllowEmptyString()][string]$LockedText = '')
    switch ($Kind) {
        'disable'  { return ("{0} -- turns off the shipped rule {1}.`r`nid: {1}`r`nmode: disable`r`n" -f $script:SIRuleMarker, $Id) }
        'override' {
            $body = ($LockedText.TrimStart([char]0xFEFF) -replace '(?m)^mode:\s*\S+', 'mode: overwrite')
            return ("{0} -- replaces the shipped rule {1}; edit below.`r`n{2}" -f $script:SIRuleMarker, $Id, $body)
        }
        'add' {
            $applies = if ($Engine -eq 'shared') { 'any' } else { $Engine }
            return (@(
                "$($script:SIRuleMarker) -- a rule of this installation.",
                "id: $Id", "appliesTo: $applies", 'mode: append', "purpose: 'Describe what this rule finds'", "category: 'Custom'", "description: ''",
                '', 'detections:', "  - id: $Id", '    detect:', '      any:', '        - kind: nameMatches', '          namePatterns:', "            - '(?i)^example-'",
                '    set:', '      Tier: 3', "      Purpose: 'Describe what this rule finds'", "      Category: 'Custom'", ''
            ) -join "`r`n")
        }
    }
}

function Test-SIRuleText {
    <# The reasons a rule text is not accepted (empty = accepted): it must parse, carry the expected id, and use only known kinds and tiers 0-3. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string[]]$Kinds)
    $why = New-Object System.Collections.Generic.List[string]
    if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Yaml.ps1'))
    }
    $o = $null
    try { $o = ConvertFrom-SIYaml -Yaml $Text -SourceName ('rule ' + $Id) } catch { $why.Add('the rule is not valid YAML: ' + $_.Exception.Message); return $why.ToArray() }
    if ($o -isnot [System.Collections.IDictionary]) { $why.Add('the rule must be a YAML mapping'); return $why.ToArray() }
    if ([string]$o['id'] -ne $Id) { $why.Add("the id must stay '$Id' -- it is what replaces the shipped rule") }
    if ([string]$o['mode'] -eq 'disable') { return $why.ToArray() }
    $ap = @($o['appliesTo'] | ForEach-Object { ([string]$_) -split '[,;]\s*' } | Where-Object { $_ })
    foreach ($a in $ap) { if ($a.ToLowerInvariant() -notin 'endpoint', 'identity', 'azure', 'publicip', 'any') { $why.Add("appliesTo '$a' is not an engine") } }
    $dets = @($o['detections'])
    if ($dets.Count -eq 0 -or $null -eq $dets[0]) { $why.Add('a rule needs at least one detection'); return $why.ToArray() }
    foreach ($d in $dets) {
        $dt = $d['detect']
        $list = if ($dt -and $dt['any']) { @($dt['any']) } elseif ($dt -and $dt['all']) { @($dt['all']) } else { @() }
        if ($list.Count -eq 0) { $why.Add(("detection '{0}': detect needs an 'any' or 'all' list" -f $d['id'])) }
        foreach ($k in $list) { if ($Kinds -notcontains [string]$k['kind']) { $why.Add(("detection '{0}': '{1}' is not a detection kind the engine knows" -f $d['id'], $k['kind'])) } }
        $set = $d['set']
        if ($set -and $null -ne $set['Tier']) { $n = 0; if (-not [int]::TryParse([string]$set['Tier'], [ref]$n) -or $n -lt 0 -or $n -gt 3) { $why.Add(("detection '{0}': Tier must be 0, 1, 2 or 3" -f $d['id'])) } }
    }
    $why.ToArray()
}

# #908: every shipped sample rule (*.custom.sample.yaml) starts with this header line. A live rule that still carries it
# is the shipped EXAMPLE copied as it was -- on one install the IP-subnet sample (10.100.1.0/24 -> Tier 0, a "Domain
# Controller") became a live rule that way. The web app keys on the same text (RuleEntry.IsShippedExample).
$script:SIRuleSampleMarkerPattern = '(?m)^[ \t]*#[ \t]*SAMPLE[ \t]*/[ \t]*TEMPLATE\b'

function Test-SIRuleSampleMarker {
    <# PURE. $true when the rule text declares itself a shipped sample / template (the '# SAMPLE / TEMPLATE' header line). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    [regex]::IsMatch($Text, $script:SIRuleSampleMarkerPattern)
}

function Get-SIRuleSamplePath {
    <#
        The shipped sample a custom rule file was copied from: <rel>.custom.yaml -> asset-profiling-enrichment\<rel>.custom.sample.yaml,
        for a file in the tree or in the overlay (whose paths are relative to the overlay root, engine first). $null when none.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Path, [string]$OverlayRoot)
    $tree = Join-Path $SIRoot 'asset-profiling-enrichment'
    $full = [System.IO.Path]::GetFullPath($Path)
    $rel = $null
    foreach ($base in @($tree, $OverlayRoot)) {
        if (-not $base) { continue }
        $b = [System.IO.Path]::GetFullPath($base).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        if ($full.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) { $rel = $full.Substring($b.Length); break }
    }
    if (-not $rel -or $rel -notmatch '(?i)\.custom\.yaml$') { return $null }
    $p = Join-Path $tree ($rel -replace '(?i)\.custom\.yaml$', '.custom.sample.yaml')
    if (Test-Path -LiteralPath $p) { $p } else { $null }
}

function Get-SIRuleSampleReason {
    <#
        PURE (#908). Why a custom rule text must NOT become a live rule, or $null:
          * it still carries the sample header ('# SAMPLE / TEMPLATE -- not loaded by the engine ...'), or
          * it is the shipped sample unchanged (-SampleText; compared with all whitespace removed).
        The importer refuses such a document and says so; the run only warns (it never drops a rule on suspicion).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [AllowEmptyString()][AllowNull()][string]$SampleText)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $squash = { param([string]$s) [regex]::Replace($s.TrimStart([char]0xFEFF), '\s+', '') }
    if (-not [string]::IsNullOrWhiteSpace($SampleText) -and (& $squash $Text) -ceq (& $squash $SampleText)) {
        return 'it is the shipped sample (.custom.sample.yaml) copied unchanged -- an example, not your rule. Edit it to describe your own assets (and remove the SAMPLE / TEMPLATE header), then import again'
    }
    if (Test-SIRuleSampleMarker -Text $Text) {
        return "it still starts with the shipped sample's '# SAMPLE / TEMPLATE -- not loaded by the engine' header, so it is the example, not a reviewed rule. Check every detection (example names, subnets and tiers), remove that header line, then import again"
    }
    $null
}

function Invoke-SIRulePlan {
    <#
        Rule changes -> per-file diffs, nothing written. A change: @{ action = disable|override|add|edit|remove; id; engine; relDir; text }.
          disable / override / add -- create the page's custom rule (refused if a custom rule for that id already exists);
          edit   -- replace the text of a rule the page created;   remove -- take a page-created rule away (it is kept as a backup).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes)
    $view = @(Get-SIRuleView -SIRoot $SIRoot -OverlayRoot $OverlayRoot)
    $kinds = @(Get-SIRuleKinds -SIRoot $SIRoot)
    $refused = New-Object System.Collections.Generic.List[object]
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Changes) {
        $id = [string]$c.id; $engine = ([string]$c.engine).ToLowerInvariant(); $action = [string]$c.action
        $name = "$engine/$id"
        $row = $view | Where-Object { $_.id -eq $id -and $_.engine -eq $engine } | Select-Object -First 1
        try {
            $relDir = if ($row) { $row.relDir } else { [string]$c.relDir }
            $target = Get-SIRuleTargetPath -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Engine $engine -RelDir $relDir -Id $id
        } catch { $refused.Add([pscustomobject]@{ name = $name; reason = $_.Exception.Message }); continue }
        $own = if ($row) { if ($row.overlay) { $row.overlay } elseif ($row.custom) { $row.custom } } else { $null }
        $old = ''; $new = $null; $path = $target
        switch ($action) {
            { $_ -in 'disable', 'override' } {
                if (-not $row -or -not $row.locked) { $refused.Add([pscustomobject]@{ name = $name; reason = 'no shipped rule with that id' }); continue }
                if ($own) { $refused.Add([pscustomobject]@{ name = $name; reason = 'this rule already has a custom version -- edit or remove that one' }); continue }
                $lockedText = [System.IO.File]::ReadAllText((Join-Path $SIRoot $row.locked.path))
                $new = New-SIRuleText -Kind $action -Id $id -Engine $engine -LockedText $lockedText
            }
            'add' {
                if ($row) { $refused.Add([pscustomobject]@{ name = $name; reason = 'a rule with that id already exists' }); continue }
                $new = if ($c.text) { [string]$c.text } else { New-SIRuleText -Kind add -Id $id -Engine $engine }
            }
            'edit' {
                if (-not $own -or -not $own.pageCreated) { $refused.Add([pscustomobject]@{ name = $name; reason = 'only a rule this page created can be edited here -- edit a hand-written rule in its file' }); continue }
                $path = if ($own.path -like 'overlay:*') { Join-Path $OverlayRoot $own.path.Substring(8) } else { Join-Path $SIRoot $own.path }
                $old = [System.IO.File]::ReadAllText($path); $new = [string]$c.text
                if (-not $new.TrimStart([char]0xFEFF).StartsWith($script:SIRuleMarker)) { $new = $script:SIRuleMarker + "`r`n" + $new }
            }
            'remove' {
                if (-not $own -or -not $own.pageCreated) { $refused.Add([pscustomobject]@{ name = $name; reason = 'only a rule this page created can be removed here' }); continue }
                $path = if ($own.path -like 'overlay:*') { Join-Path $OverlayRoot $own.path.Substring(8) } else { Join-Path $SIRoot $own.path }
                $old = [System.IO.File]::ReadAllText($path); $new = ''
            }
            default { $refused.Add([pscustomobject]@{ name = $name; reason = "unknown action '$action'" }); continue }
        }
        if ($action -ne 'remove') {
            $why = @(Test-SIRuleText -Text $new -Id $id -Kinds $kinds)
            if ($why.Count) { $refused.Add([pscustomobject]@{ name = $name; reason = ($why -join '; ') }); continue }
        }
        $label = if ($OverlayRoot -and $path.StartsWith($OverlayRoot, [StringComparison]::OrdinalIgnoreCase)) { 'overlay:' + $path.Substring($OverlayRoot.Length).TrimStart('\') } else { $path.Substring($SIRoot.Length).TrimStart('\') }
        $files.Add([pscustomobject]@{ key = $name; action = $action; path = $label; exists = (Test-Path -LiteralPath $path); hash = (Get-SIFileHash -Path $path)
            diff = (Get-SITextDiff -Old $old -New $new -Label $label); FullPath = $path; NewText = $new })
    }
    [pscustomobject]@{ files = $files.ToArray(); refused = $refused.ToArray() }
}

function Invoke-SIRuleWrite {
    <# Re-plans on the server; writes each rule only when its hash is the reviewed one; a removal keeps the file as a backup. Logged. #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Changes,
          [Parameter(Mandatory)][hashtable]$Hashes, [string]$User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    $plan = Invoke-SIRulePlan -SIRoot $SIRoot -OverlayRoot $OverlayRoot -Changes $Changes
    if (@($plan.refused).Count) { return [pscustomobject]@{ written = @(); refused = $plan.refused; error = 'some changes were refused -- nothing was written' } }
    foreach ($f in $plan.files) {
        if (-not $Hashes.ContainsKey($f.key) -or [string]$Hashes[$f.key] -ne $f.hash) { return [pscustomobject]@{ written = @(); refused = @(); error = ('{0} changed since it was reviewed -- review again' -f $f.path) } }
    }
    $logDir = Join-Path $SIRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir 'settings-changes.log'
    $written = New-Object System.Collections.Generic.List[object]
    foreach ($f in $plan.files) {
        $backup = $null
        if ($f.action -eq 'remove') {
            if ((Get-SIFileHash -Path $f.FullPath) -ne $f.hash) { throw ('{0} changed since it was reviewed' -f $f.path) }
            $backup = '{0}.removed.{1}.bak' -f $f.FullPath, (Get-Date).ToString('yyyyMMdd-HHmmss')
            [System.IO.File]::Move($f.FullPath, $backup)
        } else {
            $dir = Split-Path -Parent $f.FullPath
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $w = Write-SISettingsFile -Path $f.FullPath -Text $f.NewText -ExpectedHash $f.hash -Bom $false
            $backup = $w.Backup
        }
        $line = [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); user = $User; file = $f.path; setting = $f.key; action = $f.action }
        [System.IO.File]::AppendAllText($log, (($line | ConvertTo-Json -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        $written.Add([pscustomobject]@{ key = $f.key; path = $f.path; backup = $backup })
    }
    [pscustomobject]@{ written = $written.ToArray(); refused = @(); error = $null }
}

function Invoke-SIRuleOverlayPlan {
    <#
        Setting up the rules folder outside the code tree: every in-tree *.custom.yaml moves there (same relative path),
        and SI_EnrichmentDataRoot is set in the solution's custom file. Returns the moves and the config diff.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Target)
    if (-not [System.IO.Path]::IsPathRooted($Target)) { throw 'the rules folder must be a full path' }
    $full = [System.IO.Path]::GetFullPath($Target)
    if ($full.StartsWith([System.IO.Path]::GetFullPath($SIRoot), [StringComparison]::OrdinalIgnoreCase)) { throw 'the rules folder must be outside the SecurityInsight folder -- an update replaces that folder' }
    $tree = Join-Path $SIRoot 'asset-profiling-enrichment'
    $moves = foreach ($f in @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter '*.custom.yaml' -ErrorAction SilentlyContinue)) {
        $rel = $f.FullName.Substring($tree.Length).TrimStart('\')
        [pscustomobject]@{ from = 'asset-profiling-enrichment\' + $rel; to = $rel; FromFull = $f.FullName; ToFull = (Join-Path $full $rel)
            exists = (Test-Path -LiteralPath (Join-Path $full $rel)); hash = (Get-SIFileHash -Path $f.FullName) }
    }
    $cfg = Join-Path $SIRoot 'config\SecurityInsight.custom.ps1'
    $r = Read-SISettingsText -Path $cfg
    $ed = Edit-SIPs1Settings -Text $r.Text -Changes @(@{ Name = 'SI_EnrichmentDataRoot'; Action = 'Set'; Value = $full })
    [pscustomobject]@{ target = $full; moves = @($moves); conflicts = @($moves | Where-Object exists | ForEach-Object to)
        configDiff = (Get-SITextDiff -Old $r.Text -New $ed.Text -Label 'config\SecurityInsight.custom.ps1'); configHash = (Get-SIFileHash -Path $cfg); refused = $ed.Refused
        ConfigText = $ed.Text; ConfigBom = $r.Bom; ConfigPath = $cfg }
}

function Invoke-SIRuleOverlayWrite {
    <# Copies each rule, checks the copy is byte-identical, then keeps the in-tree original as <file>.moved.<time>.bak (out of the loader's reach) and sets SI_EnrichmentDataRoot. #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$ConfigHash, [string]$User = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
    $p = Invoke-SIRuleOverlayPlan -SIRoot $SIRoot -Target $Target
    if (@($p.refused).Count) { return [pscustomobject]@{ moved = @(); error = ('SI_EnrichmentDataRoot is set by code in the config file -- set it there: {0}' -f $p.refused[0].Reason) } }
    if (@($p.conflicts).Count) { return [pscustomobject]@{ moved = @(); error = ('the rules folder already has: {0}' -f (@($p.conflicts) -join ', ')) } }
    if ($p.configHash -ne $ConfigHash) { return [pscustomobject]@{ moved = @(); error = 'config\SecurityInsight.custom.ps1 changed since it was reviewed -- review again' } }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $moved = New-Object System.Collections.Generic.List[object]
    foreach ($m in $p.moves) {
        $dir = Split-Path -Parent $m.ToFull
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::Copy($m.FromFull, $m.ToFull, $false)
        if ((Get-SIFileHash -Path $m.ToFull) -ne $m.hash) { throw ('the copy of {0} is not identical -- stopped; nothing else was moved' -f $m.from) }
        [System.IO.File]::Move($m.FromFull, ('{0}.moved.{1}.bak' -f $m.FromFull, $stamp))
        $moved.Add([pscustomobject]@{ from = $m.from; to = $m.to })
    }
    if (-not (Test-Path -LiteralPath $p.target)) { New-Item -ItemType Directory -Path $p.target -Force | Out-Null }
    $w = Write-SISettingsFile -Path $p.ConfigPath -Text $p.ConfigText -ExpectedHash $p.configHash -Bom $p.ConfigBom
    $log = Join-Path (Join-Path $SIRoot 'logs') 'settings-changes.log'
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $log))) { New-Item -ItemType Directory -Path (Split-Path -Parent $log) -Force | Out-Null }
    $line = [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); user = $User; file = 'config\SecurityInsight.custom.ps1'; setting = 'SI_EnrichmentDataRoot'; action = 'Set'; new = $p.target; movedRules = $moved.Count }
    [System.IO.File]::AppendAllText($log, (($line | ConvertTo-Json -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    [pscustomobject]@{ moved = $moved.ToArray(); target = $p.target; configBackup = $w.Backup; error = $null }
}
