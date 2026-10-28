#Requires -Version 5.1
<#
    ONE REPORT OF EVERY DEVIATION FROM THE SHIPPED DEFAULTS.

    "What have we switched off, changed or exempted -- and why, by whom, until when?" One row per deviation, the same
    columns in both editions:

        Kind  Item  Scope  ShippedDefault  Current  Reason  Owner  ChangedBy  ChangedAt  ExpiresAt  Status

    plus HistoryName / HistoryScope: the cfg.ChangeLog name and scope the row's history is recorded under (Pro).

    Kinds (in report order):
        Exemption          "exempt this finding" (cfg.Exemption). Revoked rows are not deviations any more and are left
                           out; an expired one is listed, flagged 'expired'.
        Exclusion          a Risk Analysis exclusion: one row per excluded CVE / configuration id / asset tag, plus
                           CveMinAgeDays (cfg.Document 'exclusions', or the *.exclude*.json files of a Community install).
        DisabledDetection  a tier rule or a Risk Analysis report that is turned off.
        TierMove           a whole rule moved to another tier (cfg.ItemOverride 'ruletier'), or a rule whose own
                           override sets different tiers than the shipped rule.
        ItemOverride       any other item that replaces or adds to the shipped configuration (a report, a rule, a
                           risk index row, an ownership entry, ...).
        RiskWeights        weighted risk factors set for an engine (none ship).
        Setting            a setting whose value differs from its SHIPPED default. A setting with no shipped default is
                           install configuration (a workspace, a mail address), not a deviation, and is left out; so is
                           a secret (its value is never read).

    Connector suppressions: the Pro schema has no table for them (cfg.Connector holds connector definitions, not
    suppressions), so there is nothing to report yet; a future table is added here.

    Status: 'expired' (ExpiresAt passed) | 'expiring' (within -ExpiringDays, default 30) | 'active'.

    Owner = who introduced the deviation (the first change since it was last reset), ChangedBy / ChangedAt = the latest
    change, Reason = the latest reason given. Without a change log they fall back to the row's own Updated/Created
    fields (Pro) or to the file's time (Community).

    PURE: Get-SIDeviationReport takes rows and returns rows -- no SQL, no files. Read-SICommunityDeviationInput is the
    one reader (the files of a Community / VM install). The Pro web app has a C# twin of Get-SIDeviationReport, and a
    shared fixture (tests\fixtures\deviation-report-cases.json) holds both to the same output.

    This file is part of the FREE payload: it loads nothing from the Pro paths. ASCII only (no BOM): PowerShell 5.1
    would read anything else as Windows-1252.
#>

$script:SIDevKindOrder = @('Exemption', 'Exclusion', 'DisabledDetection', 'TierMove', 'ItemOverride', 'RiskWeights', 'Setting')
$script:SIDevColumns = @('Kind', 'Item', 'Scope', 'ShippedDefault', 'Current', 'Reason', 'Owner', 'ChangedBy', 'ChangedAt', 'ExpiresAt', 'Status')
$script:SIDevDetectionKinds = @('rule', 'rareport')
$script:SIDevNone = '(none)'

function Get-SIDeviationColumns { $script:SIDevColumns }
function Get-SIDeviationKinds { $script:SIDevKindOrder }

# =====================================================================================================================
#  VALUES
# =====================================================================================================================
function Get-SIDevValue {
    <# PURE. A field of a row that may be a hashtable or an object; $null when absent (DBNull too). #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    return , $v     # a list comes back whole (a one-item list stays a list)
}

function ConvertFrom-SIDevJson {
    <# ConvertFrom-Json that keeps date-like strings as strings where the runtime allows it (pwsh 7.5+ -DateKind). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $script:SIDevJsonDateKind) { $script:SIDevJsonDateKind = (Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind') }
    # A list stays ONE value: pwsh 7 enumerates a top-level JSON array unless -NoEnumerate (5.1 never does), and the
    # unary comma below hands it back to the caller whole.
    if ($null -eq $script:SIDevJsonNoEnum) { $script:SIDevJsonNoEnum = (Get-Command ConvertFrom-Json).Parameters.ContainsKey('NoEnumerate') }
    $a = @{ ErrorAction = 'Stop' }
    if ($script:SIDevJsonDateKind) { $a['DateKind'] = 'String' }
    if ($script:SIDevJsonNoEnum) { $a['NoEnumerate'] = $true }
    $r = ($Text | ConvertFrom-Json @a)
    return , $r
}

function ConvertTo-SIDevJsonString {
    <# PURE. A string as a JSON literal (the same escaping as the Pro configuration layer and its C# twin). #>
    param([AllowEmptyString()][string]$Value)
    $sb = New-Object System.Text.StringBuilder ($Value.Length + 2)
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $c = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($c -eq 10) { [void]$sb.Append('\n') }
        elseif ($c -eq 13) { [void]$sb.Append('\r') }
        elseif ($c -eq 9) { [void]$sb.Append('\t') }
        elseif ($c -lt 32 -or ($c -ge 0x7F -and $c -le 0x9F) -or $c -eq 0x2028 -or $c -eq 0x2029 -or $c -eq 0xFEFF) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function ConvertTo-SIDevJson {
    <#
        PURE. A value as CANONICAL JSON: compact, object keys in ordinal order, a list always an array, a whole number
        without a fraction (25 and 25.0 are the same value), other numbers in round-trip form, invariant culture.
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [System.Numerics.BigInteger]) {
        return ([string]::Format($inv, '{0}', $Value))
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ($d -eq [Math]::Floor($d) -and [Math]::Abs($d) -lt 1e15) { return ([long]$d).ToString($inv) }
        return $d.ToString('R', $inv)
    }
    if ($Value -is [datetime]) { return (ConvertTo-SIDevJsonString $Value.ToString('o', $inv)) }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid]) { return (ConvertTo-SIDevJsonString ([string]$Value)) }
    $pairs = $null
    if ($Value -is [System.Collections.IDictionary]) { $pairs = @(foreach ($k in $Value.Keys) { , @([string]$k, $Value[$k]) }) }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) { $pairs = @(foreach ($p in $Value.PSObject.Properties) { , @($p.Name, $p.Value) }) }
    if ($null -ne $pairs) {
        if ($pairs.Count -eq 0) { return '{}' }
        $names = [string[]]@($pairs | ForEach-Object { $_[0] })
        $idx = [int[]](0..($pairs.Count - 1))
        [Array]::Sort($names, $idx, [System.StringComparer]::Ordinal)
        $items = foreach ($i in $idx) { (ConvertTo-SIDevJsonString $pairs[$i][0]) + ':' + (ConvertTo-SIDevJson -Value $pairs[$i][1]) }
        return ('{' + ($items -join ',') + '}')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = @($Value)
        if ($arr.Count -eq 0) { return '[]' }
        return ('[' + ((@(foreach ($v in $arr) { ConvertTo-SIDevJson -Value $v })) -join ',') + ']')
    }
    ConvertTo-SIDevJsonString ([string]$Value)
}

function Test-SIDevEmpty {
    <# PURE. Nothing set: $null, empty text or an empty list. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return ($Value.Length -eq 0) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [System.Collections.IDictionary]) { return (@($Value).Count -eq 0) }
    $false
}

function ConvertTo-SIDevDisplay {
    <# PURE. A value as the report shows it: '(none)' when empty, else its canonical JSON. #>
    param([AllowNull()]$Value)
    if (Test-SIDevEmpty $Value) { return $script:SIDevNone }
    ConvertTo-SIDevJson -Value $Value
}

function ConvertTo-SIDevUtc {
    <# PURE. A SQL datetime2 (UTC, read back with Kind Unspecified), a DateTime or an ISO text -> a UTC DateTime; $null stays $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull] -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

function ConvertTo-SIDevUtcText {
    <# PURE. A time as 'yyyy-MM-ddTHH:mm:ssZ' (UTC), or $null. #>
    param([AllowNull()]$Value)
    $d = ConvertTo-SIDevUtc $Value
    if ($null -eq $d) { return $null }
    $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-SIDeviationStatus {
    <# PURE. 'expired' | 'expiring' (within -ExpiringDays) | 'active' (no expiry, or further away). #>
    param([AllowNull()]$ExpiresAt, [Parameter(Mandatory)][datetime]$Now, [int]$ExpiringDays = 30)
    $e = ConvertTo-SIDevUtc $ExpiresAt
    if ($null -eq $e) { return 'active' }
    $n = ConvertTo-SIDevUtc $Now
    if ($e -le $n) { return 'expired' }
    if ($e -le $n.AddDays($ExpiringDays)) { return 'expiring' }
    'active'
}

# =====================================================================================================================
#  RULES -- read from the text, no YAML round trip
# =====================================================================================================================
function Get-SIDevRuleFacts {
    <# PURE. A tier rule's tiers (distinct, ascending) and whether it is turned off ('mode: disable'). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $t = [string]$Text
    $tiers = @([regex]::Matches($t, '(?mi)^\s*Tier\s*:\s*(\d+)') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
    [pscustomobject]@{ Tiers = [int[]]$tiers; Disabled = [regex]::IsMatch($t, '(?mi)^mode\s*:\s*disable\b') }
}

function Format-SIDevTiers {
    <# PURE. 'tier 1' | 'tier 0, 2' | '(no tier)'. #>
    param([AllowEmptyCollection()][int[]]$Tiers = @())
    if (@($Tiers).Count -eq 0) { return '(no tier)' }
    'tier ' + ((@($Tiers) | ForEach-Object { [string]$_ }) -join ', ')
}

function Get-SIDevRuleClass {
    <#
        PURE. What a customer's rule body is, compared with the shipped rule it replaces:
          turned off                          -> DisabledDetection
          shipped rule exists, tiers differ   -> TierMove
          shipped rule exists                 -> ItemOverride 'overridden'
          no shipped rule                     -> ItemOverride 'added'
        -ShippedLabel names the shipped side ('template <version>' in Pro, 'shipped rule' in Community).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Body, [AllowNull()][string]$ShippedBody, [string]$ShippedLabel = 'shipped rule')
    $has = -not [string]::IsNullOrEmpty($ShippedBody)
    $f = Get-SIDevRuleFacts -Text $Body
    if ($f.Disabled) {
        return [pscustomobject]@{ Kind = 'DisabledDetection'; Shipped = $(if ($has) { 'on' } else { $script:SIDevNone }); Current = 'turned off' }
    }
    if ($has) {
        $s = Get-SIDevRuleFacts -Text $ShippedBody
        if ((Format-SIDevTiers $s.Tiers) -cne (Format-SIDevTiers $f.Tiers)) {
            return [pscustomobject]@{ Kind = 'TierMove'; Shipped = (Format-SIDevTiers $s.Tiers); Current = (Format-SIDevTiers $f.Tiers) }
        }
        return [pscustomobject]@{ Kind = 'ItemOverride'; Shipped = $ShippedLabel; Current = 'overridden' }
    }
    [pscustomobject]@{ Kind = 'ItemOverride'; Shipped = $script:SIDevNone; Current = 'added' }
}

# =====================================================================================================================
#  HISTORY
# =====================================================================================================================
function Get-SIDevHistoryKey {
    param([AllowNull()][string]$Scope, [AllowNull()][string]$Kind, [AllowNull()][string]$Name)
    ('{0}|{1}|{2}' -f [string]$Scope, [string]$Kind, [string]$Name).ToLowerInvariant()
}

function Get-SIDevHistoryIndex {
    <#
        PURE. cfg.ChangeLog rows -> per (Scope, Kind, Name): Owner (who made the first change since the last Reset),
        ChangedBy / ChangedAt (the latest change) and Reason (the latest reason given since the last Reset).
        Ordered by ChangeId (else ChangedAt), so the same rows always give the same answer.
    #>
    param([AllowEmptyCollection()][object[]]$ChangeLog = @())
    $groups = @{}
    foreach ($r in @($ChangeLog | Where-Object { $_ })) {
        $k = Get-SIDevHistoryKey -Scope (Get-SIDevValue $r 'Scope') -Kind (Get-SIDevValue $r 'Kind') -Name (Get-SIDevValue $r 'Name')
        if (-not $groups.ContainsKey($k)) { $groups[$k] = New-Object System.Collections.Generic.List[object] }
        $groups[$k].Add($r)
    }
    $index = @{}
    foreach ($k in @($groups.Keys)) {
        $rows = $groups[$k].ToArray()
        $sortKeys = @($rows | ForEach-Object {
            $id = 0L; [void][long]::TryParse([string](Get-SIDevValue $_ 'ChangeId'), [ref]$id)
            $at = ConvertTo-SIDevUtcText (Get-SIDevValue $_ 'ChangedAt'); if (-not $at) { $at = '' }
            '{0:D20}|{1}' -f $id, $at
        })
        $names = [string[]]$sortKeys; $idx = [int[]](0..($rows.Count - 1))
        [Array]::Sort($names, $idx, [System.StringComparer]::Ordinal)
        $owner = $null; $reason = $null; $by = $null; $at = $null
        foreach ($i in $idx) {
            $r = $rows[$i]
            $action = [string](Get-SIDevValue $r 'Action')
            $who = [string](Get-SIDevValue $r 'ChangedBy')
            if ($action -eq 'Reset') { $owner = $null; $reason = $null }
            elseif ($null -eq $owner -and $who) { $owner = $who }
            $why = [string](Get-SIDevValue $r 'Reason')
            if ($action -ne 'Reset' -and -not [string]::IsNullOrWhiteSpace($why)) { $reason = $why }
            $by = $who; $at = ConvertTo-SIDevUtcText (Get-SIDevValue $r 'ChangedAt')
        }
        $index[$k] = [pscustomobject]@{ Owner = $owner; ChangedBy = $by; ChangedAt = $at; Reason = $reason }
    }
    $index
}

function New-SIDeviationRow {
    <# One report row. History (from Get-SIDevHistoryIndex) wins; the Fallback* values fill what it does not have. #>
    param([string]$Kind, [string]$Item, [string]$Scope, [string]$ShippedDefault, [string]$Current, [string]$Reason,
          $History, [string]$FallbackOwner, [string]$FallbackBy, $FallbackAt, $ExpiresAt, [datetime]$Now, [int]$ExpiringDays = 30,
          [string]$HistoryName, [string]$HistoryScope)
    $owner = $FallbackOwner; $by = $FallbackBy; $at = ConvertTo-SIDevUtcText $FallbackAt; $why = $Reason
    if ($History) {
        if ($History.Owner) { $owner = $History.Owner }
        if ($History.ChangedBy) { $by = $History.ChangedBy }
        if ($History.ChangedAt) { $at = $History.ChangedAt }
        if ([string]::IsNullOrEmpty($why) -and $History.Reason) { $why = $History.Reason }
    }
    [pscustomobject][ordered]@{
        Kind = $Kind; Item = $Item; Scope = [string]$Scope; ShippedDefault = [string]$ShippedDefault; Current = [string]$Current
        Reason = [string]$why; Owner = [string]$owner; ChangedBy = [string]$by; ChangedAt = $at
        ExpiresAt = (ConvertTo-SIDevUtcText $ExpiresAt); Status = (Get-SIDeviationStatus -ExpiresAt $ExpiresAt -Now $Now -ExpiringDays $ExpiringDays)
        HistoryName = [string]$HistoryName; HistoryScope = [string]$HistoryScope
    }
}

# =====================================================================================================================
#  DOCUMENT BODIES shared by both editions
# =====================================================================================================================
function Get-SIDevExclusionEntries {
    <#
        PURE. An exclusion body (JSON text) -> one entry per excluded value: @{ Item; Shipped; Current }. Lists
        (ExcludedCves, ExcludedConfigurationIds, ExcludedAssetTags) give one entry per value; CveMinAgeDays (shipped 0)
        and any other single value give one entry. Notes ('_'-prefixed, Comment, $schema) are not exclusions.
        A body that does not parse gives one '(unreadable)' entry -- a broken file is itself worth seeing.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Body)
    $o = $null
    try { $o = ConvertFrom-SIDevJson ([string]$Body).TrimStart([char]0xFEFF) } catch { $o = $null }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return @([pscustomobject]@{ Item = '(unreadable)'; Shipped = $script:SIDevNone; Current = 'not a valid JSON object' }) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $o.PSObject.Properties) {
        if ($p.Name.StartsWith('_') -or $p.Name -eq 'Comment' -or $p.Name -eq '$schema') { continue }
        $v = $p.Value
        if ($null -ne $v -and $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            foreach ($x in @($v)) {
                if ($null -eq $x -or [string]$x -eq '') { continue }
                $text = if ($x -is [string]) { $x } else { ConvertTo-SIDevJson $x }
                $out.Add([pscustomobject]@{ Item = ('{0}: {1}' -f $p.Name, $text); Shipped = 'not excluded'; Current = 'excluded' })
            }
            continue
        }
        if (Test-SIDevEmpty $v) { continue }
        $shipped = if ($p.Name -eq 'CveMinAgeDays') { '0' } else { $script:SIDevNone }
        $cur = ConvertTo-SIDevJson $v
        if ($cur -ceq $shipped) { continue }
        $out.Add([pscustomobject]@{ Item = $p.Name; Shipped = $shipped; Current = $cur })
    }
    $out.ToArray()
}

function Get-SIDevWeightEntries {
    <# PURE. A weights body -> one entry per engine under weightedRiskFactors: @{ Item; Current = '<n> weighted field(s)' }. #>
    param([AllowEmptyString()][AllowNull()][string]$Body)
    $o = $null
    try { $o = ConvertFrom-SIDevJson ([string]$Body).TrimStart([char]0xFEFF) } catch { $o = $null }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return @([pscustomobject]@{ Item = '(unreadable)'; Current = 'not a valid JSON object' }) }
    $w = $o.PSObject.Properties['weightedRiskFactors']
    if (-not $w -or $w.Value -isnot [System.Management.Automation.PSCustomObject]) { return @() }
    @(foreach ($e in $w.Value.PSObject.Properties) {
        if ($e.Name.StartsWith('_') -or $e.Name -eq 'Comment' -or $null -eq $e.Value) { continue }
        $n = 0
        if ($e.Value -is [System.Management.Automation.PSCustomObject] -and $e.Value.PSObject.Properties['fields']) { $n = @($e.Value.fields | Where-Object { $null -ne $_ }).Count }
        [pscustomobject]@{ Item = ('weightedRiskFactors/{0}' -f $e.Name); Current = ('{0} weighted field(s)' -f $n) }
    })
}

function Get-SIDevExemptionItem {
    <# PURE. What an exemption covers, in the management GUI's words. #>
    param($Row)
    $what = [string](Get-SIDevValue $Row 'Cve'); if (-not $what) { $what = [string](Get-SIDevValue $Row 'ConfigurationId') }
    $asset = [string](Get-SIDevValue $Row 'AssetKey')
    switch ([string](Get-SIDevValue $Row 'Scope')) {
        'asset' { return ('every finding on {0}' -f $asset) }
        'issue' { return ('{0} on every asset' -f $what) }
        default { return ('{0} on {1}' -f $what, $asset) }
    }
}

# =====================================================================================================================
#  THE REPORT
# =====================================================================================================================
function Get-SIDeviationReport {
    <#
        PURE. Every deviation from the shipped defaults, one row each, in report order (kind, then scope, then item --
        ordinal).

        Pro (the settings database, sql\si-pro-settings.sql -- pass what was read; a missing table = no rows):
          -Settings   cfg.Setting    (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedAt, UpdatedBy)
          -Catalog    the settings catalog's settings (name, secret, default) -- a setting's SHIPPED default
          -Documents  cfg.Document   (Kind, DocKey, Body, UpdatedAt, UpdatedBy)
          -Templates  cfg.Template   (Kind, ItemKey, TemplateVersion, BodyJson)
          -Overrides  cfg.ItemOverride (Kind, ItemKey, State, BodyJson, UpdatedAt, UpdatedBy)
          -Exemptions cfg.Exemption  (ExemptionId, Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt,
                                      CreatedBy, CreatedAt, RevokedAt)
          -ChangeLog  cfg.ChangeLog  (ChangeId, Name, Scope, Kind, Action, ChangedAt, ChangedBy, Reason)
        Community / VM (the custom files):
          -Community  Read-SICommunityDeviationInput's result.
        -Now is a seam (UTC); -ExpiringDays sets the 'expiring' window.
    #>
    param([AllowEmptyCollection()][object[]]$Settings = @(), [AllowEmptyCollection()][object[]]$Catalog = @(),
          [AllowEmptyCollection()][object[]]$Documents = @(), [AllowEmptyCollection()][object[]]$Templates = @(),
          [AllowEmptyCollection()][object[]]$Overrides = @(), [AllowEmptyCollection()][object[]]$Exemptions = @(),
          [AllowEmptyCollection()][object[]]$ChangeLog = @(), $Community,
          [datetime]$Now = ([datetime]::UtcNow), [int]$ExpiringDays = 30)
    $rows = New-Object System.Collections.Generic.List[object]
    $hist = Get-SIDevHistoryIndex -ChangeLog @($ChangeLog)
    $histOf = { param($scope, $kind, $name) $hist[(Get-SIDevHistoryKey -Scope $scope -Kind $kind -Name $name)] }
    $common = @{ Now = $Now; ExpiringDays = $ExpiringDays }

    # ---- templates by kind/key (rule bodies and versions) ----
    $tpl = @{}
    foreach ($t in @($Templates | Where-Object { $_ })) {
        $tpl[('{0}/{1}' -f (Get-SIDevValue $t 'Kind'), (Get-SIDevValue $t 'ItemKey')).ToLowerInvariant()] = $t
    }
    $tplLabel = { param($t) ('template ' + [string](Get-SIDevValue $t 'TemplateVersion')).Trim() }

    # ---- settings: a value that differs from a KNOWN shipped default ----
    $cat = @{}; foreach ($s in @($Catalog | Where-Object { $_ })) { $cat[[string](Get-SIDevValue $s 'name')] = $s }
    foreach ($r in @($Settings | Where-Object { $_ })) {
        $name = [string](Get-SIDevValue $r 'Name'); $scope = [string](Get-SIDevValue $r 'Scope')
        if (-not [string]::IsNullOrEmpty([string](Get-SIDevValue $r 'KeyVaultSecretName'))) { continue }
        $s = $cat[$name]
        if (-not $s -or [bool](Get-SIDevValue $s 'secret')) { continue }
        $def = Get-SIDevValue $s 'default'
        if ($null -eq $def) { continue }
        $vj = Get-SIDevValue $r 'ValueJson'
        $val = $null
        if ($null -ne $vj) { try { $val = ConvertFrom-SIDevJson ([string]$vj) } catch { $val = [string]$vj } }
        $shipped = ConvertTo-SIDevDisplay $def; $cur = ConvertTo-SIDevDisplay $val
        if ($shipped -ceq $cur) { continue }
        $by = [string](Get-SIDevValue $r 'UpdatedBy')
        $rows.Add((New-SIDeviationRow @common -Kind 'Setting' -Item $name -Scope $scope -ShippedDefault $shipped -Current $cur `
            -History (& $histOf $scope '' $name) -FallbackOwner $by -FallbackBy $by -FallbackAt (Get-SIDevValue $r 'UpdatedAt') -HistoryName $name -HistoryScope $scope))
    }

    # ---- documents: exclusions, weights, the customer's own tier rules ----
    foreach ($d in @($Documents | Where-Object { $_ })) {
        $kind = [string](Get-SIDevValue $d 'Kind'); $key = [string](Get-SIDevValue $d 'DocKey'); if (-not $key) { $key = [string](Get-SIDevValue $d 'Key') }
        $body = [string](Get-SIDevValue $d 'Body')
        $by = [string](Get-SIDevValue $d 'UpdatedBy'); $at = Get-SIDevValue $d 'UpdatedAt'
        $h = & $histOf 'document' $kind $key
        $base = @{ History = $h; FallbackOwner = $by; FallbackBy = $by; FallbackAt = $at; HistoryName = $key; HistoryScope = 'document' }
        switch ($kind) {
            'exclusions' {
                foreach ($e in @(Get-SIDevExclusionEntries -Body $body)) {
                    $rows.Add((New-SIDeviationRow @common @base -Kind 'Exclusion' -Item $e.Item -Scope $key -ShippedDefault $e.Shipped -Current $e.Current))
                }
            }
            'weights' {
                foreach ($e in @(Get-SIDevWeightEntries -Body $body)) {
                    $rows.Add((New-SIDeviationRow @common @base -Kind 'RiskWeights' -Item $e.Item -Scope $key -ShippedDefault $script:SIDevNone -Current $e.Current))
                }
            }
            'rule' {
                $t = $tpl[('rule/' + $key).ToLowerInvariant()]
                $c = Get-SIDevRuleClass -Body $body -ShippedBody ([string](Get-SIDevValue $t 'BodyJson')) -ShippedLabel $(if ($t) { & $tplLabel $t } else { '' })
                $rows.Add((New-SIDeviationRow @common @base -Kind $c.Kind -Item $key -Scope 'rule' -ShippedDefault $c.Shipped -Current $c.Current))
            }
        }
    }

    # ---- item overrides: disabled items, tier moves, overridden and added items ----
    foreach ($o in @($Overrides | Where-Object { $_ })) {
        $kind = [string](Get-SIDevValue $o 'Kind'); $key = [string](Get-SIDevValue $o 'ItemKey'); $state = [string](Get-SIDevValue $o 'State')
        if ($state -ne 'override' -and $state -ne 'disable') { continue }      # inherit = follows the vendor: no deviation
        $body = [string](Get-SIDevValue $o 'BodyJson')
        $by = [string](Get-SIDevValue $o 'UpdatedBy')
        $base = @{ History = (& $histOf 'item' $kind $key); FallbackOwner = $by; FallbackBy = $by; FallbackAt = (Get-SIDevValue $o 'UpdatedAt'); HistoryName = $key; HistoryScope = 'item' }
        if ($kind -eq 'ruletier') {
            if ($state -ne 'override') { continue }
            $t = $tpl[('rule/' + $key).ToLowerInvariant()]
            $shipped = if ($t) { Format-SIDevTiers (Get-SIDevRuleFacts -Text ([string](Get-SIDevValue $t 'BodyJson'))).Tiers } else { "(the rule's own tiers)" }
            $tier = $null
            try { $b = ConvertFrom-SIDevJson $body; if ($b -is [System.Management.Automation.PSCustomObject] -and $b.PSObject.Properties['tier']) { $tier = [string]$b.tier } } catch { $tier = $null }
            $cur = if ($null -ne $tier -and $tier -ne '') { 'tier ' + $tier } else { 'tier ?' }
            $rows.Add((New-SIDeviationRow @common @base -Kind 'TierMove' -Item $key -Scope 'ruletier' -ShippedDefault $shipped -Current $cur))
            continue
        }
        $t = $tpl[('{0}/{1}' -f $kind, $key).ToLowerInvariant()]
        if ($state -eq 'disable') {
            $k = if ($script:SIDevDetectionKinds -contains $kind) { 'DisabledDetection' } else { 'ItemOverride' }
            $rows.Add((New-SIDeviationRow @common @base -Kind $k -Item $key -Scope $kind -ShippedDefault $(if ($t) { 'on' } else { $script:SIDevNone }) -Current 'turned off'))
            continue
        }
        if ($kind -eq 'rule') {
            $c = Get-SIDevRuleClass -Body $body -ShippedBody ([string](Get-SIDevValue $t 'BodyJson')) -ShippedLabel $(if ($t) { & $tplLabel $t } else { '' })
            $rows.Add((New-SIDeviationRow @common @base -Kind $c.Kind -Item $key -Scope 'rule' -ShippedDefault $c.Shipped -Current $c.Current))
            continue
        }
        $rows.Add((New-SIDeviationRow @common @base -Kind 'ItemOverride' -Item $key -Scope $kind `
            -ShippedDefault $(if ($t) { & $tplLabel $t } else { $script:SIDevNone }) -Current $(if ($t) { 'overridden' } else { 'added' })))
    }

    # ---- exemptions: every one not revoked (an expired one is flagged, not hidden) ----
    foreach ($e in @($Exemptions | Where-Object { $_ })) {
        if ($null -ne (Get-SIDevValue $e 'RevokedAt') -and [string](Get-SIDevValue $e 'RevokedAt') -ne '') { continue }
        $id = [string](Get-SIDevValue $e 'ExemptionId'); $hn = 'exemption/' + $id
        $rep = [string](Get-SIDevValue $e 'ReportName'); if (-not $rep) { $rep = 'every report' }
        $by = [string](Get-SIDevValue $e 'CreatedBy')
        $rows.Add((New-SIDeviationRow @common -Kind 'Exemption' -Item (Get-SIDevExemptionItem $e) -Scope $rep -ShippedDefault 'not exempt' `
            -Current ('exempt ({0})' -f (Get-SIDevValue $e 'Scope')) -Reason ([string](Get-SIDevValue $e 'Reason')) -History (& $histOf 'exemption' 'exemption' $hn) `
            -FallbackOwner $by -FallbackBy $by -FallbackAt (Get-SIDevValue $e 'CreatedAt') -ExpiresAt (Get-SIDevValue $e 'ExpiresAt') -HistoryName $hn -HistoryScope 'exemption'))
    }

    # ---- Community / VM: the custom files against the shipped ones ----
    if ($Community) { foreach ($r in @(Get-SIDevCommunityRows -Data $Community @common)) { $rows.Add($r) } }

    $all = $rows.ToArray()
    if ($all.Count -eq 0) { return @() }
    $us = [string][char]1
    $keys = @($all | ForEach-Object { '{0:D2}{1}{2}{1}{3}' -f [Array]::IndexOf($script:SIDevKindOrder, $_.Kind), $us, $_.Scope, $_.Item })
    $ks = [string[]]$keys; $idx = [int[]](0..($all.Count - 1))
    [Array]::Sort($ks, $idx, [System.StringComparer]::Ordinal)
    @(foreach ($i in $idx) { $all[$i] })
}

# =====================================================================================================================
#  COMMUNITY / VM -- rows from the custom files (pure over what Read-SICommunityDeviationInput read)
# =====================================================================================================================
function Get-SIDevFileHistory {
    <# PURE. The settings page's log lines for one file (and, when given, one setting) -> Owner / ChangedBy / ChangedAt. #>
    param([AllowEmptyCollection()][object[]]$Log = @(), [string]$File, [string]$Setting)
    $norm = { param($p) ([string]$p).Replace('/', '\').TrimStart('\').ToLowerInvariant() }
    $f = & $norm $File
    $mine = @($Log | Where-Object { $_ -and (& $norm (Get-SIDevValue $_ 'file')) -eq $f -and (-not $Setting -or [string](Get-SIDevValue $_ 'setting') -eq $Setting) })
    if ($mine.Count -eq 0) { return $null }
    $rows = @(for ($i = 0; $i -lt $mine.Count; $i++) {
        [pscustomobject]@{ ChangeId = $i + 1; Name = 'x'; Scope = 'x'; Kind = ''; Action = $(if ([string](Get-SIDevValue $mine[$i] 'action') -eq 'Reset') { 'Reset' } else { 'Set' })
            ChangedBy = [string](Get-SIDevValue $mine[$i] 'user'); ChangedAt = (Get-SIDevValue $mine[$i] 'time'); Reason = $null }
    })
    (Get-SIDevHistoryIndex -ChangeLog $rows)[(Get-SIDevHistoryKey -Scope 'x' -Kind '' -Name 'x')]
}

function Get-SIDevCommunityRows {
    param([Parameter(Mandatory)]$Data, [datetime]$Now = ([datetime]::UtcNow), [int]$ExpiringDays = 30)
    $c = $Data
    $log = Get-SIDevValue $c 'Log'; if ($null -eq $log) { $log = @() }
    $times = Get-SIDevValue $c 'FileTimes'; if (-not $times) { $times = @{} }
    $common = @{ Now = $Now; ExpiringDays = $ExpiringDays }
    $at = { param($file) if ($times.ContainsKey([string]$file)) { $times[[string]$file] } else { $null } }
    $out = New-Object System.Collections.Generic.List[object]

    $list = Get-SIDevValue $c 'Settings'
    foreach ($s in @($list)) {
        if (-not $s -or -not [bool](Get-SIDevValue $s 'HasDefault') -or [bool](Get-SIDevValue $s 'Secret')) { continue }
        $shipped = ConvertTo-SIDevDisplay (Get-SIDevValue $s 'Default')
        $cur = if ([bool](Get-SIDevValue $s 'Literal')) { ConvertTo-SIDevDisplay (Get-SIDevValue $s 'Value') } else { '(set by code)' }
        if ($shipped -ceq $cur) { continue }
        $name = [string](Get-SIDevValue $s 'Name'); $file = [string](Get-SIDevValue $s 'File')
        $out.Add((New-SIDeviationRow @common -Kind 'Setting' -Item $name -Scope ([string](Get-SIDevValue $s 'Scope')) -ShippedDefault $shipped -Current $cur `
            -History (Get-SIDevFileHistory -Log $log -File $file -Setting $name) -FallbackAt (& $at $file) -HistoryName $name -HistoryScope $file))
    }
    $list = Get-SIDevValue $c 'Exclusions'
    foreach ($x in @($list)) {
        if (-not $x) { continue }
        $file = [string](Get-SIDevValue $x 'File'); $key = [string](Get-SIDevValue $x 'Key')
        foreach ($e in @(Get-SIDevExclusionEntries -Body ([string](Get-SIDevValue $x 'Body')))) {
            $out.Add((New-SIDeviationRow @common -Kind 'Exclusion' -Item $e.Item -Scope $key -ShippedDefault $e.Shipped -Current $e.Current `
                -History (Get-SIDevFileHistory -Log $log -File $file) -FallbackAt (& $at $file) -HistoryName $file -HistoryScope $file))
        }
    }
    $w = Get-SIDevValue $c 'Weights'
    if ($w) {
        $file = [string](Get-SIDevValue $w 'File')
        foreach ($e in @(Get-SIDevWeightEntries -Body ([string](Get-SIDevValue $w 'Body')))) {
            $out.Add((New-SIDeviationRow @common -Kind 'RiskWeights' -Item $e.Item -Scope 'solution' -ShippedDefault $script:SIDevNone -Current $e.Current `
                -History (Get-SIDevFileHistory -Log $log -File $file) -FallbackAt (& $at $file) -HistoryName $file -HistoryScope $file))
        }
    }
    $list = Get-SIDevValue $c 'Rules'
    foreach ($r in @($list)) {
        if (-not $r) { continue }
        $file = [string](Get-SIDevValue $r 'File')
        $cl = Get-SIDevRuleClass -Body ([string](Get-SIDevValue $r 'CustomText')) -ShippedBody ([string](Get-SIDevValue $r 'LockedText')) -ShippedLabel 'shipped rule'
        $item = '{0}/{1}' -f (Get-SIDevValue $r 'Engine'), (Get-SIDevValue $r 'Id')
        $out.Add((New-SIDeviationRow @common -Kind $cl.Kind -Item $item -Scope 'rule' -ShippedDefault $cl.Shipped -Current $cl.Current `
            -History (Get-SIDevFileHistory -Log $log -File $file) -FallbackAt (& $at $file) -HistoryName $file -HistoryScope $file))
    }
    $list = Get-SIDevValue $c 'CustomReports'
    foreach ($r in @($list)) {
        if (-not $r) { continue }
        $file = [string](Get-SIDevValue $r 'File'); $rep = [bool](Get-SIDevValue $r 'Replaces')
        $out.Add((New-SIDeviationRow @common -Kind 'ItemOverride' -Item ('report/{0}' -f (Get-SIDevValue $r 'Name')) -Scope 'rareport' `
            -ShippedDefault $(if ($rep) { 'shipped report' } else { $script:SIDevNone }) -Current $(if ($rep) { 'overridden' } else { 'added' }) `
            -FallbackAt (& $at $file) -HistoryName $file -HistoryScope $file))
    }
    $out.ToArray()
}

# =====================================================================================================================
#  COMMUNITY / VM -- THE READER (files only; nothing is written)
# =====================================================================================================================
function Get-SIDevAssignments {
    <#
        PURE. Every `$global:Name = ...` assignment of a PowerShell text: Name, TopLevel (not inside an if / function /
        loop), Literal (a plain value -- text, number, $true/$false/$null, or a list of those) and Value (when literal).
        The text is parsed, never run.
    #>
    param([AllowEmptyString()][string]$Text)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$Text, [ref]$tokens, [ref]$errors)
    $found = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -match '^global:[A-Za-z_][A-Za-z0-9_]*$'
    }, $true)
    foreach ($a in $found) {
        $p = $a.Parent; $top = $true
        while ($p -and -not ($p -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -eq $p.Parent)) {
            if ($p -isnot [System.Management.Automation.Language.NamedBlockAst] -and $p -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $top = $false; break }
            $p = $p.Parent
        }
        $expr = $null; $right = $a.Right
        if ($right -is [System.Management.Automation.Language.PipelineAst] -and $right.PipelineElements.Count -eq 1 -and
            $right.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $right.PipelineElements[0].Expression }
        elseif ($right -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $right.Expression }
        $literal = $false; $value = $null
        if ($expr -and $a.Operator -eq [System.Management.Automation.Language.TokenKind]::Equals) {
            $bad = @($expr.FindAll({ param($n)
                ($n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -notin 'true', 'false', 'null') -or
                $n -is [System.Management.Automation.Language.CommandAst] -or $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                $n -is [System.Management.Automation.Language.SubExpressionAst] -or $n -is [System.Management.Automation.Language.HashtableAst] -or
                $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)).Count -gt 0
            if (-not $bad) { try { $value = $expr.SafeGetValue(); $literal = $true } catch { $literal = $false } }
        }
        [pscustomobject]@{ Name = ($a.Left.VariablePath.UserPath -replace '^global:', ''); TopLevel = $top; Literal = $literal; Value = $value }
    }
}

function Get-SIDevLayerValues {
    <# A settings file -> name -> @{ Literal; Value } (the last assignment wins; any assignment by code makes it code). #>
    param([string]$Path)
    $map = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $map }
    $text = [System.IO.File]::ReadAllText($Path)
    foreach ($a in @(Get-SIDevAssignments -Text $text)) {
        $code = -not ($a.Literal -and $a.TopLevel)
        if ($map.ContainsKey($a.Name) -and -not $map[$a.Name].Literal) { continue }
        $map[$a.Name] = [pscustomobject]@{ Literal = (-not $code); Value = $(if ($code) { $null } else { $a.Value }) }
    }
    $map
}

$script:SIDevSecretName = '(?i)(secret|password|passwd|pwd|api_?key|token|connectionstring|accountkey|thumbprint|sas)'

function Read-SICommunityDeviationInput {
    <#
        Reads a Community / VM install's custom files and the shipped files they deviate from. Nothing is written.
          settings     config\SecurityInsight.custom.ps1 and launcher\<engine>\LauncherConfig.custom.ps1, against the
                       shipped defaults (launcher\_lib\SecurityInsight.shared-defaults.ps1 and each engine's
                       LauncherConfig.defaults.ps1) -- or a settings catalog, when -CatalogPath names one. A secret
                       (by the catalog, else by its name) is never read into the report.
          exclusions   <SettingsPath>\RiskAnalysisGlobalExclusions.custom.json, <Report>.exclude.custom.json (and a
                       report's <Report>.exclude.json when it has no custom file -- the engine reads it then).
          weights      <SettingsPath>\riskscore_weighted.schema.custom.json
          rules        asset-profiling-enrichment\**\<id>.custom.yaml against <id>.locked.yaml (and the overlay folder,
                       -OverlayRoot, whose rule wins).
          reports      RiskAnalysis_Queries_Custom.yaml (SettingsPath, or its custom\ folder) against the locked catalog.
          history      logs\settings-changes.log (the Settings page's change log), else each file's last write time.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$SettingsPath, [string]$OverlayRoot, [string]$CatalogPath)
    if (-not $SettingsPath) { $SettingsPath = Join-Path $SIRoot 'risk-analysis-detection' }
    $times = @{}
    $rel = { param($full) $r = $full; if ($full.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $r = $full.Substring($SIRoot.Length).TrimStart('\', '/') }; $r.Replace('/', '\') }
    $touch = { param($full) $k = & $rel $full; $times[$k] = [System.IO.File]::GetLastWriteTimeUtc($full); $k }

    # ---- settings ----
    $catalog = @{}
    if ($CatalogPath -and (Test-Path -LiteralPath $CatalogPath)) {
        foreach ($s in @((Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json).settings)) { $catalog[[string]$s.name] = $s }
    }
    $launcher = Join-Path $SIRoot 'launcher'
    $shared = Get-SIDevLayerValues -Path (Join-Path (Join-Path $launcher '_lib') 'SecurityInsight.shared-defaults.ps1')
    $engineDefaults = [ordered]@{}
    foreach ($d in @(Get-ChildItem -LiteralPath $launcher -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        if ($d.Name -eq '_lib') { continue }
        $engineDefaults[$d.Name] = Get-SIDevLayerValues -Path (Join-Path $d.FullName 'LauncherConfig.defaults.ps1')
    }
    $defaultOf = {
        param([string]$name, [string]$engine)
        $cs = $catalog[$name]
        if ($cs -and $null -ne $cs.default) { return [pscustomobject]@{ Has = $true; Value = $cs.default } }
        if ($engine -and $engineDefaults.Contains($engine) -and $engineDefaults[$engine].ContainsKey($name) -and $engineDefaults[$engine][$name].Literal) {
            return [pscustomobject]@{ Has = $true; Value = $engineDefaults[$engine][$name].Value }
        }
        if ($shared.ContainsKey($name) -and $shared[$name].Literal) { return [pscustomobject]@{ Has = $true; Value = $shared[$name].Value } }
        if (-not $engine) {
            # a solution-wide value against the engine defaults: a default only when every engine that has one agrees
            $vals = @(foreach ($e in $engineDefaults.Keys) { if ($engineDefaults[$e].ContainsKey($name) -and $engineDefaults[$e][$name].Literal) { ConvertTo-SIDevDisplay $engineDefaults[$e][$name].Value } })
            $distinct = @($vals | Sort-Object -Unique)
            if ($distinct.Count -eq 1) {
                foreach ($e in $engineDefaults.Keys) { if ($engineDefaults[$e].ContainsKey($name)) { return [pscustomobject]@{ Has = $true; Value = $engineDefaults[$e][$name].Value } } }
            }
        }
        [pscustomobject]@{ Has = $false; Value = $null }
    }
    $settings = New-Object System.Collections.Generic.List[object]
    $customs = @(@{ Scope = 'solution'; Engine = ''; Path = (Join-Path (Join-Path $SIRoot 'config') 'SecurityInsight.custom.ps1') })
    foreach ($e in $engineDefaults.Keys) { $customs += @{ Scope = ('engine:' + $e); Engine = $e; Path = (Join-Path (Join-Path $launcher $e) 'LauncherConfig.custom.ps1') } }
    foreach ($cf in $customs) {
        if (-not (Test-Path -LiteralPath $cf.Path)) { continue }
        $file = & $touch $cf.Path
        $vals = Get-SIDevLayerValues -Path $cf.Path
        foreach ($n in @($vals.Keys | Sort-Object)) {
            $cs = $catalog[$n]
            $secret = if ($cs) { [bool]$cs.secret } else { $n -match $script:SIDevSecretName }
            $def = & $defaultOf $n $cf.Engine
            $settings.Add([pscustomobject]@{ Name = $n; Scope = $cf.Scope; File = $file; Literal = $vals[$n].Literal
                Value = $(if ($secret) { $null } else { $vals[$n].Value }); HasDefault = $def.Has; Default = $def.Value; Secret = $secret })
        }
    }

    # ---- exclusions + weights ----
    $excl = New-Object System.Collections.Generic.List[object]
    $weights = $null
    if (Test-Path -LiteralPath $SettingsPath) {
        $g = Join-Path $SettingsPath 'RiskAnalysisGlobalExclusions.custom.json'
        if (Test-Path -LiteralPath $g) { $excl.Add([pscustomobject]@{ Key = 'global'; File = (& $touch $g); Body = [System.IO.File]::ReadAllText($g) }) }
        $custom = @(Get-ChildItem -LiteralPath $SettingsPath -File -Filter '*.exclude.custom.json' -ErrorAction SilentlyContinue | Sort-Object Name)
        $seen = @{}
        foreach ($f in $custom) {
            $r = $f.Name -replace '\.exclude\.custom\.json$', ''; $seen[$r] = $true
            $excl.Add([pscustomobject]@{ Key = $r; File = (& $touch $f.FullName); Body = [System.IO.File]::ReadAllText($f.FullName) })
        }
        foreach ($f in @(Get-ChildItem -LiteralPath $SettingsPath -File -Filter '*.exclude.json' -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $r = $f.Name -replace '\.exclude\.json$', ''
            if ($seen.ContainsKey($r) -or $f.Name -like '*.exclude.custom.json') { continue }
            $excl.Add([pscustomobject]@{ Key = $r; File = (& $touch $f.FullName); Body = [System.IO.File]::ReadAllText($f.FullName) })
        }
        $wp = Join-Path $SettingsPath 'riskscore_weighted.schema.custom.json'
        if (Test-Path -LiteralPath $wp) { $weights = [pscustomobject]@{ File = (& $touch $wp); Body = [System.IO.File]::ReadAllText($wp) } }
    }

    # ---- tier rules ----
    $rules = New-Object System.Collections.Generic.List[object]
    $tree = Join-Path $SIRoot 'asset-profiling-enrichment'
    $byId = [ordered]@{}
    $add = {
        param($f, [string]$base, [string]$where)
        $parts = @($f.FullName.Substring($base.Length).TrimStart('\', '/') -split '[\\/]')
        $engine = $parts[0].ToLowerInvariant()
        if ($engine -notin 'endpoint', 'identity', 'azure', 'shared') { return }
        $text = [System.IO.File]::ReadAllText($f.FullName)
        $m = [regex]::Match($text, '(?m)^id\s*:\s*(.+?)\s*$')
        $id = if ($m.Success) { $m.Groups[1].Value.Trim("'", '"', ' ') } else { $f.Name -replace '\.(locked|custom)\.yaml$', '' }
        $k = ('{0}|{1}' -f $engine, $id).ToLowerInvariant()
        if (-not $byId.Contains($k)) { $byId[$k] = @{ Engine = $engine; Id = $id; locked = $null; custom = $null; overlay = $null } }
        $byId[$k][$where] = @{ Text = $text; Full = $f.FullName }
    }
    if (Test-Path -LiteralPath $tree) {
        foreach ($f in @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter '*.custom.yaml' -ErrorAction SilentlyContinue)) { & $add $f $tree 'custom' }
    }
    if ($OverlayRoot -and (Test-Path -LiteralPath $OverlayRoot)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $OverlayRoot -Recurse -File -Filter '*.custom.yaml' -ErrorAction SilentlyContinue)) { & $add $f $OverlayRoot 'overlay' }
    }
    if ($byId.Count -gt 0 -and (Test-Path -LiteralPath $tree)) {
        # only the shipped rules a custom rule competes with are read
        foreach ($f in @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter '*.locked.yaml' -ErrorAction SilentlyContinue)) {
            $parts = @($f.FullName.Substring($tree.Length).TrimStart('\', '/') -split '[\\/]')
            $guess = ('{0}|{1}' -f $parts[0], ($f.Name -replace '\.locked\.yaml$', '')).ToLowerInvariant()
            if ($byId.Contains($guess)) { $byId[$guess]['locked'] = @{ Text = [System.IO.File]::ReadAllText($f.FullName); Full = $f.FullName } }
        }
    }
    foreach ($k in $byId.Keys) {
        $r = $byId[$k]
        $eff = if ($r.overlay) { $r.overlay } else { $r.custom }
        if (-not $eff) { continue }
        $file = if ($r.overlay) { 'overlay:' + $r.overlay.Full.Substring($OverlayRoot.Length).TrimStart('\', '/') } else { & $rel $r.custom.Full }
        $times[$file] = [System.IO.File]::GetLastWriteTimeUtc($eff.Full)
        $rules.Add([pscustomobject]@{ Engine = $r.Engine; Id = $r.Id; File = $file; CustomText = $eff.Text; LockedText = $(if ($r.locked) { $r.locked.Text } else { $null }) })
    }

    # ---- Risk Analysis reports of the customer's own catalog ----
    $reports = New-Object System.Collections.Generic.List[object]
    $names = { param($p) @([regex]::Matches([System.IO.File]::ReadAllText($p), '(?m)^\s*-\s*ReportName:\s*([A-Za-z0-9_]+)\s*$') | ForEach-Object { $_.Groups[1].Value }) }
    $locked = @{}
    foreach ($p in @((Join-Path $SettingsPath 'RiskAnalysis_Queries_Locked.yaml'), (Join-Path (Join-Path $SettingsPath 'locked') 'RiskAnalysis_Queries_Locked.yaml'))) {
        if (Test-Path -LiteralPath $p) { foreach ($n in @(& $names $p)) { $locked[$n] = $true } }
    }
    foreach ($p in @((Join-Path (Join-Path $SettingsPath 'custom') 'RiskAnalysis_Queries_Custom.yaml'), (Join-Path $SettingsPath 'RiskAnalysis_Queries_Custom.yaml'))) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $file = & $touch $p
        foreach ($n in @(& $names $p | Sort-Object -Unique)) { $reports.Add([pscustomobject]@{ Name = $n; Replaces = $locked.ContainsKey($n); File = $file }) }
        break   # the engine reads the first one it finds (custom\ first)
    }

    # ---- the Settings page's change log ----
    $log = New-Object System.Collections.Generic.List[object]
    $lp = Join-Path (Join-Path $SIRoot 'logs') 'settings-changes.log'
    if (Test-Path -LiteralPath $lp) {
        foreach ($line in [System.IO.File]::ReadAllLines($lp)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $log.Add((ConvertFrom-SIDevJson $line)) } catch { continue }
        }
    }

    [pscustomobject]@{ Settings = $settings.ToArray(); Exclusions = $excl.ToArray(); Weights = $weights; Rules = $rules.ToArray()
        CustomReports = $reports.ToArray(); Log = $log.ToArray(); FileTimes = $times }
}

function ConvertTo-SIDevCsvField {
    <# PURE. A CSV cell: a value a spreadsheet would run as a formula gets a leading quote; quoted when it must be. #>
    param([AllowNull()][string]$Value)
    $s = [string]$Value
    if ($s.Length -gt 0 -and "=+-@`t`r".IndexOf($s[0]) -ge 0) { $s = "'" + $s }
    if ($s.IndexOfAny([char[]]@(',', '"', "`n", "`r")) -ge 0) { return ('"' + $s.Replace('"', '""') + '"') }
    $s
}

function ConvertTo-SIDeviationCsv {
    <# PURE. Report rows -> CSV text (the report columns, header first). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($script:SIDevColumns -join ','))
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $lines.Add((@(foreach ($c in $script:SIDevColumns) { ConvertTo-SIDevCsvField ([string](Get-SIDevValue $r $c)) }) -join ','))
    }
    ($lines.ToArray() -join "`r`n") + "`r`n"
}
