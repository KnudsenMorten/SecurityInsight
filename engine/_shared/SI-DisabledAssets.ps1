#Requires -Version 5.1
<#
    DISABLED ACCOUNTS AND DEVICES -- one setting per stage (REQUIREMENTS #533, owner 2026-10-10: "we need to refine the
    decision of disabled users, computers, spns and make it be optional for customers in Settings").

    The five settings (Pro: cfg.Setting through the Settings page; Community: the custom file; shipped defaults in
    launcher\_lib\SecurityInsight.shared-defaults.ps1 -- an install that never stored one gets the default on its next
    update, nothing to migrate):
      SI_DisabledAssets_Collect      (a) collection from the sources              default ON
      SI_DisabledAssets_Correlate    (b) CI correlation                           default ON
      SI_DisabledAssets_RiskAnalysis (c) Risk Analysis reports                    default OFF
      SI_DisabledAssets_StateActions (d) finding / vulnerability lifecycle, close-loop, ticket open and close  default OFF
      SI_DisabledAssets_Connectors   (e) connectors and exports (data out)        default OFF
    Each covers disabled USERS, SERVICE PRINCIPALS / MANAGED IDENTITIES and COMPUTERS.

    🔒 THE RULES
      1. DISABLED = the account is disabled in its OWN directory: Entra accountEnabled = false (user, SP / MI, device),
         AD userAccountControl ACCOUNTDISABLE (0x2). NEVER inferred from inactivity: IsEnabledActive, sign-in age and
         last-seen are not read here. No value = unknown = treated as enabled (nothing is left out on a guess).
      2. The state is read on EVERY run and nothing sticks: an account enabled again is included again everywhere.
      3. Later stages see only what earlier ones kept: (b)-(e) can include a disabled asset only while (a) collects it
         (Get-SIDisabledAssetPolicy .Effective). The Settings page says so through each setting's "needs".
      4. ABSENCE IS NOT REMEDIATION (SI rule 4). An asset a stage leaves out is EXCLUDED, not gone: its open findings,
         actions and tickets are FROZEN -- never counted absent, never resolved or closed -- and re-enabling resumes the
         same item (Split-SIAbsentByDisabled).
      5. Every stage that leaves disabled assets out logs ONE plain line with the count (Format-SIDisabledStageLine).

    Everything here is PURE (reads globals only when no -Policy is passed) and tested directly
    (tests\pester\SIv3-DisabledAssets.Tests.ps1).
#>

$script:SIDisabledAssetStages = [ordered]@{
    Collect      = @{ Setting = 'SI_DisabledAssets_Collect';      Default = $true;  Label = 'collection' }
    Correlate    = @{ Setting = 'SI_DisabledAssets_Correlate';    Default = $true;  Label = 'CI correlation' }
    RiskAnalysis = @{ Setting = 'SI_DisabledAssets_RiskAnalysis'; Default = $false; Label = 'Risk Analysis' }
    StateActions = @{ Setting = 'SI_DisabledAssets_StateActions'; Default = $false; Label = 'finding actions' }
    Connectors   = @{ Setting = 'SI_DisabledAssets_Connectors';   Default = $false; Label = 'connectors' }
}

# The directory fields that SAY whether an account is enabled, in the shapes SI carries them: a profile row
# (AccountEnabled), collect metadata (ENTRA_* / AD_*), a provider record or CI attribute (accountEnabled / enabled).
# (names are matched case-insensitively; si_account_enabled = the data model's field on a provider record / CI member)
$script:SIEnabledFlagKeys = @('AccountEnabled', 'ENTRA_Enabled', 'ENTRA_SPEnabled', 'ENTRA_AccountEnabled', 'AD_Enabled', 'IsAccountEnabled', 'si_account_enabled')
$script:SIUacKeys         = @('UserAccountControl', 'ENTRA_UserAccountControl', 'AD_UserAccountControl')

function ConvertTo-SIEnabledFlag {
    <# PURE. $true / $false / $null from a bool, 'True' / 'false', 1 / 0. Anything else is unknown ($null). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long]) { if ($Value -eq 1) { return $true }; if ($Value -eq 0) { return $false }; return $null }
    $s = ([string]$Value).Trim()
    if ($s -ieq 'true' -or $s -eq '1') { return $true }
    if ($s -ieq 'false' -or $s -eq '0') { return $false }
    return $null
}

function Get-SIBagValue {
    <# PURE. A named value from a hashtable or an object (JSON round-trips give objects), case-insensitive. #>
    param([AllowNull()]$Bag, [string]$Name)
    if ($null -eq $Bag) { return $null }
    if ($Bag -is [System.Collections.IDictionary]) {
        foreach ($k in $Bag.Keys) { if ([string]$k -ieq $Name) { return $Bag[$k] } }
        return $null
    }
    $p = $Bag.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-SIAssetEnabledState {
    <#
    .SYNOPSIS
        PURE. Is this asset's account enabled in its own directory? $true, $false, or $null (the source said nothing).
    .DESCRIPTION
        -Asset is a profile row, collect metadata (ENTRA_* / AD_*), a provider record or a CI attribute bag -- or a
        record carrying one of those under .Metadata / .Properties.collect.entra (endpoint profile rows). A DISABLED
        answer from ANY directory source wins (an account disabled in AD is disabled even when the Entra copy has not
        synced yet); otherwise an ENABLED answer; otherwise unknown. Inactivity is never read.
    #>
    param([AllowNull()]$Asset)
    if ($null -eq $Asset) { return $null }
    $bags = New-Object System.Collections.Generic.List[object]
    $bags.Add($Asset)
    $meta = Get-SIBagValue $Asset 'Metadata'
    if ($null -ne $meta) { $bags.Add($meta) }
    $props = Get-SIBagValue $Asset 'Properties'
    if ($props -is [string] -and $props.TrimStart().StartsWith('{')) { try { $props = $props | ConvertFrom-Json } catch { $props = $null } }
    if ($null -ne $props) {
        $entra = Get-SIBagValue (Get-SIBagValue $props 'collect') 'entra'
        if ($null -ne $entra) { $bags.Add($entra) }
    }
    $sawEnabled = $false
    foreach ($b in $bags) {
        foreach ($k in $script:SIEnabledFlagKeys) {
            $f = ConvertTo-SIEnabledFlag (Get-SIBagValue $b $k)
            if ($f -eq $false) { return $false }
            if ($f -eq $true) { $sawEnabled = $true }
        }
        foreach ($k in $script:SIUacKeys) {
            $v = Get-SIBagValue $b $k
            if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
            $uac = 0L
            if ([long]::TryParse(([string]@($v)[0]).Trim(), [ref]$uac)) {
                if ($uac -band 2) { return $false }
                $sawEnabled = $true
            }
        }
    }
    if ($sawEnabled) { return $true }
    return $null
}

function Test-SIAssetDisabled {
    <# PURE. $true only when a directory source SAID the account is disabled. Unknown is not disabled. #>
    param([AllowNull()]$Asset)
    return ((Get-SIAssetEnabledState -Asset $Asset) -eq $false)
}

function Get-SIAssetDisabledKind {
    <# PURE. user | servicePrincipal | computer | asset -- for the count line only. #>
    param([AllowNull()]$Asset)
    # a device record carries its device ids (Entra device id, Defender machine name)
    foreach ($dk in 'ENTRA_AadDeviceId', 'ENTRA_TrustType', 'MDE_DeviceName', 'MDE_MachineId', 'AadDeviceId') { if (Get-SIBagValue $Asset $dk) { return 'computer' } }
    $t = ''
    foreach ($k in 'IdentityType', 'ObjectType', 'ENTRA_AssetType', 'AssetKind', 'Kind', 'CiClass', 'Class', 'Source') {
        $v = Get-SIBagValue $Asset $k
        if (-not $v) { $v = Get-SIBagValue (Get-SIBagValue $Asset 'Metadata') $k }
        if ($v) { $t = [string]$v; break }
    }
    if ($t -match '(?i)ServicePrincipal|ManagedIdentity|spn|application') { return 'servicePrincipal' }
    if ($t -match '(?i)user|guest|identity') { return 'user' }
    if ($t -match '(?i)device|computer|endpoint|server|machine|EntraDevice') { return 'computer' }
    return 'asset'
}

function Get-SIDisabledAssetPolicy {
    <#
    .SYNOPSIS
        PURE (reads the five globals unless -Values is passed). Whether each stage INCLUDES disabled assets.
    .OUTPUTS
        [pscustomobject] Collect, Correlate, RiskAnalysis, StateActions, Connectors (the settings as configured) and
        Effective (the same five after rule 3: a later stage can include a disabled asset only while collection does).
    #>
    param([hashtable]$Values)
    $cfg = [ordered]@{}
    foreach ($stage in $script:SIDisabledAssetStages.Keys) {
        $def = $script:SIDisabledAssetStages[$stage]
        $raw = $null
        if ($Values) { if ($Values.ContainsKey($def.Setting)) { $raw = $Values[$def.Setting] } elseif ($Values.ContainsKey($stage)) { $raw = $Values[$stage] } }
        else { $raw = Get-Variable -Name $def.Setting -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        $f = ConvertTo-SIEnabledFlag $raw
        $cfg[$stage] = $(if ($null -eq $f) { [bool]$def.Default } else { [bool]$f })
    }
    $eff = [ordered]@{ Collect = $cfg.Collect }
    foreach ($stage in 'Correlate', 'RiskAnalysis', 'StateActions', 'Connectors') { $eff[$stage] = ($cfg.Collect -and $cfg[$stage]) }
    $out = [ordered]@{}
    foreach ($k in $cfg.Keys) { $out[$k] = $cfg[$k] }
    $out.Effective = [pscustomobject]$eff
    [pscustomobject]$out
}

function Test-SIDisabledIncluded {
    <# PURE. Does this stage include disabled assets (effective value)? #>
    param([Parameter(Mandatory)][ValidateSet('Collect', 'Correlate', 'RiskAnalysis', 'StateActions', 'Connectors')][string]$Stage, $Policy)
    if (-not $Policy) { $Policy = Get-SIDisabledAssetPolicy }
    return [bool]$Policy.Effective.$Stage
}

function Format-SIDisabledStageLine {
    <# PURE. The one plain line a stage logs. Customer-facing: no internal numbers, the setting named. #>
    param(
        [Parameter(Mandatory)][ValidateSet('Collect', 'Correlate', 'RiskAnalysis', 'StateActions', 'Connectors')][string]$Stage,
        [int]$Count, [hashtable]$ByKind, [string]$Where
    )
    $def = $script:SIDisabledAssetStages[$Stage]
    $what = if ($Where) { $Where } else { $def.Label }
    $kinds = ''
    if ($ByKind -and $ByKind.Count) {
        $parts = foreach ($k in @('user', 'servicePrincipal', 'computer', 'asset')) {
            if ($ByKind.ContainsKey($k) -and $ByKind[$k] -gt 0) {
                $n = $ByKind[$k]
                switch ($k) { 'user' { '{0} user(s)' -f $n } 'servicePrincipal' { '{0} service principal(s) / managed identit(ies)' -f $n } 'computer' { '{0} computer(s)' -f $n } default { '{0} other' -f $n } }
            }
        }
        if (@($parts).Count) { $kinds = ' (' + (@($parts) -join ', ') + ')' }
    }
    $tail = if ($Stage -eq 'Collect') { '' } else { ' Their open findings, actions and tickets are kept as they are, not resolved or closed.' }
    return ('{0}: left out {1} disabled account(s) or device(s){2} -- {3} is off.{4}' -f $what, $Count, $kinds, $def.Setting, $tail)
}

function Select-SIDisabledForStage {
    <#
    .SYNOPSIS
        PURE. Splits -Items into what a stage KEEPS and the disabled ones it EXCLUDES, by that stage's setting.
    .PARAMETER StateOf
        Optional: { param($item) <the bag Get-SIAssetEnabledState reads> }. Default: the item itself.
    .PARAMETER KeyOf
        Optional: { param($item) <the asset key> } -- fills ExcludedKeys (a case-insensitive set) so a later step can
        freeze the excluded assets' findings (Split-SIAbsentByDisabled).
    .OUTPUTS
        [pscustomobject] Kept (object[]), Excluded (object[]), ExcludedKeys (HashSet[string]), Count, ByKind, Include,
        Line (the one log line, or '' when nothing was left out).
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Items = @(),
        [Parameter(Mandatory)][ValidateSet('Collect', 'Correlate', 'RiskAnalysis', 'StateActions', 'Connectors')][string]$Stage,
        $Policy, [scriptblock]$StateOf, [scriptblock]$KeyOf, [string]$Where
    )
    if (-not $Policy) { $Policy = Get-SIDisabledAssetPolicy }
    $include = [bool]$Policy.Effective.$Stage
    $kept = New-Object System.Collections.Generic.List[object]
    $excl = New-Object System.Collections.Generic.List[object]
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $byKind = @{}
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        if ($include) { $kept.Add($it); continue }
        $bag = if ($StateOf) { & $StateOf $it } else { $it }
        if (Test-SIAssetDisabled -Asset $bag) {
            $excl.Add($it)
            $kind = Get-SIAssetDisabledKind -Asset $bag
            if (-not $byKind.ContainsKey($kind)) { $byKind[$kind] = 0 }
            $byKind[$kind]++
            if ($KeyOf) { $k = [string](& $KeyOf $it); if ($k) { [void]$keys.Add($k) } }
        } else { $kept.Add($it) }
    }
    $line = ''
    if ($excl.Count -gt 0) { $line = Format-SIDisabledStageLine -Stage $Stage -Count $excl.Count -ByKind $byKind -Where $Where }
    [pscustomobject]@{ Kept = $kept.ToArray(); Excluded = $excl.ToArray(); ExcludedKeys = $keys; Count = $excl.Count; ByKind = $byKind; Include = $include; Line = $line }
}

function Split-SIAbsentByDisabled {
    <#
    .SYNOPSIS
        PURE. Rule 4 for every close path: of the open items ABSENT from this run, which really count as absent and
        which are FROZEN because their asset is disabled and left out by a setting.
    .DESCRIPTION
        A frozen item is neither counted absent (no step towards "closed after N runs") nor resolved / closed; its
        counters stay where they are, so re-enabling resumes the same item. -FrozenKeys is the set of asset keys left
        out (Select-SIDisabledForStage .ExcludedKeys, or Get-SIDisabledAssetKeys); -KeyOf reads an item's asset key.
    .OUTPUTS
        [pscustomobject] Absent (object[]: may move towards closed), Frozen (object[]: excluded (disabled), untouched).
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Items = @(),
        [AllowNull()]$FrozenKeys,
        [Parameter(Mandatory)][scriptblock]$KeyOf
    )
    $abs = New-Object System.Collections.Generic.List[object]
    $frz = New-Object System.Collections.Generic.List[object]
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in @($FrozenKeys)) { if ($k) { [void]$set.Add([string]$k) } }
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $k = [string](& $KeyOf $it)
        if ($k -and $set.Contains($k)) { $frz.Add($it) } else { $abs.Add($it) }
    }
    [pscustomobject]@{ Absent = $abs.ToArray(); Frozen = $frz.ToArray() }
}

function Get-SIDisabledAssetKeys {
    <#
    .SYNOPSIS
        PURE. The keys of the assets a stage leaves out as disabled -- the set every close path freezes. Empty when the
        stage includes disabled assets.
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Assets = @(),
        [Parameter(Mandatory)][ValidateSet('Collect', 'Correlate', 'RiskAnalysis', 'StateActions', 'Connectors')][string]$Stage,
        [Parameter(Mandatory)][scriptblock]$KeyOf, [scriptblock]$StateOf, $Policy
    )
    (Select-SIDisabledForStage -Items $Assets -Stage $Stage -Policy $Policy -StateOf $StateOf -KeyOf $KeyOf).ExcludedKeys
}

function Get-SIDisabledAssetIdsKql {
    <#
        PURE. The SI_AssetId of every asset of one profile table whose NEWEST row says its account is disabled in its own
        directory: the identity column AccountEnabled, else an endpoint row's Entra device state
        (Properties.collect.entra.AccountEnabled). -Count answers one row (Disabled) instead of the ids.
    #>
    param([Parameter(Mandatory)][string]$TableName, [int]$LookbackDays = 8, [switch]$Count)
    $tail = if ($Count) { '| summarize Disabled = count()' } else { '| project SI_AssetId' }
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend SI_AssetId = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(SI_AssetId)
| summarize arg_max(CollectionTime, *) by SI_AssetId
| extend _en = tostring(column_ifexists("AccountEnabled", ""))
| extend _en = iff(isempty(_en), tostring(todynamic(column_ifexists("Properties", dynamic(null))).collect.entra.AccountEnabled), _en)
| where _en =~ "false"
$tail
"@
}

function Get-SIDisabledIdentityCountKql {
    <# PURE. How many identities (users, service principals, managed identities) the newest profile rows say are disabled. #>
    Get-SIDisabledAssetIdsKql -TableName 'SI_Identity_Profile_CL' -Count
}

# ---- (c) Risk Analysis: the DISABLED PART of every report's scope (#541 supersedes #533's per-line marker) ----------
# A report does not filter on the enabled state in its own KQL. data-model/report-scope.locked.json says, per report,
# what the disabled part is: 'setting' (SI_DisabledAssets_RiskAnalysis decides -- off, the default, keeps enabled
# accounts and devices only), 'exclude' (the report asks about usable accounts: never disabled ones) or 'include' (the
# disabled state is part of the finding -- the two hygiene reports and the "disabled account still ..." reports). The
# engine's scope preamble (engine/risk-analysis/_shared/RA-ScopePreamble.ps1) asks THIS function for the decision and
# the CI predicate and puts it in the report's CI blocks -- users, service principals and devices alike (an Entra device
# carries accountEnabled). A legacy marked line (a customer's own query written for #533) is still rewritten from the
# same decision.
$script:SIDisabledRaMarker = '//__SI_DISABLED_ASSETS_RA__'
$script:SIDisabledRaAlwaysSee = @('Identity_GuestWithPrivilegedRole', 'Identity_SPN_OwnsResourcePublicAccess')
$script:SIDisabledRaCiPredicate = 'coalesce(tobool(column_ifexists("si_account_enabled", bool(null))), true)'

function Get-SIDisabledAssetsRaMarker { $script:SIDisabledRaMarker }
function Get-SIDisabledAssetsRaAlwaysSee { @($script:SIDisabledRaAlwaysSee) }   # elements: callers wrap in @()

function Resolve-SIDisabledAssetsRaFilter {
    <#
    .SYNOPSIS
        PURE. The disabled part of one report's scope, from SI_DisabledAssets_RiskAnalysis and the report's mode.
    .PARAMETER Mode     the report's disabled part (report-scope): setting | exclude | include
    .PARAMETER Include  the decision already taken (the scope preamble passes it) -- wins over -Mode / -Policy
    .OUTPUTS
        [pscustomobject] Query (the KQL with any legacy marked line rewritten), Marked (how many marked lines), Include
        (disabled assets included), Predicate (the CI-row test the CI blocks apply: 'true' when disabled assets are in).
        An unknown CI enabled state (a resource, a device no directory reports) counts as enabled: only a known disabled
        asset is left out.
    #>
    param([AllowEmptyString()][string]$Query = '', $Policy, [string]$ReportName,
          [ValidateSet('setting', 'exclude', 'include')][string]$Mode = 'setting', [object]$Include = $null)
    if ($null -ne $Include) { $inc = [bool]$Include }
    else {
        switch ($Mode) {
            'include' { $inc = $true }
            'exclude' { $inc = $false }
            default   { if (-not $Policy) { $Policy = Get-SIDisabledAssetPolicy }; $inc = [bool]$Policy.Effective.RiskAnalysis }
        }
    }
    $marker = $script:SIDisabledRaMarker
    $rx = '(?m)^(?<indent>[ \t]*)\|[^\r\n]*?' + [regex]::Escape($marker) + '[ \t]*(?=\r?$)'
    $n = 0; $q = [string]$Query
    if ($q) {
        $n = [regex]::Matches($q, $rx).Count
        if ($n -gt 0) {
            $line = if ($inc) { '| where 1 == 1 ' + $marker } else { '| where AccountEnabled == true ' + $marker }
            $q = [regex]::Replace($q, $rx, ('${indent}' + $line.Replace('$', '$$')))
        }
    }
    $pred = if ($inc) { 'true' } else { $script:SIDisabledRaCiPredicate }
    [pscustomobject]@{ Query = $q; Marked = $n; Include = $inc; Predicate = $pred }
}
