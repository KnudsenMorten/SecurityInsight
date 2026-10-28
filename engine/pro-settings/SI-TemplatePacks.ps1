#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- TEMPLATE PACKS: template versions released per ring, independently of the code.

    Operator, 2026-10-03: "i need an admin interface to release new templates versions" (both the vendor side and the
    customer side) -- "typically detection methods".

    A TEMPLATE PACK is every shipped template item exactly as Publish-SITemplates computes it (kind, key, body, format,
    ContentHash, version), as ONE JSON file si-templates-<packVersion>.json plus a sha256sum line beside it. A pack is
    FULL (every templated kind) or PARTIAL (selected detection methods / kinds / items). The vendor publishes it to the
    update feed and approves it per ring; an install's updater stages the pack its ring approves in cfg.TemplatePackStaged,
    and the customer releases it -- all of it, or only selected detection methods -- through the same fingerprint gate
    as a release's own templates.

    DETECTION METHODS. The templates are mostly detection methods, so every item belongs to one:
      rule          <engine>/<method folder or file>   e.g. endpoint/AssetProfileByApplicationServiceDetection
      rareport      riskanalysis/<SecurityDomain>      e.g. riskanalysis/Endpoint; report templates: riskanalysis/ReportTemplates
      riskindex     riskanalysis/RiskIndex
      assettagging  endpoint/AssetTagging
      servicemodel  config/ServiceModel
      datamodel     datamodel/<template>              e.g. datamodel/field-catalog, datamodel/mappings-mde (#456)
    (#251: names and the CMDB ownership map are configuration, never in a pack.)
    PACK VERSIONS (#250) are their own series: the templates shipped with the code are pack 1.0 ("Default templates 1.0",
    engine\pro-settings\shipped-template-pack.json); the vendor's later packs are 1.1, 1.2, ... (Get-SIProNextPackVersion).
    The web app (pro-management, TemplateReleases.cs) computes the SAME method ids, diff and selection fingerprint; a
    test runs both on the same rows.

    THE SELECTION FINGERPRINT. What a customer accepts is named exactly: SHA-256 over '<kind>/<key>=<ContentHash>' for
    every pack item of the selected methods and '<kind>/<key>=retired' for every live item of those methods the pack no
    longer ships -- ordinal order, newline-joined. The publish job is started with it and refuses any other.

    Everything here except the store readers / writers is pure (rows in, objects out). PS 5.1 safe.
#>

if (-not (Get-Command -Name Get-SIProTextHash -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ProSettings.ps1'))
}

$script:SIProPackSchema = 1
$script:SIProPackNamePattern = '^\d{1,6}(\.\d{1,12}){1,5}$'
# #251: VENDOR-DEVELOPED content only. naming and cmdbownership are configuration -- a pack can never carry them.
# #456: datamodel = the data model's items (field catalog, provider mappings, ...; SI-DataModelTemplateRows.ps1)
$script:SIProTemplatedKinds = @('rareport', 'riskindex', 'rule', 'assettagging', 'servicemodel', 'datamodel')
$script:SIProPackStateName = 'TemplatePack'
# 'as-released' (the templates in force are the pack's) | 'customised' (an install adopted with other templates, #250)
$script:SIProPackStatusName = 'TemplatePackStatus'
$script:SIProReleaseLogName = 'template-release'
# #405 (operator decision 2026-10-06): every shipped template is one of three classes -- how a change to it travels.
#   fix        a fix to our own queries / logic: inside the product release, always installed with the code, never held
#   default    customer business logic: SecurityInsight ships the default; a customer's edit (an override) is never changed
#   microsoft  a new Microsoft data surface: a Microsoft content pack between releases, ring by ring, installed automatically
$script:SIProTemplateClasses = @('fix', 'default', 'microsoft')
# what is installed, per class (cfg.InstallState): the code release whose fix + default templates are in force; ring 1's
# direct install; the Microsoft content pack the customer rolled back from (not installed automatically again); the mode
$script:SIProCodeStateName = 'TemplateCode'
$script:SIProDirectStateName = 'TemplateDirect'
$script:SIProDeclinedStateName = 'TemplatePackDeclined'
$script:SIProModeStateName = 'TemplateMode'
# the customer's switch (Pro settings catalog, read from SQL only): hold template packs for a manual Install ("Hold template packs")
$script:SIProHoldSettingName = 'SI_InvardiaUpdate_HoldMicrosoftContent'
# this code's own SecurityInsight folder (engine\pro-settings -> two up): where its classification document lives
$script:SIProTemplatePacksSIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $script:SIProClassificationCache) { $script:SIProClassificationCache = @{} }

function Get-SIProTemplatedKinds { $script:SIProTemplatedKinds }
function Get-SIProTemplateClasses { $script:SIProTemplateClasses }

# =====================================================================================================================
#  CLASSIFICATION (#405) -- fix | default | microsoft, as data: config\template-classification.locked.json
# =====================================================================================================================
function Get-SIProTemplateClassification {
    <#
        The classification document of a SecurityInsight folder (-SIRoot; default: this code's own), cached per path:
        @{ Present; Path; Document }. A missing or unreadable file is Present = $false -- every item then reads 'fix' and
        the split install is off (Publish-SITemplates needs a present, REVIEWED classification). -Text: a document as text
        (tests, and the pack builder reading a commit).
    #>
    param([string]$SIRoot, [string]$Text)
    if ($PSBoundParameters.ContainsKey('Text')) {
        $d = $null; try { $d = ConvertFrom-SIProJson ([string]$Text).TrimStart([char]0xFEFF) } catch { $d = $null }
        return (New-SIProClassificationObject -Document $d -Path '')
    }
    if (-not $SIRoot) { $SIRoot = $script:SIProTemplatePacksSIRoot }
    $p = [System.IO.Path]::Combine($SIRoot, 'config', 'template-classification.locked.json')
    if ($script:SIProClassificationCache.ContainsKey($p)) { return $script:SIProClassificationCache[$p] }
    $doc = $null
    if (Test-Path -LiteralPath $p) { try { $doc = ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF)) } catch { $doc = $null } }
    $c = New-SIProClassificationObject -Document $doc -Path $p
    $script:SIProClassificationCache[$p] = $c
    $c
}

function New-SIProClassificationObject {
    <# The parsed document with ORDINAL (case-sensitive) lookups -- PowerShell's own property lookup ignores case, the web app's does not. #>
    param($Document, [string]$Path)
    $items = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $kinds = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    $rules = New-Object System.Collections.Generic.List[object]
    if ($Document) {
        if ($Document.PSObject.Properties['Items'] -and $Document.Items) { foreach ($pr in $Document.Items.PSObject.Properties) { if (Test-SIProTemplateClassName ([string]$pr.Value.Class)) { $items[$pr.Name] = $pr.Value } } }
        if ($Document.PSObject.Properties['ByKind'] -and $Document.ByKind) { foreach ($pr in $Document.ByKind.PSObject.Properties) { if (Test-SIProTemplateClassName ([string]$pr.Value)) { $kinds[$pr.Name] = [string]$pr.Value } } }
        if ($Document.PSObject.Properties['Rules']) {
            foreach ($r in @($Document.Rules | Where-Object { $_ })) {
                if (-not (Test-SIProTemplateClassName ([string]$r.Class)) -or -not [string]$r.Pattern) { continue }
                $rules.Add([pscustomobject]@{ Kind = [string]$r.Kind; Regex = (New-Object System.Text.RegularExpressions.Regex ([string]$r.Pattern), ([System.Text.RegularExpressions.RegexOptions]::CultureInvariant)); Class = [string]$r.Class; Reason = [string]$r.Reason })
            }
        }
    }
    [pscustomobject]@{ Present = ($null -ne $Document); Path = $Path; Document = $Document; ItemsMap = $items; KindMap = $kinds; RuleList = $rules.ToArray() }
}

function Test-SIProTemplateClassName { param([AllowEmptyString()][AllowNull()][string]$Class) $script:SIProTemplateClasses -ccontains ([string]$Class) }

function Get-SIProTemplateClass {
    <#
        PURE (given -Classification). The class of one template item: the document's Items ('<kind>/<key>', exact), then
        its Rules in order (Kind equal, Pattern an ordinal, culture-invariant .NET regex on the ItemKey), then ByKind, else
        'fix' -- the safe side: it ships with the code and is never held. The web app's TemplateClasses.Of is the same
        rule (a test runs both on every shipped item). -Detailed: @{ Name; Kind; ItemKey; Class; Source = item | rule |
        kind | fallback; Reason }.
    #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$ItemKey, $Classification, [switch]$Detailed)
    if ($null -eq $Classification) { $Classification = Get-SIProTemplateClassification }
    $name = '{0}/{1}' -f $Kind, $ItemKey
    $cls = ''; $src = ''; $why = ''
    if ($Classification -and $Classification.Present) {
        $e = $null
        if ($Classification.ItemsMap.TryGetValue($name, [ref]$e)) { $cls = [string]$e.Class; $src = 'item'; $why = [string]$e.Reason }
        if (-not $cls) {
            foreach ($r in @($Classification.RuleList)) {
                if ($r.Kind -cne $Kind) { continue }
                if ($r.Regex.IsMatch([string]$ItemKey)) { $cls = $r.Class; $src = 'rule'; $why = $r.Reason; break }
            }
        }
        $k = $null
        if (-not $cls -and $Classification.KindMap.TryGetValue([string]$Kind, [ref]$k)) { $cls = $k; $src = 'kind'; $why = ('every {0} item is {1} unless named otherwise' -f $Kind, $cls) }
    }
    if (-not $cls) { $cls = 'fix'; $src = 'fallback'; $why = 'not classified -- fix is the safe side (ships with the code, never held)' }
    if (-not $Detailed) { return $cls }
    [pscustomobject]@{ Name = $name; Kind = $Kind; ItemKey = $ItemKey; Class = $cls; Source = $src; Reason = $why }
}

function Get-SIProRowClass {
    <# A row's class: its own Class field (a pack item carries the class it was built with), else Get-SIProTemplateClass. #>
    param($Row, $Classification)
    $c = [string](Get-SIProRowValue $Row 'Class')
    if (Test-SIProTemplateClassName $c) { return $c }
    Get-SIProTemplateClass -Kind ([string](Get-SIProRowValue $Row 'Kind')) -ItemKey ([string](Get-SIProRowValue $Row 'ItemKey')) -Classification $Classification
}

function Get-SIProShippedPackPin {
    <#
        What the shipped pack version (engine\pro-settings\shipped-template-pack.json) NAMES, and whether its Fingerprint
        still pins it (#405, lane-pack14). A pack version is immutable: the same version never names different content.
        Split install (ClassificationReviewed + a classification present): the pack version names the MICROSOFT CONTENT
        only -- fix and default templates have no version of their own, they ride the code version and are installed
        with the code on every install (also one already on this pack), so a change to them never needs a pack bump.
        Gated (not reviewed): every template change waits for a review under a pack version, so the pin is every shipped
        template. Scope = microsoft | all; Fingerprint = Get-SIProTemplateSetFingerprint over the rows in scope; Pinned =
        the file's Fingerprint; Same = they match; Action = exactly what the vendor does when they do not.
    #>
    param([string]$SIRoot, [AllowEmptyCollection()][object[]]$Rows, $Classification)
    $info = Get-SIProShippedPackInfo -SIRoot $SIRoot
    if ($null -eq $Classification) { $Classification = Get-SIProTemplateClassification -SIRoot $SIRoot }
    if ($null -eq $Rows) { $Rows = @((Get-SITemplateRows -SIRoot $SIRoot).Rows) }
    $split = [bool]$info.ClassificationReviewed -and [bool]$Classification.Present
    $scope = if ($split) { 'microsoft' } else { 'all' }
    $inScope = if ($split) { @($Rows | Where-Object { $_ -and (Get-SIProRowClass -Row $_ -Classification $Classification) -eq 'microsoft' }) } else { @($Rows | Where-Object { $_ }) }
    $fp = Get-SIProTemplateSetFingerprint -Rows $inScope
    $pinned = ''
    try {
        $o = ConvertFrom-SIProJson ([System.IO.File]::ReadAllText((Join-SIProPath $SIRoot 'engine' 'pro-settings' 'shipped-template-pack.json')).TrimStart([char]0xFEFF))
        $pinned = ([string]$o.Fingerprint).Trim()
    } catch { }
    $same = $pinned -eq $fp
    $what = if ($split) { 'the Microsoft content (the {0} microsoft-class templates)' -f $inScope.Count } else { 'the shipped templates (all {0}; the classification is not reviewed, so every change is a pack)' -f $inScope.Count }
    $action = if ($same) { '' } elseif ($split) {
        ('{0} changed under Microsoft content {1}: a published Microsoft content pack never changes. Raise PackVersion (the next Microsoft content pack, e.g. {2}) and Name in engine\pro-settings\shipped-template-pack.json, set Fingerprint to {3}, and add a history line to its _doc. Fix and default templates never need this -- they ride the code version.' -f $what, $info.PackVersion, (Get-SIProNextPackVersion -Existing @($info.PackVersion)), $fp)
    } else {
        ('{0} changed under pack {1}: an install that already has {1} would never receive the change. Raise PackVersion and Name in engine\pro-settings\shipped-template-pack.json and set Fingerprint to {2}' -f $what, $info.PackVersion, $fp)
    }
    [pscustomobject]@{ PackVersion = $info.PackVersion; Scope = $scope; Split = $split; Fingerprint = $fp; Pinned = $pinned; Same = $same; Count = $inScope.Count; Action = $action }
}

function Get-SIProClassificationSummary {
    <# PURE. Per class and per kind the item counts of -Rows (the shipped templates), and every item with its decision. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), $Classification)
    $items = @(foreach ($r in @($Rows | Where-Object { $_ })) { Get-SIProTemplateClass -Kind ([string](Get-SIProRowValue $r 'Kind')) -ItemKey ([string](Get-SIProRowValue $r 'ItemKey')) -Classification $Classification -Detailed })
    $byClass = [ordered]@{}; foreach ($c in $script:SIProTemplateClasses) { $byClass[$c] = @($items | Where-Object { $_.Class -eq $c }).Count }
    $byKind = [ordered]@{}
    foreach ($k in $script:SIProTemplatedKinds) {
        $h = [ordered]@{}; foreach ($c in $script:SIProTemplateClasses) { $h[$c] = @($items | Where-Object { $_.Kind -eq $k -and $_.Class -eq $c }).Count }
        $byKind[$k] = $h
    }
    [pscustomobject]@{ Total = $items.Count; ByClass = $byClass; ByKind = $byKind; Items = $items }
}

function Get-SIProTemplatePackDecision {
    <#
        PURE. What the INSTALLED code does with a template pack -- EVERY template pack: Microsoft content and packs that
        carry more (SecurityInsight's own templates). Owner decision 2026-10-11 ("Automatic"): a template pack installs
        automatically on update, like a code fix, in every ring; a customer's edit (an override beside the template row) is
        never written, and Template conformance shows where theirs differs. "Hold" stays the customer's opt-in to approve
        by hand. -Pack: the pack (PackVersion, Content, MinCodeVersion, CodeVersion); -CodeVersion: the code this install
        runs; -Hold: the customer's Hold setting; -Declined: the pack the customer rolled back from (cfg.InstallState
        TemplatePackDeclined); -Installed: the pack in force (cfg.InstallState TemplatePack -- also what ring 1's direct
        install recorded), '' when none is a real pack; -Direct: ring 1 installs the current templates directly on every
        deploy -- no longer a reason to hold: a pack the direct install already put in force reads 'installed', a newer one
        installs like everywhere else; -Split: the install's classification is present and reviewed -- kept for the
        callers, it no longer changes the outcome (a customer's edit is an override in both modes, never written by either).
          installed  the pack is the one in force, or older -- nothing to do, nothing to Install
          wait-code  the pack needs newer code -- never installed by this code, not even by hand. The minimum is the pack's
                     MinCodeVersion; a pack without one that carries more than Microsoft content needs the code it was
                     built by (CodeVersion), so its items are never read by engines older than they were written for
          hold       Hold is on, or the customer rolled back from this pack (or a newer one): staged and shown with
                     Install, nothing written automatically -- the only outcomes that wait for an Admin
          install    installed automatically
        Returns @{ Action; Auto; Installable; Reason }. The web app's TemplatePackState.Of is the same rule (a shared case
        file, pro-management\tests\fixtures\template-pack-decision-cases.json, runs both).
    #>
    param([bool]$Split, $Pack, [AllowEmptyString()][string]$CodeVersion, [bool]$Hold, [AllowEmptyString()][string]$Declined, [bool]$Direct,
          [AllowEmptyString()][string]$Installed)
    $get = { param($n) if ($null -eq $Pack) { '' } elseif ($Pack -is [System.Collections.IDictionary]) { [string]$Pack[$n] } elseif ($Pack.PSObject.Properties[$n]) { [string]$Pack.$n } else { '' } }
    $v = & $get 'PackVersion'; $content = & $get 'Content'; $min = & $get 'MinCodeVersion'
    if (-not $min -and $content -ne 'microsoft') { $min = & $get 'CodeVersion' }
    $what = if ($content -eq 'microsoft') { 'Microsoft content {0}' -f $v } else { 'template pack {0}' -f $v }
    $mk = { param($a, [bool]$auto, [bool]$ok, $why) [pscustomobject]@{ Action = $a; Auto = $auto; Installable = $ok; Reason = $why } }
    if ($Installed -and (Test-SIProPackVersion $Installed) -and (Compare-SIProPackVersion $v $Installed) -le 0) {
        return (& $mk 'installed' $false $false ('{0} is in force already{1} -- nothing to install' -f $what, $(if ($v -ne $Installed) { ' (' + $Installed + ' is installed)' } else { '' })))
    }
    if ($min -and (Compare-SIProPackVersion $min $CodeVersion) -gt 0) {
        return (& $mk 'wait-code' $false $false ('{0} needs SecurityInsight {1} or newer; this install runs {2} -- it waits until the code has been updated' -f $what, $min, $(if ($CodeVersion) { $CodeVersion } else { 'an unknown version' })))
    }
    if ($Declined -and (Compare-SIProPackVersion $v $Declined) -le 0) {
        $declWhat = if ($content -eq 'microsoft') { 'Microsoft content {0}' -f $Declined } else { 'template pack {0}' -f $Declined }
        return (& $mk 'hold' $false $true ('you rolled back from {0} -- {1} is not installed automatically (Install it on Template releases to take it)' -f $declWhat, $v))
    }
    if ($Hold) { return (& $mk 'hold' $false $true ('Hold template packs is on -- {0} waits on Template releases until you Install it' -f $what)) }
    & $mk 'install' $true $true ('{0} is installed automatically (your own changes are kept)' -f $what)
}

function Test-SIProInstalledPackIsPack {
    <# PURE. Is a recorded TemplatePack a real pack version? A value recorded before packs had their own series carries the
       CODE version (major >= 2) and no status -- not a pack (the same rule as Get-SIProDefaultTemplateDecision). #>
    param([AllowEmptyString()][string]$InstalledPack, [AllowEmptyString()][string]$InstalledStatus)
    if (-not $InstalledPack -or -not (Test-SIProPackVersion $InstalledPack)) { return $false }
    if (-not $InstalledStatus) { $major = 0; if ([int]::TryParse(($InstalledPack.Trim().Split('.')[0]), [ref]$major) -and $major -ge 2) { return $false } }
    $true
}

# =====================================================================================================================
#  NAMES AND VERSIONS
# =====================================================================================================================
function Test-SIProPackVersion {
    <# PURE. A pack version: 2 to 6 dot-separated numbers, at most 32 characters (cfg.Template.[Version]). #>
    param([AllowEmptyString()][AllowNull()][string]$Version)
    $v = ([string]$Version).Trim()
    ($v.Length -le 32) -and ($v -match $script:SIProPackNamePattern)
}

function Compare-SIProPackVersion {
    <#
        PURE. -1 / 0 / 1. Numeric per part, as 64-bit numbers ([version] cannot hold a yyyyMMddHHmm part); a missing part
        counts as 0, so 3.0.0 = 3.0.0.0 < 3.0.0.202610031200.
    #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $pa = @(([string]$A).Trim().Split('.') | Where-Object { $_ -ne '' }); $pb = @(([string]$B).Trim().Split('.') | Where-Object { $_ -ne '' })
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { [void][long]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][long]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    0
}

function Get-SIProPackFileName {
    param([Parameter(Mandatory)][string]$PackVersion)
    if (-not (Test-SIProPackVersion $PackVersion)) { throw "not a template pack version: '$PackVersion' (2 to 6 numbers, e.g. 3.0.0.202610031200)" }
    'si-templates-{0}.json' -f $PackVersion.Trim()
}

function Get-SIProPackVersionFromName {
    <# PURE. 'si-templates-3.0.0.202610031200.json' -> '3.0.0.202610031200'; '' for any other name. #>
    param([AllowEmptyString()][string]$Name)
    $m = [regex]::Match([string]$Name, '^si-templates-(?<v>\d[\d\.]*\d)\.json$')
    if ($m.Success -and (Test-SIProPackVersion $m.Groups['v'].Value)) { return $m.Groups['v'].Value }
    ''
}

function Get-SIProNextPackVersion {
    <#
        PURE. The next template pack version (#250): template packs are their OWN series, starting at 1.0 -- never the code
        version. -Existing: the pack versions already published (the feed's si-templates-*.json, the shipped pack); none =
        '1.0'. Otherwise the next MINOR after the highest: 1.0 -> 1.1 -> 1.2 ... (1.9 -> 1.10). Versions that are not pack
        versions are ignored.
    #>
    param([AllowEmptyCollection()][string[]]$Existing = @())
    $top = ''
    foreach ($v in @($Existing | Where-Object { $_ -and (Test-SIProPackVersion $_) })) { if (-not $top -or (Compare-SIProPackVersion $v $top) -gt 0) { $top = $v.Trim() } }
    if (-not $top) { return '1.0' }
    $parts = $top.Split('.')
    $minor = [long]0; [void][long]::TryParse($parts[1], [ref]$minor)
    '{0}.{1}' -f $parts[0], ($minor + 1)
}

function New-SIProPackVersion {
    <# PURE. <release VERSION>.<yyyyMMddHHmm> of -At (UTC) -- the pack version scheme before #250. Template packs are their
       own series now (Get-SIProNextPackVersion); kept for packs that were built that way. #>
    param([Parameter(Mandatory)][string]$CodeVersion, [Parameter(Mandatory)][datetime]$At)
    $v = '{0}.{1}' -f $CodeVersion.Trim(), $At.ToUniversalTime().ToString('yyyyMMddHHmm', [System.Globalization.CultureInfo]::InvariantCulture)
    if (-not (Test-SIProPackVersion $v)) { throw "'$v' is not a usable pack version" }
    $v
}

function Get-SIProSha256Line {
    <# PURE. The sha256sum line for a file: '<hex>  <name>' + LF. #>
    param([Parameter(Mandatory)][string]$Sha256, [Parameter(Mandatory)][string]$FileName)
    '{0}  {1}' -f $Sha256.Trim().ToLowerInvariant(), $FileName + "`n"
}

function Read-SIProSha256Line {
    <# PURE. The hash out of a sha256sum file (first line, '<hex>  <name>' or '<hex> *<name>'); throws on anything else. #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [string]$FileName)
    $line = (([string]$Text).TrimStart([char]0xFEFF) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    $m = [regex]::Match([string]$line, '^(?<h>[0-9a-fA-F]{64})\s+\*?(?<n>\S.*)$')
    if (-not $m.Success) { throw 'the .sha256 file is not in sha256sum format (<64 hex>  <file name>)' }
    if ($FileName -and $m.Groups['n'].Value.Trim() -ne $FileName) { throw ("the .sha256 file names '{0}', not '{1}'" -f $m.Groups['n'].Value.Trim(), $FileName) }
    $m.Groups['h'].Value.ToLowerInvariant()
}

# =====================================================================================================================
#  DETECTION METHODS
# =====================================================================================================================
function Get-SIProTemplateMethod {
    <#
        PURE. The detection method an item belongs to: @{ Engine; Method; Id = '<engine>/<method>' }. From the item's kind,
        key, Source (the shipped file it came from) and, for a Risk Analysis report, its SecurityDomain. The web app's
        TemplateMethods.Of is the same rule.
    #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$ItemKey, [AllowEmptyString()][AllowNull()][string]$Source,
          [AllowEmptyString()][AllowNull()][string]$BodyJson)
    $clean = { param([string]$s) $c = ([regex]::Replace([string]$s, '[^A-Za-z0-9_\-]', '')); if ($c) { $c } else { 'Other' } }
    $engine = 'config'; $method = 'Other'
    switch ($Kind) {
        'rule' {
            $engine = if ($ItemKey -match '^([a-z]+)/') { $Matches[1] } else { 'shared' }
            $parts = @(([string]$Source).Replace('\', '/').Split('/') | Where-Object { $_ })
            # asset-profiling-enrichment/<engine>/<method folder>/... or asset-profiling-enrichment/<engine>/<method>.locked.yaml
            if ($parts.Count -ge 3) { $method = & $clean ($parts[2] -replace '(?i)\.locked\.yaml$', '' -replace '(?i)\.ya?ml$', '') }
        }
        'rareport' {
            $engine = 'riskanalysis'
            if ($ItemKey -like 'template/*') { $method = 'ReportTemplates' }
            else {
                $dom = ''
                try { $o = ConvertFrom-SIProJson ([string]$BodyJson); if ($o -and $o.PSObject.Properties['SecurityDomain']) { $dom = [string]$o.SecurityDomain } } catch { }
                $method = & $clean $dom
            }
        }
        'riskindex'     { $engine = 'riskanalysis'; $method = 'RiskIndex' }
        'assettagging'  { $engine = 'endpoint'; $method = 'AssetTagging' }
        'cmdbownership' { $method = 'CmdbOwnership' }
        'servicemodel'  { $method = 'ServiceModel' }
        # #456: one method per data-model template file: datamodel/field-catalog, datamodel/mappings-mde, ...
        'datamodel'     { $engine = 'datamodel'; $n = [string]$ItemKey; $ci = $n.IndexOf(':'); if ($ci -ge 0) { $n = $n.Substring(0, $ci) }; $method = & $clean ($n.Replace('/', '-')) }
        'naming'        { $method = 'Naming' }
        default         { $method = & $clean $Kind }
    }
    [pscustomobject]@{ Engine = $engine; Method = $method; Id = ('{0}/{1}' -f $engine, $method) }
}

function Get-SIProRowMethodId {
    <# A row's method id: the pack's own (Engine/Method fields) when present, else computed. #>
    param($Row)
    $e = [string](Get-SIProRowValue $Row 'Engine'); $m = [string](Get-SIProRowValue $Row 'Method')
    if ($e -and $m) { return ('{0}/{1}' -f $e, $m) }
    (Get-SIProTemplateMethod -Kind ([string](Get-SIProRowValue $Row 'Kind')) -ItemKey ([string](Get-SIProRowValue $Row 'ItemKey')) `
        -Source ([string](Get-SIProRowValue $Row 'Source')) -BodyJson ([string](Get-SIProRowValue $Row 'BodyJson'))).Id
}

function Resolve-SIProMethodSelection {
    <#
        PURE. A selection as given ('AssetProfileByIPSubnet', 'endpoint/AssetProfileByIPSubnet', '*') against the method
        ids that exist -> the matching ids (ordinal). A name that matches nothing throws: a typo must never publish
        nothing -- or everything.
    #>
    param([AllowEmptyCollection()][string[]]$Selection = @(), [AllowEmptyCollection()][string[]]$Known = @())
    $sel = @($Selection | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
    if ($sel.Count -eq 0 -or $sel -contains '*') { $out = [string[]]@($Known | Select-Object -Unique) }
    else {
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($s in $sel) {
            $hit = @($Known | Where-Object { $_ -ieq $s -or ($_.Substring($_.IndexOf('/') + 1)) -ieq $s })
            if ($hit.Count -eq 0) { throw ("'{0}' is not a detection method here (known: {1})" -f $s, ((@($Known) | Select-Object -First 30) -join ', ')) }
            foreach ($h in $hit) { if (-not $list.Contains($h)) { $list.Add($h) } }
        }
        $out = $list.ToArray()
    }
    if ($out.Count -gt 1) { [Array]::Sort($out, [System.StringComparer]::Ordinal) }
    $out
}

# =====================================================================================================================
#  THE PACK
# =====================================================================================================================
function New-SIProTemplatePack {
    <#
        PURE. A pack from template rows (Get-SITemplateRows). -Method / -Kind / -ItemKey make it PARTIAL: only those
        items, and the pack's Scope says what it covers (an item outside the scope is never retired by it).
        Items are stamped with -PackVersion and ordered ordinally by kind|key, so the same rows give the same text.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$PackVersion, [Parameter(Mandatory)][string]$CodeVersion,
          [string]$Commit = '', [string[]]$Method, [string[]]$Kind, [string[]]$ItemKey,
          # the pack's display name (the shipped one: "Default templates 1.0"); left out of the file when empty
          [string]$Name,
          # #405: only items of these classes. -Class microsoft makes a MICROSOFT CONTENT PACK (Content = 'microsoft'): its
          # scope names exactly its items (older code then never retires anything outside them) and its classes.
          [ValidateSet('fix', 'default', 'microsoft')][string[]]$Class,
          # #405: the oldest code that may install the pack (default for a Microsoft content pack: -CodeVersion)
          [string]$MinCodeVersion,
          # the classification the items are stamped with (default: this code's own)
          $Classification)
    if (-not (Test-SIProPackVersion $PackVersion)) { throw "not a template pack version: '$PackVersion'" }
    if ($null -eq $Classification) { $Classification = Get-SIProTemplateClassification }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        if ($script:SIProTemplatedKinds -notcontains [string]$r.Kind) { throw ("{0}/{1} is not template content -- a template pack carries only vendor-developed content ({2}); a name is a setting and the CMDB ownership map is configuration" -f $r.Kind, $r.ItemKey, ($script:SIProTemplatedKinds -join ', ')) }
        $m = Get-SIProTemplateMethod -Kind $r.Kind -ItemKey $r.ItemKey -Source $r.Source -BodyJson $r.BodyJson
        $cls = Get-SIProRowClass -Row $r -Classification $Classification
        if ($Class -and $Class -notcontains $cls) { continue }
        $items.Add([pscustomobject]@{ Row = $r; M = $m; Name = ('{0}/{1}' -f $r.Kind, $r.ItemKey); Class = $cls })
    }
    $full = -not ($Method -or $Kind -or $ItemKey -or $Class)
    $methodsSel = @()
    if ($Method) { $methodsSel = @(Resolve-SIProMethodSelection -Selection $Method -Known @($items | ForEach-Object { $_.M.Id } | Select-Object -Unique)) }
    if ($Kind) { foreach ($k in $Kind) { if ($script:SIProTemplatedKinds -notcontains $k) { throw "'$k' is not a templated kind ($($script:SIProTemplatedKinds -join ', '))" } } }
    $keep = @($items | Where-Object {
        (-not $Kind -or $Kind -contains $_.Row.Kind) -and (-not $Method -or $methodsSel -contains $_.M.Id) -and (-not $ItemKey -or $ItemKey -contains $_.Name -or $ItemKey -contains $_.Row.ItemKey)
    })
    if ($ItemKey) {
        foreach ($k in $ItemKey) { if (-not @($keep | Where-Object { $_.Name -eq $k -or $_.Row.ItemKey -eq $k }).Count) { throw "'$k' is not an item of this release" } }
    }
    if ($keep.Count -eq 0) { throw 'the pack would contain no item' }
    $order = Get-SIProOrdinalOrder -Keys @($keep | ForEach-Object { '{0}|{1}' -f $_.Row.Kind, $_.Row.ItemKey })
    $outItems = foreach ($i in $order) {
        $k = $keep[$i]; $r = $k.Row
        [ordered]@{ Kind = $r.Kind; ItemKey = $r.ItemKey; Engine = $k.M.Engine; Method = $k.M.Method; Class = $k.Class; Format = $r.Format; Version = $PackVersion.Trim()
            SortOrder = [int]$r.SortOrder; Source = $r.Source; BodyHash = $r.BodyHash; ContentHash = $r.ContentHash; Body = $r.BodyJson }
    }
    $outItems = @($outItems)
    $kinds = [string[]]@($outItems | ForEach-Object { $_.Kind } | Select-Object -Unique); if ($kinds.Count -gt 1) { [Array]::Sort($kinds, [System.StringComparer]::Ordinal) }
    if ($full) { $kinds = [string[]]$script:SIProTemplatedKinds.Clone(); [Array]::Sort($kinds, [System.StringComparer]::Ordinal) }
    elseif ($Kind -and -not $Method -and -not $ItemKey -and -not $Class) { $kinds = [string[]]@($Kind | Select-Object -Unique); if ($kinds.Count -gt 1) { [Array]::Sort($kinds, [System.StringComparer]::Ordinal) } }
    $scopeItems = @()
    # a class selection names its items too: code from before #405 knows no classes and must never retire anything else
    if ($ItemKey -or $Class) { $scopeItems = [string[]]@($outItems | ForEach-Object { '{0}/{1}' -f $_.Kind, $_.ItemKey }); if ($scopeItems.Count -gt 1) { [Array]::Sort($scopeItems, [System.StringComparer]::Ordinal) } }
    $fp = Get-SIProTemplateSetFingerprint -Rows @($outItems | ForEach-Object { [pscustomobject]@{ Kind = $_.Kind; ItemKey = $_.ItemKey; ContentHash = $_.ContentHash } })
    $pack = [ordered]@{ Schema = $script:SIProPackSchema; Product = 'SecurityInsight'; PackVersion = $PackVersion.Trim() }
    if ("$Name".Trim()) { $pack['Name'] = "$Name".Trim() }
    $pack['CodeVersion'] = $CodeVersion.Trim(); $pack['Commit'] = $Commit
    $classes = @()
    if ($Class) { $classes = [string[]]@($Class | Select-Object -Unique); if ($classes.Count -gt 1) { [Array]::Sort($classes, [System.StringComparer]::Ordinal) } }
    if ($classes.Count -eq 1 -and $classes[0] -eq 'microsoft') { $pack['Content'] = 'microsoft' }
    if ("$MinCodeVersion".Trim()) { $pack['MinCodeVersion'] = "$MinCodeVersion".Trim() } elseif ($pack.Contains('Content')) { $pack['MinCodeVersion'] = $CodeVersion.Trim() }
    if ($pack.Contains('MinCodeVersion') -and -not (Test-SIProPackVersion $pack['MinCodeVersion'])) { throw ("'{0}' is not a code version" -f $pack['MinCodeVersion']) }
    $scope = [ordered]@{ Full = [bool]$full; Kinds = @($kinds); Methods = @($methodsSel); Items = @($scopeItems) }
    if ($classes.Count) { $scope['Classes'] = @($classes) }
    $pack['Scope'] = $scope
    $pack['Fingerprint'] = $fp; $pack['ItemCount'] = $outItems.Count; $pack['Items'] = $outItems
    $pack
}

function Get-SIProProcessCache {
    <# #416: a cache that lives as long as the PROCESS (also across `& script` calls), by name. Results of pure work only. #>
    param([Parameter(Mandatory)][string]$Name)
    $k = 'SecurityInsight.' + $Name
    $c = [AppDomain]::CurrentDomain.GetData($k)
    if ($null -eq $c) { $c = [hashtable]::Synchronized(@{}); [AppDomain]::CurrentDomain.SetData($k, $c) }
    $c
}

function Get-SIProPackTextFor {
    <#
        #416: New-SIProTemplatePack + ConvertTo-SIProTemplatePackText, kept per process for the same input (every row's
        kind, key, body hash, content hash, order, source, format and version; the pack's own parameters; the
        classification). The shipped pack of 780 templates took seconds to build and serialise on every publish.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string]$PackVersion, [Parameter(Mandatory)][string]$CodeVersion,
          [string[]]$Kind, [string]$Name, $Classification)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($PackVersion).Append('|').Append($CodeVersion).Append('|').Append((@($Kind) -join ',')).Append('|').Append($Name).Append("`n")
    [void]$sb.Append($(if ($null -eq $Classification) { '' } else { ConvertTo-Json -InputObject $Classification -Depth 12 -Compress })).Append("`n")
    foreach ($r in @($Rows | Where-Object { $_ })) {
        [void]$sb.Append($r.Kind).Append('|').Append($r.ItemKey).Append('|').Append($r.BodyHash).Append('|').Append($r.ContentHash).Append('|').Append($r.SortOrder).Append('|').Append($r.Source).Append('|').Append($r.Format).Append('|').Append($r.TemplateVersion).Append("`n")
    }
    $key = Get-SIProTextHash $sb.ToString()
    $memo = Get-SIProProcessCache -Name 'PackText'
    if ($memo.ContainsKey($key)) { return [string]$memo[$key] }
    $a = @{ Rows = $Rows; PackVersion = $PackVersion; CodeVersion = $CodeVersion; Name = $Name; Classification = $Classification }
    if ($Kind) { $a.Kind = $Kind }
    $text = ConvertTo-SIProTemplatePackText -Pack (New-SIProTemplatePack @a)
    if ($memo.Count -ge 8) { $memo.Clear() }
    $memo[$key] = $text
    $text
}

function ConvertTo-SIProTemplatePackText {
    <# PURE. The pack file's text: indented JSON, LF line ends, ending with LF. Write it as UTF-8 WITHOUT a BOM. #>
    param([Parameter(Mandatory)]$Pack)
    (ConvertTo-SIProJson -Value $Pack) + "`n"
}

function ConvertFrom-SIProTemplatePack {
    <#
        A pack file's text -> the pack, checked: its SHA-256 (when -ExpectedSha256 is given), the schema, the version, and
        every item's integrity (the body matches its BodyHash; the content hash is the one this code computes). Returns
        @{ Pack; Sha256; Rows; Refused } -- Rows in the cfg.Template row shape. Throws on a pack that cannot be trusted
        as a whole; an item that does not validate here is in Refused (the caller decides -- Publish refuses to apply).
        -Context: Get-SIProConfigContext (validation); omitted = integrity only.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$ExpectedSha256, $Context)
    $sha = Get-SIProTextHash $Text
    if ($ExpectedSha256 -and $sha -ne $ExpectedSha256.Trim().ToLowerInvariant()) {
        throw ("the pack does not match its SHA-256 (expected {0}, the file is {1}) -- it was changed or damaged in transit" -f $ExpectedSha256.Trim().ToLowerInvariant(), $sha)
    }
    try { $p = ConvertFrom-SIProJson $Text } catch { throw ('the pack is not valid JSON: ' + $_.Exception.Message) }
    if (-not $p -or [int]$p.Schema -ne $script:SIProPackSchema) { throw ('not a SecurityInsight template pack (schema {0})' -f $(if ($p) { $p.Schema } else { '?' })) }
    if (-not (Test-SIProPackVersion ([string]$p.PackVersion))) { throw ("the pack's version '{0}' is not a pack version" -f $p.PackVersion) }
    $rows = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($it in @($p.Items)) {
        $kind = [string]$it.Kind; $key = [string]$it.ItemKey; $name = '{0}/{1}' -f $kind, $key
        if ($script:SIProTemplatedKinds -notcontains $kind) {
            if (Test-SIProFormerTemplateKind $kind) { throw ("the pack holds '{0}' -- a template pack can never change a name (a setting) or the CMDB ownership map (your configuration); it is refused" -f $name) }
            throw ("the pack holds '{0}', which is not a templated kind" -f $name)
        }
        if ($seen.ContainsKey($name)) { throw ("the pack holds {0} twice" -f $name) }
        $seen[$name] = $true
        $body = [string]$it.Body; $fmt = [string]$it.Format
        if ((Get-SIProTextHash $body) -ne ([string]$it.BodyHash).Trim()) { throw ("{0}: the body does not match its BodyHash -- the pack is damaged" -f $name) }
        $ch = Get-SIProContentHash -Body $body -Format $fmt
        if ($ch -ne ([string]$it.ContentHash).Trim()) { throw ("{0}: the content hash in the pack is not what this code computes ({1})" -f $name, $ch) }
        if ($Context) {
            $why = @(Test-SIProItem -Kind $kind -Key $key -Body $body -Format $fmt -Context $Context)
            if ($why.Count) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'pack'; Reason = ($why -join '; ') }); continue }
        }
        $rows.Add([pscustomobject]@{ Kind = $kind; ItemKey = $key; TemplateVersion = [string]$it.Version; BodyJson = $body; Format = $fmt
            SortOrder = [int]$it.SortOrder; BodyHash = ([string]$it.BodyHash).Trim(); ContentHash = $ch; Source = [string]$it.Source
            Engine = [string]$it.Engine; Method = [string]$it.Method; Class = $(if (Test-SIProTemplateClassName ([string]$it.Class)) { [string]$it.Class } else { '' }) })
    }
    if ($p.PSObject.Properties['MinCodeVersion'] -and [string]$p.MinCodeVersion -and -not (Test-SIProPackVersion ([string]$p.MinCodeVersion))) { throw ("the pack's minimum code version '{0}' is not a version" -f $p.MinCodeVersion) }
    if ([int]$p.ItemCount -ne @($p.Items).Count) { throw ('the pack says {0} item(s) but holds {1}' -f $p.ItemCount, @($p.Items).Count) }
    [pscustomobject]@{ Pack = $p; Sha256 = $sha; Rows = $rows.ToArray(); Refused = $refused.ToArray() }
}

function Get-SIProPackScope {
    <# PURE. The pack's scope as a plain object (Full; Kinds; Methods; Items), tolerant of a missing Scope. #>
    param($Pack)
    $s = if ($Pack -and $Pack.PSObject.Properties['Scope']) { $Pack.Scope } elseif ($Pack -is [System.Collections.IDictionary]) { $Pack['Scope'] } else { $null }
    $get = { param($n) if ($null -eq $s) { $null } elseif ($s -is [System.Collections.IDictionary]) { $s[$n] } elseif ($s.PSObject.Properties[$n]) { $s.$n } else { $null } }
    [pscustomobject]@{ Full = [bool](& $get 'Full'); Kinds = @(@(& $get 'Kinds') | Where-Object { $_ }); Methods = @(@(& $get 'Methods') | Where-Object { $_ }); Items = @(@(& $get 'Items') | Where-Object { $_ })
        Classes = @(@(& $get 'Classes') | Where-Object { $_ }) }
}

function Get-SIProScopeRowClass {
    <# A row's class -- computed only when the scope limits classes (#405); '' otherwise. #>
    param($Scope, $Row)
    if ($Scope -and $Scope.PSObject.Properties['Classes'] -and @($Scope.Classes | Where-Object { $_ }).Count) { return (Get-SIProRowClass -Row $Row) }
    ''
}

function Test-SIProInScope {
    <# PURE. Is an item (kind, name, method id, class) covered by a scope? Only covered items can be retired by a pack. A scope
       with Classes (#405: a Microsoft content pack, a roll back of one class) covers only items of those classes. #>
    param($Scope, [string]$Kind, [string]$Name, [string]$MethodId, [string]$Class)
    if ($Scope.PSObject.Properties['Classes'] -and @($Scope.Classes | Where-Object { $_ }).Count -and @($Scope.Classes) -notcontains $Class) { return $false }
    if (@($Scope.Kinds).Count -and @($Scope.Kinds) -notcontains $Kind) { return $false }
    if (@($Scope.Methods).Count -and @($Scope.Methods) -notcontains $MethodId) { return $false }
    if (@($Scope.Items).Count -and @($Scope.Items) -notcontains $Name) { return $false }
    $true
}

# =====================================================================================================================
#  THE DIFF, PER DETECTION METHOD, AND THE SELECTION FINGERPRINT
# =====================================================================================================================
function Get-SIProTemplatePackDiff {
    <#
        PURE. What releasing -Rows (a pack's, or a roll-back's) would do to the templates in force (-Existing: cfg.Template
        rows), within -Scope. One entry per item: Kind, ItemKey, Name, MethodId, Change = added | changed | retired |
        unchanged, OldHash, NewHash, and the customer's override on it (-Overrides: cfg.ItemOverride rows) -- Affected
        when the override is 'override' / 'disable' and the item changes. Methods: per method id the counts (Added,
        Changed, Retired, Unchanged, Affected), ordinal.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][object[]]$Existing = @(), [Parameter(Mandatory)]$Scope,
          [AllowEmptyCollection()][object[]]$Overrides = @())
    $have = @{}; foreach ($e in @($Existing | Where-Object { $_ })) { $have[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e }
    $ovr = @{}; foreach ($o in @($Overrides | Where-Object { $_ })) { $ovr[('{0}/{1}' -f (Get-SIProRowValue $o 'Kind'), (Get-SIProRowValue $o 'ItemKey'))] = [string](Get-SIProRowValue $o 'State') }
    $items = New-Object System.Collections.Generic.List[object]
    $ship = @{}
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $name = '{0}/{1}' -f (Get-SIProRowValue $r 'Kind'), (Get-SIProRowValue $r 'ItemKey'); $ship[$name] = $true
        $e = $have[$name]
        $live = $e -and ($null -eq (Get-SIProRowValue $e 'RetiredAt'))
        $new = Get-SIProRowContentHash $r
        $old = if ($live) { Get-SIProRowContentHash $e } else { '' }
        $change = if (-not $live) { 'added' } elseif ($old -ne $new) { 'changed' } else { 'unchanged' }
        $items.Add([pscustomobject]@{ Kind = [string](Get-SIProRowValue $r 'Kind'); ItemKey = [string](Get-SIProRowValue $r 'ItemKey'); Name = $name
            MethodId = (Get-SIProRowMethodId $r); Change = $change; OldHash = $old; NewHash = $new; Override = [string]$ovr[$name] })
    }
    foreach ($name in @($have.Keys)) {
        if ($ship.ContainsKey($name)) { continue }
        $e = $have[$name]
        if ($null -ne (Get-SIProRowValue $e 'RetiredAt')) { continue }
        $kind = [string](Get-SIProRowValue $e 'Kind'); $mid = Get-SIProRowMethodId $e
        if (-not (Test-SIProInScope -Scope $Scope -Kind $kind -Name $name -MethodId $mid -Class (Get-SIProScopeRowClass -Scope $Scope -Row $e))) { continue }
        $items.Add([pscustomobject]@{ Kind = $kind; ItemKey = [string](Get-SIProRowValue $e 'ItemKey'); Name = $name; MethodId = $mid; Change = 'retired'
            OldHash = (Get-SIProRowContentHash $e); NewHash = ''; Override = [string]$ovr[$name] })
    }
    $all = $items.ToArray()
    $all = @(foreach ($i in (Get-SIProOrdinalOrder -Keys @($all | ForEach-Object { $_.Name }))) { $all[$i] })
    foreach ($i in $all) { $i | Add-Member -NotePropertyName Affected -NotePropertyValue ($i.Change -ne 'unchanged' -and $i.Override -in 'override', 'disable') }
    $mids = [string[]]@($all | ForEach-Object { $_.MethodId } | Select-Object -Unique); if ($mids.Count -gt 1) { [Array]::Sort($mids, [System.StringComparer]::Ordinal) }
    $methods = foreach ($m in $mids) {
        $g = @($all | Where-Object { $_.MethodId -eq $m })
        [pscustomobject]@{ Id = $m; Engine = $m.Substring(0, $m.IndexOf('/')); Method = $m.Substring($m.IndexOf('/') + 1)
            Added = @($g | Where-Object { $_.Change -eq 'added' }).Count; Changed = @($g | Where-Object { $_.Change -eq 'changed' }).Count
            Retired = @($g | Where-Object { $_.Change -eq 'retired' }).Count; Unchanged = @($g | Where-Object { $_.Change -eq 'unchanged' }).Count
            Affected = @($g | Where-Object { $_.Affected }).Count }
    }
    [pscustomobject]@{ Items = $all; Methods = @($methods) }
}

function Get-SIProSelectionFingerprint {
    <#
        PURE. The fingerprint of WHAT IS ACCEPTED: over the diff items of the selected method ids ('*' or none = all),
        '<kind>/<key>=<NewHash>' or '<kind>/<key>=retired', ordinal, newline-joined, SHA-256. '' when nothing is selected.
    #>
    param([Parameter(Mandatory)]$Diff, [AllowEmptyCollection()][string[]]$Methods = @())
    $all = (-not $Methods) -or ($Methods -contains '*')
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Diff.Items)) {
        if (-not $all -and $Methods -notcontains $i.MethodId) { continue }
        $lines.Add(('{0}={1}' -f $i.Name, $(if ($i.Change -eq 'retired') { 'retired' } else { $i.NewHash })))
    }
    if ($lines.Count -eq 0) { return '' }
    $a = $lines.ToArray(); [Array]::Sort($a, [System.StringComparer]::Ordinal)
    Get-SIProTextHash ($a -join "`n")
}

function Get-SIProSelectionPlan {
    <#
        PURE. Narrow a publish plan (Get-SITemplatePublishPlan over the selected rows) to the selection: a retire is kept
        only for an item of a selected method that the scope covers. (The plan retires by kind; a pack retires by method.)
    #>
    param([AllowEmptyCollection()][object[]]$Plan = @(), [AllowEmptyCollection()][object[]]$Existing = @(), [Parameter(Mandatory)]$Scope,
          [AllowEmptyCollection()][string[]]$Methods = @())
    $all = (-not $Methods) -or ($Methods -contains '*')
    $have = @{}; foreach ($e in @($Existing | Where-Object { $_ })) { $have[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e }
    @(foreach ($p in @($Plan | Where-Object { $_ })) {
        if ($p.Action -ne 'retire') { $p; continue }
        $name = '{0}/{1}' -f $p.Kind, $p.ItemKey
        $mid = Get-SIProRowMethodId $have[$name]
        if (-not (Test-SIProInScope -Scope $Scope -Kind $p.Kind -Name $name -MethodId $mid -Class (Get-SIProScopeRowClass -Scope $Scope -Row $have[$name]))) { continue }
        if (-not $all -and $Methods -notcontains $mid) { continue }
        $p
    })
}

# =====================================================================================================================
#  ROLL BACK -- a previous version's items, from cfg.TemplateRevision
# =====================================================================================================================
function Get-SIProRollbackRows {
    <#
        PURE. The template rows as they were at pack / release -Version, for the items of -Methods: per item that exists
        (or existed) in cfg.Template (-Templates), the newest revision (-Revisions) whose Version is not newer than -Version.
        An item with no such revision did not exist yet -- it is absent here, so the publish retires it. Source and
        SortOrder are today's (the revision keeps the content, not where it came from).
        Limitation: an item retired BEFORE -Version whose older revision is not newer than -Version comes back (revisions
        do not record when an item was retired).
    #>
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Revisions = @(), [Parameter(Mandatory)][string]$Version,
          [AllowEmptyCollection()][string[]]$Methods = @(),
          # #405: only items of these classes (the one-click roll back of Microsoft content: -Class microsoft)
          [AllowEmptyCollection()][string[]]$Class = @(), $Classification)
    $all = (-not $Methods) -or ($Methods -contains '*')
    $Class = @($Class | Where-Object { $_ })
    if ($Class.Count) { $Templates = @($Templates | Where-Object { $_ -and $Class -contains (Get-SIProRowClass -Row $_ -Classification $Classification) }) }
    $revs = @{}
    foreach ($r in @($Revisions | Where-Object { $_ })) {
        $v = [string](Get-SIProRowValue $r 'TemplateVersion'); if (-not $v) { $v = [string](Get-SIProRowValue $r 'Version') }
        if ((Compare-SIProPackVersion $v $Version) -gt 0) { continue }
        $name = '{0}/{1}' -f (Get-SIProRowValue $r 'Kind'), (Get-SIProRowValue $r 'ItemKey')
        $cur = $revs[$name]
        if (-not $cur -or (Compare-SIProPackVersion $v $cur.V) -gt 0) { $revs[$name] = @{ V = $v; R = $r } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Templates | Where-Object { $_ })) {
        $kind = [string](Get-SIProRowValue $t 'Kind'); $key = [string](Get-SIProRowValue $t 'ItemKey'); $name = '{0}/{1}' -f $kind, $key
        if (Test-SIProFormerTemplateKind $kind) { continue }   # #251: never brought back as a template
        $mid = Get-SIProRowMethodId $t
        if (-not $all -and $Methods -notcontains $mid) { continue }
        $hit = $revs[$name]; if (-not $hit) { continue }
        $body = [string](Get-SIProRowValue $hit.R 'BodyJson'); $fmt = [string](Get-SIProRowValue $hit.R 'Format'); if (-not $fmt) { $fmt = 'json' }
        $m = Get-SIProTemplateMethod -Kind $kind -ItemKey $key -Source ([string](Get-SIProRowValue $t 'Source')) -BodyJson ([string](Get-SIProRowValue $t 'BodyJson'))
        $out.Add([pscustomobject]@{ Kind = $kind; ItemKey = $key; TemplateVersion = $hit.V; BodyJson = $body; Format = $fmt
            SortOrder = [int](Get-SIProRowValue $t 'SortOrder'); BodyHash = (Get-SIProTextHash $body); ContentHash = (Get-SIProContentHash -Body $body -Format $fmt)
            Source = [string](Get-SIProRowValue $t 'Source'); Engine = $m.Engine; Method = $m.Method })
    }
    $out.ToArray()
}

# =====================================================================================================================
#  THE VENDOR'S RING CHANNEL FOR TEMPLATES (si-templates-rings.json in the update feed)
# =====================================================================================================================
function Get-SIProRingKey {
    <# PURE. r0 | r1 | r2 | r3 from 'r1', '1' or 1 -- the framework's rings: 0 dev, 1 test (internal), 2 design partners, 3 broad. Rings above 3 read r3 (the broadest approval). '' for none. #>
    param([AllowNull()][object]$Ring)
    if ($null -eq $Ring -or "$Ring".Trim() -eq '') { return '' }
    $t = "$Ring".Trim().ToLowerInvariant().TrimStart('r')
    $n = 0
    if (-not [int]::TryParse($t, [ref]$n) -or $n -lt 0) { throw "'$Ring' is not a ring (r0, r1, r2 or r3)" }
    'r{0}' -f [Math]::Min($n, 3)
}

function Set-SIProTemplateRingApproval {
    <#
        PURE. The templates ring document with -Ring approving -PackVersion (sha -Sha256). Every other ring entry and the
        history are kept; an entry is appended to History. Promotion order: approving r1 needs the version approved at r0
        before (now or in the history), r2 needs r1, r3 needs r2 -- unless -SkipRingOrder. Returns the new document (ordered).
    #>
    param($Document, [Parameter(Mandatory)][string]$Ring, [Parameter(Mandatory)][string]$PackVersion, [Parameter(Mandatory)][string]$Sha256,
          [Parameter(Mandatory)][string]$By, [datetime]$At = [datetime]::UtcNow, [switch]$SkipRingOrder)
    $rk = Get-SIProRingKey $Ring
    if ($rk -notin 'r0', 'r1', 'r2', 'r3') { throw "'$Ring' is not a ring (r0, r1, r2 or r3)" }
    $doc = [ordered]@{ Schema = 1; Solution = 'SecurityInsight'; Templates = [ordered]@{}; History = @() }
    if ($Document) {
        $src = if ($Document -is [string]) { ConvertFrom-SIProJson $Document } else { $Document }
        $t = $src.Templates
        if ($t) { foreach ($p in $t.PSObject.Properties) { $doc.Templates[$p.Name] = $p.Value } }
        $doc.History = @($src.History | Where-Object { $_ })
    }
    if (-not $SkipRingOrder -and $rk -ne 'r0') {
        $prev = 'r{0}' -f ([int]$rk.Substring(1) - 1)
        $ok = ($doc.Templates.Contains($prev) -and [string]$doc.Templates[$prev].Version -eq $PackVersion) -or
              @($doc.History | Where-Object { [string]$_.Ring -eq $prev -and [string]$_.Version -eq $PackVersion }).Count -gt 0
        if (-not $ok) { throw ("{0} cannot approve {1}: it was never approved at {2} (promote in order r0 -> r1 -> r2 -> r3, or pass -SkipRingOrder)" -f $rk, $PackVersion, $prev) }
    }
    $when = $At.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $doc.Templates[$rk] = [ordered]@{ Version = $PackVersion; Sha256 = $Sha256.ToLowerInvariant(); ApprovedAt = $when; ApprovedBy = $By }
    $ordered = [ordered]@{}; foreach ($k in @('r0', 'r1', 'r2', 'r3')) { if ($doc.Templates.Contains($k)) { $ordered[$k] = $doc.Templates[$k] } }
    $doc.Templates = $ordered
    $hist = @($doc.History) + @([ordered]@{ Ring = $rk; Version = $PackVersion; Sha256 = $Sha256.ToLowerInvariant(); At = $when; By = $By })
    if ($hist.Count -gt 200) { $hist = @($hist | Select-Object -Last 200) }
    $doc.History = $hist
    $doc
}

function Get-SIProTemplateRingDecision {
    <#
        PURE. For an install: which pack its ring approves, and whether to act. -RingsDocument: the feed's
        si-templates-rings.json (text or object; $null = the feed has no template channel), -Ring: the install's ring
        from the ring plan ($null = not ring-managed), -Installed: the pack version recorded on the install.
        Returns @{ Act; RingKey; Version; Sha256; Reason }.
    #>
    param($RingsDocument, [AllowNull()][object]$Ring, [AllowEmptyString()][string]$Installed)
    if ($null -eq $RingsDocument -or "$RingsDocument" -eq '') { return [pscustomobject]@{ Act = $false; RingKey = ''; Version = ''; Sha256 = ''; Reason = 'the update feed has no template channel' } }
    $doc = if ($RingsDocument -is [string]) { ConvertFrom-SIProJson $RingsDocument } else { $RingsDocument }
    $rk = Get-SIProRingKey $Ring
    if (-not $rk) { return [pscustomobject]@{ Act = $false; RingKey = ''; Version = ''; Sha256 = ''; Reason = 'this install is not on an update ring -- it takes only ring-approved template packs' } }
    $e = if ($doc.Templates -and $doc.Templates.PSObject.Properties[$rk]) { $doc.Templates.$rk } else { $null }
    if (-not $e -or -not (Test-SIProPackVersion ([string]$e.Version))) { return [pscustomobject]@{ Act = $false; RingKey = $rk; Version = ''; Sha256 = ''; Reason = "ring $rk approves no template pack" } }
    $v = [string]$e.Version; $sha = ([string]$e.Sha256).ToLowerInvariant()
    if ($sha -notmatch '^[0-9a-f]{64}$') { return [pscustomobject]@{ Act = $false; RingKey = $rk; Version = $v; Sha256 = ''; Reason = "ring $rk names template pack $v without a usable SHA-256 -- ignored" } }
    if ($Installed -and (Compare-SIProPackVersion $v $Installed) -le 0) { return [pscustomobject]@{ Act = $false; RingKey = $rk; Version = $v; Sha256 = $sha; Reason = "template pack $Installed is installed; ring $rk approves $v -- nothing newer" } }
    [pscustomobject]@{ Act = $true; RingKey = $rk; Version = $v; Sha256 = $sha; Reason = ("ring {0} approves template pack {1}{2}" -f $rk, $v, $(if ($Installed) { " (installed: $Installed)" } else { '' })) }
}

function Get-SIProTemplateReleaseList {
    <#
        PURE. THE VENDOR CONSOLE CONTRACT (setup\Get-SITemplateReleases.ps1 prints it as JSON). -Packs: parsed packs
        (ConvertFrom-SIProTemplatePack results, plus .ShaFile = the sha in the .sha256 file, '' when missing),
        -RingsDocument: the feed's si-templates-rings.json. Per pack, newest first: version, code version, commit, sha
        (verified against the .sha256 file), full or partial, item count, the previous pack and what changed against it --
        in total and PER DETECTION METHOD (new / changed / retired rules) -- the rings that approve it now and every ring
        that ever approved it.
    #>
    param([AllowEmptyCollection()][object[]]$Packs = @(), $RingsDocument, [string]$Container = '')
    $doc = if ($RingsDocument -is [string] -and $RingsDocument) { ConvertFrom-SIProJson $RingsDocument } else { $RingsDocument }
    # oldest first by numeric version (an insertion sort: a handful of packs, and no culture involved)
    $list = New-Object System.Collections.Generic.List[object]; foreach ($p in $Packs) { if ($p) { $list.Add($p) } }
    $arr = $list.ToArray()
    for ($i = 1; $i -lt $arr.Count; $i++) { $j = $i; while ($j -gt 0 -and (Compare-SIProPackVersion ([string]$arr[$j - 1].Pack.PackVersion) ([string]$arr[$j].Pack.PackVersion)) -gt 0) { $t = $arr[$j - 1]; $arr[$j - 1] = $arr[$j]; $arr[$j] = $t; $j-- } }
    $rings = [ordered]@{}
    if ($doc -and $doc.Templates) { foreach ($p in $doc.Templates.PSObject.Properties) { $rings[$p.Name] = [ordered]@{ Version = [string]$p.Value.Version; Sha256 = [string]$p.Value.Sha256; ApprovedAt = [string]$p.Value.ApprovedAt; ApprovedBy = [string]$p.Value.ApprovedBy } } }
    $hist = if ($doc) { @($doc.History | Where-Object { $_ }) } else { @() }
    $out = for ($i = $arr.Count - 1; $i -ge 0; $i--) {
        $p = $arr[$i]; $v = [string]$p.Pack.PackVersion
        $prev = if ($i -gt 0) { $arr[$i - 1] } else { $null }
        $scope = Get-SIProPackScope $p.Pack
        $diff = Get-SIProTemplatePackDiff -Rows @($p.Rows) -Existing $(if ($prev) { @($prev.Rows) } else { @() }) -Scope $scope
        $changedMethods = @($diff.Methods | Where-Object { $_.Added + $_.Changed + $_.Retired -gt 0 } | ForEach-Object {
            [ordered]@{ Id = $_.Id; Engine = $_.Engine; Method = $_.Method; New = $_.Added; Changed = $_.Changed; Retired = $_.Retired } })
        $now = [string[]]@($rings.Keys | Where-Object { $rings[$_].Version -eq $v })
        $ever = [string[]]@(@($now) + @($hist | Where-Object { [string]$_.Version -eq $v } | ForEach-Object { [string]$_.Ring }) | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
        [ordered]@{
            PackVersion = $v; CodeVersion = [string]$p.Pack.CodeVersion; Commit = [string]$p.Pack.Commit; Sha256 = $p.Sha256
            ShaVerified = ([string]$p.ShaFile -eq $p.Sha256); Full = [bool]$scope.Full; Kinds = @($scope.Kinds); Methods = @($scope.Methods)
            Items = [int]$p.Pack.ItemCount; Fingerprint = [string]$p.Pack.Fingerprint; Previous = $(if ($prev) { [string]$prev.Pack.PackVersion } else { '' })
            Changes = [ordered]@{ New = @($diff.Items | Where-Object { $_.Change -eq 'added' }).Count; Changed = @($diff.Items | Where-Object { $_.Change -eq 'changed' }).Count
                Retired = @($diff.Items | Where-Object { $_.Change -eq 'retired' }).Count; Unchanged = @($diff.Items | Where-Object { $_.Change -eq 'unchanged' }).Count }
            ChangedMethods = $changedMethods; ApprovedNow = @($now); ApprovedEver = @($ever)
        }
    }
    [ordered]@{ Schema = 1; Container = $Container; Rings = $rings; Packs = @($out) }
}

# =====================================================================================================================
#  STORE: the staged packs, the installed pack, the release record (guarded -- a database without the table says so)
# =====================================================================================================================
function Test-SIProTemplatePackSchema {
    <# Does the database have cfg.TemplatePackStaged? #>
    param([Parameter(Mandatory)]$Store)
    $r = @(& $Store.Invoke "SELECT CASE WHEN OBJECT_ID('cfg.TemplatePackStaged') IS NULL THEN 0 ELSE 1 END AS HasPackStaged" @{} 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
    [bool]($r -and [int](Get-SIProRowValue $r 'HasPackStaged') -eq 1)
}

function Save-SIProTemplatePackStaged {
    <#
        Stage an available pack: the pack text exactly as received (its SHA-256 is checked again here), with its version,
        fingerprint and scope. A version is staged once -- the same version with a DIFFERENT sha is refused (a pack is
        immutable once published); the same version with the same CONTENT fingerprint is 'Same' (the text staged first is
        kept). Returns 'Staged' | 'Same' | 'Conflict' | 'Missing'.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][ValidateSet('feed', 'shipped', 'file')][string]$Origin, [string]$Ring)
    # #416: the same pack text is checked once per process (a full pack is 2.7 MB of JSON with 780 items whose hashes are
    # all verified -- seconds each time, and one update stages the shipped pack more than once)
    $memo = Get-SIProProcessCache -Name 'StagedPackSummary'
    $textSha = Get-SIProTextHash $Text
    if ($memo.ContainsKey($textSha)) { $sum = $memo[$textSha] }
    else {
        $parsed = ConvertFrom-SIProTemplatePack -Text $Text
        $sum = [pscustomobject]@{ Sha256 = $parsed.Sha256; Pack = [pscustomobject]@{ PackVersion = [string]$parsed.Pack.PackVersion; CodeVersion = [string]$parsed.Pack.CodeVersion
                                  Fingerprint = [string]$parsed.Pack.Fingerprint; ItemCount = [int]$parsed.Pack.ItemCount }; Scope = (Get-SIProPackScope $parsed.Pack) }
        if ($memo.Count -ge 16) { $memo.Clear() }
        $memo[$textSha] = $sum
    }
    $parsed = [pscustomobject]@{ Sha256 = $sum.Sha256 }
    $p = $sum.Pack; $scope = $sum.Scope
    $sql = @'
SET XACT_ABORT ON;
IF OBJECT_ID('cfg.TemplatePackStaged') IS NULL BEGIN SELECT 'Missing' AS Outcome; RETURN; END;
BEGIN TRAN;
DECLARE @have char(64), @haveFp nvarchar(64);
SELECT @have = Sha256, @haveFp = Fingerprint FROM cfg.TemplatePackStaged WITH (UPDLOCK, HOLDLOCK) WHERE PackVersion = @PackVersion;
IF @have IS NOT NULL AND @have = @Sha256 BEGIN COMMIT; SELECT 'Same' AS Outcome; RETURN; END;
-- the same version with the same CONTENT (rebuilt by a later release: only the code version / commit differ) is the same
-- pack -- the text staged first is kept
IF @have IS NOT NULL AND @haveFp = @Fingerprint BEGIN COMMIT; SELECT 'Same' AS Outcome; RETURN; END;
IF @have IS NOT NULL BEGIN ROLLBACK; SELECT 'Conflict' AS Outcome; RETURN; END;
INSERT cfg.TemplatePackStaged (PackVersion, CodeVersion, Sha256, Fingerprint, Ring, Origin, IsFull, ItemCount, ScopeJson, PackJson, StagedBy)
VALUES (@PackVersion, @CodeVersion, @Sha256, @Fingerprint, @Ring, @Origin, @IsFull, @ItemCount, @ScopeJson, @PackJson, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@LogName, 'install', 'pack-staged', 'Set', NULL, CONCAT(@PackVersion, ':', @Sha256), @By, CONCAT('template pack staged from the ', @Origin));
COMMIT;
SELECT 'Staged' AS Outcome;
'@
    $scopeJson = ConvertTo-SIProJson -Value ([ordered]@{ Full = $scope.Full; Kinds = @($scope.Kinds); Methods = @($scope.Methods); Items = @($scope.Items) }) -Canonical
    $rows = @(& $Store.Invoke $sql ([ordered]@{ PackVersion = [string]$p.PackVersion; CodeVersion = [string]$p.CodeVersion; Sha256 = $parsed.Sha256
        Fingerprint = [string]$p.Fingerprint; Ring = $(if ($Ring) { $Ring } else { $null }); Origin = $Origin; IsFull = [bool]$scope.Full
        ItemCount = [int]$p.ItemCount; ScopeJson = $scopeJson; PackJson = $Text; By = (Get-SIProSessionActor); LogName = $script:SIProReleaseLogName }) 'reader' | ForEach-Object { $_ })
    if ($rows.Count) { return [string](Get-SIProRowValue $rows[0] 'Outcome') }
    'Staged'
}

function Read-SIProTemplatePackStaged {
    <# The staged packs (no pack text), or one with its text (-PackVersion). Empty without the table. #>
    param([Parameter(Mandatory)]$Store, [string]$PackVersion)
    if ($PackVersion) {
        return @(& $Store.Invoke "IF OBJECT_ID('cfg.TemplatePackStaged') IS NOT NULL SELECT PackVersion, CodeVersion, Sha256, Fingerprint, Ring, Origin, IsFull, ItemCount, PackJson, StagedAt, StagedBy FROM cfg.TemplatePackStaged WHERE PackVersion = @PackVersion" @{ PackVersion = $PackVersion } 'reader' | ForEach-Object { $_ })
    }
    @(& $Store.Invoke "IF OBJECT_ID('cfg.TemplatePackStaged') IS NOT NULL SELECT PackVersion, CodeVersion, Sha256, Fingerprint, Ring, Origin, IsFull, ItemCount, StagedAt, StagedBy FROM cfg.TemplatePackStaged" @{} 'reader' | ForEach-Object { $_ })
}

function Read-SIProStagedPackText {
    <# One staged pack's text, checked against the SHA-256 it was staged with. Throws when absent or changed. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$PackVersion)
    $r = @(Read-SIProTemplatePackStaged -Store $Store -PackVersion $PackVersion) | Select-Object -First 1
    if (-not $r) { throw ("template pack {0} is not staged on this install" -f $PackVersion) }
    $text = [string](Get-SIProRowValue $r 'PackJson'); $sha = ([string](Get-SIProRowValue $r 'Sha256')).Trim().ToLowerInvariant()
    if ((Get-SIProTextHash $text) -ne $sha) { throw ("the staged template pack {0} does not match the SHA-256 it was staged with -- it was changed in the database" -f $PackVersion) }
    [pscustomobject]@{ Text = $text; Sha256 = $sha; Origin = [string](Get-SIProRowValue $r 'Origin'); Ring = [string](Get-SIProRowValue $r 'Ring') }
}

function Set-SIProTemplateRelease {
    <#
        Record a VERIFIED release (called only after the publish was read back): one cfg.ChangeLog row
        (Name 'template-release', Kind 'released'), and -- for a release of every method of a pack -- the installed pack
        (cfg.InstallState 'TemplatePack'). One transaction. The actor is the session; -RequestedBy (the web app user who
        accepted it) is part of the reason.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$PackVersion,
          # #405: 'code' = the fix + default templates of a code release (and its Microsoft content, unless a newer pack is
          # installed); 'auto' = a Microsoft content pack installed automatically; 'direct' = ring 1's direct install
          [Parameter(Mandatory)][ValidateSet('release', 'rollback', 'shipped', 'adopted', 'code', 'auto', 'direct')][string]$Mode,
          [AllowEmptyCollection()][string[]]$Methods = @(), [AllowEmptyString()][string]$SelectionFingerprint, [AllowEmptyString()][string]$Fingerprint,
          [bool]$Whole, [int]$Changed, [string]$RequestedBy,
          # #250: what the templates in force are against the pack -- 'as-released' (they are the pack) or 'customised' (an
          # existing install adopted with other templates). Recorded with a whole pack only (cfg.InstallState 'TemplatePackStatus').
          [ValidateSet('as-released', 'customised')][string]$Status = 'as-released',
          # #405: the code release the record belongs to (code / direct), and the classes it covered
          [string]$CodeVersion, [AllowEmptyCollection()][string[]]$Classes = @())
    $v = [ordered]@{ Mode = $Mode; Pack = $PackVersion; Methods = $(if ($Whole) { @('*') } else { @($Methods) }); Selection = $SelectionFingerprint; Fingerprint = $Fingerprint; Changed = $Changed; Status = $Status }
    if ($CodeVersion) { $v['Code'] = $CodeVersion }
    if (@($Classes | Where-Object { $_ }).Count) { $v['Classes'] = @($Classes | Where-Object { $_ }) }
    $value = ConvertTo-SIProJson -Value $v -Canonical
    $what = switch ($Mode) {
        'code'   { 'templates of SecurityInsight {0} installed with the code (fixes and defaults{1})' -f $CodeVersion, $(if ($Whole) { ', Microsoft content ' + $PackVersion } else { '; the newer Microsoft content in force is kept' }) }
        'auto'   { '{0} {1} installed automatically' -f $(if (@($Classes) -ccontains 'microsoft' -and @($Classes).Count -eq 1) { 'Microsoft content' } else { 'template pack' }), $PackVersion }
        'direct' { 'the current templates of SecurityInsight {0} installed directly (ring 1)' -f $CodeVersion }
        default  { '{0} of template pack {1}{2}' -f $Mode, $PackVersion, $(if ($Whole) { ' (every method)' } else { ' (' + @($Methods).Count + ' method(s))' }) }
    }
    $reason = '{0}{1}{2}' -f $what, $(if ($Status -eq 'customised') { ', customised: the templates in force differ from it' } else { '' }), $(if ($RequestedBy) { ', accepted by ' + $RequestedBy } else { '' })
    if ($reason.Length -gt 400) { $reason = $reason.Substring(0, 400) }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
IF @Whole = 1
BEGIN
    DECLARE @old nvarchar(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @StateName);
    IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = @StateName)
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@StateName, @Pack, @Pack, @By);
    ELSE
        UPDATE cfg.InstallState SET Value = @Pack, [Version] = @Pack, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @StateName;
    IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = @StatusName)
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@StatusName, @Status, @Pack, @By);
    ELSE
        UPDATE cfg.InstallState SET Value = @Status, [Version] = @Pack, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @StatusName;
END;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@LogName, 'install', 'released', 'Set', NULL, @Value, @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ StateName = $script:SIProPackStateName; StatusName = $script:SIProPackStatusName; Status = $Status; Pack = $PackVersion
        By = (Get-SIProSessionActor); Whole = [bool]$Whole; LogName = $script:SIProReleaseLogName; Value = $value; Reason = $reason }) 'nonquery'
}

function Read-SIProInstalledPack {
    <# The installed pack version (cfg.InstallState 'TemplatePack'), '' when none. #>
    param([Parameter(Mandatory)]$Store)
    $r = Read-SIProInstallState -Store $Store -Name $script:SIProPackStateName
    if ($r) { return ([string](Get-SIProRowValue $r 'Value')).Trim() }
    ''
}

function Read-SIProInstalledPackStatus {
    <# 'as-released' | 'customised' (cfg.InstallState 'TemplatePackStatus'); '' when none is recorded. #>
    param([Parameter(Mandatory)]$Store)
    $r = Read-SIProInstallState -Store $Store -Name $script:SIProPackStatusName
    if ($r) { return ([string](Get-SIProRowValue $r 'Value')).Trim() }
    ''
}

# =====================================================================================================================
#  #405 -- WHAT IS INSTALLED PER CLASS, AND THE CUSTOMER'S HOLD SWITCH
# =====================================================================================================================
function Read-SIProInstallStateValue {
    <# One cfg.InstallState value by name, '' when none (or no table). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Name)
    $r = Read-SIProInstallState -Store $Store -Name $Name
    if ($r) { return ([string](Get-SIProRowValue $r 'Value')).Trim() }
    ''
}

function Set-SIProInstallStateValue {
    <# Write one cfg.InstallState row (insert or update) -- what is installed per class (#405). The actor is the session. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][ValidateSet('TemplateCode', 'TemplateDirect', 'TemplatePackDeclined', 'TemplateMode')][string]$Name,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Value, [string]$Version)
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
    INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, @Version, @By);
ELSE
    UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Name = $Name; Value = $Value; Version = $(if ($Version) { $Version } else { $null }); By = (Get-SIProSessionActor); Reason = ('template state ' + $Name) }) 'nonquery'
}

function Read-SIProHoldMicrosoftContent {
    <#
        The customer's "Hold template packs" switch (SI_InvardiaUpdate_HoldMicrosoftContent; the name is kept -- it holds every template pack since 2026-10-11, the Pro settings catalog --
        read from SQL only, cfg.Setting scope 'solution'). OFF unless it is set to true. A database whose setting cannot be
        read counts as ON for this run: an automatic install is never made on a guess.
    #>
    param([Parameter(Mandatory)]$Store)
    try {
        $rows = @(& $Store.Invoke "IF OBJECT_ID(N'cfg.Setting') IS NULL SELECT CAST(NULL AS NVARCHAR(128)) AS Name, CAST(NULL AS NVARCHAR(MAX)) AS ValueJson WHERE 1 = 0; ELSE SELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'solution' AND Name = @Name;" @{ Name = $script:SIProHoldSettingName } 'reader' | ForEach-Object { $_ })
    } catch { return $true }
    foreach ($r in $rows) {
        if ([string](Get-SIProRowValue $r 'Name') -ne $script:SIProHoldSettingName) { continue }
        $v = ([string](Get-SIProRowValue $r 'ValueJson')).Trim().Trim('"').ToLowerInvariant()
        return ($v -in @('true', '1', 'on', 'yes'))
    }
    $false
}
