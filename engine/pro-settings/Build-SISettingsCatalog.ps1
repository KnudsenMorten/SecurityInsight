#Requires -Version 5.1
<#
.SYNOPSIS
    Builds config\settings.catalog.locked.json -- the list of settings the Settings page shows.

.DESCRIPTION
    Every `$global:` setting in the shipped configuration files, with its group, the comment written above it, its
    default and its type. Sources, in order of preference for the description:
      config\SecurityInsight.custom.reference.ps1            every documented setting, in numbered sections
      launcher\_lib\SecurityInsight.shared-defaults.ps1      solution defaults
      launcher\<engine>\LauncherConfig.defaults.ps1          engine defaults (the setting belongs to that engine)
      config\*.sample.ps1, launcher\<engine>\LauncherConfig.custom.sample.ps1
    A commented-out example (`# $global:X = ...`) counts: it documents a setting the code reads.

    The words a person reads come from config\settings.descriptions.locked.json, section "help", one entry per setting,
    written from the code that reads it: label (a plain display name), purpose, defaultText (what really applies when
    the setting is not set), effect (what changing it does), whenToChange, unit, advanced and group. A help entry wins
    over what the shipped files imply; a setting without one falls back to a name derived from its internal name, and
    the tool lists it so the entry gets written.

    The Pro Settings page layout comes from the same file: "categories" (shown one at a time) and "cards" (one topic,
    one Save, its settings in order) are copied into the catalog, each setting gets the card that lists it, its short
    "hint" and the on/off setting it "needs"; a list of mail addresses (MailTo, *_To) is marked itemFormat 'email'.

    It also rewrites the generated SETTINGS GLOSSARY block at the end of config\SecurityInsight.custom.reference.ps1 from
    the same text, so the Community reference and the Pro Settings page say the same thing. The block is comments only
    and is never read back as a source.

    Re-run after adding or documenting a setting; SI-SettingsPage.Tests fails when a shipped setting is missing or a
    setting has no help text.
#>
[CmdletBinding()]
param([string]$SIRoot)

$ErrorActionPreference = 'Stop'
# PS 5.1: $PSScriptRoot is empty inside a param default, so the root is resolved here.
if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
. (Join-Path $PSScriptRoot 'SI-Settings.ps1')
$re = '^\s*(#\s*)?\$global:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$'
$secretRe = '(Secret|Password|ApiKey|ClientSecret|Token|ConnectionString)$'
# Pro components (the ServiceNow connector, the vulnerability close-loop, correlation, asset properties). Their own
# engines are not in the public payload; a setting that only they read is Pro.
# SI_Pro_* = settings of the Pro platform itself (the SQL data backend, ...).
# SI_Exempted_* = how exempted findings are shown and counted (#264): exemptions exist only in Pro.
# SI_InvardiaUpdate_* = Pro updates from Invardia (Community updates from GitHub and has no such switch).
# SI_Bootstrap_WebAppCpu / _WebAppMemory / _SqlServiceObjective = the web app's and the Pro database's size (Pro only: Community has neither).
# SI_UpdateRing = the install's update ring, recorded in the Pro database (#308; Community keeps its ring in config\update.custom.json).
# SI_KeyFigures_* = the windows of the key figures (#859): the Executive overview / report / management mail are Pro (sidata).
$proRe = '^(SI_(Pro_|KeyFigures_|EnableServiceNow|ServiceNow|SN_|Cmdb_|Vuln|Correlation|AssetProperties|License|Exempted_|InvardiaUpdate_|UpdateRing$|Update_RenameDisplayNames$|Bootstrap_WebAppCpu$|Bootstrap_WebAppMemory$|Bootstrap_SqlServiceObjective$)|Mail_CloseLoop_)'
# Ranges the shipped files cannot say: written into the catalog, enforced by Test-SISettingValue (and the web app's port).
$ranges = @{ SI_Pro_DataRetentionDays = @{ min = 1 }; SI_PatchCycle_CatchUpDays = @{ min = 1 }
            # #859: the key figures' windows (Get-SIKeyFigureWindowSettings takes 1..3650; anything else = the default)
            SI_KeyFigures_RecentDays = @{ min = 1; max = 3650 }; SI_KeyFigures_MeanTimeToFixDays = @{ min = 1; max = 3650 }; SI_KeyFigures_StaleAdminDays = @{ min = 1; max = 3650 }
            # #860: the grace of the findings that are not patches (Get-SIProtectionScoreSettings takes 0..3650)
            SI_ProtectionScore_OtherGraceDays_Device = @{ min = 0; max = 3650 }; SI_ProtectionScore_OtherGraceDays_Identity = @{ min = 0; max = 3650 }
            SI_ProtectionScore_OtherGraceDays_CloudResource = @{ min = 0; max = 3650 }; SI_ProtectionScore_OtherGraceDays_PublicIp = @{ min = 0; max = 3650 }
 SI_Pro_DataLookbackDays = @{ min = 1 }; SI_VulnSync_CloseAfterRuns = @{ min = 1 }
            SI_Pro_AuditRetentionMonths = @{ min = 13 }; SI_Pro_ConfigBackupRetentionDays = @{ min = 1 }; SI_Pro_ConfigJournalRetentionDays = @{ min = 1 }; SI_Pro_CmdbSql_RetireAfterRuns = @{ min = 1 }; SI_Pro_CmdbSql_SeenWithinDays = @{ min = 1 }; SI_Cmdb_RetireAfterDays = @{ min = 1 }
            Mail_CloseLoop_Daily_SendTimeUtc = @{ pattern = '^([01][0-9]|2[0-3]):[0-5][0-9]$'; patternHint = 'HH:mm, UTC' }
            # #306: the daily pipeline's start time, local time in SI_Pipeline_TimeZone
            SI_Pipeline_StartTime = @{ pattern = '^([01][0-9]|2[0-3]):[0-5][0-9]$'; patternHint = 'HH:mm, local time' }
            # #301: full asset metadata -- a choice (security = off, full = on), its retention and its change guard
            SI_AssetProperties = @{ type = 'enum'; values = @('security', 'full') }
            # MAIL-1: how every mail is sent
            # the recommended choice first, shown as radio buttons with plain words (Settings and Get Started, #446) -- these
            # lived only in the generated catalog and were lost whenever it was rebuilt
            SI_Mail_Mode = @{ type = 'enum'; values = @('sharedMailbox', 'smtp', 'none'); editor = 'radio'
                              valueLabels = [ordered]@{ sharedMailbox = 'Shared mailbox (Office 365) -- recommended'; smtp = 'SMTP relay (your own mail server)'; none = 'No mail' } }
            # #477: the optional one-way copy of the provider records to Log Analytics
            SI_LaExport = @{ type = 'enum'; values = @('off', 'records') }
            # #491: which controls the setup report (uplink Kind=setup) carries -- the framework minimum until Invardia has imported SI's extras
            SI_Telemetry_SetupControls = @{ type = 'enum'; values = @('minimum', 'all', 'off') }
            SI_AssetProperties_RetentionDays = @{ min = 1 }; SI_AssetProperties_ChangeGuardPercent = @{ min = 1; max = 100 }
            # #528: how long the privilege tier catalog is kept while its inputs are unchanged (0 = rebuild every run)
            SI_PrivilegeTierClassifier_RefreshDays = @{ min = 0; max = 365 }
            # #534: how often the CI build rebuilds every CI while nothing it is made from changed (0 = every run)
            SI_CiBuild_FullReconcileDays = @{ min = 0; max = 365 }
            # the seconds the rules of one asset may take in the CI build before it goes on with the next (0 = no limit)
            SI_CiRulesBudgetSeconds = @{ min = 0 }
            # #308: the install's update ring -- the framework's rings 0 (dev) to 3 (broad)
            SI_UpdateRing = @{ min = 0; max = 3 }
            # owner 2026-10-18: a size support sets per install (empty = the product's) -- kept by every update, also when smaller
            SI_Bootstrap_SqlServiceObjective = @{ pattern = '^[Ss](1|2|3|4|6|7|9|12)$'; patternHint = 'S1, S2, S3, S4, S6, S7, S9 or S12; empty = the product''s rule' }
            SI_Bootstrap_WebAppCpu = @{ pattern = '^(0\.5|0\.75|[1-3](\.(0|25|5|75))?|4(\.0)?)$'; patternHint = '0.5 to 4 in steps of 0.25; empty = the product''s size' }
            SI_Bootstrap_WebAppMemory = @{ pattern = '^([1-8](\.(0|5))?)(Gi)?$'; patternHint = '1Gi to 8Gi in steps of 0.5Gi; empty = twice the CPU' }
            # #414: the vulnerability close limit (share of the open records; an optional number, 0 = none) and the collapse floor
            SI_VulnSync_MaxClosePercent = @{ min = 0; max = 100 }; SI_VulnSync_MaxCloseAbsolute = @{ min = 0 }; SI_VulnSync_CollapseFloor = @{ min = 0; max = 1 }
            # settings-honoured: the CI history retention, the ServiceNow CMDB connector and the vulnerability connectors' plan switch
            SI_Pro_CiChangeRetentionDays = @{ min = 1 }; SI_Pro_CiDailyRetentionDays = @{ min = 1 }; SI_Pro_FindingStateRetentionDays = @{ min = 1 }
            SI_Cmdb_Run = @{ type = 'enum'; values = @('plan', 'apply') }; SI_Cmdb_Mode = @{ type = 'enum'; values = @('match-only', 'create-if-unmatched') }
            SI_VulnSync_Run = @{ type = 'enum'; values = @('plan', 'apply') }; SI_Cmdb_RowLimit = @{ min = 0 }; SI_Correlation_RowLimit = @{ min = 0 }
            # #494: the days a finding has to be fixed, per severity (0 = no due date)
            SI_Pro_FindingSla_CriticalDays = @{ min = 0; max = 3650 }; SI_Pro_FindingSla_HighDays = @{ min = 0; max = 3650 }
            SI_Pro_FindingSla_MediumDays = @{ min = 0; max = 3650 }; SI_Pro_FindingSla_LowDays = @{ min = 0; max = 3650 }
            # #577: the data-quality warnings' limits (percent / percentage points, against the median of the last 3 runs)
            SI_Pro_DataQuality_AssetDropPercent = @{ min = 1; max = 100 }; SI_Pro_DataQuality_ReportDropPercent = @{ min = 1; max = 100 }
            SI_Pro_DataQuality_FillDropPoints = @{ min = 1; max = 100 }; SI_Pro_DataQuality_TierShiftPercent = @{ min = 1; max = 100 }
            # a source without a good collection for this many days: delivery waits (0 = never)
            SI_Pro_SourceDropout_HoldDeliveryDays = @{ min = 0; max = 365 }; SI_Pro_Pipeline_FirstRunRestarts = @{ min = 0 }
            # a collection that completes with far fewer assets: keep the last good one until confirmed, or take it at once
            SI_Pro_SourceDropout_AssetDropAction = @{ type = 'enum'; values = @('confirm', 'accept') }; SI_Pro_LifecycleStaleOpenRepair = @{ type = 'enum'; values = @('off', 'count', 'apply') }
            # the database write pace: the load (percent) above which the large writers slow down, and below which they go back
            SI_SqlPacing_HighPercent = @{ min = 1; max = 100 }; SI_SqlPacing_LowPercent = @{ min = 0; max = 99 } }

# Settings ONLY setup reads (Bootstrap-ContainerAppJob.ps1, Bootstrap-Auth.ps1, setup\*): marked setupOnly. Held to the code by
# SIv3-SettingsHonoured.Tests.ps1 (every one is read by setup only, and every catalog setting read by setup only is listed).
$setupOnly = @('SI_Bootstrap_Engines', 'SI_Bootstrap_EnvName', 'SI_Bootstrap_GrantTaggingRoles', 'SI_Bootstrap_ImageTag', 'SI_Bootstrap_KedaMaxReplicas',
    'SI_Bootstrap_Location', 'SI_Bootstrap_ParallelismAzure', 'SI_Bootstrap_ParallelismEndpoint', 'SI_Bootstrap_ParallelismIdentity',
    'SI_Bootstrap_ParallelismSchemaDiscovery', 'SI_Bootstrap_ScheduleAssetTagging', 'SI_Bootstrap_ScheduleAzure', 'SI_Bootstrap_ScheduleConfigBackup',
    'SI_Bootstrap_ScheduleEndpoint', 'SI_Bootstrap_ScheduleIdentity', 'SI_Bootstrap_ScheduleRiskAnalysis', 'SI_Bootstrap_ScheduleSchemaDiscovery',
    'SI_Bootstrap_ScheduleTrend', 'SI_Bootstrap_SkipImageBuild', 'SI_Bootstrap_TaggingIdentityName', 'SI_Bootstrap_TaggingScopes',
    'SI_Bootstrap_TriggerNowAfter', 'SI_Bootstrap_UseClientSecret', 'SI_Bootstrap_UseManagedIdentity', 'SI_LicenseRequest_Edition', 'SI_RebuildAuthBlock',
    'SI_RiskAnalysis_BuildSummaryByAI', 'SI_RiskAnalysis_ExportContainer', 'SI_RiskAnalysis_ExportDestination', 'SI_RiskAnalysis_ExportPrefix',
    'SI_RiskAnalysis_Mode', 'SI_RiskAnalysis_ReportTemplate', 'SI_RiskAnalysis_SendToLogAnalytics')

function Get-Entries([string]$Path, [string]$Engine, [string]$Kind) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $lines = [System.IO.File]::ReadAllLines($Path)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $section = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        # the generated glossary at the end of the reference is output of this tool, never a source
        if ($l -match '^# >>> SETTINGS GLOSSARY') { break }
        if ($l -match '^#\s*(\d+[a-z]?)\.\s+(.+?)\s*$') { $section = ($Matches[2] -split '\s{2,}--\s{2,}|\s+--\s+')[0].Trim(); continue }
        if ($l -notmatch $re) { continue }
        $name = $Matches[2]; $rhs = $Matches[3]; $commented = [bool]$Matches[1]
        # the comment block right above, stopping at a ruler, a blank line or another assignment
        $doc = New-Object System.Collections.Generic.List[string]
        for ($k = $i - 1; $k -ge 0; $k--) {
            $p = $lines[$k]
            if ($p -notmatch '^\s*#' -or $p -match '^\s*#\s*[=\-]{4,}' -or $p -match $re) { break }
            $doc.Insert(0, ($p -replace '^\s*#\s?', '').TrimEnd())
        }
        $rhsCode = ($rhs -replace '\s+#.*$', '').Trim()
        # a comment on the same line documents the setting when nothing is written above it
        if ($doc.Count -eq 0 -and $rhs -match '\s#\s*(.+)$') { $doc.Add($Matches[1].Trim()) }
        $val = $null; $lit = $false
        try {
            $a = @(Get-SIPs1Assignments -Text ('$global:x = ' + $rhsCode))
            if ($a.Count -and $a[0].Literal) { $val = $a[0].Value; $lit = $true }
        } catch { }
        [void]$seen.Add($name)
        [pscustomobject]@{ Name = $name; Engine = $Engine; Kind = $Kind; Section = $section; Doc = (($doc -join ' ') -replace '\s+', ' ').Trim()
                           Commented = $commented; Literal = $lit; Value = $val; Code = $rhsCode }
    }
    # Second pass with the parser: a default set inside a guard -- `if (-not $global:X) { $global:X = 'v' }` -- is not at
    # the start of its line, and the line pattern above misses it.
    foreach ($a in @(Get-SIPs1Assignments -Text ([System.IO.File]::ReadAllText($Path)))) {
        if ($seen.Contains($a.Name)) { continue }
        [void]$seen.Add($a.Name)
        $doc = New-Object System.Collections.Generic.List[string]
        for ($k = $a.Line - 2; $k -ge 0; $k--) {
            $p = $lines[$k]
            if ($p -notmatch '^\s*#' -or $p -match '^\s*#\s*[=\-]{4,}' -or $p -match $re) { break }
            $doc.Insert(0, ($p -replace '^\s*#\s?', '').TrimEnd())
        }
        [pscustomobject]@{ Name = $a.Name; Engine = $Engine; Kind = $Kind; Section = ''; Doc = (($doc -join ' ') -replace '\s+', ' ').Trim()
                           Commented = $false; Literal = $a.Literal; Value = $a.Value; Code = $a.ValueText }
    }
}

$all = New-Object System.Collections.Generic.List[object]
$ref = Join-Path $SIRoot 'config\SecurityInsight.custom.reference.ps1'
foreach ($e in @(Get-Entries $ref '' 'reference')) { $all.Add($e) }
foreach ($e in @(Get-Entries (Join-Path $SIRoot 'launcher\_lib\SecurityInsight.shared-defaults.ps1') '' 'default')) { $all.Add($e) }
foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $SIRoot 'launcher') -Directory | Where-Object Name -ne '_lib' | Sort-Object Name)) {
    foreach ($e in @(Get-Entries (Join-Path $d.FullName 'LauncherConfig.defaults.ps1') $d.Name 'default')) { $all.Add($e) }
    foreach ($e in @(Get-Entries (Join-Path $d.FullName 'LauncherConfig.custom.sample.ps1') $d.Name 'sample')) { $all.Add($e) }
}
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $SIRoot 'config') -Filter '*.sample.ps1')) {
    foreach ($e in @(Get-Entries $f.FullName '' 'sample')) { $all.Add($e) }
}

function Get-Label([string]$Name) {
    $n = $Name -replace '^SI_', ''
    $parts = $n -split '_'
    $split = ($parts[0] -creplace '([a-z0-9])([A-Z])', '$1 $2' -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2') -split ' '
    # an acronym (AI, SMTP, KQL) keeps its capitals; ordinary words are lower case
    $words = (@($split | ForEach-Object { if ($_ -cmatch '^[A-Z0-9]{2,}$') { $_ } else { $_.ToLowerInvariant() } }) -join ' ')
    $words = $words.Substring(0, 1).ToUpperInvariant() + $words.Substring(1)
    if ($parts.Count -gt 1) { $words += ' (' + (($parts[1..($parts.Count - 1)]) -join ' ').ToLowerInvariant() + ')' }
    $words
}

function Get-GroupName([string]$Group, [string[]]$Engines) {
    # The reference file's bookkeeping sections are not a topic a customer recognises -- those settings are shown
    # under their engine, or as "Other settings". Section titles are upper case in the file; shown in sentence case.
    $gr = ($Group -replace '\s*\(added[^)]*\)', '').Trim()
    if ($gr -match 'NEVER LISTED|NEW IN 3\.0') { if (@($Engines).Count -eq 1) { return 'Engine: ' + $Engines[0] } else { return 'Other settings' } }
    if ($gr -cmatch '[a-z]') { return $gr }
    $s = $gr.Substring(0, 1) + $gr.Substring(1).ToLowerInvariant()
    $s -replace '\bopenai\b', 'OpenAI' -replace '\bai\b', 'AI'
}

# Descriptions for settings no shipped file comments on, written from how the code reads them. A comment wins.
$descFallback = @{}
$descPath = Join-Path $SIRoot 'config\settings.descriptions.locked.json'
if (Test-Path -LiteralPath $descPath) {
    $dj = Get-Content -LiteralPath $descPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($p in $dj.descriptions.PSObject.Properties) { $descFallback[$p.Name] = [string]$p.Value }
}
# The text a person reads -- label, purpose, real default, effect, when to change, unit, advanced, group.
$help = @{}
if ($dj -and $dj.PSObject.Properties['help']) { foreach ($p in $dj.help.PSObject.Properties) { $help[$p.Name] = $p.Value } }
# The areas, in the order they are shown, each with its one-line description.
$groupList = @()
if ($dj -and $dj.PSObject.Properties['groups']) { $groupList = @($dj.groups | ForEach-Object { [ordered]@{ name = [string]$_.name; description = [string]$_.description } }) }
# Settings that no longer exist (section "retired"): written to the catalog's "retired" list -- a value left for one is
# ignored without a word -- and never listed as a setting, even if an older shipped file still mentions it.
$retired = @()
if ($dj -and $dj.PSObject.Properties['retired']) { $retired = @($dj.retired.PSObject.Properties | ForEach-Object { [string]$_.Name } | Sort-Object) }
# How the Pro Settings page lays the settings out: its categories (one shown at a time; each lists the groups whose
# settings it shows when they name no card) and its cards (one per topic, one Save each), in order.
$categoryList = @()
if ($dj -and $dj.PSObject.Properties['categories']) {
    $categoryList = @($dj.categories | ForEach-Object { [ordered]@{ name = [string]$_.name; description = [string]$_.description; groups = @($_.groups | Where-Object { $_ } | ForEach-Object { [string]$_ }) } })
}
$cardList = @()
$cardOf = @{}
if ($dj -and $dj.PSObject.Properties['cards']) {
    $cardList = @($dj.cards | ForEach-Object {
        $k = $_
        $names = @($k.settings | Where-Object { $_ } | ForEach-Object { [string]$_ })
        foreach ($n in $names) { $cardOf[$n] = [string]$k.name }
        [ordered]@{ name = [string]$k.name; category = [string]$k.category; description = [string]$k.description; settings = $names }
    })
}
# A list of mail addresses: the page edits it as address chips and refuses an entry that is not an address.
$mailListRe = '^(MailTo|.+_To)$'
$helpFields = 'label', 'purpose', 'defaultText', 'effect', 'whenToChange', 'group'
function Get-HelpValue([string]$Name, [string]$Field) {
    if (-not $help.ContainsKey($Name)) { return $null }
    $h = $help[$Name]
    if (-not $h.PSObject.Properties[$Field]) { return $null }
    $v = $h.$Field
    if ($v -is [string] -and [string]::IsNullOrWhiteSpace($v)) { return $null }
    $v
}

$settings = foreach ($g in @($all | Where-Object { $retired -notcontains $_.Name } | Group-Object Name | Sort-Object Name)) {
    $es = @($g.Group)
    $name = $g.Name
    $engines = @($es | Where-Object { $_.Engine -and $_.Kind -eq 'default' } | ForEach-Object Engine | Sort-Object -Unique)
    if ($engines.Count -eq 0) { $engines = @($es | Where-Object Engine | ForEach-Object Engine | Sort-Object -Unique) }
    $refE = @($es | Where-Object Kind -eq 'reference')
    $defE = @($es | Where-Object { $_.Kind -eq 'default' })
    $docE = @($refE + $defE + @($es | Where-Object Kind -eq 'sample')) | Where-Object { $_.Doc } | Select-Object -First 1
    $litE = @($defE + $refE + @($es | Where-Object Kind -eq 'sample')) | Where-Object Literal | Select-Object -First 1
    $type = 'text'
    if ($litE) {
        $v = $litE.Value
        if ($v -is [bool]) { $type = 'bool' }
        elseif ($v -is [int] -or $v -is [long]) { $type = 'int' }
        elseif ($v -is [double] -or $v -is [decimal]) { $type = 'number' }
        elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $type = 'list' }
    }
    $group = if ($refE.Count -and $refE[0].Section) { $refE[0].Section } elseif ($engines.Count -eq 1) { 'Engine: ' + $engines[0] } else { 'Solution' }
    $default = $null; $defaultText = $null
    if ($defE.Count) { if ($defE[-1].Literal) { $default = $defE[-1].Value } else { $defaultText = $defE[-1].Code } }
    $secret = ($name -match $secretRe) -or ($name -match 'Secret')
    $advanced = ($refE.Count -eq 0) -or ($group -match 'NEVER LISTED')
    $hAdv = Get-HelpValue $name 'advanced'
    if ($null -ne $hAdv) { $advanced = [bool]$hAdv }
    # defaultText is what a person reads as the default. The help text says what really applies; without it a secret
    # shows nothing and anything else shows the code that sets it.
    $hDef = Get-HelpValue $name 'defaultText'
    $entry = [ordered]@{
        name         = $name
        label        = $(if (Get-HelpValue $name 'label') { [string](Get-HelpValue $name 'label') } else { Get-Label $name })
        group        = $(if (Get-HelpValue $name 'group') { [string](Get-HelpValue $name 'group') } else { Get-GroupName $group $engines })
        type         = $type
        engines      = @($engines)
        edition      = $(if ($name -match $proRe) { 'pro' } else { 'community' })
        secret       = [bool]$secret
        advanced     = [bool]$advanced
        default      = $(if ($secret) { $null } else { $default })
        defaultText  = $(if ($hDef) { [string]$hDef } elseif ($secret) { $null } else { $defaultText })
        description  = $(if ($docE) { $docE.Doc } elseif ($descFallback.ContainsKey($name)) { [string]$descFallback[$name] } else { '' })
        purpose      = [string](Get-HelpValue $name 'purpose')
        effect       = [string](Get-HelpValue $name 'effect')
        whenToChange = [string](Get-HelpValue $name 'whenToChange')
    }
    $hUnit = Get-HelpValue $name 'unit'
    if ($hUnit) { $entry['unit'] = [string]$hUnit }
    # A fixed set of choices (#288): type 'enum' + the allowed values -- the Settings page shows a dropdown, and
    # Test-SISettingValue (and its C# port) refuse anything else. valueLabels are the plain words per value.
    $hValues = @(Get-HelpValue $name 'values' | Where-Object { $_ -ne $null } | ForEach-Object { [string]$_ })
    if ([string](Get-HelpValue $name 'type') -eq 'enum' -and $hValues.Count -gt 0) {
        $entry['type'] = 'enum'
        $entry['values'] = @($hValues)
        $hLabels = Get-HelpValue $name 'valueLabels'
        if ($hLabels) {
            $vl = [ordered]@{}
            foreach ($v in $hValues) { if ($hLabels.PSObject.Properties[$v]) { $vl[$v] = [string]$hLabels.$v } }
            if ($vl.Count) { $entry['valueLabels'] = $vl }
        }
    }
    if ($ranges.ContainsKey($name)) { foreach ($k in $ranges[$name].Keys) { $entry[$k] = $ranges[$name][$k] } }
    # the Settings page layout: the card it sits on, its one short hint, the on/off setting it needs
    if ($cardOf.ContainsKey($name)) { $entry['card'] = $cardOf[$name] }
    foreach ($f in 'hint', 'needs') { $hv = Get-HelpValue $name $f; if ($hv) { $entry[$f] = [string]$hv } }
    if ($entry['type'] -eq 'list' -and $name -match $mailListRe) { $entry['itemFormat'] = 'email' }
    # read only by setup (owner 2026-10-10: "show setup-time settings read-only with a note"): the Pro Settings page shows it
    # read-only, "changed by running setup" -- a value stored in the database would change nothing until setup runs again
    if ($setupOnly -contains $name) { $entry['setupOnly'] = $true }
    $entry
}

# "More info" per setting (framework SETTING-INFO-1): composed from the help words + config\settings.info.locked.json.
. (Join-Path $PSScriptRoot 'SI-SettingInfo.ps1')
$infoPath = Join-Path $SIRoot 'config\settings.info.locked.json'
$infoSrc = $null
if (Test-Path -LiteralPath $infoPath) { $infoSrc = Get-Content -LiteralPath $infoPath -Raw | ConvertFrom-Json }
$groupRisk = @{}
if ($infoSrc -and $infoSrc.PSObject.Properties['groupRisk']) { foreach ($p in $infoSrc.groupRisk.PSObject.Properties) { $groupRisk[$p.Name] = [string]$p.Value } }
$authoredInfo = @{}
if ($infoSrc -and $infoSrc.PSObject.Properties['settings']) { foreach ($p in $infoSrc.settings.PSObject.Properties) { $authoredInfo[$p.Name] = $p.Value } }
$labelByName = @{}
foreach ($s in @($settings)) { $labelByName[[string]$s.name] = [string]$s.label }
$labelOf = { param($n) if ($labelByName.ContainsKey($n)) { $labelByName[$n] } else { $n } }.GetNewClosure()
foreach ($s in @($settings)) {
    $au = $null; if ($authoredInfo.ContainsKey([string]$s.name)) { $au = $authoredInfo[[string]$s.name] }
    $s['info'] = Get-SISettingInfo -Setting $s -Authored $au -GroupRisk $groupRisk -LabelOf $labelOf
}
$unknownInfo = @($authoredInfo.Keys | Where-Object { -not $labelByName.ContainsKey($_) })
if ($unknownInfo.Count) { Write-Warning ("config\settings.info.locked.json names setting(s) the catalog does not have: {0}" -f ($unknownInfo -join ', ')) }

# A setting without its help text is shown by a name derived from its internal name. Say which, and which fields.
$noHelp = @(foreach ($s in $settings) {
    $miss = @(foreach ($f in $helpFields) { if (-not (Get-HelpValue $s.name $f)) { $f } })
    if ($miss.Count) { '{0}: {1}' -f $s.name, ($miss -join ', ') }
})
if ($noHelp.Count) {
    Write-Warning ("{0} setting(s) have no complete help entry in config\settings.descriptions.locked.json (section help):`n  {1}" -f $noHelp.Count, ($noHelp -join "`n  "))
}

$out = [ordered]@{
    _purpose  = 'The settings SecurityInsight Pro manages (its web app validates by them). GENERATED by engine\pro-settings\Build-SISettingsCatalog.ps1 from the shipped configuration files -- do not edit by hand; re-run the tool.'
    sources   = @('config\SecurityInsight.custom.reference.ps1', 'launcher\_lib\SecurityInsight.shared-defaults.ps1', 'launcher\<engine>\LauncherConfig.defaults.ps1', 'config\*.sample.ps1', 'launcher\<engine>\LauncherConfig.custom.sample.ps1', 'config\settings.descriptions.locked.json')
    groups    = @($groupList)
    categories = @($categoryList)
    cards     = @($cardList)
    settings  = @($settings)
    retired   = @($retired)
}
$json = $out | ConvertTo-Json -Depth 6
$path = Join-Path $SIRoot 'config\settings.catalog.locked.json'
[System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("settings catalog: {0} settings -> {1}" -f @($settings).Count, $path)

# ---- the SETTINGS GLOSSARY at the end of the Community reference: the same words, as comments ----
function Split-GlossaryText([string]$Text, [int]$Width) {
    $out = New-Object System.Collections.Generic.List[string]; $line = ''
    foreach ($w in @($Text -split '\s+' | Where-Object { $_ })) {
        if ($line.Length -and ($line.Length + 1 + $w.Length) -gt $Width) { $out.Add($line); $line = $w } else { $line = ($line + ' ' + $w).Trim() }
    }
    if ($line) { $out.Add($line) }
    $out
}
$glossaryStart = '# >>> SETTINGS GLOSSARY -- generated by engine\pro-settings\Build-SISettingsCatalog.ps1; do not edit by hand >>>'
$glossaryEnd = '# <<< SETTINGS GLOSSARY <<<'
if (Test-Path -LiteralPath $ref) {
    $bytes = [System.IO.File]::ReadAllBytes($ref)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $text = [System.IO.File]::ReadAllText($ref)
    $nl = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $at = $text.IndexOf($glossaryStart)
    if ($at -ge 0) { $text = $text.Substring(0, $at) }
    $text = $text.TrimEnd() + $nl
    $g = New-Object System.Collections.Generic.List[string]
    $g.Add($glossaryStart)
    $g.Add('# Every Community setting in plain words: what it is for, what applies when you do not set it, what changing it')
    $g.Add('# does, and when you would. Settings marked (advanced) are tuning and diagnostic knobs most installs never change.')
    $g.Add('# The SecurityInsight Pro Settings page shows the same text.')
    $comm = @($settings | Where-Object { $_.edition -ne 'pro' })
    $order = @($groupList | ForEach-Object { $_.name })
    foreach ($grp in @($comm | Group-Object { $_.group } | Sort-Object @{ e = { $i = [array]::IndexOf($order, $_.Name); if ($i -lt 0) { 999 } else { $i } } }, Name)) {
        $g.Add('#'); $g.Add('# ' + ('-' * 100)); $g.Add('# ' + $grp.Name)
        $gd = @($groupList | Where-Object { $_.name -eq $grp.Name } | ForEach-Object { $_.description })
        if ($gd.Count) { foreach ($l in @(Split-GlossaryText ([string]$gd[0]) 98)) { $g.Add('# ' + $l) } }
        $g.Add('# ' + ('-' * 100))
        foreach ($s in @($grp.Group | Sort-Object @{ e = { [bool]$_.advanced } }, @{ e = { $_.label } })) {
            $tags = @(); if (@($s.engines).Count -eq 1) { $tags += ('engine: ' + @($s.engines)[0]) }; if ($s.advanced) { $tags += 'advanced' }; if ($s.secret) { $tags += 'secret' }; if ($s.unit) { $tags += $s.unit }
            $g.Add('#'); $g.Add(('# {0}  [{1}]{2}' -f $s.label, $s.name, $(if ($tags.Count) { '  (' + ($tags -join ', ') + ')' } else { '' })))
            $choices = $null
            if ($s.type -eq 'enum' -and $s.Contains('values')) {
                $choices = (@($s.values) | ForEach-Object { if ($s.Contains('valueLabels') -and $s.valueLabels.Contains($_)) { "'{0}' ({1})" -f $_, $s.valueLabels[$_] } else { "'{0}'" -f $_ } }) -join '; '
            }
            $inf = $s['info']
            foreach ($pair in @(@('What it is for', $s.purpose), @('Choices', $choices), @('Default', $s.defaultText), @('If you change it', $s.effect), @('When to change', $s.whenToChange), @('Risk', $inf['risk']), @('Recommended', $inf['recommended']), @('More info', $inf['docUrl']))) {
                if ([string]::IsNullOrWhiteSpace([string]$pair[1])) { continue }
                $first = $true
                foreach ($l in @(Split-GlossaryText ([string]$pair[1]) 96)) {
                    $g.Add($(if ($first) { '#   {0,-17} {1}' -f ($pair[0] + ':'), $l } else { '#   {0,-17} {1}' -f '', $l })); $first = $false
                }
            }
        }
    }
    $g.Add($glossaryEnd)
    $text = $text + $nl + ($g -join $nl) + $nl
    [System.IO.File]::WriteAllText($ref, $text, (New-Object System.Text.UTF8Encoding($bom)))
    Write-Host ("settings glossary: {0} Community settings -> {1}" -f $comm.Count, $ref)
}
