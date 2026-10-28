#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- ALL CONFIGURATION IN SQL, WITH VENDOR TEMPLATES (REQUIREMENTS §9.3.3 phase C).

    Operator, 2026-10-03: "pro version must have all configurations stored in the sql database, so no configuration
    files .custom + .default + .locked" ... "templates, to replace the locked files today, where i provide central
    configurations, customers can choose to import in their environment - but with option to customize".

    THE MODEL (sql\si-pro-settings.sql):
      cfg.Template      the vendor baseline, ONE ROW PER ITEM (a report, a risk index row, a tier rule, a tagging rule,
                        an ownership entry, the service model, a naming default). Published from the shipped *.locked
                        files of a release by setup\Publish-SITemplates.ps1.
      cfg.ItemOverride  the customer's state per item: inherit (or no row) | override (their body) | disable.
      cfg.Document      unchanged (Pro-1b): the customer's own exclusions, weights and tier rules.
      cfg.Exemption     "exempt this finding" from the GUI; expired / revoked rows are not applied.

    RUN START: the template and the customer state are MERGED per item and MATERIALISED into a run-local folder, in
    exactly the files the engines' own loaders already read -- so the engines stay as they are. A Pro run then needs no
    configuration file of the installation: only SI_ProSqlServer / SI_ProSqlDatabase.

    PER FAMILY, NEVER HALF: a family (rules, the Risk Analysis catalog, the risk index, ...) is served from SQL as soon
    as it has template rows; until its templates are published it is read from the installation exactly as before. A
    database without the Phase C tables behaves exactly as Pro-1b.

    🔒 FAIL CLOSED, as the rest of the layer: a row that does not validate, an unknown kind, a template whose body does
    not match its hash, an exemption that is not well-formed, the same item set in two places -- the run stops with
    the reason.

    Everything here except the file writers is pure (rows in, objects out) and tested directly.
#>

$script:SIProConfigSIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Test-SISettingValue -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Settings.ps1'))
}
# SecurityInsight's own YAML reader (no powershell-yaml module).
if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Yaml.ps1'))
}
# Template versioning: the normalised content hash, the fingerprint gate, conformance (adopted from PIM4EntraPS).
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TemplateVersioning.ps1'))
# Mandatory controls on top of templates: what SecurityInsight's own code requires, never switched off by an override.
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-TemplateMandatory.ps1'))
# #275 R3: where the asset-tagging engine finds its rules -- the launchers' and the engine's own resolution, shared.
if (-not (Get-Command -Name Resolve-SIAssetTaggingFiles -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'asset-tagging', 'AssetTagging.Resolve.ps1'))
}
# The risk index rule: first match wins in Precedence order, and the conversion of a v2.2 index (same scores).
if (-not (Get-Command -Name ConvertTo-SIRiskIndexFirstMatch -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared', 'RA-RiskIndexOrder.ps1'))
}
# #559: the index keyed by the SI generic fields, and the 2.2 -> SI translation of rows stored with the old columns.
if (-not (Get-Command -Name ConvertTo-SIRiskIndexSiRows -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared', 'RA-RiskIndexSi.ps1'))
}
# the customer's overrides keyed the pre-v2 way are translated on the next template publish (CONVERGE-DEFAULTS)
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ProOverrideMigration.ps1'))
# #398: the shipped index is riskscore.index.locked.csv; riskscore.index.custom.csv is the customer's own rows, unless it
# is an unchanged copy of an earlier version's shipped index.
if (-not (Get-Command -Name Test-SIRiskIndexShippedCopy -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared', 'RA-RiskIndexFiles.ps1'))
}
# #456: the data model (field catalog, provider mappings, ...) as 'datamodel' template items -- rows, validation, the run's folder.
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-DataModelTemplateRows.ps1'))
# #274: the output scope per destination (validation and the file the engines read).
if (-not (Get-Command -Name Test-SIOutputScopeBody -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-OutputScope.ps1'))
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE KINDS. Templated = the vendor publishes a baseline for it; Format = how BodyJson is read; Key = the item key.
#  A kind not listed here is REFUSED at run start (there is deliberately no CHECK constraint on Kind in SQL -- see the
#  schema file -- so this list is the guard).
# ---------------------------------------------------------------------------------------------------------------------
#  #251 (operator decision 2026-10-04): templates hold only VENDOR-DEVELOPED content (rules, Risk Analysis reports, the risk
#  index, tagging rules, the service model). naming and cmdbownership are CONFIGURATION now:
#    naming         a name is a setting (cfg.Setting) -- the catalog default is the only default. Existing naming overrides
#                   are carried over 1:1 as setting rows by setup; a legacy override row is still read (never refused) until
#                   then, and nothing new is written as a naming item.
#    cmdbownership  ONE configuration document, key 'map' (the cmdbSourceOwnership object), seeded from the shipped file at
#                   setup and owned by the customer. The per-entry keys (defaults, assettype/<type>) are the legacy rows: read
#                   only, to carry them over (ConvertTo-SIProOwnershipMap).
$script:SIProItemKinds = [ordered]@{
    rareport      = @{ Templated = $true;  Format = 'json'; Key = '^(report|template)/[A-Za-z0-9_]{1,100}$' }
    riskindex     = @{ Templated = $true;  Format = 'json'; Key = '^row/[^\r\n]{1,124}$' }
    rule          = @{ Templated = $true;  Format = 'yaml'; Key = '^(endpoint|identity|azure|shared)/[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$' }
    assettagging  = @{ Templated = $true;  Format = 'json'; Key = '^(config|tag/[^\r\n/\\]{1,120})$' }
    cmdbownership = @{ Templated = $false; Format = 'json'; Key = '^(map|defaults|assettype/[a-z0-9][a-z0-9_\-\.]{0,99})$' }
    servicemodel  = @{ Templated = $true;  Format = 'json'; Key = '^model$' }
    # #456: the data model, one item per field / mapping / factor / output column (SI-DataModelTemplateRows.ps1): '<template>' (its
    # header) or '<template>:<item key>', e.g. 'mappings/mde:si_os_version|device|'
    datamodel     = @{ Templated = $true;  Format = 'json'; Key = (Get-SIDataModelProKeyPattern) }
    schemaoverlay = @{ Templated = $false; Format = 'json'; Key = '^(endpoint|identity|azure|publicip)$' }
    decision      = @{ Templated = $false; Format = 'yaml'; Key = '^(asset|correlation)$' }
    naming        = @{ Templated = $false; Format = 'json'; Key = '^[A-Za-z_][A-Za-z0-9_]{0,127}$' }
    weights       = @{ Templated = $false; Format = 'json'; Key = '^(model|report/[A-Za-z0-9_]{1,100})$' }
    # the tier board's 'move this whole rule to tier N': { "ruleKey": "<engine>/<id>", "tier": 0-3 } -- applied to the rule in force
    ruletier      = @{ Templated = $false; Format = 'json'; Key = '^(endpoint|identity|azure|shared)/[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$' }
    # #275 R6: the customer's override of the server-application catalog (asset-profiling-enrichment\endpoint\
    # server-applications.json: { "applications": [ { software_vendor, software_name, tier, ... } ] }), merged over the
    # shipped catalog by its own loader (EndpointCatalogTierComputer.ps1) -- materialised to SI_ProConfigRoot.
    serverapps    = @{ Templated = $false; Format = 'json'; Key = '^catalog$' }
    # #274: what each output destination receives (Excel + mail, the vulnerability and CMDB connectors) -- one item per
    # destination, materialised into config\output-scope.json (engine\_shared\SI-OutputScope.ps1 reads it)
    outputscope   = @{ Templated = $false; Format = 'json'; Key = '^(excel|vuln-sql|vuln-servicenow|cmdb-sql|cmdb-servicenow)$' }
}
# The risk index columns the engine reads (#559: keyed by the SI generic fields -- RA-RiskIndexSi.ps1) plus the notes
# column and Precedence (the row's place: first match wins, 1 = checked first).
$script:SIRiskIndexColumns = @('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class',
    'si_severity', 'VulnerabilityBase', 'si_tier', 'AssetBase', 'Comments', 'Precedence')
$script:SIRiskIndexKeyColumns = @('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class', 'si_severity', 'si_tier')
# #559: a row stored before the re-key carries the 2.2 columns -- still accepted, translated where it is written
# (riskscore.index.translation.locked.json); its item key is the 2.2 one until it is saved again.
$script:SIRiskIndexV22Columns = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId', 'SecuritySeverity',
    'RiskConsequenceScore_SecuritySeverity', 'CriticalityTierLevel', 'RiskProbablityScore_CriticialityTierLevel', 'Comments', 'Precedence')
$script:SIRiskIndexV22KeyColumns = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId', 'SecuritySeverity', 'CriticalityTierLevel')
# Naming conventions: catalog text settings that name a table, a DCR, a DCE or a workspace.
$script:SIProNamingPattern = '(?i)(dcr|dce|table|workspacename)'
# The run-local file names the engines read.
$script:SIProRaCatalogFile  = 'RiskAnalysis_Queries_Locked.yaml'
$script:SIProRiskIndexFile  = 'riskscore.index.custom.csv'
$script:SIProExemptionsFile = 'RiskAnalysisExemptions.json'

function Get-SIProItemKinds { $script:SIProItemKinds }

# =====================================================================================================================
#  JSON: one reader and one canonical writer, so a body means the same thing -- and hashes the same -- on PowerShell
#  5.1 and 7 (pwsh 7 turns date-like strings into DateTime and decimals into double; 5.1 does neither).
# =====================================================================================================================
function ConvertFrom-SIProJson {
    <# ConvertFrom-Json that keeps date-like strings as strings where the runtime allows it (pwsh 7.5+ -DateKind). #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $script:SIProJsonDateKind) { $script:SIProJsonDateKind = (Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind') }
    if ($script:SIProJsonDateKind) { return ($Text | ConvertFrom-Json -DateKind String -ErrorAction Stop) }
    $Text | ConvertFrom-Json -ErrorAction Stop
}

function ConvertTo-SIProJsonString {
    <# PURE. A string as a JSON literal. Escapes every control character and the characters YAML refuses unescaped
       (C1 controls, line / paragraph separators) -- the materialised JSON is read by a YAML parser too. #>
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

function ConvertTo-SIProJson {
    <#
        PURE. A value as JSON. -Canonical sorts object keys ordinally and writes compactly (for hashing and comparing);
        without it keys keep their order and the text is indented (for storing and materialising). A list is always an
        array; a number is invariant (a non-integer as its shortest round-trip form, whatever type the runtime parsed
        it into); a DateTime is ISO 8601.
    #>
    param([AllowNull()]$Value, [switch]$Canonical, [int]$Level = 0)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [System.Numerics.BigInteger]) {
        return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value))
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ($d -eq [Math]::Floor($d) -and [Math]::Abs($d) -lt 1e15) { return ([long]$d).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        return $d.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [datetime]) { return (ConvertTo-SIProJsonString $Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)) }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid]) { return (ConvertTo-SIProJsonString ([string]$Value)) }
    $nl = if ($Canonical) { '' } else { "`n" }
    $pad = if ($Canonical) { '' } else { '  ' * $Level }
    $pad1 = if ($Canonical) { '' } else { '  ' * ($Level + 1) }
    $sep = if ($Canonical) { ':' } else { ': ' }
    $pairs = $null
    if ($Value -is [System.Collections.IDictionary]) { $pairs = @(foreach ($k in $Value.get_Keys()) { , @([string]$k, $Value[$k]) }) }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) { $pairs = @(foreach ($p in $Value.PSObject.Properties) { , @($p.Name, $p.Value) }) }
    if ($null -ne $pairs) {
        if ($pairs.Count -eq 0) { return '{}' }
        if ($Canonical) {
            $names = [string[]]@($pairs | ForEach-Object { $_[0] })
            $idx = [int[]](0..($pairs.Count - 1))
            [Array]::Sort($names, $idx, [System.StringComparer]::Ordinal)
            $pairs = @(foreach ($i in $idx) { , $pairs[$i] })
        }
        $items = foreach ($p in $pairs) { $pad1 + (ConvertTo-SIProJsonString $p[0]) + $sep + (ConvertTo-SIProJson -Value $p[1] -Canonical:$Canonical -Level ($Level + 1)) }
        return ('{' + $nl + ($items -join (',' + $nl)) + $nl + $pad + '}')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = @($Value)
        if ($arr.Count -eq 0) { return '[]' }
        $items = foreach ($v in $arr) { $pad1 + (ConvertTo-SIProJson -Value $v -Canonical:$Canonical -Level ($Level + 1)) }
        return ('[' + $nl + ($items -join (',' + $nl)) + $nl + $pad + ']')
    }
    ConvertTo-SIProJsonString ([string]$Value)
}

function Get-SIProTextHash {
    <# PURE. SHA-256 (hex) of a text as UTF-8. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Get-SIProItemFingerprint {
    <#
        PURE. What an item SAYS, independent of how it was written: JSON -> the canonical form (key order, spacing and
        number formatting do not count); YAML -> the text with line endings, a BOM and trailing spaces normalised (its
        comments DO count -- they are part of what the operator wrote). Used to store only real differences.
    #>
    param([AllowEmptyString()][string]$Body, [string]$Format = 'json')
    if ($Format -eq 'yaml') {
        $t = $Body.TrimStart([char]0xFEFF) -replace "`r`n", "`n" -replace "`r", "`n"
        return ((($t -split "`n") | ForEach-Object { $_.TrimEnd() }) -join "`n").Trim()
    }
    try { ConvertTo-SIProJson -Value (ConvertFrom-SIProJson $Body) -Canonical } catch { $Body.Trim() }
}

function Test-SIProSameItem {
    <# PURE. Do two bodies say the same thing? #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B, [string]$Format = 'json')
    (Get-SIProItemFingerprint -Body $A -Format $Format) -ceq (Get-SIProItemFingerprint -Body $B -Format $Format)
}

# =====================================================================================================================
#  KEYS that are derived from a body
# =====================================================================================================================
function Get-SIRiskIndexKey {
    <# PURE. A risk index row's item key: its dimension columns, '|'-joined (#559: the eight SI dimensions; a row still
       written with the 2.2 columns keeps its six 2.2 dimensions -- -V22). #>
    param([Parameter(Mandatory)]$Row, [switch]$V22)
    $get = { param($n) if ($Row -is [System.Collections.IDictionary]) { [string]$Row[$n] } elseif ($Row.PSObject.Properties[$n]) { [string]$Row.$n } else { '' } }
    $cols = $script:SIRiskIndexKeyColumns; if ($V22) { $cols = $script:SIRiskIndexV22KeyColumns }
    'row/' + ((@($cols | ForEach-Object { (& $get $_).Trim() })) -join '|')
}

function Get-SIProAssetTagStemKey {
    <#
        PURE. The asset-tagging merge key of a tag name -- the SAME rule as the engine's Get-AssetTagStemKey
        (engine\asset-tagging\AssetTagging.ps1; a test runs both on the same names): '<stem>--tier<N>--SI' and
        '<stem>--excluded--SI' share the key '<STEM>--SI'. $null when the name does not follow the convention.
    #>
    param([AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $m = [regex]::Match($Name.Trim(), '^(?<stem>.+?)--(?:tier(?<tier>\d+)|excluded)--SI$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $m.Success) { return $null }
    ($m.Groups['stem'].Value + '--SI').ToUpperInvariant()
}

# =====================================================================================================================
#  VALIDATION -- the same rules for a template (at publish), an override (writer and run start) and an import.
# =====================================================================================================================
function Get-SIProConfigContext {
    <# What validating items needs from the installation (read once per run): the Pro-1b document context plus the
       settings catalog (for naming). #>
    param([string]$SIRoot, [object[]]$Catalog)
    if (-not $SIRoot) { $SIRoot = $script:SIProConfigSIRoot }
    if (-not $Catalog) { $Catalog = @(Get-SISettingsCatalog -SIRoot $SIRoot) }
    [pscustomobject]@{ SIRoot = $SIRoot; Reports = @(Get-SIRaReportNames -SIRoot $SIRoot); Kinds = @(Get-SIRuleKinds -SIRoot $SIRoot); Catalog = @($Catalog) }
}

function Test-SIProOwnershipMap {
    <#
        PURE. The reasons a CMDB ownership map (the configuration document cmdbownership/map, #251) is not accepted -- empty =
        accepted. The map is the cmdbSourceOwnership object of config\cmdb-source-ownership.locked.json. The web app's
        OwnershipMapValidator applies the same rules (both test suites read pro-management\tests\fixtures\ownership-map-cases.json).
        -Value: the JSON text, or (-Parsed) the value ConvertFrom-SIProJson made of it.
    #>
    param([AllowNull()]$Value, [switch]$Parsed)
    $why = New-Object System.Collections.Generic.List[string]
    $o = $Value
    if (-not $Parsed) {
        try { $o = ConvertFrom-SIProJson ([string]$Value) } catch { $why.Add('the ownership map is not valid JSON: ' + $_.Exception.Message); return $why.ToArray() }
    }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { $why.Add('the ownership map must be a JSON object'); return $why.ToArray() }
    $isNote = { param([string]$n) $n.StartsWith('_') -or $n -eq 'Comment' }
    $isList = { param($v) ($null -ne $v) -and ($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]) -and ($v -isnot [System.Management.Automation.PSCustomObject]) }
    $whole = { param($v) if ($null -eq $v -or $v -is [bool] -or (& $isList $v) -or $v -is [System.Management.Automation.PSCustomObject]) { return $false }
               $d = 0.0; if (-not [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $false }
               ($d -eq [Math]::Floor($d)) -and $d -ge 0 -and $d -le 3650 }
    $text = { param($v) ($v -is [string]) -and -not [string]::IsNullOrWhiteSpace($v) }
    foreach ($p in $o.PSObject.Properties) {
        if (& $isNote $p.Name) { continue }
        $v = $p.Value
        switch -CaseSensitive ($p.Name) {
            'notACiResourceTypes' { if (-not (& $isList $v) -or @(@($v) | Where-Object { -not (& $text $_) }).Count) { $why.Add('notACiResourceTypes must be a list of resource types') } }
            'defaultSiMayCreate' { if ($v -isnot [bool]) { $why.Add('defaultSiMayCreate must be true or false') } }
            'defaultExpectedWithinDays' { if (-not (& $whole $v)) { $why.Add('defaultExpectedWithinDays must be a whole number from 0 to 3650') } }
            'defaultCiClass' { if (-not (& $text $v)) { $why.Add('defaultCiClass must be a CI class name') } }
            'assetTypes' {
                if (-not (& $isList $v)) { $why.Add('assetTypes must be a list'); break }
                $seen = @{}; $n = 0
                foreach ($e in @($v)) {
                    $n++
                    if ($e -isnot [System.Management.Automation.PSCustomObject]) { $why.Add(('assetTypes[{0}] must be an object' -f $n)); continue }
                    if (-not $e.PSObject.Properties['siAssetType']) { $why.Add(('assetTypes[{0}] has no siAssetType' -f $n)); continue }
                    $raw = $e.siAssetType
                    $t = if ($raw -is [string]) { $raw.Trim().ToLowerInvariant() } else { '' }
                    if ($t -cnotmatch '^[a-z0-9][a-z0-9_\-\.]{0,99}$') { $why.Add(("assetTypes[{0}]: '{1}' is not an asset type (lower-case letters, digits, _ - .)" -f $n, $raw)); continue }
                    if ($seen.ContainsKey($t)) { $why.Add(("assetTypes: '{0}' is listed twice" -f $t)); continue }
                    $seen[$t] = $true
                    foreach ($q in $e.PSObject.Properties) {
                        if ((& $isNote $q.Name) -or $q.Name -ceq 'siAssetType') { continue }
                        switch -CaseSensitive ($q.Name) {
                            'siMayCreate' { if ($q.Value -isnot [bool]) { $why.Add(('assetTypes[{0}] ({1}): siMayCreate must be true or false' -f $n, $t)) } }
                            'expectedWithinDays' { if (-not (& $whole $q.Value)) { $why.Add(('assetTypes[{0}] ({1}): expectedWithinDays must be a whole number from 0 to 3650' -f $n, $t)) } }
                            'ciClass' { if (-not (& $text $q.Value)) { $why.Add(('assetTypes[{0}] ({1}): ciClass must be a CI class name' -f $n, $t)) } }
                            'ownedBy' { if ($null -ne $q.Value -and $q.Value -isnot [string]) { $why.Add(('assetTypes[{0}] ({1}): ownedBy must be text or null' -f $n, $t)) } }
                            default { $why.Add(("assetTypes[{0}] ({1}): '{2}' is not an asset type setting" -f $n, $t, $q.Name)) }
                        }
                    }
                }
            }
            default { $why.Add(("'{0}' is not an ownership setting" -f $p.Name)) }
        }
    }
    $why.ToArray()
}

function Test-SIProItem {
    <#
        The reasons an item body is not accepted (empty = accepted). -Context: Get-SIProConfigContext (Reports may be
        widened by the caller with the customer's own reports).
    #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key, [AllowEmptyString()][AllowNull()][string]$Body,
          [string]$Format, [Parameter(Mandatory)]$Context)
    $why = New-Object System.Collections.Generic.List[string]
    $spec = $script:SIProItemKinds[$Kind]
    if (-not $spec) { $why.Add(("'{0}' is not a configuration kind ({1})" -f $Kind, ($script:SIProItemKinds.Keys -join ', '))); return $why.ToArray() }
    if ([string]::IsNullOrEmpty($Key) -or $Key -notmatch $spec.Key) { $why.Add(("'{0}' is not a valid {1} key" -f $Key, $Kind)); return $why.ToArray() }
    if (-not $Format) { $Format = $spec.Format }
    if ($Format -ne $spec.Format) { $why.Add(("a {0} item is {1}, not {2}" -f $Kind, $spec.Format, $Format)); return $why.ToArray() }
    if ([string]::IsNullOrWhiteSpace($Body)) { $why.Add('the body is empty'); return $why.ToArray() }
    $o = $null
    if ($Format -eq 'json') {
        try { $o = ConvertFrom-SIProJson $Body } catch { $why.Add('the body is not valid JSON: ' + $_.Exception.Message); return $why.ToArray() }
    }
    $isObj = $o -is [System.Management.Automation.PSCustomObject]
    $prop = { param($n) if ($isObj -and $o.PSObject.Properties[$n]) { , $o.$n } else { $null } }   # ',' keeps a one-item list a list
    switch ($Kind) {
        'rareport' {
            if (-not $isObj) { $why.Add('a report must be a JSON object'); break }
            $name = $Key.Substring($Key.IndexOf('/') + 1)
            if ([string](& $prop 'ReportName') -cne $name) { $why.Add(("ReportName must be '{0}' -- the key names the report" -f $name)) }
            if ($Key -like 'report/*') {
                $q = & $prop 'ReportQuery'
                # the shipped catalog writes ReportQuery as a one-item YAML list; text works as well
                $qt = @(@($q) | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
                if ($qt.Count -eq 0 -or @(@($q) | Where-Object { $_ -isnot [string] }).Count) { $why.Add('a report needs a ReportQuery (text, or a list of text)') }
            } else {
                $incRaw = & $prop 'ReportsIncluded'
                $inc = @($incRaw | Where-Object { $null -ne $_ })
                if ($inc.Count -eq 0) { $why.Add('a report template needs ReportsIncluded') }
                foreach ($i in $inc) {
                    $n = if ($i -is [string]) { $i } elseif ($i.PSObject.Properties['Name']) { [string]$i.Name } elseif ($i.PSObject.Properties['ReportName']) { [string]$i.ReportName } else { '' }
                    if ($n -notmatch '^[A-Za-z0-9_]{1,100}$') { $why.Add(("ReportsIncluded: '{0}' is not a report name" -f $n)) }
                }
            }
        }
        'riskindex' {
            if (-not $isObj) { $why.Add('a risk index row must be a JSON object'); break }
            # #559: SI-keyed (the columns of today) or a row stored with the 2.2 columns (translated where it is written)
            $isV22 = (@($o.PSObject.Properties.Name) | Where-Object { $_ -in 'RiskConsequenceScore_SecuritySeverity', 'RiskProbablityScore_CriticialityTierLevel', 'SecurityDomain', 'CriticalityTierLevel' }).Count -gt 0
            $allowed = $script:SIRiskIndexColumns; if ($isV22) { $allowed = $script:SIRiskIndexV22Columns }
            foreach ($p in $o.PSObject.Properties) {
                if ($allowed -notcontains $p.Name) { $why.Add(("'{0}' is not a risk index column" -f $p.Name)); continue }
                if ($null -ne $p.Value -and ($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string])) { $why.Add(("{0} must be a single value" -f $p.Name)); continue }
                if ([string]$p.Value -match '[\r\n"]') { $why.Add(("{0} may not hold quotes or line breaks" -f $p.Name)) }
            }
            $nums = @('AssetBase', 'VulnerabilityBase', 'si_tier', 'Precedence'); if ($isV22) { $nums = @('RiskConsequenceScore_SecuritySeverity', 'RiskProbablityScore_CriticialityTierLevel', 'Precedence') }
            foreach ($n in $nums) {
                $v = [string](& $prop $n); $d = 0.0
                if ($v -and -not [double]::TryParse($v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $why.Add(("{0} must be a number" -f $n)) }
            }
            if (-not $isV22) {
                $ac = [string](& $prop 'asset_class')
                if ($ac -and @('device_server', 'device_client', 'device', 'identity', 'cloud_resource', 'public_ip') -notcontains $ac) { $why.Add(("asset_class '{0}' (device_server, device_client, device, identity, cloud_resource, public_ip or blank)" -f $ac)) }
            }
            # an empty dimension is a wildcard row (the shipped index has rows matched by configuration id at any severity)
            # a repeated row keeps its place as '<dimensions>#<n>' (the engine's index keeps every row, so a repeat is kept too)
            if ($why.Count -eq 0 -and ($Key -replace '#\d+$', '') -cne (Get-SIRiskIndexKey -Row $o -V22:$isV22)) { $why.Add(("the key must be '{0}' (or '{0}#<n>' for a repeated row) -- it is made of the row's dimension columns" -f (Get-SIRiskIndexKey -Row $o -V22:$isV22))) }
        }
        'rule' {
            $id = $Key.Substring($Key.IndexOf('/') + 1)
            foreach ($w in @(Test-SIRuleText -Text $Body.TrimStart([char]0xFEFF) -Id $id -Kinds @($Context.Kinds))) { $why.Add($w) }
        }
        'assettagging' {
            if (-not $isObj) { $why.Add('an asset-tagging item must be a JSON object'); break }
            if ($Key -eq 'config') { break }   # asset-tagging.config.json: the gates the rules name, free-form
            $stem = Get-SIProAssetTagStemKey ([string](& $prop 'AssetTagName'))
            if (-not $stem) { $why.Add("AssetTagName must be '<stem>--tier<N>--SI' or '<stem>--excluded--SI'"); break }
            if (('tag/' + $stem) -cne $Key) { $why.Add(("the key must be 'tag/{0}' -- it is the tag's merge key" -f $stem)) }
        }
        'cmdbownership' {
            if ($Key -eq 'map') { foreach ($w in @(Test-SIProOwnershipMap -Value $o -Parsed)) { $why.Add($w) }; break }
            if (-not $isObj) { $why.Add('an ownership item must be a JSON object'); break }
            if ($Key -eq 'defaults') {
                if ($o.PSObject.Properties['assetTypes']) { $why.Add("the defaults item holds no assetTypes -- each asset type is its own item (assettype/<type>)") }
                $sc = & $prop 'defaultSiMayCreate'; if ($null -ne $sc -and $sc -isnot [bool]) { $why.Add('defaultSiMayCreate must be true or false') }
                $d = & $prop 'defaultExpectedWithinDays'; $n = 0; if ($null -ne $d -and (-not [int]::TryParse([string]$d, [ref]$n) -or $n -lt 0 -or $n -gt 3650)) { $why.Add('defaultExpectedWithinDays must be a whole number from 0 to 3650') }
                $na = & $prop 'notACiResourceTypes'; if ($null -ne $na) { foreach ($t in @($na)) { if ($t -isnot [string]) { $why.Add('notACiResourceTypes must be a list of resource types') ; break } } }
            } else {
                $t = ([string](& $prop 'siAssetType')).Trim().ToLowerInvariant()
                if (('assettype/' + $t) -cne $Key) { $why.Add(("siAssetType must be '{0}' -- the key names the asset type" -f $Key.Substring(10))) }
                $sc = & $prop 'siMayCreate'; if ($null -ne $sc -and $sc -isnot [bool]) { $why.Add('siMayCreate must be true or false') }
                $d = & $prop 'expectedWithinDays'; $n = 0; if ($null -ne $d -and (-not [int]::TryParse([string]$d, [ref]$n) -or $n -lt 0 -or $n -gt 3650)) { $why.Add('expectedWithinDays must be a whole number from 0 to 3650') }
            }
        }
        'servicemodel' {
            if (-not $isObj) { $why.Add('the service model must be a JSON object'); break }
            foreach ($n in 'services', 'bindings') { $v = & $prop $n; if ($null -ne $v -and -not ($v -is [System.Collections.IEnumerable] -and $v -isnot [string])) { $why.Add(("{0} must be a list" -f $n)) } }
        }
        'schemaoverlay' {
            if (-not $isObj) { $why.Add('a schema overlay must be a JSON object'); break }
            $f = & $prop 'fields'; if ($null -ne $f -and -not ($f -is [System.Collections.IEnumerable] -and $f -isnot [string])) { $why.Add('fields must be a list') }
        }
        'decision' {
            $y = $null
            try { $y = ConvertFrom-SIYaml -Yaml $Body.TrimStart([char]0xFEFF) -SourceName ('decisions/' + $Key) } catch { $why.Add('the decisions file is not valid YAML: ' + $_.Exception.Message); break }
            if ($null -ne $y -and $y -isnot [System.Collections.IDictionary]) { $why.Add('a decisions file must be a YAML mapping') }
        }
        'naming' {
            $s = @($Context.Catalog | Where-Object { $_.name -eq $Key }) | Select-Object -First 1
            if (-not $s -or $s.type -ne 'text' -or $s.secret -or $Key -notmatch $script:SIProNamingPattern) { $why.Add(("'{0}' is not a naming setting (a text setting that names a table, DCR, DCE or workspace)" -f $Key)); break }
            if ($o -isnot [string]) { $why.Add('a naming item is one text value'); break }
            $w = Test-SISettingValue -Setting $s -Value $o
            if ($w) { $why.Add($w) }
            elseif ($o -notmatch '^[A-Za-z0-9][A-Za-z0-9_\-\.\{\}]{0,127}$') { $why.Add(("'{0}' is not a valid resource name (letters, digits, _ - . and {{placeholders}})" -f $o)) }
        }
        'ruletier' {
            if (-not $isObj) { $why.Add('a rule tier decision must be a JSON object'); break }
            if ([string](& $prop 'ruleKey') -cne $Key) { $why.Add(("ruleKey must be '{0}' -- the key names the rule" -f $Key)) }
            $tv = & $prop 'tier'; $n = 0
            if ($null -eq $tv -or -not [int]::TryParse([string]$tv, [ref]$n) -or [string]$n -ne ([string]$tv).Trim() -or $n -lt 0 -or $n -gt 3) { $why.Add('tier must be 0, 1, 2 or 3') }
        }
        'serverapps' {
            # the loader's own rule: an entry without a vendor or a name is skipped; a tier it cannot read as 0-3 is refused
            # here, because the loader casts it ([int]) and would stop the run
            if (-not $isObj) { $why.Add('the server-application catalog must be a JSON object'); break }
            $apps = & $prop 'applications'
            if ($null -eq $apps -or -not ($apps -is [System.Collections.IEnumerable] -and $apps -isnot [string])) { $why.Add('applications must be a list'); break }
            foreach ($a in @($apps)) {
                if ($a -isnot [System.Management.Automation.PSCustomObject]) { $why.Add('every application must be a JSON object'); break }
                if (-not $a.PSObject.Properties['tier']) { continue }
                $n = 0
                if (-not [int]::TryParse([string]$a.tier, [ref]$n) -or $n -lt 0 -or $n -gt 3) { $why.Add(("{0} / {1}: tier must be 0, 1, 2 or 3" -f [string]$a.software_vendor, [string]$a.software_name)) }
            }
        }
        'outputscope' {
            foreach ($w in @(Test-SIOutputScopeBody -Key $Key -Body $o)) { $why.Add($w) }
        }
        'datamodel' {
            foreach ($w in @(Test-SIDataModelProItem -Key $Key -Value $o)) { $why.Add($w) }
        }
        'weights' {
            if (-not $isObj) { $why.Add('a weights item must be a JSON object'); break }
            if ($Key -eq 'model') {
                if ($o.PSObject.Properties['weightedRiskFactors']) { $why.Add("weightedRiskFactors belongs in the weights document (cfg.Document weights/solution), not in the model sections") }
            } else {
                $rep = $Key.Substring(7)
                if (@($Context.Reports) -notcontains $rep) { $why.Add(("'{0}' is not a Risk Analysis report" -f $rep)); break }
                foreach ($w in @(Test-SIProDocument -Kind weights -Key solution -Body $Body -Context $Context)) { $why.Add($w) }
            }
        }
    }
    $why.ToArray()
}

# =====================================================================================================================
#  READING THE ROWS (guarded: a database without the Phase C tables has none of them)
# =====================================================================================================================
function Read-SIProTemplates {
    <# ContentHash (template versioning) is read where the column exists -- through EXEC, because a batch naming a
       column the table does not have fails to compile even inside an IF. #>
    param([Parameter(Mandatory)]$Store)
    $cols = "Kind, ItemKey, [Version] AS TemplateVersion, BodyJson, Format, SortOrder, BodyHash, Source, RetiredAt, CONVERT(varchar(30), CONVERT(bigint, RowVersion)) AS Version"
    $sql = "IF COL_LENGTH('cfg.Template', 'ContentHash') IS NOT NULL EXEC (N'SELECT $cols, ContentHash FROM cfg.Template') ELSE IF OBJECT_ID('cfg.Template') IS NOT NULL SELECT $cols, CAST(NULL AS char(64)) AS ContentHash FROM cfg.Template"
    & $Store.Invoke $sql @{} 'reader' | ForEach-Object { $_ }
}
function Read-SIProItemOverrides {
    param([Parameter(Mandatory)]$Store)
    & $Store.Invoke "IF OBJECT_ID('cfg.ItemOverride') IS NOT NULL SELECT Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, CONVERT(varchar(30), CONVERT(bigint, RowVersion)) AS Version FROM cfg.ItemOverride" @{} 'reader' | ForEach-Object { $_ }
}
function Read-SIProExemptions {
    param([Parameter(Mandatory)]$Store)
    # RequestId (#252) only where the column exists -- a database set up before the governed flow has none
    $cols = 'ExemptionId, Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt, RevokedAt'
    & $Store.Invoke "IF COL_LENGTH('cfg.Exemption', 'RequestId') IS NOT NULL EXEC (N'SELECT $cols, RequestId FROM cfg.Exemption') ELSE IF OBJECT_ID('cfg.Exemption') IS NOT NULL SELECT $cols, CAST(NULL AS bigint) AS RequestId FROM cfg.Exemption" @{} 'reader' | ForEach-Object { $_ }
}

function Get-SIProOrdinalOrder {
    <# PURE. The positions of -Keys in ordinal order (culture never decides an order here -- it differs between PS 5.1
       and 7). Sorts an int[] alongside the keys: [Array]::Sort with an object[] of items leaves the items unmoved in
       PowerShell, an int[] is moved. #>
    param([AllowEmptyCollection()][string[]]$Keys = @())
    if ($Keys.Count -eq 0) { return }
    $k = [string[]]$Keys.Clone(); $idx = [int[]](0..($k.Count - 1))
    [Array]::Sort($k, $idx, [System.StringComparer]::Ordinal)
    $idx
}

function Get-SIProRowValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] } else { return $null } }
    if ($Row.PSObject.Properties[$Name]) { return $Row.$Name }
    $null
}

# =====================================================================================================================
#  MERGE: template + customer state per item -> the effective items of a run.
# =====================================================================================================================
function Merge-SIProItems {
    <#
        PURE. -Templates (cfg.Template rows), -Overrides (cfg.ItemOverride rows), -Documents (accepted cfg.Document
        documents, Pro-1b). Per (kind, key):
          template only                 -> the template body           (Origin 'template')
          override State 'inherit'      -> the template body           (an explicit "follow the vendor")
          override State 'override'     -> the customer's body          (Origin 'override'; 'own' when no template)
          override State 'disable'      -> left out                     (listed in Disabled)
          retired template, no override -> left out                     (the release no longer ships it)
        Templates are checked against their BodyHash; overrides are validated by Test-SIProItem. A cfg.Document rule and
        an override of the same rule, or an override of a kind cfg.Document owns (exclusions), are refused -- one item,
        one home. Returns @{ Items; Disabled; Refused; Notes; TemplateVersion; Families }.
        Items are ordered: per kind, templates by SortOrder then key, then the customer's own items by key (ordinal), so
        the same rows always materialise the same files.
        ADDITIVE UPGRADE (adopted from PIM4EntraPS): -Revisions (cfg.TemplateRevision rows -- Read-SIProOverrideBaseRevisions
        reads just the ones needed). An override behind the shipped content whose new shipped version only ADDS (keys,
        list entries) gets those additions in its effective body; the customer's own values are never touched
        (Get-SIProAdditiveMerge). The merged body is validated like any override; one that does not validate, or a change
        that alters / removes something, stays the customer's body as stored (upgrade available, as before). Nothing is
        written: the stored override keeps its base, so the conformance view shows "new shipped additions applied".
        MANDATORY CONTROLS: -Mandatory (default: config\template-mandatory.locked.json of $Context.SIRoot). An item with a
        control that the customer switched off is applied from its template anyway; a required value the effective body
        breaks is put back on top (Set-SIProMandatoryValues). Each correction is a note. Pass -Mandatory @() for none.
    #>
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Overrides = @(),
          [AllowEmptyCollection()][object[]]$Documents = @(), [Parameter(Mandatory)]$Context,
          [AllowEmptyCollection()][object[]]$Revisions = @(), [AllowEmptyCollection()][object[]]$Mandatory)
    if ($null -eq $Mandatory) {
        $Mandatory = @()
        $mr = if ($Context -and $Context.PSObject.Properties['SIRoot'] -and $Context.SIRoot) { [string]$Context.SIRoot } else { $script:SIProConfigSIRoot }
        $Mandatory = @(Get-SIProMandatoryControls -SIRoot $mr)
    }
    $revIdx = Get-SIProRevisionIndex -Revisions @($Revisions)
    $refused = New-Object System.Collections.Generic.List[object]; $notes = New-Object System.Collections.Generic.List[string]
    $disabled = New-Object System.Collections.Generic.List[string]
    $tpl = @{}; $versions = @{}
    # #251: the CMDB ownership map's legacy rows (templates + per-entry overrides), kept for the carry-over below
    $legacyOwnTpl = New-Object System.Collections.Generic.List[object]; $legacyOwnOvr = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Templates | Where-Object { $_ })) {
        $kind = [string](Get-SIProRowValue $t 'Kind'); $key = [string](Get-SIProRowValue $t 'ItemKey')
        $body = [string](Get-SIProRowValue $t 'BodyJson'); $fmt = [string](Get-SIProRowValue $t 'Format'); if (-not $fmt) { $fmt = 'json' }
        $name = '{0}/{1}' -f $kind, $key
        # #251: a template row of a kind that is configuration now (naming, cmdbownership) is history -- never applied as a
        # template, never refused. A live ownership row still feeds the map until setup has carried it over.
        if (Test-SIProFormerTemplateKind $kind) {
            if ($kind -eq 'cmdbownership' -and $null -eq (Get-SIProRowValue $t 'RetiredAt')) { $legacyOwnTpl.Add($t) }
            continue
        }
        $spec = $script:SIProItemKinds[$kind]
        if (-not $spec -or -not $spec.Templated) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'template'; Reason = ("'{0}' is not a templated configuration kind" -f $kind) }); continue }
        if ($key -notmatch $spec.Key) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'template'; Reason = 'not a valid key' }); continue }
        if ($fmt -ne $spec.Format) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'template'; Reason = ("a {0} item is {1}" -f $kind, $spec.Format) }); continue }
        $h = [string](Get-SIProRowValue $t 'BodyHash')
        if ((Get-SIProTextHash $body) -ne $h.Trim()) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'template'; Reason = 'the body does not match its BodyHash -- republish the templates' }); continue }
        if ($fmt -eq 'json') { try { $null = ConvertFrom-SIProJson $body } catch { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'template'; Reason = 'the body is not valid JSON' }); continue } }
        $so = 0; [void][int]::TryParse([string](Get-SIProRowValue $t 'SortOrder'), [ref]$so)
        $v = [string](Get-SIProRowValue $t 'TemplateVersion'); if ($v) { $versions[$v] = $true }
        $tpl[$name] = [pscustomobject]@{ Kind = $kind; Key = $key; Body = $body; Format = $fmt; SortOrder = $so; Hash = $h.Trim()
            ContentHash = ([string](Get-SIProRowValue $t 'ContentHash')).Trim()
            Source = [string](Get-SIProRowValue $t 'Source'); Version = $v; Retired = ($null -ne (Get-SIProRowValue $t 'RetiredAt')) }
    }
    $docKeys = @{}; foreach ($d in @($Documents | Where-Object { $_ })) { $docKeys[('{0}/{1}' -f $d.Kind, $d.Key)] = $true }
    $ovr = @{}
    foreach ($o in @($Overrides | Where-Object { $_ })) {
        $kind = [string](Get-SIProRowValue $o 'Kind'); $key = [string](Get-SIProRowValue $o 'ItemKey'); $state = [string](Get-SIProRowValue $o 'State')
        $body = Get-SIProRowValue $o 'BodyJson'; $fmt = [string](Get-SIProRowValue $o 'Format'); if (-not $fmt) { $fmt = 'json' }
        $name = '{0}/{1}' -f $kind, $key
        if ($kind -eq 'exclusions') { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = 'exclusions are documents (cfg.Document), not item overrides' }); continue }
        if ($state -notin 'inherit', 'override', 'disable') { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = ("'{0}' is not a state (inherit, override, disable)" -f $state) }); continue }
        $spec = $script:SIProItemKinds[$kind]
        if (-not $spec) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = ("'{0}' is not a configuration kind" -f $kind) }); continue }
        if ($key -notmatch $spec.Key) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = 'not a valid key' }); continue }
        if ($docKeys.ContainsKey($name) -and $state -ne 'inherit') { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = 'the same item is also a cfg.Document -- one item, one home' }); continue }
        # #251: a legacy per-entry ownership row (defaults, assettype/<type>) is carried into the map, not applied by itself
        if ($kind -eq 'cmdbownership' -and $key -ne 'map') { $legacyOwnOvr.Add($o); continue }
        if ($state -eq 'override') {
            # the required values go on top BEFORE the override is validated: a stored override that weakens one (a
            # built-in factor switched off) keeps the customer's other values with the required value applied, instead of
            # being refused whole by the item rules
            if ($fmt -eq 'json' -and @($Mandatory).Count) {
                $mv0 = Set-SIProMandatoryValues -Controls $Mandatory -Kind $kind -Key $key -Body ([string]$body)
                if ($mv0.Changed) { $body = [string]$mv0.Body; foreach ($a in @($mv0.Applied)) { $notes.Add($a) } }
            }
            $why = @(Test-SIProItem -Kind $kind -Key $key -Body ([string]$body) -Format $fmt -Context $Context)
            if ($why.Count) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'override'; Reason = ($why -join '; ') }); continue }
        }
        $ovr[$name] = [pscustomobject]@{ Kind = $kind; Key = $key; State = $state; Body = [string]$body; Format = $fmt; BaseHash = [string](Get-SIProRowValue $o 'BaseHash') }
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($name in @($tpl.Keys)) {
        $t = $tpl[$name]; $o = $ovr[$name]
        if ($o -and $o.State -eq 'disable') {
            # a mandatory item is never switched off: the template applies, and the run says so
            if (-not $t.Retired -and @(Get-SIProMandatoryFor -Controls $Mandatory -Kind $t.Kind -Key $t.Key).Count) {
                $notes.Add(("{0}: switched off, but SecurityInsight requires it -- the shipped item is applied" -f $name))
                $items.Add([pscustomobject]@{ Kind = $t.Kind; Key = $t.Key; Body = $t.Body; Format = $t.Format; Origin = 'template'; SortOrder = $t.SortOrder; Source = $t.Source; Stale = $false; Mandatory = $true })
                continue
            }
            $disabled.Add($name); continue
        }
        if ($o -and $o.State -eq 'override') {
            # BaseHash is the template's normalised ContentHash (template versioning), or its raw BodyHash for an override
            # made before content hashes -- either one matching means the template's CONTENT did not move underneath it.
            $b = ([string]$o.BaseHash).Trim()
            $stale = $false
            if ($b -and $b -ne $t.Hash) {
                $ch = $t.ContentHash
                if (-not $ch) { try { $ch = Get-SIProContentHash -Body $t.Body -Format $t.Format } catch { $ch = '' } }
                $stale = ($b -ne $ch)
            }
            $effBody = $o.Body; $added = @()
            if ($stale -and $b) {
                # additive upgrade: the shipped version the override was made on, by its content hash or raw body hash
                $base = $revIdx[('{0}#{1}' -f $name, $b)]
                if ($base) {
                    $am = Get-SIProAdditiveMerge -Base ([string](Get-SIProRowValue $base 'BodyJson')) -Current $t.Body -Override $o.Body -Format $o.Format
                    if ($am.Additive) {
                        $why = @()
                        if ($am.Changed) { $why = @(Test-SIProItem -Kind $t.Kind -Key $t.Key -Body ([string]$am.Body) -Format $o.Format -Context $Context) }
                        if ($why.Count -eq 0) {
                            $effBody = [string]$am.Body; $added = @($am.Added); $stale = $false
                            if ($added.Count) { $notes.Add(("{0}: overridden -- new shipped additions applied ({1}); your own values are unchanged" -f $name, ($added -join ', '))) }
                        } else {
                            $notes.Add(("{0}: the new shipped additions do not fit your version ({1}) -- review the upgrade" -f $name, ($why -join '; ')))
                        }
                    }
                }
            }
            if ($stale) { $notes.Add(("{0}: the template changed since it was overridden -- an upgrade is available (see the template conformance view)" -f $name)) }
            $items.Add([pscustomobject]@{ Kind = $t.Kind; Key = $t.Key; Body = $effBody; Format = $o.Format; Origin = 'override'; SortOrder = $t.SortOrder; Source = $t.Source; Stale = $stale
                AdditionsApplied = ($added.Count -gt 0); Additions = $added })
            continue
        }
        if ($t.Retired) { continue }
        $items.Add([pscustomobject]@{ Kind = $t.Kind; Key = $t.Key; Body = $t.Body; Format = $t.Format; Origin = 'template'; SortOrder = $t.SortOrder; Source = $t.Source; Stale = $false })
    }
    foreach ($name in @($ovr.Keys)) {
        if ($tpl.ContainsKey($name)) { continue }
        $o = $ovr[$name]
        if ($o.State -ne 'override') {
            # a naming 'disable' / 'inherit' made against a template that is a setting now: the catalog default applies -- quiet
            if (-not (Test-SIProFormerTemplateKind $o.Kind)) { $notes.Add(("{0}: '{1}' has no template to apply to -- nothing to do" -f $name, $o.State)) }
            continue
        }
        $items.Add([pscustomobject]@{ Kind = $o.Kind; Key = $o.Key; Body = $o.Body; Format = $o.Format; Origin = 'own'; SortOrder = [int]::MaxValue; Source = ''; Stale = $false })
    }
    # #251: the CMDB ownership map. The configuration document cmdbownership/map is the map; until setup has written it, the
    # map is built from the legacy rows exactly as it was materialised before (templates with the customer's per-entry
    # overrides over them), so nothing the customer set is lost in between.
    if (-not $ovr.ContainsKey('cmdbownership/map') -and ($legacyOwnTpl.Count -or @($legacyOwnOvr | Where-Object { [string](Get-SIProRowValue $_ 'State') -eq 'override' }).Count)) {
        $mapBody = ConvertTo-SIProOwnershipMap -Templates $legacyOwnTpl.ToArray() -Overrides $legacyOwnOvr.ToArray()
        if ($mapBody) { $items.Add([pscustomobject]@{ Kind = 'cmdbownership'; Key = 'map'; Body = $mapBody; Format = 'json'; Origin = 'own'; SortOrder = [int]::MaxValue; Source = 'carried over from the ownership templates'; Stale = $false }) }
    }
    # mandatory controls: the required values ON TOP of every effective JSON body (an override cannot weaken them)
    if (@($Mandatory).Count) {
        foreach ($it in $items) {
            if ($it.Format -ne 'json') { continue }
            $mv = Set-SIProMandatoryValues -Controls $Mandatory -Kind $it.Kind -Key $it.Key -Body $it.Body
            if (-not $mv.Changed) { continue }
            $it.Body = [string]$mv.Body
            foreach ($a in @($mv.Applied)) { $notes.Add($a) }
        }
    }
    $kindOrder = @{}; $i = 0; foreach ($k in $script:SIProItemKinds.Keys) { $kindOrder[$k] = $i++ }
    $unsorted = $items.ToArray()
    $arr = @(foreach ($i in (Get-SIProOrdinalOrder -Keys @($unsorted | ForEach-Object { '{0:D3}|{1:D10}|{2}' -f $kindOrder[$_.Kind], [long]$_.SortOrder, $_.Key }))) { $unsorted[$i] })
    $families = @{}; foreach ($t in $tpl.Values) { $families[$t.Kind] = $true }
    # A family whose files are generated whole (catalog, index, ownership map, model, tagging rules) is served from SQL
    # only once its templates are published -- until then the customer's items for it cannot be applied. Say so.
    foreach ($k in 'rareport', 'riskindex', 'assettagging', 'servicemodel') {
        if ($families[$k]) { continue }
        $n = @($arr | Where-Object { $_.Kind -eq $k -and -not ($k -eq 'assettagging' -and $_.Key -eq 'config') }).Count
        if ($n) { $notes.Add(("{0} {1} item(s) are NOT applied: no {1} templates are published yet, so this family is still read from the installation -- run setup\Publish-SITemplates.ps1 -Apply" -f $n, $k)) }
    }
    $vlist = [string[]]@($versions.Keys); [Array]::Sort($vlist, [System.StringComparer]::Ordinal)
    $dl = $disabled.ToArray(); [Array]::Sort($dl, [System.StringComparer]::Ordinal)
    [pscustomobject]@{ Items = $arr; Disabled = $dl; Refused = $refused.ToArray(); Notes = $notes.ToArray()
        TemplateVersion = ($vlist -join ', '); Families = $families }
}

# =====================================================================================================================
#  EXEMPTIONS ("exempt this finding")
# =====================================================================================================================
function ConvertTo-SIProUtc {
    <# PURE. A SQL datetime2 (stored as UTC, read back with Kind Unspecified), a DateTime or an ISO text -> UTC; $null stays $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

function ConvertFrom-SIProExemptionRows {
    <#
        PURE. cfg.Exemption rows -> Active (applied), Inactive (expired or revoked -- with why), Refused (malformed; the
        run stops). -Now is a seam (UTC).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)]$Context, [datetime]$Now = ([datetime]::UtcNow))
    $active = New-Object System.Collections.Generic.List[object]; $inactive = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $id = [string](Get-SIProRowValue $r 'ExemptionId'); $name = 'exemption/' + $id
        $scope = [string](Get-SIProRowValue $r 'Scope'); $rep = [string](Get-SIProRowValue $r 'ReportName')
        $cve = [string](Get-SIProRowValue $r 'Cve'); $cfg = [string](Get-SIProRowValue $r 'ConfigurationId'); $asset = [string](Get-SIProRowValue $r 'AssetKey')
        $why = New-Object System.Collections.Generic.List[string]
        # The scopes are the management GUI's: finding = one issue on one asset; issue = one issue on every asset;
        # asset = every issue of one asset. ReportName narrows any of them to one report (empty = every report).
        if ($scope -notin 'finding', 'issue', 'asset') { $why.Add("Scope must be 'finding', 'issue' or 'asset'") }
        if ($rep -and @($Context.Reports) -notcontains $rep) { $why.Add(("'{0}' is not a Risk Analysis report" -f $rep)) }
        if ($scope -eq 'finding' -and (-not $asset -or (-not $cve -and -not $cfg))) { $why.Add('a finding exemption names an asset AND a CVE or configuration id') }
        if ($scope -eq 'issue' -and ($asset -or (-not $cve -and -not $cfg))) { $why.Add('an issue exemption names a CVE or configuration id and no asset') }
        if ($scope -eq 'asset' -and (-not $asset -or $cve -or $cfg)) { $why.Add('an asset exemption names an asset and no CVE or configuration id') }
        if ($cve -and $cve -notmatch '^CVE-\d{4}-\d{4,7}$') { $why.Add(("'{0}' is not a valid CVE id" -f $cve)) }
        if ($cfg -and $cfg -notmatch '^[A-Za-z0-9._:\-]{1,128}$') { $why.Add(("'{0}' is not a valid configuration id" -f $cfg)) }
        if ($asset -and $asset -notmatch '^[^"\\\r\n]{1,256}$') { $why.Add('the asset key may not hold quotes, backslashes or line breaks') }
        if ([string]::IsNullOrWhiteSpace([string](Get-SIProRowValue $r 'Reason'))) { $why.Add('an exemption needs a reason') }
        if ($why.Count) { $refused.Add([pscustomobject]@{ Name = $name; Scope = 'exemption'; Reason = ($why -join '; ') }); continue }
        $rev = Get-SIProRowValue $r 'RevokedAt'; $exp = ConvertTo-SIProUtc (Get-SIProRowValue $r 'ExpiresAt')
        $e = [pscustomobject]@{ Id = $id; Scope = $scope; ReportName = $(if ($rep) { $rep } else { $null }); Cve = $(if ($cve) { $cve.ToUpperInvariant() } else { $null })
            ConfigurationId = $(if ($cfg) { $cfg } else { $null }); AssetKey = $(if ($asset) { $asset } else { $null }); Reason = [string](Get-SIProRowValue $r 'Reason')
            ExpiresAt = $(if ($exp) { $exp.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null })
            RequestId = $(if ([string](Get-SIProRowValue $r 'RequestId')) { [string](Get-SIProRowValue $r 'RequestId') } else { $null }) }
        if ($null -ne $rev -and [string]$rev -ne '') { $inactive.Add([pscustomobject]@{ Exemption = $e; Why = 'revoked' }); continue }
        if ($exp -and $exp -le $Now) { $inactive.Add([pscustomobject]@{ Exemption = $e; Why = 'expired' }); continue }
        $active.Add($e)
    }
    $u = $active.ToArray()
    $a = @(foreach ($i in (Get-SIProOrdinalOrder -Keys @($u | ForEach-Object { '{0:D20}' -f [long]$_.Id }))) { $u[$i] })
    [pscustomobject]@{ Active = $a; Inactive = $inactive.ToArray(); Refused = $refused.ToArray() }
}

function Get-SIProExemptionPlan {
    <#
        PURE. How active exemptions reach Risk Analysis without changing its queries (#264): EVERY active exemption --
        finding, issue or asset scope -- goes to RiskAnalysisExemptions.json, and Risk Analysis MARKS the rows it covers
        (RA-Exemptions.ps1). Nothing becomes a KQL exclusion any more: an exclusion removes the finding from the raw data,
        and an exempted finding must stay in it (marked) so the views decide what to show and count.
        (Before #264 an exemption without an asset was merged into the report's exclusion file. The #211 exclusion lists
        themselves are unchanged: they are the customer's own "never report this" rules, not exemptions.)
        -QueryOf is accepted for compatibility and no longer used.
        Returns @{ Exclusions = (always empty); Marked = [...]; AssetScoped = the same list (the earlier name) }.
    #>
    param([AllowEmptyCollection()][object[]]$Active = @(), [hashtable]$QueryOf = @{})
    $marked = @($Active | Where-Object { $null -ne $_ })
    [pscustomobject]@{ Exclusions = [ordered]@{}; Marked = $marked; AssetScoped = $marked }
}
# =====================================================================================================================
#  MATERIALISE -- the effective configuration into the run-local folder, in the files the engines already read.
# =====================================================================================================================
function Join-SIProPath {
    <# [IO.Path]::Combine over segments that may carry either separator -- the same code runs on Windows and in the Linux container. #>
    param([Parameter(Mandatory)][string]$Base, [Parameter(ValueFromRemainingArguments)][string[]]$Parts)
    $p = $Base
    foreach ($x in $Parts) { foreach ($seg in ($x -split '[\\/]')) { if ($seg) { $p = [System.IO.Path]::Combine($p, $seg) } } }
    $p
}

function Write-SIProFile {
    param([Parameter(Mandatory)][string]$Path, [AllowEmptyString()][string]$Text)
    $d = [System.IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    # WITH a BOM: PowerShell 5.1's Get-Content (the rule loader, the report catalog loader) reads a BOM-less file as ANSI,
    # and the shipped catalog and rules carry non-ASCII text. Every reader here strips the BOM.
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($true)))
}

function ConvertTo-SIProCsvField {
    param([AllowNull()][AllowEmptyString()][string]$Value)
    '"' + ([string]$Value).Replace('"', '""') + '"'
}

function Get-SIProTemplateIncluded {
    <# PURE. The report names a report template includes (ReportsIncluded: names, or objects with Name / ReportName). #>
    param($Template)
    $inc = $null
    if ($Template -is [System.Collections.IDictionary]) { if ($Template.Contains('ReportsIncluded')) { $inc = $Template['ReportsIncluded'] } }
    elseif ($Template.PSObject.Properties['ReportsIncluded']) { $inc = $Template.ReportsIncluded }
    @(foreach ($i in @($inc | Where-Object { $null -ne $_ })) {
        if ($i -is [string]) { $i }
        elseif ($i -is [System.Collections.IDictionary]) { if ($i.Contains('Name')) { [string]$i['Name'] } else { [string]$i['ReportName'] } }
        elseif ($i.PSObject.Properties['Name']) { [string]$i.Name } else { [string]$i.ReportName }
    })
}

function Get-SIProTemplateMembership {
    <#
        Report template name -> the report names it includes, for THIS run: -FromItems = the rareport items of the run (the
        catalog is served from SQL); otherwise the installation's catalog (risk-analysis-detection\RiskAnalysis_Queries_
        Locked.yaml, then RiskAnalysis_Queries_Custom.yaml -- a custom template of the same name replaces the locked one).
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [bool]$FromItems, [string]$SIRoot)
    $map = [ordered]@{}
    if ($FromItems) {
        foreach ($it in @($Items | Where-Object { $_.Key -like 'template/*' })) { $map[$it.Key.Substring(9)] = @(Get-SIProTemplateIncluded (ConvertFrom-SIProJson $it.Body)) }
        return $map
    }
    foreach ($f in 'RiskAnalysis_Queries_Locked.yaml', 'RiskAnalysis_Queries_Custom.yaml') {
        $p = Join-SIProPath $SIRoot 'risk-analysis-detection' $f
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $y = ConvertFrom-SIYaml -Path $p -Ordered
        foreach ($t in @($y['ReportTemplates'] | Where-Object { $null -ne $_ })) { $map[[string]$t['ReportName']] = @(Get-SIProTemplateIncluded $t) }
    }
    $map
}

function Export-SIProConfig {
    <#
        Materialise everything a run needs into -RunFolder (never the installation -- a folder inside it is refused):
          rules\                      the rules overlay (set as SI_EnrichmentDataRoot): the run's existing overlay copied
                                      first; when rule TEMPLATES exist every effective template rule at its shipped place as
                                      <id>.locked.yaml, an override beside it as <id>.custom.yaml (it outranks the locked
                                      one in Get-SIRuleSet), and RulesFromSql = the tree is not read; cfg.Document rules as
                                      Pro-1b; decision files at the overlay ROOT (where their loaders look).
          risk-analysis\              (SI_ProRaSettingsPath) exclusion documents merged with exemption-derived lists,
                                      the weights document (+ the model sections), per-report weights, the report catalog
                                      (RiskAnalysis_Queries_Locked.yaml -- JSON, which is YAML), the risk index CSV,
                                      RiskAnalysisExemptions.json.
          config\                     (SI_ProConfigRoot) cmdb-source-ownership.locked.json, service-model.locked.json,
                                      asset-tagging.config.json, asset-profiling-schema\<engine>.schema.custom.json,
                                      server-applications.json (the catalog override, #275 R6);
                                      output-scope.json (#274: the output scope per destination, templates resolved);
                                      config\asset-tagging\ (SI_ProAssetTaggingPath) AssetTagging.locked.yaml.
          data-model\                 (SI_DataModelRoot, #456) every data-model template, put back together from its items
                                      (templates + overrides + own items), validated -- a file with no rows is copied
                                      from the installation.
        Returns what was written and the folders to point the engines at.
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][object[]]$Documents = @(),
          [AllowEmptyCollection()][object[]]$Exemptions = @(), [hashtable]$Families = @{},
          [Parameter(Mandatory)][string]$RunFolder, [Parameter(Mandatory)]$Context, [string]$ExistingOverlay)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $siFull = [System.IO.Path]::GetFullPath([string]$Context.SIRoot).TrimEnd('\', '/') + $sep
    $runFull = [System.IO.Path]::GetFullPath($RunFolder).TrimEnd('\', '/') + $sep
    if ($runFull.StartsWith($siFull, [StringComparison]::OrdinalIgnoreCase)) { throw ('the run-local folder {0} is inside the SecurityInsight folder -- documents are never written into the installation' -f $RunFolder) }
    $out = [ordered]@{ RulesRoot = $null; RaSettingsPath = $null; ConfigRoot = $null; AssetTaggingPath = $null; RulesFromSql = $false
        Rules = 0; Exclusions = 0; Weights = 0; Reports = 0; RiskIndexRows = 0; Exemptions = 0; ConfigFiles = 0; Decisions = 0; RuleTiers = 0; Naming = @{}
        DataModelRoot = $null; DataModelItems = 0
        Notes = (New-Object System.Collections.Generic.List[string]) }
    $byKind = @{}; foreach ($it in @($Items)) { if (-not $byKind.ContainsKey($it.Kind)) { $byKind[$it.Kind] = New-Object System.Collections.Generic.List[object] }; $byKind[$it.Kind].Add($it) }
    $kindItems = { param($k) if ($byKind.ContainsKey($k)) { $byKind[$k].ToArray() } else { @() } }

    # ---- rules overlay ------------------------------------------------------------------------------------------------
    $ruleDocs = @($Documents | Where-Object { $_.Kind -eq 'rule' })
    $ruleItems = @(& $kindItems 'rule')
    $decisions = @(& $kindItems 'decision')
    $tiers = @(& $kindItems 'ruletier')
    if ($ruleDocs.Count -or $ruleItems.Count -or $decisions.Count -or $tiers.Count -or $Families['rule']) {
        $ov = Join-SIProPath $RunFolder 'rules'
        New-Item -ItemType Directory -Path $ov -Force | Out-Null
        if (-not [string]::IsNullOrWhiteSpace($ExistingOverlay) -and (Test-Path -LiteralPath $ExistingOverlay)) {
            $src = [System.IO.Path]::GetFullPath($ExistingOverlay).TrimEnd('\', '/')
            foreach ($f in @(Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction Stop)) {
                $to = Join-SIProPath $ov $f.FullName.Substring($src.Length)
                $d = [System.IO.Path]::GetDirectoryName($to)
                if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                [System.IO.File]::Copy($f.FullName, $to, $true)
            }
        }
        # the folder a template rule ships in (relative to its engine folder), so a method filter still finds it
        $relDirOf = @{}
        foreach ($it in $ruleItems) {
            $rel = ''
            if ($it.Source) {
                $parts = @($it.Source -split '[\\/]' | Where-Object { $_ })
                $ei = [Array]::IndexOf([string[]]@($parts | ForEach-Object { $_.ToLowerInvariant() }), $it.Key.Split('/')[0])
                if ($ei -ge 0 -and $parts.Count - $ei -gt 2) { $rel = ($parts[($ei + 1)..($parts.Count - 2)] -join '/') }
            }
            $relDirOf[$it.Key] = $rel
        }
        $removeCopied = {
            param([string]$engineDir, [string]$id)
            foreach ($f in @(Get-ChildItem -LiteralPath $engineDir -Recurse -File -Filter '*.custom.yaml' -ErrorAction SilentlyContinue)) {
                $h = Get-SIRuleHeader -Text ([System.IO.File]::ReadAllText($f.FullName))
                $fid = if ($h.Id) { $h.Id } else { $f.Name -replace '\.custom\.yaml$', '' }
                if ($fid -eq $id) { Remove-Item -LiteralPath $f.FullName -Force }   # the run's own copy -- the database wins
            }
        }
        foreach ($it in $ruleItems) {
            $engine, $id = $it.Key -split '/', 2
            $edir = Join-SIProPath $ov $engine
            $name = if ($it.Origin -eq 'template') { '{0}.locked.yaml' -f $id } else { '{0}.custom.yaml' -f $id }
            if ($it.Origin -ne 'template') { & $removeCopied $edir $id }
            Write-SIProFile -Path (Join-SIProPath $edir $relDirOf[$it.Key] $name) -Text $it.Body.TrimStart([char]0xFEFF)
            $out.Rules++
        }
        foreach ($doc in $ruleDocs) {
            $engine, $id = $doc.Key -split '/', 2
            $edir = Join-SIProPath $ov $engine
            & $removeCopied $edir $id
            $rel = if ($relDirOf.ContainsKey($doc.Key)) { $relDirOf[$doc.Key] } else { '' }
            Write-SIProFile -Path (Join-SIProPath $edir $rel ('{0}.custom.yaml' -f $id)) -Text $doc.Body
            $out.Rules++
        }
        # The tier board's whole-rule moves: the rule IN FORCE (a document, else an override / template, else the shipped
        # file) with every Tier it sets changed, written as the rule's custom copy so it outranks every other source.
        foreach ($it in $tiers) {
            $tier = [int](ConvertFrom-SIProJson $it.Body).tier
            $engine, $id = $it.Key -split '/', 2
            $src = $null
            $doc = @($ruleDocs | Where-Object { $_.Key -eq $it.Key }) | Select-Object -First 1
            if ($doc) { $src = $doc.Body }
            if (-not $src) { $ri = @($ruleItems | Where-Object { $_.Key -eq $it.Key }) | Select-Object -First 1; if ($ri) { $src = $ri.Body } }
            if (-not $src -and -not $Families['rule']) {
                $tree = Join-SIProPath ([string]$Context.SIRoot) 'asset-profiling-enrichment' $engine
                $hit = @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter ('{0}.locked.yaml' -f $id) -ErrorAction SilentlyContinue) | Select-Object -First 1
                if ($hit) {
                    $src = [System.IO.File]::ReadAllText($hit.FullName)
                    if (-not $relDirOf.ContainsKey($it.Key)) { $relDirOf[$it.Key] = ($hit.DirectoryName.Substring($tree.Length).TrimStart('\', '/') -replace '\\', '/') }
                }
            }
            if (-not $src) { $out.Notes.Add(("ruletier/{0}: the rule is not in force (removed, or turned off) -- the tier decision is not applied" -f $it.Key)); continue }
            if ($src -match '(?m)^mode\s*:\s*disable\b') { $out.Notes.Add(("ruletier/{0}: the rule is turned off -- the tier decision is not applied" -f $it.Key)); continue }
            $rx = '(?m)^(\s+Tier\s*:\s*)[''"]?\d+[''"]?'
            if (-not [regex]::IsMatch($src, $rx)) { throw ("ruletier/{0}: the rule sets no Tier, so it cannot be moved to tier {1}" -f $it.Key, $tier) }
            $text = [regex]::Replace($src.TrimStart([char]0xFEFF), $rx, ('${1}' + $tier))
            $why = @(Test-SIRuleText -Text $text -Id $id -Kinds @($Context.Kinds))
            if ($why.Count) { throw ("ruletier/{0}: the moved rule does not validate: {1}" -f $it.Key, ($why -join '; ')) }
            $edir = Join-SIProPath $ov $engine
            & $removeCopied $edir $id
            $rel = if ($relDirOf.ContainsKey($it.Key)) { $relDirOf[$it.Key] } else { '' }
            Write-SIProFile -Path (Join-SIProPath $edir $rel ('{0}.custom.yaml' -f $id)) -Text $text
            $out.RuleTiers++
        }        foreach ($it in $decisions) {
            $file = if ($it.Key -eq 'asset') { 'asset-decisions.custom.yaml' } else { 'correlation-decisions.custom.yaml' }
            Write-SIProFile -Path (Join-SIProPath $ov $file) -Text $it.Body.TrimStart([char]0xFEFF)
            $out.Decisions++
        }
        $out.RulesRoot = $ov
        $out.RulesFromSql = [bool]$Families['rule']
    }

    # ---- Risk Analysis ------------------------------------------------------------------------------------------------
    $rp = Join-SIProPath $RunFolder 'risk-analysis'
    $raWritten = $false
    $ensureRa = { if (-not (Test-Path -LiteralPath $rp)) { New-Item -ItemType Directory -Path $rp -Force | Out-Null } }
    # the report catalog (only when the family is served from SQL)
    $rareports = @(& $kindItems 'rareport')
    $queryOf = @{}
    if ($Families['rareport'] -or $rareports.Count) {
        $reports = New-Object System.Collections.Generic.List[string]; $templates = New-Object System.Collections.Generic.List[object]
        $present = @{}
        foreach ($it in $rareports) {
            if ($it.Key -like 'report/*') {
                $reports.Add($it.Body.Trim()); $present[$it.Key.Substring(7)] = $true
                try { $queryOf[$it.Key.Substring(7)] = (@((ConvertFrom-SIProJson $it.Body).ReportQuery) -join "`n") } catch { }
            } else { $templates.Add($it) }
        }
        if ($Families['rareport']) {
            $tplTexts = foreach ($t in $templates) {
                # a report that is disabled (or retired) leaves every template that includes it
                $o = ConvertFrom-SIProJson $t.Body
                $inc = @($o.ReportsIncluded | Where-Object { $null -ne $_ } | Where-Object {
                    $n = if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['Name']) { [string]$_.Name } else { [string]$_.ReportName }
                    $present.ContainsKey($n) })
                $o.ReportsIncluded = $inc
                ConvertTo-SIProJson -Value $o -Level 2
            }
            & $ensureRa
            $catalogText = "{`n  `"Reports`": [`n" + (($reports | ForEach-Object { $_ }) -join ",`n") + "`n  ],`n  `"ReportTemplates`": [`n" + (@($tplTexts) -join ",`n") + "`n  ]`n}`n"
            $fileName = if ($global:ReportSettingsFileLocked) { [string]$global:ReportSettingsFileLocked } else { $script:SIProRaCatalogFile }
            Write-SIProFile -Path (Join-SIProPath $rp $fileName) -Text $catalogText
            $out.Reports = $reports.Count; $raWritten = $true
        }
    }
    if (-not $queryOf.Count) {
        # the shipped catalog tells which reports carry which exclusion block (global exemptions fan out by it)
        $lp = Join-SIProPath ([string]$Context.SIRoot) 'risk-analysis-detection' $script:SIProRaCatalogFile
        if (Test-Path -LiteralPath $lp) {
            $txt = [System.IO.File]::ReadAllText($lp)
            foreach ($m in [regex]::Matches($txt, '(?ms)^\s*-\s*ReportName:\s*([A-Za-z0-9_]+)\s*$(.*?)(?=^\s*-\s*ReportName:|\z)')) { $queryOf[$m.Groups[1].Value] = $m.Groups[2].Value }
        }
    }
    # the risk index
    if ($Families['riskindex']) {
        $rows = @(& $kindItems 'riskindex')
        # #559: the run file is keyed by the SI generic fields. A row stored with the 2.2 columns is translated
        # (riskscore.index.translation.locked.json, RA-RiskIndexSi.ps1) -- its base values unchanged.
        $raw = @(foreach ($it in $rows) { ConvertFrom-SIProJson $it.Body })
        $positioned = @($raw | Where-Object { $_ -and $_.PSObject.Properties['Precedence'] -and -not [string]::IsNullOrWhiteSpace([string]$_.Precedence) }).Count
        $allV22 = ($raw.Count -gt 0) -and (@($raw | Where-Object { -not (Test-SIRiskIndexV22Form @($_)) }).Count -eq 0)
        $text = $null
        if ($positioned -eq 0 -and $allV22) {
            # an index from before the order (v2.2 rows): the v2.2 ladder puts it in first-match order with the same scores
            # (RA-RiskIndexOrder.ps1), then every row is translated
            # (a stored item carries a blank Precedence: drop it, or the ladder is skipped and the rows are only sorted)
            $noPos = @(foreach ($o in $raw) { $c = [ordered]@{}; foreach ($pp in $o.PSObject.Properties) { if ($pp.Name -ne 'Precedence') { $c[$pp.Name] = $pp.Value } }; [pscustomobject]$c })
            $text = ConvertTo-SIRiskIndexSiCsvText -OrderedRows @(ConvertTo-SIRiskIndexSiRows -Rows $noPos)
        } else {
            # First match wins: the rows in Precedence order, renumbered 1..n. A row with no place (an item made before the
            # index had an order) is checked after every placed row -- said, so it is reviewed in the Risk index editor.
            if ($positioned -lt $raw.Count) { $out.Notes.Add(("riskindex: {0} row(s) have no place in the order (made before the risk index had one) -- they are checked after the other rows; give them a place on the Risk index page" -f ($raw.Count - $positioned))) }
            $bodies = @(foreach ($o in $raw) { [pscustomobject](ConvertTo-SIRiskIndexSiRow -Row $o) })
            $text = ConvertTo-SIRiskIndexSiCsvText -OrderedRows @(ConvertTo-SIRiskIndexSiRows -Rows $bodies)
        }
        & $ensureRa
        Write-SIProFile -Path (Join-SIProPath $rp $script:SIProRiskIndexFile) -Text $text
        $out.RiskIndexRows = $rows.Count; $raWritten = $true
    }
    # exclusions: the documents, merged with what exemptions add
    $plan = Get-SIProExemptionPlan -Active @($Exemptions) -QueryOf $queryOf
    # A document no exemption touches is written byte for byte (Pro-1b); one an exemption adds to is re-serialised.
    $exclDocs = [ordered]@{}
    foreach ($doc in @($Documents | Where-Object { $_.Kind -eq 'exclusions' })) { $exclDocs[$doc.Key] = $doc.Body }
    foreach ($rep in @($plan.Exclusions.Keys)) {
        $o = if ($exclDocs.Contains($rep)) { ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $exclDocs[$rep]) } else { [ordered]@{ '_source' = 'cfg.Exemption (SecurityInsight Pro)' } }
        foreach ($prop in 'ExcludedCves', 'ExcludedConfigurationIds') {
            $add = @($plan.Exclusions[$rep][$prop])
            if (-not $add.Count) { continue }
            $have = @(); if ($o.Contains($prop)) { $have = @($o[$prop] | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }
            $o[$prop] = @($have + @($add | Where-Object { $have -notcontains $_ }))
        }
        $exclDocs[$rep] = ConvertTo-SIProJson -Value $o
        $out.Exemptions += @($plan.Exclusions[$rep]['ExcludedCves']).Count + @($plan.Exclusions[$rep]['ExcludedConfigurationIds']).Count
    }
    foreach ($key in @($exclDocs.Keys)) {
        $pageKey = if ($key -eq 'global') { 'exclusions:global' } else { 'exclusions:' + $key }
        $target = Resolve-SIJsonTarget -SIRoot ([string]$Context.SIRoot) -Key $pageKey -Reports @($Context.Reports)
        if (-not $target) { throw ("no settings file for the exclusions of {0}" -f $key) }
        & $ensureRa
        Write-SIProFile -Path (Join-SIProPath $rp ([System.IO.Path]::GetFileName($target))) -Text $exclDocs[$key]
        $out.Exclusions++; $raWritten = $true
    }
    if ($plan.Marked.Count) {
        $file = [ordered]@{
            '_purpose' = 'SecurityInsight Pro: the approved exemptions (cfg.Exemption). Written by the settings layer for this run; engine\risk-analysis\_shared\RA-Exemptions.ps1 MARKS the rows each one covers (never drops them).'
            matchAssetColumns   = @('SI_AssetId', 'SI_CorrelationId', 'AssetId', 'AssetName', 'DeviceName', 'DeviceId')
            matchFindingColumns = @('CveId', 'Cve', 'CVE', 'ConfigurationId')
            exemptions = @($plan.Marked | ForEach-Object { [ordered]@{ id = $_.Id; scope = $_.Scope; report = $_.ReportName; assetKey = $_.AssetKey; cve = $_.Cve; configurationId = $_.ConfigurationId; expiresAt = $_.ExpiresAt; requestId = $(if ($_.PSObject.Properties['RequestId']) { $_.RequestId } else { $null }); reason = $_.Reason } })
        }
        & $ensureRa
        Write-SIProFile -Path (Join-SIProPath $rp $script:SIProExemptionsFile) -Text (ConvertTo-SIProJson -Value $file)
        $out.Exemptions += $plan.Marked.Count; $raWritten = $true
    }
    # weights: the document (+ the model sections beside it), and per-report files
    $wdoc = @($Documents | Where-Object { $_.Kind -eq 'weights' }) | Select-Object -First 1
    $model = @(& $kindItems 'weights' | Where-Object { $_.Key -eq 'model' }) | Select-Object -First 1
    if ($wdoc -or $model) {
        $text = $null
        if ($wdoc -and -not $model) { $text = $wdoc.Body }   # Pro-1b: byte for byte
        else {
            $w = [ordered]@{}
            if ($model) { $m = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $model.Body); foreach ($k in @($m.Keys)) { $w[$k] = $m[$k] } }
            if ($wdoc) { $d = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $wdoc.Body); foreach ($k in @($d.Keys)) { $w[$k] = $d[$k] } }
            $text = ConvertTo-SIProJson -Value $w
        }
        & $ensureRa
        Write-SIProFile -Path (Join-SIProPath $rp 'riskscore_weighted.schema.custom.json') -Text $text
        $out.Weights++; $raWritten = $true
    }
    foreach ($it in @(& $kindItems 'weights' | Where-Object { $_.Key -like 'report/*' })) {
        & $ensureRa
        Write-SIProFile -Path (Join-SIProPath $rp ('{0}.weighted.custom.json' -f $it.Key.Substring(7))) -Text $it.Body
        $out.Weights++; $raWritten = $true
    }
    if ($raWritten) { $out.RaSettingsPath = $rp }

    # ---- config\ -----------------------------------------------------------------------------------------------------
    $cr = Join-SIProPath $RunFolder 'config'
    # #251: the CMDB ownership map is the customer's configuration document (cmdbownership/map) -- the whole map, written
    # where engine\asset-cmdb\_shared\SI-CmdbOwnership.ps1 looks first (SI_ProConfigRoot). No document = the installation's
    # shipped map, as on a Community install.
    $ownMap = @(& $kindItems 'cmdbownership' | Where-Object { $_.Key -eq 'map' }) | Select-Object -First 1
    if ($ownMap) {
        $root = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $ownMap.Body)
        Write-SIProFile -Path (Join-SIProPath $cr 'cmdb-source-ownership.locked.json') -Text (ConvertTo-SIProJson -Value ([ordered]@{ '_source' = 'SecurityInsight Pro settings database (the CMDB ownership configuration), materialised for this run'; cmdbSourceOwnership = $root }))
        $out.ConfigFiles++; $out.ConfigRoot = $cr
    }
    if ($Families['servicemodel']) {
        $sm = @(& $kindItems 'servicemodel' | Where-Object { $_.Key -eq 'model' }) | Select-Object -First 1
        $body = if ($sm) { ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $sm.Body) } else { [ordered]@{ services = @(); bindings = @() } }
        Write-SIProFile -Path (Join-SIProPath $cr 'service-model.locked.json') -Text (ConvertTo-SIProJson -Value ([ordered]@{ '_source' = 'SecurityInsight Pro settings database, materialised for this run'; serviceModel = $body }))
        $out.ConfigFiles++; $out.ConfigRoot = $cr
    }
    $tagCfg = @(& $kindItems 'assettagging' | Where-Object { $_.Key -eq 'config' }) | Select-Object -First 1
    if ($tagCfg) { Write-SIProFile -Path (Join-SIProPath $cr 'asset-tagging.config.json') -Text $tagCfg.Body; $out.ConfigFiles++; $out.ConfigRoot = $cr }
    if ($Families['assettagging']) {
        $tags = @(& $kindItems 'assettagging' | Where-Object { $_.Key -like 'tag/*' })
        $text = ConvertTo-SIProJson -Value ([ordered]@{ AssetTagging = @($tags | ForEach-Object { ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $_.Body) }) })
        $tp = Join-SIProPath $cr 'asset-tagging'
        Write-SIProFile -Path (Join-SIProPath $tp 'AssetTagging.locked.yaml') -Text $text
        $out.ConfigFiles++; $out.ConfigRoot = $cr; $out.AssetTaggingPath = $tp
    }
    foreach ($it in @(& $kindItems 'schemaoverlay')) {
        $base = if ($it.Key -eq 'publicip') { 'public-ip' } else { $it.Key }
        Write-SIProFile -Path (Join-SIProPath $cr 'asset-profiling-schema' ('{0}.schema.custom.json' -f $base)) -Text $it.Body
        $out.ConfigFiles++; $out.ConfigRoot = $cr
    }
    # #275 R6: the server-application catalog override, where its loader looks first (SI_ProConfigRoot)
    $apps = @(& $kindItems 'serverapps' | Where-Object { $_.Key -eq 'catalog' }) | Select-Object -First 1
    if ($apps) { Write-SIProFile -Path (Join-SIProPath $cr 'server-applications.json') -Text $apps.Body; $out.ConfigFiles++; $out.ConfigRoot = $cr }
    # #274: the output scope per destination -- ONE file, every named report template resolved to its reports here (the
    # templates of THIS run: the database's when the catalog is served from SQL, else the installation's catalog), so the
    # engines and connectors never read the catalog themselves. No item = no file = everything passes, as before.
    $scopes = @(& $kindItems 'outputscope')
    if ($scopes.Count) {
        $membership = Get-SIProTemplateMembership -Items @(& $kindItems 'rareport') -FromItems ([bool]($Families['rareport'] -or @(& $kindItems 'rareport').Count)) -SIRoot ([string]$Context.SIRoot)
        $dests = [ordered]@{}
        foreach ($it in $scopes) {
            $o = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $it.Body)
            $tpl = @(Get-SIOutputScopeList $o 'templates'); $rep = @(Get-SIOutputScopeList $o 'reports')
            if (($tpl.Count + $rep.Count) -gt 0) {
                $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                foreach ($r in $rep) { [void]$set.Add([string]$r) }
                foreach ($t in $tpl) {
                    if (-not $membership.Contains([string]$t)) { $out.Notes.Add(("outputscope/{0}: the report template '{1}' does not exist in this run -- it lets no report through" -f $it.Key, $t)); continue }
                    foreach ($r in @($membership[[string]$t])) { [void]$set.Add([string]$r) }
                }
                $arr = [string[]]@($set); [Array]::Sort($arr, [System.StringComparer]::Ordinal)
                $o['resolvedReports'] = @($arr)
            }
            $dests[$it.Key] = $o
        }
        Write-SIProFile -Path (Join-SIProPath $cr 'output-scope.json') -Text (ConvertTo-SIProJson -Value ([ordered]@{ '_source' = 'SecurityInsight Pro settings database (the output scope per destination), materialised for this run'; destinations = $dests }))
        $out.ConfigFiles++; $out.ConfigRoot = $cr
    }
    # ---- #456: the data model -> <run>\data-model (SI_DataModelRoot): served from the database once its templates exist --
    $dmItems = @(& $kindItems 'datamodel')
    if ($Families['datamodel'] -or $dmItems.Count) {
        $dm = Export-SIDataModelProRoot -Items $dmItems -RunFolder $RunFolder -ShippedRoot (Join-SIProPath ([string]$Context.SIRoot) 'data-model') `
            -FromJson { param($s) ConvertFrom-SIProJson $s } -ToJson { param($v) ConvertTo-SIProJson -Value $v }
        $out.DataModelRoot = [string]$dm.Root
        $out.DataModelItems = $dmItems.Count
        foreach ($n in @($dm.Notes)) { if ($n) { $out.Notes.Add([string]$n) } }
        if (@($dm.Copied).Count -and $dmItems.Count) { $out.Notes.Add(('data model: {0} template file(s) are not in the settings database yet and come from the installation: {1}' -f @($dm.Copied).Count, (@($dm.Copied) -join ', '))) }
    }
    # ---- naming: values, not files (applied by the layer) ------------------------------------------------------------
    foreach ($it in @(& $kindItems 'naming')) { $out.Naming[$it.Key] = [pscustomobject]@{ Value = [string](ConvertFrom-SIProJson $it.Body); Origin = $it.Origin } }
    [pscustomobject]$out
}

# =====================================================================================================================
#  WRITERS (transactional, each with its cfg.ChangeLog entry) -- the importer, the GUI and tools use these.
# =====================================================================================================================
function Set-SIProItem {
    <#
        Write one item's customer state: State override (with -Body), disable, or inherit (= go back to the template:
        the row is removed). Validated BEFORE any SQL by the same rules the run applies. -BaseVersion / -BaseHash: the
        template the override was made against. ChangeLog: Name = key, Scope = 'item', Kind.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Key,
          [Parameter(Mandatory)][ValidateSet('override', 'disable', 'inherit')][string]$State, [AllowEmptyString()][string]$Body,
          [string]$Format, [string]$BaseVersion, [string]$BaseHash, [Parameter(Mandatory)][string]$ChangedBy, [string]$Reason = '', $Context)
    $spec = $script:SIProItemKinds[$Kind]
    if (-not $spec) { throw ("'{0}' is not a configuration kind" -f $Kind) }
    if ($Key -notmatch $spec.Key) { throw ("'{0}' is not a valid {1} key" -f $Key, $Kind) }
    # #251: a name is a setting now (Set-SIProSetting), and the ownership map is ONE document (cmdbownership/map)
    if ($Kind -eq 'naming' -and $State -ne 'inherit') { throw ("{0}: the names of tables, DCRs, DCE and workspace are settings -- set it with Set-SIProSetting (the catalog default applies otherwise)" -f $Key) }
    if ($Kind -eq 'cmdbownership' -and $Key -ne 'map' -and $State -ne 'inherit') { throw ("cmdbownership/{0}: the CMDB ownership map is one configuration document, cmdbownership/map" -f $Key) }
    if (-not $Format) { $Format = $spec.Format }
    $text = $null
    if ($State -eq 'override') {
        if (-not $Context) { $Context = Get-SIProConfigContext }
        $text = ([string]$Body).TrimStart([char]0xFEFF)
    }
    # mandatory controls FIRST: an override never switches off or weakens what SecurityInsight requires, and that plain
    # reason is the one given (the item rules may refuse the same change in their own words, e.g. a built-in factor)
    $mroot = if ($Context -and $Context.PSObject.Properties['SIRoot'] -and $Context.SIRoot) { [string]$Context.SIRoot } else { $script:SIProConfigSIRoot }
    $mwhy = @(Test-SIProMandatoryOverride -Controls @(Get-SIProMandatoryControls -SIRoot $mroot) -Kind $Kind -Key $Key -State $State -Body $text)
    if ($mwhy.Count) { throw ("nothing written: {0}" -f ($mwhy -join '; ')) }
    if ($State -eq 'override') {
        $why = @(Test-SIProItem -Kind $Kind -Key $Key -Body $text -Format $Format -Context $Context)
        if ($why.Count) { throw ("{0}/{1} is not valid: {2}" -f $Kind, $Key, ($why -join '; ')) }
    }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT State + COALESCE(':' + BodyJson, '') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key);
IF @State = 'inherit'
    DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
ELSE IF @old IS NOT NULL
    UPDATE cfg.ItemOverride SET State = @State, BodyJson = @Body, Format = @Format, BaseVersion = @BaseVersion, BaseHash = @BaseHash, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@Kind, @Key, @State, @Body, @Format, @BaseVersion, @BaseHash, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, 'item', @Kind, CASE WHEN @State = 'inherit' THEN 'Reset' ELSE 'Set' END, @old, @State + COALESCE(':' + @Body, ''), @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Kind = $Kind; Key = $Key; State = $State; Body = $text; Format = $Format
        BaseVersion = $(if ($BaseVersion) { $BaseVersion } else { $null }); BaseHash = $(if ($BaseHash) { $BaseHash } else { $null }); By = $ChangedBy; Reason = $Reason }) 'nonquery'
}

function New-SIProExemption {
    <# Record one exemption (validated first by the rules the run applies), with its ChangeLog entry, in one transaction. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][ValidateSet('finding', 'issue', 'asset')][string]$Scope, [string]$ReportName,
          [string]$ConfigurationId, [string]$Cve, [string]$AssetKey, [Parameter(Mandatory)][string]$Reason, [Nullable[datetime]]$ExpiresAt,
          [Parameter(Mandatory)][string]$CreatedBy, $Context)
    if (-not $Context) { $Context = Get-SIProConfigContext }
    $row = @{ ExemptionId = '0'; Scope = $Scope; ReportName = $ReportName; ConfigurationId = $ConfigurationId; Cve = $Cve; AssetKey = $AssetKey; Reason = $Reason; ExpiresAt = $ExpiresAt; RevokedAt = $null }
    $c = ConvertFrom-SIProExemptionRows -Rows @($row) -Context $Context -Now ([datetime]::MinValue)
    if (@($c.Refused).Count) { throw ('the exemption is not valid: ' + $c.Refused[0].Reason) }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
INSERT cfg.Exemption (Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy) VALUES (@Scope, @Report, @Cfg, @Cve, @Asset, @Reason, @Expires, @By);
DECLARE @id bigint = SCOPE_IDENTITY();
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (CONCAT('exemption/', CONVERT(nvarchar(30), @id)), 'exemption', 'exemption', 'Set', NULL, CONCAT(@Scope, '|', @Report, '|', @Cve, '|', @Cfg, '|', @Asset, '|', CONVERT(varchar(30), @Expires, 126)), @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Scope = $Scope; Report = $(if ($ReportName) { $ReportName } else { $null }); Cfg = $(if ($ConfigurationId) { $ConfigurationId } else { $null })
        Cve = $(if ($Cve) { $Cve.ToUpperInvariant() } else { $null }); Asset = $(if ($AssetKey) { $AssetKey } else { $null }); Reason = $Reason
        Expires = (ConvertTo-SIProUtc $ExpiresAt); By = $CreatedBy }) 'nonquery'
}

function Revoke-SIProExemption {
    <# Revoke one exemption (it stays, with RevokedAt / RevokedBy), with its ChangeLog entry, in one transaction. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][long]$ExemptionId, [Parameter(Mandatory)][string]$RevokedBy, [string]$Reason = '')
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
UPDATE cfg.Exemption SET RevokedAt = SYSUTCDATETIME(), RevokedBy = @By WHERE ExemptionId = @Id AND RevokedAt IS NULL;
IF @@ROWCOUNT = 1
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (CONCAT('exemption/', CONVERT(nvarchar(30), @Id)), 'exemption', 'exemption', 'Reset', 'active', 'revoked', @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Id = $ExemptionId; By = $RevokedBy; Reason = $Reason }) 'nonquery'
}

# =====================================================================================================================
#  TEMPLATES FROM THE SHIPPED FILES (Publish-SITemplates; the importer diffs against the same rows)
# =====================================================================================================================
function Get-SIProShippedVersion {
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = Join-SIProPath $SIRoot 'VERSION'
    if (Test-Path -LiteralPath $p) { return ([System.IO.File]::ReadAllText($p)).Trim() }
    '0.0.0'
}

function Get-SITemplateRows {
    <#
        The template rows a release ships -- VENDOR-DEVELOPED content only (#251) -- built from its *.locked files:
          rareport      risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml        report/<name>, template/<name>
          riskindex     risk-analysis-detection\riskscore.index.locked.csv (shipped)    row/<dimensions>
          rule          asset-profiling-enrichment\<engine>\**\*.locked.yaml             <engine>/<id> (YAML text)
          assettagging  asset-profiling-enrichment\endpoint\AssetTagging.locked.yaml     tag/<STEM--SI>
          servicemodel  config\service-model.locked.json                                 model
          datamodel     data-model\**\*.locked.json (#456)                                <template>, <template>:<item key>
        NOT templates: the names of tables / DCRs / DCE / workspace (settings -- the catalog default is the default) and the
        CMDB ownership map (the customer's configuration, seeded from config\cmdb-source-ownership.locked.json); nor the
        profile schemas (asset-profiling-schema\*.locked.json) -- they are the engines' data contract (hashes, entity ids),
        not configuration; a customer's schema OVERLAY is an item (schemaoverlay).
        -Version (stamped on every row): default the shipped template pack's version (engine\pro-settings\
        shipped-template-pack.json, 1.0) -- template versions are their own series, not the code version.
        Every row is validated as the run will validate it; one that does not is returned in Refused, never published.
        -Families limits what is built (tests).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$Version, $Context, [string[]]$Families)
    if (-not $Version) { $Version = (Get-SIProShippedPackInfo -SIRoot $SIRoot).PackVersion }
    # #416: building the rows takes ~30 s (780 templates, each validated, serialised and hashed) and ONE update ran it three
    # times (the template gate, the split check, the install) -- the same files give the same rows, so a process keeps the
    # result for files it has already read (Get-SITemplateRowsCacheKey: every input file's path, size and write time).
    # Never with a caller's own -Context. Every caller gets its OWN copies of the rows.
    $cacheKey = $null
    if (-not $PSBoundParameters.ContainsKey('Context')) {
        $cacheKey = Get-SITemplateRowsCacheKey -SIRoot $SIRoot -Version $Version -Families $Families
        $hit = Get-SITemplateRowsCached -Key $cacheKey
        if ($hit) { return $hit }
    }
    if (-not $Context) { $Context = Get-SIProConfigContext -SIRoot $SIRoot }
    $want = { param($k) (-not $Families) -or ($Families -contains $k) }
    $rows = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$kind, [string]$key, [string]$body, [string]$fmt, [int]$order, [string]$source)
        $why = @(Test-SIProItem -Kind $kind -Key $key -Body $body -Format $fmt -Context $Context)
        if ($why.Count) { $refused.Add([pscustomobject]@{ Name = ('{0}/{1}' -f $kind, $key); Scope = 'template'; Reason = ('{0}: {1}' -f $source, ($why -join '; ')) }); return }
        $rows.Add([pscustomobject]@{ Kind = $kind; ItemKey = $key; TemplateVersion = $Version; BodyJson = $body; Format = $fmt; SortOrder = $order; BodyHash = (Get-SIProTextHash $body)
            ContentHash = (Get-SIProContentHash -Body $body -Format $fmt); Source = $source })
    }
    if (& $want 'rareport') {
        $p = Join-SIProPath $SIRoot 'risk-analysis-detection' 'RiskAnalysis_Queries_Locked.yaml'
        if (Test-Path -LiteralPath $p) {
            $y = ConvertFrom-SIYaml -Path $p -Ordered
            $i = 0; foreach ($r in @($y['Reports'])) { & $add 'rareport' ('report/' + [string]$r['ReportName']) (ConvertTo-SIProJson -Value $r -Level 2) 'json' ($i++) 'risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml' }
            $i = 100000; foreach ($r in @($y['ReportTemplates'])) { & $add 'rareport' ('template/' + [string]$r['ReportName']) (ConvertTo-SIProJson -Value $r -Level 2) 'json' ($i++) 'risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml' }
        }
    }
    if (& $want 'riskindex') {
        $p = Join-SIProPath $SIRoot 'risk-analysis-detection' 'riskscore.index.locked.csv'
        if (Test-Path -LiteralPath $p) {
            $seen = @{}; $i = 0
            foreach ($r in @(Import-Csv -LiteralPath $p)) {
                $o = [ordered]@{}; foreach ($c in $script:SIRiskIndexColumns) { $o[$c] = $(if ($r.PSObject.Properties[$c]) { [string]$r.$c } else { '' }) }
                $key = Get-SIRiskIndexKey -Row $o
                # the engine's index keeps EVERY row (a repeated row adds to its lists), so a repeat is published as
                # '<dimensions>#<n>' -- the materialised file is then the shipped file, row for row
                if ($seen.ContainsKey($key)) { $seen[$key]++; $key = '{0}#{1}' -f $key, $seen[$key] } else { $seen[$key] = 1 }
                & $add 'riskindex' $key (ConvertTo-SIProJson -Value $o) 'json' ($i++) 'risk-analysis-detection/riskscore.index.locked.csv'
            }
        }
    }
    if (& $want 'rule') {
        $tree = Join-SIProPath $SIRoot 'asset-profiling-enrichment'
        $files = @(Get-ChildItem -LiteralPath $tree -Recurse -File -Filter '*.locked.yaml' -ErrorAction SilentlyContinue)
        $relU = [string[]]@($files | ForEach-Object { $_.FullName.Substring($tree.Length).TrimStart('\', '/').Replace('\', '/') })
        $order = Get-SIProOrdinalOrder -Keys $relU
        $rel = [string[]]@(foreach ($i in $order) { $relU[$i] }); $fa = @(foreach ($i in $order) { $files[$i] })
        $i = 0
        for ($n = 0; $n -lt $fa.Count; $n++) {
            $text = ([System.IO.File]::ReadAllText($fa[$n].FullName)).TrimStart([char]0xFEFF)
            if ($text -match '(?m)^AssetTagging\s*:') { continue }   # the asset-tagging file shares the folder; it is its own kind
            $engine = $rel[$n].Split('/')[0].ToLowerInvariant()
            $h = Get-SIRuleHeader -Text $text
            $id = if ($h.Id) { $h.Id } else { $fa[$n].Name -replace '\.locked\.yaml$', '' }
            & $add 'rule' ('{0}/{1}' -f $engine, $id) $text 'yaml' ($i++) ('asset-profiling-enrichment/' + $rel[$n])
        }
    }
    if (& $want 'assettagging') {
        $p = Join-SIProPath $SIRoot 'asset-profiling-enrichment' 'endpoint' 'AssetTagging.locked.yaml'
        if (Test-Path -LiteralPath $p) {
            $y = ConvertFrom-SIYaml -Path $p -Ordered
            $i = 0
            foreach ($t in @($y['AssetTagging'] | Where-Object { $null -ne $_ })) {
                $stem = Get-SIProAssetTagStemKey ([string]$t['AssetTagName'])
                & $add 'assettagging' ('tag/' + $stem) (ConvertTo-SIProJson -Value $t) 'json' ($i++) 'asset-profiling-enrichment/endpoint/AssetTagging.locked.yaml'
            }
        }
    }
    # #251: no cmdbownership and no naming rows -- the ownership map and the names are configuration (see the kinds above).
    if (& $want 'servicemodel') {
        $p = Join-SIProPath $SIRoot 'config' 'service-model.locked.json'
        if (Test-Path -LiteralPath $p) {
            $sm = (ConvertTo-SIOrderedJson (ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($p))))['serviceModel']
            & $add 'servicemodel' 'model' (ConvertTo-SIProJson -Value $sm) 'json' 0 'config/service-model.locked.json'
        }
    }
    # #456: the data model -- one row per field / mapping / factor / output column, plus each template's header
    if (& $want 'datamodel') {
        foreach ($r in (Get-SIDataModelTemplateRows -SIRoot $SIRoot -ToJson { param($v) ConvertTo-SIProJson -Value $v })) {
            & $add 'datamodel' $r.Key $r.Body 'json' ([int]$r.SortOrder) $r.Source
        }
    }
    $result = [pscustomobject]@{ Version = $Version; Rows = $rows.ToArray(); Refused = $refused.ToArray() }
    if ($cacheKey) { Set-SITemplateRowsCached -Key $cacheKey -Result $result; return (Get-SITemplateRowsCached -Key $cacheKey) }
    $result
}

function Get-SITemplateRowsCacheKey {
    <#
        #416: what the shipped template rows are built from, as one string: the root, the version, the families and every
        input file's relative path + size + last write time (the template sources, the shipped config the validation reads,
        the code that builds and validates them). A changed, added or removed file = another key.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$Version, [string[]]$Families)
    $root = [IO.Path]::GetFullPath($SIRoot).TrimEnd('\', '/')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($root).Append('|').Append($Version).Append('|').Append((@($Families) -join ',')).Append("`n")
    foreach ($d in @(@('risk-analysis-detection', $false), @('asset-profiling-enrichment', $true), @('config', $false), @(([IO.Path]::Combine('engine', 'pro-settings')), $false), @('data-model', $true))) {
        $dir = [IO.Path]::Combine($root, $d[0])
        if (-not [IO.Directory]::Exists($dir)) { continue }
        $opt = if ($d[1]) { [IO.SearchOption]::AllDirectories } else { [IO.SearchOption]::TopDirectoryOnly }
        $fs = [IO.Directory]::GetFiles($dir, '*', $opt); [Array]::Sort($fs, [StringComparer]::Ordinal)
        foreach ($f in $fs) { $i = New-Object IO.FileInfo($f); [void]$sb.Append($f.Substring($root.Length)).Append('|').Append($i.Length).Append('|').Append($i.LastWriteTimeUtc.Ticks).Append("`n") }
    }
    foreach ($f in @([IO.Path]::Combine($root, 'engine', '_shared', 'SI-Yaml.ps1'), [IO.Path]::Combine($root, 'engine', 'asset-profiling', 'shared', 'RuleEval.ps1'))) {
        if ([IO.File]::Exists($f)) { $i = New-Object IO.FileInfo($f); [void]$sb.Append($f.Substring($root.Length)).Append('|').Append($i.Length).Append('|').Append($i.LastWriteTimeUtc.Ticks).Append("`n") }
    }
    $sb.ToString()
}

function Get-SITemplateRowsCached {
    <# #416: the cached rows for -Key, as NEW copies (a caller may change its rows), or $null. The cache lives in the process. #>
    param([Parameter(Mandatory)][string]$Key)
    $c = [AppDomain]::CurrentDomain.GetData('SecurityInsight.TemplateRows')
    if ($null -eq $c -or -not $c.ContainsKey($Key)) { return $null }
    $r = $c[$Key]
    [pscustomobject]@{ Version = $r.Version; Rows = @(foreach ($x in $r.Rows) { $x.PSObject.Copy() }); Refused = @(foreach ($x in $r.Refused) { $x.PSObject.Copy() }) }
}

function Set-SITemplateRowsCached {
    <# #416: keeps the rows for -Key (the newest few keys only). #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)]$Result)
    $c = [AppDomain]::CurrentDomain.GetData('SecurityInsight.TemplateRows')
    if ($null -eq $c) { $c = [hashtable]::Synchronized(@{}); [AppDomain]::CurrentDomain.SetData('SecurityInsight.TemplateRows', $c) }
    if ($c.Count -ge 8) { $c.Clear() }
    $c[$Key] = $Result
}

# =====================================================================================================================
#  #250 -- THE SHIPPED TEMPLATES ARE TEMPLATE PACK 1.0 ("Default templates 1.0"), like the old .locked files
# =====================================================================================================================
function Get-SIProShippedPackInfo {
    <#
        The template pack the templates shipped with this code ARE: engine\pro-settings\shipped-template-pack.json
        (PackVersion, Name). Template pack versions are their own series starting at 1.0 -- never the code version. A
        missing or unreadable file reads as 1.0.
    #>
    param([string]$SIRoot)
    if (-not $SIRoot) { $SIRoot = $script:SIProConfigSIRoot }
    $v = '1.0'; $n = ''; $reviewed = $false
    $p = Join-SIProPath $SIRoot 'engine' 'pro-settings' 'shipped-template-pack.json'
    if (Test-Path -LiteralPath $p) {
        try {
            $o = ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF))
            $pv = ([string]$o.PackVersion).Trim()
            if ($pv -match '^\d{1,6}(\.\d{1,12}){1,5}$' -and $pv.Length -le 32) { $v = $pv }
            $n = ([string]$o.Name).Trim()
            # #405: the split install (fix + default with the code, Microsoft content packs automatic) runs only when the
            # vendor marked the shipped templates' classification as reviewed; absent or anything but true = false
            if ($o.PSObject.Properties['ClassificationReviewed'] -and $o.ClassificationReviewed -is [bool]) { $reviewed = [bool]$o.ClassificationReviewed }
        } catch { }
    }
    if (-not $n) { $n = 'Default templates {0}' -f $v }
    [pscustomobject]@{ PackVersion = $v; Name = $n; ClassificationReviewed = $reviewed }
}

function Get-SIProDefaultTemplateDecision {
    <#
        PURE. What a setup / update run does with the templates SHIPPED with its code (pack -ShippedVersion), on an install
        that recorded -InstalledPack (cfg.InstallState 'TemplatePack', '' = none) and has -LiveCount templated rows whose
        fingerprint is -InstalledFingerprint; -ShippedFingerprint = the shipped templates'.
          install          no templates yet                          -> publish the shipped templates, record the pack
          adopt            templates, no pack recorded, the SAME content as the shipped ones -> record the pack (as released)
          adopt-customised templates, no pack recorded, OTHER content   -> record "customised, based on <shipped>"; the
                           shipped pack is offered (staged) but nothing in force changes without an acceptance
          current          the shipped pack is installed and in force  -> refresh (version stamps / content hashes only)
          newer-installed  a newer pack (from the update ring) is installed -> nothing: a pack never goes backwards
          shipped-differs  the shipped pack's version is installed, but this code ships OTHER content under that version --
                           never applied: a pack version names exactly one content (the vendor ships changes as a new pack)
          release          an older pack is installed                 -> publish the shipped pack through the gate
        Returns @{ Action; Publish (run the publish); Record (adoption: write the pack / status); Status; Reason }.
    #>
    param([AllowEmptyString()][string]$InstalledPack, [AllowEmptyString()][string]$InstalledStatus, [int]$LiveCount,
          [AllowEmptyString()][string]$InstalledFingerprint, [Parameter(Mandatory)][string]$ShippedVersion,
          [AllowEmptyString()][string]$ShippedFingerprint, [string]$ShippedName)
    if (-not $ShippedName) { $ShippedName = 'Default templates {0}' -f $ShippedVersion }
    $mk = { param($a, [bool]$pub, [bool]$rec, $st, $why) [pscustomobject]@{ Action = $a; Publish = $pub; Record = $rec; Status = $st; Reason = $why } }
    $same = ([string]$InstalledFingerprint -ne '') -and ($InstalledFingerprint -eq $ShippedFingerprint)
    # A pack recorded BEFORE template packs had their own version series (1.0, 1.1, ...) carries the CODE version
    # (e.g. '3.0.0') and no pack status -- the new code always records one. It is not a pack: decide by content, like an
    # install with no pack recorded (live 2026-10-04: '3.0.0' read as newer than 1.0 and blocked the adoption).
    if ($InstalledPack -and -not $InstalledStatus) {
        $major = 0
        if ([int]::TryParse((([string]$InstalledPack).Trim().Split('.')[0]), [ref]$major) -and $major -ge 2) { $InstalledPack = '' }
    }
    if (-not $InstalledPack) {
        if ($LiveCount -le 0) { return (& $mk 'install' $true $false 'as-released' ('no templates yet -- installing {0}' -f $ShippedName)) }
        if ($same) { return (& $mk 'adopt' $true $true 'as-released' ('the templates in force are {0} -- recorded as installed' -f $ShippedName)) }
        return (& $mk 'adopt-customised' $false $true 'customised' ('the templates in force differ from {0} -- recorded as customised, based on {1}; your templates are kept, and {0} is offered on the Template releases page' -f $ShippedName, $ShippedVersion))
    }
    $cmp = Compare-SIProVersionParts $InstalledPack $ShippedVersion
    if ($cmp -gt 0) { return (& $mk 'newer-installed' $false $false $InstalledStatus ('template pack {0} is installed, newer than {1} -- nothing to do' -f $InstalledPack, $ShippedName)) }
    if ($cmp -eq 0) {
        if ($same -or $LiveCount -le 0) { return (& $mk 'current' $true $false $InstalledStatus ('{0} is installed' -f $ShippedName)) }
        if ($InstalledStatus -eq 'customised') { return (& $mk 'current' $false $false 'customised' ('{0} is installed, customised -- your templates are kept' -f $ShippedName)) }
        return (& $mk 'shipped-differs' $false $false $InstalledStatus ('{0} is installed; this release ships other template content under the same version -- it is not applied (template changes arrive as a new pack)' -f $ShippedName))
    }
    & $mk 'release' $true $false 'as-released' ('template pack {0} is installed -- {1} is released through the template gate' -f $InstalledPack, $ShippedName)
}

function Compare-SIProVersionParts {
    <# PURE. -1 / 0 / 1, numeric per part (64-bit), a missing part counts as 0 -- the same rule as Compare-SIProPackVersion. #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $pa = @(([string]$A).Trim().Split('.') | Where-Object { $_ -ne '' }); $pb = @(([string]$B).Trim().Split('.') | Where-Object { $_ -ne '' })
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { [void][long]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][long]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    0
}

# =====================================================================================================================
#  #251 -- NAMING AND CMDB OWNERSHIP BECOME CONFIGURATION (carried over 1:1, nothing lost)
# =====================================================================================================================
function Get-SIProShippedOwnershipMap {
    <# The shipped CMDB ownership map (config\cmdb-source-ownership.locked.json -> its cmdbSourceOwnership object) as JSON
       text, keys in file order; $null when the file is missing. What setup seeds the configuration document with. #>
    param([string]$SIRoot)
    if (-not $SIRoot) { $SIRoot = $script:SIProConfigSIRoot }
    $p = Join-SIProPath $SIRoot 'config' 'cmdb-source-ownership.locked.json'
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $root = (ConvertTo-SIOrderedJson (ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF))))['cmdbSourceOwnership']
    if ($null -eq $root) { return $null }
    ConvertTo-SIProJson -Value $root
}

function ConvertTo-SIProOwnershipMap {
    <#
        PURE. The CMDB ownership map built from its LEGACY rows -- exactly what the run materialised from them before #251:
        the live cmdbownership templates ('defaults' + one 'assettype/<type>' each, in SortOrder), every customer override
        replacing its entry (an override of an entry with no template adds it, after the template entries, by key), a
        'disable' removing it. -Shipped (the shipped map text) is the base when there are no template rows.
        Returns the map as JSON text, or $null when there is nothing to build from.
    #>
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Overrides = @(), [string]$Shipped)
    $entries = [ordered]@{}; $order = @{}
    $live = @($Templates | Where-Object { $_ -and [string](Get-SIProRowValue $_ 'Kind') -eq 'cmdbownership' -and $null -eq (Get-SIProRowValue $_ 'RetiredAt') })
    if ($live.Count) {
        foreach ($t in $live) {
            $k = [string](Get-SIProRowValue $t 'ItemKey'); $so = 0; [void][int]::TryParse([string](Get-SIProRowValue $t 'SortOrder'), [ref]$so)
            $entries[$k] = [string](Get-SIProRowValue $t 'BodyJson'); $order[$k] = '{0:D10}|{1}' -f $so, $k
        }
    } elseif ($Shipped) {
        $root = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $Shipped)
        $def = [ordered]@{}; foreach ($k in @($root.Keys)) { if ($k -ne 'assetTypes') { $def[$k] = $root[$k] } }
        $entries['defaults'] = ConvertTo-SIProJson -Value $def; $order['defaults'] = '{0:D10}|defaults' -f 0
        $i = 1
        foreach ($e in @($root['assetTypes'] | Where-Object { $null -ne $_ })) {
            $k = 'assettype/' + ([string]$e['siAssetType']).Trim().ToLowerInvariant()
            $entries[$k] = ConvertTo-SIProJson -Value $e; $order[$k] = '{0:D10}|{1}' -f ($i++), $k
        }
    }
    foreach ($o in @($Overrides | Where-Object { $_ -and [string](Get-SIProRowValue $_ 'Kind') -eq 'cmdbownership' })) {
        $k = [string](Get-SIProRowValue $o 'ItemKey'); if ($k -eq 'map') { continue }
        switch ([string](Get-SIProRowValue $o 'State')) {
            'override' { $entries[$k] = [string](Get-SIProRowValue $o 'BodyJson'); if (-not $order.ContainsKey($k)) { $order[$k] = '{0:D10}|{1}' -f [int]::MaxValue, $k } }
            'disable'  { if ($entries.Contains($k)) { $entries.Remove($k) } }
        }
    }
    if ($entries.Count -eq 0) { return $null }
    $map = [ordered]@{}
    if ($entries.Contains('defaults')) { $d = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $entries['defaults']); foreach ($k in @($d.Keys)) { if ($k -ne 'assetTypes') { $map[$k] = $d[$k] } } }
    $keys = [string[]]@($entries.Keys | Where-Object { $_ -like 'assettype/*' })
    $sorted = @(foreach ($i in (Get-SIProOrdinalOrder -Keys @($keys | ForEach-Object { $order[$_] }))) { $keys[$i] })
    $map['assetTypes'] = @($sorted | ForEach-Object { ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $entries[$_]) })
    ConvertTo-SIProJson -Value $map
}

function Get-SIProConfigurationMigrationPlan {
    <#
        PURE. What #251 carries over on an install (setup, the update hook and Import-SIProSettings -CreateSchema run it;
        it is idempotent -- a second run plans nothing):
          Settings  every naming OVERRIDE (State 'override') of a catalog naming setting becomes a cfg.Setting row
                    (Name, Scope 'solution', the same value) -- unless that setting already has a 'solution' row, which
                    already wins at run start (Kept). A 'disable' / 'inherit' carries nothing: the catalog default applies,
                    as it did. A name the catalog does not know is NotCarried (its row stays and is still applied).
          Map       the CMDB ownership configuration document cmdbownership/map when there is none yet: built from the
                    legacy rows when there are any (every customer override carried over), else the shipped map.
                    $null when the document exists.
          Retire    every live cfg.Template row of kind naming / cmdbownership: retired (RetiredAt), never removed.
        -Templates: cfg.Template rows; -Overrides: cfg.ItemOverride rows; -Settings: cfg.Setting rows; -Catalog: the
        settings catalog; -ShippedOwnershipMap: Get-SIProShippedOwnershipMap.
    #>
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Overrides = @(),
          [AllowEmptyCollection()][object[]]$Settings = @(), [AllowEmptyCollection()][object[]]$Catalog = @(), [string]$ShippedOwnershipMap)
    $byName = @{}; foreach ($s in @($Catalog | Where-Object { $_ })) { $byName[[string]$s.name] = $s }
    $have = @{}; foreach ($s in @($Settings | Where-Object { $_ })) { $have[('{0}|{1}' -f (Get-SIProRowValue $s 'Name'), (Get-SIProRowValue $s 'Scope'))] = $s }
    $set = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[object]; $not = New-Object System.Collections.Generic.List[object]
    $ovr = @($Overrides | Where-Object { $_ })
    $nm = @($ovr | Where-Object { [string](Get-SIProRowValue $_ 'Kind') -eq 'naming' -and [string](Get-SIProRowValue $_ 'State') -eq 'override' })
    foreach ($i in (Get-SIProOrdinalOrder -Keys @($nm | ForEach-Object { [string](Get-SIProRowValue $_ 'ItemKey') }))) {
        $o = $nm[$i]; $name = [string](Get-SIProRowValue $o 'ItemKey')
        $val = $null; try { $val = ConvertFrom-SIProJson ([string](Get-SIProRowValue $o 'BodyJson')) } catch { }
        $s = $byName[$name]
        if (-not $s -or $s.secret -or $val -isnot [string] -or (Test-SISettingValue -Setting $s -Value $val)) {
            $not.Add([pscustomobject]@{ Name = $name; Value = $val; Reason = $(if (-not $s) { 'not in the settings catalog -- the row stays and is still applied' } else { 'the value is not a valid setting value -- the row stays and is still applied' }) }); continue
        }
        $cur = $have[('{0}|solution' -f $name)]
        if ($cur) { $kept.Add([pscustomobject]@{ Name = $name; Value = $val; Setting = [string](Get-SIProRowValue $cur 'ValueJson') }); continue }
        $set.Add([pscustomobject]@{ Name = $name; Scope = 'solution'; Value = $val; From = ('naming/{0}' -f $name) })
    }
    $map = $null
    if (-not @($ovr | Where-Object { [string](Get-SIProRowValue $_ 'Kind') -eq 'cmdbownership' -and [string](Get-SIProRowValue $_ 'ItemKey') -eq 'map' }).Count) {
        $legacyT = @($Templates | Where-Object { $_ -and [string](Get-SIProRowValue $_ 'Kind') -eq 'cmdbownership' -and $null -eq (Get-SIProRowValue $_ 'RetiredAt') })
        $legacyO = @($ovr | Where-Object { [string](Get-SIProRowValue $_ 'Kind') -eq 'cmdbownership' })
        if ($legacyT.Count -or @($legacyO | Where-Object { [string](Get-SIProRowValue $_ 'State') -ne 'inherit' }).Count) {
            $body = ConvertTo-SIProOwnershipMap -Templates $legacyT -Overrides $legacyO -Shipped $ShippedOwnershipMap
            if ($body) { $map = [pscustomobject]@{ Body = $body; From = ('carried over: {0} template entr(ies), {1} of your change(s)' -f $legacyT.Count, @($legacyO | Where-Object { [string](Get-SIProRowValue $_ 'State') -ne 'inherit' }).Count) } }
        } elseif ($ShippedOwnershipMap) {
            $map = [pscustomobject]@{ Body = $ShippedOwnershipMap; From = 'the shipped default (config\cmdb-source-ownership.locked.json)' }
        }
    }
    $retire = @($Templates | Where-Object { $_ -and (Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $_ 'Kind'))) -and $null -eq (Get-SIProRowValue $_ 'RetiredAt') } |
        ForEach-Object { [pscustomobject]@{ Kind = [string](Get-SIProRowValue $_ 'Kind'); ItemKey = [string](Get-SIProRowValue $_ 'ItemKey') } })
    [pscustomobject]@{ Settings = $set.ToArray(); Kept = $kept.ToArray(); NotCarried = $not.ToArray(); Map = $map; Retire = @($retire)
        Empty = ($set.Count -eq 0 -and $null -eq $map -and @($retire).Count -eq 0) }
}

function Invoke-SIProConfigurationMigration {
    <#
        Apply Get-SIProConfigurationMigrationPlan to the database: the setting rows (Set-SIProSetting, each with its
        cfg.ChangeLog row), the ownership document (Set-SIProItem cmdbownership/map), and the retirement of the former
        template rows (RetiredAt + a cfg.ChangeLog row each; one transaction). The actor is the session. A carried-over map
        the run would refuse is NOT written (reported) -- the run keeps building it from the legacy rows, so nothing changes.
        Returns the plan plus Written = @{ Settings; Map; Retired } and Refused.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [object[]]$Catalog, $Context)
    if (-not $Catalog) { $Catalog = @(Get-SISettingsCatalog -SIRoot $SIRoot) }
    $tpl = @(Read-SIProTemplates -Store $Store); $ovr = @(Read-SIProItemOverrides -Store $Store); $set = @(Read-SIProSettings -Store $Store)
    $plan = Get-SIProConfigurationMigrationPlan -Templates $tpl -Overrides $ovr -Settings $set -Catalog $Catalog -ShippedOwnershipMap (Get-SIProShippedOwnershipMap -SIRoot $SIRoot)
    $by = '{0} (carried over: templates hold only vendor content)' -f (Get-SIProSessionActor)
    $written = [ordered]@{ Settings = 0; Map = $false; Retired = 0 }; $refused = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($plan.Settings)) {
        Set-SIProSetting -Store $Store -Catalog $Catalog -Name $s.Name -Scope $s.Scope -Action Set -Value $s.Value -ChangedBy $by -Reason ('carried over 1:1 from {0} (a name is a setting now)' -f $s.From)
        $written.Settings++
    }
    if ($plan.Map) {
        $why = @(Test-SIProOwnershipMap -Value $plan.Map.Body)
        if ($why.Count) { $refused.Add(('the CMDB ownership map was not written ({0}) -- it is still built from your earlier entries at run start' -f ($why -join '; '))) }
        else {
            if (-not $Context) { $Context = Get-SIProConfigContext -SIRoot $SIRoot -Catalog $Catalog }
            Set-SIProItem -Store $Store -Kind cmdbownership -Key map -State override -Body $plan.Map.Body -ChangedBy $by -Reason ('the CMDB ownership map is your configuration now -- {0}' -f $plan.Map.From) -Context $Context
            $written.Map = $true
        }
    }
    # the ownership rows are retired only once the map document holds what they said
    $retire = @($plan.Retire | Where-Object { $_.Kind -ne 'cmdbownership' -or -not $refused.Count })
    if ($retire.Count) {
        $sb = New-Object System.Text.StringBuilder; $p = [ordered]@{ By = $by }
        [void]$sb.AppendLine('SET XACT_ABORT ON;'); [void]$sb.AppendLine('BEGIN TRAN;')
        $i = 0
        foreach ($r in $retire) {
            $p["k$i"] = $r.Kind; $p["i$i"] = $r.ItemKey
            [void]$sb.AppendLine(("UPDATE cfg.Template SET RetiredAt = SYSUTCDATETIME() WHERE Kind = @k{0} AND ItemKey = @i{0} AND RetiredAt IS NULL;" -f $i))
            [void]$sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@i{0}, 'template', @k{0}, 'Reset', 'published', 'retired', @By, 'not a template any more -- it is configuration (kept as history)');" -f $i))
            $i++
        }
        [void]$sb.AppendLine('COMMIT;')
        & $Store.Invoke $sb.ToString() $p 'nonquery'
        $written.Retired = $i
    }
    $plan | Add-Member -NotePropertyName Written -NotePropertyValue ([pscustomobject]$written) -PassThru | Add-Member -NotePropertyName Refused -NotePropertyValue $refused.ToArray() -PassThru
}

function Get-SITemplatePublishPlan {
    <#
        PURE. What publishing -Rows over the database's current templates (-Existing) would do, per item:
          insert   new item;   update   body (hash) or version changed;   same   nothing to do;
          retire   in the database, not shipped any more (RetiredAt is set -- the row is never removed);
          revive   retired before, shipped again.
        Customer overrides are not read or touched: a version bump keeps every override.
        -RefreshMissingContentHash: an existing row without a ContentHash (published before template versioning) is
        updated even when nothing else changed, so every row carries one.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][object[]]$Existing = @(), [string[]]$Families,
          [switch]$RefreshMissingContentHash)
    $have = @{}; foreach ($e in @($Existing | Where-Object { $_ })) { $have[('{0}/{1}' -f (Get-SIProRowValue $e 'Kind'), (Get-SIProRowValue $e 'ItemKey'))] = $e }
    $ship = @{}
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        $name = '{0}/{1}' -f $r.Kind, $r.ItemKey; $ship[$name] = $true
        $e = $have[$name]
        $action = if (-not $e) { 'insert' }
                  elseif ($null -ne (Get-SIProRowValue $e 'RetiredAt')) { 'revive' }
                  elseif ([string](Get-SIProRowValue $e 'BodyHash') -ne $r.BodyHash -or [string](Get-SIProRowValue $e 'TemplateVersion') -ne $r.TemplateVersion -or [string](Get-SIProRowValue $e 'Source') -ne $r.Source -or [string](Get-SIProRowValue $e 'SortOrder') -ne [string]$r.SortOrder) { 'update' }
                  elseif ($RefreshMissingContentHash -and -not ([string](Get-SIProRowValue $e 'ContentHash')).Trim()) { 'update' }
                  else { 'same' }
        $plan.Add([pscustomobject]@{ Action = $action; Kind = $r.Kind; ItemKey = $r.ItemKey; Row = $r })
    }
    $kinds = if ($Families) { $Families } else { @($Rows | ForEach-Object { $_.Kind } | Select-Object -Unique) }
    foreach ($name in @($have.Keys)) {
        $e = $have[$name]
        if ($ship.ContainsKey($name) -or $null -ne (Get-SIProRowValue $e 'RetiredAt')) { continue }
        if ($kinds -notcontains [string](Get-SIProRowValue $e 'Kind')) { continue }
        $plan.Add([pscustomobject]@{ Action = 'retire'; Kind = [string](Get-SIProRowValue $e 'Kind'); ItemKey = [string](Get-SIProRowValue $e 'ItemKey'); Row = $null })
    }
    $u = $plan.ToArray()
    @(foreach ($i in (Get-SIProOrdinalOrder -Keys @($u | ForEach-Object { '{0}|{1}' -f $_.Kind, $_.ItemKey }))) { $u[$i] })
}

function Get-SIProStoreTransaction {
    <#
        The store's ONE-CONNECTION TRANSACTION: { param([scriptblock]$Body) } -- the body gets an invoke (sql, params, mode)
        bound to one open connection and one transaction, committed when it returns, rolled back on any error. The settings
        store has it (New-SIProSettingsStore: Transaction); a store that names its Server / Database / GetToken (the container
        updater's) gets one built here, and so does one with an OpenConnection { } (returns an OPEN SqlConnection -- the
        real-SQL tests). $null for a store with none of these (a test's fake): the caller then writes as before.
    #>
    param([Parameter(Mandatory)]$Store)
    if ($Store.PSObject.Properties['Transaction'] -and $Store.Transaction -is [scriptblock]) { return $Store.Transaction }
    $open = $null
    if ($Store.PSObject.Properties['OpenConnection'] -and $Store.OpenConnection -is [scriptblock]) { $open = $Store.OpenConnection }
    elseif ($Store.PSObject.Properties['GetToken'] -and $Store.GetToken -is [scriptblock] -and $Store.PSObject.Properties['Server'] -and "$($Store.Server)".Trim() -and $Store.PSObject.Properties['Database'] -and "$($Store.Database)".Trim()) {
        $cs = 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $Store.Server, $Store.Database
        $gt = $Store.GetToken
        $open = { $c = New-Object System.Data.SqlClient.SqlConnection($cs); $c.AccessToken = [string](& $gt); $c.Open(); $c }.GetNewClosure()
    }
    if ($open) {
        return {
            param([scriptblock]$Body)
            $cn = & $open
            $tx = $null
            try {
                $tx = $cn.BeginTransaction()
                $txInvoke = {
                    param([string]$tsql, $tp, [string]$tmode)
                    $tc = $cn.CreateCommand(); $tc.Transaction = $tx; $tc.CommandText = $tsql; $tc.CommandTimeout = 0
                    if ($tp) { foreach ($k in $tp.Keys) { [void]$tc.Parameters.AddWithValue('@' + $k, $(if ($null -eq $tp[$k]) { [System.DBNull]::Value } else { $tp[$k] })) } }
                    if ($tmode -eq 'reader') { $rd = $tc.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }; $rd.Close(); return , $out.ToArray() }
                    if ($tmode -eq 'scalar') { return $tc.ExecuteScalar() }
                    [void]$tc.ExecuteNonQuery()
                }.GetNewClosure()
                $r = & $Body $txInvoke
                $tx.Commit(); $tx = $null
                $r
            } catch {
                if ($tx) { try { $tx.Rollback() } catch { } }
                throw
            } finally { $cn.Dispose() }
        }.GetNewClosure()
    }
    $null
}

function Invoke-SITemplatePublish {
    <#
        Apply a publish plan: insert / update / revive / retire, each with a cfg.ChangeLog entry (Scope 'template', the
        version and content hash -- not the body, which can be large), in transactions of up to -BatchSize items. Every
        written row carries its normalised ContentHash, and each content is kept once in cfg.TemplateRevision. Never
        writes cfg.ItemOverride (it reads it only to leave an overridden or switched-off item out of the "upgraded"
        change-log entry). Needs the template-versioning schema (Publish-SITemplates checks it first).
        ATOMIC (ring 1 2026-10-10: a run that read the store while the first data-model publish was half-way saw part of the
        field catalog and stopped): every batch goes through the store's ONE-CONNECTION TRANSACTION (Get-SIProStoreTransaction)
        -- a reader sees the whole old set or the whole new one, never a mix (with READ COMMITTED SNAPSHOT, Azure SQL's default,
        the old set until the commit; without it the read waits for the commit). The batches stay (a command's parameters are
        limited), inside the one transaction. A store without one (a test's fake) gets the batches as before.
        -AfterBatch { param($BatchNo, $Invoke) }: test seam, called after each batch inside the transaction.
    #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyCollection()][object[]]$Plan = @(), [Parameter(Mandatory)][string]$ChangedBy, [int]$BatchSize = 100, [scriptblock]$AfterBatch)
    $work = @($Plan | Where-Object { $_.Action -ne 'same' })
    if (-not $work.Count) { return 0 }
    $txn = Get-SIProStoreTransaction -Store $Store
    $write = {
    param($Send)
    $batchNo = 0
    for ($s = 0; $s -lt $work.Count; $s += $BatchSize) {
        $chunk = @($work[$s..([Math]::Min($s + $BatchSize, $work.Count) - 1)])
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('SET XACT_ABORT ON;'); [void]$sb.AppendLine('BEGIN TRAN;')
        $p = [ordered]@{ By = $ChangedBy }
        for ($i = 0; $i -lt $chunk.Count; $i++) {
            $c = $chunk[$i]; $p["k$i"] = $c.Kind; $p["i$i"] = $c.ItemKey
            if ($c.Action -eq 'retire') {
                [void]$sb.AppendLine(("UPDATE cfg.Template SET RetiredAt = SYSUTCDATETIME() WHERE Kind = @k{0} AND ItemKey = @i{0} AND RetiredAt IS NULL;" -f $i))
                [void]$sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@i{0}, 'template', @k{0}, 'Reset', 'published', 'retired', @By, 'no longer shipped');" -f $i))
                continue
            }
            $r = $c.Row
            $ch = [string](Get-SIProRowValue $r 'ContentHash'); if (-not $ch.Trim()) { $ch = Get-SIProContentHash -Body $r.BodyJson -Format $r.Format }
            $p["v$i"] = $r.TemplateVersion; $p["b$i"] = $r.BodyJson; $p["f$i"] = $r.Format; $p["o$i"] = [int]$r.SortOrder; $p["h$i"] = $r.BodyHash; $p["s$i"] = $r.Source; $p["c$i"] = $ch.Trim()
            # #529 (3): the content in force before this write -- an item that FOLLOWS the template (no override, or inherit)
            # and changes content gets an "upgraded" entry below, naming the version it went from and to
            [void]$sb.AppendLine(("DECLARE @pv{0} nvarchar(32) = NULL, @pc{0} char(64) = NULL, @pr{0} bit = 0; SELECT @pv{0} = [Version], @pc{0} = ContentHash, @pr{0} = CASE WHEN RetiredAt IS NULL THEN 0 ELSE 1 END FROM cfg.Template WHERE Kind = @k{0} AND ItemKey = @i{0};" -f $i))
            [void]$sb.AppendLine(("IF EXISTS (SELECT 1 FROM cfg.Template WHERE Kind = @k{0} AND ItemKey = @i{0})" -f $i))
            [void]$sb.AppendLine(("    UPDATE cfg.Template SET [Version] = @v{0}, BodyJson = @b{0}, Format = @f{0}, SortOrder = @o{0}, BodyHash = @h{0}, ContentHash = @c{0}, Source = @s{0}, PublishedAt = SYSUTCDATETIME(), RetiredAt = NULL WHERE Kind = @k{0} AND ItemKey = @i{0};" -f $i))
            [void]$sb.AppendLine('ELSE')
            [void]$sb.AppendLine(("    INSERT cfg.Template (Kind, ItemKey, [Version], BodyJson, Format, SortOrder, BodyHash, ContentHash, Source) VALUES (@k{0}, @i{0}, @v{0}, @b{0}, @f{0}, @o{0}, @h{0}, @c{0}, @s{0});" -f $i))
            # every content a template ever had is kept once (by ContentHash), so "what changed since you overrode it"
            # can be shown against the body the override was made on
            [void]$sb.AppendLine(("IF NOT EXISTS (SELECT 1 FROM cfg.TemplateRevision WHERE Kind = @k{0} AND ItemKey = @i{0} AND ContentHash = @c{0}) INSERT cfg.TemplateRevision (Kind, ItemKey, ContentHash, [Version], BodyJson, Format) VALUES (@k{0}, @i{0}, @c{0}, @v{0}, @b{0}, @f{0});" -f $i))
            [void]$sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@i{0}, 'template', @k{0}, 'Set', NULL, CONCAT(@v{0}, ':', @c{0}), @By, '{1}');" -f $i, $c.Action))
            [void]$sb.AppendLine(("IF @pc{0} IS NOT NULL AND @pr{0} = 0 AND @pc{0} <> @c{0} AND NOT EXISTS (SELECT 1 FROM cfg.ItemOverride WHERE Kind = @k{0} AND ItemKey = @i{0} AND State IN ('override', 'disable')) INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@i{0}, 'item', @k{0}, 'Set', CONCAT('template ', COALESCE(@pv{0}, '(none)'), ':', @pc{0}), CONCAT('template ', @v{0}, ':', @c{0}), @By, CONCAT('upgraded: follows the new shipped version (', COALESCE(@pv{0}, '(none)'), ' -> ', @v{0}, ')'));" -f $i))
        }
        [void]$sb.AppendLine('COMMIT;')
        & $Send $sb.ToString() $p 'nonquery'
        $batchNo++
        if ($AfterBatch) { & $AfterBatch $batchNo $Send }
    }
    }
    if ($txn) { $null = & $txn $write } else { $null = & $write $Store.Invoke }
    $work.Count
}

# =====================================================================================================================
#  IMPORT: an installation's files -> only what DIFFERS from the templates (Community -> Pro)
# =====================================================================================================================
function Get-SIProAssetTaggingSources {
    <#
        #275 R3. The asset-tagging files a 2.2 run of THIS installation reads, found exactly as the launcher and the engine
        find them (AssetTagging.Resolve.ps1): SettingsPath, CustomYamlFile, LockedYamlFile and LegacyYamlFile as the
        configuration layers leave them -- config\SecurityInsight.custom.ps1, then launcher\asset-tagging\
        LauncherConfig.custom.ps1, then (internal launcher) launcher\asset-tagging\launcher.override.ps1, the last plain
        top-level assignment winning -- else the launcher's default folder (internal: asset-tagging-rules\ first).
        -SettingsPath (the importer's -AssetTaggingPath) wins, as the launcher's -SettingsPath switch does.
        Returns @{ SettingsPath; From; Flavour; Files (Resolve-SIAssetTaggingFiles, or $null when the folder cannot be
        known or read); Review (not imported, with the reason -- never silent); Info (said, nothing lost) }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$SettingsPath, [string]$Flavour)
    $review = New-Object System.Collections.Generic.List[object]; $info = New-Object System.Collections.Generic.List[object]
    $rel = { param([string]$p) if ($p.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $p.Substring($SIRoot.Length).TrimStart('\', '/') } else { $p } }
    if (-not $Flavour) { $Flavour = if ((Split-Path -Leaf (Split-Path -Parent $SIRoot)) -eq 'SOLUTIONS') { 'internal' } else { 'community' } }
    $layers = @((Join-SIProPath $SIRoot 'config' 'SecurityInsight.custom.ps1'), (Join-SIProPath $SIRoot 'launcher' 'asset-tagging' 'LauncherConfig.custom.ps1'))
    if ($Flavour -eq 'internal') { $layers += (Join-SIProPath $SIRoot 'launcher' 'asset-tagging' 'launcher.override.ps1') }   # only the internal launcher dot-sources it
    $names = 'SettingsPath', 'CustomYamlFile', 'LockedYamlFile', 'LegacyYamlFile'
    $val = @{}; $from = @{}; $byCode = @{}
    foreach ($l in $layers) {
        if (-not (Test-Path -LiteralPath $l)) { continue }
        foreach ($a in @(Get-SIPs1Assignments -Text (Read-SISettingsText -Path $l).Text | Where-Object { $names -contains $_.Name })) {
            if ($a.TopLevel -and $a.Literal) { $val[$a.Name] = [string]$a.Value; $from[$a.Name] = ('{0} line {1}' -f (& $rel $l), $a.Line); [void]$byCode.Remove($a.Name) }
            else { $byCode[$a.Name] = [pscustomobject]@{ Path = (& $rel $l); Line = $a.Line } }
        }
    }
    $out = [pscustomobject]@{ SettingsPath = $null; From = ''; Flavour = $Flavour; Files = $null; Review = $review; Info = $info }
    $tell = { param([string]$name, [string]$path, $line, [string]$reason) $review.Add([pscustomobject]@{ Name = $name; Scope = 'item'; Path = $path; Line = $line; Reason = $reason }) }
    foreach ($n in @($names | Where-Object { $byCode.ContainsKey($_) -and $_ -ne 'SettingsPath' })) {
        $c = $byCode[$n]
        & $tell ('assettagging ' + $n) $c.Path $c.Line ('{0} is set by code at line {1}, so the importer cannot tell which asset-tagging file the run reads -- the default name is used; check that nothing is missing' -f $n, $c.Line)
    }
    if (-not $SettingsPath -and $byCode.ContainsKey('SettingsPath')) {
        $c = $byCode['SettingsPath']
        & $tell 'assettagging' $c.Path $c.Line ('SettingsPath is set by code at line {0}, so the importer cannot tell which folder the asset-tagging run reads -- no asset-tagging rules are imported; run the importer again with -AssetTaggingPath <that folder>' -f $c.Line)
        return $out
    }
    $configured = if ($val.ContainsKey('SettingsPath')) { $val['SettingsPath'] } else { '' }
    $sp = Resolve-SIAssetTaggingSettingsPath -Cli $SettingsPath -Configured $configured -SIRoot $SIRoot -Flavour $Flavour
    $out.SettingsPath = $sp
    $out.From = if ($SettingsPath) { '-AssetTaggingPath' } elseif ($configured) { $from['SettingsPath'] } else { ('the {0} launcher''s default' -f $Flavour) }
    if (-not [System.IO.Path]::IsPathRooted($sp)) {
        & $tell 'assettagging' $sp $null ('the asset-tagging rules folder (SettingsPath, {0}) is a relative path -- it depends on the folder the run starts in; run the importer again with -AssetTaggingPath <the full path>' -f $out.From)
        return $out
    }
    if (-not (Test-Path -LiteralPath $sp -PathType Container)) {
        # the launcher's own default folder missing = an installation without asset tagging (the 2.2 run stopped): nothing to lose
        if (-not $SettingsPath -and -not $configured) { $out.Files = $null; return $out }
        & $tell 'assettagging' $sp $null ('the asset-tagging rules folder (SettingsPath, {0}) does not exist on this machine -- copy it here or run the importer again with -AssetTaggingPath <folder>' -f $out.From)
        return $out
    }
    $launcherDefault = { param([string]$n, [string]$d) if ($val.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace($val[$n])) { $val[$n] } else { $d } }
    # the launchers set the locked / custom names when nothing else has (AssetTagging.locked.yaml / .custom.yaml); the
    # legacy name only ever comes from the configuration or the engine's own default
    $out.Files = Resolve-SIAssetTaggingFiles -SettingsPath $sp -SIRoot $SIRoot `
        -LockedYamlFile (& $launcherDefault 'LockedYamlFile' 'AssetTagging.locked.yaml') -CustomYamlFile (& $launcherDefault 'CustomYamlFile' 'AssetTagging.custom.yaml') `
        -LegacyYamlFile (& $launcherDefault 'LegacyYamlFile' '')
    $f = $out.Files
    $shippedDir = Join-SIProPath $SIRoot 'asset-profiling-enrichment' 'endpoint'
    $isShipped = ([System.IO.Path]::GetFullPath($sp).TrimEnd('\', '/') -ieq [System.IO.Path]::GetFullPath($shippedDir).TrimEnd('\', '/'))
    if ($f.Mode -eq 'legacy') {
        $info.Add([pscustomobject]@{ Name = 'assettagging'; Path = (& $rel $f.LegacyPath); Reason = 'the run read ONLY this legacy file (no locked / custom file beside it); its tags are imported -- in Pro the shipped tags it does not restate also run: turn off the ones you do not want' })
    } elseif ($f.Mode -eq 'locked+custom' -and -not $f.LockedExists -and -not $isShipped) {
        $info.Add([pscustomobject]@{ Name = 'assettagging'; Path = (& $rel $f.CustomPath); Reason = ('the run read ONLY this file ({0} holds no {1}); its tags are imported -- in Pro the shipped tags also run: turn off the ones you do not want' -f (& $rel $sp), $f.LockedYamlFile) })
    } elseif ($f.Mode -eq 'none' -and -not $isShipped) {
        & $tell 'assettagging' (& $rel $sp) $null ('no asset-tagging rules file ({0}, {1} or {2}) is in the folder the run reads (SettingsPath, {3}) -- the 2.2 run stopped here; nothing to import' -f $f.LockedYamlFile, $f.CustomYamlFile, $f.LegacyYamlFile, $out.From)
    }
    $cands = @($f.ConfigCandidates)
    if ($f.ConfigPath) {
        foreach ($c in @($cands | Where-Object { $_ -ne $f.ConfigPath -and (Test-Path -LiteralPath $_) })) {
            $info.Add([pscustomobject]@{ Name = 'assettagging/config'; Path = (& $rel $c); Reason = ('not read by the run -- {0} comes first; not imported' -f (& $rel $f.ConfigPath)) })
        }
    }
    $out
}

function Get-SIProConfigImportPlan {
    <#
        Every configuration family an installation keeps in files, as cfg.ItemOverride rows -- ONLY what differs from the
        templates (-Templates: the rows Get-SITemplateRows builds, or the database's). Per family:
          rareport      RiskAnalysis_Queries_Custom.yaml (or custom\): a report / template that differs -> override; a
                        new one -> own
          riskindex     riskscore.index.custom.csv (the customer's own rows, #398): a row that differs from its template
                        -> override, a new row -> own, both placed before every shipped row (as the engine reads them);
                        nothing is disabled; an unchanged copy of an earlier shipped index -> nothing (Info)
          rule          a custom rule with 'mode: disable' for a shipped rule -> disable (other custom rules stay
                        cfg.Document, Get-SIProDocumentImportPlan)
          assettagging  the files the asset-tagging run reads, found as the launcher + engine find them (Get-SIProAssetTaggingSources;
                        -AssetTaggingPath wins): per tag override / own; the asset-tagging.config.json it reads -> config
          serverapps    asset-profiling-enrichment\endpoint\server-applications.json -> catalog
          cmdbownership config\cmdb-source-ownership.custom.json, merged per field over the template (the loader's rule)
          servicemodel  config\service-model.custom.json (replaces the model wholesale)
          schemaoverlay asset-profiling-schema\<engine>.schema.custom.json
          decision      config\ and overlay-root asset-decisions / correlation-decisions .custom.yaml
          weights       <Report>.weighted.custom.json -> report/<Report>; the riskscore_weighted file's sections other than
                        weightedRiskFactors -> model (weightedRiskFactors itself is the cfg.Document weights/solution)
        Not imported, with the reason: a file that does not parse or validate. Returns @{ Rows; Skipped; Same; Files }
        where Files = the source files and whether everything in them was imported (for -RetireFiles).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [AllowEmptyCollection()][object[]]$Templates = @(), [string]$OverlayRoot,
          [string]$AssetTaggingPath, [string]$AssetTaggingFlavour, $Context,
          # The templates were built from THIS installation's files, not read from the database. Kept for callers: since
          # #398 the shipped risk index (locked) and the customer's rows (custom) are separate files, so a local baseline
          # compares like any other.
          [switch]$LocalTemplates)
    if (-not $Context) { $Context = Get-SIProConfigContext -SIRoot $SIRoot }
    $tpl = @{}; foreach ($t in @($Templates)) { $tpl[('{0}/{1}' -f $t.Kind, $t.ItemKey)] = $t }
    $rows = New-Object System.Collections.Generic.List[object]; $skipped = New-Object System.Collections.Generic.List[object]
    $same = New-Object System.Collections.Generic.List[string]; $files = [ordered]@{}; $info = New-Object System.Collections.Generic.List[object]
    $rel = { param([string]$p) if ($p.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $p.Substring($SIRoot.Length).TrimStart('\', '/') } else { $p } }
    $file = { param([string]$p, [string]$kind) $k = & $rel $p; if (-not $files.Contains($k)) { $files[$k] = [pscustomobject]@{ Path = $p; Rel = $k; Kind = $kind; Complete = $true; Imported = 0 } }; $files[$k] }
    # the customer's own reports count as reports for validation
    $ctx = [pscustomobject]@{ SIRoot = $Context.SIRoot; Reports = @($Context.Reports); Kinds = @($Context.Kinds); Catalog = @($Context.Catalog) }
    $consider = {
        param([string]$kind, [string]$key, [string]$body, [string]$fmt, [string]$src)
        $f = & $file $src $kind
        $name = '{0}/{1}' -f $kind, $key
        $t = $tpl[$name]
        if ($t -and (Test-SIProSameItem -A $body -B ([string]$t.BodyJson) -Format $fmt)) { $same.Add($name); return }
        $why = @(Test-SIProItem -Kind $kind -Key $key -Body $body -Format $fmt -Context $ctx)
        if ($why.Count) { $skipped.Add([pscustomobject]@{ Name = $name; Scope = 'item'; Reason = ('{0}: {1}' -f (& $rel $src), ($why -join '; ')) }); $f.Complete = $false; return }
        $rows.Add([pscustomobject]@{ Kind = $kind; Key = $key; State = 'override'; Body = $body; Format = $fmt
            BaseVersion = $(if ($t) { [string]$t.TemplateVersion } else { $null }); BaseHash = $(if ($t) { Get-SIProRowContentHash $t } else { $null })
            Origin = $(if ($t) { 'override' } else { 'own' }); Source = (& $rel $src) })
        $f.Imported++
    }
    $rad = Join-SIProPath $SIRoot 'risk-analysis-detection'

    # ---- Risk Analysis report catalog: the custom YAML ----
    foreach ($cand in @((Join-SIProPath $rad 'custom' 'RiskAnalysis_Queries_Custom.yaml'), (Join-SIProPath $rad 'RiskAnalysis_Queries_Custom.yaml'))) {
        if (-not (Test-Path -LiteralPath $cand)) { continue }
        $y = $null
        try { $y = ConvertFrom-SIYaml -Path $cand -Ordered } catch { $skipped.Add([pscustomobject]@{ Name = (& $rel $cand); Scope = 'item'; Reason = 'not valid YAML: ' + $_.Exception.Message }); (& $file $cand 'rareport').Complete = $false; continue }
        if ($null -eq $y) { continue }
        foreach ($r in @($y['Reports'] | Where-Object { $null -ne $_ })) { $ctx.Reports = @($ctx.Reports + [string]$r['ReportName']) }
        foreach ($r in @($y['Reports'] | Where-Object { $null -ne $_ })) { & $consider 'rareport' ('report/' + [string]$r['ReportName']) (ConvertTo-SIProJson -Value $r -Level 2) 'json' $cand }
        foreach ($r in @($y['ReportTemplates'] | Where-Object { $null -ne $_ })) { & $consider 'rareport' ('template/' + [string]$r['ReportName']) (ConvertTo-SIProJson -Value $r -Level 2) 'json' $cand }
        foreach ($k in @($y.Keys | Where-Object { $_ -notin 'Reports', 'ReportTemplates' })) { $skipped.Add([pscustomobject]@{ Name = ('{0}:{1}' -f (& $rel $cand), $k); Scope = 'item'; Reason = 'only Reports and ReportTemplates are read from the custom catalog' }) }
        break   # the engine reads the custom\ copy when it exists, else the flat one
    }

    # ---- the risk index: the customer's OWN rows (#398) ----
    # riskscore.index.custom.csv is never shipped (the shipped index is riskscore.index.locked.csv, the templates); it
    # holds only the customer's rows, which the engine reads BEFORE the shipped rows and which never remove one. So the
    # import mirrors that: a row equal to its template (its place aside) changes nothing; any other row is placed before
    # every shipped row, in the file's order (a negative Precedence -- the run file renumbers 1..n); nothing is disabled.
    # A never-edited copy of an earlier version's shipped index is not the customer's and is not imported.
    $ri = Join-SIProPath $rad 'riskscore.index.custom.csv'
    $riShipped = $false
    if ((Test-Path -LiteralPath $ri) -and (Get-Command -Name Test-SIRiskIndexShippedCopy -ErrorAction SilentlyContinue)) { $riShipped = Test-SIRiskIndexShippedCopy -Path $ri }
    if ($riShipped) {
        $info.Add([pscustomobject]@{ Name = 'riskindex'; Reason = ('{0} is the unchanged risk index of an earlier version -- nothing of it is imported' -f (& $rel $ri)) })
    } elseif (Test-Path -LiteralPath $ri) {
        $count = @{}
        # A v2.2 index (no Precedence column) is put in precedence order first -- the same scores, first match wins
        # (RA-RiskIndexOrder.ps1) -- so it is compared with the templates in the form they are published in.
        # #559: and a file written with the 2.2 columns is translated to the SI keys (the form the templates are published in)
        $riRows = @(Import-Csv -LiteralPath $ri)
        $riRows = @(ConvertTo-SIRiskIndexSiRows -Rows $riRows | ForEach-Object { [pscustomobject]$_ })
        $n = $riRows.Count; $pos = 0
        foreach ($r in $riRows) {
            $pos++
            $o = [ordered]@{}; foreach ($c in $script:SIRiskIndexColumns) { $o[$c] = $(if ((Get-SIRiskIndexCell $r $c) -ne '') { Get-SIRiskIndexCell $r $c } else { '' }) }
            $key = Get-SIRiskIndexKey -Row $o
            if ($count.ContainsKey($key)) { $count[$key]++; $key = '{0}#{1}' -f $key, $count[$key] } else { $count[$key] = 1 }   # a repeat, as the templates key it
            $t = $tpl[('riskindex/{0}' -f $key)]
            if ($t) {
                $tb = ConvertFrom-SIProJson ([string]$t.BodyJson)
                $diff = @($script:SIRiskIndexColumns | Where-Object { $_ -ne 'Precedence' -and [string]$o[$_] -cne [string]$(if ($tb.PSObject.Properties[$_]) { $tb.$_ } else { '' }) })
                if (-not $diff.Count) { $same.Add(('riskindex/{0}' -f $key)); continue }
            }
            $o['Precedence'] = [string]($pos - $n - 1)
            & $consider 'riskindex' $key (ConvertTo-SIProJson -Value $o) 'json' $ri
        }
    }

    # ---- rules: a custom 'mode: disable' of a shipped rule ----
    foreach ($r in @(Get-SIRuleView -SIRoot $SIRoot -OverlayRoot $OverlayRoot)) {
        $own = if ($r.overlay) { $r.overlay } elseif ($r.custom) { $r.custom } else { $null }
        if (-not $own -or -not $r.locked -or $own.mode -ne 'disable') { continue }
        $path = if ($own.path -like 'overlay:*') { Join-SIProPath $OverlayRoot $own.path.Substring(8) } else { Join-SIProPath $SIRoot $own.path }
        $key = '{0}/{1}' -f $r.engine, $r.id
        $t = $tpl['rule/' + $key]
        $rows.Add([pscustomobject]@{ Kind = 'rule'; Key = $key; State = 'disable'; Body = $null; Format = 'yaml'; BaseVersion = $(if ($t) { [string]$t.TemplateVersion } else { $null }); BaseHash = $(if ($t) { Get-SIProRowContentHash $t } else { $null }); Origin = 'disable'; Source = (& $rel $path) })
        (& $file $path 'rule').Imported++
    }

    # ---- asset tagging: EXACTLY the files a run of this installation reads (#275 R3) -- the launchers' and the engine's
    #      own resolution (AssetTagging.Resolve.ps1); what cannot be known or read is listed, never skipped silently ----
    $tagSrc = Get-SIProAssetTaggingSources -SIRoot $SIRoot -SettingsPath $AssetTaggingPath -Flavour $AssetTaggingFlavour
    foreach ($s in $tagSrc.Review) { $skipped.Add($s) }
    foreach ($s in $tagSrc.Info) { $info.Add($s) }
    $tf = $tagSrc.Files
    if ($tf) {
        $tagFiles = @()
        if ($tf.Mode -eq 'locked+custom') {
            # a locked file OUTSIDE the shipped place is the customer's copy -- the run read it, so its tags count (a tag
            # identical to the template is not stored)
            $shippedLocked = Join-SIProPath $SIRoot 'asset-profiling-enrichment' 'endpoint' 'AssetTagging.locked.yaml'
            if ($tf.LockedExists -and ([System.IO.Path]::GetFullPath($tf.LockedPath) -ine [System.IO.Path]::GetFullPath($shippedLocked))) { $tagFiles += $tf.LockedPath }
            if ($tf.CustomExists) { $tagFiles += $tf.CustomPath }
        } elseif ($tf.Mode -eq 'legacy') { $tagFiles += $tf.LegacyPath }
        # merged as the engine merges: per tag stem, the custom file wins over the locked one
        $merged = [ordered]@{}
        foreach ($tc in $tagFiles) {
            $null = & $file $tc 'assettagging'
            $y = $null
            try { $y = ConvertFrom-SIYaml -Path $tc -Ordered } catch { $skipped.Add([pscustomobject]@{ Name = (& $rel $tc); Scope = 'item'; Path = (& $rel $tc); Reason = 'not valid YAML: ' + $_.Exception.Message }); (& $file $tc 'assettagging').Complete = $false; continue }
            if (-not $y) { continue }
            foreach ($t in @($y['AssetTagging'] | Where-Object { $null -ne $_ })) {
                $stem = Get-SIProAssetTagStemKey ([string]$t['AssetTagName'])
                if (-not $stem) { $skipped.Add([pscustomobject]@{ Name = 'assettagging/' + [string]$t['AssetTagName']; Scope = 'item'; Path = (& $rel $tc); Reason = 'the tag name does not follow <stem>--tier<N>--SI / <stem>--excluded--SI' }); (& $file $tc 'assettagging').Complete = $false; continue }
                $merged[$stem] = [pscustomobject]@{ Tag = $t; Source = $tc }
            }
        }
        foreach ($k in @($merged.Keys)) { & $consider 'assettagging' ('tag/' + $k) (ConvertTo-SIProJson -Value $merged[$k].Tag) 'json' $merged[$k].Source }
    }
    # the AutoExclude gates: the config file the run reads (config\ under the solution first, then SettingsPath)
    $tcfg = if ($tf) { $tf.ConfigPath } else { $p = Join-SIProPath $SIRoot 'config' 'asset-tagging.config.json'; if (Test-Path -LiteralPath $p) { $p } else { $null } }
    if ($tcfg) { & $consider 'assettagging' 'config' ([System.IO.File]::ReadAllText($tcfg).TrimStart([char]0xFEFF)) 'json' $tcfg }

    # ---- the server-application catalog override (#275 R6): asset-profiling-enrichment\endpoint\server-applications.json,
    #      which the endpoint profiler merges over the shipped catalog -> serverapps/catalog ----
    $sa = Join-SIProPath $SIRoot 'asset-profiling-enrichment' 'endpoint' 'server-applications.json'
    if (Test-Path -LiteralPath $sa) { & $consider 'serverapps' 'catalog' ([System.IO.File]::ReadAllText($sa).TrimStart([char]0xFEFF)) 'json' $sa }

    # ---- CMDB ownership (#251: configuration, ONE document cmdbownership/map): the shipped map with the custom file merged
    #      over it exactly as the loader merges it (top-level settings replace; an asset type replaces by siAssetType and
    #      inherits every field it does not restate) -- the whole map, which is the customer's from then on ----
    $oc = Join-SIProPath $SIRoot 'config' 'cmdb-source-ownership.custom.json'
    if (Test-Path -LiteralPath $oc) {
        $c = $null
        try { $c = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($oc))) } catch { $skipped.Add([pscustomobject]@{ Name = (& $rel $oc); Scope = 'item'; Reason = 'not valid JSON' }); (& $file $oc 'cmdbownership').Complete = $false }
        if ($c -and $c.Contains('cmdbSourceOwnership')) {
            $croot = $c['cmdbSourceOwnership']
            $shipped = Get-SIProShippedOwnershipMap -SIRoot $SIRoot
            $map = if ($shipped) { ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $shipped) } else { [ordered]@{} }
            foreach ($k in @($croot.Keys | Where-Object { $_ -ne 'assetTypes' -and -not ([string]$_).StartsWith('_') -and $_ -ne 'Comment' })) { if ($null -ne $croot[$k]) { $map[$k] = $croot[$k] } }
            $types = New-Object System.Collections.Generic.List[object]
            foreach ($e in @($map['assetTypes'] | Where-Object { $null -ne $_ })) { $types.Add($e) }
            foreach ($e in @($croot['assetTypes'] | Where-Object { $null -ne $_ })) {
                $k = ([string]$e['siAssetType']).Trim().ToLowerInvariant()
                $base = @($types | Where-Object { ([string]$_['siAssetType']).Trim().ToLowerInvariant() -eq $k }) | Select-Object -First 1
                $m = if ($base) { $base } else { $n = [ordered]@{}; $types.Add($n); $n }
                foreach ($f in @($e.Keys)) {
                    # a null siMayCreate / expectedWithinDays says nothing (the loader inherits); a null ownedBy is meaningful
                    if ($null -eq $e[$f] -and $f -in 'siMayCreate', 'expectedWithinDays', 'ciClass') { continue }
                    $m[$f] = $e[$f]
                }
                $m['siAssetType'] = $k
            }
            $map['assetTypes'] = @($types.ToArray())
            & $consider 'cmdbownership' 'map' (ConvertTo-SIProJson -Value $map) 'json' $oc
        }
    }
    # ---- service model (wholesale) ----
    $smc = Join-SIProPath $SIRoot 'config' 'service-model.custom.json'
    if (Test-Path -LiteralPath $smc) {
        $c = $null
        try { $c = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($smc))) } catch { $skipped.Add([pscustomobject]@{ Name = (& $rel $smc); Scope = 'item'; Reason = 'not valid JSON' }); (& $file $smc 'servicemodel').Complete = $false }
        if ($c -and $c.Contains('serviceModel')) { & $consider 'servicemodel' 'model' (ConvertTo-SIProJson -Value $c['serviceModel']) 'json' $smc }
    }
    # ---- schema overlays ----
    foreach ($e in 'endpoint', 'identity', 'azure', 'publicip') {
        $base = if ($e -eq 'publicip') { 'public-ip' } else { $e }
        $p = Join-SIProPath $SIRoot 'asset-profiling-schema' ('{0}.schema.custom.json' -f $base)
        if (Test-Path -LiteralPath $p) { & $consider 'schemaoverlay' $e ([System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF)) 'json' $p }
    }
    # ---- decisions: one item per kind; the loaders ADD the tree and the overlay copy, so two files are not merged here ----
    foreach ($d in @(@{ Key = 'asset'; File = 'asset-decisions.custom.yaml' }, @{ Key = 'correlation'; File = 'correlation-decisions.custom.yaml' })) {
        $found = @(@((Join-SIProPath $SIRoot 'config' $d.File)) + @($(if ($OverlayRoot) { Join-SIProPath $OverlayRoot $d.File })) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
        if ($found.Count -gt 1) {
            foreach ($f in $found) { $skipped.Add([pscustomobject]@{ Name = 'decision/' + $d.Key; Scope = 'item'; Reason = ('{0}: the installation reads two {1} files and adds them up -- combine them into one and import again' -f (& $rel $f), $d.File) }); (& $file $f 'decision').Complete = $false }
            continue
        }
        if ($found.Count -eq 1) { & $consider 'decision' $d.Key ([System.IO.File]::ReadAllText($found[0]).TrimStart([char]0xFEFF)) 'yaml' $found[0] }
    }
    # ---- weights: per-report files, and the model sections of the solution file ----
    foreach ($f in @(Get-ChildItem -LiteralPath $rad -Filter '*.weighted.custom.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $rep = $f.Name -replace '\.weighted\.custom\.json$', ''
        $text = [System.IO.File]::ReadAllText($f.FullName).TrimStart([char]0xFEFF)
        $o = $null; try { $o = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson $text) } catch { }
        if ($o) {
            $keep = [ordered]@{}; foreach ($k in @($o.Keys)) { if ($k -eq 'weightedRiskFactors' -or $k -eq '$schema' -or ([string]$k).StartsWith('_') -or $k -eq 'Comment') { $keep[$k] = $o[$k] } }
            $other = @($o.Keys | Where-Object { -not $keep.Contains($_) })
            if ($other.Count) { $skipped.Add([pscustomobject]@{ Name = 'weights/report/' + $rep + ' (other sections)'; Scope = 'item'; Info = $true; Reason = ('{0}: {1} -- a per-report file is read for weightedRiskFactors only; the other sections are not imported' -f $f.Name, ($other -join ', ')) }) }
            $text = ConvertTo-SIProJson -Value $keep
        }
        & $consider 'weights' ('report/' + $rep) $text 'json' $f.FullName
    }
    $wf = Join-SIProPath $rad 'riskscore_weighted.schema.custom.json'
    if (Test-Path -LiteralPath $wf) {
        $o = $null; try { $o = ConvertTo-SIOrderedJson (ConvertFrom-SIProJson ([System.IO.File]::ReadAllText($wf))) } catch { }
        if ($o) {
            $model = [ordered]@{}; foreach ($k in @($o.Keys)) { if ($k -ne 'weightedRiskFactors' -and $k -ne '$schema' -and -not ([string]$k).StartsWith('_') -and $k -ne 'Comment') { $model[$k] = $o[$k] } }
            if ($model.Count) { & $consider 'weights' 'model' (ConvertTo-SIProJson -Value $model) 'json' $wf }
        }
    }
    [pscustomobject]@{ Rows = $rows.ToArray(); Skipped = $skipped.ToArray(); Same = $same.ToArray(); Files = @($files.Values); Info = $info.ToArray() }
}
