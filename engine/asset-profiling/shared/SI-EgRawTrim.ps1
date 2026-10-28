#Requires -Version 5.1
<#
    THE EXPOSURE GRAPH IDENTITY INDEX KEEPS ONLY WHAT IS READ (#475; customer H 2026-10-08: 73,404 EG identity rows ran the
    identity job out of memory at 2 GiB and at 8 GiB -- every node's WHOLE rawData was parsed, indexed and carried on every
    identity record through every stage).

    The raw-data fields the identity profiler reads are declared, not hard-coded, so the set is computed per run from:
      * the identity profile schema (locked + the customer's overlay): every "rawData.<field>" path;
      * the Exposure Graph mapping of the v3 data model (locked + custom): every "rawData.<field>" path;
      * the identity rules (shipped + custom + the Pro overlay): every egSignals / roles value (egDetectedRoles reads them
        as top-level rawData fields) and every "EgRawData.<field>" / "rawData.<field>" a detection names;
      * the fields engine code reads directly ($script:SIEgRawCodeFields -- a test fails if code reads one that is not here);
      * the id fields the index finds an object's Entra id in.
    Top-level fields are kept whole (a nested path keeps its top field). Anything that cannot be read -> $null = keep
    EVERYTHING (never a silent loss of a field a rule needs). Full asset metadata (keep whole) is the caller's decision.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

# Fields engine code reads from an identity's EG rawData directly (Get-SIEgValue, RuleEval, Invoke-Classify) + the id
# fallbacks of Get-SIExposureGraphIdentities. SIv3-ScaleEgIdentity asserts every Get-SIEgValue literal is listed.
$script:SIEgRawCodeFields = @(
    'alternativeNames', 'deviceName', 'isDomainController', 'isExchangeServerDnsName', 'isSensitive', 'isTaggedAsExchangeServer', 'isAdfsServer',
    'lastSeen', 'managedIdentityMetadata', 'sidHistory', 'nestedAdGroupNames', 'tags', 'deviceDynamicTags', 'deviceManualTags',
    'aadId', 'accountObjectId', 'objectId', 'aadObjectId', 'groupId', 'principalId', 'userId', 'id'
)

function Get-SIEgRawFieldsFromText {
    <# PURE. The top-level rawData fields a text names: "rawData.<field>" and "EgRawData.<field>" (case-insensitive). #>
    param([AllowEmptyString()][string]$Text)
    foreach ($m in [regex]::Matches([string]$Text, '(?i)(?:\brawData|EgRawData)\.([A-Za-z0-9_]+)')) { $m.Groups[1].Value }
}

function Get-SIEgIdentityKeepKeys {
    <#
        The set of top-level rawData fields to keep (case-insensitive HashSet), or $null = keep everything.
        -Texts / -Rules are test seams: the schema + mapping texts, and the loaded identity rules.
    #>
    param([string]$SIRoot, [string[]]$Texts, [object[]]$Rules)
    try {
        $keep = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($f in $script:SIEgRawCodeFields) { [void]$keep.Add($f) }
        if ($null -eq $Texts) {
            if (-not $SIRoot) { return $null }
            $files = @(
                [IO.Path]::Combine($SIRoot, 'asset-profiling-schema', 'identity.schema.locked.json'),
                [IO.Path]::Combine($SIRoot, 'asset-profiling-schema', 'identity.schema.custom.json'),
                [IO.Path]::Combine($SIRoot, 'data-model', 'mappings', 'eg.locked.json'),
                [IO.Path]::Combine($SIRoot, 'data-model', 'mappings', 'eg.custom.json'))
            # the Pro settings layer's overlay (Get-SISchemaWithCustomMerge reads the same place)
            if ($global:SI_ProConfigRoot) { $files += [IO.Path]::Combine([string]$global:SI_ProConfigRoot, 'asset-profiling-schema', 'identity.schema.custom.json') }
            # #456: the Pro run's data model (templates + overrides) -- a customer's Exposure Graph mapping keeps its fields too
            if ($global:SI_DataModelRoot) { $files += [IO.Path]::Combine([string]$global:SI_DataModelRoot, 'mappings', 'eg.locked.json') }
            if (-not (Test-Path -LiteralPath $files[0])) { return $null }      # no schema: cannot tell what is read
            $Texts = foreach ($f in $files) { if (Test-Path -LiteralPath $f) { [IO.File]::ReadAllText($f) } }
        }
        foreach ($t in @($Texts)) { foreach ($k in @(Get-SIEgRawFieldsFromText $t)) { [void]$keep.Add($k) } }
        if ($null -eq $Rules) {
            if (-not (Get-Command -Name Get-SIRuleSet -ErrorAction SilentlyContinue) -and $SIRoot) {
                $rl = [IO.Path]::Combine($SIRoot, 'engine', 'asset-profiling', 'shared', 'Get-SIRuleSet.ps1')
                if (Test-Path -LiteralPath $rl) { . $rl }
            }
            if (-not (Get-Command -Name Get-SIRuleSet -ErrorAction SilentlyContinue)) { return $null }
            $Rules = @(@(Get-SIRuleSet -Engine 'identity' 3>$null) + @(Get-SIRuleSet -Engine 'identity' -Fallback 3>$null))
        }
        foreach ($r in @($Rules)) {
            if ($null -eq $r) { continue }
            foreach ($d in @($r.Detections)) {
                if ($null -eq $d) { continue }
                $spec = $d.Detect
                $sigs = @()
                if ($spec -is [System.Collections.IDictionary]) { $sigs = @($spec['egSignals']) + @($spec['roles']) }
                elseif ($spec) { foreach ($n in 'egSignals', 'roles') { $p = $spec.PSObject.Properties[$n]; if ($p) { $sigs += @($p.Value) } } }
                foreach ($s in $sigs) { if ($s -and "$s" -match '^[A-Za-z0-9_]+$') { [void]$keep.Add([string]$s) } }
                foreach ($k in @(Get-SIEgRawFieldsFromText (ConvertTo-Json -InputObject $spec -Compress -Depth 8))) { [void]$keep.Add($k) }
            }
        }
        return ,$keep
    } catch { return $null }
}

function Select-SIEgRawFields {
    <# PURE. A rawData with only the kept top-level fields (whole); -Keep $null = the rawData unchanged. #>
    param($Raw, $Keep)
    if ($null -eq $Raw -or $null -eq $Keep) { return $Raw }
    $o = [ordered]@{}
    if ($Raw -is [System.Collections.IDictionary]) { foreach ($k in @($Raw.Keys)) { if ($Keep.Contains([string]$k)) { $o[[string]$k] = $Raw[$k] } } }
    else { foreach ($p in $Raw.PSObject.Properties) { if ($Keep.Contains($p.Name)) { $o[$p.Name] = $p.Value } } }
    [pscustomobject]$o
}
