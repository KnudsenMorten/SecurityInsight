#Requires -Version 5.1
<#
    CmdbFieldPrecedence.ps1 -- A PROFILE RULE'S CMDB OVERRIDE WINS OVER THE CMDB RECORD, FIELD BY FIELD.

    Operator decision (2026-10-05), asked "should the rule's override win?": "yes". Found live on ring 1: a custom
    ADDomainController rule (cmdbId 1, cmdbDataSensitivity 'Restricted') and a custom VisualCron rule (cmdbId 6,
    cmdbDataSensitivity 'Confidential') matched dc1 / dc3 / mgmt1, yet the profile rows carried the CMDB record's values
    (Confidential for the DCs, Restricted for mgmt1): Stage Profile copied only cmdbId and cmdbName from a rule, so
    Stage Reconcile filled the other two from the CMDB.

    THE PRECEDENCE, per field:   rule override  >  CMDB record  >  nothing
    THE FIELDS a rule's `set:` may override (cmdbId is the KEY that picks the CMDB record, not an override):
        cmdbName              cmdbCriticality              cmdbDataSensitivity
    THE SOURCE of each is recorded beside it, so "why is this asset Restricted?" is answerable from the data alone:
        CmdbNameSource        CmdbCriticalitySource        CmdbDataSensitivitySource
          'rule:<RuleId>'  -- a matched rule set it
          'cmdb'           -- the CMDB record set it (the service matched by cmdbId, or a CI matched by identity)
          ''               -- no value
    (Pascal Cmdb* = SI's metadata about the CMDB data; camel cmdb* = the CMDB value itself -- #59.3 naming rule.)

    WHICH RULE, when several matched: the rule that supplied cmdbId wins for every field it sets (the override travels
    with the service it names); a field it does not set comes from the FIRST matched rule (rule order) that sets it.
    The same "first wins" order Stage Profile already uses for cmdbId.

    PS 5.1 safe: no ?. / ??, no ternary.
#>

$script:SICmdbOverrideFields = @('cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity')
$script:SICmdbFieldSourceColumns = [ordered]@{
    cmdbName            = 'CmdbNameSource'
    cmdbCriticality     = 'CmdbCriticalitySource'
    cmdbDataSensitivity = 'CmdbDataSensitivitySource'
}

function Get-SICmdbOverrideFields {
    <# The cmdb* fields a profile rule may override, in a fixed order. #>
    [string[]]$script:SICmdbOverrideFields
}

function Get-SICmdbFieldSourceColumn {
    <# The column that records where a cmdb* field's value came from ('' for a field that has none). #>
    param([Parameter(Mandatory)][string]$Field)
    if ($script:SICmdbFieldSourceColumns.Contains($Field)) { return [string]$script:SICmdbFieldSourceColumns[$Field] }
    ''
}

function Get-SICmdbSetValue {
    <# PURE. One key of a rule's `set:` block (hashtable or object, as the YAML parser returns it), trimmed; '' when absent. #>
    param($Set, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Set) { return '' }
    $v = $null
    if ($Set -is [System.Collections.IDictionary]) {
        foreach ($k in @($Set.Keys)) { if ([string]$k -ieq $Name) { $v = $Set[$k]; break } }
    } else {
        $p = $Set.PSObject.Properties[$Name]
        if ($p) { $v = $p.Value }
    }
    if ($null -eq $v) { return '' }
    if ($v -is [System.Collections.IDictionary] -or ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string]))) { return '' }
    ([string]$v).Trim()
}

function Get-SIRuleCmdbOverrides {
    <#
        PURE. The overrides the matched rules of ONE asset make, per field: field -> @{ Value; RuleId }. -RuleMatches are the
        rule matches in match order (Stage Profile's SI_RuleMatches entries: RuleId, cmdbId, and any of cmdbName /
        cmdbCriticality / cmdbDataSensitivity the rule set). A field no rule sets is absent from the answer.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$RuleMatches = @())
    $out = [ordered]@{}
    $list = @(@($RuleMatches) | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return $out }
    $owner = $list | Where-Object { [string](Get-SICmdbSetValue $_ 'cmdbId') } | Select-Object -First 1
    foreach ($f in $script:SICmdbOverrideFields) {
        $pick = $null
        if ($owner -and (Get-SICmdbSetValue $owner $f)) { $pick = $owner }
        else { $pick = $list | Where-Object { Get-SICmdbSetValue $_ $f } | Select-Object -First 1 }
        if ($pick) { $out[$f] = [pscustomobject]@{ Value = (Get-SICmdbSetValue $pick $f); RuleId = [string]$pick.RuleId } }
    }
    $out
}

function Set-SIRecordNote {
    <# Sets (or adds) one top-level property on a staged record. #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Name, $Value)
    if ($Record -is [System.Collections.IDictionary]) { $Record[$Name] = $Value; return }
    if ($Record.PSObject.Properties[$Name]) { $Record.$Name = $Value }
    else { Add-Member -InputObject $Record -MemberType NoteProperty -Name $Name -Value $Value -Force }
}

function Get-SIRecordText {
    <# A record's top-level property as trimmed text; '' when absent, null or a container. #>
    param($Record, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Record) { return '' }
    $v = $null
    if ($Record -is [System.Collections.IDictionary]) { if ($Record.Contains($Name)) { $v = $Record[$Name] } }
    elseif ($Record.PSObject.Properties[$Name]) { $v = $Record.$Name }
    if ($null -eq $v) { return '' }
    if ($v -is [System.Collections.IDictionary] -or $v -is [pscustomobject] -or ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string]))) { return '' }
    ([string]$v).Trim()
}

function Set-SIRuleCmdbOverrides {
    <#
        Stage Profile: stamps every override the matched rules make onto the record, with its source 'rule:<RuleId>'.
        A rule override is never weaker than a value already on the record -- it is the operator's explicit statement.
        Returns the number of fields stamped.
    #>
    param([Parameter(Mandatory)]$Record, [AllowNull()][AllowEmptyCollection()][object[]]$RuleMatches = @())
    $n = 0
    $ov = Get-SIRuleCmdbOverrides -RuleMatches $RuleMatches
    foreach ($f in @($ov.Keys)) {
        Set-SIRecordNote -Record $Record -Name $f -Value ([string]$ov[$f].Value)
        Set-SIRecordNote -Record $Record -Name (Get-SICmdbFieldSourceColumn $f) -Value ('rule:' + [string]$ov[$f].RuleId)
        $n++
    }
    $n
}

function Merge-SICmdbRecordField {
    <#
        Stage Reconcile: offers the CMDB record's value for one cmdb* field. The record keeps a value it already has (a
        rule override, or an earlier CMDB value) -- rule > CMDB. An empty field takes the CMDB value with source 'cmdb'.
        A value already present without a recorded source is labelled 'cmdb' only when it equals the CMDB value (it was
        filled from the CMDB before); otherwise its origin is unknown and the source stays empty rather than invented.
        Returns 'kept' | 'filled' | 'none'.
    #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Field, [AllowNull()][AllowEmptyString()][string]$CmdbValue)
    $cmdbVal = ([string]$CmdbValue).Trim()
    $srcCol = Get-SICmdbFieldSourceColumn $Field
    $have = Get-SIRecordText $Record $Field
    if ($have) {
        if ($srcCol -and -not (Get-SIRecordText $Record $srcCol) -and $cmdbVal -and $have -ceq $cmdbVal) { Set-SIRecordNote -Record $Record -Name $srcCol -Value 'cmdb' }
        return 'kept'
    }
    if (-not $cmdbVal) { return 'none' }
    Set-SIRecordNote -Record $Record -Name $Field -Value $cmdbVal
    if ($srcCol) { Set-SIRecordNote -Record $Record -Name $srcCol -Value 'cmdb' }
    'filled'
}
