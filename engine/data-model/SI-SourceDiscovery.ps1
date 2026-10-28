#Requires -Version 5.1
<#
    SecurityInsight CONTINUOUS DISCOVERY -- what every source offers, found again on every run.

    Owner: "basically puling in relevant context from the different sources. and continuesy do that so if ms adds more
    context next week we can provide it" / "otherwise we ae not selling si when you hide the rich data".

    ONE MECHANISM, A PROVIDER LIST ($script:SISourceDiscoveryProviders). Two kinds of provider:

      records   EVERY source SecurityInsight reads (Defender, Entra, Azure, Exposure Graph, Intune, Defender for Cloud, the
                public IP scan, Defender for Identity, Active Directory, the CMDB). The collectors already hand every object
                they read to the record capture as a PART of a record; when the records are published, the property names of
                every part are counted here. No request is made for it: the objects are the ones the run read anyway.
      schema    what a source SAYS it offers, read on the weekly schema sweep (the schema-discovery job): Microsoft Graph's
                published model for the object types SecurityInsight reads (one anonymous request), the column list of the
                Defender advanced hunting tables, the Exposure Graph node labels, a sample of Defender for Cloud assessments
                and sub-assessments, ServiceNow's dictionary for the tables SecurityInsight reads. A property a source offers
                and SecurityInsight does not read yet is kept as "offered, not read".

    A PROPERTY is named as the Full details export names it: a top-level value is "key"; a top-level object with
    properties gives one property per child, "key.child"; anything deeper is the child's own (JSON) value. A list of
    objects also gives "key[*].child" (what a mapping needs to read into the list).

    WHAT IS KEPT (the database, sidata.SourceProperty): per source, record type, Azure resource type, part and property --
    when it was first seen, when last, how many records carried it in the newest run, a sample value, its value type, the
    SI fields that already read it, and the full-details source it is a column of. sidata.SourceDiscoveryState keeps one
    row per source / record type / part: the first run of it is the BASELINE (what was there when discovery started is not
    "new"); everything first seen in a later run is new context. The web app's "New context available" page reads these
    rows -- it never walks a JSON document.

    READ ONLY. Never throws into a run: discovery that fails is said once and costs the run nothing; a source that could
    not be asked is recorded as "not read" with the reason (and the read permission it needs), never as "nothing new".
    PowerShell 5.1 + 7. No PowerShell modules. NO Set-StrictMode.
#>

# ---- the provider list ---------------------------------------------------------------------------------------------
# Kind 'records' needs no entry per source: every provider that hands a part to the record capture is covered. The
# labels are what the page shows; a source not listed is shown by its own name.
$script:SISourceDiscoveryLabels = [ordered]@{
    mde        = 'Microsoft Defender for Endpoint'
    entra      = 'Microsoft Entra ID (Microsoft Graph)'
    azure      = 'Azure (Resource Graph / Resource Manager)'
    eg         = 'Exposure Graph (Microsoft Security Exposure Management)'
    intune     = 'Microsoft Intune'
    mdc        = 'Microsoft Defender for Cloud'
    shodan     = 'Public IP scan (Shodan)'
    mdi        = 'Microsoft Defender for Identity'
    ad         = 'Active Directory'
    cmdb       = 'CMDB'
    servicenow = 'ServiceNow'
}

$script:SISourceDiscoveryProviders = @(
    @{ Id = 'records'; Kind = 'records'; Source = '*'; Requests = 'none'
       What = 'the objects every collector read this run, as they were handed to the record capture' }
    @{ Id = 'graph-metadata'; Kind = 'graph-metadata'; Source = 'entra'; Requests = 'one anonymous request a week'
       What = 'the properties Microsoft Graph publishes for the object types SecurityInsight reads'
       Url = 'https://graph.microsoft.com/v1.0/$metadata'
       # Graph entity type -> the record part SecurityInsight reads it as
       Routes = [ordered]@{
           user                 = @{ Source = 'entra';  RecordType = 'user';              Part = 'user' }
           device               = @{ Source = 'entra';  RecordType = 'device';            Part = 'device' }
           servicePrincipal     = @{ Source = 'entra';  RecordType = 'service_principal'; Part = 'sp' }
           application          = @{ Source = 'entra';  RecordType = 'service_principal'; Part = 'app' }
           riskyUser            = @{ Source = 'entra';  RecordType = 'user';              Part = 'risk' }
           riskyServicePrincipal = @{ Source = 'entra'; RecordType = 'service_principal'; Part = 'risk' }
           managedDevice        = @{ Source = 'intune'; RecordType = 'device';            Part = 'device' }
       } }
    @{ Id = 'defender-hunting'; Kind = 'hunting-schema'; Source = 'mde'; Requests = 'one query per table a week'
       What = 'the columns of the Defender advanced hunting tables'; Permission = 'ThreatHunting.Read.All'
       Routes = @{ DeviceInfo = @{ Source = 'mde'; RecordType = 'device'; Part = 'deviceInfo' } } }
    @{ Id = 'exposure-graph'; Kind = 'exposure-graph'; Source = 'eg'; Requests = 'the weekly sweep''s own queries'
       What = 'the node types of the Exposure Graph and their properties'; Permission = 'ThreatHunting.Read.All' }
    @{ Id = 'defender-for-cloud'; Kind = 'arg-sample'; Source = 'mdc'; Requests = 'two Resource Graph queries a week'
       What = 'the properties of Defender for Cloud assessments and sub-assessments (a sample of each)'; Permission = 'Reader'
       Queries = @(
           @{ RecordType = 'assessment';     Part = 'assessment';    Type = 'microsoft.security/assessments' }
           @{ RecordType = 'sub_assessment'; Part = 'subassessment'; Type = 'microsoft.security/assessments/subassessments' }
       ) }
    @{ Id = 'servicenow-dictionary'; Kind = 'servicenow-dictionary'; Source = 'servicenow'; Requests = 'one request per table a week'
       What = 'the columns ServiceNow''s dictionary lists for the tables SecurityInsight reads'
       Tables = @('cmdb_ci_service', 'cmdb_rel_ci', 'cmdb_ci') }
)

# A record part that is the SAME object the full asset details keep (engine/asset-profiling/shared): its properties are
# also columns of the data views ("Source: <name>" in the column chooser). 'source|record type|part' -> the source system.
$script:SISourceDiscoveryColumnSources = @{
    'mde|device|machine'              = 'mde'
    'entra|device|device'             = 'entra-device'
    'entra|user|user'                 = 'entra-user'
    'entra|service_principal|sp'      = 'entra-serviceprincipal'
    'azure|azure_resource|resource'   = 'arm'
    'azure|public_ip|resource'        = 'arm'
    'eg|device|node'                  = 'exposure-graph'
    'eg|user|node'                    = 'exposure-graph'
    'eg|service_principal|node'       = 'exposure-graph'
    'eg|azure_resource|node'          = 'exposure-graph'
    'eg|public_ip|node'               = 'exposure-graph'
    'intune|device|device'            = 'intune-device'
    'ad|device|computer'              = 'ad-computer'
}

# Wrappers the walk goes THROUGH (their children are the source's properties): 'source|part' -> the dotted prefixes.
$script:SISourceDiscoveryUnwrap = @{
    'eg|node'              = @('NodeProperties', 'NodeProperties.rawData')
    'mdc|assessment'       = @('properties')
    'mdc|subassessment'    = @('properties')
}

# Parts SecurityInsight builds itself -- not what a source offers.
$script:SISourceDiscoverySkipParts = @('derived', 'children', 'egQueryRules', 'mg')

# Properties whose children are the tenant's own keys (one "property" per tag would be noise): listed once, never opened.
$script:SISourceDiscoveryOpaque = @('tags', 'extensionAttributes', 'customSecurityAttributes', 'onPremisesExtensionAttributes')

# Properties a source offers only with a READ permission SecurityInsight does not ask for today. Proposed on the page,
# never requested or added by itself. 'source|record type|part|property' (lower case) -> the permission.
$script:SISourceDiscoveryPermissions = @{
    'entra|user|user|employeeleavedatetime' = 'User-LifeCycleInfo.Read.All'
    'entra|user|user|employeehiredate'      = 'User-LifeCycleInfo.Read.All'
    'entra|user|user|signinactivity'        = 'AuditLog.Read.All'
    'entra|user|user|customsecurityattributes'              = 'CustomSecAttributeAssignment.Read.All'
    'entra|service_principal|sp|customsecurityattributes'   = 'CustomSecAttributeAssignment.Read.All'
}

$script:SISourceDiscoveryMaxProperty = 256
$script:SISourceDiscoveryMaxSample = 200
# Measure, then adapt (Add-SISourceDiscoveryObject): every object of a part is walked until the part was seen this many
# times in one pass; beyond it one object in WalkEvery is walked and counts for WalkEvery.
$script:SISourceDiscoveryWalkAll = 2000
$script:SISourceDiscoveryWalkEvery = 10

function Get-SISourceDiscoveryProviders {
    <# PURE. The provider list (a copy): Id, Kind (records | graph-metadata | hunting-schema | exposure-graph | arg-sample | servicenow-dictionary), Source, What, Requests. #>
    foreach ($p in $script:SISourceDiscoveryProviders) { [pscustomobject]@{ Id = [string]$p.Id; Kind = [string]$p.Kind; Source = [string]$p.Source; What = [string]$p.What; Requests = [string]$p.Requests; Permission = [string]$p.Permission } }
}

function Get-SISourceDiscoveryHuntingTables {
    <# PURE. The Defender advanced hunting tables SecurityInsight reads -- their column lists are part of the weekly sweep. #>
    @('DeviceInfo', 'DeviceNetworkInfo', 'DeviceLogonEvents', 'AlertEvidence', 'AlertInfo',
      'DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareVulnerabilitiesKB', 'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSecureConfigurationAssessmentKB',
      'DeviceTvmSoftwareInventory', 'DeviceTvmInfoGathering', 'DeviceTvmHardwareFirmware', 'DeviceTvmSoftwareEvidenceBeta', 'DeviceTvmCertificateInfo', 'DeviceTvmBrowserExtensions',
      'ExposureGraphNodes', 'ExposureGraphEdges', 'IdentityInfo')
}

function Get-SISourceDiscoveryLabel {
    <# PURE. A source's name as the page shows it. #>
    param([AllowNull()][string]$Source)
    $k = ([string]$Source).Trim().ToLowerInvariant()
    if ($script:SISourceDiscoveryLabels.Contains($k)) { return [string]$script:SISourceDiscoveryLabels[$k] }
    $k
}

function Test-SISourceDiscoveryOn {
    <# PURE. Discovery is part of every run (it makes no request of its own for the records). -Setting (tests): off / false / 0 / no turns it off. #>
    param([AllowNull()]$Setting = $null)
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    return (-not ($s -in 'off', 'false', '0', 'no'))
}

function Test-SISourceObject {
    <# PURE. Is the value an object with properties (not text, not a list, not a number)? #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $false }
    if ($Value -is [System.Collections.IDictionary]) { return ($Value.Count -gt 0) }
    if ($Value -is [System.Collections.IEnumerable]) { return $false }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { foreach ($p in $Value.PSObject.Properties) { return $true }; return $false }
    return $false
}

function Get-SISourceObjectProperties {
    <# PURE. An object's own properties as name / value pairs (a hashtable's keys, or an object's properties). #>
    param([AllowNull()]$Object)
    if ($null -eq $Object) { return }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in @($Object.Keys)) { [System.Collections.Generic.KeyValuePair[string, object]]::new([string]$k, $Object[$k]) }
        return
    }
    foreach ($p in $Object.PSObject.Properties) { [System.Collections.Generic.KeyValuePair[string, object]]::new([string]$p.Name, $p.Value) }
}

function Add-SISourcePropertyNames {
    <#
        PURE. The property names of ONE source object into -Into (name -> the first value seen), as the Full details
        export names them: "key" for a top-level value, "key.child" for the children of a top-level object, and
        "key[*].child" for the children of the objects in a top-level list. -Unwrap: dotted prefixes the walk goes
        through (their children are treated as the top level). Names that are not plain property names are left out.
    #>
    param([AllowNull()]$Object, [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$Into,
          [string[]]$Unwrap = @(), [string]$Prefix = '', [int]$Depth = 0)
    if ($null -eq $Object -or $Depth -gt 4) { return }
    # a dictionary is walked as an object (the records' parts are objects already; this is the rare path)
    if ($Object -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in @($Object.Keys)) { $h[[string]$k] = $Object[$k] }
        $Object = [pscustomobject]$h
    }
    if (-not ($Object -is [System.Management.Automation.PSCustomObject])) { return }
    # THE HOT LOOP (once per property of every part of every record): no function call per property
    foreach ($pr in $Object.PSObject.Properties) {
        $name = $pr.Name
        if (-not $name -or $name[0] -eq '@' -or $name.Contains('@odata')) { continue }
        $path = $name; if ($Prefix) { $path = $Prefix + '.' + $name }
        $v = $pr.Value
        if ($v -is [System.Collections.IDictionary]) { $hv = [ordered]@{}; foreach ($k in @($v.Keys)) { $hv[[string]$k] = $v[$k] }; $v = [pscustomobject]$hv }
        $isObject = ($v -is [System.Management.Automation.PSCustomObject])
        if ($isObject -and $Unwrap.Count -gt 0 -and $Unwrap -contains $path) {
            Add-SISourcePropertyNames -Object $v -Into $Into -Unwrap $Unwrap -Prefix $path -Depth ($Depth + 1)
            continue
        }
        if (-not $Into.ContainsKey($path)) { $Into[$path] = $v }
        if ($null -eq $v -or $v -is [string] -or $v -is [ValueType]) { continue }
        if ($script:SISourceDiscoveryOpaque -contains $name) { continue }
        if ($isObject) {
            foreach ($c in $v.PSObject.Properties) {
                $cn = $c.Name
                if (-not $cn -or $cn[0] -eq '@' -or $cn.Contains('@odata')) { continue }
                $cp = $path + '.' + $cn
                if (-not $Into.ContainsKey($cp)) { $Into[$cp] = $c.Value }
            }
        } elseif ($v -is [System.Collections.IEnumerable]) {
            # a list of objects: the children of its first few items (what a mapping reads as key[*].child)
            $seen = 0
            foreach ($el in $v) {
                if ($seen -ge 3) { break }
                $seen++
                if (-not ($el -is [System.Management.Automation.PSCustomObject])) { continue }
                foreach ($c in $el.PSObject.Properties) {
                    $cn = $c.Name
                    if (-not $cn -or $cn[0] -eq '@' -or $cn.Contains('@odata')) { continue }
                    $cp = $path + '[*].' + $cn
                    if (-not $Into.ContainsKey($cp)) { $Into[$cp] = $c.Value }
                }
            }
        }
    }
}

function Get-SISourceValueType {
    <# PURE. text | number | yes/no | date | list | object | '' (no value). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return 'yes/no' }
    if ($Value -is [datetime] -or $Value -is [System.DateTimeOffset]) { return 'date' }
    if ($Value -is [ValueType]) { return 'number' }
    if ($Value -is [string]) { if ($Value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}') { return 'date' }; return 'text' }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) { return 'object' }
    if ($Value -is [System.Collections.IEnumerable]) { return 'list' }
    return 'text'
}

function ConvertTo-SISourceSample {
    <# PURE. A value as a short sample text ('' = no value): text as it is, a number / date invariant, an object or list as compact JSON -- cut at 200 characters. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $t = ''
    try {
        if ($Value -is [string]) { $t = $Value }
        elseif ($Value -is [bool]) { $t = $(if ($Value) { 'true' } else { 'false' }) }
        elseif ($Value -is [datetime]) { $t = $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        # a number (or another value with an invariant form). An OBJECT is never taken here: PowerShell's own object
        # wrapper says it can be formatted too, and has no such form -- its sample is its compact JSON, below
        elseif ($Value -isnot [System.Management.Automation.PSCustomObject] -and $Value -is [System.IFormattable]) { $t =$Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
        else {
            if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) {
                $n = 0; foreach ($x in $Value) { $n++; if ($n -gt 0) { break } }
                if ($n -eq 0) { return '' }
            }
            $t = ConvertTo-Json -InputObject $Value -Compress -Depth 3 -WarningAction SilentlyContinue
        }
    } catch { $t = '' }
    $t = ([string]$t) -replace '[\r\n\t]+', ' '
    $t = $t.Trim()
    if ($t.Length -gt $script:SISourceDiscoveryMaxSample) { $t = $t.Substring(0, $script:SISourceDiscoveryMaxSample - 1) + [char]0x2026 }
    $t
}

function New-SISourceDiscoveryState {
    <# The counters of one discovery pass: Props ('source|record type|resource type|part|property' -> its counter) and Types ('source|record type|resource type|part|origin' -> its counter). #>
    [pscustomobject]@{
        Props   = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
        Types   = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
        Objects = 0
    }
}

function Add-SISourceDiscoveryType {
    <# One record type / part of a source seen by this pass (-Records more records carried it; -ErrorText: the source could not be asked). #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$RecordType, [string]$ResourceType = '',
          [Parameter(Mandatory)][string]$Part, [string]$Origin = 'records', [int]$Records = 0, [string]$ErrorText = '', [string]$NeedsPermission = '')
    $k = ('{0}|{1}|{2}|{3}|{4}' -f $Source, $RecordType, $ResourceType, $Part, $Origin).ToLowerInvariant()
    $t = $null
    if (-not $State.Types.TryGetValue($k, [ref]$t)) {
        $t = [pscustomobject]@{ Source = $Source.ToLowerInvariant(); RecordType = $RecordType.ToLowerInvariant(); ResourceType = $ResourceType.ToLowerInvariant(); Part = $Part; Origin = $Origin
                                Records = 0; Error = ''; NeedsPermission = ''; Met = 0 }
        $State.Types[$k] = $t
    }
    $t.Records = [int]$t.Records + $Records
    if ($ErrorText) { $t.Error = $ErrorText }
    if ($NeedsPermission) { $t.NeedsPermission = $NeedsPermission }
}

function Add-SISourceDiscoveryProperty {
    <# One property of a source: counted (-Records), its first non-empty value kept as the sample. -Collected $false: the source offers it and SecurityInsight does not read it. #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$RecordType, [string]$ResourceType = '',
          [Parameter(Mandatory)][string]$Part, [Parameter(Mandatory)][string]$Property, [AllowNull()]$Value, [int]$Records = 1, [bool]$Collected = $true,
          [string]$Origin = 'records', [string]$ValueType = '')
    if ($Property.Length -gt $script:SISourceDiscoveryMaxProperty) { return }
    $k = ('{0}|{1}|{2}|{3}|{4}' -f $Source, $RecordType, $ResourceType, $Part, $Property).ToLowerInvariant()
    $p = $null
    if (-not $State.Props.TryGetValue($k, [ref]$p)) {
        $p = [pscustomobject]@{ Source = $Source.ToLowerInvariant(); RecordType = $RecordType.ToLowerInvariant(); ResourceType = $ResourceType.ToLowerInvariant(); Part = $Part; Property = $Property
                                Records = 0; Sample = ''; ValueType = $ValueType; Collected = $Collected; Origin = $Origin }
        $State.Props[$k] = $p
    }
    $p.Records = [int]$p.Records + $Records
    if ($Collected) { $p.Collected = $true }
    if (-not $p.Sample -and $null -ne $Value) {
        $s = ConvertTo-SISourceSample $Value
        if ($s) { $p.Sample = $s; if (-not $p.ValueType) { $p.ValueType = Get-SISourceValueType $Value } }
    }
}

function Add-SISourceDiscoveryObject {
    <# One object a collector read (a record part): every property name counted once for this object. #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$RecordType, [string]$ResourceType = '',
          [Parameter(Mandatory)][string]$Part, [AllowNull()]$Object, [string]$Origin = 'records', [bool]$Collected = $true)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [ValueType]) { return }
    if (-not ($Object -is [System.Management.Automation.PSCustomObject]) -and -not ($Object -is [System.Collections.IDictionary])) { return }
    $src = $Source.ToLowerInvariant(); $rt = $RecordType.ToLowerInvariant(); $res = $ResourceType.ToLowerInvariant()
    $prefix = $src + '|' + $rt + '|' + $res + '|' + $Part + '|'
    $typeKey = ($prefix + $Origin).ToLowerInvariant()
    # MEASURE, THEN ADAPT: every object of a part is walked until the part has been seen 2,000 times in this pass; from
    # there every tenth is walked and counts for ten. The names and the samples come from what is walked; the counts of a
    # very large collection are then close estimates, and the pass costs a large tenant little more than a small one.
    $t = $null
    if (-not $State.Types.TryGetValue($typeKey, [ref]$t)) {
        $t = [pscustomobject]@{ Source = $src; RecordType = $rt; ResourceType = $res; Part = $Part; Origin = $Origin; Records = 0; Error = ''; NeedsPermission = ''; Met = 0 }
        $State.Types[$typeKey] = $t
    }
    $t.Met = [int]$t.Met + 1
    $weight = 1
    if ([int]$t.Met -gt $script:SISourceDiscoveryWalkAll) {
        if (([int]$t.Met % $script:SISourceDiscoveryWalkEvery) -ne 0) { return }
        $weight = $script:SISourceDiscoveryWalkEvery
    }
    $names = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $unwrap = @(); $uk = $src + '|' + $Part.ToLowerInvariant()
    if ($script:SISourceDiscoveryUnwrap.ContainsKey($uk)) { $unwrap = @($script:SISourceDiscoveryUnwrap[$uk]) }
    Add-SISourcePropertyNames -Object $Object -Into $names -Unwrap $unwrap
    if ($names.Count -eq 0) { return }
    $t.Records = [int]$t.Records + $weight
    $max = $script:SISourceDiscoveryMaxProperty
    foreach ($kv in $names.GetEnumerator()) {
        $n = $kv.Key
        if ($n.Length -gt $max) { continue }
        $k = ($prefix + $n).ToLowerInvariant()
        $p = $null
        if (-not $State.Props.TryGetValue($k, [ref]$p)) {
            $p = [pscustomobject]@{ Source = $src; RecordType = $rt; ResourceType = $res; Part = $Part; Property = $n; Records = 0; Sample = ''; ValueType = ''; Collected = $Collected; Origin = $Origin }
            $State.Props[$k] = $p
        }
        # a record CARRIES a property when it has a value for it (a name without a value is still listed, with 0 records)
        $v = $kv.Value
        if ($null -eq $v -or ($v -is [string] -and $v.Length -eq 0)) { continue }
        $p.Records = [int]$p.Records + $weight
        if ($Collected) { $p.Collected = $true }
        if (-not $p.Sample) {
            $s = ConvertTo-SISourceSample $v
            if ($s) { $p.Sample = $s; $p.ValueType = Get-SISourceValueType $v }
        }
    }
    $State.Objects = [int]$State.Objects + 1
}

function Add-SISourceDiscoveryRecord {
    <#
        One captured record (Get-SICapturedRecords: Provider, RecordType, ResourceType, Object = its parts): every part is
        one source object. Parts SecurityInsight builds itself are left out. Never throws.
    #>
    param([Parameter(Mandatory)]$State, [AllowNull()]$Record)
    try {
        if ($null -eq $Record -or $null -eq $Record.Object) { return }
        $src = [string]$Record.Provider; $rt = [string]$Record.RecordType
        if (-not $src -or -not $rt) { return }
        # the Azure resource type is part of the key for Azure objects only (one property list per resource type)
        $res = ''; if ($src -in 'azure', 'mdc') { $res = [string]$Record.ResourceType }
        foreach ($kv in @(Get-SISourceObjectProperties $Record.Object)) {
            if ($script:SISourceDiscoverySkipParts -contains $kv.Key) { continue }
            Add-SISourceDiscoveryObject -State $State -Source $src -RecordType $rt -ResourceType $res -Part $kv.Key -Object $kv.Value
        }
    } catch { Write-Verbose ('continuous discovery: a record was left out -- ' + $_.Exception.Message) }
}

function Get-SISourceMappingIndex {
    <# PURE. The data model's mappings as 'provider|record type' -> list of @{ Field; Source (its trailing [*] removed) }. #>
    param([AllowNull()]$Model)
    $ix = @{}
    if ($null -eq $Model -or $null -eq $Model.Mappings) { return $ix }
    foreach ($prov in @($Model.Mappings.Keys)) {
        $m = $Model.Mappings[$prov]
        if ($null -eq $m) { continue }
        foreach ($row in @($m.mappings)) {
            if ($null -eq $row -or -not $row.field) { continue }
            foreach ($rt in @($row.recordTypes)) {
                $k = ('{0}|{1}' -f $prov, $rt).ToLowerInvariant()
                if (-not $ix.ContainsKey($k)) { $ix[$k] = New-Object System.Collections.Generic.List[object] }
                foreach ($s in @($row.sources)) {
                    $t = ([string]$s).Trim()
                    while ($t.EndsWith('[*]')) { $t = $t.Substring(0, $t.Length - 3) }
                    if ($t) { $ix[$k].Add([pscustomobject]@{ Field = [string]$row.field; Source = $t }) }
                }
            }
        }
    }
    $ix
}

function Get-SISourceMappedFields {
    <# PURE. The SI fields whose mapping reads the property ('part.property'): the same path, or a path inside it. #>
    param([AllowNull()]$Index, [string]$Source, [string]$RecordType, [string]$Part, [string]$Property)
    if ($null -eq $Index) { return @() }
    $k = ('{0}|{1}' -f $Source, $RecordType).ToLowerInvariant()
    if (-not $Index.ContainsKey($k)) { return @() }
    $path = $Part + '.' + $Property
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $Index[$k]) {
        $s = [string]$m.Source
        if ($s -ceq $path -or $s.StartsWith($path + '.', [StringComparison]::Ordinal) -or $s.StartsWith($path + '[', [StringComparison]::Ordinal)) {
            if (-not $out.Contains([string]$m.Field)) { $out.Add([string]$m.Field) }
        }
    }
    @($out | Sort-Object)
}

function Get-SISourceColumnSource {
    <# PURE. The full-details source system a part's properties are columns of ('' = none), and only for a property the export gives a column (at most key.child, no list path). #>
    param([string]$Source, [string]$RecordType, [string]$Part, [string]$Property)
    if ($Property.Contains('[*]') -or @($Property.Split('.')).Count -gt 2) { return '' }
    $k = ('{0}|{1}|{2}' -f $Source, $RecordType, $Part).ToLowerInvariant()
    if ($script:SISourceDiscoveryColumnSources.ContainsKey($k)) { return [string]$script:SISourceDiscoveryColumnSources[$k] }
    ''
}

function Get-SISourceDiscoveryKeyHash {
    <# PURE. SHA-256 (hex) of a lower-cased key -- the rows' primary key (the natural key is too long for an index). #>
    param([Parameter(Mandatory)][string]$Key)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Key.ToLowerInvariant())) | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
}

function ConvertTo-SISourceDiscoveryRows {
    <#
        PURE. The counters of a pass as the rows the database takes: Properties (with the SI fields that read each, the
        full-details column source, the read permission a known gated property needs) and Types.
    #>
    param([Parameter(Mandatory)]$State, [AllowNull()]$Model)
    $ix = Get-SISourceMappingIndex -Model $Model
    $props = New-Object System.Collections.Generic.List[object]
    foreach ($p in $State.Props.Values) {
        $mapped = @(Get-SISourceMappedFields -Index $ix -Source $p.Source -RecordType $p.RecordType -Part $p.Part -Property $p.Property)
        $perm = ''
        $pk = ('{0}|{1}|{2}|{3}' -f $p.Source, $p.RecordType, $p.Part, $p.Property).ToLowerInvariant()
        if ($script:SISourceDiscoveryPermissions.ContainsKey($pk)) { $perm = [string]$script:SISourceDiscoveryPermissions[$pk] }
        $mf = ($mapped -join ', '); if ($mf.Length -gt 400) { $mf = $mf.Substring(0, 400) }
        $props.Add([pscustomobject][ordered]@{
            KeyHash         = Get-SISourceDiscoveryKeyHash ('{0}|{1}|{2}|{3}|{4}' -f $p.Source, $p.RecordType, $p.ResourceType, $p.Part, $p.Property)
            TypeHash        = Get-SISourceDiscoveryKeyHash ('{0}|{1}|{2}|{3}|{4}' -f $p.Source, $p.RecordType, $p.ResourceType, $p.Part, $p.Origin)
            Source          = [string]$p.Source
            RecordType      = [string]$p.RecordType
            ResourceType    = [string]$p.ResourceType
            Part            = [string]$p.Part
            Property        = [string]$p.Property
            SourceSystem    = Get-SISourceColumnSource -Source $p.Source -RecordType $p.RecordType -Part $p.Part -Property $p.Property
            ValueType       = [string]$p.ValueType
            SampleValue     = [string]$p.Sample
            Records         = [int]$p.Records
            Collected       = [int][bool]$p.Collected
            Origin          = [string]$p.Origin
            MappedFields    = $mf
            NeedsPermission = $perm
        })
    }
    $types = New-Object System.Collections.Generic.List[object]
    foreach ($t in $State.Types.Values) {
        $err = [string]$t.Error; if ($err.Length -gt 400) { $err = $err.Substring(0, 400) }
        $types.Add([pscustomobject][ordered]@{
            TypeHash        = Get-SISourceDiscoveryKeyHash ('{0}|{1}|{2}|{3}|{4}' -f $t.Source, $t.RecordType, $t.ResourceType, $t.Part, $t.Origin)
            Source          = [string]$t.Source
            RecordType      = [string]$t.RecordType
            ResourceType    = [string]$t.ResourceType
            Part            = [string]$t.Part
            Origin          = [string]$t.Origin
            Records         = [int]$t.Records
            Error           = $err
            NeedsPermission = [string]$t.NeedsPermission
        })
    }
    [pscustomobject]@{ Properties = $props.ToArray(); Types = $types.ToArray() }
}

function Compare-SISourceDiscovery {
    <#
        PURE. The diff of two property lists (each item: Source, RecordType, ResourceType, Part, Property): what is in
        -Current and not in -Previous. -Previous $null (the first run) = nothing is new: it is the baseline.
    #>
    param([AllowNull()][object[]]$Previous, [AllowEmptyCollection()][object[]]$Current = @())
    if ($null -eq $Previous) { return @() }
    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $types = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $Previous) {
        if ($null -eq $p) { continue }
        [void]$have.Add(('{0}|{1}|{2}|{3}|{4}' -f $p.Source, $p.RecordType, $p.ResourceType, $p.Part, $p.Property))
        [void]$types.Add(('{0}|{1}|{2}|{3}' -f $p.Source, $p.RecordType, $p.ResourceType, $p.Part))
    }
    $new = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Current) {
        if ($null -eq $c) { continue }
        # a part never seen before is that part's baseline, not new context
        if (-not $types.Contains(('{0}|{1}|{2}|{3}' -f $c.Source, $c.RecordType, $c.ResourceType, $c.Part))) { continue }
        if (-not $have.Contains(('{0}|{1}|{2}|{3}|{4}' -f $c.Source, $c.RecordType, $c.ResourceType, $c.Part, $c.Property))) { $new.Add($c) }
    }
    $new.ToArray()
}

function Get-SISourceDiscoveryWriteSql {
    <#
        The ONE statement a pass is written with (additive: the tables are created by the schema, never here). A property
        seen for the first time is the BASELINE when its source / record type / part was never discovered before this
        run, else new context (Baseline = 0, FirstSeen = now). The counts of one run add up over its parts (a run
        published in several pieces). Answers one row: Properties (the pass), Added (rows new to the database), NewContext
        (of those, not baseline); -1 everywhere when the tables are not there yet.
    #>
    @'
SET XACT_ABORT ON;
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.SourceProperty') IS NULL OR OBJECT_ID(N'sidata.SourceDiscoveryState') IS NULL
BEGIN
    SELECT -1 AS Properties, -1 AS Added, -1 AS NewContext;
    RETURN;
END
DECLARE @now DATETIME2(0) = CONVERT(DATETIME2(0), @at, 126);
DECLARE @r NVARCHAR(64) = LEFT(@run, 64);
DECLARE @p TABLE (KeyHash VARBINARY(32) PRIMARY KEY, TypeHash VARBINARY(32), Source NVARCHAR(32), RecordType NVARCHAR(64), ResourceType NVARCHAR(128), Part NVARCHAR(64),
    Property NVARCHAR(256), SourceSystem NVARCHAR(32), ValueType NVARCHAR(16), SampleValue NVARCHAR(400), Records INT, Collected BIT, Origin NVARCHAR(16),
    MappedFields NVARCHAR(400), NeedsPermission NVARCHAR(128));
INSERT @p SELECT CONVERT(VARBINARY(32), KeyHash, 2), MAX(CONVERT(VARBINARY(32), TypeHash, 2)), MAX(Source), MAX(RecordType), MAX(ISNULL(ResourceType, N'')), MAX(Part), MAX(Property),
    NULLIF(MAX(SourceSystem), N''), NULLIF(MAX(ValueType), N''), NULLIF(MAX(SampleValue), N''), SUM(ISNULL(Records, 0)), CAST(MAX(CAST(ISNULL(Collected, 1) AS INT)) AS BIT), MAX(Origin),
    NULLIF(MAX(MappedFields), N''), NULLIF(MAX(NeedsPermission), N'')
FROM OPENJSON(@props) WITH (KeyHash VARCHAR(64), TypeHash VARCHAR(64), Source NVARCHAR(32), RecordType NVARCHAR(64), ResourceType NVARCHAR(128), Part NVARCHAR(64),
    Property NVARCHAR(256), SourceSystem NVARCHAR(32), ValueType NVARCHAR(16), SampleValue NVARCHAR(400), Records INT, Collected BIT, Origin NVARCHAR(16),
    MappedFields NVARCHAR(400), NeedsPermission NVARCHAR(128))
WHERE KeyHash IS NOT NULL GROUP BY KeyHash;
DECLARE @t TABLE (TypeHash VARBINARY(32) PRIMARY KEY, Source NVARCHAR(32), RecordType NVARCHAR(64), ResourceType NVARCHAR(128), Part NVARCHAR(64), Origin NVARCHAR(16),
    Records INT, Error NVARCHAR(400), NeedsPermission NVARCHAR(128));
INSERT @t SELECT CONVERT(VARBINARY(32), TypeHash, 2), MAX(Source), MAX(RecordType), MAX(ISNULL(ResourceType, N'')), MAX(Part), MAX(Origin), SUM(ISNULL(Records, 0)),
    NULLIF(MAX(Error), N''), NULLIF(MAX(NeedsPermission), N'')
FROM OPENJSON(@types) WITH (TypeHash VARCHAR(64), Source NVARCHAR(32), RecordType NVARCHAR(64), ResourceType NVARCHAR(128), Part NVARCHAR(64), Origin NVARCHAR(16),
    Records INT, Error NVARCHAR(400), NeedsPermission NVARCHAR(128))
WHERE TypeHash IS NOT NULL GROUP BY TypeHash;
DECLARE @o TABLE (Act NVARCHAR(10), Baseline BIT);
BEGIN TRANSACTION;
MERGE sidata.SourceProperty WITH (HOLDLOCK) AS t
USING @p AS s ON t.KeyHash = s.KeyHash
WHEN MATCHED THEN UPDATE SET
    LastSeen        = @now,
    Records         = CASE WHEN s.Collected = 0 THEN t.Records WHEN t.RunId = @r THEN t.Records + s.Records ELSE s.Records END,
    RunId           = CASE WHEN s.Collected = 0 THEN t.RunId ELSE @r END,
    CollectedSince  = CASE WHEN s.Collected = 1 AND t.Collected = 0 THEN @now ELSE t.CollectedSince END,
    Collected       = CASE WHEN s.Collected = 1 THEN 1 ELSE t.Collected END,
    SampleValue     = COALESCE(s.SampleValue, t.SampleValue),
    ValueType       = COALESCE(s.ValueType, t.ValueType),
    SourceSystem    = COALESCE(s.SourceSystem, t.SourceSystem),
    MappedFields    = CASE WHEN s.Collected = 1 OR s.MappedFields IS NOT NULL THEN s.MappedFields ELSE t.MappedFields END,
    NeedsPermission = COALESCE(s.NeedsPermission, t.NeedsPermission)
WHEN NOT MATCHED THEN INSERT (KeyHash, Source, RecordType, ResourceType, Part, Property, SourceSystem, ValueType, SampleValue, Records, Collected, CollectedSince, Origin,
    Baseline, MappedFields, NeedsPermission, FirstSeen, LastSeen, RunId)
    VALUES (s.KeyHash, s.Source, s.RecordType, s.ResourceType, s.Part, s.Property, s.SourceSystem, s.ValueType, s.SampleValue, s.Records, s.Collected,
        CASE WHEN s.Collected = 1 THEN @now END, s.Origin,
        CASE WHEN EXISTS (SELECT 1 FROM sidata.SourceDiscoveryState AS d WHERE d.TypeHash = s.TypeHash AND d.FirstRunId <> @r) THEN 0 ELSE 1 END,
        s.MappedFields, s.NeedsPermission, @now, @now, CASE WHEN s.Collected = 1 THEN @r END)
OUTPUT $action, inserted.Baseline INTO @o;
MERGE sidata.SourceDiscoveryState WITH (HOLDLOCK) AS t
USING @t AS s ON t.TypeHash = s.TypeHash
WHEN MATCHED THEN UPDATE SET
    LastRunAt = @now,
    Records = CASE WHEN t.RunId = @r THEN t.Records + s.Records ELSE s.Records END,
    RunId = @r, Error = s.Error, NeedsPermission = s.NeedsPermission
WHEN NOT MATCHED THEN INSERT (TypeHash, Source, RecordType, ResourceType, Part, Origin, Records, Error, NeedsPermission, FirstRunId, RunId, FirstRunAt, LastRunAt)
    VALUES (s.TypeHash, s.Source, s.RecordType, s.ResourceType, s.Part, s.Origin, s.Records, s.Error, s.NeedsPermission, @r, @r, @now, @now);
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM @p) AS Properties,
       (SELECT COUNT(*) FROM @o WHERE Act = N'INSERT') AS Added,
       (SELECT COUNT(*) FROM @o WHERE Act = N'INSERT' AND Baseline = 0) AS NewContext;
'@
}

function ConvertTo-SISourceDiscoveryJson {
    <# PURE. Always a JSON ARRAY (PowerShell 5.1 writes a one-item list as the bare object). #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items)
    if ($null -eq $Items -or @($Items).Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject @($Items) -Compress -Depth 4
    if ($j.TrimStart().StartsWith('[')) { $j } else { '[' + $j + ']' }
}

function Write-SISourceDiscovery {
    <#
        One pass -> the database. -Invoke { param($Sql, $Params, $Mode) } is the SQL seam (the record writer's). Returns
        @{ Properties; Added; NewContext; Written } -- Written $false when there is no database, the tables are not there
        yet (the updater adds them) or the write failed (said once). NEVER throws.
    #>
    param([Parameter(Mandatory)]$State, [AllowNull()]$Model, [AllowNull()][scriptblock]$Invoke, [string]$RunId = '', [datetime]$Now = [datetime]::UtcNow)
    $res = [pscustomobject]@{ Properties = 0; Added = 0; NewContext = 0; Written = $false; Reason = '' }
    try {
        if ($null -eq $State -or ($State.Props.Count -eq 0 -and $State.Types.Count -eq 0)) { $res.Reason = 'nothing was seen'; return $res }
        $rows = ConvertTo-SISourceDiscoveryRows -State $State -Model $Model
        $res.Properties = @($rows.Properties).Count
        if (-not $Invoke) { $res.Reason = 'no database is configured'; return $res }
        if (-not $RunId) { $RunId = 'run-' + $Now.ToUniversalTime().ToString('yyyyMMddHHmmss') }
        $p = @{
            props = (ConvertTo-SISourceDiscoveryJson $rows.Properties)
            types = (ConvertTo-SISourceDiscoveryJson $rows.Types)
            run   = $RunId
            at    = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
        }
        $ans = @(& $Invoke (Get-SISourceDiscoveryWriteSql) $p 'rows')
        $row = $null; if ($ans.Count -gt 0) { $row = $ans[0] }
        if ($null -eq $row) { $res.Reason = 'the database gave no answer'; return $res }
        $n = [int]$row.Properties
        if ($n -lt 0) { $res.Reason = 'the database is not updated yet (the updater adds the discovery tables)'; return $res }
        $res.Added = [int]$row.Added; $res.NewContext = [int]$row.NewContext; $res.Written = $true
    } catch {
        $res.Reason = [string]$_.Exception.Message
        if (-not $script:SISourceDiscoveryWriteSaid) {
            $script:SISourceDiscoveryWriteSaid = $true
            Write-Warning ('The list of properties each source offers could not be saved this run -- {0}. Nothing else is affected; the next run saves it.' -f $res.Reason)
        }
    }
    $res
}

function Get-SISourceDiscoverySummaryText {
    <# PURE. One plain line for the run's log. #>
    param([Parameter(Mandatory)]$Result, [string]$What = 'this run')
    if (-not $Result.Written) { return ('Source properties seen by {0}: {1} (not saved: {2}).' -f $What, [int]$Result.Properties, [string]$Result.Reason) }
    if ([int]$Result.NewContext -gt 0) { return ('Source properties seen by {0}: {1}; {2} are new since the last run -- see "New context available" in the web app.' -f $What, [int]$Result.Properties, [int]$Result.NewContext) }
    ('Source properties seen by {0}: {1}; nothing new since the last run.' -f $What, [int]$Result.Properties)
}

# =====================================================================================================================
# THE SCHEMA PROVIDERS -- the weekly sweep (the schema-discovery job). Each is one function with a test seam; each
# records "not read" with the reason when it cannot ask, and never throws.
# =====================================================================================================================

function Get-SISourceRefusedPermission {
    <# PURE. Does an error text say the read was refused for want of a permission? #>
    param([AllowNull()][string]$Message)
    return ([string]$Message -match '(?i)\b40[13]\b|forbidden|unauthori[sz]ed|access ?denied|insufficient privileges|authorization_requestdenied|AuthorizationFailed|not authorized')
}

function ConvertFrom-SIGraphMetadataXml {
    <#
        PURE (reads text, asks nothing). Microsoft Graph's published model -> entity type name -> its property names
        with their types, including the properties of the types it is built on. Read forward only (the document is
        large): only the entity types are kept.
        -Text: the document as text. The XML reader is opened and read HERE, never handed in: an open reader is read
        where it was opened (the rule the data readers follow), so the caller hands over the text.
    #>
    param([string]$Text, [string[]]$Types = @())
    if (-not $Text) { return @{} }
    $Reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($Text)))
    $all = @{}   # name -> @{ Base; Props = ordered name -> type }
    try {
        $cur = $null
        while ($Reader.Read()) {
            if ($Reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $ln = $Reader.LocalName
                if ($ln -eq 'EntityType' -or $ln -eq 'ComplexType') {
                    $cur = $null
                    if ($ln -eq 'EntityType') {
                        $n = [string]$Reader.GetAttribute('Name')
                        if ($n) {
                            $b = [string]$Reader.GetAttribute('BaseType')
                            if ($b.Contains('.')) { $b = $b.Substring($b.LastIndexOf('.') + 1) }
                            $cur = @{ Base = $b; Props = [ordered]@{} }
                            $all[$n] = $cur
                        }
                    }
                } elseif ($ln -eq 'Property' -and $null -ne $cur) {
                    $pn = [string]$Reader.GetAttribute('Name')
                    if ($pn) { $cur.Props[$pn] = [string]$Reader.GetAttribute('Type') }
                }
            } elseif ($Reader.NodeType -eq [System.Xml.XmlNodeType]::EndElement -and $Reader.LocalName -eq 'EntityType') { $cur = $null }
        }
    } finally { $Reader.Dispose() }
    $out = @{}
    $want = @($Types); if ($want.Count -eq 0) { $want = @($all.Keys) }
    foreach ($t in $want) {
        if (-not $all.ContainsKey($t)) { continue }
        $props = [ordered]@{}
        $chain = New-Object System.Collections.Generic.List[string]
        $x = $t
        for ($i = 0; $i -lt 8 -and $x -and $all.ContainsKey($x); $i++) { $chain.Add($x); $x = [string]$all[$x].Base }
        for ($i = $chain.Count - 1; $i -ge 0; $i--) { foreach ($pn in @($all[$chain[$i]].Props.Keys)) { $props[$pn] = [string]$all[$chain[$i]].Props[$pn] } }
        $out[$t] = $props
    }
    $out
}

function ConvertTo-SIGraphValueType {
    <# PURE. An Edm / Graph type name as the page's value type. #>
    param([AllowNull()][string]$Type)
    $t = [string]$Type
    if ($t.StartsWith('Collection(')) { return 'list' }
    if ($t -eq 'Edm.Boolean') { return 'yes/no' }
    if ($t -in 'Edm.DateTimeOffset', 'Edm.Date') { return 'date' }
    if ($t -in 'Edm.Int32', 'Edm.Int64', 'Edm.Int16', 'Edm.Double', 'Edm.Decimal', 'Edm.Single', 'Edm.Byte') { return 'number' }
    if ($t.StartsWith('Edm.')) { return 'text' }
    if ($t) { return 'object' }
    ''
}

function Add-SIGraphMetadataDiscovery {
    <#
        The Microsoft Graph provider: the properties Graph publishes for the object types SecurityInsight reads, as
        "offered" (a property the run's records also carry stays "read"). One anonymous request.
        -Fetch (tests): { param($Url) } -> the document as text.
    #>
    param([Parameter(Mandatory)]$State, [scriptblock]$Fetch)
    $prov = $script:SISourceDiscoveryProviders | Where-Object { $_.Id -eq 'graph-metadata' } | Select-Object -First 1
    $routes = $prov.Routes
    $map = $null; $err = ''
    try {
        if ($Fetch) { $map = ConvertFrom-SIGraphMetadataXml -Text ([string](& $Fetch ([string]$prov.Url))) -Types @($routes.Keys) }
        else {
            try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
            $client = New-Object System.Net.Http.HttpClient
            $client.Timeout = [TimeSpan]::FromSeconds(180)
            $resp = $null
            try {
                $resp = $client.GetAsync([string]$prov.Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                if (-not $resp.IsSuccessStatusCode) { throw ('Microsoft Graph answered {0}' -f [int]$resp.StatusCode) }
                # The answer is read to text here, where it was opened; the function gets the text, not an open reader.
                $xml = [string]$resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if (-not $xml) { throw 'Microsoft Graph answered an empty document' }
                $map = ConvertFrom-SIGraphMetadataXml -Text $xml -Types @($routes.Keys)
                $xml = $null
            } finally {
                if ($resp) { $resp.Dispose() }
                $client.Dispose()
            }
        }
    } catch { $err = [string]$_.Exception.Message }
    $n = 0
    foreach ($type in @($routes.Keys)) {
        $r = $routes[$type]
        if ($err -or $null -eq $map -or -not $map.ContainsKey($type)) {
            $why = $err; if (-not $why) { $why = ('Microsoft Graph does not list the type {0}' -f $type) }
            Add-SISourceDiscoveryType -State $State -Source $r.Source -RecordType $r.RecordType -Part $r.Part -Origin 'schema' -ErrorText $why
            continue
        }
        Add-SISourceDiscoveryType -State $State -Source $r.Source -RecordType $r.RecordType -Part $r.Part -Origin 'schema'
        foreach ($pn in @($map[$type].Keys)) {
            Add-SISourceDiscoveryProperty -State $State -Source $r.Source -RecordType $r.RecordType -Part $r.Part -Property $pn -Value $null -Records 0 -Collected $false `
                -Origin 'schema' -ValueType (ConvertTo-SIGraphValueType ([string]$map[$type][$pn]))
            $n++
        }
    }
    [pscustomobject]@{ Provider = 'graph-metadata'; Properties = $n; Error = $err }
}

function Add-SIHuntingSchemaDiscovery {
    <# The Defender advanced hunting provider: the tables' columns from the sweep's own catalog (TableColumns: table -> @{ Name; Type }). No request of its own. #>
    param([Parameter(Mandatory)]$State, [AllowNull()]$TableColumns, [string]$ErrorText = '')
    $prov = $script:SISourceDiscoveryProviders | Where-Object { $_.Id -eq 'defender-hunting' } | Select-Object -First 1
    $n = 0
    if ($null -eq $TableColumns -or @($TableColumns.Keys).Count -eq 0) {
        $why = $ErrorText; if (-not $why) { $why = 'no table answered' }
        $perm = ''; if (Get-SISourceRefusedPermission $why) { $perm = [string]$prov.Permission }
        Add-SISourceDiscoveryType -State $State -Source 'mde' -RecordType 'device' -Part 'deviceInfo' -Origin 'schema' -ErrorText $why -NeedsPermission $perm
        return [pscustomobject]@{ Provider = 'defender-hunting'; Properties = 0; Error = $why }
    }
    foreach ($table in @($TableColumns.Keys)) {
        $r = @{ Source = 'mde'; RecordType = ([string]$table).ToLowerInvariant(); Part = 'table' }
        if ($prov.Routes.ContainsKey([string]$table)) { $r = $prov.Routes[[string]$table] }
        Add-SISourceDiscoveryType -State $State -Source $r.Source -RecordType $r.RecordType -Part $r.Part -Origin 'schema'
        foreach ($c in @($TableColumns[$table])) {
            $cn = [string]$c.Name; if (-not $cn) { continue }
            $vt = switch -Regex ([string]$c.Type) { 'bool' { 'yes/no'; break } 'datetime' { 'date'; break } 'int|long|real|decimal|double' { 'number'; break } 'dynamic' { 'object'; break } default { 'text' } }
            Add-SISourceDiscoveryProperty -State $State -Source $r.Source -RecordType $r.RecordType -Part $r.Part -Property $cn -Value $null -Records 0 -Collected $false -Origin 'schema' -ValueType $vt
            $n++
        }
    }
    [pscustomobject]@{ Provider = 'defender-hunting'; Properties = $n; Error = '' }
}

function Add-SIExposureGraphDiscovery {
    <#
        The Exposure Graph provider: the node types SecurityInsight does NOT record yet, with their properties, from the
        sweep's own catalog (NodeProperties: label -> paths). The recorded node types are covered by the records of every
        run. No request of its own.
    #>
    param([Parameter(Mandatory)]$State, [AllowNull()]$NodeProperties)
    $n = 0
    if ($null -eq $NodeProperties) { return [pscustomobject]@{ Provider = 'exposure-graph'; Properties = 0; Error = '' } }
    foreach ($label in @($NodeProperties.Keys)) {
        $l = ([string]$label).Trim().ToLowerInvariant()
        if (-not $l) { continue }
        if ((Get-Command -Name Get-SIEgRecordType -ErrorAction SilentlyContinue) -and (Get-SIEgRecordType $l)) { continue }
        if ($l.Length -gt 64) { $l = $l.Substring(0, 64) }
        Add-SISourceDiscoveryType -State $State -Source 'eg' -RecordType $l -Part 'node' -Origin 'schema'
        foreach ($path in @($NodeProperties[$label])) {
            $p = [string]$path
            if (-not $p) { continue }
            # as deep as the records are walked: NodeProperties.rawData.<key>[.<child>]
            $tail = $p; if ($tail.StartsWith('rawData.')) { $tail = $tail.Substring(8) }
            if ($tail.Contains('[*].') -or @($tail.Replace('[*]', '').Split('.')).Count -gt 2) { continue }
            $full = 'NodeProperties.' + $p.Replace('[*]', '')
            Add-SISourceDiscoveryProperty -State $State -Source 'eg' -RecordType $l -Part 'node' -Property $full -Value $null -Records 0 -Collected $false -Origin 'schema'
            $n++
        }
    }
    [pscustomobject]@{ Provider = 'exposure-graph'; Properties = $n; Error = '' }
}

function Get-SISourceArgSampleKql {
    <# PURE. A sample of one Defender for Cloud object type, whole (name, type, properties) -- the newest first so a new property shows early. #>
    param([Parameter(Mandatory)][string]$Type, [int]$Sample = 200)
    $t = $Type.ToLowerInvariant().Replace("'", '')
    @"
securityresources
| where type =~ '$t'
| project id, name, type, properties
| take $Sample
"@
}

function Add-SIArgSampleDiscovery {
    <#
        The Defender for Cloud provider: the properties of assessments and sub-assessments, from a sample of each (one
        Resource Graph query each). The findings themselves arrive through Risk Analysis; this is what the source offers.
        -Query (tests): { param($Kql) } -> rows.
    #>
    param([Parameter(Mandatory)]$State, [string[]]$SubscriptionIds = @(), [scriptblock]$Query)
    $prov = $script:SISourceDiscoveryProviders | Where-Object { $_.Id -eq 'defender-for-cloud' } | Select-Object -First 1
    $n = 0; $errs = New-Object System.Collections.Generic.List[string]
    foreach ($q in @($prov.Queries)) {
        $rows = @(); $err = ''
        try {
            $kql = Get-SISourceArgSampleKql -Type ([string]$q.Type)
            if ($Query) { $rows = @(& $Query $kql) }
            else {
                if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
                $a = @{ Query = $kql; First = 200 }
                if (@($SubscriptionIds).Count -gt 0) { $a['Subscription'] = $SubscriptionIds }
                $page = Search-SIAzGraph @a -ErrorAction Stop
                $rows = @(if ($null -ne $page -and $page.PSObject.Properties['Data']) { $page.Data } else { $page })
            }
        } catch { $err = [string]$_.Exception.Message }
        if ($err) {
            $perm = ''; if (Get-SISourceRefusedPermission $err) { $perm = [string]$prov.Permission }
            Add-SISourceDiscoveryType -State $State -Source 'mdc' -RecordType ([string]$q.RecordType) -Part ([string]$q.Part) -Origin 'schema' -ErrorText $err -NeedsPermission $perm
            $errs.Add($err); continue
        }
        Add-SISourceDiscoveryType -State $State -Source 'mdc' -RecordType ([string]$q.RecordType) -Part ([string]$q.Part) -Origin 'schema'
        $before = $State.Props.Count
        foreach ($r in $rows) {
            if ($null -eq $r) { continue }
            $o = $r
            # Resource Graph may hand 'properties' back as JSON text
            if ($r.PSObject.Properties['properties'] -and $r.properties -is [string] -and $r.properties.TrimStart().StartsWith('{')) {
                try { $o = [pscustomobject]@{ id = $r.id; name = $r.name; type = $r.type; properties = ($r.properties | ConvertFrom-Json) } } catch { $o = $r }
            }
            Add-SISourceDiscoveryObject -State $State -Source 'mdc' -RecordType ([string]$q.RecordType) -Part ([string]$q.Part) -Object $o -Origin 'schema' -Collected $false
        }
        $n += ($State.Props.Count - $before)
    }
    [pscustomobject]@{ Provider = 'defender-for-cloud'; Properties = $n; Error = ($errs -join '; ') }
}

function Add-SISnowDictionaryDiscovery {
    <#
        The ServiceNow provider: the columns ServiceNow's dictionary lists for the tables SecurityInsight reads (one
        request per table; read only). -Read { param($Table) } -> @{ Rows (element, column_label, internal_type); Complete;
        Error } -- the caller binds it to its ServiceNow connection.
    #>
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][scriptblock]$Read, [string[]]$Tables)
    $prov = $script:SISourceDiscoveryProviders | Where-Object { $_.Id -eq 'servicenow-dictionary' } | Select-Object -First 1
    if (-not $Tables -or @($Tables).Count -eq 0) { $Tables = @($prov.Tables) }
    $n = 0; $errs = New-Object System.Collections.Generic.List[string]
    foreach ($table in $Tables) {
        $t = ([string]$table).Trim().ToLowerInvariant()
        if ($t -notmatch '^[a-z0-9_]{1,64}$') { continue }
        $ans = $null; $err = ''
        try { $ans = & $Read $t } catch { $err = [string]$_.Exception.Message }
        if (-not $err -and $null -ne $ans -and $ans.PSObject.Properties['Complete'] -and -not [bool]$ans.Complete) { $err = [string]$ans.Error; if (-not $err) { $err = 'the read did not complete' } }
        if ($err) {
            $perm = ''; if (Get-SISourceRefusedPermission $err) { $perm = 'read access to sys_dictionary for the integration user' }
            Add-SISourceDiscoveryType -State $State -Source 'servicenow' -RecordType $t -Part 'row' -Origin 'schema' -ErrorText $err -NeedsPermission $perm
            $errs.Add($err); continue
        }
        Add-SISourceDiscoveryType -State $State -Source 'servicenow' -RecordType $t -Part 'row' -Origin 'schema'
        foreach ($r in @($ans.Rows)) {
            if ($null -eq $r) { continue }
            $el = ''; if ($r.PSObject.Properties['element']) { $el = ([string]$r.element).Trim() }
            if (-not $el) { continue }
            $vt = ''; if ($r.PSObject.Properties['internal_type']) { $it = $r.internal_type; if ($it -and $it.PSObject.Properties['value']) { $it = $it.value }; $vt = ([string]$it).Trim() }
            if ($vt.Length -gt 16) { $vt = $vt.Substring(0, 16) }
            $label = ''; if ($r.PSObject.Properties['column_label']) { $label = ([string]$r.column_label).Trim() }
            # the column's label is its "sample": what a person in ServiceNow calls it
            Add-SISourceDiscoveryProperty -State $State -Source 'servicenow' -RecordType $t -Part 'row' -Property $el -Value $label -Records 0 -Collected $false -Origin 'schema' -ValueType $vt
            $n++
        }
    }
    [pscustomobject]@{ Provider = 'servicenow-dictionary'; Properties = $n; Error = ($errs -join '; ') }
}

function Test-SISourceDiscoveryDue {
    <# Is a schema provider's weekly read due? $true when its state is older than -Days, absent, or cannot be read (asking again is harmless). #>
    param([AllowNull()][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Source, [int]$Days = 6, [datetime]$Now = [datetime]::UtcNow)
    if (-not $Invoke) { return $false }
    try {
        $sql = "IF OBJECT_ID(N'sidata.SourceDiscoveryState') IS NULL SELECT CAST(NULL AS DATETIME2(0)) AS LastRunAt ELSE SELECT MAX(LastRunAt) AS LastRunAt FROM sidata.SourceDiscoveryState WHERE Source = @source AND Origin = N'schema';"
        $ans = @(& $Invoke $sql @{ source = $Source.ToLowerInvariant() } 'rows')
        if ($ans.Count -eq 0 -or $null -eq $ans[0].LastRunAt -or $ans[0].LastRunAt -is [System.DBNull]) { return $true }
        return (([datetime]$ans[0].LastRunAt).AddDays($Days) -le $Now.ToUniversalTime())
    } catch { return $true }
}

function Invoke-SISnowDictionaryDiscoveryIfDue {
    <#
        The CMDB import's call: at most once in six days, ask ServiceNow's dictionary for the tables SecurityInsight reads
        and save what it lists. Never throws, never fails the import.
    #>
    param([Parameter(Mandatory)]$Connection, [AllowNull()][scriptblock]$Invoke, [datetime]$Now = [datetime]::UtcNow, [scriptblock]$Read)
    try {
        if (-not (Test-SISourceDiscoveryOn)) { return $null }
        if (-not $Invoke -and (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { $Invoke = New-SIRecordSqlInvoke }
        if (-not (Test-SISourceDiscoveryDue -Invoke $Invoke -Source 'servicenow' -Now $Now)) { return $null }
        if (-not $Read) {
            $conn = $Connection
            $Read = {
                param($Table)
                Get-SISnowRecord -Connection $conn -Table 'sys_dictionary' -Query ('name={0}^elementISNOTEMPTY' -f $Table) -Fields @('element', 'column_label', 'internal_type') -MaxRows 5000
            }
        }
        $st = New-SISourceDiscoveryState
        $r = Add-SISnowDictionaryDiscovery -State $st -Read $Read
        $w = Write-SISourceDiscovery -State $st -Model $null -Invoke $Invoke -RunId ('schema-servicenow-' + $Now.ToUniversalTime().ToString('yyyyMMddHHmmss')) -Now $Now
        Write-Host ('[INFO] ' + (Get-SISourceDiscoverySummaryText -Result $w -What 'ServiceNow''s dictionary'))
        if ($r.Error) { Write-Host ('[INFO] ServiceNow''s dictionary could not be read for every table: ' + $r.Error) }
        return $w
    } catch { Write-Verbose ('continuous discovery (ServiceNow): ' + $_.Exception.Message); return $null }
}

function Invoke-SISourceDiscoverySweep {
    <#
        The weekly sweep (the schema-discovery job, after its own catalog is built): every schema provider, then ONE
        write. -Catalog: the job's catalog (TableColumns, NodeProperties). Returns the write's result with the providers'
        own lines; never throws.
    #>
    param([AllowNull()]$Catalog, [AllowNull()][scriptblock]$Invoke, [string]$RunId = '', [datetime]$Now = [datetime]::UtcNow,
          [string[]]$SubscriptionIds = @(), [scriptblock]$GraphFetch, [scriptblock]$ArgQuery, [string]$HuntingError = '')
    $done = New-Object System.Collections.Generic.List[object]
    $w = $null
    try {
        if (-not (Test-SISourceDiscoveryOn)) { return $null }
        $st = New-SISourceDiscoveryState
        $tc = $null; $np = $null
        if ($null -ne $Catalog) {
            if ($Catalog -is [System.Collections.IDictionary]) { $tc = $Catalog['TableColumns']; $np = $Catalog['NodeProperties'] }
            else { $tc = $Catalog.TableColumns; $np = $Catalog.NodeProperties }
        }
        try { $done.Add((Add-SIHuntingSchemaDiscovery -State $st -TableColumns $tc -ErrorText $HuntingError)) } catch { Write-Verbose $_.Exception.Message }
        try { $done.Add((Add-SIExposureGraphDiscovery -State $st -NodeProperties $np)) } catch { Write-Verbose $_.Exception.Message }
        try { $a = @{ State = $st }; if ($GraphFetch) { $a['Fetch'] = $GraphFetch }; $done.Add((Add-SIGraphMetadataDiscovery @a)) } catch { Write-Verbose $_.Exception.Message }
        try { $a = @{ State = $st; SubscriptionIds = $SubscriptionIds }; if ($ArgQuery) { $a['Query'] = $ArgQuery }; $done.Add((Add-SIArgSampleDiscovery @a)) } catch { Write-Verbose $_.Exception.Message }
        $model = $null
        try {
            if (-not (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
            $model = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
        } catch { $model = $null }
        if (-not $RunId) { $RunId = 'schema-' + $Now.ToUniversalTime().ToString('yyyyMMddHHmmss') }
        $w = Write-SISourceDiscovery -State $st -Model $model -Invoke $Invoke -RunId $RunId -Now $Now
    } catch { Write-Verbose ('continuous discovery (sweep): ' + $_.Exception.Message) }
    [pscustomobject]@{ Result = $w; Providers = $done.ToArray() }
}
