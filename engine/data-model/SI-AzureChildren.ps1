#Requires -Version 5.1
<#
    AZURE CHILD RESOURCES ROLL UP INTO THEIR PARENT, AND ONLY THE LISTED TYPES BECOME CIs (owner 2026-10-11: "extensions
    suddenly show as risk from azure ... we had defined some classes that we excluded. chk v2.2 code").

    The list is data-model/collection-scope azureResourceTypes (customer-extendable like every data-model list:
    collection-scope.custom.json, or the Pro data-model settings 'collection-scope:<type>'):
      * a listed type WITHOUT rollUpInto is a CI type: its resources are recorded and become CIs
      * a listed type WITH rollUpInto is a CHILD (v2.2 asset-profiling-schema SCHEMA subResourceRollupRules): never a record
        of its own -- it becomes a PART of its parent's record ('child|<child id>'), listed on the parent CI in
        rollUpInto.field (si_vm_extensions, si_disks, ...) and si_child_resources, and its id is a linked object of the parent
        CI (sidata.CiLink, SI_CI_CL si_linked_objects) -- so a finding on the child's id lands on the parent CI
          rollUpInto.parentBy     'path' (the ARM id one level up) or dot paths into the ARM object (managedBy,
                                  properties.virtualMachine.id, properties.ipConfiguration.id), tried in order; the id
                                  found is walked up until its type is one of parentTypes
          rollUpInto.keepOwnCi    the type stays a CI of its own and is ALSO listed on its parent (a public IP)
          rollUpInto.shape        what the parent lists of each child: { <name>: <dot path into the ARM object> }
      * a nested type that is NOT listed (microsoft.web/sites/slots) is a child of its path parent when that parent is
        listed; any other type is NOT recorded
    A CI that a type no longer recorded had (a VM extension, a data collection rule) is never deleted: its records age, it is
    not seen, and the CI build retires it once nothing has recorded it within the lookback.

    PURE except the cached scope loader (Get-SIAzureCiScope). PowerShell 5.1 safe: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIItemValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

$script:SIAzureTypePattern = '(microsoft\.[a-z0-9]+/[a-z0-9/]+)'

function ConvertTo-SIArmTypeName {
    <# PURE. A resource type or an Exposure Graph node label ('microsoft.web/sites_webapp') -> the lower-case ARM type; ''. #>
    param([AllowNull()][AllowEmptyString()][string]$Type)
    if ([string]::IsNullOrWhiteSpace($Type)) { return '' }
    $m = [regex]::Match($Type.Trim().ToLowerInvariant(), $script:SIAzureTypePattern)
    if ($m.Success) { return $m.Groups[1].Value.TrimEnd('/') }
    return ''
}

function Get-SIArmIdInfo {
    <#
        PURE. An ARM resource id -> @{ Id; Type; Name; Parent } (lower case), or $null when it is not a resource id.
        Type is read after the LAST '/providers/' (an extension resource is typed by its own provider); Parent is the id one
        level up in the same provider ('' for a top-level resource).
          .../providers/Microsoft.Compute/virtualMachines/vm1/extensions/MDE.Windows
            -> Type microsoft.compute/virtualmachines/extensions, Name mde.windows, Parent .../virtualmachines/vm1
    #>
    param([AllowNull()][AllowEmptyString()][string]$Id)
    $s = ([string]$Id).Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $s.StartsWith('/subscriptions/')) { return $null }
    $i = $s.LastIndexOf('/providers/')
    if ($i -lt 0) { return $null }
    $head = $s.Substring(0, $i)
    $segs = $s.Substring($i + 11).Split('/')
    if ($segs.Count -lt 3 -or (($segs.Count - 1) % 2) -ne 0) { return $null }
    foreach ($x in $segs) { if (-not $x) { return $null } }
    $types = New-Object System.Collections.Generic.List[string]
    for ($k = 1; $k -lt $segs.Count; $k += 2) { $types.Add($segs[$k]) }
    $parent = ''
    if ($segs.Count -gt 3) { $parent = $head + '/providers/' + ($segs[0..($segs.Count - 3)] -join '/') }
    return @{ Id = $s; Type = ($segs[0] + '/' + ($types.ToArray() -join '/')); Name = $segs[$segs.Count - 1]; Parent = $parent }
}

function Get-SIAzureObjectValues {
    <# PURE. Every value at a dot path in an object ('a.b[*].c' walks the array b; JSON text met on the way is parsed). #>
    param($Object, [string]$Path)
    $cur = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Object -or -not $Path) { return , $cur }
    $cur.Add($Object)
    foreach ($segRaw in $Path.Split('.')) {
        $walk = $segRaw.EndsWith('[*]'); $seg = $segRaw; if ($walk) { $seg = $segRaw.Substring(0, $segRaw.Length - 3) }
        $next = New-Object System.Collections.Generic.List[object]
        foreach ($o in $cur) {
            $node = $o
            if ($node -is [string]) { $t = $node.Trim(); if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { $node = $t | ConvertFrom-Json } catch { continue } } else { continue } }
            $v = $null
            if ($node -is [System.Collections.IDictionary]) { foreach ($k in $node.Keys) { if ([string]::Equals([string]$k, $seg, [StringComparison]::OrdinalIgnoreCase)) { $v = $node[$k]; break } } }
            elseif ($null -ne $node) { $pp = $node.PSObject.Properties[$seg]; if ($pp) { $v = $pp.Value } }
            if ($null -eq $v) { continue }
            if ($v -is [string] -and $walk) { $t = $v.Trim(); if ($t.StartsWith('[')) { try { $v = $t | ConvertFrom-Json } catch { } } }
            if ($walk -and $v -is [System.Collections.IEnumerable] -and -not ($v -is [string]) -and -not ($v -is [System.Collections.IDictionary])) { foreach ($x in $v) { if ($null -ne $x) { $next.Add($x) } } }
            else { $next.Add($v) }
        }
        $cur = $next
    }
    return , $cur
}

function ConvertTo-SIAzureCiScope {
    <#
        PURE. The collection-scope document -> @{ Top (the CI types); Rules (child type -> @{ Type; ParentTypes; ParentBy;
        Field; Shape; KeepOwnCi }) }. A keepOwnCi type is in Top AND has a rule.
    #>
    param($Document)
    $top = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $rules = @{}
    foreach ($it in @(Get-SIItemValue $Document 'azureResourceTypes')) {
        if ($null -eq $it) { continue }
        $t = ConvertTo-SIArmTypeName ([string](Get-SIItemValue $it 'type'))
        if (-not $t) { continue }
        $r = Get-SIItemValue $it 'rollUpInto'
        if ($null -eq $r) { [void]$top.Add($t); continue }
        $keep = (ConvertTo-SIBoolOrNull (Get-SIItemValue $r 'keepOwnCi')) -eq $true
        $by = @(@(Get-SIItemValue $r 'parentBy') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if ($by.Count -eq 0) { $by = @('path') }
        $shape = [ordered]@{}
        $sh = Get-SIItemValue $r 'shape'
        if ($null -ne $sh) {
            if ($sh -is [System.Collections.IDictionary]) { foreach ($k in $sh.Keys) { $shape[[string]$k] = [string]$sh[$k] } }
            else { foreach ($pp in $sh.PSObject.Properties) { if (-not $pp.Name.StartsWith('$')) { $shape[$pp.Name] = [string]$pp.Value } } }
        }
        $rules[$t] = @{
            Type = $t; KeepOwnCi = $keep; ParentBy = $by; Field = [string](Get-SIItemValue $r 'field'); Shape = $shape
            ParentTypes = @(@(Get-SIItemValue $r 'parentTypes') | ForEach-Object { ConvertTo-SIArmTypeName ([string]$_) } | Where-Object { $_ })
        }
        if ($keep) { [void]$top.Add($t) }
    }
    return @{ Top = $top; Rules = $rules }
}

function Test-SIAzureCiScopeItems {
    <# PURE. The problems of a collection-scope document's rollUpInto items (Test-SIDataModel): '<type>: <problem>'. #>
    param($Document, [hashtable]$Fields = @{})
    foreach ($it in @(Get-SIItemValue $Document 'azureResourceTypes')) {
        if ($null -eq $it) { continue }
        $t = [string](Get-SIItemValue $it 'type')
        if (-not (ConvertTo-SIArmTypeName $t)) { "'$t' is not an Azure resource type (microsoft.<namespace>/<type>)"; continue }
        $r = Get-SIItemValue $it 'rollUpInto'
        if ($null -eq $r) { continue }
        $pt = @(@(Get-SIItemValue $r 'parentTypes') | Where-Object { $_ })
        if ($pt.Count -eq 0) { "'$t' rollUpInto names no parentTypes" }
        foreach ($b in @(Get-SIItemValue $r 'parentBy')) { if ($b -and [string]$b -ne 'path' -and [string]$b -notmatch '^[A-Za-z][A-Za-z0-9_]*(\[\*\])?(\.[A-Za-z][A-Za-z0-9_]*(\[\*\])?)*$') { "'$t' rollUpInto parentBy '$b' is neither 'path' nor a dot path" } }
        $f = [string](Get-SIItemValue $r 'field')
        if ($f -and $Fields.Count -gt 0 -and -not $Fields.ContainsKey($f)) { "'$t' rollUpInto field '$f' is not in the field catalog" }
    }
}

function Set-SIAzureCiScope {
    <# The scope this process uses (tests; a caller that already holds the model). $null = load it again on the next use. #>
    param($Scope)
    $script:SIAzureCiScope = $Scope
    $script:SIAzureCiScopeLoaded = ($null -ne $Scope)
}

function Get-SIAzureCiScope {
    <#
        The Azure CI scope of this install, read ONCE per process: the merged collection-scope template (shipped + the
        customer's overrides). Cannot be read: said once, and every Azure type is recorded as before ($null) -- never fewer
        records because a file could not be read.
    #>
    if ($script:SIAzureCiScopeLoaded) { return $script:SIAzureCiScope }
    $script:SIAzureCiScopeLoaded = $true
    $script:SIAzureCiScope = $null
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $t = Get-SIDataModelTemplate -Name 'collection-scope' -OverlayRoot $global:SI_DataModelOverlayRoot
        $script:SIAzureCiScope = ConvertTo-SIAzureCiScope -Document $t.Document
    } catch {
        Write-Warning ('Azure resources: the list of Azure resource types that become CIs could not be read ({0}) -- every Azure resource is recorded this run.' -f $_.Exception.Message)
    }
    return $script:SIAzureCiScope
}

function Resolve-SIAzureParentAncestor {
    <# PURE. An ARM id walked up its path until its type is one of -ParentTypes -> that id (lower), else ''. #>
    param([AllowNull()][AllowEmptyString()][string]$Id, [string[]]$ParentTypes = @())
    $info = Get-SIArmIdInfo $Id
    for ($i = 0; $i -lt 8 -and $null -ne $info; $i++) {
        if ($ParentTypes.Count -eq 0 -or $ParentTypes -contains $info.Type) { return $info.Id }
        if (-not $info.Parent) { break }
        $info = Get-SIArmIdInfo $info.Parent
    }
    return ''
}

function Get-SIAzureChildParentId {
    <# PURE. The parent of a child resource by its rule (parentBy in order), else the capture's known parent of it, else ''. #>
    # -KnownParents: a hashtable or the producer's on-disk child map (SecurityInsight.DiskTextLookup, #727) -- both answer
    # ContainsKey and [key]
    param($Info, $Object, [Parameter(Mandatory)]$Rule, $KnownParents)
    foreach ($by in @($Rule.ParentBy)) {
        $cand = ''
        if ([string]$by -eq 'path') { if ($Info) { $cand = [string]$Info.Parent } }
        else { foreach ($v in (Get-SIAzureObjectValues -Object $Object -Path ([string]$by))) { if ($v -is [string] -and $v.Trim()) { $cand = $v.Trim(); break } } }
        if (-not $cand) { continue }
        $p = Resolve-SIAzureParentAncestor -Id $cand -ParentTypes @($Rule.ParentTypes)
        if ($p) { return $p }
    }
    if ($KnownParents -and $Info -and $KnownParents.ContainsKey([string]$Info.Id)) { return [string]$KnownParents[[string]$Info.Id] }
    return ''
}

function Resolve-SIAzurePlacement {
    <#
    .SYNOPSIS  PURE. Where an Azure object goes in the data model.
    .OUTPUTS   @{ Action = record | child | drop; Id; Type; ParentId (child); Rule (child / keepOwnCi); AlsoChildOf (a keepOwnCi
               type: the parent it is also listed on, '' when none); Reason (drop) }
               No scope ($null): every object is a record, as before.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Id, [AllowNull()][AllowEmptyString()][string]$Type = '', $Object, $Scope, $KnownParents)
    $info = Get-SIArmIdInfo $Id
    $t = ConvertTo-SIArmTypeName $Type
    if (-not $t -and $info) { $t = $info.Type }
    $res = @{ Action = 'record'; Id = ([string]$Id).Trim().ToLowerInvariant(); Type = $t; ParentId = ''; Rule = $null; AlsoChildOf = ''; Reason = '' }
    if ($null -eq $Scope -or -not $t) { return $res }
    $rule = $Scope.Rules[$t]
    if ($null -ne $rule) {
        $p = Get-SIAzureChildParentId -Info $info -Object $Object -Rule $rule -KnownParents $KnownParents
        $res.Rule = $rule
        if ($rule.KeepOwnCi) { $res.AlsoChildOf = $p; return $res }
        if (-not $p) { $res.Action = 'drop'; $res.Reason = 'a child resource whose parent is not known'; return $res }
        $res.Action = 'child'; $res.ParentId = $p
        return $res
    }
    if ($Scope.Top.Contains($t)) { return $res }
    if ($info -and $info.Parent) {
        $pi = Get-SIArmIdInfo $info.Parent
        if ($pi -and ($Scope.Top.Contains($pi.Type) -or $Scope.Rules.ContainsKey($pi.Type))) { $res.Action = 'child'; $res.ParentId = $pi.Id; return $res }
    }
    $res.Action = 'drop'; $res.Reason = 'not a CI type (collection-scope azureResourceTypes)'
    return $res
}

function New-SIAzureChildSummary {
    <#
        PURE. What the parent keeps of one child: { id; type; name; field (the parent's list it belongs to, '' = only
        si_child_resources); shape (the rule's shape values read from the ARM object) }.
    #>
    param([Parameter(Mandatory)][string]$Id, [string]$Type = '', $Object, $Rule)
    $info = Get-SIArmIdInfo $Id
    $t = ConvertTo-SIArmTypeName $Type; if (-not $t -and $info) { $t = $info.Type }
    $name = ''
    foreach ($v in (Get-SIAzureObjectValues -Object $Object -Path 'name')) { if ($v -is [string] -and $v.Trim()) { $name = $v.Trim(); break } }
    if (-not $name -and $info) { $name = $info.Name }
    $o = [ordered]@{ id = $Id.Trim().ToLowerInvariant(); type = $t; name = $name }
    $field = ''; if ($null -ne $Rule -and $Rule.Field) { $field = [string]$Rule.Field }
    $o['field'] = $field
    $shape = [ordered]@{}
    if ($null -ne $Rule -and $null -ne $Rule.Shape) {
        foreach ($k in @($Rule.Shape.Keys)) {
            $path = [string]$Rule.Shape[$k]
            if ($k -eq 'name') { $shape['name'] = $name; continue }
            # assigned first: the call hands back ONE list (', $list'), which a pipeline would pass on as one item
            $raw = Get-SIAzureObjectValues -Object $Object -Path $path
            $vals = @($raw | Where-Object { $null -ne $_ -and -not ($_ -is [string] -and -not $_.Trim()) })
            if ($vals.Count -eq 1) { $shape[$k] = $vals[0] } elseif ($vals.Count -gt 1) { $shape[$k] = $vals }
        }
    }
    if ($shape.Count -eq 0) { $shape['name'] = $name }
    $o['shape'] = [pscustomobject]$shape
    return [pscustomobject]$o
}

function Get-SIAzureEgArmId {
    <# PURE. The Azure resource id an Exposure Graph node names (EntityIds: { type AzureResourceId; id }), lower case; ''. #>
    param($Node)
    $e = Get-SIItemValue $Node 'EntityIds'
    if ($e -is [string]) { $s = $e.Trim(); if ($s.StartsWith('[') -or $s.StartsWith('{')) { try { $e = $s | ConvertFrom-Json } catch { $e = $null } } }
    foreach ($x in @($e)) {
        if ($null -eq $x) { continue }
        if ([string](Get-SIItemValue $x 'type') -eq 'AzureResourceId') { $id = ([string](Get-SIItemValue $x 'id')).Trim(); if ($id) { return $id.ToLowerInvariant() } }
    }
    return ''
}

function Get-SIAzurePipVia {
    <# PURE. What a public IP address's ARM object says it is attached through: properties.ipConfiguration.id, else a NAT
       gateway (properties.natGateway.id) -- lower case; '' when it is not attached. Properties kept as JSON text are parsed. #>
    param($Resource)
    if ($null -eq $Resource) { return '' }
    $props = Get-SIItemValue $Resource 'properties'
    if ($props -is [string]) { try { $props = $props | ConvertFrom-Json } catch { $props = $null } }
    $via = ([string](Get-SIItemValue (Get-SIItemValue $props 'ipConfiguration') 'id')).Trim().ToLowerInvariant()
    if (-not $via) { $via = ([string](Get-SIItemValue (Get-SIItemValue $props 'natGateway') 'id')).Trim().ToLowerInvariant() }
    return $via
}

# ---------------------------------------------------------------------------------------------------------------------
#  The capture state: the children as parts of their parent's record
# ---------------------------------------------------------------------------------------------------------------------
$script:SIRecordOwnlessParts = @('parentTags', 'egQueryRules', 'si_scope', 'diag')

function Test-SIRecordChildOnly {
    <# PURE. A captured record that holds child parts and no provider object of its own (its parent was not captured here). #>
    param($Record)
    if ($null -eq $Record -or $null -eq $Record.Parts) { return $false }
    $child = $false
    foreach ($k in @($Record.Parts.Keys)) {
        $s = [string]$k
        if ($s.StartsWith('child|')) { $child = $true; continue }
        if ($script:SIRecordOwnlessParts -contains $s) { continue }
        return $false
    }
    return $child
}

function Get-SIRecordChildState {
    <# The capture state's child bookkeeping (created on first use): ChildOf (child id -> parent id), Dropped (reason -> count). #>
    param($State)
    if ($null -eq $State) { return $null }
    if (-not $State.PSObject.Properties['ChildOf']) { $State | Add-Member -NotePropertyName 'ChildOf' -NotePropertyValue (@{}) -Force }
    if (-not $State.PSObject.Properties['Dropped']) { $State | Add-Member -NotePropertyName 'Dropped' -NotePropertyValue (@{}) -Force }
    return $State
}

function Resolve-SIRecordChildren {
    <#
        PURE over the capture state. A record made only of child parts whose OWN id is a child of another captured record (a
        public IP's link on a network interface, which is itself the virtual machine's child) hands its child parts to that
        record and is removed. Run before the records are published or handed over. Returns how many records were folded.
    #>
    param($State = $global:SIRecordCaptureState)
    if ($null -eq $State -or $null -eq $State.Records) { return 0 }
    $total = 0
    for ($round = 0; $round -lt 4; $round++) {
        $parentOf = @{}
        foreach ($e in $State.Records.GetEnumerator()) {
            foreach ($k in @($e.Value.Parts.Keys)) { $s = [string]$k; if ($s.StartsWith('child|')) { $parentOf[$s.Substring(6)] = [string]$e.Key } }
        }
        $moved = 0
        foreach ($id in @($State.Records.Keys)) {
            $rec = $State.Records[$id]
            if ([string]$rec.Provider -ne 'azure' -or -not (Test-SIRecordChildOnly $rec)) { continue }
            $target = [string]$parentOf[[string]$rec.Key]
            if (-not $target -or $target -eq $id -or -not $State.Records.ContainsKey($target)) { continue }
            $tr = $State.Records[$target]
            foreach ($k in @($rec.Parts.Keys)) { $s = [string]$k; if ($s.StartsWith('child|') -and -not $tr.Parts.Contains($s)) { $tr.Parts[$s] = $rec.Parts[$k] } }
            foreach ($en in @($rec.Engines)) { if ($en) { [void]$tr.Engines.Add([string]$en) } }
            [void]$State.Records.Remove($id)
            $moved++
        }
        $total += $moved
        if ($moved -eq 0) { break }
    }
    return $total
}

function Get-SIRecordChildParentMap {
    <# The child id -> parent id map of this process's capture (the Defender recommendations roll a disk / NIC up with it). #>
    param($State = $global:SIRecordCaptureState)
    $m = @{}
    if ($null -eq $State -or -not $State.PSObject.Properties['ChildOf'] -or $null -eq $State.ChildOf) { return $m }    foreach ($k in @($State.ChildOf.Keys)) { $m[[string]$k] = [string]$State.ChildOf[$k] }
    return $m
}
