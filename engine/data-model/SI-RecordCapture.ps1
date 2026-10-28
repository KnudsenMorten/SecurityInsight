#Requires -Version 5.1
<#
    SecurityInsight RECORD CAPTURE -- phase 1 of the v3 data model (V3-DATA-MODEL part 2, P1): every provider object
    a profiler reads becomes ONE SI RECORD (normalised SI fields, via data-model/mappings) in the DATABASE
    (sidata.CiRecord + sidata.RecordIdentifier, SI-RecordSql.ps1), where the CI build groups the records into CIs.
    Operator 2026-10-09: "we dont support la for correlation, sql only" / "la is troubleshooting and kusto" -- records are
    NOT posted to Log Analytics. SI_LaExport = records (off by default) adds a ONE-WAY copy to SI_Record_CL (and, when raw
    data is on for a provider, its whole object to SI_RecordRaw_CL) for Azure Monitor or workbooks; nothing reads it back.

    HOW IT GETS THE OBJECTS. The profilers already read each source once; their discovery and collect code hands every
    provider object here as a PART of a record, keyed by the provider's own id:
        Add-SIRecordPart -Provider mde -RecordType device -Key <machine id> -Part machine    -Object <machines API object>
        Add-SIRecordPart -Provider mde -RecordType device -Key <machine id> -Part deviceInfo -Object <DeviceInfo row>
    The parts are what the mapping's source paths start with (machine.lastSeen, deviceInfo.IsInternetFacing). A record
    seen by two profilers in one container session (Exposure Graph nodes) is one record: parts merge by key.

    COMPLETENESS. Set-SIRecordPull says whether a provider's pull was complete. Every record row carries
    si_collection_complete, so correlation and the CI lifecycle read absence only from a complete run (working rule 4:
    absence is not remediation).

    Raw data: SI_RawData = off (default) | on, or a list of providers ('mde,azure'). Raw rows go to their own table,
    because Log Analytics sets retention and price per TABLE (raw is short-lived; records are not).

    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode. Never throws into the profiler: a capture or publish
    problem is said and costs the profile run nothing.
#>

. (Join-Path $PSScriptRoot 'SI-FieldMapper.ps1')
. (Join-Path $PSScriptRoot 'SI-RecordDerived.ps1')   # the 'derived' part: facts the provider objects imply (derived.* paths of the mappings)
# Azure child resources roll up into their parent; only the listed Azure types become CIs (collection-scope azureResourceTypes)
. (Join-Path $PSScriptRoot 'SI-AzureChildren.ps1')
# continuous discovery: the property names of every published record part -- what each source offered this run
. (Join-Path $PSScriptRoot 'SI-SourceDiscovery.ps1')

# #475: records are assembled, converted and posted this many at a time (Publish-SIRecords)
$script:SIRecordBatchSize = 2000

# #721 THE RECORD STREAM. In the DISCOVER phase of a run collected in parts (the producer, every tenant, every size) the
# records are not kept: each captured part is written to a local, compressed stream as it arrives (one JSON line: the
# record's id, provider, type, key, resource type, engine and that one part) and let go. The hand-over
# (Save-SIRecordHandover) reads the stream back line by line into the run's buckets -- the same items the in-memory
# capture would have handed over, in the order they were captured, so the merge (later part wins, engines unioned)
# builds exactly the same records. Large ring-2 tenant 2026-10-16: 1,565,906 Exposure Graph user nodes, most of them
# AD-only accounts kept as AD identity records, were all held in the capture until the hand-over.
#   ids remembered   'entra', 'mdi' -- discovery adds context parts only to the Entra / Defender for Identity records it
#                    captured, so their ids (not the records) are remembered: Test-SIRecordCaptured / Get-SIRecordCapturedKeys
#   'azure' (#727)   streamed like every other provider (owner 2026-10-16: "tenants can have millions of azure obj"). What
#                    the Azure reads still need of a record is kept ON DISK, keyed by the record id (Stream.AzureIndex,
#                    SecurityInsight.DiskTextLookup: record type, resource type, whether it holds its own resource, its
#                    name, what a public IP is attached through), and which records belong together -- a resource and every
#                    child resource listed on it -- as one small number per key (Stream.Groups, SecurityInsight.KeyGroups).
#                    The hand-over routes the Azure lines into local files by GROUP and folds a child into its parent one
#                    group at a time (Save-SIRecordHandoverStream) -- the same records the in-memory fold made.
#                    The capture's child -> parent map (ChildOf) is on disk too.
$script:SIRecordStreamReadBack = @('entra', 'mdi')
# the Azure record index's fields (one text per record id, separated by this character)
$script:SIAzureIndexSep = [char]1

function Start-SIRecordCaptureStream {
    <#
        Turns this run's capture into a stream (the discover phase, Invoke-Discover). Records captured before it starts are
        written to the stream first, in their order. Returns the stream. Throws when the local stream cannot be opened --
        a producer that cannot keep its records must not discover.
    #>
    param([string]$Directory = '')
    if ($null -eq $global:SIRecordCaptureState) { $null = Reset-SIRecordCapture }
    $st = $global:SIRecordCaptureState
    if ($st.PSObject.Properties['Stream'] -and $null -ne $st.Stream) { return $st.Stream }
    if (-not $Directory) { $Directory = [IO.Path]::GetTempPath() }
    if (-not ('System.IO.Compression.GZipStream' -as [type])) { Add-Type -AssemblyName System.IO.Compression }
    $path = [IO.Path]::Combine($Directory, ('si-records-{0}.jsonl.gz' -f [guid]::NewGuid().ToString('N')))
    # #727: the Azure record index, the groups and the child map live on disk / as keys only (the types: SI-DiskLookup.ps1;
    # loaded here only for its types -- a function it defines would not outlive this call)
    if (-not ('SecurityInsight.DiskTextLookup' -as [type])) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-DiskLookup.ps1') }
    $newText = { param([string]$Name) $d = $Directory; if (-not $d) { $d = [IO.Path]::GetTempPath() }
        New-Object SecurityInsight.DiskTextLookup ([IO.Path]::Combine($d, ('si-lookup-{0}-{1}.txt' -f $Name, [guid]::NewGuid().ToString('N')))) }
    $fs = [IO.File]::Create($path)
    $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionLevel]::Fastest)
    $s = [pscustomobject]@{
        Path   = $path
        Writer = New-Object System.IO.StreamWriter($gz, (New-Object System.Text.UTF8Encoding($false)))
        Items  = 0L
        Ids    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        # #727 the Azure records: how many lines, how many of the records hold their own resource, the index, the groups
        AzureLines     = 0L
        AzureResources = 0L
        AzureIndex     = (& $newText 'azure-records')
        Groups         = (New-Object SecurityInsight.KeyGroups)
    }
    $st | Add-Member -NotePropertyName Stream -NotePropertyValue $s -Force
    # the child -> parent map on disk (its entries so far go with it)
    $cst = Get-SIRecordChildState $st
    $disk = & $newText 'azure-childof'
    foreach ($k in @($cst.ChildOf.Keys)) { $disk[[string]$k] = [string]$cst.ChildOf[$k] }
    $cst.ChildOf = $disk
    foreach ($id in @($st.Records.Keys)) {
        $rec = $st.Records[$id]
        $item = ConvertTo-SIRecordStreamItem -Id ([string]$id) -Record $rec
        if ([string]$rec.Provider -eq 'azure') {
            foreach ($pk in @($rec.Parts.Keys)) {
                $pv = $rec.Parts[$pk]; $obj = $pv
                if ([string]$pk -eq 'resource') { $obj = ConvertFrom-SIRecordParts -Parts ([ordered]@{ x = $pv }); $obj = $obj.x }
                Register-SIRecordStreamAzure -Stream $s -Id ([string]$id) -RecordType ([string]$rec.RecordType) -Key ([string]$rec.Key) -ResourceType ([string]$rec.ResourceType) -Part ([string]$pk) -Object $obj -NoLine
            }
            $s.AzureLines++
        }
        Write-SIRecordStreamItem -Stream $s -Item $item
        [void]$st.Records.Remove($id)
    }
    $s
}

function Register-SIRecordStreamAzure {
    <#
        #727 -- one Azure line of the stream, as the Azure reads and the hand-over need it later, without the record:
          * the record index (on disk): record type, resource type (the last one given), whether the record holds its own
            resource (part 'resource'), the resource's name and -- for a public IP -- what it is attached through;
          * the groups: a child resource listed on a record ('child|<child id>') joins the record's group, so the hand-over
            folds them together.
        -NoLine: the line is counted by the caller.
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Id, [string]$RecordType = '', [string]$Key = '',
          [string]$ResourceType = '', [string]$Part = '', $Object, [switch]$NoLine)
    if (-not $NoLine) { $Stream.AzureLines++ }
    $ix = $Stream.AzureIndex
    $old = $ix.GetText($Id)
    $sep = $script:SIAzureIndexSep
    if ($null -eq $old) { $f = @($RecordType, '', '0', '', ''); $chg = $true } else { $f = $old.Split($sep); $chg = $false }
    if ($ResourceType -and [string]$f[1] -cne $ResourceType) { $f[1] = $ResourceType; $chg = $true }
    if ($Part -eq 'resource') {
        if ([string]$f[2] -ne '1') { $Stream.AzureResources++ }
        $f[2] = '1'
        $f[3] = ([string](Get-SIItemValue $Object 'name')).Replace([string]$sep, ' ')
        $f[4] = ''
        if ($RecordType -eq 'public_ip') { $f[4] = Get-SIAzurePipVia -Resource $Object }
        $chg = $true
    }
    if ($chg) { [void]$ix.Put($Id, ($f -join $sep)) }
    if ($Part.StartsWith('child|')) { $Stream.Groups.Union($Key, $Part.Substring(6)) }
}

function Get-SIRecordStreamAzureInfo {
    <# #727 -- one Azure record of the stream's index: @{ Id; RecordType; Key; ResourceType; HasResource; Name; Via }, or $null. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Id)
    $t = $Stream.AzureIndex.GetText($Id)
    if ($null -eq $t) { return $null }
    $f = $t.Split($script:SIAzureIndexSep)
    $i = $Id.IndexOf('|', 6)
    @{ Id = $Id; RecordType = [string]$f[0]; Key = $Id.Substring($i + 1); ResourceType = [string]$f[1]; HasResource = ([string]$f[2] -eq '1'); Name = [string]$f[3]; Via = [string]$f[4] }
}

function Add-SIRecordStreamPart {
    <#
        #727 -- a part ADDED to an Azure record the stream already holds (the Azure context, the management groups): one line
        for that record id, written as the capture would have kept it (the object's JSON). No placement, no engine (the record
        was captured by its own source; a part set on it never added an engine).
    #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Part, [AllowNull()]$Object)
    $a = $Id.IndexOf('|'); $b = $Id.IndexOf('|', $a + 1)
    $Stream.AzureLines++
    Write-SIRecordStreamItem -Stream $Stream -Item ([ordered]@{ Id = $Id; Provider = $Id.Substring(0, $a); RecordType = $Id.Substring($a + 1, $b - $a - 1); Key = $Id.Substring($b + 1)
            ResourceType = ''; Engines = @(); Parts = [ordered]@{ $Part = (ConvertTo-Json -InputObject $Object -Compress -Depth 20) } })
}

function ConvertTo-SIRecordStreamItem {
    <# PURE. One captured record as the hand-over keeps it (its parts as JSON text) -- the same shape as ConvertTo-SIRecordHandoverItem. #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Record)
    $parts = [ordered]@{}
    foreach ($k in @($Record.Parts.Keys)) {
        $v = $Record.Parts[$k]
        if ($null -ne $v -and $v -is [psobject] -and $v.PSObject.Properties['SIJson'] -and @($v.PSObject.Properties).Count -eq 1) { $parts[$k] = [string]$v.SIJson }
        else { $parts[$k] = (ConvertTo-Json -InputObject $v -Compress -Depth 20) }
    }
    [ordered]@{ Id = $Id; Provider = $Record.Provider; RecordType = $Record.RecordType; Key = $Record.Key; ResourceType = $Record.ResourceType; Engines = @($Record.Engines); Parts = $parts }
}

function Write-SIRecordStreamItem {
    <# One item -> one line of the stream (the Id first: the hand-over buckets a line by it without parsing the rest). #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)]$Item)
    $Stream.Writer.WriteLine((ConvertTo-Json -InputObject $Item -Compress -Depth 4))
    $Stream.Items++
    if ($script:SIRecordStreamReadBack -contains [string]$Item.Provider) { [void]$Stream.Ids.Add([string]$Item.Id) }
}

function Stop-SIRecordCaptureStream {
    <# Closes the stream and removes its file (after the hand-over, or when a capture is cleared). Never throws. #>
    param($State = $global:SIRecordCaptureState)
    try {
        if ($null -eq $State -or -not $State.PSObject.Properties['Stream'] -or $null -eq $State.Stream) { return }
        $s = $State.Stream
        $State.Stream = $null
        try { $s.Writer.Dispose() } catch { }
        try { [IO.File]::Delete($s.Path) } catch { }
        # #727: the Azure record index's file goes with the stream
        try { if ($s.PSObject.Properties['AzureIndex'] -and $s.AzureIndex -is [System.IDisposable]) { $s.AzureIndex.Dispose() } } catch { }
    } catch { }
}

function Test-SIRecordCaptured {
    <# Was this record (provider|type|key) captured this run -- held, or streamed? #>
    param([Parameter(Mandatory)][string]$Id, $State = $global:SIRecordCaptureState)
    if ($null -eq $State) { return $false }
    if ($State.Records.ContainsKey($Id)) { return $true }
    return [bool]($State.PSObject.Properties['Stream'] -and $null -ne $State.Stream -and $State.Stream.Ids.Contains($Id))
}

function Get-SIRecordCapturedKeys {
    <# The keys of the captured records of one provider and record type -- held or streamed (each once). #>
    param([Parameter(Mandatory)][string]$Provider, [Parameter(Mandatory)][string]$RecordType, $State = $global:SIRecordCaptureState)
    if ($null -eq $State) { return }
    $p = $Provider.Trim().ToLowerInvariant(); $rt = $RecordType.Trim().ToLowerInvariant()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($State.Records.Values)) { if ([string]$r.Provider -eq $p -and [string]$r.RecordType -eq $rt -and $seen.Add([string]$r.Key)) { [string]$r.Key } }
    if ($State.PSObject.Properties['Stream'] -and $null -ne $State.Stream) {
        $pre = "$p|$rt|"
        foreach ($id in $State.Stream.Ids) { if ($id.StartsWith($pre, [StringComparison]::OrdinalIgnoreCase)) { $k = $id.Substring($pre.Length); if ($seen.Add($k)) { $k } } }
    }
}

function Get-SIRecordCaptureCount {
    <# How many records the capture handed over / will hand over: held records + streamed items (a record streamed in several
       parts counts once per part -- the hand-over's bucket count only needs the order of magnitude). The Azure records
       (#727) count once each (the index knows them): their context adds several lines per resource. #>
    param($State = $global:SIRecordCaptureState)
    if ($null -eq $State) { return 0L }
    $n = [long]$State.Records.Count
    if ($State.PSObject.Properties['Stream'] -and $null -ne $State.Stream) {
        $s = $State.Stream
        $n += [long]$s.Items
        if ($s.PSObject.Properties['AzureIndex'] -and $null -ne $s.AzureIndex) { $n += [long]$s.AzureIndex.Count - [long]$s.AzureLines }
    }
    $n
}

function Reset-SIRecordCapture {
    <# Starts the capture for one engine run. Records captured by an earlier engine in the same session are kept. #>
    param([string]$Engine = '', [switch]$Clear)
    if ($Clear -and $null -ne $global:SIRecordCaptureState) {
        Stop-SIRecordCaptureStream -State $global:SIRecordCaptureState
        # #727: the producer's child map is a file on disk -- it goes with the capture
        try { $co = $global:SIRecordCaptureState.ChildOf; if ($co -is [System.IDisposable]) { $co.Dispose() } } catch { }
    }
    if ($Clear -or $null -eq $global:SIRecordCaptureState) {
        $global:SIRecordCaptureState = [pscustomobject]@{
            Engine  = ''
            Records = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
            Pulls   = @{}
            # Azure child resources (SI-AzureChildren.ps1): child id -> parent id, and the objects not recorded (reason -> count)
            ChildOf = @{}
            Dropped = @{}
        }
    }
    $global:SIRecordCaptureState.Engine = ([string]$Engine).Trim().ToLowerInvariant()
    $global:SIRecordCaptureState
}

function Add-SIRecordPart {
    <#
        One provider object as a part of a record. -Key is the provider's own id (lower-cased here). A second call with
        the same provider, record type, key and part replaces the part (the newer read wins).
    #>
    param(
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$RecordType,
        [AllowNull()][AllowEmptyString()][string]$Key,
        [Parameter(Mandatory)][string]$Part,
        [AllowNull()]$Object,
        [string]$ResourceType = ''
    )
    try {
        if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Key)) { return }
        if ($null -eq $global:SIRecordCaptureState) { $null = Reset-SIRecordCapture }
        $p = $Provider.Trim().ToLowerInvariant(); $rt = $RecordType.Trim().ToLowerInvariant(); $k = $Key.Trim().ToLowerInvariant()
        # AZURE CHILD RESOURCES AND THE CI SCOPE (owner 2026-10-11, SI-AzureChildren.ps1): an Azure object keyed by its ARM id
        # (the Azure read, Defender for Cloud) is placed by data-model/collection-scope -- a CHILD (a VM extension, a disk, a
        # network interface, a subnet, a SQL database ...) becomes a part of its parent's record and is never a record (a CI)
        # of its own; a type that is not a CI type is not recorded; a public IP is recorded AND listed on what it is attached to
        if (-not $Part.StartsWith('child|') -and $p -in 'azure', 'mdc' -and $rt -in 'azure_resource', 'public_ip' -and $k.StartsWith('/subscriptions/')) {
            $cst = Get-SIRecordChildState $global:SIRecordCaptureState
            $pl = Resolve-SIAzurePlacement -Id $k -Type $ResourceType -Object $Object -Scope (Get-SIAzureCiScope) -KnownParents $cst.ChildOf
            if ($pl.Action -eq 'drop') { $cst.Dropped[[string]$pl.Reason] = [int]$cst.Dropped[[string]$pl.Reason] + 1; return }
            if ($pl.Action -eq 'child') { Add-SIRecordChild -ParentId $pl.ParentId -Id $k -Type $pl.Type -Object $Object -Rule $pl.Rule -Provider $p; return }
            if ($pl.AlsoChildOf) { Add-SIRecordChild -ParentId $pl.AlsoChildOf -Id $k -Type $pl.Type -Object $Object -Rule $pl.Rule -Provider $p -KeepOwnCi }
        }
        $id = "$p|$rt|$k"
        # #721 THE PRODUCER STREAMS ITS RECORDS: in the discover phase every part goes straight to the run's local record
        # stream (written, then let go) -- nothing of it stays in memory; Save-SIRecordHandover hands the stream over
        # #727: the Azure records too -- what the Azure reads and the fold need of them goes to the record index and the groups
        $cs = $global:SIRecordCaptureState
        if ($cs.PSObject.Properties['Stream'] -and $null -ne $cs.Stream) {
            $srt = ''; if ($ResourceType) { $srt = $ResourceType.Trim().ToLowerInvariant() }
            if ($p -eq 'azure') { Register-SIRecordStreamAzure -Stream $cs.Stream -Id $id -RecordType $rt -Key $k -ResourceType $srt -Part $Part -Object $Object }
            Write-SIRecordStreamItem -Stream $cs.Stream -Item ([ordered]@{ Id = $id; Provider = $p; RecordType = $rt; Key = $k; ResourceType = $srt
                    Engines = @([string]$cs.Engine); Parts = [ordered]@{ $Part = (ConvertTo-Json -InputObject $Object -Compress -Depth 20) } })
            return
        }
        $rec = $null
        if (-not $global:SIRecordCaptureState.Records.TryGetValue($id, [ref]$rec)) {
            $rec = [pscustomobject]@{ Provider = $p; RecordType = $rt; Key = $k; ResourceType = ''; Parts = [ordered]@{}; Engines = New-Object 'System.Collections.Generic.HashSet[string]' }
            $global:SIRecordCaptureState.Records[$id] = $rec
        }
        if ($ResourceType) { $rec.ResourceType = $ResourceType.Trim().ToLowerInvariant() }
        [void]$rec.Engines.Add([string]$global:SIRecordCaptureState.Engine)
        # #475: kept as compact JSON text, not the live object graph -- several times smaller per object (customer H: tens of
        # thousands of identities and EG nodes); parsed back when the record is assembled (Get-SICapturedRecords)
        $rec.Parts[$Part] = [pscustomobject]@{ SIJson = (ConvertTo-Json -InputObject $Object -Compress -Depth 20) }
    } catch {
        Write-Warning ('record capture: a {0} object could not be kept -- {1}' -f $Provider, $_.Exception.Message)
    }
}

function Add-SIRecordChild {
    <#
        One Azure child resource as a PART of its parent's record: part 'child|<child id>' on the Azure record of the parent
        (azure|azure_resource|<parent id>), holding what the parent lists of it (New-SIAzureChildSummary). The parent is
        walked up while it is itself a known child (a public IP on a network interface -> the virtual machine). A child the
        Azure read already placed is not replaced by another source's poorer view (Defender for Cloud, Exposure Graph).
        -KeepOwnCi: the object stays a record of its own and is ALSO listed on the parent (not remembered as a child).
    #>
    param([Parameter(Mandatory)][string]$ParentId, [Parameter(Mandatory)][string]$Id, [string]$Type = '', [AllowNull()]$Object, $Rule,
          [string]$Provider = 'azure', [switch]$KeepOwnCi)
    try {
        if ($null -eq $global:SIRecordCaptureState) { $null = Reset-SIRecordCapture }
        $cst = Get-SIRecordChildState $global:SIRecordCaptureState
        $cid = $Id.Trim().ToLowerInvariant(); $parentKey = $ParentId.Trim().ToLowerInvariant()
        if (-not $cid -or -not $parentKey -or $cid -eq $parentKey) { return }
        for ($i = 0; $i -lt 4 -and $cst.ChildOf.ContainsKey($parentKey); $i++) { $parentKey = [string]$cst.ChildOf[$parentKey] }
        if ($Provider -ne 'azure' -and $cst.ChildOf.ContainsKey($cid)) { return }
        if (-not $KeepOwnCi) { $cst.ChildOf[$cid] = $parentKey }
        Add-SIRecordPart -Provider 'azure' -RecordType 'azure_resource' -Key $parentKey -Part ('child|' + $cid) -Object (New-SIAzureChildSummary -Id $cid -Type $Type -Object $Object -Rule $Rule)
    } catch {
        Write-Warning ('record capture: an Azure child resource could not be kept on its parent -- {0}' -f $_.Exception.Message)
    }
}

function Set-SIRecordPull {
    <# How one provider's pull went this run. A provider pulled in several calls is complete only when every call was.
       -Code: why it is not complete when that is not a failure -- 'source-not-present' (the source does not exist in the
       tenant, e.g. a workspace without the IdentityInfo table); '' = a plain read result. #>
    param([Parameter(Mandatory)][string]$Provider, [bool]$Complete = $true, [string]$ErrorText = '', [string]$Code = '')
    if ($null -eq $global:SIRecordCaptureState) { $null = Reset-SIRecordCapture }
    $p = $Provider.Trim().ToLowerInvariant()
    $prev = $global:SIRecordCaptureState.Pulls[$p]
    if ($prev) {
        $Complete = [bool]$prev.Complete -and $Complete; if (-not $ErrorText) { $ErrorText = [string]$prev.Error }
        if (-not $Code -and $prev.PSObject.Properties['Code']) { $Code = [string]$prev.Code }
    }
    $global:SIRecordCaptureState.Pulls[$p] = [pscustomobject]@{ Provider = $p; Complete = [bool]$Complete; Error = [string]$ErrorText; Code = [string]$Code }
}

function Set-SIRecordPullsIncomplete {
    <#
        A discovery source of this run FAILED part-way (it threw): every provider pull registered so far is marked NOT
        complete, so the records this run did write never count as a complete collection and nothing is read from what the
        failed source did not reach (working rule 4: absence is not remediation). Without it a source that registered its
        pull as complete and then stopped left its feed "complete" with almost no record in it -- every other record of the
        feed then read as no longer seen. Returns the providers marked. Never throws.
    #>
    param([string]$Reason = '')
    try {
        if ($null -eq $global:SIRecordCaptureState -or $null -eq $global:SIRecordCaptureState.Pulls) { return }
        foreach ($p in @($global:SIRecordCaptureState.Pulls.Keys)) {
            Set-SIRecordPull -Provider ([string]$p) -Complete $false -ErrorText $Reason
            [string]$p
        }
    } catch { Write-Warning ('record capture: the pulls could not be marked not complete -- {0}' -f $_.Exception.Message) }
}

function Get-SIEgRecordType {
    <# PURE. An Exposure Graph node label -> the eg mapping's record type ('' = a node SecurityInsight does not record). #>
    param([AllowNull()][string]$NodeLabel)
    $l = ([string]$NodeLabel).Trim().ToLowerInvariant()
    if ($l -in 'device', 'computer-account') { return 'device' }
    if ($l -in 'user', 'group') { return 'user' }
    if ($l -in 'serviceprincipal', 'managedidentity') { return 'service_principal' }
    if ($l -in 'microsoft.network/publicipaddresses', 'ip') { return 'public_ip' }
    if ($l.StartsWith('microsoft.')) { return 'azure_resource' }
    return ''
}

function Get-SIRecordSourceRoute {
    <#
        PURE. The profilers' source-system names (the full-asset-properties vocabulary) -> where the object goes in the
        data model: provider, record type, part, key, resource type. $null = not recorded.
        Azure (owner 2026-10-11, SI-AzureChildren.ps1): an ARM object is placed by Add-SIRecordPart (a child resource -- a VM
        extension, a disk, a network interface, a subnet, a SQL database -- becomes a part of its parent's record; a type
        that is not a CI type is not recorded). An Exposure Graph node of an Azure type is placed here by the ARM id it
        names: a child answers @{ Child = <placement> } (a part of the parent's Azure record), a type that is not a CI type
        answers $null. -Scope: the Azure CI scope (default: this install's, Get-SIAzureCiScope).
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [AllowNull()]$Object, [AllowNull()][AllowEmptyString()][string]$AnchorValue = '',
          $Scope, $KnownParents)
    $g = { param($n) if ($null -eq $Object) { return $null }; if ($Object -is [System.Collections.IDictionary]) { return $Object[$n] }; $p = $Object.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    switch ($SourceSystem.Trim().ToLowerInvariant()) {
        'mde' { return @{ Provider = 'mde'; RecordType = 'device'; Part = 'machine'; Key = [string](& $g 'id') } }
        'entra-device' { return @{ Provider = 'entra'; RecordType = 'device'; Part = 'device'; Key = [string](& $g 'deviceId') } }
        'entra-user' { return @{ Provider = 'entra'; RecordType = 'user'; Part = 'user'; Key = [string](& $g 'id') } }
        'entra-serviceprincipal' { return @{ Provider = 'entra'; RecordType = 'service_principal'; Part = 'sp'; Key = [string](& $g 'id') } }
        'arm' {
            $t = ([string](& $g 'type')).ToLowerInvariant()
            $rt = 'azure_resource'; if ($t -eq 'microsoft.network/publicipaddresses') { $rt = 'public_ip' }
            return @{ Provider = 'azure'; RecordType = $rt; Part = 'resource'; Key = [string](& $g 'id'); ResourceType = $t }
        }
        'exposure-graph' {
            $rt = Get-SIEgRecordType ([string](& $g 'NodeLabel'))
            if (-not $rt) { return $null }
            if ($rt -eq 'azure_resource') {
                if (-not $PSBoundParameters.ContainsKey('Scope')) { $Scope = Get-SIAzureCiScope }
                if ($null -eq $KnownParents) { $cst = Get-SIRecordChildState $global:SIRecordCaptureState; if ($cst) { $KnownParents = $cst.ChildOf } }
                $pl = Resolve-SIAzurePlacement -Id (Get-SIAzureEgArmId $Object) -Type ([string](& $g 'NodeLabel')) -Object $null -Scope $Scope -KnownParents $KnownParents
                if ($pl.Action -eq 'drop') { return $null }
                if ($pl.Action -eq 'child') { return @{ Provider = 'azure'; RecordType = 'azure_resource'; Part = 'child'; Key = $pl.ParentId; Child = $pl } }
            }
            return @{ Provider = 'eg'; RecordType = $rt; Part = 'node'; Key = [string](& $g 'NodeId') }
        }
        'intune-device' { return @{ Provider = 'intune'; RecordType = 'device'; Part = 'device'; Key = [string](& $g 'id') } }
        'ad-computer' { return @{ Provider = 'ad'; RecordType = 'device'; Part = 'computer'; Key = [string](& $g 'objectGUID') } }
        default { return $null }
    }
}

function Add-SIRecordPartFromSource {
    <# The profilers' hook (called from Add-SIFullSourceObject at every level): one source object -> its record part. #>
    param([Parameter(Mandatory)][string]$SourceSystem, [AllowNull()]$Object, [AllowNull()][AllowEmptyString()][string]$AnchorValue = '')
    try {
        $r = Get-SIRecordSourceRoute -SourceSystem $SourceSystem -Object $Object -AnchorValue $AnchorValue
        if ($null -eq $r) { return }
        # an Exposure Graph node of an Azure child resource: a part of its parent's Azure record, never a record of its own
        if ($r.ContainsKey('Child')) { $c = $r.Child; Add-SIRecordChild -ParentId $c.ParentId -Id $c.Id -Type $c.Type -Object $null -Rule $c.Rule -Provider 'eg'; return }
        $rt = ''; if ($r.ContainsKey('ResourceType')) { $rt = [string]$r.ResourceType }
        Add-SIRecordPart -Provider $r.Provider -RecordType $r.RecordType -Key $r.Key -Part $r.Part -Object $Object -ResourceType $rt
    } catch { Write-Warning ('record capture: {0} -- {1}' -f $SourceSystem, $_.Exception.Message) }
}

function Set-SIRecordPullFromSource {
    <# The profilers' hook (called from Set-SIFullSourcePull at every level): a source pull's completeness -> its provider's. #>
    param([Parameter(Mandatory)][string]$SourceSystem, [bool]$Complete = $true, [string]$ErrorText = '')
    $p = switch ($SourceSystem.Trim().ToLowerInvariant()) {
        'mde' { 'mde' } 'arm' { 'azure' } 'exposure-graph' { 'eg' } 'intune-device' { 'intune' } 'ad-computer' { 'ad' }
        { $_ -like 'entra-*' } { 'entra' } default { '' }
    }
    if ($p) { Set-SIRecordPull -Provider $p -Complete $Complete -ErrorText $ErrorText }
}

function Add-SIRecordPartsFromRuleIndexes {
    <#
        The profiler's rule indexes (Build-SIRuleIndexes) as record parts, for the records this run captured:
          software     -> mde device records      ('vendor/product' list, the Defender software inventory)
          parentTags   -> azure records           (the resource group's and subscription's tags, the nearest wins)
          egQueryRules -> eg / mde / entra records (ids of the detection rules whose Exposure Graph query matched)
    #>
    param($Indexes = $global:SIRuleIndexesForRecords)
    if ($null -eq $Indexes -or $null -eq $global:SIRecordCaptureState) { return }
    $sw = $Indexes.tvmSoftware; $pc = $Indexes.parentChain; $ks = $Indexes.kustoSets
    foreach ($r in @($global:SIRecordCaptureState.Records.Values)) {
        try {
            if ($r.Provider -eq 'mde' -and $sw -and $sw.ContainsKey($r.Key)) { $r.Parts['software'] = @($sw[$r.Key]) }
            if ($r.Provider -eq 'azure' -and $pc -and $pc.Count -gt 0) {
                $tags = [ordered]@{}
                $chain = New-Object System.Collections.Generic.List[string]
                if ($r.Key -match '^(/subscriptions/[^/]+)') { $chain.Add($matches[1]) }
                if ($r.Key -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+)') { $chain.Add($matches[1]) }
                foreach ($k in $chain) {          # subscription first, then the resource group: the nearer container wins
                    if ($pc.ContainsKey($k)) { foreach ($t in @($pc[$k])) { if ($t -and $t.tag) { $tags[[string]$t.tag] = [string]$t.value } } }
                }
                if ($tags.Count -gt 0) { $r.Parts['parentTags'] = $tags }
            }
            if ($r.Provider -in 'eg', 'mde', 'entra' -and $ks -and $ks.Count -gt 0) {
                $hits = New-Object System.Collections.Generic.List[string]
                foreach ($ruleId in $ks.Keys) { if ($ks[$ruleId] -and $ks[$ruleId].Contains($r.Key)) { $hits.Add([string]$ruleId) } }
                if ($hits.Count -gt 0) { $r.Parts['egQueryRules'] = $hits.ToArray() }
            }
        } catch { Write-Warning ('record capture: rule-index parts for {0} -- {1}' -f $r.Key, $_.Exception.Message) }
    }
}

# #505: the identity profiler's computed values Risk Analysis reads from the CI (data-model/mappings/entra.locked.json,
# sources 'profile.<column>') -- look-ups no provider object carries (role and permission look-ups, privilege tiers,
# break-glass, credential expiry, owner count). Handed to the Entra record of the same object as its 'profile' part.
$script:SIIdentityProfilePartColumns = @('DisplayName', 'AppId', 'ExternalUserState', 'IsHighRiskPermissionGrant',
    'EntraRolesPermanentVerdict_Tier', 'EntraRolesEligibleVerdict_Tier', 'IsBreakGlass', 'EntraRoles_Permanent', 'EntraRoles_Eligible',
    'AzureRoles_Assignments', 'EntraAppPermissions_Application', 'NestedGroups', 'AdNestedCriticalGroups', 'CSA', 'IsOrphanSPN',
    'CredentialExpiryDays', 'IsThirdPartyMultiTenantSpn', 'LastSignInDateTime', 'LastPasswordChangeDateTime', 'HasPasswordNeverExpires',
    # a service principal's creation time (no provider object of a service principal carries it; the profiler reads it)
    'CreatedDateTime',
    # the delegated permissions the profiler read (the fall-back of si_delegated_permissions when the tenant-wide grants
    # read did not complete)
    'EntraAppPermissions_Delegated')
# Columns of the 'profile' part this file COMPUTES from the row (no profiler column holds them). Every 'profile.<column>'
# source in data-model/mappings is one of the two lists, and a column of the first list is written by the identity
# profiler (tests/pester/SIv3-UnwrittenFields.Tests.ps1 guards it).
$script:SIIdentityProfileComputedColumns = @('IsShadowAdmin')

function ConvertTo-SIProfileList {
    <# PURE. A profile row's list column (an array, or the JSON text the row builder writes) -> @{ Known; Items }. Known =
       the column holds a list at all ($null / '' = not known). #>
    param($Value)
    if ($null -eq $Value) { return @{ Known = $false; Items = @() } }
    $v = $Value
    if ($v -is [string]) {
        $s = $v.Trim()
        if (-not $s) { return @{ Known = $false; Items = @() } }
        if ($s.StartsWith('[') -or $s.StartsWith('{')) { try { $v = $s | ConvertFrom-Json } catch { return @{ Known = $false; Items = @() } } }
        else { return @{ Known = $true; Items = @($s) } }
    }
    $items = @(@($v) | Where-Object { $null -ne $_ -and -not ($_ -is [string] -and -not $_.Trim()) })
    return @{ Known = $true; Items = $items }
}

function Get-SIShadowAdminFromProfileRow {
    <#
    .SYNOPSIS  PURE. Is the identity a SHADOW ADMIN (the Identity_ShadowAdmin reports): it holds Tier 0/1 Active Directory
               group membership (Exposure Graph nestedCriticalAdGroups, the row's AdNestedCriticalGroups) but no Entra role,
               permanent or eligible (EntraRoles_Permanent / EntraRoles_Eligible -- the collector's role read, including the
               roles inherited through groups). Users only.
    .OUTPUTS   $true / $false, or $null = UNKNOWN: not a user, or the critical AD groups were not read (no Exposure Graph
               node), or "no Entra role" cannot be trusted -- unknown is never false, and never true.
    .NOTES     SHADOW-ADMIN GUARD: TRUE only when the Entra role read (permanent AND eligible, with the roles inherited
               through groups and PIM for Groups) is known to have COMPLETED this run (Get-SIProfileRoleReadComplete). A read
               that failed, stopped part-way or whose state cannot be told turns "no role" into unknown. A role the read DID
               find still makes the answer false (seeing a role proves the identity is visible in Entra).
    #>
    param($Row, $RoleReadComplete)
    if ($null -eq $Row -or [string](Get-SIItemValue $Row 'ObjectType') -ne 'User') { return $null }
    $crit = ConvertTo-SIProfileList (Get-SIItemValue $Row 'AdNestedCriticalGroups')
    if (-not $crit.Known) { return $null }
    if (@($crit.Items).Count -eq 0) { return $false }
    $perm = ConvertTo-SIProfileList (Get-SIItemValue $Row 'EntraRoles_Permanent')
    $elig = ConvertTo-SIProfileList (Get-SIItemValue $Row 'EntraRoles_Eligible')
    if ((@($perm.Items).Count + @($elig.Items).Count) -gt 0) { return $false }
    if ($null -eq $RoleReadComplete) { $RoleReadComplete = Get-SIProfileRoleReadComplete -Row $Row }
    if ($RoleReadComplete -ne $true) { return $null }
    return $true
}

function Get-SIProfileRoleReadComplete {
    <#
    .SYNOPSIS  Did the Entra role read complete for the run that built this row? $true / $false / $null (cannot tell).
                 1. the row's own stamp: Properties.collect.entra.RoleReadComplete (the identity discovery stamps every user
                    with ENTRA_RoleReadComplete) -- travels with the row, so a process that only builds record parts (a run
                    collected in parts) can tell
                 2. else the run-level flag of this process ($global:SI_EntraRoleReadState, Test-SIEntraRoleReadComplete)
                 3. else $null -- cannot tell = not complete
    #>
    param($Row)
    $props = Get-SIItemValue $Row 'Properties'
    if ($props -is [string]) { $s = $props.Trim(); if ($s.StartsWith('{')) { try { $props = $s | ConvertFrom-Json } catch { $props = $null } } else { $props = $null } }
    if ($null -ne $props) {
        $stamp = Get-SIItemValue (Get-SIItemValue (Get-SIItemValue $props 'collect') 'entra') 'RoleReadComplete'
        $b = ConvertTo-SIBoolOrNull $stamp
        if ($null -ne $b) { return $b }
    }
    if ($null -ne $global:SI_EntraRoleReadState -and (Get-Command -Name Test-SIEntraRoleReadComplete -ErrorAction SilentlyContinue)) {
        return [bool](Test-SIEntraRoleReadComplete -State $global:SI_EntraRoleReadState)
    }
    return $null
}

function Get-SIProfileRoleReadPartial {
    <# #899: why the Entra role facts of the run that built this row are partial (Properties.collect.entra.RoleReadPartial,
       stamped by the identity discovery when the role lists were kept from the stored records); '' when they are not. #>
    param($Row)
    $props = Get-SIItemValue $Row 'Properties'
    if ($props -is [string]) { $s = $props.Trim(); if ($s.StartsWith('{') -and $s.Contains('RoleReadPartial')) { try { $props = $s | ConvertFrom-Json } catch { $props = $null } } else { $props = $null } }
    if ($null -eq $props) { return '' }
    $v = Get-SIItemValue (Get-SIItemValue (Get-SIItemValue $props 'collect') 'entra') 'RoleReadPartial'
    if ($null -eq $v) { return '' }
    [string]$v
}

function Get-SIIdentityProfileRecordType {
    <# PURE. The Entra record type an identity profile row belongs to ('' = none: a group, an AD-only account). #>
    param($Row)
    switch ([string](Get-SIItemValue $Row 'ObjectType')) {
        'User' { return 'user' }
        'ServicePrincipal' { return 'service_principal' }
        'ManagedIdentity' { return 'service_principal' }
        default { return '' }
    }
}

function Add-SIRecordPartsFromProfileRows {
    <# Signals the profiler computed that no provider holds: the most frequent logon user's tier (endpoint), and the
       identity profiler's look-ups (#505, $script:SIIdentityProfilePartColumns) on the Entra record of the same object. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(),
        # a PART of a run collected in parts (#475): the provider records were captured by discovery, in ANOTHER process,
        # so this process holds none of them -- the part is kept anyway and joins its record when the run's records are
        # merged (Merge-SIRecordHandover, same record id). Default: this process is a part (SI_COLLECT_PHASE = parts).
        [Nullable[bool]]$InParts = $null)
    if ($null -eq $InParts) { $InParts = ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts') }
    # 🔴 Ring 1, 2026-10-10: in a run collected in parts the worker's capture state held NO Entra record (discovery handed
    # them over), so "the record of this object is captured here" was false for every identity, the 'profile' part was
    # never kept, and every identity CI came out without roles, permissions, privilege tiers, sign-in or shadow admin.
    $has = { param($id) $InParts -or ($null -ne $global:SIRecordCaptureState -and $global:SIRecordCaptureState.Records.ContainsKey($id)) }
    $rolePartialSaid = $false
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        # #899: the role lists of this run were kept from the stored records -- this process's run is partial for the role
        # facts too (a worker of a run collected in parts never read the roles itself)
        if (-not $rolePartialSaid) {
            $rp = Get-SIProfileRoleReadPartial -Row $row
            if ($rp) {
                $rolePartialSaid = $true
                if (-not (Get-Command -Name Add-SIEntraRolesPartialNote -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-RunOutcome.ps1') }
                Add-SIEntraRolesPartialNote -Message $rp
            }
        }
        $mde = [string](Get-SIItemValue $row 'MdeDeviceId')
        $t = Get-SIItemValue $row 'MostFrequentUserTier'
        if ($mde -and $null -ne $t -and "$t" -ne '' -and (& $has "mde|device|$($mde.ToLowerInvariant())")) {
            Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $mde -Part 'logon' -Object ([pscustomobject]@{ MostFrequentUserTier = $t })
        }
        $rt = Get-SIIdentityProfileRecordType $row
        $oid = ([string](Get-SIItemValue $row 'PrimaryEntityId')).ToLowerInvariant()
        if ($rt -and $oid -and (& $has "entra|$rt|$oid")) {
            $p = [ordered]@{}
            foreach ($c in $script:SIIdentityProfilePartColumns) {
                $v = Get-SIItemValue $row $c
                if ($null -ne $v -and -not ($v -is [string] -and $v -eq '')) { $p[$c] = $v }
            }
            # computed from the row (unwritten-fields): shadow admin -- unknown stays out of the part, never false
            $sa = Get-SIShadowAdminFromProfileRow -Row $row
            if ($null -ne $sa) { $p['IsShadowAdmin'] = [bool]$sa }
            if ($p.Count -gt 0) { Add-SIRecordPart -Provider 'entra' -RecordType $rt -Key $oid -Part 'profile' -Object ([pscustomobject]$p) }
        }
    }
}

# =====================================================================================================================
#  CIs FOLLOW THE COLLECTION SCOPE (owner 2026-10-10: "CIs follow the same scope"). The scope settings
#  (SI_IncludeInactive_Endpoint, SI_RequireMdeActive_Endpoint, SI_IncludeInactive_Identity, SI_RequireRecentSignIn_Identity)
#  leave profile rows out in the Output stage; the provider records were captured earlier and are STILL STORED -- they are
#  the evidence. The records of an asset the scope left out are MARKED (part 'si_scope', row field si_in_scope = false) so
#  the CI build leaves its CI out (Select-SICiGroupsInScope: the CI keeps its last build, its findings freeze) until the
#  asset is in scope again. IN SCOPE WINS: a record an in-scope asset also names (a re-imaged device's shared Entra device)
#  is never marked, so a live CI is never left out because a stale duplicate shares one of its records.
# =====================================================================================================================
$script:SIScopeIdKeys = @('MDE_DeviceId', 'MDE_MachineId', 'MDE_AadDeviceId', 'ENTRA_AadDeviceId', 'ENTRA_ObjectId', 'ENTRA_UserId', 'ENTRA_SPObjectId',
                          'ENTRA_Id', 'EG_NodeId', 'EG_MdeDeviceId', 'AD_ObjectGUID', 'INTUNE_Id', 'MdeDeviceId', 'AadDeviceId', 'AadObjectId', 'PrimaryEntityId')

function Get-SIProfileRecordIds {
    <# PURE. The provider ids one profile record (or its Metadata) names -- what its provider records are keyed by, lower-cased. #>
    param($Record)
    $out = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Record) { return }
    $bags = @($Record)
    $meta = Get-SIItemValue $Record 'Metadata'; if ($null -ne $meta) { $bags += $meta }
    foreach ($b in $bags) {
        foreach ($k in $script:SIScopeIdKeys) {
            $v = Get-SIItemValue $b $k
            foreach ($x in @($v)) { $s = ([string]$x).Trim(); if ($s) { [void]$out.Add($s.ToLowerInvariant()) } }
        }
    }
    # one id at a time: every caller collects them with @(...), and ', @()' made that ONE item -- the ids joined by spaces
    foreach ($i in $out) { $i }
}

function Select-SIRecordScopeMarks {
    <#
        PURE. The record keys to mark out of scope: every provider id the LEFT-OUT profile records name, minus every id a KEPT
        profile record names (in scope wins). -Before: the records before the scope filter; -Kept: after it.
    #>
    param([AllowEmptyCollection()][object[]]$Before = @(), [AllowEmptyCollection()][object[]]$Kept = @())
    $keptRefs = New-Object 'System.Collections.Generic.HashSet[object]'
    $inIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Kept)) { if ($null -eq $r) { continue }; [void]$keptRefs.Add($r); foreach ($i in @(Get-SIProfileRecordIds $r)) { [void]$inIds.Add($i) } }
    $outIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Before)) {
        if ($null -eq $r -or $keptRefs.Contains($r)) { continue }
        foreach ($i in @(Get-SIProfileRecordIds $r)) { if (-not $inIds.Contains($i)) { [void]$outIds.Add($i) } }
    }
    foreach ($i in $outIds) { $i }
}

function Get-SIRecordScopeInIds {
    <# PURE. Every provider id the KEPT (in-scope) profile records name, lower-cased. #>
    param([AllowEmptyCollection()][object[]]$Kept = @())
    $in = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Kept)) { if ($null -ne $r) { foreach ($i in @(Get-SIProfileRecordIds $r)) { [void]$in.Add($i) } } }
    foreach ($i in $in) { $i }
}

function Set-SIRecordScope {
    <#
        Marks the captured records keyed by one of -OutOfScopeIds (any provider) out of scope: part 'si_scope' { in_scope =
        false }. Returns how many records were marked. Never throws.
    #>
    param([AllowEmptyCollection()][string[]]$OutOfScopeIds = @(),
          # the ids the KEPT profile records name: marked IN scope ({ in_scope = true }, which writes no field) so that, in a
          # run collected in parts, the record hand-over keeps IN SCOPE when another part marked the same record out
          # (Merge-SIRecordHandover: in scope wins). An in-scope mark is never turned out of scope.
          [AllowEmptyCollection()][string[]]$InScopeIds = @())
    try {
        if ($null -eq $global:SIRecordCaptureState -or (@($OutOfScopeIds).Count -eq 0 -and @($InScopeIds).Count -eq 0)) { return 0 }
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($i in @($OutOfScopeIds)) { if ($i) { [void]$ids.Add([string]$i) } }
        $in = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($i in @($InScopeIds)) { if ($i) { [void]$in.Add([string]$i) } }
        $n = 0
        foreach ($rec in $global:SIRecordCaptureState.Records.Values) {
            $k = [string]$rec.Key
            if ($in.Contains($k)) { $rec.Parts['si_scope'] = [pscustomobject]@{ SIJson = '{"in_scope":true}' }; continue }
            if ($ids.Contains($k)) {
                if ($rec.Parts.Contains('si_scope') -and [string]$rec.Parts['si_scope'].SIJson -match '"in_scope"\s*:\s*true') { continue }
                $rec.Parts['si_scope'] = [pscustomobject]@{ SIJson = '{"in_scope":false}' }; $n++
            }
        }
        return $n
    } catch { Write-Warning ('record capture: the scope marks could not be set -- {0}' -f $_.Exception.Message); return 0 }
}

function Get-SIRecordScopeFlag {
    <# PURE. $false when the captured record's parts say it is out of scope, else $null (no field written). #>
    param($Object)
    $s = Get-SIItemValue $Object 'si_scope'
    if ($null -ne $s -and (Get-SIItemValue $s 'in_scope') -eq $false) { return $false }
    return $null
}

function Get-SICapturedRecords {
    <# The captured records: Provider, RecordType, Key, ResourceType, Object (the parts as one object). #>
    # plain output, one record per item: callers write @(Get-SICapturedRecords). A ", array" return here made a caller's
    # @() hold ONE item (the array) -- invisible with one record, wrong with two.
    param([string]$Engine = '')
    if ($null -eq $global:SIRecordCaptureState) { return }
    $tid = Get-SIRecordTenantId; $now = [datetime]::UtcNow
    # Azure child resources: a child's link on another child (a public IP on a network interface) moves to the record above
    $null = Resolve-SIRecordChildren -State $global:SIRecordCaptureState
    foreach ($r in @($global:SIRecordCaptureState.Records.Values)) {
        if ($Engine -and -not $r.Engines.Contains($Engine)) { continue }
        # child parts whose parent was not captured (not a CI type, or not read this run): never a record of their own
        if (Test-SIRecordChildOnly $r) { continue }
        # the parts as one object, with its 'derived' part (SI-RecordDerived.ps1) -- the same in every path, parts or not
        $obj = Add-SIRecordDerivedPart -Provider $r.Provider -RecordType $r.RecordType -Object (ConvertFrom-SIRecordParts $r.Parts) -TenantId $tid -Now $now
        [pscustomobject]@{ Provider = $r.Provider; RecordType = $r.RecordType; Key = $r.Key; ResourceType = $r.ResourceType; Object = $obj; Engines = @($r.Engines) }
    }
}

function ConvertFrom-SIRecordParts {
    <# PURE. A record's parts as one object: a part kept as JSON text (Add-SIRecordPart) is parsed back; a part set as an
       object (the rule-index parts) is used as it is. #>
    param($Parts)
    $o = [ordered]@{}
    # the Azure child resources ('child|<id>' parts) as ONE list: part 'children' (SI-RecordDerived.ps1 reads it)
    $children = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($Parts.Keys)) {
        $v = $Parts[$k]
        $pv = $v
        if ($null -ne $v -and $v -is [psobject] -and $v.PSObject.Properties['SIJson'] -and @($v.PSObject.Properties).Count -eq 1) {
            $pv = $(if ($v.SIJson) { $v.SIJson | ConvertFrom-Json } else { $null })
        }
        if (([string]$k).StartsWith('child|')) { if ($null -ne $pv) { $children.Add($pv) }; continue }
        $o[$k] = $pv
    }
    if ($children.Count -gt 0) { $o['children'] = $children.ToArray() }
    [pscustomobject]$o
}

function Get-SIRawDataProviders {
    <# PURE. SI_RawData as the set of providers whose raw objects are kept: off -> none, on -> all, 'mde,azure' -> those. #>
    param([AllowNull()]$Setting, [string[]]$AllProviders = @())
    # plain output (no ", @()" wrapper): a caller's @(...) then counts the providers, never an array inside an array
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    if (-not $s -or $s -in 'off', 'false', '0', 'no', 'none') { return }
    if ($s -in 'on', 'true', '1', 'yes', 'all') { foreach ($p in $AllProviders) { $p }; return }
    foreach ($p in $s.Split(',')) { $t = $p.Trim(); if ($t) { $t } }
}

function Test-SILaExport {
    <#
        PURE. SI_LaExport (off by default): the optional ONE-WAY copy to Log Analytics for Azure Monitor or workbooks
        (operator 2026-10-09: "we can optional support exporting data to la for azure monitor or workbooks integration").
        'records' = the provider records -> SI_Record_CL (+ SI_RecordRaw_CL). The CIs (SI_CI_CL) and the findings are in Log
        Analytics in every install -- Risk Analysis's Kusto reads them -- so they need no setting. Nothing in correlation,
        the CI build or the data sync reads an exported table back.
    #>
    param([AllowNull()]$Setting, [Parameter(Mandatory)][string]$Kind)
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    if (-not $s -or $s -in 'off', 'false', '0', 'no', 'none') { return $false }
    foreach ($x in $s.Split(',')) { if ($x.Trim() -eq $Kind.ToLowerInvariant()) { return $true } }
    return $false
}

function ConvertTo-SILogValue {
    <# PURE. A record value as Log Analytics should receive it: datetimes as UTC, decimals as invariant TEXT (the schema
       inference types a fractional number by the column before it -- the engines post decimals as text for this). #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return ([double]$Value).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture) }
    # #690 (35) a list stays a list: `return $Value` unrolled a ONE-item array into its item, so SI_CI_CL received
    # "Global Administrator" for ["Global Administrator"] and every report reading the field as a list
    # (array_length, set_has_element, mv-expand) lost the identity with one role, group, permission or port. An empty
    # list stays $null, as before.
    if ($Value -is [System.Collections.IList] -and -not ($Value -is [string])) {
        if ($Value.Count -eq 0) { return $null }
        return , $Value
    }
    return $Value
}

function ConvertTo-SIRecordRows {
    <#
    .SYNOPSIS  PURE (no I/O). Captured records -> SI_Record_CL rows, SI_RecordRaw_CL rows and the "mapped field missing"
               counts per provider and field.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Captured,
        [Parameter(Mandatory)]$Model,
        [datetime]$CollectionTime = [datetime]::UtcNow,
        [string]$RunId = '',
        [hashtable]$Pulls = @{},
        [string[]]$RawProviders = @()
    )
    $rows = New-Object System.Collections.Generic.List[object]
    $raw = New-Object System.Collections.Generic.List[object]
    $missing = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    $catalog = $Model['field-catalog']; $vmaps = $Model['value-maps'].maps
    foreach ($c in $Captured) {
        $mapping = $Model.Mappings[[string]$c.Provider]
        if ($null -eq $mapping) { $errors.Add("no mapping for provider '$($c.Provider)'"); continue }
        try {
            $res = ConvertTo-SIRecord -Object $c.Object -Mapping $mapping -RecordType $c.RecordType -Catalog $catalog -ValueMaps $vmaps -ResourceType $c.ResourceType -CollectionTime $CollectionTime -RunId $RunId
        } catch { $errors.Add(("{0} {1} {2}: {3}" -f $c.Provider, $c.RecordType, $c.Key, $_.Exception.Message)); continue }
        $complete = $true
        $pull = $Pulls[[string]$c.Provider]
        if ($pull) { $complete = [bool]$pull.Complete }
        $row = [ordered]@{}
        # ConvertTo-SILogValue, inline (once per field of every record -- #475)
        foreach ($k in $res.Record.Keys) {
            $lv = $res.Record[$k]
            if ($lv -is [datetime]) { $lv = $lv.ToUniversalTime() }
            elseif ($lv -is [double] -or $lv -is [decimal] -or $lv -is [single]) { $lv = ([double]$lv).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture) }
            $row[$k] = $lv
        }
        $row['si_collection_complete'] = $complete
        # CIs follow the collection scope: written only when out of scope, so an in-scope record's content is unchanged
        if ((Get-SIRecordScopeFlag -Object $c.Object) -eq $false) { $row['si_in_scope'] = $false }
        $rows.Add([pscustomobject]$row)
        foreach ($m in $res.Missing) { $mk = "$($c.Provider)|$m"; if ($missing.ContainsKey($mk)) { $missing[$mk]++ } else { $missing[$mk] = 1 } }
        if ($RawProviders -contains [string]$c.Provider) {
            $raw.Add([pscustomobject][ordered]@{
                si_record_key      = $row['si_record_key']
                si_provider        = $c.Provider
                si_record_type     = $c.RecordType
                si_collection_time = $CollectionTime.ToUniversalTime()
                si_run_id          = $RunId
                ('properties_' + $c.Provider + '_raw') = $c.Object
            })
        }
    }
    return @{ Rows = $rows.ToArray(); Raw = $raw.ToArray(); Missing = $missing; Errors = $errors.ToArray() }
}

function Publish-SIRecords {
    <#
        The Output stage's call: the captured records of this run -> the database (+ the optional SI_LaExport copy to
        SI_Record_CL / SI_RecordRaw_CL). Never throws. No database configured: said plainly -- the records are not kept.
        Only the records captured by THIS engine are published (a container session runs several engines; an Exposure
        Graph node read by two of them is published by each, which is harmless: same key, same collection).
        THE DATABASE DOES NOT DEPEND ON LOG ANALYTICS. The caller runs this whether or not its own Log Analytics post
        worked, and inside it the optional copy to SI_Record_CL (SI_LaExport) never decides what the database holds: a
        copy that fails is said and counted, every batch is still written, and the collection is still closed.
        -Outcome (a table the caller hands in) is filled with what happened, so "nothing to write" and "could not be
        written" are told apart: State = off | none | handed-over | no-database | written | failed, and for a written
        collection Seen, Sql, Changed, SqlFailed, Closed ($true / $false; $null when the caller closes), ExportFailed,
        ExportError; for a failed one Error. The return value is unchanged.
    #>
    param([Parameter(Mandatory)]$RunContext, [string]$Engine = '', [AllowEmptyCollection()][object[]]$ProfileRows = @(),
        # the database seam (tests): { param($Sql, $Params, $Mode) }; default = the install's database when one is configured
        [scriptblock]$SqlInvoke,
        # the collection's feed close (New-SIRecordFeedClose) when the CALLER closes it -- a run published in several calls
        # (Publish-SIRecordHandover); without it this call closes its own collection when every batch was written
        $FeedClose,
        [System.Collections.IDictionary]$Outcome,
        # what is published, for the database write's log lines ("bucket 7" -- Publish-SIRecordHandover)
        [string]$What = '')
    $note ={ param([string]$State, [string]$Why) if ($null -ne $Outcome) { $Outcome['State'] = $State; if ($Why) { $Outcome['Error'] = $Why } } }
    try {
        if ($null -eq $global:SIRecordCaptureState) { & $note 'off'; return $null }
        if ($global:SI_DataModelRecords -and ([string]$global:SI_DataModelRecords).Trim().ToLowerInvariant() -in 'off', 'false', '0') { & $note 'off'; return $null }
        if (-not $Engine) { $Engine = [string]$global:SIRecordCaptureState.Engine }
        Add-SIRecordPartsFromRuleIndexes
        Add-SIRecordPartsFromProfileRows -Rows $ProfileRows
        # rich context (Azure lane): diagnostic settings of the TIER 0 AND 1 Azure resources -- the profile rows carry the tier,
        # so it is asked here (one Azure Resource Manager read per such resource; read only; never fails the publish)
        if ($Engine -eq 'azure' -and @($ProfileRows).Count -gt 0) {
            try {
                if (-not (Get-Command -Name Add-SIRecordDiagnosticParts -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/discovery/Get-SIAzureContext.ps1') }
                $null = Add-SIRecordDiagnosticParts -Rows $ProfileRows
            } catch { Write-Warning ('diagnostic settings: ' + $_.Exception.Message) }
        }
        # #475: a PART of a run collected in parts publishes nothing -- its records are halves (Discover captured the rest
        # in another process). They are handed over; the run's last step merges and publishes every record once.
        if ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts') {
            if (-not (Get-Command -Name Save-SIRecordHandover -ErrorAction SilentlyContinue)) {
                . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-CollectParts.ps1')
                . (Join-Path $PSScriptRoot 'SI-RecordHandover.ps1')
            }
            $part = [int][Environment]::GetEnvironmentVariable('SI_COLLECT_PART')
            # the run's bucket count, as discovery decided it (#475); a run from before that: one bucket per part
            $buckets = [int][Environment]::GetEnvironmentVariable('SI_COLLECT_RECORD_BUCKETS')
            if ($buckets -lt 1) { $buckets = [Math]::Max(1, [int][Environment]::GetEnvironmentVariable('SI_COLLECT_PARTS')) }
            $saved = Save-SIRecordHandover -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine $Engine `
                -RunId ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_ENGINE_RUN')) -Who ('part-{0:D5}' -f $part) -Buckets $buckets
            Write-Host ('[INFO] {0} record(s) handed over -- published once with the rest of the run when every part is done' -f $saved)
            & $note 'handed-over'
            if ($null -ne $Outcome) { $Outcome['Seen'] = [int]$saved }
            return [pscustomobject]@{ Records = 0; Raw = 0; Sql = 0; HandedOver = $saved; Missing = @{} }
        }
        . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1')
        $model = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot
        # #456: the customer's data-model overrides in force (and any written against an older shipped item) -- one line
        $dmStatus = Get-SIDataModelStatusLine -Model $model
        if ($dmStatus) { Write-Host ('[INFO] ' + $dmStatus) }
        $rawProviders = @(Get-SIRawDataProviders -Setting $global:SI_RawData -AllProviders @($model.Mappings.Keys))
        $ct = [datetime]::UtcNow
        if ($RunContext -and $RunContext.CollectionTime) { $ct = [datetime]$RunContext.CollectionTime }
        $rid = ''; if ($RunContext -and $RunContext.RunId) { $rid = [string]$RunContext.RunId }
        # the optional one-way copy to Log Analytics (SI_LaExport = records; off by default -- it costs Log Analytics ingestion)
        $export = Test-SILaExport -Setting $global:SI_LaExport -Kind 'records'
        if (-not $export) { $rawProviders = @() }
        if ($export -and -not (Get-Command -Name Send-SIObjectMapRows -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-LogIngest.ps1')
        }
        if (-not (Get-Command -Name Write-SIRecordsToSql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecordSql.ps1') }
        if (-not $SqlInvoke) {
            $SqlInvoke = New-SIRecordSqlInvoke
            # the columns this writer needs (content hash) on a database set up by an older release -- once per process
            # (read-only: the updater applies the schema; the job's identity has data rights only)
            if ($SqlInvoke -and -not $script:SIRecordSchemaReady) {
                try {
                    $missing = @(Get-SIRecordSchemaMissing -Sql $SqlInvoke)
                    $needed = @($missing | Where-Object { $_ -in 'sidata.CiRecord', 'sidata.RecordIdentifier', 'sidata.CiRecord.ContentHash' })
                    if ($needed.Count -gt 0) {
                        Write-Warning ('records were NOT kept: the database is not updated yet (missing {0}) -- run the updater.' -f ($needed -join ', '))
                        $SqlInvoke = $null
                    } else { $script:SIRecordSchemaReady = $true }
                } catch { Write-Warning ('records: the database schema could not be checked -- {0}' -f $_.Exception.Message) }
            }
        }
        if (-not $SqlInvoke) {
            Write-Warning 'records were NOT kept: no database is configured (SI_ProSqlServer / SI_ProSqlDatabase). The records live in SQL only -- every v3 install needs its database; without it there are no CIs.'
        }
        # #475: assembled, converted and written in batches -- never every record (and every row) of a large tenant at once
        $batch = New-Object System.Collections.Generic.List[object]
        $n = 0; $nRaw = 0; $seen = 0
        $missing = @{}
        # CONTINUOUS DISCOVERY (SI-SourceDiscovery.ps1): the property names of every part of every record published here are
        # counted -- what each source offered this run. No request is made for it; a failure costs the publish nothing.
        $discovery = $null
        try {
            if (-not (Get-Command -Name New-SISourceDiscoveryState -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SourceDiscovery.ps1') }
            if (Test-SISourceDiscoveryOn) { $discovery = New-SISourceDiscoveryState }
        } catch { $discovery = $null }
        $flush = {
            if ($batch.Count -eq 0) { return }
            if ($null -ne $discovery) { foreach ($dr in $batch) { Add-SISourceDiscoveryRecord -State $discovery -Record $dr } }
            $out = ConvertTo-SIRecordRows -Captured $batch.ToArray() -Model $model -CollectionTime $ct -RunId $rid -Pulls $global:SIRecordCaptureState.Pulls -RawProviders $rawProviders
            foreach ($e in $out.Errors) { Write-Warning ('records: ' + $e) }
            # #477 / #501: the database is where the records live -- only the records whose content changed are rewritten
            if ($SqlInvoke) {
                $w = Write-SIRecordsToSql -Rows @($out.Rows) -Invoke $SqlInvoke -Now $ct -Close $recClose -What $What
                $script:SIRecBatchSql += [int]$w.Seen; $script:SIRecBatchChanged += [int]$w.Changed; $script:SIRecBatchFailed += [int]$w.Failed
            }
            if ($export) {
                # The copy to Log Analytics never decides what the database holds: it comes AFTER the database write of the
                # same batch, and a copy that fails is said once and counted -- the batches that follow are still written
                # to the database, and the collection is still closed there.
                try {
                    $script:SIRecBatchN += [int](Send-SIObjectMapRows -Rows @($out.Rows) -TableName 'SI_Record' -DcrName $(if ($global:SI_Record_DcrName) { [string]$global:SI_Record_DcrName } else { 'dcr-si-record' }))
                    if (@($out.Raw).Count -gt 0) {
                        $script:SIRecBatchRaw += [int](Send-SIObjectMapRows -Rows @($out.Raw) -TableName 'SI_RecordRaw' -DcrName $(if ($global:SI_RecordRaw_DcrName) { [string]$global:SI_RecordRaw_DcrName } else { 'dcr-si-recordraw' }))
                    }
                } catch {
                    $script:SIRecBatchExportFailed += 1
                    if (-not $script:SIRecExportError) {
                        $script:SIRecExportError = [string]$_.Exception.Message
                        Write-Warning ('records: the copy to Log Analytics (SI_LaExport) failed -- {0}. The records are written to the database all the same; only the copy in SI_Record_CL is missing for this collection.' -f $script:SIRecExportError)
                    }
                }
            }
            foreach ($m in $out.Missing.GetEnumerator()) { $missing[$m.Key] = [int]$missing[$m.Key] + [int]$m.Value }
            $batch.Clear()
        }
        $script:SIRecBatchN = 0; $script:SIRecBatchRaw = 0; $script:SIRecBatchSql = 0; $script:SIRecBatchChanged = 0; $script:SIRecBatchFailed = 0
        $script:SIRecBatchExportFailed = 0; $script:SIRecExportError = ''
        # a half-written collection never counts as a complete one (SI-RecordSql.ps1, the feed close)
        $recClose = $FeedClose; $ownClose = $false
        if (-not $recClose -and $SqlInvoke) { $recClose = New-SIRecordFeedClose -Engine $Engine; $ownClose = $true }
        foreach ($rec in (Get-SICapturedRecords -Engine $Engine)) {
            $batch.Add($rec); $seen++
            if ($batch.Count -ge $script:SIRecordBatchSize) { . $flush }
        }
        . $flush
        # the close says "every record of this collection is in the database" -- it reads the database writes only
        $closed = $null
        if ($ownClose) { $closeRes = Complete-SIRecordFeeds -Close $recClose -Invoke $SqlInvoke -CollectionTime $ct; $closed = -not [bool]$closeRes.Held }
        if ($null -ne $Outcome) {
            $Outcome['Seen'] = [int]$seen; $Outcome['Sql'] = [int]$script:SIRecBatchSql; $Outcome['Changed'] = [int]$script:SIRecBatchChanged
            $Outcome['SqlFailed'] = [int]$script:SIRecBatchFailed; $Outcome['Closed'] = $closed
            $Outcome['ExportFailed'] = [int]$script:SIRecBatchExportFailed; $Outcome['ExportError'] = [string]$script:SIRecExportError
        }
        if ($seen -eq 0) { & $note 'none'; return $null }
        & $note $(if ($SqlInvoke) { 'written' } else { 'no-database' })
        $n = $script:SIRecBatchN; $nRaw = $script:SIRecBatchRaw
        $top = @($missing.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
        $msg = '{0} record(s)' -f $seen
        if ($SqlInvoke) { $msg += (' -> the database ({0} changed, {1} unchanged)' -f $script:SIRecBatchChanged, ([int]$script:SIRecBatchSql - [int]$script:SIRecBatchChanged)) }
        else { $msg += ' -- NOT kept (no database)' }
        if ($export) {
            $msg += (', {0} -> SI_Record_CL (SI_LaExport)' -f $n); if ($nRaw) { $msg += (', {0} raw -> SI_RecordRaw_CL' -f $nRaw) }
            if ([int]$script:SIRecBatchExportFailed -gt 0) { $msg += (' -- the copy FAILED for {0} batch(es)' -f [int]$script:SIRecBatchExportFailed) }
        }
        Write-Host ('[INFO] ' + $msg)
        # Azure objects the CI scope did not record (said once per publish; the Azure profile rows are not affected)
        $cst = $global:SIRecordCaptureState
        if ($cst -and $cst.PSObject.Properties['Dropped'] -and $null -ne $cst.Dropped -and $cst.Dropped.Count -gt 0) {
            $dn = 0; foreach ($v in $cst.Dropped.Values) { $dn += [int]$v }
            Write-Host ('[INFO] Azure: {0} object(s) not recorded as CIs -- {1}' -f $dn, ((@($cst.Dropped.Keys) | Sort-Object | ForEach-Object { '{0} ({1})' -f $_, $cst.Dropped[$_] }) -join '; '))
            $cst.Dropped.Clear()   # said once: the next engine of the same session does not repeat it
        }
        if ($top.Count) { Write-Verbose ('records: mapped fields not delivered by the provider (most frequent): ' + ($top -join ', ')) }
        # continuous discovery: what the sources offered this run -> the database (the web app's "New context available")
        if ($null -ne $discovery) {
            try {
                $dw = Write-SISourceDiscovery -State $discovery -Model $model -Invoke $SqlInvoke -RunId $rid -Now $ct
                # said in the run log ONCE per process (a run collected in parts publishes bucket by bucket): what is new, that
                # nothing is new, or that it could not be saved and why -- every collection says it, not only the one that
                # found something (the endpoint and identity runs were silent, so "nothing new" and "not saved" looked alike)
                $dLine = Get-SISourceDiscoverySummaryText -Result $dw -What ('the {0} run' -f $Engine)
                $dKey = '{0}|{1}' -f $Engine, $(if (-not $dw.Written) { 'not-saved' } elseif ([int]$dw.NewContext -gt 0) { 'new' } else { 'same' })
                if ($null -eq $script:SIDiscoverySaid) { $script:SIDiscoverySaid = @{} }
                if (($dw.Written -and [int]$dw.NewContext -gt 0) -or -not $script:SIDiscoverySaid.ContainsKey($dKey)) { Write-Host ('[INFO] ' + $dLine) }
                else { Write-Verbose $dLine }
                $script:SIDiscoverySaid[$dKey] = $true
            } catch {
                if ($null -eq $script:SIDiscoverySaid) { $script:SIDiscoverySaid = @{} }
                if (-not $script:SIDiscoverySaid.ContainsKey("$Engine|failed")) { Write-Host ('[INFO] Source properties of the {0} run could not be recorded this run ({1}) -- the collection is not affected.' -f $Engine, $_.Exception.Message) }
                $script:SIDiscoverySaid["$Engine|failed"] = $true
            }
        }
        return [pscustomobject]@{ Records = $n; Raw = $nRaw; Sql = [int]$script:SIRecBatchSql; Changed = [int]$script:SIRecBatchChanged; SqlFailed = [int]$script:SIRecBatchFailed; Missing = $missing }
    } catch {
        Write-Warning ('records could not be published this run -- {0}. The profile rows are unaffected.' -f $_.Exception.Message)
        & $note 'failed' ([string]$_.Exception.Message)
        # the caller's feed close must not close a collection this call left half-written
        if ($FeedClose) { $FeedClose.Failed = [int]$FeedClose.Failed + 1 }
        # #475: a part whose records were not handed over fails (its container checks this) -- never a quietly smaller run
        if ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts') { $global:SI_RecordHandoverFailed = $_.Exception.Message }
        return $null
    }
}
