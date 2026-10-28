#Requires -Version 5.1
<#
    SecurityInsight -- AN UPDATE SAYS WHICH READ-ONLY PERMISSIONS AN EXISTING INSTALL HAS NOT GRANTED YET (owner 2026-10-11:
    SecurityInsight may ask for more read-only permissions; "customers grant on their next permission setup run").

    A release can add a permission to config/permissions.locked.json. A new install grants it at setup; an existing install
    keeps running without it -- the columns it feeds stay empty. Every update (setup/Invoke-SIContainerUpdate.ps1, last step)
    therefore compares what SecurityInsight's COLLECTION identity holds with that list and writes, per missing permission,
    ONE plain line (what it is for, that it is read-only, what stays empty) and the two lines that grant them.

      * NEVER fails or holds an update, NEVER grants or changes anything: every call here is a GET (or the Log Analytics
        query POST). Nothing is said when every permission is granted.
      * What the identity holds is READ, never guessed:
          1. the directory: the identity's application permissions (Microsoft Graph appRoleAssignments) against the app
             roles of each API in the list;
          2. when this update's sign-in may not read the directory (the updater job's identity has no directory right):
             the collection engines' OWN check of their own access token, as recorded on their newest run
             (SI_RunHealth_CL, engine/_shared/SI-PermissionCheck.ps1). A missing permission recorded there is exact. "Nothing
             missing" counts only from a run that checked THIS list in full (the record carries the fingerprint of the
             permissions it checked; a run made before a permission was added did not know it); otherwise the update says
             in one line that it could not check.
      * The command follows the rule for every command a person is shown: line 1 downloads the script from
        https://invardia.com/support/si/, line 2 runs it with this install's names filled in (never a placeholder). When a
        name is not known here, the line points at Get Started > Permissions instead.

    Functions (all but Invoke-SIPermissionNote and the two readers are PURE):
      Get-SIPermissionNoteCatalog      the collection identity's APIs + roles, and its engines, from the list
      Get-SIPermissionNoteIdentity     the collection identity and the install's names, from the job list the update read
      Get-SIPermissionNoteGranted      reader 1 (the directory)
      Get-SIPermissionNoteFromRuns     reader 2 (the engines' own check)
      Get-SIPermissionNoteMissing      the list minus what is held
      Get-SIPermissionNoteCommand      the two lines
      Get-SIPermissionNoteLines        the text
      Invoke-SIPermissionNote          all of it; never throws

    -Rest is the update's REST seam (setup/_shared/SI-UpdateRest.ps1):
        { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body }
    PowerShell 5.1-compatible (the VM sync hook); no PowerShell module, no az.
#>

# the fingerprint a collection run records for the permissions it checked (Get-SIPermissionListFingerprint)
if (-not (Get-Command -Name Get-SIPermissionListFingerprint -ErrorAction SilentlyContinue)) {
    $siPermissionNoteCheck = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-PermissionCheck.ps1')
    if (Test-Path -LiteralPath $siPermissionNoteCheck) { . $siPermissionNoteCheck }
}

$script:SIPermissionNoteUrlBase = 'https://invardia.com/support/si/'
$script:SIPermissionNoteGraph = 'https://graph.microsoft.com/'

# What a permission added after an install was made is for, and what stays empty without it. A permission that is not
# listed here is one SecurityInsight has always needed: its line says only that its data is not collected.
$script:SIPermissionNoteText = @{
    'DeviceManagementConfiguration.Read.All'  = @{ For = 'which Intune compliance policies a device does not meet, and its update ring'
                                                   Empty = 'the failing compliance policy and update ring columns stay empty' }
    'AccessReview.Read.All'                   = @{ For = 'when a privileged role, group or application was last reviewed'
                                                   Empty = 'the last access review columns stay empty' }
    'SecurityAlert.Read.All'                  = @{ For = 'the open alerts of each device: how many, their highest severity and the newest one'
                                                   Empty = 'the open alert columns of the devices stay unknown' }
    'Vulnerability.Read.All'                  = @{ For = 'the exploit details of a vulnerability from Defender (verified exploit, exploit kit, exploit type, exposed devices)'
                                                   Empty = 'the exploit detail columns of the vulnerability findings stay empty' }
    'SecurityRecommendation.Read.All'         = @{ For = 'the exposure impact and the active alert of a Defender recommendation'
                                                   Empty = 'the exposure impact and active alert columns of the vulnerability and configuration findings stay empty' }
    'SecurityEvents.Read.All'                 = @{ For = 'the Microsoft Secure Score of the tenant, sent with the hourly status report'
                                                   Empty = 'the hourly status report carries no Secure Score' }
    'Score.Read.All'                          = @{ For = 'the Defender exposure score of the tenant, sent with the hourly status report'
                                                   Empty = 'the hourly status report carries no exposure score' }
    'DeviceManagementManagedDevices.Read.All' = @{ For = 'Intune devices: serial numbers and MAC addresses for the full asset details'
                                                   Empty = 'the serial number and MAC address columns from Intune stay empty' }
    'UserAuthenticationMethod.Read.All'       = @{ For = 'the sign-in methods of each user'
                                                   Empty = 'the passwordless-only and MFA strength columns stay unknown' }
}

function Get-SIPermissionNoteProp {
    <# PURE. A property of a parsed object or a dictionary, $null when a level is absent (never throws). #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($p)) { $o = $o[$p] } else { return $null }; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function Get-SIPermissionNoteCatalog {
    <#
        The collection identity as config/permissions.locked.json lists it:
          @{ Label; Apis = @( @{ Resource; ResourceAppId; Roles = string[] } ); Engines = string[] }
        Engines = the engines that run as that identity AND check its application permissions. -Path: the list (default:
        this tree's). Throws when the list cannot be read (the caller says so in one line).
    #>
    param([string]$Path)
    if (-not $Path) { $Path = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'permissions.locked.json') }
    $cat = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $id = Get-SIPermissionNoteProp $cat @('identities', 'collection')
    if (-not $id) { throw 'the permission list names no collection identity' }
    $apis = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($id.api)) {
        if (-not $a -or -not "$($a.resourceAppId)".Trim()) { continue }
        $roles = @(@($a.roles) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if (-not $roles.Count) { continue }
        $apis.Add([pscustomobject]@{ Resource = [string]$a.resource; ResourceAppId = ([string]$a.resourceAppId).Trim().ToLowerInvariant(); Roles = $roles })
    }
    $engines = New-Object System.Collections.Generic.List[string]
    $eng = Get-SIPermissionNoteProp $cat @('engines')
    if ($eng) {
        foreach ($p in $eng.PSObject.Properties) {
            if ($p.Name -eq 'default' -or -not $p.Value) { continue }
            if ([string]$p.Value.identity -eq 'collection' -and (@($p.Value.checks) -contains 'api')) { $engines.Add($p.Name.ToLowerInvariant()) }
        }
    }
    [pscustomobject]@{ Label = [string]$id.label; Apis = $apis.ToArray(); Engines = $engines.ToArray() }
}

function Test-SIPermissionNoteSafe {
    <# PURE. A value that may be pasted into a command: a resource name, an id or a resource id -- nothing else. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    "$Value" -match '^[A-Za-z0-9/][A-Za-z0-9._()/-]{0,400}$'
}

function Get-SIPermissionNoteIdentity {
    <#
        PURE. SecurityInsight's collection identity and this install's names, read from the job list the update already has
        (ARM shape): the first job whose SI_ENGINE is one of -Engines and that names its sign-in.
          @{ Job; ClientId; ObjectId; Managed; IdentityName; IdentityResourceGroup; WorkspaceResourceId; StorageAccount; DcrResourceGroup }
        Managed = the job signs in with a user-assigned managed identity (SI_UAMI_CLIENTID); otherwise an app registration
        (SI_SPN_APPID). IdentityName / IdentityResourceGroup: the job's user-assigned identity with that client id ('' when
        the job does not say). $null when no such job is in the list.
    #>
    param([object[]]$Jobs = @(), [string[]]$Engines = @())
    $want = @($Engines | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($j in @($Jobs | Where-Object { $_ } | Sort-Object { [string]$_.name })) {
        $c = @(Get-SIPermissionNoteProp $j @('properties', 'template', 'containers') | Where-Object { $_ }) | Select-Object -First 1
        if (-not $c) { continue }
        $ev = @{}
        foreach ($e in @($c.env)) { if ($e -and "$($e.name)".Trim() -and $e.PSObject.Properties['value']) { $ev[([string]$e.name).Trim().ToUpperInvariant()] = "$($e.value)".Trim() } }
        $engine = "$($ev['SI_ENGINE'])".ToLowerInvariant()
        if (-not $engine -or ($want.Count -and $want -notcontains $engine)) { continue }
        $uami = "$($ev['SI_UAMI_CLIENTID'])"; $app = "$($ev['SI_SPN_APPID'])"
        $client = if ($uami) { $uami } else { $app }
        if (-not $client) { continue }
        $name = ''; $rg = ''
        if ($uami) {
            $ua = Get-SIPermissionNoteProp $j @('identity', 'userAssignedIdentities')
            $props = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $ua[$_] } }) } elseif ($ua) { @($ua.PSObject.Properties) } else { @() }
            foreach ($p in $props) {
                if ("$(Get-SIPermissionNoteProp $p.Value @('clientId'))".Trim() -ine $uami) { continue }
                $m = [regex]::Match([string]$p.Name, '(?i)^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/([^/]+)$')
                if ($m.Success) { $rg = $m.Groups[1].Value; $name = $m.Groups[2].Value }
                break
            }
        }
        return [pscustomobject]@{
            Job = [string]$j.name; ClientId = $client; ObjectId = "$($ev['SI_SPN_OBJECTID'])"; Managed = [bool]$uami
            IdentityName = $name; IdentityResourceGroup = $rg
            WorkspaceResourceId = "$($ev['SI_WORKSPACE_RESOURCEID'])"; StorageAccount = "$($ev['SI_STORAGE_ACCOUNT'])"; DcrResourceGroup = "$($ev['SI_DCR_RESOURCEGROUP'])"
        }
    }
    $null
}

function Get-SIPermissionNoteGraphList {
    <# Every item of a Microsoft Graph list (value[], following @odata.nextLink). @{ Status; Items }: Status is the first answer that was not 2xx (0 = no answer), else 200. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$Uri, [int]$MaxPages = 40)
    $items = New-Object System.Collections.Generic.List[object]
    $url = $Uri
    for ($p = 0; $url -and $p -lt $MaxPages; $p++) {
        $r = & $Rest 'GET' $url $null $script:SIPermissionNoteGraph @{}
        $code = 0; try { $code = [int]$r.Status } catch { $code = 0 }
        if ($code -lt 200 -or $code -ge 300) { return [pscustomobject]@{ Status = $code; Items = @() } }
        $page = $null; try { $page = [string]$r.Body | ConvertFrom-Json } catch { return [pscustomobject]@{ Status = 0; Items = @() } }
        $url = ''
        if ($page) {
            foreach ($x in @($page.value)) { if ($null -ne $x) { $items.Add($x) } }
            if ($page.PSObject.Properties['@odata.nextLink']) { $url = [string]$page.'@odata.nextLink' }
        }
    }
    [pscustomobject]@{ Status = 200; Items = $items.ToArray() }
}

function Get-SIPermissionNoteGranted {
    <#
        READER 1 -- the directory. The application permissions the identity holds, per API of -Apis:
          @{ Readable; Why; Granted = @{ <resourceAppId> = string[] }; Absent = string[] }
        Readable = $false: this sign-in may not read them (Why says it; nothing is assumed). Absent: an API of the list that
        is not in this directory at all (its product is not in use there) -- nothing can be granted on it, so nothing is
        said about it. GET only.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [string]$ObjectId, [string]$ClientId, [object[]]$Apis = @())
    $no = { param($why) [pscustomobject]@{ Readable = $false; Why = $why; Granted = @{}; Absent = @() } }
    $why = { param($code) if ($code -eq 401 -or $code -eq 403) { 'the sign-in of this update may not read the directory' } elseif ($code -eq 404) { 'the identity was not found in the directory' } elseif ($code -le 0) { 'the directory did not answer' } else { 'the directory answered HTTP {0}' -f $code } }
    $oid = "$ObjectId".Trim(); $cid = "$ClientId".Trim()
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $sp = if ($oid -match $guid) { 'servicePrincipals/{0}' -f $oid } elseif ($cid -match $guid) { "servicePrincipals(appId='{0}')" -f $cid } else { '' }
    if (-not $sp) { return (& $no 'the identity''s id is not known here') }
    $mine = Get-SIPermissionNoteGraphList -Rest $Rest -Uri ('https://graph.microsoft.com/v1.0/{0}/appRoleAssignments' -f $sp)
    if ($mine.Status -ne 200) { return (& $no (& $why $mine.Status)) }
    $granted = @{}; $absent = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Apis)) {
        if (-not $a) { continue }
        $u = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{0}')?{1}=id,appRoles" -f $a.ResourceAppId, '$select'
        $r = & $Rest 'GET' $u $null $script:SIPermissionNoteGraph @{}
        $code = 0; try { $code = [int]$r.Status } catch { $code = 0 }
        if ($code -eq 404) { $absent.Add([string]$a.ResourceAppId); continue }
        if ($code -lt 200 -or $code -ge 300) { return (& $no (& $why $code)) }
        $res = $null; try { $res = [string]$r.Body | ConvertFrom-Json } catch { return (& $no 'the directory''s answer could not be read') }
        $rid = "$($res.id)".Trim()
        if (-not $rid) { return (& $no 'the directory''s answer could not be read') }
        $byId = @{}
        foreach ($ar in @($res.appRoles)) { if ($ar -and "$($ar.id)".Trim()) { $byId[([string]$ar.id).ToLowerInvariant()] = [string]$ar.value } }
        $have = New-Object System.Collections.Generic.List[string]
        foreach ($g in @($mine.Items)) {
            if ("$($g.resourceId)".Trim() -ine $rid) { continue }
            $v = $byId[("$($g.appRoleId)").ToLowerInvariant()]
            if ($v) { $have.Add($v) }
        }
        $granted[[string]$a.ResourceAppId] = $have.ToArray()
    }
    [pscustomobject]@{ Readable = $true; Why = ''; Granted = $granted; Absent = $absent.ToArray() }
}

function Get-SIPermissionNoteFingerprint {
    <#
        PURE. The fingerprint of the list's application permissions, as a collection run records the ones it checked
        (engine/_shared/SI-PermissionCheck.ps1, Get-SIPermissionListFingerprint over '<api>|<permission>'). '' when that
        function is not in this tree -- then no run record counts as a check of the whole list.
    #>
    param([object[]]$Apis = @())
    if (-not (Get-Command -Name Get-SIPermissionListFingerprint -ErrorAction SilentlyContinue)) { return '' }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Apis)) { if ($a) { foreach ($r in @($a.Roles)) { $names.Add(('{0}|{1}' -f $a.Resource, $r)) } } }
    [string](Get-SIPermissionListFingerprint -Names $names.ToArray())
}

function Get-SIPermissionNoteKql {
    <# PURE. The newest run record of each engine that carries the engine's own permission check (last 7 days). #>
    "SI_RunHealth_CL | where TimeGenerated > ago(7d) | extend Eng = tolower(tostring(column_ifexists('Engine', ''))), Ph = tostring(column_ifexists('Phase', '')), Gaps = tostring(column_ifexists('PermissionGaps', '')) | where Ph == 'End' and isnotempty(Gaps) and Eng !startswith 'flow:' | summarize arg_max(TimeGenerated, Gaps) by Engine = Eng | project Engine, At = tostring(TimeGenerated), Gaps"
}

function ConvertFrom-SIPermissionNoteRuns {
    <#
        PURE. READER 2's answer from the run records (Engine, At = when, Gaps = the PermissionGaps JSON):
          @{ Known; Missing = @( @{ Resource; Role } ); Why }
        Only the engines of -Engines count, and only a record whose check ran (no 'error').
          * A record that checked THIS list in full ('apiChecked' = -Fingerprint, nothing left out) is exact: the newest one
            is the answer -- what it lists as missing is missing, and nothing listed means everything is granted.
          * Without such a record (the newest runs were made before a permission was added, or could not check an API):
            a permission of the list that a record says is missing is still named (the engine read its own token); when
            none says so, nothing is known -- "nothing missing" from a shorter list is not an answer.
    #>
    param([object[]]$Rows = @(), [object[]]$Apis = @(), [string[]]$Engines = @(), [string]$Fingerprint)
    $roleOf = @{}; $areas = @{}
    foreach ($a in @($Apis)) { if ($a) { $areas[([string]$a.Resource).ToLowerInvariant()] = [string]$a.Resource; foreach ($r in @($a.Roles)) { $roleOf[(([string]$a.Resource) + '|' + [string]$r).ToLowerInvariant()] = [string]$r } } }
    $want = @($Engines | ForEach-Object { "$_".ToLowerInvariant() })
    $fp = "$Fingerprint".Trim()
    $toItems = { param($keys) @($keys | ForEach-Object { [pscustomobject]@{ Resource = $areas[($_ -split '\|')[0]]; Role = $roleOf[$_] } } | Sort-Object Resource, Role) }
    $union = @{}; $seen = 0; $exact = $null; $exactAt = [long]-1
    foreach ($row in @($Rows)) {
        if (-not $row -or $want -notcontains "$($row.Engine)".ToLowerInvariant()) { continue }
        $j = $null; try { $j = [string]$row.Gaps | ConvertFrom-Json } catch { $j = $null }
        if (-not $j -or "$(Get-SIPermissionNoteProp $j @('error'))".Trim()) { continue }
        $seen++
        $mine = New-Object System.Collections.Generic.List[string]
        foreach ($i in @($j.items)) {
            if (-not $i -or "$($i.state)" -ne 'missing') { continue }
            $k = ("$($i.area)" + '|' + "$($i.item)").ToLowerInvariant()
            if ($roleOf.ContainsKey($k) -and -not $mine.Contains($k)) { $mine.Add($k) }
        }
        # a record cut short ('more' items left out) is not the whole check
        $more = 0; try { $more = [int](Get-SIPermissionNoteProp $j @('more')) } catch { $more = 0 }
        if ($fp -and $more -le 0 -and "$(Get-SIPermissionNoteProp $j @('apiChecked'))".Trim() -eq $fp) {
            $at = [long]0
            $v = Get-SIPermissionNoteProp $row @('At')
            try {
                if ($v -is [datetime]) { $at = $v.ToUniversalTime().Ticks }
                elseif ("$v".Trim()) { $at = [datetime]::Parse("$v", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal).Ticks }
            } catch { $at = [long]0 }
            if ($at -gt $exactAt) { $exactAt = $at; $exact = $mine.ToArray() }
        } else { foreach ($k in $mine) { $union[$k] = $true } }
    }
    if ($null -ne $exact) { return [pscustomobject]@{ Known = $true; Missing = @(& $toItems $exact); Why = '' } }
    if ($union.Count) { return [pscustomobject]@{ Known = $true; Missing = @(& $toItems @($union.Keys)); Why = '' } }
    [pscustomobject]@{ Known = $false; Missing = @(); Why = $(if ($seen) { 'no collection run has checked the current permission list yet' } else { 'no collection run has recorded its own check' }) }
}

function Get-SIPermissionNoteFromRuns {
    <# READER 2 -- the collection engines' own check on their newest run (one Log Analytics query). Never throws: not readable = not Known. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [string]$WorkspaceResourceId, [object[]]$Apis = @(), [string[]]$Engines = @())
    $no = [pscustomobject]@{ Known = $false; Missing = @(); Why = 'the run records could not be read' }
    $ws = "$WorkspaceResourceId".Trim().TrimEnd('/')
    if (-not $ws) { return $no }
    try {
        $url = 'https://management.azure.com{0}/api/query?api-version=2017-10-01' -f $ws
        $r = & $Rest 'POST' $url (ConvertTo-Json -InputObject ([ordered]@{ query = (Get-SIPermissionNoteKql) }) -Compress) 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
        $code = 0; try { $code = [int]$r.Status } catch { $code = 0 }
        if ($code -lt 200 -or $code -ge 300) { return $no }
        $ans = [string]$r.Body | ConvertFrom-Json
        $t = @($ans.tables)[0]; if (-not $t) { return $no }
        $cols = @($t.columns | ForEach-Object { [string]$_.name })
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($row in @($t.rows)) {
            $o = [ordered]@{}; $vals = @($row)
            for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $(if ($i -lt $vals.Count) { $vals[$i] } else { $null }) }
            $rows.Add([pscustomobject]$o)
        }
        return (ConvertFrom-SIPermissionNoteRuns -Rows $rows.ToArray() -Apis $Apis -Engines $Engines -Fingerprint (Get-SIPermissionNoteFingerprint -Apis $Apis))
    } catch { return $no }
}

function Get-SIPermissionNoteMissing {
    <# PURE. The list's permissions the identity does not hold: @( @{ Resource; Role } ), in the list's order. An API in -Absent is left out. #>
    param([object[]]$Apis = @(), [hashtable]$Granted = @{}, [string[]]$Absent = @())
    foreach ($a in @($Apis)) {
        if (-not $a -or @($Absent) -contains [string]$a.ResourceAppId) { continue }
        $have = @{}
        foreach ($g in @($Granted[[string]$a.ResourceAppId])) { if ($g) { $have[([string]$g).ToLowerInvariant()] = $true } }
        foreach ($r in @($a.Roles)) { if (-not $have.ContainsKey(([string]$r).ToLowerInvariant())) { [pscustomobject]@{ Resource = [string]$a.Resource; Role = [string]$r } } }
    }
}

function Get-SIPermissionNoteCommand {
    <#
        PURE. The two lines that grant the collection identity its permissions -- download from invardia.com, then run with
        THIS install's names (the workspace, storage and data collection resource group are always given: without them the
        script plans the Azure roles on a configuration file's names). '' when a name it needs is not known here or is not a
        plain resource name (never a placeholder).
          managed identity  -> Grant-SIIdentity.ps1 -IdentityName .. -IdentityResourceGroup .. (or -PrincipalId <object id>) .. -AllowSchemaCreate -Apply
          app registration  -> Grant-SIIdentity.ps1 -AppId <client id> .. -AllowSchemaCreate -Apply (the same script, the
                               identity found by its application id -- never by its name)
    #>
    param($Identity, [string]$SubscriptionId, [string]$WorkspaceResourceId, [string]$StorageAccount, [string]$StorageResourceGroup, [string]$DcrResourceGroup)
    if (-not $Identity) { return '' }
    $ok = { param($v) $t = "$v".Trim(); [bool]($t -and (Test-SIPermissionNoteSafe -Value $t)) }
    $arg = { param($n, $v) ' -{0} {1}' -f $n, "$v".Trim() }
    $dl = { param($s) 'Invoke-WebRequest {0}{1}.ps1 -OutFile {1}.ps1' -f $script:SIPermissionNoteUrlBase, $s }
    if (-not (& $ok $SubscriptionId)) { return '' }
    if (-not (& $ok $WorkspaceResourceId)) { return '' }
    $cmd = './Grant-SIIdentity.ps1'
    if (-not $Identity.Managed) {
        if (-not (& $ok $Identity.ClientId)) { return '' }
        $cmd += (& $arg 'AppId' $Identity.ClientId)
    }
    elseif ((& $ok $Identity.IdentityName) -and (& $ok $Identity.IdentityResourceGroup)) { $cmd += (& $arg 'IdentityName' $Identity.IdentityName) + (& $arg 'IdentityResourceGroup' $Identity.IdentityResourceGroup) }
    elseif (& $ok $Identity.ObjectId) { $cmd += (& $arg 'PrincipalId' $Identity.ObjectId) }
    else { return '' }
    $cmd += (& $arg 'SubscriptionId' $SubscriptionId) + (& $arg 'WorkspaceResourceId' $WorkspaceResourceId)
    if ((& $ok $StorageAccount) -and (& $ok $StorageResourceGroup)) { $cmd += (& $arg 'StorageAccountName' $StorageAccount) + (& $arg 'StorageResourceGroup' $StorageResourceGroup) }
    if (& $ok $DcrResourceGroup) { $cmd += (& $arg 'DcrResourceGroup' $DcrResourceGroup) }
    # -AllowSchemaCreate, as the guided install grants it: an install repaired from this note must be able to create its
    # tables and rules too (a run creates them, and gives itself no role)
    (& $dl 'Grant-SIIdentity') + "`n" + $cmd + ' -AllowSchemaCreate -Apply'
}

function Get-SIPermissionNoteLines {
    <#
        PURE. The text of the note: one line per missing permission, then who grants them and the two command lines (or
        where the command is shown, when -Command is ''). @() when nothing is missing.
    #>
    param([object[]]$Missing = @(), [string]$Command, [string]$Label = "SecurityInsight's collection identity")
    $m = @($Missing | Where-Object { $_ })
    if (-not $m.Count) { return @() }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($x in $m) {
        $t = $script:SIPermissionNoteText[[string]$x.Role]
        if ($t) { $lines.Add(('permissions: {0} {1} is not granted to {2} -- it is read-only and gives {3}. Nothing breaks without it: {4}.' -f $x.Resource, $x.Role, $Label, $t.For, $t.Empty)) }
        else { $lines.Add(('permissions: {0} {1} is not granted to {2} -- it is read-only; the data it gives is not collected until it is granted.' -f $x.Resource, $x.Role, $Label)) }
    }
    $it = if ($m.Count -eq 1) { 'it' } else { 'them' }
    if ("$Command".Trim()) {
        $lines.Add(('permissions: to grant {0}, an admin who can give admin consent (Privileged Role Administrator or Global Administrator) runs these two lines in Azure Cloud Shell or PowerShell 7 -- SecurityInsight keeps running as it does today until then:' -f $it))
        foreach ($c in ("$Command" -split "`r?`n")) { if ($c.Trim()) { $lines.Add($c.Trim()) } }
    } else {
        $lines.Add(('permissions: to grant {0}, open Get Started > Permissions in the SecurityInsight web app -- it shows the two lines to run, with this install''s names filled in. SecurityInsight keeps running as it does today until then.' -f $it))
    }
    $lines.ToArray()
}

function Invoke-SIPermissionNote {
    <#
        The whole step. READ ONLY and NEVER throws.
          @{ State = granted | missing | not-checked; Source = directory | runs | ''; Missing = @( @{ Resource; Role } ); Lines = string[] }
        granted: Lines is empty (nothing is said). not-checked: ONE line saying why -- nothing is assumed.
        -Jobs: the job list the update read. -Globals: the customer's settings (a workspace / storage name set there wins
        over the job's own).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [object[]]$Jobs = @(), [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Globals = @{},
          [string]$WorkspaceResourceId, [string]$CatalogPath)
    $notChecked = { param($why) [pscustomobject]@{ State = 'not-checked'; Source = ''; Missing = @()
        Lines = @(('permissions: not checked -- {0}. Get Started > Permissions in the SecurityInsight web app shows any permission that is missing after the next collection run.' -f $why)) } }
    try {
        $cat = Get-SIPermissionNoteCatalog -Path $CatalogPath
        $id = Get-SIPermissionNoteIdentity -Jobs $Jobs -Engines $cat.Engines
        if (-not $id) { return (& $notChecked 'the identity SecurityInsight collects with could not be told from this install''s jobs') }
        $gv = { param($n) if ($Globals -and $Globals.ContainsKey($n) -and "$($Globals[$n])".Trim()) { "$($Globals[$n])".Trim() } else { '' } }
        $ws = "$WorkspaceResourceId".Trim(); if (-not $ws) { $ws = & $gv 'SI_WorkspaceResourceId' }; if (-not $ws) { $ws = $id.WorkspaceResourceId }
        $stg = & $gv 'SI_StorageAccount'; if (-not $stg) { $stg = $id.StorageAccount }
        $stgRg = & $gv 'SI_StorageResourceGroup'; if (-not $stgRg) { $stgRg = $ResourceGroup }
        $dcr = & $gv 'SI_DcrResourceGroup'; if (-not $dcr) { $dcr = $id.DcrResourceGroup }

        $source = 'directory'; $missing = @()
        $g = Get-SIPermissionNoteGranted -Rest $Rest -ObjectId $id.ObjectId -ClientId $id.ClientId -Apis $cat.Apis
        if ($g.Readable) { $missing = @(Get-SIPermissionNoteMissing -Apis $cat.Apis -Granted $g.Granted -Absent $g.Absent) }
        else {
            $source = 'runs'
            $r = Get-SIPermissionNoteFromRuns -Rest $Rest -WorkspaceResourceId $ws -Apis $cat.Apis -Engines $cat.Engines
            if (-not $r.Known) { return (& $notChecked ('{0}, and {1}' -f $g.Why, $r.Why)) }
            $missing = @($r.Missing)
        }
        if (-not $missing.Count) { return [pscustomobject]@{ State = 'granted'; Source = $source; Missing = @(); Lines = @() } }
        $cmd = Get-SIPermissionNoteCommand -Identity $id -SubscriptionId $SubscriptionId -WorkspaceResourceId $ws -StorageAccount $stg -StorageResourceGroup $stgRg -DcrResourceGroup $dcr
        $label = if ("$($cat.Label)".Trim()) { [string]$cat.Label } else { "SecurityInsight's collection identity" }
        [pscustomobject]@{ State = 'missing'; Source = $source; Missing = $missing; Lines = @(Get-SIPermissionNoteLines -Missing $missing -Command $cmd -Label $label) }
    } catch {
        & $notChecked ('the check could not run ({0})' -f $_.Exception.Message)
    }
}
