#Requires -Version 5.1
<#
    SI-DisplayNames.ps1 -- THE NAMES PEOPLE READ, at EXISTING installs too (framework DOCS/REQUIREMENTS.md section 12.11c item 5,
    SI REQUIREMENTS #655 item 5). Owner: "Short code in Azure, full name where people read"; existing installs: "if a resource
    can be renamed, we do that. if not, we keep for now, display names are updated".

    WHAT IS RENAMED (Get-SIDisplayNameRenames) -- directory objects only, and only from SecurityInsight's own earlier default:
      the web app's sign-in application (app registration + enterprise application)  "SecurityInsight Management" -> "SecurityInsight"
      SecurityInsight's engine application (app registration + enterprise application) "SecurityInsight" -> "SecurityInsight Engine"
      the SQL admin group (display name only; mailNickname grpsisqladmins kept)        "grp-si-sql-admins" -> "SecurityInsight SQL admins"
    NEVER renamed: an Azure resource (container app, job, managed identity, SQL server, Key Vault, registry -- Azure cannot), a
    name the customer chose (anything but the earlier default is left exactly as it is), the mail sender's ADDRESS and the
    Exchange scope (customers' mail rules). The mail sender's DISPLAY name has always been "SecurityInsight" (setup\Set-SIMail.ps1):
    it is read and reported, never changed.

    ORDER AND SAFETY
      * the engine application FIRST: the web app's sign-in application takes the name "SecurityInsight", which the engine's
        application carries today. While any OTHER application is still named "SecurityInsight" the sign-in application is HELD
        (one line says which application) -- two applications of one name would let a lookup by name pick the wrong one.
      * an object is identified by its id, never by its name: the sign-in application by the web app's client id
        (AzureAd__ClientId), the engine's by its client id (SI_SPN_AppId), the group as the SQL server's Entra admin (its sid).
      * each rename is read back; a rename that does not read back is PUT BACK to the earlier name, and an application whose
        enterprise application could not follow is put back too -- never half-renamed.
      * NEVER TWICE: an object renamed once is recorded (-Done: object id -> UTC); when someone named it back since, it is left.
        The update renames only where it can keep that record (the Pro database); without it, it says what it would rename.
      * THE UPDATE'S SWITCH SI_Update_RenameDisplayNames is ON by default (owner 2026-10-18: "everything that we can rename,
        must follow agreed naming. consistent"); $false keeps the update to the plan.
      * every FINDER that looked for the earlier name also finds the new one (Find-SISqlAdminGroup, Get-SIDisplayNameAliases,
        the Graph finders in SI-GraphRest.ps1, New-SIManagementAppRegistration.ps1), so a setup run after the rename never
        creates a second object -- and never names it back.

    Pure except the -Graph seam: { param([string]$Method, [string]$Uri, $Body) } -> the parsed answer; throws on a failure.
    ASCII only; PowerShell 5.1-safe.
#>

function Get-SIDisplayNameRenames {
    <# PURE. Every directory object whose display name SecurityInsight renames at an existing install, in the order they are
       renamed (the engine application before the sign-in application: see the header). #>
    [ordered]@{
        EngineApp     = [pscustomobject]@{ Role = 'EngineApp'; Kind = 'application'; Old = 'SecurityInsight'; New = 'SecurityInsight Engine'; Nick = ''
                                           What = 'SecurityInsight''s engine application' }
        WebSignInApp  = [pscustomobject]@{ Role = 'WebSignInApp'; Kind = 'application'; Old = 'SecurityInsight Management'; New = 'SecurityInsight'; Nick = ''
                                           What = 'the web app''s sign-in application' }
        SqlAdminGroup = [pscustomobject]@{ Role = 'SqlAdminGroup'; Kind = 'group'; Old = 'grp-si-sql-admins'; New = 'SecurityInsight SQL admins'; Nick = 'grpsisqladmins'
                                           What = 'the SQL admin group' }
    }
}

function Get-SIWebSignInRoleIds {
    <# PURE. The stable app role ids of the web app's sign-in application (pro-management\deploy\New-SIManagementAppRegistration.ps1):
       an application that carries one of them IS the sign-in application, whatever its name. #>
    @('5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a05', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a01', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a02',
      '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a04', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a06')
}

function Test-SIWebSignInApplication {
    <# PURE. Does this application / service principal (an object with appRoles) carry one of the sign-in application's role ids? #>
    param([AllowNull()]$Object)
    if ($null -eq $Object -or -not $Object.PSObject.Properties['appRoles']) { return $false }
    $ids = Get-SIWebSignInRoleIds
    [bool]@(@($Object.appRoles) | Where-Object { $_ -and $_.PSObject.Properties['id'] -and $ids -contains [string]$_.id }).Count
}

function Get-SIDisplayNameAliases {
    <# PURE. Every display name the object of -Role may carry, the name asked for first: today's earlier default and the new
       one. -Name: the name a caller looks for (a customer's own name has no aliases: just itself). #>
    param([Parameter(Mandatory)][ValidateSet('EngineApp', 'WebSignInApp', 'SqlAdminGroup')][string]$Role, [AllowEmptyString()][string]$Name = '')
    $r = (Get-SIDisplayNameRenames)[$Role]
    $n = "$Name".Trim()
    if ($n -and $n -cne $r.Old -and $n -cne $r.New) { return @($n) }
    if ($n -ceq $r.New) { return @($r.New, $r.Old) }
    @($r.Old, $r.New)
}

function Test-SIDisplayNameRenameOn {
    <#
        PURE. Is SI_Update_RenameDisplayNames ON for this install? ON BY DEFAULT (owner 2026-10-18: "everything that we can
        rename, must follow agreed naming. consistent" -- every existing install reaches the names a new install gets). Only
        an explicit 'false' / '0' / 'no' / 'off' (a JSON value of the Pro database may carry quotes) turns it off; not set,
        empty or anything else is on. From -Values (the install's Pro setting / config), else -Env (default: the process --
        the updater job's variable). Off: the update says what it WOULD rename, one line each, and changes nothing;
        setup\Set-SIDisplayNames.ps1 -Apply (an administrator) renames regardless.
    #>
    param([System.Collections.IDictionary]$Values, [System.Collections.IDictionary]$Env)
    $name = 'SI_Update_RenameDisplayNames'
    $v = $null
    if ($Values -and $Values.Contains($name)) { $v = $Values[$name] }
    if ($null -eq $v -or "$v".Trim() -eq '') { $v = if ($Env) { if ($Env.Contains($name)) { $Env[$name] } else { $null } } else { [Environment]::GetEnvironmentVariable($name) } }
    if ($v -is [bool]) { return [bool]$v }
    -not ("$v".Trim().Trim('"').Trim('$').Trim() -match '^(?i)(false|0|no|off)$')
}

function Get-SIDisplayNameSettingSql {
    <# PURE. The Pro database's value of SI_Update_RenameDisplayNames (the web app's Settings page; solution scope): one
       ValueJson, or no row (not set = the default, on). #>
    "IF OBJECT_ID('cfg.Setting') IS NOT NULL SELECT ValueJson FROM cfg.Setting WHERE Name = N'SI_Update_RenameDisplayNames' AND Scope = N'solution';"
}

function Get-SIDisplayNameProp {
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    $null
}

function Get-SISqlAdminGroupFilter {
    <# PURE. The Graph $filter that finds the SQL admin group -GroupName under ANY of its names: the name asked for, the other
       of SecurityInsight's two display names, and its mailNickname (which never changes). A customer's own group: its name only. #>
    param([AllowEmptyString()][string]$GroupName = 'grp-si-sql-admins')
    # SI #750 (2026-10-27): a Community edition install's own group (setup\_shared\SI-SetupNaming.ps1, side by side with a Pro
    # install in the same tenant) is found under ITS two names and its mailNickname -- never under the Pro group's names
    $c = Get-SICommunitySqlAdminGroupNames
    if ("$GroupName".Trim() -ceq $c.Old -or "$GroupName".Trim() -ceq $c.New) {
        return (@(("displayName eq '{0}'" -f $c.Old), ("displayName eq '{0}'" -f $c.New), ("mailNickname eq '{0}'" -f $c.Nick)) -join ' or ')
    }
    $r = (Get-SIDisplayNameRenames)['SqlAdminGroup']
    $names = @(Get-SIDisplayNameAliases -Role SqlAdminGroup -Name $GroupName)
    $parts = @($names | ForEach-Object { "displayName eq '{0}'" -f $_.Replace("'", "''") })
    if ($names -ccontains $r.Old) { $parts += ("mailNickname eq '{0}'" -f $r.Nick) }
    $parts -join ' or '
}

function Get-SICommunitySqlAdminGroupNames {
    <# PURE. The Community edition install's SQL admin group (SI #750, side by side with a Pro install in one tenant): the name it
       is created and looked up by, the name people read, and its mailNickname (Set-SISqlAdminGroup.ps1: -GroupName without
       its separators). Not renamed by the update: it has had its final display name from the start. #>
    [pscustomobject]@{ Old = 'grp-si-community-sql-admins'; New = 'SecurityInsight Community SQL admins'; Nick = 'grpsicommunitysqladmins' }
}

function Find-SISqlAdminGroup {
    <#
        The SQL admin group by any of its names (Get-SISqlAdminGroupFilter), never by one display name only -- once renamed,
        a lookup of "grp-si-sql-admins" alone would find nothing and a setup run would create a SECOND group. Returns
        @{ Group (@{ Id; DisplayName; MailNickname; IsAssignableToRole; SecurityEnabled }, or $null); Count; Ids }.
        More than one group: Group $null, Count > 1 (the caller refuses). Throws when the directory cannot be read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$GroupName = 'grp-si-sql-admins')
    $f = [uri]::EscapeDataString((Get-SISqlAdminGroupFilter -GroupName $GroupName))
    $r = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/groups?`$filter=$f&`$select=id,displayName,mailNickname,securityEnabled,isAssignableToRole") $null
    $seen = @{}; $list = New-Object System.Collections.Generic.List[object]
    foreach ($g in @(Get-SIDisplayNameProp $r 'value')) {
        if (-not $g) { continue }
        $id = [string](Get-SIDisplayNameProp $g 'id'); if (-not $id -or $seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $list.Add([pscustomobject]@{ Id = $id; DisplayName = [string](Get-SIDisplayNameProp $g 'displayName'); MailNickname = [string](Get-SIDisplayNameProp $g 'mailNickname')
                                     IsAssignableToRole = [bool](Get-SIDisplayNameProp $g 'isAssignableToRole'); SecurityEnabled = [bool](Get-SIDisplayNameProp $g 'securityEnabled') })
    }
    [pscustomobject]@{ Group = $(if ($list.Count -eq 1) { $list[0] } else { $null }); Count = $list.Count; Ids = @($list | ForEach-Object { $_.Id }) }
}

function Get-SIDisplayNameErrorKind {
    <# PURE. 'rights' when a failed Graph call was a refusal (403 / Authorization_RequestDenied / insufficient privileges), else 'error'. #>
    param([AllowEmptyString()][string]$Text)
    if ("$Text" -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden') { 'rights' } else { 'error' }
}

function Get-SIDisplayNameRightsText {
    <# PURE. The rights a rename of -Kind needs, in one plain sentence. #>
    param([Parameter(Mandatory)][ValidateSet('application', 'group')][string]$Kind)
    if ($Kind -eq 'application') { return 'an owner of the application, or Application Administrator / Cloud Application Administrator (a person), or Microsoft Graph Application.ReadWrite.All (an app)' }
    'Privileged Role Administrator (a person: the group is role-assignable), or Microsoft Graph Group.ReadWrite.All with RoleManagement.ReadWrite.Directory (an app)'
}

function Get-SIDisplayNamePlan {
    <#
        READ ONLY. What would be renamed at this install: one item per object SecurityInsight can identify --
          @{ Role; Kind; What; Id (object id); AppId; SpId; SpName; Old; New; Current; Action; Line }
        Action: rename | present (already the new name) | kept (a name of the customer's own, or named back after an earlier
        rename -- never twice) | held (another application already carries the new name) | not-found | unchecked (could not
        be read). -WebAppId / -EngineAppId: client ids ('' = not known, no item); -SqlAdminSid: the SQL server's Entra admin
        ('' = no item). -Done: object id -> UTC of an earlier rename by SecurityInsight (the install's record).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$WebAppId = '', [AllowEmptyString()][string]$EngineAppId = '',
          [AllowEmptyString()][string]$SqlAdminSid = '', [hashtable]$Done = @{})
    $map = Get-SIDisplayNameRenames
    $items = New-Object System.Collections.Generic.List[object]
    $new = { param($r) [pscustomobject]@{ Role = $r.Role; Kind = $r.Kind; What = $r.What; Id = ''; AppId = ''; SpId = ''; SpName = ''; Old = $r.Old; New = $r.New; Current = ''; Action = ''; Line = '' } }
    $decide = {
        param($it)
        if ($it.Current -ceq $it.New) { $it.Action = 'present'; $it.Line = ('{0} is already named "{1}"' -f $it.What, $it.New); return }
        if ($it.Current -cne $it.Old) { $it.Action = 'kept'; $it.Line = ('{0} is named "{1}" (not SecurityInsight''s earlier name) -- kept as it is' -f $it.What, $it.Current); return }
        if ($it.Id -and $Done.ContainsKey($it.Id)) { $it.Action = 'kept'; $it.Line = ('{0} was renamed to "{1}" on {2} and has been named "{3}" again since -- left as it is (never renamed twice)' -f $it.What, $it.New, $Done[$it.Id], $it.Old); return }
        $it.Action = 'rename'; $it.Line = ('{0}: "{1}" -> "{2}"' -f $it.What, $it.Old, $it.New)
    }
    $readApp = {
        param($r, [string]$appId)
        $it = & $new $r; $it.AppId = $appId
        try {
            $a = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications(appId='{0}')?`$select=id,appId,displayName" -f $appId) $null
            if (-not $a -or -not [string](Get-SIDisplayNameProp $a 'id')) { $it.Action = 'not-found'; $it.Line = ('{0} (client id {1}) was not found -- nothing to rename' -f $it.What, $appId); return $it }
            $it.Id = [string](Get-SIDisplayNameProp $a 'id'); $it.Current = [string](Get-SIDisplayNameProp $a 'displayName')
            try {
                $s = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName" -f $appId) $null
                $sp = @(Get-SIDisplayNameProp $s 'value' | Where-Object { $_ })[0]
                if ($sp) { $it.SpId = [string](Get-SIDisplayNameProp $sp 'id'); $it.SpName = [string](Get-SIDisplayNameProp $sp 'displayName') }
            } catch { }
            & $decide $it
        } catch {
            $it.Action = 'unchecked'
            $it.Line = ('{0} (client id {1}) could not be read ({2}) -- not renamed' -f $it.What, $appId, $(if ((Get-SIDisplayNameErrorKind $_.Exception.Message) -eq 'rights') { 'this identity may not read applications' } else { $_.Exception.Message }))
        }
        $it
    }
    $engine = $null
    if ("$EngineAppId".Trim()) { $engine = & $readApp $map['EngineApp'] "$EngineAppId".Trim(); $items.Add($engine) }
    if ("$WebAppId".Trim()) {
        $web = & $readApp $map['WebSignInApp'] "$WebAppId".Trim()
        if ($web.Action -eq 'rename') {
            # another application already named "SecurityInsight" (not this one, not the engine's about to be renamed): HELD
            try {
                $f = [uri]::EscapeDataString(("displayName eq '{0}'" -f $web.New))
                $same = @(Get-SIDisplayNameProp (& $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications?`$filter=$f&`$select=id,appId,displayName") $null) 'value' | Where-Object { $_ })
                $others = @($same | Where-Object { [string](Get-SIDisplayNameProp $_ 'appId') -ine $web.AppId -and -not ($engine -and $engine.Action -eq 'rename' -and [string](Get-SIDisplayNameProp $_ 'appId') -ieq $engine.AppId) })
                if ($others.Count) {
                    $web.Action = 'held'
                    $web.Line = ('{0} is NOT renamed to "{1}": another application already has that name (client id {2}) -- rename that one first (setup\Set-SIDisplayNames.ps1 -EngineAppId <its client id>), or give it a name of your own' -f $web.What, $web.New, ((@($others | ForEach-Object { [string](Get-SIDisplayNameProp $_ 'appId') })) -join ', '))
                }
            } catch {
                $web.Action = 'unchecked'; $web.Line = ('{0}: whether another application is already named "{1}" could not be read ({2}) -- not renamed' -f $web.What, $web.New, $_.Exception.Message)
            }
        }
        $items.Add($web)
    }
    if ("$SqlAdminSid".Trim()) {
        $r = $map['SqlAdminGroup']; $it = & $new $r
        try {
            $g = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/groups/{0}?`$select=id,displayName,mailNickname" -f "$SqlAdminSid".Trim()) $null
            if (-not $g -or -not [string](Get-SIDisplayNameProp $g 'id')) { $it.Action = 'not-found'; $it.Line = 'the SQL server''s Entra admin is not a group -- no admin group to rename' }
            else {
                $it.Id = [string](Get-SIDisplayNameProp $g 'id'); $it.Current = [string](Get-SIDisplayNameProp $g 'displayName')
                $nick = [string](Get-SIDisplayNameProp $g 'mailNickname')
                # only SecurityInsight's own group (its mailNickname, or one of its two names): a customer's own admin group is never touched
                if ($nick -cne $r.Nick -and $it.Current -cne $r.Old -and $it.Current -cne $r.New) { $it.Action = 'kept'; $it.Line = ('the SQL server''s admin group is "{0}", a group of your own -- kept as it is' -f $it.Current) }
                else { & $decide $it }
            }
        } catch {
            # a 404 = the admin is not a group (a person, an application)
            if ("$($_.Exception.Message)" -match '(?i)\b404\b|Request_ResourceNotFound|does not exist') { $it.Action = 'not-found'; $it.Line = 'the SQL server''s Entra admin is not a group -- no admin group to rename' }
            else { $it.Action = 'unchecked'; $it.Line = ('the SQL admin group could not be read ({0}) -- not renamed' -f $(if ((Get-SIDisplayNameErrorKind $_.Exception.Message) -eq 'rights') { 'this identity may not read groups' } else { $_.Exception.Message })) }
        }
        $items.Add($it)
    }
    # one item per object, enumerated (callers wrap the call in @())
    $items.ToArray()
}

function Set-SIDisplayNameOnObject {
    <# One PATCH of displayName on -Path (applications/<id>, servicePrincipals/<id>, groups/<id>), then READ BACK (a few tries:
       the directory replicates). $true = it reads back as -Name. Throws when the PATCH is refused. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [scriptblock]$Sleep, [int[]]$Waits = @(0, 5, 10, 20))
    $null = & $Graph 'PATCH' ("https://graph.microsoft.com/v1.0/{0}" -f $Path) (@{ displayName = $Name } | ConvertTo-Json -Compress)
    foreach ($w in $Waits) {
        if ($w) { if ($Sleep) { & $Sleep $w } else { Start-Sleep -Seconds $w } }
        try { $b = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/{0}?`$select=id,displayName" -f $Path) $null; if ([string](Get-SIDisplayNameProp $b 'displayName') -ceq $Name) { return $true } } catch { }
    }
    $false
}

function Invoke-SIDisplayNameRenames {
    <#
        THE RENAME, item by item (the plan of Get-SIDisplayNamePlan, in its order). Only items with Action 'rename', only with
        -Apply. An application: the app registration, then its enterprise application (when it carries the earlier name); a
        group: its display name (mailNickname never). Each change READ BACK; a change that does not read back -- or an
        application whose enterprise application could not follow -- is PUT BACK to the earlier name and read back again.
        A refusal names the rights it needs and the setup script that does it. Never throws.
        Returns @{ Items (each + State: renamed | planned | failed | no-rights | put-back-failed, and Line); Lines; Done
        (object id -> UTC for what was renamed now); Renamed (count) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyCollection()][object[]]$Plan = @(), [switch]$Apply, [scriptblock]$Sleep,
          [string]$SetupCommand = '.\setup\Set-SIDisplayNames.ps1 -Apply', [datetime]$NowUtc = [datetime]::UtcNow)
    $lines = New-Object System.Collections.Generic.List[string]; $done = @{}; $n = 0
    $stamp = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $out = foreach ($it in @($Plan)) {
        if (-not $it) { continue }
        $o = [pscustomobject]@{ Role = $it.Role; Kind = $it.Kind; Id = $it.Id; Old = $it.Old; New = $it.New; Action = $it.Action; State = $it.Action; Line = $it.Line }
        if ($it.Action -ne 'rename') { $o; continue }
        if (-not $Apply) { $o.State = 'planned'; $o.Line = 'would rename ' + $it.Line; $lines.Add($o.Line); $o; continue }
        $root = if ($it.Kind -eq 'application') { 'applications/' + $it.Id } else { 'groups/' + $it.Id }
        $changed = @()
        try {
            if (-not (Set-SIDisplayNameOnObject -Graph $Graph -Path $root -Name $it.New -Sleep $Sleep)) { $changed += $root; throw 'it did not read back under the new name' }
            $changed += $root
            if ($it.Kind -eq 'application' -and $it.SpId -and $it.SpName -ceq $it.Old) {
                $spPath = 'servicePrincipals/' + $it.SpId
                if (-not (Set-SIDisplayNameOnObject -Graph $Graph -Path $spPath -Name $it.New -Sleep $Sleep)) { $changed += $spPath; throw 'its enterprise application did not read back under the new name' }
                $changed += $spPath
            }
            $o.State = 'renamed'; $o.Line = 'renamed ' + $it.Line + ', read back'; $done[$it.Id] = $stamp; $n++
        } catch {
            $why = [string]$_.Exception.Message
            $kind = Get-SIDisplayNameErrorKind $why
            # PUT BACK: everything this item changed returns to the earlier name (never half-renamed)
            $back = $true
            foreach ($p in @($changed)) { try { if (-not (Set-SIDisplayNameOnObject -Graph $Graph -Path $p -Name $it.Old -Sleep $Sleep)) { $back = $false } } catch { $back = $false } }
            if (-not $back) { $o.State = 'put-back-failed'; $o.Line = ('{0} could NOT be renamed ({1}) and could not be put back to "{2}" either -- check it in the Entra admin center' -f $it.What, $why, $it.Old) }
            elseif ($kind -eq 'rights') { $o.State = 'no-rights'; $o.Line = ('{0} is NOT renamed: this identity may not change it. It needs {1}. An administrator renames it with: {2}' -f $it.What, (Get-SIDisplayNameRightsText -Kind $it.Kind), $SetupCommand) }
            else { $o.State = 'failed'; $o.Line = ('{0} is NOT renamed ({1}){2}' -f $it.What, $why, $(if (@($changed).Count) { ' -- put back to "' + $it.Old + '"' } else { '' })) }
        }
        $lines.Add($o.Line)
        $o
    }
    [pscustomobject]@{ Items = @($out); Lines = $lines.ToArray(); Done = $done; Renamed = $n }
}

function ConvertFrom-SIDisplayNamesRecord {
    <# PURE. The record cfg.InstallState 'DisplayNames' (compact JSON: object id -> UTC) as a hashtable; empty when none / not JSON. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $h = @{}
    if (-not "$Value".Trim()) { return $h }
    try { $o = "$Value" | ConvertFrom-Json -ErrorAction Stop } catch { return $h }
    # PowerShell 7's ConvertFrom-Json turns an ISO date string into a [datetime]: written back as the same UTC text
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $o.PSObject.Properties) {
            $val = if ($p.Value -is [datetime]) { $p.Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { "$($p.Value)".Trim() }
            if ($val) { $h[$p.Name] = $val }
        }
    }
    $h
}

function Get-SIDisplayNamesRecordSql {
    <# PURE. -Read: the stored record (one value or no row); else the upsert of @Value (the whole record) by @By. #>
    param([switch]$Read)
    if ($Read) { return "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'DisplayNames';" }
    @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'DisplayNames')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'DisplayNames';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'DisplayNames', @Value, NULL, @By);
    COMMIT;
END
'@
}

function Merge-SIDisplayNamesRecord {
    <# PURE. -Current (the record) with -Done (what was renamed now) added; an id renamed before keeps its first date. Compact JSON. #>
    param([hashtable]$Current = @{}, [hashtable]$Done = @{})
    $m = [ordered]@{}
    foreach ($k in @($Current.Keys | Sort-Object)) { $m[$k] = $Current[$k] }
    foreach ($k in @($Done.Keys | Sort-Object)) { if (-not $m.Contains($k)) { $m[$k] = $Done[$k] } }
    $m | ConvertTo-Json -Compress
}
