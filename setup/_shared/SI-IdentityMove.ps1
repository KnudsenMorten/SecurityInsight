#Requires -Version 5.1
<#
    SecurityInsight -- THE IDENTITY MOVE (framework §5.5 names; framework section 12.11c "THE IDENTITY MOVE", checklist NAM-03;
    owner 2026-11-04: every identity at every install carries its standard name id-si-<role>). ONE library, two callers:
      * THE PRODUCT STEP: the updater, on every run (setup\_shared\SI-IdentityNamesStep.ps1, step 'identity-names'), as its
        OWN identity -- Ctx.Mode 'updater'. What it may not read or grant is a SUPPORT STEP (the role waits; nothing is lost);
        its SQL goes through the database setup job caj-si-dbinit (Ctx.SqlVia 'dbjob'), which is the SQL admin;
      * THE SUPPORT STEP: ops\identity-move\Move-SIIdentity.ps1 through the Invardia Support app (Ctx.Mode 'support', the
        default), for the rights only it may read and grant. Both write the SAME state rows (cfg.InstallState
        'IdentityMove.<role>'), so either one carries on where the other stopped.
    Functions only.

    Azure cannot rename a user-assigned managed identity (its name is the resource name). So one role at one install moves
    to its standard identity in the framework's SEVEN steps, each idempotent, PLAN unless -Apply, every write read back:
      1 inventory    the role's identity in use and ALL its rights: Azure role assignments (any scope, management group and
                     tenant root included), Graph app roles, Entra directory roles, federated credentials that trust it,
                     the SQL contained user + its roles and grants (every SI database), Key Vault (RBAC = Azure roles;
                     access policies otherwise), registry pull (AcrPull = an Azure role; the apps' registry identity),
                     Exchange (the shared mailbox's Application Mail.Send) when mail is on
      2 ensure       id-si-<role> (user-assigned, the install's resource group, the old identity's location and tags)
      3 copy-rights  exactly the old identity's rights; what the caller may not grant is a CUSTOMER STEP (support mode) or a
                     SUPPORT STEP (updater mode), and the role waits for it
      4 switch       attach the new identity to every app / job of the role (the old one stays attached: rollback = this
                     step reversed), point every client-id / resource-id / name reference at it (environment, Key Vault
                     secret references, registry identity, scale rules, SI settings, the install's names record); never
                     while an execution of that job or a pipeline run is going
      5 prove        the next REAL run of each re-pointed job succeeds on the new identity (an execution started after the
                     switch whose template names the new client id; the Entra managed-identity sign-in log with the new
                     object id when it may be read); a web / MCP app: a healthy revision made after the switch; the updater
                     itself: an update that signed in AS the new identity. A run that did not succeed is blamed on the new
                     identity only when the pipeline recorded a refused right or sign-in for it; anything else waits
      6 clean-up     only after EVERY role at the install is proven: the old identity's rights removed (its SQL user only
                     after the new one reads back holding all of it), it is detached everywhere, the old identity deleted;
                     the updater's own old identity only by an update that runs as the new one
      7 report       the setup step identity-names (cfg.InstallState 'IdentityNames', read by the heartbeat:
                     engine\_shared\SI-SetupSteps.ps1) per role: name, kind, object id, state

    I/O: thin seams (Invoke-SIMoveArm / -Graph / -Sql / -Sleep / -DbJob). Support mode = the Invardia Support app
    (handed in by the vendor command through Set-SIIdentityMoveIo) with -Reason, so every call is in
    the customer's audit log; updater mode = the scriptblocks Set-SIIdentityMoveIo hands in. NO PowerShell modules.
    PURE planners (Get-/Select-/Update-/Find-/Test-/ConvertTo-SIIdentityMove*) + the seams, which the tests replace.
#>

$script:SIMoveRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. ([IO.Path]::Combine($script:SIMoveRoot, 'setup', '_shared', 'SI-IdentityMoveSql.ps1'))
. ([IO.Path]::Combine($script:SIMoveRoot, 'setup', '_shared', 'SI-SetupNaming.ps1'))
. ([IO.Path]::Combine($script:SIMoveRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
. ([IO.Path]::Combine($script:SIMoveRoot, 'engine', '_shared', 'SI-InstallNames.ps1'))
. ([IO.Path]::Combine($script:SIMoveRoot, 'engine', '_shared', 'SI-SetupSteps.ps1'))
# the sign-in app's federated credential (the web identity) -- the updater image carries this one file (container\updater\Dockerfile)
$siMoveFic = [IO.Path]::Combine($script:SIMoveRoot, 'pro-management', 'deploy', 'SI-ManagementSignInCredential.ps1')
if (Test-Path -LiteralPath $siMoveFic) { . $siMoveFic }
# Set-SIProSetting (the settings write with its cfg.ChangeLog row) and the settings catalog -- a full SecurityInsight folder
# (the Support route); the updater image has no settings layer: its settings write is Set-SIMoveSetting's store path
$siMoveSet = [IO.Path]::Combine($script:SIMoveRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1')
if ((Test-Path -LiteralPath $siMoveSet) -and (Test-Path -LiteralPath ([IO.Path]::Combine($script:SIMoveRoot, 'config', 'settings.catalog.locked.json')))) { . $siMoveSet }
$script:SIMove = @{
    Steps        = @('inventory', 'ensure', 'copy-rights', 'switch', 'prove', 'clean-up', 'report')
    RoleApi      = '2022-04-01'
    MiApi        = '2023-01-31'
    AppApi       = '2025-07-01'
    KvApi        = '2023-07-01'
    SqlApi       = '2021-11-01'
    MgApi        = '2021-04-01'
    ResApi       = '2021-04-01'
    Graph        = 'https://graph.microsoft.com/v1.0'
    GraphBeta    = 'https://graph.microsoft.com/beta'
    ProDatabase  = 'sqldb-si-pro'
    StateName    = 'IdentityMove'
    ReportName   = 'IdentityNames'
    InstallStateMax = 400
    ChangedBy    = 'Invardia Support (identity move)'
    ExecDone     = @('Succeeded', 'Failed', 'Stopped', 'Degraded')
    # the pipeline's error classes (engine\_shared\SI-ErrorClass.ps1) that mean a right or a sign-in was refused
    RightsErrorClasses = @('graph-401', 'graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'sql-login', 'mi-unavailable')
    NameRx       = '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$'
    GuidRx       = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    Waits        = @{ Tries = 6; Seconds = 10; ProvisionTries = 60 }
}

# =====================================================================================================================
#  ROLES -- the standard names come from SI's naming code, never a second list
# =====================================================================================================================

function Get-SIIdentityMoveRoleTable {
    <# PURE. Per role: Standard (the CR5 name), Old (today's names, SI-InstallNames), OldPattern (the engine's id-si-<label>),
       RecordKey (the install-names record's role, '' = none), MailSender (the role SENDS shared-mailbox mail in SI's code,
       per the approved rights list setup\_shared\si-identity-rights.json: the engine -- SI-MailTransport -- and the updater
       -- its licence notice; NOT the web app, which sends no mail itself: its mail goes through the engine's mail job --
       live 2026-11-09 a web move was held for an Exchange right the web app never uses). #>
    $new = Get-SISetupComponentNames -New
    $old = Get-SIInstallNameDefaults
    [ordered]@{
        # the engine: SI-SetupNaming's ManagedIdentity with -NewNames ('id-si-engine', no ring in the name); today
        # id-si-<ring>-<edition>-<hosting>, and 'uami-securityinsight' on the oldest installs
        engine  = @{ Standard = 'id-si-engine'; Old = @('uami-securityinsight'); OldPattern = '^id-si-(r0|r1|r2|prod)-(community|pro)-(ca|vm)$'; RecordKey = ''; MailSender = $true }
        web     = @{ Standard = [string]$new.WebIdentity;     Old = @([string]$old.webIdentity);     OldPattern = ''; RecordKey = 'webIdentity';     MailSender = $false }
        mcp     = @{ Standard = [string]$new.McpIdentity;     Old = @([string]$old.mcpIdentity);     OldPattern = ''; RecordKey = 'mcpIdentity';     MailSender = $false }
        updater = @{ Standard = [string]$new.UpdaterIdentity; Old = @([string]$old.updaterIdentity); OldPattern = ''; RecordKey = 'updaterIdentity'; MailSender = $true }
        tagging = @{ Standard = [string]$new.TaggingIdentity; Old = @([string]$old.taggingIdentity); OldPattern = ''; RecordKey = 'taggingIdentity'; MailSender = $false }
    }
}

function Get-SIIdentityMoveSteps { @($script:SIMove.Steps) }

function Get-SIIdentityMoveStepOrder {
    <# PURE. The steps one invocation runs: one, or every step in the framework's order ('all'). #>
    param([Parameter(Mandatory)][string]$Step)
    if ($Step -eq 'all') { return @($script:SIMove.Steps) }
    if ($script:SIMove.Steps -notcontains $Step) { throw "Unknown step '$Step' (known: all, $($script:SIMove.Steps -join ', '))" }
    @($Step)
}

# =====================================================================================================================
#  SMALL PURE HELPERS
# =====================================================================================================================

function Get-SIMoveProp {
    <# PURE. A nested property of an object or dictionary; $null when a step is missing. #>
    param($Object, [string[]]$Path)
    Get-SISetupArmProp $Object $Path
}

function ConvertTo-SIMoveSqlDeclare {
    <# PURE. A statement's parameters as DECLAREs in front of it (the Support app's SQL call sends text only). #>
    param([System.Collections.IDictionary]$Params)
    $sb = New-Object System.Text.StringBuilder
    if ($Params) {
        foreach ($k in @($Params.Keys)) {
            if ([string]$k -notmatch '^[A-Za-z][A-Za-z0-9_]{0,63}$') { throw "Not a parameter name: '$k'" }
            [void]$sb.AppendLine(('DECLARE @{0} nvarchar(max) = {1};' -f $k, (ConvertTo-SIMoveSqlText $Params[$k])))
        }
    }
    $sb.ToString()
}

function Test-SIIdentityMoveSameScope {
    <# PURE. Two Azure scopes are the same (case-insensitive, trailing '/' ignored; '' = the tenant root '/'). #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $x = "$A".Trim().TrimEnd('/'); $y = "$B".Trim().TrimEnd('/')
    $x -ieq $y
}

function Get-SIIdentityMoveGuidTail {
    <# PURE. The last path segment (a role definition's GUID), lower case. #>
    param([AllowEmptyString()][string]$Id)
    ("$Id".TrimEnd('/') -split '/')[-1].ToLowerInvariant()
}

function New-SIIdentityMoveCustomerStep {
    <# PURE. A customer step: TWO lines (what, and where an admin does it) -- one mail per customer via Invardia. #>
    param([Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][string]$How, [string]$Key = '')
    # updater mode: what the update may not grant is NOT a customer action (Invardia ruling 2026-11-07, as #1144): it is a
    # SUPPORT STEP -- the same move run through the Invardia Support app, per install, with a reason; the role waits for it
    if ($script:SIMoveHandsOff) {
        # Invardia ruling 2026-11-07: the Support app's runs are RECORDED and BUNDLED per install -- ONE copy run for every role
        # before the updater switches anything, ONE clean-up run for every role after the proof
        $How = if ($Kind -eq 'sql-admin-group') { 'Invardia support, through the Support app: Move-SIIdentity -Step sql-admin-group -Apply (renames the group in place and the SQL server''s admin login, read back); the next update reads it.' }
               elseif ($Kind -like '*cleanup*' -or $Kind -like 'cleanup*') { 'Invardia support, through the Support app: Move-SIIdentity -Step clean-up -AllRoles -Apply (one recorded run for every role, after the proof); the next update carries on.' }
               else { 'Invardia support, through the Support app: Move-SIIdentity -Step copy-rights -AllRoles -Apply (one recorded run for every role, before the update switches anything); the next update carries on.' }
    }
    [pscustomobject]@{ Role = $Role; Kind = $Kind; Key = $(if ($Key) { $Key } else { $Kind }); What = $What; How = $How; Support = [bool]$script:SIMoveHandsOff }
}

function New-SIIdentityMoveStepResult {
    <# PURE. One step's outcome. State: done | planned | waits | customer | stop | n/a. #>
    param([Parameter(Mandatory)][string]$Step, [Parameter(Mandatory)][ValidateSet('done', 'planned', 'waits', 'customer', 'stop', 'n/a')][string]$State,
          [string[]]$Lines = @(), [object[]]$CustomerSteps = @(), $Data = $null)
    [pscustomobject]@{ Step = $Step; State = $State; Lines = @($Lines | Where-Object { $_ }); CustomerSteps = @($CustomerSteps | Where-Object { $_ }); Data = $Data }
}

function Test-SIIdentityMoveHold {
    <# PURE. Is -Handle on SI's hold list? $null list (none could be read) = held (fail closed: switch / clean-up refuse). #>
    param([Parameter(Mandatory)][string]$Handle, [AllowNull()][string[]]$HoldHandles)
    if ($null -eq $HoldHandles) { return $true }
    [bool](@($HoldHandles | Where-Object { "$_".Trim() -ieq $Handle.Trim() }).Count)
}

function Read-SIIdentityMoveHoldList {
    <# The hold list: -HoldHandles when given, else one handle per line from -HoldFile (# = comment). $null when neither
       answers (the caller then refuses switch and clean-up). The handles never live in the repository (no customer names). #>
    param([string[]]$HoldHandles, [string]$HoldFile)
    if ($PSBoundParameters.ContainsKey('HoldHandles') -and $null -ne $HoldHandles) { return @($HoldHandles | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    if ($HoldFile -and (Test-Path -LiteralPath $HoldFile)) {
        return @(Get-Content -LiteralPath $HoldFile | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
    }
    $null
}

# =====================================================================================================================
#  STEP 1 HELPERS -- which identity is the role's, and who uses it (PURE)
# =====================================================================================================================

function ConvertTo-SIIdentityMoveIdentity {
    <# PURE. An ARM userAssignedIdentities item as @{ Name; Id; ClientId; PrincipalId; Location; Tags }. #>
    param($Item)
    if ($null -eq $Item) { return $null }
    [pscustomobject]@{
        Name = [string](Get-SIMoveProp $Item @('name')); Id = [string](Get-SIMoveProp $Item @('id'))
        ClientId = ([string](Get-SIMoveProp $Item @('properties', 'clientId'))).ToLowerInvariant()
        PrincipalId = ([string](Get-SIMoveProp $Item @('properties', 'principalId'))).ToLowerInvariant()
        Location = [string](Get-SIMoveProp $Item @('location')); Tags = (Get-SIMoveProp $Item @('tags'))
    }
}

function Select-SIIdentityMoveIdentities {
    <#
        PURE. The role's OLD identity and its standard (NEW) one among -Identities (ConvertTo-SIIdentityMoveIdentity).
        -OldName overrides the old candidates. State:
          move       an old identity exists (the move has work to do, or is part-way)
          done       only the standard identity exists (nothing to move)
          none       neither exists (the role is not at this install, e.g. no asset tagging)
          ambiguous  more than one old candidate -- name it with -OldName
    #>
    param([object[]]$Identities = @(), [Parameter(Mandatory)][string]$Role, [string]$OldName)
    $def = (Get-SIIdentityMoveRoleTable)[$Role]
    if (-not $def) { throw "Unknown role '$Role'" }
    $ids = @($Identities | Where-Object { $_ -and $_.Name })
    $new = @($ids | Where-Object { $_.Name -ieq $def.Standard })[0]
    if ($OldName) {
        if ($OldName -ieq $def.Standard) { $cands = @() } else { $cands = @($ids | Where-Object { $_.Name -ieq $OldName }) }
    } else {
        $cands = @($ids | Where-Object { $n = $_.Name; (@($def.Old | Where-Object { $_ -ieq $n }).Count) -or ($def.OldPattern -and $n -match $def.OldPattern) })
    }
    $state = if ($cands.Count -gt 1) { 'ambiguous' } elseif ($cands.Count -eq 1) { 'move' } elseif ($new) { 'done' } else { 'none' }
    $why = switch ($state) {
        'ambiguous' { 'more than one old identity of the {0} role: {1} -- name the one in use with -OldName' -f $Role, (($cands | ForEach-Object Name) -join ', ') }
        'move'      { '{0} -> {1}' -f $cands[0].Name, $def.Standard }
        'done'      { 'only {0} exists: nothing to move' -f $def.Standard }
        'none'      { $(if ($OldName) { 'no identity {0} in the resource group' -f $OldName } else { 'the {0} role has no identity at this install' -f $Role }) }
    }
    [pscustomobject]@{ Role = $Role; Standard = $def.Standard; Old = $(if ($state -eq 'move') { $cands[0] } else { $null }); New = $new; State = $state; Why = $why }
}

function Get-SIIdentityMoveUsers {
    <# PURE. The apps / jobs (-Resources: ARM objects of Microsoft.App/containerApps and Microsoft.App/jobs) that carry one of
       -IdentityIds (resource ids). Returns @{ Kind app|job; Name; Id; HasIds (which of the ids, lower case); Resource }. #>
    param([object[]]$Resources = @(), [string[]]$IdentityIds = @())
    $want = @($IdentityIds | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    foreach ($r in @($Resources | Where-Object { $_ })) {
        $ua = Get-SIMoveProp $r @('identity', 'userAssignedIdentities')
        if ($null -eq $ua) { continue }
        $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object Name) }
        $has = @($keys | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $want -contains $_ })
        if (-not $has.Count) { continue }
        $type = [string](Get-SIMoveProp $r @('type'))
        [pscustomobject]@{ Kind = $(if ($type -match '(?i)/jobs$') { 'job' } else { 'app' }); Name = [string]$r.name; Id = [string]$r.id; HasIds = $has; Resource = $r }
    }
}

function Get-SIIdentityMoveReferenceMap {
    <# PURE. old value (lower case) -> new value: the client id, the object (principal) id, the resource id and the name of
       -From -> -To. #>
    param([Parameter(Mandatory)]$From, [Parameter(Mandatory)]$To)
    $m = @{}
    foreach ($p in 'ClientId', 'PrincipalId', 'Id', 'Name') {
        $a = [string](Get-SIMoveProp $From @($p)); $b = [string](Get-SIMoveProp $To @($p))
        if ($a.Trim() -and $b.Trim() -and $a -ine $b) { $m[$a.Trim().ToLowerInvariant()] = $b.Trim() }
    }
    $m
}

function Get-SIIdentityMoveReferenceValues {
    <# PURE. The values that mean "this identity" inside an app / job (outside its identity block): the client id, the object
       (principal) id and the resource id -- what the switch rewrites in EVERY container and init container, secret, Key
       Vault reference, registry, scale rule, ingress / Dapr setting, and what the read-backs and the clean-up look for. #>
    param([Parameter(Mandatory)]$Identity)
    @(foreach ($p in 'ClientId', 'PrincipalId', 'Id') { $v = [string](Get-SIMoveProp $Identity @($p)); if ($v.Trim()) { $v.Trim() } })
}

function Update-SIIdentityMoveReferences {
    <#
        PURE. Walks an ARM body (ordered dictionaries + arrays, ConvertTo-SISetupArmHashtable) and replaces every STRING VALUE
        equal (case-insensitive, trimmed) to a key of -Map by its value -- the environment, Key Vault secret references
        (secrets[].identity), the registry identity, scale rules' identity, the sign-in credential setting. The identity
        block and the tags are never touched (the old identity stays attached until clean-up). Returns @{ Node; Changes
        (paths) }.
    #>
    param($Node, [Parameter(Mandatory)][hashtable]$Map, [string]$Path = '')
    $changes = New-Object System.Collections.Generic.List[string]
    $walk = $null
    $walk = {
        param($n, [string]$p)
        if ($null -eq $n) { return $null }
        if ($n -is [string]) {
            $k = $n.Trim().ToLowerInvariant()
            if ($Map.ContainsKey($k)) { $changes.Add($p); return [string]$Map[$k] }
            return $n
        }
        if ($n -is [System.Collections.IDictionary]) {
            foreach ($key in @($n.Keys)) {
                $kp = "$p/$key"
                if ($kp -in '/identity', '/tags') { continue }
                $n[$key] = & $walk $n[$key] $kp
            }
            return $n
        }
        if ($n -is [System.Collections.IList] -and -not ($n -is [string])) {
            for ($i = 0; $i -lt $n.Count; $i++) {
                $label = $i
                $nm = Get-SIMoveProp $n[$i] @('name'); if ($nm -is [string] -and $nm) { $label = $nm }
                $n[$i] = & $walk $n[$i] "$p[$label]"
            }
            return , $n
        }
        $n
    }
    $out = & $walk $Node $Path
    [pscustomobject]@{ Node = $out; Changes = $changes.ToArray() }
}

function Find-SIIdentityMoveReferences {
    <# PURE. The paths in an ARM object where a string value equals one of -Values (outside the identity block and tags). #>
    param($Node, [string[]]$Values = @())
    $m = @{}; foreach ($v in @($Values | Where-Object { "$_".Trim() })) { $m["$v".Trim().ToLowerInvariant()] = "$v" }
    if (-not $m.Count) { return @() }
    $copy = ConvertTo-SISetupArmHashtable $Node
    @((Update-SIIdentityMoveReferences -Node $copy -Map $m).Changes)
}

function Get-SIIdentityMoveAttached {
    <# PURE. The user-assigned identity resource ids (lower case) attached to an ARM app / job. #>
    param($Resource)
    $ua = Get-SIMoveProp $Resource @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return @() }
    $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object Name) }
    @($keys | ForEach-Object { ([string]$_).ToLowerInvariant() })
}

function Remove-SIIdentityMoveAttachment {
    <# PURE. The body with -IdentityId taken out of identity.userAssignedIdentities (the type follows: SystemAssigned when a
       system identity remains, None when nothing remains).
       -MergePatch: the body is sent as a JSON MERGE PATCH (a container app's PATCH): there a key LEFT OUT of the map is KEPT
       by Azure, so the old identity's key is sent with the value null -- the only way a merge patch removes it (live at
       internal 2026-11-07: the detach PATCH without the key answered 200 and the old identity stayed attached). A PUT (a
       job, written whole) sends the map without the key. #>
    param([Parameter(Mandatory)]$Body, [Parameter(Mandatory)][string]$IdentityId, [switch]$MergePatch)
    $idn = $Body.identity
    if ($null -eq $idn) { return $Body }
    $ua = $idn.userAssignedIdentities
    $keep = [ordered]@{}; $gone = @()
    if ($ua -is [System.Collections.IDictionary]) { foreach ($k in @($ua.Keys)) { if ("$k" -ine $IdentityId) { $keep[[string]$k] = [ordered]@{} } else { $gone += [string]$k } } }
    $sys = [string]$idn.type -match '(?i)SystemAssigned'
    if ($keep.Count) {
        # the key as Azure returned it (its casing), null = removed
        if ($MergePatch) { foreach ($g in @($(if ($gone.Count) { $gone } else { @($IdentityId) }))) { $keep[$g] = $null } }
        $idn.userAssignedIdentities = $keep; $idn.type = $(if ($sys) { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' })
    }
    else { if ($idn.Contains('userAssignedIdentities')) { $idn.Remove('userAssignedIdentities') }; $idn.type = $(if ($sys) { 'SystemAssigned' } else { 'None' }) }
    $Body
}

function Add-SIIdentityMoveAttachment {
    <# PURE. The body with -IdentityId added to identity.userAssignedIdentities (kept identities stay). #>
    param([Parameter(Mandatory)]$Body, [Parameter(Mandatory)][string]$IdentityId)
    $idn = $Body.identity
    if ($null -eq $idn) { $idn = [ordered]@{ type = 'UserAssigned' }; $Body.identity = $idn }
    $ua = $idn.userAssignedIdentities
    $all = [ordered]@{}
    if ($ua -is [System.Collections.IDictionary]) { foreach ($k in @($ua.Keys)) { $all[[string]$k] = [ordered]@{} } }
    if (-not @($all.Keys | Where-Object { "$_" -ieq $IdentityId }).Count) { $all[$IdentityId] = [ordered]@{} }
    $idn.userAssignedIdentities = $all
    $idn.type = $(if ([string]$idn.type -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' })
    $Body
}

function Get-SIIdentityMoveWriteBody {
    <#
        PURE. The body that re-points ONE app / job from -From to -To (identities @{ Name; Id; ClientId }): -To attached
        (-From stays, unless -Detach), every reference rewritten. A job is written WHOLE (Merge-SIContainerAppJobUpdate: its
        secrets restored from -SecretValues); an app by PATCH of identity + configuration (secrets restored) + template.
        Returns @{ Body; Method PUT|PATCH; Changes; MissingSecrets (a write would blank them -> the caller stops) }.
        -Detach: clean-up -- -From is taken out instead of -To being added, nothing is rewritten.
    #>
    param([Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][ValidateSet('app', 'job')][string]$Kind, [hashtable]$SecretValues = @{},
          [Parameter(Mandatory)]$From, [Parameter(Mandatory)]$To, [switch]$Detach)
    $missing = @(Get-SIJobSecretsWithoutValue -Job $Resource -SecretValues $SecretValues)
    if ($Kind -eq 'job') {
        $b = Merge-SIContainerAppJobUpdate -Job $Resource -SecretValues $SecretValues
    } else {
        $b = ConvertTo-SISetupArmHashtable $Resource
        $cfg = Get-SIMoveProp $b @('properties', 'configuration')
        if ($cfg -is [System.Collections.IDictionary] -and $cfg.Contains('secrets')) {
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($s in @($cfg.secrets | Where-Object { $_ })) {
                $e = [ordered]@{ name = [string]$s.name }
                $known = $SecretValues[[string]$s.name]
                $kv = [string](Get-SIMoveProp $s @('keyVaultUrl')); if (-not $kv -and $known) { $kv = [string](Get-SIMoveProp $known @('keyVaultUrl')) }
                if ($kv) {
                    $e.keyVaultUrl = $kv
                    $sid = [string](Get-SIMoveProp $s @('identity')); if (-not $sid -and $known) { $sid = [string](Get-SIMoveProp $known @('identity')) }
                    if ($sid) { $e.identity = $sid }
                } else {
                    $v = Get-SIMoveProp $s @('value'); if ($null -eq $v -and $known) { $v = Get-SIMoveProp $known @('value') }
                    $e.value = [string]$v
                }
                $list.Add($e)
            }
            $cfg.secrets = $list.ToArray()
        }
    }
    $changes = @()
    if ($Detach) {
        # an app is PATCHed (JSON merge patch: the old key goes as null); a job is PUT whole (the map without the key)
        $b = Remove-SIIdentityMoveAttachment -Body $b -IdentityId ([string]$From.Id) -MergePatch:($Kind -eq 'app')
    } else {
        $b = Add-SIIdentityMoveAttachment -Body $b -IdentityId ([string]$To.Id)
        $r = Update-SIIdentityMoveReferences -Node $b -Map (Get-SIIdentityMoveReferenceMap -From $From -To $To)
        $b = $r.Node; $changes = @($r.Changes)
    }
    if ($Kind -eq 'job') { return [pscustomobject]@{ Body = $b; Method = 'PUT'; Changes = $changes; MissingSecrets = $missing } }
    $tpl = Get-SIMoveProp $b @('properties', 'template')
    if ($tpl -is [System.Collections.IDictionary] -and $tpl.Contains('revisionSuffix')) { $tpl.Remove('revisionSuffix') }
    $patch = [ordered]@{ identity = $b.identity; properties = [ordered]@{ configuration = (Get-SIMoveProp $b @('properties', 'configuration')); template = $tpl } }
    [pscustomobject]@{ Body = $patch; Method = 'PATCH'; Changes = $changes; MissingSecrets = $missing }
}

# =====================================================================================================================
#  STEP 3 PLANNERS -- copy exactly the old identity's rights (PURE)
# =====================================================================================================================

function ConvertTo-SIIdentityMoveAzureRole {
    <# PURE. An ARM roleAssignment as @{ Id; Scope; RoleDefinitionId; RoleGuid; PrincipalId; Condition; ConditionVersion; Description }. #>
    param($Item)
    [pscustomobject]@{
        Id = [string]$Item.id; Scope = [string](Get-SIMoveProp $Item @('properties', 'scope'))
        RoleDefinitionId = [string](Get-SIMoveProp $Item @('properties', 'roleDefinitionId'))
        RoleGuid = Get-SIIdentityMoveGuidTail ([string](Get-SIMoveProp $Item @('properties', 'roleDefinitionId')))
        PrincipalId = ([string](Get-SIMoveProp $Item @('properties', 'principalId'))).ToLowerInvariant()
        Condition = [string](Get-SIMoveProp $Item @('properties', 'condition')); ConditionVersion = [string](Get-SIMoveProp $Item @('properties', 'conditionVersion'))
        Description = [string](Get-SIMoveProp $Item @('properties', 'description'))
    }
}

function Get-SIIdentityMoveAzureCopyPlan {
    <# PURE. The old principal's Azure role assignments (-Old) the new one (-New) does not hold yet: same role definition
       (by GUID), same scope. Assignments of other principals in the lists are ignored (-OldPrincipalId / -NewPrincipalId). #>
    param([object[]]$Old = @(), [object[]]$New = @(), [Parameter(Mandatory)][string]$OldPrincipalId, [Parameter(Mandatory)][string]$NewPrincipalId)
    $have = @($New | Where-Object { $_ -and $_.PrincipalId -ieq $NewPrincipalId })
    $seen = @{}
    foreach ($a in @($Old | Where-Object { $_ -and $_.PrincipalId -ieq $OldPrincipalId })) {
        $key = ('{0}|{1}' -f $a.RoleGuid, "$($a.Scope)".TrimEnd('/').ToLowerInvariant())
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        if (@($have | Where-Object { $_.RoleGuid -eq $a.RoleGuid -and (Test-SIIdentityMoveSameScope $_.Scope $a.Scope) }).Count) { continue }
        $a
    }
}

function Get-SIIdentityMoveAzureAssignmentBody {
    <# PURE. The PUT body that gives -PrincipalId the role of -Like (an old assignment), condition and description kept. #>
    param([Parameter(Mandatory)]$Like, [Parameter(Mandatory)][string]$PrincipalId)
    $p = [ordered]@{ roleDefinitionId = [string]$Like.RoleDefinitionId; principalId = $PrincipalId; principalType = 'ServicePrincipal' }
    if ("$($Like.Condition)".Trim()) { $p.condition = [string]$Like.Condition; $p.conditionVersion = $(if ("$($Like.ConditionVersion)".Trim()) { [string]$Like.ConditionVersion } else { '2.0' }) }
    if ("$($Like.Description)".Trim()) { $p.description = [string]$Like.Description }
    [ordered]@{ properties = $p }
}

function Get-SIIdentityMoveAzureAssignmentPath {
    <# PURE. Where a new assignment at -Scope is written ('/' or '' = the tenant root). #>
    param([AllowEmptyString()][string]$Scope, [Parameter(Mandatory)][string]$Name)
    ('{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version={2}' -f "$Scope".Trim().TrimEnd('/'), $Name, $script:SIMove.RoleApi)
}

function Get-SIIdentityMoveAppRoleCopyPlan {
    <# PURE. Graph app role assignments of the old service principal the new one lacks (same resource, same app role). #>
    param([object[]]$Old = @(), [object[]]$New = @())
    foreach ($a in @($Old | Where-Object { $_ })) {
        if (@($New | Where-Object { $_ -and "$($_.resourceId)" -ieq "$($a.resourceId)" -and "$($_.appRoleId)" -ieq "$($a.appRoleId)" }).Count) { continue }
        $a
    }
}

function Get-SIIdentityMoveDirRoleCopyPlan {
    <# PURE. Entra directory role assignments of the old principal the new one lacks (same role, same directory scope). #>
    param([object[]]$Old = @(), [object[]]$New = @())
    foreach ($a in @($Old | Where-Object { $_ })) {
        $sc = if ("$($a.directoryScopeId)".Trim()) { "$($a.directoryScopeId)" } else { '/' }
        if (@($New | Where-Object { $_ -and "$($_.roleDefinitionId)" -ieq "$($a.roleDefinitionId)" -and $(if ("$($_.directoryScopeId)".Trim()) { "$($_.directoryScopeId)" } else { '/' }) -ieq $sc }).Count) { continue }
        $a
    }
}

function Get-SIIdentityMoveKvCopyPlan {
    <# PURE. Key Vault: an RBAC vault is covered by the Azure role assignments; an access-policy vault -> the old principal's
       policies the new one lacks (same permissions). -Vaults: ARM vault objects. #>
    param([object[]]$Vaults = @(), [Parameter(Mandatory)][string]$OldPrincipalId, [Parameter(Mandatory)][string]$NewPrincipalId)
    foreach ($v in @($Vaults | Where-Object { $_ })) {
        if ([bool](Get-SIMoveProp $v @('properties', 'enableRbacAuthorization'))) { continue }
        $pol = @(Get-SIMoveProp $v @('properties', 'accessPolicies'))
        $o = @($pol | Where-Object { $_ -and "$($_.objectId)" -ieq $OldPrincipalId })
        if (-not $o.Count) { continue }
        if (@($pol | Where-Object { $_ -and "$($_.objectId)" -ieq $NewPrincipalId }).Count) { continue }
        [pscustomobject]@{ VaultId = [string]$v.id; VaultName = [string]$v.name; TenantId = [string]$o[0].tenantId; Permissions = $o[0].permissions }
    }
}

function Get-SIIdentityMoveSettingPlan {
    <# PURE. SI settings (cfg.Setting rows: Name, Scope, ValueJson) whose value IS the old identity's client id or name ->
       the same setting with the new one. #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)]$From, [Parameter(Mandatory)]$To)
    $map = Get-SIIdentityMoveReferenceMap -From $From -To $To
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $raw = [string]$r.ValueJson
        if (-not $raw.Trim()) { continue }
        try { $v = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if (-not ($v -is [string])) { continue }
        $k = $v.Trim().ToLowerInvariant()
        if ($map.ContainsKey($k)) { [pscustomobject]@{ Name = [string]$r.Name; Scope = [string]$r.Scope; Old = $v; New = [string]$map[$k] } }
    }
}

function Get-SIIdentityMoveMailMode {
    <# PURE. Is SecurityInsight's mail a shared mailbox (Exchange Application Mail.Send)? From cfg.Setting rows SI_Mail_Mode /
       SI_Mail_From (scope 'solution'). Returns @{ SharedMailbox [bool]; From }. #>
    param([object[]]$Rows = @())
    $get = { param($n) $r = @($Rows | Where-Object { $_ -and $_.Name -eq $n -and ([string]$_.Scope -eq 'solution' -or -not $_.PSObject.Properties['Scope']) })[0]
             if (-not $r) { return '' }; try { [string]([string]$r.ValueJson | ConvertFrom-Json -ErrorAction Stop) } catch { '' } }
    $mode = & $get 'SI_Mail_Mode'; $from = & $get 'SI_Mail_From'
    $shared = ($mode -eq 'sharedMailbox') -or (-not $mode -and $from)
    [pscustomobject]@{ SharedMailbox = [bool]$shared; From = $from }
}

# =====================================================================================================================
#  STEPS 4-7 PLANNERS (PURE)
# =====================================================================================================================

function Select-SIIdentityMoveWaitExecutions {
    <#
        PURE. The executions of job -Name the switch must wait for. Left out: (1) the update's OWN execution
        (-Ctx.SelfExecution: its template is fixed at its start, the switch takes effect from the next execution); (2) at
        caj-si-support-grant, every execution that started at or after this invocation (-Ctx.StartedUtc, 5 s slack): the
        just-in-time support grant this invocation opened itself (live 2026-11-09: the switch waited for its own grant and
        stopped). An execution started BEFORE this invocation is still waited for.
    #>
    param([string]$Name, [object[]]$Executions = @(), $Ctx)
    $ex = @($Executions | Where-Object { $_ })
    $self = if ($Ctx) { "$($Ctx.SelfExecution)".Trim() } else { '' }
    if ($self) { $ex = @($ex | Where-Object { [string]$_.name -ne $self }) }
    $started = if ($Ctx -and $Ctx.ContainsKey('StartedUtc') -and $Ctx.StartedUtc) { ([datetime]$Ctx.StartedUtc).ToUniversalTime().AddSeconds(-5) } else { $null }
    if ($Name -eq 'caj-si-support-grant' -and $started) {
        $ex = @($ex | Where-Object {
            $t = $null; try { $t = ([datetime](Get-SIMoveProp $_ @('properties', 'startTime'))).ToUniversalTime() } catch { $t = $null }
            -not $t -or $t -lt $started })
    }
    $ex   # (no leading comma: the caller wraps it in @() -- a comma here would make an empty list count as one)
}

function Get-SIIdentityMoveRunGate {
    <#
        PURE. May -Name be re-pointed now? Never during a running execution (a running execution keeps its identity) and, for
        an engine job, never while a pipeline run is going (the product's run gate: the newest cfg.FlowRun not ended, or a
        step Starting / Running). -Executions: the job's executions (ARM); -Flow: the gate row @{ RunId; RunState;
        OpenSteps } ($null = the install has no pipeline store). Returns @{ Go; Why }.
    #>
    param([Parameter(Mandatory)][string]$Name, [ValidateSet('app', 'job')][string]$Kind = 'job', [object[]]$Executions = @(), $Flow = $null, [switch]$FlowUnreadable)
    if ($Kind -eq 'app') { return [pscustomobject]@{ Go = $true; Why = 'an app: a new revision replaces the running one' } }
    $run = @($Executions | Where-Object { $_ -and ([string](Get-SIMoveProp $_ @('properties', 'status'))) -notin $script:SIMove.ExecDone })
    if ($run.Count) { return [pscustomobject]@{ Go = $false; Why = ('{0}: execution {1} is {2}' -f $Name, [string]$run[0].name, [string](Get-SIMoveProp $run[0] @('properties', 'status'))) } }
    if ($FlowUnreadable) { return [pscustomobject]@{ Go = $false; Why = 'the pipeline state could not be read: nothing is switched (never a guess)' } }
    if ($Flow) {
        $st = [string]$Flow.RunState; $open = 0; [void][int]::TryParse("$($Flow.OpenSteps)", [ref]$open)
        if ([string]$Flow.RunId -and $st -and $st -notin 'Succeeded', 'Failed', 'Stopped', 'Cancelled') { return [pscustomobject]@{ Go = $false; Why = ('pipeline run {0} is {1}' -f $Flow.RunId, $st) } }
        if ($open -gt 0) { return [pscustomobject]@{ Go = $false; Why = ('{0} pipeline step(s) still running' -f $open) } }
    }
    [pscustomobject]@{ Go = $true; Why = 'no execution and no pipeline run going' }
}

function Get-SIIdentityMoveRunGateSql {
    <# PURE. The read-only pipeline check (no lock taken: the move never touches the install's runs). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.FlowRun') IS NULL
    SELECT CAST(NULL AS nvarchar(64)) AS RunId, CAST(NULL AS nvarchar(16)) AS RunState, 0 AS OpenSteps;
ELSE
    SELECT r.FlowRunId AS RunId, r.State AS RunState,
           (SELECT COUNT(*) FROM cfg.FlowStepRun s WHERE s.State IN (N'Starting', N'Running')) AS OpenSteps
      FROM (SELECT 1 AS One) d
      OUTER APPLY (SELECT TOP (1) FlowRunId, State FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC) r;
'@
}

function ConvertTo-SIMoveUtc {
    <# PURE. A time as UTC [datetime], or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try { [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null }
}

function Get-SIIdentityMoveJobProof {
    <#
        PURE. One re-pointed job's proof: its LATEST execution that started after -SwitchedUtc and has ended (a run that
        failed and was followed by a successful one after the missing right was given is not a standing failure -- seen live
        at internal 2026-11-04: the support-grant job failed three times while its database role was added, then succeeded).
          proven   it Succeeded and its template names -NewClientId, or (-PulledWith) the job uses the new identity only to
                   pull its image -- a successful run pulled with it (seen live: the database setup job signs in with its
                   own identity and pulls with the engine's)
          waiting  none has ended since the switch; or the latest was stopped, or succeeded without the new client id: neither
                   says anything about the identity's rights. A latest run that Failed / Degraded also waits, marked Suspect:
                   Invoke-SIMoveProve looks up why it failed (Resolve-SIIdentityMoveRightsEvidence), and only a refused right
                   or sign-in makes it 'failed'. A run that failed for any other reason is never blamed on the new identity
          idle     the job ran nothing in -IdleDays before the switch and nothing since: it does not hold the proof back
    #>
    param([Parameter(Mandatory)][string]$Name, [object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$SwitchedUtc,
          [Parameter(Mandatory)][string]$NewClientId, [int]$IdleDays = 7, [switch]$PulledWith)
    $ex = @($Executions | Where-Object { $_ } | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.name; Status = [string](Get-SIMoveProp $_ @('properties', 'status'))
            Start = ConvertTo-SIMoveUtc (Get-SIMoveProp $_ @('properties', 'startTime')); Template = (Get-SIMoveProp $_ @('properties', 'template')) } } |
        Where-Object { $_.Start } | Sort-Object Start)
    $after = @($ex | Where-Object { $_.Start -gt $SwitchedUtc -and $_.Status -in $script:SIMove.ExecDone })
    if ($after.Count) {
        $e = $after[-1]
        $earlier = @($after | Select-Object -First ($after.Count - 1) | Where-Object { $_.Status -ne 'Succeeded' }).Count
        $tail = if ($earlier) { ' (after {0} earlier run(s) that did not succeed)' -f $earlier } else { '' }
        $names = @(Find-SIIdentityMoveReferences -Node $e.Template -Values @($NewClientId)).Count -gt 0
        if ($e.Status -eq 'Succeeded' -and $names) { return [pscustomobject]@{ Name = $Name; State = 'proven'; Execution = $e.Name; Why = ('{0} succeeded on the new identity{1}' -f $e.Name, $tail) } }
        if ($e.Status -eq 'Succeeded' -and $PulledWith) { return [pscustomobject]@{ Name = $Name; State = 'proven'; Execution = $e.Name; Why = ('{0} succeeded with its image pulled by the new identity{1}' -f $e.Name, $tail) } }
        if ($e.Status -eq 'Succeeded') { return [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = $e.Name; Why = 'its latest run succeeded but did not start with the new identity; its next run decides' } }
        if ($e.Status -eq 'Stopped') { return [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = $e.Name; Why = 'its latest run was stopped, which says nothing about its rights; its next run decides' } }
        return [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = $e.Name; Suspect = $true; Why = 'its latest run did not finish successfully, and nothing shows that a right is missing. The old identity keeps every right until a later run succeeds' }
    }
    $before = @($ex | Where-Object { $_.Start -le $SwitchedUtc -and $_.Start -gt $SwitchedUtc.AddDays(-$IdleDays) })
    $since = @($ex | Where-Object { $_.Start -gt $SwitchedUtc })
    if (-not $before.Count -and -not $since.Count) { return [pscustomobject]@{ Name = $Name; State = 'idle'; Execution = ''; Why = ('no execution in the {0} days before the switch' -f $IdleDays) } }
    [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = ''; Why = 'its next run has not ended yet' }
}

function Get-SIIdentityMoveRightsEvidenceSql {
    <# PURE. The read-only look-up of why these executions failed: the class the pipeline recorded for each of its steps. #>
    param([Parameter(Mandatory)][string[]]$Executions)
    $in = @($Executions | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { ConvertTo-SIMoveSqlText $_ }) -join ', '
    "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL SELECT Execution, ErrorClass FROM cfg.FlowStepRun WHERE Execution IN ($in);"
}

function Resolve-SIIdentityMoveRightsEvidence {
    <# PURE. -Items with every Suspect job whose execution the pipeline recorded under a refused right or sign-in (-Rows:
       Execution, ErrorClass) turned to 'failed' (Rights). Every other item is returned as it is: a job with no such record
       -- outside the pipeline, or failed for another reason -- keeps waiting. #>
    param([object[]]$Items = @(), [object[]]$Rows = @())
    $refused = @{}
    foreach ($r in @($Rows | Where-Object { $_ })) {
        if ([string](Get-SIMoveProp $r @('ErrorClass')) -in $script:SIMove.RightsErrorClasses) { $refused[([string](Get-SIMoveProp $r @('Execution'))).ToLowerInvariant()] = $true }
    }
    foreach ($i in @($Items | Where-Object { $_ })) {
        if ([bool](Get-SIMoveProp $i @('Suspect')) -and $refused.ContainsKey(([string]$i.Execution).ToLowerInvariant())) {
            [pscustomobject]@{ Name = $i.Name; State = 'failed'; Execution = $i.Execution; Rights = $true; Why = 'its latest run failed because a right or a sign-in was refused to the new identity' }
        } else { $i }
    }
}

function Get-SIIdentityMoveAppProof {
    <# PURE. An app's proof: its newest ACTIVE revision was made after -SwitchedUtc, is healthy / running, and its template
       names -NewClientId. -Revisions: ARM revisions. State proven | waiting | failed. #>
    param([Parameter(Mandatory)][string]$Name, [object[]]$Revisions = @(), [Parameter(Mandatory)][datetime]$SwitchedUtc, [Parameter(Mandatory)][string]$NewClientId)
    $rv = @($Revisions | Where-Object { $_ -and [bool](Get-SIMoveProp $_ @('properties', 'active')) } | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.name; Created = ConvertTo-SIMoveUtc (Get-SIMoveProp $_ @('properties', 'createdTime'))
            Health = [string](Get-SIMoveProp $_ @('properties', 'healthState')); Running = [string](Get-SIMoveProp $_ @('properties', 'runningState'))
            Template = (Get-SIMoveProp $_ @('properties', 'template')) } } | Where-Object { $_.Created } | Sort-Object Created -Descending)
    $r = @($rv | Where-Object { $_.Created -gt $SwitchedUtc })[0]
    if (-not $r) { return [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = ''; Why = 'no active revision since the switch yet' } }
    $names = @(Find-SIIdentityMoveReferences -Node $r.Template -Values @($NewClientId)).Count -gt 0
    if (-not $names) { return [pscustomobject]@{ Name = $Name; State = 'failed'; Execution = $r.Name; Why = ('revision {0} does not name the new client id' -f $r.Name) } }
    if ($r.Health -eq 'Healthy' -and $r.Running -match '^(?i)(Running|RunningAtMaxScale)$') { return [pscustomobject]@{ Name = $Name; State = 'proven'; Execution = $r.Name; Why = ('revision {0} is healthy on the new identity' -f $r.Name) } }
    if ($r.Health -eq 'Unhealthy' -or $r.Running -match '^(?i)(Failed|Degraded)$') { return [pscustomobject]@{ Name = $Name; State = 'failed'; Execution = $r.Name; Why = ('revision {0} is {1} / {2}' -f $r.Name, $r.Health, $r.Running) } }
    [pscustomobject]@{ Name = $Name; State = 'waiting'; Execution = $r.Name; Why = ('revision {0} is {1} / {2}' -f $r.Name, $r.Health, $r.Running) }
}

function Get-SIIdentityMoveRoleProof {
    <# PURE. The role's proof from its users' proofs: failed when one failed; proven when none waits and at least one is
       proven (idle jobs do not hold it back); waiting otherwise. #>
    param([object[]]$Items = @())
    $i = @($Items | Where-Object { $_ })
    if (@($i | Where-Object State -eq 'failed').Count) { return 'failed' }
    if (@($i | Where-Object State -eq 'waiting').Count) { return 'waiting' }
    if (@($i | Where-Object State -eq 'proven').Count) { return 'proven' }
    'waiting'
}

function Test-SIIdentityMoveCleanupAllowed {
    <#
        PURE. Clean-up only after EVERY role at the install is proven (framework step 6). -Roles: per role the selection
        state (Select-SIIdentityMoveIdentities .State) and -State: the move record (per role: switchedUtc, provenUtc).
        A role with nothing to move (done / none) counts as proven. Returns @{ Allowed; Why; Waiting (roles) }.
    #>
    param([Parameter(Mandatory)][hashtable]$Selections, $State)
    $wait = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Selections.Keys | Sort-Object)) {
        $sel = $Selections[$r]
        if ($sel.State -in 'done', 'none') { continue }
        if ($sel.State -eq 'ambiguous') { $wait.Add("$r (ambiguous)"); continue }
        $rec = Get-SIMoveProp $State @('roles', $r)
        if (-not [string](Get-SIMoveProp $rec @('provenUtc')) -and -not [string](Get-SIMoveProp $rec @('cleanedUtc'))) { $wait.Add($r) }
    }
    if ($wait.Count) { return [pscustomobject]@{ Allowed = $false; Why = ('not every role is proven yet: {0}' -f ($wait -join ', ')); Waiting = $wait.ToArray() } }
    [pscustomobject]@{ Allowed = $true; Why = 'every role at the install is proven'; Waiting = @() }
}

function Update-SIIdentityMoveState {
    <# PURE. The move record (cfg.InstallState 'IdentityMove') with -Values set on -Role (null removes a key). Returns the JSON. #>
    param($State, [Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][hashtable]$Values)
    $s = ConvertTo-SISetupArmHashtable $State
    if ($null -eq $s -or -not ($s -is [System.Collections.IDictionary])) { $s = [ordered]@{} }
    if (-not $s.Contains('roles') -or -not ($s.roles -is [System.Collections.IDictionary])) { $s.roles = [ordered]@{} }
    if (-not $s.roles.Contains($Role) -or -not ($s.roles[$Role] -is [System.Collections.IDictionary])) { $s.roles[$Role] = [ordered]@{} }
    foreach ($k in @($Values.Keys)) { if ($null -eq $Values[$k]) { if ($s.roles[$Role].Contains($k)) { $s.roles[$Role].Remove($k) } } else { $s.roles[$Role][$k] = $Values[$k] } }
    $s | ConvertTo-Json -Depth 8 -Compress
}

function Get-SIIdentityNamesReport {
    <#
        PURE. Step 7: the identity-names record (cfg.InstallState 'IdentityNames') from each role's selection and use.
        -Roles: role -> @{ Selection; InUse (the identity its apps / jobs point at: @{ Name; PrincipalId }); Unknown [bool] }.
        Per role: ok (its apps / jobs use id-si-<role> and no old identity is left), missing (an old name is in use or left),
        unknown (could not be read). A role not at the install is left out. Returns @{ Record (ordered); Value (JSON) }.
    #>
    param([Parameter(Mandatory)][hashtable]$Roles, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{}
    # the five moved roles, then the two that are only checked: the database setup job's own identity and the in-network SQL
    # identity (where the install has one)
    foreach ($r in @(@((Get-SIIdentityMoveRoleTable).Keys) + @('dbinit', 'sql', 'sql-admin-group'))) {
        if (-not $Roles.ContainsKey($r)) { continue }
        $x = $Roles[$r]
        # the SQL admin group: its own entry (Get-SIIdentityMoveSqlAdminGroupEntry), as it is
        if ($x.Contains('Entry')) { if ($x.Entry) { $out[$r] = $x.Entry }; continue }
        $sel = $x.Selection
        if ($x.Unknown) { $out[$r] = [ordered]@{ state = 'unknown'; standard = $sel.Standard }; continue }
        if ($sel.State -eq 'none') { continue }
        $use = $x.InUse
        $name = if ($use) { [string]$use.Name } elseif ($sel.Old) { [string]$sel.Old.Name } else { [string]$sel.Standard }
        $oid = if ($use) { [string]$use.PrincipalId } elseif ($sel.Old) { [string]$sel.Old.PrincipalId } elseif ($sel.New) { [string]$sel.New.PrincipalId } else { '' }
        # Invardia's rule (framework 12.11c / NAM-03, 2026-11-07): a role is ok ONLY when its apps / jobs sign in as
        # id-si-<role> AND the old identity holds no rights any more. In use but the old one still holding rights (or not known
        # to hold none: -RightsLeft $null, no recorded clean-up) = missing, "clean-up pending". An old identity with no rights
        # left that still exists = ok, said in the note.
        $std = $name -ieq $sel.Standard -and ($use -or $sel.State -eq 'done')
        $left = if ($sel.Old -and $x.Contains('RightsLeft')) { $x.RightsLeft } elseif ($sel.Old) { $null } else { $false }
        $state = if ($sel.State -eq 'ambiguous' -and -not $use) { 'unknown' } elseif ($std -and $left -eq $false) { 'ok' } else { 'missing' }
        $e = [ordered]@{ state = $state; name = $name; kind = 'user-assigned'; objectId = $oid; standard = $sel.Standard }
        if ($std -and $sel.Old -and $left -ne $false) { $e.note = ('clean-up pending: the old identity {0} may still hold rights' -f $sel.Old.Name) }
        elseif ($state -eq 'ok' -and $sel.Old) { $e.note = ('the old identity {0} has no rights left (it still exists)' -f $sel.Old.Name) }
        if ($x.Contains('Note') -and $x.Note) { $e.state = 'missing'; $e.note = [string]$x.Note }
        $out[$r] = $e
    }
    $rec = [ordered]@{ checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); roles = $out }
    # cfg.InstallState.Value holds 400 characters (seen live at internal 2026-11-04: five roles did not fit). The heartbeat
    # reads state and name (and shows a note), so the detail goes first, field by field, until the record fits: standard,
    # kind, objectId, then the note. state and name are always kept.
    $value = $rec | ConvertTo-Json -Depth 6 -Compress
    foreach ($drop in 'standard', 'kind', 'objectId', 'note') {
        if ($value.Length -le $script:SIMove.InstallStateMax) { break }
        foreach ($k in @($out.Keys)) { if ($out[$k].Contains($drop)) { $out[$k].Remove($drop) } }
        $value = $rec | ConvertTo-Json -Depth 6 -Compress
    }
    [pscustomobject]@{ Record = $rec; Value = $value }
}

function Get-SIIdentityMoveInUse {
    <# PURE. The identity a role's apps / jobs sign in as: the one of -Candidates (@{ Name; Id; ClientId; PrincipalId }) whose
       client id their references name (the sign-in settings, the environment), else the one attached alone. $null = none. #>
    param([object[]]$Users = @(), [object[]]$Candidates = @())
    $c = @($Candidates | Where-Object { $_ })
    # the client id an app / job names in AZURE_CLIENT_ID is the one it signs in with (the SDK's own variable) -- it decides first
    foreach ($u in @($Users | Where-Object { $_ })) {
        foreach ($ct in @(Get-SIMoveProp $u.Resource @('properties', 'template', 'containers'))) {
            foreach ($ev in @(Get-SIMoveProp $ct @('env'))) {
                if ($ev -and [string](Get-SIMoveProp $ev @('name')) -eq 'AZURE_CLIENT_ID') { $v = ([string](Get-SIMoveProp $ev @('value'))).Trim(); $hit = @($c | Where-Object { $_.ClientId -ieq $v })[0]; if ($hit) { return $hit } }
            }
        }
    }
    foreach ($x in $c) { foreach ($u in @($Users | Where-Object { $_ })) { if (@(Find-SIIdentityMoveReferences -Node $u.Resource -Values @($x.ClientId)).Count) { return $x } } }
    $att = @($c | Where-Object { $id = $_.Id.ToLowerInvariant(); @($Users | Where-Object { $_.HasIds -contains $id }).Count })
    if ($att.Count -eq 1) { return $att[0] }
    $null
}

# =====================================================================================================================
#  THIN I/O -- every call through the Invardia Support app, with -Reason (the customer's audit log)
# =====================================================================================================================

function ConvertFrom-SIMoveAnswer {
    <# PURE. A Support-app answer (StatusCode, Content) as @{ Status; Body (parsed or $null); Text }. #>
    param($Answer)
    $text = if ($Answer) { [string]$Answer.Content } else { '' }
    $body = $null
    if ($text.Trim()) { try { $body = $text | ConvertFrom-Json -ErrorAction Stop } catch { $body = $null } }
    [pscustomobject]@{ Status = $(if ($Answer) { [int]$Answer.StatusCode } else { 0 }); Body = $body; Text = $text }
}

$script:SIMoveIo = $null

function Set-SIIdentityMoveIo {
    <#
        THE UPDATER'S SEAMS (updater mode): every ARM / Graph / SQL call of the move goes through these scriptblocks instead of
        the Invardia Support app. -Arm { param([string]$Method, [string]$Path, $Body) } and -Graph { param([string]$Method,
        [string]$Uri, $Body) } return @{ StatusCode; Content } and never throw on an HTTP status; -Sql { param([string]$Server,
        [string]$Database, [string]$Query, [bool]$Change) } returns rows; -DbJob { param($Ctx, [object[]]$Moves, [object[]]$Drops) }
        runs the database setup job with the moves / drops and returns @{ Ok; States (component -> state); Why }; -Sleep
        { param([int]$Seconds) }. $null (no argument) = back to the Support app.
    #>
    param([scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Sql, [scriptblock]$DbJob, [scriptblock]$Sleep)
    if (-not $Arm -and -not $Graph -and -not $Sql -and -not $DbJob -and -not $Sleep) { $script:SIMoveIo = $null; return }
    $script:SIMoveIo = @{ Arm = $Arm; Graph = $Graph; Sql = $Sql; DbJob = $DbJob; Sleep = $Sleep }
}

function Invoke-SIMoveDbJob {
    <# The database setup job with -Moves (@{ component; from; to; toName }: copy the old user's rights to the new one in every
       product database, read back) and -Drops (@{ component; clientId; keepClientId; keepName }: the old user dropped only
       where the kept user reads back holding all of it). Updater mode only (the seam); @{ Ok; States; Why }. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [object[]]$Moves = @(), [object[]]$Drops = @())
    if (-not $script:SIMoveIo -or -not $script:SIMoveIo.DbJob) { return [pscustomobject]@{ Ok = $false; States = @{}; Why = 'the database setup job cannot be started from here' } }
    & $script:SIMoveIo.DbJob $Ctx @($Moves) @($Drops)
}

function Invoke-SIMoveArm {
    <# ARM through the caller's seam (Set-SIIdentityMoveIo): the updater's own REST client, or -- from the vendor's Support-app
       command -- the Invardia Support app (that command hands it in; this shipped file never calls the Support app itself:
       one seam, engine\_shared\SI-AzRest.ps1, guard #548). -Path: '/subscriptions/...?api-version=...' or a full https URL (a
       nextLink). -ReadOnly: a POST that only reads (listSecrets). Never throws on an HTTP status. #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Body, [Parameter(Mandatory)][string]$Reason, [switch]$ReadOnly)
    if (-not ($script:SIMoveIo -and $script:SIMoveIo.Arm)) { throw 'the identity move has no ARM seam (Set-SIIdentityMoveIo)' }
    ConvertFrom-SIMoveAnswer (& $script:SIMoveIo.Arm $Method $Path $Body $Reason ([bool]$ReadOnly))
}

function Invoke-SIMoveGraph {
    <# Microsoft Graph through the caller's seam. -Uri: full, or relative to v1.0. Never throws on an HTTP status. #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [Parameter(Mandatory)][string]$Reason)
    $u = if ($Uri -match '^https://') { $Uri } else { $script:SIMove.Graph + '/' + $Uri.TrimStart('/') }
    if (-not ($script:SIMoveIo -and $script:SIMoveIo.Graph)) { throw 'the identity move has no Graph seam (Set-SIIdentityMoveIo)' }
    ConvertFrom-SIMoveAnswer (& $script:SIMoveIo.Graph $Method $u $Body $Reason)
}

function Invoke-SIMoveSql {
    <# T-SQL through the caller's seam. Rows as objects. -Change records a change (default: a read). Throws on a SQL error. #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Query,
          [Parameter(Mandatory)][string]$Reason, [switch]$Change)
    if (-not ($script:SIMoveIo -and $script:SIMoveIo.Sql)) { throw 'the identity move has no SQL seam (Set-SIIdentityMoveIo)' }
    & $script:SIMoveIo.Sql $Server $Database $Query ([bool]$Change) $Reason
}
function Invoke-SIMoveSleep { param([int]$Seconds) if ($script:SIMoveIo -and $script:SIMoveIo.Sleep) { & $script:SIMoveIo.Sleep $Seconds; return }; Start-Sleep -Seconds $Seconds }

function Invoke-SIMoveStoreSql {
    <# The settings store's Invoke ({ $sql, $params, $mode }) over Invoke-SIMoveSql: the parameters become DECLAREs. #>
    param([string]$Server, [string]$Database, [string]$Reason, [string]$Sql, $Params, [string]$Mode)
    $q = (ConvertTo-SIMoveSqlDeclare $Params) + $Sql
    $rows = @(Invoke-SIMoveSql -Server $Server -Database $Database -Query $q -Reason $Reason -Change:($Mode -ne 'reader'))
    , $rows
}

function New-SIMoveSqlStore {
    <# A store object (.Invoke) that Set-SIProSetting / Save-SIInstallNamesRecord accept, bound to one database. #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Reason)
    $e = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    $sb = [scriptblock]::Create(('param($sql, $params, $mode) Invoke-SIMoveStoreSql -Server {0} -Database {1} -Reason {2} -Sql $sql -Params $params -Mode $mode' -f (& $e $Server), (& $e $Database), (& $e $Reason)))
    [pscustomobject]@{ Invoke = $sb }
}

function Get-SIMoveArmList {
    <# Every item of an ARM list (nextLink followed). @{ Ok; Status; Items }. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Reason)
    $items = New-Object System.Collections.Generic.List[object]; $next = $Path; $status = 0
    while ($next) {
        $a = Invoke-SIMoveArm -Path $next -Reason $Reason
        $status = $a.Status
        if ($a.Status -ne 200) { return [pscustomobject]@{ Ok = $false; Status = $a.Status; Items = $items.ToArray(); Text = $a.Text } }
        foreach ($v in @(Get-SIMoveProp $a.Body @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $next = [string](Get-SIMoveProp $a.Body @('nextLink'))
    }
    [pscustomobject]@{ Ok = $true; Status = $status; Items = $items.ToArray(); Text = '' }
}

function Get-SIMoveGraphList {
    <# Every item of a Graph list (@odata.nextLink followed). @{ Ok; Status; Items }. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Reason)
    $items = New-Object System.Collections.Generic.List[object]; $next = $Uri; $status = 0
    while ($next) {
        $a = Invoke-SIMoveGraph -Uri $next -Reason $Reason
        $status = $a.Status
        if ($a.Status -ne 200) { return [pscustomobject]@{ Ok = $false; Status = $a.Status; Items = $items.ToArray(); Text = $a.Text } }
        foreach ($v in @(Get-SIMoveProp $a.Body @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $next = [string](Get-SIMoveProp $a.Body @('@odata.nextLink'))
    }
    [pscustomobject]@{ Ok = $true; Status = $status; Items = $items.ToArray(); Text = '' }
}

# =====================================================================================================================
#  THE INSTALL (read once per invocation)
# =====================================================================================================================

function Initialize-SIMoveInstall {
    <#
        Reads the install once into -Ctx: its resource group (-Ctx.ResourceGroup, else the ONE resource group of the session's
        subscriptions that holds caj-si-* jobs), the user-assigned identities, container apps, jobs, the SQL server and its
        databases (the state database = the one with cfg.InstallState), the Key Vaults and the sign-in app registration.
        Returns $null, or the reason it could not ('stop').
    #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $why = $Ctx.Reason
    if (-not $Ctx.ResourceGroup) {
        $found = New-Object System.Collections.Generic.List[object]
        foreach ($sub in @($Ctx.Subscriptions)) {
            $f = [uri]::EscapeDataString("resourceType eq 'Microsoft.App/jobs'")
            $l = Get-SIMoveArmList -Path ("/subscriptions/{0}/resources?api-version={1}&`$filter={2}" -f $sub, $script:SIMove.ResApi, $f) -Reason $why
            if (-not $l.Ok) { return ('the jobs of subscription {0} could not be listed (HTTP {1})' -f $sub, $l.Status) }
            foreach ($j in @($l.Items | Where-Object { [string]$_.name -like 'caj-si-*' })) {
                $rg = ([string]$j.id -split '/')[4]
                if (-not @($found | Where-Object { $_.Sub -eq $sub -and $_.Rg -ieq $rg }).Count) { $found.Add([pscustomobject]@{ Sub = $sub; Rg = $rg }) }
            }
        }
        if ($found.Count -ne 1) { return ('{0} SecurityInsight resource groups found ({1}) -- name the install''s with -ResourceGroup' -f $found.Count, (($found | ForEach-Object Rg) -join ', ')) }
        $Ctx.SubscriptionId = $found[0].Sub; $Ctx.ResourceGroup = $found[0].Rg
    } elseif (-not $Ctx.SubscriptionId) {
        foreach ($sub in @($Ctx.Subscriptions)) {
            $g = Invoke-SIMoveArm -Path ("/subscriptions/{0}/resourceGroups/{1}?api-version={2}" -f $sub, $Ctx.ResourceGroup, $script:SIMove.ResApi) -Reason $why
            if ($g.Status -eq 200) { $Ctx.SubscriptionId = $sub; break }
        }
        if (-not $Ctx.SubscriptionId) { return ('resource group {0} is in none of the session''s subscriptions' -f $Ctx.ResourceGroup) }
    }
    $base = '/subscriptions/{0}/resourceGroups/{1}/providers' -f $Ctx.SubscriptionId, $Ctx.ResourceGroup
    $ids = Get-SIMoveArmList -Path ("$base/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=" + $script:SIMove.MiApi) -Reason $why
    $apps = Get-SIMoveArmList -Path ("$base/Microsoft.App/containerApps?api-version=" + $script:SIMove.AppApi) -Reason $why
    $jobs = Get-SIMoveArmList -Path ("$base/Microsoft.App/jobs?api-version=" + $script:SIMove.AppApi) -Reason $why
    $sql = Get-SIMoveArmList -Path ("$base/Microsoft.Sql/servers?api-version=" + $script:SIMove.SqlApi) -Reason $why
    $kv = Get-SIMoveArmList -Path ("$base/Microsoft.KeyVault/vaults?api-version=" + $script:SIMove.KvApi) -Reason $why
    foreach ($x in @(@('identities', $ids), @('container apps', $apps), @('jobs', $jobs), @('SQL servers', $sql), @('Key Vaults', $kv))) {
        if (-not $x[1].Ok) { return ('the {0} of {1} could not be listed (HTTP {2})' -f $x[0], $Ctx.ResourceGroup, $x[1].Status) }
    }
    $Ctx.Identities = @($ids.Items | ForEach-Object { ConvertTo-SIIdentityMoveIdentity $_ })
    $Ctx.Apps = @($apps.Items); $Ctx.Jobs = @($jobs.Items); $Ctx.Vaults = @($kv.Items)
    $Ctx.Databases = @(); $Ctx.SqlServer = ''; $Ctx.StateDatabase = ''
    if (@($sql.Items).Count -gt 1) { return ('{0} SQL servers in {1}: the move does not guess which is SecurityInsight''s' -f @($sql.Items).Count, $Ctx.ResourceGroup) }
    if (@($sql.Items).Count -eq 1) {
        $srv = $sql.Items[0]
        $Ctx.SqlServer = [string](Get-SIMoveProp $srv @('properties', 'fullyQualifiedDomainName')); $Ctx.SqlServerId = [string]$srv.id
        $dbs = Get-SIMoveArmList -Path ([string]$srv.id + '/databases?api-version=' + $script:SIMove.SqlApi) -Reason $why
        if (-not $dbs.Ok) { return ('the databases of {0} could not be listed (HTTP {1})' -f $Ctx.SqlServer, $dbs.Status) }
        $Ctx.Databases = @($dbs.Items | ForEach-Object { [string]$_.name } | Where-Object { $_ -and $_ -ne 'master' })
        $Ctx.StateDatabase = $(if ($Ctx.Databases -contains $script:SIMove.ProDatabase) { $script:SIMove.ProDatabase } else { '' })
    }
    # the sign-in app registration: the web app's AzureAd__ClientId
    $Ctx.SignInClientId = ''
    foreach ($a in $Ctx.Apps) {
        foreach ($c in @(Get-SIMoveProp $a @('properties', 'template', 'containers'))) {
            foreach ($e in @(Get-SIMoveProp $c @('env'))) { if ($e -and [string]$e.name -eq 'AzureAd__ClientId' -and [string]$e.value -match $script:SIMove.GuidRx) { $Ctx.SignInClientId = ([string]$e.value).ToLowerInvariant() } }
        }
    }
    $null
}

# =====================================================================================================================
#  RIGHTS (I/O reads)
# =====================================================================================================================

function Read-SIMoveAzureRoles {
    <# Every Azure role assignment of -PrincipalId: per subscription of the session (that read returns assignments at, above
       and below it -- management groups and the tenant root included) and per management group the Support app can see.
       @{ Items; Unknown (what could not be read) }. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$PrincipalId)
    $f = [uri]::EscapeDataString("principalId eq '$PrincipalId'")
    $seen = @{}; $items = New-Object System.Collections.Generic.List[object]; $unknown = New-Object System.Collections.Generic.List[string]
    $paths = @(@($Ctx.Subscriptions) | ForEach-Object { "/subscriptions/$_" })
    $mg = Get-SIMoveArmList -Path ('/providers/Microsoft.Management/managementGroups?api-version=' + $script:SIMove.MgApi) -Reason $Ctx.Reason
    if ($mg.Ok) { $paths += @($mg.Items | ForEach-Object { [string]$_.id }) } else { $unknown.Add("management groups (HTTP $($mg.Status))") }
    foreach ($p in $paths) {
        $l = Get-SIMoveArmList -Path ('{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}&$filter={2}' -f $p, $script:SIMove.RoleApi, $f) -Reason $Ctx.Reason
        if (-not $l.Ok) { if ($p -match '^/subscriptions/') { $unknown.Add("$p (HTTP $($l.Status))") }; continue }
        foreach ($a in $l.Items) { $k = ([string]$a.id).ToLowerInvariant(); if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $items.Add((ConvertTo-SIIdentityMoveAzureRole $a)) } }
    }
    [pscustomobject]@{ Items = @($items | Where-Object { $_.PrincipalId -ieq $PrincipalId }); Unknown = $unknown.ToArray() }
}

function Read-SIMoveRights {
    <# Step 1's read of ONE identity's rights (-Identity @{ Name; ClientId; PrincipalId }), and -Other's SQL rows for the diff.
       Returns @{ Azure; AppRoles; DirRoles; Fic (+ SignInAppObjectId); Sql (per database rows); Kv; Unknown }. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Identity)
    $unknown = New-Object System.Collections.Generic.List[string]
    $az = Read-SIMoveAzureRoles -Ctx $Ctx -PrincipalId $Identity.PrincipalId
    foreach ($u in $az.Unknown) { if ($u -notmatch '^management groups') { $unknown.Add("Azure roles: $u") } }
    $ar = Get-SIMoveGraphList -Uri ("servicePrincipals/{0}/appRoleAssignments" -f $Identity.PrincipalId) -Reason $Ctx.Reason
    if (-not $ar.Ok) { $unknown.Add("Graph app roles (HTTP $($ar.Status))") }
    $dr = Get-SIMoveGraphList -Uri ("roleManagement/directory/roleAssignments?`$filter=" + [uri]::EscapeDataString("principalId eq '$($Identity.PrincipalId)'")) -Reason $Ctx.Reason
    if (-not $dr.Ok) { $unknown.Add("Entra directory roles (HTTP $($dr.Status))") }
    $fic = @(); $appObj = ''
    if ($Ctx.SignInClientId) {
        $app = Invoke-SIMoveGraph -Uri ("applications(appId='{0}')?`$select=id" -f $Ctx.SignInClientId) -Reason $Ctx.Reason
        if ($app.Status -eq 200) {
            $appObj = [string]$app.Body.id
            $fl = Get-SIMoveGraphList -Uri ("applications/{0}/federatedIdentityCredentials" -f $appObj) -Reason $Ctx.Reason
            if ($fl.Ok) { $fic = @($fl.Items | Where-Object { "$($_.subject)".Trim() -ieq $Identity.PrincipalId }) } else { $unknown.Add("federated credentials (HTTP $($fl.Status))") }
        } else { $unknown.Add("the sign-in app registration (HTTP $($app.Status))") }
    }
    [pscustomobject]@{ Azure = @($az.Items); AzureNotes = @($az.Unknown); AppRoles = @($ar.Items); DirRoles = @($dr.Items); Fic = @($fic); SignInAppObjectId = $appObj; Unknown = $unknown.ToArray() }
}

function Read-SIMoveSqlRows {
    <# Per database: the rows of Get-SIIdentityMoveSqlReadSql. @{ <db> = rows }; a database that cannot be read -> Unknown. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$OldClientId, [string]$NewClientId)
    $out = @{}; $unknown = New-Object System.Collections.Generic.List[string]
    foreach ($db in @($Ctx.Databases)) {
        try { $out[$db] = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $db -Query (Get-SIIdentityMoveSqlReadSql -OldClientId $OldClientId -NewClientId $NewClientId) -Reason $Ctx.Reason) }
        catch { $unknown.Add(('SQL {0}: {1} (open the Support app''s just-in-time SQL grant first)' -f $db, (([string]$_.Exception.Message) -split "`n")[0])) }
    }
    [pscustomobject]@{ Databases = $out; Unknown = $unknown.ToArray() }
}

function Read-SIMoveSettingRows {
    <# cfg.Setting rows of the state database (SI_Mail_* and every row whose value is one of -Values). #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [string[]]$Values = @())
    if (-not $Ctx.StateDatabase) { return @() }
    $in = @(@('"' + 'x' + '"') + @($Values | Where-Object { $_ } | ForEach-Object { '"' + $_.ToLowerInvariant() + '"' }) | ForEach-Object { ConvertTo-SIMoveSqlText $_ }) -join ', '
    $q = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN (N'SI_Mail_Mode', N'SI_Mail_From') OR LOWER(ValueJson) IN ($in);"
    @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason)
}

function Read-SIMoveInstallState {
    <# One cfg.InstallState value (JSON parsed); $null when there is none. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Name)
    if (-not $Ctx.StateDatabase) { return $null }
    $q = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = $(ConvertTo-SIMoveSqlText $Name);"
    $row = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason)[0]
    if (-not $row -or -not [string]$row.Value) { return $null }
    try { [string]$row.Value | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}

function ConvertTo-SIIdentityMoveMode {
    <# PURE. The update's identity-names mode from the row's value: 'apply' only when it says so; anything else (no row, an
       unknown word) is 'plan' -- the per-install plan first, nothing changed. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim().Trim('"').ToLowerInvariant()
    if ($v -eq 'apply') { return 'apply' }
    if ($v -eq 'off') { return 'off' }
    'plan'
}

function Read-SIIdentityMoveMode {
    <# The install's identity-names mode (cfg.InstallState 'IdentityMoveMode'): plan (default) | apply | off. #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    if (-not $Ctx.StateDatabase) { return 'plan' }
    $q = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'IdentityMoveMode';"
    $row = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason)[0]
    ConvertTo-SIIdentityMoveMode -Value $(if ($row) { [string](Get-SIMoveProp $row @('Value')) } else { '' })
}

function Set-SIIdentityMoveMode {
    <# The per-install approval: cfg.InstallState 'IdentityMoveMode' = plan | apply | off, written and READ BACK. Set through
       the Support app (ops identity move -UpdaterMode) once the install's plan is approved. $true = it reads back. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][ValidateSet('plan', 'apply', 'off')][string]$Mode)
    Save-SIMoveInstallState -Ctx $Ctx -Name 'IdentityMoveMode' -Value $Mode
}

function Read-SIMoveState {
    <# The move record as { roles: { <role>: {...} } } from its rows: one cfg.InstallState row per role, Name
       'IdentityMove.<role>' (cfg.InstallState.Value holds 400 characters, and one record for every role did not fit -- live
       at internal 2026-11-04). An older whole-install row 'IdentityMove' is read first; a per-role row wins. #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $roles = [ordered]@{}
    if (-not $Ctx.StateDatabase) { return [pscustomobject]@{ roles = [pscustomobject]$roles } }
    $q = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name = N'$($script:SIMove.StateName)' OR Name LIKE N'$($script:SIMove.StateName).%' ORDER BY Name;"
    foreach ($row in @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason)) {
        if (-not $row -or -not [string]$row.Value) { continue }
        $v = $null; try { $v = [string]$row.Value | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        $n = [string]$row.Name
        if ($n -eq $script:SIMove.StateName) {
            $r = Get-SIMoveProp $v @('roles')
            if ($r) { foreach ($p in @($r.PSObject.Properties)) { if (-not $roles.Contains($p.Name)) { $roles[$p.Name] = $p.Value } } }
        } else { $roles[$n.Substring($script:SIMove.StateName.Length + 1)] = $v }
    }
    [pscustomobject]@{ roles = [pscustomobject]$roles }
}

function Save-SIMoveRoleState {
    <# One role's move record (-Values set on it; null removes a key) written to its own row 'IdentityMove.<role>' and READ
       BACK. Returns $true when the stored value is what was written. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, $State, [Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][hashtable]$Values)
    $all = Update-SIIdentityMoveState -State $State -Role $Role -Values $Values | ConvertFrom-Json
    $roleObj = Get-SIMoveProp $all @('roles', $Role)
    $one = $roleObj | ConvertTo-Json -Depth 6 -Compress
    # every step's time fits; the old / new name blocks are only a note for people -- they go first when the row is too long
    foreach ($drop in 'new', 'old') {
        if ($one.Length -le $script:SIMove.InstallStateMax) { break }
        if ($roleObj -and $roleObj.PSObject.Properties[$drop]) { $roleObj.PSObject.Properties.Remove($drop); $one = $roleObj | ConvertTo-Json -Depth 6 -Compress }
    }
    if ($one.Length -gt $script:SIMove.InstallStateMax) { throw ("the move record of role {0} is {1} characters; the install state holds {2}" -f $Role, $one.Length, $script:SIMove.InstallStateMax) }
    Save-SIMoveInstallState -Ctx $Ctx -Name ('{0}.{1}' -f $script:SIMove.StateName, $Role) -Value $one
}
function Save-SIMoveInstallState {
    <# One cfg.InstallState row written (upsert) and READ BACK. Returns $true when the stored value is -Value. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    if (-not $Ctx.StateDatabase) { throw 'the install''s state database (sqldb-si-pro) was not found' }
    $q = @"
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @Name nvarchar(128) = $(ConvertTo-SIMoveSqlText $Name), @Value nvarchar(max) = $(ConvertTo-SIMoveSqlText $Value), @By nvarchar(256) = $(ConvertTo-SIMoveSqlText $script:SIMove.ChangedBy);
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
    UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
ELSE
    INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
COMMIT;
"@
    $null = Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason -Change
    $back = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query ("SET NOCOUNT ON; SELECT Value FROM cfg.InstallState WHERE Name = $(ConvertTo-SIMoveSqlText $Name);") -Reason $Ctx.Reason)[0]
    [bool]($back -and [string]$back.Value -ceq $Value)
}

function Wait-SIMoveArmProvisioned {
    <# Polls an app / job until provisioningState is Succeeded (read back). Returns the resource, or throws with Azure's words. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Id)
    for ($i = 0; $i -lt $script:SIMove.Waits.ProvisionTries; $i++) {
        $g = Invoke-SIMoveArm -Path ($Id + '?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
        $ps = [string](Get-SIMoveProp $g.Body @('properties', 'provisioningState'))
        if ($g.Status -eq 200 -and $ps -eq 'Succeeded') { return $g.Body }
        if ($g.Status -eq 200 -and $ps -match '^(?i)(Failed|Canceled)$') { throw ('{0} is {1} after the write' -f ($Id -split '/')[-1], $ps) }
        Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds
    }
    throw ('{0} did not finish provisioning in time' -f ($Id -split '/')[-1])
}

function Wait-SIMoveArmReadBack {
    <# After a write: the app / job read until provisioning has finished AND -Test { param($Body) } holds -- a read right
       after the write can still show the state from before it (provisioningState Succeeded, the write not yet taken up), so
       one read is never the verdict. Returns @{ Ok; Body (the last read) }; throws with Azure's words on Failed / Canceled. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][scriptblock]$Test)
    $back = $null
    for ($i = 0; $i -lt $script:SIMove.Waits.Tries; $i++) {
        $back = Wait-SIMoveArmProvisioned -Ctx $Ctx -Id $Id
        if (& $Test $back) { return [pscustomobject]@{ Ok = $true; Body = $back } }
        if ($i -lt $script:SIMove.Waits.Tries - 1) { Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds }
    }
    [pscustomobject]@{ Ok = $false; Body = $back }
}

# =====================================================================================================================
#  THE SEVEN STEPS
# =====================================================================================================================

function Invoke-SIMoveInventory {
    <# Step 1 (read only). Data: @{ Selection; Users; OldRights; NewRights; Sql; Settings; Mail }. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Role)
    $sel = Select-SIIdentityMoveIdentities -Identities $Ctx.Identities -Role $Role -OldName $Ctx.OldName
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('{0}: {1}' -f $Role, $sel.Why))
    if ($sel.State -eq 'ambiguous') { return New-SIIdentityMoveStepResult -Step inventory -State stop -Lines $lines -Data @{ Selection = $sel } }
    if ($sel.State -ne 'move') { return New-SIIdentityMoveStepResult -Step inventory -State 'n/a' -Lines $lines -Data @{ Selection = $sel } }
    $old = $sel.Old
    $users = @(Get-SIIdentityMoveUsers -Resources (@($Ctx.Apps) + @($Ctx.Jobs)) -IdentityIds @($old.Id, $(if ($sel.New) { $sel.New.Id })))
    $lines.Add(('{0} ({1}, object id {2}) is attached to {3} app(s) / job(s): {4}' -f $old.Name, $old.ClientId, $old.PrincipalId, $users.Count, (($users | ForEach-Object Name) -join ', ')))
    $or = Read-SIMoveRights -Ctx $Ctx -Identity $old
    $nr = if ($sel.New) { Read-SIMoveRights -Ctx $Ctx -Identity $sel.New } else { $null }
    # updater mode: the SQL side is the database setup job's (it is the SQL admin; the update's own identity may not make
    # users) -- it reads, copies and reads back in every product database itself (step 3)
    $sqlR = if ($Ctx.SqlServer -and "$($Ctx.SqlVia)" -ne 'dbjob') { Read-SIMoveSqlRows -Ctx $Ctx -OldClientId $old.ClientId -NewClientId $(if ($sel.New) { $sel.New.ClientId } else { '' }) } else { [pscustomobject]@{ Databases = @{}; Unknown = @() } }
    if ($Ctx.SqlServer -and "$($Ctx.SqlVia)" -eq 'dbjob') { $lines.Add('SQL: read, copied and read back in every product database by the database setup job (step 3)') }
    $settings = @(); $mail = [pscustomobject]@{ SharedMailbox = $false; From = '' }
    try { $settings = @(Read-SIMoveSettingRows -Ctx $Ctx -Values @($old.ClientId, $old.Name)); $mail = Get-SIIdentityMoveMailMode -Rows $settings }
    catch { $or.Unknown += ('SI settings: ' + (([string]$_.Exception.Message) -split "`n")[0]) }
    $lines.Add(('rights: {0} Azure role assignment(s) [{1}], {2} Graph app role(s), {3} Entra directory role(s), {4} federated credential(s)' -f
        @($or.Azure).Count, ((@($or.Azure) | ForEach-Object { '{0} at {1}' -f $_.RoleGuid, $(if ($_.Scope) { $_.Scope } else { '/' }) }) -join '; '), @($or.AppRoles).Count, @($or.DirRoles).Count, @($or.Fic).Count))
    foreach ($db in @($sqlR.Databases.Keys | Sort-Object)) {
        $rows = @($sqlR.Databases[$db] | Where-Object Who -eq 'old')
        $u = @($rows | Where-Object Kind -eq 'user')[0]
        $lines.Add(('SQL {0}: {1}' -f $db, $(if ($u) { 'user {0}, roles {1}, {2} explicit permission(s)' -f $u.Name, ((@($rows | Where-Object Kind -eq 'role') | ForEach-Object Name) -join ', '), @($rows | Where-Object Kind -eq 'perm').Count } else { 'no user' })))
    }
    foreach ($v in @($Ctx.Vaults)) { $lines.Add(('Key Vault {0}: {1}' -f $v.name, $(if ([bool](Get-SIMoveProp $v @('properties', 'enableRbacAuthorization'))) { 'RBAC (covered by the Azure role assignments)' } else { 'access policies' }))) }
    $lines.Add('registry pull: the AcrPull role assignment (above) and each app''s / job''s registry identity (step 4)')
    $def = (Get-SIIdentityMoveRoleTable)[$Role]
    $lines.Add(('Exchange: {0}' -f $(if ($mail.SharedMailbox -and $def.MailSender) { "shared mailbox $($mail.From): the identity's Application Mail.Send (Exchange cannot be read by this tool; step 3 grants it with Set-SIMail)" } elseif ($mail.SharedMailbox) { 'mail is on, this role does not send' } else { 'no shared-mailbox mail' })))
    $unk = @($or.Unknown) + @($sqlR.Unknown)
    foreach ($u in $unk) { $lines.Add("NOT READ: $u") }
    foreach ($u in @($or.AzureNotes | Where-Object { $_ -match '^management groups' })) { $lines.Add("note: $u -- assignments at a management group above the subscriptions are still found through them") }
    $data = @{ Selection = $sel; Users = $users; OldRights = $or; NewRights = $nr; Sql = $sqlR; Settings = $settings; Mail = $mail; Unknown = @($unk) }
    # updater mode: what the update may not READ does not stop the inventory -- step 3 makes it a support step (or trusts a
    # copy a Support-app run already read back); support mode: nothing is copied or switched until every right can be read
    $state = if ($unk.Count -and "$($Ctx.Mode)" -ne 'updater') { 'stop' } else { 'done' }
    if ($unk.Count -and "$($Ctx.Mode)" -ne 'updater') { $lines.Add('the inventory is incomplete: nothing is copied or switched until every right can be read') }
    New-SIIdentityMoveStepResult -Step inventory -State $state -Lines $lines -Data $data
}

function Invoke-SIMoveEnsure {
    <# Step 2: id-si-<role> in the install's resource group (the old identity's location and tags), created and READ BACK
       until it has its client id and principal id, then until Entra knows its service principal. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Inventory)
    $sel = $Inventory.Selection
    if ($sel.New) { return New-SIIdentityMoveStepResult -Step ensure -State done -Lines @(('{0} exists (client id {1}, object id {2})' -f $sel.New.Name, $sel.New.ClientId, $sel.New.PrincipalId)) }
    $path = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{2}?api-version={3}' -f $Ctx.SubscriptionId, $Ctx.ResourceGroup, $sel.Standard, $script:SIMove.MiApi
    $body = [ordered]@{ location = $sel.Old.Location }
    if ($sel.Old.Tags) { $body.tags = $sel.Old.Tags }
    $line = ('PUT {0} in {1} ({2}, the tags of {3})' -f $sel.Standard, $Ctx.ResourceGroup, $sel.Old.Location, $sel.Old.Name)
    if (-not $Ctx.Apply) { return New-SIIdentityMoveStepResult -Step ensure -State planned -Lines @($line) }
    $w = Invoke-SIMoveArm -Method PUT -Path $path -Body $body -Reason $Ctx.Reason
    if ($w.Status -notin 200, 201) { return New-SIIdentityMoveStepResult -Step ensure -State stop -Lines @($line, ('Azure answered HTTP {0}: {1}' -f $w.Status, $w.Text)) }
    $made = $null
    for ($i = 0; $i -lt $script:SIMove.Waits.Tries; $i++) {
        $g = Invoke-SIMoveArm -Path $path -Reason $Ctx.Reason
        if ($g.Status -eq 200) { $made = ConvertTo-SIIdentityMoveIdentity $g.Body; if ($made.ClientId -and $made.PrincipalId) { break } }
        Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds
    }
    if (-not $made -or -not $made.ClientId -or -not $made.PrincipalId) { return New-SIIdentityMoveStepResult -Step ensure -State stop -Lines @($line, 'created, but it does not read back with its client id and object id yet -- run the same step again') }
    $sp = $false
    for ($i = 0; $i -lt $script:SIMove.Waits.Tries -and -not $sp; $i++) {
        $s = Invoke-SIMoveGraph -Uri ("servicePrincipals/{0}?`$select=id,appId" -f $made.PrincipalId) -Reason $Ctx.Reason
        $sp = $s.Status -eq 200
        if (-not $sp) { Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds }
    }
    $Ctx.Identities = @(@($Ctx.Identities) + @($made))
    $Inventory.Selection = [pscustomobject]@{ Role = $sel.Role; Standard = $sel.Standard; Old = $sel.Old; New = $made; State = $sel.State; Why = $sel.Why }
    if (-not $sp) { return New-SIIdentityMoveStepResult -Step ensure -State waits -Lines @($line, ('{0} is made (client id {1}) but Entra does not show its service principal yet -- run again in a minute' -f $made.Name, $made.ClientId)) }
    New-SIIdentityMoveStepResult -Step ensure -State done -Lines @($line, ('read back: client id {0}, object id {1}' -f $made.ClientId, $made.PrincipalId))
}

function Get-SIMoveCopyPlans {
    <# PURE over the inventory: everything step 3 still has to give the new identity. #>
    param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)][string]$TenantId, [object[]]$Vaults = @(), $NewIdentity)
    $sel = $Inventory.Selection; $o = $Inventory.OldRights; $n = $Inventory.NewRights
    $newId = if ($NewIdentity) { $NewIdentity } else { $sel.New }
    $newPid = [string]$newId.PrincipalId
    $nAz = if ($n) { @($n.Azure) } else { @() }; $nAr = if ($n) { @($n.AppRoles) } else { @() }; $nDr = if ($n) { @($n.DirRoles) } else { @() }; $nFic = if ($n) { @($n.Fic) } else { @() }
    $ficNeeded = (@($o.Fic).Count -gt 0) -and -not (Test-SIMoveFicPresent -Credentials $nFic -TenantId $TenantId -PrincipalId $newPid)
    $sql = @{}
    foreach ($db in @($Inventory.Sql.Databases.Keys)) { $sql[$db] = Get-SIIdentityMoveSqlCopy -Rows $Inventory.Sql.Databases[$db] -NewName $sel.Standard -NewClientId $newId.ClientId }
    [pscustomobject]@{
        Azure    = @(Get-SIIdentityMoveAzureCopyPlan -Old $o.Azure -New $nAz -OldPrincipalId $sel.Old.PrincipalId -NewPrincipalId $newPid)
        AppRoles = @(Get-SIIdentityMoveAppRoleCopyPlan -Old $o.AppRoles -New $nAr)
        DirRoles = @(Get-SIIdentityMoveDirRoleCopyPlan -Old $o.DirRoles -New $nDr)
        Fic      = $ficNeeded
        Sql      = $sql
        Kv       = @(Get-SIIdentityMoveKvCopyPlan -Vaults $Vaults -OldPrincipalId $sel.Old.PrincipalId -NewPrincipalId $newPid)
    }
}

function Test-SIMoveFicPresent {
    <# PURE. Does the sign-in app trust -PrincipalId (a federated credential)? The web deploy's own check when it is loaded,
       else a credential whose subject is the principal id and whose issuer is the tenant's. #>
    param([object[]]$Credentials = @(), [string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    if (Get-Command -Name Test-SIManagementFederatedCredential -ErrorAction SilentlyContinue) { return [bool](Test-SIManagementFederatedCredential -Credentials $Credentials -TenantId $TenantId -PrincipalId $PrincipalId) }
    [bool](@($Credentials | Where-Object { $_ -and "$($_.subject)".Trim() -ieq $PrincipalId -and ("$($_.issuer)" -match [regex]::Escape("$TenantId")) }).Count)
}

function Test-SIMoveCopyComplete {
    <# PURE. Nothing left to copy (customer steps already confirmed are not counted by the caller). #>
    param([Parameter(Mandatory)]$Plans)
    -not (@($Plans.Azure).Count -or @($Plans.AppRoles).Count -or @($Plans.DirRoles).Count -or $Plans.Fic -or @($Plans.Kv).Count -or
          @($Plans.Sql.Values | Where-Object { $_.Sql -or @($_.Unsupported).Count }).Count)
}

function Invoke-SIMoveCopyRights {
    <# Step 3: the new identity gets exactly the old one's rights. Every grant read back; what the Support app may not grant is
       a customer step and the role waits for it. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Inventory, [string[]]$Confirmed = @())
    $sel = $Inventory.Selection; $role = $sel.Role
    $lines = New-Object System.Collections.Generic.List[string]; $cust = New-Object System.Collections.Generic.List[object]; $stop = $false
    $target = $sel.New
    if (-not $target) {
        if ($Ctx.Apply) { return New-SIIdentityMoveStepResult -Step copy-rights -State stop -Lines @(('{0} does not exist (step ensure first)' -f $sel.Standard)) }
        # a plan before the identity exists: everything the old one holds (a placeholder stands for the new identity's ids)
        $target = [pscustomobject]@{ Name = $sel.Standard; Id = ''; ClientId = '00000000-0000-0000-0000-000000000000'; PrincipalId = '00000000-0000-0000-0000-000000000000' }
        $lines.Add(('{0} does not exist yet: every right below is copied to it once it does' -f $sel.Standard))
    }
    $plans = Get-SIMoveCopyPlans -Inventory $Inventory -TenantId $Ctx.TenantId -Vaults $Ctx.Vaults -NewIdentity $target
    $newPid = $target.PrincipalId
    $moveState = $null
    if ($Ctx.StateDatabase) { try { $moveState = Read-SIMoveState -Ctx $Ctx } catch { $moveState = $null } }
    if ([string](Get-SIMoveProp $moveState @('roles', $role, 'exchangeUtc'))) { $Confirmed = @($Confirmed) + 'exchange' }
    $updater = "$($Ctx.Mode)" -eq 'updater'
    # updater mode: rights the update may not READ (an Azure scope above its resource group, Entra roles ...) are copied by a
    # Support-app run that reads them all; once one has recorded its read-back (rightsUtc -- or the role was already
    # switched, which only ever follows a complete copy), the update trusts it for those parts and checks what it can read
    $unread = @($Inventory.Unknown | Where-Object { $_ })
    if ($updater -and $unread.Count) {
        $rec = Get-SIMoveProp $moveState @('roles', $role)
        $trusted = [string](Get-SIMoveProp $rec @('rightsUtc')) -or [string](Get-SIMoveProp $rec @('switchedUtc')) -or [string](Get-SIMoveProp $rec @('provenUtc'))
        if ($trusted) { $lines.Add(('not readable by this update ({0}) -- copied and read back by a Support-app run earlier' -f ($unread -join '; '))) }
        else {
            $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind read-rights -Key 'read-rights' `
                -What ('SecurityInsight''s identity {0} must get every right {1} has today, and this update may not read all of them: {2}.' -f $sel.Standard, $sel.Old.Name, ($unread -join '; ')) `
                -How 'x'))
            $lines.Add(('support step: the rights this update may not read are copied by the Support app ({0})' -f ($unread -join '; ')))
        }
    }
    foreach ($a in $plans.Azure) {
        $sc = if ("$($a.Scope)".Trim()) { $a.Scope } else { '/' }
        $line = 'Azure role {0} at {1}' -f $a.RoleGuid, $sc
        if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
        $ok = $false; $st = 0; $txt = ''
        for ($i = 0; $i -lt $script:SIMove.Waits.Tries -and -not $ok; $i++) {
            $w = Invoke-SIMoveArm -Method PUT -Path (Get-SIIdentityMoveAzureAssignmentPath -Scope $a.Scope -Name ([guid]::NewGuid().ToString())) -Body (Get-SIIdentityMoveAzureAssignmentBody -Like $a -PrincipalId $newPid) -Reason $Ctx.Reason
            $st = $w.Status; $txt = $w.Text
            if ($st -in 200, 201 -or ($st -eq 409 -and $txt -match 'RoleAssignmentExists')) { $ok = $true; break }
            if ($st -eq 400 -and $txt -match 'PrincipalNotFound') { Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds; continue }
            break
        }
        if ($ok) { $lines.Add("granted: $line") }
        elseif ($st -eq 403) {
            $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind azure-role -Key ("azure-role:{0}:{1}" -f $a.RoleGuid, $sc) `
                -What ('SecurityInsight''s identity {0} needs the Azure role {1} at {2} (the same right {3} has today).' -f $sel.Standard, $a.RoleGuid, $sc, $sel.Old.Name) `
                -How ('An Owner / User Access Administrator of {0}: Access control (IAM) > Add role assignment > that role > Managed identity > {1} (resource group {2}).' -f $sc, $sel.Standard, $Ctx.ResourceGroup)))
            $lines.Add("customer step: $line (the Support app may not grant it)")
        } else { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1} {2}' -f $line, $st, ($txt -split "`n")[0])) }
    }
    $missingGraph = New-Object System.Collections.Generic.List[string]
    foreach ($a in $plans.AppRoles) {
        $line = 'Graph app role {0} on {1}' -f $a.appRoleId, $(if ($a.resourceDisplayName) { $a.resourceDisplayName } else { $a.resourceId })
        if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
        $w = Invoke-SIMoveGraph -Method POST -Uri ("servicePrincipals/{0}/appRoleAssignments" -f $newPid) -Body ([ordered]@{ principalId = $newPid; resourceId = [string]$a.resourceId; appRoleId = [string]$a.appRoleId }) -Reason $Ctx.Reason
        if ($w.Status -in 200, 201 -or ($w.Status -eq 400 -and $w.Text -match 'already exists')) { $lines.Add("granted: $line") }
        elseif ($w.Status -eq 403) { $missingGraph.Add(('{0} ({1})' -f $a.appRoleId, $(if ($a.resourceDisplayName) { $a.resourceDisplayName } else { $a.resourceId }))); $lines.Add("customer step: $line") }
        else { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1} {2}' -f $line, $w.Status, ($w.Text -split "`n")[0])) }
    }
    if ($missingGraph.Count) {
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind graph-app-roles `
            -What ('SecurityInsight''s identity {0} needs the same application permissions {1} has today: {2}.' -f $sel.Standard, $sel.Old.Name, ($missingGraph -join ', ')) `
            -How ('A Privileged Role Administrator runs Grant-SIIdentity.ps1 -IdentityName {0} -IdentityResourceGroup {1} -SubscriptionId {2} -Apply (https://invardia.com/support/si/Grant-SIIdentity.ps1).' -f $sel.Standard, $Ctx.ResourceGroup, $Ctx.SubscriptionId)))
    }
    foreach ($a in $plans.DirRoles) {
        $line = 'Entra directory role {0} at {1}' -f $a.roleDefinitionId, $(if ($a.directoryScopeId) { $a.directoryScopeId } else { '/' })
        if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
        $w = Invoke-SIMoveGraph -Method POST -Uri 'roleManagement/directory/roleAssignments' -Body ([ordered]@{ principalId = $newPid; roleDefinitionId = [string]$a.roleDefinitionId; directoryScopeId = $(if ($a.directoryScopeId) { [string]$a.directoryScopeId } else { '/' }) }) -Reason $Ctx.Reason
        if ($w.Status -in 200, 201) { $lines.Add("granted: $line") }
        elseif ($w.Status -eq 403) {
            $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind directory-role -Key ("directory-role:{0}" -f $a.roleDefinitionId) `
                -What ('SecurityInsight''s identity {0} needs the Entra role {1} that {2} holds today.' -f $sel.Standard, $a.roleDefinitionId, $sel.Old.Name) `
                -How ('A Privileged Role Administrator: Entra admin center > Roles and administrators > that role > Add assignments > {0}.' -f $sel.Standard)))
            $lines.Add("customer step: $line")
        } else { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1}' -f $line, $w.Status)) }
    }
    if ($plans.Fic -and -not (Get-Command -Name Get-SIManagementFederatedCredentialSpec -ErrorAction SilentlyContinue)) {
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind federated-credential -What ('The web app''s sign-in registration must trust SecurityInsight''s new web identity {0} (a federated credential).' -f $sel.Standard) -How 'x'))
        $lines.Add('support step: the federated credential (this copy of SecurityInsight carries no sign-in credential builder)')
    } elseif ($plans.Fic) {
        $spec = Get-SIManagementFederatedCredentialSpec -TenantId $Ctx.TenantId -PrincipalId $newPid
        $line = 'federated credential {0} on the sign-in app {1} (subject {2})' -f $spec.name, $Ctx.SignInClientId, $newPid
        if (-not $Ctx.Apply) { $lines.Add("plan: $line") }
        else {
            $w = Invoke-SIMoveGraph -Method POST -Uri ("applications/{0}/federatedIdentityCredentials" -f $Inventory.OldRights.SignInAppObjectId) -Body $spec -Reason $Ctx.Reason
            if ($w.Status -in 200, 201) { $lines.Add("granted: $line") }
            elseif ($w.Status -eq 403) {
                $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind federated-credential `
                    -What ('The web app''s sign-in registration must trust SecurityInsight''s new web identity {0} (a federated credential; no secret, no certificate).' -f $sel.Standard) `
                    -How ('An Application Administrator: Entra admin center > App registrations > the SecurityInsight sign-in app > Certificates & secrets > Federated credentials > Add > Managed identity > {0}.' -f $sel.Standard)))
                $lines.Add("customer step: $line")
            } else { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1}' -f $line, $w.Status)) }
        }
    }
    foreach ($db in @($plans.Sql.Keys | Sort-Object)) {
        $p = $plans.Sql[$db]
        foreach ($u in $p.Unsupported) { $stop = $true; $lines.Add(('STOP: SQL {0}: {1} cannot be copied by this tool (column-level or an unknown class) -- copy it by hand, then run again' -f $db, $u)) }
        if (-not $p.Sql) { continue }
        if (-not $Ctx.Apply) { $lines.Add(('plan: SQL {0}: {1}' -f $db, ($p.Items -join '; '))); continue }
        try {
            $null = Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $db -Query $p.Sql -Reason $Ctx.Reason -Change
            $lines.Add(('granted: SQL {0}: {1}' -f $db, ($p.Items -join '; ')))
        } catch { $stop = $true; $lines.Add(('FAILED: SQL {0}: {1}' -f $db, (([string]$_.Exception.Message) -split "`n")[0])) }
    }
    # updater mode: the database setup job copies the old user's roles and grants in EVERY product database and reads them
    # back (setup\_shared\SI-DbInitJob.ps1, SI_DBINIT_MOVES) -- once per role (sqlUtc), the job's run is not repeated
    if ($updater -and $Ctx.SqlServer -and "$($Ctx.SqlVia)" -eq 'dbjob') {
        $sqlDone = [string](Get-SIMoveProp $moveState @('roles', $role, 'sqlUtc'))
        $mv = [ordered]@{ component = $role; from = $sel.Old.ClientId; to = [string]$target.ClientId; toName = $sel.Standard }
        if ($sqlDone) { $lines.Add(('SQL: copied and read back by the database setup job at {0}' -f $sqlDone)) }
        elseif (-not $Ctx.Apply) { $lines.Add(('plan: SQL: the database setup job copies {0}''s user, roles and grants to {1} in every product database and reads them back' -f $sel.Old.Name, $sel.Standard)) }
        else {
            $dj = Invoke-SIMoveDbJob -Ctx $Ctx -Moves @($mv)
            $st = if ($dj -and $dj.States) { [string]$dj.States[$role] } else { '' }
            if ($dj -and $dj.Ok -and $st -in 'ok', 'none') {
                $lines.Add(('granted: SQL: the database setup job copied {0}''s rights to {1} in every product database ({2}, read back)' -f $sel.Old.Name, $sel.Standard, $st))
                $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                if (-not (Save-SIMoveRoleState -Ctx $Ctx -State $moveState -Role $role -Values @{ sqlUtc = $now })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record (SQL copied)') }
                else { try { $moveState = Read-SIMoveState -Ctx $Ctx } catch { } }
            } elseif ($dj -and "$($dj.Why)" -match '^waits:') { $lines.Add(('SQL {0}' -f $dj.Why)); $script:SIMoveSqlWaits = $true }
            else { $stop = $true; $lines.Add(('FAILED: SQL: the database setup job did not copy and read back {0} ({1}) -- the old identity keeps every right' -f $sel.Standard, $(if ($dj) { $dj.Why } else { 'no answer' }))) }
        }
    }
    foreach ($k in $plans.Kv) {
        $line = 'Key Vault {0}: the access policy of {1}' -f $k.VaultName, $sel.Old.Name
        if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
        $w = Invoke-SIMoveArm -Method PUT -Path ('{0}/accessPolicies/add?api-version={1}' -f $k.VaultId, $script:SIMove.KvApi) -Body ([ordered]@{ properties = [ordered]@{ accessPolicies = @([ordered]@{ tenantId = $k.TenantId; objectId = $newPid; permissions = $k.Permissions }) } }) -Reason $Ctx.Reason
        if ($w.Status -in 200, 201) { $lines.Add("granted: $line") } else { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1}' -f $line, $w.Status)) }
    }
    # Exchange: the shared mailbox's Application Mail.Send for the new identity -- through SI's own mail setup (Set-SIMail.ps1,
    # its Exchange admin role activated just in time); when it cannot, a customer step
    $def = (Get-SIIdentityMoveRoleTable)[$role]
    if ($Inventory.Mail.SharedMailbox -and $def.MailSender -and $Confirmed -notcontains 'exchange' -and $updater) {
        # the update never signs in to Exchange: a support step (Set-SIMail.ps1 through the Support app)
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind exchange -What ('SecurityInsight''s identity {0} must be allowed to send as {1} (Exchange: Application Mail.Send in the mailbox''s scope), as {2} is today.' -f $sel.Standard, $Inventory.Mail.From, $sel.Old.Name) -How 'x'))
        $lines.Add(('support step: Exchange: Application Mail.Send for {0} on {1}' -f $sel.Standard, $Inventory.Mail.From))
    } elseif ($Inventory.Mail.SharedMailbox -and $def.MailSender -and $Confirmed -notcontains 'exchange') {
        $line = 'Exchange: Application Mail.Send for {0} on {1}' -f $sel.Standard, $Inventory.Mail.From
        if (-not $Ctx.Apply) { $lines.Add("plan: $line (Set-SIMail.ps1 -IdentityObjectId $newPid)") }
        else {
            $ok = $false
            try { $ok = Invoke-SIMoveMailGrant -Ctx $Ctx -From $Inventory.Mail.From -PrincipalId $newPid } catch { $lines.Add(('Exchange: {0}' -f (([string]$_.Exception.Message) -split "`n")[0])) }
            if ($ok) {
                $lines.Add("granted: $line (read back by Set-SIMail)")
                $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                if (-not (Save-SIMoveRoleState -Ctx $Ctx -State $moveState -Role $role -Values @{ exchangeUtc = $now })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record (Exchange granted)') }
            }
            else {
                $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind exchange `
                    -What ('SecurityInsight''s identity {0} must be allowed to send as {1} (Exchange: Application Mail.Send in the mailbox''s scope), as {2} is today.' -f $sel.Standard, $Inventory.Mail.From, $sel.Old.Name) `
                    -How ('An Exchange administrator runs Set-SIMail.ps1 -SharedMailbox {0} -IdentityObjectId {1} -UseSignedInAccount -Apply (https://invardia.com/support/si/Set-SIMail.ps1).' -f $Inventory.Mail.From, $newPid)))
                $lines.Add("customer step: $line")
            }
        }
    }
    # READ BACK: the inventory of the new identity again, and the plans must be empty except the customer steps
    if ($Ctx.Apply -and -not $stop) {
        $Inventory.NewRights = Read-SIMoveRights -Ctx $Ctx -Identity $sel.New
        if ($Ctx.SqlServer -and "$($Ctx.SqlVia)" -ne 'dbjob') { $Inventory.Sql = Read-SIMoveSqlRows -Ctx $Ctx -OldClientId $sel.Old.ClientId -NewClientId $sel.New.ClientId }
        $after = Get-SIMoveCopyPlans -Inventory $Inventory -TenantId $Ctx.TenantId -Vaults $Ctx.Vaults
        $openAz = @($after.Azure | Where-Object { $a = $_; -not @($cust | Where-Object { $_.Kind -eq 'azure-role' -and $_.Key -like ("azure-role:{0}:*" -f $a.RoleGuid) }).Count })
        $openGraph = if (@($cust | Where-Object Kind -eq 'graph-app-roles').Count) { @() } else { @($after.AppRoles) }
        $openDir = @($after.DirRoles | Where-Object { $a = $_; -not @($cust | Where-Object { $_.Key -eq ("directory-role:{0}" -f $a.roleDefinitionId) }).Count })
        $openFic = $after.Fic -and -not @($cust | Where-Object Kind -eq 'federated-credential').Count
        $openSql = @($after.Sql.Keys | Where-Object { $after.Sql[$_].Sql })
        if ($openAz.Count -or $openGraph.Count -or $openDir.Count -or $openFic -or $openSql.Count -or @($after.Kv).Count) {
            $stop = $true
            $lines.Add(('READ BACK: still missing after the grants -- Azure {0}, Graph {1}, Entra {2}, federated credential {3}, SQL {4}, Key Vault {5}' -f $openAz.Count, $openGraph.Count, $openDir.Count, [bool]$openFic, ($openSql -join ','), @($after.Kv).Count))
        } else {
            $lines.Add(('read back: the new identity holds every right {0} could grant' -f $(if ($updater) { 'this update' } else { 'the Support app' })))
            # a run that READ every right and found none missing records it: the update trusts this copy for what it may not
            # read itself (support mode; an update only when it could read everything)
            if (-not $cust.Count -and -not @($Inventory.Unknown | Where-Object { $_ }).Count) {
                $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                if (-not (Save-SIMoveRoleState -Ctx $Ctx -State (Read-SIMoveState -Ctx $Ctx) -Role $role -Values @{ rightsUtc = $now })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record (rights copied)') }
            }
        }
    }
    $sqlWait = [bool]$script:SIMoveSqlWaits; $script:SIMoveSqlWaits = $false
    $state = if ($stop) { 'stop' } elseif ($cust.Count) { 'customer' } elseif ($sqlWait) { 'waits' } elseif (-not $Ctx.Apply -and -not (Test-SIMoveCopyComplete -Plans $plans)) { 'planned' } else { 'done' }
    if ($state -eq 'done' -and -not $lines.Count) { $lines.Add('the new identity already holds every right of the old one') }
    New-SIIdentityMoveStepResult -Step copy-rights -State $state -Lines $lines -CustomerSteps $cust -Data $plans
}

function Invoke-SIMoveMailGrant {
    <# Exchange through SI's own mail setup (setup\Set-SIMail.ps1, in this Support session): the new identity registered and
       given the scoped Application Mail.Send; its own read-back (Test-ServicePrincipalAuthorization) decides. $true = granted. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$PrincipalId)
    $out = Join-Path ([IO.Path]::GetTempPath()) ('si-idmove-mail-{0}.json' -f [guid]::NewGuid().ToString('n'))
    try {
        $null = & (Join-Path $script:SIMoveRoot 'setup\Set-SIMail.ps1') -Mode sharedMailbox -SharedMailbox $From -CreateMailbox:$false -IdentityObjectId @($PrincipalId) `
            -UseSignedInAccount -ActivateExchangeAdmin -Apply -OutFile $out
        if (-not (Test-Path -LiteralPath $out)) { return $false }
        $r = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
        [bool]$r.ok
    } finally { Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue }
}

function Invoke-SIMoveSwitch {
    <# Step 4: attach + switch every app / job of the role (old identity stays attached), the SI settings and the install's
       names record; never while an execution of that job or a pipeline run is going. -Rollback: the same, reversed. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Inventory, $CopyResult, [switch]$Rollback, [string[]]$Confirmed = @())
    $sel = $Inventory.Selection; $role = $sel.Role
    if (-not $sel.New) { return New-SIIdentityMoveStepResult -Step switch -State $(if ($Ctx.Apply) { 'waits' } else { 'planned' }) -Lines @(('{0} does not exist yet: nothing can point at it' -f $sel.Standard)) }
    if (-not $Rollback -and $CopyResult -and $CopyResult.State -ne 'done') {
        return New-SIIdentityMoveStepResult -Step switch -State $(if ($Ctx.Apply) { 'waits' } else { 'planned' }) -Lines @(('the rights are not all copied yet (copy-rights: {0}): the role is not switched' -f $CopyResult.State))
    }
    if (-not $Rollback -and -not $CopyResult) {
        # switch run on its own: the copy is checked again from the inventory (and Exchange from the move record / -ConfirmCustomerStep)
        $plans = Get-SIMoveCopyPlans -Inventory $Inventory -TenantId $Ctx.TenantId -Vaults $Ctx.Vaults
        $mailOpen = $false
        if ($Inventory.Mail.SharedMailbox -and (Get-SIIdentityMoveRoleTable)[$role].MailSender -and $Confirmed -notcontains 'exchange') {
            $mailOpen = -not [string](Get-SIMoveProp (Read-SIMoveState -Ctx $Ctx) @('roles', $role, 'exchangeUtc'))
        }
        if (-not (Test-SIMoveCopyComplete -Plans $plans) -or $mailOpen) {
            return New-SIIdentityMoveStepResult -Step switch -State waits -Lines @(('the new identity does not hold every right of the old one yet{0}: run copy-rights first' -f $(if ($mailOpen) { ' (Exchange Mail.Send not confirmed)' } else { '' })))
        }
    }
    if (-not $Rollback -and "$($Ctx.Mode)" -eq 'updater') {
        $mst = $null; try { $mst = Read-SIMoveState -Ctx $Ctx } catch { $mst = $null }
        # the database side is the database setup job's: no switch before its copy read back
        if ($Ctx.SqlServer -and "$($Ctx.SqlVia)" -eq 'dbjob' -and -not [string](Get-SIMoveProp $mst @('roles', $role, 'sqlUtc')) -and -not [string](Get-SIMoveProp $mst @('roles', $role, 'switchedUtc'))) {
            return New-SIIdentityMoveStepResult -Step switch -State $(if ($Ctx.Apply) { 'waits' } else { 'planned' }) -Lines @(('the database setup job has not copied {0}''s database rights yet: the role is not switched' -f $sel.Standard))
        }
        # THE UPDATER LAST: the identity that runs this step is switched only when every other role at the install is proven
        # (the next update then runs as the new identity, proves it, and only an update running AS it removes the old one)
        if ($role -eq 'updater') {
            $sels = @{}; foreach ($r in @((Get-SIIdentityMoveRoleTable).Keys | Where-Object { $_ -ne 'updater' })) { $sels[$r] = Select-SIIdentityMoveIdentities -Identities $Ctx.Identities -Role $r }
            $g = Test-SIIdentityMoveCleanupAllowed -Selections $sels -State $mst
            if (-not $g.Allowed) { return New-SIIdentityMoveStepResult -Step switch -State $(if ($Ctx.Apply) { 'waits' } else { 'planned' }) -Lines @(('the updater moves last: {0}' -f $g.Why)) }
        }
    }
    $from = if ($Rollback) { $sel.New } else { $sel.Old }; $to = if ($Rollback) { $sel.Old } else { $sel.New }
    $lines = New-Object System.Collections.Generic.List[string]; $wait = $false; $stop = $false
    # the switch time is taken BEFORE the first write: the revision a web app makes from the switch (and a run started from
    # here on) is the proof -- a time taken after the write would make that revision older than the switch, and the role
    # would wait for the next release's revision
    $t0 = [datetime]::UtcNow.AddSeconds(-1)
    $flow = $null; $flowBad = $false
    if (@($Inventory.Users | Where-Object Kind -eq 'job').Count -and $Ctx.StateDatabase) {
        try { $flow = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query (Get-SIIdentityMoveRunGateSql) -Reason $Ctx.Reason)[0] } catch { $flowBad = $true }
    }
    foreach ($u in @($Inventory.Users)) {
        $r = Invoke-SIMoveArm -Path ($u.Id + '?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
        if ($r.Status -ne 200) { $stop = $true; $lines.Add(('{0}: could not be read (HTTP {1})' -f $u.Name, $r.Status)); continue }
        $res = $r.Body
        # EVERY reference, in every container and init container (the web app's sign-in front is a second container: live at
        # internal 2026-11-07), every secret / Key Vault reference, registry, scale rule, ingress / Dapr setting
        $fromVals = @(Get-SIIdentityMoveReferenceValues -Identity $from)
        $refs = @(Find-SIIdentityMoveReferences -Node $res -Values $fromVals)
        $attached = (Get-SIIdentityMoveAttached $res) -contains $to.Id.ToLowerInvariant()
        if ($attached -and -not $refs.Count) { $lines.Add(('{0}: already on {1}' -f $u.Name, $to.Name)); continue }
        $ex = @()
        if ($u.Kind -eq 'job') { $exl = Get-SIMoveArmList -Path ($u.Id + '/executions?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason; if ($exl.Ok) { $ex = @($exl.Items) } else { $flowBad = $true } }
        # the update that runs this step is an execution of its own job: it never waits for itself (its own template is
        # fixed at its start -- the switch takes effect from the next execution)
        $ex = @(Select-SIIdentityMoveWaitExecutions -Name $u.Name -Executions $ex -Ctx $Ctx)
        $gate = Get-SIIdentityMoveRunGate -Name $u.Name -Kind $u.Kind -Executions $ex -Flow $flow -FlowUnreadable:$flowBad
        if (-not $gate.Go) { $wait = $true; $lines.Add(('{0}: waits -- {1}' -f $u.Name, ($gate.Why -replace ('^' + [regex]::Escape($u.Name) + ': '), ''))); continue }
        $sv = Invoke-SIMoveArm -Method POST -Path ($u.Id + '/listSecrets?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason -ReadOnly
        $vals = @{}; foreach ($s in @(Get-SIMoveProp $sv.Body @('value'))) { if ($s -and $s.name) { $vals[[string]$s.name] = $s } }
        $wb = Get-SIIdentityMoveWriteBody -Resource $res -Kind $u.Kind -SecretValues $vals -From $from -To $to
        if ($wb.MissingSecrets.Count) { $stop = $true; $lines.Add(('{0}: NOT written -- its secret(s) {1} could not be read back and would be blanked' -f $u.Name, ($wb.MissingSecrets -join ', '))); continue }
        $line = '{0}: attach {1}; {2} reference(s) -> {1} ({3})' -f $u.Name, $to.Name, @($wb.Changes).Count, (@($wb.Changes) -join ', ')
        if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
        $w = Invoke-SIMoveArm -Method $wb.Method -Path ($u.Id + '?api-version=' + $script:SIMove.AppApi) -Body $wb.Body -Reason $Ctx.Reason
        if ($w.Status -notin 200, 201, 202) { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1} {2}' -f $line, $w.Status, ($w.Text -split "`n")[0])); continue }
        try {
            # read back until the write shows: the new identity attached and NOTHING (any container, init container, secret,
            # registry ...) naming the old one -- a read right after the write may still show the state before it
            $toId = $to.Id.ToLowerInvariant()
            $rb = Wait-SIMoveArmReadBack -Ctx $Ctx -Id $u.Id -Test { param($b) ((Get-SIIdentityMoveAttached $b) -contains $toId) -and -not @(Find-SIIdentityMoveReferences -Node $b -Values $fromVals).Count }
            $left = @(Find-SIIdentityMoveReferences -Node $rb.Body -Values $fromVals)
            if (-not $rb.Ok) { $stop = $true; $lines.Add(('READ BACK FAILED: {0} ({1})' -f $u.Name, $(if ($left.Count) { 'still names the old identity at ' + ($left -join ', ') } else { "$($to.Name) is not attached" }))) }
            else { $lines.Add("switched: $line") }
        } catch { $stop = $true; $lines.Add(('FAILED: {0}: {1}' -f $u.Name, $_.Exception.Message)) }
    }
    # what counts as "switched now": an app / job written in this run (the settings and the names record below are kept in
    # line on every run and never count -- else a run that finds everything switched would record the switch again and
    # throw the role's proof away)
    $switchedNow = @($lines | Where-Object { $_ -like 'switched:*' }).Count -gt 0
    # SI settings that store the identity's client id or name, and the install's names record
    if ($Ctx.StateDatabase -and -not $wait -and -not $stop) {
        $rows = @(Read-SIMoveSettingRows -Ctx $Ctx -Values @($from.ClientId, $from.Name))
        foreach ($s in @(Get-SIIdentityMoveSettingPlan -Rows $rows -From $from -To $to)) {
            $line = 'setting {0} ({1}): {2} -> {3}' -f $s.Name, $s.Scope, $s.Old, $s.New
            if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
            try { Set-SIMoveSetting -Ctx $Ctx -Name $s.Name -Scope $s.Scope -Value $s.New -Old $s.Old; $lines.Add("switched: $line") }
            catch { $stop = $true; $lines.Add(('FAILED: {0}: {1}' -f $line, (([string]$_.Exception.Message) -split "`n")[0])) }
        }
        if ($Ctx.Apply -and @(Get-SIIdentityMoveSettingPlan -Rows @(Read-SIMoveSettingRows -Ctx $Ctx -Values @($from.ClientId, $from.Name)) -From $from -To $to).Count) { $stop = $true; $lines.Add('READ BACK FAILED: a setting still names the old identity') }
        $rk = (Get-SIIdentityMoveRoleTable)[$role].RecordKey
        if ($rk) {
            if (-not $Ctx.Apply) { $lines.Add(('plan: the install''s names record: {0} = {1}' -f $rk, $to.Name)) }
            elseif (-not (Save-SIMoveInstallNames -Ctx $Ctx -Key $rk -Name $to.Name)) { $stop = $true; $lines.Add(('READ BACK FAILED: the names record does not say {0} = {1}' -f $rk, $to.Name)) }
            else { $lines.Add(('switched: the install''s names record {0} = {1}' -f $rk, $to.Name)) }
        }
    }
    # recorded when something was switched now, or never recorded before: a run that finds every app / job already on the
    # new identity keeps the recorded switch time and its proof (an update every hour must not reset the proof for ever)
    $known = $null; if ($Ctx.Apply -and -not $wait -and -not $stop -and -not $Rollback -and -not $switchedNow) { try { $known = Get-SIMoveProp (Read-SIMoveState -Ctx $Ctx) @('roles', $role, 'switchedUtc') } catch { $known = $null } }
    if ($Ctx.Apply -and -not $wait -and -not $stop -and ($Rollback -or $switchedNow -or -not [string]$known)) {
        $st = Read-SIMoveState -Ctx $Ctx
        $now = $t0.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $vals = if ($Rollback) { @{ switchedUtc = $null; provenUtc = $null; rolledBackUtc = $now } } else {
            @{ switchedUtc = $now; provenUtc = $null; old = [ordered]@{ name = $sel.Old.Name; clientId = $sel.Old.ClientId }
               new = [ordered]@{ name = $sel.New.Name; clientId = $sel.New.ClientId } } }
        if (-not (Save-SIMoveRoleState -Ctx $Ctx -State $st -Role $role -Values $vals)) { $stop = $true; $lines.Add('READ BACK FAILED: the move record') }
        else { $lines.Add(('recorded: {0} {1} at {2}' -f $role, $(if ($Rollback) { 'switched back' } else { 'switched' }), $now)) }
    }
    $state = if ($stop) { 'stop' } elseif ($wait) { 'waits' } elseif (-not $Ctx.Apply -and @($lines | Where-Object { $_ -like 'plan:*' }).Count) { 'planned' } else { 'done' }
    New-SIIdentityMoveStepResult -Step switch -State $state -Lines $lines
}

function Set-SIMoveSetting {
    <# One SI setting through the product's own write (Set-SIProSetting: validated by the catalog, with its cfg.ChangeLog row
       in the same transaction), over the Support app's SQL. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$Value, [string]$Old = '')
    if (-not (Get-Command -Name Set-SIProSetting -ErrorAction SilentlyContinue)) {
        # the updater image carries no settings layer: the one row is changed only where it still holds the OLD value (never
        # a blind write); the caller reads it back (Get-SIIdentityMoveSettingPlan finds nothing left)
        $q = "SET NOCOUNT ON; UPDATE cfg.Setting SET ValueJson = {2} WHERE Name = {0} AND Scope = {1} AND LOWER(ValueJson) = LOWER({3});" -f `
            (ConvertTo-SIMoveSqlText $Name), (ConvertTo-SIMoveSqlText $Scope), (ConvertTo-SIMoveSqlText ($Value | ConvertTo-Json -Compress)), (ConvertTo-SIMoveSqlText ("$Old" | ConvertTo-Json -Compress))
        $null = Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query $q -Reason $Ctx.Reason -Change
        return
    }
    if (-not $script:SIMoveCatalog) { $script:SIMoveCatalog = @(Get-SISettingsCatalog -SIRoot $script:SIMoveRoot) }
    $store = New-SIMoveSqlStore -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Reason $Ctx.Reason
    $null = Set-SIProSetting -Store $store -Catalog $script:SIMoveCatalog -Name $Name -Scope $Scope -Action Set -Value $Value -ChangedBy $script:SIMove.ChangedBy -Reason $Ctx.Reason
}

function Save-SIMoveInstallNames {
    <# The install's names record (cfg.InstallState 'InstallNames', engine\_shared\SI-InstallNames.ps1) with -Key = -Name, read back. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Name)
    $store = New-SIMoveSqlStore -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Reason $Ctx.Reason
    $cur = Read-SIInstallNamesRecord -Store $store
    $rec = New-SIInstallNamesRecord -Names @{ $Key = $Name } -Current $cur
    if (-not (Save-SIInstallNamesRecord -Store $store -Value $rec.Value -By $script:SIMove.ChangedBy)) { return $false }
    (Get-SIInstallNameProp -Record (Read-SIInstallNamesRecord -Store $store) -Role $Key) -ieq $Name
}

function Invoke-SIMoveProve {
    <# Step 5: the role's next REAL run on the new identity -- per re-pointed job its latest ended execution after the switch, per app
       a healthy revision made after it; the managed-identity sign-in log (object id) as evidence when it can be read. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Inventory, [int]$IdleDays = 7)
    $sel = $Inventory.Selection; $role = $sel.Role
    $st = Read-SIMoveState -Ctx $Ctx
    $rec = Get-SIMoveProp $st @('roles', $role)
    $sw = ConvertTo-SIMoveUtc (Get-SIMoveProp $rec @('switchedUtc'))
    if ([string](Get-SIMoveProp $rec @('provenUtc'))) { return New-SIIdentityMoveStepResult -Step prove -State done -Lines @(('{0} proven at {1}' -f $role, (Get-SIMoveProp $rec @('provenUtc')))) }
    if (-not $sw -or -not $sel.New) { return New-SIIdentityMoveStepResult -Step prove -State $(if ($Ctx.Apply) { 'waits' } else { 'planned' }) -Lines @(('{0} is not switched yet: nothing to prove' -f $role)) }
    $items = New-Object System.Collections.Generic.List[object]; $lines = New-Object System.Collections.Generic.List[string]
    # the updater itself: THIS update signed in as the new identity and got this far (ARM read, the state database read and
    # written) -- a read with its own token, the strongest proof there is. An update still running as the old one waits.
    # (an updater that signs in with a CERTIFICATE never runs as its managed identity: its job's next run is the proof, as any job)
    $selfProof = ($role -eq 'updater' -and "$($Ctx.Mode)" -eq 'updater' -and "$($Ctx.SelfAuth)" -ne 'Certificate')
    if ($selfProof) {
        if ("$($Ctx.SelfClientId)".Trim() -ieq [string]$sel.New.ClientId) { $items.Add([pscustomobject]@{ Name = 'this update'; State = 'proven'; Execution = "$($Ctx.SelfExecution)"; Why = ('it signed in as {0} and read Azure and the state database with its own token' -f $sel.New.Name) }) }
        else { $items.Add([pscustomobject]@{ Name = 'this update'; State = 'waiting'; Execution = ''; Why = ('it still signs in as {0}; the next update runs as {1}' -f $sel.Old.Name, $sel.New.Name) }) }
        $lines.Add(('{0}: {1} -- {2}' -f $items[0].Name, $items[0].State, $items[0].Why))
    }
    foreach ($u in @($Inventory.Users | Where-Object { -not $selfProof })) {
        if ($u.Kind -eq 'job') {
            $l = Get-SIMoveArmList -Path ($u.Id + '/executions?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
            # the job pulls its image with the new identity and its template names no client id of this role (old or new):
            # that pull is its only use of the identity
            $pull = @(@(Get-SIMoveProp $u.Resource @('properties', 'configuration', 'registries')) | Where-Object { $_ } | Where-Object { [string](Get-SIMoveProp $_ @('identity')) -ieq [string]$sel.New.Id }).Count -gt 0
            $tplNames = @(Find-SIIdentityMoveReferences -Node (Get-SIMoveProp $u.Resource @('properties', 'template')) -Values @(@($sel.New.ClientId, $(if ($sel.Old) { $sel.Old.ClientId })) | Where-Object { $_ })).Count -gt 0
            $p = if ($l.Ok) { Get-SIIdentityMoveJobProof -Name $u.Name -Executions $l.Items -SwitchedUtc $sw -NewClientId $sel.New.ClientId -IdleDays $IdleDays -PulledWith:($pull -and -not $tplNames) } else { [pscustomobject]@{ Name = $u.Name; State = 'waiting'; Why = "executions not readable (HTTP $($l.Status))" } }
        } else {
            $l = Get-SIMoveArmList -Path ($u.Id + '/revisions?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
            $p = if ($l.Ok) { Get-SIIdentityMoveAppProof -Name $u.Name -Revisions $l.Items -SwitchedUtc $sw -NewClientId $sel.New.ClientId } else { [pscustomobject]@{ Name = $u.Name; State = 'waiting'; Why = "revisions not readable (HTTP $($l.Status))" } }
        }
        # something wrote the OLD identity back after the switch (e.g. a second container's setting): not proven -- the next
        # switch re-points it; clean-up never starts on an app / job that still names the old identity
        if ($sel.Old -and $p.State -in 'proven', 'idle') {
            $again = @(Find-SIIdentityMoveReferences -Node $u.Resource -Values @(Get-SIIdentityMoveReferenceValues -Identity $sel.Old))
            if ($again.Count) { $p = [pscustomobject]@{ Name = $u.Name; State = 'waiting'; Execution = ''; Why =('it names the old identity {0} again ({1}) -- the next switch re-points it' -f $sel.Old.Name, ($again -join ', ')) } }
        }
        $items.Add($p)
    }
    # a job whose latest run failed: was a right or a sign-in refused? Read only when there is such a run; what cannot be read
    # is not known, and not known is never a failure
    $suspects = @($items | Where-Object { [bool](Get-SIMoveProp $_ @('Suspect')) })
    $evidence = @(); $evidenceRead = $true
    if ($suspects.Count) {
        if ($Ctx.SqlServer -and $Ctx.StateDatabase) {
            try { $evidence = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $Ctx.StateDatabase -Query (Get-SIIdentityMoveRightsEvidenceSql -Executions @($suspects | ForEach-Object { [string]$_.Execution })) -Reason $Ctx.Reason) } catch { $evidenceRead = $false }
        } else { $evidenceRead = $false }
    }
    $items = @(Resolve-SIIdentityMoveRightsEvidence -Items $items -Rows $evidence)
    foreach ($p in @($items | Where-Object { -not $selfProof })) {
        if ([bool](Get-SIMoveProp $p @('Suspect'))) { $lines.Add(('WARNING: {0}: {1}' -f $p.Name, $p.Why)) }
        else { $lines.Add(('{0}: {1} -- {2}' -f $p.Name, $p.State, $p.Why)) }
    }
    if (-not $evidenceRead) { $lines.Add('why those runs failed could not be read, so they count as waiting') }
    # evidence: the new identity's own sign-ins (its object id) since the switch -- read when the Support app may
    $f = [uri]::EscapeDataString(("createdDateTime ge {0} and servicePrincipalId eq '{1}' and signInEventTypes/any(t: t eq 'managedIdentity')" -f $sw.ToString('yyyy-MM-ddTHH:mm:ssZ'), $sel.New.PrincipalId))
    $sg = Invoke-SIMoveGraph -Uri ("{0}/auditLogs/signIns?`$top=1&`$filter={1}" -f $script:SIMove.GraphBeta, $f) -Reason $Ctx.Reason
    if ($sg.Status -eq 200) { $lines.Add(('sign-in log: {0} sign-in(s) of object id {1} since the switch' -f @(Get-SIMoveProp $sg.Body @('value')).Count, $sel.New.PrincipalId)) }
    else { $lines.Add(('sign-in log: not readable (HTTP {0}) -- the proof rests on the runs' -f $sg.Status)) }
    $verdict = Get-SIIdentityMoveRoleProof -Items $items
    if ($verdict -eq 'proven' -and $Ctx.Apply) {
        $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        if (Save-SIMoveRoleState -Ctx $Ctx -State $st -Role $role -Values @{ provenUtc = $now }) { $lines.Add("recorded: $role proven at $now") }
        else { return New-SIIdentityMoveStepResult -Step prove -State stop -Lines ($lines.ToArray() + 'READ BACK FAILED: the move record') }
    }
    $state = switch ($verdict) { 'proven' { $(if ($Ctx.Apply) { 'done' } else { 'planned' }) } 'failed' { 'stop' } default { 'waits' } }
    if ($verdict -eq 'failed') {
        $bad = @($items | Where-Object State -eq 'failed')
        # an app: the revision is named; its log says why, which need not be a right
        foreach ($b in @($bad | Where-Object { -not [bool](Get-SIMoveProp $_ @('Rights')) })) { $lines.Add(('{0}: {1}. The old identity keeps every right until it is healthy' -f $b.Name, $b.Why)) }
        if (@($bad | Where-Object { [bool](Get-SIMoveProp $_ @('Rights')) }).Count) { $lines.Add('a run was refused a right on the new identity: switch back with -Step switch -Rollback -Apply, then find the missing right') }
    }
    New-SIIdentityMoveStepResult -Step prove -State $state -Lines $lines -Data @{ Verdict = $verdict; Items = @($items) }
}

function Invoke-SIMoveCleanup {
    <# Step 6: ONLY after every role at the install is proven -- the old identity's rights removed (each removal read back),
       it is detached from every app / job, and the old user-assigned identity is deleted. #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)]$Inventory)
    $sel = $Inventory.Selection; $role = $sel.Role; $old = $sel.Old
    $st = Read-SIMoveState -Ctx $Ctx
    $sels = @{}; foreach ($r in @((Get-SIIdentityMoveRoleTable).Keys)) { $sels[$r] = Select-SIIdentityMoveIdentities -Identities $Ctx.Identities -Role $r -OldName $(if ($r -eq $role) { $Ctx.OldName } else { '' }) }
    $gate = Test-SIIdentityMoveCleanupAllowed -Selections $sels -State $st
    if (-not $gate.Allowed) { return New-SIIdentityMoveStepResult -Step clean-up -State waits -Lines @($gate.Why) }
    if ($role -eq 'updater' -and "$($Ctx.Mode)" -eq 'updater' -and "$($Ctx.SelfAuth)" -ne 'Certificate' -and "$($Ctx.SelfClientId)".Trim() -ine [string]$sel.New.ClientId) {
        return New-SIIdentityMoveStepResult -Step clean-up -State waits -Lines @(('the updater''s old identity {0} is removed only by an update that runs as {1} -- this one signs in as {2}' -f $old.Name, $sel.New.Name, $(if ("$($Ctx.SelfClientId)".Trim()) { "$($Ctx.SelfClientId)".Trim() } else { 'an unknown identity' })))
    }
    $lines = New-Object System.Collections.Generic.List[string]; $cust = New-Object System.Collections.Generic.List[object]; $stop = $false
    # 1. nothing may still point at the old identity
    foreach ($u in @($Inventory.Users)) {
        $r = Invoke-SIMoveArm -Path ($u.Id + '?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
        $refs = if ($r.Status -eq 200) { @(Find-SIIdentityMoveReferences -Node $r.Body -Values @(Get-SIIdentityMoveReferenceValues -Identity $old)) } else { @('unreadable') }
        if ($refs.Count) { return New-SIIdentityMoveStepResult -Step clean-up -State stop -Lines @(('{0} still names {1} ({2}): nothing is removed' -f $u.Name, $old.Name, ($refs -join ', '))) }
    }
    $o = $Inventory.OldRights
    $do = { param([string]$What, [scriptblock]$Act)
        if (-not $Ctx.Apply) { $lines.Add("plan: remove $What"); return }
        $a = & $Act
        if ($a.Status -in 200, 202, 204, 404) { $lines.Add("removed: $What") }
        elseif ($a.Status -eq 403) { $script:SIMoveCleanupCustomer += , $What; $lines.Add("customer step: remove $What") }
        else { Set-Variable -Name stop -Value $true -Scope 1; $lines.Add(('FAILED: remove {0}: HTTP {1}' -f $What, $a.Status)) } }
    $script:SIMoveCleanupCustomer = @()
    foreach ($a in @($o.Azure)) { $id = $a.Id; & $do ('Azure role {0} at {1}' -f $a.RoleGuid, $(if ($a.Scope) { $a.Scope } else { '/' })) { Invoke-SIMoveArm -Method DELETE -Path ($id + '?api-version=' + $script:SIMove.RoleApi) -Reason $Ctx.Reason } }
    foreach ($a in @($o.AppRoles)) { $id = [string]$a.id; & $do ('Graph app role {0}' -f $a.appRoleId) { Invoke-SIMoveGraph -Method DELETE -Uri ("servicePrincipals/{0}/appRoleAssignments/{1}" -f $old.PrincipalId, $id) -Reason $Ctx.Reason } }
    foreach ($a in @($o.DirRoles)) { $id = [string]$a.id; & $do ('Entra role {0}' -f $a.roleDefinitionId) { Invoke-SIMoveGraph -Method DELETE -Uri ("roleManagement/directory/roleAssignments/{0}" -f $id) -Reason $Ctx.Reason } }
    foreach ($a in @($o.Fic)) { $id = [string]$a.id; & $do ('federated credential {0}' -f $a.name) { Invoke-SIMoveGraph -Method DELETE -Uri ("applications/{0}/federatedIdentityCredentials/{1}" -f $o.SignInAppObjectId, $id) -Reason $Ctx.Reason } }
    foreach ($v in @($Ctx.Vaults | Where-Object { -not [bool](Get-SIMoveProp $_ @('properties', 'enableRbacAuthorization')) })) {
        $pol = @(@(Get-SIMoveProp $v @('properties', 'accessPolicies')) | Where-Object { $_ -and "$($_.objectId)" -ieq $old.PrincipalId })
        if (-not $pol.Count) { continue }
        $vid = [string]$v.id; $body = [ordered]@{ properties = [ordered]@{ accessPolicies = @($pol) } }
        & $do ('Key Vault {0} access policy' -f $v.name) { Invoke-SIMoveArm -Method PUT -Path ('{0}/accessPolicies/remove?api-version={1}' -f $vid, $script:SIMove.KvApi) -Body $body -Reason $Ctx.Reason }
    }
    # NEVER LOSE SQL ACCESS: the old user is dropped only where a read made right now shows the new user holding every role
    # and permission of it (Test-SIIdentityMoveSqlCovered); anything else keeps the old user and stops the clean-up
    foreach ($db in @($Inventory.Sql.Databases.Keys | Sort-Object)) {
        if (-not @($Inventory.Sql.Databases[$db] | Where-Object { $_.Who -eq 'old' -and $_.Kind -eq 'user' }).Count) { continue }
        if (-not $Ctx.Apply) { $lines.Add("plan: remove SQL user of $($old.Name) in $db (only once the user of $($sel.New.Name) reads back holding all of it)"); continue }
        try {
            $rowsNow = @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $db -Query (Get-SIIdentityMoveSqlReadSql -OldClientId $old.ClientId -NewClientId $sel.New.ClientId) -Reason $Ctx.Reason)
            $cov = Test-SIIdentityMoveSqlCovered -Rows $rowsNow -KeepName $sel.New.Name -KeepClientId $sel.New.ClientId
            if (-not $cov.OldUser) { $lines.Add("removed: SQL user of $($old.Name) in $db (already gone)"); continue }
            if (-not $cov.Drop) { $stop = $true; $lines.Add(('KEPT: SQL user of {0} in {1}: {2}' -f $old.Name, $db, $cov.Why)); continue }
            # #1164: a procedure SecurityInsight makes that runs AS the old user (it blocks the drop) is made again as the new
            # user, read back; a signed or unknown one keeps the old user (Get-SIIdentityMoveSqlModuleSql)
            $mods = Resolve-SIIdentityMoveSqlModules -Rows @(Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $db -Query (Get-SIIdentityMoveSqlModuleSql -OldSid (ConvertTo-SIMoveSid $old.ClientId) -NewSid (ConvertTo-SIMoveSid $sel.New.ClientId)) -Reason $Ctx.Reason -Change)
            foreach ($l in @($mods.Moved)) { $lines.Add(('done: SQL {0}: {1}' -f $db, $l)) }
            if (-not $mods.Clear) { $stop = $true; $lines.Add(('KEPT: SQL user of {0} in {1}: {2}' -f $old.Name, $db, $(if (@($mods.Kept).Count) { @($mods.Kept) -join '; ' } else { 'a procedure still runs as it' }))); continue }
            $null = Invoke-SIMoveSql -Server $Ctx.SqlServer -Database $db -Query (Get-SIIdentityMoveSqlDropSql -OldClientId $old.ClientId) -Reason $Ctx.Reason -Change
            $lines.Add("removed: SQL user of $($old.Name) in $db ($($cov.Why))")
        } catch { $stop = $true; $lines.Add(('FAILED: SQL {0}: {1}' -f $db, (([string]$_.Exception.Message) -split "`n")[0])) }
    }
    # updater mode: the database setup job drops the old user in every product database -- itself checking, per database,
    # that the new user reads back holding all of it (SI_DBINIT_DROPS); once per role (sqlDroppedUtc)
    if ("$($Ctx.Mode)" -eq 'updater' -and $Ctx.SqlServer -and "$($Ctx.SqlVia)" -eq 'dbjob' -and -not $stop) {
        $dropDone = [string](Get-SIMoveProp $st @('roles', $role, 'sqlDroppedUtc'))
        if ($dropDone) { $lines.Add(('removed: the SQL users of {0} (the database setup job, {1})' -f $old.Name, $dropDone)) }
        elseif (-not $Ctx.Apply) { $lines.Add(('plan: the database setup job drops the user of {0} in every product database where the user of {1} reads back holding all of it' -f $old.Name, $sel.New.Name)) }
        else {
            $dj = Invoke-SIMoveDbJob -Ctx $Ctx -Drops @([ordered]@{ component = $role; clientId = $old.ClientId; keepClientId = $sel.New.ClientId; keepName = $sel.New.Name })
            $dst = if ($dj -and $dj.States) { [string]$dj.States[$role] } else { '' }
            if ($dj -and $dj.Ok -and $dst -in 'dropped', 'none') {
                $lines.Add(('removed: the SQL users of {0} in every product database (the database setup job read {1} back first)' -f $old.Name, $sel.New.Name))
                $nowT = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                if (-not (Save-SIMoveRoleState -Ctx $Ctx -State $st -Role $role -Values @{ sqlDroppedUtc = $nowT })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record (SQL users dropped)') }
                else { $st = Read-SIMoveState -Ctx $Ctx }
            } else { $stop = $true; $lines.Add(('KEPT: the SQL users of {0} -- the database setup job did not drop them ({1})' -f $old.Name, $(if ($dj) { $dj.Why } else { 'no answer' }))) }
        }
    }
    if ($Inventory.Mail.SharedMailbox -and (Get-SIIdentityMoveRoleTable)[$role].MailSender) {
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind exchange-cleanup `
            -What ('SecurityInsight''s old identity {0} (app id {1}) no longer sends mail: its Application Mail.Send role assignment for {2} can be removed.' -f $old.Name, $old.ClientId, $Inventory.Mail.From) `
            -How ('An Exchange administrator removes the Exchange management role assignment ''Application Mail.Send'' of app id {0} (Exchange Online: Get-ManagementRoleAssignment -Role ''Application Mail.Send'', then Remove-ManagementRoleAssignment on that one).' -f $old.ClientId)))
    }
    foreach ($w in @($script:SIMoveCleanupCustomer)) {
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind cleanup -Key ("cleanup:$w") -What ('The old SecurityInsight identity {0} still holds: {1}.' -f $old.Name, $w) -How 'An administrator of that scope removes this assignment (Access control (IAM) > Role assignments, or the Entra admin center).'))
    }
    # updater mode: rights the update may not even READ (a scope above its resource group, Entra roles) may still be held by
    # the old identity -- it is not deleted until a Support-app run has removed them (its clean-up reads everything)
    if ("$($Ctx.Mode)" -eq 'updater' -and @($Inventory.Unknown | Where-Object { $_ }).Count) {
        $cust.Add((New-SIIdentityMoveCustomerStep -Role $role -Kind cleanup -Key 'cleanup:unread' -What ('The old SecurityInsight identity {0} may still hold rights this update may not read ({1}).' -f $old.Name, (@($Inventory.Unknown) -join '; ')) -How 'x'))
        $lines.Add(('support step: the old identity''s rights this update may not read are removed by the Support app before {0} is deleted' -f $old.Name))
    }
    # every right of the old identity is gone (removed now, read by a run that could read them all, nothing left for support):
    # recorded -- the names report's "no rights left" (Invardia, 2026-11-07); the identity itself may still be deleted below
    if ($Ctx.Apply -and -not $stop -and -not @($cust | Where-Object Kind -eq 'cleanup').Count) {
        $nowC = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        if (-not (Save-SIMoveRoleState -Ctx $Ctx -State (Read-SIMoveState -Ctx $Ctx) -Role $role -Values @{ rightsClearedUtc = $nowC })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record (rights cleared)') }
        else { $st = Read-SIMoveState -Ctx $Ctx }
    }
    # 2. detach, 3. delete
    if (-not $stop) {
        foreach ($u in @($Inventory.Users)) {
            $r = Invoke-SIMoveArm -Path ($u.Id + '?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason
            if ((Get-SIIdentityMoveAttached $r.Body) -notcontains $old.Id.ToLowerInvariant()) { continue }
            $line = '{0}: detach {1}' -f $u.Name, $old.Name
            if (-not $Ctx.Apply) { $lines.Add("plan: $line"); continue }
            $sv = Invoke-SIMoveArm -Method POST -Path ($u.Id + '/listSecrets?api-version=' + $script:SIMove.AppApi) -Reason $Ctx.Reason -ReadOnly
            $vals = @{}; foreach ($s in @(Get-SIMoveProp $sv.Body @('value'))) { if ($s -and $s.name) { $vals[[string]$s.name] = $s } }
            $wb = Get-SIIdentityMoveWriteBody -Resource $r.Body -Kind $u.Kind -SecretValues $vals -From $old -To $sel.New -Detach
            if ($wb.MissingSecrets.Count) { $stop = $true; $lines.Add("FAILED: $line (secrets not readable)"); continue }
            $w = Invoke-SIMoveArm -Method $wb.Method -Path ($u.Id + '?api-version=' + $script:SIMove.AppApi) -Body $wb.Body -Reason $Ctx.Reason
            if ($w.Status -notin 200, 201, 202) { $stop = $true; $lines.Add(('FAILED: {0}: HTTP {1}' -f $line, $w.Status)); continue }
            # read back until provisioning has finished AND the old identity is no longer attached (a read right after the
            # PATCH may still show the state before it)
            try {
                $oldIdLc = $old.Id.ToLowerInvariant()
                $rb = Wait-SIMoveArmReadBack -Ctx $Ctx -Id $u.Id -Test { param($b) (Get-SIIdentityMoveAttached $b) -notcontains $oldIdLc }
                if (-not $rb.Ok) { $stop = $true; $lines.Add(("READ BACK FAILED: $line (still attached after {0} reads, {1} {2})" -f $script:SIMove.Waits.Tries, $wb.Method, $(if ($wb.Method -eq 'PATCH') { 'with the old key set to null' } else { 'of the whole resource' }))) }
                else { $lines.Add("done: $line") }
            }
            catch { $stop = $true; $lines.Add(('FAILED: {0}: {1}' -f $line, $_.Exception.Message)) }
        }
    }
    if (-not $stop -and -not @($cust | Where-Object Kind -eq 'cleanup').Count) {
        $path = $old.Id + '?api-version=' + $script:SIMove.MiApi
        if (-not $Ctx.Apply) { $lines.Add(('plan: delete the old identity {0}' -f $old.Name)) }
        else {
            $d = Invoke-SIMoveArm -Method DELETE -Path $path -Reason $Ctx.Reason
            $g = Invoke-SIMoveArm -Path $path -Reason $Ctx.Reason
            if ($d.Status -in 200, 204, 404 -and $g.Status -eq 404) {
                $lines.Add(('deleted: {0} (read back: gone)' -f $old.Name))
                $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                if (-not (Save-SIMoveRoleState -Ctx $Ctx -State $st -Role $role -Values @{ cleanedUtc = $now })) { $stop = $true; $lines.Add('READ BACK FAILED: the move record') }
            } else { $stop = $true; $lines.Add(('FAILED: delete {0}: HTTP {1}, read back HTTP {2}' -f $old.Name, $d.Status, $g.Status)) }
        }
    }
    $state = if ($stop) { 'stop' } elseif (@($cust | Where-Object Kind -eq 'cleanup').Count) { 'customer' } elseif (-not $Ctx.Apply) { 'planned' } else { 'done' }
    New-SIIdentityMoveStepResult -Step clean-up -State $state -Lines $lines -CustomerSteps $cust
}

# =====================================================================================================================
#  THE SQL ADMIN GROUP -- renamed IN PLACE to its standard name (framework §12.11c: groups and app display names keep
#  their object; Invardia 2026-11-07). Same object id: membership and the SQL server's admin binding (its sid) are
#  untouched; only the group's displayName (and mailNickname where it differs) and the server admin's LOGIN TEXT change.
# =====================================================================================================================

function Get-SIIdentityMoveSqlAdminGroupNames {
    <# PURE. Which SecurityInsight SQL admin group this is (by either of its names or its mailNickname) and its standard name:
       @{ Ours; Edition pro | community; Standard; Nick }. A group of the customer's own: Ours $false. #>
    param([AllowEmptyString()][string]$DisplayName = '', [AllowEmptyString()][string]$MailNickname = '')
    $c = @{ Edition = 'community'; Standard = 'grp-si-community-sql-admins'; Nick = 'grpsicommunitysqladmins'; Names = @('grp-si-community-sql-admins', 'SecurityInsight Community SQL admins') }
    $p = @{ Edition = 'pro'; Standard = 'grp-si-sql-admins'; Nick = 'grpsisqladmins'; Names = @('grp-si-sql-admins', 'SecurityInsight SQL admins') }
    foreach ($x in $c, $p) {
        if ($x.Names -ccontains "$DisplayName".Trim() -or "$MailNickname".Trim() -ceq $x.Nick) { return [pscustomobject]@{ Ours = $true; Edition = $x.Edition; Standard = $x.Standard; Nick = $x.Nick } }
    }
    [pscustomobject]@{ Ours = $false; Edition = ''; Standard = ''; Nick = '' }
}

function Read-SIMoveSqlAdmin {
    <# The SQL server's Entra administrator (ARM administrators/ActiveDirectory) and, when it is a group, that group (Graph, by
       the admin's sid). @{ State ok | none | not-group | unread; Admin (login, sid, tenantId, administratorType); Group (id,
       displayName, mailNickname); Path; Why }. Read only. #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $res = { param($st, $why, $a, $g, $path) [pscustomobject]@{ State = $st; Why = $why; Admin = $a; Group = $g; Path = $path } }
    if (-not "$($Ctx.SqlServerId)".Trim()) { return (& $res 'none' 'the install has no SQL server' $null $null '') }
    $path = '{0}/administrators/ActiveDirectory?api-version={1}' -f $Ctx.SqlServerId, $script:SIMove.SqlApi
    $a = Invoke-SIMoveArm -Path $path -Reason $Ctx.Reason
    if ($a.Status -eq 404) { return (& $res 'none' 'the SQL server has no Entra administrator' $null $null $path) }
    if ($a.Status -ne 200) { return (& $res 'unread' ('the SQL server''s Entra administrator could not be read (HTTP {0})' -f $a.Status) $null $null $path) }
    $sid = [string](Get-SIMoveProp $a.Body @('properties', 'sid'))
    if ($sid -notmatch $script:SIMove.GuidRx) { return (& $res 'not-group' 'the SQL server''s Entra administrator has no object id' $a.Body $null $path) }
    $g = Invoke-SIMoveGraph -Uri ("groups/{0}?`$select=id,displayName,mailNickname" -f $sid) -Reason $Ctx.Reason
    if ($g.Status -eq 404) { return (& $res 'not-group' 'the SQL server''s Entra administrator is not a group' $a.Body $null $path) }
    if ($g.Status -ne 200) { return (& $res 'unread' ('the SQL admin group could not be read (HTTP {0})' -f $g.Status) $a.Body $null $path) }
    & $res 'ok' '' $a.Body $g.Body $path
}

function Get-SIIdentityMoveSqlAdminGroupEntry {
    <# The names report's 'sql-admin-group' entry: ok when the group AND the SQL server's admin login carry the standard name,
       else missing with the name; unknown when it could not be read; $null when the install has no admin group. #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    try { $r = Read-SIMoveSqlAdmin -Ctx $Ctx } catch { return [ordered]@{ state = 'unknown'; standard = 'grp-si-sql-admins' } }
    if ($r.State -eq 'unread') { return [ordered]@{ state = 'unknown'; standard = 'grp-si-sql-admins' } }
    if ($r.State -ne 'ok') { return $null }
    $dn = [string](Get-SIMoveProp $r.Group @('displayName')); $login = [string](Get-SIMoveProp $r.Admin @('properties', 'login'))
    $n = Get-SIIdentityMoveSqlAdminGroupNames -DisplayName $dn -MailNickname ([string](Get-SIMoveProp $r.Group @('mailNickname')))
    # a group of the customer's OWN (their choice, framework DEPLOY-2; Invardia ruling 2026-11-07): ok, said in the note
    if (-not $n.Ours) { return [ordered]@{ state = 'ok'; name = $dn; note = 'customer''s own group' } }
    $e = [ordered]@{ state = $(if ($dn -ceq $n.Standard -and $login -ceq $n.Standard) { 'ok' } else { 'missing' }); name = $dn; standard = $n.Standard }
    if ($dn -ceq $n.Standard -and $login -cne $n.Standard) { $e.note = ('the SQL server''s admin login still reads "{0}"' -f $login) }
    $e
}

function Invoke-SIMoveSqlAdminGroup {
    <#
        THE SQL ADMIN GROUP'S NAME, in place (plan unless -Ctx.Apply): the group the SQL server's Entra admin names (by its sid)
        gets its standard name -- "SecurityInsight SQL admins" -> grp-si-sql-admins, "SecurityInsight Community SQL admins" ->
        grp-si-community-sql-admins; its mailNickname only where it differs from the standard one -- READ BACK; then the SQL
        server's admin LOGIN TEXT is set to that name with the SAME sid and tenant (ARM administrators/ActiveDirectory),
        READ BACK. NEVER: a member added or removed, the admin object removed or replaced, a group of the customer's own
        renamed. A refusal (403) is ONE support step (Move-SIIdentity -Step sql-admin-group), never a customer action.
    #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $r = Read-SIMoveSqlAdmin -Ctx $Ctx
    if ($r.State -eq 'unread') { return New-SIIdentityMoveStepResult -Step sql-admin-group -State stop -Lines @($r.Why) }
    if ($r.State -ne 'ok') { return New-SIIdentityMoveStepResult -Step sql-admin-group -State 'n/a' -Lines @(('sql-admin-group: {0} -- nothing to rename' -f $r.Why)) }
    $gid = [string](Get-SIMoveProp $r.Group @('id')); $dn = [string](Get-SIMoveProp $r.Group @('displayName')); $nick = [string](Get-SIMoveProp $r.Group @('mailNickname'))
    $login = [string](Get-SIMoveProp $r.Admin @('properties', 'login')); $sid = [string](Get-SIMoveProp $r.Admin @('properties', 'sid')); $tid = [string](Get-SIMoveProp $r.Admin @('properties', 'tenantId'))
    $n = Get-SIIdentityMoveSqlAdminGroupNames -DisplayName $dn -MailNickname $nick
    if (-not $n.Ours) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State 'n/a' -Lines @(('sql-admin-group: the SQL server''s admin is "{0}", a group of the customer''s own -- not renamed' -f $dn)) }
    $lines = New-Object System.Collections.Generic.List[string]
    $needGroup = $dn -cne $n.Standard; $needNick = $nick -and $nick -cne $n.Nick; $needLogin = $login -cne $n.Standard
    if (-not $needGroup -and -not $needNick -and -not $needLogin) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State done -Lines @(('sql-admin-group: "{0}" (object id {1}) and the SQL server''s admin login already carry the standard name' -f $dn, $gid)) }
    if (-not $Ctx.Apply) {
        if ($needGroup -or $needNick) { $lines.Add(('plan: the SQL admin group (object id {0}): "{1}" -> "{2}" in place{3} -- membership untouched' -f $gid, $dn, $n.Standard, $(if ($needNick) { ', mailNickname -> ' + $n.Nick } else { '' }))) }
        if ($needLogin) { $lines.Add(('plan: the SQL server''s Entra admin login "{0}" -> "{1}" (same sid {2})' -f $login, $n.Standard, $sid)) }
        return New-SIIdentityMoveStepResult -Step sql-admin-group -State planned -Lines $lines
    }
    $support = { param($what) New-SIIdentityMoveStepResult -Step sql-admin-group -State customer -Lines ($lines.ToArray() + ('support step: ' + $what)) -CustomerSteps @(New-SIIdentityMoveCustomerStep -Role 'sql-admin-group' -Kind 'sql-admin-group' -What $what -How 'Move-SIIdentity -Step sql-admin-group -Apply (through the Support app)') }
    if ($needGroup -or $needNick) {
        $body = [ordered]@{}; if ($needGroup) { $body.displayName = $n.Standard }; if ($needNick) { $body.mailNickname = $n.Nick }
        $w = Invoke-SIMoveGraph -Method PATCH -Uri ("groups/{0}" -f $gid) -Body $body -Reason $Ctx.Reason
        if ($w.Status -eq 403) { return (& $support ('the SQL admin group "{0}" must be renamed in place to "{1}" -- this update may not change it' -f $dn, $n.Standard)) }
        if ($w.Status -notin 200, 204) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State stop -Lines ($lines.ToArray() + ('FAILED: the SQL admin group was not renamed (HTTP {0})' -f $w.Status)) }
        $back = $null
        for ($i = 0; $i -lt $script:SIMove.Waits.Tries; $i++) {
            $g = Invoke-SIMoveGraph -Uri ("groups/{0}?`$select=id,displayName,mailNickname" -f $gid) -Reason $Ctx.Reason
            if ($g.Status -eq 200 -and [string](Get-SIMoveProp $g.Body @('displayName')) -ceq $n.Standard -and (-not $needNick -or [string](Get-SIMoveProp $g.Body @('mailNickname')) -ceq $n.Nick)) { $back = $g.Body; break }
            Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds
        }
        if (-not $back) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State stop -Lines ($lines.ToArray() + 'READ BACK FAILED: the SQL admin group does not read back under its standard name yet -- the next update checks it') }
        $lines.Add(('renamed: the SQL admin group (object id {0}, the same object) "{1}" -> "{2}", read back' -f $gid, $dn, $n.Standard))
    }
    if ($needLogin) {
        $type = [string](Get-SIMoveProp $r.Admin @('properties', 'administratorType')); if (-not $type) { $type = 'ActiveDirectory' }
        $body = [ordered]@{ properties = [ordered]@{ administratorType = $type; login = $n.Standard; sid = $sid; tenantId = $tid } }
        $w = Invoke-SIMoveArm -Method PUT -Path $r.Path -Body $body -Reason $Ctx.Reason
        if ($w.Status -eq 403) { return (& $support ('the SQL server''s Entra admin login must read "{0}" (the same group, sid {1}) -- this update may not change it' -f $n.Standard, $sid)) }
        if ($w.Status -notin 200, 201, 202) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State stop -Lines ($lines.ToArray() + ('FAILED: the SQL server''s admin login was not changed (HTTP {0}) -- the admin itself is unchanged' -f $w.Status)) }
        $ok = $false
        for ($i = 0; $i -lt $script:SIMove.Waits.Tries; $i++) {
            $a = Invoke-SIMoveArm -Path $r.Path -Reason $Ctx.Reason
            if ($a.Status -eq 200 -and [string](Get-SIMoveProp $a.Body @('properties', 'login')) -ceq $n.Standard -and [string](Get-SIMoveProp $a.Body @('properties', 'sid')) -ieq $sid) { $ok = $true; break }
            Invoke-SIMoveSleep -Seconds $script:SIMove.Waits.Seconds
        }
        if (-not $ok) { return New-SIIdentityMoveStepResult -Step sql-admin-group -State stop -Lines ($lines.ToArray() + 'READ BACK FAILED: the SQL server''s admin login does not read back with the standard name and the same sid yet') }
        $lines.Add(('updated: the SQL server''s Entra admin login "{0}" -> "{1}" (the same sid {2}), read back' -f $login, $n.Standard, $sid))
    }
    New-SIIdentityMoveStepResult -Step sql-admin-group -State done -Lines $lines
}

function Invoke-SIMoveReport {
    <# Step 7: the setup step identity-names for EVERY role at the install -> cfg.InstallState 'IdentityNames' (read back),
       which the heartbeat sends as setupSteps (engine\_shared\SI-SetupSteps.ps1). #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $roles = @{}
    # whether an old identity still holds rights: the move record's clean-up result (rightsClearedUtc: every right of it removed
    # by a run that could read them all). No record = not known = "clean-up pending" (Invardia, 2026-11-07)
    $mst = $null; if ($Ctx.StateDatabase) { try { $mst = Read-SIMoveState -Ctx $Ctx } catch { $mst = $null } }
    foreach ($r in @((Get-SIIdentityMoveRoleTable).Keys)) {
        $sel = Select-SIIdentityMoveIdentities -Identities $Ctx.Identities -Role $r -OldName $(if ($r -eq $Ctx.Role) { $Ctx.OldName } else { '' })
        $cands = @(@($sel.Old, $sel.New) | Where-Object { $_ })
        $users = @(Get-SIIdentityMoveUsers -Resources (@($Ctx.Apps) + @($Ctx.Jobs)) -IdentityIds @($cands | ForEach-Object Id))
        $cleared = [string](Get-SIMoveProp $mst @('roles', $r, 'rightsClearedUtc'))
        $roles[$r] = @{ Selection = $sel; InUse = (Get-SIIdentityMoveInUse -Users $users -Candidates $cands); Unknown = $false; RightsLeft = $(if ($cleared) { $false } else { $null }) }
        # an updater that signs in with a CERTIFICATE (SI_UPDATER_AUTH not ManagedIdentity) does not run as its identity at all:
        # missing, said -- moving it to its managed identity is its own step of the plan
        if ($r -eq 'updater' -and "$($Ctx.SelfAuth)" -eq 'Certificate' -and $sel.State -ne 'none') { $roles[$r].Note = 'the updater signs in with a certificate, not with its managed identity' }
    }
    $roles['sql-admin-group'] = @{ Entry = (Get-SIIdentityMoveSqlAdminGroupEntry -Ctx $Ctx) }
    # the database setup job's own identity (the one SI_DBINIT_MI_CLIENT_ID names) and the in-network SQL identity, checked only
    $dbj = @($Ctx.Jobs | Where-Object { [string]$_.name -eq 'caj-si-dbinit' })[0]
    if ($dbj) {
        $mi = ''; foreach ($ct in @(Get-SIMoveProp $dbj @('properties', 'template', 'containers'))) { foreach ($ev in @(Get-SIMoveProp $ct @('env'))) { if ($ev -and [string](Get-SIMoveProp $ev @('name')) -eq 'SI_DBINIT_MI_CLIENT_ID') { $mi = ([string](Get-SIMoveProp $ev @('value'))).Trim() } } }
        $use = @($Ctx.Identities | Where-Object { $_ -and $mi -and $_.ClientId -ieq $mi })[0]
        $std = @($Ctx.Identities | Where-Object { $_ -and $_.Name -ieq 'id-si-dbinit' })[0]
        $roles['dbinit'] = @{ Selection = [pscustomobject]@{ Role = 'dbinit'; Standard = 'id-si-dbinit'; Old = $(if ($use -and $use.Name -ine 'id-si-dbinit') { $use } else { $null }); New = $std; State = $(if ($use -and $use.Name -ine 'id-si-dbinit') { 'move' } elseif ($std) { 'done' } else { 'none' }) }; InUse = $use; Unknown = (-not $use) }
    }
    $sqlId = @($Ctx.Identities | Where-Object { $_ -and $_.Name -ieq 'id-si-sql' })[0]
    if ($sqlId) { $roles['sql'] = @{ Selection = [pscustomobject]@{ Role = 'sql'; Standard = 'id-si-sql'; Old = $null; New = $sqlId; State = 'done' }; InUse = $sqlId; Unknown = $false } }
    $rep = Get-SIIdentityNamesReport -Roles $roles
    $lines = @($rep.Record.roles.Keys | ForEach-Object { $e = $rep.Record.roles[$_]; '{0}: {1} ({2}{3})' -f $_, $e.state, $e.name, $(if ($e.objectId) { ", object id $($e.objectId)" } else { '' }) })
    $step = @(Get-SISetupSteps -StateRows @([pscustomobject]@{ Name = $script:SIMove.ReportName; Value = $rep.Value; UpdatedAt = $null }) -NowUtc ([datetime]::UtcNow) | Where-Object { $_.key -eq 'identity-names' })[0]
    if ($step) { $lines += ('heartbeat setup step: identity-names {0}{1}' -f $step.state, $(if ($step.PSObject.Properties['detail']) { ' -- ' + $step.detail } else { '' })) }
    if (-not $Ctx.Apply) { return New-SIIdentityMoveStepResult -Step report -State planned -Lines (@($lines) + 'plan: write cfg.InstallState IdentityNames') -Data $rep }
    if (-not $Ctx.StateDatabase) { return New-SIIdentityMoveStepResult -Step report -State stop -Lines (@($lines) + 'no state database: nothing recorded') -Data $rep }
    if (Save-SIMoveInstallState -Ctx $Ctx -Name $script:SIMove.ReportName -Value $rep.Value) { return New-SIIdentityMoveStepResult -Step report -State done -Lines (@($lines) + 'recorded and read back: cfg.InstallState IdentityNames') -Data $rep }
    New-SIIdentityMoveStepResult -Step report -State stop -Lines (@($lines) + 'READ BACK FAILED: cfg.InstallState IdentityNames') -Data $rep
}

function Invoke-SIIdentityMove {
    <#
        THE ORCHESTRATION of one role at one install: the steps of -Steps in the framework's order. A step that does not end
        'done' (or 'n/a' / 'planned' in a plan) ends the chain; 'report' always runs when it was asked for. Switch and
        clean-up refuse at an install on SI's hold list (or when the hold list could not be read). Returns @{ Results;
        CustomerSteps }.
    #>
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][string[]]$Steps, [AllowNull()][string[]]$HoldHandles, [switch]$Rollback,
          [string[]]$Confirmed = @(), [int]$IdleDays = 7, [switch]$Initialized)
    $results = New-Object System.Collections.Generic.List[object]
    # updater mode: what it may not do is a SUPPORT step, never a customer action (New-SIIdentityMoveCustomerStep)
    $script:SIMoveHandsOff = ("$($Ctx.Mode)" -eq 'updater')
    # -Initialized: the caller read the install once already (the updater moves every role in one run)
    $init = if ($Initialized) { $null } else { Initialize-SIMoveInstall -Ctx $Ctx }
    if ($init) { $results.Add((New-SIIdentityMoveStepResult -Step inventory -State stop -Lines @($init))); return [pscustomobject]@{ Results = $results.ToArray(); CustomerSteps = @() } }
    $held = Test-SIIdentityMoveHold -Handle $Ctx.Handle -HoldHandles $HoldHandles
    $inv = $null; $copy = $null; $ended = $false
    $needInv = @($Steps | Where-Object { $_ -ne 'report' }).Count -gt 0
    if ($needInv) {
        $r = Invoke-SIMoveInventory -Ctx $Ctx -Role $Ctx.Role
        if ($Steps -contains 'inventory') { $results.Add($r) }
        $inv = $r.Data
        if ($r.State -ne 'done') { $ended = $true; if ($Steps -notcontains 'inventory') { $results.Add($r) } }
    }
    foreach ($s in @($Steps | Where-Object { $_ -notin 'inventory', 'report' })) {
        if ($ended) { break }
        if ($s -in 'switch', 'clean-up' -and $held) {
            $results.Add((New-SIIdentityMoveStepResult -Step $s -State stop -Lines @($(if ($null -eq $HoldHandles) { 'the hold list could not be read (-HoldHandles or the hold file): switch and clean-up refuse' } else { ('{0} is on SI''s hold list: no switch, no clean-up' -f $Ctx.Handle) }))))
            $ended = $true; break
        }
        $r = switch ($s) {
            'ensure'      { Invoke-SIMoveEnsure -Ctx $Ctx -Inventory $inv }
            'copy-rights' { Invoke-SIMoveCopyRights -Ctx $Ctx -Inventory $inv -Confirmed $Confirmed }
            'switch'      { Invoke-SIMoveSwitch -Ctx $Ctx -Inventory $inv -CopyResult $copy -Rollback:$Rollback -Confirmed $Confirmed }
            'prove'       { Invoke-SIMoveProve -Ctx $Ctx -Inventory $inv -IdleDays $IdleDays }
            'clean-up'    { Invoke-SIMoveCleanup -Ctx $Ctx -Inventory $inv }
        }
        if ($s -eq 'copy-rights') { $copy = $r }
        $results.Add($r)
        $okStates = if ($Ctx.Apply) { @('done', 'n/a') } else { @('done', 'n/a', 'planned') }
        if ($r.State -notin $okStates) { $ended = $true }
    }
    if ($Steps -contains 'report') { $results.Add((Invoke-SIMoveReport -Ctx $Ctx)) }
    [pscustomobject]@{ Results = $results.ToArray(); CustomerSteps = @($results | ForEach-Object { $_.CustomerSteps } | Where-Object { $_ }) }
}
