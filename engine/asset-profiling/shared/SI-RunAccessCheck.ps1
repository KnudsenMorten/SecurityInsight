# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

<#
    WHAT A COLLECTION RUN NEEDS IN AZURE -- CHECKED, NEVER CREATED AND NEVER GRANTED.

    A run assigns no role and creates no resource group, workspace, data collection endpoint or storage account. Setup
    does that (setup\ConfigWizard\backend\Initialize-SIInfra.ps1 creates the resources, setup\Grant-SIIdentity.ps1 grants
    the identity). The run only LOOKS, read-only and once per process:

      * do the workspace, the rules' resource group, the data collection endpoint (and the storage account, when its
        resource group is configured) exist?
      * may the run's identity SEND -- Monitoring Metrics Publisher on the rules' resource group?
      * and, asked for only by a run that has to create a table / rule or add a column: may it CREATE -- Monitoring
        Contributor on the rules' resource group, Log Analytics Contributor on the workspace?

    Something missing is ONE plain line naming it and the setup command that fixes it. The run then goes on exactly as
    before: the send (or the create) fails with its own error. What cannot be read is never guessed: an identity that
    may not read its role assignments, a role definition that cannot be read, a lookup that is refused -- no line.

    A role counts when it is held at the scope or above it, directly or through a group, and when its DEFINITION allows
    the action -- so Contributor, Owner or a custom role that allows it is not reported as missing.

    Every call in this file is a GET (the -Arm seam has no method argument). The guard test
    tests\pester\SIv3-RunAssignsNoRole.Tests.ps1 holds that, and that no collection source writes a role assignment.
#>

# The built-in roles a SecurityInsight identity normally holds, with the part of each definition this check reads --
# so the usual install needs no role-definition lookup at all. Any other role is read from Azure, once per process.
$script:SIRunAccessKnownRoles = @{
    '3913510d-42f4-4e42-8a64-420c390055eb' = @{ Name = 'Monitoring Metrics Publisher';   Actions = @(); DataActions = @('Microsoft.Insights/Metrics/Write', 'Microsoft.Insights/Telemetry/Write') }
    '749f88d5-cbae-40b8-bcfc-e573ddc772fa' = @{ Name = 'Monitoring Contributor';         Actions = @('Microsoft.Insights/dataCollectionRules/*', 'Microsoft.Insights/dataCollectionEndpoints/*'); DataActions = @() }
    '92aaf0da-9dab-42b6-94a3-d43ce8d16293' = @{ Name = 'Log Analytics Contributor';      Actions = @('Microsoft.OperationalInsights/*'); DataActions = @() }
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = @{ Name = 'Contributor';                    Actions = @('*'); DataActions = @() }
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = @{ Name = 'Owner';                          Actions = @('*'); DataActions = @() }
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' = @{ Name = 'Reader';                         Actions = @('*/read'); DataActions = @() }
    '73c42c96-874c-492b-b04d-ab87d138a893' = @{ Name = 'Log Analytics Reader';           Actions = @('*/read'); DataActions = @() }
    '43d0d8ad-25c7-4714-9337-8ba259a9fe05' = @{ Name = 'Monitoring Reader';              Actions = @('*/read'); DataActions = @() }
    '7f951dda-4ed3-4680-a7ca-43fe172d538d' = @{ Name = 'AcrPull';                        Actions = @(); DataActions = @() }
    '4633458b-17de-408a-b874-0445c86b69e6' = @{ Name = 'Key Vault Secrets User';         Actions = @(); DataActions = @() }
    'ba92f5b4-2d11-453d-a403-e96b0029c9fe' = @{ Name = 'Storage Blob Data Contributor';  Actions = @(); DataActions = @() }
    '974c5e8b-45b9-4653-ba55-5f855dd0fb88' = @{ Name = 'Storage Queue Data Contributor'; Actions = @(); DataActions = @() }
    '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3' = @{ Name = 'Storage Table Data Contributor'; Actions = @(); DataActions = @() }
}

function Get-SIRunAccessValues {
    <# The settings the check reads, from the run's globals. -StorageAccountName: the run's own argument, which wins. #>
    param([string]$StorageAccountName)
    $v = @{}
    foreach ($n in 'SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SI_WorkspaceResourceGroup', 'SI_WorkspaceName', 'SI_DceResourceGroup',
                   'SI_DcrResourceGroup', 'SI_DceName', 'SI_StorageAccount', 'SI_StorageResourceGroup', 'SI_SPN_ObjectId', 'SI_LogIngest_ObjectId') {
        $v[$n] = "$(Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue)"
    }
    if (-not [string]::IsNullOrWhiteSpace($StorageAccountName)) { $v['SI_StorageAccount'] = $StorageAccountName }
    $v
}

function Resolve-SIRunAccessTarget {
    <#
        PURE. The names and resource ids a collection run sends to, from its settings -- the same order and the same
        fallback names the run has always used: the subscription, resource group and name of the workspace are read from
        SI_WorkspaceResourceId when they are not set on their own. SubscriptionId is '' when nothing names one.
        StorageAccountId is '' unless SI_StorageResourceGroup says where the account is (it is reached by NAME).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    $get = { param($n) ([string]$Values[$n]).Trim() }
    $sub = & $get 'SI_AzSubscriptionId'
    $wsRg = & $get 'SI_WorkspaceResourceGroup'; if (-not $wsRg) { $wsRg = 'rg-securityinsight' }
    $wsName = & $get 'SI_WorkspaceName'; if (-not $wsName) { $wsName = 'log-platform-management-securityinsight' }
    $wsId = & $get 'SI_WorkspaceResourceId'
    if ($wsId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[^/]+/workspaces/([^/?]+)') {
        if (-not $sub) { $sub = $Matches[1] }
        if ($wsRg -eq 'rg-securityinsight') { $wsRg = $Matches[2] }
        if ($wsName -eq 'log-platform-management-securityinsight') { $wsName = $Matches[3] }
    }
    $dceRg = & $get 'SI_DceResourceGroup'; if (-not $dceRg) { $dceRg = 'rg-securityinsight' }
    $dcrRg = & $get 'SI_DcrResourceGroup'; if (-not $dcrRg) { $dcrRg = 'rg-securityinsight' }
    $dceName = & $get 'SI_DceName'; if (-not $dceName) { $dceName = 'dce-si-securityinsight' }
    if (-not $wsId -and $sub) { $wsId = "/subscriptions/$sub/resourceGroups/$wsRg/providers/Microsoft.OperationalInsights/workspaces/$wsName" }
    $stAcct = & $get 'SI_StorageAccount'
    $stRg = & $get 'SI_StorageResourceGroup'
    [pscustomobject]@{
        SubscriptionId         = $sub
        WorkspaceResourceId    = $wsId
        WorkspaceName          = $wsName
        WorkspaceResourceGroup = $wsRg
        DcrResourceGroup       = $dcrRg
        DcrResourceGroupId     = $(if ($sub) { "/subscriptions/$sub/resourceGroups/$dcrRg" } else { '' })
        DceResourceGroup       = $dceRg
        DceName                = $dceName
        DceId                  = $(if ($sub) { "/subscriptions/$sub/resourceGroups/$dceRg/providers/Microsoft.Insights/dataCollectionEndpoints/$dceName" } else { '' })
        StorageAccount         = $stAcct
        StorageResourceGroup   = $stRg
        StorageAccountId       = $(if ($sub -and $stAcct -and $stRg) { "/subscriptions/$sub/resourceGroups/$stRg/providers/Microsoft.Storage/storageAccounts/$stAcct" } else { '' })
    }
}

function Get-SIRunAccessNeeds {
    <#
        PURE. What the identity must be allowed to do: Send = post rows through the rules; Create = make a table / a rule
        or add a column (asked for only by a run that has to). Each is @{ Key; Role (the built-in role setup grants for
        it); Scope; ScopeText; Action; DataAction (a data action, not a management action); Why }.
    #>
    param([Parameter(Mandatory)]$Target, [ValidateSet('Send', 'Create')][string]$Need = 'Send')
    $rgText = "resource group '{0}'" -f $Target.DcrResourceGroup
    if ($Need -eq 'Send') {
        if ($Target.DcrResourceGroupId) {
            [pscustomobject]@{ Key = 'send'; Role = 'Monitoring Metrics Publisher'; Scope = [string]$Target.DcrResourceGroupId; ScopeText = $rgText
                               Action = 'Microsoft.Insights/Telemetry/Write'; DataAction = $true; Why = 'to send rows to Log Analytics' }
        }
        return
    }
    if ($Target.DcrResourceGroupId) {
        [pscustomobject]@{ Key = 'rule'; Role = 'Monitoring Contributor'; Scope = [string]$Target.DcrResourceGroupId; ScopeText = $rgText
                           Action = 'Microsoft.Insights/dataCollectionRules/write'; DataAction = $false; Why = 'to create or extend a data collection rule' }
    }
    if ($Target.WorkspaceResourceId) {
        [pscustomobject]@{ Key = 'table'; Role = 'Log Analytics Contributor'; Scope = [string]$Target.WorkspaceResourceId; ScopeText = ("workspace '{0}'" -f $Target.WorkspaceName)
                           Action = 'Microsoft.OperationalInsights/workspaces/tables/write'; DataAction = $false; Why = 'to create a table or add a column' }
    }
}

function Test-SIRunAccessPattern {
    <# PURE. Does one action pattern of a role definition ('*' = anything, any case) cover the action? #>
    param([string]$Pattern, [string]$Action)
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $false }
    $rx = '^' + [regex]::Escape($Pattern.Trim()).Replace('\*', '.*') + '$'
    [regex]::IsMatch($Action, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Test-SIRunAccessAllowed {
    <#
        PURE. Does a role definition allow the action? -Definition: @{ Actions; NotActions; DataActions; NotDataActions }
        (one permission block). Allowed = a pattern covers it and no "not" pattern takes it away again.
    #>
    param($Definition, [string]$Action, [bool]$DataAction)
    if (-not $Definition) { return $false }
    $yes = if ($DataAction) { @($Definition.DataActions) } else { @($Definition.Actions) }
    $no = if ($DataAction) { @($Definition.NotDataActions) } else { @($Definition.NotActions) }
    foreach ($n in $no) { if (Test-SIRunAccessPattern -Pattern ([string]$n) -Action $Action) { return $false } }
    foreach ($y in $yes) { if (Test-SIRunAccessPattern -Pattern ([string]$y) -Action $Action) { return $true } }
    $false
}

function Test-SIRunAccessScopeCovers {
    <# PURE. Is a role assignment's scope the needed scope or above it? ('/' is above everything.) #>
    param([string]$AssignmentScope, [string]$NeededScope)
    $a = "$AssignmentScope".TrimEnd('/').ToLowerInvariant(); $n = "$NeededScope".TrimEnd('/').ToLowerInvariant()
    if (-not $n) { return $false }
    ($a -eq '') -or ($a -eq $n) -or $n.StartsWith($a + '/')
}

function Get-SIRunAccessRoleId {
    <# PURE. The role definition's own id (the GUID at the end of a roleDefinitionId), lower case. #>
    param([string]$RoleDefinitionId)
    (("$RoleDefinitionId".TrimEnd('/') -split '/')[-1]).ToLowerInvariant()
}

function Get-SIRunAccessVerdict {
    <#
        PURE. One answer per need: Held, Missing, or Unknown.
          -Assignments  the identity's role assignments: each @{ Scope; RoleDefinitionId }
          -Definitions  role id (GUID) -> the definitions read from Azure: a LIST of permission blocks, or $null when the
                        definition could not be read. The built-in roles of this file need no entry.
        Held    = an assignment at the scope or above it whose definition allows the action.
        Unknown = nothing found that allows it, but an assignment there has a definition that could not be read --
                  it may allow it, so nothing is said.
        Missing = every assignment there was read and none allows it.
    #>
    param([object[]]$Needs = @(), [object[]]$Assignments = @(), [System.Collections.IDictionary]$Definitions = @{})
    foreach ($need in @($Needs | Where-Object { $_ })) {
        $held = $false; $unread = $false
        foreach ($a in @($Assignments | Where-Object { $_ })) {
            if (-not (Test-SIRunAccessScopeCovers -AssignmentScope ([string]$a.Scope) -NeededScope ([string]$need.Scope))) { continue }
            $id = Get-SIRunAccessRoleId -RoleDefinitionId ([string]$a.RoleDefinitionId)
            $blocks = @()
            if ($script:SIRunAccessKnownRoles.ContainsKey($id)) { $blocks = @($script:SIRunAccessKnownRoles[$id]) }
            elseif ($Definitions.Contains($id) -and $null -ne $Definitions[$id]) { $blocks = @($Definitions[$id]) }
            else { $unread = $true; continue }
            foreach ($b in $blocks) { if (Test-SIRunAccessAllowed -Definition $b -Action ([string]$need.Action) -DataAction ([bool]$need.DataAction)) { $held = $true; break } }
            if ($held) { break }
        }
        [pscustomobject]@{ Need = $need; State = $(if ($held) { 'Held' } elseif ($unread) { 'Unknown' } else { 'Missing' }) }
    }
}

function Get-SIRunAccessFixCommand {
    <#
        PURE. The setup command that grants the identity what a run needs -- with THIS install's names, so it needs no
        configuration file where it is run. -AllowSchemaCreate is always there: an install repaired with this command
        must also be able to create its tables and rules. '' when the identity or the workspace is not known.
    #>
    param([Parameter(Mandatory)]$Target, [string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId) -or -not $Target.WorkspaceResourceId -or -not $Target.SubscriptionId) { return '' }
    $cmd = 'setup\Grant-SIIdentity.ps1 -PrincipalId {0} -SubscriptionId {1} -WorkspaceResourceId {2}' -f $PrincipalId.Trim(), $Target.SubscriptionId, $Target.WorkspaceResourceId
    if ($Target.StorageAccount -and $Target.StorageResourceGroup) { $cmd += ' -StorageAccountName {0} -StorageResourceGroup {1}' -f $Target.StorageAccount, $Target.StorageResourceGroup }
    if ($Target.DcrResourceGroup) { $cmd += ' -DcrResourceGroup {0}' -f $Target.DcrResourceGroup }
    $cmd + ' -AllowSchemaCreate -Apply'
}

function Get-SIRunAccessLine {
    <#
        PURE. THE one line, or '' when there is nothing to say. Resources that do not exist come first (a role on
        something that is not there says nothing); otherwise the roles the identity does not hold.
          -MissingResources  texts such as "the Log Analytics workspace 'x' (resource group 'y')"
          -Verdicts          Get-SIRunAccessVerdict's answers; only Missing is said, never Unknown
    #>
    param([string[]]$MissingResources = @(), [object[]]$Verdicts = @(), [Parameter(Mandatory)]$Target, [string]$PrincipalId)
    $res = @($MissingResources | Where-Object { $_ })
    if ($res.Count) {
        return ('access check: {0} {1} not exist in subscription {2} -- a run creates no Azure resource, so nothing was created and what the run sends there will fail. Create it with setup\ConfigWizard\backend\Initialize-SIInfra.ps1 (it creates only what is missing), then run again.' -f `
            ($res -join ' and '), $(if ($res.Count -gt 1) { 'do' } else { 'does' }), $Target.SubscriptionId)
    }
    $miss = @($Verdicts | Where-Object { $_ -and $_.State -eq 'Missing' })
    if (-not $miss.Count) { return '' }
    $what = @($miss | ForEach-Object { '{0} on {1} ({2})' -f $_.Need.Role, $_.Need.ScopeText, $_.Need.Why }) -join ' and '
    $who = if ([string]::IsNullOrWhiteSpace($PrincipalId)) { "SecurityInsight's identity" } else { "SecurityInsight's identity ($($PrincipalId.Trim()))" }
    $cmd = Get-SIRunAccessFixCommand -Target $Target -PrincipalId $PrincipalId
    $fix = if ($cmd) { 'Someone who may assign roles runs: {0}' -f $cmd } else { 'Someone who may assign roles runs setup\Grant-SIIdentity.ps1 -AllowSchemaCreate -Apply for this identity.' }
    'access check: {0} does not hold {1} -- a run assigns no role, so nothing was changed and that step will fail. {2}' -f $who, $what, $fix
}

function Get-SIRunAccessState {
    <# The check's memory for THIS process: the role assignments and definitions it read, and the lines it has said. #>
    $s = Get-Variable -Name SI_RunAccessState -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($s -isnot [hashtable]) {
        $s = @{ Assignments = @{}; Definitions = @{}; Said = @{}; Resources = @{} }
        Set-Variable -Name SI_RunAccessState -Scope Global -Value $s
    }
    $s
}

function Get-SIRunAccessPrincipalId {
    <# The object id of the identity this process is signed in as (read from its own token), else the configured one. #>
    param([System.Collections.IDictionary]$Values = @{})
    try {
        $c = ConvertFrom-SIJwtPayload (Get-SIAzureToken -Audience Arm)
        if ($c -and "$($c.oid)".Trim()) { return "$($c.oid)".Trim() }
    } catch { }
    foreach ($n in 'SI_SPN_ObjectId', 'SI_LogIngest_ObjectId') { if ("$($Values[$n])".Trim()) { return "$($Values[$n])".Trim() } }
    ''
}

function Get-SIRunAccessDefaultArm {
    <# The real read: one GET against Azure Resource Manager ($null for "not found"). There is no method argument. #>
    { param([string]$Path, [string]$ApiVersion, [bool]$List)
        if ($List) { Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -List } else { Invoke-SIArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound } }
}

function Get-SIRunAccessMissingResources {
    <#
        Which of the things the run sends to do not exist -- texts for the line. Only a clear "not found" counts: a
        lookup that is refused or fails says nothing. The endpoint is looked for by name in the whole subscription
        before it is called missing (the send finds it there too). Read once per process (-State).
    #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][hashtable]$State)
    $key = ('{0}|{1}|{2}|{3}' -f $Target.WorkspaceResourceId, $Target.DcrResourceGroupId, $Target.DceId, $Target.StorageAccountId).ToLowerInvariant()
    if ($State.Resources.ContainsKey($key)) { return @($State.Resources[$key]) }
    $missing = New-Object System.Collections.Generic.List[string]
    $absent = { param($path, $api) try { $null -eq (& $Arm $path $api $false) } catch { $false } }
    if ($Target.DcrResourceGroupId -and (& $absent $Target.DcrResourceGroupId '2021-04-01')) {
        $missing.Add(("the resource group '{0}' of the data collection rules" -f $Target.DcrResourceGroup))
    }
    if ($Target.WorkspaceResourceId -and (& $absent $Target.WorkspaceResourceId '2022-10-01')) {
        $missing.Add(("the Log Analytics workspace '{0}' (resource group '{1}')" -f $Target.WorkspaceName, $Target.WorkspaceResourceGroup))
    }
    if ($Target.DceId -and (& $absent $Target.DceId '2023-03-11')) {
        $elsewhere = $true   # not listed = not known: say nothing
        try {
            $all = @(& $Arm ("/subscriptions/{0}/providers/Microsoft.Insights/dataCollectionEndpoints" -f $Target.SubscriptionId) '2023-03-11' $true)
            $elsewhere = @($all | Where-Object { $_ -and [string]$_.name -eq $Target.DceName }).Count -gt 0
        } catch { $elsewhere = $true }
        if (-not $elsewhere) { $missing.Add(("the data collection endpoint '{0}'" -f $Target.DceName)) }
    }
    if ($Target.StorageAccountId -and (& $absent $Target.StorageAccountId '2023-01-01')) {
        $missing.Add(("the storage account '{0}' (resource group '{1}')" -f $Target.StorageAccount, $Target.StorageResourceGroup))
    }
    $State.Resources[$key] = $missing.ToArray()
    @($State.Resources[$key])
}

function Get-SIRunAccessAssignments {
    <#
        The identity's role assignments in a subscription -- at, above and below it, in ONE read, kept for the process.
        Returns @{ Readable; Items } where each item is @{ Scope; RoleDefinitionId }. Readable = $false when the identity
        may not read role assignments (or the read failed): nothing is said then.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][hashtable]$State)
    $key = ('{0}|{1}' -f $SubscriptionId, $PrincipalId).ToLowerInvariant()
    if ($State.Assignments.ContainsKey($key)) { return $State.Assignments[$key] }
    $out = @{ Readable = $false; Items = @() }
    try {
        $path = '/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}' -f $SubscriptionId, [uri]::EscapeDataString(("principalId eq '{0}'" -f $PrincipalId))
        $rows = @(& $Arm $path '2022-04-01' $true)
        $out.Items = @($rows | Where-Object { $_ -and $_.properties } | ForEach-Object { [pscustomobject]@{ Scope = [string]$_.properties.scope; RoleDefinitionId = [string]$_.properties.roleDefinitionId } })
        $out.Readable = $true
    } catch { $out.Readable = $false }
    $State.Assignments[$key] = $out
    $out
}

function Add-SIRunAccessDefinitions {
    <# Reads the definition of every role in -Assignments this file does not know, once per process. Unreadable = $null. #>
    param([object[]]$Assignments = @(), [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][hashtable]$State)
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $id = Get-SIRunAccessRoleId -RoleDefinitionId ([string]$a.RoleDefinitionId)
        if (-not $id -or $script:SIRunAccessKnownRoles.ContainsKey($id) -or $State.Definitions.ContainsKey($id)) { continue }
        $blocks = $null
        try {
            $d = & $Arm ([string]$a.RoleDefinitionId) '2022-04-01' $false
            if ($d -and $d.properties) {
                $blocks = @(@($d.properties.permissions) | Where-Object { $_ } | ForEach-Object {
                    @{ Actions = @($_.actions); NotActions = @($_.notActions); DataActions = @($_.dataActions); NotDataActions = @($_.notDataActions) } })
            }
        } catch { $blocks = $null }
        $State.Definitions[$id] = $blocks
    }
}

function Invoke-SIRunAccessCheck {
    <#
        THE CHECK. Read-only. Returns @{ Checked; Line; Missing; MissingResources } -- Line is the one line to print, ''
        when there is nothing to say (everything is there, the role list cannot be read, or this process said it already).
          -Need       Send (default) or Create
          -Resources  also check that the workspace, the rules' resource group, the endpoint and the storage account exist
          -Arm        the read ({ param($Path, $ApiVersion, $List) }); tests pass their own
          -State      the per-process memory; tests pass their own
        A role that looks missing is looked for once more the way Azure itself answers "what may this identity do here"
        (assignments at the scope and above it, group memberships included) before anything is said.
    #>
    param([Parameter(Mandatory)]$Target, [string]$PrincipalId, [ValidateSet('Send', 'Create')][string]$Need = 'Send', [switch]$Resources,
          [scriptblock]$Arm, [hashtable]$State)
    if (-not $Arm) { $Arm = Get-SIRunAccessDefaultArm }
    if (-not $State) { $State = Get-SIRunAccessState }
    $result = [pscustomobject]@{ Checked = $false; Line = ''; Missing = @(); MissingResources = @() }
    if (-not $Target.SubscriptionId) { return $result }

    $missingRes = @()
    if ($Resources) { $missingRes = @(Get-SIRunAccessMissingResources -Target $Target -Arm $Arm -State $State) }
    $verdicts = @()
    if (-not $missingRes.Count -and -not [string]::IsNullOrWhiteSpace($PrincipalId)) {
        $needs = @(Get-SIRunAccessNeeds -Target $Target -Need $Need)
        $list = Get-SIRunAccessAssignments -SubscriptionId $Target.SubscriptionId -PrincipalId $PrincipalId -Arm $Arm -State $State
        if (-not $list.Readable) { return $result }
        $items = @($list.Items)
        # a workspace in another subscription: its own assignments are read there
        if ($Target.WorkspaceResourceId -match '^/subscriptions/([^/]+)/' -and $Matches[1] -ne $Target.SubscriptionId -and @($needs | Where-Object { $_.Key -eq 'table' }).Count) {
            $other = Get-SIRunAccessAssignments -SubscriptionId $Matches[1] -PrincipalId $PrincipalId -Arm $Arm -State $State
            if (-not $other.Readable) { return $result }
            $items = @($items) + @($other.Items)
        }
        Add-SIRunAccessDefinitions -Assignments $items -Arm $Arm -State $State
        $verdicts = @(Get-SIRunAccessVerdict -Needs $needs -Assignments $items -Definitions $State.Definitions)
        $confirmed = New-Object System.Collections.Generic.List[object]
        foreach ($v in $verdicts) {
            if ($v.State -ne 'Missing') { $confirmed.Add($v); continue }
            # held through a group? Azure's own answer for this scope, before anything is said
            try {
                $path = '{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}' -f ([string]$v.Need.Scope).TrimEnd('/'), [uri]::EscapeDataString(("assignedTo('{0}')" -f $PrincipalId))
                $more = @(@(& $Arm $path '2022-04-01' $true) | Where-Object { $_ -and $_.properties } | ForEach-Object { [pscustomobject]@{ Scope = [string]$_.properties.scope; RoleDefinitionId = [string]$_.properties.roleDefinitionId } })
                Add-SIRunAccessDefinitions -Assignments $more -Arm $Arm -State $State
                $again = @(Get-SIRunAccessVerdict -Needs @($v.Need) -Assignments $more -Definitions $State.Definitions)
                if ($again.Count -eq 1 -and $again[0].State -eq 'Missing') { $confirmed.Add($v) } else { $confirmed.Add([pscustomobject]@{ Need = $v.Need; State = $(if ($again.Count -eq 1) { $again[0].State } else { 'Unknown' }) }) }
            } catch { $confirmed.Add([pscustomobject]@{ Need = $v.Need; State = 'Unknown' }) }
        }
        $verdicts = $confirmed.ToArray()
    }
    $result.Checked = $true
    $result.MissingResources = @($missingRes)
    $result.Missing = @($verdicts | Where-Object { $_.State -eq 'Missing' } | ForEach-Object { $_.Need })
    $line = Get-SIRunAccessLine -MissingResources $missingRes -Verdicts $verdicts -Target $Target -PrincipalId $PrincipalId
    if ($line -and -not $State.Said.ContainsKey($line)) { $State.Said[$line] = $true; $result.Line = $line }
    $result
}

function Write-SIRunAccessNote {
    <#
        What the run calls: the check, and its one line into the run log when there is one. Never throws and never stops
        the run. -Target: what Resolve-SIRunAccessTarget returned (resolved from the globals when not given).
    #>
    param($Target, [ValidateSet('Send', 'Create')][string]$Need = 'Send', [switch]$Resources)
    try {
        $values = Get-SIRunAccessValues
        if (-not $Target) { $Target = Resolve-SIRunAccessTarget -Values $values }
        $r = Invoke-SIRunAccessCheck -Target $Target -PrincipalId (Get-SIRunAccessPrincipalId -Values $values) -Need $Need -Resources:$Resources
        if ($r.Line) { Write-Warning $r.Line }
    } catch { Write-Verbose ('access check skipped: {0}' -f $_.Exception.Message) }
}
