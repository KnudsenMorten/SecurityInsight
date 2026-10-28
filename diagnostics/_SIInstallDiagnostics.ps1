#Requires -Version 5.1
<#
    SecurityInsight -- the install diagnostics' shared engine: diagnostics/Test-SIInstall.ps1 (is this install healthy and
    isolated?) and diagnostics/Invoke-SIJobsOnce.ps1 (run every engine job once, in schedule order).

    Product scripts, usable at a customer: no environment value is written in here. Everything comes from the install's
    own config file (config/SecurityInsight.custom.ps1), read WITHOUT running it -- the file may read Key Vault, and a
    diagnostic must never do that.

    Azure is reached over plain REST (engine/_shared/SI-AzRest.ps1: Log Analytics data plane, ARM, Resource Graph), so
    no Az module is needed. EVERY call that leaves the process goes through a seam ($Seams: Arm, LaQuery, Graph, Now,
    Sleep, Print), so the tests run the whole flow offline.

    Ships in both editions; PS 5.1 and PowerShell 7 (Cloud Shell, Linux).
#>

$script:SIDiagRoot = Split-Path -Parent $PSScriptRoot
# loaded unless the REAL file is (Get-SIAzRestState is only defined there; a test's global Invoke-SIArm stub is not it)
if (-not (Get-Command -Name Get-SIAzRestState -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine($script:SIDiagRoot, 'engine', '_shared', 'SI-AzRest.ps1'))
}

# A role that can CHANGE something. Read roles (Reader, Log Analytics Reader, AcrPull, Key Vault Secrets User) never count.
$script:SIDiagWriteRolePattern = '(?i)(owner|contributor|monitoring metrics publisher|user access administrator|role based access control administrator)'
$script:SIDiagFailedExitReasons = @('error', 'settings-error')
$script:SIDiagJobApi = '2024-03-01'

# ---------------------------------------------------------------------------------------------------------------------
# The install's config, read without running it
# ---------------------------------------------------------------------------------------------------------------------
function Read-SIInstallConfigValues {
    <#
        PURE apart from reading the file. The constant top-level `$global:<Name> = <value>` assignments of a config file,
        WITHOUT running it: strings, numbers, $true / $false, arrays of those. A value computed at run time (a Key Vault
        lookup, a variable) is skipped. Later assignments win, as when the file runs.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "The install's config file was not found: $Path" }
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    $out = @{}
    $statements = @()
    if ($ast.BeginBlock) { $statements += @($ast.BeginBlock.Statements) }
    if ($ast.ProcessBlock) { $statements += @($ast.ProcessBlock.Statements) }
    if ($ast.EndBlock) { $statements += @($ast.EndBlock.Statements) }
    foreach ($s in $statements) {
        if ($s -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
        if ([string]$s.Operator -ne 'Equals') { continue }
        $left = $s.Left
        while ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $name = [string]$left.VariablePath.UserPath
        if ($name -notmatch '^(?i)global:(.+)$') { continue }
        $key = $Matches[1]
        $right = $s.Right
        $expr = $null
        if ($right -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $right.Expression }
        elseif ($right -is [System.Management.Automation.Language.PipelineAst] -and @($right.PipelineElements).Count -eq 1 -and
                $right.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $right.PipelineElements[0].Expression }
        if (-not $expr) { continue }
        try { $out[$key] = $expr.SafeGetValue() } catch { continue }
    }
    $out
}

function Get-SIInstallTargetFromConfig {
    <#
        PURE. What the diagnostics look at, from the config values: subscription, the install's resource group, the
        workspace, the DCR resource group, the storage account, the identity, the configured DCR names and the grants
        SecurityInsight documents for its identity.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)
    $get = { param([string[]]$Names) foreach ($n in $Names) { $v = $Values[$n]; if ($null -ne $v -and "$v".Trim()) { return "$v".Trim() } }; '' }
    $ws = & $get @('SI_WorkspaceResourceId')
    $wsParts = if ($ws) { $ws.Trim('/') -split '/' } else { @() }
    $sub = & $get @('SI_Bootstrap_SubscriptionId', 'SI_AzSubscriptionId')
    if (-not $sub -and $wsParts.Count -ge 2) { $sub = $wsParts[1] }
    $rg = & $get @('SI_Bootstrap_ResourceGroupName', 'SI_DcrResourceGroup', 'SI_WorkspaceResourceGroup')
    if (-not $rg -and $wsParts.Count -ge 4) { $rg = $wsParts[3] }
    if (-not $ws) {
        $wsName = & $get @('SI_WorkspaceName'); $wsRg = & $get @('SI_WorkspaceResourceGroup')
        if (-not $wsRg) { $wsRg = $rg }
        if ($sub -and $wsRg -and $wsName) { $ws = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}' -f $sub, $wsRg, $wsName }
    }
    $dcrRg = & $get @('SI_DcrResourceGroup'); if (-not $dcrRg) { $dcrRg = $rg }
    $stg = & $get @('SI_StorageAccount'); $stgRg = & $get @('SI_StorageResourceGroup'); if (-not $stgRg) { $stgRg = $dcrRg }
    $stgId = if ($sub -and $stg) { '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}' -f $sub, $stgRg, $stg } else { '' }
    # The configured DCR names: every SI_*Dcr* / *_DcrName* setting holding a name (not a {0} pattern).
    $dcrNames = @($Values.Keys | Where-Object { $_ -match '(?i)^SI_.*dcr' -and $_ -notmatch '(?i)(pattern|resourcegroup|^SI_Dcr.*Rg)' } | Sort-Object |
        ForEach-Object { [string]$Values[$_] } | Where-Object { $_ -and $_ -notmatch '[{}]' } | Select-Object -Unique)
    $scopes = @($Values['SI_Bootstrap_IdentityReaderScopes'] | Where-Object { $_ })
    if (-not $scopes.Count -and $sub) { $scopes = @("/subscriptions/$sub") }
    [pscustomobject]@{
        SubscriptionId       = $sub
        ResourceGroup        = $rg
        ResourceGroupId      = $(if ($sub -and $rg) { '/subscriptions/{0}/resourceGroups/{1}' -f $sub, $rg } else { '' })
        WorkspaceResourceId  = $ws
        DcrResourceGroup     = $dcrRg
        DcrResourceGroupId   = $(if ($sub -and $dcrRg) { '/subscriptions/{0}/resourceGroups/{1}' -f $sub, $dcrRg } else { '' })
        StorageAccountId     = $stgId
        IdentityName         = (& $get @('SI_Bootstrap_ManagedIdentityName'))
        IdentityClientId     = (& $get @('SI_ManagedIdentityClientId', 'SI_SPN_ManagedIdentityClientId', 'SI_UAMI_ClientId'))
        DefenderWorkspaceId  = (& $get @('SI_DefenderWorkspaceResourceId'))
        ReaderScopes         = $scopes
        DcrNames             = $dcrNames
        KeyVaultName         = (& $get @('SI_KeyVaultName', 'SpnKeyVaultName'))
    }
}

function Get-SIInstallDocumentedWriteGrants {
    <#
        PURE. The WRITE grants SecurityInsight documents for its identity (the write rows of the container identity plan,
        container/_shared/SI-ContainerConfig.ps1 Get-SIContainerIdentityGrantPlan, plus the two first-run schema grants of
        setup/Grant-SIIdentity.ps1 -AllowSchemaCreate). Each is @{ Role; Scope }. A test pins this list to that plan.
    #>
    param([Parameter(Mandatory)]$Target)
    $g = New-Object System.Collections.Generic.List[object]
    $add = { param($r, $s) if ("$s".Trim()) { $g.Add([pscustomobject]@{ Role = $r; Scope = $s }) } }
    & $add 'Monitoring Metrics Publisher' $Target.DcrResourceGroupId
    foreach ($r in 'Storage Blob Data Contributor', 'Storage Queue Data Contributor', 'Storage Table Data Contributor') { & $add $r $Target.StorageAccountId }
    & $add 'Monitoring Contributor' $Target.DcrResourceGroupId
    & $add 'Log Analytics Contributor' $Target.WorkspaceResourceId
    $g.ToArray()
}

function Test-SIScopeInside {
    <# PURE. Is a scope the resource group (id) or inside it? #>
    param([string]$Scope, [string]$ResourceGroupId)
    if (-not $ResourceGroupId) { return $false }
    $s = "$Scope".TrimEnd('/').ToLowerInvariant(); $r = $ResourceGroupId.TrimEnd('/').ToLowerInvariant()
    ($s -eq $r) -or $s.StartsWith($r + '/')
}

function ConvertTo-SIDiagUtc {
    <# PURE. A Log Analytics / ARM time (text) as UTC [datetime], or $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or -not "$Value".Trim()) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

# ---------------------------------------------------------------------------------------------------------------------
# Seams and sign-in
# ---------------------------------------------------------------------------------------------------------------------
function Get-SIDiagnosticsDefaultSeams {
    <# The real calls. Tests replace any of them. #>
    @{
        Arm     = { param([string]$Method, [string]$Path, [string]$ApiVersion, [switch]$List, $Body)
                    $a = @{ Method = $(if ($Method) { $Method } else { 'GET' }); Path = $Path }
                    if ($ApiVersion) { $a.ApiVersion = $ApiVersion }
                    if ($null -ne $Body) { $a.Body = $Body }
                    if ($List) { $a.List = $true }
                    Invoke-SIArm @a }
        LaQuery = { param([string]$WorkspaceId, [string]$Query) Invoke-SILaQuery -WorkspaceId $WorkspaceId -Query $Query }
        Graph   = { param([string]$Query, [string[]]$Subscription) Search-SIResourceGraph -Query $Query -Subscription $Subscription }
        Now     = { [datetime]::UtcNow }
        # #239: the licence request state the updater keeps (Key Vault secret SI-LicenceRequest-State; never the token)
        LicenceState = { param([string]$VaultName) Get-SIKeyVaultSecretValue -VaultName $VaultName -Name 'SI-LicenceRequest-State' }
        # #240: the update state the updater keeps (source, last manifest per kind, holds; never the install key)
        UpdateState  = { param([string]$VaultName) Get-SIKeyVaultSecretValue -VaultName $VaultName -Name 'SI-Update-State' }
        Sleep   = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }
        Print   = { param([string]$Text, [string]$Color) if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text } }
    }
}

function Merge-SIDiagnosticsSeams {
    param([System.Collections.IDictionary]$Seams)
    $s = Get-SIDiagnosticsDefaultSeams
    if ($Seams) { foreach ($k in @($Seams.Keys)) { if ($Seams[$k] -is [scriptblock]) { $s[$k] = $Seams[$k] } } }
    $s
}

function Initialize-SIDiagnosticsSignIn {
    <#
        Who the REST calls run as. SecurityInsight v3 uses no PowerShell modules, so there is no Az session to borrow:
          Config     the install's own identity from its config: its managed identity on its VM / Arc server, or its
                     service principal certificate (from the machine's certificate store)
          Auto       a service principal certificate named in the environment (SI_DIAGNOSTICS_APPID +
                     SI_DIAGNOSTICS_TENANTID + SI_DIAGNOSTICS_CERTTHUMBPRINT) when all three are set, otherwise Config
          AzContext  no longer supported (it borrowed an Az PowerShell session); refused, naming the alternatives
    #>
    param([ValidateSet('Auto', 'AzContext', 'Config')][string]$SignIn = 'Auto', [System.Collections.IDictionary]$Values = @{})
    $st = Get-SIAzRestState
    if ($SignIn -eq 'AzContext') {
        throw 'SecurityInsight no longer uses an Az PowerShell session (-SignIn AzContext). Use -SignIn Config (the install''s own identity), or set SI_DIAGNOSTICS_APPID, SI_DIAGNOSTICS_TENANTID and SI_DIAGNOSTICS_CERTTHUMBPRINT to a service principal whose certificate is in this machine''s certificate store.'
    }
    if ($SignIn -eq 'Auto') {
        $eApp = [string]$env:SI_DIAGNOSTICS_APPID; $eTid = [string]$env:SI_DIAGNOSTICS_TENANTID; $eThumb = [string]$env:SI_DIAGNOSTICS_CERTTHUMBPRINT
        if ($eApp -and $eTid -and $eThumb) {
            $st.Connection = @{ Mode = 'Certificate'; AppId = $eApp; TenantId = $eTid; Thumbprint = ($eThumb -replace '\s', '') }
            return 'Certificate'
        }
    }
    $auth = [string]$Values['SI_AuthMethod']
    if ($auth -eq 'ManagedIdentity' -or [bool]$Values['SI_UseManagedIdentity']) {
        if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) {
            . ([IO.Path]::Combine($script:SIDiagRoot, 'auth', 'SI-ManagedIdentity.ps1'))
            # published globally: the token layer looks it up after this function has returned
            $f = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue
            if ($f) { Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $f.ScriptBlock }
        }
        $cid = [string]$Values['SI_UAMI_ClientId']; if (-not $cid) { $cid = [string]$Values['SI_ManagedIdentityClientId'] }
        $st.Connection = @{ Mode = 'ManagedIdentity'; ClientId = $cid }
        return 'ManagedIdentity'
    }
    $app = [string]$Values['SI_SPN_AppId']; $tid = [string]$Values['SI_SPN_TenantId']; $thumb = [string]$Values['SI_SPN_CertThumbprint']
    if ($app -and $tid -and $thumb) { $st.Connection = @{ Mode = 'Certificate'; AppId = $app; TenantId = $tid; Thumbprint = ($thumb -replace '\s', '') }; return 'Certificate' }
    throw 'No sign-in: run this where the install''s own identity is available (its managed identity, or its service principal certificate in this machine''s certificate store), or set SI_DIAGNOSTICS_APPID, SI_DIAGNOSTICS_TENANTID and SI_DIAGNOSTICS_CERTTHUMBPRINT to a service principal that can read the install''s resource group and its workspace.'
}

# ---------------------------------------------------------------------------------------------------------------------
# Test-SIInstall: data, run health, DCRs, isolation
# ---------------------------------------------------------------------------------------------------------------------
function Get-SIDiagLicenceRequest {
    <# The licence request state (JSON from SI-LicenceRequest-State) as the client reads it; the client is loaded on first use. #>
    param([AllowNull()][string]$Json)
    if (-not (Get-Command -Name Get-SILicenceRequestStatus -ErrorAction SilentlyContinue)) {
        . ([IO.Path]::Combine($script:SIDiagRoot, 'engine', '_shared', 'SI-LicenceRequest.ps1'))
    }
    Get-SILicenceRequestStatus -Json $Json
}

function Get-SIDiagUpdateState {
    <#
        #240: the update state (JSON from SI-Update-State) as the Pro update client reads it. $null on a copy without the
        client (Community) -- that install takes no updates from Invardia.
    #>
    param([AllowNull()][string]$Json)
    if (-not (Get-Command -Name Get-SIInvardiaUpdateStatus -ErrorAction SilentlyContinue)) {
        $client = [IO.Path]::Combine($script:SIDiagRoot, 'engine', '_shared', 'SI-InvardiaUpdate.ps1')
        if (-not (Test-Path -LiteralPath $client)) { return $null }
        . $client
    }
    Get-SIInvardiaUpdateStatus -Json $Json
}

function New-SIDiagFinding {
    param([Parameter(Mandatory)][string]$Area, [Parameter(Mandatory)][string]$Text)
    [pscustomobject]@{ Area = $Area; Text = $Text }
}

function Get-SIRunHealthSummary {
    <#
        PURE. Run-health rows (Engine, Phase, At, ExitReason, DurationSec -- the latest per Engine + Phase) as one line per
        engine: LastStart, LastEnd, ExitReason, DurationSec and Problem (empty = healthy). A problem is an END with a
        failed ExitReason, or a START newer than the last END that is older than -RunningGraceHours (it never ended:
        killed, out of memory, or stuck).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [datetime]$NowUtc = [datetime]::UtcNow, [double]$RunningGraceHours = 4)
    $by = [ordered]@{}
    foreach ($r in @($Rows)) {
        $e = [string]$r.Engine; if (-not $e) { continue }
        if (-not $by.Contains($e)) { $by[$e] = [ordered]@{ Start = $null; End = $null; ExitReason = ''; DurationSec = '' } }
        $at = ConvertTo-SIDiagUtc $r.At
        if ([string]$r.Phase -eq 'Start') { $by[$e].Start = $at }
        elseif ([string]$r.Phase -eq 'End') { $by[$e].End = $at; $by[$e].ExitReason = [string]$r.ExitReason; $by[$e].DurationSec = [string]$r.DurationSec }
    }
    foreach ($e in @($by.Keys | Sort-Object)) {
        $h = $by[$e]; $problem = ''
        if ($h.End -and ($script:SIDiagFailedExitReasons -contains $h.ExitReason)) { $problem = "its last run ended with '$($h.ExitReason)'" }
        # #276: a dry run is not a failure, but nothing was published -- said, so a forgotten -WhatIfMode is seen.
        if ($h.End -and $h.ExitReason -eq 'dry-run') { $problem = 'its last run was a dry run -- nothing was published' }
        if ($h.Start -and (-not $h.End -or $h.Start -gt $h.End) -and ($NowUtc - $h.Start).TotalHours -gt $RunningGraceHours) {
            $problem = 'its last run started {0:yyyy-MM-dd HH:mm}Z and never ended (stopped, out of memory, or still hanging)' -f $h.Start
        }
        [pscustomobject]@{ Engine = $e; LastStart = $h.Start; LastEnd = $h.End; ExitReason = $h.ExitReason; DurationSec = $h.DurationSec; Problem = $problem }
    }
}

function Get-SIIdentityPrincipal {
    <# The install's user-assigned identity: by name, else by client id, else the only one in its resource group. #>
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][System.Collections.IDictionary]$Seams, [string]$IdentityName)
    $list = @(& $Seams.Arm 'GET' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities' -f $Target.ResourceGroupId) '2023-01-31' -List:$true $null | Where-Object { $_ })
    $name = if ($IdentityName) { $IdentityName } else { $Target.IdentityName }
    $pick = $null
    if ($name) { $pick = @($list | Where-Object { [string]$_.name -eq $name }) | Select-Object -First 1 }
    if (-not $pick -and $Target.IdentityClientId) { $pick = @($list | Where-Object { [string]$_.properties.clientId -eq $Target.IdentityClientId }) | Select-Object -First 1 }
    if (-not $pick -and -not $name -and $list.Count -eq 1) { $pick = $list[0] }
    if (-not $pick) { return $null }
    [pscustomobject]@{ Name = [string]$pick.name; PrincipalId = [string]$pick.properties.principalId; ClientId = [string]$pick.properties.clientId }
}

function Get-SIPrincipalRoleAssignments {
    <#
        Every role assignment of a principal that this sign-in can see: ARM at the install's subscription (assignments at,
        above and below it -- management groups included) plus Resource Graph (other subscriptions). Each:
        @{ Id; Scope; RoleDefinitionId; Role }. Role names are resolved once per definition.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][System.Collections.IDictionary]$Seams, $Notes)
    $byId = [ordered]@{}
    $filter = [uri]::EscapeDataString(("principalId eq '{0}'" -f $PrincipalId))
    $arm = @(& $Seams.Arm 'GET' ("/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?`$filter={1}" -f $SubscriptionId, $filter) '2022-04-01' -List:$true $null | Where-Object { $_ })
    foreach ($a in $arm) { $byId[([string]$a.id).ToLowerInvariant()] = [pscustomobject]@{ Id = [string]$a.id; Scope = [string]$a.properties.scope; RoleDefinitionId = [string]$a.properties.roleDefinitionId } }
    try {
        $q = "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | where tostring(properties.principalId) =~ '{0}' | project id, scope = tostring(properties.scope), roleDefinitionId = tostring(properties.roleDefinitionId)" -f $PrincipalId
        foreach ($g in @(& $Seams.Graph $q @() | Where-Object { $_ })) {
            $k = ([string]$g.id).ToLowerInvariant()
            if (-not $byId.Contains($k)) { $byId[$k] = [pscustomobject]@{ Id = [string]$g.id; Scope = [string]$g.scope; RoleDefinitionId = [string]$g.roleDefinitionId } }
        }
    } catch { if ($null -ne $Notes) { $Notes.Add(('Resource Graph could not be read, so only this subscription''s view of the role assignments was checked: {0}' -f $_.Exception.Message)) } }
    $names = @{}
    foreach ($a in $byId.Values) {
        $rd = $a.RoleDefinitionId; $key = ($rd -split '/')[-1].ToLowerInvariant()
        if (-not $names.ContainsKey($key)) {
            $n = ''
            try { $d = & $Seams.Arm 'GET' $rd '2022-04-01' -List:$false $null; $n = [string]$d.properties.roleName } catch { $n = '' }
            $names[$key] = $(if ($n) { $n } else { "role $key" })
        }
        $a | Add-Member -NotePropertyName Role -NotePropertyValue $names[$key] -Force
        $a
    }
}

function Invoke-SIInstallCheck {
    <#
        The whole check. Returns @{ Ok; Findings; Notes; Tables; Engines; Dcrs; Identity; Assignments; Target }.
        Findings = what is WRONG (exit 1). Notes = worth knowing, not wrong.
    #>
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Seams,
        [double]$SinceHours = 26,
        [double]$RunningGraceHours = 4,
        [string]$IdentityName,
        [string]$PrincipalId,
        [string[]]$AllowedGrant = @()
    )
    $say = { param($t, $c) try { & $Seams.Print $t $c } catch { } }
    $findings = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    $now = & $Seams.Now
    $res = [ordered]@{ Ok = $false; Findings = $null; Notes = $null; Tables = @(); Engines = @(); Dcrs = @(); Identity = $null; Assignments = @(); LicenceRequest = $null; Updates = $null; Target = $Target }
    foreach ($req in 'SubscriptionId', 'ResourceGroup', 'WorkspaceResourceId') {
        if (-not $Target.$req) { $findings.Add((New-SIDiagFinding -Area 'config' -Text "the config does not say $req")) }
    }
    if ($findings.Count) { $res.Findings = $findings.ToArray(); $res.Notes = $notes.ToArray(); return [pscustomobject]$res }
    $h = [Math]::Max(1, [int][Math]::Ceiling($SinceHours))

    & $say ("== SecurityInsight install: {0} / {1}" -f $Target.SubscriptionId, $Target.ResourceGroup) 'Cyan'

    # ---- 1. data per SI table (Log Analytics data plane) ----
    $wsGuid = ''
    try { $w = & $Seams.Arm 'GET' $Target.WorkspaceResourceId '2022-10-01' -List:$false $null; $wsGuid = [string]$w.properties.customerId }
    catch { $findings.Add((New-SIDiagFinding -Area 'workspace' -Text ("the workspace could not be read: {0}" -f $_.Exception.Message))) }
    & $say ("== rows per SI table in the last {0} h" -f $h) 'Cyan'
    if ($wsGuid) {
        try {
            # (LastSeen, not "last": that is a reserved word in KQL)
            $q = "union withsource=SITable isfuzzy=true SI_* | where TimeGenerated > ago({0}h) | summarize Rows = count(), LastSeen = max(TimeGenerated) by SITable | order by SITable asc" -f $h
            $rows = @((& $Seams.LaQuery $wsGuid $q).Results | Where-Object { $_ })
            $res.Tables = @($rows | ForEach-Object { [pscustomobject]@{ Table = [string]$_.SITable; Rows = [long]$_.Rows; LastSeen = (ConvertTo-SIDiagUtc $_.LastSeen) } })
            foreach ($t in $res.Tables) { & $say ('  {0,-40} {1,10}  last {2:yyyy-MM-dd HH:mm}Z' -f $t.Table, $t.Rows, $t.LastSeen) '' }
            if (-not $res.Tables.Count) { $findings.Add((New-SIDiagFinding -Area 'data' -Text ("no SecurityInsight table received data in the last {0} h" -f $h))) }
        } catch { $findings.Add((New-SIDiagFinding -Area 'data' -Text ("the SI tables could not be queried: {0}" -f $_.Exception.Message))) }

        # ---- 2. run health per engine ----
        & $say '== run health per engine (latest start / end)' 'Cyan'
        try {
            $q = "SI_RunHealth_CL | where TimeGenerated > ago({0}h) | extend ExitReason = tostring(column_ifexists('ExitReason', '')), DurationSec = tostring(column_ifexists('DurationSec', '')) | summarize arg_max(TimeGenerated, ExitReason, DurationSec) by Engine, Phase | project Engine, Phase, At = TimeGenerated, ExitReason, DurationSec | order by Engine asc, Phase asc" -f $h
            $rh = @((& $Seams.LaQuery $wsGuid $q).Results | Where-Object { $_ })
            $res.Engines = @(Get-SIRunHealthSummary -Rows $rh -NowUtc $now -RunningGraceHours $RunningGraceHours)
            foreach ($e in $res.Engines) {
                & $say ('  {0,-28} start {1,-17} end {2,-17} {3,-16} {4}' -f $e.Engine, $(if ($e.LastStart) { $e.LastStart.ToString('yyyy-MM-dd HH:mm') } else { '-' }),
                    $(if ($e.LastEnd) { $e.LastEnd.ToString('yyyy-MM-dd HH:mm') } else { '-' }), $e.ExitReason, $(if ($e.DurationSec) { $e.DurationSec + ' s' } else { '' })) $(if ($e.Problem) { 'Red' } else { '' })
                if ($e.Problem) { $findings.Add((New-SIDiagFinding -Area 'run health' -Text ('{0}: {1}' -f $e.Engine, $e.Problem))) }
            }
            if (-not $res.Engines.Count) { $findings.Add((New-SIDiagFinding -Area 'run health' -Text ("no engine reported a run in the last {0} h" -f $h))) }
        } catch { $findings.Add((New-SIDiagFinding -Area 'run health' -Text ("the run-health table could not be read (no engine has reported yet?): {0}" -f $_.Exception.Message))) }
    }

    # ---- 3. the DCRs in its resource group(s) ----
    & $say ("== data collection rules in {0}" -f $Target.ResourceGroup) 'Cyan'
    $rgIds = @($Target.ResourceGroupId, $Target.DcrResourceGroupId | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    $mine = New-Object System.Collections.Generic.List[object]
    foreach ($rgId in $rgIds) {
        try { foreach ($d in @(& $Seams.Arm 'GET' ($rgId + '/providers/Microsoft.Insights/dataCollectionRules') '2022-06-01' -List:$true $null | Where-Object { $_ })) { $mine.Add($d) } }
        catch { $findings.Add((New-SIDiagFinding -Area 'dcr' -Text ("the data collection rules in {0} could not be listed: {1}" -f $rgId, $_.Exception.Message))) }
    }
    $res.Dcrs = @($mine | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Id = [string]$_.id } } | Sort-Object Name)
    foreach ($d in $res.Dcrs) { & $say ('  ' + $d.Name) '' }
    $missingCfg = @($Target.DcrNames | Where-Object { $n = $_; -not @($res.Dcrs | Where-Object { $_.Name -eq $n }).Count })
    if ($missingCfg.Count) { $notes.Add(('configured but not created yet (an engine creates its rule on its first run): {0}' -f ($missingCfg -join ', '))) }

    # ---- 4. ISOLATION ----
    & $say '== isolation: the install''s identity holds no write role outside its resource group' 'Cyan'
    $pid_ = $PrincipalId
    if (-not $pid_) {
        try {
            $ident = Get-SIIdentityPrincipal -Target $Target -Seams $Seams -IdentityName $IdentityName
            if ($ident) { $res.Identity = $ident; $pid_ = $ident.PrincipalId }
        } catch { $notes.Add(('the identities in the resource group could not be listed: {0}' -f $_.Exception.Message)) }
    } else { $res.Identity = [pscustomobject]@{ Name = ''; PrincipalId = $PrincipalId; ClientId = '' } }
    if (-not $pid_) {
        $findings.Add((New-SIDiagFinding -Area 'isolation' -Text 'the install''s managed identity could not be found, so its access is UNKNOWN (not checked) -- pass -IdentityName or -PrincipalId'))
    } else {
        & $say ('  identity {0} ({1})' -f $res.Identity.Name, $pid_) ''
        try {
            $res.Assignments = @(Get-SIPrincipalRoleAssignments -PrincipalId $pid_ -SubscriptionId $Target.SubscriptionId -Seams $Seams -Notes $notes)
            $doc = @(Get-SIInstallDocumentedWriteGrants -Target $Target) + @($AllowedGrant | Where-Object { $_ -match '@' } | ForEach-Object { $p = $_ -split '@', 2; [pscustomobject]@{ Role = $p[0].Trim(); Scope = $p[1].Trim() } })
            foreach ($a in $res.Assignments) {
                $inside = Test-SIScopeInside -Scope $a.Scope -ResourceGroupId $Target.ResourceGroupId
                $write = $a.Role -match $script:SIDiagWriteRolePattern
                $isDoc = @($doc | Where-Object { $_.Role -eq $a.Role -and $_.Scope.TrimEnd('/') -ieq $a.Scope.TrimEnd('/') }).Count -gt 0
                $tag = if (-not $write) { 'read' } elseif ($inside) { 'inside' } elseif ($isDoc) { 'documented' } else { 'NOT ALLOWED' }
                & $say ('  [{0,-11}] {1,-36} on {2}' -f $tag, $a.Role, $a.Scope) $(if ($tag -eq 'NOT ALLOWED') { 'Red' } else { '' })
                if ($tag -eq 'NOT ALLOWED') { $findings.Add((New-SIDiagFinding -Area 'isolation' -Text ('{0} on {1} -- a write role outside the install''s resource group' -f $a.Role, $a.Scope))) }
            }
        } catch { $findings.Add((New-SIDiagFinding -Area 'isolation' -Text ('the identity''s role assignments could not be read, so its access is UNKNOWN: {0}' -f $_.Exception.Message))) }
    }

    & $say '== isolation: the install''s data collection rule names are unique in the subscription' 'Cyan'
    try {
        $all = @(& $Seams.Arm 'GET' ('/subscriptions/{0}/providers/Microsoft.Insights/dataCollectionRules' -f $Target.SubscriptionId) '2022-06-01' -List:$true $null | Where-Object { $_ })
        $mineIds = @($res.Dcrs | ForEach-Object { $_.Id.ToLowerInvariant() })
        $dups = 0
        foreach ($d in $res.Dcrs) {
            $others = @($all | Where-Object { [string]$_.name -ieq $d.Name -and $mineIds -notcontains ([string]$_.id).ToLowerInvariant() })
            foreach ($o in $others) {
                $dups++
                $findings.Add((New-SIDiagFinding -Area 'isolation' -Text ('data collection rule name {0} is also used by {1} -- an engine that resolves the rule by name can send this install''s data there' -f $d.Name, [string]$o.id)))
            }
        }
        & $say $(if ($dups) { "  $dups duplicate name(s)" } else { '  every name is unique' }) $(if ($dups) { 'Red' } else { '' })
    } catch { $findings.Add((New-SIDiagFinding -Area 'isolation' -Text ('the subscription''s data collection rules could not be listed, so name uniqueness is UNKNOWN: {0}' -f $_.Exception.Message))) }

    # ---- 5. the licence request (#239): requested / pending / approved / rejected, valid-to, the last check ----
    $res.LicenceRequest = $null
    if ($Target.KeyVaultName) {
        & $say '== licence request' 'Cyan'
        try {
            $lr = Get-SIDiagLicenceRequest -Json (& $Seams.LicenceState $Target.KeyVaultName)
            $res.LicenceRequest = $lr
            & $say ('  {0}; last check {1}' -f $lr.Summary, $(if ($lr.LastCheckUtc) { ([datetime]$lr.LastCheckUtc).ToString('yyyy-MM-dd HH:mm') + 'Z' } else { 'never' })) $(if ($lr.Status -eq 'rejected') { 'Red' } elseif ($lr.LastError) { 'Yellow' } else { '' })
            if ($lr.Status -eq 'rejected') { $findings.Add((New-SIDiagFinding -Area 'licence' -Text ('Invardia REJECTED this install''s licence request{0} -- contact Invardia, then run setup/Request-SILicense.ps1 -Force' -f $(if ($lr.Reason) { ": $($lr.Reason)" } else { '' })))) }
            elseif ($lr.LastError) { $notes.Add(('licence request: ' + $lr.LastError)) }
        } catch { $notes.Add(('the licence request state could not be read: {0}' -f $_.Exception.Message)) }
    }

    # ---- 6. updates (#240): the source, the last manifest per kind (version, sequence, ring), the last check, any HOLD ----
    $res.Updates = $null
    if ($Target.KeyVaultName -and $Seams.Contains('UpdateState')) {
        try {
            $json = & $Seams.UpdateState $Target.KeyVaultName
            $us = Get-SIDiagUpdateState -Json $json
            if ($us) {
                & $say '== updates' 'Cyan'
                $res.Updates = $us
                & $say ('  {0}' -f $us.Summary) $(if ($us.Refused -or $us.ClaimResult -eq 'conflict') { 'Red' } elseif (@($us.Holds).Count -or $us.LastError) { 'Yellow' } else { '' })
                foreach ($h in @($us.Holds)) { & $say ('  HOLD {0}' -f $h) 'Yellow'; $notes.Add(('update on hold -- {0}' -f $h)) }
                if ($us.Refused) { $findings.Add((New-SIDiagFinding -Area 'updates' -Text ('an update manifest from Invardia was REFUSED: {0}' -f $us.LastError))) }
                elseif ($us.ClaimResult -eq 'conflict') { $findings.Add((New-SIDiagFinding -Area 'updates' -Text ('the install key could not be claimed: {0}' -f $us.ClaimReason))) }
                elseif ($us.LastError) { $notes.Add(('updates: ' + $us.LastError)) }
            }
        } catch { $notes.Add(('the update state could not be read: {0}' -f $_.Exception.Message)) }
    }

    $res.Findings = $findings.ToArray(); $res.Notes = $notes.ToArray(); $res.Ok = ($findings.Count -eq 0)
    & $say '== summary' 'Cyan'
    foreach ($n in $res.Notes) { & $say ('  note: ' + $n) 'DarkGray' }
    if ($res.Ok) { & $say '  OK -- data arrives, every engine''s last run is healthy, and the install is isolated.' 'Green' }
    else { foreach ($f in $res.Findings) { & $say ('  WRONG [{0}] {1}' -f $f.Area, $f.Text) 'Red' } }
    [pscustomobject]$res
}

# ---------------------------------------------------------------------------------------------------------------------
# Invoke-SIJobsOnce: every Container Apps job once, in schedule order
# ---------------------------------------------------------------------------------------------------------------------
function Get-SICronMinuteOfDay {
    <# PURE. The minute of the day a cron expression fires first (minute hour ...); a field that is not a number counts as 0, an unreadable expression sorts last. #>
    param([AllowNull()][string]$Cron)
    $f = @("$Cron".Trim() -split '\s+')
    if ($f.Count -lt 2) { return [int]::MaxValue }
    $num = { param($x) $m = [regex]::Match("$x", '^\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
    (& $num $f[1]) * 60 + (& $num $f[0])
}

function Get-SIJobRunPlan {
    <#
        PURE. The install's Container Apps jobs as run groups, in schedule order: jobs that start at the same time of day
        form one group (they run in parallel), groups run one after the other. The updater (it changes the install) is
        left out unless -IncludeUpdater; event-triggered jobs are left out (they run when work arrives). Returns
        @{ Groups = @(@{ At; Jobs = @(@{ Name; Id; Cron }) }); Skipped = @(@{ Name; Why }) }.
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), [switch]$IncludeUpdater, [string[]]$Only = @(), [string[]]$Exclude = @())
    $skipped = New-Object System.Collections.Generic.List[object]
    $run = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $name = [string]$j.name
        $trigger = [string]$j.properties.configuration.triggerType
        $cron = ''
        try { $cron = [string]$j.properties.configuration.scheduleTriggerConfig.cronExpression } catch { $cron = '' }
        if (@($Only).Count -and $Only -notcontains $name) { continue }
        if ($Exclude -contains $name) { $skipped.Add([pscustomobject]@{ Name = $name; Why = 'excluded' }); continue }
        if ($name -match '(?i)updater' -and -not $IncludeUpdater) { $skipped.Add([pscustomobject]@{ Name = $name; Why = 'the updater changes the install -- pass -IncludeUpdater to run it' }); continue }
        if ($trigger -eq 'Event') { $skipped.Add([pscustomobject]@{ Name = $name; Why = 'event-triggered: it runs when work arrives' }); continue }
        $run.Add([pscustomobject]@{ Name = $name; Id = [string]$j.id; Cron = $cron; Minute = $(if ($trigger -eq 'Schedule' -and $cron) { Get-SICronMinuteOfDay $cron } else { [int]::MaxValue - 1 }) })
    }
    $groups = @($run | Group-Object Minute | Sort-Object { [int]$_.Name } | ForEach-Object {
        $m = [int]$_.Name
        $at = if ($m -ge [int]::MaxValue - 1) { 'manual' } else { '{0:00}:{1:00}' -f [Math]::Floor($m / 60), ($m % 60) }
        [pscustomobject]@{ At = $at; Jobs = @($_.Group | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Id = $_.Id; Cron = $_.Cron } }) }
    })
    [pscustomobject]@{ Groups = $groups; Skipped = $skipped.ToArray() }
}

function Invoke-SIJobRunOnce {
    <#
        Starts each group's jobs, waits for every execution to finish, then the next group. Returns
        @{ Ok; Runs = @(@{ Job; Execution; Status; DurationMin; Group }) }. Success = every execution 'Succeeded'.
    #>
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Seams,
        [int]$PollSeconds = 30,
        [int]$TimeoutMinutes = 120
    )
    $say = { param($t, $c) try { & $Seams.Print $t $c } catch { } }
    $runs = New-Object System.Collections.Generic.List[object]
    $active = @('Running', 'Processing', 'Unknown', '')
    $gi = 0
    foreach ($g in @($Plan.Groups)) {
        $gi++
        & $say ('== group {0} ({1}): {2}' -f $gi, $g.At, (@($g.Jobs | ForEach-Object Name) -join ', ')) 'Cyan'
        $live = @()
        foreach ($j in @($g.Jobs)) {
            $t0 = & $Seams.Now
            try {
                $r = & $Seams.Arm 'POST' ($j.Id + '/start') $script:SIDiagJobApi -List:$false $null
                $exec = [string]$r.name
                if (-not $exec -and $r.id) { $exec = ([string]$r.id -split '/')[-1] }
                if (-not $exec) { throw 'the start returned no execution' }
                & $say ('  {0:HH:mm:ss}  {1,-34} started {2}' -f $t0, $j.Name, $exec) ''
                $live += [pscustomobject]@{ Job = $j.Name; Id = $j.Id; Execution = $exec; Start = $t0; Status = 'Running'; End = $null; Group = $gi }
            } catch {
                & $say ('  {0:HH:mm:ss}  {1,-34} could not be started: {2}' -f $t0, $j.Name, $_.Exception.Message) 'Red'
                $runs.Add([pscustomobject]@{ Job = $j.Name; Execution = ''; Status = 'NotStarted'; DurationMin = 0; Group = $gi })
            }
        }
        $deadline = (& $Seams.Now).AddMinutes($TimeoutMinutes)
        while (@($live | Where-Object { $active -contains $_.Status }).Count) {
            if ((& $Seams.Now) -ge $deadline) { break }
            & $Seams.Sleep $PollSeconds
            foreach ($x in @($live | Where-Object { $active -contains $_.Status })) {
                try {
                    $e = & $Seams.Arm 'GET' ('{0}/executions/{1}' -f $x.Id, $x.Execution) $script:SIDiagJobApi -List:$false $null
                    $st = [string]$e.properties.status
                    if ($st -and $active -notcontains $st) {
                        $x.Status = $st
                        $x.End = ConvertTo-SIDiagUtc $e.properties.endTime
                        $s0 = ConvertTo-SIDiagUtc $e.properties.startTime; if ($s0) { $x.Start = $s0 }
                        if (-not $x.End) { $x.End = & $Seams.Now }
                        & $say ('  {0:HH:mm:ss}  {1,-34} {2,-10} after {3:N1} min' -f (& $Seams.Now), $x.Job, $st, ($x.End - $x.Start).TotalMinutes) $(if ($st -eq 'Succeeded') { 'Green' } else { 'Red' })
                    }
                } catch { & $say ('  {0,-34} status not readable yet: {1}' -f $x.Job, $_.Exception.Message) 'DarkGray' }
            }
        }
        foreach ($x in $live) {
            if ($active -contains $x.Status) {
                $x.Status = 'TimedOut'; $x.End = & $Seams.Now
                & $say ('  {0,-34} STILL RUNNING after {1} min -- counted as a failure' -f $x.Job, $TimeoutMinutes) 'Red'
            }
            $runs.Add([pscustomobject]@{ Job = $x.Job; Execution = $x.Execution; Status = $x.Status; DurationMin = [Math]::Round(($x.End - $x.Start).TotalMinutes, 1); Group = $x.Group })
        }
    }
    $bad = @($runs | Where-Object { $_.Status -ne 'Succeeded' })
    & $say '== summary' 'Cyan'
    foreach ($r in $runs) { & $say ('  {0,-34} {1,-10} {2,6:N1} min  {3}' -f $r.Job, $r.Status, $r.DurationMin, $r.Execution) $(if ($r.Status -eq 'Succeeded') { '' } else { 'Red' }) }
    & $say $(if ($bad.Count) { "  $($bad.Count) of $($runs.Count) job run(s) did not succeed." } else { "  all $($runs.Count) job run(s) succeeded." }) $(if ($bad.Count) { 'Red' } else { 'Green' })
    [pscustomobject]@{ Ok = ($bad.Count -eq 0 -and $runs.Count -gt 0); Runs = $runs.ToArray() }
}
