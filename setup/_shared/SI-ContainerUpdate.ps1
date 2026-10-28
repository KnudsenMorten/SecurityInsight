#Requires -Version 5.1
<#
    SecurityInsight -- container update DECISIONS (pure; no Azure calls). The orchestrator
    setup/Invoke-SIContainerUpdate.ps1 executes; this file decides, so every decision is testable offline.

    WHY (#107, operator ruling 2026-09-29: "use the same flow as PIM is doing, that is proven and works").
    A container-hosted SecurityInsight bakes its tree into the image (`COPY . /app/`) and no entrypoint
    pulls code, so a synced update reached the sync host's disk and NO job ever ran it. PIM4EntraPS solves
    the same problem through its solution.deploy.json deploy hook: after a sync that changed the solution,
    the sync engine runs the solution's own update script, which builds the image from the pulled tree,
    rolls the hosting to it, verifies, and rolls back on failure. SI now does the same, adapted to
    Container Apps JOBS: jobs have no revisions, so the rollback target is each job's previous image,
    captured before anything changes.
#>

function Resolve-SIContainerUpdateTarget {
    <#
        Where the container hosting lives, or $null when this is not a container install.
        Explicit parameters win, then the customer's own config globals -- the SAME names setup uses
        (SI_Bootstrap_*). There are NO shipped defaults on purpose: a default would be the operator's own
        resource names, and a customer who set nothing would then target the operator's infrastructure
        (PIM BUG-28). Nothing configured = a VM install = nothing to update.
    #>
    param(
        [string]$ResourceGroupName,
        [string]$AcrName,
        [string]$SubscriptionId,
        [hashtable]$Globals = @{}
    )
    $pick = { param($explicit, $name) if (-not [string]::IsNullOrWhiteSpace($explicit)) { return $explicit.Trim() }
              $g = $Globals[$name]; if ($g -and -not [string]::IsNullOrWhiteSpace([string]$g)) { return ([string]$g).Trim() }; return $null }
    $rg  = & $pick $ResourceGroupName 'SI_Bootstrap_ResourceGroupName'
    $acr = & $pick $AcrName 'SI_Bootstrap_AcrName'
    $sub = & $pick $SubscriptionId 'SI_Bootstrap_SubscriptionId'
    if (-not $sub) {
        # The workspace id carries the subscription the solution was installed into.
        $ws = [string]$Globals['SI_WorkspaceResourceId']
        if ($ws -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
    }
    if (-not $rg -and -not $acr) { return $null }
    if (-not $rg -or -not $acr) {
        throw ("Container hosting is only half configured (resource group: '{0}', registry: '{1}'). Set both SI_Bootstrap_ResourceGroupName and SI_Bootstrap_AcrName in config\SecurityInsight.custom.ps1, or neither on a VM install." -f $rg, $acr)
    }
    if (-not $sub) { throw 'Container hosting is configured but no subscription could be resolved. Set SI_Bootstrap_SubscriptionId in config\SecurityInsight.custom.ps1.' }
    return [pscustomobject]@{ ResourceGroupName = $rg; AcrName = $acr; SubscriptionId = $sub }
}

function Resolve-SIBootstrapSubscription {
    <#
        PURE. The ONE subscription container setup works in, and where it came from. The install's own config decides:
        the saved hosting (SI_Bootstrap_SubscriptionId), then SI_AzSubscriptionId, then the workspace id; the signed-in
        Az context only when the config names none. Measured 2026-10-02: setup read the Az PowerShell context while az
        ran against its OWN default -- two different subscriptions in one run.
    #>
    param([hashtable]$Globals = @{}, [string]$ContextSubscriptionId, [string]$Explicit)
    # An explicit -SubscriptionId (the guided install passes its own answer) wins over every global: a value left in the
    # session, or a config file that is not the install's own, never moves it (live 2026-10-06: ring 1's subscription).
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) { return [pscustomobject]@{ SubscriptionId = $Explicit.Trim(); Source = 'the -SubscriptionId parameter' } }
    foreach ($n in 'SI_Bootstrap_SubscriptionId', 'SI_AzSubscriptionId') {
        $v = [string]$Globals[$n]
        if (-not [string]::IsNullOrWhiteSpace($v)) { return [pscustomobject]@{ SubscriptionId = $v.Trim(); Source = $n } }
    }
    $ws = [string]$Globals['SI_WorkspaceResourceId']
    if ($ws -match '/subscriptions/([^/]+)/') { return [pscustomobject]@{ SubscriptionId = $Matches[1]; Source = 'SI_WorkspaceResourceId' } }
    if (-not [string]::IsNullOrWhiteSpace($ContextSubscriptionId)) { return [pscustomobject]@{ SubscriptionId = $ContextSubscriptionId.Trim(); Source = 'the signed-in Azure context' } }
    [pscustomobject]@{ SubscriptionId = $null; Source = $null }
}

function Add-SIAzSubscriptionArg {
    <#
        PURE. The az arguments with an explicit --subscription on every subscription-scoped command -- never az's own
        default. Directory, REST, sign-in and CLI-housekeeping commands take none; a call that names one keeps it.
    #>
    param([string[]]$AzArgs, [string]$SubscriptionId)
    $a = @($AzArgs)
    if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or -not $a.Count) { return $a }
    if ($a[0] -in 'ad', 'rest', 'login', 'logout', 'account', 'version', 'extension', 'config', 'bicep', 'upgrade', 'cloud') { return $a }
    if ($a -contains '--subscription') { return $a }
    $a + @('--subscription', $SubscriptionId)
}

function Get-SIRegistryPullArgs {
    <#
        PURE. How a job pulls its image. Managed identity: AS the identity (`--registry-identity`; AcrPull is in its grant
        plan) -- no password. Otherwise the registry's admin credentials, as before; when admin access is disabled (the
        secure setting) a clear refusal instead of the null-index crash measured 2026-10-02.
    #>
    param([string]$Mode, [string]$IdentityResourceId, $AdminCredential, [string]$AcrName)
    if ($Mode -eq 'ManagedIdentity') {
        if ([string]::IsNullOrWhiteSpace($IdentityResourceId)) { throw 'managed-identity mode without an identity -- the jobs could not pull their image.' }
        return @('--registry-identity', $IdentityResourceId)
    }
    $user = if ($AdminCredential) { [string]$AdminCredential.username }
    $pass = if ($AdminCredential -and $AdminCredential.passwords) { [string]@($AdminCredential.passwords)[0].value }
    if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pass)) {
        throw ("Registry '{0}' gives no admin credentials (admin access is disabled -- the secure setting). Run with -UseManagedIdentity so the jobs pull as their identity, or enable admin access on the registry." -f $AcrName)
    }
    @('--registry-username', $user, '--registry-password', $pass)
}

function Get-SIContainerContentHash {
    <#
        A stable hash of what goes into the image, so an unchanged tree never rebuilds. Relative path +
        SHA-256 of every file, sorted ordinally; folders that never reach an image (run output, local
        state, tests, docs, the web app) are left out. Same content -> same hash on any host.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $skip = @('logs', 'output', 'staging', 'internal', 'tests', 'docs', 'analyzer-web', '.git', 'demo')
    # BUILD OUTPUT at any depth is never content: no tracked file lives in a bin\ / obj\ / node_modules\ folder, so a
    # clean tree (a release archive, a sync) hashes exactly as before. Measured 2026-10-07 on the test VM: the gate's
    # `dotnet build` of pro-management\ (alongside Pester) left thousands of build files here, and every one of the ten
    # end-to-end runs of SIv3-ContainerUpdate hashed them all on PowerShell 5.1 -- the batch passed its 1,200 s timeout.
    $buildDirs = @('bin', 'obj', 'node_modules')
    $root = (Resolve-Path -LiteralPath $SolutionRoot).Path.TrimEnd('\', '/')
    $lines = New-Object System.Collections.Generic.List[string]
    # a walk that never ENTERS a skipped folder (Get-ChildItem -Recurse listed tests\, docs\ and every build folder first,
    # then dropped them); hidden files count as before (-Force)
    $files = New-Object System.Collections.Generic.List[string]
    $dirs = New-Object System.Collections.Generic.Stack[string]
    $dirs.Push($root)
    while ($dirs.Count) {
        $d = $dirs.Pop()
        try { foreach ($x in [IO.Directory]::GetFiles($d)) { $files.Add($x) } } catch { }
        $subs = @(); try { $subs = [IO.Directory]::GetDirectories($d) } catch { }
        foreach ($s in $subs) {
            $n = [IO.Path]::GetFileName($s).ToLowerInvariant()
            if ($d -eq $root -and $skip -contains $n) { continue }
            if ($buildDirs -contains $n) { continue }
            # a junction / symbolic link is not followed (a shipped tree has none)
            try { if (([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint)) { continue } } catch { continue }
            $dirs.Push($s)
        }
    }
    # one SHA-256 for every file (Get-FileHash per file costs a cmdlet call each on 5.1); the same upper-case hex
    $fileSha = [System.Security.Cryptography.SHA256]::Create()
    try {
    foreach ($full in $files) {
        $rel = $full.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
        if ($skip -contains ($rel -split '/')[0].ToLowerInvariant()) { continue }
        if ($rel -like '*.custom.*' -and $rel -notlike '*.custom.sample.*') { continue }   # customer files never ship in an image
        # ...nor do the customer files .dockerignore keeps out by name (they reach the jobs from storage): a changed CMDB.csv
        # or custom query file must not rebuild an image that does not contain it.
        if ($rel -match '(?i)^asset-profiling-providers/[^/]+/CMDB\.csv$|(^|/)RiskAnalysis_Queries_Custom\.yaml$|\.exclude\.json$') { continue }
        # #178: the VM sync never carries launcher.community-* (its manifest excludes them) while a release archive
        # does, so the VM hook and the managed updater computed DIFFERENT tags for the same release -- and each
        # rebuilt and re-rolled every night. No container runs a community launcher; they do not decide the image.
        if ((Split-Path -Leaf $rel) -like 'launcher.community-*') { continue }
        $fs = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $h = ([BitConverter]::ToString($fileSha.ComputeHash($fs)) -replace '-', '') } finally { $fs.Dispose() }
        $lines.Add(('{0}|{1}' -f $rel, $h))
    }
    } finally { $fileSha.Dispose() }
    $arr = $lines.ToArray(); [Array]::Sort($arr, [StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($arr -join "`n"))) } finally { $sha.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Get-SIContainerImageTag {
    <# v<VERSION>-<first 12 of the content hash>: readable, and unique per content. #>
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$ContentHash)
    $v = ($Version.Trim() -replace '[^0-9A-Za-z._-]', '-')
    return ('v{0}-{1}' -f $v, $ContentHash.Substring(0, 12))
}

function Get-SIContainerUpdatePlan {
    <#
        Which jobs to point at the new image. A job is SecurityInsight's when its image is this registry's
        si-orchestrator repository -- discovered, not recomputed from naming rules, so KEDA producer/worker
        pairs and renamed jobs are all found. Returns one entry per SI job with the action:
          'update'  -> image differs from the target
          'current' -> already on the target (idempotent re-run)
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Jobs,      # @{ Name; Image }
        [Parameter(Mandatory)][string]$LoginServer,
        [Parameter(Mandatory)][string]$TargetImage
    )
    $repo = ('{0}/si-orchestrator' -f $LoginServer).ToLowerInvariant()
    foreach ($j in $Jobs) {
        $img = ([string]$j.Image).ToLowerInvariant()
        if (-not ($img.StartsWith($repo + ':') -or $img.StartsWith($repo + '@'))) { continue }
        [pscustomobject]@{
            Name          = [string]$j.Name
            PreviousImage = [string]$j.Image
            Action        = $(if ($img -eq $TargetImage.ToLowerInvariant()) { 'current' } else { 'update' })
        }
    }
}

function Get-SIContainerRollbackPlan {
    <#
        After a failed update: every job that was changed goes back to the image it had before -- but ONLY while it still
        runs the image THIS update set (-NewImage, with -Current = name -> image read back now). A job someone else moved in
        the meantime is left where it is (Action 'skip'). Found live 2026-10-05 (#350): an updater run collided with a
        manual deploy ("an active provisioning operation in progress"), and its rollback put seven jobs back on the image
        from BEFORE both -- over the manual deploy's newer one. Without -Current every changed job is restored, as before.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Updated,   # plan entries that were updated
          [string]$NewImage, [hashtable]$Current)
    foreach ($u in $Updated) {
        $now = if ($Current -and $Current.ContainsKey($u.Name)) { [string]$Current[$u.Name] } else { $null }
        if ($NewImage -and $null -ne $now -and $now -ne $NewImage) {
            [pscustomobject]@{ Name = $u.Name; Image = $u.PreviousImage; Action = 'skip'; Now = $now }
        } else { [pscustomobject]@{ Name = $u.Name; Image = $u.PreviousImage; Action = 'restore'; Now = $now } }
    }
}

# ---- where the containers live, SAVED so every later update can find them (#166) ----------------------
# Resolve-SIContainerUpdateTarget reads SI_Bootstrap_* from config\SecurityInsight.custom.ps1. Until
# 2026-09-30 nothing ever WROTE them: the container setup set them in memory for its own run and the
# config had been written before that step anyway -- so the update hook found "no container hosting",
# exited 0, and the jobs stayed on the old image with no error. The container setup now saves them here,
# as one marked block that a re-run REPLACES (never duplicates), and everything outside it is untouched.
$script:SIContainerBlockBegin = '# >>> SecurityInsight container hosting -- written by setup; a re-run replaces this block >>>'
$script:SIContainerBlockEnd   = '# <<< SecurityInsight container hosting <<<'

function ConvertTo-SIConfigLiteral {
    # Same rule as the config wizard's writer: inside a single-quoted literal the only special characters
    # are the quote characters (ASCII + four Unicode quotes); doubling each makes it literal.
    param([AllowNull()][object]$Value)
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    foreach ($q in @([char]0x27, [char]0x2018, [char]0x2019, [char]0x201A, [char]0x201B)) {
        $s = $s.Replace([string]$q, [string]$q + [string]$q)
    }
    "'" + $s + "'"
}

function Get-SIContainerHostingBlock {
    <# PURE. The text of the block for these values (only the ones given). #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$AcrName,
        [string]$EnvName,
        [string]$Location,
        [string]$UpdaterJob,
        [string]$ManagedIdentityName
    )
    $lines = @($script:SIContainerBlockBegin)
    $pairs = [ordered]@{
        SI_Bootstrap_SubscriptionId    = $SubscriptionId
        SI_Bootstrap_ResourceGroupName = $ResourceGroupName
        SI_Bootstrap_AcrName           = $AcrName
        SI_Bootstrap_EnvName           = $EnvName
        SI_Bootstrap_Location          = $Location
        SI_Bootstrap_UpdaterJob        = $UpdaterJob
        SI_Bootstrap_ManagedIdentityName = $ManagedIdentityName
    }
    foreach ($k in $pairs.Keys) {
        if ([string]::IsNullOrWhiteSpace([string]$pairs[$k])) { continue }
        $lines += ('$global:{0} = {1}' -f $k.PadRight(30), (ConvertTo-SIConfigLiteral ([string]$pairs[$k]).Trim()))
    }
    $lines += $script:SIContainerBlockEnd
    $lines -join "`r`n"
}

function Get-SIContainerHostingValue {
    <# PURE. One value from the saved block (a single-quoted literal, quotes doubled), or '' when absent. #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [Parameter(Mandatory)][string]$Name)
    if (-not $Text) { return '' }
    $m = [regex]::Match($Text, '(?m)^[ \t]*\$global:' + [regex]::Escape($Name) + '[ \t]*=[ \t]*''((?:[^'']|'''')*)''')
    if (-not $m.Success) { return '' }
    $m.Groups[1].Value.Replace("''", "'")
}

function Get-SIUpdaterManagedJob {
    <#
        PURE. The updater job that owns this install's rollout, or $null. Set by Upgrade-SIToPro.ps1: from then on
        the job rolls the containers to what the customer's ring approves, and a hand roll from a git pull would
        put them on a version the ring has not approved (PIM: Upgrade-PimToPro, "do NOT keep running
        Update-PimCommunity.ps1").
    #>
    param([hashtable]$Globals = @{})
    $j = [string]$Globals['SI_Bootstrap_UpdaterJob']
    if ([string]::IsNullOrWhiteSpace($j)) { return $null }
    $j.Trim()
}

function Get-SIContainerUpdateGuidance {
    <# PURE. What container setup tells the customer about updates: the Community command, or the updater job that owns it. #>
    param([string]$UpdaterJob)
    if (-not [string]::IsNullOrWhiteSpace($UpdaterJob)) {
        return @(("Updates: the updater job '{0}' (SecurityInsight Pro) rolls these containers to the version your update ring approves -- nothing to run." -f $UpdaterJob.Trim()))
    }
    @(
        'Updates: run .\Update-SecurityInsight.ps1 -Apply when you want the latest release -- it pulls it and rebuilds + rolls these containers (verify, roll back on failure).',
        'With SecurityInsight Pro: .\setup\Upgrade-SIToPro.ps1 (from the Pro package) installs the updater job, which keeps the containers on your update ring by itself -- updates come from Invardia.'
    )
}

function Get-SIProUpgradePlan {
    <#
        PURE. What Upgrade-SIToPro.ps1 passes to Install-SIUpdaterJob.ps1: the hosting this install SAVED (#166) and its
        identity -- the job's managed identity (-UseManagedIdentity), or the SPN and the Key Vault secret name of its
        certificate. Updates come from Invardia (SI's own update feed is retired, 2026-10-06), so no feed link is asked for.
        Explicit values win. Returns @{ Args; Missing } -- nothing is guessed: a missing value is named so the customer can
        pass it.
    #>
    param(
        [hashtable]$Globals = @{},
        [string]$CertSecretName,
        [string]$KeyVaultName,
        [string]$EnvName,
        [switch]$UseManagedIdentity
    )
    $pick = { param($explicit, [string[]]$names)
        if (-not [string]::IsNullOrWhiteSpace($explicit)) { return $explicit.Trim() }
        foreach ($n in $names) { $g = [string]$Globals[$n]; if (-not [string]::IsNullOrWhiteSpace($g)) { return $g.Trim() } }
        '' }
    $sub = & $pick '' @('SI_Bootstrap_SubscriptionId')
    if (-not $sub -and ([string]$Globals['SI_WorkspaceResourceId']) -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
    $a = [ordered]@{
        SubscriptionId      = $sub
        ResourceGroupName   = & $pick '' @('SI_Bootstrap_ResourceGroupName')
        AcrName             = & $pick '' @('SI_Bootstrap_AcrName')
        EnvName             = & $pick $EnvName @('SI_Bootstrap_EnvName')
        KeyVaultName        = & $pick $KeyVaultName @('SI_KeyVaultName', 'SpnKeyVaultName')
    }
    if (-not $UseManagedIdentity) {
        $a['CertSecretName'] = & $pick $CertSecretName @()
        $a['SpnClientId']    = & $pick '' @('SI_SPN_AppId')
    }
    $a['TenantId'] = & $pick '' @('SI_SPN_TenantId')
    $missing = @($a.Keys | Where-Object { -not $a[$_] })
    [pscustomobject]@{ Args = $a; Missing = $missing }
}

function Merge-SIContainerHostingBlock {
    <#
      PURE. Returns the config text with the block replaced, or appended when absent. Everything outside
      the markers is returned byte-for-byte. Two or more blocks (a hand-copied one) are collapsed into one.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [Parameter(Mandatory)][string]$Block)
    $t = if ($null -eq $Text) { '' } else { $Text }
    $pattern = '(?ms)^[ \t]*' + [regex]::Escape($script:SIContainerBlockBegin) + '.*?' + [regex]::Escape($script:SIContainerBlockEnd) + '[ \t]*(\r?\n)?'
    $found = [regex]::Matches($t, $pattern)
    if ($found.Count -eq 0) {
        $sep = if ($t.Length -eq 0 -or $t.EndsWith("`n")) { '' } else { "`r`n" }
        return $t + $sep + $Block + "`r`n"
    }
    # A hashtable, not a bool: an assignment inside the evaluator would only set a local copy per call,
    # and every match would get the block.
    $state = @{ First = $true; Block = $Block }
    return [regex]::Replace($t, $pattern, {
        param($m)
        if ($state.First) { $state.First = $false; return $state.Block + "`r`n" }
        return ''
    }.GetNewClosure())
}

function Save-SIContainerHostingConfig {
    <#
      Writes the block into the customer's config file. Idempotent: identical content is not rewritten.
      A changed file is backed up to *.bak.<timestamp> first, and written UTF-8 WITH a BOM -- Windows
      PowerShell 5.1 reads a BOM-less file in the ANSI code page. Returns @{ Path; Changed; Backup }.
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$AcrName,
        [string]$EnvName,
        [string]$Location,
        # Set by Upgrade-SIToPro.ps1 only. When not passed, the value already in the block is KEPT: a re-run of container
        # setup must never quietly hand a Pro install, updated by its updater job, back to the Community update.
        [string]$UpdaterJob,
        # Set by the container setup, which picks the engine jobs' identity name. When not passed, the value already
        # in the block is KEPT, so a later Bootstrap-ContainerAppJob.ps1 run finds the same identity.
        [string]$ManagedIdentityName
    )
    $old = ''
    if (Test-Path -LiteralPath $ConfigPath) { $old = [IO.File]::ReadAllText($ConfigPath) }   # honours a BOM
    if (-not $PSBoundParameters.ContainsKey('UpdaterJob')) { $UpdaterJob = Get-SIContainerHostingValue -Text $old -Name 'SI_Bootstrap_UpdaterJob' }
    if (-not $PSBoundParameters.ContainsKey('ManagedIdentityName')) {
        # Only from inside the block: a value elsewhere in the file stays where the customer put it.
        $blk = [regex]::Match($old, '(?ms)' + [regex]::Escape($script:SIContainerBlockBegin) + '.*?' + [regex]::Escape($script:SIContainerBlockEnd))
        $ManagedIdentityName = if ($blk.Success) { Get-SIContainerHostingValue -Text $blk.Value -Name 'SI_Bootstrap_ManagedIdentityName' } else { '' }
    }
    $block = Get-SIContainerHostingBlock -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AcrName $AcrName -EnvName $EnvName -Location $Location -UpdaterJob $UpdaterJob -ManagedIdentityName $ManagedIdentityName
    $new = Merge-SIContainerHostingBlock -Text $old -Block $block
    if ($new -ceq $old) { return [pscustomobject]@{ Path = $ConfigPath; Changed = $false; Backup = $null } }
    $backup = $null
    if (Test-Path -LiteralPath $ConfigPath) {
        $backup = '{0}.bak.{1:yyyyMMdd-HHmmss}' -f $ConfigPath, (Get-Date)
        Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force
    } else {
        $dir = Split-Path -Parent $ConfigPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    }
    [IO.File]::WriteAllText($ConfigPath, $new, [Text.UTF8Encoding]::new($true))
    [pscustomobject]@{ Path = $ConfigPath; Changed = $true; Backup = $backup }
}
