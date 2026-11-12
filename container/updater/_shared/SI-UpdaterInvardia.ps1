#Requires -Version 5.1
<#
    caj-si-updater -- UPDATES FROM INVARDIA (#240): THE ONE UPDATE CLIENT OF BOTH EDITIONS (framework PRO-COMMUNITY-SAME,
    owner 2026-11-11: "it must be same pro community"). The client is engine/_shared/SI-InvardiaUpdate.ps1 (carried by the
    image under /si); this file wires it to the updater's REST sign-in (#521) and to the build / roll / verify and template
    gate. Pro and Community installs run every step below the same way; ONLY the manifest address and its credential differ
    (Resolve-SIUpdaterUpdateRoute): an install with a licence asks Invardia's install route with its install key; a Community
    install without one asks Invardia's anonymous Community route for its ring (_shared/SI-UpdaterCommunity.ps1) and takes the
    public release zip (the package source). The template channel is a licensed feature: asked on the install route only.

    One run:
      1. the install key: in the install's Key Vault (SI-Invardia-InstallKey), else CLAIMED from Invardia with the licence
         and the tenant of the SPN's own token (a 409 is reported and never claimed again in a loop). CLAIM AGAIN, ONCE:
         after Invardia reset the install's key, an Admin asks for one more claim (Settings > Updates in the web app writes
         cfg.InstallState 'InstallKeyClaimAgain'; or SI_UPDATER_CLAIM_AGAIN=1 on ONE execution of the job). The run takes
         the request away first, then claims once -- claimed, or held again on another 409; never a loop;
      2. Pro: the TEMPLATES manifest -- is a template pack released for this install's ring at all (then templates follow
         that channel, and a code roll does not republish the release's own templates);
      3. the CODE manifest (skipped when the customer blocks 'engine-image'): verified, sequence checked, HOLD on a manual
         step; a version other than the one the jobs run -> download, size + SHA-256, the archive's shape and VERSION,
         extract, Invoke-SIUpdaterRoll (template gate, build, roll, verify, restore on failure);
      4. Pro: a newer template pack -> download, verify, then the template-pack gate with the code the jobs now run;
      5. the state (source, last manifest per kind, applied sequence, holds, last check) into the Key Vault
         (SI-Update-State) and, on Pro, cfg.InstallState 'UpdateState' for the web app and the health check.

    THE RING (framework UPDATE-1.7, operator 2026-10-06: "Solution (si, pim) decides WHAT version and WHICH Ring to release
    in updates, Invardia relays only"): every pull carries THIS environment's own ring -- SI_UPDATER_RING on the job, else
    the ring recorded for the install (cfg.InstallState 'Ring': Set-SIInstallRing.ps1 / 'Update ring' on the Settings page /
    the guided install), else the admin's 'Update ring' setting. The signed manifest must name that ring. No ring known = NO
    pull on the install route (the run says why and ends); a Community install that never recorded one takes ring 3 (broad).
    Rings 0-3 for both editions.

    Configuration (environment on the updater job): SI_UPDATER_KEY_VAULT (required), [SI_UPDATER_RING = 0..3],
    [SI_UPDATER_INVARDIA_BASE_URL],
    [SI_UPDATER_ACCEPT_MANUAL_STEP = 'code:<sequence>,templates:<sequence>' -- releases a manual-step HOLD for exactly that
    sequence], [SI_UPDATER_CLAIM_AGAIN = 1 -- set on ONE execution only (an execution started with it): claim the
    install key once more after Invardia reset it], plus the template-gate settings the feed path uses. The updater SPN needs Key Vault Secrets Officer there.
#>

function Find-SIUpdaterInvardiaRoot {
    <# The SecurityInsight code the updater image carries (/si), or -- from a checkout -- this solution's root. #>
    param([string[]]$Candidates)
    if (-not $Candidates) { $Candidates = @('/si', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..')) }
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath ([IO.Path]::Combine($c, 'engine', '_shared', 'SI-InvardiaUpdate.ps1')))) { return [IO.Path]::GetFullPath($c) }
    }
    $null
}

function ConvertFrom-SIUpdaterManualStepAccept {
    <# PURE. 'code:17,templates:4' -> @{ code = 17; templates = 4 }; a kind not named = -1 (nothing accepted). 'community:<n>'
       (the form a Community install's earlier updater took) is the code kind. #>
    param([AllowEmptyString()][string]$Text)
    $h = @{ code = [long]-1; templates = [long]-1 }
    foreach ($p in @("$Text" -split '[,;\s]+' | Where-Object { $_ })) {
        if ($p -match '^(code|templates|community):(\d{1,18})$') { $h[$(if ($Matches[1] -eq 'community') { 'code' } else { $Matches[1] })] = [long]$Matches[2] }
    }
    $h
}

# the roll steps (pre-roll, post-roll, self-retry, the state row, the running release)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-UpdaterRollSteps.ps1'))
# the Community manifest address and package of the one client (PRO-COMMUNITY-SAME)
. ([IO.Path]::Combine($PSScriptRoot, 'SI-UpdaterCommunity.ps1'))
# the ONE opt-in rule (framework PRO-COMMUNITY-SAME): the code the image carries (/si), else this checkout's
foreach ($__siConn in @('/si/engine/_shared/SI-InvardiaConnect.ps1', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'engine', '_shared', 'SI-InvardiaConnect.ps1'))) { if (-not (Get-Command -Name Test-SIInvardiaConnect -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $__siConn)) { . $__siConn } }

function Resolve-SIUpdaterUpdateRoute {
    <#
        PURE. Which MANIFEST ADDRESS this install asks -- the only thing that differs between the editions (framework
        PRO-COMMUNITY-SAME). Returns @{ Route ('invardia' | 'community'); Reason }:
          * a licence is installed (SI-License in the install's Key Vault)  -> 'invardia': the install route, with the install key;
          * no licence, and the install IS the Community edition -- the resource group's 'edition' tag (-Edition, what the
            install recorded), else the job's SI_UPDATER_SOURCE = community (-Source, an install made before the tag)
                                                                            -> 'community': Invardia's anonymous Community route;
          * otherwise (a Pro install whose licence is not there yet)        -> 'invardia': it waits for its licence (INSTALL-1),
            never takes the Community package.
        The step set follows the licence, never which files the image carries.
    #>
    param([bool]$HasLicence, [AllowEmptyString()][string]$Edition = '', [AllowEmptyString()][string]$Source = '')
    $ed = "$Edition".Trim().ToLowerInvariant(); $src = "$Source".Trim().ToLowerInvariant()
    if ($HasLicence) { return [pscustomobject]@{ Route = 'invardia'; Reason = 'a licence is installed: Invardia''s install route, with the install key' } }
    if ($ed -eq 'community') { return [pscustomobject]@{ Route = 'community'; Reason = 'the Community edition (the resource group''s edition tag), no licence: Invardia''s Community route for this ring' } }
    if (-not $ed -and $src -eq 'community') { return [pscustomobject]@{ Route = 'community'; Reason = 'the Community edition (SI_UPDATER_SOURCE on the updater job), no licence: Invardia''s Community route for this ring' } }
    [pscustomobject]@{ Route = 'invardia'; Reason = $(if ($ed -eq 'pro') { 'SecurityInsight Pro (the resource group''s edition tag): Invardia''s install route -- it waits for its licence' } else { 'Invardia''s install route' }) }
}

function Test-SIUpdaterInvardiaConnected {
    <# Is this install connected to Invardia (framework PRO-COMMUNITY-SAME, opt-in)? The install route = yes (Pro, as before);
       the Community route = only when SI_Invardia_Connect says yes (the job's SI_CFG_SI_Invardia_Connect / SI_INVARDIA_CONNECT,
       else the configuration's global). One rule: engine\_shared\SI-InvardiaConnect.ps1. Never throws. #>
    param([Parameter(Mandatory)][string]$Route, [scriptblock]$Get)
    try {
        if (-not (Get-Command -Name Test-SIInvardiaConnect -ErrorAction SilentlyContinue)) {
            foreach ($c in @('/si/engine/_shared/SI-InvardiaConnect.ps1', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'engine', '_shared', 'SI-InvardiaConnect.ps1'))) { if (Test-Path -LiteralPath $c) { . $c; break } }
        }
        $ev = ''
        if ($Get) { foreach ($n in 'SI_CFG_SI_Invardia_Connect', 'SI_INVARDIA_CONNECT') { $v = [string](& $Get $n); if ($v.Trim()) { $ev = $v; break } } }
        return [bool](Test-SIInvardiaConnect -Edition $(if ($Route -eq 'community') { 'community' } else { 'pro' }) -EnvValue $ev)
    } catch { return ($Route -ne 'community') }
}

function Get-SIUpdaterInstallEdition {
    <# The install's recorded edition: the resource group's 'edition' tag ('community' / 'pro', on a SecurityInsight group:
       tag product si or purpose securityinsight), '' when none or it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    try {
        $g = Invoke-SIUpdaterArm -Path ('/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup) -ApiVersion '2021-04-01' -AllowNotFound
        if (-not $g -or -not $g.PSObject.Properties['tags'] -or -not $g.tags) { return '' }
        $t = $g.tags
        $tv = { param($n) $p = @($t.PSObject.Properties | Where-Object { $_.Name -ieq $n }) | Select-Object -First 1; if ($p) { "$($p.Value)".Trim().ToLowerInvariant() } else { '' } }
        $ed = & $tv 'edition'
        if ((& $tv 'product') -eq 'si' -or (& $tv 'purpose') -eq 'securityinsight') { if ($ed -in 'community', 'pro') { return $ed } }
        ''
    } catch { '' }
}

function Get-SIUpdaterInvardiaCodeDecision {
    <#
        PURE. A verified CODE manifest result against what the jobs run. Returns @{ Act; Applied; Hold; Reason }:
          * update / current naming the version the jobs run       -> nothing to roll; the sequence counts as applied;
          * update naming another version:
              - minFromVersion above the running version            -> HOLD (an intermediate release is needed first);
              - LOWER than the running version and nothing applied from Invardia yet -> HOLD (forward-only until the first
                Invardia release is applied; after that a lower version with a HIGHER sequence is the vendor's deliberate rollback);
              - LOWER than the running version while the jobs run a release of a pre-release WAVE (-AppliedWave, CR3 #657) and
                the manifest is the ring's own (no wave)                -> keep it: an install is never moved back by the end
                of a wave; it follows its ring again once the ring reaches its version;
              - otherwise                                           -> roll it.
    #>
    param([Parameter(Mandatory)]$Result, [AllowEmptyString()][string]$Deployed, [long]$AppliedSequence = -1, [AllowEmptyString()][string]$AppliedWave = '')
    $no = { param($why, $applied = $false, $hold = '') [pscustomobject]@{ Act = $false; Applied = $applied; Hold = $hold; Reason = $why } }
    if ($Result.Action -notin @('update', 'current')) { return (& $no $Result.Reason) }
    $v = [string]$Result.Version
    if ($Deployed -and (Compare-SIInvardiaVersion $v $Deployed) -eq 0) { return (& $no ("the jobs run {0} already (sequence {1})" -f $v, $Result.Sequence) $true) }
    if ($Result.Action -eq 'current') { return (& $no $Result.Reason) }
    $min = if ($Result.Manifest.PSObject.Properties['minFromVersion']) { "$($Result.Manifest.minFromVersion)".Trim() } else { '' }
    if ($min -and $Deployed -and (Compare-SIInvardiaVersion $Deployed $min) -lt 0) {
        $h = "HELD: {0} needs at least {1} installed first; the jobs run {2}" -f $v, $min, $Deployed
        return (& $no $h $false $h)
    }
    if ($Deployed -and (Compare-SIInvardiaVersion $v $Deployed) -lt 0 -and $AppliedSequence -lt 0) {
        $h = "HELD: Invardia names {0}, older than the {1} the jobs run, and no Invardia release has been applied here yet -- the updater never moves the jobs backward on a first manifest" -f $v, $Deployed
        return (& $no $h $false $h)
    }
    $mWave = if ($Result.PSObject.Properties['Wave']) { "$($Result.Wave)".Trim() } else { '' }
    if ("$AppliedWave".Trim() -and -not $mWave -and $Deployed -and (Compare-SIInvardiaVersion $v $Deployed) -lt 0) {
        return (& $no ("this install keeps {0} from the pre-release wave '{1}': ring {2} names {3}, and an install is never moved back -- it follows its ring again once the ring reaches {0}" -f $Deployed, "$AppliedWave".Trim(), $Result.Ring, $v))
    }
    [pscustomobject]@{ Act = $true; Applied = $false; Hold = ''; Reason = $(if ($Deployed -and (Compare-SIInvardiaVersion $v $Deployed) -lt 0) { "the vendor rolls back to $v (sequence $($Result.Sequence))" } else { $Result.Reason }) }
}

function Resolve-SIUpdaterInvardiaRing {
    <#
        UPDATE-1.7: the ring THIS environment pulls for -- SecurityInsight decides it, Invardia only relays. Returns
        @{ Ring (0..3 or $null); Source; Reason }:
          1. SI_UPDATER_RING on the updater job (-EnvRing) -- also recorded as the install's ring (cfg.InstallState 'Ring');
          2. else the ring recorded for the install (cfg.InstallState 'Ring'; the admin's 'Update ring' setting is recorded
             there first, a ring read from the resource-group name never replaces a recorded one);
          3. else the admin's 'Update ring' setting (SI_UpdateRing in the database);
          4. else -DefaultRing (0-3; the Community route's 3, for an install that never recorded one);
          5. else none -> no pull is made, and Reason says why in plain words.
        Rings 0-3 for both editions (PRO-COMMUNITY-SAME). An SI_UPDATER_RING that is not 0-3 is NOT replaced by the recorded
        ring -- a wrong setting is reported, not guessed. -Channel: the route recorded with the ring. Never throws.
    #>
    param([AllowEmptyString()][string]$EnvRing, $Store, [string]$ResourceGroup = '', [int]$DefaultRing = -1, [string]$Channel = 'invardia')
    $out = { param($r, $src, $why) [pscustomobject]@{ Ring = $r; Source = $src; Reason = $why } }
    $envText = "$EnvRing".Trim()
    $envN = ConvertTo-SIInvardiaPullRing $envText
    if ($envText -and $envN -lt 0) { return (& $out $null 'SI_UPDATER_RING' (Get-SIInvardiaNoRingReason -Ring $envText)) }
    if ($Store -and (Get-Command -Name Invoke-SIRecordInstallRing -ErrorAction SilentlyContinue)) {
        try {
            $rec = Invoke-SIRecordInstallRing -Store $Store -Ring $(if ($envN -ge 0) { $envN } else { $null }) -RingSource updater -ResourceGroupName $ResourceGroup -Channel $Channel -SetBy 'caj-si-updater'
            if ($rec.Written -or $rec.Reason -like 'the update ring could not be recorded*') { Write-UpdLog ("update ring: {0}" -f $rec.Reason) }
        } catch { Write-UpdLog ("update ring: could not be recorded ({0})" -f $_.Exception.Message) }
    }
    if ($envN -ge 0) { return (& $out $envN 'SI_UPDATER_RING' ("ring {0} (SI_UPDATER_RING on the updater job)" -f $envN)) }
    if ($Store -and (Get-Command -Name Read-SIInstallRing -ErrorAction SilentlyContinue)) {
        $row = $null; try { $row = Read-SIInstallRing -Store $Store } catch { $row = $null }
        if ($row -and $null -ne $row.Ring) { return (& $out ([int]$row.Ring) 'install' ("ring {0} (recorded for this install{1})" -f $row.Ring, $(if ($row.SetBy) { " by $($row.SetBy)" } else { '' }))) }
    }
    if ($Store -and (Get-Command -Name Read-SIUpdateRingSetting -ErrorAction SilentlyContinue)) {
        $set = $null; try { $set = Read-SIUpdateRingSetting -Store $Store } catch { $set = $null }
        if ($null -ne $set -and [int]$set -ge 0 -and [int]$set -le 3) { return (& $out ([int]$set) 'setting' ("ring {0} (the Update ring setting)" -f $set)) }
    }
    if ($DefaultRing -ge 0 -and $DefaultRing -le 3) { return (& $out $DefaultRing 'default' ("ring {0} (none recorded for this install -- the default ring of the Community route)" -f $DefaultRing)) }
    & $out $null '' (Get-SIInvardiaNoRingReason -Ring $null)
}

function Get-SIUpdaterClaimAgainTakeSql {
    <# The web app's one-shot request (Settings > Updates, 'claim it again'): TAKEN in one statement -- read and removed together. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Taken, CAST(NULL AS nvarchar(256)) AS RequestedBy, CAST(NULL AS datetime2(0)) AS RequestedAt;
ELSE
BEGIN
    DECLARE @t TABLE (UpdatedBy NVARCHAR(256) NULL, UpdatedAt DATETIME2(0) NULL);
    DELETE FROM cfg.InstallState OUTPUT deleted.UpdatedBy, deleted.UpdatedAt INTO @t WHERE Name = N'InstallKeyClaimAgain';
    SELECT CAST(COUNT(*) AS int) AS Taken, MAX(UpdatedBy) AS RequestedBy, MAX(UpdatedAt) AS RequestedAt FROM @t;
END
'@
}

function Receive-SIUpdaterClaimAgain {
    <#
        'CLAIM THE INSTALL KEY AGAIN' -- a one-shot request, for after Invardia reset the install's key. NEVER throws.
        Returns @{ Asked; By; Reason }:
          * SI_UPDATER_CLAIM_AGAIN = 1 / true / yes / on (-EnvValue) on this execution -> asked;
          * the web app's request (cfg.InstallState 'InstallKeyClaimAgain', set by an Admin on Settings > Updates) -> TAKEN
            here, read and deleted in one statement, BEFORE any claim. Whatever the claim then answers, the request is gone:
            a refused claim is never asked again by the same request. A request that cannot be taken = NOT asked (no loop).
    #>
    param([AllowEmptyString()][string]$EnvValue, $Store)
    $asked = $false; $by = ''; $why = New-Object System.Collections.Generic.List[string]
    if ("$EnvValue".Trim() -match '^(?i)(1|true|yes|on)$') { $asked = $true; $by = 'SI_UPDATER_CLAIM_AGAIN on this updater run'; $why.Add('SI_UPDATER_CLAIM_AGAIN is set on this run') }
    elseif ("$EnvValue".Trim()) { $why.Add(("SI_UPDATER_CLAIM_AGAIN = '{0}' is not 1 -- ignored" -f "$EnvValue".Trim())) }
    if ($Store) {
        try {
            $row = @(& $Store.Invoke (Get-SIUpdaterClaimAgainTakeSql) ([ordered]@{}) 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
            $get = { param($n) if ($row -is [System.Collections.IDictionary]) { $row[$n] } elseif ($row -and $row.PSObject.Properties[$n]) { $row.$n } else { $null } }
            if ($row -and [int](& $get 'Taken') -gt 0) {
                $who = "$(& $get 'RequestedBy')".Trim()
                $asked = $true
                if (-not $by) { $by = $(if ($who) { $who } else { 'the web app' }) }
                $why.Add(("{0} asked on the Settings page -- the request is taken away now, whatever the claim answers" -f $(if ($who) { $who } else { 'an Admin' })))
            }
        } catch { $why.Add(("the web app's request could not be read and taken away ({0}) -- not claimed again on it" -f $_.Exception.Message)) }
    }
    [pscustomobject]@{ Asked = $asked; By = $by; Reason = ($why -join '; ') }
}

function Invoke-SIUpdaterFromInvardia {
    <#
        One update run -- the same for Pro and Community installs. Returns the exit code (0 = nothing to do / applied / held;
        1 = a step failed). -Seams: tests only (merged over the real REST-backed Key Vault seams; Http / Download / ClaimHttp /
        TenantId / TrustedKeys; the Community route's GetManifest / CommunityTrustedKeys / DownloadPrefix; ReadEdition { } ->
        the install's recorded edition; ReadCommunityState { } -> the earlier Community state row).
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$AcrName, [string[]]$Blocked = @(), $Store, [AllowEmptyString()][string]$Deployed,
          [string]$AcceptFingerprint, [string]$SIRoot, [hashtable]$Seams, [string]$Work)
    $get = { param($k) $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { '' } else { "$v".Trim() } }
    # CR5 step 1 (#655): the web app, MCP server and updater job are named by the install record this run resolved
    # (Get-SIUpdaterInstallName in Start-SIUpdater.ps1), then the job's variable, then today's name -- never a literal here
    $nameOf = { param($role) if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { Get-SIUpdaterInstallName -Role $role -Env $Env }
                             else { $v = & $get (@{ web = 'SI_UPDATER_WEB_APP'; mcp = 'SI_UPDATER_MCP_APP'; updater = 'SI_UPDATER_JOB_NAME' }[$role])
                                    if ($v) { $v } else { @{ web = 'ca-si-management'; mcp = 'ca-si-mcp'; updater = 'caj-si-updater' }[$role] } } }
    if (-not $SIRoot) { $SIRoot = Find-SIUpdaterInvardiaRoot }
    if (-not $SIRoot) { Write-UpdLog 'updates from Invardia: this updater image does not carry the client -- re-run setup/Install-SIUpdaterJob.ps1 to rebuild it'; return 1 }
    . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-InvardiaUpdate.ps1'))
    # framework INSTALL-1: a Pro install made without a licence waits for it (Get-SIAssignedLicence), then its parked jobs go on
    $awaitLib = [IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-AssignedLicence.ps1')
    if (Test-Path -LiteralPath $awaitLib) { . $awaitLib }
    $vault = & $get 'SI_UPDATER_KEY_VAULT'
    $s = if ($Seams -and $Seams['ReadSecret'] -and $Seams['WriteSecret']) { @{} } else { New-SIInvardiaUpdateSeams -VaultName $vault -Mode Rest -SubscriptionId $SubscriptionId }
    if ($Seams) { foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] } }
    $base = & $get 'SI_UPDATER_INVARDIA_BASE_URL'
    $now = if ($s['Now']) { ([datetime](& $s.Now)).ToUniversalTime() } else { [datetime]::UtcNow }
    if (-not $Work) { $Work = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    New-Item -ItemType Directory -Force -Path $Work | Out-Null

    # #427: every failure of this run is recorded for Invardia's uplink (SI-UpdaterTelemetry.ps1; absent = nothing recorded)
    $fail = { param($step, $text) if (Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue) { Add-SIUpdaterFailure -Step $step -Text $text } }
    # #506: the run's stages to Invardia (SI-UpdaterRunTrack.ps1; absent = not tracked, never a failed update)
    $track = { param($what, $a, $b) if (Get-Command -Name Invoke-SIUpdaterTrackHook -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterTrackHook -What $what -A $a -B $b -Seams $s -Store $Store -Env $Env -Deployed $Deployed -Ring $ringPick.Ring -BaseUrl $base } }
    $stateJson = $null; try { $stateJson = & $s.ReadSecret 'SI-Update-State' } catch { Write-UpdLog ("updates from Invardia: the update state could not be read ({0}) -- starting from none" -f $_.Exception.Message) }
    $state = ConvertFrom-SIInvardiaUpdateState -Json $stateJson

    # ---- THE MANIFEST ADDRESS (PRO-COMMUNITY-SAME): the only thing that differs between the editions. The licence decides
    # (an installed licence = the install route); without one, the install's recorded edition (the resource group's tag, else
    # the job's SI_UPDATER_SOURCE). Every other step below is the same for both. ----
    $hasLicence = $false
    if ($s['ReadSecret']) { try { $hasLicence = [bool]"$(& $s.ReadSecret $script:SIInvardiaUpdateSecretLicence)".Trim() } catch { $hasLicence = $false } }
    $edition = if ($s['ReadEdition']) { [string](& $s.ReadEdition) } elseif (-not (Get-Module -Name Pester)) { Get-SIUpdaterInstallEdition -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup } else { '' }
    $routePick = Resolve-SIUpdaterUpdateRoute -HasLicence $hasLicence -Edition $edition -Source (& $get 'SI_UPDATER_SOURCE')
    $route = $routePick.Route
    Write-UpdLog ("update source: {0}" -f $routePick.Reason)
    # framework PRO-COMMUNITY-SAME (opt-in, owner 2026-11-11): the install route (a licence, or Pro waiting for its licence) is a
    # connected install, as before; an install on the Community route claims nothing and sends nothing that identifies it until
    # it said yes to "Connect this install to Invardia" (SI_Invardia_Connect, Test-SIInvardiaConnect). The Community manifest is
    # read anonymously (the ring only) either way.
    $connected = Test-SIUpdaterInvardiaConnected -Route $route -Get $get
    $global:SI_UpdaterConnected = $connected
    if ($route -eq 'community') {
        # COMPAT: an existing Community install kept what it applied in cfg.InstallState 'CommunityUpdateState' -- carried over once
        $oldRow = if ($s['ReadCommunityState']) { [string](& $s.ReadCommunityState) } else { Read-SIUpdaterCommunityStateRow -Store $Store }
        if (Merge-SIUpdaterCommunityState -State $state -Json $oldRow) { Write-UpdLog ("update state: the earlier Community record is carried over (applied sequence {0}, {1})" -f $state.code.appliedSequence, $state.code.appliedVersion) }
    }
    # sequences are counted per manifest address: an install that moves between them (a Community install that gets a licence,
    # the same install changing edition) starts the new address from the version rule, never from the other address's sequence
    if ("$($state.channel)".Trim() -and "$($state.channel)" -ne $route) {
        Write-UpdLog ("update state: the manifest address moved from {0} to {1} -- the applied sequence starts again from the version this install runs" -f $state.channel, $route)
        $state.code.appliedSequence = [long]-1; $state.code.appliedWave = ''
    }
    $state.channel = $route
    $state.source = $route; $state.lastCheckUtc = $now; $state.lastError = ''
    # The from-version: what this updater recorded when it last applied a release (state.code.appliedVersion) when the
    # jobs' image tags know only its base version (images are tagged by content: v3.0.0-<hash>) -- never anything else
    $Deployed = Resolve-SIUpdaterRunningRelease -Deployed $Deployed -AppliedVersion ([string]$state.code.appliedVersion)
    # what this install runs, for the reports this run sends (the updater's own image release rides as its build)
    $global:SI_UpdaterEngineVersion = "$Deployed".Trim()
    $rc = 0
    $save = {
        try { & $s.WriteSecret 'SI-Update-State' (ConvertTo-SIInvardiaUpdateStateJson -State $state) } catch { Write-UpdLog ("WARNING: the update state could not be saved in the Key Vault: {0}" -f $_.Exception.Message) }
        if ($Store) { try { Save-SIUpdaterInvardiaStateRow -Store $Store -Json (ConvertTo-SIInvardiaUpdateStateJson -State $state -Compact) } catch { Write-UpdLog ("WARNING: the update state could not be shown in the Pro database: {0}" -f $_.Exception.Message) } }
        # (#308 / UPDATE-1.7: the install's ring is SI's own -- recorded by Resolve-SIUpdaterInvardiaRing below, never taken from a manifest)
    }

    # UPDATE-1.7: the ring this environment pulls for -- SI decides it; none = no pull (Request-SIInvardiaManifest says why)
    $ringPick = Resolve-SIUpdaterInvardiaRing -EnvRing (& $get 'SI_UPDATER_RING') -Store $Store -ResourceGroup $ResourceGroup -Channel $route -DefaultRing $(if ($route -eq 'community') { 3 } else { -1 })
    Write-UpdLog ("update ring: {0}" -f $ringPick.Reason)
    # the ring the updater's own status reports to Invardia carry (Send-SIUpdaterFailureReports -> Get-SITelemetryContext)
    $global:SI_UpdaterResolvedRing = $ringPick.Ring

    # ---- THE RUN GATE (owner 2026-10-23, SI-UpdaterRunGate.ps1): nothing that changes the install -- the database step,
    # the code roll, the size step, the template publish -- runs while a pipeline run is going. Asked once, at the first of
    # them; GO holds the install's lock to the end of this run. WAIT / UNREADABLE: nothing is changed, said plainly, and the
    # wait is handed to the pipeline runner (tag si-update-waits), which starts this updater again once the run has ended
    # and before it starts the next one. Seams (tests): RunGate { param($Holder) }, Beat, ExitGate, ReadWaits, WriteWaits,
    # SecondPass. A test that brings no seam never reaches Azure or a database (Go, nothing read or written).
    $real = -not (Get-Module -Name Pester)
    $gate = @{ Result = $null; Deferred = $false; TagRead = $false; Tag = $null; JobId = ''; Cleared = $false; SecondPass = $false }
    $updaterJob = & $nameOf 'updater'
    $holder = if (Get-Command -Name Get-SIUpdaterRunGateHolder -ErrorAction SilentlyContinue) { Get-SIUpdaterRunGateHolder -Env $Env } else { 'caj-si-updater' }
    $readTag = {
        if ($gate.TagRead) { return }
        $gate.TagRead = $true
        try {
            $t = if ($s['ReadWaits']) { & $s.ReadWaits } elseif ($real -and (Get-Command -Name Read-SIUpdaterWaitsTag -ErrorAction SilentlyContinue)) { Read-SIUpdaterWaitsTag -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -JobName $updaterJob } else { $null }
            if ($t) { $gate.Tag = ConvertFrom-SIUpdateWaitsTag -Value ([string]$t.Value); $gate.JobId = [string]$t.JobId }
        } catch { Write-UpdLog ("the update's wait mark could not be read: {0}" -f $_.Exception.Message) }
    }
    $writeTag = { param($value)
        if ($s['WriteWaits']) { $null = & $s.WriteWaits $value }
        elseif ($real -and $gate.JobId) { $null = Write-SIUpdaterWaitsTag -JobId $gate.JobId -Value $value }
        elseif ($real) { Write-UpdLog ("WARNING: the update's wait could not be handed to the pipeline runner: the updater job {0} could not be read -- the next update tries again" -f $updaterJob) } }
    # #1150: an "update now" start (SI_UPDATER_MODE update-now: the heartbeat's signal, Stop-SIRunAndUpdate, a person) also
    # respects a run that is only STARTING -- the pipeline runner's execution of the last minutes, not yet in the run record
    $startingRun = $null
    if ((& $get 'SI_UPDATER_MODE') -ieq 'update-now' -and (Get-Command -Name Get-SIUpdaterStartingRun -ErrorAction SilentlyContinue)) {
        $startingRun = { Get-SIUpdaterStartingRun -Executions @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs/caj-si-flow/executions') -List) -NowUtc ([datetime]::UtcNow) }
    }
    $askGate = {
        if ($s['RunGate']) { & $s.RunGate $holder }
        elseif ($real -and (Get-Command -Name Invoke-SIUpdaterRunGate -ErrorAction SilentlyContinue)) {
            Invoke-SIUpdaterRunGate -Store $Store -Holder $holder -SubscriptionId $SubscriptionId -StartingRun $startingRun `
                -BusyJobs { $en = Get-SIUpdaterEnvironment -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob $updaterJob
                            @(Get-SIUpdaterBusyJobs -JobNames @($en.JobNames) -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) } `
                -DatabaseMissing { if ($Store -and "$($Store.Server)" -and "$($Store.Database)") { Test-SIUpdaterDatabaseMissing -Server ([string]$Store.Server) -Database ([string]$Store.Database) -SubscriptionId $SubscriptionId } else { $false } }
        } else { [pscustomobject]@{ Go = $true; Verdict = 'Go'; Kind = ''; Reason = 'no run gate in this image'; RunId = ''; LockTaken = $false; Holder = '' } }
    }
    $passGate = {
        if ($gate.Result) { return $gate.Result }
        $r = & $askGate
        Write-UpdLog ("run gate: {0}" -f $r.Reason)
        # AN UPDATE NEVER CANCELS A RUNNING PIPELINE (owner 2026-11-05: "it must not auto cancel a running job due to missing
        # upd"; it replaces the 6-hour bound of 2026-10-29, which cut a run after its Risk Analysis had finished). The update
        # waits for the run to end and is installed between two runs (the wait mark: a run that ends starts no new one first).
        $gate.Result = $r
        # #911 (d): the lock is beaten at EVERY step of the update from here on -- also inside the release's own update script
        # (setup\Invoke-SIContainerUpdate.ps1 beats it at each of its steps through Invoke-SIUpdaterLockBeat)
        if ($r.LockTaken -and (Get-Command -Name Register-SIUpdaterLockBeat -ErrorAction SilentlyContinue)) {
            Register-SIUpdaterLockBeat -Store $Store -Holder $holder -Beat $(if ($s['Beat']) { $s['Beat'] } else { $null }) -Real:([bool]$real)
        }
        if ($r.Go) {
            # the wait is over: the mark is taken away, so the pipeline runner holds nothing for it
            & $readTag
            if ($gate.Tag) { & $writeTag ''; $gate.Cleared = $true; Write-UpdLog ("the update waited since {0:yyyy-MM-dd HH:mm}Z -- it is installed now, between two pipeline runs" -f $gate.Tag.SinceUtc) }
            $state.waitsSinceUtc = $null; $state.waitsReason = ''; $state.waitsKind = ''
        }
        $r
    }
    $markWaits = {
        param($r)
        if ($gate.Deferred) { return }
        & $readTag
        $since = if ($gate.Tag) { $gate.Tag.SinceUtc } elseif ($state.waitsSinceUtc) { [datetime]$state.waitsSinceUtc } else { $now }
        $state.waitsSinceUtc = $since; $state.waitsReason = [string]$r.Reason; $state.waitsKind = [string]$r.Kind
        & $writeTag (ConvertTo-SIUpdateWaitsTag -SinceUtc $since -SetUtc $now -Kind $(if ($r.Kind) { [string]$r.Kind } else { 'run' }) -Reason ([string]$r.Reason))
        $gate.Deferred = $true
        & $track 'waiting' ([string]$r.Reason)
    }
    $beat = { param($what) if ($gate.Result -and $gate.Result.LockTaken) { if ($s['Beat']) { $null = & $s.Beat $holder $what } elseif ($real) { $null = Update-SIUpdaterRunGateBeat -Store $Store -Holder $holder -What ('an update of SecurityInsight: ' + $what) } } }
    # the template publish waits too (a gate already passed this run is not asked again)
    $templatesGo = { $g = & $passGate; if (-not $g.Go) { Write-UpdLog ("templates: not installed now -- {0}" -f $g.Reason); & $markWaits $g; return $false }; & $beat 'the template pack'; $true }

    try {
    try {
        # ---- 1. the install key: stored, or claimed (never in a loop after a 409) ----
        # 'claim it again' (one-shot): the request is taken away BEFORE the claim, so it is used once whatever the answer
        $global:SI_UpdaterStep = 'claim'
        $again = Receive-SIUpdaterClaimAgain -EnvValue (& $get 'SI_UPDATER_CLAIM_AGAIN') -Store $Store
        if ($again.Reason) { Write-UpdLog ("install key, claim again: {0}" -f $again.Reason) }
        $force = [bool]($again.Asked -and $state.claimResult -eq 'conflict')
        if ($again.Asked -and -not $force) { Write-UpdLog ("install key, claim again: the claim is not held (last claim: {0}) -- nothing to claim again" -f $(if ($state.claimResult) { $state.claimResult } else { 'none' })) }
        $claim = if ($connected) { Request-SIInvardiaInstallKey -State $state -Seams $s -BaseUrl $base -NowUtc $now -Force:$force -Community:($route -eq 'community') }
                  else { [pscustomobject]@{ Action = 'off'; Reason = (Get-SIInvardiaConnectSkipText -What 'no install key claim'); HasKey = $false } }
        if ($force) {
            $state.claimAgainResult = [string]$claim.Action; $state.claimAgainBy = [string]$again.By; $state.claimAgainUtc = $now
            Write-UpdLog ("install key, claim again: claimed once -- {0}" -f $(if ($claim.Action -eq 'claimed') { 'claimed' } elseif ($claim.Action -eq 'conflict') { 'Invardia refused it again (409); held until the next request' } else { $claim.Action }))
        }
        Write-UpdLog ("install key: {0} -- {1}" -f $claim.Action, $claim.Reason)
        if (Get-Command -Name Get-SIUpdaterClaimFailure -ErrorAction SilentlyContinue) { $cf0 = Get-SIUpdaterClaimFailure -Claim $claim; if ($cf0) { & $fail 'claim' $cf0 } }
        if ($route -eq 'invardia' -and -not $claim.HasKey -and (Get-Command -Name Get-SIAssignedLicence -ErrorAction SilentlyContinue) -and $s['ReadSecret']) {
            # framework INSTALL-1: no licence yet -- the existing licence request (knock, owner approval, pull) brings it; said in plain words
            $al = Get-SIAssignedLicence -ReadSecret $s['ReadSecret']
            if (-not $al.Assigned) { Write-UpdLog ('{0} ({1})' -f $script:SIAwaitLicenceText, $al.Reason) }
        }
        # the install route needs the key; the Community route is anonymous and goes on without one (the same steps follow)
        if (-not $claim.HasKey -and $route -ne 'community') { & $save; return 0 }
        # framework INSTALL-1: the licence is assigned and the key claimed -- the jobs the install parked go on now (only those
        # marked si-awaits-licence; a job an administrator disabled stays disabled). Never fails the run: the next run tries again.
        if ($claim.HasKey -and (Get-Command -Name Resume-SIAwaitingLicenceJobs -ErrorAction SilentlyContinue)) {
            try {
                $parkedNow = if ($s['ListJobs']) { @(& $s.ListJobs) } elseif ($real) { @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) } else { @() }
                $patchJob = if ($s['PatchJob']) { $s['PatchJob'] } else { { param($j, $b) $null = Invoke-SIUpdaterArm -Method PATCH -Path ([string]$j.id) -Body $b; $true } }
                $on = @(Resume-SIAwaitingLicenceJobs -Jobs $parkedNow -Patch $patchJob -Log { param($m) Write-UpdLog $m })
                if ($on.Count) { Write-UpdLog ('the licence is assigned: {0} job(s) are switched on -- {1}' -f $on.Count, ($on -join ', ')) }
            } catch { Write-UpdLog ('the jobs waiting for the licence were not switched on now ({0}) -- the next run tries again' -f $_.Exception.Message) }
        }
        $global:SI_UpdaterStep = 'manifest'
        $ep = Get-SIInvardiaUpdatesEndpoint -State $state -BaseUrl $base
        $accept = ConvertFrom-SIUpdaterManualStepAccept (& $get 'SI_UPDATER_ACCEPT_MANUAL_STEP')
        # Invardia S16: the install's LASTING id (SI-InstallId, made once by the licence knock), read once for both pulls and
        # sent as X-Invardia-Install-Id -- read only; none / unreadable = no header, never a made-up one
        # live 2026-11-01: an install whose licence was renewed before 3.0.17 never knocked again, and the heartbeat's identity
        # may not write the vault -- so no install had an id. The updater holds Key Vault Secrets Officer (it writes
        # SI-Update-State): it CREATES the id once when missing (Resolve: create once, never rewrite, the oldest version wins)
        $installId = if ((Get-Command -Name Resolve-SIInvardiaInstallId -ErrorAction SilentlyContinue) -and $s['ReadSecret'] -and $s['WriteSecret']) { Resolve-SIInvardiaInstallId -ReadSecret $s['ReadSecret'] -WriteSecret $s['WriteSecret'] -ReadVersions $s['ReadVersions'] }
                      elseif ((Get-Command -Name Get-SIInvardiaInstallId -ErrorAction SilentlyContinue) -and $s['ReadSecret']) { Get-SIInvardiaInstallId -ReadSecret $s['ReadSecret'] -ReadVersions $s['ReadVersions'] } else { '' }
        Write-UpdLog ("install id: {0}" -f $(if ($installId) { 'present (sent to Invardia with the update check)' } else { 'none -- the vault could not be read or written; sent without it this time' }))
        $ask = {
            param($kind)
            $k = $state[$kind]
            if ($k.nextTryUtc -and $now -lt [datetime]$k.nextTryUtc) {
                Write-UpdLog ("{0}: Invardia asked to wait until {1:yyyy-MM-dd HH:mm}Z -- not asked this run" -f $kind, [datetime]$k.nextTryUtc)
                return $null
            }
            $r = if ($route -eq 'community') {
                     # the Community route (anonymous, per ring): the same signed-manifest checks, answered in the same shape
                     if ($null -eq $ringPick.Ring) { New-SIInvardiaManifestResult -Kind $kind -Action 'off' -Reason $ringPick.Reason }
                     else {
                         $cb = Get-SIUpdaterCommunityBase -Override (& $get 'SI_UPDATER_COMMUNITY_BASE_URL')
                         if ($cb.Note) { Write-UpdLog $cb.Note }
                         Request-SIUpdaterCommunityCode -Ring ([int]$ringPick.Ring) -AppliedSequence $k.appliedSequence -RunningVersion "$Deployed" -AcceptManualStepSequence $accept[$kind] -BaseUrl $cb.Base -Seams $s
                     }
                 } else {
                     Request-SIInvardiaManifest -Kind $kind -Seams $s -BaseUrl $base -AppliedSequence $k.appliedSequence -AcceptManualStepSequence $accept[$kind] `
                         -ManifestUri $ep.ManifestUri -KeyHeader $ep.KeyHeader -RunningVersion $(if ($kind -eq 'code') { "$Deployed" } else { '' }) `
                         -Ring $(if ($null -ne $ringPick.Ring) { $ringPick.Ring } else { (& $get 'SI_UPDATER_RING') }) `
                         -AppliedWave $(if ($k.Contains('appliedWave')) { [string]$k.appliedWave } else { '' }) -AppliedVersion ([string]$k.appliedVersion) -InstallId $installId
                 }
            Set-SIInvardiaUpdateCheck -State $state -Result $r -NowUtc $now
            Write-UpdLog ("{0} manifest: {1} -- {2}" -f $kind, $r.Action, $r.Reason)
            # CR3 (#657): a manifest Invardia served for a pre-release wave -- said once in the log
            if ($r.PSObject.Properties['Wave'] -and "$($r.Wave)".Trim()) { Write-UpdLog ("{0}: Invardia serves {1} to this install early, in the pre-release wave '{2}' (no ring move; the header shows it)" -f $kind, $r.Version, $r.Wave) }
            $r
        }

        # ---- 2. templates: is a pack released for this ring at all? (the template channel is a licensed feature: asked on
        # the install route only; a Community install takes the release's own templates through the template gate) ----
        $tpl = $null; $channel = $false
        if ($Store -and $route -ne 'community') { $tpl = & $ask 'templates'; $channel = [bool]($tpl -and $tpl.Action -in @('update', 'current', 'hold')) }

        # the release package of a verified code result, by the route's package source: @{ Ok; Reason; Root; Commit; Version }
        # (the install route: the Pro package, size + SHA-256, its shape and VERSION; the Community route: the public zip)
        $fetchCode = {
            param($res, $dir, [string]$Name = 'SecurityInsight', [switch]$Quiet)
            if ($route -eq 'community') { return (Save-SIUpdaterCommunityRelease -Result $res -Work $dir -Seams $s -Ring $(if ($null -ne $ringPick.Ring) { [int]$ringPick.Ring } else { 0 })) }
            $ff = Save-SIInvardiaUpdateFile -Result $res -OutDir $dir -Seams $s
            if (-not $ff.Ok) { return [pscustomobject]@{ Ok = $false; Step = 'download'; Reason = $ff.Reason; Root = ''; Commit = ''; Version = '' } }
            if (-not $Quiet) { Write-UpdLog ("code: {0}" -f $ff.Reason) }
            $sh = Test-SIFeedArchiveShape -Path $ff.Path
            # the archive's VERSION is the signed version, or the VERSION of which it is a build (3.0.0.<build>, ring 1)
            if (-not $sh.Ok -or -not (Test-SIInvardiaReleaseOfVersion -Released $res.Version -Archive $sh.Version)) {
                $why = if (-not $sh.Ok) { "not a usable release: $($sh.Reason)" } else { "it holds SecurityInsight $($sh.Version), not the $($res.Version) the signed manifest names" }
                return [pscustomobject]@{ Ok = $false; Step = 'verify'; Reason = $why; Root = ''; Commit = ''; Version = '' }
            }
            $root = Join-Path $dir $Name
            $nf = Expand-SIUpdaterSolution -ZipPath $ff.Path -Destination $root
            if (-not $Quiet) { Write-UpdLog ("{0} file(s) of SecurityInsight {1} extracted" -f $nf, $res.Version) }
            [pscustomobject]@{ Ok = $true; Reason = ''; Root = $root; Commit = "$($sh.Commit)"; Version = "$($res.Version)" }
        }

        # ---- 3. code ----
        $code = $null; $siNow = $null; $runs = $Deployed; $dec = $null; $roll = $null; $relCommit = ''
        if ($Blocked -contains 'engine-image') { Write-UpdLog 'code: the customer blocks engine-image updates -- not asked' }
        else { $code = & $ask 'code' }
        if ($code) {
            $dec = Get-SIUpdaterInvardiaCodeDecision -Result $code -Deployed $Deployed -AppliedSequence $state.code.appliedSequence -AppliedWave ([string]$state.code.appliedWave)
            if ($dec.Hold) { $state.code.hold = $dec.Hold }
            if ($dec.Applied) { Set-SIInvardiaUpdateApplied -State $state -Result $code -NowUtc $now }
            Write-UpdLog ("code: {0}" -f $dec.Reason)
            & $track 'open' $code $dec
            if ($dec.Act) {
                $global:SI_UpdaterStep = 'download'
                $pkg = & $fetchCode $code $Work
                if (-not $pkg.Ok) {
                    $stepName = if ($pkg.PSObject.Properties['Step'] -and $pkg.Step) { [string]$pkg.Step } else { 'verify' }
                    $state.code.lastAction = 'refused'; $state.code.lastReason = $pkg.Reason; $state.lastError = "code: $($pkg.Reason)"
                    Write-UpdLog ("code REFUSED: {0} -- nothing was rolled" -f $pkg.Reason); & $fail $stepName ("code REFUSED: {0}" -f $pkg.Reason); & $save; return 1
                }
                $global:SI_UpdaterStep = 'verify'
                if ($route -eq 'community') { Write-UpdLog $pkg.Reason }
                $si = [string]$pkg.Root; $relCommit = [string]$pkg.Commit
                # never roll under a manual deploy; a running pipeline run holds the update (owner 2026-10-23, the run gate
                # below -- replaces the 2026-10-12 rule); a release that says it must be installed while no SI job runs at
                # all still waits for them here (SI_UPDATER_WAIT_MINUTES is that wait)
                $waitMin = 60; [void][int]::TryParse((& $get 'SI_UPDATER_WAIT_MINUTES'), [ref]$waitMin); if ($waitMin -le 0) { $waitMin = 60 }
                $pre = if ($s['PreRoll']) { & $s.PreRoll } else { Invoke-SIUpdaterInvardiaPreRoll -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -WaitMinutes $waitMin -SIRoot $si }
                if (-not $pre.Go) {
                    $state.code.lastAction = 'deferred'; $state.code.lastReason = $pre.Reason
                    Write-UpdLog ("code: deferred -- {0}" -f $pre.Reason); & $track 'waiting' $pre.Reason; & $save; return 0
                }
                # a manual deploy of exactly this release (fast-deploy records si-installed = the released version on the
                # updater job): it runs already -- counted as applied, nothing is built or rolled twice
                $recorded = if ($pre.Environment -and $pre.Environment.Record) { "$($pre.Environment.Record.Version)".Trim() } else { '' }
                if ($recorded -and $recorded -eq "$($code.Version)") {
                    Set-SIInvardiaUpdateApplied -State $state -Result $code -NowUtc $now
                    $global:SI_UpdaterEngineVersion = "$($code.Version)".Trim()
                    Write-UpdLog ("code: {0} is recorded as installed on this environment (a manual deploy of this release) -- nothing to roll" -f $code.Version)
                    & $track 'current' ("{0} is installed already" -f $code.Version)
                    $dec = [pscustomobject]@{ Act = $false }
                }
            }
            if ($dec.Act) {
                # 2026-10-23: never under a running pipeline run -- the run gate, before the database step and the roll
                $gr = & $passGate
                if (-not $gr.Go) {
                    $state.code.lastAction = 'deferred'; $state.code.lastReason = [string]$gr.Reason
                    Write-UpdLog ("code: deferred -- {0}" -f $gr.Reason); & $markWaits $gr; & $save; return 0
                }
                & $beat ('installing {0}' -f $code.Version)
                # IMAGE-PRUNE (owner 2026-11-12): what ran until now -- the PREVIOUS release's images, as the install records them
                # on its jobs and apps -- read BEFORE anything is rolled (SI-UpdaterImagePrune.ps1). Only read here; the
                # clean-up itself runs after a healthy post-roll below. Not readable = nothing is pruned this run.
                $imgBefore = $null
                if ($s['ImageSnapshot']) { $imgBefore = & $s.ImageSnapshot }
                elseif ($real -and (Get-Command -Name Get-SIUpdaterImageSnapshot -ErrorAction SilentlyContinue)) {
                    try {
                        $imgLogin = if ($pre.Environment -and "$($pre.Environment.LoginServer)") { [string]$pre.Environment.LoginServer } else { [string](Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup).loginServer }
                        $imgBefore = Get-SIUpdaterImageSnapshot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -LoginServer $imgLogin -UpdaterJob (& $nameOf 'updater')
                    } catch { $imgBefore = [pscustomobject]@{ Ok = $false; Refs = @(); Reason = $_.Exception.Message } }
                }
                # #405: ring 1 (internal) gets the release's templates installed directly, exactly as on the ring channel
                $roll = Invoke-SIUpdaterRoll -SIRoot $si -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Store $Store `
                            -AcceptFingerprint $AcceptFingerprint -TemplatesFollowChannel:$channel -InstallTemplatesDirect:($ringPick.Ring -eq 1) `
                            -Version "$($code.Version)" -Commit $relCommit `
                            -WebApp (& $nameOf 'web') `
                            -McpApp (& $nameOf 'mcp') `
                            -UpdaterJob (& $nameOf 'updater') `
                            -SelfOff:((& $get 'SI_UPDATER_SELF_UPDATE') -match '^(?i)(0|false|off|no)$')
                if ($roll.Held) { $state.code.hold = $roll.Reason; & $track 'waiting' $roll.Reason }
                elseif ($roll.Code -eq 0) {
                    Set-SIInvardiaUpdateApplied -State $state -Result $code -NowUtc $now; $siNow = $si; $runs = $code.Version
                    # the engine version this install runs from now on -- reported by THIS run, not only from the next one
                    $global:SI_UpdaterEngineVersion = "$($code.Version)".Trim()
                    & $track 'applied' $code.Version
                    # owner 2026-11-09: the code rolled; a template change of this release that waits for an Admin is recorded
                    # as pending (the Settings page shows it; an accept by fingerprint publishes it on a later run, below)
                    $pendLine = if ($roll.PSObject.Properties['TemplatesPending']) { "$($roll.TemplatesPending)".Trim() } else { '' }
                    if ($pendLine) { $state.templates.hold = $pendLine; $state.templates.pendingFingerprint = [string]$roll.TemplatesPendingFingerprint }
                    else { $state.templates.pendingFingerprint = '' }
                    & $beat 'the web app and the updater itself'
                    # Pro: the web app + MCP server, the installed record, then the updater itself -- as the ring channel does
                    $post =if ($s['PostRoll']) { & $s.PostRoll $si $code.Version $relCommit }
                            else { Invoke-SIUpdaterInvardiaPostRoll -SIRoot $si -Version $code.Version -Commit $relCommit -Environment $pre.Environment -ResourceGroup $ResourceGroup `
                                       -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterJob (& $nameOf 'updater') `
                                       -WebApp (& $nameOf 'web') `
                                       -McpApp (& $nameOf 'mcp') `
                                       -SelfOff:((& $get 'SI_UPDATER_SELF_UPDATE') -match '^(?i)(0|false|off|no)$') }
                    Write-UpdLog ("code: {0}" -f $post.Text)
                    if ($post.Code -ne 0) { $rc = 1; $state.lastError = "code: $($post.Text)"; & $fail 'post-roll' ([string]$post.Text) }
                    # the updater moved onto this release: its update steps run in the second update, started at the end of this run
                    elseif ($post.PSObject.Properties['SelfAction'] -and [string]$post.SelfAction -eq 'rolled') { $gate.SecondPass = $true }
                    # IMAGE-PRUNE (owner 2026-11-12): ONLY after the update AND its read-back ended well (the engine roll verified,
                    # the post-roll healthy): the install's own registry keeps this release + the one before; one line per
                    # repository. Never fails the update (SI-UpdaterImagePrune.ps1; SI_Updater_ImagePrune = off turns it off).
                    if ($post.Code -eq 0) {
                        & $beat 'old images'
                        if ($s['ImagePrune']) { $null = & $s.ImagePrune $imgBefore }
                        elseif ($real -and (Get-Command -Name Invoke-SIUpdaterImagePruneStep -ErrorAction SilentlyContinue)) {
                            $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Healthy $true `
                                        -Before $imgBefore -Version "$($code.Version)" -PreviousVersion "$Deployed" -UpdaterJob (& $nameOf 'updater') -Get $get `
                                        -ReadSecret $s['ReadSecret'] -WriteSecret $s['WriteSecret'] -Store $Store
                        }
                    }
                }
                else {
                    $rc = [int]$roll.Code; $state.lastError = $(if ($roll.Reason) { "code: $($roll.Reason)" } else { "code: the roll failed (exit $($roll.Code)); the jobs were restored" })
                    # the database / templates / build / roll step recorded its own failure (Invoke-SIUpdaterRoll); this only when none did
                    if ((Get-Command -Name Get-SIUpdaterFailures -ErrorAction SilentlyContinue) -and -not @(Get-SIUpdaterFailures).Count) { & $fail 'roll' $state.lastError }
                }
            }
        }
        # #756: NO NEW CODE THIS RUN (the ring's release is applied already, held, or not asked) -- the sizes the customer's
        # settings set still apply on every daily run, not only when new code is installed (live 2026-10-19: S2 set, the code
        # current, the database stayed S3). Only the size steps run (Invoke-SIUpdaterSizingPass: SQL database, jobs, web app);
        # nothing is built or rolled. A roll that ran this run sized them already. Never fails the run.
        if (-not $roll -or $roll.Held) {
            # held: a manual step Invardia named (Action hold), the forward-only / minimum-version rule
            $isHeld = [bool]($code -and $code.Action -eq 'hold') -or [bool]($dec -and $dec.PSObject.Properties['Hold'] -and $dec.Hold) -or [bool]($roll -and $roll.Held)
            $why = if ($code -and $code.Action -in @('update', 'current') -and -not $isHeld) { "the code is current ({0})" -f $(if ("$global:SI_UpdaterEngineVersion".Trim()) { "$global:SI_UpdaterEngineVersion".Trim() } else { "$($code.Version)" }) }
                   elseif ($isHeld) { 'no new code is installed this run (the code update is held)' }
                   else { 'no new code is installed this run' }
            # 2026-10-23: the size step changes the install too (the SQL tier, the jobs) -- never under a running pipeline run
            $grS = & $passGate
            if (-not $grS.Go) { Write-UpdLog ("sizes: not checked now -- {0}" -f $grS.Reason); & $markWaits $grS }
            elseif ($s['SizingPass']) { & $beat 'the sizes'; $null = & $s.SizingPass $why }
            # (a test that brings no seam never runs the real update script against Azure)
            elseif (-not (Get-Module -Name Pester)) { & $beat 'the sizes'; $null = Invoke-SIUpdaterSizingPass -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Store $Store -Why $why }
        }
        # #350 (c): nothing rolled this run, but an earlier run could not move the updater itself -- try that again (the image
        # in the registry; a failed build is rebuilt with the next release). A failure here never fails the run.
        if (-not $siNow -and -not ((& $get 'SI_UPDATER_SELF_UPDATE') -match '^(?i)(0|false|off|no)$')) {
            if ($s['SelfRetry']) { $null = & $s.SelfRetry } else { $null = Invoke-SIUpdaterInvardiaSelfRetry -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId `
                                                                        -UpdaterJob (& $nameOf 'updater') }
        }

        # ---- 3b. a template change that waited while the code rolled, accepted since by SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT ----
        # (owner 2026-11-09: the code never waited for it; an Admin's accept on the Template releases page publishes it through
        # the templates job instead). Only for the release the jobs run now; nothing waits = nothing done. Still waiting = said
        # again in the update state (the template check of this run cleared its hold line).
        $pendFp = [string]$state.templates.pendingFingerprint
        if ($pendFp -and $Store -and (Get-Command -Name Read-SIUpdaterTemplateFingerprint -ErrorAction SilentlyContinue) -and (Read-SIUpdaterTemplateFingerprint -Store $Store) -eq $pendFp) {
            Write-UpdLog 'configuration templates: the template change that waited is in force now'
            $state.templates.pendingFingerprint = ''; $pendFp = ''
        }
        $pendAccepted = [bool]($pendFp -and "$AcceptFingerprint".Length -ge 12 -and $pendFp.StartsWith("$AcceptFingerprint", [StringComparison]::OrdinalIgnoreCase))
        if ($pendFp -and -not $pendAccepted -and -not "$($state.templates.hold)".Trim()) {
            $state.templates.hold = 'the template change of the release the jobs run waits for an Admin (fingerprint {0}): accept it on the Template releases page, or with SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT on the updater job' -f $pendFp.Substring(0, [Math]::Min(12, $pendFp.Length))
        }
        if ($pendAccepted -and $Store -and -not $siNow -and
            $code -and $code.Action -in @('update', 'current') -and $runs -and (Compare-SIInvardiaVersion $code.Version $runs) -eq 0 -and (& $templatesGo)) {
            try {
                $cf = & $fetchCode $code (Join-Path $Work 'installed') ('installed-' + $runs) -Quiet
                if ($cf.Ok) { $siNow = [string]$cf.Root }
                if ($siNow) {
                    $pt = Invoke-SIUpdaterPendingTemplates -SIRoot $siNow -Store $Store -AcceptFingerprint $AcceptFingerprint
                    Write-UpdLog ("configuration templates: {0}" -f $pt.Reason)
                    if ($pt.Done) { $state.templates.pendingFingerprint = ''; $state.templates.hold = '' }
                    else { $state.templates.hold = $pt.Reason; if ($pt.Fingerprint) { $state.templates.pendingFingerprint = $pt.Fingerprint } }
                } else { Write-UpdLog ("configuration templates: the template change that waits is not published now -- the release {0} could not be read ({1}); the next run tries again" -f $runs, $cf.Reason) }
            } catch { $state.lastError = "templates: $($_.Exception.Message)"; Write-UpdLog ("configuration templates FAILED: {0}" -f $_.Exception.Message); & $fail 'templates' ("configuration templates FAILED: {0}" -f $_.Exception.Message); $rc = 1 }
        }

        # ---- 4. templates: a newer pack, through the gate with the code the jobs run ----
        if ($tpl -and $tpl.Action -eq 'update' -and (& $templatesGo)) {
            $installed = ''; try { $installed = Read-SIUpdaterInstalledPack -Store $Store } catch { $installed = '' }
            if ($installed -and (Compare-SIInvardiaVersion $tpl.Version $installed) -eq 0) {
                Set-SIInvardiaUpdateApplied -State $state -Result $tpl -NowUtc $now
                Write-UpdLog ("templates: pack {0} is installed already" -f $installed)
            } else {
                $f = Save-SIInvardiaUpdateFile -Result $tpl -OutDir $Work -Seams $s
                if (-not $f.Ok) { $state.templates.lastAction = 'refused'; $state.templates.lastReason = $f.Reason; $state.lastError = "templates: $($f.Reason)"; Write-UpdLog ("templates REFUSED: {0}" -f $f.Reason); & $fail 'template-pack' ("templates REFUSED: {0}" -f $f.Reason); $rc = 1 }
                else {
                    # the pack under the name and with the sha256sum line the release's publish script expects
                    $names = Get-SIFeedTemplatePackNames -PackVersion $tpl.Version
                    $pack = Join-Path $Work $names.Pack
                    if ($f.Path -ne $pack) { Move-Item -LiteralPath $f.Path -Destination $pack -Force }
                    [IO.File]::WriteAllText("$pack.sha256", (Format-SIFeedChecksum -Hash $f.Sha256 -ArchiveName $names.Pack), (New-Object System.Text.UTF8Encoding($false)))
                    if (-not $siNow -and $code -and $code.Action -in @('update', 'current') -and $runs -and (Compare-SIInvardiaVersion $code.Version $runs) -eq 0) {
                        $cf = & $fetchCode $code (Join-Path $Work 'installed') ('installed-' + $runs) -Quiet
                        if ($cf.Ok) { $siNow = [string]$cf.Root }
                    }
                    if (-not $siNow) {
                        $state.templates.hold = ("HELD: template pack {0} is released, but the code the jobs run ({1}) is not the ring's release -- update the code first" -f $tpl.Version, $(if ($runs) { $runs } else { 'unknown' }))
                        Write-UpdLog ("templates: {0}" -f $state.templates.hold)
                    } else {
                        try {
                            $g = Invoke-SIUpdaterTemplatePackGate -SIRoot $siNow -Store $Store -PackFile $pack -PackVersion $tpl.Version -RingKey ('r{0}' -f $tpl.Ring) -Origin feed -Deployed $runs -AcceptFingerprint $AcceptFingerprint `
                                -ManifestB64 $(if ($tpl.PSObject.Properties['ManifestB64']) { [string]$tpl.ManifestB64 } else { '' }) -Signature $(if ($tpl.PSObject.Properties['Signature']) { [string]$tpl.Signature } else { '' }) -KeyId ([string]$tpl.KeyId)
                            Write-UpdLog ("templates: {0}" -f $g.Reason)
                            if ($g.Action -eq 'published') { Set-SIInvardiaUpdateApplied -State $state -Result $tpl -NowUtc $now } else { $state.templates.hold = $g.Reason }
                        } catch { $state.lastError = "templates: $($_.Exception.Message)"; Write-UpdLog ("templates FAILED: {0}" -f $_.Exception.Message); & $fail 'template-pack' ("templates FAILED: {0}" -f $_.Exception.Message); $rc = 1 }
                    }
                }
            }
        }
    } catch {
        $state.lastError = (Hide-SIInvardiaSecret $_.Exception.Message)
        Write-UpdLog ("updates from Invardia FAILED: {0}" -f $state.lastError)
        & $fail $(if ("$global:SI_UpdaterStep".Trim()) { "$global:SI_UpdaterStep" } else { 'updater' }) $state.lastError
        $rc = 1
    }
    & $save
    $rc
    } finally {
        # the install's lock, when this run took it: released -- the pipeline's next wake-up takes the queue on the new build
        if (Get-Command -Name Unregister-SIUpdaterLockBeat -ErrorAction SilentlyContinue) { Unregister-SIUpdaterLockBeat }
        if ($gate.Result -and $gate.Result.LockTaken) {
            $null = if ($s['ExitGate']) { & $s.ExitGate $holder } elseif ($real) { Exit-SIUpdaterRunGate -Store $Store -Holder $holder } else { $null }
            Write-UpdLog 'run gate: the install''s lock is released'
        }
        # a wait mark this run neither renewed nor cleared at the gate (it ended before it got there: no new code, refused,
        # failed): taken away, so the pipeline runner never holds its queue for an update that is not waiting any more
        if (-not $gate.Deferred -and -not $gate.Cleared) {
            & $readTag
            if ($gate.Tag) { & $writeTag ''; Write-UpdLog 'the update''s wait mark is taken away: this update run ended before it reached its install step (see above)' }
        }
        # the second update (this release's own update steps), started once this run is done -- still between two runs
        if ($gate.SecondPass) {
            $line = if ($s['SecondPass']) { & $s.SecondPass } elseif ($real -and (Get-Command -Name Start-SIUpdaterSecondPass -ErrorAction SilentlyContinue)) { Start-SIUpdaterSecondPass -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -JobName $updaterJob } else { '' }
            if ($line) { Write-UpdLog $line }
        }
    }
}
