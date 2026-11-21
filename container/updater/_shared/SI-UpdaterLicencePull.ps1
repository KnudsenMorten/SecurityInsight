#Requires -Version 5.1
<#
    caj-si-updater -- SUPPORT ASKS FOR A LICENCE OF AN EDITION THROUGH THE UPDATE (SI_UPDATER_LICENCE_PULL; Invardia design
    2026-11-20, revised the same day: Invardia's licence API stays locked -- NO licence id is ever sent).

    WHY: nobody writes the licence secret by hand (Invardia ruling 2026-11-15: install state is changed only by the update,
    through a control-plane value on the updater job). The licence request step (SI-UpdaterLicence.ps1) asks Invardia only
    when the install has no licence or it ends within 30 days; this value asks for a licence of ONE edition on purpose (a
    test Pro Business licence proving the Business limits live), or puts the licence kept before back.

      SI_UPDATER_LICENCE_PULL = request:pro-business     FILES A LICENCE REQUEST with the normal knock of the licence request
                              request:pro-enterprise     route (engine\_shared\SI-LicenceRequest.ps1: POST <base>/api/licence-
                                                         requests, edition 'pro-business' / 'pro-single-tenant'), ONCE. The
                                                         owner approves it in Invardia's back office with that edition. This
                                                         and every later update then only PULLS (the request's own pull
                                                         token, kept in the vault as SI-LicencePull-PullToken) until Invardia
                                                         delivers. The knock carries NO proof of possession (no install key, no
                                                         current licence id or hash): a proven knock is approved automatically
                                                         with the licence the tenant already has -- this request is the owner's
                                                         decision.
      SI_UPDATER_LICENCE_PULL = request:previous         the licence kept in SI-License-Previous is installed again. No request.
      SI_UPDATER_CONTROLPLANE_REASON                     REQUIRED: who asked and why (Test-SIControlPlaneReason).

    THE GUARD (both ways, explicitly tested): the licence is verified OFFLINE before anything is written -- the framework
    verifier (engine\_shared\AitLicense.ps1) against the trusted signers ONLY, and the signer that verifies it must be
    CN=Invardia-Licensing or the old CN=AutomateIT-Licensing-Service; its tenantIds must name THIS install's tenant (the tid
    of the identity's own token, never config); valid today (not expired, not in grace, not yet valid = refused); product
    SecurityInsight, features SecurityInsight has; and a requested licence must be of the EDITION asked for (Pro Business =
    the signed payload carries a limits object; Pro Enterprise = it carries none).
    THEN: the licence in force is kept as SI-License-Previous in the same vault and read back (a request only -- a restore
    leaves it); the licence is written by setup\Set-SILicense.ps1 (which verifies again and reads it back); it is read back
    once more; ONE plain line says which licence, its edition and its end date. Audited like the licence request
    (licence.request.install / licence.request.fail on cfg.AuditEvent) with a cfg.ChangeLog row.
    ONCE PER VALUE: the request filed is kept in cfg.InstallState 'ControlPlaneLicencePullRequest' (no token -- that is in
    the vault); the value is recorded as DONE in 'ControlPlaneLicencePull' once the matching licence is installed (or a
    restore is), and the same value on a later update does nothing.

    NEVER FAILS THE UPDATE: every refusal or failure is ONE warning line, and the licence in force stays.
#>

$script:SIUpdLicPullEnv        = 'SI_UPDATER_LICENCE_PULL'
$script:SIUpdLicPullState      = 'ControlPlaneLicencePull'
$script:SIUpdLicPullReqState   = 'ControlPlaneLicencePullRequest'
$script:SIUpdLicPullToken      = 'SI-LicencePull-PullToken'
$script:SIUpdLicPullPrevious   = 'SI-License-Previous'
$script:SIUpdLicPullSigners    = @('CN=Invardia-Licensing', 'CN=AutomateIT-Licensing-Service')

function ConvertFrom-SIUpdaterLicencePullValue {
    <#
        PURE. The env's value -> @{ Kind ('' = not set | request | restore | bad); Value (as recorded, lower-case);
        Edition (Invardia's edition id on the knock); Label (the edition the licence must be: 'Pro Business' | 'Pro Enterprise') }.
        Only request:pro-business, request:pro-enterprise and request:previous -- a licence id is never a value.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $t = "$Value".Trim()
    $o = { param($k, $v, $e, $l) [pscustomobject]@{ Kind = $k; Value = $v; Edition = $e; Label = $l } }
    if (-not $t) { return (& $o '' '' '' '') }
    switch -Regex ($t.ToLowerInvariant()) {
        '^request:\s*pro-business$'   { return (& $o 'request' 'request:pro-business' 'pro-business' 'Pro Business') }
        '^request:\s*pro-enterprise$' { return (& $o 'request' 'request:pro-enterprise' 'pro-single-tenant' 'Pro Enterprise') }
        '^request:\s*previous$'       { return (& $o 'restore' 'request:previous' '' '') }
    }
    & $o 'bad' $t '' ''
}

function Get-SIUpdaterLicencePullTrustedCerts {
    <#
        The signers a licence loaded this way may carry: the framework verifier's own two public certificates
        (engine\_shared\AitLicense.ps1 -- CN=AutomateIT-Licensing-Service and CN=Invardia-Licensing), read from that file of
        -SIRoot. Never configuration. Empty when the file is not there (the caller refuses).
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $f = [IO.Path]::Combine($SIRoot, 'engine', '_shared', 'AitLicense.ps1')
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    $src = [IO.File]::ReadAllText($f)
    @(foreach ($n in 'AitLicenseSignerCertB64', 'AitLicenseInvardiaCertB64') {
        $m = [regex]::Match($src, '(?m)^\$script:' + $n + "\s*=\s*'([A-Za-z0-9+/=]+)'")
        if ($m.Success) { $m.Groups[1].Value }
    })
}

function Get-SIUpdaterLicencePullSigner {
    <#
        PURE. The subject of the trusted certificate whose key verifies this licence document's signature, or '' when none
        does. -TrustedCertsB64: the signers tried (the framework's two by default).
    #>
    param([AllowNull()]$Document, [AllowNull()][string[]]$TrustedCertsB64)
    try {
        if ($null -eq $Document -or -not $Document.payloadB64 -or -not $Document.signature) { return '' }
        $pb = [Convert]::FromBase64String("$($Document.payloadB64)"); $sb = [Convert]::FromBase64String("$($Document.signature)")
        foreach ($c in @($TrustedCertsB64 | Where-Object { $_ })) {
            if (Test-AitLicenseSignature -PayloadBytes $pb -SignatureBytes $sb -PublicCertB64 $c) {
                $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($c))
                return [string]$x.Subject
            }
        }
    } catch { }
    ''
}

function Test-SIUpdaterLicencePullCandidate {
    <#
        The offline check of the licence about to be installed (delivered or restored). The licence request's own check
        (Test-SILicenceRequestFile: SHA-256, signature against the trusted signers, valid today, THIS tenant among its
        tenantIds, product, features) PLUS: the signer is one of the two named signers; -ExpectEdition: 'Pro Business' |
        'Pro Enterprise' (Get-SILicenceDimension of the signed licence). -Text: the licence JSON.
        Returns @{ Ok; Problems; License (Get-SILicense, with Limits); Signer; Edition }. Never throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [AllowNull()][string]$TenantId, [Parameter(Mandatory)][string[]]$TrustedCertsB64,
          [Parameter(Mandatory)][datetime]$Now, [string]$ExpectEdition = '')
    $problems = New-Object System.Collections.Generic.List[string]
    $out = { param($lic, $sig, $ed) [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray(); License = $lic; Signer = $sig; Edition = $ed } }
    try {
        $t = "$Text".TrimStart([char]0xFEFF).Trim()
        if ($t -and -not $t.StartsWith('{')) { try { $t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)).TrimStart([char]0xFEFF).Trim() } catch { } }
        if (-not $t -or $t -eq '-') { $problems.Add('there is no licence'); return (& $out $null '' '') }
        $bytes = [Text.Encoding]::UTF8.GetBytes($t)
        $file = [pscustomobject]@{ sha256 = (Get-SILicenceRequestSha256 -Bytes $bytes); contentBase64 = [Convert]::ToBase64String($bytes) }
        $v = Test-SILicenceRequestFile -Licence $file -TenantId $TenantId -TrustedCertsB64 $TrustedCertsB64 -Now $Now
        foreach ($p in @($v.Problems)) { $problems.Add([string]$p) }
        $doc = $null; try { $doc = $t | ConvertFrom-Json -ErrorAction Stop } catch { $doc = $null }
        $signer = Get-SIUpdaterLicencePullSigner -Document $doc -TrustedCertsB64 $TrustedCertsB64
        if ($signer -and $script:SIUpdLicPullSigners -notcontains $signer) {
            $problems.Add(("the licence is signed by {0}, not by {1}" -f $signer, ($script:SIUpdLicPullSigners -join ' or ')))
        }
        $lic = Get-SILicense -SecretText $t -TrustedCertsB64 $TrustedCertsB64 -Now $Now
        $ed = Get-SILicenceDimension -License $lic
        if ($ExpectEdition -and $ed -ne $ExpectEdition) {
            $problems.Add(("the licence is {0}, not the {1} asked for" -f $(if ($ed -eq 'Community') { 'not a valid Pro licence' } else { $ed }), $ExpectEdition))
        }
        return (& $out $lic $signer $ed)
    } catch { $problems.Add(("the licence could not be checked: {0}" -f (([string]$_.Exception.Message) -split "`n")[0])); return (& $out $null '' '') }
}

function Write-SIUpdaterLicencePullChangeLog {
    <# One cfg.ChangeLog row for the licence switched (ids only, never the licence text). No table = nothing. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [AllowEmptyString()][string]$OldId, [Parameter(Mandatory)][string]$NewId, [string]$Reason)
    $sql = @'
IF OBJECT_ID('cfg.ChangeLog') IS NOT NULL
    INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (N'SI-License', 'install', 'install', 'Set', @Old, @New, @By, @Reason);
'@
    $r = "$Reason"; if ($r.Length -gt 400) { $r = $r.Substring(0, 400) }
    $null = & $Store.Invoke $sql ([ordered]@{ Old = $(if ($OldId) { $OldId } else { $null }); New = $NewId; By = 'the update (control-plane value)'; Reason = $r }) 'nonquery'
}

function Invoke-SIUpdaterLicencePull {
    <#
        THE STEP (Start-SIUpdater, right before the licence request step). -Env: the job's environment (a name not in it is
        read from the process). -Store: the Pro store (cfg.InstallState for once per value, the audit trail, the change log).
        -Connected: the install may call Invardia (PRO-COMMUNITY-SAME); -Switch: the customer's SI_LicenseRequest_Auto (off =
        Invardia is not asked). A restore needs neither (no call leaves the install).
        Tests only: -Seams (merged over the real licence request seams), -TrustedCertsB64, -Audit { param($Action, $Outcome, $Text) }.
        Returns @{ Action (none | already | requested | waiting | installed | restored | refused | failed); LicenceId; Lines }.
        NEVER throws.
    #>
    param([hashtable]$Env = @{}, $Store, [string]$SubscriptionId, [string]$SIRoot, [bool]$Connected = $true, $Switch,
          [scriptblock]$Log, [hashtable]$Seams, [string[]]$TrustedCertsB64, [scriptblock]$Audit)
    if (-not $Log) { $Log = { param($m) Write-Host $m } }
    $siLpLines = New-Object System.Collections.Generic.List[string]
    $res = [pscustomobject]@{ Action = 'none'; LicenceId = ''; Lines = @() }
    $envName = $script:SIUpdLicPullEnv
    $say = { param($m) $siLpLines.Add([string]$m); try { $null = & $Log ([string]$m) } catch { } }
    $err = { param($e) (([string]$e.Exception.Message) -split "`n")[0].Trim() }
    $value = $null; $reason = ''; $auditOn = $false
    # every refusal / failure: ONE warning line, an audit row once the request is a real one, the licence in force stays
    $refuse = {
        param([string]$Why, [string]$Action = 'refused')
        $res.Action = $Action
        & $say ('WARNING: licence pull: {0}={1} -- {2}; the licence in force stays' -f $envName, $(if ($value) { $value.Value } else { '' }), $Why)
        if ($auditOn) {
            try {
                $txt = ('{0}={1} not applied: {2} (asked: {3})' -f $envName, $value.Value, $Why, $reason)
                $oc = $(if ($Action -eq 'failed') { 'error' } else { 'refused' })
                if ($Audit) { $null = & $Audit 'licence.request.fail' $oc $txt }
                elseif ($Store) { Write-SIUpdaterAuditRow -Store $Store -Action 'licence.request.fail' -Outcome $oc -Text $txt -Actor 'caj-si-updater (licence pull)' -Reason $reason -Target 'SI-License' }
            } catch { }
        }
    }
    $done = { $res.Lines = $siLpLines.ToArray(); $res }
    try {
        $read = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])".Trim() } else { "$([Environment]::GetEnvironmentVariable($k))".Trim() } }
        $value = ConvertFrom-SIUpdaterLicencePullValue (& $read $envName)
        if (-not $value.Kind) { return (& $done) }
        if ($value.Kind -eq 'bad') { & $refuse ("'{0}' is not request:pro-business, request:pro-enterprise or request:previous" -f $value.Value); return (& $done) }

        if (-not $SIRoot) { $SIRoot = Find-SIUpdaterLicenceRoot }
        if (-not $SIRoot) { & $refuse 'this updater image does not carry the licence client'; return (& $done) }
        if (-not (Get-Command -Name Test-SIControlPlaneReason -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-ControlPlaneValues.ps1')) }
        if (-not (Get-Command -Name Test-SILicenceRequestFile -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-LicenceRequest.ps1')) }

        # ---- once per value ----
        if (-not $Store) { & $refuse 'no Pro database is configured on the updater job, so it cannot be done once'; return (& $done) }
        $prev = $null; $pend = $null
        try {
            $prev = Read-SIControlPlaneInstallState -Store $Store -Name $script:SIUpdLicPullState
            $pt = Read-SIControlPlaneInstallState -Store $Store -Name $script:SIUpdLicPullReqState
            if ("$pt".Trim()) { try { $pend = "$pt" | ConvertFrom-Json -ErrorAction Stop } catch { $pend = $null } }
        } catch { & $refuse ('whether it was applied before could not be read ({0})' -f (& $err $_)) 'failed'; return (& $done) }
        if ($prev -and $prev -ceq $value.Value) {
            $res.Action = 'already'
            & $say ('licence pull: {0}={1} is the value already applied -- nothing done' -f $envName, $value.Value)
            return (& $done)
        }
        # ---- who asked ----
        $reason = & $read 'SI_UPDATER_CONTROLPLANE_REASON'
        $whoWhy = Test-SIControlPlaneReason -Reason $reason
        if ($whoWhy) { & $refuse ("it needs SI_UPDATER_CONTROLPLANE_REASON to name who asked and why ('<person>: <why>'); {0}" -f $whoWhy); return (& $done) }
        if ($reason.Length -gt 400) { $reason = $reason.Substring(0, 400) }
        $auditOn = $true

        # ---- the vault, the tenant (the identity token's), the trusted signers ----
        $vault = & $read 'SI_UPDATER_KEY_VAULT'
        if (-not $vault -and -not $Seams) { & $refuse 'SI_UPDATER_KEY_VAULT is not set on the updater job'; return (& $done) }
        $s = if ($vault) { New-SILicenceRequestSeams -VaultName $vault -Mode Rest -SubscriptionId $SubscriptionId -SIRoot $SIRoot } else { @{} }
        if ($Seams) { foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] } }
        $now = if ($s['Now']) { ([datetime](& $s.Now)).ToUniversalTime() } else { [datetime]::UtcNow }
        $certs = @($TrustedCertsB64 | Where-Object { $_ })
        if (-not $certs.Count) { $certs = @(Get-SIUpdaterLicencePullTrustedCerts -SIRoot $SIRoot) }
        if (-not $certs.Count) { & $refuse 'the trusted licence signers are not loaded (engine\_shared\AitLicense.ps1)' 'failed'; return (& $done) }
        $tenant = ''
        try { $tenant = [string](& $s.TenantId) } catch { $tenant = '' }
        if (-not (Test-SILicenceRequestTenantProven $tenant)) { & $refuse 'the tenant this install runs in could not be proven from its identity token'; return (& $done) }
        $tenant = $tenant.ToLowerInvariant()

        # ---- what is in force now ----
        $curText = "$(& $s.ReadSecret 'SI-License')".TrimStart([char]0xFEFF).Trim()
        $cur = $null
        if ($curText -and $curText -ne '-') { $cur = Get-SILicense -SecretText $curText -TrustedCertsB64 $certs -Now $now }
        $curId = if ($cur -and "$($cur.Status)" -notin @('Missing', 'Invalid')) { "$($cur.LicenseId)".Trim().ToLowerInvariant() } else { '' }
        $recordDone = { Write-SIControlPlaneInstallState -Store $Store -Name $script:SIUpdLicPullState -Value $value.Value }
        $clearPending = {
            try { Write-SIControlPlaneInstallState -Store $Store -Name $script:SIUpdLicPullReqState -Value 'none' } catch { }
            try { & $s.WriteSecret $script:SIUpdLicPullToken '-' } catch { }
        }

        # ---- the licence to install ----
        $candText = ''
        if ($value.Kind -eq 'restore') {
            $candText = "$(& $s.ReadSecret $script:SIUpdLicPullPrevious)".TrimStart([char]0xFEFF).Trim()
            if (-not $candText -or $candText -eq '-') { & $refuse ('there is no {0} in the Key Vault to restore' -f $script:SIUpdLicPullPrevious); return (& $done) }
        } else {
            # the licence in force is of that edition already (valid, this tenant): nothing to ask for
            if ($cur -and "$($cur.Status)" -eq 'Valid' -and (Test-AitLicenseTenant -License $cur -TenantId $tenant) -and (Get-SILicenceDimension -License $cur) -eq $value.Label) {
                & $recordDone; & $clearPending
                $res.Action = 'already'; $res.LicenceId = $curId
                & $say ('licence pull: the licence in force ({0}) is {1} already -- nothing asked ({2}={3})' -f $curId, $value.Label, $envName, $value.Value)
                return (& $done)
            }
            if (-not $Connected) { & $refuse 'this install is not connected to Invardia (SI_Invardia_Connect), so Invardia is not asked'; return (& $done) }
            if ($Switch -and -not $Switch.On) { & $refuse 'licence requests are switched off at this install (SI_LicenseRequest_Auto), so Invardia is not asked'; return (& $done) }
            $base = Get-SILicenceRequestBaseUrl -BaseUrl (& $read 'SI_LICENSE_REQUEST_BASE_URL')
            $http = if ($s['Http']) { $s['Http'] } else { { param($u, $b, $t, $k, $i) Invoke-SILicenceRequestHttp -Uri $u -Body $b -Token $t -InstallKey $k -InstallId $i } }
            $tok = ''
            $filed = ($pend -and "$($pend.value)" -ceq $value.Value -and "$($pend.requestId)")
            if ($filed) { $tok = "$(& $s.ReadSecret $script:SIUpdLicPullToken)".Trim(); if ($tok -eq '-') { $tok = '' } }
            if (-not $filed -or -not $tok) {
                # ---- FILE THE REQUEST, once: the normal knock with the edition. No licence id, no proof of possession. ----
                $iid = "$(& $s.ReadSecret 'SI-InstallId')".Trim()
                if ($iid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { & $refuse 'this install has no install id (SI-InstallId) yet -- the licence request step makes it'; return (& $done) }
                $version = ''; $vf = [IO.Path]::Combine($SIRoot, 'VERSION'); if (Test-Path -LiteralPath $vf) { $version = ([IO.File]::ReadAllText($vf)).Trim() }; if (-not $version) { $version = '0.0.0' }
                $body = New-SILicenceRequestBody -Version $version -TenantId $tenant -InstallId $iid -Edition $value.Edition -ContactEmail (& $read 'SI_LICENSE_REQUEST_CONTACT_EMAIL')
                $k = & $http ($base + '/api/licence-requests') $body $null '' (ConvertTo-SIInvardiaInstallId $iid)
                $kj = $null; try { $kj = "$($k.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
                if ([int]$k.Status -notin @(200, 201, 202) -or -not $kj -or -not "$($kj.pullToken)".Trim() -or -not "$($kj.requestId)".Trim()) {
                    & $refuse $(if ([int]$k.Status -eq 0) { "Invardia could not be reached ($($k.Error)) -- the next update files the request" } else { "Invardia answered $([int]$k.Status) to the licence request -- the next update files it again" }) 'failed'
                    return (& $done)
                }
                $tok = [string]$kj.pullToken
                & $s.WriteSecret $script:SIUpdLicPullToken $tok
                $pend = [pscustomobject]@{ value = $value.Value; requestId = [string]$kj.requestId; requestedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
                Write-SIControlPlaneInstallState -Store $Store -Name $script:SIUpdLicPullReqState -Value ($pend | ConvertTo-Json -Compress)
                $res.Action = 'requested'
                & $say ('licence pull: a licence request for {0} filed with Invardia (request {1}; {2}={3}) -- the owner approves it in Invardia; this and every later update pulls it' -f $value.Label, $pend.requestId, $envName, $value.Value)
                try {
                    $txt = ('{0}={1}: a licence request for {2} filed (request {3}); asked: {4}' -f $envName, $value.Value, $value.Label, $pend.requestId, $reason)
                    if ($Audit) { $null = & $Audit 'licence.request.send' 'ok' $txt }
                    else { Write-SIUpdaterAuditRow -Store $Store -Action 'licence.request.send' -Outcome ok -Text $txt -Actor 'caj-si-updater (licence pull)' -Reason $reason -Target 'Invardia licence request' }
                } catch { }
            }
            # ---- PULL what Invardia approved (the request's own token) ----
            $p = & $http ($base + '/api/licence-requests/pull') '{}' $tok
            $tok = $null
            if ([int]$p.Status -eq 401) { & $clearPending; & $refuse ('Invardia no longer knows request {0} -- the next update files a new one' -f $pend.requestId) 'failed'; return (& $done) }
            $pj = $null; try { $pj = "$($p.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
            if ([int]$p.Status -ne 200 -or -not $pj) { & $refuse $(if ([int]$p.Status -eq 0) { "Invardia could not be reached ($($p.Error)) -- the next update pulls again" } else { "Invardia answered $([int]$p.Status) to the pull -- the next update pulls again" }) 'failed'; return (& $done) }
            if ("$($pj.status)" -eq 'Rejected') {
                & $clearPending
                & $refuse ('Invardia REJECTED request {0}{1}' -f $pend.requestId, $(if ($pj.PSObject.Properties['reason'] -and "$($pj.reason)") { ": $($pj.reason)" } else { '' }))
                return (& $done)
            }
            if ("$($pj.status)" -ne 'Approved' -or -not $pj.PSObject.Properties['licence'] -or $null -eq $pj.licence) {
                if ($res.Action -ne 'requested') { $res.Action = 'waiting' }
                & $say ('licence pull: request {0} for {1} is waiting for Invardia''s approval -- the next update pulls again' -f $pend.requestId, $value.Label)
                return (& $done)
            }
            # the file as delivered: its SHA-256 first, then the same offline check as a restored one
            $fv = Test-SILicenceRequestFile -Licence $pj.licence -TenantId $tenant -TrustedCertsB64 $certs -Now $now
            if (-not $fv.Text) { & $refuse ('the licence Invardia sent was NOT installed: {0}' -f (@($fv.Problems) -join '; ')); return (& $done) }
            $candText = [string]$fv.Text
        }
        $chk = Test-SIUpdaterLicencePullCandidate -Text $candText -TenantId $tenant -TrustedCertsB64 $certs -Now $now -ExpectEdition $value.Label
        if (-not $chk.Ok) { & $refuse ('the licence was NOT installed: {0}' -f (@($chk.Problems) -join '; ')); return (& $done) }
        $newId = "$($chk.License.LicenseId)".Trim().ToLowerInvariant()
        $res.LicenceId = $newId
        if ($value.Kind -eq 'restore' -and $curId -and $curId -eq $newId -and "$($cur.Status)" -eq 'Valid') {
            & $recordDone
            $res.Action = 'already'
            & $say ('licence pull: the licence kept in {0} ({1}) is the licence in force already -- nothing replaced' -f $script:SIUpdLicPullPrevious, $newId)
            return (& $done)
        }

        # ---- keep the licence in force (a request), read back ----
        $kept = $false
        if ($value.Kind -eq 'request' -and $curText -and $curText -ne '-') {
            try {
                & $s.WriteSecret $script:SIUpdLicPullPrevious $curText
                $back = "$(& $s.ReadSecret $script:SIUpdLicPullPrevious)".TrimStart([char]0xFEFF).Trim()
                if ($back -cne $curText) { throw 'it did not read back identical' }
                $kept = $true
            } catch { & $refuse ('the licence in force could not be kept as {0} ({1}) -- nothing replaced' -f $script:SIUpdLicPullPrevious, (& $err $_)) 'failed'; return (& $done) }
        }

        # ---- install (Set-SILicense verifies again and reads back), then read it back once more ----
        $ins = $null
        try { $ins = & $s.Install $candText $tenant } catch { $ins = [pscustomobject]@{ Ok = $false; Message = (& $err $_) } }
        if (-not $ins -or -not $ins.Ok) { & $refuse ('the licence verified but could not be installed: {0}' -f $(if ($ins) { $ins.Message } else { 'no result' })) 'failed'; return (& $done) }
        $after = Get-SILicense -SecretText ("$(& $s.ReadSecret 'SI-License')") -TrustedCertsB64 $certs -Now $now
        if (-not $after -or "$($after.Status)" -ne 'Valid' -or "$($after.LicenseId)".Trim().ToLowerInvariant() -ne $newId) {
            & $refuse 'the licence was written but did not read back as the one verified' 'failed'; return (& $done)
        }
        $edition = Get-SILicenceDimension -License $after
        $to = ([datetime]$after.ValidTo).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $res.Action = $(if ($value.Kind -eq 'restore') { 'restored' } else { 'installed' })
        & $say ('licence pull: licence {0} {1} -- {2}, valid to {3} (from {4}={5}; read back; {6})' -f $newId,
            $(if ($value.Kind -eq 'restore') { 'restored from ' + $script:SIUpdLicPullPrevious } else { 'installed' }), $edition, $to, $envName, $value.Value,
            $(if ($kept) { 'the licence before it kept as ' + $script:SIUpdLicPullPrevious } elseif ($value.Kind -eq 'request') { 'there was no licence before it' } else { $script:SIUpdLicPullPrevious + ' left as it is' }))
        # ---- audit + change log (never the licence text) ----
        $txt = ('{0}={1}: licence {2} ({3}, valid to {4}) installed by the update; before: {5}; asked: {6}' -f $envName, $value.Value, $newId, $edition, $to, $(if ($curId) { $curId } else { 'none' }), $reason)
        try {
            if ($Audit) { $null = & $Audit 'licence.request.install' 'ok' $txt }
            else { Write-SIUpdaterAuditRow -Store $Store -Action 'licence.request.install' -Outcome ok -Text $txt -Actor 'caj-si-updater (licence pull)' -Reason $reason -Target 'SI-License' }
        } catch { & $say ('WARNING: licence pull: the audit row was not written ({0}) -- the licence is installed' -f (& $err $_)) }
        try { Write-SIUpdaterLicencePullChangeLog -Store $Store -OldId $curId -NewId $newId -Reason $reason }
        catch { & $say ('WARNING: licence pull: the change-log row was not written ({0}) -- the licence is installed' -f (& $err $_)) }
        try { & $recordDone; if ($value.Kind -eq 'request') { & $clearPending } }
        catch { & $say ('WARNING: licence pull: that {0} was applied could not be recorded ({1}) -- the next update checks again' -f $envName, (& $err $_)) }
    } catch {
        & $refuse ('not applied ({0})' -f (& $err $_)) 'failed'
    }
    & $done
}
