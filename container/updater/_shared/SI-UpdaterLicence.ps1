#Requires -Version 5.1
<#
    caj-si-updater -- the LICENCE REQUEST step (#239). Each update run asks Invardia for this install's licence when it
    has none (or it ends within 30 days), pulls the approved file, verifies it offline and installs it as SI-License.
    The client is engine/_shared/SI-LicenceRequest.ps1; this file only wires it to the updater's REST sign-in (#521).

    Configuration (environment on the updater job, written by setup/Install-SIUpdaterJob.ps1):
      SI_UPDATER_KEY_VAULT              the install's Key Vault (SI-License, the pull token, the request state). Unset = off.
      THE SWITCH: SI_LicenseRequest_Auto (Pro Settings page), else [SI_LICENSE_REQUEST_AUTO] on the job, else ON
                  (engine/_shared/SI-ProAutomation.ps1). Off = no call to Invardia at all, and the log says so.
      AFTER A REQUEST: a request sent, a licence installed or a failure is written to the audit trail (licence.request.*,
                  Pro database) and -- installed or failed -- mailed to the guard-mail recipients (SI_GuardMail_To, else
                  MailTo, else the SuperAdmins) through the install's mail relay settings; the same failure is mailed
                  again only after 7 days. Quiet while the licence is valid or a request is waiting.
      [SI_LICENSE_REQUEST_BASE_URL]     default https://invardia.com
      [SI_LICENSE_REQUEST_CONTACT_EMAIL, SI_LICENSE_REQUEST_EDITION]   sent only when set
    The updater SPN needs 'Key Vault Secrets Officer' on that vault (Install-SIUpdaterJob.ps1 -GrantSpnRoles).

    🔒 NEVER FAILS THE UPDATE RUN: everything here is caught and logged as one line.
#>

function Find-SIUpdaterLicenceRoot {
    <# The SecurityInsight code the updater image carries (/si), or -- running from a checkout -- this solution's root. #>
    param([string[]]$Candidates)
    if (-not $Candidates) { $Candidates = @('/si', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..')) }
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath ([IO.Path]::Combine($c, 'engine', '_shared', 'SI-LicenceRequest.ps1')))) { return [IO.Path]::GetFullPath($c) }
    }
    $null
}

function Invoke-SIUpdaterLicenceRequest {
    <#
        One licence request cycle as the updater. Returns the client's result, or $null when it is off or could not run.
        -Seams: tests only (merged over the real REST-backed seams).
    #>
    param([hashtable]$Env = @{}, [string]$SubscriptionId, [scriptblock]$Log, [string]$SIRoot, [hashtable]$Seams,
          $Switch, $Store, [scriptblock]$Mail, [scriptblock]$Audit)
    if (-not $Log) { $Log = { param($m) Write-Host $m } }
    try {
        $get = { param($k) $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { '' } else { "$v".Trim() } }
        # The customer's switch (SI_LicenseRequest_Auto): off = nothing is asked, and the log says so. The installed
        # licence is still verified and shown in the web app (no call to Invardia for that).
        if ($Switch -and -not $Switch.On) {
            & $Log ("licence requests: {0}" -f $Switch.Text)
            try {
                $offVault = & $get 'SI_UPDATER_KEY_VAULT'
                $offRoot = if ($SIRoot) { $SIRoot } else { Find-SIUpdaterLicenceRoot }
                $offStore = $Store
                $offSql = & $get 'SI_UPDATER_PRO_SQL_SERVER'; $offDb = & $get 'SI_UPDATER_PRO_SQL_DATABASE'
                if (-not $offStore -and $offSql -and $offDb -and (Get-Command -Name New-SIUpdaterProStore -ErrorAction SilentlyContinue)) {
                    $offStore = New-SIUpdaterProStore -Server $offSql -Database $offDb -SubscriptionId $SubscriptionId
                }
                if ($offVault -and $offRoot -and $offStore) {
                    . ([IO.Path]::Combine($offRoot, 'engine', '_shared', 'SI-LicenceRequest.ps1'))
                    $os = New-SILicenceRequestSeams -VaultName $offVault -Mode Rest -SubscriptionId $SubscriptionId -SIRoot $offRoot
                    if ($Seams) { foreach ($k in @($Seams.Keys)) { $os[$k] = $Seams[$k] } }
                    Save-SIUpdaterLicenceSummary -Seams $os -Store $offStore -Log $Log
                }
            } catch { & $Log ("installed licence not recorded: {0}" -f $_.Exception.Message) }
            return $null
        }
        $vault = & $get 'SI_UPDATER_KEY_VAULT'
        if (-not $vault) { & $Log 'licence requests: off (SI_UPDATER_KEY_VAULT is not set on the updater job)'; return $null }
        if (-not $SIRoot) { $SIRoot = Find-SIUpdaterLicenceRoot }
        if (-not $SIRoot) { & $Log 'licence requests: this updater image does not carry the licence client -- re-run setup/Install-SIUpdaterJob.ps1 to rebuild it'; return $null }
        . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-LicenceRequest.ps1'))

        $s = New-SILicenceRequestSeams -VaultName $vault -Mode Rest -SubscriptionId $SubscriptionId -SIRoot $SIRoot
        # a closure: inside the client $log is its own variable, and a dynamic lookup would find that one
        $updLog = $Log
        $s.Log = { param($lvl, $t) & $updLog ("licence request{0}: {1}" -f $(if ($lvl -eq 'warn') { ' WARNING' } else { '' }), $t) }.GetNewClosure()
        # Pro: the state is shown in the web app from the Pro database (cfg.InstallState 'LicenceRequest').
        $proSql = & $get 'SI_UPDATER_PRO_SQL_SERVER'; $proDb = & $get 'SI_UPDATER_PRO_SQL_DATABASE'
        $store = $Store
        if (-not $store -and $proSql -and $proDb -and (Get-Command -Name New-SIUpdaterProStore -ErrorAction SilentlyContinue)) {
            $store = New-SIUpdaterProStore -Server $proSql -Database $proDb -SubscriptionId $SubscriptionId
        }
        if ($store) { $s.SaveState = { param($json) Save-SILicenceRequestProState -Store $store -Json $json } }
        # #517: Invardia re-issued the licence (an engine run recorded the newest id) -> the client asks now, once per id
        if ($store -and (Get-Command -Name Read-SILicenceSupersededMark -ErrorAction SilentlyContinue)) { $s.SupersededBy = { Read-SILicenceSupersededMark -Store $store } }
        if ($Seams) { foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] } }
        # Count the calls that leave for Invardia: a failure is news (audit + mail) only when Invardia was asked.
        $siUpdLrCalls = @{ N = 0 }
        $siUpdLrInner = $s['Http']
        $s.Http = { param($u, $b, $t) $siUpdLrCalls.N++; if ($siUpdLrInner) { & $siUpdLrInner $u $b $t } else { Invoke-SILicenceRequestHttp -Uri $u -Body $b -Token $t } }

        $version = ''
        $vf = [IO.Path]::Combine($SIRoot, 'VERSION')
        if (Test-Path -LiteralPath $vf) { $version = ([IO.File]::ReadAllText($vf)).Trim() }
        if (-not $version) { $version = '0.0.0' }
        $r = Invoke-SILicenceRequest -Seams $s -Version $version -BaseUrl (& $get 'SI_LICENSE_REQUEST_BASE_URL') `
                -ContactEmail (& $get 'SI_LICENSE_REQUEST_CONTACT_EMAIL') -Edition (& $get 'SI_LICENSE_REQUEST_EDITION')
        & $Log ("licence request: {0} -- {1}" -f $r.Action, $r.Message)
        # the installed licence (as it is after this cycle), verified, for the web app's Licence card
        if ($store) { Save-SIUpdaterLicenceSummary -Seams $s -Store $store -Log $Log }
        $null = Send-SIUpdaterLicenceNotice -Result $r -Contacted ($siUpdLrCalls.N -gt 0) -Seams $s -Store $store -SIRoot $SIRoot -Log $Log -Mail $Mail -Audit $Audit
        return $r
    } catch {
        & $Log ("licence request skipped: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Save-SILicenceRequestProState {
    <#
        The licence request state (compact JSON, no token) into cfg.InstallState 'LicenceRequest', for the web app. A row in
        cfg.ChangeLog only when the status changes (the value is rewritten on every run with the last check time).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Json)
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @old nvarchar(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'LicenceRequest');
    IF @old IS NULL
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'LicenceRequest', @Value, NULL, @By);
    ELSE
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'LicenceRequest';
    IF (@old IS NULL OR ISNULL(JSON_VALUE(@old, '$.status'), N'') <> ISNULL(JSON_VALUE(@Value, '$.status'), N'')) AND OBJECT_ID('cfg.ChangeLog') IS NOT NULL
        INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
        VALUES (N'LicenceRequest', 'install', 'install', 'Set', JSON_VALUE(@old, '$.status'), JSON_VALUE(@Value, '$.status'), @By, N'licence request');
    COMMIT;
END
'@
    $v = $Json
    if ($v.Length -gt 400) { $o = $v | ConvertFrom-Json; $o.reason = ''; $o.lastError = 'see the updater log'; $v = $o | ConvertTo-Json -Compress }
    & $Store.Invoke $sql ([ordered]@{ Value = $v; By = 'caj-si-updater' }) 'nonquery'
}

function Save-SIUpdaterLicenceSummary {
    <#
        The INSTALLED licence (SI-License), verified offline with the engines' own checks (Get-SILicense: signature,
        dates) plus whether it names this tenant, into cfg.InstallState 'Licence' for the web app's Licence card. The
        web app never reads the licence secret. Never throws: a failure is one log line.
        -Seams: the licence request seams (ReadSecret, TenantId, CurrentLicence, Now).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Seams, [Parameter(Mandatory)]$Store, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($m) Write-Host $m } }
    try {
        $now = if ($Seams['Now']) { ([datetime](& $Seams.Now)).ToUniversalTime() } else { [datetime]::UtcNow }
        $lic = $null
        if ($Seams['CurrentLicence']) { $lic = & $Seams.CurrentLicence }
        elseif (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue) { $lic = Get-SILicense -SecretText ("$(& $Seams.ReadSecret 'SI-License')") -Now $now }
        $tenant = $null
        try { $tenant = [string](& $Seams.TenantId) } catch { $tenant = $null }
        $json = ConvertTo-SILicenceSummaryJson -License $lic -TenantId $tenant -NowUtc $now
        Save-SILicenceProSummary -Store $Store -Json $json
        $o = $json | ConvertFrom-Json
        & $Log ("installed licence: {0}{1}" -f $o.status, $(if ($o.validTo) { ", valid until $($o.validTo)" } else { '' }))
    } catch { & $Log ("installed licence not recorded: {0}" -f $_.Exception.Message) }
}

function Save-SILicenceProSummary {
    <# The installed-licence summary into cfg.InstallState 'Licence' (NVARCHAR(400); the free text is dropped first if it is too long). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Json)
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @old nvarchar(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'Licence');
    IF @old IS NULL
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'Licence', @Value, NULL, @By);
    ELSE
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'Licence';
    COMMIT;
END
'@
    $v = $Json
    if ($v.Length -gt 400) { $o = $v | ConvertFrom-Json; $o.reason = ''; $v = $o | ConvertTo-Json -Compress }
    if ($v.Length -gt 400) { $o = $v | ConvertFrom-Json; $o.features = ''; $v = $o | ConvertTo-Json -Compress }
    & $Store.Invoke $sql ([ordered]@{ Value = $v; By = 'caj-si-updater' }) 'nonquery'
}

function Send-SIUpdaterLicenceNotice {
    <#
        After one licence request: the audit row and the mail the result calls for (Get-SILicenceRequestNotice in
        engine/_shared/SI-ProAutomation.ps1). Never throws. -Seams: the client's (ReadSecret / WriteSecret keep the last
        mailed notice in SI-LicenceRequest-Notice). -Mail / -Audit: tests only -- { param($Notice) } -> $true when done.
    #>
    param([Parameter(Mandatory)]$Result, [bool]$Contacted, [Parameter(Mandatory)][System.Collections.IDictionary]$Seams, $Store,
          [string]$SIRoot, [scriptblock]$Log, [scriptblock]$Mail, [scriptblock]$Audit)
    if (-not $Log) { $Log = { param($m) Write-Host $m } }
    try {
        if (-not (Get-Command -Name Get-SILicenceRequestNotice -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-ProAutomation.ps1')) }
        $secret = 'SI-LicenceRequest-Notice'
        $prev = $null; try { $t = & $Seams.ReadSecret $secret; if ("$t".Trim()) { $prev = "$t" | ConvertFrom-Json } } catch { $prev = $null }
        $now = if ($Seams['Now']) { ([datetime](& $Seams.Now)).ToUniversalTime() } else { [datetime]::UtcNow }
        $n = Get-SILicenceRequestNotice -Result $Result -Contacted $Contacted -Previous $prev -NowUtc $now
        if ($n.Kind -eq 'quiet') { return $n }
        # ---- the audit trail (Pro database) ----
        if ($n.Audit) {
            if ($Audit) { try { $null = & $Audit $n } catch { & $Log ("licence request WARNING: the audit row was not written: {0}" -f $_.Exception.Message) } }
            elseif ($Store) {
                try { Write-SIUpdaterAuditRow -Store $Store -Action $n.Audit.Action -Outcome $n.Audit.Outcome -Text $n.Audit.Text }
                catch { & $Log ("licence request WARNING: the audit row '{0}' was not written: {1} -- the request itself is not affected" -f $n.Audit.Action, $_.Exception.Message) }
            } else { & $Log 'licence request: not written to the audit trail (no Pro database is configured on the updater job)' }
        }
        # ---- the mail ----
        if ($n.Mail) {
            $sent = $false
            if ($Mail) { try { $sent = [bool](& $Mail $n) } catch { & $Log ("licence request: the mail was not sent: {0}" -f $_.Exception.Message) } }
            else {
                $m = Send-SIUpdaterNoticeMail -Notice $n -Store $Store -ReadSecret $Seams.ReadSecret -SIRoot $SIRoot
                $sent = [bool]$m.Sent
                if (-not $sent) { & $Log ("licence request: the mail was not sent: {0}" -f $m.Why) }
            }
            if ($sent) {
                & $Log ("licence request: mailed -- {0}" -f $n.Subject)
                try { & $Seams.WriteSecret $secret ((@{ key = $n.Key; mailedUtc = $now.ToString('o') }) | ConvertTo-Json -Compress) }
                catch { & $Log ("licence request WARNING: the mail record could not be saved: {0}" -f $_.Exception.Message) }
            }
        }
        return $n
    } catch { & $Log ("licence request: the audit / mail step was skipped: {0}" -f $_.Exception.Message); return $null }
}

function Write-SIUpdaterAuditRow {
    <#
        One 'event' row on the install's audit trail (cfg.AuditEvent), as the updater job. The same statement and fields as
        the product's audit writer; kept here because the updater image carries no Pro settings code. The action must be
        lower-case domain.object.verb and is on the closed list (config\audit-actions.locked.json, checked by a test).
        THROWS on failure -- the caller logs it and carries on.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Action, [ValidateSet('ok', 'error', 'refused', 'held')][string]$Outcome = 'ok', [string]$Text)
    if ($Action -notmatch '^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$') { throw "audit action '$Action' is not lower-case domain.object.verb" }
    $sql = @'
IF OBJECT_ID(N'cfg.AuditEvent') IS NULL
    SELECT N'Missing' AS Outcome;
ELSE
BEGIN
    INSERT cfg.AuditEvent (RecordType, Action, Actor, ActorSource, Target, Reason, Outcome, OutcomeText, BeforeJson, AfterJson, CorrelationId, WhatIf, ScopeDomain, ScopeDepartmentId)
    VALUES (N'event', @Action, @Actor, @ActorSource, @Target, @Reason, @Outcome, @OutcomeText, @BeforeJson, @AfterJson, @CorrelationId, @WhatIf, @ScopeDomain, @ScopeDepartmentId);
    SELECT N'Saved' AS Outcome;
END
'@
    # long opaque runs (a token, a key) never reach the trail
    $t = [regex]::Replace("$Text", '(?<![A-Za-z0-9_\-+=])(?=[A-Za-z0-9_\-+=]*[0-9])(?=[A-Za-z0-9_\-+=]*[A-Za-z])[A-Za-z0-9_\-+=]{40,}', '(hidden)')
    if ($t.Length -gt 1000) { $t = $t.Substring(0, 1000) }
    $p = [ordered]@{ Action = $Action; Actor = 'caj-si-updater (licence request)'; ActorSource = 'job'; Target = 'Invardia licence request'; Reason = 'automatic licence request'
                     Outcome = $Outcome; OutcomeText = $t; BeforeJson = $null; AfterJson = $null; CorrelationId = $null; WhatIf = $false; ScopeDomain = $null; ScopeDepartmentId = $null }
    $r = & $Store.Invoke $sql $p 'scalar'
    if ("$r" -eq 'Missing') { throw 'the Pro database has no audit trail table yet' }
}

function Send-SIUpdaterNoticeMail {
    <#
        One notice mail from the updater. The recipients and the relay are the install's own settings in the Pro database
        (SI_GuardMail_To, else MailTo, else the SuperAdmins; SmtpServer / SMTPPort / SMTPFrom / ..., secrets read from the
        Key Vault), sent with the one mail transport (Send-SIMail: shared mailbox or SMTP, SI_Mail_Mode). Returns @{ Sent; Why }. Never throws.
    #>
    param([Parameter(Mandatory)]$Notice, $Store, [scriptblock]$ReadSecret, [string]$SIRoot)
    try {
        if (-not $Store) { return [pscustomobject]@{ Sent = $false; Why = 'no Pro database is configured on the updater job, so the mail settings are unknown' } }
        if (-not (Get-Command -Name Get-SIGuardSmtp -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-Guard.ps1')) }
        $set = Read-SIProSolutionSettings -Store $Store
        if (-not $set.Ok) { return [pscustomobject]@{ Sent = $false; Why = ("the Pro settings could not be read ({0})" -f $set.Error) } }
        $g = @{}
        foreach ($k in @($set.Values.Keys)) { $g[$k] = $set.Values[$k] }
        foreach ($k in @($set.Secrets.Keys)) { if ($ReadSecret) { try { $g[$k] = & $ReadSecret $set.Secrets[$k] } catch { } } }
        $admins = @()
        try { $admins = @(& $Store.Invoke (Get-SIGuardSql 'SuperAdmins') @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { [string]$_['Mail'] }) } catch { }
        $rcp = Get-SIGuardMailRecipients -Globals $g -SuperAdminMails $admins
        if (-not @($rcp.To).Count) { return [pscustomobject]@{ Sent = $false; Why = 'no recipient is configured (SI_GuardMail_To, MailTo or a SuperAdmin with a mail address)' } }
        $smtp = Get-SIGuardSmtp -Globals $g
        if ($smtp.Off) { return [pscustomobject]@{ Sent = $false; Why = 'mail is off (SI_Mail_Mode = none)' } }
        if (@($smtp.Problems).Count) { return [pscustomobject]@{ Sent = $false; Why = (@($smtp.Problems) -join '; ') } }
        $prio = if ($Notice.Kind -eq 'failure') { 'High' } else { 'Normal' }
        $null = Send-SIGuardMailDefault -Smtp $smtp -To @($rcp.To) -Subject $Notice.Subject -Html (ConvertTo-SIProAutoMailHtml -Lines $Notice.Lines) -Priority $prio
        [pscustomobject]@{ Sent = $true; Why = '' }
    } catch { [pscustomobject]@{ Sent = $false; Why = $_.Exception.Message } }
}
