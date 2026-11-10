#Requires -Version 5.1
<#
    SecurityInsight -- setupSteps on the identified heartbeat (#1065, DESIGN 12c-0; Invardia's alignment gap no-setup-steps,
    checklist TEL-03, framework 0.1 A).

    THE FIELD (Invardia DESIGN ch 9 "Fleet consistency - the setup-step grid", agreed with SI 2026-11-03):
        setupSteps: [ { key, title, state, since?, how?, checkedAt?, detail? } ]   at most 50
          key        kebab-case, at most 60          title   at most 120
          state      ok | missing | n/a | unknown     how     updater | support-app | customer
          checkedAt  ISO time (UTC)                   detail  at most 200, plain words, NEVER a command
    Invardia takes it leniently (a bad item is dropped alone, never the heartbeat) and replaces the install's list whole on
    every heartbeat that carries it. The field is in Invardia's closed list of heartbeat keys (SETUP_STEPS_KEYS), so it
    never costs the record; it is still in the optional fields a refused record is sent again without.

    ONLY STEPS WITH A REAL CHECK. Each state below comes from a check that ran at this install -- the updater's own record
    of its last run (cfg.InstallState) or this heartbeat's own read -- never a guess. A step SecurityInsight cannot check
    yet is LEFT OUT (no entry), not sent as 'unknown': 'unknown' means "the check ran and could not tell".
      updater-keyvault   the updater may use its Key Vault hand-over key -- cfg.InstallState 'SecretHandover'
                         { state ok | missing, checkedUtc }, written by the updater on every run
      updater-database   the updater may change the database -- cfg.InstallState 'UpdateState': its last run named no
                         database-rights error (missing when it did)
      support-grant-jit  Invardia support's read-only database role and the just-in-time grant are installed -- this
                         heartbeat's read of cfg.SupportGrantStatus (Get-SISupportGrantStatus) -- AND (#1151 SEC-01) no STANDING
                         support admin is left: the updater's row 'SupportStanding' { state ok | missing | unknown, dbOwner,
                         group, checkedUtc, why } (setup\_shared\SI-SupportStandingUpdate.ps1). While it says standing db_owner
                         or SQL admin group membership is still there, the step reads 'missing'; no row yet = the grant alone
      mail-send-right    sending is restricted to the shared mailbox -- cfg.InstallState 'MailRestriction' (+ an
                         administrator's attestation); left out while mail is not set up
      identity-names     every identity follows id-si-<role> (framework 12.11c THE IDENTITY MOVE, checklist NAM-03) --
                         cfg.InstallState 'IdentityNames' { checkedUtc, roles: { <role>: { state ok | missing | unknown,
                         name, kind, objectId, standard } } }, written by the updater on EVERY update (its step
                         identity-names, setup\_shared\SI-IdentityNamesStep.ps1: the identity in use per role) and by the
                         identity move's Support-app route; ok only when every role is ok
      db-job             the database setup job caj-si-dbinit (framework SEC-08) -- cfg.InstallState 'DbJob', its own
                         result row { state ok | failed, at, run, by, n, why }; 'waiting' (written by the updater) = its
                         identity is not yet proven a member of the SQL admin group; left out while there is no row.
                         Framework §4.5 G4: the updater's own row 'DbJobMembership' { state ok | renewal-failed | gone |
                         missing, at, end } -- gone = missing (updates are held); renewal-failed keeps ok, said in the detail
      signin-app-owner   the web sign-in app owned by the updater (framework SECAUDIT-1a item 2) -- cfg.InstallState
                         'SignInAppOwner' { state, app, why?, checkedUtc }, written by the updater's owner step every update
      web-app-name       the web app under its standard name ca-si-management (an install moved to ca-si-web goes back;
                         'forwarding' = ca-si-web still forwards) -- cfg.InstallState 'WebAppName' { state, from, to, forwardSince?,
                         why?, checkedUtc }, written by the updater's move step; 'awaiting-signin-proof' = waiting for the
                         first sign-in on the new web app (the old one redirects there until then). Web app names are
                         not aligned: 'missing' ONLY for a move back to ca-si-management that is under way and stuck;
                         'kept', 'held', a row without a target and a row that moved toward ca-si-web = n/a
    The Invardia Support app's own database access is NOT a step here: Invardia checks it itself from the heartbeat's
    supportSqlAccess (its step support-arm).

    PURE apart from Read-SISetupStepRows (one read of cfg.InstallState through the caller's database seam). NEVER throws.
#>

function Get-SISetupStepsContract {
    <# The value of $script:SISetupSteps, made on first use in the scope that reads it. #>
    if ($null -eq $script:SISetupSteps) { $script:SISetupSteps = @{
        Max       = 50
        KeyRx     = '^[a-z][a-z0-9-]{0,59}$'
        TitleMax  = 120
        DetailMax = 200
        States    = @('ok', 'missing', 'n/a', 'unknown')
        Hows      = @('updater', 'support-app', 'customer')
        # the steps this release checks, in the order they are sent
        Steps     = [ordered]@{
            'updater-keyvault'  = @{ Title = 'The updater may use its Key Vault hand-over key'; How = 'customer' }
            'updater-database'  = @{ Title = 'The updater may change the SecurityInsight database'; How = 'customer' }
            'support-grant-jit' = @{ Title = 'Invardia support: read-only database role and the just-in-time grant'; How = 'support-app' }
            'mail-send-right'   = @{ Title = 'Mail sending is restricted to the shared mailbox'; How = 'customer' }
            'identity-names'    = @{ Title = 'Every SecurityInsight identity has its standard name (id-si-<role>)'; How = 'support-app' }
            'db-job'            = @{ Title = 'The database setup job runs as its own identity'; How = 'support-app' }
            'signin-app-owner'  = @{ Title = 'The web sign-in app is owned by the install''s updater'; How = 'support-app' }
            'web-app-name'      = @{ Title = 'The web app runs under its standard name (ca-si-management)'; How = 'updater' }
        }
        # the cfg.InstallState rows the checks read
        StateNames = @('SecretHandover', 'UpdateState', 'MailRestriction', 'MailRestrictionAttestation', 'IdentityNames', 'DbJob', 'DbJobMembership', 'SignInAppOwner', 'WebAppName', 'SupportStanding')
        # an update error that names the updater's database rights (the same words Get-SIHeartbeatWarnings reads as si-upd-0802)
        DbRightsRx = '(?i)db_ddladmin|db_securityadmin|permission was denied|permission denied in database|CREATE TABLE permission|ALTER permission|not have permission'
        # a detail that looks like something to run is never sent (Invardia drops it too)
        CommandRx  = '(?i)[\r\n]|\.ps1\b|\bpwsh\b|\baz |\bInvoke-|\s-Apply\b|\b(Set|New|Grant|Remove|Add)-[A-Z]'
    } }
    , $script:SISetupSteps
}
$script:SISetupSteps = $null; $null = Get-SISetupStepsContract

function ConvertTo-SISetupStepUtc {
    <# PURE. A time as yyyy-MM-ddTHH:mm:ssZ (UTC), or '' (nothing, DBNull, not a time). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return '' }
    $d = $null
    if ($Value -is [datetime]) { $d = $(if ($Value.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($Value, 'Utc') } else { $Value.ToUniversalTime() }) }
    else { try { $d = [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { return '' } }
    $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function New-SISetupStep {
    <# PURE. One entry in the agreed shape, or $null when the key / state / how is not one Invardia takes. The detail is
       plain text, at most 200 characters, and left out when it looks like a command. #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$State, [AllowEmptyString()][string]$CheckedAt = '',
          [AllowEmptyString()][string]$Detail = '', [AllowEmptyString()][string]$Since = '')
    $c = Get-SISetupStepsContract
    if ($Key -notmatch $c.KeyRx -or -not $c.Steps.Contains($Key) -or $State -notin $c.States) { return $null }
    $def = $c.Steps[$Key]
    $e = [ordered]@{ key = $Key; title = ([string]$def.Title).Substring(0, [Math]::Min(([string]$def.Title).Length, $c.TitleMax)); state = $State }
    if ("$Since".Trim() -and "$Since".Trim().Length -le 20) { $e.since = "$Since".Trim() }
    if ($def.How -in $c.Hows) { $e.how = $def.How }
    if ("$CheckedAt".Trim()) { $e.checkedAt = "$CheckedAt".Trim() }
    # a command is judged on the text as given (a line break is one of its signs), then the text is made plain
    $isCommand = ("$Detail" -match $c.CommandRx)
    $d = [regex]::Replace("$Detail", '[\x00-\x1F\x7F<>]', ' ')
    $d = [regex]::Replace($d, '\s+', ' ').Trim()
    if ($d -and -not $isCommand -and $d -notmatch $c.CommandRx) {
        if ($d.Length -gt $c.DetailMax) { $d = $d.Substring(0, $c.DetailMax - 3).TrimEnd() + '...' }
        $e.detail = $d
    }
    [pscustomobject]$e
}

function Get-SISetupStepRowValue {
    <# PURE. A cfg.InstallState row's Value by its Name ('' when there is none). Rows: objects or hashtables with Name, Value
       (and optionally UpdatedAt). #>
    param([AllowNull()][object[]]$Rows, [Parameter(Mandatory)][string]$Name, [string]$Field = 'Value')
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $n = if ($r -is [System.Collections.IDictionary]) { [string]$r['Name'] } elseif ($r.PSObject.Properties['Name']) { [string]$r.Name } else { '' }
        if ($n -ne $Name) { continue }
        $v = if ($r -is [System.Collections.IDictionary]) { $r[$Field] } elseif ($r.PSObject.Properties[$Field]) { $r.$Field } else { $null }
        if ($null -eq $v -or $v -is [DBNull]) { return '' }
        return $v
    }
    ''
}

function ConvertFrom-SISetupStepJson {
    <# PURE. A row's JSON value as an object, or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if (-not "$Text".Trim()) { return $null }
    try { "$Text" | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}

function Get-SISetupSteps {
    <#
        PURE. The heartbeat's setupSteps from the checks this install ran (see the file's help). Returns the entries in the
        catalog's order -- an empty array when no step could be checked (the caller then leaves the field out).
          -StateRows     cfg.InstallState rows (Name, Value[, UpdatedAt]) -- Read-SISetupStepRows
          -SupportGrant  this heartbeat's Get-SISupportGrantStatus answer (@{ Wire; Text }); $null = not read (left out)
    #>
    param([AllowNull()][object[]]$StateRows, [AllowNull()]$SupportGrant, [datetime]$NowUtc = [datetime]::UtcNow)
    $c = Get-SISetupStepsContract
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($e) if ($e -and $out.Count -lt $c.Max) { $out.Add($e) } }
    try {
        # updater-keyvault: the updater's own record of its hand-over key, every run
        $ho = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'SecretHandover'))
        if ($ho -and $ho.PSObject.Properties['state']) {
            $at = ConvertTo-SISetupStepUtc $(if ($ho.PSObject.Properties['checkedUtc']) { $ho.checkedUtc } else { Get-SISetupStepRowValue $StateRows 'SecretHandover' 'UpdatedAt' })
            switch ("$($ho.state)".Trim().ToLowerInvariant()) {
                'ok'      { & $add (New-SISetupStep -Key 'updater-keyvault' -State 'ok' -CheckedAt $at -Detail 'The updater read its Key Vault hand-over key on its last run.') }
                'missing' { & $add (New-SISetupStep -Key 'updater-keyvault' -State 'missing' -CheckedAt $at -Detail 'The updater may not use its Key Vault hand-over key: the updater setup must be run again with its role grants.') }
            }
        }
    } catch { }
    try {
        # updater-database: the updater's last run, as it recorded it
        $us = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'UpdateState'))
        if ($us) {
            $at = ConvertTo-SISetupStepUtc $(if ($us.PSObject.Properties['lastCheckUtc']) { $us.lastCheckUtc } else { Get-SISetupStepRowValue $StateRows 'UpdateState' 'UpdatedAt' })
            $err = if ($us.PSObject.Properties['error']) { "$($us.error)" } else { '' }
            if ($err -match $c.DbRightsRx) { & $add (New-SISetupStep -Key 'updater-database' -State 'missing' -CheckedAt $at -Detail 'The last update stopped on the updater''s database rights.') }
            elseif ($at) { & $add (New-SISetupStep -Key 'updater-database' -State 'ok' -CheckedAt $at -Detail 'The updater''s last run named no database-rights problem.') }
        }
    } catch { }
    try {
        # support-grant-jit: this heartbeat's own read of the support grant's status (every product database)
        if ($null -ne $SupportGrant) {
            $wire = if ($SupportGrant.PSObject.Properties['Wire']) { $SupportGrant.Wire } else { $null }
            $text = if ($SupportGrant.PSObject.Properties['Text']) { [string]$SupportGrant.Text } else { '' }
            $at = ConvertTo-SISetupStepUtc $NowUtc
            if ($wire) {
                $ro = if ($wire -is [System.Collections.IDictionary]) { $wire['readOnly'] } else { $wire.readOnly }
                if ($ro -eq $true) {
                    # #1151 SEC-01: installed is not enough -- the standing admin must be gone too (the updater's row)
                    $ss = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'SupportStanding'))
                    $ssState = if ($ss -and $ss.PSObject.Properties['state']) { "$($ss.state)".Trim().ToLowerInvariant() } else { '' }
                    $ssWhy = if ($ss -and $ss.PSObject.Properties['why']) { "$($ss.why)".Trim() } else { '' }
                    if ($ssState -eq 'missing') { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'missing' -CheckedAt $at -Detail ('Installed, but ' + $(if ($ssWhy) { $ssWhy.Substring(0, 1).ToLowerInvariant() + $ssWhy.Substring(1) } else { 'standing support admin remains.' }))) }
                    elseif ($ssState -eq 'unknown') { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'unknown' -CheckedAt $at -Detail 'Installed; whether standing support admin remains could not be read.') }
                    elseif ($ssState -eq 'ok') { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'ok' -CheckedAt $at -Detail 'Installed in every database; the read-only role is held; no standing admin.') }
                    else { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'ok' -CheckedAt $at -Detail 'Installed in every database; the read-only role is held.') }
                }
                elseif ($ro -eq $false) { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'missing' -CheckedAt $at -Detail 'The read-only support role or the just-in-time grant is missing in at least one database.') }
                else { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'unknown' -CheckedAt $at -Detail 'At least one database could not be read.') }
            } elseif ($text -match 'no support grant procedures yet') {
                & $add (New-SISetupStep -Key 'support-grant-jit' -State 'missing' -CheckedAt $at -Detail 'The just-in-time support grant is not installed yet (one Invardia support session).')
            } elseif ($text -match 'could not be read') {
                & $add (New-SISetupStep -Key 'support-grant-jit' -State 'unknown' -CheckedAt $at -Detail 'The support grant''s status could not be read.')
            }
        }
    } catch { }
    try {
        # mail-send-right: the restriction the mail setup recorded (+ an administrator's attestation); no record = no mail set up
        $mr = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'MailRestriction'))
        $att = [string](Get-SISetupStepRowValue $StateRows 'MailRestrictionAttestation')
        if ($mr -and $mr.PSObject.Properties['state']) {
            $at = ConvertTo-SISetupStepUtc (Get-SISetupStepRowValue $StateRows 'MailRestriction' 'UpdatedAt')
            switch ("$($mr.state)".Trim().ToLowerInvariant()) {
                { $_ -in @('verified', 'legacy-policy') } { & $add (New-SISetupStep -Key 'mail-send-right' -State 'ok' -CheckedAt $at -Detail 'Sending is restricted to the shared mailbox and verified.') }
                'unverified' {
                    if ("$att".Trim()) { & $add (New-SISetupStep -Key 'mail-send-right' -State 'ok' -CheckedAt $at -Detail 'Restricted to the shared mailbox; an administrator attested it.') }
                    else { & $add (New-SISetupStep -Key 'mail-send-right' -State 'unknown' -CheckedAt $at -Detail 'Restricted, but not verified: no test mailbox and no attestation.') }
                }
                'unrestricted' { & $add (New-SISetupStep -Key 'mail-send-right' -State 'missing' -CheckedAt $at -Detail 'The send right is not restricted to the shared mailbox; sending is refused until it is.') }
                'not-granted'  { & $add (New-SISetupStep -Key 'mail-send-right' -State 'missing' -CheckedAt $at -Detail 'SecurityInsight may not send as the shared mailbox yet.') }
                'error'        { & $add (New-SISetupStep -Key 'mail-send-right' -State 'unknown' -CheckedAt $at -Detail 'The restriction check failed; it runs again with the mail setup.') }
            }
        }
    } catch { }
    try {
        # identity-names: the identity move's own check of every role (name, kind, object id per role in the row)
        $idn = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'IdentityNames'))
        $roles = if ($idn -and $idn.PSObject.Properties['roles']) { $idn.roles } else { $null }
        if ($roles) {
            $parts = New-Object System.Collections.Generic.List[string]; $states = New-Object System.Collections.Generic.List[string]
            foreach ($p in @($roles.PSObject.Properties)) {
                $st = if ($p.Value -and $p.Value.PSObject.Properties['state']) { "$($p.Value.state)".Trim().ToLowerInvariant() } else { 'unknown' }
                if ($st -notin 'ok', 'missing', 'unknown') { $st = 'unknown' }
                $states.Add($st)
                $nm = if ($p.Value -and $p.Value.PSObject.Properties['name']) { "$($p.Value.name)".Trim() } else { '' }
                $parts.Add($(if ($st -eq 'ok' -or -not $nm) { '{0} {1}' -f $p.Name, $st } else { '{0} {1} ({2})' -f $p.Name, $st, $nm }))
            }
            if ($states.Count) {
                $all = if ($states -contains 'missing') { 'missing' } elseif ($states -contains 'unknown') { 'unknown' } else { 'ok' }
                $at = ConvertTo-SISetupStepUtc $(if ($idn.PSObject.Properties['checkedUtc']) { $idn.checkedUtc } else { Get-SISetupStepRowValue $StateRows 'IdentityNames' 'UpdatedAt' })
                & $add (New-SISetupStep -Key 'identity-names' -State $all -CheckedAt $at -Detail ('Identities: ' + ($parts -join ', ') + '.'))
            }
        }
    } catch { }
    try {
        # db-job (framework SEC-08, Invardia DESIGN ch 12 point 5): the database setup job caj-si-dbinit's own result row
        # (written by the job; 'waiting' by the updater while the job's identity is not proven a member of the admin group)
        $dj = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'DbJob'))
        if ($dj -and $dj.PSObject.Properties['state']) {
            $at = ConvertTo-SISetupStepUtc $(if ($dj.PSObject.Properties['at']) { $dj.at } else { Get-SISetupStepRowValue $StateRows 'DbJob' 'UpdatedAt' })
            $since = ConvertTo-SISetupStepUtc (Get-SISetupStepRowValue $StateRows 'DbJob' 'UpdatedAt')
            $why = if ($dj.PSObject.Properties['why']) { "$($dj.why)".Trim() } else { '' }
            # framework §4.5 SQL-ADMIN-GROUP G4: the updater's own check of the job identity's membership (its own row)
            $mb = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'DbJobMembership'))
            $mbState = if ($mb -and $mb.PSObject.Properties['state']) { "$($mb.state)".Trim().ToLowerInvariant() } else { '' }
            $mbEnd = if ($mb -and $mb.PSObject.Properties['end']) { ConvertTo-SISetupStepUtc $mb.end } else { '' }
            $mbAt = if ($mb -and $mb.PSObject.Properties['at']) { ConvertTo-SISetupStepUtc $mb.at } else { '' }
            if ($mbState -eq 'gone') {
                & $add (New-SISetupStep -Key 'db-job' -State 'missing' -CheckedAt $(if ($mbAt) { $mbAt } else { $at }) -Since $since -Detail 'Its identity is no longer a member of the SQL admin group; updates are held until it is again.')
            }
            else { switch ("$($dj.state)".Trim().ToLowerInvariant()) {
                'ok'      {
                    if ($mbState -eq 'renewal-failed') { & $add (New-SISetupStep -Key 'db-job' -State 'ok' -CheckedAt $at -Since $since -Detail ('Its last run read back every database user. Its SQL admin group membership{0} could not be renewed yet; the updater tries again.' -f $(if ($mbEnd) { ' ends ' + $mbEnd.Substring(0, 10) + ' and' } else { '' }))) }
                    else { & $add (New-SISetupStep -Key 'db-job' -State 'ok' -CheckedAt $at -Since $since -Detail 'Its last run read back every database user of the install.') }
                }
                'failed'  { & $add (New-SISetupStep -Key 'db-job' -State 'missing' -CheckedAt $at -Since $since -Detail ('Its last run failed' + $(if ($why) { ': ' + $why } else { '.' }))) }
                'waiting' { & $add (New-SISetupStep -Key 'db-job' -State 'missing' -CheckedAt $at -Since $since -Detail 'Not run yet: its identity must be added once to the SQL admin group.') }
            } }
        }
    } catch { }
    try {
        # signin-app-owner: the updater's owner step (SignInAppOwner) -- owned, or which Support-app step it waits for
        $so = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'SignInAppOwner'))
        if ($so -and $so.PSObject.Properties['state']) {
            $at = ConvertTo-SISetupStepUtc $(if ($so.PSObject.Properties['checkedUtc']) { $so.checkedUtc } else { Get-SISetupStepRowValue $StateRows 'SignInAppOwner' 'UpdatedAt' })
            switch ("$($so.state)".Trim().ToLowerInvariant()) {
                'owned'              { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'ok' -CheckedAt $at -Detail 'Owned by the updater, which proved it may change it; the Support app is no longer an owner.') }
                'owned-support-kept' { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'ok' -CheckedAt $at -Detail 'Owned by the updater; the Support app is still an owner (the updater tries again).') }
                'needs-support-step' { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'missing' -CheckedAt $at -Detail 'Waiting for a Support-app step that adds the updater as an owner.') }
                'needs-permission'   { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'missing' -CheckedAt $at -Detail 'Waiting for a Support-app step that grants the updater Application.ReadWrite.OwnedBy.') }
                'proof-failed'       { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'missing' -CheckedAt $at -Detail 'The updater owns it but could not prove it may change it; it tries again.') }
                'unknown'            { & $add (New-SISetupStep -Key 'signin-app-owner' -State 'unknown' -CheckedAt $at -Detail 'The updater could not check who owns it.') }
            }
        }
    } catch { }
    try {
        # web-app-name: the updater's move step (WebAppName); 'awaiting-signin-proof' = waiting for the first sign-in
        $wn = ConvertFrom-SISetupStepJson ([string](Get-SISetupStepRowValue $StateRows 'WebAppName'))
        if ($wn -and $wn.PSObject.Properties['state']) {
            $at = ConvertTo-SISetupStepUtc $(if ($wn.PSObject.Properties['checkedUtc']) { $wn.checkedUtc } else { Get-SISetupStepRowValue $StateRows 'WebAppName' 'UpdatedAt' })
            $st = "$($wn.state)".Trim().ToLowerInvariant()
            # web app names are not aligned (existing installs keep theirs): the step is 'missing' ONLY for a move back to
            # ca-si-management that is under way and stuck; kept / held / a row without a target / a row of an older release
            # that moved toward ca-si-web = n/a
            $toMgmt = $wn.PSObject.Properties['to'] -and "$($wn.to)".Trim() -ieq 'ca-si-management'
            $stepState = if ($st -eq 'moved') { 'ok' } elseif ($st -in 'forwarding', 'awaiting-signin-proof' -and $toMgmt) { 'ok' } elseif ($toMgmt -and $st -notin 'kept', 'held', '') { 'missing' } else { 'n/a' }
            $detail = if ($stepState -eq 'n/a') { 'This install keeps its web app name; nothing to move.' } else { switch ($st) {
                'moved'                 { 'The web app runs as ca-si-management.' }
                'kept'                  { 'This install keeps its web app name; nothing to move.' }
                'held'                  { 'A second web app exists beside the web app but is not in use; nothing is changed until the move is finished or undone.' }
                'forwarding'            { 'The web app runs as ca-si-management again; ca-si-web sends people there for a few days, then it is removed.' }
                'awaiting-signin-proof' { 'The web app runs as ca-si-management again; ca-si-web sends people there and is removed after the first sign-in.' }
                'waiting-owner'         { 'Waiting for the updater to own the web sign-in app; the web app keeps serving as it is.' }
                'custom-domain'         { 'ca-si-management is ready; the custom domain on ca-si-web is moved by a Support-app step first.' }
                'public-address'        { 'ca-si-management is ready; the public address setting names a custom host, so ca-si-web stays until it is changed.' }
                default                 { 'Not moved yet (' + $st + '); the old web app keeps serving and the next update tries again.' }
            } }
            & $add (New-SISetupStep -Key 'web-app-name' -State $stepState -CheckedAt $at -Detail $detail)
        }
    } catch { }
    $out.ToArray()
}

function Get-SISetupStepRowsSql {
    <# PURE. The ONE read of cfg.InstallState the checks need (the table may be missing on an older schema: no rows). #>
    $names = ((Get-SISetupStepsContract).StateNames | ForEach-Object { "N'$_'" }) -join ', '
    "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Name, Value, UpdatedAt FROM cfg.InstallState WHERE Name IN ($names)"
}

function Read-SISetupStepRows {
    <# The cfg.InstallState rows through the caller's settings-database seam { param($Sql, $Params, $Mode) }. Never throws:
       no seam, no table or a failed read = no rows. #>
    param([scriptblock]$Invoke)
    if (-not $Invoke) { return }
    try { @(& $Invoke (Get-SISetupStepRowsSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) } catch { }
}
