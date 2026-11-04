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
                         heartbeat's read of cfg.SupportGrantStatus (Get-SISupportGrantStatus)
      mail-send-right    sending is restricted to the shared mailbox -- cfg.InstallState 'MailRestriction' (+ an
                         administrator's attestation); left out while mail is not set up
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
        }
        # the cfg.InstallState rows the checks read
        StateNames = @('SecretHandover', 'UpdateState', 'MailRestriction', 'MailRestrictionAttestation')
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
                if ($ro -eq $true) { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'ok' -CheckedAt $at -Detail 'Installed in every database; the read-only role is held.') }
                elseif ($ro -eq $false) { & $add (New-SISetupStep -Key 'support-grant-jit' -State 'missing' -CheckedAt $at -Detail 'The read-only support role is missing in at least one database.') }
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
