#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE SUPPORT LEVEL SET IN THE INVARDIA PORTAL, APPLIED BY THE UPDATER (framework "SUPPORT ACCESS -
    THE CUSTOMER CONTROLS IT IN THE INVARDIA PORTAL", point 2; Invardia + SI 2026-11-04).

    The customer sets the Invardia Support app's level in the Invardia portal. The UPDATER -- never the engine (the engine may
    only EXECUTE the four signed support-grant procedures; SECAUDIT-1a: "the engine can never name a principal or raise a
    level") -- reads it with its OWN authenticated call:
        GET <base>/api/support/consent   header X-Invardia-Install-Key: <the install key>
        -> 200 { environmentId, product, supportConsent: { level: 'troubleshoot' | 'setup' | 'none', appId?: '<guid>' } }
    (the answer is for the key's own environment + product) and applies it on every run in the Pro database:
      troubleshoot | setup   row 1 of cfg.SupportConsent = that level, Source 'customer' (the customer set it), ConsentedBy
                             'Invardia portal', the Support app = the answer's appId, else the one recorded there
      none / anything else   the row is removed: the support grant refuses to open (the read-only user is NOT touched --
                             framework point 5: never lose access)
      Invardia unreachable, or an answer without supportConsent: nothing is changed -- the last level stays
    The consent trigger lets the updater write exactly such a row, or remove the row. Once Invardia has answered, the
    marker cfg.InstallState 'SupportConsentPortal' stops the DERIVED consent (SI-SupportGrantUpdate.ps1) from being made
    again, so a level the portal took away never comes back. The signed procedures are unchanged: a session can never
    exceed the level. Every line says what was done or why not; nothing here fails the update.
    PURE apart from the seams: -Get { param([string]$Uri, [hashtable]$Headers) } (the parsed answer; throws on a refusal),
    -Sql { param([string]$Query, $Params, [string]$Mode) } on the Pro database. PS 5.1 safe; no module.
#>

$script:SISupportPortalConsent = @{
    By      = 'Invardia portal'
    Path    = '/api/support/consent'
    Header  = 'X-Invardia-Install-Key'
    Base    = 'https://invardia.com'
    Levels  = @('troubleshoot', 'setup')
    GuidRx  = '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
}

function ConvertFrom-SISupportPortalAnswer {
    <# PURE. Invardia's answer -> @{ Ok; Level ('troubleshoot' | 'setup' | 'none'); AppId (lower-case guid or ''); Why }. An
       answer without supportConsent is NOT ok (nothing is changed); a level it does not know is 'none'. #>
    param($Answer)
    $bad = { param($w) [pscustomobject]@{ Ok = $false; Level = ''; AppId = ''; Why = $w } }
    if ($null -eq $Answer) { return (& $bad 'no answer') }
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $sc = & $get $Answer 'supportConsent'
    if ($null -eq $sc) { return (& $bad 'the answer carries no supportConsent') }
    $lv = ("" + (& $get $sc 'level')).Trim().ToLowerInvariant()
    if ($lv -notin $script:SISupportPortalConsent.Levels) { $lv = 'none' }
    $app = ("" + (& $get $sc 'appId')).Trim().ToLowerInvariant()
    if ($app -notmatch $script:SISupportPortalConsent.GuidRx) { $app = '' }
    [pscustomobject]@{ Ok = $true; Level = $lv; AppId = $app; Why = '' }
}

function Get-SISupportPortalConsentSql {
    <# PURE. THE write (parameters @Level: troubleshoot | setup | '' = none; @AppId: '' = keep the recorded one; @By), then the
       marker cfg.InstallState 'SupportConsentPortal'. ONE row back: Outcome (applied | removed | unchanged | no-app),
       PrevLevel, PrevBy, Level, Consent (the row now: level|source|by; '' = none). #>
    @'
DECLARE @pl nvarchar(16), @pb nvarchar(256), @pa uniqueidentifier, @app uniqueidentifier, @o nvarchar(16);
SELECT @pl = [Level], @pb = ConsentedBy, @pa = AppId FROM cfg.SupportConsent WHERE Id = 1;
SET @app = COALESCE(TRY_CONVERT(uniqueidentifier, NULLIF(@AppId, N'')), @pa);
IF ISNULL(@Level, N'') = N''
BEGIN
    IF @pl IS NULL SET @o = N'unchanged';
    ELSE BEGIN DELETE FROM cfg.SupportConsent WHERE Id = 1; SET @o = N'removed'; END
END
ELSE IF @app IS NULL SET @o = N'no-app';
ELSE IF @pl = @Level AND @pb = N'Invardia portal' AND @pa = @app SET @o = N'unchanged';
ELSE IF @pl IS NULL
BEGIN
    INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, @app, @Level, N'customer', N'Invardia portal');
    SET @o = N'applied';
END
ELSE
BEGIN
    UPDATE cfg.SupportConsent SET AppId = @app, [Level] = @Level, Source = N'customer', ConsentedBy = N'Invardia portal', ConsentedUtc = SYSUTCDATETIME() WHERE Id = 1;
    SET @o = N'applied';
END
IF @o <> N'no-app'
BEGIN
    DECLARE @mark nvarchar(400) = LEFT(N'{"level":"' + CASE WHEN ISNULL(@Level, N'') = N'' THEN N'none' ELSE @Level END + N'","checkedUtc":"' + CONVERT(nvarchar(19), SYSUTCDATETIME(), 126) + N'Z"}', 400);
    UPDATE cfg.InstallState SET Value = @mark, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = LEFT(@By, 256) WHERE Name = N'SupportConsentPortal';
    IF @@ROWCOUNT = 0 INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'SupportConsentPortal', @mark, LEFT(@By, 256));
END
SELECT @o AS Outcome, ISNULL(@pl, N'') AS PrevLevel, ISNULL(@pb, N'') AS PrevBy, ISNULL(@Level, N'') AS [Level],
       ISNULL((SELECT [Level] + N'|' + Source + N'|' + ConsentedBy FROM cfg.SupportConsent WHERE Id = 1), N'') AS Consent;
'@
}

function Invoke-SISupportPortalConsent {
    <#
        The level set in the Invardia portal, applied (see the header). @{ Action (applied | removed | unchanged | no-app |
        planned | skipped | failed); Level; Line; Change (@{ From; To } or $null) }. Never throws; nothing is changed when
        Invardia cannot be read. Every change is READ BACK.
    #>
    param([Parameter(Mandatory)][scriptblock]$Get, [Parameter(Mandatory)][scriptblock]$Sql, [AllowEmptyString()][string]$InstallKey,
          [string]$BaseUrl = '', [switch]$WhatIf)
    $c = $script:SISupportPortalConsent
    $out = { param($a, $lv, $l, $ch) [pscustomobject]@{ Action = $a; Level = $lv; Line = $l; Change = $ch } }
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
    if (-not "$InstallKey".Trim()) { return (& $out 'skipped' '' 'support consent (Invardia portal): not read -- this install has no install key yet; the last level stays' $null) }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $c.Base }
    try { $ans = & $Get ($base + $c.Path) @{ $c.Header = "$InstallKey".Trim() } }
    catch { return (& $out 'skipped' '' ('support consent (Invardia portal): Invardia could not be read ({0}) -- the last level stays' -f (($_.Exception.Message -split "`n")[0])) $null) }
    $p = ConvertFrom-SISupportPortalAnswer -Answer $ans
    if (-not $p.Ok) { return (& $out 'skipped' '' ('support consent (Invardia portal): {0} -- the last level stays' -f $p.Why) $null) }
    if ($WhatIf) { return (& $out 'planned' $p.Level ('support consent (Invardia portal): would apply level {0}' -f $p.Level) $null) }
    try {
        # 'reader': the updater's Pro store reads rows only in that mode (any other mode runs the statement without an answer)
        $r = @(& $Sql (Get-SISupportPortalConsentSql) @{ Level = $(if ($p.Level -eq 'none') { '' } else { $p.Level }); AppId = $p.AppId; By = 'caj-si-updater' } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $o = & $val $r 'Outcome'; $now = & $val $r 'Consent'
        $from = if (& $val $r 'PrevLevel') { '{0} ({1})' -f (& $val $r 'PrevLevel'), (& $val $r 'PrevBy') } else { 'none' }
        switch ($o) {
            'unchanged' { return (& $out 'unchanged' $p.Level '' $null) }
            'no-app' { return (& $out 'no-app' $p.Level ('support consent (Invardia portal): level {0} received, but no Support app is known here (Invardia sent no app id and none is recorded) -- not applied' -f $p.Level) $null) }
            'removed' {
                if ($now) { return (& $out 'failed' 'none' ('support consent (Invardia portal): level none received, but the consent still reads {0} -- the next update tries again' -f $now) $null) }
                return (& $out 'removed' 'none' ('support consent (Invardia portal): {0} -> none (the level set in the Invardia portal), read back' -f $from) ([pscustomobject]@{ From = $from; To = 'none' }))
            }
            'applied' {
                if ($now -ne ('{0}|customer|{1}' -f $p.Level, $c.By)) { return (& $out 'failed' $p.Level ('support consent (Invardia portal): level {0} sent, but the row reads {1} -- the next update tries again' -f $p.Level, $(if ($now) { $now } else { 'nothing' })) $null) }
                return (& $out 'applied' $p.Level ('support consent (Invardia portal): {0} -> {1} (the level set in the Invardia portal), read back' -f $from, $p.Level) ([pscustomobject]@{ From = $from; To = $p.Level }))
            }
            default { return (& $out 'failed' $p.Level 'support consent (Invardia portal): the database gave no answer -- the next update tries again' $null) }
        }
    } catch { & $out 'failed' $p.Level ('support consent (Invardia portal): not applied ({0}) -- the next update tries again' -f (($_.Exception.Message -split "`n")[0])) $null }
}

# =====================================================================================================================
#  #1021 (found live at an install 2026-11-04): THE CONSENT IN EVERY PRODUCT DATABASE. The support grant's procedures are in
#  every product database (the Pro database, the identity ledger, the data database) and each checks ITS OWN cfg.SupportConsent
#  -- the portal's level written into the Pro database only made the ledger refuse with no-consent and the grant was rolled
#  back. So on every run the updater MIRRORS the Pro database's consent into the other product databases (the list the
#  database setup job recorded: cfg.InstallState 'SupportGrantDatabases'), read back. It can write only what the consent
#  trigger lets si_updater write: a row from the Invardia portal (Source customer, ConsentedBy 'Invardia portal'), or no
#  row. A consent the customer's admin or a derived step wrote in the Pro database is copied by the database setup job (it
#  is the owner there). Never written by the Support app. Never fails the update.
# =====================================================================================================================

function Get-SISupportConsentMirrorSql {
    <# PURE. In ONE other product database: the portal's row (@Level troubleshoot | setup, @AppId) written, or (@Level '')
       the row removed; nothing when the support grant's table is not there. ONE row back: Outcome (applied | removed |
       unchanged | no-table), Consent (the row now: level|source|by|appid; '' = none). No marker: cfg.InstallState may not be
       there. #>
@'
DECLARE @o nvarchar(16) = N'no-table';
IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL
BEGIN
    DECLARE @pl nvarchar(16), @pb nvarchar(256), @pa uniqueidentifier, @ps nvarchar(16);
    SELECT @pl = [Level], @pb = ConsentedBy, @pa = AppId, @ps = Source FROM cfg.SupportConsent WHERE Id = 1;
    IF ISNULL(@Level, N'') = N''
    BEGIN
        IF @pl IS NULL SET @o = N'unchanged';
        ELSE BEGIN DELETE FROM cfg.SupportConsent WHERE Id = 1; SET @o = N'removed'; END
    END
    ELSE IF @pl = @Level AND @pb = N'Invardia portal' AND @ps = N'customer' AND @pa = CONVERT(uniqueidentifier, @AppId) SET @o = N'unchanged';
    ELSE IF @pl IS NULL BEGIN INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, CONVERT(uniqueidentifier, @AppId), @Level, N'customer', N'Invardia portal'); SET @o = N'applied'; END
    ELSE BEGIN UPDATE cfg.SupportConsent SET AppId = CONVERT(uniqueidentifier, @AppId), [Level] = @Level, Source = N'customer', ConsentedBy = N'Invardia portal', ConsentedUtc = SYSUTCDATETIME() WHERE Id = 1; SET @o = N'applied'; END
END
SELECT @o AS Outcome,
       CASE WHEN OBJECT_ID(N'cfg.SupportConsent') IS NULL THEN N'' ELSE ISNULL((SELECT [Level] + N'|' + Source + N'|' + ConsentedBy + N'|' + LOWER(CONVERT(nvarchar(36), AppId)) FROM cfg.SupportConsent WHERE Id = 1), N'') END AS Consent;
'@
}

function Get-SISupportConsentProReadSql {
    <# PURE. READ ONLY: the Pro database's consent row (level|source|by|appid; '-' = no table), and the list the job recorded. #>
@'
SELECT CASE WHEN OBJECT_ID(N'cfg.SupportConsent') IS NULL THEN N'-' ELSE ISNULL((SELECT [Level] + N'|' + Source + N'|' + ConsentedBy + N'|' + LOWER(CONVERT(nvarchar(36), AppId)) FROM cfg.SupportConsent WHERE Id = 1), N'') END AS Consent,
       CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportGrantDatabases'), N'') END AS Databases;
'@
}

function Invoke-SISupportConsentMirror {
    <#
        The Pro database's consent mirrored into each other product database (see the block above). -ProSql: the Pro database
        { param($Query, $Params, $Mode) }; -Open { param([string]$Database) } -> the same seam for that database (throws when
        it cannot be opened). Returns @{ Lines[]; Results (@{ Database; Action; Consent }) }. Never throws; every write is
        READ BACK. A Pro consent the updater may not write elsewhere (the customer's admin's, or derived) is one line.
    #>
    param([Parameter(Mandatory)][scriptblock]$ProSql, [Parameter(Mandatory)][scriptblock]$Open)
    $lines = New-Object System.Collections.Generic.List[string]; $res = New-Object System.Collections.Generic.List[object]
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
    $by = 'Invardia portal'
    try {
        $row = @(& $ProSql (Get-SISupportConsentProReadSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $consent = & $val $row 'Consent'
        $dbs = @((& $val $row 'Databases') -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z0-9_.-]{1,128}$' } | Select-Object -Unique)
        if ($consent -eq '-' -or -not $dbs.Count) { return [pscustomobject]@{ Lines = $lines.ToArray(); Results = $res.ToArray() } }
        $level = ''; $app = ''
        if ($consent) {
            $p = $consent -split '\|'
            if ($p.Count -lt 4 -or $p[1] -ne 'customer' -or $p[2] -ne $by) {
                $lines.Add(('support consent: the Pro database''s consent ({0}) was not given in the Invardia portal -- the database setup job copies it into {1}' -f $p[0], ($dbs -join ', ')))
                return [pscustomobject]@{ Lines = $lines.ToArray(); Results = $res.ToArray() }
            }
            $level = $p[0]; $app = $p[3]
        }
        $want = if ($level) { '{0}|customer|{1}|{2}' -f $level, $by, $app } else { '' }
        foreach ($d in $dbs) {
            try {
                $sql = & $Open $d
                $r = @(& $sql (Get-SISupportConsentMirrorSql) @{ Level = $level; AppId = $app } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
                $o = & $val $r 'Outcome'; $now = & $val $r 'Consent'
                if ($o -eq 'no-table') { $res.Add([pscustomobject]@{ Database = $d; Action = 'no-table'; Consent = '' }); continue }
                if ($now -ne $want) {
                    $lines.Add(('WARNING: support consent: {0} reads {1} after the mirror, not the Pro database''s {2} -- the next run tries again' -f $d, $(if ($now) { $now } else { 'none' }), $(if ($level) { $level } else { 'none' })))
                    $res.Add([pscustomobject]@{ Database = $d; Action = 'failed'; Consent = $now }); continue
                }
                $res.Add([pscustomobject]@{ Database = $d; Action = $o; Consent = $now })
                if ($o -in 'applied', 'removed') { $lines.Add(('support consent: {0} now {1} (the Pro database''s, from the Invardia portal), read back' -f $d, $(if ($level) { $level } else { 'none' }))) }
            } catch {
                $lines.Add(('WARNING: support consent: {0} was not mirrored ({1}) -- the next run tries again' -f $d, (($_.Exception.Message -split "`n")[0])))
                $res.Add([pscustomobject]@{ Database = $d; Action = 'failed'; Consent = '' })
            }
        }
    } catch { $lines.Add(('WARNING: support consent: the Pro database''s consent could not be read for the mirror ({0})' -f (($_.Exception.Message -split "`n")[0]))) }
    [pscustomobject]@{ Lines = $lines.ToArray(); Results = $res.ToArray() }
}
