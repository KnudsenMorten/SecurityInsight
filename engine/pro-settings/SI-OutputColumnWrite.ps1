#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE OUTPUT COLUMN WRITER: one output column's customer state, written EXACTLY as the web app
    writes an Admin's change on Configuration > Connectors > Fields sent.

    The row: cfg.ItemOverride, Kind 'datamodel', ItemKey 'outputs/<output>:<column target>', Format 'json', State
      override  the column with its body { "target", "from", "op"?, "as"?, "position"? } -- the web app's
                OutputMapRules.Body (pro-management\src\SI.Management.Core\ProData\OutputMaps.cs). A column shipped
                switched OFF ("off": true in data-model\outputs\<output>.locked.json) is switched ON by this row: the body
                carries no "off", and the run's data model uses the override instead of the shipped column.
      disable   the shipped column is not sent
      inherit   back to the shipped column: the row is REMOVED
    BaseVersion / BaseHash are the live cfg.Template row of the same key, read inside the statement; the cfg.ChangeLog row
    (Name = the key, Scope 'item', Kind, Action Set | Reset, Old / New = State[:BodyJson], ChangedBy, Reason) is written in
    the SAME transaction.

    THE STATEMENT IS THE WEB APP'S OWN: Get-SIProOutputColumnWriteSql is ItemOverrideRepository.WriteSql
    (pro-management\src\SI.Management.Web\Changes\ItemOverrideRepository.cs) character for character, sent with the same
    parameters (Kind, Key, State, Body, Format, By, Reason) -- a test holds the two texts equal -- so a value the update
    writes is the row an Admin's change writes. Its own file, so the updater image carries it without the settings layer
    (setup\_shared\SI-ControlPlaneValues.ps1, SI_UPDATER_OUTPUTS). PS 5.1 and 7; no module.
#>

function Get-SIProOutputColumnWriteSql {
    <# PURE. ItemOverrideRepository.WriteSql, character for character (a test compares). #>
    @'
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.ItemOverride') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT State + COALESCE(N':' + BodyJson, N'') FROM cfg.ItemOverride WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND ItemKey = @Key);
DECLARE @BaseVersion nvarchar(32) = NULL, @BaseHash char(64) = NULL;
IF OBJECT_ID(N'cfg.Template') IS NOT NULL
    SELECT @BaseVersion = [Version], @BaseHash = COALESCE(ContentHash, BodyHash) FROM cfg.Template WHERE Kind = @Kind AND ItemKey = @Key AND RetiredAt IS NULL;
IF @State = N'inherit'
    DELETE FROM cfg.ItemOverride WHERE Kind = @Kind AND ItemKey = @Key;
ELSE IF @old IS NOT NULL
    UPDATE cfg.ItemOverride SET State = @State, BodyJson = @Body, Format = @Format, BaseVersion = @BaseVersion, BaseHash = @BaseHash, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND ItemKey = @Key;
ELSE
    INSERT cfg.ItemOverride (Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedBy) VALUES (@Kind, @Key, @State, @Body, @Format, @BaseVersion, @BaseHash, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, N'item', @Kind, CASE WHEN @State = N'inherit' THEN N'Reset' ELSE N'Set' END, @old, @State + COALESCE(N':' + @Body, N''), @By, @Reason);
COMMIT;
SELECT N'Saved' AS Outcome;
'@
}

function Get-SIProOutputColumnReadSql {
    <# PURE. ItemOverrideRepository.ReadSql, character for character (a test compares). #>
    @'
IF OBJECT_ID(N'cfg.ItemOverride') IS NOT NULL
SELECT Kind, ItemKey, State, BodyJson, Format, BaseVersion, BaseHash, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version
FROM cfg.ItemOverride
WHERE Kind = @Kind AND ItemKey = @Key;
'@
}

function Get-SIProOutputColumnKey {
    <# PURE. The data-model key of one output column -- OutputMapRules.Key. #>
    param([Parameter(Mandatory)][string]$Output, [Parameter(Mandatory)][string]$Target)
    'outputs/' + $Output + ':' + $Target
}

function Get-SIProOutputColumnBody {
    <#
        PURE. The override body of a column -- OutputMapRules.Body: { "target", "from", "op"?, "as"?, "position"? } in that
        order, nothing else (a shipped column's "off" is never carried: the override IS the column switched on).
    #>
    param([Parameter(Mandatory)]$Column)
    $g = { param($n) $p = $Column.PSObject.Properties[$n]; if ($Column -is [System.Collections.IDictionary]) { if ($Column.Contains($n)) { $Column[$n] } else { $null } } elseif ($p) { $p.Value } else { $null } }
    $o = [ordered]@{ target = [string](& $g 'target'); from = [string](& $g 'from') }
    $op = [string](& $g 'op'); if (-not [string]::IsNullOrWhiteSpace($op)) { $o['op'] = $op.Trim() }
    $as = [string](& $g 'as'); if (-not [string]::IsNullOrWhiteSpace($as)) { $o['as'] = $as.Trim() }
    $pos = & $g 'position'; if ($null -ne $pos -and "$pos" -ne '') { $o['position'] = [int]$pos }
    ConvertTo-Json -InputObject $o -Compress
}

function Read-SIProOutputColumn {
    <# One output column's cfg.ItemOverride row: @{ State; BodyJson; UpdatedBy } or $null when there is none. Throws on a SQL error. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Key)
    $rows = @(& $Store.Invoke (Get-SIProOutputColumnReadSql) ([ordered]@{ Kind = 'datamodel'; Key = $Key }) 'reader' | ForEach-Object { $_ })
    $r = $rows | Where-Object { $_ } | Select-Object -First 1
    if (-not $r) { return $null }
    $get = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
    $s = & $get 'State'; $b = & $get 'BodyJson'; $u = & $get 'UpdatedBy'
    if ($null -eq $s -or $s -is [System.DBNull]) { return $null }
    [pscustomobject]@{ State = [string]$s; BodyJson = $(if ($null -eq $b -or $b -is [System.DBNull]) { $null } else { [string]$b }); UpdatedBy = $(if ($null -eq $u -or $u -is [System.DBNull]) { $null } else { [string]$u }) }
}

function Test-SIProOutputColumnWrite {
    <# PURE. The reasons a write is refused (empty = accepted): the key, the state, and an override's body naming its key. #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$State, [AllowNull()][AllowEmptyString()][string]$Body)
    $m = [regex]::Match($Key, '^outputs/([a-z][a-z0-9\-]{0,60}):(.+)$')
    if (-not $m.Success -or $Key.Length -gt 128 -or $Key -match '[\x00-\x1f]') { return @(("'{0}' is not an output column (outputs/<output>:<column>, at most 128 characters)" -f $Key)) }
    if ($State -cnotin 'override', 'disable', 'inherit') { return @(("'{0}' is not a state (override, disable, inherit)" -f $State)) }
    if ($State -ne 'override') { return @() }
    if ([string]::IsNullOrWhiteSpace($Body)) { return @('the column is empty') }
    try { $o = ConvertFrom-Json -InputObject $Body -ErrorAction Stop } catch { return @('the column is not valid JSON') }
    if ($o -isnot [System.Management.Automation.PSCustomObject]) { return @('a column must be a JSON object') }
    $why = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($o.PSObject.Properties)) { if ($p.Name -cnotin 'target', 'from', 'op', 'as', 'position') { $why.Add(("'{0}' is not part of a column (target, from, op, as, position)" -f $p.Name)) } }
    if ([string]$o.target -cne $m.Groups[2].Value) { $why.Add(("the target must be '{0}' -- the key names the column" -f $m.Groups[2].Value)) }
    if ([string]::IsNullOrWhiteSpace([string]$o.from)) { $why.Add('the column reads nothing') }
    $why.ToArray()
}

function Set-SIProOutputColumn {
    <#
        Write one output column's state through the web app's own statement (Get-SIProOutputColumnWriteSql) and its
        parameters. -State override (with -Body) | disable | inherit (the row is removed). Validated first: nothing is sent
        for a refused write (throws with the reason). Returns the statement's outcome: 'Saved' | 'Missing' (no
        cfg.ItemOverride yet -- nothing written).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$State, [AllowNull()][AllowEmptyString()][string]$Body,
          [Parameter(Mandatory)][string]$ChangedBy, [string]$Reason = '')
    $why = @(Test-SIProOutputColumnWrite -Key $Key -State $State -Body $Body)
    if ($why.Count) { throw ("datamodel/{0} is not valid: {1}" -f $Key, ($why -join '; ')) }
    $r = $(if ([string]::IsNullOrWhiteSpace($Reason)) { '' } else { $Reason.Trim() })
    if ($r.Length -gt 400) { $r = $r.Substring(0, 400) }
    $by = $(if ($ChangedBy.Length -gt 256) { $ChangedBy.Substring(0, 256) } else { $ChangedBy })
    $p = [ordered]@{ Kind = 'datamodel'; Key = $Key; State = $State; Body = $(if ($State -eq 'override') { ([string]$Body).TrimStart([char]0xFEFF) } else { $null }); Format = 'json'; By = $by; Reason = $r }
    $rows = @(& $Store.Invoke (Get-SIProOutputColumnWriteSql) $p 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
    $o = $null
    if ($rows.Count) { $x = $rows[0]; $o = $(if ($x -is [System.Collections.IDictionary]) { $x['Outcome'] } else { $x.Outcome }) }
    if ([string]$o -eq 'Missing') { return 'Missing' }
    if ([string]$o -ne 'Saved') { throw 'the output column write returned no outcome' }
    'Saved'
}
