#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE SETTINGS STORE (REQUIREMENTS §9.2, Pro-1).

    In Pro every setting lives in SQL (cfg.Setting, sql\si-pro-settings.sql) and the launcher loads it at run start as
    the CLOSEST configuration layer: shipped defaults and the files load first, then this. Engines are unchanged -- they
    see the same $global: values a Community install sets in files.

    🔒 FAIL CLOSED (operator, 2026-10-02): "SQL unreachable at run start = the run FAILS". A Pro install's settings are
    authoritative; running on whatever the files happen to say instead would be a silent, wrong run. The same goes for a
    row that does not validate -- it is refused, and the run stops with the reason, rather than handing an engine a bad
    value.

    The validation is the Community Settings page's own (engine\pro-settings\SI-Settings.ps1: the catalog and
    Test-SISettingValue), so a value is checked by the same rules whichever edition wrote it.
    Everything here except the store's default Invoke and Invoke-SIProSettingsLayer is pure and tested directly.
#>

$script:SIProRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# Azure access (Log Analytics: has any run ever ended well -- Get-SIProSettingsGoodRunCount): plain REST, no modules
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
if (-not (Get-Command Test-SISettingValue -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Settings.ps1'))
}
# Phase C: templates, item overrides, exemptions and the materialisation of every configuration family.
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ProConfig.ps1'))
# #260: the audit trail's PowerShell writer (Write-SIAuditEvent) -- every Pro tool that opens the store can record its steps.
. ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Audit.ps1'))
# the install's update ring (Read-SIInstallRingFacts): read at run start for the ring every status report carries
if (-not (Get-Command -Name Read-SIInstallRingFacts -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '_shared', 'SI-InstallRing.ps1')) }

function Get-SIProTokenCacheUntil {
    <#
        PURE. How long a SQL access token may be reused: until 5 minutes before its OWN expiry (the JWT 'exp' claim), never
        longer than 45 minutes. A token that cannot be read keeps the 45 minutes (the sign-in retry covers it). customer G
        2026-10-09: a managed-identity token can arrive with minutes left -- held for a fixed 45 it expired mid-run.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Token, [datetime]$Now = [datetime]::UtcNow)
    $max = $Now.AddMinutes(45)
    try {
        $part = ([string]$Token).Split('.')[1]
        $part = $part.Replace('-', '+').Replace('_', '/'); switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
        $exp = [long](([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json).exp)
        if ($exp -le 0) { return $max }
        $until = [DateTimeOffset]::FromUnixTimeSeconds($exp).UtcDateTime.AddMinutes(-5)
        if ($until -lt $max) { return $until }
        return $max
    } catch { return $max }
}

function Get-SIProSqlLoginFailureText {
    <#
        PURE. The plain words for a sign-in the Pro database refused TWICE (the second time with a fresh token): WHICH
        identity needs a database user, from the token's own claims (appid / oid, and the audience it was issued for), and
        how to grant it. Keeps the server's text ("Login failed for user ...") so the error class stays sql-login. A token
        for another resource than the database is said as such (that is a product defect, not a missing grant).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Token, [string]$Server, [string]$Database, [AllowEmptyString()][string]$ServerText)
    $c = $null
    try {
        $part = ([string]$Token).Split('.')[1]
        $part = $part.Replace('-', '+').Replace('_', '/'); switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
    } catch { $c = $null }
    $app = ''; $oid = ''; $aud = ''
    if ($c) {
        if ($c.PSObject.Properties['appid']) { $app = [string]$c.appid } elseif ($c.PSObject.Properties['azp']) { $app = [string]$c.azp }
        if ($c.PSObject.Properties['oid']) { $oid = [string]$c.oid }
        if ($c.PSObject.Properties['aud']) { $aud = [string]$c.aud }
    }
    $who = if ($app -or $oid) { ('the identity with client id {0}{1}' -f $(if ($app) { $app } else { '(unknown)' }), $(if ($oid) { " (object id $oid)" } else { '' })) } else { "this job's identity" }
    if ($aud -and $aud.TrimEnd('/') -notmatch '^https://database\.windows\.net$') {
        return ("the Pro database {0}/{1} refused the sign-in: the token was issued for '{2}', not for the database (https://database.windows.net/) -- a product defect, please report it. {3}" -f $Server, $Database, $aud, $ServerText)
    }
    ("the Pro database {0}/{1} refused the sign-in of {2}, also with a fresh token: it has no user in that database. Re-run the setup's database step (it grants every job's identity), or in the database as an Entra admin: CREATE USER [<the job's identity name>] FROM EXTERNAL PROVIDER; then give it the SecurityInsight roles. {3}" -f $Server, $Database, $who, $ServerText)
}

function New-SIProSettingsStore {
    <#
        The Pro database. -Invoke is the ONE seam (sql, params, mode 'reader' | 'nonquery' | 'scalar') -- tests pass a
        fake; the default opens a connection per call with an Entra token for the engine SPN (certificate), the same way
        the vulnerability close-loop reaches the same database.
    #>
    param([string]$Server, [string]$Database, [string]$AppId, [string]$TenantId, [string]$CertThumbprint, [scriptblock]$Invoke)
    if (-not $Invoke) {
        if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { throw 'the Pro database is not configured (SI_ProSqlServer / SI_ProSqlDatabase)' }
        $srv = $Server; $db = $Database; $app = $AppId; $ten = $TenantId
        $tokenCache = @{ Token = $null; Until = [datetime]::MinValue }
        if ($global:SI_UseManagedIdentity) {
            # #211 (2): a container signed in as the job's managed identity (#209) -- Pro is container-only. The SQL
            # token comes from the identity endpoint; no certificate exists there.
            # The container entry point loads the identity helper; an engine never loads it itself.
            if (-not (Get-Command -Name 'Get-SIManagedIdentityToken' -ErrorAction SilentlyContinue)) {
                throw 'managed identity: the identity token helper is not loaded -- this sign-in works only inside a SecurityInsight container.'
            }
            $miFn = ${function:Get-SIManagedIdentityToken}
            $getToken = { param([switch]$Fresh) & $miFn -Resource 'https://database.windows.net/' -ForceRefresh:$Fresh }.GetNewClosure()
        } else {
            if (-not (Get-Command -Name 'Get-SILedgerAccessToken' -ErrorAction SilentlyContinue)) {
                . (Join-Path $script:SIProRoot 'engine\data-model\identity\SI-ObjectLedgerStore.ps1')
            }
            $cert = Get-SILedgerCertificate -Thumbprint $CertThumbprint
            if (-not $cert) { throw ("the engine certificate {0} with a private key was not found" -f $CertThumbprint) }
            $tokenFn = ${function:Get-SILedgerAccessToken}
            # (a certificate token is requested new on every call -- -Fresh changes nothing here)
            $getToken = { param([switch]$Fresh) & $tokenFn -Certificate $cert -AppId $app -TenantId $ten }.GetNewClosure()
        }
        $untilOf = ${function:Get-SIProTokenCacheUntil}
        $loginText = ${function:Get-SIProSqlLoginFailureText}
        $Invoke = {
            param([string]$sql, $p, [string]$mode)
            if (-not $tokenCache.Token -or [datetime]::UtcNow -ge $tokenCache.Until) {
                $tokenCache.Token = & $getToken
                $tokenCache.Until = & $untilOf -Token $tokenCache.Token -Now ([datetime]::UtcNow)
            }
            $cs = 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $srv, $db
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
            $cn.AccessToken = $tokenCache.Token
            try {
                # customer G 2026-10-09: a token held for a fixed 45 minutes expired mid-run and every call answered "Login
                # failed" (18456). A failed sign-in takes a FRESH token and opens once more; a second failure is the answer.
                try { $cn.Open() }
                catch {
                    $sx = $_.Exception; while ($sx -and -not ($sx -is [System.Data.SqlClient.SqlException]) -and $sx.InnerException) { $sx = $sx.InnerException }
                    if (-not ($sx -is [System.Data.SqlClient.SqlException]) -or [int]$sx.Number -ne 18456) { throw }
                    $cn.Dispose()
                    Start-Sleep -Seconds 3
                    $tokenCache.Token = & $getToken -Fresh
                    $tokenCache.Until = & $untilOf -Token $tokenCache.Token -Now ([datetime]::UtcNow)
                    $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
                    $cn.AccessToken = $tokenCache.Token
                    # refused again with a fresh token: say WHICH identity needs the grant, in plain words (rc.465, MarkDone)
                    try { $cn.Open() }
                    catch {
                        $sx2 = $_.Exception; while ($sx2 -and -not ($sx2 -is [System.Data.SqlClient.SqlException]) -and $sx2.InnerException) { $sx2 = $sx2.InnerException }
                        if (-not ($sx2 -is [System.Data.SqlClient.SqlException]) -or [int]$sx2.Number -ne 18456) { throw }
                        throw (& $loginText -Token $tokenCache.Token -Server $srv -Database $db -ServerText $sx2.Message)
                    }
                }
                # mode 'transaction' (-p = { param($TxInvoke) }): ONE connection, ONE transaction for everything the body sends
                # through $TxInvoke (sql, params, mode) -- committed when the body returns, rolled back on any error (the template
                # publish: a run never reads a half-written set)
                if ($mode -eq 'transaction') {
                    $tx = $cn.BeginTransaction()
                    $txInvoke = {
                        param([string]$tsql, $tp, [string]$tmode)
                        $tc = $cn.CreateCommand(); $tc.Transaction = $tx; $tc.CommandText = $tsql; $tc.CommandTimeout = 0
                        if ($tp) { foreach ($k in $tp.Keys) { [void]$tc.Parameters.AddWithValue('@' + $k, $(if ($null -eq $tp[$k]) { [System.DBNull]::Value } else { $tp[$k] })) } }
                        if ($tmode -eq 'reader') { $rd = $tc.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }; $rd.Close(); return , $out.ToArray() }
                        if ($tmode -eq 'scalar') { return $tc.ExecuteScalar() }
                        [void]$tc.ExecuteNonQuery()
                    }.GetNewClosure()
                    try { $r = & $p $txInvoke; $tx.Commit(); $tx = $null; return $r }
                    catch { if ($tx) { try { $tx.Rollback() } catch { } }; throw }
                }
                $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 0
                if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
                switch ($mode) {
                    'reader' {
                        $rd = $cmd.ExecuteReader()
                        $out = New-Object System.Collections.Generic.List[object]
                        while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                        $rd.Close(); , $out.ToArray()
                    }
                    'scalar' { $cmd.ExecuteScalar() }
                    default  { [void]$cmd.ExecuteNonQuery() }
                }
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        $own = $Invoke
        $txn = { param([scriptblock]$Body) & $own '' $Body 'transaction' }.GetNewClosure()
        return [pscustomobject]@{ Name = ('{0}/{1}' -f $Server, $Database); Invoke = $Invoke; Transaction = $txn }
    }
    [pscustomobject]@{ Name = ('{0}/{1}' -f $Server, $Database); Invoke = $Invoke }
}

function Read-SIProSettings {
    <# Every row of cfg.Setting, one per pipeline item (the reader returns its rows as ONE array -- unrolled here, so
       @(Read-SIProSettings) counts rows, not result sets). #>
    param([Parameter(Mandatory)]$Store)
    & $Store.Invoke 'SELECT Name, Scope, ValueJson, KeyVaultSecretName, CONVERT(varchar(30), CONVERT(bigint, RowVersion)) AS Version FROM cfg.Setting' @{} 'reader' | ForEach-Object { $_ }
}

function ConvertFrom-SIProSettingRows {
    <#
        PURE. cfg.Setting rows -> the values this engine runs with, validated against the catalog.
        Scope: 'solution' rows apply to every engine, 'engine:<folder>' rows to that engine only and win over 'solution'.
        Refused (the caller stops the run): an unknown setting, a Pro setting row that does not parse, a value of the
        wrong type, a secret stored as a value, or a non-secret stored as a Key Vault reference.
        -Retired: settings that no longer exist (Get-SISettingsRetiredNames) -- a row for one is skipped without a word.
        Returns @{ Values = name -> value; Secrets = name -> Key Vault secret name; Refused = [@{ Name; Scope; Reason }] }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][object[]]$Catalog, [Parameter(Mandatory)][string]$Engine,
          [AllowEmptyCollection()][string[]]$Retired = @())
    $byName = @{}; foreach ($s in $Catalog) { $byName[[string]$s.name] = $s }
    $values = [ordered]@{}; $secrets = [ordered]@{}; $refused = New-Object System.Collections.Generic.List[object]
    $ordered = @($Rows | Where-Object { $_ } | Sort-Object { if ([string]$_.Scope -eq 'solution') { 0 } else { 1 } })
    foreach ($r in $ordered) {
        $name = [string]$r.Name; $scope = [string]$r.Scope
        if ($scope -ne 'solution' -and $scope -ne ('engine:' + $Engine)) { continue }    # another engine's setting
        if (@($Retired) -contains $name) { continue }                                     # a setting that no longer exists
        $s = $byName[$name]
        if (-not $s) { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = 'not a known setting' }); continue }
        $kv = [string]$r.KeyVaultSecretName
        if ($s.secret) {
            if ($null -ne $r.ValueJson -and [string]$r.ValueJson -ne '') { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = 'a secret must be a Key Vault reference, never a stored value' }); continue }
            if (-not $kv) { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = 'a secret setting without a Key Vault secret name' }); continue }
            $secrets[$name] = $kv; continue
        }
        if ($kv) { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = 'only a secret setting may point at Key Vault' }); continue }
        $v = $null
        try { $v = ([string]$r.ValueJson) | ConvertFrom-Json -ErrorAction Stop } catch { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = 'the stored value is not valid JSON' }); continue }
        if ($s.type -eq 'list' -and $null -ne $v) { $v = @($v | ForEach-Object { [string]$_ }) }
        if ($s.type -eq 'int' -and $null -ne $v) { $n = 0L; if ([long]::TryParse([string]$v, [ref]$n)) { $v = [int]$n } }
        $why = Test-SISettingValue -Setting $s -Value $v
        if ($why) { $refused.Add([pscustomobject]@{ Name = $name; Scope = $scope; Reason = $why }); continue }
        # a number reaches the engine as a [double] whether it was stored as 0.01 or as the text "0.01"
        if ($s.type -eq 'number') { $v = ConvertTo-SISettingNumber $v }
        $values[$name] = $v
    }
    [pscustomobject]@{ Values = $values; Secrets = $secrets; Refused = $refused.ToArray() }
}

# The web app's own settings (stored at scope engine:management-web, never in the engines' catalog) that an ENGINE reads too.
# ConvertFrom-SIProSettingRows skips that scope -- it belongs to the web app -- so these are read here, as plain text:
#   SIWeb_EnvironmentName, SIWeb_TenantName, SIWeb_PublicBaseUrl   every mail's subject, footer and links (MAIL-1)
#   SIWeb_CmdbSource                                                the ONE CMDB owner the CI build takes CMDB values from
#                                                                   (engine\data-model\SI-CiBuildRun.ps1 Get-SICmdbOwner)
#   SIWeb_NumberFormatDefault                                       the number format of the guard mails (SI-Guard.ps1)
$script:SIProWebSettingsForEngines = @('SIWeb_EnvironmentName', 'SIWeb_TenantName', 'SIWeb_PublicBaseUrl', 'SIWeb_CmdbSource', 'SIWeb_NumberFormatDefault')

# the names, one by one (a ', @()' here made @(Get-SIProWebSettingsForEngines) ONE item holding the whole list)
function Get-SIProWebSettingsForEngines { foreach ($n in @($script:SIProWebSettingsForEngines)) { $n } }

function ConvertFrom-SIProWebSettingRows {
    <#
        PURE. cfg.Setting rows -> the web-app settings an engine reads (Get-SIProWebSettingsForEngines), each @{ Name; Value }.
        Only rows at scope engine:management-web whose value is a non-empty JSON string count; anything else is skipped
        without a word (the web app validates its own settings).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    foreach ($wr in @($Rows | Where-Object { $_ -and [string]$_.Scope -eq 'engine:management-web' -and $script:SIProWebSettingsForEngines -contains [string]$_.Name })) {
        $wv = $null
        try { $wv = ([string]$wr.ValueJson) | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($wv -is [string] -and $wv.Trim()) { [pscustomobject]@{ Name = [string]$wr.Name; Value = $wv.Trim() } }
    }
}

function Read-SIProDocuments {
    <# Every row of cfg.Document, one per pipeline item. A database that has not had the Pro-1b schema applied yet has no
       documents: the read is guarded, so it returns nothing instead of failing on a missing table. #>
    param([Parameter(Mandatory)]$Store)
    & $Store.Invoke "IF OBJECT_ID('cfg.Document') IS NOT NULL SELECT Kind, [Key] AS DocKey, Body, CONVERT(varchar(30), CONVERT(bigint, [Version])) AS Version FROM cfg.Document" @{} 'reader' | ForEach-Object { $_ }
}

# =====================================================================================================================
#  Pro-1b -- STRUCTURED SETTINGS AS DOCUMENTS (cfg.Document, REQUIREMENTS §9.2 B / C.3)
#  The validation is the Community Settings page's own (Test-SIJsonChange for exclusions and weights, Test-SIRuleText for
#  tier rules) -- called, not copied -- so a document is checked by the same rules whichever edition wrote it.
# =====================================================================================================================
$script:SIProDocKinds = @('exclusions', 'weights', 'rule')

function Get-SIProDocumentContext {
    <# What validating a document needs from the installation: the shipped Risk Analysis report names and the rule kinds
       the engine knows. Read once per run (and only when there are documents). #>
    param([string]$SIRoot = $script:SIProRoot)
    [pscustomobject]@{ SIRoot = $SIRoot; Reports = @(Get-SIRaReportNames -SIRoot $SIRoot); Kinds = @(Get-SIRuleKinds -SIRoot $SIRoot) }
}

function Test-SIProDocumentKey {
    <# PURE. $null when the key is valid for the kind, else the reason. #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key)
    if ($script:SIProDocKinds -notcontains $Kind) { return ("'{0}' is not a document kind (exclusions, weights, rule)" -f $Kind) }
    if ([string]::IsNullOrEmpty($Key) -or $Key.Length -gt 128) { return 'the key must be 1 to 128 characters' }
    switch ($Kind) {
        'exclusions' { if ($Key -ne 'global' -and $Key -notmatch '^[A-Za-z0-9_]+$') { return ("'{0}' is not 'global' or a report name" -f $Key) } }
        'weights'    { if ($Key -ne 'solution') { return "the weights document has the key 'solution'" } }
        'rule'       { if ($Key -notmatch '^(endpoint|identity|azure|shared)/[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$') { return ("'{0}' is not '<engine>/<rule id>' (engine: endpoint, identity, azure or shared)" -f $Key) } }
    }
    $null
}

function Test-SIProDocument {
    <#
        The reasons a document is not accepted (empty = accepted). -Context from Get-SIProDocumentContext.
          exclusions -- a JSON object; every property is checked by Test-SIJsonChange (CVE ids, configuration ids, tags,
                        CveMinAgeDays). Notes ('_'-prefixed, or Comment) are allowed and never reach a query. Anything
                        else -- including the engine's legacy alias names, which it would paste into KQL unchecked -- is
                        refused.
          weights    -- a JSON object with weightedRiskFactors (each engine checked by Test-SIJsonChange), $schema and
                        notes. Other sections of the weights file are not managed as a document and are refused.
          rule       -- the tier rule YAML, checked by Test-SIRuleText: it parses, carries the key's id, uses only the
                        kinds the engine knows, tiers 0-3.
    #>
    param([AllowEmptyString()][string]$Kind, [AllowEmptyString()][string]$Key, [AllowEmptyString()][AllowNull()][string]$Body, [Parameter(Mandatory)]$Context)
    $why = New-Object System.Collections.Generic.List[string]
    $k = Test-SIProDocumentKey -Kind $Kind -Key $Key
    if ($k) { $why.Add($k); return $why.ToArray() }
    if ([string]::IsNullOrWhiteSpace($Body)) { $why.Add('the document is empty'); return $why.ToArray() }
    $isNote = { param([string]$n) $n.StartsWith('_') -or $n -eq 'Comment' }
    $parseObject = {
        param([string]$text)
        $o = $null
        try { $o = $text | ConvertFrom-Json -ErrorAction Stop } catch { $why.Add('the document is not valid JSON: ' + $_.Exception.Message); return $null }
        if ($o -isnot [System.Management.Automation.PSCustomObject]) { $why.Add('the document must be a JSON object'); return $null }
        $o
    }
    switch ($Kind) {
        'exclusions' {
            if ($Key -ne 'global' -and @($Context.Reports) -notcontains $Key) { $why.Add(("'{0}' is not a shipped Risk Analysis report" -f $Key)); break }
            $o = & $parseObject $Body
            if ($null -eq $o) { break }
            $fileKey = if ($Key -eq 'global') { 'exclusions:global' } else { 'exclusions:' + $Key }
            foreach ($p in $o.PSObject.Properties) {
                if (& $isNote $p.Name) { continue }
                foreach ($w in @(Test-SIJsonChange -Key $fileKey -Property $p.Name -Value $p.Value)) { $why.Add($w) }
            }
        }
        'weights' {
            $o = & $parseObject $Body
            if ($null -eq $o) { break }
            foreach ($p in $o.PSObject.Properties) {
                if ((& $isNote $p.Name) -or $p.Name -eq '$schema') { continue }
                if ($p.Name -ne 'weightedRiskFactors') { $why.Add(("'{0}' is not managed as a Pro document -- only weightedRiskFactors (keep other sections in the file)" -f $p.Name)); continue }
                if ($p.Value -isnot [System.Management.Automation.PSCustomObject]) { $why.Add('weightedRiskFactors must be an object keyed by engine'); continue }
                foreach ($e in $p.Value.PSObject.Properties) {
                    if (& $isNote $e.Name) { continue }
                    foreach ($w in @(Test-SIJsonChange -Key 'weights' -Property $e.Name -Value $e.Value)) { $why.Add($w) }
                }
            }
        }
        'rule' {
            $id = $Key.Substring($Key.IndexOf('/') + 1)
            foreach ($w in @(Test-SIRuleText -Text $Body.TrimStart([char]0xFEFF) -Id $id -Kinds @($Context.Kinds))) { $why.Add($w) }
        }
    }
    $why.ToArray()
}

function ConvertFrom-SIProDocumentRows {
    <# cfg.Document rows -> the accepted documents and the refused ones (Name = kind/key, Scope = 'document', Reason). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)]$Context)
    $docs = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows | Where-Object { $_ })) {
        $kind = [string]$r.Kind; $key = [string]$r.DocKey
        $why = @(Test-SIProDocument -Kind $kind -Key $key -Body ([string]$r.Body) -Context $Context)
        if ($why.Count) { $refused.Add([pscustomobject]@{ Name = ('{0}/{1}' -f $kind, $key); Scope = 'document'; Reason = ($why -join '; ') }); continue }
        $docs.Add([pscustomobject]@{ Kind = $kind; Key = $key; Body = ([string]$r.Body).TrimStart([char]0xFEFF) })
    }
    [pscustomobject]@{ Documents = $docs.ToArray(); Refused = $refused.ToArray() }
}

function Get-SIProSettingsVersion {
    <#
        PURE. The version of the settings a run used (REQUIREMENTS §9.2 C.5): '<highest row version>-<12 hex>'. The row
        version (SQL rowversion, database-wide and increasing) says WHEN; the hash of every (Name, Scope, ValueJson,
        KeyVaultSecretName) and (Kind, Key, Body), sorted ordinally, says WHAT -- so two runs with the same version ran
        on the same settings, and a removed row changes the version even though no row version moved.
    #>
    param([AllowEmptyCollection()][object[]]$Settings = @(), [AllowEmptyCollection()][object[]]$Documents = @(),
          # Phase C: templates (by hash -- the body is large), item overrides and exemptions count too. A database without
          # them hashes exactly as before.
          [AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][object[]]$Overrides = @(),
          [AllowEmptyCollection()][object[]]$Exemptions = @())
    $us = [string][char]0x1F; $nul = [string][char]0
    $max = 0L
    $recs = New-Object System.Collections.Generic.List[string]
    $rec = {
        param([string]$tag, $row, [string[]]$fields)
        $v = 0L; if ([long]::TryParse([string](Get-SIProRowValue $row 'Version'), [ref]$v) -and $v -gt $script:__siVerMax) { $script:__siVerMax = $v }
        $f = foreach ($n in $fields) { $x = Get-SIProRowValue $row $n; if ($null -eq $x -or $x -is [System.DBNull]) { $nul } elseif ($x -is [datetime]) { $x.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) } else { [string]$x } }
        $recs.Add($tag + $us + ($f -join $us))
    }
    $script:__siVerMax = 0L
    foreach ($r in @($Settings | Where-Object { $_ })) { & $rec 'S' $r @('Name', 'Scope', 'ValueJson', 'KeyVaultSecretName') }
    foreach ($r in @($Documents | Where-Object { $_ })) { & $rec 'D' $r @('Kind', 'DocKey', 'Body') }
    foreach ($r in @($Templates | Where-Object { $_ })) { & $rec 'T' $r @('Kind', 'ItemKey', 'TemplateVersion', 'BodyHash', 'Format', 'SortOrder', 'RetiredAt') }
    foreach ($r in @($Overrides | Where-Object { $_ })) { & $rec 'O' $r @('Kind', 'ItemKey', 'State', 'BodyJson', 'Format') }
    foreach ($r in @($Exemptions | Where-Object { $_ })) { & $rec 'E' $r @('ExemptionId', 'Scope', 'ReportName', 'ConfigurationId', 'Cve', 'AssetKey', 'ExpiresAt', 'RevokedAt') }
    $max = $script:__siVerMax
    $recs.Sort([System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($recs.ToArray() -join [string][char]0x1E))) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    '{0}-{1}' -f $max, $h.Substring(0, 12)
}

function New-SIProRunFolder {
    <# The run's own folder for materialised documents: under the temp folder (never the installation), unique per run.
       Folders of earlier runs older than two days are cleared on the way (best effort). #>
    param([Parameter(Mandatory)][string]$Engine, [string]$Root)
    if (-not $Root) { $Root = Join-Path ([System.IO.Path]::GetTempPath()) 'si-pro-run' }
    if (-not (Test-Path -LiteralPath $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    $cut = (Get-Date).AddDays(-2)
    foreach ($old in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut })) {
        Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    $dir = Join-Path $Root ('{0}-{1}-{2}' -f ($Engine -replace '[^A-Za-z0-9_\-]', '_'), (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $dir
}

function Export-SIProDocuments {
    <#
        Materialise validated documents into the run-local folder, in exactly the shape the engines' own loaders read:
          rule       -> <run>\rules\<engine>\<id>.custom.yaml  -- returned as RulesRoot, to be set as SI_EnrichmentDataRoot.
                        The overlay a run had before (-ExistingOverlay: other operator rules, asset / correlation decision
                        files at its root) is COPIED in first, so nothing it supplied is lost; a document then replaces a
                        copied rule with the same id. The original overlay is only read.
          exclusions -> <run>\risk-analysis\RiskAnalysisGlobalExclusions.custom.json | <Report>.exclude.custom.json
          weights    -> <run>\risk-analysis\riskscore_weighted.schema.custom.json   -- returned as RaSettingsPath.
        The file names come from the Settings page's own mapping (Resolve-SIJsonTarget). Refuses a run folder inside the
        SecurityInsight folder: the shipped tree is never written.
        Phase C: the documents-only form of Export-SIProConfig (SI-ProConfig.ps1), which also materialises templates,
        item overrides and exemptions.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Documents, [Parameter(Mandatory)][string]$RunFolder,
          [Parameter(Mandatory)]$Context, [string]$ExistingOverlay)
    $m = Export-SIProConfig -Documents @($Documents) -RunFolder $RunFolder -Context $Context -ExistingOverlay $ExistingOverlay
    [pscustomobject]@{ RulesRoot = $m.RulesRoot; RaSettingsPath = $m.RaSettingsPath; Rules = $m.Rules; Exclusions = $m.Exclusions; Weights = $m.Weights }
}
# =====================================================================================================================
#  RUN HEALTH ON A SETTINGS FAILURE (REQUIREMENTS §9.2 C.4): the run still FAILS, and leaves one END record saying why.
# =====================================================================================================================
function ConvertTo-SIProSafeText {
    <# PURE. A failure message made safe for a log record: tokens, keys and passwords redacted, one line, bounded. #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [int]$Max = 2000)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text -replace '(?i)(bearer\s+)[A-Za-z0-9\-\._~\+/]+=*', '$1[redacted]'
    $t = $t -replace 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', '[redacted-token]'
    $t = $t -replace '(?i)\b(password|pwd|accountkey|sharedaccesskey|sig|client_secret|clientsecret|secret|accesstoken|access_token)(\s*[=:]\s*)([^;&\s,]+)', '$1$2[redacted]'
    $t = ($t -replace '\s*\r?\n\s*', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    $t
}

function Send-SIProSettingsFailureRow {
    <#
        One run-health END record for a run the settings layer stopped: ExitReason 'settings-error', the reason (made safe)
        and, when the rows were read, the settings version. NEVER THROWS -- it runs while another failure is on its way
        out, and must neither mask it nor replace it with a second error.
        Posted with the engines' own Send-SIRunHealthRow, using what layers 1-5 loaded (workspace, endpoint, identity).
        When no Log Analytics target is configured at this point the record cannot be posted; the same line is written to
        the console -- the launcher's transcript, which is where the launcher's own "Failed to load layered config"
        failure lands -- so the reason is kept either way. -Send is a test seam: & $Send <RunContext> <ExitReason> <Message>.
    #>
    param([Parameter(Mandatory)][string]$Engine, [AllowEmptyString()][string]$Message, [string]$Version, [datetime]$StartedAt = ([datetime]::UtcNow), [scriptblock]$Send,
          # UPLINK-FIX: 'success-partial' for an install that is not finished yet (Test-SIProSettingsInstallPending) -- a warning
          [ValidateSet('settings-error', 'success-partial')][string]$ExitReason = 'settings-error')
    $runId = [guid]::NewGuid().ToString()
    $msg = ''; $status = 'not posted'
    try {
        $msg = ConvertTo-SIProSafeText $Message
        if ($Version) { $msg = '{0} [settings version {1}]' -f $msg, $Version }
        $ctx = [pscustomobject]@{ RunId = $runId; Engine = $Engine; ShardIndex = 0; ShardCount = 1; StartedAt = $StartedAt.ToUniversalTime(); CollectionTime = [datetime]::SpecifyKind($StartedAt.ToUniversalTime(), [DateTimeKind]::Utc); FailedStep = 'settings' }
        if ($Send) {
            & $Send $ctx $ExitReason $msg
            $status = 'handed to the run-health sender'
        } elseif (-not $global:SI_WorkspaceResourceId -or -not $global:SI_DceName -or -not $global:SI_DcrResourceGroup) {
            $status = 'not posted -- no Log Analytics target (SI_WorkspaceResourceId / SI_DceName / SI_DcrResourceGroup) is configured at this point'
        } else {
            if (-not (Get-Command -Name 'Send-SIRunHealthRow' -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIProRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1') }
            if (-not (Get-Command -Name 'Initialize-SIIngestGlobals' -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIProRoot 'engine\_shared\SI-LogIngest.ps1') }
            Initialize-SIIngestGlobals
            Send-SIRunHealthRow -RunContext $ctx -Phase 'End' -AssetCount -1 -ExitReason $ExitReason -ErrorMessage $msg
            $status = 'posted (best effort -- a failed post is warned above)'
        }
    } catch {
        $status = 'not posted -- ' + (ConvertTo-SIProSafeText $_.Exception.Message 300)
    }
    try { Write-Host ('[RUN-HEALTH] End  Engine={0}  RunId={1}  ExitReason={4}  {2}  -- {3}' -f $Engine, $runId, $status, $msg, $ExitReason) -ForegroundColor Yellow } catch { }
    [pscustomobject]@{ RunId = $runId; ExitReason = $ExitReason; ErrorMessage = $msg; Status = $status }
}

function Invoke-SIProSettingsLayer {
    <#
        Run start, Pro: read cfg.Setting, cfg.Document and (Phase C) cfg.Template, cfg.ItemOverride and cfg.Exemption; set
        the $global: values for this engine and materialise everything else to a run-local folder. THROWS -- and so fails
        the run -- when the database cannot be read, a setting, document, template, override or exemption is refused, a
        Key Vault secret cannot be resolved, or the configuration cannot be materialised. Before the failure leaves, ONE
        run-health END record says why (Send-SIProSettingsFailureRow); the failure itself is rethrown unchanged.
        On success:
          $global:SI_ProSettingsVersion   the settings version this run used (every row of every table counts)
          $global:SI_EnrichmentDataRoot   the run-local rules overlay (tier rules, decision files)
          $global:SI_ProRulesFromSql      $true when the tier rules come from the templates -- the shipped tree is not read
          $global:SI_ProRaSettingsPath    Risk Analysis: exclusions (+ exemptions), weights, the report catalog, the risk index
          $global:SI_ProConfigRoot        CMDB ownership, service model, asset-tagging config, schema overlays
          $global:SI_ProAssetTaggingPath  the asset-tagging rules
          $global:SI_DataModelRoot        the data model (field catalog, provider mappings, ...): templates + overrides (#456)
          $global:SI_ProTemplateVersion   the release the templates were published from
          names (tables, DCRs, ...)     cfg.Setting rows like every setting (#251: names are settings, the catalog
                                        default is the default); a naming override row from before setup carried it
                                        over still sets its name, and a cfg.Setting row wins over it
        -Store, -Catalog, -ResolveSecret, -DocumentContext, -RunRoot, -RunHealth and -Now are seams for tests; by default
        the store is built from SI_ProSqlServer / SI_ProSqlDatabase and the engine SPN.
    #>
    param([Parameter(Mandatory)][string]$Engine, $Store, [object[]]$Catalog, [scriptblock]$ResolveSecret,
          $DocumentContext, [string]$RunRoot, [scriptblock]$RunHealth,
          # Names this host owns and the database must not override -- a container passes its container-owned list
          # (SI-ContainerConfig's protected names). Live 2026-10-02: an internal install's AutomationFramework = true,
          # imported into the database, re-enabled the internal platform framework inside a container and Risk Analysis
          # failed. Skipped names are reported in $global:SI_ProSettingsSkipped, never applied.
          [string[]]$ExcludeNames = @(),
          [datetime]$Now = ([datetime]::UtcNow),
          # UPLINK-FIX: { } -> how many runs ever ended well on this install (Test-SIProSettingsInstallPending; tests)
          [scriptblock]$RunsBefore)
    $global:SI_ProSettingsInstallPending = $null; $global:SI_ProSettingsTaggingNoAccess = $null
    # the permission self-check's database part (engine\_shared\SI-PermissionCheck.ps1): what this run saw of its own access
    $global:SI_ProDatabaseAccess = $null
    $started = [datetime]::UtcNow
    $version = ''
    foreach ($n in 'SI_ProSettingsVersion', 'SI_ProRaSettingsPath', 'SI_ProConfigRoot', 'SI_ProAssetTaggingPath', 'SI_ProRulesFromSql', 'SI_ProTemplateVersion', 'SI_DataModelRoot') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    try {
        if (-not $Catalog) { $Catalog = @(Get-SISettingsCatalog -SIRoot $script:SIProRoot) }
        if (-not $Store) {
            # The settings database ('settings-database') is in BOTH versions since 2026-10-18 (owner: the free version has
            # the database): a free feature, so this check never consults a licence. It stays at this one place: should the
            # feature ever be paid again, a refusal stops the run with the reason (one run-health record, below) -- never a
            # run on other settings.
            if (-not (Get-Command -Name Test-SIFeatureAvailable -ErrorAction SilentlyContinue)) {
                . ([System.IO.Path]::Combine($script:SIProRoot, 'engine', 'SI-FeatureCatalog.ps1'))
            }
            $gate = Test-SIFeatureAvailable -Feature 'settings-database'
            if (-not $gate.Allowed) { throw ("SecurityInsight Pro: the settings database is not licensed for this tenant ({0}) -- install a licence that includes it." -f $gate.Reason) }
            # the engine SPN: SI_SPN_* where set, else the identity Connect-Platform set in layer 1 (internal installs) --
            # the same fallback the vulnerability close-loop uses. Read only; no global is changed here.
            $first = { param([object[]]$v) foreach ($x in $v) { if (-not [string]::IsNullOrWhiteSpace([string]$x)) { return [string]$x } }; '' }
            $Store = New-SIProSettingsStore -Server ([string]$global:SI_ProSqlServer) -Database ([string]$global:SI_ProSqlDatabase) `
                        -AppId (& $first @($global:SI_SPN_AppId, $global:HighPriv_Modern_ApplicationID_Azure)) `
                        -TenantId (& $first @($global:SI_SPN_TenantId, $global:AzureTenantId)) `
                        -CertThumbprint (& $first @($global:SI_SPN_CertThumbprint, $global:HighPriv_Modern_CertificateThumbprint_Azure))
        }
        $rows = $null; $docRows = $null; $tplRows = $null; $ovrRows = $null; $exRows = $null; $revRows = @()
        try {
            $rows = @(Read-SIProSettings -Store $Store); $docRows = @(Read-SIProDocuments -Store $Store)
            $tplRows = @(Read-SIProTemplates -Store $Store); $ovrRows = @(Read-SIProItemOverrides -Store $Store); $exRows = @(Read-SIProExemptions -Store $Store)
            # the shipped bodies the stale overrides were made on -- for the additive upgrade (only those rows are read)
            # (never fails the run: without them an override behind the shipped content stays as stored, upgrade available)
            $revRows = @()
            try { $revRows = @(Read-SIProOverrideBaseRevisions -Store $Store | Where-Object { $_ }) } catch { $revRows = @() }
        }
        catch { throw ("SecurityInsight Pro: the settings database {0} could not be read -- the run stops rather than use other settings. {1}" -f $Store.Name, $_.Exception.Message) }
        # signed in and read: the identity's own database roles, for the permission self-check (never fails the run)
        $global:SI_ProDatabaseAccess = Read-SIProDatabaseAccess -Store $Store
        # the ring this install reports to Invardia (SI-TelemetrySend): the updater's state and the recorded ring, read on
        # the connection already open -- never a second sign-in at run end. Never fails the run.
        $global:SI_InstallRingFacts = $null
        if (Get-Command -Name Read-SIInstallRingFacts -ErrorAction SilentlyContinue) { $global:SI_InstallRingFacts = Read-SIInstallRingFacts -Store $Store }
        # #517: the same store records Invardia's "your licence was re-issued" answer for the updater (SI-TelemetrySend) --
        # never a second sign-in at run end
        $global:SI_ProSettingsStore = $Store
        $version = Get-SIProSettingsVersion -Settings @($rows) -Documents @($docRows) -Templates @($tplRows) -Overrides @($ovrRows) -Exemptions @($exRows)
        $c = ConvertFrom-SIProSettingRows -Rows @($rows) -Catalog $Catalog -Engine $Engine -Retired @(Get-SISettingsRetiredNames)
        $d = [pscustomobject]@{ Documents = @(); Refused = @() }
        $any = @($docRows).Count + @($tplRows).Count + @($ovrRows).Count + @($exRows).Count
        $m = [pscustomobject]@{ Items = @(); Disabled = @(); Refused = @(); Notes = @(); TemplateVersion = ''; Families = @{} }
        $x = [pscustomobject]@{ Active = @(); Inactive = @(); Refused = @() }
        if ($any) {
            if (-not $DocumentContext) { $DocumentContext = Get-SIProDocumentContext -SIRoot $script:SIProRoot }
            # the customer's own Risk Analysis reports (and the templates' reports) are reports too
            $reports = New-Object System.Collections.Generic.List[string]
            foreach ($r in @($DocumentContext.Reports)) { $reports.Add([string]$r) }
            foreach ($r in @(@($tplRows) + @($ovrRows) | Where-Object { [string](Get-SIProRowValue $_ 'Kind') -eq 'rareport' -and [string](Get-SIProRowValue $_ 'ItemKey') -like 'report/*' })) {
                $n = ([string](Get-SIProRowValue $r 'ItemKey')).Substring(7); if (-not $reports.Contains($n)) { $reports.Add($n) }
            }
            $ctx = [pscustomobject]@{ SIRoot = $DocumentContext.SIRoot; Reports = $reports.ToArray(); Kinds = @($DocumentContext.Kinds); Catalog = @($Catalog) }
            if (@($docRows).Count) { $d = ConvertFrom-SIProDocumentRows -Rows @($docRows) -Context $ctx }
            # A STORED OVERRIDE NEVER STOPS THE RUN (owner 2026-10-10): one from the previous model is migrated for this run
            # (Resolve-SIProRunOverrides, the update's own translation, in memory -- the update writes it), one that still
            # does not validate is left out and its template applies -- each said, per item.
            $ovRes = Resolve-SIProRunOverrides -Overrides @($ovrRows) -SIRoot $script:SIProRoot
            $ovrRows = @($ovRes.Overrides)
            $m = Merge-SIProItems -Templates @($tplRows) -Overrides @($ovrRows) -Documents @($d.Documents) -Context $ctx -Revisions @($revRows)
            $badOvr = @($m.Refused | Where-Object { $_.Scope -eq 'override' })
            if ($badOvr.Count) {
                $skip = @{}; foreach ($b in $badOvr) { $skip[[string]$b.Name] = [string]$b.Reason }
                $ovrRows = @($ovrRows | Where-Object { -not $skip.ContainsKey(('{0}/{1}' -f (Get-SIProRowValue $_ 'Kind'), (Get-SIProRowValue $_ 'ItemKey'))) })
                $m = Merge-SIProItems -Templates @($tplRows) -Overrides @($ovrRows) -Documents @($d.Documents) -Context $ctx -Revisions @($revRows)
                $more = New-Object System.Collections.Generic.List[string]
                foreach ($n in @($ovRes.Notes)) { $more.Add([string]$n) }
                foreach ($k in $skip.Keys) { $more.Add(("{0}: your change does not validate ({1}) -- this run uses the shipped template for it; fix or reset it on the web app" -f $k, $skip[$k])) }
                foreach ($n in @($m.Notes)) { $more.Add([string]$n) }
                $m.Notes = $more.ToArray()
            } elseif (@($ovRes.Notes).Count) {
                $m.Notes = @(@($ovRes.Notes) + @($m.Notes) | Where-Object { $_ })
            }
            $x = ConvertFrom-SIProExemptionRows -Rows @($exRows) -Context $ctx -Now $Now
            $DocumentContext = $ctx
        }
        $bad = New-Object System.Collections.Generic.List[string]
        if (@($c.Refused).Count) {
            $list = (@($c.Refused) | ForEach-Object { '{0} ({1}): {2}' -f $_.Name, $_.Scope, $_.Reason }) -join '; '
            $bad.Add(("{0} setting(s) in the settings database are not valid -- the run stops. {1}" -f @($c.Refused).Count, $list))
        }
        if (@($d.Refused).Count) {
            $list = (@($d.Refused) | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Reason }) -join '; '
            $bad.Add(("{0} document(s) in the settings database are not valid -- the run stops. {1}" -f @($d.Refused).Count, $list))
        }
        if (@($m.Refused).Count) {
            $list = (@($m.Refused) | ForEach-Object { '{0} ({1}): {2}' -f $_.Name, $_.Scope, $_.Reason }) -join '; '
            $bad.Add(("{0} configuration item(s) in the settings database are not valid -- the run stops. {1}" -f @($m.Refused).Count, $list))
        }
        if (@($x.Refused).Count) {
            $list = (@($x.Refused) | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Reason }) -join '; '
            $bad.Add(("{0} exemption(s) in the settings database are not valid -- the run stops. {1}" -f @($x.Refused).Count, $list))
        }
        if ($bad.Count) { throw ('SecurityInsight Pro: ' + ($bad -join ' ')) }

        $skipped = New-Object System.Collections.Generic.List[string]
        # Names first, so a cfg.Setting row for the same name still wins below. #251: names are settings -- only a naming
        # override row written before setup carried it over to cfg.Setting reaches here (a naming template is history).
        foreach ($it in @($m.Items | Where-Object { $_.Kind -eq 'naming' })) {
            if ($ExcludeNames -contains $it.Key) { if (-not $skipped.Contains($it.Key)) { $skipped.Add($it.Key) }; continue }
            $val = [string](ConvertFrom-SIProJson $it.Body)
            $cur = Get-Variable -Name $it.Key -Scope Global -ErrorAction SilentlyContinue
            if ($it.Origin -eq 'template' -and $cur -and -not [string]::IsNullOrWhiteSpace([string]$cur.Value)) { continue }
            Set-Variable -Name $it.Key -Value $val -Scope Global
        }
        foreach ($k in @($c.Values.Keys)) {
            if ($ExcludeNames -contains $k) { if (-not $skipped.Contains($k)) { $skipped.Add($k) }; continue }
            Set-Variable -Name $k -Value $c.Values[$k] -Scope Global
        }
        # MAIL-1: every mail's footer and subject name the environment as the web app's header does -- its name, tenant name and
        # address are web-app settings (scope engine:management-web); read here (read only, plain text) for the mail transport.
        # The same for every other web-app setting an engine reads (Get-SIProWebSettingsForEngines): the CMDB owner the CI build
        # uses and the number format of the guard mails. Without this they were never set in a run, so the customer's choice
        # on the web app was ignored by the engines.
        foreach ($wv in @(ConvertFrom-SIProWebSettingRows -Rows @($rows))) {
            if (-not [string](Get-Variable -Name ([string]$wv.Name) -Scope Global -ValueOnly -ErrorAction SilentlyContinue)) { Set-Variable -Name ([string]$wv.Name) -Value $wv.Value -Scope Global }
        }
        foreach ($k in @($c.Secrets.Keys)) { if ($ExcludeNames -contains $k) { $skipped.Add($k); [void]$c.Secrets.Remove($k) } }
        $global:SI_ProSettingsSkipped = $skipped.ToArray()
        if ($c.Secrets.Count) {
            if (-not $ResolveSecret) {
                if (-not (Get-Command Get-SIKvSecret -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIProRoot 'auth\Get-SIKvSecret.ps1') }
                if (-not (Get-Command Get-SIVaultName -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIProRoot 'auth\Get-SIVaultName.ps1') }
                $ResolveSecret = { param($secretName) Get-SIKvSecret -VaultName (Get-SIVaultName) -SecretName $secretName }
            }
            foreach ($k in $c.Secrets.Keys) {
                $val = $null
                try { $val = & $ResolveSecret ([string]$c.Secrets[$k]) } catch { $val = $null }
                if ([string]::IsNullOrEmpty([string]$val)) { throw ("SecurityInsight Pro: the Key Vault secret '{0}' for {1} could not be read -- the run stops." -f $c.Secrets[$k], $k) }
                Set-Variable -Name $k -Value $val -Scope Global
            }
        }

        $mat = [pscustomobject]@{ RulesRoot = $null; RaSettingsPath = $null; ConfigRoot = $null; AssetTaggingPath = $null; RulesFromSql = $false; Rules = 0; Exclusions = 0; Weights = 0 }
        $toWrite = @($m.Items | Where-Object { $_.Kind -ne 'naming' })
        if (@($d.Documents).Count -or $toWrite.Count -or @($x.Active).Count -or @($m.Families.Keys | Where-Object { $_ -ne 'naming' }).Count) {
            try {
                $runFolder = New-SIProRunFolder -Engine $Engine -Root $RunRoot
                $mat = Export-SIProConfig -Items $toWrite -Documents @($d.Documents) -Exemptions @($x.Active) -Families $m.Families -RunFolder $runFolder -Context $DocumentContext -ExistingOverlay ([string]$global:SI_EnrichmentDataRoot)
            } catch { throw ("SecurityInsight Pro: the settings documents could not be prepared for this run -- the run stops. {0}" -f $_.Exception.Message) }
            if ($mat.RulesRoot) { $global:SI_EnrichmentDataRoot = [string]$mat.RulesRoot }
            if ($mat.RulesFromSql) { $global:SI_ProRulesFromSql = $true }
            if ($mat.RaSettingsPath) { $global:SI_ProRaSettingsPath = [string]$mat.RaSettingsPath }
            if ($mat.ConfigRoot) { $global:SI_ProConfigRoot = [string]$mat.ConfigRoot }
            if ($mat.AssetTaggingPath) { $global:SI_ProAssetTaggingPath = [string]$mat.AssetTaggingPath }
            # #456: the data model (catalog, mappings, ...) from the templates + the customer's overrides -- what the record
            # writer, the CI build and the outputs read (Get-SIDataModelRoot)
            if ($mat.PSObject.Properties['DataModelRoot'] -and $mat.DataModelRoot) { $global:SI_DataModelRoot = [string]$mat.DataModelRoot }
        }
        if ($m.TemplateVersion) {
            $global:SI_ProTemplateVersion = $m.TemplateVersion
            # #250: template versions are their own series (pack 1.0, 1.1, ...); the code ships one of them
            $shippedPack = Get-SIProShippedPackInfo -SIRoot $script:SIProRoot
            $fam = [string[]]@($m.Families.Keys); [Array]::Sort($fam, [System.StringComparer]::Ordinal)
            Write-Host ('[pro-settings] configuration from the database: {0} item(s) from templates {1} ({2}), {3} disabled, {4} exemption(s) in force ({5} expired or revoked)' -f `
                @($m.Items).Count, $m.TemplateVersion, ($fam -join ', '), @($m.Disabled).Count, @($x.Active).Count, @($x.Inactive).Count)
            $older = @(([string]$m.TemplateVersion).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and (Compare-SIProVersionParts $_ $shippedPack.PackVersion) -lt 0 })
            if ($older.Count -and $older.Count -eq @(([string]$m.TemplateVersion).Split(',') | Where-Object { $_.Trim() }).Count) {
                Write-Host ('[pro-settings] the templates in force are {0}; this release ships {1} -- the next setup or update run installs them (your own changes are kept)' -f $m.TemplateVersion, $shippedPack.Name) -ForegroundColor Yellow
            }
        }
        foreach ($note in @(@($m.Notes) + @($mat.Notes) | Where-Object { $_ })) { Write-Host ('[pro-settings] {0}' -f $note) -ForegroundColor Yellow }
        $global:SI_ProSettingsVersion = $version
        # #302 (AUDIT-1.1): the changes people committed in the web app are in force for this job from now -- one audit
        # event per change, naming the person who asked for it (and the approver). Never fails the run.
        $applied = 0
        if ($Store.Invoke -and (Get-Command -Name Invoke-SIChangeAttributionApply -ErrorAction SilentlyContinue)) {
            try { $applied = Invoke-SIChangeAttributionApply -Invoke $Store.Invoke -Job $Engine -Log { param($l, $msg) Write-Host ('[pro-settings] {0}' -f $msg) -ForegroundColor Yellow } } catch { $applied = 0 }
            if ($applied -gt 0) { Write-Host ('[pro-settings] {0} change(s) committed in the web app are in force from this run (recorded on the audit trail with who asked for them)' -f $applied) }
        }
        [pscustomobject]@{ Store = $Store.Name; Values = $c.Values.Count; Secrets = $c.Secrets.Count; Documents = @($d.Documents).Count
            Items = @($m.Items).Count; Disabled = @($m.Disabled).Count; Exemptions = @($x.Active).Count; TemplateVersion = $m.TemplateVersion
            Version = $version; RulesRoot = $mat.RulesRoot; RaSettingsPath = $mat.RaSettingsPath; ConfigRoot = $mat.ConfigRoot
            AssetTaggingPath = $mat.AssetTaggingPath; RulesFromSql = [bool]$mat.RulesFromSql }
    } catch {
        $failure = $_
        $fmsg = [string]$failure.Exception.Message
        # the permission self-check: the failed sign-in is recorded WITH its error text -- the check reads from it whether
        # the database refused the identity (no database user) or its server's firewall refused the job before any
        # sign-in (Get-SIPermissionDatabaseFailure, engine\_shared\SI-PermissionCheck.ps1); the run-health record says which
        if ($null -eq $global:SI_ProDatabaseAccess -and (Test-SIProSettingsSqlNotReady $fmsg)) { $global:SI_ProDatabaseAccess = @{ SignIn = 'failed'; Roles = $null; Error = $fmsg } }
        # UPLINK-FIX (customer G 2026-10-07): the guided install creates the jobs (step container-jobs) BEFORE the Pro
        # database and the identity's database user (pro-sql / pro-schema), so the flow's 5-minute wake-ups during the
        # install cannot sign in to it. While NO run has ever ended well on this install, that is "the install is not
        # finished", not a failure: a warning record, and the container ends cleanly ($global:SI_ProSettingsInstallPending).
        if (Test-SIProSettingsInstallPending -Message $fmsg -RunsBefore $RunsBefore) {
            $global:SI_ProSettingsInstallPending = $true
            $null = Send-SIProSettingsFailureRow -Engine $Engine -ExitReason 'success-partial' -Version $version -StartedAt $started -Send $RunHealth `
                -Message ('install not finished: the settings database cannot be signed in to yet (its database user is created later in the install); this run did nothing. ' + $fmsg)
        } elseif ($Engine -eq 'asset-tagging' -and (Test-SIProSettingsSqlNotReady $fmsg)) {
            # Fix request 85bd728f: asset tagging runs under its OWN identity (#236), and installs made before the fix never
            # gave it a database user. Nothing is tagged (it reports only by default) and nothing else is affected: a warning
            # that says how to fix it, and the container ends cleanly -- never a failed run every morning (#448).
            $global:SI_ProSettingsTaggingNoAccess = $true
            $tagWhy = 'its own identity has no user in the Pro database; this run did nothing. Fix once, as the SQL server''s Entra admin: setup\Grant-SITaggingDatabase.ps1 -Apply. '
            # the server's firewall refused the job before any sign-in: the database user is not the problem, and the record says so
            if ((Get-Command -Name Get-SIPermissionDatabaseFailure -ErrorAction SilentlyContinue) -and (Get-SIPermissionDatabaseFailure -Message $fmsg) -eq 'firewall') {
                $tagWhy = 'the database server''s firewall refused this job before it could sign in (its database user is not the problem); this run did nothing. Fix: in the Azure portal allow Azure services and resources to access the SQL server (Networking), or run the guided install again. '
            }
            $null = Send-SIProSettingsFailureRow -Engine $Engine -ExitReason 'success-partial' -Version $version -StartedAt $started -Send $RunHealth `
                -Message ('asset tagging cannot read its settings: ' + $tagWhy + $fmsg)
        } else {
            $null = Send-SIProSettingsFailureRow -Engine $Engine -Message $fmsg -Version $version -StartedAt $started -Send $RunHealth
        }
        throw $failure
    }
}

function Read-SIProDatabaseAccess {
    <#
        After a successful sign-in: this identity's own roles in the Pro database (IS_ROLEMEMBER), for the permission
        self-check (engine\_shared\SI-PermissionCheck.ps1). Returns @{ SignIn = 'ok'; Roles = @{ db_owner; db_datareader;
        db_datawriter } -> '1' / '0' / $null (unknown); User }. NEVER THROWS: a role query that fails leaves the roles
        unknown (the check then says "not checked", never "missing").
    #>
    param([Parameter(Mandatory)]$Store)
    $out = @{ SignIn = 'ok'; Roles = @{}; User = ''; Error = '' }
    try {
        $rows = @(& $Store.Invoke "SELECT USER_NAME() AS UserName, IS_ROLEMEMBER(N'db_owner') AS db_owner, IS_ROLEMEMBER(N'db_datareader') AS db_datareader, IS_ROLEMEMBER(N'db_datawriter') AS db_datawriter" @{} 'reader' | ForEach-Object { $_ })
        $r = $rows | Where-Object { $_ } | Select-Object -First 1
        if ($r) {
            $get = { param($n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } else { $null } } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
            foreach ($n in 'db_owner', 'db_datareader', 'db_datawriter') {
                $v = & $get $n
                $out.Roles[$n] = $(if ($null -eq $v -or $v -is [System.DBNull]) { $null } else { [string][int]$v })
            }
            $out.User = [string](& $get 'UserName')
        }
    } catch { $out.Error = [string]$_.Exception.Message }
    $out
}

function Test-SIProSettingsSqlNotReady {
    <# PURE. The settings database refused the SIGN-IN (no login / no database user yet) -- not a bad row, not a network fault. #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    [bool]("$Message" -match "(?i)Login failed for user|Cannot open (server|database) .* requested by the login|token-identified principal")
}

function Test-SIProSettingsSqlNotCreated {
    <# PURE. The settings database's SERVER does not exist (yet): its name does not resolve, or the database is not there.
       customer H 2026-10-08: the flow woke while the install was still creating the server. Only "install pending" uses it --
       together with "no run ever ended well"; on an established install it stays a settings-error. #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    [bool]("$Message" -match "(?i)No such host is known|Name or service not known|nodename nor servname|could not be resolved|Database '[^']+' on server '[^']+' is not currently available|Cannot open database .* The login failed")
}

function Test-SIProSettingsInstallPending {
    <#
        Is a settings-database sign-in failure the install still running (UPLINK-FIX, customer G 2026-10-07)? Only when the
        failure is a sign-in refusal (Test-SIProSettingsSqlNotReady) AND no run has EVER ended well on this install
        (SI_RunHealth_CL: an End with success / success-partial; a table that does not exist yet = none). Anything that
        cannot be told is NOT pending -- the failure is then reported as before. -RunsBefore { } -> [long] (tests).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Message, [scriptblock]$RunsBefore)
    if (-not (Test-SIProSettingsSqlNotReady $Message) -and -not (Test-SIProSettingsSqlNotCreated $Message)) { return $false }
    $n = -1L
    try {
        if ($RunsBefore) { $n = [long](& $RunsBefore) }
        elseif (-not (Get-Module -Name Pester)) { $n = Get-SIProSettingsGoodRunCount }
    } catch { $n = -1L }
    return ($n -eq 0)
}

function Get-SIProSettingsGoodRunCount {
    <# How many runs ever ended well on this install (0 or 1 -- 'take 1'): SI_RunHealth_CL in its workspace. A table that
       does not exist yet is 0; anything else that fails throws (the caller then treats it as unknown). #>
    if (-not (Get-Command -Name Resolve-SIV3WorkspaceId -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($script:SIProRoot, 'engine', '_shared', 'SI-V3Snapshot.ps1')) }
    if (-not (Get-Command -Name Test-SIKqlTableMissing -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($script:SIProRoot, 'engine', '_shared', 'SI-KqlError.ps1')) }
    $ws = Resolve-SIV3WorkspaceId
    # A GOOD RUN IS A RUN OF AN ENGINE. The pipeline's own records do not count (Engine 'flow' and 'flow:<step>'): the
    # "install not finished" record this very check writes is Engine 'flow', ExitReason success-partial -- counted, it made
    # the SECOND wake-up of an unfinished install a failed run the customer had to fix (the first customer install,
    # 2026-10-12: one such report every 5 minutes). Neither does any record that says the install is not finished.
    $kql = "SI_RunHealth_CL | where Phase == 'End' and ExitReason in ('success', 'success-partial') and Engine != 'flow' and not(Engine startswith 'flow:') and not(tostring(column_ifexists('ErrorMessage', '')) startswith 'install not finished') | take 1 | count | project n = Count"
    try { $r = @((Invoke-SIAzOperationalInsightsQuery -WorkspaceId $ws -Query $kql -ErrorAction Stop).Results) }
    catch { if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName 'SI_RunHealth_CL') { return 0L }; throw }
    if (-not $r.Count) { return 0L }
    [long]$r[0].n
}
function Set-SIProSetting {
    <#
        Write one setting: Set (a value, or for a secret a Key Vault secret name) or Reset (remove the row), with its
        cfg.ChangeLog entry in the SAME transaction. Validated first by the same rules the reader applies.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][object[]]$Catalog, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Scope, [ValidateSet('Set', 'Reset')][string]$Action = 'Set', $Value, [string]$KeyVaultSecretName,
          [Parameter(Mandatory)][string]$ChangedBy, [string]$Reason = '')
    $s = $Catalog | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $s) { throw "'$Name' is not a known setting" }
    if ($Scope -ne 'solution' -and $Scope -notmatch '^engine:[a-z0-9\-]+$') { throw "'$Scope' is not a valid scope" }
    $json = $null; $kv = $null
    if ($Action -eq 'Set') {
        if ($s.secret) { if (-not $KeyVaultSecretName) { throw "$Name is a secret: give its Key Vault secret name, never the value" }; $kv = $KeyVaultSecretName }
        else {
            $why = Test-SISettingValue -Setting $s -Value $Value
            if ($why) { throw "$Name $why" }
            $json = ConvertTo-SIJsonText $Value
        }
    }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT COALESCE(ValueJson, 'keyvault:' + KeyVaultSecretName) FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope);
IF @Action = 'Reset'
    DELETE FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope;
ELSE IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @Name AND Scope = @Scope)
    UPDATE cfg.Setting SET ValueJson = @ValueJson, KeyVaultSecretName = @Kv, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name AND Scope = @Scope;
ELSE
    INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@Name, @Scope, @ValueJson, @Kv, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, @Scope, @Action, @old, COALESCE(@ValueJson, 'keyvault:' + @Kv), @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Name = $Name; Scope = $Scope; Action = $Action; ValueJson = $json; Kv = $kv; By = $ChangedBy; Reason = $Reason }) 'nonquery'
}

function Set-SIProDocument {
    <#
        Write one document: Set (create or replace its Body) or Reset (remove it), with its cfg.ChangeLog entry (Name = the
        key, Scope = 'document', Kind) in the SAME transaction. Validated BEFORE any SQL by the same rules the run-start
        reader applies (Test-SIProDocument), so the writer can never store what the reader would refuse.
        -Context is a seam (Get-SIProDocumentContext by default).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Key,
          [ValidateSet('Set', 'Reset')][string]$Action = 'Set', [AllowEmptyString()][string]$Body,
          [Parameter(Mandatory)][string]$ChangedBy, [string]$Reason = '', $Context)
    $bad = Test-SIProDocumentKey -Kind $Kind -Key $Key
    if ($bad) { throw ("{0}/{1}: {2}" -f $Kind, $Key, $bad) }
    $text = $null
    if ($Action -eq 'Set') {
        if (-not $Context) { $Context = Get-SIProDocumentContext -SIRoot $script:SIProRoot }
        $text = ([string]$Body).TrimStart([char]0xFEFF)
        $why = @(Test-SIProDocument -Kind $Kind -Key $Key -Body $text -Context $Context)
        if ($why.Count) { throw ("{0}/{1} is not valid: {2}" -f $Kind, $Key, ($why -join '; ')) }
    }
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(max) = (SELECT Body FROM cfg.Document WITH (UPDLOCK, HOLDLOCK) WHERE Kind = @Kind AND [Key] = @Key);
IF @Action = 'Reset'
    DELETE FROM cfg.Document WHERE Kind = @Kind AND [Key] = @Key;
ELSE IF @old IS NOT NULL
    UPDATE cfg.Document SET Body = @Body, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Kind = @Kind AND [Key] = @Key;
ELSE
    INSERT cfg.Document (Kind, [Key], Body, UpdatedBy) VALUES (@Kind, @Key, @Body, @By);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Key, 'document', @Kind, @Action, @old, @Body, @By, @Reason);
COMMIT;
'@
    & $Store.Invoke $sql ([ordered]@{ Kind = $Kind; Key = $Key; Action = $Action; Body = $text; By = $ChangedBy; Reason = $Reason }) 'nonquery'
}

function Get-SIProDocumentImportPlan {
    <#
        What importing an install's structured settings into cfg.Document would write, each validated exactly as the run
        will validate it:
          exclusions  risk-analysis-detection\RiskAnalysisGlobalExclusions.custom.json -> exclusions/global
                      risk-analysis-detection\<Report>.exclude.custom.json            -> exclusions/<Report>
                      ...else <Report>.exclude.json (the shipped sample's name; the engine's own order, #275 R1)
                      config\*.exclude*.json is read by nothing: LISTED with where it belongs, not imported (#275 G10)
          weights     risk-analysis-detection\riskscore_weighted.schema.custom.json   -> weights/solution
          rule        every custom tier rule -- page-created or hand-written, in the tree or in the overlay
                      (-OverlayRoot); where both exist the overlay one is the rule in force -> rule/<engine>/<id>
        Not imported, with the reason: a file that does not validate, a per-report *.weighted.custom.json (not a document
        kind), and an asset-tagging file (it is not a tier rule). The files are left as they are.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$OverlayRoot, $Context)
    if (-not $Context) { $Context = Get-SIProDocumentContext -SIRoot $SIRoot }
    $rows = New-Object System.Collections.Generic.List[object]; $skipped = New-Object System.Collections.Generic.List[object]
    $cands = New-Object System.Collections.Generic.List[object]
    $dir = Join-Path $SIRoot 'risk-analysis-detection'
    $info = New-Object System.Collections.Generic.List[object]
    $relOf = { param([string]$p) if ($p.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $p.Substring($SIRoot.Length).TrimStart('\', '/') } else { $p } }
    $g = Join-Path $dir 'RiskAnalysisGlobalExclusions.custom.json'
    if (Test-Path -LiteralPath $g) { $cands.Add([pscustomobject]@{ Kind = 'exclusions'; Key = 'global'; Path = $g }) }
    # #275 R1: per report, the file the 2.2 engine reads (RA-ExcludeLists.ps1 Get-ReportExcludeJson): <R>.exclude.custom.json,
    # else <R>.exclude.json -- the name the shipped *.exclude.json.sample becomes -- the FIRST that parses. The other one,
    # when both exist, was never read; it is said, not imported.
    $byReport = [ordered]@{}
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^[^.]+\.exclude(\.custom)?\.json$' } | Sort-Object Name)) {
        $rep = $f.Name -replace '(?i)\.exclude(\.custom)?\.json$', ''
        if (-not $byReport.Contains($rep)) { $byReport[$rep] = @{ Custom = $null; Plain = $null } }
        if ($f.Name -match '(?i)\.exclude\.custom\.json$') { $byReport[$rep].Custom = $f.FullName } else { $byReport[$rep].Plain = $f.FullName }
    }
    $parses = { param([string]$p) try { $null = ([System.IO.File]::ReadAllText($p)).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop; $true } catch { $false } }
    foreach ($rep in @($byReport.Keys)) {
        $pair = $byReport[$rep]
        $use = $pair.Custom
        if ($pair.Custom -and $pair.Plain) {
            if (& $parses $pair.Custom) { $info.Add([pscustomobject]@{ Name = ('exclusions/{0}' -f $rep); Path = (& $relOf $pair.Plain); Reason = ('never read -- {0} comes first; not imported' -f (Split-Path -Leaf $pair.Custom)) }) }
            else {
                # the engine skips a file it cannot parse and reads the next one: so does the import (and says so)
                $use = $pair.Plain
                $skipped.Add([pscustomobject]@{ Name = ('exclusions/{0}' -f $rep); Scope = 'document'; Path = (& $relOf $pair.Custom); Reason = ('{0}: not valid JSON -- the run skipped it and read {1}, which is what is imported' -f (& $relOf $pair.Custom), (Split-Path -Leaf $pair.Plain)) })
            }
        } elseif (-not $use) { $use = $pair.Plain }
        $cands.Add([pscustomobject]@{ Kind = 'exclusions'; Key = $rep; Path = $use })
    }
    # #275 G10: exclusion files in config\ -- where the README once said to put them. Nothing has ever read them (2.2 or
    # 3.0), so they are not imported (that would switch on exclusions that were never in force); each is listed with the
    # place it belongs.
    if (-not (Get-Command -Name Get-SIMisplacedExcludeFiles -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'risk-analysis', '_shared', 'RA-ExcludeLists.ps1')) }
    foreach ($m in @(Get-SIMisplacedExcludeFiles -SIRoot $SIRoot)) {
        $skipped.Add([pscustomobject]@{ Name = ('exclusions/' + ($m.Name -replace '(?i)\.exclude(\.custom)?\.json$|\.custom\.json$', '')); Scope = 'document'; Path = (& $relOf $m.Path)
            Reason = ('nothing reads exclusion files in config\ (2.2 or 3.0) -- these exclusions were never in force. To use them, move the file to {0}, check it, and import again' -f (& $relOf $m.ShouldBe)) })
    }
    $w = Join-Path $dir 'riskscore_weighted.schema.custom.json'
    if (Test-Path -LiteralPath $w) { $cands.Add([pscustomobject]@{ Kind = 'weights'; Key = 'solution'; Path = $w }) }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.weighted.custom.json' -File -ErrorAction SilentlyContinue)) {
        $skipped.Add([pscustomobject]@{ Name = $f.Name; Scope = 'document'; Info = $true; Reason = ('a per-report weights file is not a document kind -- it is imported as the configuration item weights/report/{0}' -f ($f.Name -replace '\.weighted\.custom\.json$', '')) })
    }
    foreach ($r in @(Get-SIRuleView -SIRoot $SIRoot -OverlayRoot $OverlayRoot)) {
        $own = if ($r.overlay) { $r.overlay } elseif ($r.custom) { $r.custom } else { $null }
        if (-not $own) { continue }
        # Phase C: turning a SHIPPED rule off is a state of its template (cfg.ItemOverride 'disable'), planned by
        # Get-SIProConfigImportPlan -- not a document.
        if ($r.locked -and $own.mode -eq 'disable') { continue }
        $path = if ($own.path -like 'overlay:*') { Join-Path $OverlayRoot $own.path.Substring(8) } else { Join-Path $SIRoot $own.path }
        $cands.Add([pscustomobject]@{ Kind = 'rule'; Key = ('{0}/{1}' -f $r.engine, $r.id); Path = $path })
    }
    foreach ($c in $cands) {
        $text = ([System.IO.File]::ReadAllText($c.Path)).TrimStart([char]0xFEFF)
        $rel = if ($c.Path.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $c.Path.Substring($SIRoot.Length).TrimStart('\') } else { $c.Path }
        $name = '{0}/{1}' -f $c.Kind, $c.Key
        if ($c.Kind -eq 'rule' -and $text -match '(?m)^AssetTagging\s*:') { $skipped.Add([pscustomobject]@{ Name = $name; Scope = 'document'; Info = $true; Path = $rel; Reason = ('{0} is an asset-tagging file, not a tier rule -- it stays in the files' -f $rel) }); continue }
        if ($c.Kind -eq 'rule') {
            # #908: a copied sample is an EXAMPLE, never a live rule -- the IP-subnet sample's 10.100.1.0/24 -> Tier 0 became
            # one on an install this way. Refused (listed under "Not imported -- review"), the file is left as it is.
            $sp = Get-SIRuleSamplePath -SIRoot $SIRoot -Path $c.Path -OverlayRoot $OverlayRoot
            $st = if ($sp) { [System.IO.File]::ReadAllText($sp) } else { $null }
            $sw = Get-SIRuleSampleReason -Text $text -SampleText $st
            if ($sw) { $skipped.Add([pscustomobject]@{ Name = $name; Scope = 'document'; Path = $rel; Reason = ('{0}: the shipped example -- {1}' -f $rel, $sw) }); continue }
        }
        if ($c.Kind -eq 'weights') {
            # An install's weights file is often the full risk-score model (mappers, normalizers, notes). Only its
            # weightedRiskFactors is a Pro document -- that is all Risk Analysis reads from the Pro copy -- so that section
            # is imported (with $schema and the file's notes) and every other section stays in the file, listed here.
            $o = $null; try { $o = ConvertFrom-SIProJson $text } catch { $o = $null }
            if ($o -is [System.Management.Automation.PSCustomObject]) {
                $keep = { param([string]$n) $n.StartsWith('_') -or $n -eq 'Comment' -or $n -eq '$schema' -or $n -eq 'weightedRiskFactors' }
                $other = @($o.PSObject.Properties | Where-Object { -not (& $keep $_.Name) } | ForEach-Object { $_.Name })
                if (-not $o.PSObject.Properties['weightedRiskFactors']) {
                    $skipped.Add([pscustomobject]@{ Name = $name; Scope = 'document'; Reason = ('{0}: it has no weightedRiskFactors -- only weightedRiskFactors is managed as a Pro document (keep other sections in the file)' -f $rel) }); continue
                }
                if ($other.Count -gt 0) {
                    $doc = [ordered]@{}
                    foreach ($p in $o.PSObject.Properties) { if (& $keep $p.Name) { $doc[$p.Name] = $p.Value } }
                    $text = ConvertTo-SIJsonText $doc
                    # #224: the sections are listed in FILE order (never a culture sort, which differs between PS 5.1 and 7).
                    $skipped.Add([pscustomobject]@{ Name = ('{0} (other sections)' -f $name); Scope = 'document'; Info = $true; Reason = ('{0}: {1} -- not part of the weights document; they are imported as the configuration item weights/model (Get-SIProConfigImportPlan)' -f $rel, ($other -join ', ')) })
                }
            }
        }
        $why = @(Test-SIProDocument -Kind $c.Kind -Key $c.Key -Body $text -Context $Context)
        if ($why.Count) { $skipped.Add([pscustomobject]@{ Name = $name; Scope = 'document'; Reason = ('{0}: {1}' -f $rel, ($why -join '; ')) }); continue }
        $rows.Add([pscustomobject]@{ Kind = $c.Kind; Key = $c.Key; Body = $text; Source = $rel })
    }
    [pscustomobject]@{ Rows = $rows.ToArray(); Skipped = $skipped.ToArray(); Info = $info.ToArray() }
}

function Get-SIProLauncherOverrideFiles {
    <#
        #275 R4. Every launcher\<engine>\launcher.override.ps1 of an installation: free PowerShell the 2.2 internal launchers
        dot-source AFTER the configuration layers (so it wins over LauncherConfig.custom.ps1). A container never runs it, so
        Pro would silently lose what it sets: the importer lists every one. @{ Path; Rel; Engine; Scope = 'engine:<engine>' }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $SIRoot 'launcher') -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $p = Join-Path $d.FullName 'launcher.override.ps1'
        if (-not (Test-Path -LiteralPath $p)) { continue }
        [pscustomobject]@{ Path = $p; Rel = ('launcher\{0}\launcher.override.ps1' -f $d.Name); Engine = $d.Name; Scope = ('engine:{0}' -f $d.Name.ToLowerInvariant()) }
    }
}

function Get-SIPs1CodeStatements {
    <#
        PURE. The top-level statements of a PowerShell text that are NOT a `$global:Name = ...` assignment -- code a settings
        import cannot carry (a function, a condition, a command, a local variable). Per statement: Line, Text (its first line).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if (@($errors).Count) {
        $e = @($errors)[0]
        [pscustomobject]@{ Line = $e.Extent.StartLineNumber; Text = ('the file does not parse: ' + $e.Message) }
        return
    }
    $stmts = New-Object System.Collections.Generic.List[object]
    if ($ast.ParamBlock) { $stmts.Add($ast.ParamBlock) }
    foreach ($b in @($ast.DynamicParamBlock, $ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) { if ($b) { foreach ($s in $b.Statements) { $stmts.Add($s) } } }
    foreach ($s in $stmts) {
        if ($s -is [System.Management.Automation.Language.AssignmentStatementAst] -and $s.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $s.Left.VariablePath.UserPath -match '^global:[A-Za-z_][A-Za-z0-9_]*$') { continue }
        $first = ($s.Extent.Text -split "`r?`n")[0].Trim()
        if ($first.Length -gt 120) { $first = $first.Substring(0, 117) + '...' }
        [pscustomobject]@{ Line = $s.Extent.StartLineNumber; Text = $first }
    }
}

function Get-SIProImportPlan {
    <#
        PURE given a root. What importing an install's custom files into cfg.Setting would write: every catalog setting
        the solution file or an engine file sets as a plain value. A value set by code, and any secret, is NOT imported
        -- it is listed with the reason, so the operator moves it by hand (a secret becomes a Key Vault reference).
        A name that ANY imported file sets by code is not imported at any scope: the database layer is read last, so a
        row would override that code (a Key Vault pull, an engine's own condition). The files stay in place in Pro, so
        leaving the name out keeps exactly today's behaviour.
        #275 R4: every launcher\<engine>\launcher.override.ps1 is read after the custom files (the launcher dot-sources it
        last, so it wins at its engine's scope): its plain top-level `$global:Name = <literal>` catalog settings are
        imported at scope engine:<engine>; everything else in it (code) is listed as needing manual review, with the line.
        Returns @{ Rows; Skipped; Overrides (one per override file: Rel, Scope, Imported, Review) }. Every skipped entry
        carries Path (the file) and, where there is one, Line.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][object[]]$Catalog)
    $byName = @{}; foreach ($s in $Catalog) { $byName[[string]$s.name] = $s }
    $retired = @(Get-SISettingsRetiredNames)
    $rows = New-Object System.Collections.Generic.List[object]; $skipped = New-Object System.Collections.Generic.List[object]
    $sources = New-Object System.Collections.Generic.List[object]
    $targets = Get-SISettingsTargets -SIRoot $SIRoot
    foreach ($key in $targets.Keys) {
        $scope = if ($key -eq 'solution') { 'solution' } else { $key }
        $p = $targets[$key]
        $rel = if ($p.StartsWith($SIRoot, [StringComparison]::OrdinalIgnoreCase)) { $p.Substring($SIRoot.Length).TrimStart('\', '/') } else { $p }
        $sources.Add([pscustomobject]@{ Path = $p; Rel = $rel; Scope = $scope; Override = $null })
    }
    $overrides = New-Object System.Collections.Generic.List[object]
    foreach ($o in @(Get-SIProLauncherOverrideFiles -SIRoot $SIRoot)) {
        $entry = [pscustomobject]@{ Rel = $o.Rel; Engine = $o.Engine; Scope = $o.Scope; Imported = 0; Review = 0 }
        $overrides.Add($entry)
        $sources.Add([pscustomobject]@{ Path = $o.Path; Rel = $o.Rel; Scope = $o.Scope; Override = $entry })
    }
    foreach ($src in $sources) {
        $r = Read-SISettingsText -Path $src.Path
        if (-not $r.Exists) { continue }
        $scope = $src.Scope
        $skip = { param([string]$name, $line, [string]$reason) $skipped.Add([pscustomobject]@{ Name = $name; Scope = $scope; Path = $src.Rel; Line = $line; Reason = $reason }); if ($src.Override) { $src.Override.Review++ } }
        if ($src.Override) {
            # the code in an override file: listed line by line -- a Pro run never executes it
            foreach ($c in @(Get-SIPs1CodeStatements -Text $r.Text)) {
                & $skip ('{0}:{1}' -f $src.Rel, $c.Line) $c.Line ('code at line {0} ({1}) -- a Pro run does not run launcher.override.ps1; move what it does into Settings' -f $c.Line, $c.Text)
            }
        }
        foreach ($a in @(Get-SIPs1Assignments -Text $r.Text)) {
            if ($retired -contains $a.Name) { continue }    # a setting that no longer exists: not imported, not listed
            $s = $byName[$a.Name]
            # Phase C: a name the catalog does not know is REPORTED (it stays in the file, and a Pro run without the file
            # will not have it), and a Pro-edition setting is imported like any other -- this is the Pro database.
            if (-not $s) { & $skip $a.Name $a.Line ('not in the settings catalog (line {0}) -- not imported; a Pro run reads only catalog settings from the database' -f $a.Line); continue }
            if ($s.secret) {
                # A secret's VALUE never enters the database. When the file pulls it from Key Vault by a literal secret
                # name, that name becomes the database's Key Vault reference; otherwise it is listed for the operator.
                $kv = [regex]::Match([string]$a.ValueText, '(?i)(Get-SIKvSecret|Get-AzKeyVaultSecret|keyvault\s+secret\s+show)\b.*?(-SecretName|-Name|--name)\s+[''"]([A-Za-z0-9\-]{1,127})[''"]')
                if ($kv.Success) {
                    $prev = $rows | Where-Object { $_.Name -eq $a.Name -and $_.Scope -eq $scope } | Select-Object -First 1
                    if ($prev) { [void]$rows.Remove($prev) }
                    $rows.Add([pscustomobject]@{ Name = $a.Name; Scope = $scope; Value = $null; KeyVaultSecretName = $kv.Groups[3].Value; Line = $a.Line; Source = $src.Rel })
                    if ($src.Override) { $src.Override.Imported++ }
                    continue
                }
                & $skip $a.Name $a.Line 'a secret -- store it in Key Vault and set its secret name'; continue
            }
            if (-not ($a.TopLevel -and $a.Literal)) { & $skip $a.Name $a.Line ('set by code at line {0}' -f $a.Line); continue }
            $why = Test-SISettingValue -Setting $s -Value $a.Value
            if ($why) { & $skip $a.Name $a.Line $why; continue }
            # the last assignment in a file is the one that runs (and an override file runs after the custom file)
            $prev = $rows | Where-Object { $_.Name -eq $a.Name -and $_.Scope -eq $scope } | Select-Object -First 1
            if ($prev) { [void]$rows.Remove($prev) }
            $rows.Add([pscustomobject]@{ Name = $a.Name; Scope = $scope; Value = $a.Value; Line = $a.Line; Source = $src.Rel })
            if ($src.Override) { $src.Override.Imported++ }
        }
    }
    $byCode = @{}; foreach ($s in $skipped) { if ($s.Reason -like 'set by code*') { $byCode[$s.Name] = $s } }
    foreach ($r in @($rows | Where-Object { $byCode.ContainsKey($_.Name) })) {
        [void]$rows.Remove($r)
        $skipped.Add([pscustomobject]@{ Name = $r.Name; Scope = $r.Scope; Path = $r.Source; Line = $r.Line; Reason = ('kept in the files -- {0} also sets it by code; a database value would override that code' -f $byCode[$r.Name].Scope) })
        $ov = @($overrides | Where-Object { $_.Rel -eq $r.Source }) | Select-Object -First 1
        if ($ov) { $ov.Imported--; $ov.Review++ }
    }
    [pscustomobject]@{ Rows = $rows.ToArray(); Skipped = $skipped.ToArray(); Overrides = $overrides.ToArray() }
}

function Get-SIProImportReview {
    <#
        #275. PURE. The import report's final section, "Not imported -- review": every entry any plan did NOT import, as one
        line a person can act on, plus the exit code a wizard and the upgrade test check:
            0 = everything was imported          2 = items need review (listed)
        Entry kinds: 'not-imported' ("not imported: <path> -- <reason>") and 'needs-review' (code, or a value set by code:
        "needs manual review: <file>:<line> -- <reason>"). Entries a plan marks Info -- nothing is lost (a file the run never
        read, sections imported elsewhere) -- go to Informational and do not change the exit code.
        Also returns LauncherOverrides: every launcher.override.ps1 found, with what was imported from it.
    #>
    param($Settings, $Documents, $Items, $Connectors)
    $review = New-Object System.Collections.Generic.List[object]; $infos = New-Object System.Collections.Generic.List[object]
    $prop = { param($o, [string]$n) if ($o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $sections = @(@{ N = 'settings'; P = $Settings }, @{ N = 'documents'; P = $Documents }, @{ N = 'items'; P = $Items }, @{ N = 'connectors'; P = $Connectors })
    foreach ($sec in $sections) {
        if (-not $sec.P) { continue }
        foreach ($s in @(& $prop $sec.P 'Skipped')) {
            if (-not $s) { continue }
            $path = [string](& $prop $s 'Path'); $line = & $prop $s 'Line'; $name = [string](& $prop $s 'Name'); $reason = [string](& $prop $s 'Reason')
            if (-not $path) { $path = $name }
            if ([bool](& $prop $s 'Info')) {
                $infos.Add([pscustomobject]@{ Section = $sec.N; Name = $name; Path = $path; Reason = $reason; Text = ('note: {0} -- {1}' -f $path, $reason) }); continue
            }
            $isCode = ($reason -match '^(code at line|set by code)') -and $null -ne $line
            $kind = if ($isCode) { 'needs-review' } else { 'not-imported' }
            $where = if ($isCode -and $null -ne $line) { '{0}:{1}' -f $path, $line } elseif ($name -and $name -ne $path) { '{0} ({1})' -f $path, $name } else { $path }
            $text = if ($isCode) { 'needs manual review: {0} -- {1}' -f $where, $reason } else { 'not imported: {0} -- {1}' -f $where, $reason }
            $review.Add([pscustomobject]@{ Section = $sec.N; Kind = $kind; Name = $name; Path = $path; Line = $line; Reason = $reason; Text = $text })
        }
        foreach ($s in @(& $prop $sec.P 'Info')) {
            if (-not $s) { continue }
            $path = [string](& $prop $s 'Path'); $reason = [string](& $prop $s 'Reason')
            $infos.Add([pscustomobject]@{ Section = $sec.N; Name = [string](& $prop $s 'Name'); Path = $path; Reason = $reason; Text = ('note: {0} -- {1}' -f $path, $reason) })
        }
    }
    $ov = @(& $prop $Settings 'Overrides' | Where-Object { $_ })
    [pscustomobject]@{
        NotImported = $review.ToArray(); Informational = $infos.ToArray(); LauncherOverrides = $ov
        ExitCode = $(if ($review.Count) { 2 } else { 0 })
    }
}

function ConvertTo-SIProImportReportJson {
    <# PURE. The import report as JSON (-ReportPath): what was planned / imported per part, the launcher overrides found, the
       informational notes and the "Not imported -- review" section with the exit code. #>
    param([Parameter(Mandatory)]$Review, $Settings, $Documents, $Items, $Connectors, [string]$SIRoot, [bool]$Applied, [string]$GeneratedAt)
    $rep = [ordered]@{
        schema      = 'securityinsight.import-report/1'
        generatedAt = $GeneratedAt
        installPath = $SIRoot
        applied     = $Applied
        exitCode    = $Review.ExitCode
        result      = $(if ($Review.ExitCode -eq 0) { 'everything imported' } else { 'items need review' })
        imported    = [ordered]@{
            settings   = @(@($Settings.Rows) | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = $_.Name; scope = $_.Scope; source = [string]$_.Source; line = $_.Line; keyVaultSecretName = [string]$_.KeyVaultSecretName } })
            documents  = @(@($Documents.Rows) | Where-Object { $_ } | ForEach-Object { [ordered]@{ kind = $_.Kind; key = $_.Key; source = $_.Source } })
            items      = @(@($Items.Rows) | Where-Object { $_ } | ForEach-Object { [ordered]@{ kind = $_.Kind; key = $_.Key; state = $_.State; source = $_.Source } })
            connectors = @(@($(if ($Connectors) { $Connectors.Rows })) | Where-Object { $_ -and $_.Action -ne 'same' } | ForEach-Object { [ordered]@{ name = [string]$_.Definition.Name; action = $_.Action } })
            sameAsTemplate = @(@($(if ($Items) { $Items.Same })) | Where-Object { $_ })
        }
        launcherOverrides = @($Review.LauncherOverrides | ForEach-Object { [ordered]@{ path = $_.Rel; scope = $_.Scope; settingsImported = $_.Imported; needsReview = $_.Review } })
        informational     = @($Review.Informational | ForEach-Object { [ordered]@{ section = $_.Section; path = $_.Path; name = $_.Name; reason = $_.Reason } })
        notImported       = @($Review.NotImported | ForEach-Object { [ordered]@{ section = $_.Section; kind = $_.Kind; path = $_.Path; line = $_.Line; name = $_.Name; reason = $_.Reason; text = $_.Text } })
    }
    ConvertTo-Json -InputObject $rep -Depth 6
}

function Get-SIProSettingsEngineName {
    <#
        PURE. The engine folder a container job's SI_ENGINE maps to -- the name `engine:<folder>` settings rows use (#211 (2)).
        The two Risk Analysis jobs share one folder, the close-loop job uses asset-cmdb's; every other container
        engine IS its launcher folder.
    #>
    param([Parameter(Mandatory)][string]$ContainerEngine)
    $e = $ContainerEngine.Trim().ToLowerInvariant()
    switch ($e) {
        'risk-analysis-detailed' { return 'risk-analysis' }
        'ptc'                    { return 'privilege-tier-classifier' }
        # the close-loop job is the VM's `asset-cmdb launcher -Vulnerabilities` (#216)
        'asset-vulnerabilities'  { return 'asset-cmdb' }
        # ...and so does the close-loop's daily mail job (engine\asset-cmdb\Invoke-SICloseLoopMail.ps1)
        'close-loop-mail'        { return 'asset-cmdb' }
        # ...and the SQL CMDB connector (#271, engine\asset-cmdb\Invoke-SICmdbSql.ps1)
        'asset-cmdb-sql'         { return 'asset-cmdb' }
        # the Pro data sync job (L-DATA) is the engine\pro-data folder
        'asset-datasync'         { return 'pro-data' }
        default                  { return $e }
    }
}
