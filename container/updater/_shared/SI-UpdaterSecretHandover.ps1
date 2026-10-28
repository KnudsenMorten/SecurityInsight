#Requires -Version 5.1
<#
    caj-si-updater -- SecurityInsight Pro: THE SECRET HAND-OVER (owner 2026-10-10: "this is a security concern, can we
    commit this to the engine and then the engine commits it, so the gui keeps read only if possible"). Loaded by
    Start-SIUpdater.ps1 when present (the Community edition has no Pro database and does not carry it).

    The web app NEVER writes a secret and holds no Key Vault right. It encrypts a pasted secret in memory -- a random
    AES-256-GCM data key encrypts the secret, RSA-OAEP-256 with the PUBLIC half of this updater's hand-over key wraps the
    data key -- and leaves only that ciphertext in cfg.PendingSecret (pro-management/src/SI.Management.Web/Settings/
    SecretHandover.cs). This file is the other half, run on EVERY updater run and alone in the short "apply settings" run
    the web app starts (SI_UPDATER_MODE = apply-settings):

      1. THE KEY PAIR: an RSA 3072 KEY in the install's Key Vault (SI_UPDATER_KEY_VAULT), 'SI-Settings-Handover' --
         a Key Vault key is never exportable, so the private half never leaves the vault; its PUBLIC half and version are
         published in cfg.SecretHandoverKey for the web app. Created once (keys/create), read on every run (keys/get).
      2. APPLY: every cfg.PendingSecret row -- the data key unwrapped INSIDE the vault (keys/decrypt), the secret decrypted
         here (AES-GCM, bound to the setting, the secret name and the key version), written to Key Vault (secrets PUT, the
         same right the licence step uses), the setting pointed at the secret's NAME (cfg.Setting KeyVaultSecretName), the
         row deleted and "stored" logged in cfg.ChangeLog -- in ONE transaction. A row that cannot be stored keeps a reason in
         plain words (no commands, no resource ids, no codes) until it is stored or replaced; a row waiting for days, or for
         a key version that no longer exists, is REPORTED (the run's failure report) -- never silently dropped.
      3. CONVERGE (existing installs): the web app's identity no longer needs "Key Vault Secrets Officer". The one grant
         SecurityInsight itself told a customer to make (the Get Started refusal before this release: that role, assigned
         to the web app's identity, at EXACTLY the vault's scope) is removed. Nothing else is touched: not an inherited
         assignment, not another scope, not another role, not another identity.

    Every Azure call goes through the run's ONE REST seam (-Rest, setup/_shared/SI-UpdateRest.ps1): pure REST, Key Vault
    api-version 7.4, no az CLI, no PowerShell module. The updater's identity needs "Key Vault Crypto Officer" on the vault
    for 1 and 2 (setup\Install-SIUpdaterJob.ps1 -GrantSpnRoles gives it) and "Key Vault Secrets Officer" (it has it).
    Nothing here throws into the run: each step returns what it did, in words.
#>

$script:SIHandoverKeyName = 'SI-Settings-Handover'
$script:SIKvApi = '7.4'
$script:SIHandoverOverdueDays = 3

function ConvertTo-SIB64Url {
    <# PURE. base64url (no padding). #>
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-SIB64Url {
    <# PURE. base64url -> bytes. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $t = $Text.Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    , [Convert]::FromBase64String($t)
}

function Get-SIHandoverAad {
    <# PURE. The AES-GCM additional data: binds a ciphertext to its setting, secret name and key version (the web app's SecretEnvelope.Aad). #>
    param([string]$SettingName, [string]$SecretName, [string]$KeyVersion)
    , [Text.Encoding]::UTF8.GetBytes(('si-secret-handover|{0}|{1}|{2}' -f $SettingName, $SecretName, $KeyVersion))
}

function Unprotect-SIHandoverPayload {
    <# AES-256-GCM decrypt of one pending secret with the unwrapped data key. Throws when the tag does not match. #>
    param([Parameter(Mandatory)][byte[]]$DataKey, [Parameter(Mandatory)][byte[]]$Nonce, [Parameter(Mandatory)][byte[]]$Tag,
          [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Ciphertext, [Parameter(Mandatory)][byte[]]$Aad)
    $aes = $null
    # .NET 8 (PowerShell 7.4+) takes the tag size; .NET 6 / 7 only the key
    try { $aes = [System.Security.Cryptography.AesGcm]::new($DataKey, 16) } catch { $aes = [System.Security.Cryptography.AesGcm]::new($DataKey) }
    $plain = New-Object byte[] $Ciphertext.Length
    try { $aes.Decrypt($Nonce, $Ciphertext, $Tag, $plain, $Aad) } finally { $aes.Dispose() }
    $text = [Text.Encoding]::UTF8.GetString($plain)
    [Array]::Clear($plain, 0, $plain.Length)
    $text
}

function Invoke-SIHandoverKv {
    <# One Key Vault data-plane call through the seam. Never throws: @{ Status; Json (parsed body or $null) }. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body)
    $b = if ($null -ne $Body -and -not ($Body -is [string])) { ConvertTo-Json -InputObject $Body -Depth 10 -Compress } else { $Body }
    $r = $null
    try { $r = & $Rest $Method $Uri $b 'https://vault.azure.net/' @{ 'Content-Type' = 'application/json' } } catch { $r = $null }
    $code = 0; try { $code = [int]$r.Status } catch { }
    $j = $null
    if ($r -and "$($r.Body)".Trim()) { try { $j = "$($r.Body)" | ConvertFrom-Json } catch { $j = $null } }
    [pscustomobject]@{ Status = $code; Json = $j }
}

function Get-SIHandoverPlainReason {
    <# PURE. A Key Vault answer in words a customer can act on -- no command, no resource id, no status code. #>
    param([int]$Status, [ValidateSet('key', 'decrypt', 'secret', 'grant')][string]$What)
    if ($Status -eq 401 -or $Status -eq 403) {
        switch ($What) {
            'key'     { return 'the updater may not create or read its hand-over key in your Key Vault yet. Run the updater setup again with its role grants -- it adds that right.' }
            'decrypt' { return 'the updater may not use its hand-over key in your Key Vault. Run the updater setup again with its role grants -- it adds that right.' }
            'secret'  { return 'the updater may not write secrets in your Key Vault. Run the updater setup again with its role grants.' }
            'grant'   { return 'the updater may not remove role assignments. The web app no longer needs to write secrets in your Key Vault: run the updater setup again with its role grants, and it removes that right.' }
        }
    }
    if ($Status -eq 404) {
        switch ($What) {
            'decrypt' { return 'the key it was encrypted with no longer exists in your Key Vault. Paste the key again.' }
            default   { return 'your Key Vault could not be found from the updater. Check the Key Vault on the Settings page.' }
        }
    }
    if ($Status -eq 0) { return 'your Key Vault could not be reached from the updater. It tries again on its next run.' }
    'your Key Vault did not accept the request. The updater tries again on its next run.'
}

function Publish-SIHandoverKey {
    <# The public half in cfg.SecretHandoverKey (current version marked, older ones kept but not current). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$KeyVersion, [Parameter(Mandatory)][string]$KeyName, [Parameter(Mandatory)][string]$PublicJwk)
    $sql = @'
IF OBJECT_ID(N'cfg.SecretHandoverKey') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.SecretHandoverKey WITH (UPDLOCK, HOLDLOCK) WHERE KeyVersion = @KeyVersion AND IsCurrent = 1 AND PublicJwk = @Jwk)
    AND NOT EXISTS (SELECT 1 FROM cfg.SecretHandoverKey WHERE KeyVersion <> @KeyVersion AND IsCurrent = 1)
BEGIN COMMIT; SELECT N'Current' AS Outcome; RETURN; END;
UPDATE cfg.SecretHandoverKey SET IsCurrent = 0 WHERE KeyVersion <> @KeyVersion AND IsCurrent = 1;
IF EXISTS (SELECT 1 FROM cfg.SecretHandoverKey WHERE KeyVersion = @KeyVersion)
    UPDATE cfg.SecretHandoverKey SET PublicJwk = @Jwk, KeyName = @KeyName, IsCurrent = 1, PublishedAt = SYSUTCDATETIME(), PublishedBy = @By WHERE KeyVersion = @KeyVersion;
ELSE
    INSERT cfg.SecretHandoverKey (KeyVersion, KeyName, PublicJwk, IsCurrent, PublishedBy) VALUES (@KeyVersion, @KeyName, @Jwk, 1, @By);
COMMIT;
SELECT N'Published' AS Outcome;
'@
    $rows = @(& $Store.Invoke $sql ([ordered]@{ KeyVersion = $KeyVersion; KeyName = $KeyName; Jwk = $PublicJwk; By = 'caj-si-updater' }) 'reader' | ForEach-Object { $_ })
    if (-not $rows.Count) { return 'Published' }
    $r = $rows[0]; if ($r -is [System.Collections.IDictionary]) { [string]$r['Outcome'] } else { [string]$r.Outcome }
}

function Initialize-SIUpdaterHandoverKey {
    <#
        Step 1: the hand-over key in -VaultName (created when missing: RSA 3072, never exportable) and its public half
        published for the web app. Returns @{ Ok; KeyVersion; Created; Reason; NeedsSetup (the updater lacks its Key Vault right:
        a customer action, not a failure -- ring 1 2026-10-10) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$VaultName, $Store)
    $base = 'https://{0}.vault.azure.net/keys/{1}' -f $VaultName, $script:SIHandoverKeyName
    $out = { param($ok, $ver, $created, $why, $setup = $false) [pscustomobject]@{ Ok = $ok; KeyVersion = $ver; Created = $created; Reason = $why; NeedsSetup = [bool]$setup } }
    $created = $false
    $g = Invoke-SIHandoverKv -Rest $Rest -Uri ('{0}?api-version={1}' -f $base, $script:SIKvApi)
    if ($g.Status -eq 404) {
        $body = [ordered]@{ kty = 'RSA'; key_size = 3072; key_ops = @('decrypt', 'encrypt'); attributes = [ordered]@{ enabled = $true; exportable = $false }
            tags = [ordered]@{ purpose = 'SecurityInsight secret hand-over: the web app encrypts, the updater decrypts in the vault' } }
        $g = Invoke-SIHandoverKv -Rest $Rest -Method POST -Uri ('{0}/create?api-version={1}' -f $base, $script:SIKvApi) -Body $body
        $created = $true
    }
    if ($g.Status -lt 200 -or $g.Status -ge 300 -or -not $g.Json -or -not $g.Json.key) {
        return (& $out $false '' $created ('The secure hand-over is not ready: ' + (Get-SIHandoverPlainReason -Status $g.Status -What key)) ($g.Status -in @(401, 403)))
    }
    $k = $g.Json.key
    $ver = ([string]$k.kid).TrimEnd('/').Split('/')[-1]
    if (-not $ver -or -not $k.n -or -not $k.e) { return (& $out $false '' $created 'The secure hand-over is not ready: the hand-over key in your Key Vault is not an RSA key. It is made again on the next run.') }
    if ($Store) {
        $jwk = ConvertTo-Json -InputObject ([ordered]@{ kty = 'RSA'; n = [string]$k.n; e = [string]$k.e }) -Compress
        try { $null = Publish-SIHandoverKey -Store $Store -KeyVersion $ver -KeyName $script:SIHandoverKeyName -PublicJwk $jwk }
        catch { return (& $out $false $ver $created ('The secure hand-over key could not be published in the Pro database: ' + $_.Exception.Message)) }
    }
    & $out $true $ver $created ('secure hand-over key {0} (version {1})' -f $(if ($created) { 'created' } else { 'present' }), $ver)
}

function Get-SIPendingSecretRows {
    <# Every cfg.PendingSecret row (empty when the table does not exist yet). #>
    param([Parameter(Mandatory)]$Store)
    $sql = "IF OBJECT_ID(N'cfg.PendingSecret') IS NOT NULL SELECT PendingId, SettingName, SecretName, KeyVersion, WrappedKey, Nonce, Tag, Ciphertext, CreatedBy, CreatedAt, Attempts, FailureText FROM cfg.PendingSecret ORDER BY PendingId"
    @(& $Store.Invoke $sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
}

function Get-SIRowValue { param($Row, [string]$Name) if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] } else { $Row.$Name } }

function Set-SIPendingSecretFailure {
    <# A row that could not be stored keeps the reason (plain words, at most 400 characters) and counts the attempt. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][long]$PendingId, [Parameter(Mandatory)][string]$Reason)
    $why = $Reason.Trim(); if ($why.Length -gt 400) { $why = $why.Substring(0, 397) + '...' }
    $null = & $Store.Invoke 'UPDATE cfg.PendingSecret SET Attempts = Attempts + 1, LastAttemptAt = SYSUTCDATETIME(), FailureText = @Why WHERE PendingId = @Id' ([ordered]@{ Id = $PendingId; Why = $why }) 'nonquery'
}

# #822 THE ALLOW-LIST, the SAME rules as the web app's SecretAllowList.cs (pro-management/src/SI.Management.Web/Settings) --
# a test (SIv3-SecretAllowList.Tests.ps1) keeps the two equal. The updater checks it again BEFORE it decrypts or writes, so
# a row that did not come from the web app's handler (a hand-made INSERT) can still never set an Invardia-issued secret.
$script:SIHandoverAllowedSettings = [ordered]@{ 'OpenAI_apiKey' = 'SI-OpenAI-Key'; 'SMTPPassword' = 'SI-Smtp-Password'; 'SI_Shodan_ApiKey' = 'SI-Shodan-ApiKey'; 'SHODAN_ApiKey' = 'SI-Shodan-ApiKey' }
$script:SIHandoverConnectorRefs = @('instance', 'user', 'password', 'apikey', 'token', 'clientId', 'clientSecret')
$script:SIHandoverConnectorPrefixes = @('SI-ServiceNow-', 'SI-Connector-')
$script:SIHandoverInvardiaIssued = @('SI-Invardia-InstallKey', 'SI-InstallId', 'SI-License', 'SI-Update-State', 'SI-Settings-Handover',
    'SI-LicenceRequest-State', 'SI-LicenceRequest-Notice', 'SI-LicenceRequest-PullToken')
$script:SIHandoverConnectorTargetPrefix = 'connector:'

function Test-SIHandoverAllowed {
    <# PURE. '' = this hand-over (setting or connector:name/ref, secret name) may be written; else why not, in plain words. #>
    param([AllowEmptyString()][string]$Target, [AllowEmptyString()][string]$SecretName)
    if ($SecretName -cnotmatch '^[0-9A-Za-z-]{1,127}$') { return 'not a Key Vault secret name' }
    foreach ($n in $script:SIHandoverInvardiaIssued) { if ($SecretName -ieq $n) { return 'this secret is issued by Invardia or kept by the product itself -- it is never set from the web app' } }
    if ($SecretName -ilike 'SI-Invardia-*' -or $SecretName -ilike 'SI-LicenceRequest-*') { return 'this secret is issued by Invardia or kept by the product itself -- it is never set from the web app' }
    if ($Target.StartsWith($script:SIHandoverConnectorTargetPrefix, [StringComparison]::Ordinal)) {
        $rest = $Target.Substring($script:SIHandoverConnectorTargetPrefix.Length)
        $slash = $rest.LastIndexOf('/')
        if ($slash -le 0) { return 'not a connector secret' }
        $name = $rest.Substring(0, $slash); $ref = $rest.Substring($slash + 1)
        if ($name -cnotmatch '^[A-Za-z0-9 _.-]{1,100}$') { return 'not a connector name' }
        if (-not ($script:SIHandoverConnectorRefs | Where-Object { $_ -ieq $ref })) { return ("'{0}' is not a connector secret that can be set from the web app" -f $ref) }
        if (-not ($script:SIHandoverConnectorPrefixes | Where-Object { $SecretName.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) { return 'a connector secret must be named SI-ServiceNow-... or SI-Connector-...' }
        return ''
    }
    if (-not $script:SIHandoverAllowedSettings.Contains($Target)) { return ("'{0}' is not a secret that can be set from the web app" -f $Target) }
    if ([string]$script:SIHandoverAllowedSettings[$Target] -cne $SecretName) { return ("'{0}' is stored as {1}" -f $Target, $script:SIHandoverAllowedSettings[$Target]) }
    ''
}

function Complete-SIPendingSecret {
    <#
        The secret is in Key Vault: in ONE transaction the setting names the secret (cfg.Setting KeyVaultSecretName, scope
        'solution'), the change is logged "stored" (never the value) and the pending row is deleted.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][long]$PendingId, [Parameter(Mandatory)][string]$SettingName,
          [Parameter(Mandatory)][string]$SecretName, [Parameter(Mandatory)][string]$By)
    # #822: a CONNECTOR secret (connector:name/ref) -- the connector row already names the secret, so no setting is pointed
    # at it; both kinds leave the 'secret-stored' line the page reads ("set at ... by ...", never the value)
    $sql = (Get-SICompletePendingSecretSql -Connector:($SettingName.StartsWith($script:SIHandoverConnectorTargetPrefix, [StringComparison]::Ordinal)))
    $null = & $Store.Invoke $sql ([ordered]@{ Id = $PendingId; Name = $SettingName; Kv = $SecretName; By = $By }) 'nonquery'
}

function Get-SICompletePendingSecretSql {
    <# PURE. The one transaction that completes a stored secret: a setting is pointed at its name (not a connector secret);
       the 'secret-stored' line is written; the pending row deleted. #>
    param([switch]$Connector)
    $setting = if ($Connector) { '' } else { @'
DECLARE @old nvarchar(max) = (SELECT COALESCE(ValueJson, N'keyvault:' + KeyVaultSecretName) FROM cfg.Setting WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name AND Scope = N'solution');
IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @Name AND Scope = N'solution')
    UPDATE cfg.Setting SET ValueJson = NULL, KeyVaultSecretName = @Kv, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name AND Scope = N'solution';
ELSE
    INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@Name, N'solution', NULL, @Kv, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, N'solution', N'Set', @old, N'keyvault:' + @Kv, @By, N'stored in Key Vault by the updater (handed over in the web app; the value is never recorded)');
'@ }
    @"
SET XACT_ABORT ON;
BEGIN TRAN;
EXEC sys.sp_set_session_context @key = N'si.audit.actor', @value = @By;
EXEC sys.sp_set_session_context @key = N'si.cfg.source', @value = N'gui';
EXEC sys.sp_set_session_context @key = N'si.cfg.reason', @value = N'secret handed over in the web app, stored in Key Vault by the updater';
$setting
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, N'secret-stored', N'Set', NULL, N'keyvault:' + @Kv, @By, N'secret set in the web app, stored in Key Vault by the updater (the value is never recorded)');
DELETE FROM cfg.PendingSecret WHERE PendingId = @Id;
COMMIT;
"@
}

function Invoke-SIUpdaterPendingSecrets {
    <#
        Step 2: every pending secret -> Key Vault (-SecretVault), the data key unwrapped in -KeyVault. Returns
        @{ Stored; Failed; Overdue (texts to REPORT); Lines }. -Now: tests.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$KeyVault,
          [Parameter(Mandatory)][string]$SecretVault, [datetime]$Now = [datetime]::UtcNow)
    $stored = 0; $failed = 0
    $overdue = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($row in @(Get-SIPendingSecretRows -Store $Store)) {
        $id = [long](Get-SIRowValue $row 'PendingId'); $setting = [string](Get-SIRowValue $row 'SettingName'); $secret = [string](Get-SIRowValue $row 'SecretName')
        $ver = [string](Get-SIRowValue $row 'KeyVersion'); $by = [string](Get-SIRowValue $row 'CreatedBy')
        $created = Get-SIRowValue $row 'CreatedAt'
        $why = ''
        $refused = Test-SIHandoverAllowed -Target $setting -SecretName $secret
        if ($refused) {
            # #822: never decrypted, never written -- the reason stays on the row for the page
            $why = ('it is not a secret the web app may set ({0}). Nothing was written.' -f $refused)
        } elseif ($secret -notmatch '^[0-9A-Za-z-]{1,127}$' -or $ver -notmatch '^[0-9A-Za-z]{1,64}$') {
            $why = 'it was handed over with a name the updater cannot use. Paste the key again.'
        } else {
            $dec = Invoke-SIHandoverKv -Rest $Rest -Method POST -Uri ('https://{0}.vault.azure.net/keys/{1}/{2}/decrypt?api-version={3}' -f $KeyVault, $script:SIHandoverKeyName, $ver, $script:SIKvApi) `
                       -Body ([ordered]@{ alg = 'RSA-OAEP-256'; value = [string](Get-SIRowValue $row 'WrappedKey') })
            if ($dec.Status -lt 200 -or $dec.Status -ge 300 -or -not $dec.Json -or -not $dec.Json.value) {
                $why = Get-SIHandoverPlainReason -Status $dec.Status -What decrypt
                if ($dec.Status -eq 404) { $overdue.Add(('a waiting secret for {0} was encrypted with a hand-over key version that no longer exists' -f $setting)) }
            } else {
                $dataKey = $null; $plain = $null
                try {
                    $dataKey = ConvertFrom-SIB64Url ([string]$dec.Json.value)
                    $plain = Unprotect-SIHandoverPayload -DataKey $dataKey -Nonce (ConvertFrom-SIB64Url ([string](Get-SIRowValue $row 'Nonce'))) -Tag (ConvertFrom-SIB64Url ([string](Get-SIRowValue $row 'Tag'))) `
                                 -Ciphertext (ConvertFrom-SIB64Url ([string](Get-SIRowValue $row 'Ciphertext'))) -Aad (Get-SIHandoverAad -SettingName $setting -SecretName $secret -KeyVersion $ver)
                } catch { $plain = $null }
                finally { if ($dataKey) { [Array]::Clear($dataKey, 0, $dataKey.Length) } }
                if ($null -eq $plain) {
                    $why = 'it could not be decrypted (it was changed after it was handed over). Paste the key again.'
                } else {
                    $put = Invoke-SIHandoverKv -Rest $Rest -Method PUT -Uri ('https://{0}.vault.azure.net/secrets/{1}?api-version={2}' -f $SecretVault, $secret, $script:SIKvApi) `
                               -Body ([ordered]@{ value = $plain; contentType = ('SecurityInsight: {0}' -f $setting) })
                    $plain = $null
                    if ($put.Status -lt 200 -or $put.Status -ge 300) { $why = Get-SIHandoverPlainReason -Status $put.Status -What secret }
                    else {
                        try {
                            Complete-SIPendingSecret -Store $Store -PendingId $id -SettingName $setting -SecretName $secret -By $(if ($by) { $by } else { 'caj-si-updater' })
                            $stored++
                            $lines.Add($(if ($setting.StartsWith($script:SIHandoverConnectorTargetPrefix, [StringComparison]::Ordinal)) { 'secret for {0} stored in Key Vault as {1}; the connector names it' -f $setting, $secret } else { 'secret for {0} stored in Key Vault as {1}; the setting names it' -f $setting, $secret }))
                        } catch { $why = 'it is in your Key Vault, but the setting could not be pointed at it. The updater tries again on its next run.' }
                    }
                }
            }
        }
        if ($why) {
            $failed++
            try { Set-SIPendingSecretFailure -Store $Store -PendingId $id -Reason $why } catch { $lines.Add(('WARNING: the reason could not be recorded on the waiting secret for {0}: {1}' -f $setting, $_.Exception.Message)) }
            $lines.Add(('secret for {0} NOT stored: {1}' -f $setting, $why))
            # a secret that has waited for days is REPORTED, never silently dropped (the row stays, with its reason)
            if ($created -is [datetime] -and ($Now - $created).TotalDays -gt $script:SIHandoverOverdueDays) {
                $overdue.Add(('a secret for {0} has been waiting to be stored since {1:yyyy-MM-dd}' -f $setting, $created))
            }
        }
    }
    [pscustomobject]@{ Stored = $stored; Failed = $failed; Overdue = $overdue.ToArray(); Lines = $lines.ToArray() }
}

function Select-SIWebSecretGrant {
    <#
        PURE. Of -Assignments (ARM role assignments as listed at the vault), ONLY the grant SecurityInsight told customers to
        make for the web app: role "Key Vault Secrets Officer", principal -PrincipalId (the web app's identity), scope EXACTLY
        -VaultId. An inherited assignment (resource group, subscription), another role or another identity never matches.
    #>
    param([AllowEmptyCollection()][object[]]$Assignments, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$VaultId)
    $vid = $VaultId.TrimEnd('/')
    # The role id lives here, not in a $script: variable: setup\Install-SIUpdaterJob.ps1 calls this function from ITS script,
    # where $script: is the installer's scope -- a function loaded earlier would see no role id there and match nothing.
    $officer = 'b86a8fe4-c7d1-4c71-91f0-9e0ab7c7da1b'   # Key Vault Secrets Officer (built-in, the same id in every tenant)
    @(@($Assignments) | Where-Object {
        $_ -and $_.properties -and
        ((([string]$_.properties.roleDefinitionId).TrimEnd('/') -split '/')[-1]) -ieq $officer -and
        ([string]$_.properties.principalId) -ieq $PrincipalId -and
        (([string]$_.properties.scope).TrimEnd('/')) -ieq $vid
    })
}

function Get-SIUpdaterWebPrincipalIds {
    <# The principal (object) ids of the web app's identities: its user-assigned identities and its system identity. #>
    param([Parameter(Mandatory)][string]$WebApp, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    $a = $null
    try { $a = Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $a = $null }
    if (-not $a -or -not $a.identity) { return @() }
    $ids = New-Object System.Collections.Generic.List[string]
    if ($a.identity.PSObject.Properties['principalId'] -and $a.identity.principalId) { $ids.Add([string]$a.identity.principalId) }
    if ($a.identity.PSObject.Properties['userAssignedIdentities'] -and $a.identity.userAssignedIdentities) {
        foreach ($p in @($a.identity.userAssignedIdentities.PSObject.Properties)) { if ($p.Value -and $p.Value.principalId) { $ids.Add([string]$p.Value.principalId) } }
    }
    @($ids | Select-Object -Unique)
}

function Get-SIUpdaterVaultId {
    <# The vault's ARM id: in -ResourceGroup, else among the subscription's vaults. '' when it cannot be found. #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup)
    $v = $null
    if ($ResourceGroup) { try { $v = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.KeyVault/vaults/' + $VaultName)) -ApiVersion '2023-07-01' -AllowNotFound } catch { $v = $null } }
    if (-not $v) { try { $v = @(Invoke-SIUpdaterArm -Path ('/subscriptions/{0}/providers/Microsoft.KeyVault/vaults' -f $SubscriptionId) -ApiVersion '2023-07-01' -List | Where-Object { $_ -and ([string]$_.name) -ieq $VaultName }) | Select-Object -First 1 } catch { $v = $null } }
    if ($v) { [string]$v.id } else { '' }
}

function Remove-SIUpdaterWebSecretGrant {
    <#
        Step 3 (CONVERGE-DEFAULTS): the web app's "Key Vault Secrets Officer" at exactly the vault (Select-SIWebSecretGrant)
        is removed. Returns @{ Removed; Reason }. Never throws; a refusal is said in plain words (and reported).
    #>
    param([Parameter(Mandatory)][string]$VaultId, [AllowEmptyCollection()][string[]]$PrincipalIds)
    $removed = 0
    foreach ($principal in @($PrincipalIds | Where-Object { $_ })) {
        $list = @()
        try { $list = @(Invoke-SIUpdaterArm -Path ($VaultId.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments?$filter=' + [uri]::EscapeDataString(("principalId eq '{0}'" -f $principal))) -ApiVersion '2022-04-01' -List) }
        catch { return [pscustomobject]@{ Removed = $removed; Reason = 'The web app''s old Key Vault right could not be checked from the updater. It checks again on its next run.' } }
        foreach ($a in @(Select-SIWebSecretGrant -Assignments $list -PrincipalId $principal -VaultId $VaultId)) {
            try { $null = Invoke-SIUpdaterArm -Method DELETE -Path ([string]$a.id) -ApiVersion '2022-04-01' -AllowNotFound; $removed++ }
            catch {
                $st = if ("$($_.Exception.Message)" -match 'HTTP (\d{3})') { [int]$Matches[1] } else { 0 }
                return [pscustomobject]@{ Removed = $removed; Reason = ('The web app still holds the right to write secrets in your Key Vault: ' + (Get-SIHandoverPlainReason -Status $st -What grant)) }
            }
        }
    }
    [pscustomobject]@{ Removed = $removed; Reason = $(if ($removed) { 'the web app''s right to write secrets in your Key Vault was removed (it hands secrets to the updater now)' } else { '' }) }
}

function Get-SIUpdaterSecretVault {
    <# The vault the secrets go to: the Settings page's Key Vault name (SI_KeyVaultName, where the engines read them), else the updater's. #>
    param($Store, [Parameter(Mandatory)][string]$UpdaterVault)
    if ($Store) {
        try {
            $rows = @(& $Store.Invoke "SELECT TOP (1) ValueJson FROM cfg.Setting WHERE Name = N'SI_KeyVaultName' AND Scope = N'solution'" @{} 'reader' | ForEach-Object { $_ })
            if ($rows.Count) {
                $v = [string](Get-SIRowValue $rows[0] 'ValueJson')
                if ($v) { try { $v = [string]($v | ConvertFrom-Json) } catch { } ; $v = $v.Trim('"').Trim() }
                if ($v -match '^[A-Za-z][A-Za-z0-9-]{2,23}$') { return $v }
            }
        } catch { }
    }
    $UpdaterVault
}

function Invoke-SIUpdaterSecretHandover {
    <#
        The three steps, in order, for one run. Never throws. Returns @{ Key; Apply; Grant; Report (texts for the run's
        failure report) }. -Log { param($m) }. -WebApp: the web app's container app (SI_UPDATER_WEB_APP, ca-si-management).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, $Store, [Parameter(Mandatory)][string]$KeyVault, [string]$SubscriptionId, [string]$ResourceGroup,
          [string]$WebApp = 'ca-si-management', [scriptblock]$Log = { param($m) }, [datetime]$Now = [datetime]::UtcNow)
    $report = New-Object System.Collections.Generic.List[string]
    $action = New-Object System.Collections.Generic.List[string]
    $key = $null; $apply = $null; $grant = $null
    try {
        if (-not $Store) { & $Log 'secret hand-over: no Pro database on this install -- nothing to hand over'; return [pscustomobject]@{ Key = $null; Apply = $null; Grant = $null; Report = @(); CustomerAction = @() } }
        $key = Initialize-SIUpdaterHandoverKey -Rest $Rest -VaultName $KeyVault -Store $Store
        & $Log ('secret hand-over: {0}' -f $key.Reason)
        # ring 1 2026-10-10 (Invardia fix request): the updater may not use its hand-over key yet = the install has not re-run
        # the updater setup with its role grants since the hand-over arrived. EXPECTED, the customer's action -- never an
        # update failure: reported as a customer action (kv-403) with the exact command (the run's own words stay plain).
        if (-not $key.Ok -and $key.NeedsSetup) { $action.Add(('{0} Command: {1}' -f $key.Reason, (Get-SIHandoverSetupCommand -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup))) }
        elseif (-not $key.Ok) { $report.Add($key.Reason) }
        $apply = Invoke-SIUpdaterPendingSecrets -Rest $Rest -Store $Store -KeyVault $KeyVault -SecretVault (Get-SIUpdaterSecretVault -Store $Store -UpdaterVault $KeyVault) -Now $Now
        foreach ($l in @($apply.Lines)) { & $Log ('secret hand-over: {0}' -f $l) }
        foreach ($o in @($apply.Overdue)) { & $Log ('secret hand-over: REPORTED -- {0}' -f $o); $report.Add($o) }
        if ($SubscriptionId -and $WebApp) {
            $vid = Get-SIUpdaterVaultId -VaultName $KeyVault -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
            if ($vid) {
                $grant = Remove-SIUpdaterWebSecretGrant -VaultId $vid -PrincipalIds @(Get-SIUpdaterWebPrincipalIds -WebApp $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId)
                if ($grant.Reason) { & $Log ('secret hand-over: {0}' -f $grant.Reason) }
                if ($grant.Reason -and -not $grant.Removed) { $report.Add($grant.Reason) }
            }
        }
    } catch {
        & $Log ('secret hand-over: WARNING {0}' -f $_.Exception.Message)
        $report.Add(('the secret hand-over step stopped: {0}' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Key = $key; Apply = $apply; Grant = $grant; Report = $report.ToArray(); CustomerAction = $action.ToArray() }
}

function Get-SIHandoverSetupCommand {
    <# PURE. The exact command that gives the updater its Key Vault rights (Key Vault Crypto Officer for the hand-over key):
       the updater setup with its role grants, for THIS install's subscription and resource group. #>
    param([AllowEmptyString()][string]$SubscriptionId, [AllowEmptyString()][string]$ResourceGroup)
    $s = if ("$SubscriptionId".Trim()) { "$SubscriptionId".Trim() } else { '<subscription id>' }
    $g = if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { '<resource group of the SecurityInsight jobs>' }
    '.\setup\Install-SIUpdaterJob.ps1 -SubscriptionId {0} -ResourceGroupName {1} -GrantSpnRoles' -f $s, $g
}

function Get-SIHandoverControlState {
    <# PURE. The setup report's secret-handover control from this run's hand-over result: ok (the key is ready), missing (the
       updater lacks its Key Vault right -- the customer re-runs the updater setup), $null (no Pro database / not known). #>
    param([AllowNull()]$Result)
    if ($null -eq $Result -or $null -eq $Result.Key) { return $null }
    if ($Result.Key.Ok) { return 'ok' }
    if ($Result.Key.PSObject.Properties['NeedsSetup'] -and $Result.Key.NeedsSetup) { return 'missing' }
    $null
}
