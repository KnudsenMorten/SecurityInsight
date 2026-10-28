#Requires -Version 5.1
<#
    SecurityInsight Pro -- WHAT IT DOES WITH INVARDIA BY ITSELF, and the two switches that turn it off.

    Owner decision 2026-10-05 (the same treatment as the status reports): a Pro install asks Invardia for its licence by
    itself and takes its Pro updates from Invardia by itself -- both ON by default, fresh and upgraded installs alike, and
    both switchable by the customer:

      SI_LicenseRequest_Auto      the updater job asks Invardia for a licence when there is none, it ends within 30 days,
                                  or it is in its grace period; quiet while the licence is valid.
                                  Job environment: SI_LICENSE_REQUEST_AUTO.
      SI_InvardiaUpdate_Enabled   the updater job checks Invardia for this install's ring and applies a release (signed
                                  manifest, hold on a manual step or a too-old version, restore on failure).
                                  Job environment: SI_INVARDIA_UPDATE_ENABLED.

    Where a switch comes from, first wins: the Pro settings database (cfg.Setting, scope 'solution' -- the web app's
    Settings page), then the job's environment, else ON. If the Pro database cannot be READ the step is skipped for this
    run (a customer's "off" is never overruled by an unreadable database).

    The licence notice: what the updater audits and mails after a licence request (Get-SILicenceRequestNotice). Success
    (a licence installed) and failure (refused, rejected, invalid, network, error) are audited and mailed; a failure that
    keeps repeating is mailed again only after 7 days. Nothing is said while the licence is valid or a request is waiting.

    Everything here is PURE except Read-SIProSolutionSettings (one SELECT through the store's seam). Never throws.
    Customer-facing words only. PS 5.1 and 7.
#>

$script:SIProAuto = @{
    Switches = [ordered]@{
        SI_LicenseRequest_Auto    = @{ Env = 'SI_LICENSE_REQUEST_AUTO';    Label = 'automatic licence request';  OffText = 'automatic licence request is off' }
        SI_InvardiaUpdate_Enabled = @{ Env = 'SI_INVARDIA_UPDATE_ENABLED'; Label = 'Pro updates from Invardia'; OffText = 'Pro updates from Invardia are off' }
    }
    RemailDays   = 7
    NoticeSecret = 'SI-LicenceRequest-Notice'
}

function ConvertTo-SIProAutoFlag {
    <# PURE. $true / 'true' / '1' / 'on' / 'yes' -> $true; $false / 'false' / '0' / 'off' / 'no' / 'disabled' -> $false; anything else -> $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = "$Value".Trim().Trim('$').Trim('"').ToLowerInvariant()
    if ($s -in @('true', '1', 'on', 'yes', 'enabled')) { return $true }
    if ($s -in @('false', '0', 'off', 'no', 'disabled')) { return $false }
    $null
}

function Get-SIProAutoSwitchNames { @($script:SIProAuto.Switches.Keys) }

function Resolve-SIProAutoSwitch {
    <#
        PURE. One switch: -SettingValue (the Pro settings value, or a $global: on a VM), then -EnvValue (the job's
        environment), else ON. Returns @{ Name; On; Source = setting | environment | default; Text }.
    #>
    param([Parameter(Mandatory)][ValidateSet('SI_LicenseRequest_Auto', 'SI_InvardiaUpdate_Enabled')][string]$Name,
          [AllowNull()]$SettingValue, [AllowNull()][AllowEmptyString()][string]$EnvValue)
    $def = $script:SIProAuto.Switches[$Name]
    $on = $true; $src = 'default'
    $v = ConvertTo-SIProAutoFlag $SettingValue
    if ($null -ne $v) { $on = $v; $src = 'setting' }
    else {
        $e = ConvertTo-SIProAutoFlag $EnvValue
        if ($null -ne $e) { $on = $e; $src = 'environment' }
    }
    $how = switch ($src) { 'setting' { "the setting $Name" } 'environment' { "the job setting $($def.Env)" } default { 'the default' } }
    $text = if ($on) { '{0} is on ({1})' -f $def.Label, $how } else { '{0} ({1}) -- nothing is asked from Invardia for it' -f $def.OffText, $how }
    [pscustomobject]@{ Name = $Name; On = [bool]$on; Source = $src; Text = $text }
}

function Read-SIProSolutionSettings {
    <#
        The Pro database's solution-wide settings (cfg.Setting, scope 'solution') through a store's (sql, params, mode)
        seam. Returns @{ Ok; Values = name -> value (parsed JSON); Secrets = name -> Key Vault secret name; Error }.
        No database = Ok with nothing in it. Never throws.
    #>
    param($Store, [scriptblock]$Invoke)
    $res = [pscustomobject]@{ Ok = $true; Values = @{}; Secrets = @{}; Error = '' }
    if (-not $Invoke -and $Store) { $Invoke = $Store.Invoke }
    if (-not $Invoke) { return $res }
    try {
        $sql = "IF OBJECT_ID(N'cfg.Setting') IS NULL SELECT CAST(NULL AS NVARCHAR(128)) AS Name, CAST(NULL AS NVARCHAR(MAX)) AS ValueJson, CAST(NULL AS NVARCHAR(256)) AS KeyVaultSecretName WHERE 1 = 0; ELSE SELECT Name, ValueJson, KeyVaultSecretName FROM cfg.Setting WHERE Scope = N'solution';"
        foreach ($r in @(& $Invoke $sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ })) {
            $name = [string]$r['Name']; if (-not $name) { continue }
            $kv = [string]$r['KeyVaultSecretName']
            if ($kv) { $res.Secrets[$name] = $kv; continue }
            $raw = [string]$r['ValueJson']
            $v = $null; try { $v = $raw | ConvertFrom-Json -ErrorAction Stop } catch { $v = $raw }
            $res.Values[$name] = $v
        }
    } catch { $res.Ok = $false; $res.Error = [string]$_.Exception.Message }
    $res
}

function Get-SIProAutoSwitches {
    <#
        Both switches for the updater: -Settings (Read-SIProSolutionSettings), -Env (a hashtable, else the process
        environment). An unreadable database (-Settings.Ok = $false) turns BOTH steps off for this run, saying why.
        Returns name -> Resolve-SIProAutoSwitch result.
    #>
    param($Settings, [hashtable]$Env = @{})
    $out = [ordered]@{}
    foreach ($n in (Get-SIProAutoSwitchNames)) {
        $envName = $script:SIProAuto.Switches[$n].Env
        $ev = if ($Env.ContainsKey($envName)) { [string]$Env[$envName] } else { [Environment]::GetEnvironmentVariable($envName) }
        if ($Settings -and -not $Settings.Ok) {
            $out[$n] = [pscustomobject]@{ Name = $n; On = $false; Source = 'unreadable'
                                          Text = ('{0}: skipped this run -- the Pro settings database could not be read, so a switch set to off there cannot be seen ({1})' -f $script:SIProAuto.Switches[$n].Label, $Settings.Error) }
            continue
        }
        $sv = if ($Settings -and $Settings.Values.ContainsKey($n)) { $Settings.Values[$n] } else { $null }
        $out[$n] = Resolve-SIProAutoSwitch -Name $n -SettingValue $sv -EnvValue $ev
    }
    $out
}

# =====================================================================================================================
#  The licence notice -- what the updater audits and mails after a licence request
# =====================================================================================================================
function Get-SILicenceRequestNotice {
    <#
        PURE. -Result: the licence request client's result (Action, Message, State). -Contacted: whether this run called
        Invardia. -Previous: the last mailed notice (@{ key; mailedUtc }) or $null.
        Returns @{ Kind = quiet | sent | success | failure; Audit (@{ Action; Outcome; Text } or $null); Mail ($true/$false);
                   Key; Subject; Lines }.
          none / pending / waiting (nothing new)                    -> quiet: no audit, no mail
          knocked (a request was sent)                              -> audit licence.request.send, no mail
          installed                                                 -> audit licence.request.install + mail (success)
          refused / rejected / invalid / network / error            -> audit licence.request.fail (when Invardia was called
                                                                       or the request could not even be made) + mail, the
                                                                       same failure at most once every 7 days
    #>
    param([AllowNull()]$Result, [bool]$Contacted = $false, [AllowNull()]$Previous, [datetime]$NowUtc = [datetime]::UtcNow)
    $q = [pscustomobject]@{ Kind = 'quiet'; Audit = $null; Mail = $false; Key = ''; Subject = ''; Lines = @() }
    if (-not $Result) { return $q }
    $a = [string]$Result.Action
    $msg = [string]$Result.Message
    $validTo = ''; try { if ($Result.State -and $Result.State.PSObject.Properties['ValidTo']) { $validTo = [string]$Result.State.ValidTo } } catch { }
    switch ($a) {
        'knocked' {
            return [pscustomobject]@{ Kind = 'sent'; Audit = @{ Action = 'licence.request.send'; Outcome = 'ok'; Text = $msg }; Mail = $false; Key = ''; Subject = ''; Lines = @() }
        }
        'installed' {
            $lines = @('SecurityInsight Pro asked Invardia for its licence by itself, and the new licence is installed.',
                       $(if ($validTo) { ' - It is valid until {0}.' -f $validTo } else { ' - ' + $msg }),
                       ' - Nothing needs to be done. To stop these automatic requests, set "Automatic licence request" (SI_LicenseRequest_Auto) to off on the Settings page.')
            return [pscustomobject]@{ Kind = 'success'; Audit = @{ Action = 'licence.request.install'; Outcome = 'ok'; Text = $msg }; Mail = $true
                                      Key = 'installed|' + $validTo; Subject = 'New Pro licence installed'; Lines = $lines }
        }
        { $_ -in @('refused', 'rejected', 'invalid', 'network', 'error') } {
            # a rejection still waiting out its 7 days, or a request not repeated yet, is not news: no call was made
            $news = $Contacted -or $a -in @('refused', 'error')
            if (-not $news) { return $q }
            $key = 'failure|' + $a
            $mail = $true
            if ($Previous -and [string]$Previous.key -eq $key -and $Previous.mailedUtc) {
                try { if ($NowUtc -lt ([datetime]$Previous.mailedUtc).ToUniversalTime().AddDays($script:SIProAuto.RemailDays)) { $mail = $false } } catch { }
            }
            $what = switch ($a) {
                'rejected' { 'Invardia rejected the licence request.' }
                'invalid'  { 'Invardia refused the licence request as incomplete.' }
                'network'  { 'Invardia could not be reached for the licence request.' }
                'refused'  { 'The licence request could not be made, or the licence Invardia sent did not pass the checks and was not installed.' }
                default    { 'The licence request did not complete.' }
            }
            $lines = @(('SecurityInsight Pro asked Invardia for its licence by itself, and it did not succeed. {0}' -f $what),
                       (' - Details: {0}' -f $msg),
                       ' - The current licence (if any) stays in place; the request is tried again on the next nightly run.',
                       ' - To ask by hand, run Request-SILicense in the setup folder. To stop the automatic requests, set "Automatic licence request" (SI_LicenseRequest_Auto) to off on the Settings page.',
                       ' - Licences: https://portal.invardia.com/ > Licences. Questions: info@invardia.com.')
            return [pscustomobject]@{ Kind = 'failure'; Audit = @{ Action = 'licence.request.fail'; Outcome = $(if ($a -eq 'rejected') { 'refused' } else { 'error' }); Text = $msg }
                                      Mail = $mail; Key = $key; Subject = 'Failed: the automatic Pro licence request did not succeed'; Lines = $lines }
        }
    }
    $q
}

function ConvertTo-SIProAutoMailHtml {
    <# PURE. Notice lines -> the HTML body in the one mail layout (MAIL-2 / #573, SI-MailLayout.ps1): the first line is the
       summary, the " - " lines a list; everything encoded, real paragraphs. #>
    param([AllowEmptyCollection()][string[]]$Lines, [string]$Title = 'SecurityInsight Pro')
    if (-not (Get-Command -Name New-SIMailLayout -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-MailLayout.ps1')) }
    $first = [string]@($Lines)[0]
    $rest = @(@($Lines) | Select-Object -Skip 1 | Where-Object { "$_".Trim() } | ForEach-Object { '- ' + ($_ -replace '^\s*-\s*', '').Trim() })
    (New-SIMailLayout -Title $Title -Summary $first -Paragraphs @(($rest -join "`n"))).Html
}

# =====================================================================================================================
#  The one-time notice (first run after the update, Pro) -- SI-FirstRun.ps1 shows it
# =====================================================================================================================
function Get-SIProAutoNoticeLines {
    <# PURE. The one-time notice: what a Pro install now does with Invardia by itself, and how to switch each off. #>
    param([bool]$LicenceOn = $true, [bool]$UpdatesOn = $true)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('SecurityInsight Pro now works with Invardia by itself. Nothing needs to be done:')
    if ($LicenceOn) { $l.Add(' - Automatic licence request: every night the updater job asks Invardia for this installation''s licence when there is none, it ends within 30 days or it is in its grace period. The result is recorded in the audit trail and mailed to you. To turn it off, set "Automatic licence request" (SI_LicenseRequest_Auto) to off on the Settings page, or SI_LICENSE_REQUEST_AUTO=false on the updater job.') }
    if ($UpdatesOn) { $l.Add(' - Pro updates from Invardia: every night the updater job checks Invardia for a release approved for this installation''s ring, verifies its signature and applies it, restoring the previous version if anything fails. To turn it off, set "Pro updates from Invardia" (SI_InvardiaUpdate_Enabled) to off on the Settings page, or SI_INVARDIA_UPDATE_ENABLED=false on the updater job.') }
    $l.Add(' - This notice is shown once.')
    @($l.ToArray())
}
