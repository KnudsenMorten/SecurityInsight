<#
.SYNOPSIS
    Sets (or resets) ONE SecurityInsight Pro setting by its name -- the same row Settings in the Pro web app writes, with
    its change log entry. PLAN BY DEFAULT; -Apply writes.

.DESCRIPTION
    For a setting an operator or support must change without the web app (a guard switch at night, a setting the web
    app does not offer yet). The value is validated by the same rules the engines read it with (Set-SIProSetting in
    engine\pro-settings\SI-ProSettings.ps1: the catalog's type, limits, choices); the write and its cfg.ChangeLog row
    are one transaction, and -Reason is recorded with it. No PowerShell module; the Pro database is reached with the
    install's own identity (or -AppId / -TenantId / -CertThumbprint), or with -SupportSql through the Invardia Support
    app's audited Invoke-InvardiaSupportSql (open the install's Support session first).

    SUPPORT WITHOUT STANDING ADMIN: where the Support app holds only its read-only role in the database (just-in-time
    support access), -SupportSql -Apply opens the support grant (setup level, at most 1 hour) first, waits until it reads
    back, writes the setting and closes the grant again -- each said in one line. When the grant cannot be opened (no
    consent, or the customer consented only to troubleshoot) the setting is NOT written and the script fails, saying why
    and what to do. Where the Support app still holds the right, nothing changes: no grant is asked.

.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Value false -Reason 'a smaller report must not stop the demo data'
.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Value false -Reason '...' -Apply
.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Reset -Reason 'back to the default' -Apply
.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name Mail_CloseLoop_Daily_To -Value 'one@example.com' -Reason 'one recipient for the daily mail' -Apply
.EXAMPLE
    . Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'SI support: one setting'
    .\setup\Set-SIProSetting.ps1 -SupportSql -SqlServer <server> -Database <db> -ResourceGroupName <rg> -Name SI_Guard_RaOutputRowDrop_Enabled -Value false -Reason '...' -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SIProSetting/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Name,
    # The value as text (true / false, a number, a word, or JSON for a list). A list also takes plain text as ONE item
    # (a mail address setting, name ending in _To: addresses separated by commas). Not for a secret: give -KeyVaultSecretName.
    [string]$Value,
    [string]$KeyVaultSecretName,
    # Remove the row: the setting goes back to its default.
    [switch]$Reset,
    # 'solution' (every engine, the default) or 'engine:<name>' (the web app's own settings: 'engine:management-web').
    [string]$Scope = '',
    [Parameter(Mandatory)][string]$Reason,
    [switch]$Apply,
    [string]$SqlServer = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # Reach the database through the Invardia Support app's audited SQL (Invoke-InvardiaSupportSql; open the session first).
    [switch]$SupportSql,
    # With -SupportSql: where the install is, for the support grant (else the Support session finds it).
    [string]$SubscriptionId = '',
    [string]$ResourceGroupName = '',
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    [switch]$PassThru,
    # TEST SEAM: the support grant's open / close (with -SupportSql the Support session's Open- / Close-InvardiaSupportGrant)
    [Parameter(DontShow)][System.Collections.IDictionary]$SupportGrant
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIProSetting' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: the setting is not written
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
$why = ([string]$Reason).Trim()
if ($why.Length -lt 10) { throw 'say why the setting is changed (-Reason, at least 10 characters): it is kept in the change log' }

. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-ProSettings.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportWrite.ps1'))
$catalog = @((Get-Content -Raw -LiteralPath ([IO.Path]::Combine($siRoot, 'config', 'settings.catalog.locked.json')) | ConvertFrom-Json).settings)
$s = $catalog | Where-Object { $_.name -eq $Name } | Select-Object -First 1
if (-not $s) { throw "'$Name' is not a SecurityInsight setting (config\settings.catalog.locked.json)" }
if (-not $Scope) { $Scope = 'solution' }
$action = if ($Reset) { 'Reset' } else { 'Set' }
if ($action -eq 'Set' -and -not $s.secret -and -not $PSBoundParameters.ContainsKey('Value')) { throw "give -Value (or -Reset to go back to the default)" }

# the value in the setting's own type (the catalog says which): "false" for a switch is the boolean false
$typed = $Value
if ($action -eq 'Set' -and -not $s.secret) {
    switch ([string]$s.type) {
        'bool' { if ($Value -match '^(?i)(true|false|1|0|on|off|yes|no)$') { $typed = $Value -match '^(?i)(true|1|on|yes)$' } else { throw "$Name is a switch: give true or false" } }
        'int'  { $n = 0L; if ([long]::TryParse($Value, [ref]$n)) { $typed = $n } else { throw "$Name is a whole number" } }
        'number' { $d = 0.0; if ([double]::TryParse($Value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $typed = $d } else { throw "$Name is a number" } }
        'list' {
            # a list stays a list with ONE item too: PowerShell 7's ConvertFrom-Json hands a one-item JSON array back as
            # its item, which the setting's own check then refuses ("must be a list")
            if ($Value -match '^\s*\[') { $p = $Value | ConvertFrom-Json; $typed = [object[]]@(foreach ($x in $p) { $x }) }
            elseif ($Value -match '^\s*\{') { $typed = $Value | ConvertFrom-Json }
            elseif ($Name -match '_To$') {
                # the mail address settings (name ends in _To): a plain value is the addresses, comma-separated
                $typed = [object[]]@(([string]$Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
            elseif ("$Value".Trim()) { $typed = [object[]]@(([string]$Value).Trim()) }   # every other list: plain text is ONE item (JSON for several)
            else { $typed = [object[]]@() }
        }
        default { if ($Value -match '^\s*[\[\{]') { $typed = $Value | ConvertFrom-Json } }
    }
}
$by = 'setup: ' + [Environment]::UserName
Write-Host ('{0} {1} ({2}) = {3}  -- {4}' -f $(if ($Apply) { '[APPLY]' } else { '[PLAN] ' }), $Name, $Scope, $(if ($Reset) { '(default)' } elseif ($s.secret) { 'keyvault:' + $KeyVaultSecretName } else { [string]$Value }), $why)
$result = [pscustomobject]@{ Name = $Name; Scope = $Scope; Action = $action; Value = $(if ($Reset) { $null } else { $Value }); Applied = $false }
if (-not $Apply) { Write-Host 'Plan only -- run again with -Apply to write.' -ForegroundColor Yellow; if ($PassThru) { return $result }; return }

if (-not $Store) {
    if (-not $SqlServer -or -not $Database) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
    if ($SupportSql) {
        if (-not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) { throw '-SupportSql needs the Invardia Support session (Connect-InvardiaSupport.ps1) open in this shell: Invoke-InvardiaSupportSql was not found. Nothing was written.' }
        $Store = New-SIProSettingSupportStore -Server $SqlServer -Database $Database -Reason ('SecurityInsight setting {0}: {1}' -f $Name, $why)
    } else {
        $Store = New-SIProSettingsStore -Server $SqlServer -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
    }
}
$write = { Set-SIProSetting -Store $Store -Catalog $catalog -Name $Name -Scope $Scope -Action $action -Value $typed -KeyVaultSecretName $KeyVaultSecretName -ChangedBy $by -Reason $why }
if ($SupportSql -and -not $SupportGrant) { $SupportGrant = New-SISupportGrantSeams -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroupName }
if ($SupportGrant) {
    # the Support session: where the Support app is read-only in the database, the support grant is opened for this write
    # and closed again; a grant that cannot be opened FAILS the script (a setting asked for and not written is no success)
    $ga = Get-SISupportGrantArgs -SupportGrant $SupportGrant
    $ga['Purpose'] = ('the setting {0}' -f $Name); $ga['Tool'] = 'Set-SIProSetting'; $ga['GrantLevel'] = 'setup'; $ga['WriteKind'] = 'setting'
    $ga['Do'] = $write; $ga['Probe'] = { & $Store.Invoke (Get-SISupportAccessProbeSql) @{} 'reader' }
    $null = Invoke-SISupportWithGrant @ga
} else {
    & $write
}
$result.Applied = $true
Write-Host ('Written: {0} ({1}) -- applies from the next run.' -f $Name, $Scope) -ForegroundColor Green
if ($PassThru) { return $result }
} finally { Stop-SIScriptRun -Run $siRun }
