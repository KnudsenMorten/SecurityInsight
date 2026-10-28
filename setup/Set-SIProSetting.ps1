<#
.SYNOPSIS
    Sets (or resets) ONE SecurityInsight Pro setting by its name -- the same row Settings in the Pro web app writes, with
    its change log entry. PLAN BY DEFAULT; -Apply writes.

.DESCRIPTION
    For a setting an operator or support must change without the web app (a guard switch at night, a setting the web
    app does not offer yet). The value is validated by the same rules the engines read it with (Set-SIProSetting in
    engine\pro-settings\SI-ProSettings.ps1: the catalog's type, limits, choices); the write and its cfg.ChangeLog row
    are one transaction, and -Reason is recorded with it. No PowerShell module; the Pro database is reached with the
    install's own identity (or -AppId / -TenantId / -CertThumbprint).

.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Value false -Reason 'a smaller report must not stop the demo data'
.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Value false -Reason '...' -Apply
.EXAMPLE
    .\setup\Set-SIProSetting.ps1 -Name SI_Guard_RaOutputRowDrop_Enabled -Reset -Reason 'back to the default' -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SIProSetting/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Name,
    # The value as text (true / false, a number, a word, or JSON for a list). Not for a secret: give -KeyVaultSecretName.
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
    # The database, already open (New-SIProSettingsStore -Invoke ...): a test's fake, or a caller's store.
    $Store,
    [switch]$PassThru
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
        default { if ($Value -match '^\s*[\[\{]') { $typed = $Value | ConvertFrom-Json } }
    }
}
$by = 'setup: ' + [Environment]::UserName
Write-Host ('{0} {1} ({2}) = {3}  -- {4}' -f $(if ($Apply) { '[APPLY]' } else { '[PLAN] ' }), $Name, $Scope, $(if ($Reset) { '(default)' } elseif ($s.secret) { 'keyvault:' + $KeyVaultSecretName } else { [string]$Value }), $why)
$result = [pscustomobject]@{ Name = $Name; Scope = $Scope; Action = $action; Value = $(if ($Reset) { $null } else { $Value }); Applied = $false }
if (-not $Apply) { Write-Host 'Plan only -- run again with -Apply to write.' -ForegroundColor Yellow; if ($PassThru) { return $result }; return }

if (-not $Store) {
    if (-not $SqlServer -or -not $Database) { throw 'the Pro database is not configured: give -SqlServer and -Database (or load config\SecurityInsight.custom.ps1: SI_ProSqlServer / SI_ProSqlDatabase)' }
    $Store = New-SIProSettingsStore -Server $SqlServer -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint
}
Set-SIProSetting -Store $Store -Catalog $catalog -Name $Name -Scope $Scope -Action $action -Value $typed -KeyVaultSecretName $KeyVaultSecretName -ChangedBy $by -Reason $why
$result.Applied = $true
Write-Host ('Written: {0} ({1}) -- applies from the next run.' -f $Name, $Scope) -ForegroundColor Green
if ($PassThru) { return $result }
} finally { Stop-SIScriptRun -Run $siRun }
