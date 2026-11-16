#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE ONE SETTING WRITER (Set-SIProSetting), its own file since #1270 (2026-11-15).

    The same writer every Pro tool uses (setup\Set-SIProSetting.ps1, Import-SIProSettings.ps1, the identity move) -- kept in
    a file of its own so the updater image can carry it WITHOUT the whole settings layer: the update's control-plane step
    (setup\_shared\SI-ControlPlaneValues.ps1) writes a value from the updater job's SI_UPDATER_SETTINGS through exactly
    this function -- the catalog's type checks, the row and its cfg.ChangeLog entry in ONE transaction. It needs only
    SI-Settings.ps1 (the catalog and Test-SISettingValue, loaded here when missing); a SECRET setting also needs
    Test-SISecretSettingReference (SI-ProSettings.ps1), which the control-plane path never reaches (it refuses secrets).
    engine\pro-settings\SI-ProSettings.ps1 dot-sources this file.
#>

if (-not (Get-Command -Name Test-SISettingValue -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Settings.ps1'))
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
        if ($s.secret) {
            if (-not $KeyVaultSecretName) { throw "$Name is a secret: give its Key Vault secret name, never the value" }
            # the same rule the engine reads with: a secret setting names its own Key Vault secret
            $ownWhy = Test-SISecretSettingReference -Setting $Name -SecretName $KeyVaultSecretName
            if ($ownWhy) { throw "${Name}: $ownWhy" }
            $kv = $KeyVaultSecretName
        }
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
