#Requires -Version 5.1
<#
    SecurityInsight -- THE TENANT'S SIZE, RECORDED BY THE COLLECTION THAT COUNTED IT (found 2026-10-16: a 153,000-user
    tenant ran every sized job on 2 CPU / 4 GiB because the updater could not read the tenant's size).

    The update's job-size rule (setup\_shared\SI-JobSizing.ps1) needs the tenant's users / groups / service principals /
    devices. The updater's identity has no directory read, so its Microsoft Graph $count is refused. But the identity and
    endpoint collections already COUNT the directory before they read it (engine\asset-profiling\stages\Invoke-Discover.ps1:
    the streaming discovery's part count), with the collection's own directory rights. Those counts are now recorded where
    the updater already reads: the Pro database, cfg.InstallState 'TenantSize' -- on the connection the run already has
    ($global:SI_ProSettingsStore; the engine role holds SELECT / INSERT / UPDATE on cfg.InstallState, SI-EngineGrants.ps1).
    No new right for any identity.

    The value is compact JSON: {"users":n,"groups":n,"servicePrincipals":n,"devices":n,"identityAt":"<utc>","devicesAt":"<utc>"}.
    Each collection writes ITS half (identity: users, groups, service principals; endpoint: devices) and keeps the other
    one -- merged in ONE statement under an update lock, because both collections run at the same time. A count that was
    not read is left as it was (never written as 0). PS 5.1 + 7.
#>

$script:SITenantSizeMarkName = 'TenantSize'

function ConvertTo-SITenantSizeMarkParams {
    <#
        PURE. The statement's parameters for -Counts (Users / Groups / ServicePrincipals / Devices; a key that is absent,
        $null or negative is NOT written -- ''), the half each count belongs to stamped with -NowUtc. $null when nothing
        is left to write.
    #>
    param([hashtable]$Counts, $NowUtc)
    if (-not $Counts) { return $null }
    $at = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $atText = $at.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $p = [ordered]@{ Name = $script:SITenantSizeMarkName; Users = ''; Groups = ''; ServicePrincipals = ''; Devices = ''; IdentityAt = ''; DevicesAt = ''; By = 'si-engine (collection counts)' }
    $any = $false
    foreach ($k in 'Users', 'Groups', 'ServicePrincipals', 'Devices') {
        if (-not $Counts.ContainsKey($k) -or $null -eq $Counts[$k]) { continue }
        $n = 0L
        if (-not [long]::TryParse("$($Counts[$k])", [ref]$n) -or $n -lt 0) { continue }
        $p[$k] = $n.ToString([Globalization.CultureInfo]::InvariantCulture); $any = $true
        if ($k -eq 'Devices') { $p.DevicesAt = $atText } else { $p.IdentityAt = $atText }
    }
    if (-not $any) { return $null }
    $p
}

function Get-SITenantSizeMarkSaveSql {
    <# The ONE statement that merges a collection's half into cfg.InstallState 'TenantSize' (the other half is kept). #>
    @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @old nvarchar(400) = (SELECT Value FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name);
    DECLARE @v nvarchar(400) = CASE WHEN @old IS NOT NULL AND ISJSON(@old) = 1 THEN @old ELSE N'{}' END;
    IF @Users <> N'' SET @v = JSON_MODIFY(@v, '$.users', CONVERT(bigint, @Users));
    IF @Groups <> N'' SET @v = JSON_MODIFY(@v, '$.groups', CONVERT(bigint, @Groups));
    IF @ServicePrincipals <> N'' SET @v = JSON_MODIFY(@v, '$.servicePrincipals', CONVERT(bigint, @ServicePrincipals));
    IF @Devices <> N'' SET @v = JSON_MODIFY(@v, '$.devices', CONVERT(bigint, @Devices));
    IF @IdentityAt <> N'' SET @v = JSON_MODIFY(@v, '$.identityAt', @IdentityAt);
    IF @DevicesAt <> N'' SET @v = JSON_MODIFY(@v, '$.devicesAt', @DevicesAt);
    IF @old IS NULL
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @v, NULL, @By);
    ELSE
        UPDATE cfg.InstallState SET Value = @v, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
    COMMIT;
END
'@
}

function Save-SITenantSizeMark {
    <# Records -Counts (a collection's half) on -Store (the run's Pro database store: .Invoke sql params mode). Throws on failure. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][hashtable]$Counts, $NowUtc)
    $p = ConvertTo-SITenantSizeMarkParams -Counts $Counts -NowUtc $NowUtc
    if ($null -eq $p) { return $false }
    $null = & $Store.Invoke (Get-SITenantSizeMarkSaveSql) $p 'nonquery'
    $true
}

function Invoke-SITenantSizeMarkSave {
    <#
        A collection's directory counts for the update's job-size rule: -OnSave (tests), else the Pro database this run
        opened ($global:SI_ProSettingsStore -- no second sign-in; Community has none and records nothing). One plain line.
        NEVER throws; $true when recorded.
    #>
    param([hashtable]$Counts, [scriptblock]$OnSave, $NowUtc, [scriptblock]$Log)
    $done = $false; $why = ''
    try {
        if ($OnSave) { $null = & $OnSave $Counts; $done = $true }
        elseif ($global:SI_ProSettingsStore) { $done = [bool](Save-SITenantSizeMark -Store $global:SI_ProSettingsStore -Counts $Counts -NowUtc $NowUtc) }
        else { return $false }
    } catch { $done = $false; $why = (("$($_.Exception.Message)" -replace '\s+', ' ').Trim()) }
    try {
        $line = if ($done) { 'tenant size recorded for the update''s job sizing (the counts this collection read)' }
                else { 'the tenant size could not be recorded for the update''s job sizing{0} -- the update uses its other sources' -f $(if ($why) { " ($why)" } else { '' }) }
        if ($Log) { & $Log $line } else { Write-Host (' [INFO] ' + $line) }
    } catch { }
    $done
}

function ConvertFrom-SITenantSizeMark {
    <#
        PURE. The recorded value (cfg.InstallState 'TenantSize' JSON) -> @{ Users; Groups; ServicePrincipals; Devices;
        IdentityAt; DevicesAt } (a count not recorded = 0, a time not recorded = ''), or $null when nothing usable is in it.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $o = $null
    try { $o = $Value | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if ($null -eq $o) { return $null }
    $c = @{ Users = 0L; Groups = 0L; ServicePrincipals = 0L; Devices = 0L; IdentityAt = ''; DevicesAt = '' }
    $any = $false
    foreach ($pair in @(@('users', 'Users'), @('groups', 'Groups'), @('servicePrincipals', 'ServicePrincipals'), @('devices', 'Devices'))) {
        $pp = $o.PSObject.Properties[$pair[0]]
        $n = 0L
        if ($pp -and $null -ne $pp.Value -and [long]::TryParse("$($pp.Value)", [ref]$n) -and $n -ge 0) { $c[$pair[1]] = $n; if ($n -gt 0) { $any = $true } }
    }
    # the times as the text that was written (ConvertFrom-Json on pwsh 7 would turn them into local dates)
    foreach ($pair in @(@('identityAt', 'IdentityAt'), @('devicesAt', 'DevicesAt'))) {
        $m = [regex]::Match($Value, ('"{0}"\s*:\s*"([^"]*)"' -f $pair[0]))
        if ($m.Success) { $c[$pair[1]] = $m.Groups[1].Value }
    }
    if ($any) { $c } else { $null }
}
