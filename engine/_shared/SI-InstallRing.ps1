#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- THIS INSTALL'S UPDATE RING, recorded once where everyone reads it (#308).

.DESCRIPTION
    The ring is a property of the INSTALL, known when it is installed -- not something only an updater run discovers.
    ONE record: the Pro database row cfg.InstallState 'Ring', compact JSON

        { "ring": 1, "channel": "internal", "setBy": "bootstrap", "source": "setting", "setAt": "2026-10-05T10:00:00Z" }

    written by every path that knows the ring:
      setup\Set-SIInstallRing.ps1   the command an admin (or a build script) runs -- also what the guided install and
                                    Bootstrap-ContainerAppJob.ps1 call
      the updater job               whenever it resolves a ring (Invardia's manifest; the release map on the feed path)

    WHICH RING a writer records -- Resolve-SIInstallRing:
      1. the ring the writer was GIVEN (-Ring on the command line; the ring the updater resolved)   source 'parameter' / 'updater'
      2. the admin's setting SI_UpdateRing (0-3) in the Pro database, else in the configuration       source 'setting'
      3. the ring in the install's resource-group name (rg-si-r1-pro-ca = 1; rg-si-prod-... = 3)     source 'resource-group'
    Source 3 is derived, so it never replaces a row that is already there; 1 and 2 always write.

    The web app's header reads, in order: the updater's state (UpdateState) > this row > the setting.

    Rings are the framework's: 0 dev, 1 internal, 2 design partners / early release, 3 broad.
    Everything here is PURE except Save-SIInstallRing / Read-SIInstallRing / Read-SIUpdateRingSetting, which go through
    the store seam ($Store.Invoke(sql, params, mode)) the rest of the Pro code uses. Never writes outside cfg.InstallState.
    Windows PowerShell 5.1 and PowerShell 7.
#>

$script:SIInstallRingStateName = 'Ring'
$script:SIUpdateRingSettingName = 'SI_UpdateRing'
$script:SIInstallRingSources = @('parameter', 'updater', 'setting', 'resource-group')

function ConvertTo-SIUpdateRing {
    <#
        PURE. A ring in any of the forms the product uses -> 0..3, or $null when it is not one.
        0..3 (number or text), 'r0'..'r3', 'ring 1', and the setup naming's 'prod' (a production install = 3, broad).
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $null }
    $t = ("$Value").Trim().ToLowerInvariant()
    if (-not $t) { return $null }
    if ($t -eq 'prod') { return 3 }
    $t = $t -replace '^(ring\s*|r)', ''
    $n = 0
    if (-not [int]::TryParse($t, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $null }
    if ($n -lt 0 -or $n -gt 3) { return $null }
    [int]$n
}

function Get-SIRingFromResourceGroupName {
    <# PURE. The ring in a resource group named by setup's pattern (rg-si-<r0|r1|r2|prod>-<edition>-<hosting>), else $null. #>
    param([AllowNull()][AllowEmptyString()][string]$ResourceGroupName)
    if ("$ResourceGroupName" -cmatch '^rg-si-(r0|r1|r2|prod)-(community|pro)-(ca|vm)(-[a-z0-9][a-z0-9-]*)?$') { return (ConvertTo-SIUpdateRing $Matches[1]) }
    $null
}

function Resolve-SIInstallRing {
    <#
        PURE. Which ring a writer records, and why. -Ring = the ring the writer was given (a parameter, or the ring the
        updater resolved; -RingSource says which); -Setting = SI_UpdateRing; -ResourceGroupName = the install's resource
        group. Returns @{ Ring; Source; Weak; Problems } -- Ring $null = nothing known (write nothing).
    #>
    param([AllowNull()]$Ring, [ValidateSet('parameter', 'updater')][string]$RingSource = 'parameter', [AllowNull()]$Setting,
          [AllowNull()][AllowEmptyString()][string]$ResourceGroupName)
    $problems = New-Object System.Collections.Generic.List[string]
    $given = ConvertTo-SIUpdateRing $Ring
    if ($null -ne $Ring -and "$Ring".Trim() -and $null -eq $given) { $problems.Add(("'{0}' is not an update ring (0, 1, 2 or 3)" -f $Ring)) }
    $set = ConvertTo-SIUpdateRing $Setting
    if ($null -ne $Setting -and "$Setting".Trim() -and $null -eq $set) { $problems.Add(("the setting {0} = '{1}' is not an update ring (0, 1, 2 or 3) -- ignored" -f $script:SIUpdateRingSettingName, $Setting)) }
    if ($null -ne $given) { return [pscustomobject]@{ Ring = $given; Source = $RingSource; Weak = $false; Problems = $problems.ToArray() } }
    if ($null -ne $set) { return [pscustomobject]@{ Ring = $set; Source = 'setting'; Weak = $false; Problems = $problems.ToArray() } }
    $rg = Get-SIRingFromResourceGroupName -ResourceGroupName $ResourceGroupName
    if ($null -ne $rg) { return [pscustomobject]@{ Ring = $rg; Source = 'resource-group'; Weak = $true; Problems = $problems.ToArray() } }
    [pscustomobject]@{ Ring = $null; Source = ''; Weak = $false; Problems = $problems.ToArray() }
}

function ConvertTo-SIInstallRingJson {
    <# PURE. The row's value: compact JSON { ring, channel, setBy, source, setAt } (cfg.InstallState.Value is NVARCHAR(400)). #>
    param([Parameter(Mandatory)][int]$Ring, [string]$Channel = '', [Parameter(Mandatory)][string]$SetBy, [string]$Source = '',
          [Parameter(Mandatory)][datetime]$NowUtc)
    $cut = { param($t, $n) $t = ("$t").Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) } else { $t } }
    $o = [ordered]@{
        ring    = $Ring
        channel = (& $cut $Channel 40)
        setBy   = (& $cut $SetBy 80)
        source  = (& $cut $Source 40)
        setAt   = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $o | ConvertTo-Json -Compress
}

function ConvertFrom-SIInstallRingJson {
    <# PURE. The row's value -> @{ Ring; Channel; SetBy; Source; SetAt }, or $null when it holds no usable ring. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not $o -or -not $o.PSObject.Properties['ring']) { return $null }
    $r = ConvertTo-SIUpdateRing $o.ring
    if ($null -eq $r) { return $null }
    # (PowerShell 7's ConvertFrom-Json turns an ISO time into a [datetime]: written back in the same ISO form)
    $p = { param($n) if ($o.PSObject.Properties[$n] -and $null -ne $o.$n) { $v = $o.$n; if ($v -is [datetime]) { $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { "$v" } } else { '' } }
    [pscustomobject]@{ Ring = $r; Channel = (& $p 'channel'); SetBy = (& $p 'setBy'); Source = (& $p 'source'); SetAt = (& $p 'setAt') }
}

function Get-SIInstallRingSql {
    <#
        The upsert. @Weak = 1 (a ring derived from a name) never replaces a row that is already there. Returns one row:
        Written 1 / 0. Without cfg.InstallState (a database setup has not created yet) nothing is written (Written 0, NoTable 1).
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Written, CAST(1 AS int) AS NoTable;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    DECLARE @written int = 0;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
    BEGIN
        IF @Weak = 0
        BEGIN
            UPDATE cfg.InstallState SET Value = @Value, [Version] = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
            SET @written = 1;
        END
    END
    ELSE
    BEGIN
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
        SET @written = 1;
    END
    COMMIT;
    SELECT @written AS Written, CAST(0 AS int) AS NoTable;
END
'@
}

function Save-SIInstallRing {
    <#
        Writes the row. Returns @{ Written; Ring; Reason }. Throws only on a database error (the callers decide whether that
        stops them -- every caller in the product treats it as a warning).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][int]$Ring, [string]$Channel = '', [Parameter(Mandatory)][string]$SetBy,
          [string]$Source = '', [switch]$Weak, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($Ring -lt 0 -or $Ring -gt 3) { throw ("{0} is not an update ring (0, 1, 2 or 3)" -f $Ring) }
    $json = ConvertTo-SIInstallRingJson -Ring $Ring -Channel $Channel -SetBy $SetBy -Source $Source -NowUtc $NowUtc
    $rows = @(& $Store.Invoke (Get-SIInstallRingSql) ([ordered]@{ Name = $script:SIInstallRingStateName; Value = $json; By = $SetBy; Weak = $(if ($Weak) { 1 } else { 0 }) }) 'reader' | ForEach-Object { $_ })
    $row = $rows | Select-Object -First 1
    $get = { param($n) if ($row -is [System.Collections.IDictionary]) { $row[$n] } elseif ($row) { $row.$n } else { $null } }
    if ($row -and [int](& $get 'NoTable') -eq 1) { return [pscustomobject]@{ Written = $false; Ring = $Ring; Reason = 'the Pro database has no cfg.InstallState yet (run setup first) -- nothing recorded' } }
    if ($row -and [int](& $get 'Written') -eq 1) { return [pscustomobject]@{ Written = $true; Ring = $Ring; Reason = ('ring {0} recorded for this install ({1})' -f $Ring, $(if ($Source) { $Source } else { $SetBy })) } }
    [pscustomobject]@{ Written = $false; Ring = $Ring; Reason = ('a ring is recorded already -- ring {0} from the resource-group name does not replace it' -f $Ring) }
}

function Read-SIInstallRing {
    <# The recorded row (ConvertFrom-SIInstallRingJson), or $null. #>
    param([Parameter(Mandatory)]$Store)
    $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name" ([ordered]@{ Name = $script:SIInstallRingStateName }) 'reader' | ForEach-Object { $_ })
    $row = $rows | Select-Object -First 1
    if (-not $row) { return $null }
    ConvertFrom-SIInstallRingJson ([string]$(if ($row -is [System.Collections.IDictionary]) { $row['Value'] } else { $row.Value }))
}

function Read-SIUpdateRingSetting {
    <# The admin's SI_UpdateRing at solution scope in the Pro database (0..3), or $null (not set, not a ring, or no table). #>
    param([Parameter(Mandatory)]$Store)
    $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.Setting') IS NOT NULL SELECT ValueJson FROM cfg.Setting WHERE Name = @Name AND Scope = N'solution'" ([ordered]@{ Name = $script:SIUpdateRingSettingName }) 'reader' | ForEach-Object { $_ })
    $row = $rows | Select-Object -First 1
    if (-not $row) { return $null }
    $j = [string]$(if ($row -is [System.Collections.IDictionary]) { $row['ValueJson'] } else { $row.ValueJson })
    if (-not $j) { return $null }
    try { $v = $j | ConvertFrom-Json -ErrorAction Stop } catch { $v = $j }
    ConvertTo-SIUpdateRing $v
}

function Invoke-SIRecordInstallRing {
    <#
        The one entry every writer calls: resolve the ring (Resolve-SIInstallRing; the database setting first, else
        -ConfigSetting = $global:SI_UpdateRing from the configuration), record it, say what happened. NEVER throws:
        returns @{ Written; Ring; Source; Reason; Problems }.
    #>
    param([Parameter(Mandatory)]$Store, [AllowNull()]$Ring, [ValidateSet('parameter', 'updater')][string]$RingSource = 'parameter',
          [AllowNull()]$ConfigSetting, [AllowNull()][AllowEmptyString()][string]$ResourceGroupName, [string]$Channel = '',
          [Parameter(Mandatory)][string]$SetBy, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [pscustomobject]@{ Written = $false; Ring = $null; Source = ''; Reason = ''; Problems = @() }
    try {
        $setting = $null
        try { $setting = Read-SIUpdateRingSetting -Store $Store } catch { $setting = $null }
        if ($null -eq $setting) { $setting = $ConfigSetting }
        $r = Resolve-SIInstallRing -Ring $Ring -RingSource $RingSource -Setting $setting -ResourceGroupName $ResourceGroupName
        $out.Problems = $r.Problems; $out.Source = $r.Source; $out.Ring = $r.Ring
        if ($null -eq $r.Ring) {
            $out.Reason = ("no update ring is known here -- set {0} (0-3) on the Settings page, or run setup\Set-SIInstallRing.ps1 -Ring <0-3>" -f $script:SIUpdateRingSettingName)
            return $out
        }
        $s = Save-SIInstallRing -Store $Store -Ring $r.Ring -Channel $Channel -SetBy $SetBy -Source $r.Source -Weak:([bool]$r.Weak) -NowUtc $NowUtc
        $out.Written = $s.Written; $out.Reason = $s.Reason
    } catch {
        $out.Reason = ('the update ring could not be recorded: {0}' -f $_.Exception.Message)
    }
    $out
}

# The ring a status report carries is resolved in engine\_shared\SI-ReportedRing.ps1 (shipped in both editions);
# this Pro file only reads the two rows it is resolved from.
function Read-SIInstallRingFacts {
    <#
        The cfg.InstallState rows the reported ring is read from ('UpdateState' and 'Ring') -- plus the install's own links
        ('Endpoints', framework §8.4, recorded by the updater for the identified heartbeat) -- in ONE query on a store the
        caller already opened (the Pro settings layer at run start). Returns @{ UpdateState; Ring; Endpoints } (JSON text,
        '' when absent) -- and InvardiaEnvironment (#710: the environment id Invardia's answer named, for the customer
        mail's portal link). NEVER THROWS: a failed read leaves all empty -- the ring then falls back to the setting.
    #>
    param([Parameter(Mandatory)]$Store)
    $out = [pscustomobject]@{ UpdateState = ''; Ring = ''; Endpoints = ''; PipelineSchedule = ''; SecretHandover = ''; InvardiaEnvironment = '' }
    try {
        $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Name, Value FROM cfg.InstallState WHERE Name IN (N'UpdateState', N'Ring', N'Endpoints', N'PipelineSchedule', N'SecretHandover', N'InvardiaEnvironment')" @{} 'reader' | ForEach-Object { $_ })
        foreach ($row in $rows) {
            if (-not $row) { continue }
            $get = { param($n) if ($row -is [System.Collections.IDictionary]) { if ($row.Contains($n)) { $row[$n] } else { $null } } elseif ($row.PSObject.Properties[$n]) { $row.$n } else { $null } }
            $n = [string](& $get 'Name'); $v = & $get 'Value'
            if ($null -eq $v -or $v -is [System.DBNull]) { continue }
            if ($n -eq 'UpdateState') { $out.UpdateState = [string]$v } elseif ($n -eq 'PipelineSchedule') { $out.PipelineSchedule = [string]$v } elseif ($n -eq 'SecretHandover') { $out.SecretHandover = [string]$v } elseif ($n -eq 'Endpoints') { $out.Endpoints = [string]$v } elseif ($n -eq 'InvardiaEnvironment') { $out.InvardiaEnvironment = [string]$v } elseif ($n -eq $script:SIInstallRingStateName) { $out.Ring = [string]$v }
        }
    } catch { }
    $out
}
