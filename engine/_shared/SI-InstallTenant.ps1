#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- THE TENANT THIS INSTALL SERVES, its name read from the tenant itself and recorded once where the
    web app reads it.

.DESCRIPTION
    The web app's header shows TENANT (the tenant's name) beside TENANT ID, as PIM Manager does. The name is never typed
    by hand: setup reads the Entra organization through Microsoft Graph (GET /organization: its displayName and the
    verified domain marked isInitial -- the tenant's onmicrosoft.com domain) and records it in the Pro database row
    cfg.InstallState 'Tenant', compact JSON

        { "tenantId": "...", "name": "Contoso Ltd", "initialDomain": "contoso.onmicrosoft.com", "setBy": "bootstrap", "setAt": "2026-10-09T10:00:00Z" }

    Writers: setup\Set-SIInstallTenant.ps1 (the guided install and Bootstrap-ContainerAppJob.ps1 run it), and the data
    sync every run as the engine identity, only when the name changed (-OnlyIfChanged). The web app's
    setting "Tenant name (override)" (SIWeb_TenantName) wins over the record; without either the header shows the
    initial domain, and with nothing at all "not recorded" with a tooltip saying how it gets filled.

    Everything here is PURE except Save-SIInstallTenant / Read-SIInstallTenant, which go through the store seam
    ($Store.Invoke(sql, params, mode)) the rest of the Pro code uses. Never writes outside cfg.InstallState.
    Windows PowerShell 5.1 and PowerShell 7. No ?. / ??.
#>

$script:SIInstallTenantStateName = 'Tenant'

function Select-SIInstallTenantOrganization {
    <#
        PURE. The GET /organization response (the list, or one organization) -> @{ TenantId; Name; InitialDomain }.
        The initial domain is the verified domain marked isInitial (else the default one). Empty strings when not there.
    #>
    param([AllowNull()]$Response)
    $out = [pscustomobject]@{ TenantId = ''; Name = ''; InitialDomain = '' }
    if ($null -eq $Response) { return $out }
    $org = $Response
    if ($Response -is [System.Collections.IDictionary]) {
        if ($Response.Contains('value')) { $org = @($Response['value']) | Select-Object -First 1 }
    } elseif ($Response.PSObject.Properties['value']) { $org = @($Response.value) | Select-Object -First 1 }
    if ($null -eq $org) { return $out }
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } else { $null } } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $out.TenantId = ("$(& $get $org 'id')").Trim()
    $out.Name = ("$(& $get $org 'displayName')").Trim()
    $doms = @(@(& $get $org 'verifiedDomains') | Where-Object { $null -ne $_ })
    foreach ($d in $doms) { if ((& $get $d 'isInitial') -eq $true -and "$(& $get $d 'name')".Trim()) { $out.InitialDomain = ("$(& $get $d 'name')").Trim(); return $out } }
    foreach ($d in $doms) { if ((& $get $d 'isDefault') -eq $true -and "$(& $get $d 'name')".Trim()) { $out.InitialDomain = ("$(& $get $d 'name')").Trim(); return $out } }
    $out
}

function ConvertTo-SIInstallTenantJson {
    <# PURE. The row's value: compact JSON { tenantId, name, initialDomain, setBy, setAt } (cfg.InstallState.Value is NVARCHAR(400)). #>
    param([string]$TenantId = '', [string]$Name = '', [string]$InitialDomain = '', [Parameter(Mandatory)][string]$SetBy, [Parameter(Mandatory)][datetime]$NowUtc)
    $cut = { param($t, $n) $t = ("$t").Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) } else { $t } }
    $o = [ordered]@{
        tenantId      = (& $cut $TenantId 40)
        name          = (& $cut $Name 100)
        initialDomain = (& $cut $InitialDomain 100)
        setBy         = (& $cut $SetBy 40)
        setAt         = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $o | ConvertTo-Json -Compress
}

function ConvertFrom-SIInstallTenantJson {
    <# PURE. The row's value -> @{ TenantId; Name; InitialDomain; SetBy; SetAt }, or $null when it names neither a name nor a domain. #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if (-not $o) { return $null }
    $p = { param($n) if ($o.PSObject.Properties[$n] -and $null -ne $o.$n) { $v = $o.$n; if ($v -is [datetime]) { $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { ("$v").Trim() } } else { '' } }
    $r = [pscustomobject]@{ TenantId = (& $p 'tenantId'); Name = (& $p 'name'); InitialDomain = (& $p 'initialDomain'); SetBy = (& $p 'setBy'); SetAt = (& $p 'setAt') }
    if (-not $r.Name -and -not $r.InitialDomain) { return $null }
    $r
}

function Get-SIInstallTenantSql {
    <# The upsert. Without cfg.InstallState (a database setup has not created yet) nothing is written (Written 0, NoTable 1). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.InstallState') IS NULL
    SELECT CAST(0 AS int) AS Written, CAST(1 AS int) AS NoTable;
ELSE
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
        UPDATE cfg.InstallState SET Value = @Value, [Version] = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
    COMMIT;
    SELECT CAST(1 AS int) AS Written, CAST(0 AS int) AS NoTable;
END
'@
}

function Save-SIInstallTenant {
    <# Writes the row. Returns @{ Written; Reason }. Throws only on a database error. #>
    param([Parameter(Mandatory)]$Store, [string]$TenantId = '', [string]$Name = '', [string]$InitialDomain = '', [Parameter(Mandatory)][string]$SetBy,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $json = ConvertTo-SIInstallTenantJson -TenantId $TenantId -Name $Name -InitialDomain $InitialDomain -SetBy $SetBy -NowUtc $NowUtc
    $rows = @(& $Store.Invoke (Get-SIInstallTenantSql) ([ordered]@{ Name = $script:SIInstallTenantStateName; Value = $json; By = $SetBy }) 'reader' | ForEach-Object { $_ })
    $row = $rows | Select-Object -First 1
    $get = { param($n) if ($row -is [System.Collections.IDictionary]) { $row[$n] } elseif ($row) { $row.$n } else { $null } }
    if ($row -and [int](& $get 'NoTable') -eq 1) { return [pscustomobject]@{ Written = $false; Reason = 'the Pro database has no cfg.InstallState yet (run setup first) -- nothing recorded' } }
    $what = if ($Name) { "'{0}'" -f $Name } else { ("'{0}' (its domain: the name could not be read)" -f $InitialDomain) }
    [pscustomobject]@{ Written = $true; Reason = ('tenant {0} recorded for this install' -f $what) }
}

function Read-SIInstallTenant {
    <# The recorded row (ConvertFrom-SIInstallTenantJson), or $null. #>
    param([Parameter(Mandatory)]$Store)
    $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name" ([ordered]@{ Name = $script:SIInstallTenantStateName }) 'reader' | ForEach-Object { $_ })
    $row = $rows | Select-Object -First 1
    if (-not $row) { return $null }
    ConvertFrom-SIInstallTenantJson ([string]$(if ($row -is [System.Collections.IDictionary]) { $row['Value'] } else { $row.Value }))
}

function Invoke-SIRecordInstallTenant {
    <#
        The one entry every writer calls. -Name / -InitialDomain when the caller has them already; otherwise -GraphGet
        (returns the GET /organization response) is asked. Records what is known; with neither a name nor a domain it
        writes nothing (a name already recorded stays). NEVER throws: returns @{ Written; TenantId; Name; InitialDomain; Reason }.
    #>
    param([Parameter(Mandatory)]$Store, [string]$TenantId = '', [string]$Name = '', [string]$InitialDomain = '', [scriptblock]$GraphGet,
          [Parameter(Mandatory)][string]$SetBy, [datetime]$NowUtc = [datetime]::UtcNow,
          # the engines' daily refresh: write only when the name or the domain differs from what is recorded
          [switch]$OnlyIfChanged)
    $out = [pscustomobject]@{ Written = $false; TenantId = "$TenantId".Trim(); Name = "$Name".Trim(); InitialDomain = "$InitialDomain".Trim(); Reason = '' }
    try {
        if (-not $out.Name -and $GraphGet) {
            try {
                $org = Select-SIInstallTenantOrganization -Response (& $GraphGet)
                $out.Name = $org.Name
                if (-not $out.InitialDomain) { $out.InitialDomain = $org.InitialDomain }
                if ($org.TenantId) {
                    if ($out.TenantId -and -not [string]::Equals($out.TenantId, $org.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $out.Reason = ('the signed-in tenant ({0}) is not the tenant this install serves ({1}) -- nothing recorded; sign in to the right tenant and run setup\Set-SIInstallTenant.ps1 again' -f $org.TenantId, $out.TenantId)
                        $out.Name = ''; $out.InitialDomain = ''
                        return $out
                    }
                    $out.TenantId = $org.TenantId
                }
            } catch {
                $out.Reason = ("the tenant's name could not be read from Entra ID: {0}" -f $_.Exception.Message)
            }
        }
        if (-not $out.Name -and -not $out.InitialDomain) {
            if (-not $out.Reason) { $out.Reason = "the tenant's name is not known here -- run setup\Set-SIInstallTenant.ps1 signed in to the tenant, or set ""Tenant name (override)"" on the Settings page" }
            return $out
        }
        if ($OnlyIfChanged) {
            $was = Read-SIInstallTenant -Store $Store
            if ($was -and [string]::Equals("$($was.Name)", $out.Name, [System.StringComparison]::Ordinal) -and
                [string]::Equals("$($was.InitialDomain)", $out.InitialDomain, [System.StringComparison]::OrdinalIgnoreCase)) {
                $out.Reason = ("tenant '{0}' is recorded already -- unchanged" -f $(if ($out.Name) { $out.Name } else { $out.InitialDomain }))
                return $out
            }
        }
        $s = Save-SIInstallTenant -Store $Store -TenantId $out.TenantId -Name $out.Name -InitialDomain $out.InitialDomain -SetBy $SetBy -NowUtc $NowUtc
        $out.Written = $s.Written; $out.Reason = $s.Reason
    } catch {
        $out.Reason = ('the tenant could not be recorded: {0}' -f $_.Exception.Message)
    }
    $out
}
