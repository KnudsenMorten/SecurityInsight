#Requires -Version 5.1
<#
    SI-InstallNames.ps1 -- the names of THIS install's own Azure resources, read from one place (framework DOCS/REQUIREMENTS.md
    section 12.11c NAMING item 6, SI REQUIREMENTS #655 step 1): never a literal in the code that looks a resource up, so the names
    every install runs with today and the shorter names a NEW install gets later (a separate step) work side by side.

    TODAY'S NAME IS THE DEFAULT (owner 2026-10-14: existing installs keep what they have): an install with no record and no
    variable resolves exactly the names it runs with now -- nothing is renamed, nothing has to be set.

    Resolution, per role (the first that answers):
      1. the install record: cfg.InstallState 'InstallNames' (compact JSON, one name per role + recordedUtc), written by the
         updater (Save-SIInstallNamesRecord) from what it runs with -- preloaded per process in $global:SI_InstallNames
      2. the variables an install's updater job carries (SI_UPDATER_WEB_APP, SI_UPDATER_MCP_APP, SI_UPDATER_JOB_NAME; set by
         setup\Install-SIUpdaterJob.ps1)
      3. today's name (Get-SIInstallNameDefaults)
    A record that cannot be read is never an error: the next source answers.
    Get-SIInstallNameCandidates gives a FINDER every name worth trying, in order (the resolved name, then today's name), so a
    lookup keeps working on an install whose record names something else.

    Pure except Read-SIInstallNamesRecord / Save-SIInstallNamesRecord (one cfg.InstallState read / write over -Store).
    ASCII only; PowerShell 5.1-safe.
#>

function Get-SIInstallNameDefaults {
    <# PURE. Today's names -- what every existing install runs with. A table in a function, not a $script: variable, so a
       caller that dot-sources this file from another scope still sees it. #>
    [ordered]@{
        web             = 'ca-si-management'                 # the Pro web app
        mcp             = 'ca-si-mcp'                        # its MCP server
        updater         = 'caj-si-updater'                   # the product updater job
        templates       = 'caj-si-templates'                 # the template release job
        webIdentity     = 'uami-si-management'               # the web app's own identity
        mcpIdentity     = 'uami-si-mcp'                      # the MCP server's own identity
        updaterIdentity = 'uami-si-updater'                  # the updater job's own identity
        taggingIdentity = 'uami-securityinsight-tagging'     # asset tagging's own identity
    }
}

function Get-SIInstallNameRoles { @((Get-SIInstallNameDefaults).Keys) }

function Get-SIInstallNameVariable {
    <# PURE. The updater job's variable that names -Role ('' = none). #>
    param([Parameter(Mandatory)][string]$Role)
    switch ($Role) {
        'web'     { 'SI_UPDATER_WEB_APP' }
        'mcp'     { 'SI_UPDATER_MCP_APP' }
        'updater' { 'SI_UPDATER_JOB_NAME' }
        default   { '' }
    }
}

function Test-SIInstallNameValue {
    <# PURE. A name accepted from a record or a variable: an Azure resource name, 2-90 letters, digits, '-', '_', '.'. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    [bool]("$Value".Trim() -match '^[A-Za-z0-9][A-Za-z0-9._-]{1,89}$')
}

function Get-SIInstallNameProp {
    <# PURE. One role's value from a record (a hashtable, a parsed JSON object or a JSON string); '' when it has none. #>
    param([AllowNull()]$Record, [Parameter(Mandatory)][string]$Role)
    if ($null -eq $Record) { return '' }
    if ($Record -is [string]) { $Record = ConvertFrom-SIInstallNamesValue -Value $Record; if ($null -eq $Record) { return '' } }
    if ($Record -is [System.Collections.IDictionary]) { if ($Record.Contains($Role)) { return "$($Record[$Role])".Trim() } else { return '' } }
    if ($Record.PSObject.Properties[$Role]) { return "$($Record.$Role)".Trim() }
    ''
}

function ConvertFrom-SIInstallNamesValue {
    <# PURE. The cfg.InstallState 'InstallNames' value (compact JSON) as an object; $null when empty or not JSON. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    try { $o = "$Value" | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if ($o -is [System.Management.Automation.PSCustomObject]) { return $o }
    $null
}

function Get-SIInstallName {
    <#
        THE name of one part of this install. -Role: web | mcp | updater | templates | webIdentity | mcpIdentity |
        updaterIdentity | taggingIdentity. Record -> variable -> today's name (see the header). -Record: the record a caller
        already holds (else $global:SI_InstallNames); -NoRecord skips it. -Env: variables to read before the process's own
        (the updater's run hashtable; tests). Never throws for a known role; an unknown role throws (a typo must never
        quietly become another resource).
    #>
    param([Parameter(Mandatory)][string]$Role, [AllowNull()]$Record = $null, [switch]$NoRecord, [hashtable]$Env = @{})
    $defaults = Get-SIInstallNameDefaults
    if (-not $defaults.Contains($Role)) { throw ("Get-SIInstallName: unknown role '{0}' (known: {1})" -f $Role, ((Get-SIInstallNameRoles) -join ', ')) }
    if (-not $NoRecord) {
        $rec = if ($null -ne $Record) { $Record } else { $global:SI_InstallNames }
        $v = Get-SIInstallNameProp -Record $rec -Role $Role
        if (Test-SIInstallNameValue $v) { return $v }
    }
    $var = Get-SIInstallNameVariable -Role $Role
    if ($var) {
        $e = if ($Env.ContainsKey($var)) { "$($Env[$var])".Trim() } else { "$([Environment]::GetEnvironmentVariable($var))".Trim() }
        if (Test-SIInstallNameValue $e) { return $e }
    }
    [string]$defaults[$Role]
}

function Get-SIInstallNameCandidates {
    <# PURE apart from Get-SIInstallName's reads. Every name a FINDER tries for -Role, in order: the resolved name, then
       today's name; no duplicates (case-insensitive). #>
    param([Parameter(Mandatory)][string]$Role, [AllowNull()]$Record = $null, [hashtable]$Env = @{})
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @((Get-SIInstallName -Role $Role -Record $Record -Env $Env), [string](Get-SIInstallNameDefaults)[$Role])) {
        if ((Test-SIInstallNameValue $n) -and -not @($out | Where-Object { $_ -ieq $n }).Count) { $out.Add("$n".Trim()) }
    }
    $out.ToArray()
}

function New-SIInstallNamesRecord {
    <#
        PURE. The record the updater stores: -Names (role -> name; an empty or invalid name is left out) over -Current (what
        is stored; a hashtable, object or JSON). A role -Names does not give keeps its stored value; a role neither gives is
        left out (its readers fall back to the variable, then today's name). Returns @{ Record (ordered, + recordedUtc);
        Value (compact JSON); Changed }.
    #>
    param([hashtable]$Names = @{}, [AllowNull()]$Current = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{}; $changed = $false
    foreach ($r in (Get-SIInstallNameRoles)) {
        $cur = Get-SIInstallNameProp -Record $Current -Role $r
        $new = if ($Names.ContainsKey($r)) { "$($Names[$r])".Trim() } else { '' }
        if (Test-SIInstallNameValue $new) { $out[$r] = $new } elseif (Test-SIInstallNameValue $cur) { $out[$r] = $cur }
        if ($out.Contains($r) -and $out[$r] -cne $cur) { $changed = $true }
    }
    $out['recordedUtc'] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    @{ Record = $out; Value = ($out | ConvertTo-Json -Compress); Changed = $changed }
}

function Read-SIInstallNamesRecord {
    <# The stored record (cfg.InstallState 'InstallNames') over -Store (the Pro database: $Store.Invoke $sql $params 'reader');
       $null when there is none, the table is not there, or it cannot be read. Never throws. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return $null }
    $sql = "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'InstallNames';"
    try {
        # the store answers its rows as ONE array (', $out.ToArray()'): ForEach-Object unrolls it, as every reader does
        $row = @(& $Store.Invoke $sql ([ordered]@{}) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        if (-not $row) { return $null }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } elseif ($row.PSObject.Properties['Value']) { [string]$row.Value } else { [string]$row }
        ConvertFrom-SIInstallNamesValue -Value $v
    } catch { $null }
}

function Save-SIInstallNamesRecord {
    <# The record (-Value, compact JSON from New-SIInstallNamesRecord) into cfg.InstallState 'InstallNames'. Never throws:
       $true written, $false not. #>
    param($Store, [AllowEmptyString()][string]$Value, [string]$By = 'caj-si-updater')
    if (-not $Store -or -not $Store.Invoke -or -not "$Value".Trim()) { return $false }
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'InstallNames')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'InstallNames';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'InstallNames', @Value, NULL, @By);
    COMMIT;
END
'@
    try { $null = & $Store.Invoke $sql ([ordered]@{ Value = "$Value"; By = $By }) 'nonquery'; $true } catch { $false }
}
