#Requires -Version 5.1
<#
    SecurityInsight -- A RE-ISSUED LICENCE REACHES THE INSTALL BY ITSELF (#517; framework DOCS/REQUIREMENTS.md §12.6b,
    Invardia live 1.0.230).

    HOW: every IDENTIFIED status report carries the installed licence's id (LicenceId, a lower-case GUID -- left out when
    the licence has no GUID-shaped id, else Invardia refuses the whole report). When Invardia has re-issued that licence it
    answers 202 {"supersededBy": "<newest id>"}. The engine run that hears it records the id here, in the Pro database
    (cfg.InstallState 'LicenceSupersededBy', on the connection the run already has); the updater's licence step reads it on
    its next run and knocks at once with currentLicenceId -- Invardia then approves the successor by itself and the normal
    pull installs it (verified offline as every licence is). The same id is knocked for only once.

    The marker only says "ask now"; nothing is trusted from it -- the licence itself is verified as always. PS 5.1 + 7.
#>

function Get-SILicenceSupersededNameState {
    <# The value of $script:SILicenceSupersededName, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SILicenceSupersededName) { $script:SILicenceSupersededName = 'LicenceSupersededBy' }
    , $script:SILicenceSupersededName
}
$script:SILicenceSupersededName = $null; $null = Get-SILicenceSupersededNameState
function Get-SILicenceSupersededGuidState {
    <# The value of $script:SILicenceSupersededGuid, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SILicenceSupersededGuid) { $script:SILicenceSupersededGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' }
    , $script:SILicenceSupersededGuid
}
$script:SILicenceSupersededGuid = $null; $null = Get-SILicenceSupersededGuidState

function ConvertTo-SILicenceIdOrEmpty {
    <# PURE. A licence id as the lower-case GUID Invardia takes, or '' when it is not GUID-shaped. #>
    param([AllowNull()][AllowEmptyString()][string]$LicenceId)
    $v = "$LicenceId".Trim()
    if ($v -match (Get-SILicenceSupersededGuidState)) { return $v.ToLowerInvariant() }
    ''
}

function Get-SILicenceSupersededFromAnswer {
    <# PURE. The supersededBy id of an uplink answer (a parsed body, or its text), '' when none / not a GUID. #>
    param([AllowNull()]$Answer)
    if ($null -eq $Answer) { return '' }
    $o = $Answer
    if ($Answer -is [string]) { if (-not $Answer.Trim()) { return '' }; try { $o = $Answer | ConvertFrom-Json -ErrorAction Stop } catch { return '' } }
    $v = ''
    if ($o -is [System.Collections.IDictionary]) { if ($o.Contains('supersededBy')) { $v = [string]$o['supersededBy'] } }
    elseif ($o.PSObject.Properties['supersededBy']) { $v = [string]$o.supersededBy }
    ConvertTo-SILicenceIdOrEmpty $v
}

function Save-SILicenceSupersededMark {
    <# Records the newest licence id Invardia named (cfg.InstallState 'LicenceSupersededBy') on -Store. Throws on failure. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$LicenceId, $NowUtc)
    $id = ConvertTo-SILicenceIdOrEmpty $LicenceId
    if (-not $id) { throw "not a licence id: '$LicenceId'" }
    $at = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $v = ([ordered]@{ licenceId = $id; seenUtc = $at.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress)
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
    COMMIT;
END
'@
    $null = & $Store.Invoke $sql ([ordered]@{ Name = (Get-SILicenceSupersededNameState); Value = $v; By = 'si-engine (Invardia uplink)' }) 'nonquery'
}

function Read-SILicenceSupersededMark {
    <# The licence id the last report heard (cfg.InstallState 'LicenceSupersededBy') on -Store, '' when none. NEVER throws. #>
    param([Parameter(Mandatory)]$Store)
    try {
        $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'LicenceSupersededBy'" @{} 'reader' | ForEach-Object { $_ })
        foreach ($row in $rows) {
            if (-not $row) { continue }
            $v = if ($row -is [System.Collections.IDictionary]) { $row['Value'] } else { $row.Value }
            if ($null -eq $v -or $v -is [System.DBNull]) { continue }
            return (Get-SILicenceSupersededFromAnswer ([string]$v -replace '"licenceId"', '"supersededBy"'))
        }
    } catch { }
    ''
}
