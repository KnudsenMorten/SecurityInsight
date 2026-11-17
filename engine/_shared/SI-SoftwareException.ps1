#Requires -Version 5.1
<#
    A PER-SERVER EXCEPTION OF A SOFTWARE DETECTION (REQUIREMENTS #1219 (4), owner 2026-11-16: "we cannot make a generic rule
    where we look at paths ... we need a way to fine tune on a per server so i can exempt a wrong detection of wordpress so it
    doesnt use that on that specific server").

    An Admin (SI GUI, Pro) marks ONE rule's match of ONE software on ONE CI a false positive, with a reason
    (sidata.CiSoftwareException, the same pattern as the manual CI overrides sidata.CiOverride: soft removal, who / when / why,
    one cfg.ChangeLog row per set and per undo -- pro-management\src\SI.Management.Web\Changes\SoftwareExceptionStore.cs).

    APPLIED in both tier computations, before the MIN of the tier sources:
      the CI build      Invoke-SICiRules (engine\data-model\SI-CiEnrich.ps1): the rule named by the exception is evaluated on
                        the CI WITHOUT the excepted software in si_installed_software -- its other conditions (a name, a tag)
                        still count; every other rule sees the CI as it is. The CI carries si_software_exceptions (each
                        exception, and what it did: removed the rule's claim / the rule still claims through other evidence /
                        the rule did not match that software).
      the profiler      Test-SIKind_hasSoftwareInstalled (engine\asset-profiling\shared\RuleEval.ps1): that rule does not look
                        at the excepted software on the CI's Defender devices (sidata.CiLink).
    Scope = exactly (CI, rule id, vendor/product): never another server, never another rule. The findings are untouched (a
    finding is never hidden); the CI says the detection is excepted. No exception = every function here answers "none" and
    both computations run exactly as before (a database without the table answers no rows). A read that FAILS changes no
    tier: the CI build builds no CI that run and the endpoint profile is not stored that run -- both keep their last good state
    and say so (Invoke-SICiBuild, Invoke-SIProfile).

    PURE except the two SQL texts and Read-SIDeviceSoftwareExceptions (one read through a SQL seam). PowerShell 5.1 / 7.
#>

function Get-SISoftwareExceptionValue {
    <# PURE. A value from a dictionary or an object; $null when absent or DBNull. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    $v = $null
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { $v = $Item[$Name] } }
    else { $p = $Item.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    return $v
}

function ConvertTo-SISoftwareExceptionKey {
    <# PURE. The software an exception names as the software lists carry it: 'vendor/product', lower-case, trimmed. #>
    param([string]$Vendor, [string]$Product)
    ('{0}/{1}' -f ([string]$Vendor).Trim(), ([string]$Product).Trim()).ToLowerInvariant()
}

function Get-SICiRuleIdOf {
    <# PURE. The rule id of a CI rule ('<rule id>/<detection id>' -> '<rule id>'); a plain rule id stays as it is. #>
    param([string]$CiRuleId)
    $s = ([string]$CiRuleId).Trim()
    $i = $s.IndexOf('/')
    if ($i -gt 0) { return $s.Substring(0, $i) }
    return $s
}

function Get-SICiSoftwareExceptionReadSql {
    <# Every exception in force (not removed). A database without the table answers no rows (the updater creates it). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiSoftwareException') IS NULL
    SELECT CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS NVARCHAR(200)) AS RuleId, CAST(NULL AS NVARCHAR(256)) AS Vendor, CAST(NULL AS NVARCHAR(256)) AS Product,
           CAST(NULL AS NVARCHAR(1000)) AS Reason, CAST(NULL AS NVARCHAR(256)) AS SetBy, CAST(NULL AS DATETIME2(0)) AS SetAt WHERE 1 = 0;
ELSE
    EXEC sp_executesql N'SELECT CiId, RuleId, Vendor, Product, Reason, SetBy, SetAt FROM sidata.CiSoftwareException WHERE ISNULL(Removed, 0) = 0';
'@
}

function ConvertTo-SICiSoftwareExceptionIndex {
    <#
        PURE. Exception rows -> CiId (case-insensitive) -> [ { rule; software ('vendor/product'); vendor; product; reason; set_by;
        set_at } ]. A row without a CI, a rule or a product is left out (it names nothing).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $idx = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $ci = ([string](Get-SISoftwareExceptionValue $r 'CiId')).Trim()
        $rule = ([string](Get-SISoftwareExceptionValue $r 'RuleId')).Trim()
        $vendor = ([string](Get-SISoftwareExceptionValue $r 'Vendor')).Trim().ToLowerInvariant()
        $product = ([string](Get-SISoftwareExceptionValue $r 'Product')).Trim().ToLowerInvariant()
        if (-not $ci -or -not $rule -or -not $product) { continue }
        if (-not $idx.ContainsKey($ci)) { $idx[$ci] = New-Object System.Collections.Generic.List[object] }
        $at = Get-SISoftwareExceptionValue $r 'SetAt'
        if ($at -is [datetime]) { $at = $at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } elseif ($null -ne $at) { $at = [string]$at }
        $idx[$ci].Add([ordered]@{ rule = $rule; software = (ConvertTo-SISoftwareExceptionKey $vendor $product); vendor = $vendor; product = $product
                reason = [string](Get-SISoftwareExceptionValue $r 'Reason'); set_by = [string](Get-SISoftwareExceptionValue $r 'SetBy'); set_at = $at })
    }
    foreach ($k in @($idx.Keys)) { $idx[$k] = $idx[$k].ToArray() }
    $idx
}

function Get-SICiSoftwareExceptedItem {
    <#
        PURE. The CI as ONE rule sees it when exceptions name that rule on this CI: a shallow copy whose si_installed_software
        leaves out the excepted software (every other field the same objects). The CI itself when nothing is left out (it does
        not carry the software) -- never a change to the CI.
    #>
    param([Parameter(Mandatory)]$Ci, [AllowEmptyCollection()][object[]]$Exceptions = @())
    if (@($Exceptions).Count -eq 0) { return $Ci }
    $drop = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @($Exceptions)) { if ($null -ne $e) { [void]$drop.Add([string](Get-SISoftwareExceptionValue $e 'software')) } }
    $sw = Get-SISoftwareExceptionValue $Ci 'si_installed_software'
    if ($null -eq $sw) { return $Ci }
    $all = @($sw)
    if ($sw -is [string]) { $all = @($sw) }
    $kept = New-Object System.Collections.Generic.List[object]
    $removed = 0
    foreach ($v in $all) {
        if ($null -ne $v -and $drop.Contains(([string]$v).Trim())) { $removed++; continue }
        $kept.Add($v)
    }
    if ($removed -eq 0) { return $Ci }
    $copy = [ordered]@{}
    foreach ($k in @($Ci.Keys)) { $copy[$k] = $Ci[$k] }
    $copy['si_installed_software'] = $kept.ToArray()
    return $copy
}

function Get-SISoftwareExceptionEffectText {
    <# PURE. What an exception did on the CI, in words (the CI page, the explanation). #>
    param([string]$Effect)
    switch ($Effect) {
        'removed' { 'the rule no longer claims a tier on this server' }
        'other-evidence' { 'the rule still claims through its other evidence' }
        default { 'the rule did not match this software on this server' }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  The profiler: per Defender device (through sidata.CiLink)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDeviceSoftwareExceptionReadSql {
    <# Every exception in force with the Defender devices of its CI (sidata.CiLink, provider mde). No table = no rows. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiSoftwareException') IS NULL OR OBJECT_ID('sidata.CiLink') IS NULL
    SELECT CAST(NULL AS NVARCHAR(64)) AS DeviceId, CAST(NULL AS NVARCHAR(200)) AS RuleId, CAST(NULL AS NVARCHAR(256)) AS Vendor, CAST(NULL AS NVARCHAR(256)) AS Product WHERE 1 = 0;
ELSE
    EXEC sp_executesql N'SELECT DISTINCT LOWER(l.NativeId) AS DeviceId, x.RuleId, x.Vendor, x.Product
FROM sidata.CiSoftwareException x JOIN sidata.CiLink l ON l.CiId = x.CiId AND l.Provider = N''mde''
WHERE ISNULL(x.Removed, 0) = 0';
'@
}

function ConvertTo-SIDeviceSoftwareExceptionIndex {
    <# PURE. Rows (DeviceId, RuleId, Vendor, Product) -> device id (lower-case) -> rule id (case-insensitive) -> a case-insensitive
       set of 'vendor/product' -- the shape Test-SIKind_hasSoftwareInstalled reads ($script:SIRuleIndexes.softwareExceptions). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $idx = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $d = ([string](Get-SISoftwareExceptionValue $r 'DeviceId')).Trim().ToLowerInvariant()
        $rule = ([string](Get-SISoftwareExceptionValue $r 'RuleId')).Trim()
        $p = ([string](Get-SISoftwareExceptionValue $r 'Product')).Trim()
        if (-not $d -or -not $rule -or -not $p) { continue }
        if (-not $idx.ContainsKey($d)) { $idx[$d] = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase) }
        if (-not $idx[$d].ContainsKey($rule)) { $idx[$d][$rule] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
        [void]$idx[$d][$rule].Add((ConvertTo-SISoftwareExceptionKey ([string](Get-SISoftwareExceptionValue $r 'Vendor')) $p))
    }
    return $idx
}

function Read-SIDeviceSoftwareExceptions {
    <#
    .SYNOPSIS  The exceptions in force per Defender device for the profiler. Never throws: @{ Index; Rows; Error }.
    .PARAMETER Invoke  the SQL seam { param($Sql, $Params, $Mode) }; none = the install's database when one is configured
                       (none configured = no exceptions -- nothing can have set one).
    #>
    param([scriptblock]$Invoke)
    $res = @{ Index = @{}; Rows = 0; Error = $null; FromCache = $false; CacheAt = $null; ReadError = $null }
    try {
        if (-not $Invoke) {
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
                $rs = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-RecordSql.ps1')
                if ([IO.File]::Exists($rs)) { . $rs }
            }
            if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { $Invoke = New-SIRecordSqlInvoke }
        }
        if (-not $Invoke) { return $res }
        try { $rows = @(& $Invoke (Get-SIDeviceSoftwareExceptionReadSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
        catch {
            # the LAST GOOD read (owner 2026-11-17): never profile without the exceptions an Admin set
            $err = $_.Exception.Message
            $c = Read-SIBuildInputCache -Invoke $Invoke -Name 'device-software-exceptions'
            if ($null -eq $c) { throw $err }
            $res.FromCache = $true; $res.CacheAt = $c.SavedAt; $res.ReadError = $err
            $rows = @($c.Rows)
        }
        if (-not $res.FromCache) { $null = Save-SIBuildInputCache -Invoke $Invoke -Name 'device-software-exceptions' -Rows $rows }
        $res.Rows = $rows.Count
        $res.Index = ConvertTo-SIDeviceSoftwareExceptionIndex -Rows $rows
    } catch { $res.Error = $_.Exception.Message; $res.Index = @{} }
    return $res
}

# ---------------------------------------------------------------------------------------------------------------------
#  The finding mark for an output (the finding field si_detection_excepted, ServiceNow column u_si_detection_excepted --
#  shipped OFF: worked out only when an output column reads it)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIFindingDetectionExcepted {
    <#
        PURE. The rule id(s) excepted on the finding's CI (si_ci_id) for the finding's software (si_affected_vendor x
        si_affected_product, a value or a list; no vendor = the product alone), sorted and joined with '; '; '' when none.
        -Index: ConvertTo-SICiSoftwareExceptionIndex.
    #>
    param($Item, [hashtable]$Index)
    if ($null -eq $Index -or $Index.Count -eq 0 -or $null -eq $Item) { return '' }
    $ci = ([string](Get-SISoftwareExceptionValue $Item 'si_ci_id')).Trim()
    if (-not $ci -or -not $Index.ContainsKey($ci)) { return '' }
    $list = { param($v) @(@($v) | ForEach-Object { ([string]$_) -split ';' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }) }
    $vs = & $list (Get-SISoftwareExceptionValue $Item 'si_affected_vendor')
    $ps = & $list (Get-SISoftwareExceptionValue $Item 'si_affected_product')
    if ($ps.Count -eq 0) { return '' }
    $rules = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    foreach ($e in @($Index[$ci])) {
        if ($null -eq $e) { continue }
        $ep = [string]$e.product
        if ($ps -notcontains $ep) { continue }
        if ($vs.Count -gt 0 -and $vs -notcontains [string]$e.vendor) { continue }
        [void]$rules.Add([string]$e.rule)
    }
    return (@($rules) -join '; ')
}

function Add-SIFindingDetectionExcepted {
    <# Puts si_detection_excepted on a finding item (a dictionary or an object) when an exception names it; an item without
       one is left exactly as it is. #>
    param($Item, [hashtable]$Index)
    $v = Get-SIFindingDetectionExcepted -Item $Item -Index $Index
    if (-not $v) { return }
    if ($Item -is [System.Collections.IDictionary]) { $Item['si_detection_excepted'] = $v }
    else { $Item | Add-Member -NotePropertyName 'si_detection_excepted' -NotePropertyValue $v -Force }
}

function Read-SIOutputSoftwareExceptionIndex {
    <# The exceptions in force as the CI build reads them (ConvertTo-SICiSoftwareExceptionIndex), for an output whose column
       reads si_detection_excepted. -Invoke: the SQL seam; none = the install's database (none configured = no exception can
       exist: an empty index). THROWS on a failed read: a switched-on column is never emptied by a read that failed. #>
    param([scriptblock]$Invoke)
    if (-not $Invoke) {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
            $rs = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-RecordSql.ps1')
            if ([IO.File]::Exists($rs)) { . $rs }
        }
        if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { $Invoke = New-SIRecordSqlInvoke }
    }
    if (-not $Invoke) { return @{} }
    try { $rows = @(& $Invoke (Get-SICiSoftwareExceptionReadSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch { throw ('the per-server software exceptions could not be read for the column u_si_detection_excepted ({0}) -- nothing is sent with an unknown value' -f $_.Exception.Message) }
    ConvertTo-SICiSoftwareExceptionIndex -Rows $rows
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE LAST GOOD READ (owner 2026-11-17): a failed read of an Admin's exceptions or manual CI overrides never stops a tier
#  computation and never lets the rules decide without them -- the last good read is used (sidata.CiBuildInputCache, written
#  after every good read) and the run says so. Only when there is no last good copy either is the computation held.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIBuildInputCacheSql {
    <# -Part read (@Name -> Json, SavedAt) | write (@Name, @Json). A database without the table: no row / nothing written. #>
    param([Parameter(Mandatory)][ValidateSet('read', 'write')][string]$Part)
    if ($Part -eq 'read') {
        return @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiBuildInputCache') IS NULL SELECT CAST(NULL AS NVARCHAR(MAX)) AS Json, CAST(NULL AS DATETIME2(0)) AS SavedAt WHERE 1 = 0;
ELSE EXEC sp_executesql N'SELECT Json, SavedAt FROM sidata.CiBuildInputCache WHERE Name = @n', N'@n NVARCHAR(64)', @n = @Name;
'@
    }
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiBuildInputCache') IS NOT NULL
    EXEC sp_executesql N'MERGE sidata.CiBuildInputCache AS c USING (SELECT @n AS Name) AS x ON c.Name = x.Name
WHEN MATCHED THEN UPDATE SET Json = @j, SavedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, Json, SavedAt) VALUES (@n, @j, SYSUTCDATETIME());', N'@n NVARCHAR(64), @j NVARCHAR(MAX)', @n = @Name, @j = @Json;
'@
}

function ConvertTo-SIBuildInputCacheJson {
    <# PURE. Rows (dictionaries or objects) -> JSON; a [datetime] is kept exactly (its ticks and kind), DBNull as null. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $h = [ordered]@{}
        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys | ForEach-Object { [string]$_ }) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($nm in $names) {
            $v = if ($r -is [System.Collections.IDictionary]) { $r[$nm] } else { $r.$nm }
            if ($v -is [System.DBNull]) { $v = $null }
            elseif ($v -is [datetime]) { $v = ('dt:{0}:{1}' -f $v.Ticks, [int]$v.Kind) }
            $h[$nm] = $v
        }
        $out.Add($h)
    }
    ConvertTo-Json -InputObject @($out.ToArray()) -Compress -Depth 4
}

function ConvertFrom-SIBuildInputCacheJson {
    <# PURE. The cache's JSON -> rows (hashtables), every saved [datetime] back exactly as it was. #>
    param([string]$Json)
    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $Json) { return , $rows.ToArray() }
    foreach ($o in @(ConvertFrom-Json -InputObject $Json)) {
        if ($null -eq $o) { continue }
        $h = @{}
        foreach ($p in $o.PSObject.Properties) {
            $v = $p.Value
            if ($v -is [string] -and $v -match '^dt:(-?\d+):(\d)$') { $v = [datetime]::new([long]$Matches[1], [System.DateTimeKind][int]$Matches[2]) }
            $h[$p.Name] = $v
        }
        $rows.Add($h)
    }
    , $rows.ToArray()
}

function Save-SIBuildInputCache {
    <# The last good read of -Name kept for a read that fails later. Never throws; $true when kept. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Name, [AllowEmptyCollection()][object[]]$Rows = @())
    try { $null = & $Invoke (Get-SIBuildInputCacheSql -Part 'write') @{ Name = $Name; Json = (ConvertTo-SIBuildInputCacheJson -Rows $Rows) } 'nonquery'; return $true }
    catch { return $false }
}

function Read-SIBuildInputCache {
    <# The last good read of -Name: @{ Rows; SavedAt }, or $null when there is none (or it cannot be read either). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Name)
    try {
        $r = @(& $Invoke (Get-SIBuildInputCacheSql -Part 'read') @{ Name = $Name } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($null -eq $r) { return $null }
        $j = Get-SISoftwareExceptionValue $r 'Json'
        if ($null -eq $j) { return $null }
        return [pscustomobject]@{ Rows = (ConvertFrom-SIBuildInputCacheJson -Json ([string]$j)); SavedAt = (Get-SISoftwareExceptionValue $r 'SavedAt') }
    } catch { return $null }
}
