#Requires -Version 5.1
<#
    SecurityInsight -- REPORT-FAILURE CAUSES, CAPABILITIES AND LICENCES IN THE UPLINK (#709; framework DOCS/REQUIREMENTS.md
    8.16 UPLINK-CAUSES, the contract -- this file is SecurityInsight's own probe, catalogue and mapping).

    WHAT IT BUILDS (pure builders; the sender, SI-TelemetrySend.ps1, puts them on the records):
      run record  `Reports` -- at most 20 items, the most severe first, ONLY for reports that failed, were not applicable or
                  deviated. Every item carries Report (an id, never a title), Code (si-<area>-<nnnn>, from
                  data-model/errors.locked.json), CauseClass (the closed list), MissingName / MissingLicence / Bucket,
                  FixedIn + Action (from the catalogue), the context numbers (RunMs, Rows, LastGoodRunMs, LastGoodRows,
                  SourceCount, Buckets, Retries {429, 502, 504}, QueryHash, QueryChanged, Region, StartedUtc) and -- on an
                  IDENTIFIED record only -- Detail: the engine's first error line, through SecurityInsight's secret scrub, at
                  most 500 characters. A value that is not known is null, never guessed.
      heartbeat   `Capabilities` (the closed keys, booleans -- a key that could not be measured is LEFT OUT, never sent as
                  false by guess), `CiColumns` (the optional SI_CI_CL columns present, at most 40 ids) and `Licences` (the
                  tenant's SKU part numbers from Graph subscribedSkus -- only when the run's identity may read them; no
                  permission is ever added for it).

    THE RULES:
      * A Reports problem never costs the run record: ConvertTo-SIUplinkReports never throws (an item it cannot map gets
        the generic code of its class; an item it cannot build at all is left out; nothing at all = no Reports), and the
        sender sends the record again WITHOUT the optional fields when Invardia refuses it (Send-SITelemetryRecordWithFallback).
      * Code and CauseClass are ALWAYS on an item (Invardia refuses the whole record, 422, for an item without them).
      * Detail never carries a secret: SecurityInsight's own scrub (ConvertTo-SITelemetryErrorText) and the framework's
        (ConvertTo-AitUplinkRedacted), then any long token-shaped run is cut; a Detail that still looks like a secret is
        dropped (Invardia refuses the whole record for one).
      * Ids: lower case, letters, digits and dashes, at most 60 (`Identity_SPN_OwnerMismatch` -> `identity-spn-ownermismatch`,
        `si_cmdb_id` -> `si-cmdb-id`).

    PS 5.1 and 7. Nothing here touches the network except the probe readers (Get-SICapabilityProbe's defaults), which a
    test session never calls.
#>

function Get-SIUplinkCausesState {
    <# The value of $script:SIUplinkCauses, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIUplinkCauses) { $script:SIUplinkCauses = @{
    CauseClasses   = @('no-data-source', 'missing-column', 'query-defect', 'platform-timeout', 'too-large', 'count-more', 'count-less',
                       'settings-unreachable', 'permission', 'missing-licence', 'out-of-memory', 'held-last-good', 'held-too-long')
    Actions        = @('none', 'fixed-in', 'support', 'customer')
    # most severe first: a run that could not read its settings, rows that are missing, SecurityInsight's own defects, a
    # permission, the platform; then what does not apply (licence, data source) and last a count that was only higher
    # #711: out of memory is SecurityInsight's own defect (the run held more than it needed) -- ranked with the query defects
    # #902: a hold held too long ranks with the missing rows (count-less), a hold that is information only comes last
    Severity       = @{ 'settings-unreachable' = 1; 'count-less' = 2; 'held-too-long' = 2; 'out-of-memory' = 3; 'query-defect' = 4; 'permission' = 5; 'platform-timeout' = 6
                        'too-large' = 7; 'missing-column' = 8; 'missing-licence' = 9; 'no-data-source' = 10; 'count-more' = 11; 'held-last-good' = 12 }
    MaxReports     = 20
    DetailMax      = 500
    IdMax          = 60
    CodePattern    = '^si-[a-z]{2,8}-\d{4}$'
    DocsBase       = 'https://invardia.com/docs/si/errors/'
    CapabilityKeys = @('defenderXdr', 'defenderVulnMgmt', 'mdi', 'intune', 'entraP2Pim', 'cmdb', 'sentinel', 'dataLake')
    MaxCiColumns   = 40
    MaxLicences    = 40
    # the SI_CI_CL columns that exist only where their source does (a CMDB, ServiceNow) -- the CMDB-less install lesson
    OptionalCiColumnPattern = '^si_(cmdb|servicenow|snow)_[a-z0-9_]+$'
    # service plans that say what a report needs (Graph subscribedSkus servicePlans[].servicePlanName)
    PlanCapabilities = @{ 'INTUNE_A' = 'intune'; 'AAD_PREMIUM_P2' = 'entraP2Pim'; 'TVM_PREMIUM_1' = 'defenderVulnMgmt' }
    # the generic code of each class: an unknown failure gets it until it is given its own (framework 8.16)
    GenericCodes   = @{ 'no-data-source' = 'si-ra-0901'; 'missing-column' = 'si-ra-0902'; 'query-defect' = 'si-ra-0903'; 'platform-timeout' = 'si-ra-0904'
                        'too-large' = 'si-ra-0905'; 'count-more' = 'si-ra-0906'; 'count-less' = 'si-ra-0907'; 'settings-unreachable' = 'si-ra-0908'
                        'permission' = 'si-ra-0909'; 'missing-licence' = 'si-ra-0910'
                        # #711: a report that ran Risk Analysis out of memory has its own code from the start (support, a ticket)
                        'out-of-memory' = 'si-ra-0303'
                        # #902: a hold's code always comes from the hold list (data-model/hold-kinds.locked.json); these are only
                        # the classes' generic codes for the catalogue's rule "every class has one"
                        'held-last-good' = 'si-ra-0911'; 'held-too-long' = 'si-ra-0913' }
    # a failure whose cause is not recognised at all (the support worker escalates these for a human)
    UnknownCode    = 'si-ra-0900'
    # =================================================================================================================
    # #902 THE HOLD CONTRACT WITH INVARDIA (framework 8.16 on main) -- every name of it is HERE, so a rename is one edit.
    #   a report held ON PURPOSE (it keeps its last complete result, nothing of it closes) is an item of class
    #   HoldClassInfo (information only at Invardia: no alert, no fix request); the same report held
    #   escalateAfterDetailedRuns Detailed runs in a row is an item of class HoldClassEscalated (a normal failure at Invardia:
    #   run alert, fix request, ticket). Both carry the HoldFields: Held (true), KeptAgeHours (whole hours from the kept
    #   result's collection time to this run's; null = none), HeldRuns (runs of this grain in a row, this one included).
    HoldClassInfo      = 'held-last-good'
    HoldClassEscalated = 'held-too-long'
    HoldFieldHeld      = 'Held'
    HoldFieldAge       = 'KeptAgeHours'
    HoldFieldRuns      = 'HeldRuns'
    # REMOVE-ME (#902): Invardia's validator refuses an unknown item field (422 on Reports.Held) until its version is live.
    # Until then the two classes and the three fields are NOT sent: an information hold is left OUT of Reports[], an
    # escalated hold goes as a normal failure -- its escalation code, class HoldOffEscalatedClass, without the fields.
    # Switch: setting SI_Uplink_SendHoldFields (job variable SI_UPLINK_SENDHOLDFIELDS): on / off / a ring list / auto =
    # the rings in HoldFieldsRings -- confirmed for NO ring yet. When Invardia's version is live on every ring: send always,
    # drop the switch, HoldFieldsRings and HoldOffEscalatedClass.
    HoldFieldsSwitch      = 'SI_Uplink_SendHoldFields'
    # Invardia's validator takes them since 1.0.592 (716b371, 2026-10-26): RING 0 FIRST (internal), the other rings once
    # Invardia has checked internal's first held item on its environment page
    HoldFieldsRings       = @(0)
    HoldOffEscalatedClass = 'count-less'
} }
    , $script:SIUplinkCauses
}
$script:SIUplinkCauses = $null; $null = Get-SIUplinkCausesState

# #902: the one list of hold kinds (the code of each hold)
if (-not (Get-Command -Name Get-SIHoldKindCode -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-HoldKinds.ps1')) }

function Get-SIUplinkCausesContract { (Get-SIUplinkCausesState) }

function Resolve-SIUplinkHoldFieldsSwitch {
    <#
        PURE (with -Value / -EnvValue). REMOVE-ME (#902): do the hold classes and fields go out from this install?
        SI_Uplink_SendHoldFields (setting) > SI_UPLINK_SENDHOLDFIELDS (job variable) > auto (the rings in HoldFieldsRings --
        none yet). on / true / yes = on; off / false / no = off; a ring list ("0", "0,1") = on for those rings. -Ring not
        known = off unless 'on'. @{ On; Setting; Reason } (the same rule as Resolve-SIUplinkFieldSwitch).
    #>
    param([AllowNull()]$Ring, $Value = '__read__', $EnvValue = '__read__', [int[]]$ConfirmedRings = @((Get-SIUplinkCausesState).HoldFieldsRings))
    $name = [string](Get-SIUplinkCausesState).HoldFieldsSwitch
    if ("$Value" -eq '__read__') { $Value = Get-Variable -Name $name -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    if ("$EnvValue" -eq '__read__') { $EnvValue = [Environment]::GetEnvironmentVariable($name.ToUpperInvariant()) }
    $rn = -1
    if ($null -ne $Ring -and "$Ring".Trim() -ne '') { if (-not [int]::TryParse("$Ring", [ref]$rn)) { $rn = -1 } }
    $set = ''
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $set = $(if ($v) { 'on' } else { 'off' }); break }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        $set = $s; break
    }
    if ($set -in @('on', 'true', 'yes', 'enabled')) { return [pscustomobject]@{ On = $true; Setting = 'on'; Reason = "$name is on" } }
    if ($set -in @('off', 'false', 'no', 'disabled')) { return [pscustomobject]@{ On = $false; Setting = 'off'; Reason = "$name is off" } }
    if ($set -match '^(ring\s*)?[0-3](\s*[,;]\s*(ring\s*)?[0-3])*$') {
        $rings = @([regex]::Matches($set, '[0-3]') | ForEach-Object { [int]$_.Value })
        return [pscustomobject]@{ On = ($rn -ge 0 -and $rings -contains $rn); Setting = 'rings'; Reason = ("$name is on for ring(s) {0}" -f ($rings -join ', ')) }
    }
    $on = ($rn -ge 0 -and @($ConfirmedRings) -contains $rn)
    [pscustomobject]@{ On = $on; Setting = 'auto'; Reason = $(if ($on) { "ring $rn takes the hold fields" } else { 'the hold fields wait until Invardia has confirmed them' }) }
}

function Get-SIUplinkFactValue {
    <# PURE. One value of a report fact (a hashtable or an object); $null when it has none. #>
    param([AllowNull()]$Fact, [string]$Name)
    if ($null -eq $Fact) { return $null }
    if ($Fact -is [System.Collections.IDictionary]) { if ($Fact.Contains($Name)) { return $Fact[$Name] } else { return $null } }
    if ($Fact.PSObject.Properties[$Name]) { return $Fact.$Name }
    $null
}

function Test-SIUplinkFactHeld {
    <# PURE. #902: is the fact a report held ON PURPOSE (a HoldKind of the list)? 'escalated' when it is held too long, 'info'
       when it is information only, '' when it is not a hold (every other fact -- mapped exactly as before). #>
    param([AllowNull()]$Fact)
    $k = [string](Get-SIUplinkFactValue $Fact 'HoldKind')
    if (-not $k -or -not (Test-SIHoldKind -Kind $k)) { return '' }
    if ([bool](Get-SIUplinkFactValue $Fact 'Escalated')) { return 'escalated' }
    'info'
}

function Add-SIReportCauseHoldFacts {
    <#
        PURE. #902: the run's report facts with each held report's hold added (-Held: Split-RAReportFailures .Held -- Report,
        Kind, Names, HeldRuns, KeptResultAt, Escalated): HoldKind, HoldNames, HeldRuns, Escalated, KeptResultUtc and
        KeptAgeHours (whole hours from the kept result to -RunUtc, this run's collection time; $null when either is not
        known). A fact of a report that is not held is returned as it is. Never throws.
    #>
    param([AllowNull()][object[]]$Facts, [AllowNull()][object[]]$Held, $RunUtc)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $byName = @{}
        foreach ($h in @($Held | Where-Object { $_ -and [string]$_.Report })) { $byName[[string]$h.Report] = $h }
        foreach ($f in @($Facts | Where-Object { $null -ne $_ })) {
            $r = [string](Get-SIUplinkFactValue $f 'Report')
            $h = $byName[$r]
            if ($null -ne $h -and $f -isnot [System.Collections.IDictionary]) {
                $kept = $null; if ($h.KeptResultAt) { try { $kept = ([datetime]$h.KeptResultAt).ToUniversalTime() } catch { $kept = $null } }
                $age = $null
                if ($null -ne $kept -and $null -ne $RunUtc) { try { $hrs = ([datetime]$RunUtc).ToUniversalTime() - $kept; if ($hrs.TotalHours -ge 0) { $age = [long][Math]::Floor($hrs.TotalHours) } } catch { $age = $null } }
                foreach ($kv in @(@('HoldKind', [string]$h.Kind), @('HoldNames', [string[]]@($h.Names | Where-Object { $_ })), @('HeldRuns', [int]$(if ($h.HeldRuns) { $h.HeldRuns } else { 1 })),
                                  @('Escalated', [bool]$h.Escalated), @('KeptResultUtc', $kept), @('KeptAgeHours', $age))) {
                    Add-Member -InputObject $f -NotePropertyName $kv[0] -NotePropertyValue $kv[1] -Force
                }
            }
            $out.Add($f)
        }
    } catch { return @($Facts) }
    $out.ToArray()
}

function Write-SIUplinkDiag {
    param([string]$Line)
    try { if (Get-Command -Name Write-Diag -ErrorAction SilentlyContinue) { Write-Diag $Line } else { Write-Verbose $Line } } catch { }
}

function ConvertTo-SIUplinkId {
    <# PURE. An id for the uplink: lower case, a-z 0-9 and dashes, no leading / trailing / double dash, at most 60. '' = none. #>
    param([AllowNull()][AllowEmptyString()][string]$Value, [int]$Max = 60)
    $v = ("$Value".Trim().ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($v.Length -gt $Max) { $v = $v.Substring(0, $Max).TrimEnd('-') }
    $v
}

function Get-SIErrorCatalogue {
    <# The error catalogue (data-model/errors.locked.json), read once per process. -Path is the test seam. @() when it cannot
       be read -- every mapping then falls back to the generic codes, which are known here too. #>
    param([string]$Path)
    if (-not $Path -and $null -ne $script:SIErrorCatalogueCache) { return $script:SIErrorCatalogueCache }
    $p = $Path
    if (-not $p) { $p = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'errors.locked.json') }
    $out = @()
    try { $out = @([System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop) } catch { $out = @() }
    if (-not $Path) { $script:SIErrorCatalogueCache = $out }
    # emitted item by item (a ', $out' would reach a caller's @() as ONE nested array)
    $out
}

function Get-SIErrorCodeUrl {
    <# PURE. The public page of an error code: https://invardia.com/docs/si/errors/<code>/ -- '' for a value that is not a code. #>
    param([AllowNull()][AllowEmptyString()][string]$Code)
    $c = "$Code".Trim().ToLowerInvariant()
    if ($c -notmatch (Get-SIUplinkCausesState).CodePattern) { return '' }
    (Get-SIUplinkCausesState).DocsBase + $c + '/'
}

function Get-SIReportCause {
    <#
        PURE. The cause of ONE report that failed, did not apply or deviated, from what the engine knows: -State (Failed |
        NotComplete | NotApplicable | Deviated) and -Text (the engine's own reason / error). Returns @{ CauseClass;
        MissingName } -- CauseClass is ALWAYS a value of the closed list; MissingName the missing table / column / keyword as an
        id, else ''. Recognised = Known $true; a text no rule recognises = Known $false (the caller gives it si-ra-0900).
    #>
    param([AllowEmptyString()][AllowNull()][string]$State, [AllowEmptyString()][AllowNull()][string]$Text)
    $t = [string]$Text
    $r = { param($c, $n, $k = $true) [pscustomobject]@{ CauseClass = $c; MissingName = (ConvertTo-SIUplinkId $n); Known = [bool]$k } }
    # ---- the settings database ------------------------------------------------------------------------------------------
    if ($t -match '(?i)SQL error 40\b|error: 40 -|settings database (cannot|could not) be reached|could not reach (its|the) (own )?settings database|settings database is not reachable') { return (& $r 'settings-unreachable' '') }
    # ---- #711: the process ran out of memory (before the other rules: its text can carry any other words) ------------------
    if ($t -match '(?i)OutOfMemoryException|\bOOMKilled\b|\bout of memory\b|\bsi-ra-0303\b') { return (& $r 'out-of-memory' '') }
    # ---- a data source / licence this tenant does not have ---------------------------------------------------------------
    if ($t -match "(?i)Failed to resolve (?:table or column )?expression named '(DeviceTvm[A-Za-z]+)'") { return (& $r 'missing-licence' $Matches[1]) }
    if ($t -match '(?i)Account is not provisioned|advanced hunting is not provisioned') { return (& $r 'no-data-source' 'defender-xdr') }
    if ($t -match "(?i)Failed to resolve (?:table or column )?expression named '(SI_[A-Za-z0-9_]+_CL)'") { return (& $r 'no-data-source' $Matches[1]) }
    if ($t -match "(?i)Failed to resolve (?:table or column )?expression named '((?:Device|Identity|Email|Cloud|Alert|Url|Exposure|Aad|Behavior)[A-Za-z]+)'") { return (& $r 'no-data-source' $Matches[1]) }
    # ---- a column that is not there (an optional CI column at an install without its source) -----------------------------
    if ($t -match "(?i)Failed to resolve scalar expression named '([^']+)'") { return (& $r 'missing-column' $Matches[1]) }
    if ($t -match "(?i)Failed to resolve (?:table or column )?expression named '([^']+)'") { return (& $r 'missing-column' $Matches[1]) }
    if ("$State" -eq 'NotApplicable') { return (& $r 'no-data-source' '') }
    # ---- the count against the source --------------------------------------------------------------------------------------
    if ($t -match '(?i)more than the source''s count') { return (& $r 'count-more' '') }
    if ($t -match '(?i)the source holds (\d+) row\(s\)[^|]*retrieved (\d+)') {
        if ([long]$Matches[2] -gt [long]$Matches[1]) { return (& $r 'count-more' '') }
        return (& $r 'count-less' '')
    }
    if ($t -match '(?i)neither stored nor accounted for|far fewer findings|fewer (rows|findings) than|lost (a )?bucket|could not be read \(a query that timed out') { return (& $r 'count-less' '') }
    # ---- too large ------------------------------------------------------------------------------------------------------
    if ($t -match '(?i)413 Request Entity Too Large|Query body (EXCEEDED|is being tuned)|request body .*too large') { return (& $r 'too-large' 'query-body') }
    if ($t -match '(?i)502 Bad Gateway|exceeded the allowed (result size|limits)|its row limit|OutOfMemory|out of memory|too large') { return (& $r 'too-large' '') }
    # ---- SecurityInsight's own query -------------------------------------------------------------------------------------
    if ($t -match '(?i)\bSYN0002\b') { return (& $r 'query-defect' 'syn0002') }
    # ---- everything else through the run classifier ----------------------------------------------------------------------
    $cls = 'unknown'
    try { if (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue) { $cls = Get-SIErrorClass -Message $t } } catch { $cls = 'unknown' }
    switch -Regex ($cls) {
        '^(graph-401|graph-403|defender-403|arm-403|kv-403|storage-403)$' { return (& $r 'permission' '') }
        '^licence-invalid$' { return (& $r 'missing-licence' '') }
        '^(sql-login|settings-error)$' { return (& $r 'settings-unreachable' '') }
        '^table-missing$' { return (& $r 'no-data-source' '') }
        '^kql-query-defect$' { return (& $r 'query-defect' '') }
        '^(platform-timeout|platform-5xx|throttled|mi-unavailable)$' { return (& $r 'platform-timeout' '') }
        '^ingest-' { return (& $r 'count-less' '') }
    }
    # not recognised: a product defect until it is given its own code (framework 8.16: a failure without a cause is a defect)
    & $r 'query-defect' '' $false
}

function Resolve-SIReportCauseCode {
    <#
        PURE. The stable code of a cause: the catalogue's own code when one fits (si-ra-0101 DeviceTvm* absent, si-ra-0102 a
        missing optional CI column, si-ra-0103 a KQL reserved word, si-ra-0201 more rows than the count, si-ra-0302 the report
        query too large, si-ra-0303 Risk Analysis out of memory (its generic code), si-set-0401 the settings database), else the GENERIC code of its class, else -- a cause nothing
        recognised -- si-ra-0900. NEVER throws, never returns ''.
    #>
    param([Parameter(Mandatory)]$Cause)
    try {
        $cc = [string]$Cause.CauseClass; $mn = [string]$Cause.MissingName
        if ($Cause.PSObject.Properties['Known'] -and -not $Cause.Known) { return (Get-SIUplinkCausesState).UnknownCode }
        switch ($cc) {
            'missing-licence'      { if ($mn -like 'devicetvm*') { return 'si-ra-0101' } }
            'no-data-source'       { if ($mn -like 'devicetvm*') { return 'si-ra-0101' } }
            'missing-column'       { if ($mn -match ('^' + ((Get-SIUplinkCausesState).OptionalCiColumnPattern.Trim('^', '$') -replace '_', '-') + '$')) { return 'si-ra-0102' } }
            'query-defect'         { if ($mn -eq 'syn0002') { return 'si-ra-0103' } }
            'count-more'           { return 'si-ra-0201' }
            'too-large'            { if ($mn -eq 'query-body') { return 'si-ra-0302' } }
            'settings-unreachable' { return 'si-set-0401' }
        }
        $g = (Get-SIUplinkCausesState).GenericCodes[$cc]
        if ($g) { return $g }
    } catch { }
    (Get-SIUplinkCausesState).UnknownCode
}

function ConvertTo-SIUplinkDetail {
    <#
        PURE. The bounded free text of one item (framework 8.16 Detail): the FIRST line of the engine's error, through
        SecurityInsight's secret scrub (ConvertTo-SITelemetryErrorText) and the framework's (ConvertTo-AitUplinkRedacted),
        every long token-shaped run cut, at most 500 characters. $null when there is no text, or when what is left still
        looks like a secret (Invardia refuses the whole record for one -- the record matters more than the Detail).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    try {
        $line = @("$Text" -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -First 1
        if (-not $line) { return $null }
        if (Get-Command -Name ConvertTo-SITelemetryErrorText -ErrorAction SilentlyContinue) { $line = ConvertTo-SITelemetryErrorText $line }
        if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $line = ConvertTo-AitUplinkRedacted -Text $line }
        # connection strings and SAS-style keys the two scrubs do not name
        $line = [regex]::Replace($line, '(?i)\b(Server|Data Source|User ID|Uid|Initial Catalog)\s*=\s*[^;]+;', '$1=[redacted];')
        $line = [regex]::Replace($line, '(?i)\b(token|key|credential|secret)\s*[=:]\s*\S+', '$1=[redacted]')
        # a long run of token characters with letters AND digits (a key, a token, a hash) is cut whatever it is
        $line = [regex]::Replace($line, '[A-Za-z0-9+/_=\-]{32,}', { param($m) if ($m.Value -match '[A-Za-z]' -and $m.Value -match '\d') { '[redacted]' } else { $m.Value } })
        if ($line.Length -gt (Get-SIUplinkCausesState).DetailMax) { $line = $line.Substring(0, (Get-SIUplinkCausesState).DetailMax) }
        if (Test-SIUplinkLooksSecret $line) { return $null }
        return $line
    } catch { return $null }
}

function Test-SIUplinkLooksSecret {
    <# PURE. Does a text still look like it carries a secret (the shapes Invardia's check refuses)? #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text"
    if (-not $t) { return $false }
    if ($t -match 'eyJ[A-Za-z0-9_-]{8,}\.') { return $true }
    if ($t -match '-----BEGIN ') { return $true }
    if ($t -match '(?i)\b(password|pwd|client_secret|accountkey|sharedaccesskey|apikey|api_key)\s*[=:]\s*(?!\[redacted\])\S') { return $true }
    if ($t -match '(?i)[?&]sig=(?!\[redacted\])') { return $true }
    if ($t -match 'inv-[A-Za-z0-9_-]{20,}') { return $true }
    $false
}

function Compare-SIUplinkVersion {
    <# PURE. -1 / 0 / 1 for two dotted versions (each part a whole number -- 3.0.0.202610151821 has a part too large for
       [version]); $null when either cannot be read. Only the leading dotted digits count ('3.0.0.2026...+abc' reads). #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    $pa = if ("$A" -match '^\s*(\d+(?:\.\d+)*)') { @($Matches[1] -split '\.') } else { return $null }
    $pb = if ("$B" -match '^\s*(\d+(?:\.\d+)*)') { @($Matches[1] -split '\.') } else { return $null }
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($i -lt $pa.Count) { [decimal]$pa[$i] } else { [decimal]0 }
        $y = if ($i -lt $pb.Count) { [decimal]$pb[$i] } else { [decimal]0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    0
}

function Get-SIUplinkCatalogueAction {
    <# PURE. Action + FixedIn of a code for THIS version: the catalogue's; a 'fixed-in' whose fix this version already has
       (the cause came back) is 'support' with no FixedIn -- never a promise the release already broke. #>
    param([AllowNull()]$Entry, [AllowEmptyString()][string]$Version)
    $act = 'support'; $fix = $null
    if ($Entry) {
        $a = "$($Entry.action)".Trim().ToLowerInvariant(); if ((Get-SIUplinkCausesState).Actions -contains $a) { $act = $a }
        if ("$($Entry.fixedIn)".Trim()) { $fix = "$($Entry.fixedIn)".Trim() }
    }
    if ($act -eq 'fixed-in') {
        $cmp = Compare-SIUplinkVersion -A $Version -B $fix
        if (-not $fix -or ($null -ne $cmp -and $cmp -ge 0)) { $act = 'support'; $fix = $null }
    } elseif ($act -ne 'none') { $fix = $null }   # 'none' keeps the version since which the report is simply not applicable
    [pscustomobject]@{ Action = $act; FixedIn = $fix }
}

function ConvertTo-SIUplinkNumber {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    $d = 0.0
    if (-not [double]::TryParse("$Value", [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ($d -lt 0 -or [double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
    [long][Math]::Floor($d)
}

function ConvertTo-SIUplinkReports {
    <#
        PURE. The run record's `Reports` from the run's report facts (-Facts: what Risk Analysis put on its run context as
        ReportCauses -- Report, State, Why, StartedUtc, RunMs, Rows, SourceCount, Buckets, QueryHash, Retries, LastGoodRows,
        LastGoodRunMs, LastGoodQueryHash, Bucket). -Identified adds Detail (anonymous: no text ever leaves). -Version decides
        Action / FixedIn; -Region the install's Azure region; -Catalogue the error catalogue (default the shipped one).
        At most 20 items, the most severe first. NEVER throws: an item that cannot be built is left out, nothing = @().
        #902: a fact of a report held ON PURPOSE (HoldKind of the list, Add-SIReportCauseHoldFacts) is never mapped by its
        text: its code is the hold list's (the escalation code once Escalated). With -HoldFields (the hold contract is live
        for this install, Resolve-SIUplinkHoldFieldsSwitch) it is class held-last-good / held-too-long with Held, KeptAgeHours
        and HeldRuns; without it an information hold is left OUT and an escalated hold goes as a normal failure (its code,
        class count-less, no hold fields). An information hold sorts after every real failure. Every other fact: as before.
    #>
    param([AllowNull()][object[]]$Facts, [switch]$Identified, [AllowEmptyString()][string]$Version, [AllowEmptyString()][string]$Region,
          [AllowNull()][object[]]$Catalogue, [switch]$HoldFields)
    $items = New-Object System.Collections.Generic.List[object]
    try {
        if ($null -eq $Facts -or @($Facts).Count -eq 0) { return @() }
        $cat = if ($PSBoundParameters.ContainsKey('Catalogue')) { @($Catalogue) } else { @(Get-SIErrorCatalogue) }
        $byCode = @{}; foreach ($e in $cat) { if ($e -and "$($e.code)".Trim()) { $byCode["$($e.code)".Trim().ToLowerInvariant()] = $e } }
        $reg = ConvertTo-SIUplinkId $Region
        $seen = @{}
        foreach ($f in @($Facts)) {
            try {
                if ($null -eq $f) { continue }
                $get = { param($n) if ($f -is [System.Collections.IDictionary]) { if ($f.Contains($n)) { $f[$n] } else { $null } } elseif ($f.PSObject.Properties[$n]) { $f.$n } else { $null } }
                $rid = ConvertTo-SIUplinkId ([string](& $get 'Report'))
                if (-not $rid -or $seen.ContainsKey($rid)) { continue }
                $state = [string](& $get 'State'); $why = [string](& $get 'Why')
                $hold = Test-SIUplinkFactHeld -Fact $f
                $cause = $null
                if ($hold) {
                    # #902: a report held ON PURPOSE -- its code from the hold list, never from its text (never si-ra-0900)
                    if ($hold -eq 'info' -and -not $HoldFields) { continue }   # information only: left out until Invardia takes the class
                    $hn = @(& $get 'HoldNames' | Where-Object { "$_".Trim() })
                    $hc = $(if ($hold -eq 'escalated') { $(if ($HoldFields) { [string](Get-SIUplinkCausesState).HoldClassEscalated } else { [string](Get-SIUplinkCausesState).HoldOffEscalatedClass }) } else { [string](Get-SIUplinkCausesState).HoldClassInfo })
                    $cause = [pscustomobject]@{ CauseClass = $hc; MissingName = $(if ($hn.Count) { ConvertTo-SIUplinkId ([string]$hn[0]) } else { '' }); Known = $true }
                    $code = Get-SIHoldKindCode -Kind ([string](& $get 'HoldKind')) -Escalated:($hold -eq 'escalated')
                } else {
                try { $cause = Get-SIReportCause -State $state -Text $why } catch { $cause = $null }
                if ($null -eq $cause -or (Get-SIUplinkCausesState).CauseClasses -notcontains [string]$cause.CauseClass) { $cause = [pscustomobject]@{ CauseClass = 'query-defect'; MissingName = ''; Known = $false } }
                # a COMPLETE report with more rows than the source counted (nothing is missing) is not a report problem at
                # all: it is never put in Reports -- Invardia made even an Action = none item a fix request (telemetry
                # si-ra-0201). It stays visible as a note (Get-SIUplinkReportNotes: the run's own log and run record).
                if ($state -eq 'Complete' -and [string]$cause.CauseClass -eq 'count-more') { continue }
                $code = Resolve-SIReportCauseCode -Cause $cause
                }
                if ($code -notmatch (Get-SIUplinkCausesState).CodePattern) { $code = (Get-SIUplinkCausesState).UnknownCode }
                $act = Get-SIUplinkCatalogueAction -Entry $byCode[$code] -Version $Version
                $qh =ConvertTo-SIUplinkId ([string](& $get 'QueryHash')) -Max 16
                $lgq = ConvertTo-SIUplinkId ([string](& $get 'LastGoodQueryHash')) -Max 16
                $ret = & $get 'Retries'
                $rv = [ordered]@{ '429' = 0L; '502' = 0L; '504' = 0L }
                if ($ret) { foreach ($k in @('429', '502', '504')) { $x = $null; if ($ret -is [System.Collections.IDictionary]) { if ($ret.Contains($k)) { $x = $ret[$k] } } elseif ($ret.PSObject.Properties[$k]) { $x = $ret.$k }; $n = ConvertTo-SIUplinkNumber $x; if ($null -ne $n) { $rv[$k] = $n } } }
                $st = & $get 'StartedUtc'; $stText = $null
                if ($st) { try { $stText = ([datetime]$st).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } catch { $stText = $null } }
                $bk = ConvertTo-SIUplinkId ([string](& $get 'Bucket'))
                $it = [ordered]@{
                    Report         = $rid
                    Code           = $code
                    CauseClass     = [string]$cause.CauseClass
                    MissingName    = $(if ($cause.MissingName) { [string]$cause.MissingName } else { $null })
                    MissingLicence = $null
                    Bucket         = $(if ($bk) { $bk } else { $null })
                    FixedIn        = $act.FixedIn
                    Action         = $act.Action
                    RunMs          = (ConvertTo-SIUplinkNumber (& $get 'RunMs'))
                    Rows           = (ConvertTo-SIUplinkNumber (& $get 'Rows'))
                    LastGoodRunMs  = (ConvertTo-SIUplinkNumber (& $get 'LastGoodRunMs'))
                    LastGoodRows   = (ConvertTo-SIUplinkNumber (& $get 'LastGoodRows'))
                    SourceCount    = (ConvertTo-SIUplinkNumber (& $get 'SourceCount'))
                    Buckets        = (ConvertTo-SIUplinkNumber (& $get 'Buckets'))
                    Retries        = [pscustomobject]$rv
                    QueryHash      = $(if ($qh) { $qh } else { $null })
                    QueryChanged   = $(if ($qh -and $lgq) { [bool]($qh -ne $lgq) } else { $null })
                    Region         = $(if ($reg) { $reg } else { $null })
                    StartedUtc     = $stText
                }
                if ($hold -and $HoldFields) {
                    # #902: the hold contract's three fields (names in $script:SIUplinkCauses, one place)
                    $it[[string](Get-SIUplinkCausesState).HoldFieldHeld] = $true
                    $it[[string](Get-SIUplinkCausesState).HoldFieldAge] = (ConvertTo-SIUplinkNumber (& $get 'KeptAgeHours'))
                    $hr = ConvertTo-SIUplinkNumber (& $get 'HeldRuns'); if ($null -eq $hr -or $hr -lt 1) { $hr = 1L }
                    $it[[string](Get-SIUplinkCausesState).HoldFieldRuns] = $hr
                }
                # #709: the cause in plain words FIRST ("<report>, <step>: <why>."), then the engine's own first error line
                if ($Identified) {
                    if ($hold) { $it.Detail = Join-SIUplinkCauseDetail -Sentence (Get-SIHoldCauseSentence -Fact $f) -Raw '' } else { $it.Detail = Join-SIUplinkCauseDetail -Sentence (Get-SIReportCauseSentence -Fact $f -Cause $cause) -Raw (ConvertTo-SIUplinkDetail $why) }
                }
                $seen[$rid] = $true
                # #902: an information hold sorts after every real failure (it never pushes a real item out of the 20)
                $failed = [int]($state -in @('Failed', 'NotComplete')); if ($hold -eq 'info') { $failed = 0 }
                $items.Add([pscustomobject]@{ Sev = [int](Get-SIUplinkCausesState).Severity[[string]$cause.CauseClass]; Failed = $failed; Item = [pscustomobject]$it })
            } catch { continue }
        }
        # most severe first (a failure before a not-applicable report), then the report id -- the same order every run
        $sorted = @($items | Sort-Object -Property @{ Expression = { $_.Failed }; Descending = $true }, @{ Expression = { $_.Sev } }, @{ Expression = { $_.Item.Report } })
        $out = @($sorted | Select-Object -First (Get-SIUplinkCausesState).MaxReports | ForEach-Object { $_.Item })
        return $out
    } catch { return @() }
}

function ConvertTo-SIUplinkFailureItem {
    <#
        PURE. SUP-2026-00198 (2026-10-19): ONE Reports[] item for a failure OUTSIDE a Risk Analysis report -- the updater's
        roll / restore -- whose catalogue code the caller KNOWS (-Code, e.g. si-upd-0803). The item has the shape of a report
        item (ConvertTo-SIUplinkReports): Report = '<job>-<step>' (an id, e.g. updater-roll), Code, CauseClass and
        FixedIn / Action from the catalogue entry, the context numbers null (not known, never guessed), Detail (-Text,
        scrubbed, at most 500) on an IDENTIFIED record only. @() for a code that is not in the catalogue -- an item never
        carries a code Invardia cannot look up. NEVER throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Code, [AllowEmptyString()][string]$Job = 'updater', [AllowEmptyString()][string]$Step = '',
          [AllowEmptyString()][string]$Text = '', [switch]$Identified, [AllowEmptyString()][string]$Version, [AllowEmptyString()][string]$Region,
          [AllowNull()][object[]]$Catalogue)
    try {
        $c = "$Code".Trim().ToLowerInvariant()
        if ($c -notmatch (Get-SIUplinkCausesState).CodePattern) { return @() }
        $cat = if ($PSBoundParameters.ContainsKey('Catalogue')) { @($Catalogue) } else { @(Get-SIErrorCatalogue) }
        $e = @($cat | Where-Object { $_ -and "$($_.code)".Trim().ToLowerInvariant() -eq $c })[0]
        if (-not $e -or (Get-SIUplinkCausesState).CauseClasses -notcontains [string]$e.causeClass) { return @() }
        $act = Get-SIUplinkCatalogueAction -Entry $e -Version $Version
        $rid = ConvertTo-SIUplinkId ((@("$Job".Trim(), "$Step".Trim()) | Where-Object { $_ }) -join '-')
        if (-not $rid) { $rid = 'updater' }
        $reg = ConvertTo-SIUplinkId $Region
        $it = [ordered]@{
            Report = $rid; Code = $c; CauseClass = [string]$e.causeClass; MissingName = $null; MissingLicence = $null; Bucket = $null
            FixedIn = $act.FixedIn; Action = $act.Action; RunMs = $null; Rows = $null; LastGoodRunMs = $null; LastGoodRows = $null
            SourceCount = $null; Buckets = $null; Retries = [pscustomobject][ordered]@{ '429' = 0L; '502' = 0L; '504' = 0L }
            QueryHash = $null; QueryChanged = $null; Region = $(if ($reg) { $reg } else { $null }); StartedUtc = $null
        }
        if ($Identified) { $d = ConvertTo-SIUplinkDetail $Text; if ($d) { $it.Detail = $d } }
        [pscustomobject]$it
    } catch { @() }
}

function Get-SIReportCauseFacts {
    <#
        PURE. The facts of every report of a Risk Analysis run that FAILED, is NOT COMPLETE, did NOT APPLY or DEVIATED (more
        rows than the source's count) -- what ConvertTo-SIUplinkReports maps. From what the run already keeps:
          -Notes       report -> @{ StartedUtc; EndedUtc; State (NotApplicable | Complete | NotComplete | Unverified); Why; Rows;
                       SourceCount; Buckets; QueryHash }   (Risk Analysis' $script:RAReportNotes)
          -Failures    @{ Report; Why } -- Add-RAReportFailure's list
          -Incomplete  @{ Report; Why } -- the row-count guard's reports
          -Done        report -> the verdict (Complete | NotComplete | Unverified)
          -Retries     report -> @{ '429'; '502'; '504' } (Add-SIReportRetryAnswer)
          -LastGood    report -> @{ Rows; QueryHash } (the report's last complete run, Read-RAStreamLastGood)
        Returns a list of objects; a report that ran clean is not in it. Never throws.
    #>
    param([System.Collections.IDictionary]$Notes, [AllowNull()][object[]]$Failures, [AllowNull()][object[]]$Incomplete,
          [System.Collections.IDictionary]$Done, [System.Collections.IDictionary]$Retries, [System.Collections.IDictionary]$LastGood)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $why = { param($list, $n) @(@($list) | Where-Object { $_ -and [string]$_.Report -eq $n } | ForEach-Object { [string]$_.Why }) | Select-Object -First 1 }
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($n in @(@($Failures) + @($Incomplete) | Where-Object { $_ } | ForEach-Object { [string]$_.Report })) { if ($n -and -not $names.Contains($n)) { $names.Add($n) } }
        if ($Notes) { foreach ($n in @($Notes.Keys)) { if (-not $names.Contains([string]$n)) { $names.Add([string]$n) } } }
        foreach ($n in $names) {
            $note = if ($Notes -and $Notes.Contains($n)) { $Notes[$n] } else { $null }
            $nv = { param($k) if ($null -eq $note) { $null } elseif ($note -is [System.Collections.IDictionary]) { if ($note.Contains($k)) { $note[$k] } else { $null } } elseif ($note.PSObject.Properties[$k]) { $note.$k } else { $null } }
            $state = ''; $text = ''
            $fw = & $why $Failures $n; $iw = & $why $Incomplete $n
            $verdict = if ($Done -and $Done.Contains($n)) { [string]$Done[$n] } else { '' }
            if ($fw) { $state = $(if ($verdict -eq 'NotComplete' -and $fw -match '^not complete: ') { 'NotComplete' } else { 'Failed' }); $text = $fw }
            elseif ($iw) { $state = 'NotComplete'; $text = $iw }
            elseif ([string](& $nv 'State') -eq 'NotApplicable') { $state = 'NotApplicable'; $text = [string](& $nv 'Why') }
            # #814: more rows than the source's count on a COMPLETE report keeps its verdict -- nothing is missing, so it is a
            # note (Get-SIUplinkReportNotes), never a report item. Labelled Deviated for every report, a Complete Summary's
            # count-more reached Invardia as si-ra-0201 with Action = support (fix request e394f927, rc13 and later).
            elseif ([string](& $nv 'Why') -match '(?i)more than the source''s count') {
                $state = $(if ([string](& $nv 'State') -eq 'Complete' -or $verdict -eq 'Complete') { 'Complete' } else { 'Deviated' }); $text = [string](& $nv 'Why')
            }
            else { continue }
            $runMs = $null
            try { $s = & $nv 'StartedUtc'; $e = & $nv 'EndedUtc'; if ($s -and $e) { $runMs = [long][Math]::Max(0, (([datetime]$e) - ([datetime]$s)).TotalMilliseconds) } } catch { $runMs = $null }
            $lg = if ($LastGood -and $LastGood.Contains($n)) { $LastGood[$n] } else { $null }
            $out.Add([pscustomobject]@{
                Report = $n; State = $state; Why = $text; StartedUtc = (& $nv 'StartedUtc'); RunMs = $runMs
                Rows = (& $nv 'Rows'); SourceCount = (& $nv 'SourceCount'); Buckets = (& $nv 'Buckets'); QueryHash = [string](& $nv 'QueryHash')
                Retries = $(if ($Retries -and $Retries.Contains($n)) { $Retries[$n] } else { $null })
                LastGoodRows = $(if ($lg) { $lg.Rows } else { $null }); LastGoodRunMs = $null
                LastGoodQueryHash = $(if ($lg) { [string]$lg.QueryHash } else { '' })
            })
        }
    } catch { }
    $out.ToArray()
}

# =====================================================================================================================
#  #709 -- THE CAUSE IN PLAIN WORDS: which report, which step, and why
# =====================================================================================================================
# A class ("kql-query-defect", "report-incomplete") took a session reading logs to explain. Each failed / not complete /
# not applicable report gets ONE short sentence built from what the engine already wrote (the reason Risk Analysis keeps in
# sidata.RaReportStatus, the error of a failed query, the retries it counted): "<report>, <step>: <why>". The numbers in
# it are the report's own (rows, sizes, retries) -- never a secret, never a ticket number. It travels on the fields
# Invardia already takes: the item's Detail (identified installs; first, before the engine's own first error line) and the
# run record's ErrorMessage of a run with reports that are not complete (identified). Anonymous installs send no text.

function Get-SIReportCauseStep {
    <# PURE. The step of the report the text is about, in plain words. #>
    param([AllowEmptyString()][AllowNull()][string]$State, [AllowEmptyString()][AllowNull()][string]$Text, [AllowEmptyString()][AllowNull()][string]$CauseClass)
    $t = [string]$Text
    if ($CauseClass -eq 'settings-unreachable') { return 'reading its settings' }
    if ($CauseClass -eq 'out-of-memory') { return 'holding its rows in memory' }
    if ($t -match '(?i)^\s*its query could not be sent') { return 'sending its query to Microsoft Defender' }
    if ($t -match '(?i)lookup (this report needs|it needs) could not be read|^\s*it was not run: a lookup') { return 'reading a lookup it needs' }
    if ($t -match '(?i)^\s*it was not run|it is not in this run|not in this worker''s template') { return 'starting the report' }
    if ($t -match '(?i)could not collect it from its worker') { return 'collecting it from its worker' }
    if ($t -match '(?i)^\s*its result could not be read') { return 'reading its result' }
    if ($t -match '(?i)neither stored nor accounted for|\bstored \d+') { return 'storing its rows' }
    if ($t -match '(?i)quer(y|ies) slice\(s\)|slice\(s\) of the report could not be read|bucket\(s\) could not be read') { return 'reading the parts of its query' }
    if ($t -match '(?i)the source holds \d+ row\(s\)|more than the source''s count|count the report''s rows') { return 'checking its rows against the source' }
    if ($CauseClass -in @('count-less', 'count-more')) { return 'checking its rows against the source' }
    if ($t -match '(?i)^\s*its query failed') { return 'running its query' }
    if ("$State" -eq 'NotApplicable' -or $CauseClass -in @('no-data-source', 'missing-licence')) { return 'checking its data source' }
    if ($CauseClass -in @('platform-timeout', 'too-large', 'query-defect', 'missing-column', 'permission')) { return 'running its query' }
    'running the report'
}

function Get-SIReportCauseWhy {
    <# PURE. Why, in plain words, from the cause and the engine's own text (its numbers kept). Never '' -- a text no rule
       reads says that the cause was not recognised. #>
    param([AllowEmptyString()][AllowNull()][string]$State, [AllowEmptyString()][AllowNull()][string]$Text, $Cause, $Retries)
    $t = [string]$Text
    $cc = if ($Cause) { [string]$Cause.CauseClass } else { '' }
    $mn = if ($Cause) { [string]$Cause.MissingName } else { '' }
    $rv = @{ '429' = 0L; '502' = 0L; '504' = 0L }
    if ($Retries) { foreach ($k in @('429', '502', '504')) { $x = $null; if ($Retries -is [System.Collections.IDictionary]) { if ($Retries.Contains($k)) { $x = $Retries[$k] } } elseif ($Retries.PSObject.Properties[$k]) { $x = $Retries.$k }; $n = ConvertTo-SIUplinkNumber $x; if ($null -ne $n) { $rv[$k] = $n } } }
    $times = { param($n) if ([long]$n -eq 1) { 'once' } else { '{0} times' -f $n } }
    # ---- too large: the lookup that has to travel whole, against what one Defender query carries ----------------------------
    if ($t -match '(?i)the lookups? (?<names>.+?) (is|are) needed whole in every part of the query') {
        $first = [regex]::Match($Matches['names'], '(?<n>[A-Za-z_][A-Za-z0-9_]*) \((?<r>[\d,\.]+) rows, (?<s>[\d\.]+ (MB|KB|bytes))\)')
        $cap = [regex]::Match($t, '(?i)can carry \((?<c>[\d\.]+ (MB|KB|bytes))\)')
        $qs = [regex]::Match($t, '(?i)that is (?<q>[\d\.]+ (MB|KB|bytes)) in every part')
        $s = if ($first.Success) { 'the lookup {0} is {1}' -f $first.Groups['n'].Value, $first.Groups['s'].Value } else { 'a lookup has to travel whole in every part of the query' }
        if ($qs.Success) { $s += (' (the query {0} in every part)' -f $qs.Groups['q'].Value) }
        if ($cap.Success) { $s += (', over the {0} one Microsoft Defender query can carry -- more parts cannot make it fit' -f $cap.Groups['c'].Value) }
        else { $s += ', more than one Microsoft Defender query can carry' }
        return $s
    }
    if ($t -match '(?i)lookup (this report needs|it needs) could not be read') {
        $why = [regex]::Match($t, '(?i)could not be read(?: from Log Analytics)?\s*(\([^)]*\))?\s*--\s*(?<w>[^|]{1,160})')
        if ($why.Success) { $w = ConvertTo-SIUplinkDetail ($why.Groups['w'].Value.Trim().TrimEnd('.')); if ($w) { return ('a lookup it needs could not be read -- {0}' -f $w) } }
        return 'a lookup it needs could not be read'
    }
    # ---- the count against the source / storage (the reasons Risk Analysis keeps in sidata.RaReportStatus) ----------------
    $m = [regex]::Match($t, '(?i)the source holds (?<e>\d+) row\(s\)[^|]*?retrieved (?<r>\d+)')
    if ($m.Success) { return ('the source holds {0} rows, the run retrieved {1}' -f $m.Groups['e'].Value, $m.Groups['r'].Value) }
    $m = [regex]::Match($t, '(?i)retrieved (?<r>\d+) row\(s\), more than the source''s count of (?<e>\d+)')
    if ($m.Success) { return ('the run retrieved {0} rows, more than the source''s count of {1} -- nothing is missing' -f $m.Groups['r'].Value, $m.Groups['e'].Value) }
    $m = [regex]::Match($t, '(?i)retrieved (?<r>\d+) row\(s\) and stored (?<s>\d+): (?<l>\d+) row\(s\)')
    if ($m.Success) { return ('{0} rows were retrieved and {1} stored -- {2} are neither stored nor accounted for' -f $m.Groups['r'].Value, $m.Groups['s'].Value, $m.Groups['l'].Value) }
    $m = [regex]::Match($t, '(?i)(?<n>\d+) query slice\(s\) of the report could not be read')
    if ($m.Success) { return ('{0} part(s) of its query could not be read -- their rows are unknown, not resolved' -f $m.Groups['n'].Value) }
    if ($t -match '(?i)far fewer findings') { return 'it returned far fewer findings than its last run' }
    if ($t -match '(?i)could not collect it from its worker') { return 'its worker did not hand its result back' }
    if ($t -match '(?i)it is not in this run|not in this worker''s template') { return 'it is not in this run' }
    switch ($cc) {
        'settings-unreachable' { return 'the settings database could not be reached' }
        'out-of-memory'        { return 'Risk Analysis ran out of memory' }
        'permission'           { return 'the run''s identity was refused access -- a permission is missing' }
        'missing-licence'      {
            if ($mn -like 'devicetvm*') { return ('the tenant has no Defender vulnerability management (the table {0} is not there)' -f $mn) }
            return 'a licence this report needs is not in the tenant'
        }
        'no-data-source'       {
            if ($mn -eq 'defender-xdr') { return 'advanced hunting (Microsoft Defender XDR) is not set up in this tenant' }
            if ($mn) { return ('the data source {0} is not in this tenant' -f $mn) }
            return 'the data source it reads is not in this tenant'
        }
        'missing-column'       { if ($mn) { return ('the column {0} is not there -- its source is not set up at this install' -f $mn) }; return 'a column it reads is not there' }
        'platform-timeout'     {
            $parts = @()
            if ($rv['504'] -gt 0) { $parts += ('Microsoft Defender timed out {0}' -f (& $times $rv['504'])) }
            if ($rv['429'] -gt 0) { $parts += ('it was throttled {0}' -f (& $times $rv['429'])) }
            if ($rv['502'] -gt 0) { $parts += ('the gateway refused it {0}' -f (& $times $rv['502'])) }
            if ($parts.Count) { return ($parts -join ', ') }
            return 'the platform did not answer in time'
        }
        'too-large'            {
            if ($mn -eq 'query-body') { return 'the query is larger than Microsoft Defender accepts' }
            if ($rv['502'] -gt 0) { return ('the answer was too large for one Microsoft Defender query (refused {0})' -f (& $times $rv['502'])) }
            return 'the answer was too large for one query'
        }
        'query-defect'         {
            $at = [regex]::Match($t, "(?i)could not be parsed at '(?<tok>[^']{1,40})' on line \[(?<l>\d+),\s*(?<c>\d+)\]")
            if ($at.Success) { return ('the query has a syntax error at ''{0}'' (line {1}, position {2})' -f $at.Groups['tok'].Value, $at.Groups['l'].Value, $at.Groups['c'].Value) }
            if ($mn -eq 'syn0002' -or $t -match '(?i)\bSYN0002\b|syntax error') { return 'the query has a syntax error' }
            if ($Cause -and $Cause.PSObject.Properties['Known'] -and -not $Cause.Known) { return 'the cause was not recognised -- the run''s log has the error' }
            return 'the query failed'
        }
    }
    if ($cc -eq 'count-less') { return 'fewer rows were stored than the source holds' }
    if ($cc -eq 'count-more') { return 'more rows than the source''s count -- nothing is missing' }
    if ("$State" -eq 'NotApplicable') { return 'it does not apply at this install' }
    'the cause was not recognised -- the run''s log has the error'
}

function Get-SIReportCauseSentence {
    <#
        PURE. "<report>, <step>: <why>." -- one short sentence a person can act on, from a report fact (Report, State, Why,
        Retries). -Cause: Get-SIReportCause's answer when the caller has it. At most 300 characters. Never throws ('' only for
        a fact with no report).
    #>
    param([AllowNull()]$Fact, $Cause)
    try {
        if ($null -eq $Fact) { return '' }
        $get = { param($n) if ($Fact -is [System.Collections.IDictionary]) { if ($Fact.Contains($n)) { $Fact[$n] } else { $null } } elseif ($Fact.PSObject.Properties[$n]) { $Fact.$n } else { $null } }
        # the report's uplink id (the one Reports[] already carries) -- never its display name (#641: no report name leaves
        # the install)
        $rep = ConvertTo-SIUplinkId ([string](& $get 'Report'))
        if (-not $rep) { return '' }
        $state = [string](& $get 'State'); $text = [string](& $get 'Why')
        # the reason Risk Analysis kept starts "not complete: <reason>" -- the reason is what explains it
        $plain = ($text -replace '(?i)^\s*not complete:\s*', '')
        if ($null -eq $Cause) { try { $Cause = Get-SIReportCause -State $state -Text $text } catch { $Cause = $null } }
        $cc = if ($Cause) { [string]$Cause.CauseClass } else { '' }
        $step = Get-SIReportCauseStep -State $state -Text $plain -CauseClass $cc
        $why = Get-SIReportCauseWhy -State $state -Text $plain -Cause $Cause -Retries (& $get 'Retries')
        $s = ('{0}, {1}: {2}.' -f $rep, $step, $why) -replace '\.\.$', '.'
        if ($s.Length -gt 300) { $s = $s.Substring(0, 297).TrimEnd() + '...' }
        # built from SecurityInsight's own words, the report's numbers and names -- still never sent when it looks like a secret
        if (Test-SIUplinkLooksSecret $s) { return '' }
        return $s
    } catch { return '' }
}

function Join-SIUplinkCauseDetail {
    <# PURE. An item's Detail: the plain sentence, then " | " and the engine's own first error line (already scrubbed), at
       most 500 characters; $null when there is neither. #>
    param([AllowNull()][AllowEmptyString()][string]$Sentence, [AllowNull()][AllowEmptyString()][string]$Raw)
    $s = "$Sentence".Trim(); $r = "$Raw".Trim()
    $d = if ($s -and $r) { '{0} | {1}' -f $s, $r } elseif ($s) { $s } elseif ($r) { $r } else { '' }
    if (-not $d) { return $null }
    if ($d.Length -gt (Get-SIUplinkCausesState).DetailMax) { $d = $d.Substring(0, (Get-SIUplinkCausesState).DetailMax) }
    $d
}

function Get-SIUplinkReportNotes {
    <#
        PURE. The reports of a run that are COMPLETE but returned more rows than the source counted -- information, never a
        failure (ConvertTo-SIUplinkReports leaves them out). Each @{ Report; Rows; SourceCount; Note }. Never throws.
    #>
    param([AllowNull()][object[]]$Facts)
    try {
        foreach ($f in @($Facts | Where-Object { $_ })) {
            $get = { param($n) if ($f -is [System.Collections.IDictionary]) { if ($f.Contains($n)) { $f[$n] } else { $null } } elseif ($f.PSObject.Properties[$n]) { $f.$n } else { $null } }
            $st = [string](& $get 'State'); if ($st -ne 'Complete') { continue }
            $c = $null; try { $c = Get-SIReportCause -State $st -Text ([string](& $get 'Why')) } catch { $c = $null }
            if (-not $c -or [string]$c.CauseClass -ne 'count-more') { continue }
            [pscustomobject][ordered]@{ Report = [string](& $get 'Report'); Rows = (ConvertTo-SIUplinkNumber (& $get 'Rows')); SourceCount = (ConvertTo-SIUplinkNumber (& $get 'SourceCount'))
                                        Note = 'complete -- more rows than the source counted, nothing is missing (no action)' }
        }
    } catch { }
}

function Get-SIHoldCauseSentence {
    <# PURE. #902: a report held ON PURPOSE in plain words -- "<report>, held at its last complete result for <n> run(s) in a
       row: <why>." At most 300 characters; '' when it would look like a secret or the fact has no report. #>
    param([AllowNull()]$Fact)
    try {
        $rid = ConvertTo-SIUplinkId ([string](Get-SIUplinkFactValue $Fact 'Report'))
        if (-not $rid) { return '' }
        $n = ConvertTo-SIUplinkNumber (Get-SIUplinkFactValue $Fact 'HeldRuns'); if ($null -eq $n -or $n -lt 1) { $n = 1L }
        $why = (([string](Get-SIUplinkFactValue $Fact 'Why')) -replace '(?i)^\s*not complete:\s*', '').Trim().TrimEnd('.')
        $s = ('{0}, held at its last complete result for {1} run(s) in a row: {2}.' -f $rid, $n, $why)
        if ($s.Length -gt 300) { $s = $s.Substring(0, 297).TrimEnd() + '...' }
        if (Test-SIUplinkLooksSecret $s) { return '' }
        $s
    } catch { '' }
}

function Get-SIReportCauseHeadline {
    <# PURE. The sentence of the most severe report that FAILED or is NOT COMPLETE (ConvertTo-SIUplinkReports' order), for
       the run record's message. '' when there is none. #902: a report held ON PURPOSE that is information only is never
       the headline; an escalated hold is, as a held report (held-too-long). #>
    param([AllowNull()][object[]]$Facts)
    try {
        $best = $null; $bestSev = [int]::MaxValue
        foreach ($f in @($Facts | Where-Object { $_ })) {
            $st = [string]$(if ($f -is [System.Collections.IDictionary]) { $f['State'] } else { $f.State })
            if ($st -notin @('Failed', 'NotComplete')) { continue }
            $hold = Test-SIUplinkFactHeld -Fact $f
            if ($hold -eq 'info') { continue }
            if ($hold -eq 'escalated') {
                $sevH = [int](Get-SIUplinkCausesState).Severity[[string](Get-SIUplinkCausesState).HoldClassEscalated]
                if ($sevH -lt $bestSev) { $best = @{ F = $f; C = $null; H = $true }; $bestSev = $sevH }
                continue
            }
            $wt = [string]$(if ($f -is [System.Collections.IDictionary]) { $f['Why'] } else { $f.Why })
            $c = $null; try { $c = Get-SIReportCause -State $st -Text $wt } catch { $c = $null }
            $sev = if ($c -and (Get-SIUplinkCausesState).Severity.ContainsKey([string]$c.CauseClass)) { [int](Get-SIUplinkCausesState).Severity[[string]$c.CauseClass] } else { 99 }
            if ($sev -lt $bestSev) { $best = @{ F = $f; C = $c }; $bestSev = $sev }
        }
        if ($null -eq $best) { return '' }
        if ($best.H) { return (Get-SIHoldCauseSentence -Fact $best.F) }
        Get-SIReportCauseSentence -Fact $best.F -Cause $best.C
    } catch { '' }
}

function Get-SIReportStatusReasonsSql {
    <# The reasons Risk Analysis kept for the reports of ONE collection and grain that are NOT COMPLETE (sidata.RaReportStatus). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RaReportStatus') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS NVARCHAR(2000)) AS Reason WHERE 1 = 0; RETURN; END
DECLARE @t datetime2(3) = CONVERT(datetime2(3), @CollectionTime, 126);
SELECT ReportName, Reason FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = @Grain AND State = N'NotComplete' AND NULLIF(Reason, N'') IS NOT NULL;
'@
}

function Add-SIReportCauseStoredReasons {
    <#
        PURE. The run's report facts, completed with the NotComplete reasons kept in sidata.RaReportStatus (-Stored: rows of
        ReportName + Reason): a fact without a reason takes the stored one; a report the database holds as NOT COMPLETE that
        has no fact in this process (a queue worker's report) is added as NotComplete with its reason. Never throws.
    #>
    param([AllowNull()][object[]]$Facts, [AllowNull()][object[]]$Stored)
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $byName = @{}
        foreach ($r in @($Stored | Where-Object { $_ })) {
            $n = [string]$(if ($r -is [System.Collections.IDictionary]) { $r['ReportName'] } else { $r.ReportName }); $w = [string]$(if ($r -is [System.Collections.IDictionary]) { $r['Reason'] } else { $r.Reason })
            if ($n -and $w -and -not $byName.ContainsKey($n)) { $byName[$n] = $w }
        }
        $seen = @{}
        foreach ($f in @($Facts | Where-Object { $_ })) {
            $n = [string]$f.Report; $seen[$n] = $true
            if (-not "$($f.Why)".Trim() -and $byName.ContainsKey($n)) { $f.Why = $byName[$n]; if (-not "$($f.State)".Trim()) { $f.State = 'NotComplete' } }
            $out.Add($f)
        }
        foreach ($n in @($byName.Keys | Sort-Object)) {
            if ($seen.ContainsKey($n)) { continue }
            $out.Add([pscustomobject]@{ Report = $n; State = 'NotComplete'; Why = $byName[$n]; StartedUtc = $null; RunMs = $null; Rows = $null; SourceCount = $null; Buckets = $null
                                        QueryHash = ''; Retries = $null; LastGoodRows = $null; LastGoodRunMs = $null; LastGoodQueryHash = '' })
        }
    } catch { return @($Facts) }
    $out.ToArray()
}

function Add-SIReportRetryAnswer {
    <# Counts one platform answer (429 / 502 / 504) for the report that is running ($global:SI_UplinkCurrentReport) --
       Risk Analysis' hunting call reports each failed attempt here. Never throws. #>
    param([AllowNull()][AllowEmptyString()][string]$Message, [string]$Report = [string]$global:SI_UplinkCurrentReport)
    try {
        if (-not "$Report".Trim() -or -not "$Message".Trim()) { return }
        $k = if ($Message -match '(?i)\b429\b|Too ?Many ?Requests|throttl') { '429' } elseif ($Message -match '(?i)\b502\b|Bad Gateway') { '502' } elseif ($Message -match '(?i)\b504\b|Gateway Time-?out|TaskCanceledException|A task was canceled|timed? ?out') { '504' } else { '' }
        if (-not $k) { return }
        if ($null -eq $global:SI_UplinkRetryAnswers -or $global:SI_UplinkRetryAnswers -isnot [hashtable]) { $global:SI_UplinkRetryAnswers = @{} }
        if (-not $global:SI_UplinkRetryAnswers.ContainsKey($Report)) { $global:SI_UplinkRetryAnswers[$Report] = @{ '429' = 0L; '502' = 0L; '504' = 0L } }
        $global:SI_UplinkRetryAnswers[$Report][$k] = [long]$global:SI_UplinkRetryAnswers[$Report][$k] + 1
    } catch { }
}

function Get-SIUplinkRegion {
    <# The install's Azure region: SI_Location, else the container's SI_CFG_SI_Location / SI_LOCATION. '' = not known. #>
    param([scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    foreach ($v in @([string]$global:SI_Location, [string](& $GetEnv 'SI_CFG_SI_Location'), [string](& $GetEnv 'SI_LOCATION'))) { if ("$v".Trim()) { return (ConvertTo-SIUplinkId $v) } }
    ''
}

function Limit-SIUplinkRecordSize {
    <#
        The uplink's body limit is 16 KB. A record whose Reports make it larger is cut down -- never refused, never dropped:
        the Details are shortened to 200 characters, then left out, then the least severe items are left out (the list is
        already most severe first). Works on the record in place and returns it. Never throws.
    #>
    param([Parameter(Mandatory)]$Record, [int]$MaxBytes = 15000)
    try {
        if (-not $Record.PSObject.Properties['Reports']) { return $Record }
        $size = { [System.Text.Encoding]::UTF8.GetByteCount(($Record | ConvertTo-Json -Depth 8 -Compress)) }
        if ((& $size) -le $MaxBytes) { return $Record }
        foreach ($i in @($Record.Reports)) { if ($i.PSObject.Properties['Detail'] -and "$($i.Detail)".Length -gt 200) { $i.Detail = "$($i.Detail)".Substring(0, 200) } }
        if ((& $size) -le $MaxBytes) { return $Record }
        foreach ($i in @($Record.Reports)) { if ($i.PSObject.Properties['Detail']) { $i.PSObject.Properties.Remove('Detail') } }
        $list = New-Object System.Collections.Generic.List[object]; foreach ($i in @($Record.Reports)) { $list.Add($i) }
        while ($list.Count -gt 0 -and (& $size) -gt $MaxBytes) { $list.RemoveAt($list.Count - 1); $Record.Reports = @($list.ToArray()) }
        if ($list.Count -eq 0) { $Record.PSObject.Properties.Remove('Reports') }
    } catch { try { $Record.PSObject.Properties.Remove('Reports') } catch { } }
    $Record
}

# =====================================================================================================================
#  The capability probe (heartbeat): Capabilities, CiColumns, Licences
# =====================================================================================================================
function Get-SICapabilityProbeLaQuery {
    <# The ONE Log Analytics query of the probe: the CI table's columns, and whether Sentinel has incidents or alerts. #>
    @'
union isfuzzy=true
 (SI_CI_CL | getschema | project Kind = "col", Name = tolower(ColumnName)),
 (SecurityIncident | where TimeGenerated > ago(90d) | take 1 | project Kind = "sentinel", Name = ""),
 (SecurityAlert | where TimeGenerated > ago(90d) | take 1 | project Kind = "sentinel", Name = ""),
 (print Kind = "ok", Name = "")
| distinct Kind, Name
'@
}

function Get-SICapabilityProbeLaMayBeMissing {
    <# The tables of the probe's Log Analytics query a workspace may not have (2026-10-23: in a workspace without Sentinel
       the whole answer was refused as cut, so the status report left out the Sentinel, CMDB and CI-column details). #>
    @('SecurityIncident', 'SecurityAlert')
}

function Get-SICapabilityProbeHuntingQuery {
    <# The ONE advanced hunting query of the probe: Defender XDR, Defender vulnerability management, Defender for Identity,
       and whether SecurityInsight's own table is visible there (Sentinel data lake mirroring). #>
    @'
union isfuzzy=true
 (DeviceInfo | take 1 | project T = "xdr"),
 (DeviceTvmSoftwareVulnerabilities | take 1 | project T = "tvm"),
 (IdentityDirectoryEvents | take 1 | project T = "mdi"),
 (SI_CI_CL | take 1 | project T = "lake")
| distinct T
'@
}

function ConvertFrom-SICapabilityProbe {
    <#
        PURE. The probe's answers as the heartbeat's three fields. -LaRows (the LA query's rows, $null = not read), -HuntRows
        (the hunting query's rows, $null = not read), -HuntNotProvisioned (no Defender XDR at all), -Skus (Graph
        subscribedSkus .value, $null = not read). A key whose answer was not read is LEFT OUT.
        Returns @{ Capabilities (ordered); CiColumns (ids); Licences (ids) }.
    #>
    param([AllowNull()][object[]]$LaRows, [AllowNull()][object[]]$HuntRows, [switch]$HuntNotProvisioned, [AllowNull()][object[]]$Skus, [switch]$SkusRead)
    $cap = [ordered]@{}
    $ci = New-Object System.Collections.Generic.List[string]
    $lic = New-Object System.Collections.Generic.List[string]
    if ($null -ne $LaRows) {
        $okRow = @($LaRows | Where-Object { $_ -and [string]$_.Kind -eq 'ok' }).Count -gt 0
        if ($okRow) {
            $cols = @($LaRows | Where-Object { $_ -and [string]$_.Kind -eq 'col' } | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
            if ($cols.Count) {
                $opt = @($cols | Where-Object { $_ -match (Get-SIUplinkCausesState).OptionalCiColumnPattern } | Sort-Object -Unique)
                foreach ($c in ($opt | Select-Object -First (Get-SIUplinkCausesState).MaxCiColumns)) { $id = ConvertTo-SIUplinkId $c; if ($id) { $ci.Add($id) } }
                $cap['cmdb'] = [bool](@($opt | Where-Object { $_ -like 'si_cmdb_*' }).Count -gt 0)
            }
            $cap['sentinel'] = [bool](@($LaRows | Where-Object { $_ -and [string]$_.Kind -eq 'sentinel' }).Count -gt 0)
        }
    }
    if ($HuntNotProvisioned) { $cap['defenderXdr'] = $false; $cap['defenderVulnMgmt'] = $false; $cap['mdi'] = $false }
    elseif ($null -ne $HuntRows) {
        $ts = @($HuntRows | Where-Object { $_ } | ForEach-Object { [string]$_.T })
        $cap['defenderXdr'] = [bool]($ts -contains 'xdr'); $cap['defenderVulnMgmt'] = [bool]($ts -contains 'tvm'); $cap['mdi'] = [bool]($ts -contains 'mdi')
        $cap['dataLake'] = [bool]($ts -contains 'lake')
    }
    if ($SkusRead -and $null -ne $Skus) {
        $plans = @{}
        foreach ($s in @($Skus)) {
            if ($null -eq $s) { continue }
            $status = [string]$s.capabilityStatus
            if ($status -and $status -notin @('Enabled', 'Warning')) { continue }
            $id = ConvertTo-SIUplinkId ([string]$s.skuPartNumber)
            if ($id -and -not $lic.Contains($id) -and $lic.Count -lt (Get-SIUplinkCausesState).MaxLicences) { $lic.Add($id) }
            foreach ($p in @($s.servicePlans)) { if ($p -and [string]$p.servicePlanName) { $plans[[string]$p.servicePlanName] = $true } }
        }
        foreach ($pn in @((Get-SIUplinkCausesState).PlanCapabilities.Keys)) {
            $k = (Get-SIUplinkCausesState).PlanCapabilities[$pn]
            if ($k -eq 'defenderVulnMgmt') { continue }   # measured from the data itself (DeviceTvm*), the licence only adds to it
            $cap[$k] = [bool]($plans.ContainsKey($pn) -or ($cap.Contains($k) -and $cap[$k]))
        }
    }
    # the closed keys only, in the agreed order
    $closed = [ordered]@{}; foreach ($k in (Get-SIUplinkCausesState).CapabilityKeys) { if ($cap.Contains($k)) { $closed[$k] = [bool]$cap[$k] } }
    [pscustomobject]@{ Capabilities = $closed; CiColumns = @($ci.ToArray()); Licences = @($lic.ToArray()) }
}

function Get-SICapabilityProbe {
    <#
        THE PROBE, once per process ($global:SI_CapabilityProbe): one Log Analytics query, one advanced hunting query and --
        only when the run's identity may read them -- Graph subscribedSkus. -RunQuery { param($Kql) rows }, -RunHunting
        { param($Kql) rows }, -GraphGet { param($Uri) response } are the seams (defaults: SI-TelemetryCounts.ps1's readers and
        SI-GraphRest.ps1). A test session never reads anything without a seam. Licences that cannot be read (no permission,
        no Graph sign-in) are left out and said in ONE Write-Diag line; no permission is ever added for them. Never throws.
    #>
    param([scriptblock]$RunQuery, [scriptblock]$RunHunting, [scriptblock]$GraphGet, [switch]$Refresh)
    if (-not $Refresh -and -not ($RunQuery -or $RunHunting -or $GraphGet) -and $null -ne $global:SI_CapabilityProbe) { return $global:SI_CapabilityProbe }
    $test = [bool](Get-Module -Name Pester)
    $la = $null; $hunt = $null; $notProv = $false; $skus = $null; $skusRead = $false
    try {
        if (-not $RunQuery -and -not $test -and (Get-Command -Name Invoke-SITelemetryLaQuery -ErrorAction SilentlyContinue)) { $RunQuery = { param($Kql) Invoke-SITelemetryLaQuery -Query $Kql -MayBeMissing @(Get-SICapabilityProbeLaMayBeMissing) } }
        if ($RunQuery) { try { $la = & $RunQuery (Get-SICapabilityProbeLaQuery); if ($null -ne $la) { $la = @($la) } } catch { $la = $null; Write-SIUplinkDiag ("capability probe: the workspace could not be read ({0})" -f $_.Exception.Message) } }
    } catch { $la = $null }
    try {
        if (-not $RunHunting -and -not $test -and (Get-Command -Name Invoke-SITelemetryHuntingQuery -ErrorAction SilentlyContinue)) { $RunHunting = { param($Kql) Invoke-SITelemetryHuntingQuery -Query $Kql } }
        if ($RunHunting) {
            try { $hunt = @(& $RunHunting (Get-SICapabilityProbeHuntingQuery)) }
            catch {
                $hunt = $null
                if ("$($_.Exception.Message)" -match 'Account is not provisioned') { $notProv = $true }
                else { Write-SIUplinkDiag ("capability probe: advanced hunting could not be read ({0})" -f $_.Exception.Message) }
            }
        }
    } catch { $hunt = $null }
    try {
        if (-not $GraphGet -and -not $test -and (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) -and (Get-Command -Name Invoke-SIGraphRest -ErrorAction SilentlyContinue)) {
            $GraphGet = { param($Uri) $tok = Get-SIGraphToken -Resource Graph; Invoke-SIGraphRest -Uri $Uri -Token $tok -TimeoutSec 30 -MaxAttempts 1 }
        }
        if ($GraphGet) {
            # Directory.Read.All (config\permissions.locked.json, collection identity) covers GET /subscribedSkus; an identity
            # that was not granted it answers 403 -- then there are no Licences, said once, and nothing is granted
            try { $resp = & $GraphGet '/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans'; $skus = @(if ($resp -and $resp.PSObject.Properties['value']) { $resp.value } else { $resp }); $skusRead = $true }
            catch { $skus = $null; Write-SIUplinkDiag ("capability probe: no Licences in the status report -- the tenant's licences (Graph subscribedSkus) could not be read with this identity ({0}); it needs Directory.Read.All, which SecurityInsight's permission list already names -- nothing is granted here" -f $_.Exception.Message) }
        } else { Write-SIUplinkDiag 'capability probe: no Licences in the status report -- no Microsoft Graph sign-in is loaded in this job' }
    } catch { $skus = $null; $skusRead = $false }
    $p = $null
    try { $p = ConvertFrom-SICapabilityProbe -LaRows $la -HuntRows $hunt -HuntNotProvisioned:$notProv -Skus $skus -SkusRead:$skusRead } catch { $p = [pscustomobject]@{ Capabilities = [ordered]@{}; CiColumns = @(); Licences = @() } }
    if (-not ($PSBoundParameters.ContainsKey('RunQuery') -or $PSBoundParameters.ContainsKey('RunHunting') -or $PSBoundParameters.ContainsKey('GraphGet'))) { $global:SI_CapabilityProbe = $p }
    $p
}

# =====================================================================================================================
#  Customer mails: the reference codes of a failure, each linked to its page
# =====================================================================================================================
function Get-SIUplinkMailCodes {
    <# PURE. The distinct codes of a run's report facts (ConvertTo-SIUplinkReports' mapping), in its order, at most 20. #>
    param([AllowNull()][object[]]$Facts)
    try { @(@(ConvertTo-SIUplinkReports -Facts $Facts) | ForEach-Object { [string]$_.Code } | Select-Object -Unique) } catch { @() }
}

function ConvertTo-SIErrorCodeMailHtml {
    <# PURE. One paragraph for a failure mail: 'Reference: <code> (linked to its page), ...' -- '' when there is none. #>
    param([AllowNull()][string[]]$Codes)
    $links = @(@($Codes) | Where-Object { Get-SIErrorCodeUrl $_ } | Select-Object -Unique | ForEach-Object {
        $u = Get-SIErrorCodeUrl $_
        '<a href="{0}" style="color:#0969da;">{1}</a>' -f [System.Net.WebUtility]::HtmlEncode($u), [System.Net.WebUtility]::HtmlEncode(([string]$_).ToLowerInvariant())
    })
    if (-not $links.Count) { return '' }
    '<p style="margin:0 0 10px 0;">Reference: {0} &mdash; each code''s page says what it means and what to do.</p>' -f ($links -join ', ')
}
