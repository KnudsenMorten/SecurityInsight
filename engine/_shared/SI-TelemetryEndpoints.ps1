#Requires -Version 5.1
<#
    SecurityInsight -- the INSTALL'S OWN LINKS on the identified heartbeat, and the deep Link on a failed run report
    (framework §8.9 ENDPOINTS, Invardia: "Open SecurityInsight" buttons in every mail about the environment).

    THE FIELD (identified heartbeat only -- an anonymous record never carries it), Invardia's contract (§8.9):
        endpoints: [ { kind, url, label? } ]
          - the property is `endpoints` (lower case); each entry has kind and url, optionally label -- NO other key (one
            other key makes Invardia refuse the whole list);
          - kind: ^[a-z][a-z0-9-]{1,30}$, §8.9's names: webapp = the Pro web app, mcp = its MCP server; each kind once;
          - url: https only, no user name / password, no query string, no fragment, at most 400 characters;
          - label: plain text, at most 60 characters (optional);
          - at most 12 entries; the field is left out when nothing is known.

    THE SEND GATE: a list Invardia's validator does not accept makes it refuse the WHOLE report (422), so the heartbeat
    carries `endpoints` only while SI_Telemetry_SendEndpoints is on -- ON by default since Invardia's validator is live
    (2026-10-10); a customer can switch it off. The run report's deep Link is not gated.

    WHERE THE ADDRESSES COME FROM -- the install's own hosting and settings, never a hard-coded name:
        1. the hosting record the updater keeps (cfg.InstallState 'Endpoints'): it reads the Container App FQDN of the web
           app (ca-si-management) and the MCP server (ca-si-mcp) over ARM on every run (Save-SIInstallEndpointsRow); an
           engine run reads the row at run start with the ring facts ($global:SI_InstallRingFacts.Endpoints); the updater
           itself also keeps what it just read in $global:SI_InstallEndpoints. A row written before §8.9 (entries with
           `role`: web / mcp) is read as kind (webapp / mcp);
        2. the web app's public address setting (SIWeb_PublicBaseUrl) when the hosting record has no webapp entry.

    THE DEEP LINK: an identified run report that did not end ok carries Link = <web app>/Admin/RunHealth (the run-health
    page); guard records already carry <web app>/Admin/Guards (SI-Guard.ps1). No web app known = no Link.

    PURE except Save-SIInstallEndpointsRow (one SQL write on a store the caller opened), Get-SITelemetryInstallEndpoints
    and Test-SITelemetrySendEndpoints (read the run's globals). Nothing here throws to a telemetry caller: a bad value is
    dropped, never sent.
#>

$script:SITelemetryEndpointRules = @{
    Max           = 12
    KindPattern   = '^[a-z][a-z0-9-]{1,30}$'
    UrlMax        = 400
    LabelMax      = 60
    Keys          = @('kind', 'url', 'label')
    # the names an older row used (role) -> §8.9's kinds
    RoleAliases   = @{ web = 'webapp' }
    Labels        = @{ webapp = 'SecurityInsight web app'; mcp = 'SecurityInsight MCP server' }
    StateName     = 'Endpoints'      # cfg.InstallState row
    StateMax      = 400              # cfg.InstallState.Value is NVARCHAR(400)
    RunHealthPath = '/Admin/RunHealth'
}

function Get-SITelemetryEndpointRules { $script:SITelemetryEndpointRules }

function Test-SITelemetrySendEndpoints {
    <# The send gate: $global:SI_Telemetry_SendEndpoints, else the environment variable SI_TELEMETRY_SENDENDPOINTS; ON
       when neither is set (Invardia accepts install links), otherwise on only for true / 1 / on / yes. #>
    param([AllowNull()]$Value = $global:SI_Telemetry_SendEndpoints, [AllowNull()][AllowEmptyString()][string]$EnvValue = [Environment]::GetEnvironmentVariable('SI_TELEMETRY_SENDENDPOINTS'))
    $v = if ($null -ne $Value -and "$Value".Trim() -ne '') { "$Value" } else { "$EnvValue" }
    if (-not $v.Trim()) { return $true }
    return ($v.Trim().ToLowerInvariant() -in @('true', '1', 'on', 'yes', '$true'))
}

function ConvertTo-SITelemetryEndpointUrl {
    <# PURE. One address as Invardia accepts it: https://host[:port][/path], no query, no fragment, no credentials, no
       trailing slash, at most 400 characters. A bare host name (a Container App FQDN) becomes https://<host>. '' for
       anything else. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    if ($v -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        if ($v -match '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+(:\d{1,5})?(/[^?#]*)?$') { $v = 'https://' + $v }
        else { return '' }
    }
    $u = $null
    if (-not [System.Uri]::TryCreate($v, [System.UriKind]::Absolute, [ref]$u)) { return '' }
    if ($u.Scheme -ne 'https') { return '' }
    if ($u.Query -or $u.Fragment -or $v.Contains('?') -or $v.Contains('#')) { return '' }
    if ($u.UserInfo -or $v -match '^https://[^/]*@') { return '' }
    if (-not $u.Host -or $u.Host -notmatch '\.') { return '' }
    $out = 'https://' + $u.Authority.ToLowerInvariant() + $u.AbsolutePath.TrimEnd('/')
    if ($out.Length -gt $script:SITelemetryEndpointRules.UrlMax) { return '' }
    $out
}

function ConvertTo-SITelemetryEndpointLabel {
    <# PURE. A label as plain text: control characters and markup characters removed, spaces collapsed, at most 60
       characters. '' when nothing is left. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $t = [regex]::Replace("$Value", '[\x00-\x1F\x7F<>]', ' ')
    $t = [regex]::Replace($t, '\s+', ' ').Trim()
    if ($t.Length -gt $script:SITelemetryEndpointRules.LabelMax) { $t = $t.Substring(0, $script:SITelemetryEndpointRules.LabelMax).TrimEnd() }
    $t
}

function ConvertTo-SITelemetryEndpointList {
    <# PURE. Items (hashtables or objects, in priority order) as the §8.9 wire list: each entry exactly kind + url (+ label
       when one is given), valid entries only, each kind once (the first wins), at most 12. An item with `role` instead of
       `kind` (a row written before §8.9) is read as kind, web -> webapp. Writes the entries one by one (none = nothing to send),
       so every caller collects them with @(...) and the list is never wrapped in a second array. #>
    param([AllowNull()][object[]]$Items)
    $r = $script:SITelemetryEndpointRules
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($it in @($Items)) {
        if ($null -eq $it -or $out.Count -ge $r.Max) { continue }
        $get = { param($n) if ($it -is [System.Collections.IDictionary]) { if ($it.Contains($n)) { $it[$n] } else { $null } } elseif ($it.PSObject.Properties[$n]) { $it.$n } else { $null } }
        $kind = "$(& $get 'kind')".Trim().ToLowerInvariant()
        if (-not $kind) {
            $role = "$(& $get 'role')".Trim().ToLowerInvariant()
            $kind = if ($r.RoleAliases.ContainsKey($role)) { $r.RoleAliases[$role] } else { $role }
        }
        if ($kind -notmatch $r.KindPattern -or $seen.ContainsKey($kind)) { continue }
        $url = ConvertTo-SITelemetryEndpointUrl ([string](& $get 'url'))
        if (-not $url) { continue }
        $seen[$kind] = $true
        $e = [ordered]@{ kind = $kind; url = $url }
        $label = ConvertTo-SITelemetryEndpointLabel ([string](& $get 'label'))
        if ($label) { $e['label'] = $label }
        $out.Add([pscustomobject]$e)
    }
    $out.ToArray()
}

function ConvertTo-SIInstallEndpointsValue {
    <# PURE. The list as the cfg.InstallState 'Endpoints' value (compact JSON, kind + url only -- labels are added when the
       report is built -- at most 400 characters: entries that would pass the limit are left out, in order). '' for an
       empty list. #>
    param([AllowNull()][object[]]$Endpoints)
    $list = @(ConvertTo-SITelemetryEndpointList -Items $Endpoints | ForEach-Object { [pscustomobject][ordered]@{ kind = $_.kind; url = $_.url } })
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($e in $list) {
        $keep.Add($e)
        $json = ConvertTo-Json -InputObject @($keep.ToArray()) -Compress -Depth 3
        if ($json.Length -gt $script:SITelemetryEndpointRules.StateMax) { $keep.RemoveAt($keep.Count - 1) }
    }
    if (-not $keep.Count) { return '' }
    ConvertTo-Json -InputObject @($keep.ToArray()) -Compress -Depth 3
}

function ConvertFrom-SIInstallEndpointsValue {
    <# PURE. The cfg.InstallState 'Endpoints' value back as the checked list (an old row with `role` reads as kind).
       Damaged JSON = an empty list. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return }
    try { $j = "$Value".Trim() | ConvertFrom-Json -ErrorAction Stop } catch { return }
    ConvertTo-SITelemetryEndpointList -Items @($j)
}

function Resolve-SITelemetryEndpoints {
    <# PURE. The heartbeat's list: the hosting record first (-Hosting: what the updater read, or the recorded row), then the
       web app's public address setting as 'webapp' when the hosting record has none; each known kind gets its plain
       label. #>
    param([AllowNull()][object[]]$Hosting, [AllowNull()][AllowEmptyString()][string]$PublicBaseUrl)
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($h in @(ConvertTo-SITelemetryEndpointList -Items $Hosting)) { $items.Add($h) }
    if ("$PublicBaseUrl".Trim()) { $items.Add([pscustomobject]@{ kind = 'webapp'; url = "$PublicBaseUrl".Trim() }) }
    $labels = $script:SITelemetryEndpointRules.Labels
    $withLabels = @(ConvertTo-SITelemetryEndpointList -Items $items.ToArray() | ForEach-Object {
        $e = [ordered]@{ kind = $_.kind; url = $_.url }
        if ($_.PSObject.Properties['label'] -and "$($_.label)") { $e['label'] = $_.label } elseif ($labels.ContainsKey($_.kind)) { $e['label'] = $labels[$_.kind] }
        $e })
    ConvertTo-SITelemetryEndpointList -Items $withLabels
}

function Get-SITelemetryRunLink {
    <# PURE. The deep link of a run report that did not end ok: the web app's run-health page. '' without a web app.
       (An old entry with role 'web' counts as the web app.) #>
    param([AllowNull()][object[]]$Endpoints)
    $web = @(ConvertTo-SITelemetryEndpointList -Items $Endpoints | Where-Object { "$($_.kind)" -eq 'webapp' } | Select-Object -First 1)
    if (-not $web.Count) { return '' }
    $web[0].url + $script:SITelemetryEndpointRules.RunHealthPath
}

function Get-SITelemetryInstallEndpoints {
    <# This install's links from the run's globals (never throws; an empty list when nothing is known):
       $global:SI_InstallEndpoints (the updater, this run) > $global:SI_InstallRingFacts.Endpoints (the recorded row) and
       $global:SIWeb_PublicBaseUrl (the web app's address setting). #>
    try {
        $hosting = @()
        if ($global:SI_InstallEndpoints) { $hosting = @($global:SI_InstallEndpoints) }
        elseif ($global:SI_InstallRingFacts -and $global:SI_InstallRingFacts.PSObject.Properties['Endpoints']) {
            $hosting = @(ConvertFrom-SIInstallEndpointsValue ([string]$global:SI_InstallRingFacts.Endpoints))
        }
        Resolve-SITelemetryEndpoints -Hosting $hosting -PublicBaseUrl ([string]$global:SIWeb_PublicBaseUrl)
    } catch { }
}

function Save-SIInstallEndpointsRow {
    <# The install's links into cfg.InstallState 'Endpoints' (the updater, after it read the Container Apps). Nothing to
       write (an empty list) leaves the row as it is. Never throws: $true written, $false not. #>
    param([Parameter(Mandatory)]$Store, [AllowNull()][object[]]$Endpoints, [string]$By = 'caj-si-updater')
    $v = ConvertTo-SIInstallEndpointsValue -Endpoints $Endpoints
    if (-not $v) { return $false }
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'Endpoints')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'Endpoints' AND Value <> @Value;
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'Endpoints', @Value, NULL, @By);
    COMMIT;
END
'@
    try { $null = & $Store.Invoke $sql ([ordered]@{ Value = $v; By = $By }) 'nonquery'; $true } catch { $false }
}
