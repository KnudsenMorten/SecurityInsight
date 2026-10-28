#Requires -Version 5.1
<#
    THE SOURCE'S OWN FIRST-SEEN ON EVERY FINDING ROW THAT HAS ONE (#636, owner 2026-10-19: "Yes, build it" -- the protection
    score's "within accepted lifecycle" view ages a finding by the source's first-seen before SI's own first detection).
    One field, si_source_first_seen (data-model/field-catalog.locked.json), from what each source really gives
    (checked against Microsoft's documentation 2026-10-19):

      Defender for Endpoint, vulnerabilities  the software vulnerabilities export -- GET /api/machines/SoftwareVulnerabilitiesExport
                                              (Vulnerability.Read.All, already granted), GZIP files with one JSON object per
                                              line; documented property FirstSeenTimestamp ("First time this product CVE was
                                              seen on the device"). The FILES variant for every tenant size (one method for
                                              all sizes; Microsoft recommends it above 100,000 devices). Read once per run;
                                              per device + CVE the earliest sighting is kept. Advanced hunting
                                              (DeviceTvmSoftwareVulnerabilities, which the reports read) has no such column.
      Defender for Cloud                      firstEvaluationDate (already on the rows as si_source_first_detected)
      Shodan (public IPs)                     the first banner SI collected for the IP (the CI's si_banner_first_seen) --
                                              Shodan gives no first-seen per service or port
    NO SUCH DATE (a finding of these counts as "no date" unless SI saw it first): Defender for Endpoint secure configurations
    (the export's Timestamp is the LAST time the configuration was seen), the identity posture checks (no detection behind
    them; Entra ID Protection's riskDetection.detectedDateTime belongs to risk detections, which no SI report lists as a
    finding), Defender for Identity investigation priority (a score), exposure graph paths, the Endpoint active-compromise
    report (it reads the CI's compromise flag, not the alerts -- an alert's firstActivityDateTime is not on the row).

    SI_RA_SourceFirstSeen = off switches the Defender read off (the rows then keep what their report gave). A refused or
    failed read is said ONCE per run and changes nothing; it never fails the run.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.
$script:RASourceFirstSeenExportUrl = 'https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport?sasValidHours=6'

function Test-RASourceFirstSeenOn {
    <# PURE. The Defender read is on unless SI_RA_SourceFirstSeen says off. #>
    param($Setting = $global:SI_RA_SourceFirstSeen)
    -not ($Setting -and ([string]$Setting).Trim().ToLowerInvariant() -in 'off', 'false', '0', 'no')
}

function ConvertTo-RASourceFirstSeenKey {
    <# PURE. device id + CVE as the index keys them: "<device id lower>|<CVE upper>"; '' when either is missing. #>
    param([string]$DeviceId, [string]$Cve)
    $d = "$DeviceId".Trim().ToLowerInvariant(); $c = "$Cve".Trim().ToUpperInvariant()
    if (-not $d -or $c -notmatch '^CVE-\d{4}-\d+$') { return '' }
    $d + '|' + $c
}

function ConvertFrom-RASourceFirstSeenLine {
    <#
        PURE. One line of the export (a JSON object) -> @{ Key; FirstSeen } or $null. Read with a regex, not a JSON parse per
        line (a large tenant has millions of lines); the property names in any case (FirstSeenTimestamp / firstSeenTimestamp).
    #>
    param([string]$Line)
    if (-not $Line) { return $null }
    $d = [regex]::Match($Line, '"(?i:deviceId)"\s*:\s*"([^"]+)"'); if (-not $d.Success) { return $null }
    $c = [regex]::Match($Line, '"(?i:cveId)"\s*:\s*"([^"]+)"'); if (-not $c.Success) { return $null }
    $f = [regex]::Match($Line, '"(?i:firstSeenTimestamp)"\s*:\s*"([^"]+)"'); if (-not $f.Success) { return $null }
    $k = ConvertTo-RASourceFirstSeenKey -DeviceId $d.Groups[1].Value -Cve $c.Groups[1].Value
    if (-not $k) { return $null }
    $t = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetime]::TryParse($f.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$t)) { return $null }
    @{ Key = $k; FirstSeen = $t }
}

function Add-RASourceFirstSeenLines {
    <# PURE over -Index. Lines into the index, the earliest sighting per key kept. Answers the lines read. #>
    param([Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, datetime]]$Index, [AllowEmptyCollection()][string[]]$Lines = @())
    $n = 0
    foreach ($l in $Lines) {
        $x = ConvertFrom-RASourceFirstSeenLine -Line $l
        if ($null -eq $x) { continue }
        $n++
        $cur = [datetime]::MinValue
        if (-not $Index.TryGetValue($x.Key, [ref]$cur) -or $x.FirstSeen -lt $cur) { $Index[$x.Key] = $x.FirstSeen }
    }
    $n
}

function Read-RASourceFirstSeenIndex {
    <#
        The run's Defender first-sighting index: @{ Index (key -> UTC datetime); Complete; Error; Files; Lines }. Read once per
        run (cached in $global:RA_SourceFirstSeenIndex). Never throws.
        -Fetch: test seam { param($url) -> @{ Files = @(url...) ; Error } } for the export call, and -Download { param($fileUrl)
        -> string[] lines } for one file; by default the Defender API with the run's token, and each file streamed through
        GZip line by line (never held whole).
    #>
    param([scriptblock]$Fetch, [scriptblock]$Download, [switch]$Refresh)
    if (-not $Refresh -and $null -ne $global:RA_SourceFirstSeenIndex) { return $global:RA_SourceFirstSeenIndex }
    $state = @{ Index = (New-Object 'System.Collections.Generic.Dictionary[string,datetime]' ([StringComparer]::Ordinal)); Complete = $false; Error = $null; Files = 0; Lines = 0 }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $files = @()
        if ($Fetch) {
            $r = & $Fetch $script:RASourceFirstSeenExportUrl
            if ($null -eq $r -or $r.Error) { throw ([string]$(if ($r) { $r.Error } else { 'no answer' })) }
            $files = @($r.Files)
        } else {
            $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
            if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
            $token = Get-SIGraphToken -Resource Defender
            if (-not $token) { throw 'no token for the Defender API' }
            $resp = Invoke-RestMethod -Method Get -Uri $script:RASourceFirstSeenExportUrl -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 300 -ErrorAction Stop
            $files = @($resp.exportFiles)
        }
        foreach ($u in $files) {
            if (-not $u) { continue }
            $state.Files++
            if ($Download) {
                $state.Lines += [long](Add-RASourceFirstSeenLines -Index $state.Index -Lines @(& $Download $u))
                continue
            }
            # one file streamed: HTTP -> GZip -> lines, a block of lines at a time into the index
            $req = [System.Net.HttpWebRequest]::Create([string]$u); $req.Timeout = 600000; $req.ReadWriteTimeout = 600000
            $res = $req.GetResponse()
            try {
                $gz = New-Object System.IO.Compression.GZipStream($res.GetResponseStream(), [System.IO.Compression.CompressionMode]::Decompress)
                $rd = New-Object System.IO.StreamReader($gz, [Text.Encoding]::UTF8)
                $block = New-Object 'System.Collections.Generic.List[string]'
                while ($null -ne ($line = $rd.ReadLine())) {
                    $block.Add($line)
                    if ($block.Count -ge 20000) { $state.Lines += [long](Add-RASourceFirstSeenLines -Index $state.Index -Lines $block.ToArray()); $block.Clear() }
                }
                if ($block.Count -gt 0) { $state.Lines += [long](Add-RASourceFirstSeenLines -Index $state.Index -Lines $block.ToArray()) }
                $rd.Dispose()
            } finally { $res.Close() }
        }
        $state.Complete = $true
    } catch {
        $state.Error = $_.Exception.Message
    }
    Write-Host ('[SourceFirstSeen] Defender''s software vulnerabilities export: {0:N0} file(s), {1:N0} device-CVE sighting(s), {2:N0} kept, {3:N0} s{4}' -f $state.Files, $state.Lines, $state.Index.Count, $sw.Elapsed.TotalSeconds, $(if ($state.Complete) { '' } else { ' -- NOT complete' }))
    $global:RA_SourceFirstSeenIndex = $state
    $state
}

function Get-RASourceFirstSeenMessage {
    <# PURE. What to tell the operator when the read did not complete -- plain words; '' when it did. #>
    param([hashtable]$State)
    if ($null -eq $State -or $State.Complete) { return '' }
    $err = [string]$State.Error
    if ($err -match '(?i)\b403\b|Forbidden|Unauthorized|\b401\b') {
        return 'Defender''s first sighting of each vulnerability was not read: the permission Vulnerability.Read.All is not granted to SecurityInsight -- run the permission setup again. The findings are complete without it; the protection score then ages them by SecurityInsight''s own first detection.'
    }
    'Defender''s first sighting of each vulnerability could not be read in this run ({0}). The findings are complete without it; the protection score then ages them by SecurityInsight''s own first detection.' -f $err
}

function Get-RASourceFirstSeenRowValue {
    <# PURE. The first non-empty of -Names on a row (object or dictionary), $null when none. #>
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $v = $null
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n] } }
        elseif ($Row.PSObject.Properties[$n]) { $v = $Row.$n }
        if ($null -ne $v -and -not ($v -is [System.DBNull]) -and "$v".Trim()) { return $v }
    }
    $null
}

function Add-RASourceFirstSeen {
    <#
        Puts si_source_first_seen on every row whose source gives one (see the file header); a row that has it already keeps
        it. Returns the rows. -Index: test seam (the state of Read-RASourceFirstSeenIndex); -Log { param($message) } for the
        one message of a read that did not complete.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index, [scriptblock]$Log, [scriptblock]$Fetch, [scriptblock]$Download)
    $setv = {
        param($r, $v)
        if ($r -is [System.Collections.IDictionary]) { $r['si_source_first_seen'] = $v }
        else { $r | Add-Member -NotePropertyName 'si_source_first_seen' -NotePropertyValue $v -Force }
    }
    $cveRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if ($null -ne (Get-RASourceFirstSeenRowValue $r @('si_source_first_seen'))) { continue }
        # Defender for Cloud: firstEvaluationDate came with the row
        $mdc = Get-RASourceFirstSeenRowValue $r @('si_source_first_detected')
        if ($null -ne $mdc) { & $setv $r $mdc; continue }
        # a public IP: the first banner SI collected for it (the CI's context)
        $ban = Get-RASourceFirstSeenRowValue $r @('si_banner_first_seen')
        if ($null -ne $ban) { & $setv $r $ban; continue }
        $dev = Get-RASourceFirstSeenRowValue $r @('MdeDeviceId', 'DeviceId', 'si_link_mde')
        $cve = Get-RASourceFirstSeenRowValue $r @('si_cve', 'Cve', 'CveId', 'ConfigurationId', 'FindingName')
        if ($dev -and ("$cve" -match '^(?i)CVE-\d{4}-\d+$')) { $cveRows.Add($r) }
    }
    if ($cveRows.Count -eq 0) { return , @($Rows) }
    if ($null -eq $Index) {
        if (-not (Test-RASourceFirstSeenOn)) { return , @($Rows) }
        $Index = Read-RASourceFirstSeenIndex -Fetch $Fetch -Download $Download
    }
    if ($null -eq $Index -or -not $Index.Complete) {
        if (-not $global:RA_SourceFirstSeenSaid) {
            $global:RA_SourceFirstSeenSaid = $true
            $msg = Get-RASourceFirstSeenMessage -State $Index
            if ($msg) { if ($Log) { & $Log $msg } else { Write-Warning $msg } }
        }
        return , @($Rows)
    }
    $ix = $Index.Index
    foreach ($r in $cveRows) {
        $k = ConvertTo-RASourceFirstSeenKey -DeviceId ([string](Get-RASourceFirstSeenRowValue $r @('MdeDeviceId', 'DeviceId', 'si_link_mde'))) -Cve ([string](Get-RASourceFirstSeenRowValue $r @('si_cve', 'Cve', 'CveId', 'ConfigurationId', 'FindingName')))
        $t = [datetime]::MinValue
        if ($k -and $ix.TryGetValue($k, [ref]$t)) { & $setv $r ($t.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)) }
    }
    , @($Rows)
}
