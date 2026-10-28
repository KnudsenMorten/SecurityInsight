#Requires -Version 5.1
<#
    SecurityInsight -- what a CONTAINER job keeps in the install's own storage account, because its disk does not outlive it.

    On a VM the install's folder holds two things a container job never has:

      1. THE CUSTOMER'S CUSTOMISATION FILES -- their CMDB.csv, custom Risk Analysis queries, exclusion files, enrichment
         rules, schema overlays and decision files. A container image must never carry a tenant's files (the image is a
         shared artifact; .dockerignore keeps them out), and an updater rebuild from the published archive could not carry
         them anyway. So setup (Bootstrap-ContainerAppJob.ps1, and the update hook after every sync) copies the install's
         customisation files to the 'sioverlay' container of the install's storage account, and every job restores them
         into its own folder tree at start -- to the same places a VM reads them. Community needs no licence for this.
         A Pro install with the settings database keeps its configuration in the database; the overlay is then not used.
      2. THE RISK ANALYSIS BUCKET CACHE (OUTPUT/AutoBucketCache.json) -- the bucket counts that let a run skip the probe.
         Kept per report template in the 'sistate' container: loaded before the run, saved after it.

    Contract (the same as the privilege-tier catalog blob, engine/_shared/SI-CatalogBlob.ps1):
      * Never fails a run: a storage error is a warning, and the run continues without the copy.
      * No storage account configured = silent no-op.
      * OAuth through the job's identity only. No account key.
      * ONLY customisation files travel -- an allow-list of names (Test-SIOverlayPath), checked when uploading AND when
        restoring. Never a script, never a config .ps1 (those carry secrets; settings travel as SI_CFG_*), never a
        sample, never a shipped file.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../engine/_shared/SI-AzRest.ps1') }

$script:SIOverlayContainer = 'sioverlay'
$script:SIStateContainer   = 'sistate'

# The customisation files, as paths relative to the solution root ('/' separators, any letter case). Nothing else.
$script:SIOverlayPatterns = @(
    '^asset-profiling-enrichment/.+\.custom\.ya?ml$',                                 # enrichment / tier rules
    '^asset-profiling-schema/[^/]+\.schema\.custom\.json$',                            # schema overlays
    '^asset-profiling-providers/(generic-cmdb|servicenow-cmdb)/cmdb\.csv$',            # the customer's CMDB export
    '^risk-analysis-detection/(custom/)?riskanalysis_queries_custom\.yaml$',           # custom Risk Analysis queries
    '^risk-analysis-detection/(custom/)?[^/]+\.exclude(\.custom)?\.json$',             # per-report exclusions
    '^risk-analysis-detection/riskanalysisglobalexclusions\.custom\.json$',            # global exclusions
    '^risk-analysis-detection/[^/]+\.weighted\.custom\.json$',                         # per-report weights
    '^risk-analysis-detection/riskscore_weighted\.schema\.custom\.json$',              # solution-wide weights
    '^risk-analysis-detection/riskscore\.index\.custom\.csv$',                         # the customer's own risk index rows (#398)
    '^config/(asset-decisions|correlation-decisions)\.custom\.ya?ml$',                 # operator decisions
    '^config/cmdb-source-ownership\.custom\.json$',                                    # CMDB ownership overrides
    '^config/job-flow\.custom\.json$',                                                 # the daily job flow (#269)
    '^config/asset-tagging\.config\.json$',                                            # asset-tagging AutoExclude gates (#275 G13)
    '^asset-profiling-enrichment/endpoint/server-applications\.json$',                 # server-application catalog override (#275 G13)
    '^data-model/(mappings/|outputs/)?[a-z0-9][a-z0-9_\-]*\.custom\.json$'             # data-model overrides: catalog, mappings, ... (#456)
)

function ConvertTo-SIOverlayRelativePath {
    <# PURE. A relative path in the overlay's form: '/' separators, no leading './' or '/'. $null when it is not relative
       or climbs out of the tree. #>
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = ($Path.Trim() -replace '\\', '/')
    while ($p.StartsWith('./')) { $p = $p.Substring(2) }
    if ($p.StartsWith('/') -or $p -match '^[A-Za-z]:' -or $p -match '(^|/)\.\.(/|$)' -or $p -match '//' ) { return $null }
    return $p
}

function Test-SIOverlayPath {
    <# PURE. Is this relative path a customisation file the overlay may carry? Samples, scripts and anything outside the
       allow-list are refused. #>
    param([AllowNull()][AllowEmptyString()][string]$RelativePath)
    $p = ConvertTo-SIOverlayRelativePath -Path $RelativePath
    if (-not $p) { return $false }
    if ($p -match '(?i)\.sample(\.|$)' -or $p -match '(?i)\.(ps1|psm1|psd1|exe|dll|sh|cmd|bat)$') { return $false }
    foreach ($rx in $script:SIOverlayPatterns) { if ($p -match ('(?i)' + $rx)) { return $true } }
    return $false
}

function Get-SIContainerOverlayFiles {
    <# The install's customisation files under -Root: @{ RelativePath; FullName; Length }, sorted. Run output, the
       internal folder and the web app are never walked. #>
    param([Parameter(Mandatory)][string]$Root)
    $rootFull = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd('\', '/')
    $skip = '^(\.git|output|data|logs|staging|internal|analyzer-web|tests|docs|demo)(/|$)'
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($top in @('asset-profiling-enrichment', 'asset-profiling-schema', 'asset-profiling-providers', 'risk-analysis-detection', 'config')) {
        $dir = Join-Path $rootFull $top
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue)) {
            $rel = ConvertTo-SIOverlayRelativePath -Path ($f.FullName.Substring($rootFull.Length + 1))
            if (-not $rel -or $rel -match ('(?i)' + $skip) -or -not (Test-SIOverlayPath -RelativePath $rel)) { continue }
            $out.Add([pscustomobject]@{ RelativePath = $rel; FullName = $f.FullName; Length = $f.Length })
        }
    }
    $out.ToArray() | Sort-Object RelativePath
}

function Publish-SIContainerOverlay {
    <#
        Setup side. Copies the install's customisation files to the 'sioverlay' container of -AccountName, and removes a
        file there that the install no longer has (so deleting a customisation takes effect too). Never throws. Returns
        @{ Files; Uploaded; Removed; Failed; Message }.
        -Rest: the update's REST seam (setup/_shared/SI-UpdateRest.ps1; #521, no az CLI): the blob data plane over OAuth.
        The only path: the az seam (-Az) is gone.
    #>
    param([Parameter(Mandatory)][string]$Root, [string]$AccountName, [scriptblock]$Rest)
    $res = [ordered]@{ Files = @(); Uploaded = 0; Removed = @(); Failed = @(); Message = '' }
    if ([string]::IsNullOrWhiteSpace($AccountName)) { $res.Message = 'no storage account configured -- customisation files are not shared with the container jobs'; return [pscustomobject]$res }
    if (-not $Rest) { throw 'Publish-SIContainerOverlay: pass -Rest (the REST seam of setup\_shared\SI-UpdateRest.ps1).' }
    $files = @(Get-SIContainerOverlayFiles -Root $Root)
    $res.Files = @($files | ForEach-Object { $_.RelativePath })
    Publish-SIContainerOverlayRest -Files $files -AccountName $AccountName -Rest $Rest -Result $res
}

function Publish-SIContainerOverlayRest {
    <#
        Publish-SIContainerOverlay over the blob data plane (-Rest seam, audience https://storage.azure.com/, OAuth only):
        the container (PUT ?restype=container; 409 = it exists), one PUT BlockBlob per file, the list (GET ?comp=list, every
        page), one DELETE per blob the install no longer has. Only names the overlay may hold are ever removed. Never throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Files, [Parameter(Mandatory)][string]$AccountName, [Parameter(Mandatory)][scriptblock]$Rest,
          [Parameter(Mandatory)][System.Collections.IDictionary]$Result)
    $res = $Result
    $st = 'https://storage.azure.com/'
    $ver = @{ 'x-ms-version' = '2021-08-06' }
    $base = 'https://{0}.blob.core.windows.net/{1}' -f $AccountName, $script:SIOverlayContainer
    $blobUri = { param($name) $base + '/' + ((@(([string]$name) -split '/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/') }
    $why = { param($r) $b = ("$($r.Body)" -replace '\s+', ' ').Trim(); if ($b.Length -gt 300) { $b = $b.Substring(0, 297) + '...' }; 'HTTP {0}: {1}' -f $r.Status, $b }
    try {
        $r = & $Rest 'PUT' ($base + '?restype=container') $null $st $ver
        $cs = [int]$r.Status
        if (-not ($cs -eq 409 -or ($cs -ge 200 -and $cs -lt 300))) {
            $res.Failed = @('(container)')
            $res.Message = ("could not reach the '{0}' container in storage account '{1}' ({2}) -- the container jobs keep the customisation files shared last time. Setup needs Storage Blob Data Contributor there." -f $script:SIOverlayContainer, $AccountName, (& $why $r))
            return [pscustomobject]$res
        }
        $up = 0; $bad = New-Object System.Collections.Generic.List[string]; $firstErr = ''
        foreach ($f in @($Files)) {
            $h = @{ 'x-ms-version' = '2021-08-06'; 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/octet-stream' }
            $u = & $Rest 'PUT' (& $blobUri $f.RelativePath) ([IO.File]::ReadAllBytes($f.FullName)) $st $h
            if ([int]$u.Status -ge 200 -and [int]$u.Status -lt 300) { $up++ } else { $bad.Add([string]$f.RelativePath); if (-not $firstErr) { $firstErr = & $why $u } }
        }
        $res.Uploaded = $up
        if ($bad.Count) { $res.Failed = @($bad); $res.Message = ('upload failed: {0}' -f $firstErr) }
        # the blobs there now (every page), then what the install no longer has
        $remote = New-Object System.Collections.Generic.List[string]; $marker = ''; $listed = $true
        for ($p = 0; $p -lt 50; $p++) {
            $l = & $Rest 'GET' ($base + '?restype=container&comp=list' + $(if ($marker) { '&marker=' + [uri]::EscapeDataString($marker) } else { '' })) $null $st $ver
            if ([int]$l.Status -lt 200 -or [int]$l.Status -ge 300) { $listed = $false; break }
            $xml = [string]$l.Body; if ($xml.Length -and $xml[0] -eq [char]0xFEFF) { $xml = $xml.Substring(1) }
            $doc = [xml]$xml
            foreach ($n in @($doc.SelectNodes('//Blobs/Blob/Name'))) { if ($n) { $remote.Add([string]$n.InnerText) } }
            $nm = $doc.SelectSingleNode('//NextMarker'); $marker = if ($nm) { [string]$nm.InnerText } else { '' }
            if (-not $marker) { break }
        }
        if ($listed) {
            $have = @{}; foreach ($n in $res.Files) { $have[$n.ToLowerInvariant()] = $true }
            $removed = New-Object System.Collections.Generic.List[string]
            foreach ($b in $remote) {
                if (-not (Test-SIOverlayPath -RelativePath $b) -or $have.ContainsKey(([string]$b).ToLowerInvariant())) { continue }
                $d = & $Rest 'DELETE' (& $blobUri $b) $null $st $ver
                $ds = [int]$d.Status
                if (($ds -ge 200 -and $ds -lt 300) -or $ds -eq 404) { $removed.Add([string]$b) } else { $res.Failed = @($res.Failed) + @([string]$b) }
            }
            $res.Removed = $removed.ToArray()
        }
    } catch { $res.Failed = @($res.Failed) + @('(overlay)'); $res.Message = ('the customisation files were not shared: {0}' -f $_.Exception.Message) }
    if (-not $res.Message) { $res.Message = ('{0} customisation file(s) shared with the container jobs{1}' -f $res.Uploaded, $(if (@($res.Removed).Count) { ('; {0} no longer present removed' -f @($res.Removed).Count) } else { '' })) }
    [pscustomobject]$res
}

function Get-SIRunStateContext {
    param([string]$AccountName)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $null }
    return (New-SIAzStorageContext -StorageAccountName $AccountName -UseConnectedAccount -ErrorAction Stop)
}

function Restore-SIContainerOverlay {
    <#
        Container side. Downloads the install's customisation files from 'sioverlay' into a run-local folder, then puts
        each where a VM has it: -TargetRoot\<relative path>. A name outside the allow-list is skipped, whoever uploaded
        it. Never throws. Returns @{ Applied; Skipped; Source } -- Source 'storage' or 'none'.
    #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$TargetRoot, [string]$RunFolder)
    $applied = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[string]
    $none = { [pscustomobject]@{ Applied = $applied.ToArray(); Skipped = $skipped.ToArray(); Source = 'none' } }
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return (& $none) }
    if ([string]::IsNullOrWhiteSpace($RunFolder)) { $RunFolder = Join-Path ([IO.Path]::GetTempPath()) ('si-overlay-{0}' -f [guid]::NewGuid().ToString('N')) }
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        $blobs = @()
        try { $blobs = @(Get-SIAzStorageBlob -Container $script:SIOverlayContainer -Context $ctx -ErrorAction Stop | Where-Object { $_ }) }
        catch {
            if ("$($_.Exception.Message)" -match '(?i)ContainerNotFound|does not exist|404|Can not find the container') { return (& $none) }   # nothing shared yet
            throw
        }
        foreach ($b in $blobs) {
            $rel = ConvertTo-SIOverlayRelativePath -Path ([string]$b.Name)
            if (-not $rel -or -not (Test-SIOverlayPath -RelativePath $rel)) { $skipped.Add([string]$b.Name); continue }
            $local = Join-Path $RunFolder ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
            $d = Split-Path -Parent $local
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
            Get-SIAzStorageBlobContent -Container $script:SIOverlayContainer -Blob ([string]$b.Name) -Destination $local -Context $ctx -Force -ErrorAction Stop | Out-Null
            $target = Join-Path $TargetRoot ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
            $td = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $td)) { New-Item -ItemType Directory -Force -Path $td | Out-Null }
            Copy-Item -LiteralPath $local -Destination $target -Force
            $applied.Add($rel)
        }
        return [pscustomobject]@{ Applied = $applied.ToArray(); Skipped = $skipped.ToArray(); Source = $(if ($applied.Count) { 'storage' } else { 'none' }) }
    } catch {
        Write-Warning ("Could not restore the customisation files from storage account '{0}' ({1}); this run uses {2}." -f $AccountName, $_.Exception.Message, $(if ($applied.Count) { ('the {0} restored before the error' -f $applied.Count) } else { 'the shipped files only' }))
        return [pscustomobject]@{ Applied = $applied.ToArray(); Skipped = $skipped.ToArray(); Source = $(if ($applied.Count) { 'storage' } else { 'none' }) }
    }
}

function Get-SIRaAutoBucketCacheBlobName {
    <# PURE. The bucket cache's blob, one per report template (the Summary and Detailed jobs never overwrite each other). #>
    param([Parameter(Mandatory)][string]$Template)
    $t = ($Template.Trim() -replace '[^A-Za-z0-9_.-]', '_')
    return ('risk-analysis/AutoBucketCache.{0}.json' -f $t)
}

function Get-SIRaAutoBucketCacheLocalPath {
    <# PURE. Where the Risk Analysis engine keeps the bucket cache -- the same path as Get-AutoBucketCachePath. #>
    param([Parameter(Mandatory)][string]$SettingsPath)
    Join-Path $SettingsPath "OUTPUT\AutoBucketCache.json"
}

function Restore-SIRaAutoBucketCache {
    <# Container side, before the run. Loads the template's bucket cache from 'sistate' when there is one. Never throws.
       Returns 'storage' (loaded) or 'none'. #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$LocalPath, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return 'none' }
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        $blobName = Get-SIRaAutoBucketCacheBlobName -Template $Template
        $blob = $null
        try { $blob = Get-SIAzStorageBlob -Container $script:SIStateContainer -Blob $blobName -Context $ctx -ErrorAction Stop } catch { $blob = $null }
        if (-not $blob) { return 'none' }
        $dir = Split-Path -Parent $LocalPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $tmp = Join-Path $dir ('.bucketcache-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        try {
            Get-SIAzStorageBlobContent -Container $script:SIStateContainer -Blob $blobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
            $null = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            Move-Item -LiteralPath $tmp -Destination $LocalPath -Force
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        return 'storage'
    } catch {
        Write-Warning ("Could not load the Risk Analysis bucket cache from storage account '{0}' ({1}); this run probes the bucket counts again." -f $AccountName, $_.Exception.Message)
        return 'none'
    }
}

function ConvertFrom-SIRaAutoBucketCacheJson {
    <# PURE. The text of an earlier bucket cache -> the counts as a hashtable ('<report>|<fingerprint>' -> count, '__confirmed'); @{} when unreadable. #>
    param([AllowEmptyString()][string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return @{} }
    try { $h = ConvertFrom-Json -InputObject $Json -AsHashtable -ErrorAction Stop } catch { return @{} }
    if ($h -isnot [System.Collections.IDictionary]) { return @{} }
    foreach ($w in 'Entries', 'Cache', 'Data', 'AutoBucket') { if ($h.Contains($w) -and $h[$w] -is [System.Collections.IDictionary]) { $h = $h[$w]; break } }
    $out = @{}
    foreach ($k in @($h.Keys)) {
        if ([string]$k -eq '__confirmed' -and $h[$k] -is [System.Collections.IDictionary]) {
            # ConvertFrom-Json turns an ISO time into a DateTime: kept as ISO 8601 (UTC), never in a regional format
            $c = @{}
            foreach ($ck in @($h[$k].Keys)) { $v = $h[$k][$ck]; $c[[string]$ck] = $(if ($v -is [datetime]) { $v.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) } else { [string]$v }) }
            $out['__confirmed'] = $c; continue
        }
        $out[[string]$k] = $h[$k]
    }
    return $out
}

function Get-SIRaAutoBucketCacheForImport {
    <#
        #640: the ONE-TIME import. The counts this template learned while they were kept in the storage account, read once so
        the database can take them over (no install loses its learned counts). $null when there are none. Never throws.
    #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return $null }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-bucketimport-{0}.json' -f [guid]::NewGuid().ToString('N'))
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        $blobName = Get-SIRaAutoBucketCacheBlobName -Template $Template
        $blob = $null
        try { $blob = Get-SIAzStorageBlob -Container $script:SIStateContainer -Blob $blobName -Context $ctx -ErrorAction Stop } catch { $blob = $null }
        if (-not $blob) { return $null }
        Get-SIAzStorageBlobContent -Container $script:SIStateContainer -Blob $blobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
        return (ConvertFrom-SIRaAutoBucketCacheJson -Json ([IO.File]::ReadAllText($tmp)))
    } catch {
        Write-Warning ("The earlier bucket counts could not be read from storage account '{0}' ({1}); the reports are sized again where the database has no count." -f $AccountName, $_.Exception.Message)
        return $null
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Save-SIRaAutoBucketCache {
    <# Container side, after the run. Saves the template's bucket cache to 'sistate'. Never throws; $true when saved. #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$LocalPath, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($AccountName) -or -not (Test-Path -LiteralPath $LocalPath)) { return $false }
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        if (-not (Get-SIAzStorageContainer -Name $script:SIStateContainer -Context $ctx -ErrorAction SilentlyContinue)) {
            New-SIAzStorageContainer -Name $script:SIStateContainer -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
        }
        Set-SIAzStorageBlobContent -File $LocalPath -Container $script:SIStateContainer -Blob (Get-SIRaAutoBucketCacheBlobName -Template $Template) `
            -Context $ctx -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Warning ("The Risk Analysis bucket cache was not saved to storage account '{0}' ({1}); the next run probes the bucket counts again." -f $AccountName, $_.Exception.Message)
        return $false
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE RISK ANALYSIS COMPLETENESS HISTORY (OUTPUT/RowCountHistory.json, OUTPUT/ColumnFillHistory.json): the per-report
# finding counts and column fill of the previous run. The completeness check compares every report with its previous
# run; in a container the folder dies with the replica, so every run read "no prior run recorded" and could never see
# a report that lost most of its findings (measured on ring 1, 2026-10-05: every run of both templates). Kept per
# report template in 'sistate' like the bucket cache -- the Summary and Detailed jobs never overwrite each other.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIRaGuardHistoryFiles {
    <# PURE. The completeness history files: the engine's own local paths and their blob names for one template. #>
    param([Parameter(Mandatory)][string]$SettingsPath, [Parameter(Mandatory)][string]$Template)
    $t = ($Template.Trim() -replace '[^A-Za-z0-9_.-]', '_')
    foreach ($base in 'RowCountHistory', 'ColumnFillHistory') {
        [pscustomobject]@{
            LocalPath = (Join-Path $SettingsPath ("OUTPUT\{0}.json" -f $base))
            BlobName  = ('risk-analysis/{0}.{1}.json' -f $base, $t)
        }
    }
}

function Restore-SIRaGuardHistory {
    <# Container side, before the run. Loads the template's completeness history from 'sistate'. Never throws.
       Returns the number of files restored (0 = none stored yet, or storage unavailable). #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$SettingsPath, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return 0 }
    $n = 0
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        foreach ($f in @(Get-SIRaGuardHistoryFiles -SettingsPath $SettingsPath -Template $Template)) {
            $blob = $null
            try { $blob = Get-SIAzStorageBlob -Container $script:SIStateContainer -Blob $f.BlobName -Context $ctx -ErrorAction Stop } catch { $blob = $null }
            if (-not $blob) { continue }
            $dir = Split-Path -Parent $f.LocalPath
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
            $tmp = Join-Path $dir ('.guardhistory-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
            try {
                Get-SIAzStorageBlobContent -Container $script:SIStateContainer -Blob $f.BlobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
                $null = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                Move-Item -LiteralPath $tmp -Destination $f.LocalPath -Force
                $n++
            } finally {
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
        }
    } catch {
        Write-Warning ("Could not load the Risk Analysis completeness history from storage account '{0}' ({1}); this run cannot compare its reports with the previous run." -f $AccountName, $_.Exception.Message)
    }
    return $n
}

function Save-SIRaGuardHistory {
    <# Container side, after the run. Saves the template's completeness history to 'sistate'. Never throws.
       Returns the number of files saved. #>
    param([string]$AccountName, [Parameter(Mandatory)][string]$SettingsPath, [Parameter(Mandatory)][string]$Template)
    if ([string]::IsNullOrWhiteSpace($AccountName)) { return 0 }
    $files = @(Get-SIRaGuardHistoryFiles -SettingsPath $SettingsPath -Template $Template | Where-Object { Test-Path -LiteralPath $_.LocalPath })
    if ($files.Count -eq 0) { return 0 }
    $n = 0
    try {
        $ctx = Get-SIRunStateContext -AccountName $AccountName
        if (-not (Get-SIAzStorageContainer -Name $script:SIStateContainer -Context $ctx -ErrorAction SilentlyContinue)) {
            New-SIAzStorageContainer -Name $script:SIStateContainer -Context $ctx -Permission Off -ErrorAction Stop | Out-Null
        }
        foreach ($f in $files) {
            Set-SIAzStorageBlobContent -File $f.LocalPath -Container $script:SIStateContainer -Blob $f.BlobName -Context $ctx -Force -ErrorAction Stop | Out-Null
            $n++
        }
    } catch {
        Write-Warning ("The Risk Analysis completeness history was not saved to storage account '{0}' ({1}); the next run cannot compare its reports with this one." -f $AccountName, $_.Exception.Message)
    }
    return $n
}
