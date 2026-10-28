<#
.SYNOPSIS
    Shared UNC / Azure Storage blob upload helper for SecurityInsight engines.

.DESCRIPTION
    Dot-source this file then call Send-ExportFile -LocalPath <path> -Destination <url-or-unc>.

    Destination type is AUTO-DETECTED from the prefix:
      \\server\share\subpath\                             -> UNC (Copy-Item)
      https://<acct>.blob.core.windows.net/<container>/... -> Azure Storage blob (Set-AzStorageBlobContent)

    If the destination already holds a file with the same name, the existing copy
    is first renamed to <name>.<yyyy-MM-dd_HHmmss>.<ext>.bak before the new one
    is written. So the canonical path always holds the latest run; older runs
    become timestamped backups next to it.

    Requires the caller to define Write-Info / Write-Ok / Write-Warn functions
    (both RiskAnalysis + IAC engines already do so).

    Auth:
      UNC     -- caller's Windows identity needs write to the share.
      Azure   -- the SPN that ran the engine needs 'Storage Blob Data Contributor'
                 on the destination container (or its parent storage account).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function Send-ExportFile {
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$Destination,
        # Optional -- enables container auto-create + RBAC self-heal for Azure Storage
        [string]$IngestionSpnAppId,      # AAD App (client) ID of the engine's SPN
        [string]$IngestionSpnObjectId,   # SPN ObjectId (optional; resolved from AppId when omitted)
        # #744: the file's blocks already sent while it was written (New-SIExportStagedUpload) -- committed after the backup
        $Staged
    )
    if (-not (Test-Path -LiteralPath $LocalPath)) {
        Write-Warn "  export source not found: $LocalPath -- skipping"
        return
    }
    $fileName = Split-Path -Leaf $LocalPath

    if ($Destination -match '^\\\\') {
        Send-ExportFile-Unc -LocalPath $LocalPath -DestinationDir $Destination -FileName $fileName
    }
    elseif ($Destination -match '^https://([^.]+)\.blob\.core\.windows\.net/([^/]+)/?(.*)$') {
        Send-ExportFile-AzStorage -LocalPath $LocalPath `
            -StorageAccount       $Matches[1] `
            -Container            $Matches[2] `
            -Prefix               $Matches[3].TrimEnd('/') `
            -FileName             $fileName `
            -IngestionSpnAppId    $IngestionSpnAppId `
            -IngestionSpnObjectId $IngestionSpnObjectId `
            -Staged               $Staged
    }
    else {
        Write-Warn ("  unrecognized ExportDestination scheme: '{0}' (expected '\\server\share\path\' or 'https://<acct>.blob.core.windows.net/<container>/[<prefix>/]')" -f $Destination)
    }
}

function Ensure-SecurityInsightStorageContainer {
    <#
    Ensures a blob container exists in the given storage account. If the
    SecurityInsight SPN's ObjectId is supplied, also tries to grant it
    'Storage Blob Data Contributor' on the container (scoped) so future runs
    can read + write without RBAC handholding.

    Requires the CALLER to already have permission to manage the storage
    account (either Owner / Contributor on the storage account, or
    Storage Blob Data Contributor at account scope). If the caller's SPN
    lacks either, we warn clearly and return $false.
    #>
    param(
        [Parameter(Mandatory)] [object] $StorageContext,
        [Parameter(Mandatory)] [string] $StorageAccount,
        [Parameter(Mandatory)] [string] $Container,
        [string] $IngestionSpnObjectId
    )
    # Already present? Done.
    $existing = Get-SIAzStorageContainer -Context $StorageContext -Name $Container -ErrorAction SilentlyContinue
    if ($existing) { return $true }

    Write-Info ("  container '{0}' not found in '{1}' -- creating" -f $Container, $StorageAccount)
    try {
        New-SIAzStorageContainer -Context $StorageContext -Name $Container -ErrorAction Stop | Out-Null
        Write-Ok ("  created container '{0}'" -f $Container)
    } catch {
        Write-Warn ("  container creation failed: {0}" -f $_.Exception.Message)
        Write-Warn ("  Grant the running SPN 'Storage Blob Data Contributor' (data-plane) OR 'Contributor' (management-plane) on the storage account '{0}' and re-run." -f $StorageAccount)
        return $false
    }

    # Best-effort RBAC grant at container scope so the SPN can continue ingesting.
    if ($IngestionSpnObjectId) {
        try {
            $sa = Get-SIAzStorageAccount -ErrorAction SilentlyContinue | Where-Object { $_.StorageAccountName -eq $StorageAccount } | Select-Object -First 1
            if ($sa) {
                $containerScope = "$($sa.Id)/blobServices/default/containers/$Container"
                $already = Get-SIAzRoleAssignment -ObjectId $IngestionSpnObjectId -Scope $containerScope -RoleDefinitionName 'Storage Blob Data Contributor' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Scope -eq $containerScope }
                if (-not $already) {
                    New-SIAzRoleAssignment -ObjectId $IngestionSpnObjectId -RoleDefinitionName 'Storage Blob Data Contributor' -Scope $containerScope -ErrorAction Stop | Out-Null
                    Write-Ok ("  assigned 'Storage Blob Data Contributor' at {0}" -f $containerScope)
                    Write-Info "  waiting 30s for RBAC propagation..."
                    Start-Sleep -Seconds 30
                }
            } else {
                Write-Info ("  storage account '{0}' not visible to current context -- skipping RBAC grant (container was created successfully)" -f $StorageAccount)
            }
        } catch {
            Write-Warn ("  could not assign 'Storage Blob Data Contributor' to SPN: {0}" -f $_.Exception.Message)
            Write-Warn "  The container exists, but the SPN may need RBAC granted manually (caller likely lacks User Access Administrator/Owner on the storage account)."
        }
    }
    return $true
}

function Send-ExportFile-Unc {
    param([string]$LocalPath, [string]$DestinationDir, [string]$FileName)
    try {
        if (-not (Test-Path -LiteralPath $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $destPath = Join-Path $DestinationDir $FileName
        if (Test-Path -LiteralPath $destPath) {
            $stamp      = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            $ext        = [System.IO.Path]::GetExtension($FileName).TrimStart('.')
            $base       = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
            $backupName = "{0}.{1}.{2}.bak" -f $base, $stamp, $ext
            $backupPath = Join-Path $DestinationDir $backupName
            Move-Item -LiteralPath $destPath -Destination $backupPath -Force
            Write-Info ("  backed up existing -> {0}" -f $backupName)
        }
        Copy-Item -LiteralPath $LocalPath -Destination $destPath -Force
        Write-Ok ("  uploaded -> {0}" -f $destPath)
    } catch {
        Write-Warn ("  UNC upload of '{0}' failed: {1}" -f $FileName, $_.Exception.Message)
    }
}

# THE BLOB IS STREAMED, NEVER WHOLE IN MEMORY (a large install 2026-10-13: backing up the previous workbook read it into
# memory and ran out). An upload goes from the file and a backup copy from the blob, one BLOCK at a time (Put Block, then
# Put Block List). The block size is a transfer buffer, not a limit: a file of any size goes up as many blocks (Azure takes
# up to 50,000 per blob, so 8 MB blocks reach ~390 GB); only the blocks in flight are in memory.
#
# #744 SEVERAL BLOCKS AT ONCE, AND THE BACKUP COPY MADE BY AZURE (a large customer 2026-10-17: after "Uploading export
# files" 52 minutes passed without a line -- the previous run's multi-GB JSON file was downloaded and uploaded again as the
# backup, then the new one uploaded, every 4 MB block one request after the other):
#   * up to 4 blocks go up at once (Get-SIExportUploadDegree), each on a worker with the retry rule (429 / 408 / 5xx / no
#     answer: wait, try again); a 401 is sent once more with a fresh token; anything else fails the upload, as before;
#   * the backup copy is made BY THE SERVICE (Put Block From URL, 100 MB ranges, against the source's ETag): nothing of it
#     travels through this machine. A service that refuses it -> the range-by-range copy as before;
#   * the JSON file's blocks go up WHILE it is written (New-SIExportStagedUpload): at the upload step only the backup and
#     the commit are left. If anything of that fails, the file goes up from the disk as before;
#   * a line at least every minute while a file goes up ("export: ... MB of ... MB").
# An Invardia support session (its recording wrapper takes one request at a time), or SI_ExportUpload_Parallel = 1: one
# block at a time through Invoke-SIStorageRequest, exactly as before.
$script:SIExportBlockBytes = 8MB
# one server-side copy request (Put Block From URL takes up to 4000 MiB; 100 MB finishes well inside the request's time limit)
$script:SIExportCopyBlockBytes = 100MB
# a line at least this often while a file goes up
$script:SIExportProgressSeconds = 60
# what the upload workers run: these functions, as they are in this run (a test's fake included), and nothing else
$script:SIExportWorkerFunctions = @('Invoke-SIAzRestHttp', 'Remove-SIAzRestCaughtError')

function Get-SIExportBlockId {
    <# PURE. Block n's id: base64 of a fixed-length name, as Azure requires every id of one blob to have the same length.
       -Tag (the JSON file's blocks sent while it is written): '<tag>-<n>', a tag of its own per run, so two runs never mix. #>
    param([int]$Index, [string]$Tag = '')
    $name = if ($Tag) { '{0}-{1:D6}' -f $Tag, $Index } else { 'blk{0:D6}' -f $Index }
    [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($name))
}

function Get-SIExportUploadDegree {
    <# PURE over the setting. Blocks in flight at once: 4. SI_ExportUpload_Parallel (global) or the environment variable
       SI_EXPORTUPLOAD_PARALLEL: 1 / 0 / off = one at a time (as before); a number = that many, at most 8. #>
    param($Setting = $(Get-Variable -Scope Global -Name SI_ExportUpload_Parallel -ValueOnly -ErrorAction Ignore), [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_EXPORTUPLOAD_PARALLEL)
    $s = if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '') { ([string]$Setting).Trim() } elseif ($EnvValue) { $EnvValue.Trim() } else { '' }
    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
    $n = 0
    if ($s -ne '' -and [int]::TryParse($s, [ref]$n)) { if ($n -le 1) { return 1 }; return [Math]::Min(8, $n) }
    4
}

function Test-SIExportServerCopy {
    <# PURE over the setting. The backup copy made by the service (on unless SI_ExportServerCopy = off / false / 0). #>
    param($Setting = $(Get-Variable -Scope Global -Name SI_ExportServerCopy -ValueOnly -ErrorAction Ignore))
    if ($null -eq $Setting -or ([string]$Setting).Trim() -eq '') { return $true }
    -not (([string]$Setting).Trim() -match '^(?i)(off|false|no|0|disabled?)$')
}

function Write-SIExportLine {
    param([string]$Text)
    if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $Text } else { Write-Host $Text }
}

function Get-SIExportWorkerScript {
    <# The worker: ONE storage request with the retry rule (working rule 4): 429 / 408 / 5xx / no answer -> wait (the
       service's Retry-After, else 2, 4, 8 ... s, at most 60) and try again; any other answer is returned as it is. #>
    @'
param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [int]$MaxAttempts)
for ($attempt = 1; ; $attempt++) {
    $Headers['x-ms-date'] = [datetime]::UtcNow.ToString('R')
    $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/octet-stream'
    $code = [int]$r.StatusCode
    $err = ''; if ($r.Headers -and $r.Headers['x-ms-error-code']) { $err = [string]$r.Headers['x-ms-error-code'] }
    if ($code -ge 200 -and $code -lt 300) { return @{ Code = $code; Attempts = $attempt; Content = ''; ErrorCode = '' } }
    $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
    if (-not $transient -or $attempt -ge $MaxAttempts) { return @{ Code = $code; Attempts = $attempt; Content = [string]$r.Content; ErrorCode = $err } }
    $wait = 0
    if (-not [int]::TryParse([string]$r.RetryAfter, [ref]$wait) -or $wait -le 0) { $wait = [int][Math]::Pow(2, $attempt) }
    Start-Sleep -Seconds ([Math]::Min(60, $wait))
}
'@
}

function New-SIExportRequestPool {
    <# The workers of one upload (-Degree at once; 1 = in line, through Invoke-SIStorageRequest, as before). #>
    param([int]$Degree = 0, [int]$MaxAttempts = 6)
    if ($Degree -le 0) { $Degree = Get-SIExportUploadDegree }
    # an Invardia support session: every request goes through its recording wrapper, in line
    if ($Degree -gt 1 -and (Get-Command -Name Test-SISupportRequestRoute -ErrorAction SilentlyContinue) -and (Test-SISupportRequestRoute -Audience Storage)) { $Degree = 1 }
    $p = @{ Degree = $Degree; Pool = $null; InFlight = (New-Object 'System.Collections.Generic.List[object]'); Failed = $null; Done = 0L; Sent = 0L
            MaxAttempts = $MaxAttempts; Script = (Get-SIExportWorkerScript) }
    if ($Degree -gt 1) {
        # the worker's environment: the HTTP seam as it is in this run, the functions it calls, and $SIExportSeam (a test's
        # shared state, $null in a real run). Never a script block of this runspace: a worker runs only text it was given.
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        foreach ($fn in $script:SIExportWorkerFunctions) {
            $def = (Get-Command -Name $fn -CommandType Function -ErrorAction Stop).Definition
            $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def)))
        }
        $seam = Get-Variable -Scope Global -Name SIExportSeam -ValueOnly -ErrorAction Ignore
        $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('SIExportSeam', $seam, '')))
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Degree, $iss, $Host)
        $pool.Open()
        $p.Pool = $pool
    }
    $p
}

function Send-SIExportPoolRequest {
    <#
        One storage request of an upload: -Request @{ Method; Uri; Headers; Body; What }. In line (one at a time) through
        Invoke-SIStorageRequest; with workers it is handed to one, waiting first while -Degree are in flight. A failure is
        recorded on the pool (.Failed, the first one) and nothing more is sent after it.
    #>
    param([Parameter(Mandatory)][hashtable]$Pool, [Parameter(Mandatory)][hashtable]$Request)
    while ($Pool.InFlight.Count -ge [Math]::Max(1, $Pool.Degree)) { Receive-SIExportPoolResults -Pool $Pool -WaitOne }
    if ($Pool.Failed) { return }
    $Pool.Sent++
    if ($null -eq $Pool.Pool) {
        try {
            $null = Invoke-SIStorageRequest -Method $Request.Method -Uri $Request.Uri -Body $Request.Body -ContentType 'application/octet-stream' -Headers $Request.Headers -What $Request.What
            $Pool.Done++
        } catch { if (-not $Pool.Failed) { $Pool.Failed = [string]$_.Exception.Message } }
        return
    }
    $token = Get-SIAzureToken -Audience Storage -ForceRefresh:([bool]$Request.Refresh)
    $h = @{ 'Authorization' = ('Bearer ' + $token); 'x-ms-version' = (Get-SIStorageApiVersion); 'x-ms-date' = [datetime]::UtcNow.ToString('R') }
    if ($Request.Headers) { foreach ($k in $Request.Headers.Keys) { $h[$k] = $Request.Headers[$k] } }
    $ps = [powershell]::Create()
    $ps.RunspacePool = $Pool.Pool
    [void]$ps.AddScript($Pool.Script).AddArgument([string]$Request.Method).AddArgument([string]$Request.Uri).AddArgument($h).AddArgument($Request.Body).AddArgument($Pool.MaxAttempts)
    $Request.PS = $ps
    $Request.Handle = $ps.BeginInvoke()
    [void]$Pool.InFlight.Add($Request)
}

function Receive-SIExportPoolResults {
    <# The answers of the requests that finished; -WaitOne waits for at least one (when any is in flight); -All for all.
       2xx = done; 401 = sent once more with a fresh token; anything else = the upload has FAILED (the service's words). #>
    param([Parameter(Mandatory)][hashtable]$Pool, [switch]$WaitOne, [switch]$All)
    while ($Pool.InFlight.Count -gt 0) {
        $done = @($Pool.InFlight | Where-Object { $_.Handle.IsCompleted })
        if ($done.Count -eq 0) {
            if (-not $WaitOne -and -not $All) { return }
            $handles = [System.Threading.WaitHandle[]]@($Pool.InFlight | ForEach-Object { $_.Handle.AsyncWaitHandle } | Select-Object -First 64)
            [void][System.Threading.WaitHandle]::WaitAny($handles, 1000)
            continue
        }
        foreach ($b in $done) { [void]$Pool.InFlight.Remove($b) }
        foreach ($b in $done) {
            $res = $null
            try { $res = @($b.PS.EndInvoke($b.Handle)) | ForEach-Object { $_.psobject.BaseObject } | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1 }
            catch { $res = @{ Code = 0; Content = $_.Exception.Message; ErrorCode = '' } }
            finally { try { $b.PS.Dispose() } catch { }; $b.PS = $null; $b.Handle = $null }
            if (-not ($res -is [hashtable])) { $res = @{ Code = 0; Content = 'the request''s worker returned no answer'; ErrorCode = '' } }
            $code = [int]$res.Code
            if ($code -ge 200 -and $code -lt 300) { $Pool.Done++; continue }
            if ($code -eq 401 -and -not $b.Refresh -and -not $Pool.Failed) {
                $b.Refresh = $true
                try { Send-SIExportPoolRequest -Pool $Pool -Request $b } catch { if (-not $Pool.Failed) { $Pool.Failed = [string]$_.Exception.Message } }
                continue
            }
            if (-not $Pool.Failed) {
                $ec = if ($res.ErrorCode) { ' ' + [string]$res.ErrorCode } else { '' }
                $Pool.Failed = ("{0} failed. HTTP Status: {1}{2} Response: {3}" -f $b.What, $code, $ec, [string]$res.Content)
            }
        }
        if ($WaitOne -and -not $All) { return }
    }
}

function Close-SIExportRequestPool {
    param([hashtable]$Pool)
    if ($null -eq $Pool) { return }
    foreach ($b in $Pool.InFlight.ToArray()) { try { if ($b.PS) { $b.PS.Stop(); $b.PS.Dispose() } } catch { } }
    $Pool.InFlight.Clear()
    if ($Pool.Pool) { try { $Pool.Pool.Close(); $Pool.Pool.Dispose() } catch { }; $Pool.Pool = $null }
}

function Send-SIExportBlock {
    param([string]$Account, [string]$Container, [string]$Blob, [string]$Id, [byte[]]$Bytes)
    $null = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob") -Query ('comp=block&blockid=' + [uri]::EscapeDataString($Id))) `
        -Body $Bytes -ContentType 'application/octet-stream' -What ("Upload a block of '{0}/{1}'" -f $Container, $Blob)
}

function New-SIExportBlockRequest {
    <# PURE. The Put Block request of one block (Send-SIExportPoolRequest's -Request). #>
    param([string]$Account, [string]$Container, [string]$Blob, [string]$Id, [byte[]]$Bytes)
    @{ Method = 'PUT'; Uri = (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob") -Query ('comp=block&blockid=' + [uri]::EscapeDataString($Id)))
       Headers = @{}; Body = $Bytes; What = ("Upload a block of '{0}/{1}'" -f $Container, $Blob) }
}

function Complete-SIExportBlockList {
    <# Commits the blocks, in order, as the blob's content (Put Block List). Returns the new ETag. #>
    param([string]$Account, [string]$Container, [string]$Blob, [string[]]$Ids, [string]$ContentType = 'application/octet-stream')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="utf-8"?><BlockList>')
    foreach ($id in $Ids) { [void]$sb.Append('<Latest>').Append($id).Append('</Latest>') }
    [void]$sb.Append('</BlockList>')
    if (-not $ContentType) { $ContentType = 'application/octet-stream' }
    $r = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob") -Query 'comp=blocklist') -Body $sb.ToString() `
        -ContentType 'application/xml' -Headers @{ 'x-ms-blob-content-type' = $ContentType } -What ("Commit the blocks of '{0}/{1}'" -f $Container, $Blob)
    [string]$r.Headers['ETag']
}

function Send-SIExportBlockBlob {
    <# Uploads -File as a block blob, read from the file one block at a time, up to -Degree blocks in flight (#744). An
       empty file is one empty upload. A line at least every minute. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob, [Parameter(Mandatory)][string]$File, [int]$Degree = 0)
    $len = (Get-Item -LiteralPath $File).Length
    if ($len -eq 0) { return (Set-SIBlobContent -Account $Account -Container $Container -Blob $Blob -Bytes ([byte[]]::new(0))) }
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $pool = New-SIExportRequestPool -Degree $Degree
    $clock = [System.Diagnostics.Stopwatch]::StartNew(); $said = 0.0; $sent = 0L
    $fs = [System.IO.File]::OpenRead($File)
    try {
        $size = [int]$script:SIExportBlockBytes
        while ($true) {
            # a buffer of its own per block (the blocks in flight are still being sent); fill it (a read may return less
            # than asked before the end of the file)
            $buf = [byte[]]::new($size)
            $n = 0
            while ($n -lt $buf.Length) { $r = $fs.Read($buf, $n, $buf.Length - $n); if ($r -le 0) { break }; $n += $r }
            if ($n -le 0) { break }
            [byte[]]$body = $null
            if ($n -eq $buf.Length) { $body = $buf } else { $body = [byte[]]::new($n); [Array]::Copy($buf, $body, $n) }
            $buf = $null
            $id = Get-SIExportBlockId -Index $ids.Count
            Send-SIExportPoolRequest -Pool $pool -Request (New-SIExportBlockRequest -Account $Account -Container $Container -Blob $Blob -Id $id -Bytes $body)
            if ($pool.Failed) { throw $pool.Failed }
            [void]$ids.Add($id)
            $sent += $n; $body = $null
            if ($clock.Elapsed.TotalSeconds - $said -ge $script:SIExportProgressSeconds) {
                $said = $clock.Elapsed.TotalSeconds
                Write-SIExportLine ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '  export: {0} -- {1:N0} MB of {2:N0} MB sent', $Blob, ($sent / 1MB), ($len / 1MB)))
            }
            if ($n -lt $size) { break }
        }
        Receive-SIExportPoolResults -Pool $pool -All
        if ($pool.Failed) { throw $pool.Failed }
    } finally { $fs.Dispose(); Close-SIExportRequestPool -Pool $pool }
    Complete-SIExportBlockList -Account $Account -Container $Container -Blob $Blob -Ids $ids.ToArray()
}

function Copy-SIExportBlobServerSide {
    <#
        #744: the backup copy made BY THE SERVICE -- Put Block From URL, one range of -SrcBlob (100 MB) per block of
        -DestBlob, every range read against the source's ETag (a source that changes during the copy fails it, never a
        backup of two versions), up to -Degree at once, then the blocks committed with the source's content type. Nothing
        of the blob travels through this machine. Returns $true when copied (or nothing to copy), $false when the service
        refused (the caller then copies range by range -- the first range is answered before any other is sent, so a
        service that does not take it costs one request).
    #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$SrcBlob, [Parameter(Mandatory)][string]$DestBlob, [int]$Degree = 0)
    $p = Get-SIBlobProperties -Account $Account -Container $Container -Blob $SrcBlob
    if (-not $p) { return $true }
    $len = [long]$p.Length
    if ($len -le 0) { $null = Set-SIBlobContent -Account $Account -Container $Container -Blob $DestBlob -Bytes ([byte[]]::new(0)); return $true }
    $src = Get-SIStorageUri -Account $Account -Path ("$Container/$SrcBlob")
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $pool = New-SIExportRequestPool -Degree $Degree
    try {
        $off = 0L
        while ($off -lt $len) {
            $end = [Math]::Min($len, $off + [long]$script:SIExportCopyBlockBytes) - 1
            $id = Get-SIExportBlockId -Index $ids.Count
            # the source is read as this run's identity (a bearer token for the source, the same audience)
            $h = @{ 'x-ms-copy-source' = $src; 'x-ms-source-range' = ('bytes={0}-{1}' -f $off, $end)
                    'x-ms-copy-source-authorization' = ('Bearer ' + (Get-SIAzureToken -Audience Storage)) }
            if ($p.ETag) { $h['x-ms-source-if-match'] = [string]$p.ETag }
            Send-SIExportPoolRequest -Pool $pool -Request @{ Method = 'PUT'; Uri = (Get-SIStorageUri -Account $Account -Path ("$Container/$DestBlob") -Query ('comp=block&blockid=' + [uri]::EscapeDataString($id)))
                                                           Headers = $h; Body = $null; What = ("Copy a range of '{0}/{1}' in Azure" -f $Container, $SrcBlob) }
            [void]$ids.Add($id)
            if ($ids.Count -eq 1) { Receive-SIExportPoolResults -Pool $pool -All }
            if ($pool.Failed) { break }
            $off = $end + 1
        }
        Receive-SIExportPoolResults -Pool $pool -All
        if ($pool.Failed) {
            if (Get-Command -Name Write-Diag -ErrorAction SilentlyContinue) { Write-Diag ("the backup copy made in Azure was refused ({0}); it is copied range by range instead" -f $pool.Failed) }
            return $false
        }
    } finally { Close-SIExportRequestPool -Pool $pool }
    $null = Complete-SIExportBlockList -Account $Account -Container $Container -Blob $DestBlob -Ids $ids.ToArray() -ContentType ([string]$p.ContentType)
    $true
}

function Copy-SIExportBlobInBlocks {
    <#
        Copies a blob to another name in the same container. #744: by the service first (Copy-SIExportBlobServerSide); when
        it refuses -- or SI_ExportServerCopy = off -- one range at a time through this machine (Get Blob with x-ms-range ->
        Put Block), then the blocks committed. Every range is read against the source's ETag: a source that changes during
        the copy fails the copy (412) instead of giving a backup of two versions. A missing source copies nothing.
    #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$SrcBlob, [Parameter(Mandatory)][string]$DestBlob)
    if (Test-SIExportServerCopy) {
        if (Copy-SIExportBlobServerSide -Account $Account -Container $Container -SrcBlob $SrcBlob -DestBlob $DestBlob) { return }
    }
    $p = Get-SIBlobProperties -Account $Account -Container $Container -Blob $SrcBlob
    if (-not $p) { return }
    $len = [long]$p.Length
    if ($len -le 0) { $null = Set-SIBlobContent -Account $Account -Container $Container -Blob $DestBlob -Bytes ([byte[]]::new(0)); return }
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $off = 0L
    while ($off -lt $len) {
        $end = [Math]::Min($len, $off + [long]$script:SIExportBlockBytes) - 1
        $h = @{ 'x-ms-range' = ('bytes={0}-{1}' -f $off, $end) }
        if ($p.ETag) { $h['If-Match'] = [string]$p.ETag }
        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$SrcBlob")) -Headers $h -AsBytes -What ("Read a range of '{0}/{1}'" -f $Container, $SrcBlob)
        [byte[]]$body = $r.Bytes
        $r = $null
        $want = $end - $off + 1
        if ($null -eq $body -or $body.Length -ne $want) { throw ("the backup copy of '{0}' read {1} of {2} byte(s) at offset {3}" -f $SrcBlob, $(if ($null -eq $body) { 0 } else { $body.Length }), $want, $off) }
        $id = Get-SIExportBlockId -Index $ids.Count
        Send-SIExportBlock -Account $Account -Container $Container -Blob $DestBlob -Id $id -Bytes $body
        [void]$ids.Add($id)
        $body = $null
        $off = $end + 1
    }
    $null = Complete-SIExportBlockList -Account $Account -Container $Container -Blob $DestBlob -Ids $ids.ToArray() -ContentType ([string]$p.ContentType)
}

# ---------------------------------------------------------------------------------------------------------------------
#  #744 THE JSON FILE'S BLOCKS GO UP WHILE IT IS WRITTEN (Write-RAJsonArrayFile -Upload, RA-Delivery.ps1)
#
#  Every byte written to the local file is also added here, in order; each time ~8 MB are waiting they go up as one block
#  (Put Block, uncommitted: the blob's content does not change). At the upload step (Send-ExportFile -Staged) the existing
#  blob is backed up and the blocks are COMMITTED -- the blob then holds exactly the local file's bytes. Any failure while
#  writing stops the staging (said once, never fails the file); the upload step then sends the file from the disk as before.
#  Memory: the blocks in flight (-Degree) and the one being filled.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIExportBlobTarget {
    <# PURE. An Azure Storage export destination + file name -> @{ Account; Container; Blob } ($null for any other destination). #>
    param([string]$Destination, [string]$FileName)
    if ([string]$Destination -notmatch '^https://([^.]+)\.blob\.core\.windows\.net/([^/]+)/?(.*)$') { return $null }
    $prefix = $Matches[3].TrimEnd('/')
    @{ Account = $Matches[1]; Container = $Matches[2]; Blob = $(if ($prefix) { ($prefix.Trim('/') + '/' + $FileName) } else { $FileName }) }
}

function New-SIExportStagedUpload {
    <# A staged upload of -FileName to -Destination ($null when the destination is not Azure Storage). #>
    param([string]$Destination, [Parameter(Mandatory)][string]$FileName, [int]$Degree = 0)
    $t = Get-SIExportBlobTarget -Destination $Destination -FileName $FileName
    if ($null -eq $t) { return $null }
    @{ Account = $t.Account; Container = $t.Container; Blob = $t.Blob; Tag = [guid]::NewGuid().ToString('N').Substring(0, 8)
       Ids = (New-Object 'System.Collections.Generic.List[string]'); Pool = (New-SIExportRequestPool -Degree $Degree)
       Buffer = (New-Object System.IO.MemoryStream); BlockBytes = [long]$script:SIExportBlockBytes; Bytes = 0L; Failed = $null; Ready = $false }
}

function Send-SIExportStagedBlock {
    param([Parameter(Mandatory)][hashtable]$Upload)
    $body = $Upload.Buffer.ToArray()
    $Upload.Buffer.SetLength(0)
    $id = Get-SIExportBlockId -Index $Upload.Ids.Count -Tag $Upload.Tag
    Send-SIExportPoolRequest -Pool $Upload.Pool -Request (New-SIExportBlockRequest -Account $Upload.Account -Container $Upload.Container -Blob $Upload.Blob -Id $id -Bytes $body)
    [void]$Upload.Ids.Add($id)
    if ($Upload.Pool.Failed) { throw $Upload.Pool.Failed }
}

function Stop-SIExportStagedUpload {
    <# Staging stops (the upload step sends the file from the disk instead). Said once. Never throws. #>
    param($Upload, [string]$Why)
    if ($null -eq $Upload) { return }
    if (-not $Upload.Failed) {
        $Upload.Failed = if ($Why) { $Why } else { 'stopped' }
        Write-SIExportLine ("  export: the file's blocks are not sent while it is written ({0}) -- it is uploaded from the disk at the upload step instead" -f $Upload.Failed)
    }
    $Upload.Ready = $false
    try { Close-SIExportRequestPool -Pool $Upload.Pool } catch { }
    try { $Upload.Buffer.Dispose() } catch { }
}

function Add-SIExportStagedBytes {
    <# Adds the next -Count bytes of the file. Never throws: a failure stops the staging (Stop-SIExportStagedUpload). #>
    param($Upload, [Parameter(Mandatory)][byte[]]$Bytes, [int]$Count = -1)
    if ($null -eq $Upload -or $Upload.Failed) { return }
    if ($Count -lt 0) { $Count = $Bytes.Length }
    try {
        $Upload.Buffer.Write($Bytes, 0, $Count)
        $Upload.Bytes += $Count
        if ($Upload.Buffer.Length -ge $Upload.BlockBytes) { Send-SIExportStagedBlock -Upload $Upload }
    } catch { Stop-SIExportStagedUpload -Upload $Upload -Why $_.Exception.Message }
}

function Complete-SIExportStagedUpload {
    <# The end of the file: the last block sent and every block answered. $true = ready to commit at the upload step. #>
    param($Upload)
    if ($null -eq $Upload -or $Upload.Failed) { return $false }
    try {
        if ($Upload.Buffer.Length -gt 0) { Send-SIExportStagedBlock -Upload $Upload }
        Receive-SIExportPoolResults -Pool $Upload.Pool -All
        if ($Upload.Pool.Failed) { throw $Upload.Pool.Failed }
        $Upload.Ready = $true
    } catch { Stop-SIExportStagedUpload -Upload $Upload -Why $_.Exception.Message; return $false }
    finally { try { Close-SIExportRequestPool -Pool $Upload.Pool } catch { }; try { $Upload.Buffer.Dispose() } catch { } }
    $true
}

function Send-ExportFile-AzStorage {
    param(
        [string]$LocalPath,
        [string]$StorageAccount,
        [string]$Container,
        [string]$Prefix,
        [string]$FileName,
        [string]$IngestionSpnAppId,
        [string]$IngestionSpnObjectId,
        $Staged
    )
    try {
        # Storage over plain REST with the run's identity (OAuth) -- no PowerShell module.

        $ctx = New-SIAzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount

        # Resolve SPN ObjectId once (for container RBAC grant) -- optional
        if (-not $IngestionSpnObjectId -and $IngestionSpnAppId) {
            try {
                $spn = Get-SIAzADServicePrincipal -ApplicationId $IngestionSpnAppId -ErrorAction SilentlyContinue
                if ($spn) { $IngestionSpnObjectId = [string]$spn.Id }
            } catch { }
        }

        # Ensure container exists (creates + best-effort RBAC grant if missing)
        $ok = Ensure-SecurityInsightStorageContainer -StorageContext $ctx -StorageAccount $StorageAccount -Container $Container -IngestionSpnObjectId $IngestionSpnObjectId
        if (-not $ok) { return }

        $blobName = if ($Prefix) { ($Prefix.Trim('/') + '/' + $FileName) } else { $FileName }

        $existing = Get-SIAzStorageBlob -Context $ctx -Container $Container -Blob $blobName -ErrorAction SilentlyContinue
        if ($existing) {
            $stamp      = Get-Date -Format 'yyyy-MM-dd_HHmmss'
            $ext        = [System.IO.Path]::GetExtension($FileName).TrimStart('.')
            $base       = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
            $backupName = if ($Prefix) { ($Prefix.Trim('/') + '/' + ("{0}.{1}.{2}.bak" -f $base, $stamp, $ext)) } else { ("{0}.{1}.{2}.bak" -f $base, $stamp, $ext) }
            # one block at a time, never the whole previous workbook in memory (a large install 2026-10-13 ran out of memory here)
            Copy-SIExportBlobInBlocks -Account $StorageAccount -Container $Container -SrcBlob $blobName -DestBlob $backupName
            Write-Info ("  backed up existing -> {0}" -f $backupName)
        }

        # #744: the blocks sent while the file was written -- committed now, when they are this file's, all of it
        if ($Staged -and $Staged.Ready -and $Staged.Account -eq $StorageAccount -and $Staged.Container -eq $Container -and $Staged.Blob -eq $blobName -and
            [long]$Staged.Bytes -eq [long](Get-Item -LiteralPath $LocalPath).Length) {
            try {
                $null = Complete-SIExportBlockList -Account $StorageAccount -Container $Container -Blob $blobName -Ids $Staged.Ids.ToArray()
                Write-Ok ("  uploaded -> https://{0}.blob.core.windows.net/{1}/{2} (sent while it was written)" -f $StorageAccount, $Container, $blobName)
                return
            } catch {
                Write-Info ("  the blocks sent while the file was written could not be committed ({0}) -- it is uploaded from the disk instead" -f $_.Exception.Message)
            }
        }

        # from the file, one block at a time
        $null = Send-SIExportBlockBlob -Account $StorageAccount -Container $Container -Blob $blobName -File $LocalPath
        Write-Ok ("  uploaded -> https://{0}.blob.core.windows.net/{1}/{2}" -f $StorageAccount, $Container, $blobName)
    } catch {
        Write-Warn ("  Azure Storage upload of '{0}' failed: {1} (Storage Blob Data Contributor on the container required for the SecurityInsight SPN)" -f $FileName, $_.Exception.Message)
    }
}
