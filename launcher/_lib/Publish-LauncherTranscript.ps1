#Requires -Version 5.1
<#
.SYNOPSIS
    Publish a finished launcher transcript to the SI staging blob container.

.DESCRIPTION
    #55.1 -- the transcript mechanism has been built and default-on since
    v2.2.312, but it only produces a durable record on a host with a durable
    filesystem. A Container Apps Job replica's filesystem dies with the replica,
    so the host recommended for LARGE tenants was the one host that kept no
    forensic record of a run at all: stdout survives only until the execution
    ages out of the Container Apps log store, and nothing scraped it.

    This is the (b) half of #55 -- the run log follows the run OUTPUT to the
    same place the operator already goes to fetch it. StagingBlob.ps1 has
    carried engine output there since v2.2; it has never carried logs.

    THREE RULES THIS FILE FOLLOWS, in priority order:

    1. IT NEVER THROWS. A transcript is an explanatory artifact. Failing a
       collection run because its log could not be uploaded trades the
       customer's inventory for their audit trail, which is the wrong way
       round -- same trade the tier-attribution work refused. Every failure
       path warns and returns $null.

    2. IT STOPS THE TRANSCRIPT BEFORE READING THE FILE. Start-Transcript
       buffers, so uploading while the transcript is still open ships a
       truncated file missing exactly the tail an operator wants: the error at
       the end of a failed run. Stopping first is the whole point of doing this
       in a helper rather than inline at each call site.

    3. IT PRUNES ITS OWN BLOBS. Bootstrap-Storage.ps1's lifecycle rule
       ('si-staging-7day-delete') is prefix-scoped to 'sistaging/staging/' and
       therefore does NOT cover this prefix -- verified in that file, not
       assumed. Run logs would accumulate forever otherwise. Retention matches
       the local-disk rule ($global:SI_LogRetentionDays, default 30) so the two
       halves of one feature cannot disagree about how long a run is remembered.

    Deliberately NOT under 'staging/': that prefix is swept at 7 days, which is
    shorter than the 30-day local transcript retention. A forensic record that
    silently outlives its container copy by a different number of days is the
    kind of inconsistency an operator only discovers when they need the log.

.NOTES
    PS 5.1 compatible -- this folder is shared with the VM launchers, which run
    on Windows PowerShell 5.1. No ?. / ?? / ternary.
#>

function Get-SIRunLogBlobName {
    <#
        Pure. The blob name for one transcript. Split out so a test can assert
        the layout without a storage account.

        Layout: <prefix>/<engine>/<original file name>
        The file name already carries engine_flavour[_sim][_template]_<utcStamp>,
        so the per-engine folder is for narrowing a listing, not for identity.
    #>
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter()][string]$Engine,
        [Parameter()][string]$Prefix = 'run-logs'
    )
    $engineSeg = 'unknown'
    if (-not [string]::IsNullOrWhiteSpace($Engine)) {
        $safe = [regex]::Replace($Engine, '[^A-Za-z0-9\-]', '')
        if ($safe) { $engineSeg = $safe.ToLowerInvariant() }
    }
    return ('{0}/{1}/{2}' -f $Prefix.Trim('/'), $engineSeg, $FileName)
}

function Get-SIExpiredRunLogBlob {
    <#
        Pure. Given a blob listing and a cutoff, return the names to delete.
        A function rather than an inline Where-Object so the retention decision
        is executable by a test -- the same reason AUDIT #17 extracted the
        column-population halt.

        A blob with no LastModified is KEPT. Deleting on missing metadata would
        destroy a record because we could not read its age, which is the exact
        inversion of what retention is for.
    #>
    param(
        [Parameter()][object[]]$Blobs,
        [Parameter(Mandatory)][datetime]$Cutoff
    )
    $doomed = New-Object System.Collections.Generic.List[string]
    foreach ($b in @($Blobs)) {
        if ($null -eq $b) { continue }
        if (-not $b.PSObject.Properties['LastModified'] -or $null -eq $b.LastModified) { continue }
        $lm = $null
        try { $lm = ([datetimeoffset]$b.LastModified).UtcDateTime } catch { continue }
        if ($lm -lt $Cutoff) { [void]$doomed.Add([string]$b.Name) }
    }
    return $doomed.ToArray()
}

function New-SIRunLogStorageContext {
    <#
        Build a storage context for the run-log upload from the container's env
        contract (SI_STORAGE_ACCOUNT / SI_STORAGE_KEY / SI_UAMI_CLIENTID), so the
        three container entrypoints do not each carry a copy of this.

        NEVER THROWS and never prompts. Returns $null when storage is not
        configured -- Publish-SILauncherTranscript then warns that the log stays
        on the ephemeral filesystem, which is the honest outcome, not an error.

        Callers that already hold a context (the KEDA worker builds one for the
        shard queue) should pass theirs instead of calling this.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$StorageContextScript = '/app/engine/asset-profiling/storage/StorageContext.ps1'
    )
    try {
        if (-not (Get-Command -Name New-SIStorageContext -ErrorAction SilentlyContinue)) {
            if (-not (Test-Path -LiteralPath $StorageContextScript)) { return $null }
            . $StorageContextScript
        }

        $account = [Environment]::GetEnvironmentVariable('SI_STORAGE_ACCOUNT')
        if ([string]::IsNullOrWhiteSpace($account)) { $account = [string]$global:SI_StorageAccount }
        if ([string]::IsNullOrWhiteSpace($account)) { return $null }

        # Same precedence the entrypoints already use: UAMI when explicitly
        # preferred and present, shared key otherwise.
        $uami      = [Environment]::GetEnvironmentVariable('SI_UAMI_CLIENTID')
        $preferUmi = ([Environment]::GetEnvironmentVariable('SI_PREFER_UAMI')) -in '1','true','True','yes'
        if ($preferUmi -and -not [string]::IsNullOrWhiteSpace($uami)) {
            return (New-SIStorageContext -AccountName $account -UseOAuth)
        }

        $key = [Environment]::GetEnvironmentVariable('SI_STORAGE_KEY')
        if ([string]::IsNullOrWhiteSpace($key)) { $key = [string]$global:SI_StorageKey }
        if ([string]::IsNullOrWhiteSpace($key)) {
            # No key, but a connected account may still work for blob.
            if (-not [string]::IsNullOrWhiteSpace($uami)) { return (New-SIStorageContext -AccountName $account -UseOAuth) }
            return $null
        }
        return (New-SIStorageContext -AccountName $account -AccountKey $key)
    }
    catch {
        Write-Warning ('[run-log] could not build a storage context: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Publish-SILauncherTranscript {
    [CmdletBinding()]
    param(
        # Defaults to the transcript this session started ($global:SI_TranscriptPath).
        [Parameter()][string]$Path,

        # Storage context from New-SIStorageContext (KeyAuth | OAuth | Mock).
        # Required: this function never invents credentials of its own.
        [Parameter()][object]$Context,

        [Parameter()][string]$Engine,
        [Parameter()][string]$ContainerName = 'sistaging',
        [Parameter()][string]$Prefix = 'run-logs',
        [Parameter()][int]$RetentionDays = $(if ($global:SI_LogRetentionDays) { [int]$global:SI_LogRetentionDays } else { 30 })
    )

    # The operator turned transcripts off. Silent -- they know.
    if ($global:SI_DisableTranscript) { return $null }

    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = [string]$global:SI_TranscriptPath }
    # No transcript was started. Start-SILauncherTranscript already warned about
    # whatever went wrong; a second warning here would just be noise.
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    # RULE 2 -- close it before reading it, or the tail is missing.
    if ($global:SI_TranscriptPath -and $global:SI_TranscriptPath -eq $Path) {
        if (Get-Command -Name Stop-SILauncherTranscript -ErrorAction SilentlyContinue) {
            Stop-SILauncherTranscript
        } else {
            try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
            Remove-Variable -Name SI_TranscriptPath -Scope Global -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning ("[run-log] transcript not found at {0} -- nothing to publish." -f $Path)
        return $null
    }

    if ($null -eq $Context) {
        Write-Warning '[run-log] no storage context supplied -- transcript stays on the container filesystem and will be lost when the replica exits.'
        return $null
    }

    $fileName = Split-Path -Leaf $Path
    $blobName = Get-SIRunLogBlobName -FileName $fileName -Engine $Engine -Prefix $Prefix

    # Mock: mirror Write-SIStageShard's contract so the same tests can drive both.
    if ($Context.Mode -eq 'Mock') {
        if (-not $Context.MockState.Blobs.ContainsKey($ContainerName)) {
            $Context.MockState.Blobs[$ContainerName] = @{}
        }
        $Context.MockState.Blobs[$ContainerName][$blobName] = [System.IO.File]::ReadAllText($Path)
        return $blobName
    }

    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        # Ensure the container. Deliberately NOT calling StagingBlob.ps1's
        # Initialize-SIStagingContainer: launcher/_lib must not take a hard
        # dependency on an engine path, and duplicating four lines is the
        # cheaper trade than coupling the two (the solution's own rule about
        # isolation beating DRY, applied inside the solution).
        $existing = Get-AzStorageContainer -Name $ContainerName -Context $Context.AzContext -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-AzStorageContainer -Name $ContainerName -Context $Context.AzContext -Permission Off -ErrorAction Stop | Out-Null
        }

        Set-AzStorageBlobContent -Container $ContainerName -File $Path -Blob $blobName `
            -Context $Context.AzContext -Force -Verbose:$false -ErrorAction Stop | Out-Null
        Write-Host ('[run-log] transcript published -> {0}/{1}' -f $ContainerName, $blobName)
    }
    catch {
        # RULE 1. The run's real work is already done and ingested by this point;
        # losing the log is a degradation, not a failure.
        Write-Warning ('[run-log] could not publish transcript to {0}/{1}: {2}' -f $ContainerName, $blobName, $_.Exception.Message)
        $ProgressPreference = $prevProgress
        return $null
    }

    # RULE 3 -- prune. Best-effort and entirely separate from the upload's
    # success: a failed prune must not report a successful publish as failed.
    if ($RetentionDays -gt 0) {
        try {
            $cutoff  = [datetime]::UtcNow.AddDays(-$RetentionDays)
            $listing = @(Get-AzStorageBlob -Container $ContainerName -Prefix (($Prefix.Trim('/')) + '/') `
                            -Context $Context.AzContext -Verbose:$false -ErrorAction Stop)
            $doomed  = @(Get-SIExpiredRunLogBlob -Blobs $listing -Cutoff $cutoff)
            foreach ($name in $doomed) {
                Remove-AzStorageBlob -Container $ContainerName -Blob $name -Context $Context.AzContext -Force -ErrorAction SilentlyContinue
            }
            if ($doomed.Count -gt 0) {
                Write-Host ('[run-log] retention: removed {0} run log(s) older than {1} day(s).' -f $doomed.Count, $RetentionDays)
            }
        } catch {
            Write-Warning ('[run-log] retention prune skipped: {0}' -f $_.Exception.Message)
        }
    }

    $ProgressPreference = $prevProgress
    return $blobName
}
