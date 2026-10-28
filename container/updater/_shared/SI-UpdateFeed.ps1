#Requires -Version 5.1
<#
    SecurityInsight -- RELEASE ARCHIVE helpers shared by the updater (container/updater) and the release step
    (setup/Publish-SIRelease.ps1): the archive's shape and VERSION, the template-pack file names and the sha256sum line.
    Pure; no network.

    (SI's own update FEED -- a storage container with a read-only link, channel.json and the publish / access scripts -- is
    RETIRED, 2026-10-06: "one solution: invardia". Nothing here reads a feed.)
#>

function Format-SIFeedChecksum {
    <# PURE. The .sha256 file's content, exactly as sha256sum writes it: "<hex>  <file name>" and a line feed. #>
    param([Parameter(Mandatory)][string]$Hash, [Parameter(Mandatory)][string]$ArchiveName)
    if ($Hash -notmatch '^[0-9a-fA-F]{64}$') { throw "not a SHA-256 hash: '$Hash'" }
    ('{0}  {1}' -f $Hash.ToLowerInvariant(), $ArchiveName) + "`n"
}

function Get-SIFeedTemplatePackNames {
    <# The two blobs of one template pack: the pack and its sha256sum line. #>
    param([Parameter(Mandatory)][string]$PackVersion)
    $v = "$PackVersion".Trim()
    if ($v.Length -gt 32 -or $v -notmatch '^\d{1,6}(\.\d{1,12}){1,5}$') { throw "not a template pack version: '$PackVersion'" }
    [pscustomobject]@{ Pack = "si-templates-$v.json"; Sha = "si-templates-$v.json.sha256" }
}

function Test-SIFeedArchiveShape {
    <#
      A release archive the updater can use: one wrapping folder, SOLUTIONS/SecurityInsight/ under it, and a
      VERSION file there. Returns @{ Ok; Reason; Files; Version }. Checked at PUBLISH time, in a second --
      the alternative is an updater that fails in a customer tenant at 02:00.
    #>
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $files = 0; $version = $null; $tops = @{}; $display = $null; $commit = ''
        foreach ($e in $zip.Entries) {
            $name = $e.FullName -replace '\\', '/'
            $i = $name.IndexOf('/'); if ($i -lt 0) { continue }
            $tops[$name.Substring(0, $i)] = $true
            $rel = $name.Substring($i + 1)
            if (-not $rel.StartsWith('SOLUTIONS/SecurityInsight/') -or $rel.EndsWith('/')) { continue }
            $files++
            if ($rel -eq 'SOLUTIONS/SecurityInsight/VERSION') {
                $r = New-Object System.IO.StreamReader($e.Open())
                try { $version = $r.ReadToEnd().Trim() } finally { $r.Dispose() }
            }
            if ($rel -eq 'SOLUTIONS/SecurityInsight/BUILD.json') {
                # #350: the build the archive was packed from (SI-BuildInfo.ps1) -- its display names a pre-release (3.0.0-rc.42)
                $r = New-Object System.IO.StreamReader($e.Open())
                try {
                    $j = $r.ReadToEnd().TrimStart([char]0xFEFF) | ConvertFrom-Json
                    if ("$($j.display)".Trim()) { $display = "$($j.display)".Trim() }
                    $commit = "$($j.commit)".Trim().ToLowerInvariant()
                } catch { } finally { $r.Dispose() }
            }
        }
        if ($tops.Count -ne 1) { return [pscustomobject]@{ Ok = $false; Reason = "expected ONE wrapping folder, found $($tops.Count)"; Files = $files; Version = $version; Display = $display; Commit = $commit } }
        if ($files -eq 0)      { return [pscustomobject]@{ Ok = $false; Reason = 'no SOLUTIONS/SecurityInsight/ files in the archive'; Files = 0; Version = $null; Display = $null; Commit = '' } }
        if (-not $version)     { return [pscustomobject]@{ Ok = $false; Reason = 'SOLUTIONS/SecurityInsight/VERSION is missing'; Files = $files; Version = $null; Display = $display; Commit = $commit } }
        # Display = the build (BUILD.json) when the archive carries one, else the VERSION: what a ring channel names
        [pscustomobject]@{ Ok = $true; Reason = ''; Files = $files; Version = $version; Display = $(if ($display) { $display } else { $version }); Commit = $commit }
    } finally { $zip.Dispose() }
}

