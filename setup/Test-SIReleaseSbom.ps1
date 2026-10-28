#Requires -Version 7.0
<#
.SYNOPSIS
    Checks a SecurityInsight release against its software bill of materials (sbom.cdx.json, CycloneDX).

.DESCRIPTION
    Every signed SecurityInsight release carries a CycloneDX SBOM (SOLUTIONS\SecurityInsight\sbom.cdx.json): the container
    base images, the .NET packages of the web app and the MCP server, and every file of the release with its SHA-256.
    The release archive's SHA-256 is what the signed update manifest names, so the SBOM inside it is covered by that
    signature.

    -Path an archive (securityinsight-src-<version>.zip): -ExpectedSha256 (the signed manifest's value) is checked first,
    then every file in the archive against the SBOM -- a file whose hash differs, a file the SBOM lists that is missing, and
    a file the SBOM does not list are each reported.
    -Path a folder (an installed SecurityInsight folder, which carries sbom.cdx.json): every file the SBOM lists is checked;
    files an install adds itself (logs, customer configuration) are not the release's and are only counted with -Strict.
    Exit 0 = matches, 1 = does not. No module, no network.

.EXAMPLE
    .\setup\Test-SIReleaseSbom.ps1 -Path .\securityinsight-src-3.0.0.zip -ExpectedSha256 <sha-256 from the manifest>
.EXAMPLE
    .\setup\Test-SIReleaseSbom.ps1 -Path C:\SecurityInsight\SOLUTIONS\SecurityInsight
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ExpectedSha256,
    [string]$SbomPath,
    [switch]$Strict,
    [switch]$PassThru,
    [Parameter(DontShow)][switch]$DefineOnly
)

function Test-SIReleaseSbomFiles {
    <# PURE. -Listed / -Found: @{ <relative path> = <sha-256> }. Returns @{ Ok; Changed; Missing; Unlisted }. #>
    param([Parameter(Mandatory)][hashtable]$Listed, [Parameter(Mandatory)][hashtable]$Found, [switch]$Strict)
    $changed = @(); $missing = @(); $unlisted = @()
    foreach ($k in @($Listed.Keys | Sort-Object)) {
        if (-not $Found.ContainsKey($k)) { $missing += $k; continue }
        if ([string]$Found[$k] -ne [string]$Listed[$k]) { $changed += $k }
    }
    foreach ($k in @($Found.Keys | Sort-Object)) { if (-not $Listed.ContainsKey($k)) { $unlisted += $k } }
    $ok = (-not $changed.Count) -and (-not $missing.Count) -and ((-not $Strict) -or -not $unlisted.Count)
    [pscustomobject]@{ Ok = $ok; Changed = $changed; Missing = $missing; Unlisted = $unlisted }
}

function Get-SIReleaseSbomListed {
    <# PURE. The files an SBOM lists: @{ <relative path> = <sha-256> }. #>
    param([Parameter(Mandatory)]$Sbom)
    if ([string]$Sbom.bomFormat -ne 'CycloneDX') { throw 'not a CycloneDX document' }
    $h = @{}
    foreach ($c in @($Sbom.components | Where-Object { $_ -and [string]$_.type -eq 'file' })) {
        $sha = @($c.hashes | Where-Object { [string]$_.alg -eq 'SHA-256' } | ForEach-Object { ([string]$_.content).ToLowerInvariant() }) | Select-Object -First 1
        if ($sha) { $h[[string]$c.name] = $sha }
    }
    $h
}

if ($DefineOnly) { return }
$ErrorActionPreference = 'Stop'
$full = (Resolve-Path -LiteralPath $Path).Path
$found = @{}; $sbomText = $null
if (Test-Path -LiteralPath $full -PathType Leaf) {
    if ($ExpectedSha256) {
        $s = [IO.File]::OpenRead($full); try { $got = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($s)).ToLowerInvariant() } finally { $s.Dispose() }
        if ($got -ne $ExpectedSha256.Trim().ToLowerInvariant()) { Write-Host ("The archive's SHA-256 is {0}, not the signed {1}: this is not the signed release." -f $got, $ExpectedSha256) -ForegroundColor Red; exit 1 }
        Write-Host ('archive SHA-256 matches the signed value ({0})' -f $got)
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($full)
    try {
        foreach ($e in $zip.Entries) {
            $n = $e.FullName.Replace('\', '/'); if ($n.EndsWith('/')) { continue }
            $i = $n.IndexOf('/SOLUTIONS/SecurityInsight/'); if ($i -lt 0) { continue }
            $rel = $n.Substring($i + '/SOLUTIONS/SecurityInsight/'.Length)
            $st = $e.Open()
            try {
                if ($rel -eq 'sbom.cdx.json') { $r = New-Object IO.StreamReader($st); $sbomText = $r.ReadToEnd(); continue }
                $found[$rel] = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($st)).ToLowerInvariant()
            } finally { $st.Dispose() }
        }
    } finally { $zip.Dispose() }
    $Strict = $true   # an archive is the release: a file the SBOM does not list is a difference
} else {
    foreach ($f in Get-ChildItem -LiteralPath $full -Recurse -File -Force) {
        $rel = [IO.Path]::GetRelativePath($full, $f.FullName).Replace('\', '/')
        if ($rel -eq 'sbom.cdx.json') { continue }
        $s = [IO.File]::OpenRead($f.FullName); try { $found[$rel] = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($s)).ToLowerInvariant() } finally { $s.Dispose() }
    }
    $p = if ($SbomPath) { $SbomPath } else { Join-Path $full 'sbom.cdx.json' }
    if (Test-Path -LiteralPath $p) { $sbomText = [IO.File]::ReadAllText($p) }
}
if ($SbomPath -and -not $sbomText) { $sbomText = [IO.File]::ReadAllText($SbomPath) }
if (-not $sbomText) { Write-Host 'No sbom.cdx.json was found (a release from before the SBOM carries none).' -ForegroundColor Yellow; exit 1 }
$listed = Get-SIReleaseSbomListed -Sbom ($sbomText | ConvertFrom-Json)
$r = Test-SIReleaseSbomFiles -Listed $listed -Found $found -Strict:$Strict
Write-Host ('{0} files listed; {1} changed, {2} missing, {3} not listed' -f $listed.Count, $r.Changed.Count, $r.Missing.Count, $r.Unlisted.Count)
foreach ($x in $r.Changed | Select-Object -First 20) { Write-Host ('  changed:    {0}' -f $x) -ForegroundColor Red }
foreach ($x in $r.Missing | Select-Object -First 20) { Write-Host ('  missing:    {0}' -f $x) -ForegroundColor Red }
if ($Strict) { foreach ($x in $r.Unlisted | Select-Object -First 20) { Write-Host ('  not listed: {0}' -f $x) -ForegroundColor Red } }
Write-Host $(if ($r.Ok) { 'The release matches its SBOM.' } else { 'The release does NOT match its SBOM.' }) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
if ($PassThru) { $r }
if (-not $r.Ok) { exit 1 }
