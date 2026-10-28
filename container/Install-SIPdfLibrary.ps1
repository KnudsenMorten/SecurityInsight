#Requires -Version 7.0
<#
.SYNOPSIS
    Image build step (#574): puts the PDF library's managed DLLs (PDFsharp + MigraDoc 6.2.4, MIT) into -Destination.

.DESCRIPTION
    Run by container/Dockerfile and container/updater/Dockerfile while the image is built -- never by a person, never at
    run time. Downloads EXACTLY the packages pinned in engine/_shared/pdf/SI.Pdf.packages.json from nuget.org, refuses any
    package whose SHA-512 differs from the pinned one, and copies only the listed net8.0 DLLs (managed code: no native
    library, no executable, no PowerShell module) plus each package's licence notice. engine/_shared/SI-MailPdf.ps1 loads
    them from there (SI_PDF_LIB). The build fails when a package cannot be fetched or does not match.

.PARAMETER Destination
    The folder for the DLLs (the images use /opt/si/pdf).

.PARAMETER Manifest
    The pinned package list (default: engine/_shared/pdf/SI.Pdf.packages.json next to this script's solution).

.PARAMETER PackageSource
    The NuGet flat container (default https://api.nuget.org/v3-flatcontainer). A folder holding the .nupkg files works too.

.EXAMPLE
    pwsh -NoProfile -File container/Install-SIPdfLibrary.ps1 -Destination /opt/si/pdf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Destination,
    [string]$Manifest,
    [string]$PackageSource = 'https://api.nuget.org/v3-flatcontainer'
)
$ErrorActionPreference = 'Stop'
if (-not $Manifest) { $Manifest = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'pdf', 'SI.Pdf.packages.json') }
$m = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
$fw = [string]$m.framework
$null = New-Item -ItemType Directory -Force -Path $Destination
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$work = Join-Path ([IO.Path]::GetTempPath()) ('si-pdf-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Force -Path $work
$notice = New-Object System.Text.StringBuilder
[void]$notice.AppendLine('SecurityInsight -- third-party components in this folder (the mail PDF library). All MIT licensed.')
try {
    foreach ($p in @($m.packages)) {
        $id = [string]$p.id; $ver = [string]$p.version; $lid = $id.ToLowerInvariant()
        $file = Join-Path $work ('{0}.{1}.nupkg' -f $lid, $ver)
        if ($PackageSource -match '^https://') {
            $uri = '{0}/{1}/{2}/{1}.{2}.nupkg' -f $PackageSource.TrimEnd('/'), $lid, $ver
            Write-Host ("pdf library: {0} {1} <- {2}" -f $id, $ver, $uri)
            Invoke-WebRequest -Uri $uri -OutFile $file -UseBasicParsing -MaximumRetryCount 3 -RetryIntervalSec 5
        } else {
            Copy-Item -LiteralPath (Join-Path $PackageSource ('{0}.{1}.nupkg' -f $lid, $ver)) -Destination $file
        }
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA512).Hash.ToLowerInvariant()
        if ($hash -ne ([string]$p.sha512).ToLowerInvariant()) { throw ("{0} {1}: SHA-512 {2} is not the pinned {3} -- refused" -f $id, $ver, $hash, $p.sha512) }
        $zip = [IO.Compression.ZipFile]::OpenRead($file)
        try {
            foreach ($dll in @($p.dlls)) {
                $entry = $zip.GetEntry(('lib/{0}/{1}' -f $fw, $dll))
                if (-not $entry) { throw ("{0} {1}: lib/{2}/{3} is not in the package" -f $id, $ver, $fw, $dll) }
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Destination $dll), $true)
            }
        } finally { $zip.Dispose() }
        [void]$notice.AppendLine(('- {0} {1} ({2}): {3}' -f $id, $ver, $p.license, (@($p.dlls) -join ', ')))
    }
    [void]$notice.AppendLine('MIT licence text: https://licenses.nuget.org/MIT -- see engine/_shared/pdf/THIRD-PARTY-NOTICES.md.')
    [IO.File]::WriteAllText((Join-Path $Destination 'THIRD-PARTY-NOTICES.txt'), $notice.ToString())
    $bad = @(Get-ChildItem -LiteralPath $Destination -File | Where-Object { $_.Extension -notin '.dll', '.txt' })
    if ($bad.Count) { throw ('only managed DLLs belong in the PDF library folder, found: ' + (($bad | ForEach-Object Name) -join ', ')) }
    Write-Host ("pdf library: {0} DLL(s) in {1}" -f @(Get-ChildItem -LiteralPath $Destination -Filter *.dll).Count, $Destination)
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
