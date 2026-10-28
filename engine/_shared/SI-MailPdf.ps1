# pwsh 7 (Add-Type on .NET 8); in Windows PowerShell 5.1 the PDF is simply not built and the mail goes without it.
<#
    SECURITYINSIGHT -- THE MAIL PDF (REQUIREMENTS #574; owner: "include pdf file with summary and relavant infp in mails").
    Send-SIMail (SI-MailTransport.ps1) attaches ONE PDF to every mail that reports something: the mail's own content (after
    the #573 layout) -- its summary first, then the facts, lists and tables in the mail's order -- as an A4 PDF. Built by
    the ONE PDF builder, engine/_shared/pdf/SIMailPdf.cs (the web app compiles the same file), compiled here with Add-Type
    against the PDFsharp + MigraDoc DLLs (MIT; container/Install-SIPdfLibrary.ps1 puts them in the images, SI_PDF_LIB).

    A PDF that cannot be built NEVER blocks the mail: New-SIMailPdf returns the reason, Send-SIMail sends without it and
    says so. No PowerShell module, no browser, no native code.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIMailPdfRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:SIMailPdfState = @{ Loaded = $false; Error = $null }

function Get-SIPdfPackageManifest {
    <# The pinned package list (engine/_shared/pdf/SI.Pdf.packages.json). #>
    Get-Content -Raw -LiteralPath ([IO.Path]::Combine($PSScriptRoot, 'pdf', 'SI.Pdf.packages.json')) | ConvertFrom-Json
}

function Find-SIPdfLibrary {
    <#
        Where the PDF DLLs are: @{ Files (name -> path); Missing (names) }. Looked for, per DLL, in: SI_PDF_LIB, /opt/si/pdf
        (the images), engine/_shared/pdf/lib (a local install), then the NuGet package cache (a developer or test machine
        that built the web app: ~/.nuget/packages/<id>/<version>/lib/net8.0).
    #>
    param([string[]]$Dirs)
    $m = Get-SIPdfPackageManifest
    $fw = [string]$m.framework
    $base = @()
    if ($Dirs) { $base += $Dirs }
    if ("$env:SI_PDF_LIB".Trim()) { $base += "$env:SI_PDF_LIB".Trim() }
    $base += '/opt/si/pdf'
    $base += [IO.Path]::Combine($PSScriptRoot, 'pdf', 'lib')
    $nuget = if ("$env:NUGET_PACKAGES".Trim()) { "$env:NUGET_PACKAGES".Trim() } else { [IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), '.nuget', 'packages') }
    $files = [ordered]@{}; $missing = @()
    foreach ($p in @($m.packages)) {
        foreach ($dll in @($p.dlls)) {
            $hit = $null
            foreach ($d in $base) { $c = [IO.Path]::Combine($d, $dll); if (Test-Path -LiteralPath $c) { $hit = $c; break } }
            if (-not $hit) { $c = [IO.Path]::Combine($nuget, ([string]$p.id).ToLowerInvariant(), [string]$p.version, 'lib', $fw, $dll); if (Test-Path -LiteralPath $c) { $hit = $c } }
            if ($hit) { $files[$dll] = $hit } else { $missing += $dll }
        }
    }
    [pscustomobject]@{ Files = $files; Missing = $missing }
}

function Import-SIPdfBuilder {
    <# Loads the PDF DLLs and compiles the ONE builder (SIMailPdf.cs) once per process. $true, or $false with the reason
       in $script:SIMailPdfState.Error. Never throws. #>
    param([string[]]$Dirs)
    if ('SecurityInsight.Pdf.SIMailPdf' -as [type]) { $script:SIMailPdfState.Loaded = $true; return $true }
    try {
        $lib = Find-SIPdfLibrary -Dirs $Dirs
        if (@($lib.Missing).Count) { throw ('the PDF library is not installed (missing: {0}; the images carry it in /opt/si/pdf)' -f (@($lib.Missing) -join ', ')) }
        $loaded = @{}; foreach ($a in [AppDomain]::CurrentDomain.GetAssemblies()) { $loaded[$a.GetName().Name] = $true }
        # dependencies first
        $order = @('Microsoft.Extensions.DependencyInjection.Abstractions.dll', 'Microsoft.Extensions.Logging.Abstractions.dll', 'PdfSharp.Shared.dll', 'PdfSharp.System.dll', 'PdfSharp.dll', 'PdfSharp.Charting.dll', 'MigraDoc.DocumentObjectModel.dll', 'MigraDoc.Rendering.dll')
        foreach ($n in $order) {
            if (-not $lib.Files.Contains($n)) { continue }
            if ($loaded.ContainsKey([IO.Path]::GetFileNameWithoutExtension($n))) { continue }
            $null = [Reflection.Assembly]::LoadFrom([string]$lib.Files[$n])
        }
        $src = [IO.Path]::Combine($PSScriptRoot, 'pdf', 'SIMailPdf.cs')
        # -ReferencedAssemblies replaces Add-Type's default references: the PDF DLLs + .NET's own reference set (pwsh ships it
        # in $PSHOME/ref; without that folder, the runtime's own assemblies)
        $netRefs = @()
        $refDir = [IO.Path]::Combine($PSHOME, 'ref')
        if (Test-Path -LiteralPath $refDir) { $netRefs = @(Get-ChildItem -LiteralPath $refDir -Filter '*.dll' -File | ForEach-Object FullName) }
        else { $netRefs = @(([string][AppContext]::GetData('TRUSTED_PLATFORM_ASSEMBLIES')) -split [IO.Path]::PathSeparator | Where-Object { $_ -match '[\\/](System|Microsoft\.CSharp|netstandard|mscorlib)[^\\/]*\.dll$' }) }
        $refs = @(@($lib.Files.Values | ForEach-Object { [string]$_ }) + $netRefs)
        Add-Type -Path $src -ReferencedAssemblies $refs -IgnoreWarnings -ErrorAction Stop
        $script:SIMailPdfState.Loaded = $true; $script:SIMailPdfState.Error = $null
        return $true
    } catch {
        $script:SIMailPdfState.Error = $_.Exception.Message
        return $false
    }
}

function ConvertTo-SIMailPdfFileName {
    <# PURE. 'SecurityInsight - <subject>.pdf', safe on every file system, at most ~90 characters. #>
    param([string]$Subject)
    $s = ("$Subject" -replace '[\\/:*?"<>|\[\]\r\n\t]+', ' ' -replace '\s+', ' ').Trim(' ', '.', '-')
    if (-not $s) { $s = 'SecurityInsight' }
    if ($s -notmatch '(?i)securityinsight') { $s = 'SecurityInsight - ' + $s }
    if ($s.Length -gt 86) { $s = $s.Substring(0, 86).TrimEnd(' ', '.', '-') }
    $s + '.pdf'
}

function New-SIMailPdf {
    <#
        The PDF of a mail: -Title (the subject), -Html (the body as it is sent). Returns @{ Bytes; Error }; never throws.
        The footer line names SecurityInsight and the environment (-Footer).
    #>
    param([string]$Title, [AllowEmptyString()][string]$Html, [string]$Footer = 'SecurityInsight')
    if (-not (Import-SIPdfBuilder)) { return [pscustomobject]@{ Bytes = $null; Error = [string]$script:SIMailPdfState.Error } }
    try {
        $bytes = [SecurityInsight.Pdf.SIMailPdf]::FromHtml($Title, $Html, $Footer)
        if (-not $bytes -or $bytes.Length -lt 100) { throw 'the PDF came out empty' }
        [pscustomobject]@{ Bytes = $bytes; Error = $null }
    } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        [pscustomobject]@{ Bytes = $null; Error = ('the PDF could not be built: ' + $e.Message) }
    }
}

function Save-SIMailPdf {
    <# Writes the PDF bytes to a fresh temp folder under its mail name; returns the path (Send-SIMail removes it). #>
    param([Parameter(Mandatory)][byte[]]$Bytes, [string]$Subject)
    $dir = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'si-mail-pdf-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Force -Path $dir
    $path = [IO.Path]::Combine($dir, (ConvertTo-SIMailPdfFileName -Subject $Subject))
    [IO.File]::WriteAllBytes($path, $Bytes)
    $path
}
