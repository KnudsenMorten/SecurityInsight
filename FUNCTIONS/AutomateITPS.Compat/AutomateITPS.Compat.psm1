Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter *.ps1 -ErrorAction SilentlyContinue)

foreach ($file in $public) {
    try {
        . $file.FullName
    }
    catch {
        throw "AutomateITPS.Compat: failed to load $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $public.BaseName
