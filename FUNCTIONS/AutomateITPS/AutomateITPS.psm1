Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter *.ps1 -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "AutomateITPS: failed to load $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $public.BaseName
