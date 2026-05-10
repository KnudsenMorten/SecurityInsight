Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---- Defensive shims for constrained PS 5.1 runspaces ----------------------
# In SYSTEM-context scheduled tasks, -NoProfile shells, and certain hosts,
# Microsoft.PowerShell.Utility + Microsoft.PowerShell.Security cmdlets fail
# to autoload even though their modules are technically present. Az.Monitor
# (DCR cmdlets), Connect-MicrosoftGraphPS, and others rely on these. Define
# global shims that fall back to direct .NET so engines and downstream
# modules don't blow up. Real cmdlets win when present.

if (-not (Get-Command New-Guid -ErrorAction SilentlyContinue)) {
    function global:New-Guid { [System.Guid]::NewGuid() }
}

if (-not (Get-Command ConvertTo-SecureString -ErrorAction SilentlyContinue)) {
    function global:ConvertTo-SecureString {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position = 0, ValueFromPipeline)] [string]$String,
            [switch]$AsPlainText,
            [switch]$Force
        )
        # Mirrors the common -AsPlainText -Force path that callers actually use.
        # Pure .NET, no module dependency. Don't try to mimic key-based decrypt
        # paths -- callers using -Key/-SecureKey have a real cmdlet path on
        # uncontrained runspaces.
        return [System.Net.NetworkCredential]::new('', $String).SecurePassword
    }
}

# v2.3 layout: Public\ has thematic subfolders (Connect/, Config/, Vault/, Health/)
# plus loose .ps1 files for legacy / not-yet-categorised exports. Walk recursively
# so subfolder files load on Import-Module without needing a per-folder pass.
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "AutomateITPS: failed to load $($file.FullName): $_"
    }
}

# BaseName is the function name (matches one-function-per-file convention).
# Recursive Get-ChildItem returns the same BaseName regardless of subfolder.
Export-ModuleMember -Function $public.BaseName
