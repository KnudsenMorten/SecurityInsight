#Requires -Version 5.1
<#
.SYNOPSIS
    The build identity of this SecurityInsight folder, computed ONCE at build/package time; -OutFile stamps BUILD.json.
.DESCRIPTION
    Thin entry point over engine\_shared\SI-BuildInfo.ps1 (Get-SIBuildInfo), for the image builders and the package
    builders. In a git work tree it reads git; without git it returns what BUILD.json already says.
      .\setup\_shared\Get-SIBuildInfo.ps1                         # print the build
      .\setup\_shared\Get-SIBuildInfo.ps1 -OutFile .\BUILD.json   # stamp it
.PARAMETER SolutionRoot   The SecurityInsight folder (holds VERSION). Default: two levels up from this script.
.PARAMETER OutFile        Write BUILD.json here.
.PARAMETER Channel        The update channel the build is meant for, when known.
.PARAMETER Ring           The ring the build is meant for, when known.
#>
[CmdletBinding()]
param([string]$SolutionRoot, [string]$OutFile, [string]$Channel, $Ring)
if (-not $SolutionRoot) { $SolutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
. ([System.IO.Path]::Combine($SolutionRoot, 'engine', '_shared', 'SI-BuildInfo.ps1'))
$info = Get-SIBuildInfo -SolutionRoot $SolutionRoot -Channel $Channel -Ring $Ring
if ($OutFile) { $null = Write-SIBuildInfo -Info $info -Path $OutFile }
$info
