<#
.SYNOPSIS
    Updates this SecurityInsight install to the version its update ring approves -- VM and container installs alike.

.DESCRIPTION
    The Community edition's update. It needs no git.

      1. Reads Invardia's SIGNED Community manifest for this install's ring (3 = broad, the default;
         2 = early release -- set it in config\update.custom.json: { "ring": 2 }).
      2. Verifies it: signed by the SecurityInsight update key this version ships with, for this product and this ring, of
         the major version installed (a new major version is a new installation, never an update),
         never older than what this install already applied, and not held (a release can ask for a manual step first, or
         need a newer starting version -- it then says so and waits).
      3. Downloads the release zip and checks it is exactly the signed one (size and SHA-256).
      4. Applies it: pauses this install's scheduled tasks (a running engine = the update waits for the next run), keeps a
         backup, writes the release, checks the result, and restores the backup on any failure. Your *.custom.* files,
         logs, output and data are never touched. On a container install the new release then rebuilds the engine image
         in your registry and rolls the jobs (and restores the previous image on failure).

    Running it updates when -- and only when -- your ring has a newer release. Schedule it, or let the job flow run it.

.PARAMETER Ring
    Use this ring for this run only (2 or 3). The lasting setting is config\update.custom.json.

.PARAMETER AcceptManualStep
    A release that asks for a manual step is held until you have done it; then re-run with the sequence number it printed.

.PARAMETER ShowReleaseNotes
    After an update, print the release notes of the new version.

.PARAMETER SkipContainerUpdate
    Update the files only; leave the container jobs where they are.

.PARAMETER Apply
    Accepted for compatibility; running the command always applies what the ring approves.

.EXAMPLE
    cd C:\SecurityInsight
    .\Update-SecurityInsight.ps1

.NOTES
    Status: v2.2.152 -- new. 3.0.0 (and the 2.2 hand-over release) -- the signed, ring-gated update channel; no git.
    Developed by Morten Knudsen, Microsoft MVP | https://mortenknudsen.net
#>
[CmdletBinding()]
param(
    [Parameter()] [ValidateSet(0, 2, 3)] [int]$Ring = 0,
    [Parameter()] [long]$AcceptManualStep = -1,
    [Parameter()] [switch]$ShowReleaseNotes,
    [Parameter()] [switch]$SkipContainerUpdate,
    [Parameter()] [switch]$Apply,
    [Parameter(DontShow)] [string]$BaseUrl
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot

Write-Host ''
Write-Host '===================================================================' -ForegroundColor Cyan
Write-Host ' SecurityInsight Updater' -ForegroundColor Cyan
Write-Host '===================================================================' -ForegroundColor Cyan

$client = [IO.Path]::Combine($repoRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')
if (-not (Test-Path -LiteralPath $client)) {
    Write-Host '  [ERR]  the update client (engine\_shared\SI-CommunityUpdate.ps1) is missing -- download the latest release zip from https://github.com/KnudsenMorten/SecurityInsight/releases' -ForegroundColor Red
    exit 1
}
. $client

$p = @{ Root = $repoRoot; Ring = $Ring; AcceptManualStepSequence = $AcceptManualStep; SkipContainerUpdate = $SkipContainerUpdate }
if ($BaseUrl) { $p.BaseUrl = $BaseUrl }
$r = Invoke-SICommunityUpdate @p

foreach ($l in $r.Log) {
    $c = if ($l -match '^(refused|rolledback|error|network):|^WARNING') { 'Red' } elseif ($l -match '^(hold|waiting):|^note:') { 'Yellow' } elseif ($l -match '^(updated|current|none):') { 'Green' } else { 'Gray' }
    Write-Host ("  {0}" -f $l) -ForegroundColor $c
}

if ($r.Action -eq 'updated' -and $ShowReleaseNotes) {
    $rn = [IO.Path]::Combine($repoRoot, 'RELEASENOTES.md')
    if (Test-Path -LiteralPath $rn) {
        Write-Host ''
        Write-Host ("  release notes since v{0}:" -f $r.FromVersion) -ForegroundColor Gray
        $emit = $false
        foreach ($l in [IO.File]::ReadAllLines($rn)) {
            if ($r.FromVersion -and $l -match ('^## v' + [regex]::Escape($r.FromVersion) + '\b')) { break }
            $emit = $emit -or ($l -match '^## v')
            if ($emit) { Write-Host "    $l" -ForegroundColor Gray }
        }
    }
}
if ($r.Action -eq 'updated') { Write-Host ("  Your scheduled engines run v{0} on their next cycle." -f $r.ToVersion) -ForegroundColor Gray }
Write-Host ''
if (@('refused', 'rolledback', 'error', 'network') -contains $r.Action) { exit 1 }
exit 0
