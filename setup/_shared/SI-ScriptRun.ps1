#Requires -Version 5.1
<#
    EVERY SCRIPT A PERSON RUNS (framework DOCS/REQUIREMENTS.md section 12.7 SCRIPT-DOC-1 + section 12.10 SECURITY-PACK-1; SI #481 / #484).
    One helper, called first by each such script:

      $siRun = Start-SIScriptRun -Script '<Script>'
      try { ...the script... } finally { Stop-SIScriptRun -Run $siRun }

    Start-SIScriptRun prints, as the script's FIRST line (SI #547, owner 2026-10-10: "do you provide the version in all
    scripts, so i can troubleshoot better"):
        <Script> version <version> - documentation: https://invardia.com/docs/si/scripts/<Script>/
    (the page Invardia renders from the script's <Script>.doc.json). The transcript is started BEFORE that line is printed,
    so the same line is also the first line of the transcript. The version (Get-SIScriptVersion), in this order:
        1. the version stamped into a PUBLISHED copy: release\Build-SISupportScripts.ps1 rewrites the
           $script:SIScriptVersionStamp line below in the copy of this file each self-contained script embeds;
        2. the install / package / checkout this file sits in: BUILD.json (its display, e.g. 3.0.0-rc.12), else VERSION;
        3. "unknown (not a released copy)".
    It then says plainly when -WhatIf is on (nothing is changed). The transcript is a local file in ONE known folder:
        Windows : %LOCALAPPDATA%\SecurityInsight\script-logs\<Script>-<yyyyMMdd-HHmmss>.log
        others  : ~/.securityinsight/script-logs/<Script>-<yyyyMMdd-HHmmss>.log
    Stop-SIScriptRun ends the transcript and prints its path. The transcript holds what the script printed -- the scripts
    never print a secret value (section 12.10 "no secrets in, no secrets out"). A transcript that cannot be started (a host
    without transcription, a read-only profile) is said and the script goes on: it never blocks the work.
    The transcript and its folder are written even under -WhatIf (-WhatIf:$false): they are the record of what was
    previewed, not a change to the customer's environment.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

# SI #547 -- the PUBLISH STAMP. Empty in the repository and the package; release\Build-SISupportScripts.ps1 writes the release
# version here (Set-SIScriptVersionStamp) in the copy a self-contained script embeds. Keep this line's shape: the build
# refuses to publish when it cannot find it.
$script:SIScriptVersionStamp = ''
# the folder this helper lives in (setup\_shared) -- the solution root is two levels up
$script:SIScriptRunHome = $PSScriptRoot

function Get-SIScriptVersion {
    <#
        The version a person-run script reports. -Stamp (default: the publish stamp above) wins; else -SolutionRoot's
        BUILD.json display / version, else its VERSION file; else 'unknown (not a released copy)'. Never throws.
    #>
    param([AllowEmptyString()][string]$Stamp = [string]$script:SIScriptVersionStamp, [AllowEmptyString()][string]$SolutionRoot = '')
    if ("$Stamp".Trim()) { return "$Stamp".Trim() }
    if (-not "$SolutionRoot".Trim() -and "$($script:SIScriptRunHome)".Trim()) {
        try { $SolutionRoot = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$script:SIScriptRunHome, '..', '..')) } catch { $SolutionRoot = '' }
    }
    if ("$SolutionRoot".Trim()) {
        try {
            # not [IO.Path]::Combine(..., 'BUILD.json'): the support-script builder embeds every data file a helper names that
            # way, and a published copy must never carry the build machine's BUILD.json (its version comes from the stamp)
            $bj = $SolutionRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar + 'BUILD.json'
            if ([IO.File]::Exists($bj)) {
                $j = [IO.File]::ReadAllText($bj) | ConvertFrom-Json
                if ("$($j.display)".Trim()) { return "$($j.display)".Trim() }
                if ("$($j.version)".Trim()) { return "$($j.version)".Trim() }
            }
        } catch { }
        try {
            $vf = [IO.Path]::Combine($SolutionRoot, 'VERSION')
            if ([IO.File]::Exists($vf)) { $v = ([IO.File]::ReadAllText($vf)).Trim(); if ($v) { return $v } }
        } catch { }
    }
    'unknown (not a released copy)'
}

function Get-SIScriptFirstLine {
    <# PURE. The first line of every person-run script: "<Script> version <v> - documentation: <link>". #>
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$Version)
    $n = [IO.Path]::GetFileNameWithoutExtension($Script.Trim())
    '{0} version {1} - documentation: {2}' -f $n, $Version, (Get-SIScriptDocUrl -Script $n)
}

function Get-SIScriptDocUrl {
    <# PURE. The documentation page of a script (no .ps1, trailing slash -- confirmed by Invardia 2026-10-09). #>
    param([Parameter(Mandatory)][string]$Script)
    $n = ([IO.Path]::GetFileNameWithoutExtension($Script.Trim()))
    'https://invardia.com/docs/si/scripts/{0}/' -f $n
}

function Get-SIScriptLogFolder {
    <# PURE apart from reading the environment. The one known folder every script's transcript goes to. #>
    if ($env:SI_SCRIPT_LOG_DIR) { return [string]$env:SI_SCRIPT_LOG_DIR }
    if ($env:LOCALAPPDATA) { return [IO.Path]::Combine($env:LOCALAPPDATA, 'SecurityInsight', 'script-logs') }
    $h = $HOME; if (-not $h) { $h = [Environment]::GetFolderPath('UserProfile') }
    [IO.Path]::Combine($h, '.securityinsight', 'script-logs')
}

function Start-SIScriptRun {
    <#
        The first thing a script does. Returns the run (pass it to Stop-SIScriptRun). -WhatIf comes from the caller's
        $WhatIfPreference; -Quiet (tests) prints nothing and starts no transcript.
    #>
    param([Parameter(Mandatory)][string]$Script, [switch]$Quiet, [bool]$WhatIfOn = [bool]$WhatIfPreference)
    if ($env:SI_SCRIPT_RUN_QUIET -eq '1') { $Quiet = [switch]$true }      # tests: no banner, no transcript
    $name = [IO.Path]::GetFileNameWithoutExtension($Script.Trim())
    $ver = Get-SIScriptVersion
    $run = [pscustomobject]@{ Script = $name; DocUrl = (Get-SIScriptDocUrl -Script $name); Version = $ver; FirstLine = (Get-SIScriptFirstLine -Script $name -Version $ver)
                              Transcript = ''; Started = $false; WhatIf = $WhatIfOn; Quiet = [bool]$Quiet }
    if ($Quiet) { return $run }
    # the transcript FIRST (silently), so the version line below is the first line of the console AND of the transcript
    $noTranscript = ''
    try {
        $dir = Get-SIScriptLogFolder
        if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
        $path = [IO.Path]::Combine($dir, ('{0}-{1:yyyyMMdd-HHmmss}.log' -f $name, [datetime]::Now))
        $null = Start-Transcript -LiteralPath $path -WhatIf:$false -ErrorAction Stop
        $run.Transcript = $path; $run.Started = $true
    } catch {
        $noTranscript = $_.Exception.Message
    }
    Write-Host $run.FirstLine
    if ($noTranscript) { Write-Host ('(no transcript of this run: {0})' -f $noTranscript) -ForegroundColor DarkGray }
    if ($WhatIfOn) { Write-Host '-WhatIf: this run only reads and shows what it would change -- nothing is changed.' -ForegroundColor Yellow }
    $run
}

function Stop-SIScriptRun {
    <# The last thing a script does (in its finally block): ends the transcript and prints where it is. #>
    param($Run)
    if ($null -eq $Run -or $Run.Quiet) { return }
    if ($Run.Started) {
        try { $null = Stop-Transcript -ErrorAction Stop } catch { }
        Write-Host ('Transcript of this run: {0}' -f $Run.Transcript)
    }
}
