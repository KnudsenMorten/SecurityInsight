#Requires -Version 5.1
<#
.SYNOPSIS
    Default transcript logging for every SI v2.2 launcher (community-vm,
    internal-vm, container) across all engines (risk-analysis + the 4
    asset-profiling engines).

.DESCRIPTION
    Wraps Start-Transcript / Stop-Transcript with sensible defaults so each
    launcher run leaves a copy on disk for forensics + customer support
    even when the operator didn't redirect stdout.

    Log path : <v22Root>/logs/<engine>_<flavour>_<utcStamp>.log
                - one folder per repo, not per launcher (easier to grep)
                - utcStamp = yyyyMMddTHHmmssZ (sortable)
                - <flavour> = 'community-vm' | 'internal-vm' | 'container'
                - <engine>  = 'risk-analysis' | 'identity' | 'endpoint' | 'azure' | 'publicip'

    Retention: prune log files older than $RetentionDays (default 30).
    Customers can override via $global:SI_LogRetentionDays in config
    or by passing -RetentionDays from the launcher.

    Honours $global:SI_DisableTranscript = $true (lab/CI override).

.NOTES
    PS 5.1 quirks handled:
      - Start-Transcript silently fails when an existing transcript is open
        in the same session (e.g. user already started one). We Stop-Transcript
        defensively first inside a try/catch.
      - Some hosts (ConsoleHost / ISE / Code) treat -NoClobber differently;
        we use -Force + a unique filename so collisions are impossible.
      - The $global:SI_TranscriptPath sentinel lets the matching Stop-* find
        the right path even if Start-Transcript's $LASTEXITCODE state is lost.
#>

function Start-SILauncherTranscript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][ValidateSet('community-vm','internal-vm','container')][string]$Flavour,
        [Parameter()][string]$RepoRoot,
        [Parameter()][int]$RetentionDays = $(if ($global:SI_LogRetentionDays) { [int]$global:SI_LogRetentionDays } else { 30 })
    )

    if ($global:SI_DisableTranscript) { return $null }

    # Resolve repo root: caller's $InstallPath > walk up from $PSScriptRoot.
    # Walk-up accepts EITHER layout marker:
    #   * <root>/SOLUTIONS/SecurityInsight/VERSION  -- monorepo (internal)
    #   * <root>/VERSION                            -- flat publish (community)
    if (-not $RepoRoot) {
        $cur = $PSScriptRoot
        while ($cur -and `
               -not (Test-Path (Join-Path $cur 'SOLUTIONS\SecurityInsight\VERSION')) -and `
               -not (Test-Path (Join-Path $cur 'VERSION'))) {
            $parent = Split-Path -Parent $cur
            if (-not $parent -or $parent -eq $cur) { break }
            $cur = $parent
        }
        $RepoRoot = $cur
    }

    # Layout-aware logs dir. Pre-v2.2.312 unconditionally appended
    # 'SOLUTIONS/SecurityInsight/logs' whenever -RepoRoot was passed (every
    # launcher passes $InstallPath), which on a flat community install at
    # C:\<install>\ created a stray C:\<install>\SOLUTIONS\SecurityInsight\logs\
    # folder where operators couldn't find their transcripts. Now: probe for the
    # monorepo marker; fall back to '<root>/logs' on flat layouts.
    $logsDir = if ($RepoRoot -and (Test-Path -LiteralPath (Join-Path $RepoRoot 'SOLUTIONS\SecurityInsight\VERSION'))) {
        Join-Path $RepoRoot 'SOLUTIONS/SecurityInsight/logs'
    } elseif ($RepoRoot) {
        Join-Path $RepoRoot 'logs'
    } else {
        # last-resort fallback: relative to this helper.
        Join-Path $PSScriptRoot '..\..\logs'
    }
    if (-not (Test-Path -LiteralPath $logsDir)) {
        try {
            New-Item -ItemType Directory -Path $logsDir -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning ("Could not create transcript folder {0}: {1}. Continuing without transcript." -f $logsDir, $_.Exception.Message)
            return $null
        }
    }

    # Retention prune (best-effort -- never throws)
    if ($RetentionDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        try {
            Get-ChildItem -LiteralPath $logsDir -Filter '*.log' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $logPath = Join-Path $logsDir ("{0}_{1}_{2}.log" -f $Engine, $Flavour, $stamp)

    # Defensive: stop any prior transcript silently.
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }

    try {
        Start-Transcript -Path $logPath -Force -ErrorAction Stop | Out-Null
        $global:SI_TranscriptPath = $logPath
        return $logPath
    } catch {
        Write-Warning ("Start-Transcript failed ({0}); continuing without transcript." -f $_.Exception.Message)
        return $null
    }
}

function Stop-SILauncherTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Remove-Variable -Name SI_TranscriptPath -Scope Global -ErrorAction SilentlyContinue
}
