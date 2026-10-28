#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  WHICH RISK INDEX FILES A RUN READS -- the locked + custom model (#398).
#
#    risk-analysis-detection\riskscore.index.locked.csv         SHIPPED. Replaced by every update.
#    risk-analysis-detection\riskscore.index.custom.csv         YOURS. Never shipped, never replaced. Optional.
#    risk-analysis-detection\riskscore.index.custom.sample.csv  SHIPPED. A starting point for your own rows.
#
#  Your rows (custom) are checked FIRST, then the shipped rows -- first match wins (RA-RiskIndexOrder.ps1). A row of
#  yours therefore wins over a shipped row it fits the same findings as; a finding none of your rows fits is scored
#  by the shipped index. Your file may be a few rows or a whole index; with a Precedence column the rows are walked
#  in that order, without one (a 2.2 index) they are converted exactly as 2.2 scored them.
#
#  🔴 WHY (v3 upgrade test, 2026-10-05). Until 3.0 the shipped index itself was called riskscore.index.custom.csv,
#  so which index an upgraded install scored with depended on HOW it was upgraded: the signed update never touches
#  *.custom.* (it kept 2.2's 59 rows), a git pull brought 3.0's 99 rows, the internal sync overwrote the file --
#  customer edits included. Now the shipped index has a locked name, and the custom name is only ever yours.
#
#  🔑 THE MIGRATION (every run, so every upgrade path gets it -- signed update, git pull, sync, container image).
#  A riskscore.index.custom.csv that is BYTE-FOR-BYTE a file SecurityInsight shipped (line endings and a UTF-8 BOM
#  aside) was never edited: it is removed and the locked file takes over. Anything else is your edit: it is kept, read
#  as your rows over the shipped ones, and the run log says so once. The shipped versions are listed below by SHA-256
#  (tests/pester/SIv3-RiskIndexFiles.Tests.ps1 proves the list against the files in git history).
#
#  PowerShell 5.1 compatible. No Set-StrictMode here (it leaks into the caller's scope).
#######################################################################################################

$script:SIRiskIndexLockedName = 'riskscore.index.locked.csv'
$script:SIRiskIndexCustomName = 'riskscore.index.custom.csv'

# SHA-256 of every riskscore.index.custom.csv SecurityInsight ever shipped, after Get-SIRiskIndexFileHash's
# normalisation: 2.2.0 - 2.2.461 (59 rows) and the 3.0 pre-release index (99 rows, Precedence) that internal ring-1
# installs received before it moved to the locked name.
$script:SIRiskIndexShippedCustomHashes = @(
    'a840970d76adff3343a04087ac289358c68e093c9b5d406cd324edbb4e6c636e',   # 2.2.0 - 2.2.461 (git blob e2fb10baf)
    '45eb7ab5518f5ce9ebc4a1128b1c85a1e8ee7c2828349f819b20a6e092a931cb',   # 3.0 pre-release   (git blob ef1e50146)
    # #559: the 3.0 locked index with the 2.2 columns (99 rows, Precedence) -- a copy of it under the custom name is not an
    # edit either (the shipped index is now keyed by the SI fields; this copy would only re-add the translated rows)
    'eadac5f370c27fc7066a1e0576729308c13fd64447da098ad6ea644b5b9fb483'    # 3.0 locked, 2.2 keys (git blob 702f53316)
)

function Get-SIRiskIndexFileHash {
    <# PURE (reads one file). SHA-256 (lower-case hex) of the file's text with a UTF-8 BOM removed and CRLF -> LF, so a
       git checkout with autocrlf and a zip download of the same release hash the same. $null when it cannot be read. #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        $b = [System.IO.File]::ReadAllBytes($Path)
        $start = 0
        if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $start = 3 }
        $text = [System.Text.Encoding]::UTF8.GetString($b, $start, $b.Length - $start).Replace("`r`n", "`n")
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
        return (-join ($h | ForEach-Object { $_.ToString('x2') }))
    } catch { return $null }
}

function Test-SIRiskIndexShippedCopy {
    <# PURE (reads one file). $true when -Path is byte-for-byte (see Get-SIRiskIndexFileHash) a shipped risk index. #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$KnownHashes = $script:SIRiskIndexShippedCustomHashes)
    $h = Get-SIRiskIndexFileHash -Path $Path
    if (-not $h) { return $false }
    return (@($KnownHashes) -contains $h)
}

function Resolve-SIRiskIndexFiles {
    <#
        Decides which risk index files this run reads, and migrates a never-edited copy of a shipped index away.
          -Folder         the folder holding the index files (risk-analysis-detection)
          -NoticeMarker   a file whose presence means "the run log already said the custom file is used as your rows"
                          (VM: under logs\state). Empty = say it on every run (a container has no local state).
          -NoRemove       never delete (tests, a read-only tree): an unedited shipped copy is then only ignored
        Returns @{ LockedPath; CustomPath ($null = none read); Action = none | removed-unedited | ignored-unedited |
        overlay; Lines (what to tell the run log) }. Never throws for the custom file; a missing locked file is the
        caller's error.
    #>
    param([Parameter(Mandatory)][string]$Folder, [string]$NoticeMarker, [switch]$NoRemove,
          [string[]]$KnownHashes = $script:SIRiskIndexShippedCustomHashes)
    $locked = Join-Path $Folder $script:SIRiskIndexLockedName
    $custom = Join-Path $Folder $script:SIRiskIndexCustomName
    $res = [pscustomobject]@{ LockedPath = $locked; CustomPath = $null; Action = 'none'; Lines = @() }
    if (-not (Test-Path -LiteralPath $custom -PathType Leaf)) { return $res }

    if (Test-SIRiskIndexShippedCopy -Path $custom -KnownHashes $KnownHashes) {
        $removed = $false
        if (-not $NoRemove) { try { Remove-Item -LiteralPath $custom -Force -ErrorAction Stop; $removed = $true } catch { $removed = $false } }
        if ($removed) {
            $res.Action = 'removed-unedited'
            $res.Lines = @(('Risk index: {0} was the unchanged risk index of an earlier version, so it was removed. The shipped index ({1}) is used, and updates keep it current.' -f $script:SIRiskIndexCustomName, $script:SIRiskIndexLockedName))
        } else {
            $res.Action = 'ignored-unedited'
            $res.Lines = @(('Risk index: {0} is the unchanged risk index of an earlier version, so it is not used. The shipped index ({1}) is used; delete {0} to stop this line.' -f $script:SIRiskIndexCustomName, $script:SIRiskIndexLockedName))
        }
        return $res
    }

    $res.CustomPath = $custom
    $res.Action = 'overlay'
    $say = $true
    if ($NoticeMarker) { try { $say = -not (Test-Path -LiteralPath $NoticeMarker) } catch { $say = $true } }
    if ($say) {
        $res.Lines = @(
            ('Risk index: your own {0} is kept and read FIRST, before the shipped index ({1}): where one of your rows fits a finding it sets the score, and every other finding is scored by the shipped index, which updates keep current.' -f $script:SIRiskIndexCustomName, $script:SIRiskIndexLockedName),
            ('If you edited it only to change a few rows, keep just those rows in it; if you did not mean to change scoring, delete it. This is said once.')
        )
        if ($NoticeMarker) {
            try {
                $null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $NoticeMarker))
                [System.IO.File]::WriteAllText($NoticeMarker, ('{0:o}' -f [datetime]::UtcNow))
            } catch { }
        }
    }
    $res
}
