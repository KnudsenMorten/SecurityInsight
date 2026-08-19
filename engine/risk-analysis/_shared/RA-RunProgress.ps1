#Requires -Version 5.1
<#
    RA-RunProgress.ps1  --  AUDIT #16 tranche 3.

    Lifted VERBATIM from Invoke-RiskAnalysis.ps1 lines 361-541 and dot-sourced back at
    that exact position, so load order and conditional definition are unchanged. The
    working rule for this split, learned the hard way in tranches 1-2, is:

        contiguous span + dot-source in place + no $PSScriptRoot

    The audit's own prescription -- "split along the existing banner-comment seams" -- is
    UNSAFE here: those seams interleave executable statements with declarations (16
    statements sit among the 76 definitions in the FUNCTIONS region alone), so a
    seam-sized lift would reorder load-time execution. This span was chosen instead by
    asking the AST for the largest run of nothing-but-function-definitions sharing one
    parent, with only blank/comment lines between them -- verified, not eyeballed.

    Contents (12 functions, one theme: how a run reports itself):
      * the superseded-attempt ledger  -- Reset/Add/Resolve/Flush-SupersededAttempts,
        which keeps a retried-then-succeeded path from logging a WARN it has earned back
      * run progress + timing          -- Write-Phase, Write-Sep, Tick, Tock
      * output-safety helpers          -- Ensure-Directory, Resolve-AssetNamesForRow,
        ConvertTo-XlsxSafeString, Reset-ExcelOutput

    These are called from all over the engine and depend on script-scope state only at
    CALL time, never at definition time -- which is what makes the lift safe.
#>
function Reset-SupersededAttempts {
    $script:_SupersededAttempts = New-Object System.Collections.Generic.List[string]
}
function Add-SupersededAttempt {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Message)
    [void]$script:_SupersededAttempts.Add(('{0}: {1}' -f $Path, $Message))
}
function Resolve-SupersededOnSuccess {
    # Call right before returning rows from a successful path. Emits ONE INFO if
    # earlier paths were tried + failed; never WARN (a later path won).
    param([Parameter(Mandatory)][string]$WinningPath)
    $n = $script:_SupersededAttempts.Count
    if ($n -gt 0) {
        Write-Info ("auth/data via {0} (after {1} superseded fallback attempt(s); earlier-path detail at [DIAG])." -f $WinningPath, $n)
        Reset-SupersededAttempts
    }
}
function Flush-SupersededAttempts {
    # Call when EVERY path has failed for this query. Emits a SINGLE consolidated
    # WARN with all per-attempt detail, then clears the buffer.
    if ($script:_SupersededAttempts.Count -gt 0) {
        Write-Warn2 ("all data paths failed for this query; attempts: {0}" -f ($script:_SupersededAttempts -join ' || '))
        Reset-SupersededAttempts
    }
}
function Write-Phase  {
    param([Parameter(Mandatory)][string]$Title, [string]$Subtitle = '')
    # flush-left (no 1-char indent). Subtitles are usually multi-line
    # report descriptions from YAML; with a leading-space the first line indents
    # but PowerShell's Write-Host doesn't propagate the indent to wrapped /
    # newline-split lines, so they end up flush-left while line 1 floats one char
    # right -- looked broken. All lines now start at column 0 for clean alignment.
    $line = '-' * 88
    Write-Host ''
    Write-Host $line -ForegroundColor White
    Write-Host $Title.ToUpper() -ForegroundColor Cyan
    if ($Subtitle) { Write-Host $Subtitle -ForegroundColor White }
    Write-Host $line -ForegroundColor White
}
function Write-Sep          { Write-Host ("-" * 80) -ForegroundColor DarkCyan }
function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Resolve-AssetNamesForRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter()][AllowNull()] [object] $AssetsText
    )

    function _ToText([AllowNull()][object]$v) {
        if ($null -eq $v) { return "" }

        # Already a string
        if ($v -is [string]) { return $v }

        # Arrays / IEnumerable (but not string) -> try JSON first, else join
        if (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string])) {
            try { return ($v | ConvertTo-Json -Compress -Depth 12) } catch {}
            try {
                $parts = @()
                foreach ($x in $v) { if ($null -ne $x) { $parts += ("" + $x) } }
                return ($parts -join ",")
            } catch {
                return ("" + $v)
            }
        }

        # PSCustomObject / Hashtable -> JSON
        if ($v -is [pscustomobject] -or $v -is [hashtable] -or $v -is [System.Collections.IDictionary]) {
            try { return ($v | ConvertTo-Json -Compress -Depth 12) } catch { return ("" + $v) }
        }

        return ("" + $v)
    }

    $assetsTextNorm = (_ToText $AssetsText).Trim()

    # 1) Summary mode: parse ImpactedAssets text (json array or comma list)
    if (-not [string]::IsNullOrWhiteSpace($assetsTextNorm)) {
        $list = Split-ImpactedAssets -AssetsText $assetsTextNorm
        if ($list -and @($list).Count -gt 0) { return @($list) }
    }

    # 2) Detailed mode: one asset per row in a dedicated column
    $fallback = Get-RowValue -Row $Row -Names @(
        "AssetName","DeviceName","Device","MachineName","Computer",
        "HostName","DnsName","FQDN","Endpoint","Asset"
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$fallback)) {
        # 🔴 ONE ROW, ONE ASSET -- DO NOT SPLIT THIS VALUE. (v2.2.441)
        # This branch is reached only in DETAILED mode, where the column is a per-row single asset
        # (see the comment above it). It used to split on [,;], which is not a list separator here --
        # it is punctuation INSIDE a display name. Reported from a customer's Detailed AI summary,
        # where one identity became three "assets":
        #     "<Person> (Admin, Cloud, ID)"  ->  "<Person> (Admin" + "Cloud" + "ID)"
        # and "Service Account, AI for IT" -> "Service Account" + "AI for IT".
        # 🔑 The damage is not cosmetic. Each fragment aggregates as its OWN asset, so it gets its own
        # risk score and its own row in the Top-N -- the real asset's findings are split across
        # phantoms, the phantoms crowd out genuine assets in a ranked list, and the same person can
        # appear twice (once whole from the JSON path, once shredded from here) with different scores.
        # Bare words like "Cloud" and "ID)" then get presented to an operator as top-risk Tier 0 assets.
        # 🪤 This is the SECOND time this exact class has been fixed in this function: Split-ImpactedAssets
        # already carries a note about tokenizing on whitespace and exploding a description into ~10 fake
        # assets. Same mistake, different delimiter -- an asset NAME is atomic, and only a column that is
        # genuinely a LIST may be split. That column is handled above, by Split-ImpactedAssets.
        # A multi-asset value arriving here would now stay whole: visibly wrong and traceable to its
        # report, rather than silently manufacturing assets that never existed.
        return @(([string]$fallback).Trim())
    }

    return @()
}

# ===== reset helper (delete workbook at start when OverwriteXlsx is true) =====
function ConvertTo-XlsxSafeString {
    [CmdletBinding()]
    param([Parameter()][AllowEmptyString()][AllowNull()][string]$Value)

    # XLSX shared-strings safety. Excel's strict XML validator (per XML 1.0 spec) rejects
    # control characters 0x00-0x1F (except TAB/LF/CR), DEL 0x7F, and lone UTF-16 surrogate
    # halves. When such a char slips into a cell value -- typically via a KQL extract()
    # result, a CSA / TierSources JSON blob, or pasted-in text -- Excel still recovers
    # the workbook on open but pops the "Repaired Records: String properties from
    # /xl/sharedStrings.xml" warning. Stripping at the source kills the warning for
    # every customer. v2.1.206.
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    # Control chars 0x00-0x1F (except TAB/LF/CR) + DEL 0x7F.
    $Value = [regex]::Replace($Value, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
    # Lone UTF-16 surrogate halves (high without trailing low, or low without leading high).
    $Value = [regex]::Replace($Value, '[\uD800-\uDBFF](?![\uDC00-\uDFFF])', '')
    $Value = [regex]::Replace($Value, '(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', '')
    # also strip Unicode non-characters (U+FFFE / U+FFFF) and the
    # rarely-seen line / paragraph separators (U+2028 / U+2029) -- EPPlus
    # sharedStrings.xml writer accepts them but Excel's stricter validator on
    # open triggers the "Repaired Records" warning.
    $Value = [regex]::Replace($Value, "[\uFFFE\uFFFF\u2028\u2029]", '')
    # Excel cell hard limit: 32,767 chars. Strings beyond that trigger the
    # "We found a problem with some content" repair dialog on open. Compose the
    # truncation marker first, then back off the substring length so the COMBINED
    # result is guaranteed <= 32767. v2.2 -- common source: MoreDetails
    # for reports with hundreds of CVEs.
    if ($Value.Length -gt 32767) {
        $clip   = $Value.Length - 32767  # provisional; recomputed after sizing
        $marker = '... [truncated {0} chars]' -f $clip
        # Re-derive marker after we know the actual cut so the suffix length is honest
        $cut    = 32767 - $marker.Length
        if ($cut -lt 0) { $cut = 0 }
        $clip   = $Value.Length - $cut
        $marker = '... [truncated {0} chars]' -f $clip
        # If new marker grew (e.g. clip count is now 5 digits), shrink cut once more
        $cut    = 32767 - $marker.Length
        if ($cut -lt 0) { $cut = 0 }
        $Value  = $Value.Substring(0, $cut) + $marker
    }
    return $Value
}

function Reset-ExcelOutput {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter()][switch]$ForceRemove = $true
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  if (Test-Path $Path) {
    if ($ForceRemove) {
      try { [System.IO.File]::SetAttributes($Path, 'Normal') } catch {}
      $deleted = $false
      for ($i = 1; $i -le 5 -and -not $deleted; $i++) {
        try {
          Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
          $deleted = $true
        } catch {
          Write-Warn2 ("excel file locked (attempt {0}/5); retrying..." -f $i)
          Start-Sleep -Milliseconds 500
        }
      }
      if (-not $deleted) { throw "Could not delete existing Excel file: $Path (locked)" }
    } else {
      Write-Warn2 "Overwrite disabled; keeping existing Excel file and appending sheets."
    }
  }
  $script:_sheetWritten = @{}
}

