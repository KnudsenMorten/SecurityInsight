#Requires -Version 5.1
<#
.SYNOPSIS
    AST inventory of the functions in a PowerShell engine script - the evidence baseline for a
    behaviour-preserving file split (audit #16).

.DESCRIPTION
    Audit #16 asks for `Invoke-RiskAnalysis.ps1` (10,561 lines / 127 functions) to be split along its
    banner-comment seams into dot-sourced files under `_shared/`, "no behaviour change, purely
    structural". The problem is proving that second half: the SI Pester gate PARSES the engine, it
    never runs it, so nothing offline can show a split preserved behaviour.

    This is the missing evidence. It walks the AST and emits, per function:
      * name, start/end line, length
      * a SHA-256 of the function's exact source text
      * whether the body references $PSScriptRoot, $MyInvocation or $PSCommandPath

    Run it BEFORE and AFTER a split and compare. Identical name + hash sets mean every function's
    body survived byte-for-byte, whatever file it now lives in.

    THE TRAP IT IS BUILT TO CATCH ($PSScriptRoot):
    dot-sourcing does not change a function's text, but it DOES change what $PSScriptRoot means
    inside it. In the engine root that is `engine/risk-analysis`; in a dot-sourced `_shared/` file it
    becomes `engine/risk-analysis/_shared`. This engine derives $siRoot as
    `Split-Path -Parent (Split-Path -Parent $PSScriptRoot)` in several places, so any function moved
    one directory deeper silently resolves a DIFFERENT root - identical text, different behaviour,
    and no parse error to warn anyone. Those functions are reported as **PinnedToScriptRoot**: they
    either stay where they are, or the split must capture the original root at load time first.

.PARAMETER Path
    Engine script(s) to inventory. Accepts wildcards / multiple paths.

.PARAMETER Baseline
    A previously written inventory JSON to COMPARE against. Reports added, removed and CHANGED
    functions and exits 1 if anything differs.

.PARAMETER OutFile
    Write the inventory as JSON (use for the "before" snapshot).

.EXAMPLE
    # Before the split
    .\tests\Get-EngineFunctionInventory.ps1 -Path engine\risk-analysis\Invoke-RiskAnalysis.ps1 -OutFile before.json

.EXAMPLE
    # After the split - every function must still be present, byte-identical
    .\tests\Get-EngineFunctionInventory.ps1 -Path engine\risk-analysis\*.ps1,engine\risk-analysis\_shared\*.ps1 -Baseline before.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Path,
    [string]$Baseline,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Get-FunctionInventory {
    param([string[]]$Files)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $out = @()

    foreach ($file in $Files) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) {
            throw "PARSE ERROR in '$file': $($errors[0].Message)"
        }

        # $true = search nested functions too; a function defined inside another still exists.
        $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

        foreach ($fn in $fns) {
            $text = $fn.Extent.Text
            $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '')

            # Only the RESOLUTION-SENSITIVE automatic variables. $PSScriptRoot is the one that
            # actually moves; the other two are listed because they shift for the same reason.
            $pinned = $text -match '\$PSScriptRoot|\$PSCommandPath|\$MyInvocation'

            $out += [pscustomobject]@{
                Name                = $fn.Name
                File                = Split-Path -Leaf $file
                StartLine           = $fn.Extent.StartLineNumber
                EndLine             = $fn.Extent.EndLineNumber
                Lines               = $fn.Extent.EndLineNumber - $fn.Extent.StartLineNumber + 1
                BodySha256          = $hash
                PinnedToScriptRoot  = [bool]$pinned
            }
        }
    }
    $sha.Dispose()
    return $out | Sort-Object Name, BodySha256
}

# Resolve wildcards; keep only .ps1
$files = @()
foreach ($p in $Path) {
    $files += Get-ChildItem -Path $p -File -ErrorAction Stop | Where-Object Extension -eq '.ps1' | Select-Object -ExpandProperty FullName
}
if (-not $files) { throw "No .ps1 files matched: $($Path -join ', ')" }

$inv = Get-FunctionInventory -Files $files

Write-Host ""
Write-Host ">> Function inventory" -ForegroundColor Cyan
Write-Host ("   files      : {0}" -f $files.Count)
Write-Host ("   functions  : {0}" -f $inv.Count)
$dupes = $inv | Group-Object Name | Where-Object Count -gt 1
if ($dupes) {
    # Two functions with the same name = the LAST one loaded wins. Across a split that ordering is
    # decided by dot-source order, which is exactly the kind of thing a split can silently change.
    Write-Host ("   DUPLICATE NAMES: {0} -- load order decides which definition wins" -f $dupes.Count) -ForegroundColor Yellow
    $dupes | ForEach-Object { Write-Host ("     {0} x{1}" -f $_.Name, $_.Count) -ForegroundColor Yellow }
}
$pinned = @($inv | Where-Object PinnedToScriptRoot)
Write-Host ("   pinned to `$PSScriptRoot / `$MyInvocation : {0}" -f $pinned.Count) -ForegroundColor $(if ($pinned.Count) { 'Yellow' } else { 'Green' })
if ($pinned.Count) {
    Write-Host "   ^ these CANNOT be moved to a deeper directory without changing what they resolve to." -ForegroundColor Yellow
    $pinned | ForEach-Object { Write-Host ("     {0}  ({1}:{2})" -f $_.Name, $_.File, $_.StartLine) -ForegroundColor Yellow }
}

if ($OutFile) {
    $inv | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutFile -Encoding UTF8
    Write-Host (">> Wrote {0}" -f $OutFile) -ForegroundColor Green
}

if ($Baseline) {
    if (-not (Test-Path $Baseline)) { throw "Baseline not found: $Baseline" }
    $old = Get-Content -Raw -LiteralPath $Baseline | ConvertFrom-Json

    # Key on Name+BodySha256, NOT Name alone.
    #
    # Keying by name collapses duplicate definitions, and duplicates are the exact hazard this tool
    # exists to report: keeping one entry per name meant deleting one of two same-named functions
    # showed up as "everything survived" while the printed count silently dropped. A comparison that
    # contradicts the count is worse than no comparison. Definition IDENTITY is the pair.
    $keyOf   = { param($f) '{0}|{1}' -f $f.Name, $f.BodySha256 }
    $oldMap  = @{}; foreach ($f in $old) { $oldMap[(& $keyOf $f)] = $f }
    $newMap  = @{}; foreach ($f in $inv) { $newMap[(& $keyOf $f)] = $f }

    $removed = @($oldMap.Keys | Where-Object { -not $newMap.ContainsKey($_) } | ForEach-Object { $oldMap[$_] })
    $added   = @($newMap.Keys | Where-Object { -not $oldMap.ContainsKey($_) } | ForEach-Object { $newMap[$_] })
    # Same name AND same bytes, different file = the intended outcome of a split, not a difference.
    $moved   = @($oldMap.Keys | Where-Object { $newMap.ContainsKey($_) -and $oldMap[$_].File -ne $newMap[$_].File })

    # A body edit shows up as one removal + one addition of the same NAME. Separate it out so a
    # rewrite is not mistaken for an unrelated delete/add pair.
    $changed = @($removed | Where-Object { $n = $_.Name; $added.Name -contains $n } | ForEach-Object { $_.Name } | Sort-Object -Unique)
    $removed = @($removed | Where-Object { $changed -notcontains $_.Name })
    $added   = @($added   | Where-Object { $changed -notcontains $_.Name })

    if ($old.Count -ne $inv.Count) {
        Write-Host ("   COUNT: {0} -> {1}" -f $old.Count, $inv.Count) -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host ">> Compared against $Baseline" -ForegroundColor Cyan
    Write-Host ("   moved (body identical) : {0}" -f $moved.Count) -ForegroundColor Green
    Write-Host ("   REMOVED                : {0}" -f $removed.Count) -ForegroundColor $(if ($removed.Count) { 'Red' } else { 'Green' })
    Write-Host ("   ADDED                  : {0}" -f $added.Count)   -ForegroundColor $(if ($added.Count) { 'Red' } else { 'Green' })
    Write-Host ("   CHANGED BODY           : {0}" -f $changed.Count) -ForegroundColor $(if ($changed.Count) { 'Red' } else { 'Green' })
    $removed | ForEach-Object { Write-Host ("     REMOVED: {0} (was {1}:{2})" -f $_.Name, $_.File, $_.StartLine) -ForegroundColor Red }
    $added   | ForEach-Object { Write-Host ("     ADDED:   {0} ({1}:{2})" -f $_.Name, $_.File, $_.StartLine) -ForegroundColor Red }
    $changed | ForEach-Object { Write-Host "     CHANGED: $_" -ForegroundColor Red }

    if ($removed.Count -or $added.Count -or $changed.Count) {
        Write-Host ">> NOT behaviour-preserving on the function inventory." -ForegroundColor Red
        exit 1
    }
    Write-Host ">> Every function survived byte-for-byte." -ForegroundColor Green
}

exit 0
