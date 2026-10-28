#Requires -Version 5.1
<#
    SecurityInsight -- the image build context, at a SHORT path when the install's own path is too deep for the build.

    `az acr build <folder>` packs the folder with the Azure CLI's own Python. On Windows that packer cannot open a file whose
    full path is longer than 260 characters (unless long paths are switched on for the machine), so an install that lives in
    a deep folder -- a git worktree, a nested sync target -- fails the build on the longest rule files (a relative path in this
    solution is up to ~150 characters). Found building ring 1 from a deep worktree (#350).

    The fix stays inside the product: when the longest file path would pass the limit, the build context is copied to a short
    folder under the temp directory first (robocopy: it reads long paths), and the build runs from there. The image is the same:
    the build context is the same files (the .dockerignore travels with them), and the image tag is computed from the install
    itself, never from the stage. Linux (the updater container) never stages.

    Used by setup\Invoke-SIContainerUpdate.ps1 (the engine image), setup\Install-SIUpdaterJob.ps1 (the updater image) and the
    updater's own builds of the web app and of itself (container\updater).
#>

function Get-SIBuildStageDecision {
    <#
      PURE. Whether a build context at -ContextPath must be staged at a short path before `az acr build`.
      -LongestRelative = the longest file path below the context (characters, relative); -1 = the tree could not be read
      (on PowerShell 5.1 a path over the limit already fails to enumerate -- that alone means "stage").
      Returns @{ Stage; Longest; Reason }.
    #>
    param([Parameter(Mandatory)][string]$ContextPath, [int]$LongestRelative = 0, [bool]$IsWindowsHost = $true, [int]$Limit = 240)
    if (-not $IsWindowsHost) { return [pscustomobject]@{ Stage = $false; Longest = 0; Reason = 'not Windows -- the build reads the folder as it is' } }
    $root = $ContextPath.TrimEnd('\', '/')
    if ($LongestRelative -lt 0) { return [pscustomobject]@{ Stage = $true; Longest = -1; Reason = ('the folder {0} holds paths too long to read -- the build runs from a short copy' -f $root) } }
    $longest = $root.Length + 1 + $LongestRelative
    if ($longest -gt $Limit) { return [pscustomobject]@{ Stage = $true; Longest = $longest; Reason = ('the longest file path is {0} characters (limit {1}) -- the build runs from a short copy' -f $longest, $Limit) } }
    [pscustomobject]@{ Stage = $false; Longest = $longest; Reason = ('the longest file path is {0} characters -- the build reads the folder as it is' -f $longest) }
}

function Test-SIBuildHostIsWindows {
    if ($PSVersionTable.PSVersion.Major -lt 6) { return $true }
    [bool]$IsWindows
}

function Get-SIBuildContextLongestPath {
    <# The longest relative file path below -Path, or -1 when the tree cannot be enumerated (a path too long for this host). #>
    param([Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $max = 0
    try {
        foreach ($f in [IO.Directory]::EnumerateFiles($root, '*', [IO.SearchOption]::AllDirectories)) {
            $n = $f.Length - $root.Length - 1
            if ($n -gt $max) { $max = $n }
        }
    } catch { return -1 }
    $max
}

function New-SIBuildStageCopy {
    <#
      Copies -Source to the short folder -Destination with robocopy (it reads and writes paths longer than 260 characters).
      Leaves out what a build never needs: .git, bin, obj, node_modules. robocopy exit codes 0-7 are success, 8+ a failure.
    #>
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    $out = & robocopy $Source $Destination /E /XD .git bin obj node_modules /R:1 /W:1 /NFL /NDL /NJH /NJS /NP 2>&1
    $code = $LASTEXITCODE; $global:LASTEXITCODE = 0
    if ($code -ge 8) { throw ("the build context could not be copied to {0} (robocopy {1}): {2}" -f $Destination, $code, (($out | ForEach-Object { "$_" }) -join ' ').Trim()) }
}

function Get-SIBuildStageRoot {
    <# A short, new folder for one stage: <temp>\sib-<8 hex>; a temp path longer than 60 characters uses <system drive>\sib instead. #>
    $tmp = [IO.Path]::GetTempPath()
    if ($tmp.Length -gt 60 -and $env:SystemDrive) { $tmp = $env:SystemDrive + '\sib' }
    Join-Path $tmp ('sib-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
}

function Invoke-SIInBuildContext {
    <#
      Runs -Action with the current directory at the build context of -Path: the folder itself, or -- when its paths are too
      long for the build on this host -- a short copy of it, removed afterwards. -Action gets the context path as $args[0].
      -Copy / -IsWindowsHost / -Limit: tests only.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Action, [scriptblock]$Copy, [object]$IsWindowsHost, [int]$Limit = 240,
          [scriptblock]$Log)
    $win = if ($null -ne $IsWindowsHost) { [bool]$IsWindowsHost } else { Test-SIBuildHostIsWindows }
    $longest = if ($win) { Get-SIBuildContextLongestPath -Path $Path } else { 0 }
    $d = Get-SIBuildStageDecision -ContextPath ([IO.Path]::GetFullPath($Path)) -LongestRelative $longest -IsWindowsHost $win -Limit $Limit
    $ctx = $Path; $stage = $null
    if ($d.Stage) {
        $stage = Get-SIBuildStageRoot
        if ($Log) { & $Log ("{0}: {1}" -f $d.Reason, $stage) }
        if ($Copy) { & $Copy $Path $stage } else { New-SIBuildStageCopy -Source $Path -Destination $stage }
        $ctx = $stage
    }
    Push-Location -LiteralPath $ctx
    try { & $Action $ctx }
    finally {
        Pop-Location
        if ($stage -and (Test-Path -LiteralPath $stage)) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
            # a long path the stage itself holds is removed by robocopy mirroring an empty folder over it
            if (Test-Path -LiteralPath $stage) {
                $empty = Join-Path ([IO.Path]::GetTempPath()) ('sib-empty-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
                New-Item -ItemType Directory -Force -Path $empty | Out-Null
                try { $null = & robocopy $empty $stage /MIR /R:0 /W:0 /NFL /NDL /NJH /NJS /NP 2>&1; $global:LASTEXITCODE = 0 } catch { }
                Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
