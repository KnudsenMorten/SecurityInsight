#Requires -Version 5.1
<#
    SecurityInsight (vendor tooling) -- GIT TEXT AS UTF-8, WHATEVER THE CONSOLE (#917).

    Found 2026-10-27 (the ring 0 release 3.0.0.202610272235): Release-SI step 3e read REQUIREMENTS with `& git show
    <commit>:...` in a detached PowerShell (Start-Process, output redirected) whose console encoding was IBM437. PowerShell
    decodes a native command's output with [Console]::OutputEncoding, so every status mark (the open, built, paused, done and closed marks) came back
    garbled, the parser saw 0 open items, and the backlog push removed all 500 from Invardia's backlog.

    Invoke-SIGitText runs git as a process of its own and reads its standard output as UTF-8 BYTES decoded as UTF-8 -- the
    console's encoding is never used. Every `git show` / `git log` of text in SI's release and support tooling goes through
    it. Returns the lines (as `& git` would, without the line ends) and sets $global:LASTEXITCODE to git's exit code. Never
    prints git's standard error (it is returned on -ErrorText when asked). PS 5.1 and 7.
#>

function ConvertTo-SIGitArgumentString {
    <# PURE. The arguments as one command line (Windows rules: a part with a space or a quote is quoted, a quote doubled
       with a backslash) -- for Windows PowerShell 5.1, whose ProcessStartInfo has no ArgumentList. #>
    param([string[]]$Arguments)
    (@($Arguments) | ForEach-Object {
        $a = [string]$_
        if ($a -eq '') { '""' }
        elseif ($a -match '[\s"]') { '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
        else { $a }
    }) -join ' '
}

function Invoke-SIGitText {
    <#
        git -C <RepoRoot> <Arguments>, its output read as UTF-8 whatever the console encoding. Returns string[] (one per line).
        -RepoRoot: the repository (omitted = the current folder). -Git: the git executable (default 'git'). -ErrorText
        [ref]: git's standard error. Sets $global:LASTEXITCODE.
    #>
    param([string]$RepoRoot, [Parameter(Mandatory)][string[]]$Arguments, [string]$Git = 'git', [ref]$ErrorText)
    $all = New-Object System.Collections.Generic.List[string]
    if ("$RepoRoot".Trim()) { $all.Add('-C'); $all.Add($RepoRoot) }
    foreach ($a in @($Arguments)) { $all.Add([string]$a) }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Git
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    if ($psi.PSObject.Properties['ArgumentList'] -and $null -ne $psi.ArgumentList) { foreach ($a in $all) { $psi.ArgumentList.Add($a) } }
    else { $psi.Arguments = ConvertTo-SIGitArgumentString -Arguments $all.ToArray() }
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $errTask = $p.StandardError.ReadToEndAsync()
        $text = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        $err = $errTask.GetAwaiter().GetResult()
        $global:LASTEXITCODE = $p.ExitCode
    } finally { $p.Dispose() }
    if ($ErrorText) { $ErrorText.Value = $err }
    if (-not $text) { return @() }
    $text = $text.TrimStart([char]0xFEFF)
    if ($text.EndsWith("`n")) { $text = $text.Substring(0, $text.Length - 1) }
    [string[]]($text -split "`r?`n")
}

function Get-SIGitFileText {
    <# The text of <Ref>:<Path> (git show), decoded as UTF-8 whatever the console; lines joined with "`n". '' when git
       could not show it ($global:LASTEXITCODE says why). #>
    param([string]$RepoRoot, [Parameter(Mandatory)][string]$Ref, [Parameter(Mandatory)][string]$Path)
    $l = @(Invoke-SIGitText -RepoRoot $RepoRoot -Arguments @('show', ('{0}:{1}' -f $Ref, $Path)))
    if ($global:LASTEXITCODE -ne 0) { return '' }
    (@($l) -join "`n")
}
