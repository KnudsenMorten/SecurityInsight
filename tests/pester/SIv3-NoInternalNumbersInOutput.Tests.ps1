#Requires -Version 5.1
<#
    NO INTERNAL TASK / AUDIT NUMBERS IN WHAT A CUSTOMER SEES.

    The 2.2.460 -> 3.0 upgrade test found the run-health message Risk Analysis writes to the customer's
    SI_RunHealth_CL ending in "(audit #62)". Customers read these lines and tables; an internal number means
    nothing to them and makes them call. Comments may carry numbers -- every STRING in the shipped scripts may not.

    The scan is AST-based: every string constant / expandable string in engine\, launcher\, container\, setup\ and
    Update-SecurityInsight.ps1, except
      * arguments to Write-Verbose / Write-Debug / Write-Diag (verbose-only diagnostics), and
      * lines INSIDE a string that are a KQL ('//') or SQL ('--') comment of a query text.
    A hit is 'audit #<n>' (any case) or '#<2-3 digits>' after a space, '(' or '[' or at the start.
#>

BeforeDiscovery {
    $script:SIRootD = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    function script:Get-SIInternalNumberHits {
        param([Parameter(Mandatory)][string]$Root)
        $rx = '(?i)\baudit\s*#\s*\d+|(^|[\s(\[])#\d{2,3}(\.\d+)?\b'
        $quiet = @('Write-Verbose', 'Write-Debug', 'Write-Diag')
        $paths = @('engine', 'launcher', 'container', 'setup') | ForEach-Object { Join-Path $Root $_ } | Where-Object { Test-Path -LiteralPath $_ }
        $files = @(@(Get-ChildItem -LiteralPath $paths -Recurse -Filter '*.ps1' -File) + @(Get-Item -LiteralPath (Join-Path $Root 'Update-SecurityInsight.ps1') -ErrorAction SilentlyContinue))
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in $files) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            $strs = $ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
            foreach ($s in $strs) {
                if ($s.Parent -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { continue }
                $text = [string]$s.Value
                if ($text -notmatch $rx) { continue }
                # query-text comments are not shown to anyone
                $lines = @($text -split "`r?`n" | Where-Object { $_.TrimStart() -notmatch '^(//|--)' })
                if (-not (@($lines | Where-Object { $_ -match $rx }).Count)) { continue }
                $p = $s.Parent; $cmd = ''
                while ($p) {
                    if ($p -is [System.Management.Automation.Language.CommandAst]) { $cmd = [string]$p.GetCommandName(); break }
                    $p = $p.Parent
                }
                if ($quiet -contains $cmd) { continue }
                $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/')
                $one = ($text -replace '\s+', ' ')
                $hits.Add(('{0}:{1}  {2}' -f $rel, $s.Extent.StartLineNumber, $one.Substring(0, [Math]::Min(140, $one.Length))))
            }
        }
        return @($hits)
    }
}

Describe 'customer-facing strings carry no internal task or audit numbers' {
    It 'no shipped string names an audit or task number (every hit is listed as file:line)' {
        $hits = @(Get-SIInternalNumberHits -Root $script:SIRoot)
        $hits | Should -BeNullOrEmpty -Because ("internal numbers reach customer logs, mails and tables:`n" + ($hits -join "`n"))
    }

    It 'the rule catches what it must and leaves alone what it must (self-check)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-noint-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $tmp 'engine')
        Set-Content -LiteralPath (Join-Path $tmp 'Update-SecurityInsight.ps1') -Value '# nothing'
        Set-Content -LiteralPath (Join-Path $tmp 'engine\x.ps1') -Encoding UTF8 -Value @'
# a comment may say audit #62 and #198
Write-Host 'report is PARTIAL (audit #62)'
Write-Warning "see #198 for details"
throw 'failed (#58.2)'
$m = 'bucket lost -- AUDIT #7'
Write-Verbose 'diag only #123'
Write-Host 'colour #FF00AA and C# and issue#12 and 50# and #1'
$q = @"
// #264 -- a KQL comment
T | take 1
"@
'@
        try {
            $h = @(Get-SIInternalNumberHits -Root $tmp)
            $h.Count | Should -Be 4
            ($h -join "`n") | Should -Match 'x\.ps1:2 '
            ($h -join "`n") | Should -Match 'x\.ps1:3 '
            ($h -join "`n") | Should -Match 'x\.ps1:4 '
            ($h -join "`n") | Should -Match 'x\.ps1:5 '
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
