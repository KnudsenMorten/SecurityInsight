#Requires -Version 7.0
<#
    #1415 NO SUITE LEAVES A GLOBAL LOGGER STUB BEHIND. A suite that defined Write-SIInfo / Write-SIWarn (or the progress
    helpers) as GLOBAL no-op or capture stubs outlived its own file in a shared Pester process: the next suite's product code
    wrote its lines into the stub, and the assertions on those lines read nothing (SIv3-ParentTagsParts, SIv3-PayloadProfile,
    SIv3-MfaUnknownNotNoMfa after SIv3-RoleReadCheck / SIv3-ScaleReaders*). Stubs go in script scope (function:script:, or
    function script:Name) -- visible to the product dot-sourced into the suite, gone with the suite.
    Static: the suites' text is read, nothing run.
#>

BeforeAll {
    $script:PesterDir = $PSScriptRoot
    # #1420 (a): the Risk Analysis loggers (Write-Info / Write-Warn2 / Write-Ok / Write-Diag / Write-Err2) leaked the same way
    $script:LoggerNames = '(?:Write-SI\w*|Reset-SIProgress|Write-Info|Write-Warn2|Write-Ok|Write-Diag|Write-Err2)'
    function script:Find-SIGlobalLoggerStub {
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
        $hits = New-Object System.Collections.Generic.List[string]
        $lines = $Text -split "`r?`n"
        # #1420 (c): a suite that SAVES a global logger and RESTORES it ($old = Get-Item function:global:X ... Set-Item
        # function:global:X -Value $old) leaves nothing behind -- that logger's lines are not a leak
        $kept = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in [regex]::Matches($Text, ('(?im)^[^#\r\n]*\$(\w+)\s*=\s*[^\r\n]*function:\\?global:({0})\b' -f $script:LoggerNames))) {
            $var = [regex]::Escape($m.Groups[1].Value); $nm = $m.Groups[2].Value
            if ($Text -match ('(?im)^[^#\r\n]*(?:Set-Item|New-Item)[^\r\n]*function:\\?global:{0}\b[^\r\n]*-Value\s+\(?\${1}\b' -f [regex]::Escape($nm), $var)) { [void]$kept.Add($nm) }
        }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            if ($l -match '^\s*#' -or $l -match 'Remove-Item') { continue }
            $nm = ''
            if ($l -match ('(?i)(?:function\s+global:|function:\\?global:)({0})\b' -f $script:LoggerNames)) { $nm = $Matches[1] }
            if ($nm -and $kept.Contains($nm)) { continue }
            # function global:Write-SIInfo { ... } / Set-Item function:global:Write-SIWarn
            if ($nm) { $hits.Add(($i + 1)); continue }
            # foreach ($n in 'Write-SIInfo', ...) { ... Set-Item -Path ("function:global:{0}" -f $n) ... } (same or next line)
            if ($l -match '(?i)function:\\?global:\{0\}') {
                $ctx = $l; if ($i -gt 0) { $ctx = $lines[$i - 1] + "`n" + $l }
                if ($ctx -match ("(?i)foreach\s*\(\s*\`$\w+\s+in\s+[^)]*'{0}'" -f $script:LoggerNames)) { $hits.Add(($i + 1)) }
            }
        }
        $hits.ToArray()
    }
}

Describe 'no suite defines a global Write-SI* logger stub (#1415)' {
    It 'the check finds each shape it guards against (control)' {
        @(Find-SIGlobalLoggerStub -Text "function global:Write-SIInfo { param(`$m) }").Count | Should -Be 1
        @(Find-SIGlobalLoggerStub -Text "Set-Item -Path 'function:global:Write-SIWarn' -Value { }").Count | Should -Be 1
        @(Find-SIGlobalLoggerStub -Text "foreach (`$n in 'Write-SIInfo', 'Write-SIWarn') {`n    if (-not (Get-Command `$n)) { Set-Item -Path (`"function:global:{0}`" -f `$n) -Value { param() } }`n}").Count | Should -Be 1
        @(Find-SIGlobalLoggerStub -Text "foreach (`$n in 'Write-SIInfo') { Set-Item -Path (`"function:script:{0}`" -f `$n) -Value { } }").Count | Should -Be 0
        @(Find-SIGlobalLoggerStub -Text "foreach (`$n in 'Get-AzContext') { Set-Item -Path (`"function:global:{0}`" -f `$n) -Value { } }").Count | Should -Be 0 -Because 'only the loggers are guarded here'
        @(Find-SIGlobalLoggerStub -Text "Remove-Item -Path 'function:global:Write-SIInfo'").Count | Should -Be 0 -Because 'removing one is a clean-up, not a stub'
        # #1420 (a): the Risk Analysis loggers are guarded too
        @(Find-SIGlobalLoggerStub -Text "function global:Write-Warn2 { param(`$m) }").Count | Should -Be 1
        @(Find-SIGlobalLoggerStub -Text "function script:Write-Info { param(`$m) }").Count | Should -Be 0
        # #1420 (c): saved and restored = no leak; set without the restore = still a hit
        $saveRestore = "`$old = Get-Item function:global:Write-SIInfo`nSet-Item -Path function:global:Write-SIInfo -Value { param(`$m) }`ntry { } finally { Set-Item -Path function:global:Write-SIInfo -Value `$old }"
        @(Find-SIGlobalLoggerStub -Text $saveRestore).Count | Should -Be 0 -Because 'the suite puts back what it found'
        @(Find-SIGlobalLoggerStub -Text "`$old = Get-Item function:global:Write-SIInfo`nSet-Item -Path function:global:Write-SIInfo -Value { param(`$m) }").Count | Should -BeGreaterThan 0 -Because 'saved but never restored is a leak'
    }
    It 'the check reads the suites (control)' {
        @(Get-ChildItem -LiteralPath $script:PesterDir -Filter '*.Tests.ps1' -File).Count | Should -BeGreaterThan 100
    }
    It 'no suite under tests/pester defines one' {
        $found = foreach ($f in Get-ChildItem -LiteralPath $script:PesterDir -Filter '*.ps1' -File) {
            if ($f.Name -eq 'SIv3-NoGlobalLoggerStubs.Tests.ps1') { continue }
            $h = @(Find-SIGlobalLoggerStub -Text ([IO.File]::ReadAllText($f.FullName)))
            if ($h.Count) { '{0}:{1}' -f $f.Name, ($h -join ',') }
        }
        @($found) -join '; ' | Should -BeExactly '' -Because 'a global logger stub outlives the suite in a shared Pester process -- use function:script:'
    }
}
