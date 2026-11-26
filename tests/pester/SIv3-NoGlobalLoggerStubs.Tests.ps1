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
    $script:LoggerNames = '(?:Write-SI\w*|Reset-SIProgress)'
    function script:Find-SIGlobalLoggerStub {
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
        $hits = New-Object System.Collections.Generic.List[string]
        $lines = $Text -split "`r?`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            if ($l -match '^\s*#' -or $l -match 'Remove-Item') { continue }
            # function global:Write-SIInfo { ... } / Set-Item function:global:Write-SIWarn
            if ($l -match ('(?i)function\s+global:{0}\b' -f $script:LoggerNames) -or $l -match ('(?i)function:\\?global:{0}\b' -f $script:LoggerNames)) { $hits.Add(($i + 1)); continue }
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
