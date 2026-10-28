#Requires -Version 5.1
<#
    SI v3 -- #102. A COMMENT INSIDE A BACKTICK CONTINUATION SILENTLY TRUNCATES THE COMMAND.

    🔴 WHAT HAPPENED. On 2026-08-31 one correction was applied at three call sites: pass the FULL row
    set to `CheckCreateUpdate-TableDcr-Structure` rather than a sample, because AzLogDcrIngestPS infers
    the table's column set from whatever it is handed. The explanation was written **between two
    backtick-continued argument lines** -- and a comment ENDS a backtick continuation. Every argument
    after the comment was dropped, **including the `-Data` the comment was added to introduce.**

    ⏱️ OBSERVED ON A REAL RUN 2026-09-02. The correlation engine correlated 1274 rows into 1273
    objects, updated the identity ledger, built 2095 map rows -- and then died at publish:

        Send-SIObjectMapRows : Cannot process command because of one or more missing mandatory
        parameters: Data AzDcrSetLogIngestApiAppPermissionsDcrLevel AzLogDcrTableCreateFromReferenceMachine

    Those three are **exactly** the mandatory parameters that sit after the comment block. Reproduced
    in isolation: a two-line comment between `-A 'first' \`` and `-Data 'payload'` throws
    `missing mandatory parameters: Data Flag`.

    🪤 THE TWO SIBLING SITES FAILED QUIETLY INSTEAD. `Invoke-SchemaOutput.ps1` and `Invoke-Tagging.ps1`
    make the same call inside a try/catch, so their audit tables simply stopped being maintained while
    the profilers reported success. **The loud failure is the lucky one.**

    📌 A PARSE CHECK DOES NOT CATCH THIS -- the file is valid PowerShell, and that is the whole
    problem. It has to be a lexical rule, which is what this file is.

    🔒 THE RULE: a line of CODE ending in a continuation backtick may not be followed by a comment
    line. Put the comment above the statement.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path

    function script:Find-SICommentInContinuation {
        param([Parameter(Mandatory)][string]$Root)
        $found = New-Object System.Collections.ArrayList
        $files = Get-ChildItem -Path $Root -Filter *.ps1 -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch '\\tests\\' }
        foreach ($f in $files) {
            $lines = [System.IO.File]::ReadAllLines($f.FullName)
            for ($i = 0; $i -lt $lines.Count - 1; $i++) {
                # 🪤 THE `-notmatch '^\s*#'` ON THE FIRST LINE IS LOAD-BEARING. Without it this finds 54
                # hits instead of 3 -- because a COMMENT line ending in a markdown code span (…`) looks
                # identical to a continuation. A check that cries wolf 51 times is a check nobody reads.
                if ($lines[$i] -match '`\s*$' -and $lines[$i] -notmatch '^\s*#' -and $lines[$i + 1] -match '^\s*#') {
                    [void]$found.Add(('{0}:{1}' -f $f.FullName.Substring($Root.Length + 1), ($i + 1)))
                }
            }
        }
        , $found.ToArray()
    }
}

Describe '🔬 THE RULE IS REAL -- PowerShell is run, not quoted' {

    It 'a comment between continued argument lines DROPS every argument after it' {
        # Not asserted from documentation: the shipped runtime is asked directly, and the failure it
        # produces is the same shape as the live one.
        $repro = @'
function Test-Target {
    param([Parameter(Mandatory)]$A, [Parameter(Mandatory)]$Data, [Parameter(Mandatory)]$Flag)
    'BOUND'
}
try {
    Test-Target `
        -A 'first' `
        # a comment inside the continuation chain
        -Data 'payload' `
        -Flag $true
} catch { 'THREW: ' + $_.Exception.Message }
'@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($repro))
        $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -EncodedCommand $enc 2>&1
        $joined = (@($out) | ForEach-Object { [string]$_ }) -join ' '
        $joined | Should -Match 'missing mandatory parameters'
        $joined | Should -Match 'Data'
        $joined | Should -Not -Match 'BOUND'
    }

    It 'and the same call with the comment moved ABOVE it binds normally' {
        # The control. Without it, the test above only proves that something failed.
        $repro = @'
function Test-Target {
    param([Parameter(Mandatory)]$A, [Parameter(Mandatory)]$Data, [Parameter(Mandatory)]$Flag)
    'BOUND'
}
# a comment above the statement
Test-Target `
    -A 'first' `
    -Data 'payload' `
    -Flag $true
'@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($repro))
        $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -EncodedCommand $enc 2>&1
        ((@($out) | ForEach-Object { [string]$_ }) -join ' ') | Should -Match 'BOUND'
    }
}

Describe '🔒 NO SHIPPED FILE PUTS A COMMENT INSIDE A CONTINUATION' {

    It 'the scanner actually reads files -- or the assertion below is vacuous' {
        # A source scan that matches no files passes for the wrong reason.
        @(Get-ChildItem -Path $script:SIRootDir -Filter *.ps1 -Recurse -File |
            Where-Object { $_.FullName -notmatch '\\tests\\' }).Count | Should -BeGreaterThan 100
    }

    It 'and finds none' {
        # Three existed on 2026-09-02, all introduced by one change on 2026-08-31:
        #   engine\asset-correlation\_shared\SI-CorrelationIngest.ps1   -> failed loudly every run
        #   engine\asset-profiling\stages\Invoke-SchemaOutput.ps1       -> failed quietly in a catch
        #   engine\asset-profiling\stages\Invoke-Tagging.ps1            -> failed quietly in a catch
        $offenders = script:Find-SICommentInContinuation -Root $script:SIRootDir
        ($offenders -join ', ') | Should -Be ''
    }
}
