#Requires -Version 5.1
<#
    SI v3 -- #104. THE 2-PHASE CL FETCH CAPTURED THE WRONG `| project` AND BUILT AN UNPARSEABLE QUERY.

    🔴 THE DEFECT. `Resolve-ProfileAugmentPlan`'s let-block regex anchored `(?<proj>…)` on the FIRST
    `| project` after the table name. When the let-block contains a NESTED `| join kind=leftouter ( … )`
    — which the v3 asset-identity backfill authors into the catalog to carry `_v3Pk` / `_v3Name` /
    `_v3Id` — that first project belongs to the INNER subquery, so the capture ran past the subquery's
    closing bracket. The fetch then contained a bare `) on $left.PrimaryEntityId == $right._v3Pk` with
    nothing that opened it, and Log Analytics answered `SYN0002 — could not be parsed at ')'`.

    🪤 AND IT WAS ALL BUT INVISIBLE. `Invoke-ProfileAugment` catches the error, warns once, and continues
    with an EMPTY lookup — which is CACHED per (TableName, RightKey). MEASURED on the 2026-09-02 chain:
    the Detailed grain built **20 plans, every one keyed SI_Azure_Profile_CL | Target_AzureResourceId_Guid**,
    so ONE failed fetch emptied all 20 while the log said `CL fetch failed` exactly once, and every
    augment line read `0 hits`. The ColumnFillGuard passed on that same run, because the columns had been
    empty on the previous run too — it catches a REGRESSION, and a defect stable across runs looks like
    steady state.

    🔬 THE FIXTURE IS THE POINT OF THIS FILE, AND IT WAS EXPENSIVE TO GET.
    `tests/fixtures/ra-augment-input-104.kql` is the EXACT string the engine handed the resolver on a
    real run, captured via `$global:SI_RA_DumpAugmentInput`. It is not reconstructed and not hand-written.
    🔴 **Do not be tempted to substitute `staging/risk-analysis/ra-rendered-*.kql`.** Those are written
    AFTER the legacy path inlines the CL snapshot as a `datatable(…)` — they are the OUTPUT of the
    decision this resolver makes, never its input. MEASURED: the UNMODIFIED resolver returns **0 plans on
    all 79** of them, so a control run there cannot tell a good change from a bad one. Two fixes were
    "verified" against those files before that control was run, and both measurements were noise.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:AugmentFile = Join-Path $script:SIRootDir 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1'
    $script:Fixture     = Join-Path $script:SIRootDir 'tests\fixtures\ra-augment-input-104.kql'

    # The resolver is exercised in a CHILD process: it is a large regex over a 26 KB query, and a
    # pathological variant of it can backtrack for minutes. A child keeps a bad edit from wedging the
    # whole suite, and lets the timeout below turn that into a readable failure.
    function script:Get-Plans {
        param([string]$ModulePath, [string]$QueryPath, [int]$TimeoutSec = 120)
        $code = @"
`$ErrorActionPreference='Continue'
function Write-Info  { param(`$m) }
function Write-Warn2 { param(`$m) }
. '$ModulePath'
`$kql = [System.IO.File]::ReadAllText('$QueryPath')
`$r = Resolve-ProfileAugmentPlan -Query `$kql
`$p = @(`$r.Plans)
'PLANS=' + `$p.Count
foreach (`$x in `$p) {
    `$pk = [string]`$x['ProjectionKql']
    'VAR=' + `$x['Var']
    'RKEY=' + `$x['RightKey']
    'BROKENTAIL=' + (`$pk -match '\)\s*on\s+\`$(?:left|right)')
    'FIRSTPROJ=' + ((`$pk -split "``n" | Where-Object { `$_ -match '\| project' } | Select-Object -First 1).Trim())
}
"@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        # the child runs the gate's own PowerShell (v3 gates PowerShell 7 only, 2026-10-09; 5.1 on the opt-in)
        $job = Start-Job -ScriptBlock { param($e, $x) & $x -NoProfile -NonInteractive -EncodedCommand $e 2>&1 } -ArgumentList $enc, (Get-Process -Id $PID).Path
        if (Wait-Job $job -Timeout $TimeoutSec) { $out = Receive-Job $job } else { Stop-Job $job; $out = @('TIMEOUT') }
        Remove-Job $job -Force
        , @($out | ForEach-Object { [string]$_ })
    }
}

Describe '🔬 The fixture is real, and it is the input -- not an artefact of the decision' {

    It 'the captured input exists and is the query, not an inlined datatable' {
        Test-Path $script:Fixture | Should -BeTrue
        $kql = Get-Content $script:Fixture -Raw
        $kql.Length | Should -BeGreaterThan 10000
        # The tell-tale of the WRONG artefact: the legacy path rewrites the let-block to a datatable.
        $kql | Should -Not -Match 'let\s+_TargetCmdb\s*=\s*datatable\('
        # The shape under test: a CL let-block containing a NESTED join.
        $kql | Should -Match 'let\s+_TargetCmdb\s*='
        $kql | Should -Match '_v3Pk'
        $kql | Should -Match 'join\s+kind\s*=\s*leftouter'
    }
}

Describe '🔴 The shipped resolver builds a PARSEABLE fetch from that input' {

    BeforeAll { $script:Now = script:Get-Plans -ModulePath $script:AugmentFile -QueryPath $script:Fixture }

    It 'did not hang' { $script:Now | Should -Not -Contain 'TIMEOUT' }

    It 'still produces the plan -- the fix must not disable 2-phase to avoid the bug' {
        # Declining the plan would also "fix" the empty columns, by pushing every one of these reports
        # onto the inline-datatable path the 2-phase design exists to avoid. That is not the fix.
        ($script:Now | Where-Object { $_ -like 'PLANS=*' }) | Should -Be 'PLANS=1'
        ($script:Now | Where-Object { $_ -like 'VAR=*' })    | Should -Be 'VAR=_TargetCmdb'
        ($script:Now | Where-Object { $_ -like 'RKEY=*' })   | Should -Be 'RKEY=Target_AzureResourceId_Guid'
    }

    It '🔒 and the fetch carries NO orphaned join tail -- this is the defect' {
        ($script:Now | Where-Object { $_ -like 'BROKENTAIL=*' }) | Should -Be 'BROKENTAIL=False'
    }

    It 'because it captured the OUTER projection, not the nested subquery''s' {
        $first = ($script:Now | Where-Object { $_ -like 'FIRSTPROJ=*' })
        $first | Should -BeLike '*Target_AzureResourceId_Guid*'
        $first | Should -Not -BeLike '*_v3Pk*'
    }
}

Describe '🔬 THE CONTROL -- the pre-fix regex reproduces the live failure on this same input' {

    # 🔑 Without this, the assertions above prove only that the current code works, not that they guard
    # anything. The pre-fix regex differed by ONE quantifier: `[^;]*?` (lazy) before `| project` instead
    # of `[^;]*` (greedy). Reconstructed here from the shipped source so it cannot drift into fiction.

    BeforeAll {
        $script:PreFix = Join-Path ([System.IO.Path]::GetTempPath()) ('RA-ProfileAugment-prefix-{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
        $src = [System.IO.File]::ReadAllText($script:AugmentFile)
        $greedy = '_CL\b[^;]*\|\s*project\s+(?<proj>[^;]*?)\|\s*where'
        $lazy   = '_CL\b[^;]*?\|\s*project\s+(?<proj>[^;]*?)\|\s*where'
        $script:GreedyPresent = $src.Contains($greedy)
        [System.IO.File]::WriteAllText($script:PreFix, $src.Replace($greedy, $lazy), (New-Object System.Text.UTF8Encoding($true)))
    }
    AfterAll { if ($script:PreFix -and (Test-Path $script:PreFix)) { Remove-Item $script:PreFix -Force -ErrorAction SilentlyContinue } }

    It '🪤 the greedy quantifier is actually present in the shipped source' {
        # If this fails, the reconstruction below rewrote nothing and the control is vacuous -- the same
        # trap the cancelled-on-creation suite guards with its "extracted both shipped predicates" check.
        $script:GreedyPresent | Should -BeTrue
    }

    It 'the pre-fix regex yields a fetch WITH the orphaned join tail' {
        $before = script:Get-Plans -ModulePath $script:PreFix -QueryPath $script:Fixture
        $before | Should -Not -Contain 'TIMEOUT'
        ($before | Where-Object { $_ -like 'PLANS=*' })      | Should -Be 'PLANS=1'
        ($before | Where-Object { $_ -like 'BROKENTAIL=*' }) | Should -Be 'BROKENTAIL=True'
        ($before | Where-Object { $_ -like 'FIRSTPROJ=*' })  | Should -BeLike '*_v3Pk*'
    }
}

Describe '🔒 The diagnostic capture that produced the fixture stays inert by default' {

    BeforeAll {
        $script:HuntFile = Join-Path $script:SIRootDir 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'
        $script:HuntRaw  = Get-Content $script:HuntFile -Raw
    }

    It 'every write is behind $global:SI_RA_DumpAugmentInput' {
        # ~6,000 installs never set it; they must pay nothing and write nothing.
        ([regex]::Matches($script:HuntRaw, 'if \(\$global:SI_RA_DumpAugmentInput\)')).Count | Should -Be 2
        $script:HuntRaw | Should -Match 'ra-augin-'
    }

    It 'and no CODE anywhere in the shipped tree enables it by default' {
        # 🪤 Comments must be stripped first. The instruction "Set $global:SI_RA_DumpAugmentInput = $true
        # to enable" lives in a comment two lines above the guard, and a naive scan flags the very file
        # that implements the guard correctly -- a check that indicts its own subject teaches nothing.
        $setters = New-Object System.Collections.ArrayList
        foreach ($f in (Get-ChildItem -Path $script:SIRootDir -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.FullName -notmatch '\\tests\\' })) {
            $raw = [System.IO.File]::ReadAllText($f.FullName)
            if ($raw -notmatch 'SI_RA_DumpAugmentInput') { continue }
            $noBlocks = [regex]::Replace($raw, '(?s)<#.*?#>', '')
            $code = ($noBlocks -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            if ($code -match '\$global:SI_RA_DumpAugmentInput\s*=') {
                [void]$setters.Add($f.FullName.Substring($script:SIRootDir.Length + 1))
            }
        }
        ($setters -join ', ') | Should -Be ''
    }
}
