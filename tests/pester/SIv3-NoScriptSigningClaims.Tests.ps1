#Requires -Version 5.1
<#
    PUBLIC TEXT SAYS NOTHING ABOUT SCRIPT SIGNING (owner 2026-10-28: "scripts are not signed"; public text names no
    script signing until it is live -- no "signed" claim and no "not signed" either, only the SHA256SUMS check).

    What must hold: no page, pack, drawing or slide that is handed over or published names Authenticode, Trusted
    Signing, a code-signing certificate, NOT SIGNED or unsigned scripts. The signed UPDATE MANIFESTS stay named -- they
    are real -- so "signed release" / "signed manifest" is not matched.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Rx = '(?i)Authenticode|Trusted Signing|code-signing|NOT SIGNED|unsigned script|scripts are (?:not )?signed|signed scripts'
    $script:Public = @(
        'docs\DESIGN.md', 'docs\FEATURES.md', 'README.md', 'RELEASENOTES.md'
    ) | ForEach-Object { Join-Path $script:SIRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }
    foreach ($dir in 'release\product-info', 'pro-management\src\SI.Management.Web\ProductDocs') {
        $p = Join-Path $script:SIRoot $dir
        if (Test-Path -LiteralPath $p) {
            $script:Public += @(Get-ChildItem -LiteralPath $p -Recurse -File -Include '*.md', '*.json', '*.html', '*.txt' |
                Where-Object { $_.Name -ne 'IN-BUILD.md' } | ForEach-Object { $_.FullName })
        }
    }
}

Describe 'public text says nothing about script signing' {

    It 'finds the public pages it checks' {
        @($script:Public).Count | Should -BeGreaterThan 10
    }

    It 'no public page, pack, drawing or slide names script signing' {
        $hits = foreach ($f in $script:Public) {
            $n = 0
            foreach ($line in [IO.File]::ReadAllLines($f)) {
                $n++
                if ($line -match $script:Rx) { '{0}:{1} -> {2}' -f $f.Substring($script:SIRoot.Length + 1), $n, $Matches[0] }
            }
        }
        @($hits) | Should -BeNullOrEmpty -Because 'scripts are not signed and public text says nothing about script signing until it is live'
    }

    It 'the guard catches a claim and a "not signed" line alike' {
        'Every script is Authenticode-signed with the vendor''s certificate.' | Should -Match $script:Rx
        'NOT SIGNED today.' | Should -Match $script:Rx
        'Releases are signed by Invardia and verified by the install.' | Should -Not -Match $script:Rx
    }
}
