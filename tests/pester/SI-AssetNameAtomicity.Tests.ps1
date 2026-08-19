#Requires -Version 5.1
<#
    v2.2.441 -- AN ASSET NAME IS ATOMIC. Only a column that is genuinely a LIST may be split.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS.

    WHAT HAPPENED. A customer's Detailed AI-summary email ranked "Cloud" and "ID)" as Tier 0 top-risk
    assets. Resolve-AssetNamesForRow's DETAILED branch -- documented one line above itself as "one asset
    per row in a dedicated column" -- split that single value on [,;]. So one identity became three:

        "<Person> (Admin, Cloud, ID)"  ->  "<Person> (Admin" + "Cloud" + "ID)"
        "Service Account, Reporting"   ->  "Service Account" + "Reporting"

    WHY IT MATTERS MORE THAN IT LOOKS. Each fragment aggregates as its own asset: its own risk score,
    its own row in the Top-N. The real asset's findings are divided across phantoms, the phantoms crowd
    genuine assets out of a ranked list an operator is meant to act on, and the same person can appear
    TWICE with different scores -- once whole (via the JSON list path) and once shredded (via this one).

    SECOND TIME FOR THIS CLASS. Split-ImpactedAssets already carries a note about a previous version
    tokenizing on whitespace and exploding one description into ~10 fake assets ("account", "with",
    "SPN", "can", "Admin"...). Same mistake, different delimiter. Hence this file guards the PROPERTY --
    a name is atomic -- rather than the one delimiter that happened to bite.

    No real customer names appear here; all fixtures are invented.
#>

$script:Ps51Path = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:HasPs51  = Test-Path -LiteralPath $script:Ps51Path

BeforeAll {
    $script:SIRoot = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..') ''
    $raShared  = Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') '_shared'
    $script:RaEngineFile = Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') 'Invoke-RiskAnalysis.ps1'

    . (Join-Path $raShared 'RA-RowShaping.ps1')
    . (Join-Path $raShared 'RA-RunProgress.ps1')

    # Split-ImpactedAssets is declared INSIDE Invoke-RiskAnalysis.ps1 (it is in scope at runtime
    # because Resolve-AssetNamesForRow is called from there). Extract it by AST rather than copying it,
    # so this file can never drift from the shipped implementation.
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:RaEngineFile, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Invoke-RiskAnalysis.ps1 has parse errors: $($errors[0].Message)" }
    $fn = @($ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Split-ImpactedAssets'
    }, $true))
    if ($fn.Count -ne 1) { throw "expected exactly one Split-ImpactedAssets definition, found $($fn.Count)" }
    $script:SplitText = $fn[0].Extent.Text
    . ([scriptblock]::Create($script:SplitText))
}

Describe 'the DETAILED single-asset column is atomic -- one row, one asset' {

    It 'keeps <Name> whole' -ForEach @(
        @{ Name = 'SVC-Reporting (Admin, Cloud, ID)' }
        @{ Name = 'Service Account, Reporting' }
        @{ Name = 'Doe, Jane (Admin, Cloud, ID)' }
        @{ Name = 'app-01; app-02 shared alias' }
        @{ Name = 'plain-host.example.test' }
    ) {
        $out = Resolve-AssetNamesForRow -Row ([pscustomobject]@{ AssetName = $Name }) -AssetsText $null
        @($out).Count | Should -Be 1 -Because "an asset NAME is atomic; '$Name' is one asset, not a list"
        @($out)[0]    | Should -Be $Name
    }

    It 'the exact customer shape produces ONE asset, not three phantoms' {
        # The reported symptom, reproduced: "Cloud" and "ID)" were ranked as Tier 0 assets.
        $out = @(Resolve-AssetNamesForRow -Row ([pscustomobject]@{ AssetName = 'SVC-Reporting (Admin, Cloud, ID)' }) -AssetsText $null)
        $out.Count | Should -Be 1
        $out | Should -Not -Contain 'Cloud'
        $out | Should -Not -Contain 'ID)'
    }

    It 'falls back across the alternate name columns without splitting them either' {
        $out = Resolve-AssetNamesForRow -Row ([pscustomobject]@{ DeviceName = 'Doe, Jane (Admin)' }) -AssetsText $null
        @($out).Count | Should -Be 1
        @($out)[0]    | Should -Be 'Doe, Jane (Admin)'
    }

    It 'a row with no resolvable name yields nothing rather than a blank asset' {
        @(Resolve-AssetNamesForRow -Row ([pscustomobject]@{ Unrelated = 'x' }) -AssetsText $null).Count | Should -Be 0
    }
}

Describe 'the LIST column still splits -- the fix must not disable splitting everywhere' {

    It 'a JSON array becomes one asset per element' {
        # NEGATIVE PASS for the fix above: if this ever returns 1, the fix went too far and the
        # Summary path stopped resolving assets at all.
        $json = ConvertTo-Json -Compress @('host-a.example.test', 'host-b.example.test', 'host-c.example.test')
        $out  = @(Resolve-AssetNamesForRow -Row ([pscustomobject]@{}) -AssetsText $json)
        $out.Count | Should -Be 3
    }

    It 'and a comma INSIDE a JSON element stays part of that element' {
        # The whole point: the delimiter is the array structure, not a character inside a name.
        $json = ConvertTo-Json -Compress @('host-a.example.test', 'SVC-Reporting (Admin, Cloud, ID)')
        $out  = @(Resolve-AssetNamesForRow -Row ([pscustomobject]@{}) -AssetsText $json)
        $out.Count | Should -Be 2
        $out | Should -Contain 'SVC-Reporting (Admin, Cloud, ID)'
        $out | Should -Not -Contain 'Cloud'
    }

    It 'the list path wins over the single-asset column when both are present' {
        $json = ConvertTo-Json -Compress @('host-a.example.test', 'host-b.example.test')
        $out  = @(Resolve-AssetNamesForRow -Row ([pscustomobject]@{ AssetName = 'ignored.example.test' }) -AssetsText $json)
        $out.Count | Should -Be 2
        $out | Should -Not -Contain 'ignored.example.test'
    }
}

Describe 'HOST-1 -- the list path decodes JSON, so it must agree on the host the ENGINE runs on' {
<#
    Framework finding HOST-1 (DOCS/REQUIREMENTS.md): the suites run pwsh 7, every engine runs Windows
    PowerShell 5.1, and ConvertFrom-Json does not behave identically across them. Split-ImpactedAssets
    decodes JSON, so it is in exactly that risk class -- assert it there rather than assume.
#>

    BeforeAll {
        $script:Ps51 = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }

    It 'a 3-element JSON list resolves to 3 under real PowerShell 5.1' -Skip:(-not $script:HasPs51) {
        $probe = @"
`$ErrorActionPreference = 'Stop'
$script:SplitText
`$out = @(Split-ImpactedAssets -AssetsText '["a.example.test","b.example.test","c.example.test"]')
Write-Output `$out.Count
"@
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ("si-atom-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".ps1")
        Set-Content -LiteralPath $f -Value $probe -Encoding UTF8
        try { [int](@(& $script:Ps51 -NoProfile -ExecutionPolicy Bypass -File $f)[-1]) | Should -Be 3 }
        finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It 'and a comma inside an element survives on PowerShell 5.1 too' -Skip:(-not $script:HasPs51) {
        $probe = @"
`$ErrorActionPreference = 'Stop'
$script:SplitText
`$out = @(Split-ImpactedAssets -AssetsText '["a.example.test","SVC (Admin, Cloud, ID)"]')
Write-Output `$out.Count
"@
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ("si-atom-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".ps1")
        Set-Content -LiteralPath $f -Value $probe -Encoding UTF8
        try { [int](@(& $script:Ps51 -NoProfile -ExecutionPolicy Bypass -File $f)[-1]) | Should -Be 2 }
        finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'the source guard -- the split must not come back' {

    BeforeAll {
        # The exact expression that shipped the defect, kept verbatim as the guard's own fixture.
        $script:BadSplitSample = "`$parts = @(`$val -split '\s*[,;]\s*' | Where-Object { `$_ })"
        $script:BadSplitRegex  = "-split\s+'\\s\*\[,;\]\\s\*'"
        $script:RunProgressSrc = Get-Content -Raw -LiteralPath (Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') '_shared\RA-RunProgress.ps1')
    }

    It 'SELF-CHECK: the pattern actually matches the expression it is meant to forbid' {
        # 🔴 Without this the guard is decoration. The first version of it was over-escaped
        # (`\\\\s` instead of `\\s`), so it matched NOTHING and would have passed happily while the
        # defect sat in the file -- a guard that cannot fire is worse than no guard, because it reads
        # as coverage. Caught by testing the regex against a known-bad sample instead of trusting it.
        $script:BadSplitSample | Should -Match $script:BadSplitRegex
    }

    It 'the DETAILED branch contains no [,;] split' {
        $script:RunProgressSrc | Should -Not -Match $script:BadSplitRegex
    }
}

Describe 'mail attachment size guard -- an oversized workbook must not take the whole message with it' {
<#
    v2.2.441. The mail step attaches the .xlsx. With the Excel cap now admitting up to 1,000,000 rows
    that file can reach hundreds of MB, and an oversized attachment does not arrive truncated -- the
    relay rejects the ENTIRE message, so the operator loses the AI summary and the findings too.

    The subtle part, and the reason this is a function rather than an inline comparison: MIME
    attachments are base64-encoded and inflate by ~37%. A check against the on-disk size passes for a
    20 MB file and the relay still refuses 27 MB of message.
#>

    BeforeAll {
        . (Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') '_shared\RA-Mail.ps1')
    }

    It 'measures the ENCODED size, not the size on disk' {
        # 20 MB file -> ~27.4 MB message. On-disk logic would have said "fits" against a 20 MB budget.
        $r = Test-SIMailAttachmentFits -SizeBytes (20MB) -MaxMb 20
        $r.DiskMb    | Should -Be 20
        $r.EncodedMb | Should -BeGreaterThan 27
        $r.Fits      | Should -BeFalse -Because 'the wire size is what the relay enforces'
    }

    It 'admits a workbook that genuinely fits the 20 MB budget' {
        $r = Test-SIMailAttachmentFits -SizeBytes (10MB) -MaxMb 20
        $r.Fits | Should -BeTrue
    }

    It 'the shipped default budget is 20 MB' {
        (Test-SIMailAttachmentFits -SizeBytes (1MB)).MaxMb | Should -Be 20
    }

    It 'a typical report attaches without complaint' {
        # ~0.7 MB is what a real Detailed run produces today; it must not trip the guard.
        (Test-SIMailAttachmentFits -SizeBytes (700KB) -MaxMb 20).Fits | Should -BeTrue
    }

    It 'a huge workbook is refused' {
        (Test-SIMailAttachmentFits -SizeBytes (250MB) -MaxMb 20).Fits | Should -BeFalse
    }

    It 'the engine DROPS THE ATTACHMENT and still sends -- it must never skip the mail' {
        # The trade only works if the message still goes out; losing the summary to save the
        # spreadsheet would be the wrong way round.
        $src = Get-Content -Raw -LiteralPath (Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') 'Invoke-RiskAnalysis.ps1')
        $src | Should -Match 'Test-SIMailAttachmentFits'
        $src | Should -Match 'NOT attaching'
        # and the reader is told, at the TOP of the body, where the file actually is
        $src | Should -Match 'too large to attach'
        $src | Should -Match '\$bodyHtml = \$_attachNotice \+ \$bodyHtml'
    }
}
