#Requires -Version 5.1
<#
    SETUP GRANTS READER ONLY; TAG CONTRIBUTOR IS AN EXPLICIT OPT-IN (#142).

    Operator decision 2026-09-28: "Reader only; Tag Contributor only when explicitly opted in". SI collection is
    read-only, and Tag Contributor at tenant root lets the SPN write tags on every resource in the tenant --
    only the asset-tagging engine needs it. New-SISpn already made it opt-in (-IncludeTagContributor), but
    the two v2 setup scripts that granted it by default are retired in v3 (#755); what stays checked is the wizard's
    switch and that no shipped script hard-codes Reader + Tag Contributor.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function script:Get-AzureRolesExpr([string]$Path) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $ht = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] -and
                (@($n.KeyValuePairs | Where-Object { $_.Item1.Extent.Text -eq 'AzureRoles' }).Count -gt 0) }, $true) | Select-Object -First 1
        if (-not $ht) { return $null }
        ($ht.KeyValuePairs | Where-Object { $_.Item1.Extent.Text -eq 'AzureRoles' } | Select-Object -First 1).Item2.Extent.Text
    }
    function script:Eval([string]$Expr, [bool]$OptIn) {
        & ([scriptblock]::Create(('param($IncludeTagContributor) ' + $Expr))) $OptIn
    }
}

Describe 'the default Azure role set is Reader only' {
    It 'New-SISpn still adds Tag Contributor only under its switch' {
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\New-SISpn.ps1') -Raw) |
            Should -Match "(?s)if \(\`$IncludeTagContributor\) \{\s*\`$tenantRolePairs \+= @\{Name='Tag Contributor'"
    }
    It 'no shipped script hard-codes Reader + Tag Contributor as a default any more' {
        $hits = Get-ChildItem $script:SIRoot -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\tests\\' } |
                Select-String -Pattern "@\('Reader',\s*'Tag Contributor'\)" | ForEach-Object { '{0}:{1}' -f $_.Filename, $_.LineNumber }
        @($hits).Count | Should -Be 0 -Because ($hits -join ', ')
    }
}
