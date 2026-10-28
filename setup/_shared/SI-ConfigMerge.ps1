#Requires -Version 5.1
<#
    SecurityInsight -- UPGRADE an existing config\SecurityInsight.custom.ps1 without losing anything (#176).

    Re-running setup on an install that already has a config used to be a choice between two failures:
    refuse (the wizard threw "Refusing to overwrite" AFTER its SPN and infrastructure steps had run; the CLI
    skipped the config entirely, so no new setting was ever added) or regenerate (every hand-added setting --
    and there are many on a long-lived install -- silently gone).

    MERGE instead: every value the customer has stays exactly as it is; only settings the file does not
    assign yet are appended, in one marked block. The file is parsed with the PowerShell parser, not matched
    line by line, so a multi-line value is one statement and is never cut in half.

    Scope, stated: only TOP-LEVEL `$global:Name = ...` assignments are candidates. Logic in the generated file
    (e.g. `if (-not $global:SI_SPN_Secret) { <Key Vault read> }`) is not merged -- a block that reads secrets
    is exactly what must not be duplicated into a file that already has its own.
#>

$script:SIMergeBlockBegin = '# >>> added by SecurityInsight setup -- settings this file did not have yet >>>'
$script:SIMergeBlockEnd   = '# <<< added by SecurityInsight setup <<<'

function Get-SIConfigAssignments {
    <#
      PURE. The top-level $global: assignments in a config script: name -> the statement's full text, in order.
      Throws when the text does not parse -- a broken customer config is reported, never "merged into".
    #>
    param([AllowEmptyString()][string]$Text)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$Text, [ref]$tokens, [ref]$errors)
    if (@($errors).Count) { throw ("the config does not parse: {0} (line {1})" -f $errors[0].Message, $errors[0].Extent.StartLineNumber) }
    $out = [ordered]@{}
    foreach ($st in $ast.EndBlock.Statements) {
        if ($st -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { continue }
        $left = $st.Left
        if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $vp = $left.VariablePath
        if (-not $vp.IsGlobal -and $vp.UserPath -notlike 'global:*') { continue }
        $name = ($vp.UserPath -replace '^global:', '')
        if (-not $out.Contains($name)) { $out[$name] = $st.Extent.Text }
    }
    return $out
}

function Merge-SICustomConfig {
    <#
      PURE. Returns @{ Text; Added } -- the existing text with every assignment from -Generated that the existing
      file does not make appended in one marked block (dated). Nothing already there is changed, re-ordered or
      re-quoted. Nothing missing = the existing text unchanged and Added empty.
    #>
    param(
        [AllowEmptyString()][string]$Existing,
        [AllowEmptyString()][string]$Generated,
        [string]$Stamp = (Get-Date).ToString('yyyy-MM-dd')
    )
    $have = Get-SIConfigAssignments -Text $Existing
    $new  = Get-SIConfigAssignments -Text $Generated
    $added = @($new.Keys | Where-Object { -not $have.Contains($_) })
    if (-not $added.Count) { return [pscustomobject]@{ Text = $Existing; Added = @() } }
    $nl = if ($Existing -match "`r`n") { "`r`n" } else { "`n" }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('')
    $lines.Add("$($script:SIMergeBlockBegin) ($Stamp)")
    foreach ($n in $added) { $lines.Add(($new[$n] -replace "`r?`n", $nl)) }
    $lines.Add($script:SIMergeBlockEnd)
    $sep = if ($Existing.Length -eq 0 -or $Existing.EndsWith("`n")) { '' } else { $nl }
    [pscustomobject]@{ Text = $Existing + $sep + ($lines -join $nl) + $nl; Added = $added }
}

function Update-SICustomConfigFile {
    <#
      Merge -Generated into the config file at -Path. A changed file is backed up to *.bak.<timestamp> first and
      written UTF-8 WITH a BOM (Windows PowerShell 5.1 reads a BOM-less file as ANSI). Returns @{ Path; Added; Backup }.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Generated)
    $existing = [IO.File]::ReadAllText($Path)
    $m = Merge-SICustomConfig -Existing $existing -Generated $Generated
    if (-not @($m.Added).Count) { return [pscustomobject]@{ Path = $Path; Added = @(); Backup = $null } }
    $backup = '{0}.bak.{1:yyyyMMdd-HHmmss}' -f $Path, (Get-Date)
    Copy-Item -LiteralPath $Path -Destination $backup -Force
    [IO.File]::WriteAllText($Path, $m.Text, [Text.UTF8Encoding]::new($true))
    [pscustomobject]@{ Path = $Path; Added = @($m.Added); Backup = $backup }
}
