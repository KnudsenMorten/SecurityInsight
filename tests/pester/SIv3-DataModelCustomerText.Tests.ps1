#Requires -Version 5.1
<#
    THE DATA MODEL'S CUSTOMER-FACING TEXT NAMES NO INTERNAL NUMBER (CLAUDE.md rule 3).
    The field catalog, the risk factors and the other data-model templates are shown in the Pro web app and published into
    the customer's database; their descriptions, names and labels are customer text. A field-catalog merge on 2026-10-10
    shipped 13 descriptions ending "(#505)". OFFLINE: reads every shipped data-model template.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Files = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'data-model') -Filter '*.locked.json' -Recurse -File)
    function script:Get-CustomerText($Node, [string]$Path) {
        if ($null -eq $Node) { return }
        if ($Node -is [System.Array]) { $i = 0; foreach ($x in $Node) { Get-CustomerText $x ('{0}[{1}]' -f $Path, $i); $i++ }; return }
        if ($Node -is [pscustomobject]) {
            foreach ($p in $Node.PSObject.Properties) {
                if ($p.Name -in @('description', 'name', 'label', 'title', 'displayName') -and $p.Value -is [string]) {
                    [pscustomobject]@{ Path = ('{0}.{1}' -f $Path, $p.Name); Text = [string]$p.Value }
                } else { Get-CustomerText $p.Value ('{0}.{1}' -f $Path, $p.Name) }
            }
        }
    }
}

Describe 'Data-model customer text' {
    It 'finds the shipped data-model templates' {
        $script:Files.Count | Should -BeGreaterThan 5
    }
    It 'no description, name or label carries an internal number (#123)' {
        $bad = foreach ($f in $script:Files) {
            $doc = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
            foreach ($t in @(Get-CustomerText $doc '')) {
                if ($t.Text -match '#\d{2,4}\b') { '{0}{1}: {2}' -f $f.Name, $t.Path, $t.Text }
            }
        }
        @($bad) | Should -BeNullOrEmpty
    }
}
