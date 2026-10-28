#Requires -Version 5.1
<#
    ONE TraceID PER FINDING ON ONE ASSET -- TWO DISTINCT ASSETS WITH THE SAME NAME NO LONGER SHARE ONE.

    Measured in the 2026-10-08 release test: 12 TraceIDs were shared by distinct assets with the same name --
    service principals whose names differ only by case (the id is a hash of the LOWER-CASED TraceName) and
    same-named SQL databases on two servers. A Detailed row whose TraceName another row of the same report shares
    while naming a different asset now carries the asset's id before '-SI'. Every other row keeps exactly the
    TraceName / TraceID the engine stamped before, so ids that were already unique do not move.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowShaping.ps1')
    # the id as the engine stamped it before this change: first 16 hex of SHA-256(lower-cased TraceName)
    function Get-OldTraceId([string]$Name) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant()))) -replace '-', '').Substring(0, 16).ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    function New-Row([string]$Asset, [string]$Id, [string]$Cmdb = '') {
        [pscustomobject]@{ ConfigurationName = 'SPN stale secret'; SecuritySeverity = 'High'; cmdbName = $Cmdb; AssetName = $Asset; SI_AssetId = $Id }
    }
}

Describe 'TraceName / TraceID' {
    It 'an asset whose name is unique keeps exactly the id it had' {
        $rows = @((New-Row 'app-one' 'id-1'), (New-Row 'app-two' 'id-2'))
        Set-RATraceIdentity -Rows $rows -IsDetailed $true
        $rows[0].TraceName | Should -BeExactly 'SPN stale secret-High-app-one-SI'
        $rows[0].TraceID   | Should -BeExactly (Get-OldTraceId 'SPN stale secret-High-app-one-SI')
        $rows[1].TraceID   | Should -BeExactly (Get-OldTraceId 'SPN stale secret-High-app-two-SI')
    }

    It 'two service principals whose names differ only by case get two ids' {
        $rows = @((New-Row 'MyApp' 'aaaa-1'), (New-Row 'myapp' 'bbbb-2'))
        Set-RATraceIdentity -Rows $rows -IsDetailed $true
        $rows[0].TraceID | Should -Not -Be $rows[1].TraceID
        $rows[0].TraceName | Should -BeExactly 'SPN stale secret-High-MyApp-aaaa-1-SI'
        $rows[1].TraceName | Should -BeExactly 'SPN stale secret-High-myapp-bbbb-2-SI'
    }

    It 'same-named databases on two servers get two ids; both keep the same id on the next run' {
        $mk = { @((New-Row 'salesdb' '/subscriptions/s/resourceGroups/r/providers/Microsoft.Sql/servers/a/databases/salesdb'),
                  (New-Row 'salesdb' '/subscriptions/s/resourceGroups/r/providers/Microsoft.Sql/servers/b/databases/salesdb')) }
        $run1 = & $mk; Set-RATraceIdentity -Rows $run1 -IsDetailed $true
        $run2 = & $mk; [array]::Reverse($run2); Set-RATraceIdentity -Rows $run2 -IsDetailed $true
        $run1[0].TraceID | Should -Not -Be $run1[1].TraceID
        @($run1.TraceID | Sort-Object) | Should -Be @($run2.TraceID | Sort-Object) -Because 'row order does not change an id'
    }

    It 'the same asset on two rows of a report (one finding, two rows) keeps ONE id -- no suffix' {
        $rows = @((New-Row 'srv01' 'dev-1'), (New-Row 'srv01' 'DEV-1'))
        Set-RATraceIdentity -Rows $rows -IsDetailed $true
        $rows[0].TraceID | Should -Be $rows[1].TraceID
        $rows[0].TraceName | Should -BeExactly 'SPN stale secret-High-srv01-SI'
    }

    It 'a Summary row is unchanged: no asset name, no asset id' {
        $rows = @((New-Row 'x' 'id-1' 'Payroll'), (New-Row 'y' 'id-2' 'Payroll'))
        Set-RATraceIdentity -Rows $rows -IsDetailed $false
        $rows[0].TraceName | Should -BeExactly 'SPN stale secret-High-Payroll-SI'
        $rows[0].TraceID | Should -BeExactly (Get-OldTraceId 'SPN stale secret-High-Payroll-SI')
        $rows[1].TraceID | Should -Be $rows[0].TraceID
    }

    It 'empty parts are skipped and a row without any asset id cannot be told apart (it keeps the plain name)' {
        $rows = @([pscustomobject]@{ ConfigurationName = 'C'; SecuritySeverity = ''; AssetName = 'h' }, [pscustomobject]@{ ConfigurationName = 'C'; SecuritySeverity = ''; AssetName = 'H' })
        Set-RATraceIdentity -Rows $rows -IsDetailed $true
        $rows[0].TraceName | Should -BeExactly 'C-h-SI'
        $rows[0].TraceID | Should -Be $rows[1].TraceID
    }

    It 'WIRING -- the engine stamps through Set-RATraceIdentity, right after risk scoring' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $src | Should -Match 'Set-RATraceIdentity -Rows @\(\$RiskScoreArray\) -IsDetailed \$isDetailedShape'
        $src.IndexOf('Tick "risk scoring"') | Should -BeLessThan $src.IndexOf('Set-RATraceIdentity -Rows')
        $src | Should -Not -Match "NotePropertyName 'TraceID'" -Because 'one place builds the id'
    }
}
