#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- READ-ONLY: the duplicate check (REQUIREMENTS #1365, #693 (6) / (9)) on one install: the findings and
    remediation tasks that are still TWO where the merge rules make ONE, per rule, with examples.

.DESCRIPTION
    The same check the data sync runs after it wrote the findings per CI and the tasks (engine\pro-data\_shared\
    SI-DataDuplicateCheck.ps1, Invoke-SIDataDuplicateCheck -ReadOnly), over the install's published findings
    (sidata.CiFinding), the facts of the collection they are of (sidata.Finding) and the newest built remediation tasks
    (sidata.RemediationTask). The rules: the install's recommendation equivalence (the shipped template; -Rules: a merged
    template's JSON file instead), production groups only.

    READ-ONLY: SELECT batches only (temporary tables of the batch itself), nothing is written. No PowerShell module. Two ways to
    reach the database:
      * the Invardia Support session (Connect-InvardiaSupport, then this script with -Server / -Database): every statement goes
        through Invoke-InvardiaSupportSql -ReadOnly, so the customer's audit log records it with -Reason;
      * -Invoke { param([string]$Query) <rows> }: any read-only connection.

.EXAMPLE
    . .\Connect-InvardiaSupport.ps1 -Environment <install handle> -NoGraph -Production -Reason 'SI: read-only -- duplicate check'
    .\setup\Get-SIDuplicateCheck.ps1 -Server <sql server>.database.windows.net -Database <pro database> -PassThru
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$Database,
    # the seam instead of the Support session: { param([string]$Query) } returning rows
    [scriptblock]$Invoke,
    # a recommendation-equivalence template (JSON) to check with instead of the shipped one
    [string]$Rules,
    [int]$Examples = 10,
    [int]$OwnersPerPage = 400,
    [string]$Reason = 'SI: read-only -- duplicate findings / tasks not merged (#1365)',
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::Combine($PSScriptRoot, '..')
if (-not (Get-Command -Name Invoke-SIDataDuplicateCheck -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($root, 'engine', 'pro-data', '_shared', 'SI-DataDuplicateCheck.ps1')) }

function ConvertTo-SIDupDiagBatch {
    <# PURE. A statement with its @parameters as typed text in front (a read-only session takes no parameters). #>
    param([string]$Sql, [hashtable]$Params = @{})
    $pre = New-Object System.Text.StringBuilder
    foreach ($k in @($Params.Keys)) {
        $v = $Params[$k]
        if ($null -eq $v) { [void]$pre.AppendLine(('DECLARE @{0} nvarchar(max) = NULL;' -f $k)) }
        else { [void]$pre.AppendLine(("DECLARE @{0} nvarchar(max) = N'{1}';" -f $k, ([string]$v).Replace("'", "''"))) }
    }
    $pre.ToString() + $Sql
}

if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $Invoke) {
    if (-not $Server -or -not $Database) { throw 'give -Server and -Database (an open Invardia Support session), or -Invoke' }
    if (-not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) { throw 'no Invardia Support session is open: connect with Connect-InvardiaSupport first (Invoke-InvardiaSupportSql is not loaded)' }
    $srv = if ($Server -match '\.') { $Server } else { $Server + '.database.windows.net' }
    $Invoke = { param([string]$Query) @((Invoke-InvardiaSupportSql -Server $srv -Database $Database -Query $Query -Reason $Reason -ReadOnly -TimeoutSec 900).Rows) }
}
$read = $Invoke
$seam = {
    param($Sql, $Params, $Mode)
    if ($Mode -notin 'reader', 'scalar') { throw ('the diagnostics are read-only: a {0} statement is never sent' -f $Mode) }
    $rows = @(& $read (ConvertTo-SIDupDiagBatch -Sql $Sql -Params $(if ($Params) { $Params } else { @{} })))
    if ($Mode -eq 'scalar') {
        if (-not $rows.Count -or $null -eq $rows[0]) { return $null }
        $r = $rows[0]
        if ($r -is [System.Data.DataRow]) { return $r[0] }
        if ($r -is [System.Collections.IDictionary]) { return @($r.Values)[0] }
        return @($r.PSObject.Properties | Where-Object { $_.Name -notin 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors' })[0].Value
    }
    , $rows
}

$idx = $null
if ($Rules) {
    $doc = [IO.File]::ReadAllText($Rules) | ConvertFrom-Json
    $idx = ConvertTo-SIRecommendationEquivalenceIndex -Document $doc
} else {
    $doc = [IO.File]::ReadAllText([IO.Path]::Combine($root, 'data-model', 'recommendation-equivalence.locked.json')) | ConvertFrom-Json
    $idx = ConvertTo-SIRecommendationEquivalenceIndex -Document $doc
}
$global:SI_Pro_DuplicateExamples = $Examples
$lines = New-Object System.Collections.Generic.List[string]
$res = Invoke-SIDataDuplicateCheck -Invoke $seam -ReadOnly -Index $idx -OwnersPerPage $OwnersPerPage -Log { param($l, $m) $lines.Add(('[{0}] {1}' -f $l, $m)) }
Write-Host ('Duplicate check (read-only) -- published findings of {0}; {1} candidate asset(s); {2} s ({3})' -f $res.CollectionTime, $res.Candidates, $res.Seconds, $res.Phases)
if ([string]$res.Status -ne 'ok') { Write-Host ('Status: {0} {1}' -f $res.Status, $res.Error) }
foreach ($r in @($res.Rules)) {
    Write-Host ('  {0}: {1} duplicate(s) on {2} asset(s)' -f $r.Id, $r.Duplicates, $r.Owners)
    foreach ($e in @($r.Examples)) { Write-Host ('      e.g. ' + [string]$e.text) }
}
Write-Host ('Total: {0}' -f $res.Total)
if ($PassThru) { $res }
