#Requires -Version 5.1
<#
    SecurityInsight -- EXISTING INSTALLS GET THE PIPELINE A NEW INSTALL GETS (#754, #748; rule: existing installs reach
    new-install state). The stored pipeline (cfg.JobFlow 'daily' in the Pro database) is what the pipeline runner and the
    web app read. Both already bring an old layout to the current one IN MEMORY as they read it (engine\_shared\SI-JobFlow.ps1:
    ConvertFrom-SIJobFlowJson -- Update-SIJobFlowDefaultLayout, Move-SIJobFlowStepAfterNeeds, the updater / a retired job taken
    out), but nothing STORED it until a person saved the pipeline on the Jobs page. Every update now stores it:

      * WHAT (Get-SIPipelineLayoutPlan, PURE): the stored definition read as the runner reads it, plus every step the map
        marks 'required' whose job is installed and that the pipeline does not have (Add-SIJobFlowRequiredStep: the
        verification service, which runs the daily data health check -- #748). Level 3 of the default layout (#754): Risk
        Analysis Summary and Detailed start together after the asset correlation, on a pipeline still on the default layout
        of its own level; a pipeline a person changed is only marked with the level, never re-laid. Nothing changed = no write.
      * HOW (Invoke-SIPipelineLayout): ONE parameterised UPDATE of cfg.JobFlow, only while the row still holds the text that
        was read (a save from the web app in between wins -- the next update looks again), then the row is READ BACK: it must
        be the planned text, and reading it once more must change nothing (idempotent). One plain line per change.
      * Never throws; -WhatIf: the plan only, nothing written. No az CLI, no PowerShell module: SQL through ONE seam,
        -Sql { param([string]$Query, $Params, [string]$Mode) } ('reader' -> rows, 'nonquery' -> count).
#>

if (-not (Get-Command -Name ConvertFrom-SIJobFlowJson -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-JobFlow.ps1'))
}

$script:SIPipelineLayout = @{ By = 'update (pipeline layout)'; FlowId = 'daily' }

function Get-SIPipelineLayoutPlan {
    <#
        PURE. -FlowJson: the stored definition ('' / $null = none: nothing to do). -Installed: the install's jobs (keys or
        caj-si-* names). Returns @{ Changed; FlowJson (the definition to store, or $null); Lines (one plain line per change);
        DefaultsLevel }. The runner's own reading decides the layout, so the stored pipeline is exactly what the runner runs.
    #>
    param([AllowEmptyString()][AllowNull()][string]$FlowJson = '', [AllowEmptyCollection()][string[]]$Installed = @(), $Map)
    $none = [pscustomobject]@{ Changed = $false; FlowJson = $null; Lines = @(); DefaultsLevel = 0 }
    if (-not "$FlowJson".Trim()) { return $none }
    if (-not $Map) { $Map = Get-SIJobFlowMap }
    $d = ConvertFrom-SIJobFlowJson -Json $FlowJson -Map $Map
    $d = Add-SIJobFlowRequiredStep -Definition $d -Installed $Installed -Map $Map
    $new = ConvertTo-SIJobFlowJson -Definition $d
    $lvl = if ($d.PSObject.Properties['DefaultsLevel']) { [int]$d.DefaultsLevel } else { 0 }
    # only the level moved (a pipeline a person changed): stored too, so the decision is never made again
    $moved = [bool]($d.PSObject.Properties['Migrated'] -and $d.Migrated)
    $storedLevel = 1
    $m = [regex]::Match($FlowJson, '"defaults"\s*:\s*(\d+)'); if ($m.Success) { $storedLevel = [int]$m.Groups[1].Value }
    if (-not $moved -and $storedLevel -ge $lvl) { return [pscustomobject]@{ Changed = $false; FlowJson = $null; Lines = @(); DefaultsLevel = $lvl } }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($(if ($d.PSObject.Properties['MigrationNotes']) { $d.MigrationNotes }))) { if ($n) { $lines.Add(('The daily pipeline: {0}.' -f ([string]$n).TrimEnd('.'))) } }
    if (-not $lines.Count) { $lines.Add(('The daily pipeline is kept as it is (it was changed by a person); it is marked with the current layout level {0}, so it is never re-laid.' -f $lvl)) }
    [pscustomobject]@{ Changed = $true; FlowJson = $new; Lines = $lines.ToArray(); DefaultsLevel = $lvl }
}

function Get-SIPipelineLayoutSql {
    <# The statements. 'Read': the stored daily pipeline. 'Apply': the new text, only while the row still holds the old. #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Name)
    if ($Name -eq 'Read') {
        return "IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL SELECT DefinitionJson FROM cfg.JobFlow WHERE FlowId = @FlowId;"
    }
    "UPDATE cfg.JobFlow SET DefinitionJson = @New, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE FlowId = @FlowId AND DefinitionJson = @Old;"
}

function Invoke-SIPipelineLayout {
    <#
        The stored pipeline brought to the new-install state, once per change (see the header). -Sql: the seam; -Installed:
        the install's jobs. Never throws. Returns @{ Action = none | kept | plan | changed | raced | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [AllowEmptyCollection()][string[]]$Installed = @(), $Map, [switch]$WhatIf)
    try {
        if (-not $Map) { $Map = Get-SIJobFlowMap }
        $read = {
            $rows = @(& $Sql (Get-SIPipelineLayoutSql -Name Read) @{ FlowId = $script:SIPipelineLayout.FlowId } 'reader' | Where-Object { $_ })
            if (-not $rows.Count) { return '' }
            $r = $rows[0]
            $v = if ($r -is [System.Collections.IDictionary]) { $r['DefinitionJson'] } else { $r.DefinitionJson }
            if ($null -eq $v -or $v -is [DBNull]) { '' } else { [string]$v }
        }
        $old = & $read
        if (-not $old.Trim()) { return [pscustomobject]@{ Action = 'none'; Lines = @() } }
        $plan = Get-SIPipelineLayoutPlan -FlowJson $old -Installed $Installed -Map $Map
        if (-not $plan.Changed) { return [pscustomobject]@{ Action = 'kept'; Lines = @() } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) } }
        $n = [int](& $Sql (Get-SIPipelineLayoutSql -Name Apply) @{ FlowId = $script:SIPipelineLayout.FlowId; Old = $old; New = [string]$plan.FlowJson; By = $script:SIPipelineLayout.By } 'nonquery')
        if ($n -lt 1) { return [pscustomobject]@{ Action = 'raced'; Lines = @('The daily pipeline was saved by someone else while the update read it -- it is checked again on the next update.') } }
        # READ BACK: the row holds the planned text, and reading it once more changes nothing
        $back = & $read
        if ($back -ne [string]$plan.FlowJson) { return [pscustomobject]@{ Action = 'failed'; Lines = @('The daily pipeline did not read back as written -- the next update checks it again.') } }
        $again = Get-SIPipelineLayoutPlan -FlowJson $back -Installed $Installed -Map $Map
        if ($again.Changed) { return [pscustomobject]@{ Action = 'failed'; Lines = @(@($plan.Lines) + 'The daily pipeline would change again when read once more -- the next update checks it again.') } }
        [pscustomobject]@{ Action = 'changed'; Lines = @($plan.Lines) }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The daily pipeline''s layout was not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}

# ---------------------------------------------------------------------------------------------------------------------
#  #636 LEVEL 4 -- RISK ANALYSIS SUMMARY OFF BY DEFAULT (owner 2026-10-19: "i prefer to switch so detailed becomes the engine
#  default and summary is optional"). The layout plan above stores it like every level: on a stored pipeline that is still
#  the default of its level with every step on, the Summary step (risk-analysis) is switched off (Update-SIJobFlowDefaultLayout,
#  one line); one a person changed keeps it, and one line says so. What hangs on the Summary report then follows here:
#  the management summary reports a person scheduled for the Summary report's data (cfg.MgmtReport Grain 'Summary') show the
#  Detailed report's -- once, only while the stored pipeline has the Summary step off, one line per report moved.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIMgmtReportsDetailedSql {
    <# 'Read': the scheduled Summary reports. 'Apply': each to Detailed, only while it is still Summary (a save in between wins). #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Name)
    if ($Name -eq 'Read') {
        return "IF OBJECT_ID(N'cfg.MgmtReport') IS NOT NULL SELECT ReportId, Name FROM cfg.MgmtReport WHERE Grain = N'Summary' AND RemovedAt IS NULL ORDER BY ReportId;"
    }
    "UPDATE cfg.MgmtReport SET Grain = N'Detailed', UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE ReportId = @Id AND Grain = N'Summary' AND RemovedAt IS NULL;"
}

function Invoke-SIMgmtReportsDetailed {
    <#
        The scheduled management summary reports of the Summary report's data -> the Detailed report's, while the stored pipeline
        has the Summary step off (engine\_shared\SI-SummaryStep.ps1). -Sql: the seam (as Invoke-SIPipelineLayout). Never throws.
        Returns @{ Action = none | kept | plan | changed | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [switch]$WhatIf)
    try {
        if (-not (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue)) {
            . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-SummaryStep.ps1'))
        }
        $state = Get-SISummaryStepState -Invoke $Sql -StoredOnly
        if ($state -ne 'off') { return [pscustomobject]@{ Action = 'kept'; Lines = @() } }
        $reports = @(& $Sql (Get-SIMgmtReportsDetailedSql -Name Read) @{} 'reader' | Where-Object { $_ })
        if (-not $reports.Count) { return [pscustomobject]@{ Action = 'none'; Lines = @() } }
        $val = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($r in $reports) {
            $line = "The management summary report '{0}' now shows the Detailed report's data (the Risk Analysis Summary step is off)." -f [string](& $val $r 'Name')
            if ($WhatIf) { $lines.Add($line + ' (re-run with -Apply)'); continue }
            $n = [int](& $Sql (Get-SIMgmtReportsDetailedSql -Name Apply) @{ Id = [long](& $val $r 'ReportId'); By = $script:SIPipelineLayout.By } 'nonquery')
            if ($n -ge 1) { $lines.Add($line) }
        }
        [pscustomobject]@{ Action = $(if ($WhatIf) { 'plan' } elseif ($lines.Count) { 'changed' } else { 'none' }); Lines = $lines.ToArray() }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The management summary reports were not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}
