#Requires -Version 5.1
<#
    IS THE RISK ANALYSIS SUMMARY STEP ON? (REQUIREMENTS #636, owner 2026-10-19: "i prefer to switch so detailed becomes the
    engine default and summary is optional, which a customer can enable if they want" / "i dont see a need for summary in
    pipeline").

    The Summary step (job 'risk-analysis') is OFF by default in both editions (config\job-flow.locked.json defaultEnabled);
    a customer switches it on per install with the step's own switch (Operations > Jobs, or config\job-flow.custom.json).
    What reads this:
      * the Detailed run's mail (Invoke-RiskAnalysis.ps1): the Summary mail settings (RiskAnalysis_Summary_SendMail / _To)
        move to the management mail -- the Detailed mail -- while the Summary step is not on (a customer who switches it on
        gets the Summary mail again, and the Detailed mail goes only to its own recipients, as before);
      * the data sync (SI-DataSync.ps1 / SI-DataQuality.ps1): no Summary load and no Summary warnings for a step that is off.
    The web app has the same rule (Jobs/SummaryStep.cs).

    The answer: 'on' | 'off' | 'unknown'.
      'off'      the stored pipeline (mode flow) has the step switched off, or does not have it; or no pipeline is stored
                 and the shipped default is off;
      'on'       the stored pipeline runs it;
      'unknown'  the jobs run on their own timers (mode schedules), or the pipeline could not be read -- a caller then keeps
                 what it did before (nothing moves).
    PURE except Get-SISummaryStepState's reads (the -Invoke seam, a file).
#>

$script:SISummaryStepJob = 'risk-analysis'

function Get-SISummaryStepStateFromJson {
    <# PURE. The state from a stored definition's JSON (schema 1 or 2, as the web app and the runner write it). #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { return 'unknown' }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return 'unknown' }
    $mode = ''; if ($o.PSObject.Properties['mode'] -and $o.mode) { $mode = ([string]$o.mode).ToLowerInvariant() }
    if ($mode -and $mode -ne 'flow') { return 'unknown' }
    $steps = New-Object System.Collections.Generic.List[object]
    if ($o.PSObject.Properties['stages'] -and $null -ne $o.stages) { foreach ($st in @($o.stages)) { if ($st -and $st.PSObject.Properties['steps']) { foreach ($s in @($st.steps)) { if ($s) { $steps.Add($s) } } } } }
    if (-not $steps.Count -and $o.PSObject.Properties['steps']) { foreach ($s in @($o.steps)) { if ($s) { $steps.Add($s) } } }
    foreach ($s in $steps) {
        $k = ([string]$s.job).Trim().ToLowerInvariant(); if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
        if ($k -ne $script:SISummaryStepJob) { continue }
        $en = $true; if ($s.PSObject.Properties['enabled'] -and $null -ne $s.enabled -and "$($s.enabled)" -ne '') { $en = [bool]$s.enabled }
        if ($en) { return 'on' } else { return 'off' }
    }
    'off'
}

function Get-SISummaryStepDefaultState {
    <# PURE. What a new install gets: the map's defaultEnabled of the Summary step (config\job-flow.locked.json). #>
    param([string]$MapPath = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'job-flow.locked.json'))
    try {
        $m = [IO.File]::ReadAllText($MapPath) | ConvertFrom-Json
        $j = @($m.jobs | Where-Object { [string]$_.key -eq $script:SISummaryStepJob })[0]
        if ($j -and $j.PSObject.Properties['defaultEnabled'] -and $j.defaultEnabled -eq $false) { return 'off' }
        return 'on'
    } catch { return 'off' }
}

function Get-SISummaryStepState {
    <#
        The Summary step's state for this install. -Invoke (Pro): the Pro database seam { param($sql, $params, $mode) } --
        cfg.JobFlow 'daily'. -FlowFile (a VM / Community): config\job-flow.custom.json. Neither stored: the shipped default.
        A read that fails = 'unknown'. Never throws. -StoredOnly: only what the database says ('unknown' when it holds no
        pipeline) -- for the readers that must never hide a step on a guess (the data sync's Summary load, the data quality,
        the status report).
    #>
    param([scriptblock]$Invoke, [string]$Mode = 'reader', [string]$FlowFile = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'job-flow.custom.json'),
          [switch]$StoredOnly)
    try {
        if ($Invoke) {
            $rows = @(& $Invoke "IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL SELECT DefinitionJson FROM cfg.JobFlow WHERE FlowId = N'daily';" @{} $Mode | ForEach-Object { $_ } | Where-Object { $_ })
            if ($rows.Count) {
                $r = $rows[0]; $v = if ($r -is [System.Collections.IDictionary]) { $r['DefinitionJson'] } else { $r.DefinitionJson }
                if ($null -ne $v -and -not ($v -is [DBNull]) -and "$v".Trim()) { return (Get-SISummaryStepStateFromJson -Json ([string]$v)) }
            }
        }
        if ($StoredOnly) { return 'unknown' }
        if ($FlowFile -and (Test-Path -LiteralPath $FlowFile)) { return (Get-SISummaryStepStateFromJson -Json ([IO.File]::ReadAllText($FlowFile))) }
        return (Get-SISummaryStepDefaultState)
    } catch { return 'unknown' }
}

function Resolve-SIManagementMailRouting {
    <#
        PURE. The Detailed run's mail -- the management mail -- with the Summary mail settings moved onto it while the Summary
        step is not on. -SummaryStep: 'on' | 'off' | 'unknown' (unknown = as before: nothing moves).
        Returns @{ Send; To (distinct, case-insensitive, Detailed recipients first); Moved (the Summary recipients added) }.
    #>
    param([bool]$DetailedSend, [AllowEmptyCollection()][string[]]$DetailedTo = @(), [bool]$SummarySend, [AllowEmptyCollection()][string[]]$SummaryTo = @(),
          [ValidateSet('on', 'off', 'unknown')][string]$SummaryStep = 'unknown')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $to = New-Object System.Collections.Generic.List[string]
    $moved = New-Object System.Collections.Generic.List[string]
    $move = ($SummaryStep -eq 'off' -and $SummarySend)
    # the Detailed recipients receive it when the Detailed mail is on (or when nothing moves: exactly as before)
    if ($DetailedSend -or -not $move) { foreach ($a in @($DetailedTo)) { $t = ([string]$a).Trim(); if ($t -and $seen.Add($t)) { $to.Add($t) } } }
    $send = $DetailedSend
    if ($move) {
        foreach ($a in @($SummaryTo)) { $t = ([string]$a).Trim(); if ($t -and $seen.Add($t)) { $to.Add($t); $moved.Add($t) } }
        if ($to.Count) { $send = $true }
    }
    [pscustomobject]@{ Send = [bool]$send; To = $to.ToArray(); Moved = $moved.ToArray() }
}
