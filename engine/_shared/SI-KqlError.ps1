#Requires -Version 5.1
<#
    SecurityInsight -- what a failed Log Analytics query actually said (#221).

    WHY. Az.OperationalInsights throws ErrorResponseException whose MESSAGE is only
    "Operation returned an invalid status code 'BadRequest'". The reason -- e.g. SEM0100 "Failed to resolve table or
    column expression named 'SI_PublicIP_Profile_CL'" -- is in the response body (Exception.Response.Content /
    Exception.Body). Measured 2026-10-03 on 3.4.0 (container) and 3.4.1 (mgmt1), PS 5.1 and pwsh 7 alike.
    Readers that classified on the message therefore never recognised a MISSING table: on a fresh install, where a
    profile or Risk Analysis table does not exist yet, correlation, trend and the close-loop failed outright.

    A missing table is the ONLY error a reader may treat as "no data here yet". Everything else still fails loudly --
    a throttle or timeout must never pass as an empty table (#132).

    PS 5.1 safe: no ?. / ??.
#>

function Get-SIKqlErrorText {
    <# PURE. Every text a Log Analytics query failure carries: the message, the response body, the typed body, inner
       exceptions and ErrorDetails -- joined, so a caller can classify on what the service really said. #>
    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $parts.Add([string]$ErrorRecord.ErrorDetails.Message)
    }
    $depth = 0
    while ($ex -and $depth -lt 5) {
        $parts.Add([string]$ex.Message)
        if ($ex.PSObject.Properties['Response'] -and $ex.Response) {
            $c = $null
            if ($ex.Response.PSObject.Properties['Content']) { $c = $ex.Response.Content }
            if ($c) { $parts.Add([string]$c) }
        }
        if ($ex.PSObject.Properties['Body'] -and $ex.Body) {
            try { $parts.Add((ConvertTo-Json -InputObject $ex.Body -Depth 8 -Compress)) } catch { $parts.Add([string]$ex.Body) }
        }
        $ex = $ex.InnerException
        $depth++
    }
    return (($parts | Where-Object { $_ }) -join ' | ')
}

function Get-SIKqlErrorSummary {
    <# PURE. ONE log-ready line: the exception message plus the service's own error code(s) and the innermost
       message, e.g. "Operation returned an invalid status code 'BadRequest' -- SemanticError/SEM0100: 'summarize'
       operator: Failed to resolve scalar expression named 'AssetName'". Without it a query defect logs only
       "BadRequest", which says nothing about what to fix. The bare message is kept at the front so classifiers that
       match on it (BadRequest, TaskCanceledException, 502 ...) see exactly what they saw before. #>
    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    $base = if ($ex -and $ex.PSObject.Properties['Message']) { [string]$ex.Message } else { [string]$ex }
    $text = Get-SIKqlErrorText -ErrorRecord $ErrorRecord
    if (-not $text) { return $base }
    # The Log Analytics body nests the reason: error -> innererror (SemanticError / SyntaxError) -> innererror
    # (SEM0100 ...). Collect the innererror chain of the first body found; the deepest message is the useful one.
    $rx = '"innererror"\s*:\s*\{\s*"code"\s*:\s*"([^"]*)"\s*,\s*"message"\s*:\s*"((?:[^"\\]|\\.)*)"'
    $ms = [regex]::Matches($text, $rx)
    if ($ms.Count -eq 0) { return $base }
    $codes = New-Object System.Collections.Generic.List[string]
    $msg = ''
    foreach ($m in $ms) {
        $c = $m.Groups[1].Value
        if ($codes.Contains($c)) { break }   # a second copy of the same body (typed body / ErrorDetails) starts here
        $codes.Add($c)
        $msg = $m.Groups[2].Value
    }
    try { $msg = [regex]::Unescape($msg) } catch { }
    $detail = ('{0}: {1}' -f ($codes -join '/'), $msg)
    if ($base -and $base.Contains($msg)) { return $base }
    if (-not $base) { return $detail }
    return ('{0} -- {1}' -f $base, $detail)
}

function Test-SIKqlTableMissing {
    <# PURE. True only when the failure says THIS table does not exist in the workspace. #>
    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord, [Parameter(Mandatory)][string]$TableName)
    $t = Get-SIKqlErrorText -ErrorRecord $ErrorRecord
    if (-not $t) { return $false }
    $name = [regex]::Escape($TableName)
    # #876: a 'union' leaf says "table expression", a 'where' leaf "table or column expression" -- both: the table is not there
    if ($t -match ("Failed to resolve table (?:or column )?expression named \\?['""]?{0}" -f $name)) { return $true }
    if ($t -match $name -and $t -match '(?i)SEM0100|could not be found|does not exist|unknown table') { return $true }
    return $false
}
