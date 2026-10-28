#Requires -Version 5.1
<#
    SecurityInsight -- THE ONE LIST OF REPORTS HELD ON PURPOSE (#902; owner 2026-10-26: "Approve, next release").

    A report SI holds back ON PURPOSE keeps its last complete result and closes nothing (#900 a source that went silent,
    #899 an incomplete Entra role read, #901 the run publishes). WHICH reasons exist, and the stable code of each, is ONE
    list: data-model/hold-kinds.locked.json. Every reader goes through this file -- the stored sidata.RaReportStatus.HoldKind
    (Add-RADeliberateHold, Set-RAStreamReportNotComplete), the uplink item (SI-UplinkCauses.ps1), the mail (RA-ReportMail.ps1)
    and the heartbeat Warnings -- and the web app reads the same file (SI.Management.Core/Holds/HoldKinds.cs). A test fails
    when code emits a kind that is not in the list (SIv3-HoldKinds.Tests.ps1).

    The safe direction everywhere: a list that cannot be read has NO kinds, so every report is a real failure (nothing is
    hidden as "held"). Whether a report IS held stays Get-RADeliberateHoldKind's rule (RA-SilentSource.ps1) -- not here.
    PS 5.1 and 7. No modules, no network.
#>

$script:SIHoldKindsCache = $null

function Get-SIHoldKinds {
    <# The list, read once per process (-Path: the test seam, never cached). @{ Version; EscalateAfterDetailedRuns; Kinds =
       @(@{ Kind; Code; EscalationCode; AcceptEmpty }) }. No kinds when the file cannot be read. #>
    param([string]$Path)
    if (-not $Path -and $null -ne $script:SIHoldKindsCache) { return $script:SIHoldKindsCache }
    $p = $Path
    if (-not $p) { $p = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'hold-kinds.locked.json') }
    $out = [pscustomobject]@{ Version = 0; EscalateAfterDetailedRuns = 3; Kinds = @() }
    try {
        $j = [System.IO.File]::ReadAllText($p).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
        $n = 3; if ($j.PSObject.Properties['escalateAfterDetailedRuns'] -and [int]$j.escalateAfterDetailedRuns -ge 1) { $n = [int]$j.escalateAfterDetailedRuns }
        $kinds = @(@($j.kinds) | Where-Object { $_ -and "$($_.kind)".Trim() -and "$($_.code)" -match '^si-[a-z]{2,8}-\d{4}$' -and "$($_.escalationCode)" -match '^si-[a-z]{2,8}-\d{4}$' } | ForEach-Object {
            [pscustomobject]@{ Kind = "$($_.kind)".Trim(); Code = "$($_.code)".Trim().ToLowerInvariant(); EscalationCode = "$($_.escalationCode)".Trim().ToLowerInvariant(); AcceptEmpty = [bool]$_.acceptEmpty }
        })
        $out = [pscustomobject]@{ Version = [int]$j.version; EscalateAfterDetailedRuns = $n; Kinds = $kinds }
    } catch { }
    if (-not $Path) { $script:SIHoldKindsCache = $out }
    $out
}

function Get-SIHoldKind {
    <# The list entry of -Kind ($null when the kind is not in the list). #>
    param([AllowNull()][AllowEmptyString()][string]$Kind)
    if (-not "$Kind".Trim()) { return $null }
    @((Get-SIHoldKinds).Kinds | Where-Object { $_.Kind -eq "$Kind".Trim() })[0]
}

function Test-SIHoldKind {
    <# Is -Kind a kind of the list? ('' and an unknown kind: no -- the report is then a real failure.) #>
    param([AllowNull()][AllowEmptyString()][string]$Kind)
    [bool](Get-SIHoldKind -Kind $Kind)
}

function Get-SIHoldKindCode {
    <# The catalogue code of -Kind: its information code, or its escalation code with -Escalated. '' for an unknown kind. #>
    param([AllowNull()][AllowEmptyString()][string]$Kind, [switch]$Escalated)
    $k = Get-SIHoldKind -Kind $Kind
    if (-not $k) { return '' }
    if ($Escalated) { return [string]$k.EscalationCode }
    [string]$k.Code
}

function Test-SIHoldKindAcceptEmpty {
    <# May an Admin accept the source of a report held for -Kind as empty for good? Only a kind of the list that says so. #>
    param([AllowNull()][AllowEmptyString()][string]$Kind)
    $k = Get-SIHoldKind -Kind $Kind
    [bool]($k -and $k.AcceptEmpty)
}

function Test-SIHoldEscalated {
    <# PURE. Is a hold escalated -- a real problem? Only a DETAILED run's hold, held -HeldRuns runs in a row (this run
       included), at least escalateAfterDetailedRuns of the list. #>
    param([AllowNull()]$HeldRuns, [AllowNull()][AllowEmptyString()][string]$Grain)
    if ("$Grain" -ne 'Detailed') { return $false }
    $n = 0
    if ($null -eq $HeldRuns -or $HeldRuns -is [System.DBNull] -or -not [int]::TryParse("$HeldRuns", [ref]$n)) { return $false }
    $n -ge [int](Get-SIHoldKinds).EscalateAfterDetailedRuns
}

function Get-RAHoldStreak {
    <#
        PURE. #902 (4): how many runs of this grain in a row a report is held for -Kind, this run included. -Previous: the
        report's previous verdict row of the same grain (HoldKind, HeldRuns; $null = none). Held for the SAME kind before ->
        its HeldRuns + 1; anything else (Complete, a real failure, another kind, no row, a row from before the column) -> 1.
    #>
    param([Parameter(Mandatory)][string]$Kind, [AllowNull()]$Previous)
    if ($null -eq $Previous) { return 1 }
    $pk = $null; $pr = $null
    if ($Previous -is [System.Collections.IDictionary]) { $pk = $Previous['HoldKind']; $pr = $Previous['HeldRuns'] }
    else { if ($Previous.PSObject.Properties['HoldKind']) { $pk = $Previous.HoldKind }; if ($Previous.PSObject.Properties['HeldRuns']) { $pr = $Previous.HeldRuns } }
    if ($null -eq $pk -or $pk -is [System.DBNull] -or "$pk" -ne $Kind) { return 1 }
    $n = 0
    if ($null -eq $pr -or $pr -is [System.DBNull] -or -not [int]::TryParse("$pr", [ref]$n) -or $n -lt 1) { return 1 }
    $n + 1
}
