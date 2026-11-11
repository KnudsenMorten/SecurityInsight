#Requires -Version 5.1
<#
.SYNOPSIS
    Who receives a report mail once the install's list of people is confirmed (#1172).

.DESCRIPTION
    SecurityInsight Pro keeps ONE list of people (Configuration > Reports and alerts): a row per person, a tick per report
    and alert. Saving it writes every report's OWN recipient list exactly (RiskAnalysis_Summary_To, RiskAnalysis_Detailed_To,
    Mail_CloseLoop_Daily_To, SI_GuardMail_To, ...) and records who confirmed it in the web-app setting
    SIWeb_MailRecipientsConfirmed, which the settings layer hands to every job (Get-SIProWebSettingsForEngines).

    While that setting is NOT set, nothing changes: a report's own list, else the older name, else the default list
    (MailTo) -- exactly as before. Once it IS set, a report goes to its own list and to nobody else: an empty list means
    no one, and the report is not mailed (said once in the run's log, never a failed run). The saved list also empties the
    default list, so the safety-check mail's fallback (Get-SIGuardMailRecipients: its list, else MailTo, else the
    SuperAdmins) can no longer bring back an address nobody ticked.
#>

function Test-SIMailRecipientsExact {
    <# PURE. $true once the install's list of people was confirmed (SIWeb_MailRecipientsConfirmed holds a value). #>
    param([System.Collections.IDictionary]$Globals)
    $v = if ($Globals) { if ($Globals.Contains('SIWeb_MailRecipientsConfirmed')) { $Globals['SIWeb_MailRecipientsConfirmed'] } else { $null } }
         else { $global:SIWeb_MailRecipientsConfirmed }
    -not [string]::IsNullOrWhiteSpace([string]$v)
}

function Resolve-SIReportRecipients {
    <#
        PURE. One report's recipients. -Exact (the list of people is confirmed): -Own only, blanks dropped -- empty = nobody.
        Otherwise the order the engines always used: -Own, else -Legacy (the older name), else -Default (MailTo).
        Writes the addresses to the pipeline (none = nobody); callers wrap the call in @( ).
    #>
    param([AllowNull()][object]$Own, [AllowNull()][object]$Legacy, [AllowNull()][object]$Default, [bool]$Exact)
    $clean = { param($v) @(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $own = @(& $clean $Own)
    if ($Exact -or $own.Count) { return $own }
    $old = @(& $clean $Legacy)
    if ($old.Count) { return $old }
    @(& $clean $Default)
}
