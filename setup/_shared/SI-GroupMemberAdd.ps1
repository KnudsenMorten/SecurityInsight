#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- adding a member to an Entra group that was created moments ago: wait out Entra replication, then
    read the membership back (owner rule: "after a REST create, wait and read back").

.DESCRIPTION
    #1092 (a private Pro install on 3.0.31): the in-network SQL identity could not be added to the database admin group a
    few minutes after Set-SISqlAdminGroup made it -- Microsoft Graph answered 404 "Resource 'Group_<id>' does not exist or
    one of its queried reference-property objects are not present" (the new group had not reached every directory replica
    yet), and the step ended as a warning that sent the customer to Invardia support.

    Invoke-SIGroupMemberAddRetry is the ONE policy for every place SecurityInsight adds a group member right after the
    group (or the member) was created -- Set-SISqlAdminGroup.ps1, the private-network step's SQL identity and the Support
    app's membership (Set-SISupportAppGroupMember), Grant-SISupportAccess.ps1:
      * the add is tried; ONLY a "not found" answer (404 / Request_ResourceNotFound / does not exist) is waited for and
        tried again, with a growing wait (5, 10, 20, 40, then 60 seconds), up to -LimitSeconds in all (default 300 =
        5 minutes, said in the log line);
      * "already exists" counts as added; any other answer (a refusal: 403, Authorization_RequestDenied) stops at once;
      * an add that went through is READ BACK (-Test, asked from the member's side) with short waits;
      * only past the limit is it given up -- State 'notfound', which the caller turns into its warning.
    The caller hands in the two calls as script blocks, so the POST and the member-side check stay in each caller's own
    words, and the tests run it offline:
        -Add  { }  the POST of the member; throws on a refusal
        -Test { }  $true when the membership reads back; throws when the directory cannot be asked
    Returns [pscustomobject]@{ State; Detail; Error; WaitedSeconds }:
        added      added (or already there), and read back
        unchecked  added, but the directory does not show it yet within the read-back waits
        refused    the add was refused (Error = the directory's answer)
        notfound   the directory still did not know the group (or the member) when the limit was reached
    (A file loaded from inside a function: nothing here depends on a value of its own script scope.)
#>

function Get-SIGroupMemberAddWaits {
    <# PURE. The waits between the tries of an add that answered "not found": 5, 10, 20, 40, then 60 seconds each, the last
       one cut so that together they are exactly -LimitSeconds. #>
    param([int]$LimitSeconds = 300)
    $out = New-Object System.Collections.Generic.List[int]
    $total = 0; $next = 5
    while ($total -lt $LimitSeconds) {
        $w = [Math]::Min($next, $LimitSeconds - $total)
        $out.Add($w); $total += $w
        $next = [Math]::Min($next * 2, 60)
    }
    $out.ToArray()
}

function Test-SIGroupMemberAddNotYet {
    <# PURE. Is this answer to a member add "the directory does not know the group / the member YET" (Entra replication)?
       A refusal is never "not yet", even when its text also says "not found". #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    $t = [string]$Message
    if ($t -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden') { return $false }
    [bool]($t -match '(?i)\b404\b|Request_ResourceNotFound|ResourceNotFound|does not exist|not found|NotFound')
}

function Get-SIGroupMemberAddLimitText {
    <# PURE. The limit as people read it: "5 minutes", "1 minute", "45 seconds". #>
    param([int]$LimitSeconds = 300)
    if ($LimitSeconds -lt 60) { return ('{0} seconds' -f $LimitSeconds) }
    $m = [int][Math]::Ceiling($LimitSeconds / 60.0)
    if ($m -eq 1) { '1 minute' } else { '{0} minutes' -f $m }
}

function Invoke-SIGroupMemberAddRetry {
    param([Parameter(Mandatory)][scriptblock]$Add, [Parameter(Mandatory)][scriptblock]$Test, [string]$What = 'the member',
          [scriptblock]$Sleep, [scriptblock]$Print, [int]$LimitSeconds = 300, [int[]]$ReadBackWaits = @(5, 10, 15, 30))
    # names of their own: the -Add / -Test blocks run in the CALLER's variables ($grp, $sp, $Graph, $GroupId ...)
    $siGmWaits = @(Get-SIGroupMemberAddWaits -LimitSeconds $LimitSeconds)
    $siGmLimit = Get-SIGroupMemberAddLimitText -LimitSeconds $LimitSeconds
    $siGmWaited = 0; $siGmTry = 0; $siGmDone = $false; $siGmErr = ''; $siGmSaid = $false
    $siGmNap = { param($s) if ($s -le 0) { return }; if ($Sleep) { & $Sleep $s } else { Start-Sleep -Seconds $s } }
    $siGmSay = { param($t) if ($Print) { & $Print $t } else { Write-Host $t -ForegroundColor DarkGray } }
    $siGmOut = { param($st, $d) [pscustomobject]@{ State = $st; Detail = [string]$d; Error = $siGmErr; WaitedSeconds = $siGmWaited } }
    while (-not $siGmDone) {
        try { $null = & $Add; $siGmDone = $true }
        catch {
            $siGmErr = ('{0} {1}' -f [string]$_.Exception.Message, $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' })).Trim()
            if ($siGmErr -match '(?i)already exist') { $siGmDone = $true; break }
            if (-not (Test-SIGroupMemberAddNotYet -Message $siGmErr)) { return (& $siGmOut 'refused' ('{0} could not be added: {1}' -f $What, $siGmErr)) }
            if ($siGmTry -ge $siGmWaits.Count) {
                return (& $siGmOut 'notfound' ('{0} could not be added: the directory still answers "not found" after {1} of waiting for the new group to replicate (Entra) -- {2}' -f $What, $siGmLimit, $siGmErr))
            }
            if (-not $siGmSaid) {
                & $siGmSay ('      [waiting ] the directory does not know the new group (or {0}) yet -- Entra replication; trying again for up to {1}' -f $What, $siGmLimit)
                $siGmSaid = $true
            }
            $siGmW = [int]$siGmWaits[$siGmTry]; $siGmTry++
            & $siGmNap $siGmW; $siGmWaited += $siGmW
        }
    }
    # READ BACK: the membership the directory HAS, not the request it accepted
    $siGmLast = ''
    foreach ($siGmR in @(0) + @($ReadBackWaits)) {
        & $siGmNap ([int]$siGmR)
        try { if (& $Test) { return (& $siGmOut 'added' ('{0} added, and read back from the directory{1}' -f $What, $(if ($siGmWaited) { (' (after {0} s of Entra replication)' -f $siGmWaited) } else { '' }))) } }
        catch { $siGmLast = [string]$_.Exception.Message }
    }
    & $siGmOut 'unchecked' ('could not be checked: the member was added, but the directory does not show it yet{0}' -f $(if ($siGmLast) { ' (' + $siGmLast + ')' } else { '' }))
}
