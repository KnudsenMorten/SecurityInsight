#Requires -Version 5.1
<#
    SecurityInsight SETUP -- a database server's NEW Entra administrator is waited for before anyone signs in with it (#695).

    Why: the customer-run install at customer B, 2026-10-15 (read from Azure's activity log). 07:50:06Z the installer set
    the SQL server's Entra admin (Microsoft.Sql/servers/administrators/write, the admin group, Entra-only sign-in) and Azure
    answered Accepted -- the change is ASYNCHRONOUS; 07:50:14-19Z the installer signed in to the database and was refused
    ("Login failed for user '<token-identified principal>'"); 07:50:22Z Azure finished the admin write (Succeeded). The
    read-back of the administrators resource shows the new admin AT ONCE, while the server is still taking it, so a read
    back alone does not prove the change is done.

      Wait-SIArmAsyncOperation   after an ARM write answered 201/202: polls Azure's own operation (Azure-AsyncOperation,
                                 else Location) until it is finished. Bounded; a failed operation throws with Azure's words.
      Wait-SISqlAdminWrite       after the admin write: the operation finished AND the admin read back is the expected one.
      Test-SISqlAdminIs          PURE: is this administrators resource the expected principal (sid, and login when given)?
      Test-SISqlLoginNotReady    PURE: is this error text the refusal of an Entra token sign-in -- the answer of a server
                                 that does not know its new administrator yet? A wrong password, a firewall refusal or any
                                 other SQL error is NOT.
      Invoke-SISqlLoginRetry     the first sign-in after the administrator was set: ONLY that refusal, and only within the
                                 first minutes after the admin was set, is waited out (30 s at a time, up to 5 minutes),
                                 with one plain line; then the real message. Every other error returns / throws at once.

    No PowerShell module: the REST calls are a scriptblock the caller passes (Invoke-SIAzRestMethod in setup). PS 5.1 safe.
#>

function Get-SIArmAsyncOperationUrl {
    <# PURE. The URL Azure gave to follow an accepted write: @{ Url; Kind = 'AsyncOperation' | 'Location' }, $null when
       the answer names none (a write that finished at once). -Response: StatusCode + Headers (any dictionary). #>
    param($Response)
    if ($null -eq $Response) { return $null }
    $h = $null; $pp = $Response.PSObject.Properties['Headers']; if ($pp) { $h = $pp.Value } elseif ($Response -is [System.Collections.IDictionary]) { $h = $Response['Headers'] }
    if (-not ($h -is [System.Collections.IDictionary])) { return $null }
    $find = { param([string]$name) foreach ($k in @($h.Keys)) { if ([string]$k -ieq $name) { $v = $h[$k]; if ($v -is [array]) { $v = $v[0] }; if ("$v".Trim()) { return "$v".Trim() } } }; $null }
    $a = & $find 'Azure-AsyncOperation'
    if ($a) { return [pscustomobject]@{ Url = $a; Kind = 'AsyncOperation' } }
    $l = & $find 'Location'
    if ($l) { return [pscustomobject]@{ Url = $l; Kind = 'Location' } }
    $null
}

function Wait-SIArmAsyncOperation {
    <#
        After an ARM write: when Azure answered 201/202 with an operation to follow, polls it until it is FINISHED --
        Azure-AsyncOperation: its status Succeeded (Failed / Canceled THROW with Azure's error); Location: 202 = still
        running, 200/204 = done. A write that finished at once (no operation named) returns at once. Bounded (-TimeoutSec,
        polls every -PollSec); at the deadline it THROWS. One plain line while it waits (-Print). Returns $true when it
        waited on an operation, $false when there was none.
        -Rest { param([string]$Method, [string]$Path) } -> @{ StatusCode; Content } (Invoke-SIAzRestMethod in setup).
    #>
    param($Response, [Parameter(Mandatory)][scriptblock]$Rest, [int]$TimeoutSec = 600, [int]$PollSec = 10,
          [scriptblock]$Sleep, [scriptblock]$Print, [string]$What = 'the change')
    $code = 0; try { $code = [int]$Response.StatusCode } catch { $code = 0 }
    if ($code -notin 201, 202) { return $false }
    $op = Get-SIArmAsyncOperationUrl -Response $Response
    if (-not $op) { return $false }
    $polls = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSec / [double][Math]::Max(1, $PollSec)))
    $said = $false; $state = 'accepted'
    for ($i = 0; $i -le $polls; $i++) {
        $r = $null; try { $r = & $Rest 'GET' $op.Url } catch { $r = $null }
        $sc = 0; try { $sc = [int]$r.StatusCode } catch { $sc = 0 }
        $j = $null; try { if ($r -and "$($r.Content)".Trim()) { $j = [string]$r.Content | ConvertFrom-Json } } catch { $j = $null }
        if ($op.Kind -eq 'AsyncOperation') {
            $st = ''; if ($j -and $j.PSObject.Properties['status']) { $st = [string]$j.status }
            if ($st -ieq 'Succeeded') { return $true }
            if ($st -in 'Failed', 'Canceled', 'Cancelled') {
                $why = ''; if ($j.PSObject.Properties['error'] -and $j.error) { $why = $(if ($j.error.PSObject.Properties['message']) { [string]$j.error.message } else { [string]($j.error | ConvertTo-Json -Compress -Depth 5) }) }
                throw ('{0}: Azure reports it {1}{2}' -f $What, $st, $(if ($why) { ' -- ' + $why } else { '' }))
            }
            if ($st) { $state = $st }
        } else {
            if ($sc -in 200, 204) { return $true }
            if ($sc -ge 400) { throw ('{0}: Azure reports it failed ({1}){2}' -f $What, $sc, $(if ($r -and "$($r.Content)".Trim()) { ' -- ' + [string]$r.Content } else { '' })) }
            if ($sc -eq 202) { $state = 'in progress' }
        }
        if ($i -ge $polls) { break }
        if (-not $said -and $Print) { & $Print ('       Azure is still applying {0} -- waiting until it is done ...' -f $What); $said = $true }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    }
    throw ('{0} is not finished {1} seconds after Azure accepted it (Azure shows: {2}).' -f $What, $TimeoutSec, $state)
}

function Test-SISqlAdminIs {
    <# PURE. Is -Admin (the administrators resource as read, or its properties) the principal -Sid, named -Login when given? #>
    param($Admin, [Parameter(Mandatory)][string]$Sid, [string]$Login)
    if ($null -eq $Admin) { return $false }
    $p = $Admin; $pp = $Admin.PSObject.Properties['properties']; if ($pp -and $pp.Value) { $p = $pp.Value }
    $s = ''; $sp = $p.PSObject.Properties['sid']; if ($sp) { $s = [string]$sp.Value }
    if ($s -ine $Sid) { return $false }
    if ($Login) { $l = ''; $lp = $p.PSObject.Properties['login']; if ($lp) { $l = [string]$lp.Value }; if ($l -ne $Login) { return $false } }
    $true
}

function Wait-SISqlAdminWrite {
    <#
        After the write of a database server's Entra administrator (PUT .../administrators/ActiveDirectory): WAITS until
        Azure has FINISHED it (Wait-SIArmAsyncOperation on the answer of the write) and READS BACK that the administrator is
        -Sid (named -Login when given). Both inside ONE bounded window (-TimeoutSec, -PollSec steps). THROWS when the write
        failed, or when the administrator read back is still not the expected one at the deadline. Returns the
        administrators resource as read.
        -Rest { param([string]$Method, [string]$Path) } -> @{ StatusCode; Content }; -AdminPath: the administrators resource
        (with its api-version).
    #>
    param($Response, [Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$AdminPath, [Parameter(Mandatory)][string]$Sid,
          [string]$Login, [int]$TimeoutSec = 600, [int]$PollSec = 10, [scriptblock]$Sleep, [scriptblock]$Print, [string]$What = 'the new Entra admin')
    $started = [datetime]::UtcNow
    $null = Wait-SIArmAsyncOperation -Response $Response -Rest $Rest -TimeoutSec $TimeoutSec -PollSec $PollSec -Sleep $Sleep -Print $Print -What $What
    # the rest of the window for the read-back (a test's instant -Sleep: at most TimeoutSec / PollSec reads)
    $left = [Math]::Max($PollSec, $TimeoutSec - [int]([datetime]::UtcNow - $started).TotalSeconds)
    $polls = [Math]::Max(1, [int][Math]::Ceiling($left / [double][Math]::Max(1, $PollSec)))
    $after = $null; $said = $false
    for ($i = 0; $i -le $polls; $i++) {
        $after = $null
        try { $r = & $Rest 'GET' $AdminPath; if ($r -and [int]$r.StatusCode -lt 300 -and "$($r.Content)".Trim()) { $after = [string]$r.Content | ConvertFrom-Json } } catch { $after = $null }
        if (Test-SISqlAdminIs -Admin $after -Sid $Sid -Login $Login) { return $after }
        if ($i -ge $polls) { break }
        if (-not $said -and $Print) { & $Print ('       {0} is not shown on the server yet -- waiting until it is ...' -f $What); $said = $true }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    }
    $shown = 'none, or the server could not be read'
    if ($after) { $p = $after; if ($after.PSObject.Properties['properties'] -and $after.properties) { $p = $after.properties }; $shown = [string]$p.login }
    throw ('{0} did not take effect within {1} seconds (the server shows: {2}) -- check the server' -f $What, $TimeoutSec, $shown)
}

function Test-SISqlLoginNotReady {
    <# PURE. The refusal of an ENTRA TOKEN sign-in ("Login failed for user '<token-identified principal>'") -- what a server
       answers while it does not know its new Entra administrator yet. A wrong password ("Login failed for user 'sa'"), a
       firewall refusal, a missing database or any other SQL error is not. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    [bool]("$Text" -match "(?i)Login failed for user\s+'<token-identified principal>'")
}

function Invoke-SISqlLoginRetry {
    <#
        Runs -Action (the first sign-in after the database server's administrator was set). When it answers the refusal of
        Test-SISqlLoginNotReady -- thrown, or in the .Error of the result it returns -- AND the administrator was set within
        the last -WindowSec seconds (-AdminSetAt, UTC), it is waited for (-StepSec at a time, up to -WaitSec in all) with one
        plain line, then run again. After that the real answer: the result as it came, or the error thrown again. Any
        other error is never retried. Returns the action's result.
    #>
    param([Parameter(Mandatory)][scriptblock]$Action, $AdminSetAt, [scriptblock]$Now, [scriptblock]$Sleep, [scriptblock]$Print,
          [int]$WaitSec = 300, [int]$StepSec = 30, [int]$WindowSec = 900)
    $nowFn = $(if ($Now) { $Now } else { { [datetime]::UtcNow } })
    $setAt = $null
    if ($AdminSetAt -is [datetime]) { $setAt = $AdminSetAt }
    elseif ("$AdminSetAt".Trim()) { $d = [datetime]::MinValue; if ([datetime]::TryParse("$AdminSetAt", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $setAt = $d } }
    $waited = 0; $said = $false
    while ($true) {
        $result = $null; $thrown = $null
        try { $result = & $Action } catch { $thrown = $_ }
        $text = $(if ($thrown) { [string]$thrown.Exception.Message } elseif ($result -and $result.PSObject.Properties['Error']) { [string]$result.Error } else { '' })
        $recent = $false
        if ($setAt) { $recent = ((([datetime](& $nowFn)).ToUniversalTime() - $setAt.ToUniversalTime()).TotalSeconds -le $WindowSec) }
        if (-not $text -or -not (Test-SISqlLoginNotReady -Text $text) -or -not $recent -or $waited -ge $WaitSec) {
            if ($thrown) { throw $thrown }
            return $result
        }
        if (-not $said -and $Print) { & $Print ('       the database server does not let the sign-in in yet: its new administrator was set moments ago -- waiting {0} s at a time (up to {1} minutes) ...' -f $StepSec, [Math]::Ceiling($WaitSec / 60.0)); $said = $true }
        if ($Sleep) { & $Sleep $StepSec } else { Start-Sleep -Seconds $StepSec }
        $waited += $StepSec
    }
}
