#Requires -Version 5.1
<#
    A SUPPORT TOOL THAT WRITES, WHERE VENDOR SUPPORT HOLDS NO STANDING DATABASE ADMIN (setup\_shared\SI-SupportWrite.ps1;
    framework SECAUDIT-1a / §5.5). Live 2026-11-08 at the vendor's own install: after the Support app's standing admin was
    taken away (it keeps only the read-only role si_support_read), Stop-SIRunAndUpdate's audit row "could not be written"
    and Set-SIProSetting failed. The tools now open the support grant just in time (Invardia's Open-InvardiaSupportGrant:
    one request on si-support-requests, the job caj-si-support-grant grants), wait for it to read back, write, and close it.

    Offline, every seam a fake (the probe of the Support app's own rights, the open, the close, the write, the clock):
      * read-only -> the grant opened (setup, a reason of at most 200 characters), the read-back waited for (bounded, said),
        the write made, the grant closed -- one line each;
      * a standing right, a grant already open, rights that cannot be read, an install not on just-in-time access -> NO
        grant asked (as before);
      * the grant refused -> an AUDIT write is a warning (Done false, never throws, the write is not tried); a SETTING write
        fails plainly (throws), nothing written;
      * opened but never read back / the write throws / the close fails -> closed in every case, said;
      * a -Do block that reads its caller's $Level / $Say / $Sleep sees the CALLER's values (PowerShell scopes are dynamic);
      * setup\Set-SIProSetting.ps1 end to end with a fake store: read-only + grant -> written; refused -> fails, nothing
        written; standing -> no grant.
    NEGATIVE test per rule (the "never" half of each). Free file (both editions); PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SupportWrite.ps1'))

    # ONE fake world: the Support app's roles in the database, what the grant job does, what was written
    function script:New-GrantWorld {
        param([bool]$Owner = $false, [bool]$Reader = $false, [bool]$ReadOnly = $true, [switch]$Refuse, [string]$RefuseText = 'The grant job caj-si-support-grant execution x ended ''Failed'' (exit 3 = no consent on record in the product).',
              [int]$LagReads = 1, [switch]$NeverReadsBack, [switch]$CloseFails, [string]$GrantedLevel = 'setup', [switch]$ProbeThrows)
        $w = @{ Owner = $Owner; Reader = $Reader; ReadOnly = $ReadOnly; Refuse = [bool]$Refuse; RefuseText = $RefuseText; LagReads = $LagReads; NeverReadsBack = [bool]$NeverReadsBack
                CloseFails = [bool]$CloseFails; GrantedLevel = $GrantedLevel; ProbeThrows = [bool]$ProbeThrows; Granted = $false; SinceOpen = 0
                Opens = (New-Object System.Collections.Generic.List[object]); Closes = (New-Object System.Collections.Generic.List[string])
                Writes = (New-Object System.Collections.Generic.List[string]); Said = (New-Object System.Collections.Generic.List[string]); Slept = 0 }
        $w.Probe = {
            if ($w.ProbeThrows) { throw 'Login failed for user ''<token-identified principal>''.' }
            $g = $false
            if ($w.Granted -and -not $w.NeverReadsBack) { $w.SinceOpen++; $g = ($w.SinceOpen -gt $w.LagReads) }
            $own = $w.Owner -or ($g -and $w.GrantedLevel -eq 'setup'); $rd = $w.Reader -or ($g -and $w.GrantedLevel -eq 'troubleshoot')
            @{ UserName = 'Invardia Support'; IsOwner = [int]$own; IsReader = [int]$rd; IsReadOnly = [int]$w.ReadOnly }
        }.GetNewClosure()
        $w.Open = {
            param($Level, $Reason)
            $w.Opens.Add([pscustomobject]@{ Level = $Level; Reason = $Reason })
            if ($w.Refuse) { throw $w.RefuseText }
            $w.Granted = $true; $w.SinceOpen = 0
            [pscustomobject]@{ Product = 'securityinsight'; Action = 'open'; Level = $w.GrantedLevel; MaxUntil = '2026-11-08T13:00:00Z'; Status = 'Succeeded'; Meaning = 'granted' }
        }.GetNewClosure()
        $w.Close = { param($Reason) $w.Closes.Add($Reason); if ($w.CloseFails) { throw 'Putting the request on stsi/si-support-requests failed: HTTP 403' }; $w.Granted = $false }.GetNewClosure()
        $w.Say = { param($t, $c) $w.Said.Add($t) }.GetNewClosure()
        $w.Sleep = { param($s) $w.Slept += $s }.GetNewClosure()
        # the write: refused like SQL Server refuses it unless the Support app holds the role right now
        $w.Write = { $p = & $w.Probe; if (-not [int]$p.IsOwner) { throw 'The INSERT permission was denied on the object ''AuditEvent'', database ''sqldb-si'', schema ''audit''.' }; $w.Writes.Add('row'); 'written' }.GetNewClosure()
        $w
    }
    function script:Invoke-Grant {
        param($W, [string]$Kind = 'audit', [string]$Level = 'setup', [scriptblock]$Do, [switch]$NoOpen, [switch]$NoClose, [int]$Tries = 3)
        $a = @{ Purpose = 'the audit row job.execution.start'; Tool = 'Stop-SIRunAndUpdate'; GrantLevel = $Level; WriteKind = $Kind; Probe = $W.Probe
                Do = $(if ($Do) { $Do } else { $W.Write }); GrantSay = $W.Say; GrantSleep = $W.Sleep; GrantReadBackTries = $Tries; GrantReadBackSeconds = 10 }
        if (-not $NoOpen) { $a.Open = $W.Open }
        if (-not $NoClose) { $a.Close = $W.Close }
        Invoke-SISupportWithGrant @a
    }
}

Describe 'the Support app is read-only: the grant is opened, read back, the write made, the grant closed' {
    It 'opens at the setup level with the tool and the purpose as the reason, waits for the read-back, writes, closes -- one line each' {
        $W = New-GrantWorld -LagReads 1
        $r = Invoke-Grant $W
        $r.Done | Should -BeTrue; $r.Asked | Should -BeTrue; $r.Opened | Should -BeTrue; $r.Closed | Should -BeTrue
        $r.Value | Should -Be 'written'
        $W.Writes.Count | Should -Be 1
        $W.Opens.Count | Should -Be 1; $W.Closes.Count | Should -Be 1
        $W.Opens[0].Level | Should -Be 'setup'
        $W.Opens[0].Reason | Should -Be 'SecurityInsight Stop-SIRunAndUpdate: the audit row job.execution.start'
        $txt = $W.Said -join "`n"
        $txt | Should -Match 'the Support app is read-only here: opening the support grant \(setup, at most 1 h\) for: the audit row job\.execution\.start'
        $txt | Should -Match 'waiting for the support grant to read back \(db_owner in this database; up to 20 s\)'
        $txt | Should -Match 'support grant open \(setup until 2026-11-08T13:00:00Z UTC\), read back: db_owner in this database'
        $txt | Should -Match 'support grant closed again'
        $W.Slept | Should -Be 10 -Because 'the read-back showed the role on the second read: one wait'
        @($r.Lines).Count | Should -Be 4
    }
    It 'a read-back at once: no wait line, no wait' {
        $W = New-GrantWorld -LagReads 0
        $r = Invoke-Grant $W
        $r.Done | Should -BeTrue
        ($W.Said -join "`n") | Should -Not -Match 'waiting for the support grant'
        $W.Slept | Should -Be 0
    }
    It 'troubleshoot: db_datareader is enough (a read of the data tables)' {
        $W = New-GrantWorld -LagReads 0 -GrantedLevel 'troubleshoot'
        $r = Invoke-Grant $W -Level troubleshoot -Do { 'read' }
        $r.Done | Should -BeTrue; $r.Value | Should -Be 'read'
        $W.Opens[0].Level | Should -Be 'troubleshoot'
        ($W.Said -join "`n") | Should -Match 'read back: db_datareader in this database'
    }
    It 'the reason is one line of at most 200 characters (the grant job refuses more)' {
        $t = Get-SISupportGrantReason -Tool 'Set-SIProSetting' -Purpose (('x' * 300) + "`nsecond line")
        $t.Length | Should -Be 200
        $t | Should -Not -Match "[\r\n]"
    }
}

Describe 'no grant is asked where the Support app is not read-only (behaviour as before)' {
    It '<Name>' -ForEach @(
        @{ Name = 'a standing db_owner (an install not moved yet)';            Opt = @{ Owner = $true } }
        @{ Name = 'a grant already open (someone opened it before)';          Opt = @{ Owner = $true; ReadOnly = $true } }
        @{ Name = 'not in the read-only role (not on just-in-time access)';   Opt = @{ Owner = $false; ReadOnly = $false } }
        @{ Name = 'its rights cannot be read';                                Opt = @{ ProbeThrows = $true } }
    ) {
        $W = New-GrantWorld @Opt
        $r = Invoke-Grant $W -Do { 'as before' }
        $r.Done | Should -BeTrue; $r.Value | Should -Be 'as before'
        $r.Asked | Should -BeFalse
        $W.Opens.Count | Should -Be 0 -Because 'NEGATIVE: never a grant where it is not needed'
        $W.Closes.Count | Should -Be 0 -Because 'NEGATIVE: a grant someone else opened is never closed'
        $W.Said.Count | Should -Be 0
    }
    It 'the need, pure: read-only and lacking the right = ask; every other shape = no' {
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ IsOwner = 0; IsReader = 0; IsReadOnly = 1 }) -Level setup).Ask | Should -BeTrue
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ IsOwner = 0; IsReader = 1; IsReadOnly = 1 }) -Level setup).Ask | Should -BeTrue -Because 'a reader cannot write'
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ IsOwner = 0; IsReader = 1; IsReadOnly = 1 }) -Level troubleshoot).Ask | Should -BeFalse
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ IsOwner = 1; IsReader = 0; IsReadOnly = 1 }) -Level setup).Ask | Should -BeFalse
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ IsOwner = 0; IsReader = 0; IsReadOnly = 0 }) -Level setup).Ask | Should -BeFalse
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow $null) -Level setup).Ask | Should -BeFalse
        (Get-SISupportGrantNeed -Access (ConvertFrom-SISupportAccessRow @{ U = 'dbo'; O = 1 }) -Level setup).Ask | Should -BeFalse -Because 'a row of another shape is not known'
    }
    It 'the probe is ONE read of the Support app''s own memberships (functions on itself; no table, no data)' {
        $q = Get-SISupportAccessProbeSql
        $q | Should -Match "IS_ROLEMEMBER\(N'db_owner'\)"
        $q | Should -Match "IS_ROLEMEMBER\(N'si_support_read'\)"
        $q | Should -Not -Match '(?i)\bFROM\b|INSERT|UPDATE|DELETE|MERGE|EXEC'
    }
}

Describe 'the grant cannot be opened' {
    It 'an AUDIT write: a warning -- Done false, the reason and what to do, never throws, the write never tried' {
        $W = New-GrantWorld -Refuse
        $r = Invoke-Grant $W -Kind audit
        $r.Done | Should -BeFalse; $r.Opened | Should -BeFalse
        $r.Why | Should -Match 'the audit row job\.execution\.start was not made: the support grant could not be opened \(The grant job caj-si-support-grant .*no consent on record'
        $r.Why | Should -Match 'Open-InvardiaSupportGrant -Product si -Level setup'
        ($W.Said -join "`n") | Should -Match 'the support grant could NOT be opened: '
        $W.Writes.Count | Should -Be 0
        $W.Closes.Count | Should -Be 0 -Because 'NEGATIVE: nothing was opened, so nothing is closed'
    }
    It 'a SETTING write: fails plainly (throws), nothing written' {
        $W = New-GrantWorld -Refuse -RefuseText 'Refused: the customer consented to troubleshoot; -Level setup is more than that (owner rule 4b: never more than the customer agreed to).'
        { Invoke-Grant $W -Kind setting } | Should -Throw '*was not made: the support grant could not be opened (Refused: the customer consented to troubleshoot*'
        $W.Writes.Count | Should -Be 0
    }
    It 'a Support session without the open call (an older Connect-InvardiaSupport): audit = warning, setting = fails; the write never tried' {
        $W = New-GrantWorld
        $r = Invoke-Grant $W -Kind audit -NoOpen
        $r.Done | Should -BeFalse
        $r.Why | Should -Match 'this Support session cannot open the support grant'
        { Invoke-Grant (New-GrantWorld) -Kind setting -NoOpen } | Should -Throw '*cannot open the support grant*'
        $W.Writes.Count | Should -Be 0
    }
}

Describe 'opened, then something goes wrong: the grant is closed in every case' {
    It 'opened but never read back: closed again; audit = warning, setting = fails; the write never tried' {
        $W = New-GrantWorld -NeverReadsBack
        $r = Invoke-Grant $W -Kind audit -Tries 3
        $r.Done | Should -BeFalse; $r.Opened | Should -BeTrue; $r.Closed | Should -BeTrue
        $r.Why | Should -Match 'does not show db_owner after 20 s'
        $W.Writes.Count | Should -Be 0
        $W.Slept | Should -Be 20 -Because 'bounded: 3 reads, 2 waits of 10 s'
        $W2 = New-GrantWorld -NeverReadsBack
        { Invoke-Grant $W2 -Kind setting } | Should -Throw '*does not show db_owner*'
        $W2.Closes.Count | Should -Be 1
    }
    It 'granted below what is needed (the customer consented to troubleshoot): said, closed, not written' {
        $W = New-GrantWorld -GrantedLevel 'troubleshoot' -LagReads 0
        $r = Invoke-Grant $W -Kind audit
        $r.Done | Should -BeFalse
        $r.Why | Should -Match 'opened at level troubleshoot but this database does not show db_owner .* the customer consented to troubleshoot, this needs setup'
        $W.Closes.Count | Should -Be 1
    }
    It 'a SETTING write that throws: closed first, then its error goes on' {
        $W = New-GrantWorld -LagReads 0
        { Invoke-Grant $W -Kind setting -Do { throw 'the value is not one of the choices' } } | Should -Throw 'the value is not one of the choices'
        $W.Closes.Count | Should -Be 1
    }
    It 'an AUDIT write that throws: closed, Done false with its error, never throws' {
        $W = New-GrantWorld -LagReads 0
        $r = Invoke-Grant $W -Kind audit -Do { throw 'deadlock victim' }
        $r.Done | Should -BeFalse; $r.Why | Should -Be 'deadlock victim'; $r.Closed | Should -BeTrue
    }
    It 'the close fails: said with what to do, the write stands' {
        $W = New-GrantWorld -LagReads 0 -CloseFails
        $r = Invoke-Grant $W
        $r.Done | Should -BeTrue; $r.Closed | Should -BeFalse
        ($W.Said -join "`n") | Should -Match 'the support grant could NOT be closed \(Putting the request .*HTTP 403\) -- it ends by itself at 2026-11-08T13:00:00Z UTC; to close it now: Close-InvardiaSupportGrant -Product si'
    }
    It 'no close call in the session: said, it ends by itself' {
        $W = New-GrantWorld -LagReads 0
        $r = Invoke-Grant $W -NoClose
        $r.Done | Should -BeTrue
        ($W.Said -join "`n") | Should -Match 'was not closed from here .* it ends by itself at 2026-11-08T13:00:00Z UTC'
    }
}

Describe 'the -Do block sees its CALLER''s variables (PowerShell scopes are dynamic)' {
    It 'a caller''s $Level / $Say / $Sleep / $ReadBackTries are not shadowed by the helper''s own parameters' {
        $W = New-GrantWorld -LagReads 0
        $Level = 'the caller''s consent level'; $Say = 'the caller''s say'; $Sleep = 'the caller''s sleep'; $ReadBackTries = 'the caller''s tries'; $Kind = 'the caller''s kind'
        # called DIRECTLY (not through this suite's Invoke-Grant, which has a $Level / $Kind of its own)
        $r = Invoke-SISupportWithGrant -Purpose 'p' -Tool 't' -GrantLevel setup -WriteKind setting -Probe $W.Probe -Open $W.Open -Close $W.Close -GrantSay $W.Say -GrantSleep $W.Sleep `
                 -Do { '{0}|{1}|{2}|{3}|{4}' -f $Level, $Say, $Sleep, $ReadBackTries, $Kind }
        $r.Value | Should -Be 'the caller''s consent level|the caller''s say|the caller''s sleep|the caller''s tries|the caller''s kind'
    }
    It 'the seam dictionary maps onto the helper''s own names' {
        $o = { 'o' }; $c = { 'c' }; $s = { 's' }; $z = { 'z' }
        $a = Get-SISupportGrantArgs -SupportGrant @{ Open = $o; Close = $c; Say = $s; Sleep = $z; ReadBackTries = 2; ReadBackSeconds = 0 }
        $a.Open | Should -Be $o; $a.Close | Should -Be $c; $a.GrantSay | Should -Be $s; $a.GrantSleep | Should -Be $z
        $a.GrantReadBackTries | Should -Be 2; $a.GrantReadBackSeconds | Should -Be 0
        $a.ContainsKey('Say') | Should -BeFalse
        $d = Get-SISupportGrantArgs -SupportGrant $null -Say $s
        $d.Open | Should -BeNullOrEmpty; $d.GrantSay | Should -Be $s
    }
    It 'no Support session in the shell: no open call is handed out (the write then says so)' {
        if (Get-Command -Name Open-InvardiaSupportGrant -ErrorAction SilentlyContinue) { Set-ItResult -Skipped -Because 'an Invardia Support session is loaded in this shell' }
        (New-SISupportGrantSeams -SubscriptionId 's' -ResourceGroup 'rg').Open | Should -BeNullOrEmpty
    }
    It 'the Support session store sends every parameter DECLAREd (Invardia''s SQL call takes none) and reads as reads' {
        $sent = New-Object System.Collections.Generic.List[object]
        $st = New-SIProSettingSupportStore -Server 'server' -Database 'sqldb-si' -Reason 'SecurityInsight setting X: why' -Invoke { param($S, $D, $Q, $R, $RO) $sent.Add([pscustomobject]@{ S = $S; D = $D; Q = $Q; R = $R; RO = $RO }); [pscustomobject]@{ RowsAffected = 1; Rows = @(@{ A = 7 }) } }.GetNewClosure()
        $null = & $st.Invoke 'UPDATE cfg.Setting SET ValueJson = @V WHERE Name = @N;' ([ordered]@{ V = "it's"; N = 'X'; B = $true; I = 5; Z = $null }) 'nonquery'
        $sent[0].S | Should -Be ('server' + '.database.windows.net')
        $sent[0].RO | Should -BeFalse
        $sent[0].Q | Should -Match "DECLARE @V nvarchar\(max\) = N'it''s';"
        $sent[0].Q | Should -Match 'DECLARE @B bit = 1;'
        $sent[0].Q | Should -Match 'DECLARE @I bigint = 5;'
        $sent[0].Q | Should -Match 'DECLARE @Z nvarchar\(max\) = NULL;'
        $sent[0].R | Should -Be 'SecurityInsight setting X: why'
        (& $st.Invoke 'SELECT 7 AS A;' @{} 'scalar') | Should -Be 7
        $sent[1].RO | Should -BeFalse -Because 'scalar is not a read flag'
        $null = & $st.Invoke 'SELECT 1;' @{} 'reader'
        $sent[2].RO | Should -BeTrue
        { & $st.Invoke 'SELECT 1;' @{ 'a;b' = 1 } 'reader' } | Should -Throw "*is not a parameter name*"
    }
}

Describe 'setup\Set-SIProSetting.ps1 from a Support session (a fake store)' {
    BeforeAll {
        $script:SetScript = [IO.Path]::Combine($script:SIRoot, 'setup', 'Set-SIProSetting.ps1')
        function script:New-SettingStore($W) {
            $state = @{ Calls = New-Object System.Collections.Generic.List[object] }
            $inv = {
                param($sql, $p, $mode)
                $state.Calls.Add(@{ Sql = $sql; P = $p; Mode = $mode })
                if ($sql -match 'AS IsReadOnly') { return , @(& $W.Probe) }
                if ($mode -eq 'nonquery') { $pr = & $W.Probe; if (-not [int]$pr.IsOwner) { throw 'The INSERT permission was denied on the object ''Setting''.' }; $W.Writes.Add([string]$p.Name); return 1 }
                , @()
            }.GetNewClosure()
            [pscustomobject]@{ Name = 'fake/pro (support)'; Invoke = $inv; State = $state }
        }
        $script:RunSet = {
            param($W, [switch]$NoGrant)
            $a = @{ Name = 'SI_Guard_RaOutputRowDrop_Enabled'; Value = 'false'; Reason = 'the offline test of the support grant path'; Apply = $true; Store = (New-SettingStore $W); PassThru = $true }
            if (-not $NoGrant) { $a.SupportGrant = @{ Open = $W.Open; Close = $W.Close; Say = $W.Say; Sleep = $W.Sleep; ReadBackTries = 3; ReadBackSeconds = 0 } }
            & $script:SetScript @a 6>$null
        }
    }
    It 'read-only: the grant opened, the setting written, the grant closed' {
        $W = New-GrantWorld -LagReads 0
        $r = & $script:RunSet $W
        $r.Applied | Should -BeTrue
        $W.Writes | Should -Be @('SI_Guard_RaOutputRowDrop_Enabled')
        $W.Opens.Count | Should -Be 1; $W.Closes.Count | Should -Be 1
        $W.Opens[0].Reason | Should -Be 'SecurityInsight Set-SIProSetting: the setting SI_Guard_RaOutputRowDrop_Enabled'
    }
    It 'the grant refused: the script FAILS plainly, nothing written' {
        $W = New-GrantWorld -Refuse
        { & $script:RunSet $W } | Should -Throw '*the setting SI_Guard_RaOutputRowDrop_Enabled was not made: the support grant could not be opened*'
        $W.Writes.Count | Should -Be 0
    }
    It 'a standing right: written, no grant asked' {
        $W = New-GrantWorld -Owner $true
        $r = & $script:RunSet $W
        $r.Applied | Should -BeTrue
        $W.Writes.Count | Should -Be 1
        $W.Opens.Count | Should -Be 0
    }
    It 'NEGATIVE: without a Support session (no -SupportSql, no seam) nothing about a grant is read or asked' {
        $W = New-GrantWorld -Owner $true
        $st = New-SettingStore $W
        $null = & $script:SetScript -Name 'SI_Guard_RaOutputRowDrop_Enabled' -Value 'false' -Reason 'the offline test of the support grant path' -Apply -Store $st 6>$null
        @($st.State.Calls | Where-Object { $_.Sql -match 'AS IsReadOnly' }).Count | Should -Be 0
        $W.Opens.Count | Should -Be 0
    }
    It 'the plan (no -Apply) asks no grant and writes nothing' {
        $W = New-GrantWorld
        $null = & $script:SetScript -Name 'SI_Guard_RaOutputRowDrop_Enabled' -Value 'false' -Reason 'the offline test of the support grant path' -Store (New-SettingStore $W) -SupportGrant @{ Open = $W.Open; Close = $W.Close } 6>$null
        $W.Opens.Count | Should -Be 0; $W.Writes.Count | Should -Be 0
    }
}
