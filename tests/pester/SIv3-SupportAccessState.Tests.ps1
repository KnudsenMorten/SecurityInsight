#Requires -Version 5.1
<#
    Invardia 2026-11-20 (OPEN-01 / SECAUDIT-1a): the heartbeat's STATE field SupportAccess { level, adminUntil, readUser,
    checkedUtc } -- the shape Invardia takes for every product (C:\claude-sessions\Invardia\packages\core\src\heartbeatstate.ts,
    SUPPORT_STATE_CONTRACT.SupportAccess). engine\support-grant\SI-SupportGrant.ps1 (ConvertTo-SISupportAccessState,
    Start-SISupportAccessHeartbeat), engine\_shared\SI-HeartbeatJob.ps1 (Send-SIHeartbeatTick -Extra),
    engine\heartbeat\Invoke-SIHeartbeat.ps1, engine\support-grant\Invoke-SISupportGrant.ps1.

    What must hold (no database, no network -- every seam is a stub):
      - level = what the Support app holds NOW, read from the install: troubleshoot / setup while a grant is open (with
        adminUntil = its expiry), read = only the read-only user, none = neither; never what was asked;
      - a state that could not be read is LEFT OUT (never 'none'), and the tick says why;
      - the field rides on EVERY identified heartbeat (no switch), one object at the top level (Invardia takes it SOFT:
        a bad shape drops the field alone, so it is not on the resend-without list);
      - the extra heartbeat after an open / close / expiry goes OUTSIDE the half hour's claim; the grant job starts it as
        the pipeline runner starts a job (its own container, every variable kept, SI_HEARTBEAT_EXTRA = support-access);
      - the old support.* events and their switch SI_Uplink_SendSupportGrant are gone.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
    if (-not (Get-Command -Name ConvertTo-SISupportAccessState -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\support-grant\SI-SupportGrant.ps1') }
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-20T10:07:00', [DateTimeKind]::Utc)
    function script:Row([string]$Db, [int]$User = 1, [int]$Ro = 1, [int]$Open = 0, $Until = $null, $Level = $null) {
        [pscustomobject]@{ Database = $Db; Signed = 1; UserPresent = $User; ReadOnlyHeld = $Ro; JitOpen = $Open; JitUntilUtc = $Until; JitLevel = $Level; JitOverdue = 0; StandingOwner = 0 }
    }
    # a fake product database answering the status procedure (or throwing)
    function script:Db($Answer) { { param($Sql, $Params, $Mode) if ($Answer -is [string] -and $Answer -like 'THROW*') { throw $Answer.Substring(6) }; , @($Answer) }.GetNewClosure() }
    function script:Status([object[]]$Rows) {
        $dbs = [ordered]@{}; $i = 0
        foreach ($r in $Rows) { $dbs[('db{0}' -f $i)] = (Db $r); $i++ }
        Get-SISupportGrantStatus -Databases $dbs -NowUtc $script:Now
    }
    function script:New-Ctx {
        [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://stub.example.test/report'; AccessCode = 'inv-TESTKEYabcdefghijklmnopqrstuvwxyz'
            Edition = 'pro'; LicenceState = 'valid'; Version = '3.1.39'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; Ring = 2
            InstallId = ''; TenantId = '7f3e2a10-4b5c-4d6e-8f90-a1b2c3d4e5f6'; StateDirectory = ''; EnvironmentName = 'Contoso'; LicenceId = ''; Endpoints = @(); AnonymousReason = '' }
    }
    function script:New-Transport([string]$Refuse = '') {
        $sent = New-Object System.Collections.Generic.List[object]
        $t = { param($Record, $Endpoint, $AccessCode, $TimeoutSec)
               $sent.Add(($Record | ConvertTo-Json -Depth 8 -Compress))
               if ($Refuse -and $Record.PSObject.Properties[$Refuse]) { return [pscustomobject]@{ Status = 'failed'; Reason = 'uplink POST failed: 422 unknown field' } }
               [pscustomobject]@{ Status = 'ok'; Reason = 'ok'; SupersededBy = '' } }.GetNewClosure()
        [pscustomobject]@{ Transport = $t; Sent = $sent }
    }
    function script:New-Claim {
        $log = New-Object System.Collections.Generic.List[object]
        $inv = { param($sql, $p, $mode) $log.Add([pscustomobject]@{ Sql = $sql; Mode = $mode }); if ($sql -match 'HeartbeatJob') { @{ Claimed = 1 } } }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Log = $log }
    }
    function script:Tick($Status, [switch]$Extra, [string]$Refuse = '') {
        $t = New-Transport -Refuse $Refuse; $c = New-Claim
        $r = Send-SIHeartbeatTick -Context (New-Ctx) -Transport $t.Transport -Now $script:Now -ClaimInvoke $c.Invoke -HeartbeatCounts { @{} } `
                -SetupStepRows @() -SupportGrantStatus { param($n) $Status }.GetNewClosure() -SupportSqlAccess { param($n) $null } -FieldSwitch @{} -Extra:$Extra
        [pscustomobject]@{ R = $r; Sent = $t.Sent; Claim = $c.Log }
    }
}

Describe 'the state: what the Support app holds NOW, read from the install' {
    It 'read: no grant open, the read-only user present and in its role in every database' {
        $s = ConvertTo-SISupportAccessState -Status (Status @((Row 'pro'), (Row 'ledger')))
        $s.Wire.level | Should -Be 'read'; $s.Wire.readUser | Should -BeTrue
        $s.Wire.Contains('adminUntil') | Should -BeFalse -Because 'adminUntil only while a troubleshoot / setup grant is open'
        $s.Wire.checkedUtc | Should -Be '2026-11-20T10:07:00Z'
    }
    It 'troubleshoot / setup: a grant is open -- its level, adminUntil = its latest expiry over the databases' {
        $s = ConvertTo-SISupportAccessState -Status (Status @((Row 'pro' 1 1 1 '2026-11-20T12:00:00Z' 'troubleshoot'), (Row 'ledger' 1 1 1 '2026-11-20T13:30:00Z' 'troubleshoot')))
        $s.Wire.level | Should -Be 'troubleshoot'; $s.Wire.adminUntil | Should -Be '2026-11-20T13:30:00Z'; $s.Wire.readUser | Should -BeTrue
        (ConvertTo-SISupportAccessState -Status (Status @((Row 'pro' 1 1 1 '2026-11-20T12:00:00Z' 'setup')))).Wire.level | Should -Be 'setup'
    }
    It 'none: no grant open and the read-only user is missing (or out of its role) in a database' {
        $s = ConvertTo-SISupportAccessState -Status (Status @((Row 'pro'), (Row 'ledger' 0 0)))
        $s.Wire.level | Should -Be 'none'; $s.Wire.readUser | Should -BeFalse
        (ConvertTo-SISupportAccessState -Status (Status @((Row 'pro' 1 0)))).Wire.level | Should -Be 'none'
    }
    It 'never invented: a database that could not be read, no answer, or an open grant without level / expiry = LEFT OUT (never none)' {
        $u = ConvertTo-SISupportAccessState -Status (Status @((Row 'pro'), 'THROW timeout'))
        $u.Wire | Should -BeNullOrEmpty; $u.Why | Should -Match 'could not be read'
        (ConvertTo-SISupportAccessState -Status $null).Wire | Should -BeNullOrEmpty
        (ConvertTo-SISupportAccessState -Status ([pscustomobject]@{ Wire = $null; Text = 'x'; Rows = @(); Unread = 0 })).Wire | Should -BeNullOrEmpty
        (ConvertTo-SISupportAccessState -Status (Status @((Row 'pro' 1 1 1 '2026-11-20T12:00:00Z' $null)))).Wire | Should -BeNullOrEmpty
        (ConvertTo-SISupportAccessState -Status (Status @((Row 'pro' 1 1 1 $null 'setup')))).Wire | Should -BeNullOrEmpty
    }
    It 'the shape is exactly Invardia''s: level (closed list) / adminUntil / readUser / checkedUtc, ISO UTC times' {
        foreach ($st in @((Status @((Row 'pro'))), (Status @((Row 'pro' 1 1 1 '2026-11-20T12:00:00Z' 'setup'))), (Status @((Row 'pro' 0 0))))) {
            $w = (ConvertTo-SISupportAccessState -Status $st).Wire
            @($w.Keys | Where-Object { $_ -notin @('level', 'adminUntil', 'readUser', 'checkedUtc') }) | Should -BeNullOrEmpty
            $w.level | Should -BeIn @('none', 'read', 'troubleshoot', 'setup')
            $w.checkedUtc | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
            if ($w.Contains('adminUntil')) { $w.adminUntil | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$' }
            $w.readUser | Should -BeOfType [bool]
        }
    }
    It 'the status says how many databases could not be read (Unread)' {
        (Status @((Row 'pro'), 'THROW down')).Unread | Should -Be 1
        (Status @((Row 'pro'))).Unread | Should -Be 0
    }
}

Describe 'on EVERY heartbeat (Send-SIHeartbeatTick)' {
    It 'the identified heartbeat carries SupportAccess at any ring (no switch), and the tick says it' {
        $x = Tick (Status @((Row 'pro' 1 1 1 '2026-11-20T12:00:00Z' 'troubleshoot')))
        $x.R.Status | Should -Be 'sent'
        # read as sent (PowerShell 7's ConvertFrom-Json would turn the time into a date): the exact text on the wire
        $x.Sent[0] | Should -Match ([regex]::Escape('"SupportAccess":{"level":"troubleshoot","adminUntil":"2026-11-20T12:00:00Z","readUser":true,"checkedUtc":"2026-11-20T10:07:00Z"}'))
        $x.R.Reason | Should -Match 'SupportAccess'
        $x.R.Reason | Should -Match 'support access: troubleshoot until 2026-11-20T12:00:00Z'
    }
    It 'a state that could not be read is left out and the tick says why' {
        $x = Tick (Status @((Row 'pro'), 'THROW timeout'))
        $x.Sent[0] | Should -Not -Match '"SupportAccess"'
        $x.R.Reason | Should -Match 'support access: not sent this time -- 1 database\(s\) could not be read'
    }
    It 'a read state goes on the heartbeat as one object at the top level, where Invardia reads its state fields' {
        $x = Tick (Status @((Row 'pro')))
        $j = $x.Sent[0] | ConvertFrom-Json
        $j.PSObject.Properties['SupportAccess'] | Should -Not -BeNullOrEmpty
        $j.SupportAccess.level | Should -Be 'read'; $j.SupportAccess.readUser | Should -BeTrue
        $j.SupportAccess.PSObject.Properties['adminUntil'] | Should -BeNullOrEmpty
    }
    It '-Extra (after a grant opened / closed / expired): sent at once OUTSIDE the half hour''s claim; a normal tick claims' {
        $e = Tick (Status @((Row 'pro'))) -Extra
        $e.R.Status | Should -Be 'sent'
        @($e.Claim | Where-Object { $_.Sql -match 'HeartbeatJob' }).Count | Should -Be 0 -Because 'the extra heartbeat neither takes nor completes the half hour'
        @($e.Claim | Where-Object { $_.Sql -match 'HeartbeatDelivery' }).Count | Should -Be 0
        $e.R.Reason | Should -Match 'the extra heartbeat after a support access change'
        $n = Tick (Status @((Row 'pro')))
        @($n.Claim | Where-Object { $_.Sql -match 'HeartbeatJob' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'the extra heartbeat: started from the grant job the way the pipeline runner starts a job' {
    It 'GET the heartbeat job, POST /start with its own container and every variable kept + SI_HEARTBEAT_EXTRA=support-access' {
        $calls = New-Object System.Collections.Generic.List[object]
        $job = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'heartbeat'; image = 'acr/si-orchestrator:v1'
                    env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'heartbeat' }, [pscustomobject]@{ name = 'SI_SECRET'; secretRef = 'sec' }) }) } } }
        $arm = { param($Method, $Path, $Body) $calls.Add([pscustomobject]@{ M = $Method; P = $Path; B = $Body }); if ($Method -eq 'GET') { $job } else { [pscustomobject]@{ name = 'caj-si-heartbeat-x1' } } }.GetNewClosure()
        $r = Start-SISupportAccessHeartbeat -Arm $arm -SubscriptionId 'sub1' -ResourceGroup 'rg1'
        $r.Started | Should -BeTrue; $r.Execution | Should -Be 'caj-si-heartbeat-x1'
        $calls[0].M | Should -Be 'GET'; $calls[0].P | Should -Be '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.App/jobs/caj-si-heartbeat'
        $calls[1].M | Should -Be 'POST'; $calls[1].P | Should -Be '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.App/jobs/caj-si-heartbeat/start'
        $env = @($calls[1].B.containers[0].env)
        @($env | Where-Object { $_.name -eq 'SI_HEARTBEAT_EXTRA' })[0].value | Should -Be 'support-access'
        @($env | Where-Object { $_.name -eq 'SI_ENGINE' })[0].value | Should -Be 'heartbeat'
        @($env | Where-Object { $_.name -eq 'SI_SECRET' })[0].secretRef | Should -Be 'sec'
        $calls[1].B.containers[0].image | Should -Be 'acr/si-orchestrator:v1'
    }
    It 'never throws: no job target, no job, an ARM failure -- Started false with why' {
        $old = @{}; foreach ($n in 'SI_JOBS_SUBSCRIPTIONID', 'SI_JOBS_RESOURCEGROUP', 'SI_FLOW_SUBSCRIPTIONID', 'SI_FLOW_RESOURCEGROUP') { $old[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null) }
        try {
            $a = Start-SISupportAccessHeartbeat -Arm { param($m, $p, $b) throw 'not called' }
            $a.Started | Should -BeFalse; $a.Why | Should -Match 'SI_JOBS_SUBSCRIPTIONID'
        } finally { foreach ($n in $old.Keys) { [Environment]::SetEnvironmentVariable($n, $old[$n]) } }
        (Start-SISupportAccessHeartbeat -Arm { param($m, $p, $b) $null } -SubscriptionId 's' -ResourceGroup 'r').Why | Should -Match 'is not a job of this install'
        (Start-SISupportAccessHeartbeat -Arm { param($m, $p, $b) throw '403 Forbidden' } -SubscriptionId 's' -ResourceGroup 'r').Why | Should -Match '403'
    }
}

Describe 'WIRING' {
    BeforeAll {
        $script:Grant = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\support-grant\Invoke-SISupportGrant.ps1'))
        $script:Hb = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\heartbeat\Invoke-SIHeartbeat.ps1'))
        $script:Lib = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\support-grant\SI-SupportGrant.ps1'))
    }
    It 'the grant job starts the extra heartbeat after an open / close (its -Report callback) -- the old events and their switch are gone' {
        $script:Grant | Should -Match 'Start-SISupportAccessHeartbeat'
        $script:Grant | Should -Match ([regex]::Escape('Invoke-SISupportGrantJob -Databases $dbs -Receive $receive -Remove $remove -NowUtc $nowUtc -Say $say -Report $report'))
        foreach ($t in @($script:Grant, $script:Lib)) { $t | Should -Not -Match 'Resolve-SIUplinkSupportGrantSwitch|SI_UPLINK_SENDSUPPORTGRANT|\$global:SI_Uplink_SendSupportGrant' }
        $script:Grant | Should -Not -Match "'supportGrant'"
    }
    It 'the heartbeat job: SI_HEARTBEAT_EXTRA=support-access = one tick with -Extra and nothing else; an expired grant revoked = one extra tick' {
        $script:Hb | Should -Match ([regex]::Escape("GetEnvironmentVariable('SI_HEARTBEAT_EXTRA')"))
        $script:Hb | Should -Match ([regex]::Escape('-ClaimInvoke $proInvoke -Extra:$extra'))
        $script:Hb | Should -Match ([regex]::Escape('if ($extra) { exit 0 }'))
        $script:Hb | Should -Match '(?s)Invoke-SISupportGrantSweep.{0,800}\[int\]\$sg\.Closed -gt 0.{0,200}Send-SIHeartbeatTick .{0,120}-Extra'
    }
}
