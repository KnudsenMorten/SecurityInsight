#Requires -Version 5.1
<#
    SecurityInsight Pro -- RELEASING A HELD CLOSE SET ONCE (operator decision 2026-10-04: "mass closes from patching or
    remediation must never block -- we cannot block").

    When the close limit halts a vulnerability connector run, the closes it held are stored as a RELEASE CANDIDATE: the
    run id, the counts (per asset, per CVE) and the finding ids (cfg.GuardRelease in the Pro database; a JSON file under
    state\vuln-held-closes on an install without one). An Admin releases THAT set once -- Operations > Guards (safety checks) ("Release
    these closes"), the link in the guard mail, or on a VM:  Invoke-SIVulnLoop.ps1 -ReleaseHeldCloses <runId>.
    The connector's next run (or the run the release starts) then:
      * re-checks that the newest results are COMPLETE -- otherwise the release waits;
      * closes exactly the released findings that are STILL ABSENT and still qualify for a close -- a finding that came
        back is not closed, and nothing outside the released set gets past the limit;
      * marks the release applied (what closed, what came back). A release is never a setting change and expires after
        7 days. Every approval is audited (guard.release.approve), every application too (guard.release.apply).
    PS 5.1 safe. NO Set-StrictMode here (it leaks into the caller's scope).
#>

$script:SIVulnReleaseDays = 7

function Get-SIVulnReleaseSql {
    <# The statements over cfg.GuardRelease (sql\si-pro-settings.sql). Fixed text, every value a parameter. #>
    param([Parameter(Mandatory)][ValidateSet('Exists', 'Insert', 'Open', 'Approve', 'SetState', 'Expire', 'Supersede')][string]$Name)
    switch ($Name) {
        'Exists'   { "SELECT CASE WHEN OBJECT_ID(N'cfg.GuardRelease') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;" }
        'Insert'   { @'
IF NOT EXISTS (SELECT 1 FROM cfg.GuardRelease WHERE Connector = @Connector AND RunId = @RunId)
INSERT cfg.GuardRelease (GuardId, Connector, ConnectorKind, RunId, ExpiresUtc, HeldCount, SummaryJson, ItemsJson, State)
VALUES (@GuardId, @Connector, @ConnectorKind, @RunId, DATEADD(day, @Days, SYSUTCDATETIME()), @HeldCount, @SummaryJson, @ItemsJson, N'held');
'@ }
        'Open'     { "SELECT ReleaseId, GuardId, Connector, ConnectorKind, RunId, HeldUtc, ExpiresUtc, HeldCount, ItemsJson, State, ReleasedBy, ReleasedUtc FROM cfg.GuardRelease WHERE Connector = @Connector AND State IN (N'held', N'released') AND ExpiresUtc > SYSUTCDATETIME();" }
        # GUARD-1.6 (#404): a release from the command line is bound to the held plan as it is now and ends after one run or
        # 24 hours, like one from the web app (which a SuperAdmin gives, with a reason)
        'Approve'  { "UPDATE cfg.GuardRelease SET State = N'released', ReleasedBy = @By, ReleasedUtc = SYSUTCDATETIME(), ReleaseReason = N'released on the command line', PlanHash = CurrentPlanHash, ReleaseUntilUtc = DATEADD(HOUR, 24, SYSUTCDATETIME()), ReleaseScope = N'run' WHERE RunId = @RunId AND (@Connector = N'' OR Connector = @Connector) AND State = N'held' AND ExpiresUtc > SYSUTCDATETIME(); SELECT @@ROWCOUNT AS Released;" }
        'SetState' { "UPDATE cfg.GuardRelease SET State = @State, AppliedUtc = SYSUTCDATETIME(), AppliedRunId = @AppliedRunId, AppliedText = LEFT(@Text, 1000) WHERE ReleaseId = @ReleaseId AND State = N'released';" }
        # #448 (operator 2026-10-09: "noone can use the system due to these blockings"): ONLY CURRENT HOLDS. A newer run of
        # the same check decided again under today's rules, so the older HELD sets of that check and connector are closed
        # (state expired, the reason in AppliedText) -- by key (a collection: every candidate at or before the newest
        # loaded collection) or by time (a connector run: every set held before this run's own, or before now). A set a
        # SuperAdmin already released is left to its run. Answers the closed rows (for the audit trail).
        'Supersede' { @'
DECLARE @t datetime2(7) = (SELECT MAX(HeldUtc) FROM cfg.GuardRelease WHERE Connector = @Connector AND RunId = @RunId);
IF @t IS NULL SET @t = SYSUTCDATETIME();
UPDATE cfg.GuardRelease SET State = N'expired', AppliedUtc = SYSUTCDATETIME(), AppliedRunId = @RunId, AppliedText = LEFT(@Text, 1000)
OUTPUT deleted.ReleaseId AS ReleaseId, deleted.RunId AS RunId, deleted.HeldCount AS HeldCount
WHERE Connector = @Connector AND GuardId = @GuardId AND State = N'held'
  AND ((@ByKey = 1 AND RunId <= @RunId) OR (@ByKey = 0 AND RunId <> @RunId AND HeldUtc <= @t));
'@ }
        # GUARD-1.6 (#404): a release ENDS BY ITSELF -- its time ran out before a run applied it, or the held plan is no longer
        # the one that was released (a changed plan needs a new release): the set is held again (it can be released again
        # until the held set itself expires). Every apply path opens its candidates through 'Open', which runs this first.
        'Expire'   { @'
UPDATE cfg.GuardRelease SET State = N'expired' WHERE State IN (N'held', N'released') AND ExpiresUtc <= SYSUTCDATETIME();
IF COL_LENGTH(N'cfg.GuardRelease', N'CurrentPlanHash') IS NOT NULL
    EXEC (N'UPDATE cfg.GuardRelease SET State = N''held'', AppliedText = LEFT(CASE WHEN PlanHash IS NOT NULL AND PlanHash <> CurrentPlanHash THEN N''the held plan changed after it was released -- a changed plan needs a new release'' ELSE N''the release ended before a run applied it -- release it again if it should still go through'' END, 1000) WHERE State = N''released'' AND ((ReleaseUntilUtc IS NOT NULL AND ReleaseUntilUtc <= SYSUTCDATETIME()) OR (PlanHash IS NOT NULL AND PlanHash <> CurrentPlanHash));');
'@ }
    }
}

function ConvertTo-SIVulnHeldSet {
    <#
        PURE. The held closes of one halted run -> the release candidate: the finding ids (SysId, asset id, asset name, CVE,
        the reason it would have closed with) and the counts a person decides on -- per asset and per CVE, largest first.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records, [Parameter(Mandatory)][string]$Connector, [string]$ConnectorKind = '',
          [Parameter(Mandatory)][string]$RunId, [string]$GuardId = 'vuln.connector.close-ceiling', [int]$Top = 50)
    $v = { param($o, [string]$n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $items = @($Records | Where-Object { $_ } | ForEach-Object {
        [pscustomobject]@{ SysId = [string](& $v $_ 'SysId'); CorrelationId = [string](& $v $_ 'CorrelationId'); AssetName = [string](& $v $_ 'AssetName')
                           Cve = [string](& $v $_ 'Cve'); Reason = [string](& $v $_ 'CloseReason') } })
    $byAsset = @($items | Group-Object { if ($_.AssetName) { $_.AssetName } else { $_.CorrelationId } } | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } })
    $byCve = @($items | Group-Object Cve | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } })
    $assets = @($items | ForEach-Object { $_.CorrelationId } | Select-Object -Unique).Count
    $cves = @($items | ForEach-Object { $_.Cve } | Select-Object -Unique).Count
    [pscustomobject]@{
        GuardId = $GuardId; Connector = $Connector; ConnectorKind = $ConnectorKind; RunId = $RunId; HeldCount = $items.Count; Items = $items
        ItemsJson = (ConvertTo-Json -InputObject @($items) -Compress -Depth 3)
        SummaryJson = (ConvertTo-Json -InputObject ([pscustomobject]@{ Assets = $assets; Cves = $cves; ByAsset = $byAsset; ByCve = $byCve }) -Compress -Depth 4)
    }
}

function New-SIVulnReleaseStore {
    <#
        Where release candidates live: -Invoke (the Pro database's (sql, params, mode) seam -- cfg.GuardRelease) or -Folder
        (one JSON file per connector and run, for an install without a Pro database). Methods:
          Save(set)                       store a held set (once per connector and run)
          Open(connector)                 its held / released, unexpired candidates (expired ones are marked expired first)
          Approve(runId, connector, by)   held -> released; answers how many
          Finish(release, state, runId, text)   released -> applied
    #>
    param([scriptblock]$Invoke, [string]$Folder)
    if (-not $Invoke -and -not $Folder) { return $null }
    $s = [pscustomobject]@{ Invoke = $Invoke; Folder = $Folder; Days = $script:SIVulnReleaseDays; HasTable = $null }
    $s | Add-Member -MemberType ScriptMethod -Name Ready -Value {
        if ($this.Folder) { if (-not (Test-Path -LiteralPath $this.Folder)) { New-Item -ItemType Directory -Path $this.Folder -Force | Out-Null }; return $true }
        if ($null -eq $this.HasTable) {
            $r = @(& $this.Invoke (Get-SIVulnReleaseSql 'Exists') @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
            $h = if ($r -is [System.Collections.IDictionary]) { $r['HasTable'] } elseif ($r) { $r.HasTable } else { 0 }
            $this.HasTable = ([int]$h -eq 1)
        }
        $this.HasTable
    }
    $s | Add-Member -MemberType ScriptMethod -Name FileOf -Value { param([string]$connector, [string]$runId) [System.IO.Path]::Combine($this.Folder, ('{0}--{1}.json' -f ($connector -replace '[^A-Za-z0-9\-]', '_'), ($runId -replace '[^A-Za-z0-9\-]', '_'))) }
    $s | Add-Member -MemberType ScriptMethod -Name Save -Value {
        param($set)
        if (-not $this.Ready()) { return 'the Pro database has no cfg.GuardRelease yet -- apply sql\si-pro-settings.sql (it only adds)' }
        if ($this.Folder) {
            $f = $this.FileOf($set.Connector, $set.RunId)
            if (Test-Path -LiteralPath $f) { return '' }
            $doc = [pscustomobject]@{ ReleaseId = $f; GuardId = $set.GuardId; Connector = $set.Connector; ConnectorKind = $set.ConnectorKind; RunId = $set.RunId
                                      HeldUtc = [datetime]::UtcNow.ToString('o'); ExpiresUtc = [datetime]::UtcNow.AddDays($this.Days).ToString('o'); HeldCount = $set.HeldCount
                                      SummaryJson = $set.SummaryJson; ItemsJson = $set.ItemsJson; State = 'held'; ReleasedBy = ''; ReleasedUtc = ''; AppliedText = '' }
            [System.IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
            return ''
        }
        & $this.Invoke (Get-SIVulnReleaseSql 'Insert') ([ordered]@{ GuardId = $set.GuardId; Connector = $set.Connector; ConnectorKind = $set.ConnectorKind; RunId = $set.RunId
                                                                    Days = [int]$this.Days; HeldCount = [int]$set.HeldCount; SummaryJson = $set.SummaryJson; ItemsJson = $set.ItemsJson }) 'nonquery'
        ''
    }
    $s | Add-Member -MemberType ScriptMethod -Name ReadFile -Value { param([string]$f) [System.IO.File]::ReadAllText($f).TrimStart([char]0xFEFF) | ConvertFrom-Json }
    $s | Add-Member -MemberType ScriptMethod -Name WriteFile -Value { param([string]$f, $doc) [System.IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $doc -Depth 4), (New-Object System.Text.UTF8Encoding($false))) }
    $s | Add-Member -MemberType ScriptMethod -Name Open -Value {
        param([string]$connector)
        if (-not $this.Ready()) { return @() }
        if ($this.Folder) {
            $out = New-Object System.Collections.ArrayList
            foreach ($fi in @(Get-ChildItem -LiteralPath $this.Folder -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
                $d = $this.ReadFile($fi.FullName)
                if ([string]$d.Connector -ne $connector -or [string]$d.State -notin 'held', 'released') { continue }
                if ([datetime]::Parse([string]$d.ExpiresUtc, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() -le [datetime]::UtcNow) { $d.State = 'expired'; $this.WriteFile($fi.FullName, $d); continue }
                [void]$out.Add($d)
            }
            return , $out.ToArray()
        }
        & $this.Invoke (Get-SIVulnReleaseSql 'Expire') @{} 'nonquery'
        , @(& $this.Invoke (Get-SIVulnReleaseSql 'Open') ([ordered]@{ Connector = $connector }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } })
    }
    $s | Add-Member -MemberType ScriptMethod -Name Approve -Value {
        param([string]$runId, [string]$connector, [string]$by)
        if (-not $this.Ready()) { return 0 }
        if ($this.Folder) {
            $n = 0
            foreach ($fi in @(Get-ChildItem -LiteralPath $this.Folder -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
                $d = $this.ReadFile($fi.FullName)
                if ([string]$d.RunId -ne $runId -or [string]$d.State -ne 'held' -or ($connector -and [string]$d.Connector -ne $connector)) { continue }
                if ([datetime]::Parse([string]$d.ExpiresUtc, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() -le [datetime]::UtcNow) { continue }
                $d.State = 'released'; $d.ReleasedBy = $by; $d.ReleasedUtc = [datetime]::UtcNow.ToString('o'); $this.WriteFile($fi.FullName, $d); $n++
            }
            return $n
        }
        $r = @(& $this.Invoke (Get-SIVulnReleaseSql 'Approve') ([ordered]@{ RunId = $runId; Connector = [string]$connector; By = $by }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        [int]$(if ($r -is [System.Collections.IDictionary]) { $r['Released'] } elseif ($r) { $r.Released } else { 0 })
    }
    $s | Add-Member -MemberType ScriptMethod -Name Finish -Value {
        param($release, [string]$state, [string]$runId, [string]$text)
        if ($this.Folder) { $f = [string]$release.ReleaseId; $d = $this.ReadFile($f); $d.State = $state; $d.AppliedText = $text; $this.WriteFile($f, $d); return }
        & $this.Invoke (Get-SIVulnReleaseSql 'SetState') ([ordered]@{ State = $state; AppliedRunId = $runId; Text = $text; ReleaseId = [long]$release.ReleaseId }) 'nonquery'
    }
    # #448: ONLY CURRENT HOLDS -- the older held sets of one check and connector are closed (Get-SIVulnReleaseSql 'Supersede'),
    # each on the audit trail as guard.release.supersede (actor: the job). -byKey: a collection key (every candidate at or
    # before it); otherwise by time (held before -runId's own set, or before now). Answers the closed sets. Never throws
    # for the audit; a failed close throws to the caller (which says so and goes on).
    $s | Add-Member -MemberType ScriptMethod -Name Supersede -Value {
        param([string]$connector, [string]$guardId, [string]$runId, [bool]$byKey, [string]$text, [string]$job)
        if (-not $this.Ready()) { return , @() }
        $closed = New-Object System.Collections.Generic.List[object]
        if ($this.Folder) {
            $mine = @(Get-ChildItem -LiteralPath $this.Folder -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ File = $_.FullName; Doc = $this.ReadFile($_.FullName) } })
            $own = @($mine | Where-Object { [string]$_.Doc.Connector -eq $connector -and [string]$_.Doc.RunId -eq $runId }) | Select-Object -First 1
            $t = if ($own) { [datetime]::Parse([string]$own.Doc.HeldUtc, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() } else { [datetime]::UtcNow }
            foreach ($m in $mine) {
                $d = $m.Doc
                if ([string]$d.Connector -ne $connector -or [string]$d.GuardId -ne $guardId -or [string]$d.State -ne 'held') { continue }
                $older = if ($byKey) { [string]::CompareOrdinal([string]$d.RunId, $runId) -le 0 }
                         else { [string]$d.RunId -ne $runId -and [datetime]::Parse([string]$d.HeldUtc, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() -le $t }
                if (-not $older) { continue }
                $d.State = 'expired'; $d.AppliedText = $text; $this.WriteFile($m.File, $d)
                $closed.Add([pscustomobject]@{ ReleaseId = $m.File; RunId = [string]$d.RunId; HeldCount = $d.HeldCount })
            }
            return , $closed.ToArray()
        }
        $rows = & $this.Invoke (Get-SIVulnReleaseSql 'Supersede') ([ordered]@{ Connector = $connector; GuardId = $guardId; RunId = $runId; ByKey = [int][bool]$byKey; Text = $text }) 'reader'
        foreach ($r in @($rows)) {
            if ($null -eq $r) { continue }
            $g = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
            $closed.Add([pscustomobject]@{ ReleaseId = (& $g 'ReleaseId'); RunId = [string](& $g 'RunId'); HeldCount = (& $g 'HeldCount') })
        }
        if ($closed.Count -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
            $actor = if (Get-Command -Name Get-SIAuditActor -ErrorAction SilentlyContinue) { Get-SIAuditActor -Job $job } else { $job }
            foreach ($c in $closed) {
                try {
                    [void](Write-SIAuditEvent -Invoke $this.Invoke -Action 'guard.release.supersede' -Actor $actor -ActorSource 'job' -Target ('release/' + $c.RunId) -Outcome 'ok' -OutcomeText $text `
                        -After ([ordered]@{ Guard = $guardId; Connector = $connector; Held = $c.HeldCount; DecidedBy = $runId }) -Log { param($l, $m) })
                } catch { }
            }
        }
        , $closed.ToArray()
    }
    $s
}

function Get-SIVulnReleasedSysIds {
    <# PURE. The SysIds of the RELEASED candidates (state 'released'), as a list; held ones are not released yet. #>
    param([AllowEmptyCollection()][object[]]$Releases = @())
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Releases | Where-Object { $_ -and [string]$_.State -eq 'released' })) {
        $items = [string]$r.ItemsJson
        if (-not $items) { continue }
        # PS 5.1: ConvertFrom-Json hands a JSON array over as ONE object -- assign first, then enumerate
        $arr = ConvertFrom-Json -InputObject $items
        foreach ($i in $arr) { if ($i -and $i.SysId -and -not $ids.Contains([string]$i.SysId)) { $ids.Add([string]$i.SysId) } }
    }
    $ids.ToArray()
}

function Get-SIVulnReleaseOutcome {
    <#
        PURE. What one released set did in this run: closed (released and closing now), came back (released, but SI reports
        the finding again -- not closed), not closing (released, neither: already closed, or no longer qualifying).
    #>
    param([Parameter(Mandatory)]$Release, [Parameter(Mandatory)]$Plan)
    $ids = @(Get-SIVulnReleasedSysIds -Releases @($Release))
    $val = { param($o, [string]$n) if ($o -is [System.Collections.IDictionary]) { [string]$o[$n] } elseif ($o -and $o.PSObject.Properties[$n]) { [string]$o.$n } else { '' } }
    $closing = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($c in @($Plan.ToClose)) { [void]$closing.Add((& $val $c 'SysId')) }
    $back = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($u in @($Plan.ToUpdate) + @($Plan.ToReopen)) { if ($u) { [void]$back.Add((& $val $u.Actual 'SysId')) } }
    $n = @{ Closed = 0; CameBack = 0; NotClosing = 0 }
    foreach ($i in $ids) { if ($closing.Contains($i)) { $n.Closed++ } elseif ($back.Contains($i)) { $n.CameBack++ } else { $n.NotClosing++ } }
    [pscustomobject]@{ Released = $ids.Count; Closed = $n.Closed; CameBack = $n.CameBack; NotClosing = $n.NotClosing
                       Text = ('released {0}: closed {1}; {2} came back and stay open; {3} not closing (already closed or no longer absent long enough)' -f $ids.Count, $n.Closed, $n.CameBack, $n.NotClosing) }
}
