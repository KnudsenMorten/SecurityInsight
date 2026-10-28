#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- the verification service's run, behind seams (the reads, the database, the clock), so the
    whole run is tested on fixtures. The real reads are wired in ..\Invoke-SIVerification.ps1; the checks are in
    SI-Verification.ps1 and the store in SI-VerificationStore.ps1.

    -Sources: a hashtable of scriptblocks, each returning the rows of ONE source (a source that throws makes every check
    that needs it NOT CHECKED with the reason -- never 'no gaps'):
        Subscriptions, Pricings, Vms, Connectors      Azure Resource Graph
        Machines                                      Defender for Endpoint /api/machines
        Devices                                       Microsoft Graph /devices
        HuntingCount   param($table) -> row count     Advanced Hunting
        SignInCounts   -> hashtable table -> count    the security workspace (Log Analytics)
        RunHealth      -> the END rows of the window  SecurityInsight's workspace (SI_RunHealth_CL)
    A source left out = the check is not checked ('not configured').
#>

$script:SIVerifyNotInTenantPrefix = 'not in this tenant'

function Get-SIVerifyNotInTenantText {
    <#
        PURE. #876 (a first run on a bare tenant): when a source's failure says the PRODUCT it reads is not part of this
        tenant (no licence for it) -- Defender XDR's advanced hunting "Account is not provisioned", Defender for Endpoint's
        "tenant is not onboarded / not licensed" -- the line 'not in this tenant: <product> is not part of this tenant's
        licences'; '' for anything else (a permission refusal, a throttle, a timeout stay "could not be read").
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = [string]$Text
    $p = ''
    if ($t -match '(?i)Account is not provisioned|advanced hunting is not provisioned') { $p = 'Microsoft Defender XDR (advanced hunting)' }
    elseif ($t -match '(?i)tenant (?:is )?not (?:onboarded|provisioned)|not onboarded to (?:Microsoft )?Defender|\bInvalidLicense\b|\bMissingLicense\b|no valid licen[cs]e for (?:Microsoft )?Defender') { $p = 'Microsoft Defender for Endpoint' }
    if (-not $p) { return '' }
    ('{0}: {1} is not part of this tenant''s licences -- nothing to check here' -f $script:SIVerifyNotInTenantPrefix, $p)
}

function Invoke-SIVerificationChecks {
    <# Runs every check of the catalog over -Sources. Returns CheckId -> @{ Ran; Reason; Findings; Keep }. #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][hashtable]$Sources, [int]$StaleDays = 30, [datetime]$Now = [datetime]::UtcNow,
          [string]$WorkspaceName = 'the security workspace')
    $cache = @{}
    $get = {
        param([string]$name)
        if ($cache.ContainsKey($name)) { return $cache[$name] }
        $entry = $null
        if (-not $Sources.ContainsKey($name) -or $null -eq $Sources[$name]) { $entry = @{ Ok = $false; Rows = @(); Error = ('the source {0} is not configured' -f $name) } }
        else {
            try { $entry = @{ Ok = $true; Rows = @(& $Sources[$name] | Where-Object { $null -ne $_ }); Error = '' } }
            catch {
                # #876: a product the tenant does not have is "not in this tenant" (information), never "could not be read"
                $nit = Get-SIVerifyNotInTenantText -Text ('{0} {1}' -f $_.Exception.Message, $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' }))
                $entry = @{ Ok = $false; Rows = @(); Error = $(if ($nit) { $nit } else { ('{0} could not be read: {1}' -f $name, $_.Exception.Message) }) }
            }
        }
        $cache[$name] = $entry
        $entry
    }
    $heartbeat = 7
    if ($Catalog.defaults -and $Catalog.defaults.heartbeatDays) { $heartbeat = [int]$Catalog.defaults.heartbeatDays }
    $res = @{}
    $notRun = { param([string]$reason) @{ Ran = $false; Reason = $reason; Findings = @(); Keep = @() } }
    $ran = { param($findings, [string]$reason = '', $keep = @()) @{ Ran = $true; Reason = $reason; Findings = @($findings | Where-Object { $null -ne $_ }); Keep = @($keep | Where-Object { $_ }) } }
    foreach ($c in @($Catalog.checks | Where-Object { [string]$_.state -ne 'not_used' })) {
        $id = [string]$c.id
        try {
            switch ($id) {
                'defender-plan-off' {
                    $s = & $get 'Subscriptions'; $p = & $get 'Pricings'
                    if (-not $s.Ok) { $res[$id] = & $notRun $s.Error; break }
                    if (-not $p.Ok) { $res[$id] = & $notRun $p.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyDefenderPlans -Catalog $Catalog -Pricings $p.Rows -Subscriptions $s.Rows)
                }
                'vm-not-onboarded' {
                    $v = & $get 'Vms'; $m = & $get 'Machines'
                    if (-not $v.Ok) { $res[$id] = & $notRun $v.Error; break }
                    if (-not $m.Ok) { $res[$id] = & $notRun $m.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyVmOnboarding -Catalog $Catalog -Vms $v.Rows -Machines $m.Rows)
                }
                'device-not-onboarded' {
                    $d = & $get 'Devices'; $m = & $get 'Machines'
                    if (-not $d.Ok) { $res[$id] = & $notRun $d.Error; break }
                    if (-not $m.Ok) { $res[$id] = & $notRun $m.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyDeviceOnboarding -Catalog $Catalog -Devices $d.Rows -Machines $m.Rows -StaleDays $StaleDays -Now $Now)
                }
                'sensor-unhealthy' {
                    $m = & $get 'Machines'
                    if (-not $m.Ok) { $res[$id] = & $notRun $m.Error; break }
                    $res[$id] = & $ran (Test-SIVerifySensorHealth -Catalog $Catalog -Machines $m.Rows -StaleDays $StaleDays -HeartbeatDays $heartbeat -Now $Now)
                }
                'os-unsupported' {
                    $m = & $get 'Machines'
                    if (-not $m.Ok) { $res[$id] = & $notRun $m.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyUnsupportedOs -Catalog $Catalog -Machines $m.Rows -StaleDays $StaleDays -Now $Now)
                }
                'multicloud-connector-absent' {
                    $x = & $get 'Connectors'
                    if (-not $x.Ok) { $res[$id] = & $notRun $x.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyMulticloud -Catalog $Catalog -Connectors $x.Rows)
                }
                'hunting-table-empty' {
                    if (-not $Sources.ContainsKey('HuntingCount') -or $null -eq $Sources['HuntingCount']) { $res[$id] = & $notRun 'the source HuntingCount is not configured'; break }
                    $counts = @{}; $failed = New-Object System.Collections.Generic.List[string]; $huntAbsent = ''
                    foreach ($t in @($Catalog.huntingTables)) {
                        try { $n = & $Sources['HuntingCount'] ([string]$t); if ($null -eq $n) { $failed.Add([string]$t) } else { $counts[[string]$t] = [long]$n } }
                        catch {
                            $failed.Add([string]$t)
                            if (-not $huntAbsent) { $huntAbsent = Get-SIVerifyNotInTenantText -Text ('{0} {1}' -f $_.Exception.Message, $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' })) }
                        }
                    }
                    # #876: advanced hunting not provisioned (no Defender XDR) -- not in this tenant, said as information
                    if ($counts.Count -eq 0 -and $huntAbsent) { $res[$id] = & $notRun $huntAbsent; break }
                    if ($counts.Count -eq 0) { $res[$id] = & $notRun ('Advanced Hunting could not be read for {0}' -f ($failed -join ', ')); break }
                    $keep = @($failed | ForEach-Object { ('{0}|{1}' -f $id, $_).ToLowerInvariant() })
                    $reason = ''; if ($failed.Count) { $reason = 'not checked: ' + ($failed -join ', ') + ' (could not be read)' }
                    $res[$id] = & $ran (Test-SIVerifyHuntingTables -Catalog $Catalog -Counts $counts) $reason $keep
                }
                'signin-logs-missing' {
                    if (-not $Sources.ContainsKey('SignInCounts') -or $null -eq $Sources['SignInCounts']) { $res[$id] = & $notRun 'the source SignInCounts is not configured (SI_DefenderWorkspaceResourceId)'; break }
                    $counts = $null
                    try { $counts = & $Sources['SignInCounts'] } catch { $res[$id] = & $notRun ('the security workspace could not be read: {0}' -f $_.Exception.Message); break }
                    if (-not ($counts -is [hashtable])) { $res[$id] = & $notRun 'the security workspace returned no counts'; break }
                    $res[$id] = & $ran (Test-SIVerifySignInLogs -Catalog $Catalog -Counts $counts -WorkspaceName $WorkspaceName)
                }
                'collector-incomplete' {
                    $h = & $get 'RunHealth'
                    if (-not $h.Ok) { $res[$id] = & $notRun $h.Error; break }
                    $res[$id] = & $ran (Test-SIVerifyCollectors -Catalog $Catalog -RunHealth $h.Rows)
                }
                default { $res[$id] = & $notRun ('no evaluator for the check {0}' -f $id) }
            }
        } catch {
            $res[$id] = & $notRun ('the check failed: {0}' -f $_.Exception.Message)
        }
    }
    $res
}

function Get-SIVerificationControls {
    <#
        PURE. The hook for the setup telemetry's controls (framework §8.7, SI #491): one control per check --
        verification.<checkId>, state pass (no open gaps) | fail (open gaps) | unknown (not checked), with counts and no
        names of the customer's objects (telemetry carries counts, never scopes).
    #>
    param([AllowEmptyCollection()][object[]]$Summary = @())
    foreach ($s in $Summary) {
        $state = 'pass'
        if ($s.State -eq 'not-checked') { $state = 'unknown' } elseif ([int]$s.Open -gt 0) { $state = 'fail' }
        [pscustomobject][ordered]@{ ControlId = ('verification.' + $s.CheckId); State = $state; Open = [int]$s.Open; Ignored = [int]$s.Ignored; Accepted = [int]$s.Accepted; ReviewDue = [int]$s.ReviewDue }
    }
}

function Get-SIVerificationOutcome {
    <# PURE. The run's verdict for run health: success when every check ran; success-partial when one or more were not checked. #>
    param([AllowEmptyCollection()][object[]]$Summary = @())
    # #876: a check whose product is not in this tenant is information, not a gap in the run -- said, never partial
    $nit = @($Summary | Where-Object { $_.State -eq 'not-checked' -and ([string]$_.Reason).StartsWith($script:SIVerifyNotInTenantPrefix) })
    $nc = @($Summary | Where-Object { $_.State -eq 'not-checked' -and -not ([string]$_.Reason).StartsWith($script:SIVerifyNotInTenantPrefix) })
    $info = if ($nit.Count) { ('not in this tenant: ' + (@($nit | ForEach-Object { $_.CheckId }) -join ', ')) } else { '' }
    if ($nc.Count -eq 0) { return @{ Exit = 'success'; Message = $info } }
    @{ Exit = 'success-partial'; Message = ('not checked: ' + (@($nc | ForEach-Object { '{0} ({1})' -f $_.CheckId, $_.Reason }) -join '; ')) }
}

function Read-SIVerificationRows {
    <# The rows of a 'reader' call, one by one (the invoke returns them as ONE array object). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    $x = & $Invoke $Sql $Params 'reader'
    foreach ($r in @($x)) { if ($null -ne $r) { $r } }
}

function Invoke-SIVerificationCore {
    <#
        The whole run behind the seams: the checks, then -- unless -DryRun -- the run, results and summary in the Pro
        database (-Invoke). Never changes anything outside the Pro database. Returns @{ Results; Summary; Controls;
        Outcome; RunId; Written }.
    #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][hashtable]$Sources, [scriptblock]$Invoke, [int]$StaleDays = 30,
          [datetime]$Now = [datetime]::UtcNow, [string]$WorkspaceName = 'the security workspace', [switch]$DryRun,
          [scriptblock]$Log = { param($level, $msg) Write-Host ("[{0}] {1}" -f $level, $msg) })
    $results = Invoke-SIVerificationChecks -Catalog $Catalog -Sources $Sources -StaleDays $StaleDays -Now $Now -WorkspaceName $WorkspaceName
    foreach ($id in @($results.Keys | Sort-Object)) {
        $r = $results[$id]
        if (-not $r.Ran -and ([string]$r.Reason).StartsWith($script:SIVerifyNotInTenantPrefix)) { & $Log 'INFO' ('{0}: {1}' -f $id, $r.Reason) }
        elseif (-not $r.Ran) { & $Log 'WARN' ('{0}: NOT CHECKED -- {1}' -f $id, $r.Reason) }
        else { & $Log $(if (@($r.Findings).Count) { 'WARN' } else { 'OK' }) ('{0}: {1} gap(s){2}' -f $id, @($r.Findings).Count, $(if ($r.Reason) { ' -- ' + $r.Reason } else { '' })) }
    }
    $out = [ordered]@{ Results = $results; Summary = @(); Controls = @(); Outcome = $null; RunId = 0; Written = $false }
    $decisions = @{}
    $runId = 0
    $canWrite = $false
    if ($Invoke -and -not $DryRun) {
        $probe = @(Read-SIVerificationRows -Invoke $Invoke -Sql (Get-SIVerificationProbeSql)) | Select-Object -First 1
        $has = 0; if ($probe) { $has = [int](Get-SIVerifyValue $probe 'HasTables') }
        if ($has -ne 1) { & $Log 'WARN' 'The Pro database has no verification tables yet (apply sql\si-pro-settings.sql; it only adds) -- the results are not stored.' }
        else { $canWrite = $true }
    }
    if ($canWrite) {
        $runId = [long](& $Invoke (Get-SIVerificationRunStartSql) @{ CatalogVersion = [string]$Catalog.version } 'scalar')
        Write-SIVerificationResults -Invoke $Invoke -RunId $runId -Results $results
        $decisions = Get-SIVerificationDecisionState -Decisions @(Read-SIVerificationRows -Invoke $Invoke -Sql (Get-SIVerificationDecisionsSql)) -Now $Now
    }
    $summary = @(Get-SIVerificationSummary -Catalog $Catalog -Results $results -Decisions $decisions)
    $outcome = Get-SIVerificationOutcome -Summary $summary
    if ($canWrite) {
        $sj = ConvertTo-Json -InputObject @($summary) -Depth 4 -Compress
        if (-not $sj.StartsWith('[')) { $sj = '[' + $sj + ']' }
        [void](& $Invoke (Get-SIVerificationRunEndSql) @{ RunId = $runId; Outcome = [string]$outcome.Exit; SummaryJson = $sj } 'nonquery')
        $out.Written = $true
    }
    $out.Summary = $summary; $out.Controls = @(Get-SIVerificationControls -Summary $summary); $out.Outcome = $outcome; $out.RunId = $runId
    [pscustomobject]$out
}
