#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE DATA-OUT HOLD of the data health model (CR2, REQUIREMENTS #656). ONE call for every writer
    that sends data out of SecurityInsight (the vulnerability connectors, the ServiceNow CMDB, the SQL CMDB hand-off, asset
    tagging, every data-out output):

        $h = Resolve-SIDataHealthHold -Channel '<connector name>'
        if ($h.Held) { <plan only: write nothing outside, say $h.Reason> }

    Held = the install's data health state is Unhealthy and no SuperAdmin let this channel through (Operations > Data
    health, with a reason, until the data is Healthy again). The state is read ONCE per process from the Pro database
    (cfg.DataHealthState + cfg.DataHealthOverride) and kept.
    NEVER THROWS. Not held when: there is no Pro database, the install has no data health tables yet (an older install),
    no cycle has run, or the state cannot be read -- the last two are said once (a hold is only for a real Unhealthy state;
    owner: "hold only on real failure").
#>

if (-not (Get-Command -Name Test-SIDataHealthChannelHeld -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-health', '_shared', 'SI-DataHealth.ps1'))
}
if (-not (Get-Command -Name Get-SIDataHealthStateSql -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-health', '_shared', 'SI-DataHealthStore.ps1'))
}

function Get-SIDataHealthHoldState {
    <#
        The state and the open overrides, read once per process ($global:SI_DataHealthHoldState). -Invoke: the Pro database
        (default: one built from SI_ProSqlServer / SI_ProSqlDatabase with the run's sign-in). -Refresh reads again.
        Returns @{ State; Overrides; Read (true when the database answered); Note }.
    #>
    param([scriptblock]$Invoke, [switch]$Refresh)
    if (-not $Refresh -and -not $Invoke -and $global:SI_DataHealthHoldState) { return $global:SI_DataHealthHoldState }
    $res = [pscustomobject]@{ State = $null; Overrides = @(); Read = $false; Note = '' }
    try {
        if (-not $Invoke) {
            $server = ''; $database = ''
            foreach ($pair in @(@('SI_ProSqlServer', 'SI_ProSqlDatabase'), @('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'))) {
                $s = "$(Get-Variable -Name $pair[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
                $d = "$(Get-Variable -Name $pair[1] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
                if ($s -and $d) { $server = $s; $database = $d; break }
            }
            if (-not ($server -and $database)) { $res.Note = 'no Pro database'; $global:SI_DataHealthHoldState = $res; return $res }
            if (-not (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue)) {
                . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'data-sql', 'SI-DataSql.ps1'))
            }
            $Invoke = New-SIDataSqlInvoke -Server $server -Database $database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
        }
        $st = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthStateSql)) | Select-Object -First 1
        $ov = @(Read-SIDataHealthRows -Invoke $Invoke -Sql (Get-SIDataHealthOverridesSql))
        $res.State = $st; $res.Overrides = $ov; $res.Read = $true
        if (-not $st) { $res.Note = 'no data health cycle has run yet' }
    } catch {
        $res.Note = ('the data health state could not be read ({0})' -f $_.Exception.Message)
    }
    $global:SI_DataHealthHoldState = $res
    $res
}

function Resolve-SIDataHealthHold {
    <#
        Is -Channel held now? Returns @{ Held; Overridden; State; Since; Reason; Channel }. -HoldState: a
        Get-SIDataHealthHoldState result (tests; default: read once per process). -Log { param($level, $message) } says a
        hold, an override, or why the state is not known (each once per channel).
    #>
    param([Parameter(Mandatory)][string]$Channel, $HoldState, [scriptblock]$Invoke, [scriptblock]$Log)
    $out = [pscustomobject]@{ Held = $false; Overridden = $false; State = 'Unknown'; Since = $null; Reason = ''; Channel = $Channel }
    try {
        if ($null -eq $HoldState) { $HoldState = Get-SIDataHealthHoldState -Invoke $Invoke }
        if (-not $HoldState.State) {
            if ($Log -and $HoldState.Note -and $HoldState.Note -ne 'no Pro database') { & $Log 'INFO' ('data health: {0} -- {1} is not held.' -f $HoldState.Note, $Channel) }
            return $out
        }
        $t = Test-SIDataHealthChannelHeld -State $HoldState.State -Overrides @($HoldState.Overrides) -Channel $Channel
        $out.Held = [bool]$t.Held; $out.Overridden = [bool]$t.Overridden; $out.State = [string]$t.State; $out.Since = $t.Since; $out.Reason = [string]$t.Reason
        if ($Log) {
            if ($t.Held) { & $Log 'WARN' ('HELD -- {0}. This run plans and reports only.' -f $t.Reason) }
            elseif ($t.Overridden) { & $Log 'WARN' ('data health is Unhealthy, but {0} was {1} -- it sends as usual.' -f $Channel, $t.Reason) }
        }
    } catch {
        if ($Log) { & $Log 'INFO' ('data health: the hold could not be decided ({0}) -- {1} is not held.' -f $_.Exception.Message, $Channel) }
    }
    $out
}
