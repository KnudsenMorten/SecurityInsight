#Requires -Version 5.1
<#
    caj-si-updater -- the MANUAL-DEPLOY MARK (#350). A manual deploy (fast-deploy, a bootstrap) marks itself on the updater
    job (tag si-deploy-running); the updater never rolls the same jobs at the same time.

    (The ring channel this file used to hold -- channel.json in SI's own storage feed -- is RETIRED, 2026-10-06: Pro updates
    come only from Invardia's platform, the ring is decided by SecurityInsight when it releases, framework UPDATE-1.7.)
    PURE and PowerShell 5.1-compatible.
#>

function Test-SIUpdaterDeployLock {
    <#
      PURE. A manual deploy in progress marks itself on the updater job (tag si-deploy-running = "<UTC ISO time> <who>",
      removed when it ends). A mark younger than -MaxHours means: do not roll now (found live 2026-10-05: an updater roll and
      a manual deploy at the same minute fought over the same jobs). An older mark is a deploy that died -- ignored, said so.
      Returns @{ Locked; Reason }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value, [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxHours = 3)
    $v = "$Value".Trim()
    if (-not $v) { return [pscustomobject]@{ Locked = $false; Reason = '' } }
    $ts = ($v -split '\s+')[0]; $d = [datetime]::MinValue
    if (-not [datetime]::TryParse($ts, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
        return [pscustomobject]@{ Locked = $true; Reason = "a manual deploy is marked as running ('$v') -- the update waits for the next run" }
    }
    $age = $NowUtc.ToUniversalTime() - $d
    if ($age.TotalHours -lt $MaxHours) { return [pscustomobject]@{ Locked = $true; Reason = ("a manual deploy is running ({0}, {1:N0} min ago) -- the update waits for the next run" -f $v, $age.TotalMinutes) } }
    [pscustomobject]@{ Locked = $false; Reason = ("a manual deploy mark from {0} is older than {1} h -- ignored (that deploy did not finish cleanly)" -f $v, $MaxHours) }
}

