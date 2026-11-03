#Requires -Version 5.1
<#
    SecurityInsight Pro -- INFRASTRUCTURE FIRST, THEN THE LICENCE (framework INSTALL-1, owner 2026-11-02: "pro installs from
    invardia, option 1"). A Pro install without a licence deploys the whole environment and runs NOTHING: every scheduled
    job is parked (triggerType Manual, its schedule remembered). The licence then arrives the existing way (Invardia DESIGN
    §6): the updater knocks, the owner approves, the updater pulls it and claims its install key -- and the jobs the
    install parked are switched back on.

      Get-SIAssignedLicence      "has a licence been assigned?": SI-License is in the install's Key Vault, written by the
                                 updater's existing licence request (knock, owner approval, pull).
      ConvertTo-SIAwaitLicenceJobPatch / ConvertTo-SIResumeLicenceJobPatch
                                 PURE: the ARM PATCH bodies that park a scheduled job and switch it back. The schedule is
                                 remembered in the tag si-disabled-cron (the web app's own Disable / Enable use the same
                                 tag), and the tag si-awaits-licence marks the jobs the INSTALL parked -- only those are
                                 switched back: a job an administrator disabled stays disabled.
      Resume-SIAwaitingLicenceJobs
                                 switches the marked jobs back on (through -Patch). Never throws.

    Nothing here calls out on its own: every call goes through a script block the caller passes. PS 5.1 + 7. No modules.
#>

$script:SIAwaitLicenceTag   = 'si-awaits-licence'
$script:SIDisabledCronTag   = 'si-disabled-cron'
$script:SIAwaitLicenceText  = 'SecurityInsight Pro is installed and waits for its licence: nothing runs until the licence is approved; the updater asks Invardia for it, and once it arrives SecurityInsight starts by itself.'


function Get-SIAssignedLicence {
    <#
        Has a licence been assigned to this installation? THE ONE SEAM. Today (the existing design, Invardia DESIGN §6
        "Licence requests from the updater"): the updater knocks (POST /api/licence-requests), the owner approves, the updater
        pulls the signed licence into the install's Key Vault (SI-License) -- so "assigned" = SI-License is there.
        -ReadSecret { param($Name) <text or $null> }. Returns [pscustomobject]@{ Assigned; Reason }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$ReadSecret)
    $text = $null
    try { $text = & $ReadSecret 'SI-License' } catch { return [pscustomobject]@{ Assigned = $false; Reason = ('the licence could not be read ({0})' -f $_.Exception.Message) } }
    if ("$text".Trim()) { return [pscustomobject]@{ Assigned = $true; Reason = 'the licence is in the Key Vault' } }
    [pscustomobject]@{ Assigned = $false; Reason = 'no licence has been approved for this installation yet' }
}
function Get-SIAwaitLicenceJobProp {
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $o[$p]; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function ConvertTo-SIAwaitLicenceJobTags {
    param($Job)
    $h = [ordered]@{}
    $tags = Get-SIAwaitLicenceJobProp $Job @('tags')
    if ($tags -is [System.Collections.IDictionary]) { foreach ($k in $tags.Keys) { $h[[string]$k] = [string]$tags[$k] } }
    elseif ($tags) { foreach ($p in $tags.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
    $h
}

function ConvertTo-SIAwaitLicenceJobPatch {
    <#
        PURE. A job as ARM returns it -> the PATCH body that parks it until the licence: triggerType Manual, its cron in
        si-disabled-cron, the mark si-awaits-licence. $null when there is nothing to park (not a scheduled job).
    #>
    param([Parameter(Mandatory)]$Job)
    $cfg = Get-SIAwaitLicenceJobProp $Job @('properties', 'configuration')
    if ([string](Get-SIAwaitLicenceJobProp $cfg @('triggerType')) -ne 'Schedule') { return $null }
    $cron = [string](Get-SIAwaitLicenceJobProp $cfg @('scheduleTriggerConfig', 'cronExpression'))
    if (-not $cron.Trim()) { return $null }
    $tags = ConvertTo-SIAwaitLicenceJobTags $Job
    $tags[$script:SIDisabledCronTag] = $cron
    $tags[$script:SIAwaitLicenceTag] = '1'
    $timeout = Get-SIAwaitLicenceJobProp $cfg @('replicaTimeout'); if ($null -eq $timeout) { $timeout = 1800 }
    [ordered]@{ tags = $tags; properties = [ordered]@{ configuration = [ordered]@{
        triggerType = 'Manual'; replicaTimeout = [int]$timeout
        manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } } } }
}

function ConvertTo-SIResumeLicenceJobPatch {
    <#
        PURE. A job the install parked (marked si-awaits-licence, its cron in si-disabled-cron) -> the PATCH body that
        switches its schedule back on and removes both tags. $null for any other job (an administrator's Disable is kept).
    #>
    param([Parameter(Mandatory)]$Job)
    $tags = ConvertTo-SIAwaitLicenceJobTags $Job
    if ([string]$tags[$script:SIAwaitLicenceTag] -ne '1') { return $null }
    $cron = [string]$tags[$script:SIDisabledCronTag]
    if (-not $cron.Trim()) { return $null }
    $cfg = Get-SIAwaitLicenceJobProp $Job @('properties', 'configuration')
    $timeout = Get-SIAwaitLicenceJobProp $cfg @('replicaTimeout'); if ($null -eq $timeout) { $timeout = 1800 }
    $tags.Remove($script:SIAwaitLicenceTag); $tags.Remove($script:SIDisabledCronTag)
    [ordered]@{ tags = $tags; properties = [ordered]@{ configuration = [ordered]@{
        triggerType = 'Schedule'; replicaTimeout = [int]$timeout
        scheduleTriggerConfig = [ordered]@{ cronExpression = $cron; parallelism = 1; replicaCompletionCount = 1 } } } }
}

function Resume-SIAwaitingLicenceJobs {
    <#
        Switches every job the install parked back on. -Jobs: the resource group's jobs as ARM returns them; -Patch
        { param($Job, $Body) } sends one PATCH (returns $true when it was accepted). Returns the names switched back on.
        Never throws: a refused PATCH is left for the next run (the mark stays).
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), [Parameter(Mandatory)][scriptblock]$Patch, [scriptblock]$Log)
    $done = New-Object System.Collections.Generic.List[string]
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $body = ConvertTo-SIResumeLicenceJobPatch -Job $j
        if ($null -eq $body) { continue }
        $name = [string](Get-SIAwaitLicenceJobProp $j @('name'))
        $ok = $false
        try { $ok = [bool](& $Patch $j $body) } catch { $ok = $false; if ($Log) { & $Log ('{0}: not switched on now ({1}) -- the next run tries again' -f $name, $_.Exception.Message) } }
        if ($ok) { $done.Add($name) }
    }
    $done.ToArray()   # unrolled: callers take @( ... )
}
