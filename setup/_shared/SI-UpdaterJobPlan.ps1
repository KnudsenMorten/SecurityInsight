#Requires -Version 5.1
<#
    SecurityInsight -- what setup\Install-SIUpdaterJob.ps1 does to an EXISTING updater job (found live on internal ring 1,
    2026-10-10): re-running the setup for its role grants -- what the "needs customer action" text tells a customer to do --
    planned to point caj-si-updater at si-updater:v<VERSION> while the job ran the image it had rolled itself to
    (si-updater:v3.0.0.<stamp>-<commit>, tags si-updater-image / si-updater-previous). That would DOWNGRADE the updater.

      Resolve-SIUpdaterJobImage  an existing job keeps the image it runs (else its si-updater-image tag's); only an explicit
                                 -Image changes it; a new job gets the image this setup builds.
      Resolve-SIUpdaterJobSize   an existing job keeps its size when it is at least 4 CPU / 8 GiB, else it is raised to that
                                 floor -- never lowered.
    PURE. PS 5.1 safe.
#>

function Resolve-SIUpdaterJobImage {
    <#
        PURE. -Existing: the job as ARM returns it ($null = no job yet); -Default: the image this setup builds
        (<registry>/si-updater:v<VERSION>); -Explicit: an -Image the person passed (a full reference, or a tag / name:tag of
        si-updater in -LoginServer). Returns @{ Image; Build (this setup must build -Default); Source = explicit | job | tag |
        new; Why }.
    #>
    param($Existing, [Parameter(Mandatory)][string]$Default, [AllowEmptyString()][string]$Explicit, [AllowEmptyString()][string]$LoginServer)
    $mk = { param($img, $build, $src, $why) [pscustomobject]@{ Image = $img; Build = [bool]$build; Source = $src; Why = $why } }
    $e = "$Explicit".Trim()
    if ($e) {
        $img = if ($e -match '/') { $e } elseif ($e -match ':') { '{0}/{1}' -f $LoginServer, $e } else { '{0}/si-updater:{1}' -f $LoginServer, $e }
        return (& $mk $img ($img -eq $Default) 'explicit' ('the image you passed (-Image): {0}' -f $img))
    }
    if ($null -ne $Existing) {
        $cur = ''
        try { $cur = [string](@($Existing.properties.template.containers | Where-Object { $_ })[0].image) } catch { $cur = '' }
        if ($cur.Trim()) { return (& $mk $cur.Trim() $false 'job' ('the job keeps the image it runs: {0} (pass -Image to change it; the updater moves itself to the version your ring approves)' -f $cur.Trim())) }
        $tag = ''
        try { if ($Existing.tags -and $Existing.tags.PSObject.Properties['si-updater-image']) { $tag = [string]$Existing.tags.'si-updater-image' } } catch { $tag = '' }
        if ($tag.Trim()) { return (& $mk $tag.Trim() $false 'tag' ('the job keeps the image it last rolled to (tag si-updater-image): {0}' -f $tag.Trim())) }
    }
    & $mk $Default $true 'new' ('a new job: the image this setup builds, {0}' -f $Default)
}

function Resolve-SIUpdaterJobSize {
    <#
        PURE. The size an existing updater job gets: its own when it is at least -MinCpu / -MinMemoryGi (4 / 8 -- the registry
        build ran out of memory on 0.5 / 1), else raised to that floor (each value at least its floor; never lowered).
        Returns @{ Change; Cpu; Memory ('<n>Gi'); Why }.
    #>
    param($Existing, [double]$MinCpu = 4, [double]$MinMemoryGi = 8)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $c = $null; try { $c = @($Existing.properties.template.containers | Where-Object { $_ })[0] } catch { $c = $null }
    $cpu = 0.0; $mem = 0.0
    if ($c -and $c.resources) {
        try { $cpu = [double]::Parse([string]$c.resources.cpu, $inv) } catch { $cpu = 0.0 }
        $m = [regex]::Match([string]$c.resources.memory, '^\s*([0-9]+(?:\.[0-9]+)?)\s*Gi\s*$'); if ($m.Success) { $mem = [double]::Parse($m.Groups[1].Value, $inv) }
    }
    if ($cpu -ge $MinCpu -and $mem -ge $MinMemoryGi) { return [pscustomobject]@{ Change = $false; Cpu = ''; Memory = ''; Why = ('keeps its size: {0} CPU / {1}' -f $c.resources.cpu, $c.resources.memory) } }
    $nc = [Math]::Max($cpu, $MinCpu); $nm = [Math]::Max($mem, $MinMemoryGi)
    [pscustomobject]@{ Change = $true; Cpu = $nc.ToString('0.0#', $inv); Memory = ('{0}Gi' -f $nm.ToString($inv)); Why = ('raised to {0} CPU / {1}Gi (it had {2} / {3})' -f $nc.ToString('0.0#', $inv), $nm.ToString($inv), $(if ($c) { $c.resources.cpu } else { '?' }), $(if ($c) { $c.resources.memory } else { '?' })) }
}
