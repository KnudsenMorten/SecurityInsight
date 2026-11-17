#Requires -Version 7.0
<#
    THE TIERS OF ONE CODE TREE (the before / after proof of SIv3-SoftwareException.Tests.ps1, run in its own process so the two
    trees' functions never mix). Over a fixed set of CIs built from EVERY shipped endpoint hasSoftwareInstalled detection (one CI
    per software name the rules look for, with the rule's OS) plus named CIs (WordPress on two servers, a PAW, a domain
    controller, several wikis on one server, a CI without software):
      CI     the CI build's rule step (Invoke-SICiRules, every shipped endpoint rule + the operator tier tags, as the CI build
             converts them) -- one line per CI: 'C|<ci id>|<the whole CI after the rules, compact JSON>'
      P      the profiler (Invoke-SIRuleEval, every shipped endpoint rule on a Defender device carrying the same software) --
             one line per match: 'P|<device>|<rule>|<detection>|<tier>'
    -Exceptions: JSON rows of sidata.CiSoftwareException (CiId, RuleId, Vendor, Product, Reason, SetBy, SetAt) -- given only
    to a tree that knows them (this one); the CI's devices are 'dev-<ci id>'. Lines to -Out (UTF-8, no BOM, LF).
#>
param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Out, [string]$Exceptions = '')
$ErrorActionPreference = 'Stop'
function Write-SIInfo { param($m) }
function Write-SIWarn { param($m) }
if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }
$eng = Join-Path $Root 'engine'
. (Join-Path $eng 'data-model\SI-RecordCapture.ps1')
. (Join-Path $eng 'data-model\SI-CiEnrich.ps1')
. (Join-Path $eng 'data-model\SI-DataModelTemplates.ps1')
. (Join-Path $eng 'data-model\SI-CiBuildSql.ps1')
. (Join-Path $eng 'asset-profiling\shared\Get-SIRuleSet.ps1')
. (Join-Path $eng 'asset-profiling\shared\RuleEval.ps1')
. (Join-Path $eng 'asset-profiling\shared\RuleIndexes.ps1')

$model = Get-SIDataModel -Root (Join-Path $Root 'data-model')
$trust = Get-SICiTrustIndex $model['trust']
$ctx = @{ Lists = (Get-SIDataModelListContext $model); Now = [datetime]'2026-11-16T06:00:00Z' }
$all = Get-SIRuleSet -Engine endpoint 3>$null
$fb = Get-SIRuleSet -Engine endpoint -Fallback 3>$null
$ruleSet = @(@($all) + @($fb) | Where-Object { $_ })
if ($ruleSet.Count -lt 100) { throw "the shipped endpoint rules did not load ($($ruleSet.Count))" }
$ciRules = @(@((ConvertTo-SICiRules -RuleSet $ruleSet).Rules) + @(ConvertTo-SICiTagTierRules -TagPattern '(?i)tier[_-]?(?<tier>[0-3])(--SI)?'))
$byClass = Get-SICiRulesByClass -Rules $ciRules
$osMap = Get-SICiOsScopeMap

# ---- the CIs: one per software name a shipped detection looks for (the first pattern, '*' taken out), with its rule's OS ----
$cis = New-Object System.Collections.Generic.List[object]
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$i = 0
foreach ($r in @($all)) {
    $os = 'windows_server'
    $sc = @($r.osPlatformScope | Where-Object { $_ })
    if ($sc.Count -gt 0) { $k = ([string]$sc[0]).ToLowerInvariant(); if ($osMap.ContainsKey($k)) { $os = $osMap[$k][0] } }
    foreach ($d in @($r.Detections)) {
        foreach ($s in @(@($d.Detect.any) + @($d.Detect.all) | Where-Object { $_ })) {
            if ([string]$s.kind -ne 'hasSoftwareInstalled') { continue }
            $p = ([string]@($s.tvmSoftwareNames)[0]).ToLowerInvariant().Replace('*', '').Trim('/')
            if (-not $p) { continue }
            $sw = $p; if ($sw -notmatch '/') { $sw = 'vendor/' + $sw }
            if (-not $seen.Add($sw + '|' + $os)) { continue }
            $i++
            $cis.Add([ordered]@{ si_ci_id = ('ci-{0:d4}' -f $i); si_class = 'device'; si_os_platform = $os; si_asset_name = ('srv{0:d4}' -f $i); si_hostname = ('srv{0:d4}' -f $i)
                    si_installed_software = @($sw, 'microsoft/edge') })
        }
    }
}
$tag = { param($n) [ordered]@{ source = 'mde'; name = $n; value = '' } }
$cis.Add([ordered]@{ si_ci_id = 'ci-wp'; si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'web01'; si_hostname = 'web01'; si_installed_software = @('wordpress/wordpress', 'microsoft/edge', 'microsoft/sql_server_2019') })
$cis.Add([ordered]@{ si_ci_id = 'ci-wp2'; si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'web02'; si_hostname = 'web02'; si_installed_software = @('wordpress/wordpress', 'microsoft/edge') })
$cis.Add([ordered]@{ si_ci_id = 'ci-wiki'; si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'wiki1'; si_hostname = 'wiki1'; si_installed_software = @('mediawiki/mediawiki', 'wordpress/wordpress', 'atlassian/confluence_server') })
$cis.Add([ordered]@{ si_ci_id = 'ci-paw'; si_class = 'device'; si_os_platform = 'windows'; si_asset_name = 'paw-pxj70zk58z'; si_hostname = 'paw-pxj70zk58z'; si_tags = @((& $tag 'EmployeeWorkstations--tier3--SI'), (& $tag 'PAWDevices--tier0--SI')) })
$cis.Add([ordered]@{ si_ci_id = 'ci-dc8'; si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'dc8.contoso.local'; si_hostname = 'dc8'; si_tags = @((& $tag 'DomainControllerDNS--tier0--SI')); si_installed_software = @('microsoft/windows_server_2022') })
$cis.Add([ordered]@{ si_ci_id = 'ci-none'; si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'app9'; si_hostname = 'app9' })

$exRows = @()
if ($Exceptions) { $exRows = @([IO.File]::ReadAllText($Exceptions) | ConvertFrom-Json) }
$sb = New-Object System.Text.StringBuilder

# ---- the CI build's rule step ----
$p = @{ Rules = $ciRules; Trust = $trust; Context = $ctx; Now = $ctx.Now; RulesByClass = $byClass; FieldCache = @{} }
if ($Exceptions) { $p['SoftwareExceptions'] = ConvertTo-SICiSoftwareExceptionIndex -Rows $exRows }
foreach ($ci in $cis) {
    $null = Invoke-SICiRules -Ci $ci @p
    [void]$sb.Append('C|').Append($ci['si_ci_id']).Append('|').Append((ConvertTo-Json -InputObject $ci -Compress -Depth 12)).Append("`n")
}

# ---- the profiler: the same software on a Defender device per CI ----
$script:SIRuleIndexes = @{ tvmSoftware = @{}; groupMembers = @{}; parentChain = @{}; kustoSets = @{}; BuildStats = @{} }
foreach ($ci in $cis) { $script:SIRuleIndexes.tvmSoftware[('dev-' + $ci['si_ci_id'])] = @(@($ci['si_installed_software']) | Where-Object { $_ }) }
if ($Exceptions) {
    $devRows = @(foreach ($x in $exRows) { [pscustomobject]@{ DeviceId = ('dev-' + [string]$x.CiId); RuleId = $x.RuleId; Vendor = $x.Vendor; Product = $x.Product } })
    $script:SIRuleIndexes['softwareExceptions'] = ConvertTo-SIDeviceSoftwareExceptionIndex -Rows $devRows
}
$rules = @($all)
foreach ($ci in $cis) {
    $dev = 'dev-' + $ci['si_ci_id']
    $asset = [pscustomobject]@{ Name = [string]$ci['si_asset_name']; Metadata = @{ MDE_DeviceId = $dev; MDE_ComputerDnsName = [string]$ci['si_asset_name'] } }
    foreach ($r in $rules) {
        $hit = Invoke-SIRuleEval -Asset $asset -Rule $r
        if (-not $hit) { continue }
        $t = ''; if ($null -ne $hit.Set -and $null -ne $hit.Set.Tier) { $t = [string]$hit.Set.Tier }
        [void]$sb.Append(('P|{0}|{1}|{2}|{3}' -f $dev, $hit.RuleId, $hit.DetectionId, $t)).Append("`n")
    }
}
[IO.File]::WriteAllText($Out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("{0} CI(s), {1} line(s) written by {2}" -f $cis.Count, ($sb.ToString().Split("`n").Count - 1), $Root)
