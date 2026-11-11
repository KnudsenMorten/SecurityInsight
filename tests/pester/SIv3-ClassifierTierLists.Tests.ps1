#Requires -Version 5.1
<#
    THE CLASSIFIER'S TIER LISTS SAY ONE THING (engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1, $SystemPrompt).
    The owner delegated the Tier 0 / Tier 1 boundary to SI: consistency over day-to-day AI changes. The prompt's
    "Application Permissions (Graph / API)" lists are read from the script text (AST, never run) and checked:
    the named permissions sit in the named tier, and no permission is in two tier lists (a permission is keyed by its
    name plus app / delegated, so an app permission in Tier 2 and its self-scoped delegated form in Tier 3 are two keys).
    Offline, no network. PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $path = Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $asg = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left)" -eq '$SystemPrompt' }, $true) | Select-Object -First 1
    $script:Prompt = [string]$asg.Right.Expression.Value
    if (-not $script:Prompt) { $script:Prompt = [string]$asg.Right.Extent.Text }

    # the application-permission list of each tier: tier number -> list of @{ Key; Name; Text }
    $script:Lists = @{}
    $tier = -1
    foreach ($line in ($script:Prompt -split "`r?`n")) {
        $m = [regex]::Match($line, '^=== TIER (\d) ')
        if ($m.Success) { $tier = [int]$m.Groups[1].Value; continue }
        if ($line -match '^===') { $tier = -1; continue }
        if ($tier -ge 0 -and $line -match '^Application Permissions \(Graph / API\):\s*(.*)$') {
            $items = New-Object System.Collections.Generic.List[object]
            # split on top-level commas only (never inside a parenthesis)
            $depth = 0; $cur = ''
            foreach ($ch in $Matches[1].ToCharArray()) {
                if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')') { $depth-- }
                if ($ch -eq ',' -and $depth -eq 0) { $items.Add($cur.Trim()); $cur = '' } else { $cur += $ch }
            }
            if ($cur.Trim()) { $items.Add($cur.Trim()) }
            $script:Lists[$tier] = @($items | Where-Object { $_ } | ForEach-Object {
                $name = ($_ -replace '\s*\(.*$', '').Trim()
                $kind = $(if ($_ -match '\(delegated') { 'delegated' } else { 'app' })
                [pscustomobject]@{ Key = ('{0}|{1}' -f $name.ToLowerInvariant(), $kind); Name = $name; Text = $_ }
            })
        }
    }
    function script:Names([int]$Tier) { @($script:Lists[$Tier] | ForEach-Object { $_.Name }) }
}

Describe 'the classifier prompt''s tier lists' {
    It 'the prompt and all four application-permission lists are found' {
        $script:Prompt | Should -Match '=== TIER 0 - Immediate full environment compromise ==='
        foreach ($t in 0, 1, 2, 3) { @($script:Lists[$t]).Count | Should -BeGreaterThan 3 -Because "tier $t has an application-permission list" }
    }
    It 'Tier 0 adds Application.ReadWrite.All and PrivilegedAccess.ReadWrite.AzureADGroup and drops CrossTenantUserProfileSharing.ReadWrite.All' {
        $t0 = Names 0
        $t0 | Should -Contain 'Application.ReadWrite.All'
        $t0 | Should -Contain 'PrivilegedAccess.ReadWrite.AzureADGroup'
        foreach ($t in 0, 1, 2, 3) { Names $t | Should -Not -Contain 'CrossTenantUserProfileSharing.ReadWrite.All' }
    }
    It 'Organization.ReadWrite.All and Domain.ReadWrite.All are in Tier 0 only' {
        foreach ($p in 'Organization.ReadWrite.All', 'Domain.ReadWrite.All') {
            Names 0 | Should -Contain $p
            foreach ($t in 1, 2, 3) { Names $t | Should -Not -Contain $p }
        }
    }
    It 'Tier 1 adds the five owner-reviewed raises' {
        $t1 = Names 1
        foreach ($p in 'AppFederatedCredentialIssuers.ReadWrite.All', 'AppCertTrustConfiguration.ReadWrite.All', 'DeviceManagementCloudCA.ReadWrite.All', 'CrossTenantIdentityMapping.ReadWrite.All', 'Policy.ReadWrite.Recovery') {
            $t1 | Should -Contain $p
        }
        $t1 | Should -Not -Contain 'Application.ReadWrite.All'
    }
    It 'Mail.ReadWrite (app, all users) is in Tier 2 only, and the prompt says it is data plane' {
        foreach ($t in 0, 1) { Names $t | Should -Not -Contain 'Mail.ReadWrite' }
        $m = @($script:Lists[2] | Where-Object { $_.Name -eq 'Mail.ReadWrite' })
        $m.Count | Should -Be 1
        $m[0].Text | Should -Match 'data plane'
    }
    It 'no permission is in two tier lists' {
        $all = foreach ($t in 0, 1, 2, 3) { foreach ($i in @($script:Lists[$t])) { [pscustomobject]@{ Tier = $t; Key = $i.Key; Name = $i.Name } } }
        $dups = @($all | Group-Object Key | Where-Object { @($_.Group | Select-Object -ExpandProperty Tier -Unique).Count -gt 1 } |
            ForEach-Object { '{0} in tiers {1}' -f $_.Group[0].Name, ((@($_.Group | Select-Object -ExpandProperty Tier -Unique)) -join '+') })
        $dups | Should -BeNullOrEmpty
    }
}
