#Requires -Version 5.1
<#
    RE-RUNNING SETUP UPGRADES AN EXISTING CONFIG -- NOTHING LOST, NOTHING REFUSED MID-WAY (#176).

    Before: the wizard threw "Refusing to overwrite" AFTER its SPN and infrastructure phases had run; unattended
    setup stopped, or with -ForceConfigOverwrite regenerated the file and dropped every hand-added setting; the CLI
    skipped the file (so no v3 setting ever arrived) or, with -Force, overwrote it with no backup. Now all three
    MERGE: every existing value stays byte-identical, only missing settings are appended, after a backup.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ConfigMerge.ps1')
    function script:New-TempFile([string]$Text) {
        $p = Join-Path ([IO.Path]::GetTempPath()) ('si176-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
        [IO.File]::WriteAllText($p, $Text, [Text.UTF8Encoding]::new($true)); $p
    }
    function script:Get-Code([string]$Rel) { ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
}

Describe 'Merge-SICustomConfig -- add what is missing, change nothing else' {
    It 'only settings the file does not assign are added; every existing byte is kept' {
        $existing = "# my notes`r`n`$global:SI_SPN_AppId = 'mine'`r`n`$global:SI_HandAdded = 42`r`n"
        $generated = "`$global:SI_SPN_AppId = 'generated'`r`n`$global:SI_AzSubscriptionId = 'sub-1'`r`n`$global:SI_DceResourceGroup = 'rg'`r`n"
        $m = Merge-SICustomConfig -Existing $existing -Generated $generated -Stamp '2026-09-30'
        @($m.Added) -join ',' | Should -Be 'SI_AzSubscriptionId,SI_DceResourceGroup'
        $m.Text.StartsWith($existing) | Should -BeTrue
        $m.Text | Should -Match "SI_SPN_AppId = 'mine'"
        $m.Text | Should -Not -Match "SI_SPN_AppId = 'generated'"
        $m.Text | Should -Match 'added by SecurityInsight setup -- settings this file did not have yet >>> \(2026-09-30\)'
    }
    It 'a second run adds nothing (idempotent)' {
        $m1 = Merge-SICustomConfig -Existing "`$global:A = 1`n" -Generated "`$global:A = 1`n`$global:B = 2`n"
        $m2 = Merge-SICustomConfig -Existing $m1.Text -Generated "`$global:A = 1`n`$global:B = 2`n"
        @($m2.Added).Count | Should -Be 0
        $m2.Text | Should -BeExactly $m1.Text
    }
    It 'a multi-line value is ONE statement -- never cut in half' {
        $generated = "`$global:SI_Sinks_Endpoint = @(`n    'LA',`n    'Excel'`n)`n`$global:SI_X = 1`n"
        $m = Merge-SICustomConfig -Existing "`$global:SI_X = 5`n" -Generated $generated
        @($m.Added) | Should -Be @('SI_Sinks_Endpoint')
        $m.Text | Should -Match "(?s)SI_Sinks_Endpoint = @\(\s*'LA',\s*'Excel'\s*\)"
        { [scriptblock]::Create($m.Text) } | Should -Not -Throw
    }
    It 'logic in the generated file (a Key Vault read block) is never merged in' {
        $generated = "`$global:SI_Y = 1`nif (-not `$global:SI_SPN_Secret) {`n    `$global:SI_SPN_Secret = Get-Secret`n}`n"
        $m = Merge-SICustomConfig -Existing "`$global:SI_Z = 1`n" -Generated $generated
        @($m.Added) | Should -Be @('SI_Y')
        $m.Text | Should -Not -Match 'Get-Secret'
    }
    It 'a config that does not parse is reported, never merged into' {
        { Merge-SICustomConfig -Existing "`$global:A = (`n" -Generated "`$global:B = 1`n" } | Should -Throw '*does not parse*'
    }
    It 'the merged file still loads, with the customer values and the added ones' {
        $m = Merge-SICustomConfig -Existing "`$global:SI_M1 = 'kept'`r`n" -Generated "`$global:SI_M1 = 'x'`r`n`$global:SI_M2 = 'new'`r`n"
        try {
            . ([scriptblock]::Create($m.Text))
            "$global:SI_M1|$global:SI_M2" | Should -Be 'kept|new'
        } finally { Remove-Variable SI_M1, SI_M2 -Scope Global -ErrorAction SilentlyContinue }
    }
}

Describe 'Update-SICustomConfigFile -- backup, BOM, and no rewrite when nothing is missing' {
    It 'backs up, writes UTF-8 with a BOM, keeps non-ASCII values' {
        $nonAscii = [string][char]0xE6 + [char]0xF8 + [char]0xE5
        $p = New-TempFile ("`$global:SI_Name = '" + $nonAscii + "'`r`n")
        try {
            $r = Update-SICustomConfigFile -Path $p -Generated "`$global:SI_New = 1`r`n"
            @($r.Added) | Should -Be @('SI_New')
            Test-Path -LiteralPath $r.Backup | Should -BeTrue
            $b = [IO.File]::ReadAllBytes($p); ($b[0], $b[1], $b[2]) -join ',' | Should -Be '239,187,191'
            [IO.File]::ReadAllText($p) | Should -Match $nonAscii
            (Update-SICustomConfigFile -Path $p -Generated "`$global:SI_New = 1`r`n").Backup | Should -BeNullOrEmpty
        } finally { Remove-Item -Path "$p*" -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'END TO END -- the wizard writer upgrades a real existing config with -Merge' {
    It 'the existing values stay, the settings it lacked are added, nothing throws' {
        $existing = "# hand-edited`r`n`$global:SI_SPN_TenantId = 'tenant-mine'`r`n`$global:SI_HandTuned = 7`r`n"
        $p = New-TempFile $existing
        try {
            $spn = [pscustomobject]@{ TenantId = 'tenant-generated'; AppId = 'app-1'; ObjectId = 'obj-1'; CredKind = 'Cert'; CertThumbprint = 'ABC'; KvName = $null }
            $infra = [pscustomobject]@{ SubscriptionId = 'sub-1'; ResourceGroupName = 'rg'; Location = 'westeurope'; WorkspaceName = 'ws'
                                        WorkspaceResourceId = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
                                        DceName = 'dce'; DceIngestionUri = 'https://dce'; DcrResourceGroupName = 'rg'; StorageAccountName = 'st'; StorageResourceGroupName = 'rg' }
            $out = & (Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Write-SICustomConfig.ps1') -OutputPath $p -Spn $spn -Infra $infra -Merge 6>$null
            $out.Merged | Should -BeTrue
            @($out.Added).Count | Should -BeGreaterThan 5
            $t = [IO.File]::ReadAllText($p)
            $t.StartsWith($existing) | Should -BeTrue
            $t | Should -Match "SI_SPN_TenantId = 'tenant-mine'"
            $t | Should -Not -Match "SI_SPN_TenantId = 'tenant-generated'"
            $t | Should -Match 'SI_WorkspaceResourceId'
        } finally { Remove-Item -Path "$p*" -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'WIRING -- every setup path merges an existing config' {
    It 'the wizard passes -Merge, and no longer throws after its SPN + infra phases' {
        Get-Code 'setup\ConfigWizard\Start-SetupWizard.ps1' | Should -Match '\$cfgArgs\.Merge = \$true'
    }
    It 'unattended setup merges by default; -ForceConfigOverwrite keeps its meaning' {
        Get-Code 'Setup-SecurityInsight-Unattended.ps1' | Should -Match 'if \(\$ForceConfigOverwrite\) \{ \$cfgArgs\.Force = \$true \} else \{ \$cfgArgs\.Merge = \$true \}'
    }
}
