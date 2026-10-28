#Requires -Version 7.0
<#
    A JOB IS NEVER READ OR WRITTEN WITH AN API VERSION THAT DROPS ITS QUEUE TRIGGER'S IDENTITY.

    Why: 2026-10-12, the collection workers of a new customer install never started. The jobs had been written with
    Microsoft.App api-version 2024-03-01, which does not know the queue scale rule's `identity` and drops it without a word
    (not returned on a GET, not stored on a PUT). Storage is identity-only, so the scaler could not read the queue. A job
    that is read and written back with that version loses the identity too.
    Offline: reads the source, and builds one scale rule.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Old = @('2022-03-01', '2022-10-01', '2023-05-01', '2023-08-01-preview', '2023-11-02-preview', '2024-02-02-preview', '2024-03-01', '2024-08-02-preview')
}

Describe 'Microsoft.App jobs and the API version' {
    It 'no setup, updater or pipeline file names a Microsoft.App version older than the one that keeps the trigger''s identity' {
        $bad = New-Object System.Collections.Generic.List[string]
        $files = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Include '*.ps1' | Where-Object { $_.FullName -notmatch '[\\/](tests|bin|obj|logs|output|staging)[\\/]' })
        foreach ($f in $files) {
            $n = 0
            foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
                $n++
                if ($line -match '^\s*#') { continue }
                foreach ($v in $script:Old) {
                    # the version as a quoted value on a line that is about jobs / container apps (other providers have their own versions)
                    if ($line -match ("'" + [regex]::Escape($v) + "'") -and $line -match '(?i)Microsoft\.App|AppArmApi|JobSizeArmApi|ArmApi\s*=|\$ApiVersion\s*=|\$existing\.id|/jobs|containerApps') {
                        $bad.Add(('{0}:{1}: {2}' -f $f.FullName.Substring($script:SIRoot.Length + 1), $n, $line.Trim()))
                    }
                }
            }
        }
        $bad.ToArray() | Should -BeNullOrEmpty -Because 'a job read or written with an older Microsoft.App version loses its queue scale rule identity -- the workers then never start'
    }
    It 'the version the setup writes jobs with is 2025-07-01' {
        $arm = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
        $arm | Should -Match "\`$script:SIAppArmApi\s+= '2025-07-01'"
    }
    It 'the queue scale rule the setup builds carries the identity' {
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupAzure.ps1'))
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
        . ([IO.Path]::Combine($script:SIRoot, 'container', '_shared', 'SI-ContainerConfig.ps1'))
        $id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-x'
        $rule = ConvertFrom-SIScaleRuleArgs -ScaleArgs @(Get-SIKedaQueueScaleArgs -Engine identity -StorageAccount 'stx' -IdentityResourceId $id)
        $rule.identity | Should -Be $id
        $rule.type | Should -Be 'azure-queue'
        $rule.metadata['queueName'] | Should -Be 'si-identity-shards'
    }
}
