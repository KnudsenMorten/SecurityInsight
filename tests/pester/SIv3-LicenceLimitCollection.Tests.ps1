#Requires -Version 5.1
<#
    #474 -- A PRO BUSINESS LICENCE'S DEVICE LIMIT IS ENFORCED AT COLLECTION, AS A WARNING (framework 12.6).
    What these tests keep true:
      * the endpoint collection counts the devices it discovered against the signed `devices` limit;
      * from 90 % it warns, above the limit it says how many devices are above it, above the limit + 10 % it is the alarm --
        the same thresholds as the web app's banner;
      * every device is still collected: the message says nothing is left out, the check never throws and never stops a run;
      * Pro Enterprise (no limits), Community and an invalid licence: nothing is checked;
      * WIRING: Invoke-SIEngineRun runs the check right after Discover for the endpoint engine and puts the message on the
        END record when the limit is reached, without changing the run's outcome.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\SI-FeatureCatalog.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceLimit.ps1')
    function script:Lic([string]$Sku = 'Pro-Business', [string]$Status = 'Valid', $Limits = ([ordered]@{ devices = 250 })) {
        [pscustomobject]@{ Status = $Status; Sku = $Sku; Limits = $Limits; Features = @('*'); TenantIds = @() }
    }
}

Describe '#474 the device limit, in plain words' {
    It 'under 90 %: ok, no warning words' {
        $s = Get-SILicenceLimitState -Limit 250 -Devices 200
        $s.State | Should -Be 'ok'
        $s.Message | Should -Match 'covers 250 devices; this run found 200'
    }
    It 'from 90 %: near -- says how many are left and that nothing is stopped' {
        $s = Get-SILicenceLimitState -Limit 250 -Devices 225
        $s.State | Should -Be 'near'
        $s.Message | Should -Match '90 % of the limit, 25 left'
        $s.Message | Should -Match 'Nothing is stopped'
    }
    It 'above the limit: over -- how many above, every device collected, what to do' {
        $s = Get-SILicenceLimitState -Limit 250 -Devices 251
        $s.State | Should -Be 'over'
        $s.Message | Should -Match '1 above the limit'
        $s.Message | Should -Match 'All 251 were collected -- nothing is left out'
        $s.Message | Should -Match 'ask Invardia for a higher limit or for Pro Enterprise'
    }
    It 'above the limit + 10 %: alarm' {
        (Get-SILicenceLimitState -Limit 250 -Devices 276).State | Should -Be 'alarm'
        (Get-SILicenceLimitState -Limit 250 -Devices 275).State | Should -Be 'over'
    }
    It 'no limit: none' {
        (Get-SILicenceLimitState -Limit $null -Devices 9999).State | Should -Be 'none'
    }
}

Describe '#474 which licence has a device limit' {
    It 'a valid Pro Business licence: its signed devices limit' { Get-SILicenceDeviceLimit -License (Lic) | Should -Be 250 }
    It 'Pro Enterprise (no limits), a Community sku, an expired licence, no licence: none' {
        Get-SILicenceDeviceLimit -License (Lic -Limits $null) | Should -BeNullOrEmpty
        Get-SILicenceDeviceLimit -License (Lic -Sku 'Community') | Should -BeNullOrEmpty
        Get-SILicenceDeviceLimit -License (Lic -Status 'Expired') | Should -BeNullOrEmpty
        Get-SILicenceDeviceLimit -License $null | Should -BeNullOrEmpty
    }
    It 'Business without a device limit (another product''s limit only): none' {
        Get-SILicenceDeviceLimit -License (Lic -Limits ([ordered]@{ admins = 5 })) | Should -BeNullOrEmpty
    }
}

Describe '#474 the check at collection never stops anything' {
    AfterEach { $global:SI_LicenceUsage = $null }
    It 'endpoint over the limit: ONE warning, the usage is kept for reporting' {
        $log = New-Object System.Collections.Generic.List[object]
        $s = Invoke-SILicenceLimitCheck -Engine 'endpoint' -DeviceCount 300 -License (Lic) -Log { param($l, $m) $log.Add(@($l, $m)) }.GetNewClosure()
        $s.State | Should -Be 'alarm'
        $log.Count | Should -Be 1
        $log[0][0] | Should -Be 'WARN'
        $log[0][1] | Should -Match '50 above the limit'
        $global:SI_LicenceUsage.Devices | Should -Be 300
        $global:SI_LicenceUsage.Limit | Should -Be 250
    }
    It 'another engine, Enterprise, or an unknown count: nothing checked, nothing said' {
        $log = New-Object System.Collections.Generic.List[object]
        $sb = { param($l, $m) $log.Add($m) }.GetNewClosure()
        Invoke-SILicenceLimitCheck -Engine 'identity' -DeviceCount 300 -License (Lic) -Log $sb | Should -BeNullOrEmpty
        Invoke-SILicenceLimitCheck -Engine 'endpoint' -DeviceCount 300 -License (Lic -Limits $null) -Log $sb | Should -BeNullOrEmpty
        Invoke-SILicenceLimitCheck -Engine 'endpoint' -DeviceCount -1 -License (Lic) -Log $sb | Should -BeNullOrEmpty
        $log.Count | Should -Be 0
    }
    It 'a broken licence object never throws' {
        { Invoke-SILicenceLimitCheck -Engine 'endpoint' -DeviceCount 10 -License ([pscustomobject]@{ Status = 'Valid'; Sku = 'Pro'; Limits = 'garbage' }) -Log { } 3>$null } | Should -Not -Throw
    }
    It 'the module has no throw and no exit (a limit is never a stop)' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceLimit.ps1')
        $src | Should -Not -Match '(?m)^\s*throw\b'
        $src | Should -Not -Match '(?m)^\s*exit\b'
    }
}

Describe 'WIRING' {
    It 'Invoke-SIEngineRun checks right after Discover for the endpoint engine and puts the message on the END record' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $disc = $src.IndexOf('$assetCount = [int]$result.AssetCount')
        $chk = $src.IndexOf('Invoke-SILicenceLimitCheck -Engine $Engine -DeviceCount $assetCount')
        $disc | Should -BeGreaterThan 0
        $chk | Should -BeGreaterThan $disc
        $src | Should -Match ([regex]::Escape("_shared/SI-LicenceLimit.ps1"))
        $note = $src.IndexOf('[string]$global:SI_LicenceLimitNote) | Where-Object')
        $note | Should -BeGreaterThan $src.IndexOf('$exitErrorMsg = $__outcome.Message')
        $note | Should -BeLessThan $src.IndexOf('-Phase ''End''')
    }
}
