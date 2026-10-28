#Requires -Version 5.1
<#
    ASSET TAGGING WRITES TO MDE AND ENTRA -- NONE OF ITS FAILURES MAY BECOME A WRONG WRITE (#136).

      * a FAILED read of an identity's custom security attributes returned @(), and the PATCH then wrote
        "@() + the new tag" over the whole multi-value attribute -- erasing its existing tags (tier-0
        among them) on a transient error;
      * every launcher reset $global:WhatIfMode (and SuppressErrors/SuppressWarnings) from the CLI switch
        AFTER the config layers loaded, so a dry run set in config became LIVE writes;
      * the device-name-pattern filter matched EVERYTHING when no patterns were configured -- and its
        only user is the Auto-NamePattern--Excluded--SI rule, so enabling it early excluded the whole
        estate from Risk Analysis;
      * the Defender token was built once per run, so a long run hit 401 part-way.
    The engine is a script, so its functions are lifted by AST and run against mocks. No network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $engine = Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($engine, [ref]$null, [ref]$null)
    foreach ($name in 'Get-EntraCurrentCSATags','Test-DeviceNameMatchesConfigPatterns','Invoke-DefenderRest') {
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    # Stubs so the lifted functions' dependencies exist and can be mocked.
    function script:Invoke-ATGraphRequest { param($Method, $Uri, $Body) }
    function script:Get-DefenderAccessHeaders { @{ Authorization = 'Bearer FRESH' } }
    function script:Write-Info { param($m) }
    $script:DefenderLastCall   = [datetime]::MinValue
    $script:DefenderMinDelayMs = 0

    function script:New-HttpError([int]$Status) {
        $e = New-Object System.Exception ("HTTP $Status")
        $e | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $Status; Headers = @{} }) -Force
        $e
    }
}

Describe 'a failed CSA read never becomes an overwrite' {
    It 'a GET failure THROWS (it used to return @(), and the PATCH then erased every existing tag)' {
        Mock Invoke-ATGraphRequest { throw 'Forbidden (403)' }
        { Get-EntraCurrentCSATags -Endpoint 'users' -ObjectId 'u1' -AttributeSet 'SI' } | Should -Throw '*refusing to write over unknown tags*'
    }
    It 'an object with no CSA yet is still a genuine empty set' {
        Mock Invoke-ATGraphRequest { [pscustomobject]@{ customSecurityAttributes = $null } }
        @(Get-EntraCurrentCSATags -Endpoint 'users' -ObjectId 'u1' -AttributeSet 'SI').Count | Should -Be 0
    }
    It 'existing tags are read back' {
        Mock Invoke-ATGraphRequest { [pscustomobject]@{ customSecurityAttributes = [pscustomobject]@{ SI = [pscustomobject]@{ AssetTags = @('T0--tier0--SI','x') } } } }
        @(Get-EntraCurrentCSATags -Endpoint 'users' -ObjectId 'u1' -AttributeSet 'SI') | Should -Be @('T0--tier0--SI','x')
    }
}

Describe 'the name-pattern exclusion fails CLOSED' {
    It 'no patterns configured -> nothing matches (it matched EVERYTHING)' {
        $assetTaggingConfig = [pscustomobject]@{ DeviceNamePatterns = [pscustomobject]@{ StartsWith = @(); Contains = @(); MatchesRegex = @() } }
        Test-DeviceNameMatchesConfigPatterns -DeviceName 'prod-dc01' | Should -BeFalse
    }
    It 'a missing DeviceNamePatterns block -> nothing matches' {
        $assetTaggingConfig = [pscustomobject]@{ Other = 1 }
        Test-DeviceNameMatchesConfigPatterns -DeviceName 'prod-dc01' | Should -BeFalse
    }
    It 'a configured pattern still matches exactly what it names' {
        $assetTaggingConfig = [pscustomobject]@{ DeviceNamePatterns = [pscustomobject]@{ StartsWith = @('lab-'); Contains = @(); MatchesRegex = @() } }
        Test-DeviceNameMatchesConfigPatterns -DeviceName 'LAB-01'    | Should -BeTrue
        Test-DeviceNameMatchesConfigPatterns -DeviceName 'prod-dc01' | Should -BeFalse
    }
    It 'the rule loop skips an enabled name-pattern rule that has no patterns, and says so' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-tagging\AssetTagging.ps1') -Raw
        $src | Should -Match '(?s)if \(\$ruleApplyDeviceNamePatterns\) \{.{0,600}if \(\$npCount -eq 0\) \{.{0,400}tagging NOTHING.{0,300}continue'
    }
}

Describe 'the Defender token survives a long run' {
    It 'a 401 refreshes the token ONCE, retries, and the caller''s headers carry the new token' {
        $script:calls = 0
        Mock Invoke-RestMethod { $script:calls++; if ($script:calls -eq 1) { throw (New-HttpError 401) }; @{ ok = $true } }
        $h = @{ Authorization = 'Bearer OLD' }
        $script:DefenderHeadersAt = [datetime]::UtcNow
        $r = Invoke-DefenderRest -Method GET -Uri 'https://x/api/machines/1' -Headers $h -MaxAttempts 3
        $r.ok            | Should -BeTrue
        $script:calls    | Should -Be 2
        $h.Authorization | Should -Be 'Bearer FRESH'
    }
    It 'a second 401 is a real authorisation failure and is thrown' {
        Mock Invoke-RestMethod { throw (New-HttpError 401) }
        $script:DefenderHeadersAt = [datetime]::UtcNow
        { Invoke-DefenderRest -Method GET -Uri 'https://x' -Headers @{ Authorization = 'Bearer OLD' } -MaxAttempts 3 } | Should -Throw
    }
    It 'headers older than 45 minutes are refreshed BEFORE the call' {
        Mock Invoke-RestMethod { @{ ok = $true } }
        $h = @{ Authorization = 'Bearer OLD' }
        $script:DefenderHeadersAt = [datetime]::UtcNow.AddMinutes(-50)
        $null = Invoke-DefenderRest -Method GET -Uri 'https://x' -Headers $h -MaxAttempts 3
        $h.Authorization | Should -Be 'Bearer FRESH'
    }
}

Describe 'WIRING -- every launcher honours a config dry run' {
    It 'no launcher unconditionally resets WhatIfMode / SuppressErrors / SuppressWarnings from the CLI switch' {
        $bad = New-Object System.Collections.ArrayList
        foreach ($f in Get-ChildItem (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'launcher.*-vm.ps1') {
            $src = Get-Content -LiteralPath $f.FullName -Raw
            if ($src -match '(?m)^\s*\$global:(WhatIfMode|SuppressErrors|SuppressWarnings)\s*=\s*\[bool\]\$\1\s*$') { [void]$bad.Add($f.Name) }
            if ($src -notmatch "PSBoundParameters\.ContainsKey\('WhatIfMode'\)") { [void]$bad.Add("$($f.Name) (no bound-parameter check)") }
        }
        $bad.Count | Should -Be 0 -Because ($bad -join ', ')
    }
    It 'RA ResetCache set in config is not reset to the launcher default' {
        foreach ($f in Get-ChildItem (Join-Path $script:SIRoot 'launcher\risk-analysis') -Filter 'launcher.*-vm.ps1') {
            $src = Get-Content -LiteralPath $f.FullName -Raw
            $src | Should -Not -Match '(?m)^\s*\$global:ResetCache\s*=\s*\$ResetCache_Default\s*$' -Because $f.Name
            $src | Should -Match 'if \(-not \(Test-Path variable:global:ResetCache\)\)' -Because $f.Name
        }
    }
}
