#Requires -Version 5.1
<#
    Exclusion by '--Excluded--SI' tag: the flag, and the REASON that explains it.

    BACKGROUND. An operator tagged "lots of devices" in the Defender portal with '--Excluded--SI' and
    they kept appearing in reports. Cause: Test-SIEndpointExcludedByTag scanned the EG tag arrays but
    NOT MDE_MachineTags -- while the flat AssetTags column has always been built from MDE_MachineTags +
    EG_DeviceManualTags + EG_DeviceDynamicTags. So the tag was visible in the asset's own output and
    did nothing, which is the worst shape a control can have: it looks applied.

    The second half is ExcludedReason. Exclusion used to be invisible -- an excluded asset simply
    vanished from every report, which an operator cannot tell apart from collection being broken.
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-profiling\shared\Get-SIRiskFactors.ps1')
    function Rec { param([hashtable]$P) [pscustomobject]$P }
}

Describe 'which tag sources can exclude an asset' {

    It '🔴 MDE_MachineTags excludes -- the Defender-portal tag, and the source that was missed' {
        $r = Rec @{ MDE_MachineTags = @('Prod','Auto-CanBeOnboarded--Excluded--SI') }
        Test-SIEndpointExcludedByTag -Record $r | Should -BeTrue
        Get-SIEndpointExclusionReason -Record $r | Should -Match 'MDE_MachineTags'
    }

    It '<_> excludes' -ForEach @('EG_DeviceManualTags','EG_DeviceDynamicTags','EG_Tags','DeviceManualTags','DeviceDynamicTags','MachineTags') {
        $r = [pscustomobject]@{ $_ = @("x--Excluded--SI") }
        Test-SIEndpointExcludedByTag -Record $r | Should -BeTrue
    }

    It 'an untagged asset is not excluded and carries an EMPTY reason, not a placeholder' {
        # A non-empty default here would make every asset look deliberately excluded in the report.
        $r = Rec @{ MDE_MachineTags = @('Prod','Finance') }
        Test-SIEndpointExcludedByTag  -Record $r | Should -BeFalse
        Get-SIEndpointExclusionReason -Record $r | Should -BeExactly ''
    }

    It 'a record with no tag fields at all does not throw' {
        { Get-SIEndpointExclusionReason -Record (Rec @{ AssetName = 'srv1' }) } | Should -Not -Throw
    }
}

Describe 'tag shapes -- the sources genuinely arrive in three different forms' {

    It 'accepts a string array' {
        Get-SIEndpointExclusionReason -Record (Rec @{ MDE_MachineTags = @('a','b--Excluded--SI') }) | Should -Match 'Excluded--SI'
    }

    It 'accepts a semicolon-joined string' {
        Get-SIEndpointExclusionReason -Record (Rec @{ MDE_MachineTags = 'a;b--Excluded--SI;c' }) | Should -Match 'Excluded--SI'
    }

    It 'accepts a bare single string' {
        Get-SIEndpointExclusionReason -Record (Rec @{ MDE_MachineTags = 'only--Excluded--SI' }) | Should -Match 'Excluded--SI'
    }
}

Describe 'the reason names the tag AND its source' {

    It 'formats as "Field: tag" so an operator can find and remove it' {
        Get-SIEndpointExclusionReason -Record (Rec @{ MDE_MachineTags = @('Auto-InsufficientInfo--Excluded--SI') }) |
            Should -BeExactly 'MDE_MachineTags: Auto-InsufficientInfo--Excluded--SI'
    }

    It 'reports EVERY matching tag when several apply, joined and de-duplicated' {
        $r = Rec @{
            MDE_MachineTags      = @('a--Excluded--SI')
            EG_DeviceManualTags  = @('b--Excluded--SI')
        }
        $reason = Get-SIEndpointExclusionReason -Record $r
        $reason | Should -Match 'MDE_MachineTags: a--Excluded--SI'
        $reason | Should -Match 'EG_DeviceManualTags: b--Excluded--SI'
    }

    It 'does not repeat an identical entry' {
        $r = Rec @{ MDE_MachineTags = @('dup--Excluded--SI','dup--Excluded--SI') }
        (Get-SIEndpointExclusionReason -Record $r) | Should -BeExactly 'MDE_MachineTags: dup--Excluded--SI'
    }
}

Describe '🔑 the flag and the reason can never disagree' {
    # They are derived from ONE evaluation. Two functions applying the same rule separately is how a
    # "why" column drifts from the filter it is supposed to explain -- and the filter is what silently
    # removes the asset from every report.

    It 'IsExcludedByTag is true exactly when ExcludedReason is non-empty' -ForEach @(
        @{ Tags = @('clean');                  Expect = $false }
        @{ Tags = @('x--Excluded--SI');        Expect = $true  }
        @{ Tags = @();                         Expect = $false }
        @{ Tags = @('a','b--Excluded--SI','c');Expect = $true  }
    ) {
        $rf = Get-SIEndpointRiskFactors -Record ([pscustomobject]@{ MDE_MachineTags = $Tags })
        [bool]$rf.IsExcludedByTag | Should -Be $Expect
        (-not [string]::IsNullOrEmpty($rf.ExcludedReason)) | Should -Be $Expect
    }

    It 'the risk-factor set actually emits ExcludedReason' {
        $rf = Get-SIEndpointRiskFactors -Record ([pscustomobject]@{ MDE_MachineTags = @('z--Excluded--SI') })
        $rf.Keys | Should -Contain 'ExcludedReason'
        $rf.ExcludedReason | Should -Match 'z--Excluded--SI'
    }
}
