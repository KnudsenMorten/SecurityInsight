#Requires -Version 5.1
<#
    The device reports read DeviceInfo as an OPTIONAL table (REQUIREMENTS #1104). Found live 2026-11-04 on a tenant with
    Defender for Business (no DeviceInfo in its hunting schema): Device_Missing_CVEs, Device_Recommendations and
    Device_EndOfSupport_Software came back with 0 rows while the vulnerability tables held the data (63,871 rows), because
    one left-outer join to DeviceInfo -- for a name or an exclusion reason only -- failed the whole query.
    Every DeviceInfo read in the locked catalog is now `union isfuzzy=true (datatable(<the columns it reads>)[]), (DeviceInfo)`:
    a tenant without the table gets an empty, typed source; a tenant with it reads the same rows as before (proven
    read-only on both kinds of tenant). Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Yaml = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml'))
    # every line that names the table DeviceInfo (not DeviceInfoLatest, not a comment)
    $script:Lines = @($script:Yaml -split "`r?`n" | Where-Object { $_ -match '(^|[^A-Za-z_])DeviceInfo([^A-Za-z_]|$)' -and $_ -notmatch '^\s*//' })
}

Describe 'DeviceInfo is an optional table in the locked report catalog (#1104)' {
    It 'the catalog still reads DeviceInfo (the guard would pass on nothing otherwise)' {
        $script:Lines.Count | Should -BeGreaterThan 0
    }
    It 'every read of DeviceInfo is the optional form: union isfuzzy=true with a typed empty datatable' {
        $bad = @($script:Lines | Where-Object { $_ -notmatch 'union isfuzzy=true \(datatable\(DeviceId:string, Timestamp:datetime[^)]*\)\[\]\), \(DeviceInfo\)' })
        $bad | Should -BeNullOrEmpty -Because 'a plain DeviceInfo read fails the whole report on a tenant without the table (Defender for Business)'
    }
    It 'the empty datatable carries every DeviceInfo column the name blocks read (DeviceName, OSPlatform)' {
        $named = @($script:Lines | Where-Object { $_ -match '^\s*union isfuzzy=true' })
        $named.Count | Should -BeGreaterThan 0
        foreach ($l in $named) { $l | Should -Match 'DeviceName:string, OSPlatform:string' }
    }
}
