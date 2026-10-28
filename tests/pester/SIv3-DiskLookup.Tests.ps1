#Requires -Version 5.1
<#
    #726 -- THE IDENTITY COLLECTION'S TENANT-SIZED LOOKUPS LIVE ON DISK (owner 2026-10-16: "fix the streaming code for
    identity now"; the large ring-2 tenant's identity producer peaked at 6.65 GB with #721 -- the Exposure Graph identity
    index and the MFA registration map held as hashtables of objects).
    What these keep true (offline):
      1. SecurityInsight.DiskLookup: one entry per write on disk (PowerShell's own serialization), only the keys in memory;
         `$l[<key>]` reads the entry back TYPE FAITHFUL (an ISO date / '/Date(...)/' text stays the identical string, a date
         stays a date -- ConvertFrom-Json would turn the texts into dates); keys case-insensitive (as the hashtables); SetKey replaces, TryAddKey keeps the
         first; a missing key reads $null; Dispose removes the file;
      2. the Exposure Graph identity index and the MFA registration map ARE disk lookups, for every tenant (no size switch),
         and read as before: an entry by Entra id, SID, name and node id; an MFA entry's empty lists stay empty lists;
      3. GUARD: neither is built as a hashtable again; a released index's file goes with it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    foreach ($n in 'Write-SIInfo', 'Write-SIProgress', 'Reset-SIProgress', 'Write-SIWarn', 'Write-SIDiag') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:script:{0}" -f $n) -Value { param($Message) } }
    }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DiskLookup.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
}

Describe '1. the on-disk lookup' {
    It 'writes entries, reads them back as they were, keys case-insensitive; SetKey replaces, TryAddKey keeps the first' {
        $l = New-SIDiskLookup -Name 'test'
        try {
            $orig = [pscustomobject]@{ id = 'a'; n = 1; list = @('x'); empty = @(); nested = [pscustomobject]@{ k = @(); flag = $true; nothing = $null } }
            $a = $l.Append((ConvertTo-SIDiskLookupText $orig))
            $b = $l.Append((ConvertTo-SIDiskLookupText ([pscustomobject]@{ id = 'b' })))
            $l.SetKey('Key-A', $a); $l.TryAddKey('key-a', $b) | Should -BeFalse; $l.TryAddKey('other', $b) | Should -BeTrue
            $l.Count | Should -Be 2
            $l.ContainsKey('KEY-A') | Should -BeTrue
            $e = $l['key-a']
            $e.id | Should -Be 'a'
            (ConvertTo-Json $e -Compress -Depth 5) | Should -Be (ConvertTo-Json $orig -Compress -Depth 5)
            @($e.empty).Count | Should -Be 0
            $e.n | Should -BeOfType [int]
            $l.SetKey('key-a', $b); $l['key-a'].id | Should -Be 'b'
            $l['missing'] | Should -BeNullOrEmpty
            $null = $l.Put('p', (ConvertTo-SIDiskLookupText ([pscustomobject]@{ v = 2 }))); $l['P'].v | Should -Be 2
            $path = $l.Path; Test-Path -LiteralPath $path | Should -BeTrue
        } finally { Remove-SIDiskLookup $l }
        Test-Path -LiteralPath $path | Should -BeFalse -Because 'the file goes with the lookup'
    }
    It 'TYPE FAITHFUL: an ISO date text and a /Date(...)/ text stay the identical STRINGS; a date stays a date' {
        $l = New-SIDiskLookup -Name 'dates'
        try {
            $dt = [datetime]::new(2026, 10, 16, 10, 0, 0, [DateTimeKind]::Utc)
            $null = $l.Put('k', (ConvertTo-SIDiskLookupText ([pscustomobject]@{ iso = '2026-10-16T10:00:00Z'; ms = '/Date(1760608800000)/'; local = '10/10/2026 00:00:00'; when = $dt })))
            $e = $l['k']
            $e.iso | Should -BeOfType [string]; $e.iso | Should -BeExactly '2026-10-16T10:00:00Z'
            $e.ms | Should -BeOfType [string]; $e.ms | Should -BeExactly '/Date(1760608800000)/'
            $e.local | Should -BeExactly '10/10/2026 00:00:00'
            $e.when | Should -BeOfType [datetime]; $e.when | Should -Be $dt; $e.when.Kind | Should -Be ([DateTimeKind]::Utc)
            [string]$e.iso | Should -BeExactly '2026-10-16T10:00:00Z' -Because 'never re-formatted as a date'
        } finally { Remove-SIDiskLookup $l }
    }
}

Describe '2. the identity lookups are on disk and read as before' {
    BeforeAll { $script:Np1 = '{"rawData":{"accountUpn":"one@x.example","isMfaRegistered":true,"assignedRoles":[],"lastSeen":"2026-10-01T08:00:00Z","whenCreated":"2019-08-12T10:11:12Z","pwdLastSet":"/Date(1760608800000)/"}}' }
    It 'the Exposure Graph identity index: a disk lookup, an entry by Entra id, SID, name and node id' {
        Mock Invoke-SIEgIdentityQuery {
            param($Query)
            if ($Query -match '\| count$') { return @{ Ok = $true; Rows = @([pscustomobject]@{ Count = $(if ($Query -match "'user'") { 2 } else { 0 }) }); Error = '' } }
            if ($Query -notmatch "'user'") { return @{ Ok = $true; Rows = @(); Error = '' } }
            @{ Ok = $true; Error = ''; Rows = @(
                [pscustomobject]@{ NodeId = 'nid-1'; NodeLabel = 'user'; NodeName = 'User One'; Categories = '["identity"]'
                    EntityIds = '["{\"type\":\"AadObjectId\",\"id\":\"objectid=aaaaaaaa-0000-4000-8000-000000000001\"}","{\"type\":\"SecurityIdentifier\",\"id\":\"S-1-5-21-1-2-3-1001\"}"]'
                    NodeProperties = $script:Np1 }
                [pscustomobject]@{ NodeId = 'nid-2'; NodeLabel = 'user'; NodeName = 'AD only'; Categories = '["identity"]'
                    EntityIds = '["{\"type\":\"SecurityIdentifier\",\"id\":\"S-1-5-21-1-2-3-1002\"}"]'
                    NodeProperties = '{"rawData":{"accountName":"adonly","accountDomain":"corp"}}' }) }
        }
        $script:_SICache = @{}
        $m = Get-SIExposureGraphIdentities 6>$null 3>$null
        try {
            $m.GetType().FullName | Should -Be 'SecurityInsight.DiskLookup'
            $m['aaaaaaaa-0000-4000-8000-000000000001'].RawData.accountUpn | Should -Be 'one@x.example'
            $m['s-1-5-21-1-2-3-1001'].NodeId | Should -Be 'nid-1'
            $m['user one'].NodeId | Should -Be 'nid-1'
            $m['nid-1'].NodeName | Should -Be 'User One'
            # the entry's rawData is exactly what the in-memory index held (dates the hunting read parsed stay dates, texts stay texts)
            . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-EgRawTrim.ps1')
            $want = Select-SIEgRawFields -Raw (($script:Np1 | ConvertFrom-Json).rawData) -Keep (Get-SIEgIdentityKeepKeys -SIRoot $script:SIRoot)
            (ConvertTo-Json $m['nid-1'].RawData -Compress -Depth 10) | Should -BeExactly (ConvertTo-Json $want -Compress -Depth 10)
            $m.ContainsKey('nid-2') | Should -BeFalse -Because 'an AD-only node enriches no Entra object (it is a record, not an index entry)'
            $m.Count | Should -Be 4
        } finally { Remove-SIDiskLookup $m; $script:_SICache = @{} }
    }
    It 'the MFA registration map: a disk lookup; an empty list stays an empty list, a missing user is unknown' {
        $script:_SICache = @{}
        $fetch = { param($Url, $Token) [pscustomobject]@{ Complete = $true; Error = ''; Count = 2; Pages = 1; Rows = @(
            [pscustomobject]@{ id = 'u1'; isMfaRegistered = $true; isMfaCapable = $true; methodsRegistered = @('password', 'microsoftAuthenticatorPush'); systemPreferredAuthenticationMethods = @(); lastUpdatedDateTime = '2026-10-10T00:00:00Z' }
            [pscustomobject]@{ id = 'u2'; isMfaRegistered = $false; methodsRegistered = @(); systemPreferredAuthenticationMethods = @('push') }) } }
        $m = Get-SIEntraMfaRegistrationByPrincipal -Token 't' -Fetch $fetch
        try {
            $m.GetType().FullName | Should -Be 'SecurityInsight.DiskLookup'
            $m.Count | Should -Be 2
            $m['u1'].MfaLastUpdatedDateTime | Should -BeExactly '2026-10-10T00:00:00Z' -Because 'an ISO text stays the identical string'
            $f1 = ConvertTo-SIUserMfaFields -Entry $m['u1']
            $f1.ENTRA_MfaIsRegistered | Should -BeTrue
            @($f1.ENTRA_MfaMethods) | Should -Be @('microsoftAuthenticatorPush')
            @($f1.ENTRA_MfaSystemPreferredMethods).Count | Should -Be 0 -Because 'an empty list read back is still empty, never one null'
            @((ConvertTo-SIUserMfaFields -Entry $m['u2']).ENTRA_MfaSystemPreferredMethods) | Should -Be @('push')
            (ConvertTo-SIUserMfaFields -Entry $m['u9']).ENTRA_MfaIsRegistered | Should -BeNullOrEmpty -Because '#522: no row is unknown, never "no MFA"'
        } finally { Remove-SIDiskLookup $m; $script:_SICache = @{} }
    }
}

Describe '3. GUARD: one method -- the identity lookups are never whole-tenant hashtables again' {
    It 'the index and the MFA map are built as disk lookups, unconditionally' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'))
        $src | Should -Match ([regex]::Escape("`$egMap = New-SIDiskLookup -Name 'eg-identity'"))
        $src | Should -Match ([regex]::Escape("`$byPrincipal = New-SIDiskLookup -Name 'mfa-registration'"))
        $fn = { param($name) $i = $src.IndexOf("function $name"); $j = $src.IndexOf("`nfunction ", $i + 10); if ($j -lt 0) { $j = $src.Length }; $src.Substring($i, $j - $i) }
        $eg = & $fn 'Get-SIExposureGraphIdentities'; $mfa = & $fn 'Get-SIEntraMfaRegistrationByPrincipal'
        $eg | Should -Not -Match '\$egMap\s*=\s*@\{\}'
        $eg | Should -Not -Match '\$egMap\[[^\]]+\]\s*='
        $mfa | Should -Not -Match '\$byPrincipal\s*=\s*@\{\}'
        $mfa | Should -Not -Match '\$byPrincipal\[[^\]]+\]\s*='
    }
    It 'a released index takes its file with it (Discover and the engine run)' {
        foreach ($f in 'engine\asset-profiling\stages\Invoke-Discover.ps1', 'engine\asset-profiling\Invoke-SIEngineRun.ps1') {
            $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f))
            $i = $t.IndexOf("Remove-SIDiskLookup `$script:_SICache['EgIdentitiesMap']"); $j = $t.IndexOf("`$script:_SICache.Remove('EgIdentitiesMap')")
            ($i -gt 0 -and $j -gt $i) | Should -BeTrue -Because $f
        }
    }
}
