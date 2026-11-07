#Requires -Version 5.1
<#
    THE SUPPORT LEVEL SET IN THE INVARDIA PORTAL, APPLIED BY THE UPDATER (setup\_shared\SI-SupportPortalConsent.ps1; framework
    SUPPORT ACCESS point 2). The updater -- never the engine -- reads GET /api/support/consent with the install key and applies
    the level in the Pro database (Source customer, ConsentedBy 'Invardia portal'), read back; none = the row removed;
    Invardia unreachable / no supportConsent = nothing changed; once Invardia answered, the derived consent is not made again.
    Offline (fake Invardia + a fake Pro database that keeps the row); PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SupportPortalConsent.ps1'))
    $script:App = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'
    # a fake Pro database that runs THE statement's logic on one kept row (what the real statement does, in PowerShell)
    function script:New-FakePro {
        param([string]$Level = '', [string]$By = '', [string]$AppId = '')
        $box = @{ Level = $Level; By = $By; AppId = $AppId; Source = $(if ($Level) { 'derived' } else { '' }); Marker = ''; Calls = 0; Modes = @() }
        $inv = {
            param($Sql, $Params, $Mode)
            $box.Calls++; $box.Modes += $Mode
            if ($Mode -ne 'reader') { return }   # the updater's store answers rows ONLY in reader mode
            $pl = $box.Level; $pb = $box.By; $app = if ($Params.AppId) { $Params.AppId } else { $box.AppId }
            $o = ''
            if (-not $Params.Level) { if (-not $pl) { $o = 'unchanged' } else { $box.Level = ''; $box.By = ''; $box.Source = ''; $o = 'removed' } }
            elseif (-not $app) { $o = 'no-app' }
            elseif ($pl -eq $Params.Level -and $pb -eq 'Invardia portal' -and $box.AppId -eq $app) { $o = 'unchanged' }
            else { $box.Level = $Params.Level; $box.By = 'Invardia portal'; $box.Source = 'customer'; $box.AppId = $app; $o = 'applied' }
            if ($o -ne 'no-app') { $box.Marker = $(if ($Params.Level) { $Params.Level } else { 'none' }) }
            , @(@{ Outcome = $o; PrevLevel = $pl; PrevBy = $pb; Level = [string]$Params.Level; Consent = $(if ($box.Level) { '{0}|{1}|{2}' -f $box.Level, $box.Source, $box.By } else { '' }) })
        }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Box = $box }
    }
    function script:Answer($Level, $AppId) { $sc = [ordered]@{ level = $Level }; if ($AppId) { $sc.appId = $AppId }; { [pscustomobject]@{ environmentId = 'e'; product = 'securityinsight'; supportConsent = [pscustomobject]$sc } }.GetNewClosure() }
}

Describe 'the call to Invardia' {
    It 'GET <base>/api/support/consent with the install key in its header; the base defaults to invardia.com' {
        $seen = @{}
        $get = { param($Uri, $Headers) $seen.Uri = $Uri; $seen.H = $Headers; [pscustomobject]@{ supportConsent = [pscustomobject]@{ level = 'setup' } } }.GetNewClosure()
        $db = New-FakePro -Level 'setup' -By 'Invardia portal' -AppId $script:App
        $null = Invoke-SISupportPortalConsent -Get $get -Sql $db.Invoke -InstallKey ' key-1 '
        $seen.Uri | Should -Be 'https://invardia.com/api/support/consent'
        $seen.H['X-Invardia-Install-Key'] | Should -Be 'key-1'
        $null = Invoke-SISupportPortalConsent -Get $get -Sql $db.Invoke -InstallKey 'k' -BaseUrl 'https://test.example/'
        $seen.Uri | Should -Be 'https://test.example/api/support/consent'
    }
    It 'no install key, Invardia unreachable, or an answer without supportConsent: NOTHING is changed (the last level stays)' {
        $db = New-FakePro -Level 'setup' -By 'Invardia portal' -AppId $script:App
        (Invoke-SISupportPortalConsent -Get (Answer 'none') -Sql $db.Invoke -InstallKey '').Action | Should -Be 'skipped'
        (Invoke-SISupportPortalConsent -Get { throw '401 key' } -Sql $db.Invoke -InstallKey 'k').Action | Should -Be 'skipped'
        (Invoke-SISupportPortalConsent -Get { [pscustomobject]@{ environmentId = 'e' } } -Sql $db.Invoke -InstallKey 'k').Action | Should -Be 'skipped'
        $db.Box.Calls | Should -Be 0 -Because 'the database is not touched when Invardia did not answer'
        $db.Box.Level | Should -Be 'setup'
    }
}

Describe 'applying the level, read back' {
    It 'setup over a derived troubleshoot: applied as customer / Invardia portal, read back, the marker written, the change named' {
        $db = New-FakePro -Level 'troubleshoot' -By 'caj-si-updater (derived)' -AppId $script:App
        $r = Invoke-SISupportPortalConsent -Get (Answer 'setup') -Sql $db.Invoke -InstallKey 'k'
        $r.Action | Should -Be 'applied'
        $r.Line | Should -Match 'read back'
        $r.Change.To | Should -Be 'setup'
        $db.Box.Level | Should -Be 'setup'; $db.Box.By | Should -Be 'Invardia portal'; $db.Box.Source | Should -Be 'customer'
        $db.Box.Marker | Should -Be 'setup'
        @($db.Box.Modes) | Should -Be @('reader') -Because 'the updater store answers rows only in reader mode'
    }
    It 'none removes the consent (read back as removed); unknown values are none; the same level again changes nothing' {
        $db = New-FakePro -Level 'setup' -By 'Invardia portal' -AppId $script:App
        (Invoke-SISupportPortalConsent -Get (Answer 'setup') -Sql $db.Invoke -InstallKey 'k').Action | Should -Be 'unchanged'
        $r = Invoke-SISupportPortalConsent -Get (Answer 'read') -Sql $db.Invoke -InstallKey 'k'
        $r.Action | Should -Be 'removed'; $r.Change.To | Should -Be 'none'
        $db.Box.Level | Should -Be ''
        $db.Box.Marker | Should -Be 'none'
    }
    It 'the app id comes from the answer, else the recorded one; none anywhere = said, not applied' {
        $db = New-FakePro
        $r = Invoke-SISupportPortalConsent -Get (Answer 'troubleshoot') -Sql $db.Invoke -InstallKey 'k'
        $r.Action | Should -Be 'no-app'; $r.Line | Should -Match 'no Support app is known here'
        $r2 = Invoke-SISupportPortalConsent -Get (Answer 'troubleshoot' $script:App.ToUpperInvariant()) -Sql $db.Invoke -InstallKey 'k'
        $r2.Action | Should -Be 'applied'; $db.Box.AppId | Should -Be $script:App
    }
    It 'a database error is said, never thrown' {
        { Invoke-SISupportPortalConsent -Get (Answer 'setup') -Sql { throw 'refused' } -InstallKey 'k' } | Should -Not -Throw
        (Invoke-SISupportPortalConsent -Get (Answer 'setup') -Sql { throw 'refused' } -InstallKey 'k').Action | Should -Be 'failed'
    }
}

Describe 'the statement and the wiring' {
    It 'writes only row 1 as customer / Invardia portal, removes only row 1, marks SupportConsentPortal; nothing destructive beyond the row' {
        $s = Get-SISupportPortalConsentSql
        $s | Should -Match "VALUES \(1, @app, @Level, N'customer', N'Invardia portal'\)"
        $s | Should -Match "Source = N'customer', ConsentedBy = N'Invardia portal'"
        $s | Should -Match 'DELETE FROM cfg\.SupportConsent WHERE Id = 1'
        $s | Should -Match "Name = N'SupportConsentPortal'"
        $s | Should -Not -Match '(?i)DROP |TRUNCATE|ALTER (TABLE|ROLE)|sp_addrolemember'
    }
    It 'the UPDATER applies it on every run (Pro store, its own install key), audits a change; the engine never does' {
        $u = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Start-SIUpdater.ps1'))
        $u | Should -Match "Invoke-SISupportPortalConsent -Get \`$pcGet -Sql \`$proStore\.Invoke -InstallKey \`$pcKey"
        $u | Should -Match "-Name 'SI-Invardia-InstallKey'"
        $u | Should -Match "-Action 'support\.consent\.applied'"
        foreach ($f in Get-ChildItem -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'engine')) -Recurse -Filter '*.ps1') {
            [IO.File]::ReadAllText($f.FullName) | Should -Not -Match 'Invoke-SISupportPortalConsent|SI-SupportPortalConsent\.ps1' -Because "$($f.Name): the engine never applies the consent"
        }
    }
    It 'the derived consent is not made once Invardia has answered (a level the portal took away never comes back)' {
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SupportGrantUpdate.ps1'))
        (Get-SISupportGrantConsentReadSql) | Should -Match "Name = N'SupportConsentPortal'"
        $sql = { param($q, $p, $m) , @(@{ SupportApp = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'; Consent = ''; Portal = '{"level":"none"}' }) }
        $r = Invoke-SISupportGrantDerivedConsent -Rest { throw 'not called' } -Sql $sql -SubscriptionId 's' -ResourceGroup 'rg' -VaultName 'kv'
        $r.Action | Should -Be 'none'
        $r.Line | Should -BeNullOrEmpty
    }
    It 'the audit action is on the closed list' {
        $acts = (Get-Content -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'config', 'audit-actions.locked.json')) -Raw | ConvertFrom-Json).actions
        @($acts | Where-Object { $_.action -eq 'support.consent.applied' -and $_.source -eq 'job' }).Count | Should -Be 1
    }
}
