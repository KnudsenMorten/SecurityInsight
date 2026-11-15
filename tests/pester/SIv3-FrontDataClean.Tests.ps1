#Requires -Version 7.0
<#
    THE EARLIER SIGN-IN FRONT'S DATA-PLANE LEFTOVERS, DELETED BY SECURITYINSIGHT'S OWN CODE (#1260; Invardia works on control
    planes only): setup\_shared\SI-BuiltInAuthStandard.ps1 Invoke-SIBuiltInAuthFrontDataClean -- the signin-front images in the
    install's registry and the Key Vault keys signin-front-dp / SI-Web-KeyRing -- and its call from the updater
    (container\updater\Start-SIUpdater.ps1, Invoke-SIUpdaterBuiltInAuthStep), BEFORE the standard's leftover check.
    FULLY OFFLINE: ARM, the registry and the Key Vault are fakes (script scope) that record what they were asked:
      * deleted ONLY when the web app reads back switched (built-in sign-in on, no front container, the latest ready
        revision Healthy and running, no active revision / no app running the front) -- each part read back;
      * kept while the front runs; the keys kept while the web app does not run on its own key store (BlobUri unset or not
        in the running revision) or id-si-web still holds a role on the key;
      * a refused delete is a warning and a support step, never a throw; plan deletes nothing;
      * ASSERT-WIRING: the real updater step reaches the real clean (no -FrontDataClean seam) and runs it before the standard.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuth.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-BuiltInAuthStandard.ps1')
    # defined in the SAME scope as the dot-sourced updater
    function Write-UpdLog { param($m) $script:Log.Add([string]$m) }
    $script:Log = New-Object System.Collections.Generic.List[string]

    $script:Rg      = '/subscriptions/s/resourceGroups/rg'
    $script:WebId   = $script:Rg + '/providers/Microsoft.App/containerApps/ca-si-management'
    $script:VaultId = $script:Rg + '/providers/Microsoft.KeyVault/vaults/kv-si'
    $script:WebPrin = 'dddddddd-1111-2222-3333-444444444444'
    $script:Blob    = 'https://stsi.blob.core.windows.net/si-auth-tokens/dataprotection/keys.xml'
    $script:Crypto  = '/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/e147488a-f6f5-4113-8e2d-b22465e65bf6'
    $script:Login   = 'acrsi.azurecr.io'

    # THE FAKE WORLD (in $script:FD). Opt: Setting (SI_Web_BuiltInAuth), Front (a signin-front container in the app's
    # template), Platform (built-in sign-in on), Latest / Ready (revision names), Health, Running, OldFront (an older ACTIVE
    # revision still runs the front), OtherApp (another app names a signin-front image), Blob (DataProtection__BlobUri on the
    # app; '' = unset), RevBlob (the running revision's value), Roles (key names id-si-web still holds a role on), Keys (keys
    # in the vault), KvGet / KvDelete (the vault's answers), Images (digests in signin-front), Locked (digests locked),
    # RegDelete (Ok | 403), ListThrows (the registry list's error).
    function script:New-FdWorld([hashtable]$Opt = @{}) {
        $o = @{ Setting = '1'; Front = $false; Platform = $true; Latest = 'ca-si-management--r2'; Ready = 'ca-si-management--r2'; Health = 'Healthy'; Running = 'Running'
                OldFront = $false; OtherApp = $false; Blob = $script:Blob; RevBlob = $script:Blob; Roles = @(); Keys = @('signin-front-dp', 'SI-Web-KeyRing')
                KvGet = 0; KvDelete = 200; Images = @(('sha256:' + ('a' * 64)), ('sha256:' + ('b' * 64))); Locked = @(); RegDelete = 'Ok'; ListThrows = '' }
        # (GetEnumerator / ['...']: an option named Keys would hide the hashtable's own .Keys)
        foreach ($p in @($Opt.GetEnumerator())) { $o[[string]$p.Key] = $p.Value }
        $script:FD = @{ Opt = $o; Calls = New-Object System.Collections.Generic.List[string]
                        Keys = New-Object System.Collections.Generic.List[string]; Images = New-Object System.Collections.Generic.List[string] }
        foreach ($k in @($o['Keys'])) { if ($k) { $script:FD.Keys.Add([string]$k) } }
        foreach ($d in @($o['Images'])) { if ($d) { $script:FD.Images.Add([string]$d) } }
        $script:FD.Arm = {
            param($Method, $Path, $Body)
            $W = $script:FD; $O = $W.Opt
            $W.Calls.Add("ARM $Method $Path")
            $webEnv = { param($blob) $e = @(); if ($O.Setting) { $e += [pscustomobject]@{ name = 'SI_Web_BuiltInAuth'; value = $O.Setting } }; if ($blob) { $e += [pscustomobject]@{ name = 'DataProtection__BlobUri'; value = $blob } }; , $e }
            if ($Method -eq 'GET' -and $Path -match '/authConfigs/current\?') { return [pscustomobject]@{ properties = [pscustomobject]@{ platform = [pscustomobject]@{ enabled = [bool]$O.Platform } } } }
            if ($Method -eq 'GET' -and $Path -match '/containerApps/ca-si-management/revisions\?') {
                $front = [pscustomobject]@{ name = 'signin-front'; image = "$($script:Login)/signin-front:2.1.2-src-x"; env = @() }
                $webC = [pscustomobject]@{ name = 'web'; image = "$($script:Login)/si-management:3.1.24"; env = (& $webEnv $O.RevBlob) }
                $cur = [pscustomobject]@{ name = $O.Latest; properties = [pscustomobject]@{ active = $true; healthState = $O.Health; runningState = $O.Running; template = [pscustomobject]@{ containers = @($webC) } } }
                $old = [pscustomobject]@{ name = 'ca-si-management--r1'; properties = [pscustomobject]@{ active = [bool]$O.OldFront; healthState = 'Healthy'; runningState = 'Running'; template = [pscustomobject]@{ containers = @($front, $webC) } } }
                return [pscustomobject]@{ value = @($old, $cur) }
            }
            if ($Method -eq 'GET' -and $Path -match '/containerApps/ca-si-management\?') {
                $cs = @([pscustomobject]@{ name = 'web'; image = "$($script:Login)/si-management:3.1.24"; env = (& $webEnv $O.Blob) })
                if ($O.Front) { $cs = @([pscustomobject]@{ name = 'signin-front'; image = "$($script:Login)/signin-front:2.1.2"; env = @() }) + $cs }
                $ua = [pscustomobject]@{}
                $ua | Add-Member -NotePropertyName ($script:Rg + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-web') -NotePropertyValue ([pscustomobject]@{ clientId = 'cccccccc-1111-2222-3333-444444444444'; principalId = $script:WebPrin })
                return [pscustomobject]@{ name = 'ca-si-management'; identity = [pscustomobject]@{ userAssignedIdentities = $ua }
                    properties = [pscustomobject]@{ latestRevisionName = $O.Latest; latestReadyRevisionName = $O.Ready
                        configuration = [pscustomobject]@{ ingress = [pscustomobject]@{ targetPort = $(if ($O.Front) { 8443 } else { 8080 }) } }; template = [pscustomobject]@{ containers = $cs } } }
            }
            if ($Method -eq 'GET' -and $Path -match '/providers/Microsoft\.App/containerApps\?') {
                $mcp = [pscustomobject]@{ name = 'ca-si-mcp'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'mcp'; image = "$($script:Login)/si-mcp:3.1.24" }) } } }
                $other = [pscustomobject]@{ name = 'ca-other'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'x'; image = "$($script:Login)/signin-front@sha256:$('c' * 64)" }) } } }
                return [pscustomobject]@{ value = @(@($mcp) + @(if ($O.OtherApp) { $other })) }
            }
            if ($Method -eq 'GET' -and $Path -match '/keys/([^/]+)/providers/Microsoft\.Authorization/roleAssignments\?') {
                $kn = $Matches[1]; $scope = '{0}/keys/{1}' -f $script:VaultId, $kn
                $v = @(if (@($O.Roles) -contains $kn) { [pscustomobject]@{ id = "$scope/providers/Microsoft.Authorization/roleAssignments/w1"; properties = [pscustomobject]@{ principalId = $script:WebPrin; roleDefinitionId = $script:Crypto; scope = $scope } } })
                return [pscustomobject]@{ value = $v }
            }
            $null
        }
        $script:FD.Registry = @{
            LoginServer = $script:Login
            List = { param($Repo) $W = $script:FD; $W.Calls.Add("REG LIST $Repo")
                if ($W.Opt.ListThrows) { throw $W.Opt.ListThrows }
                if ($Repo -ne 'signin-front' -or -not $W.Images.Count) { return [pscustomobject]@{ Found = ($W.Images.Count -gt 0); Manifests = @() } }
                [pscustomobject]@{ Found = $true; Manifests = @($W.Images | ForEach-Object { [pscustomobject]@{ Digest = $_; Tags = @('2.1.2-src-' + $_.Substring(7, 6)); DeleteEnabled = (@($W.Opt.Locked) -notcontains $_) } }) } }
            Delete = { param($Repo, $Digest) $W = $script:FD; $W.Calls.Add("REG DELETE $Repo $Digest")
                if ($W.Opt.RegDelete -eq '403') { return [pscustomobject]@{ Ok = $false; Status = 403; Why = 'HTTP 403' } }
                $null = $W.Images.Remove($Digest); [pscustomobject]@{ Ok = $true; Status = 202; Why = '' } }
        }
        $script:FD.Kv = {
            param($Method, $Uri, $Body)
            $W = $script:FD; $W.Calls.Add("KV $Method $Uri")
            $kn = if ($Uri -match '/keys/([^/?]+)') { $Matches[1] } else { '' }
            if ($Method -eq 'GET') { if ($W.Opt.KvGet) { return [pscustomobject]@{ Status = $W.Opt.KvGet; Json = $null } }; return [pscustomobject]@{ Status = $(if ($W.Keys.Contains($kn)) { 200 } else { 404 }); Json = $null } }
            if ($Method -eq 'DELETE') { if ([int]$W.Opt.KvDelete -lt 300) { $null = $W.Keys.Remove($kn) }; return [pscustomobject]@{ Status = [int]$W.Opt.KvDelete; Json = $null } }
            [pscustomobject]@{ Status = 400; Json = $null }
        }
        $script:FD
    }
    function script:Invoke-Fd([hashtable]$Opt = @{}, [string]$Mode = 'apply') {
        $w = New-FdWorld $Opt
        Invoke-SIBuiltInAuthFrontDataClean -Arm $w.Arm -Mode $Mode -WebAppId $script:WebId -Registry $w.Registry -LoginServer $script:Login `
            -KeyVault $w.Kv -VaultName 'kv-si' -VaultId $script:VaultId -Sleep { param($s) } -Tries 2
    }
    function script:Get-Deletes { @($script:FD.Calls | Where-Object { $_ -match '^(REG|KV|ARM) DELETE ' }) }
}

Describe 'the earlier sign-in''s images and keys: deleted only when the web app reads back switched' {
    It 'switched and read back: every signin-front image and both keys are deleted, each read back; one plain line each' {
        $r = Invoke-Fd
        $r.Images | Should -Be 'removed'
        $r.Keys['signin-front-dp'] | Should -Be 'removed'
        $r.Keys['SI-Web-KeyRing'] | Should -Be 'removed'
        @($r.Support).Count | Should -Be 0
        @($r.Warnings).Count | Should -Be 0
        $script:FD.Images.Count | Should -Be 0
        $script:FD.Keys.Count | Should -Be 0
        @($script:FD.Calls | Where-Object { $_ -like 'REG DELETE signin-front sha256:*' }).Count | Should -Be 2
        @($script:FD.Calls | Where-Object { $_ -like 'REG DELETE *' -and $_ -notlike 'REG DELETE signin-front *' }).Count | Should -Be 0 -Because 'no other repository is ever touched'
        @($script:FD.Calls | Where-Object { $_ -match '^KV DELETE https://kv-si\.vault\.azure\.net/keys/(signin-front-dp|SI-Web-KeyRing)\?api-version=' }).Count | Should -Be 2
        @($script:FD.Calls | Where-Object { $_ -match '^ARM (PUT|PATCH|DELETE|POST) ' }).Count | Should -Be 0 -Because 'nothing in Azure Resource Manager is written'
        # the read-back comes AFTER each delete
        $c = @($script:FD.Calls)
        $iDel = [array]::IndexOf($c, @($c | Where-Object { $_ -like 'KV DELETE *signin-front-dp*' })[0])
        @($c[($iDel + 1)..($c.Count - 1)] | Where-Object { $_ -like 'KV GET *signin-front-dp*' }).Count | Should -BeGreaterThan 0
        ($r.Lines -join "`n") | Should -Match 'the earlier sign-in''s images \(signin-front in acrsi\.azurecr\.io\): removed -- 2 image\(s\) \(tags 2\.1\.2-src-'
        ($r.Lines -join "`n") | Should -Match 'the earlier sign-in''s key signin-front-dp in kv-si: removed \(soft delete'
        ($r.Lines -join "`n") | Should -Match 'the earlier sign-in''s key SI-Web-KeyRing in kv-si: removed'
    }
    It 'kept while the front may still run (<Why>): nothing is deleted, the reason is said' -ForEach @(
        @{ Why = 'SI_Web_BuiltInAuth is not 1';               Opt = @{ Setting = '' };                      Want = 'SI_Web_BuiltInAuth is not 1' }
        @{ Why = 'the signin-front container is in the app';  Opt = @{ Front = $true };                     Want = 'the sign-in front container is still there' }
        @{ Why = 'the built-in sign-in is off';               Opt = @{ Platform = $false };                 Want = 'built-in sign-in is not on' }
        @{ Why = 'the latest revision is not the ready one';  Opt = @{ Ready = 'ca-si-management--r1' };   Want = 'is not the ready one' }
        @{ Why = 'the latest revision is not Healthy';        Opt = @{ Health = 'Unhealthy' };              Want = 'is Unhealthy, not Healthy' }
        @{ Why = 'the latest revision is not running';        Opt = @{ Running = 'Stopped' };               Want = 'is Stopped' }
        @{ Why = 'an older ACTIVE revision runs the front';   Opt = @{ OldFront = $true };                  Want = 'r1 still runs the sign-in front' }
        @{ Why = 'another app names a signin-front image';    Opt = @{ OtherApp = $true };                  Want = 'ca-other still names a sign-in front image' }
    ) {
        $r = Invoke-Fd $Opt
        $r.Images | Should -Be 'kept'
        $r.Keys['signin-front-dp'] | Should -Be 'kept'; $r.Keys['SI-Web-KeyRing'] | Should -Be 'kept'
        @(Get-Deletes).Count | Should -Be 0
        @($script:FD.Calls | Where-Object { $_ -like 'REG *' -or $_ -like 'KV *' }).Count | Should -Be 0 -Because 'not even read'
        ($r.Lines -join "`n") | Should -Match ([regex]::Escape($Want))
        ($r.Lines -join "`n") | Should -Match 'stored images and keys are kept'
    }
    It 'the keys stay while the web app does not run on its own key store (<Why>); the images still go' -ForEach @(
        @{ Why = 'DataProtection__BlobUri unset';                     Opt = @{ Blob = ''; RevBlob = '' };  Want = 'DataProtection__BlobUri is not set' }
        @{ Why = 'the running revision does not carry it yet';        Opt = @{ RevBlob = '' };             Want = 'does not run with DataProtection__BlobUri yet' }
    ) {
        $r = Invoke-Fd $Opt
        $r.Images | Should -Be 'removed'
        $r.Keys['signin-front-dp'] | Should -Be 'kept'; $r.Keys['SI-Web-KeyRing'] | Should -Be 'kept'
        @($script:FD.Calls | Where-Object { $_ -like 'KV *' }).Count | Should -Be 0
        $script:FD.Keys.Count | Should -Be 2
        ($r.Lines -join "`n") | Should -Match ([regex]::Escape($Want))
    }
    It 'a key id-si-web still holds a role on is kept (the key-ring step takes the role away first); the other goes' {
        $r = Invoke-Fd @{ Roles = @('SI-Web-KeyRing') }
        $r.Keys['signin-front-dp'] | Should -Be 'removed'
        $r.Keys['SI-Web-KeyRing'] | Should -Be 'kept'
        @($script:FD.Calls | Where-Object { $_ -like 'KV DELETE *SI-Web-KeyRing*' }).Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'key SI-Web-KeyRing: kept -- id-si-web still holds a role on it'
    }
    It 'a key whose rights cannot be read here (no vault id) is kept' {
        $w = New-FdWorld
        $r = Invoke-SIBuiltInAuthFrontDataClean -Arm $w.Arm -Mode apply -WebAppId $script:WebId -Registry $w.Registry -KeyVault $w.Kv -VaultName 'kv-si' -VaultId '' -Sleep { param($s) } -Tries 2
        $r.Keys['signin-front-dp'] | Should -Be 'kept'
        @($script:FD.Calls | Where-Object { $_ -like 'KV DELETE *' }).Count | Should -Be 0
    }
    It 'already gone: "none left" for the images and each key, nothing deleted' {
        $r = Invoke-Fd @{ Images = @(); Keys = @() }
        $r.Images | Should -Be 'none'
        $r.Keys['signin-front-dp'] | Should -Be 'none'; $r.Keys['SI-Web-KeyRing'] | Should -Be 'none'
        @(Get-Deletes).Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'images \(signin-front in acrsi\.azurecr\.io\): none left'
        ($r.Lines -join "`n") | Should -Match 'key signin-front-dp in kv-si: none left'
    }
    It 'plan says what would go and deletes NOTHING' {
        $r = Invoke-Fd @{} 'plan'
        $r.Images | Should -Be 'planned'
        $r.Keys['signin-front-dp'] | Should -Be 'planned'; $r.Keys['SI-Web-KeyRing'] | Should -Be 'planned'
        @(Get-Deletes).Count | Should -Be 0
        $script:FD.Images.Count | Should -Be 2; $script:FD.Keys.Count | Should -Be 2
        ($r.Lines -join "`n") | Should -Match 'would delete 2 image\(s\).*nothing was deleted'
        ($r.Lines -join "`n") | Should -Match 'key signin-front-dp in kv-si: would delete it \(soft delete\) -- nothing was deleted'
    }
}

Describe 'a refusal is a warning and a support step, never a failure' {
    It 'the registry refuses the delete: images "refused", a warning and the support step that gives the right back; the keys still go' {
        $r = Invoke-Fd @{ RegDelete = '403' }
        $r.Images | Should -Be 'refused'
        ($r.Warnings -join "`n") | Should -Match 'images \(signin-front in acrsi\.azurecr\.io\): NOT removed -- the registry refused the delete'
        @($r.Support | Where-Object { $_ -match '^the support partner gives the updater back its delete right on the install''s registry acrsi\.azurecr\.io' }).Count | Should -Be 1
        $r.Keys['signin-front-dp'] | Should -Be 'removed'
    }
    It 'the registry refuses the updater''s token: not checked, refused, a support step' {
        $r = Invoke-Fd @{ ListThrows = 'the registry refused the token exchange: HTTP 401' }
        $r.Images | Should -Be 'refused'
        @($r.Support).Count | Should -Be 1
    }
    It 'the registry cannot be reached (not a refusal): a warning, no support step, nothing deleted' {
        $r = Invoke-Fd @{ ListThrows = 'the images of signin-front could not be listed: HTTP 500' }
        $r.Images | Should -Be 'failed'
        @($r.Support).Count | Should -Be 0
        @($script:FD.Calls | Where-Object { $_ -like 'REG DELETE *' }).Count | Should -Be 0
    }
    It 'an image locked against deletion is kept and said' {
        $w0 = 'sha256:' + ('a' * 64)
        $r = Invoke-Fd @{ Locked = @($w0) }
        $r.Images | Should -Be 'kept'
        ($r.Warnings -join "`n") | Should -Match '1 locked against deletion -- kept'
        @($script:FD.Calls | Where-Object { $_ -eq "REG DELETE signin-front $w0" }).Count | Should -Be 0
    }
    It 'the Key Vault refuses the delete (<Code>): the key "refused", a warning and a support step; never a throw' -ForEach @(@{ Code = 403 }, @{ Code = 401 }) {
        $r = Invoke-Fd @{ KvDelete = $Code }
        $r.Keys['signin-front-dp'] | Should -Be 'refused'; $r.Keys['SI-Web-KeyRing'] | Should -Be 'refused'
        @($r.Support | Where-Object { $_ -match '^the support partner gives the updater back its Key Vault key right \(Key Vault Crypto Officer on the vault kv-si\), so the update removes the key (signin-front-dp|SI-Web-KeyRing) itself$' }).Count | Should -Be 2
        ($r.Warnings -join "`n") | Should -Match "NOT removed -- the Key Vault refused the delete \(HTTP $Code\)"
    }
    It 'the Key Vault refuses the read: not checked, refused, a support step, no delete sent' {
        $r = Invoke-Fd @{ KvGet = 403 }
        $r.Keys['signin-front-dp'] | Should -Be 'refused'
        @($script:FD.Calls | Where-Object { $_ -like 'KV DELETE *' }).Count | Should -Be 0
        @($r.Support).Count | Should -Be 2
    }
    It 'the web app cannot be read: a warning, nothing deleted, never a throw' {
        $arm = { param($m, $p, $b) throw 'HTTP 500 boom' }
        $r = Invoke-SIBuiltInAuthFrontDataClean -Arm $arm -Mode apply -WebAppId $script:WebId -Sleep { param($s) }
        ($r.Warnings -join "`n") | Should -Match 'were not checked -- the web app could not be read'
        $r.Images | Should -Be 'not-checked'
    }
    It 'the support texts give a right back and name no way around a control' {
        $r1 = Invoke-Fd @{ RegDelete = '403'; KvDelete = 403 }
        foreach ($s in @($r1.Support)) {
            $s | Should -Match 'gives the updater back'
            $s | Should -Not -Match '(?i)bypass|work ?around|disable|turn off|skip|without (the|a) (check|right)'
        }
    }
}

Describe 'the leftover report no longer lists what the update removed' {
    It 'images gone = no image line; images still there = a line that says the update removes them (no other owner named)' {
        $f = [pscustomobject]@{ Web = $null; Images = [pscustomobject]@{ LoginServer = $script:Login; Found = $false; Tags = @() } }
        @(Get-SIBuiltInAuthLeftoverFindings -Facts $f).Count | Should -Be 0
        $f.Images = [pscustomobject]@{ LoginServer = $script:Login; Found = $true; Tags = @('2.1.2-src-x') }
        $t = @(Get-SIBuiltInAuthLeftoverFindings -Facts $f)
        $t.Count | Should -Be 1
        $t[0] | Should -Match '1 signin-front image\(s\) still stored in acrsi\.azurecr\.io \(tags 2\.1\.2-src-x\) -- the update removes them once the web app reads back without the sign-in front'
        $t[0] | Should -Not -Match 'image clean-up'
    }
}

Describe 'ASSERT-WIRING: the real updater step reaches the real clean, before the standard''s check' {
    BeforeEach { $script:Log.Clear(); $global:SI_UpdaterFailures = $null }
    AfterAll { $global:SI_UpdaterFailures = $null }
    It 'apply after a switch that read back: the real Invoke-SIBuiltInAuthFrontDataClean deletes and reads back; then the standard runs' {
        (Get-Command Invoke-SIBuiltInAuthFrontDataClean -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty -Because 'the updater loads SI-BuiltInAuthStandard.ps1'
        $w = New-FdWorld
        $script:order = New-Object System.Collections.Generic.List[string]
        $std = { param($a) $script:order.Add('standard:' + $script:FD.Images.Count + ':' + $script:FD.Keys.Count); [pscustomobject]@{ Ok = $true; McpState = 'in-place'; Lines = @(); Warnings = @() } }
        $conv = { param($a) [pscustomobject]@{ Ok = $true; State = 'in-place'; Lines = @() } }
        $r = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'apply'; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 's' -ResourceGroup 'rg' `
                 -Converge $conv -Arm $w.Arm -Graph { } -SigninDrop { param($a) $null } -Standard $std `
                 -FrontRegistry $w.Registry -FrontKeyVault $w.Kv -FrontVaultName 'kv-si' -VaultId $script:VaultId
        $r.FrontData | Should -Not -BeNullOrEmpty
        $r.FrontData.Images | Should -Be 'removed'
        $r.FrontData.Keys['signin-front-dp'] | Should -Be 'removed'
        $r.FrontData.Keys['SI-Web-KeyRing'] | Should -Be 'removed'
        @($script:order) | Should -Be @('standard:0:0') -Because 'the standard''s leftover check runs AFTER the clean, so it no longer lists them'
        ($script:Log -join "`n") | Should -Match 'the earlier sign-in''s images \(signin-front in acrsi\.azurecr\.io\): removed'
        ($script:Log -join "`n") | Should -Match 'the earlier sign-in''s key signin-front-dp in kv-si: removed'
        $src = (Get-Command Invoke-SIUpdaterBuiltInAuthStep).ScriptBlock.ToString()
        $src.IndexOf('& $FrontDataClean $fa') | Should -BeLessThan $src.IndexOf('& $Standard $sa')
        $src.IndexOf('& $SigninDrop') | Should -BeLessThan $src.IndexOf('& $FrontDataClean $fa')
        $src | Should -Match 'New-SIUpdaterRegistrySeam -LoginServer' -Because 'the image clean-up''s own registry seam'
        $src | Should -Match 'Invoke-SIHandoverKv -Rest \(Get-SIUpdaterRest\)' -Because 'the Key Vault data plane through the run''s REST seam'
    }
    It 'a refusal through the real step: a WARNING line and one Support-app customer action, never a failure' {
        $w = New-FdWorld @{ KvDelete = 403; RegDelete = '403' }
        $conv = { param($a) [pscustomobject]@{ Ok = $true; State = 'applied'; Lines = @() } }
        $null = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'apply'; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 's' -ResourceGroup 'rg' `
                 -Converge $conv -Arm $w.Arm -Graph { } -SigninDrop { param($a) $null } -Standard { param($a) $null } `
                 -FrontRegistry $w.Registry -FrontKeyVault $w.Kv -FrontVaultName 'kv-si' -VaultId $script:VaultId
        ($script:Log -join "`n") | Should -Match 'WARNING: the earlier sign-in''s key signin-front-dp in kv-si: NOT removed'
        @($global:SI_UpdaterFailures | Where-Object { $_.Kind -eq 'customer-action' -and $_.Text -match '^Support-app step: the support partner gives the updater back' }).Count | Should -Be 3
        @($global:SI_UpdaterFailures | Where-Object { $_.Kind -ne 'customer-action' }).Count | Should -Be 0 -Because 'a refusal never fails the update'
    }
    It 'plan through the real step: says what would go, deletes nothing' {
        $w = New-FdWorld
        $conv = { param($a) [pscustomobject]@{ Ok = $true; State = 'in-place'; Lines = @() } }
        $r = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = 'plan'; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 's' -ResourceGroup 'rg' `
                 -Converge $conv -Arm $w.Arm -Graph { } -Standard { param($a) $null } `
                 -FrontRegistry $w.Registry -FrontKeyVault $w.Kv -FrontVaultName 'kv-si' -VaultId $script:VaultId
        $r.FrontData.Images | Should -Be 'planned'
        @(Get-Deletes).Count | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'would delete 2 image\(s\)'
    }
    It 'a failed or rolled-back apply never reaches it; off never reaches it' {
        foreach ($case in @(@{ M = 'apply'; S = 'failed'; Ok = $false }, @{ M = 'apply'; S = 'rolled-back'; Ok = $false }, @{ M = 'off'; S = 'in-place'; Ok = $true })) {
            $w = New-FdWorld
            $st = $case.S; $ok = $case.Ok
            $conv = { param($a) [pscustomobject]@{ Ok = $ok; State = $st; Lines = @() } }.GetNewClosure()
            $r = Invoke-SIUpdaterBuiltInAuthStep -Env @{ SI_Updater_BuiltInAuth = $case.M; SI_UPDATER_WEB_APP = 'ca-si-management' } -SubscriptionId 's' -ResourceGroup 'rg' `
                     -Converge $conv -Arm $w.Arm -Graph { } -Standard { param($a) $null } `
                     -FrontRegistry $w.Registry -FrontKeyVault $w.Kv -FrontVaultName 'kv-si' -VaultId $script:VaultId
            @($script:FD.Calls | Where-Object { $_ -like 'REG *' -or $_ -like 'KV *' }).Count | Should -Be 0 -Because "$($case.M) $($case.S)"
        }
    }
}
