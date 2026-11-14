#Requires -Version 5.1
<#
    SI #1215 -- IMAGE-PRUNE (framework IMAGE-PATCH-1 "IMAGE-PRUNE", owner 2026-11-12): after a successful update and its
    read-back, the install's OWN registry keeps only the images of the current release and of the one before
    (container/updater/_shared/SI-UpdaterImagePrune.ps1, called from _shared/SI-UpdaterInvardia.ps1 after the post-roll).

    EVERYTHING IS OFFLINE. The registry is a fake (List / Manifest / Delete over an in-memory set of manifests); the REST seam
    of the real registry seam is a fake that records every address; Azure reads are mocks. A real HTTP call fails the test.

    Covered: current + previous kept, older deleted; NEVER before a healthy read-back (and a failed or unread update prunes
    nothing); NEVER another registry (a registry outside the install's resource group; images of other registries; every
    address the real seam calls is the install's registry); previous NOT recorded = everything kept; a tag shared with a
    kept image kept; a base image used by a kept build kept (and one that cannot be proven unused kept); multi-platform
    children kept; the read-back count per repository; the switch; the record and the state row; the wiring.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
    if (-not (Get-Command -Name Invoke-SIUpdaterImagePrune -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImagePrune.ps1') }

    Mock Invoke-WebRequest { throw 'no network in tests' }
    Mock Invoke-RestMethod { throw 'no network in tests' }
    $script:Login = 'acrsi.azurecr.io'

    # a stable fake digest per name
    function script:D([string]$n) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { 'sha256:' + (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($n)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
    }
    # one manifest of the fake registry
    function script:M([string]$Name, [string[]]$Tags = @(), [string[]]$Layers = @(), [string[]]$Children = @(), [bool]$DeleteEnabled = $true, [switch]$Unreadable) {
        [pscustomobject]@{ Digest = (D $Name); Name = $Name; Tags = @($Tags); Layers = @($Layers | ForEach-Object { D $_ }); Children = @($Children | ForEach-Object { D $_ })
                           DeleteEnabled = $DeleteEnabled; Unreadable = [bool]$Unreadable }
    }
    # the fake registry: repo -> manifests; every call recorded; Delete removes; ListFails = repos whose listing throws
    function script:New-FakeRegistry([hashtable]$Repos, [string[]]$ListFails = @(), [string[]]$DeleteFails = @()) {
        $w = @{ Repos = @{}; Calls = (New-Object System.Collections.Generic.List[string]); Deleted = (New-Object System.Collections.Generic.List[string])
                ListFails = @($ListFails); DeleteFails = @($DeleteFails | ForEach-Object { D $_ }) }
        foreach ($k in $Repos.Keys) { $l = New-Object System.Collections.ArrayList; foreach ($m in @($Repos[$k])) { $null = $l.Add($m) }; $w.Repos[$k] = $l }
        $w.Seam = @{
            LoginServer = 'acrsi.azurecr.io'
            List = {
                param($Repo)
                $w.Calls.Add("LIST $Repo")
                if ($w.ListFails -contains $Repo) { throw 'HTTP 500' }
                if (-not $w.Repos.ContainsKey($Repo)) { return [pscustomobject]@{ Found = $false; Manifests = @() } }
                [pscustomobject]@{ Found = $true; Manifests = @($w.Repos[$Repo] | ForEach-Object { [pscustomobject]@{ Digest = $_.Digest; Tags = @($_.Tags); MediaType = ''; DeleteEnabled = $_.DeleteEnabled } }) }
            }.GetNewClosure()
            Manifest = {
                param($Repo, $Digest)
                $w.Calls.Add("GET $Repo@$Digest")
                if (-not $w.Repos.ContainsKey($Repo)) { return $null }
                $m = @($w.Repos[$Repo] | Where-Object { $_.Digest -eq $Digest }) | Select-Object -First 1
                if (-not $m) {
                    # a child of a multi-platform image lives in the same repository, untagged
                    return $null
                }
                if ($m.Unreadable) { return $null }
                if (@($m.Children).Count) { return [pscustomobject]@{ mediaType = 'application/vnd.oci.image.index.v1+json'; manifests = @($m.Children | ForEach-Object { [pscustomobject]@{ digest = $_ } }) } }
                [pscustomobject]@{ mediaType = 'application/vnd.docker.distribution.manifest.v2+json'; layers = @($m.Layers | ForEach-Object { [pscustomobject]@{ digest = $_ } }) }
            }.GetNewClosure()
            Delete = {
                param($Repo, $Digest)
                $w.Calls.Add("DELETE $Repo@$Digest")
                if ($w.DeleteFails -contains $Digest) { return [pscustomobject]@{ Ok = $false; Status = 403; Why = 'HTTP 403' } }
                $m = @($w.Repos[$Repo] | Where-Object { $_.Digest -eq $Digest }) | Select-Object -First 1
                if ($m) { $w.Repos[$Repo].Remove($m); $w.Deleted.Add("$Repo/$($m.Name)") }
                [pscustomobject]@{ Ok = $true; Status = 202; Why = '' }
            }.GetNewClosure()
        }
        $w
    }
    # a snapshot of what the install runs, from 'repo:tag' strings (prefixed with the install's login server unless they carry a host)
    function script:Snap([string[]]$Refs, [bool]$Ok = $true, [string]$Reason = 'read') {
        $r = @(foreach ($x in $Refs) { $img = if ($x -match '^[a-z0-9.-]+\.[a-z]+/') { $x } else { "$($script:Login)/$x" }; $c = ConvertTo-SIUpdaterImageRef -Image $img -LoginServer $script:Login; if ($c) { $c } })
        [pscustomobject]@{ Ok = $Ok; Refs = $r; Reason = $Reason }
    }
    # THE STANDARD REGISTRY: the engine (current v4, previous v3, older v2 + v1) on two bases (h1 new, h0 old), the web app (3)
    function script:New-StandardRegistry {
        New-FakeRegistry @{
            'si-orchestrator' = @(
                (M 'orch-v4' @('v4-aaa') @('L0', 'Lb1', 'L4')),
                (M 'orch-v3' @('v3-bbb') @('L0', 'Lb1', 'L3')),
                (M 'orch-v2' @('v2-ccc') @('L0', 'Lb0', 'L2')),
                (M 'orch-v1' @('v1-ddd') @('L0', 'Lb0', 'L1')))
            'si-base' = @(
                (M 'base-h1' @('h1') @('L0', 'Lb1')),
                (M 'base-h0' @('h0') @('L0', 'Lb0')))
            'si-management' = @(
                (M 'web-s2' @('src-2') @('W0', 'W2')),
                (M 'web-s1' @('src-1') @('W0', 'W1')),
                (M 'web-s0' @('src-0') @('W0', 'W9')))
        }
    }
    $script:Cur = { Snap @('si-orchestrator:v4-aaa', 'si-management:src-2') }
    $script:Prev = { Snap @('si-orchestrator:v3-bbb', 'si-management:src-1') }
}

Describe 'IMAGE-PRUNE: the current and the previous release are kept, older images are deleted' {
    It 'deletes the engine and web images of older releases and the base no kept build uses; keeps the rest' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -RegistryResourceGroup 'rg-si' -InstallResourceGroup 'rg-si'
        $r.Done | Should -BeTrue
        @($f.Deleted | Sort-Object) | Should -Be @(@('si-base/base-h0', 'si-management/web-s0', 'si-orchestrator/orch-v1', 'si-orchestrator/orch-v2') | Sort-Object)
        @($f.Repos['si-orchestrator'] | ForEach-Object { $_.Name }) | Should -Be @('orch-v4', 'orch-v3')
        @($f.Repos['si-base'] | ForEach-Object { $_.Name }) | Should -Be @('base-h1')
        @($f.Repos['si-management'] | ForEach-Object { $_.Name }) | Should -Be @('web-s2', 'web-s1')
    }
    It 'reads back what is left and says the count per repository, one plain line each' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev)
        $o = @($r.Repos | Where-Object { $_.Repo -eq 'si-orchestrator' })[0]
        $o.Deleted | Should -Be 2; $o.Left | Should -Be 2; $o.Before | Should -Be 4; $o.Kept | Should -Be 2
        @($r.Repos | Where-Object { $_.Repo -eq 'si-base' })[0].Left | Should -Be 1
        @($r.Repos | Where-Object { $_.Repo -eq 'si-management' })[0].Left | Should -Be 2
        @($r.Lines) | Should -Contain 'si-orchestrator: 2 old images deleted, 2 left (this release and the one before)'
        ($r.Lines -join "`n") | Should -Match 'si-base: 1 old base images deleted, 1 left'
        # the read-back is a second listing after the deletes
        @($f.Calls | Where-Object { $_ -eq 'LIST si-orchestrator' }).Count | Should -Be 2
        ($r.Lines -join "`n") | Should -Not -Match '#\d|1215' -Because 'customer-facing text carries no internal numbers'
    }
    It 'a repository the install records nothing for is never touched' {
        $f = New-StandardRegistry
        $f.Repos['someone-else'] = New-Object System.Collections.ArrayList
        $null = $f.Repos['someone-else'].Add((M 'x1' @('1.0') @('X0')))
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev)
        @($f.Calls | Where-Object { $_ -like '*someone-else*' }).Count | Should -Be 0
    }
    It 'the release record''s current (the release before, as the last update recorded it) is kept too' {
        $f = New-StandardRegistry
        $rec = @((Snap @('si-orchestrator:v2-ccc')).Refs)
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -Recorded $rec
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v2'
        @($f.Deleted) | Should -Not -Contain 'si-base/base-h0' -Because 'orch-v2 is kept, so the base it is built on is kept'
        @($f.Deleted) | Should -Contain 'si-orchestrator/orch-v1'
    }
    It 'an image named by digest is kept by its digest' {
        $f = New-StandardRegistry
        $cur = Snap @(('si-orchestrator@' + (D 'orch-v4')), 'si-management:src-2')
        $prev = Snap @(('si-orchestrator@' + (D 'orch-v2')), 'si-management:src-1')
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $cur -Previous $prev
        @($f.Deleted) | Should -Contain 'si-orchestrator/orch-v3'
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v2'
    }
}

Describe 'IMAGE-PRUNE NEGATIVE: never before a healthy read-back; a failed or unread update prunes nothing' {
    It 'an update that did not end healthy deletes nothing and does not even read the registry' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $false -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev)
        $r.Done | Should -BeFalse
        $f.Calls.Count | Should -Be 0
        $r.Reason | Should -Match 'did not end healthy'
    }
    It 'what runs now could not be read back: nothing deleted' {
        $f = New-StandardRegistry
        foreach ($c in @($null, (Snap @() -Ok $false -Reason 'ARM 503'), (Snap @()))) {
            $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $c -Previous (& $script:Prev)
            $r.Done | Should -BeFalse
        }
        @($f.Calls | Where-Object { $_ -like 'DELETE*' }).Count | Should -Be 0
    }
    It 'the step itself: Healthy false = no registry, no Azure read, no record written' {
        $f = New-StandardRegistry
        Mock Write-UpdLog { }
        Mock Get-SIUpdaterRegistry { throw 'must not be read' }
        $script:Written = @{}
        $res = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $false -Before (& $script:Prev) -After (& $script:Cur) `
                   -Registry $f.Seam -Get { param($n) '' } -WriteSecret { param($n, $v) $script:Written[$n] = $v }
        $res | Should -BeNullOrEmpty
        $f.Calls.Count | Should -Be 0
        $script:Written.Count | Should -Be 0
        Should -Invoke Get-SIUpdaterRegistry -Times 0 -Exactly
    }
}

Describe 'IMAGE-PRUNE NEGATIVE: never another registry, never anything else' {
    It 'a registry outside the install''s own resource group is never pruned' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -RegistryResourceGroup 'rg-shared' -InstallResourceGroup 'rg-si'
        $r.Done | Should -BeFalse
        $r.Reason | Should -Match 'not in this install''s own resource group'
        $f.Calls.Count | Should -Be 0
    }
    It 'images of other registries (Microsoft''s, another registry) are not this registry''s repositories' {
        (ConvertTo-SIUpdaterImageRef -Image 'mcr.microsoft.com/dotnet/aspnet:10.0' -LoginServer $script:Login) | Should -BeNullOrEmpty
        (ConvertTo-SIUpdaterImageRef -Image 'otheracr.azurecr.io/si-orchestrator:v4' -LoginServer $script:Login) | Should -BeNullOrEmpty
        (ConvertTo-SIUpdaterImageRef -Image 'si-orchestrator:v4' -LoginServer $script:Login) | Should -BeNullOrEmpty
        $f = New-StandardRegistry
        $cur = Snap @('si-orchestrator:v4-aaa', 'si-management:src-2', 'mcr.microsoft.com/k8se/quickstart:latest', 'otheracr.azurecr.io/thing:1')
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $cur -Previous (& $script:Prev)
        @($f.Calls | Where-Object { $_ -match 'quickstart|thing|k8se' }).Count | Should -Be 0
    }
    It 'the real registry seam calls ONLY https://(the install''s login server)/ -- the token exchange, the listing, the manifest, the delete' {
        $script:Uris = New-Object System.Collections.Generic.List[string]
        $rest = {
            param($Method, $Uri, $Body, $Resource, $Headers)
            $script:Uris.Add("$Method $Uri")
            if ($Uri -like '*/oauth2/exchange') { return [pscustomobject]@{ Status = 200; Body = '{"refresh_token":"r"}'; Headers = @{} } }
            if ($Uri -like '*/oauth2/token') { return [pscustomobject]@{ Status = 200; Body = '{"access_token":"a"}'; Headers = @{} } }
            if ($Uri -like '*/_manifests*' -and $Uri -notlike '*last=*') {
                return [pscustomobject]@{ Status = 200; Body = ('{"manifests":[{"digest":"' + (D 'a') + '","tags":["v1"],"changeableAttributes":{"deleteEnabled":true}}]}')
                                          Headers = @{ Link = '<https://evil.example.com/acr/v1/si-orchestrator/_manifests?last=x&n=1000>; rel="next"' } }
            }
            if ($Method -eq 'GET' -and $Uri -like '*/v2/*/manifests/*') { return [pscustomobject]@{ Status = 200; Body = '{"layers":[{"digest":"' + (D 'L') + '"}]}'; Headers = @{} } }
            if ($Method -eq 'DELETE') { return [pscustomobject]@{ Status = 202; Body = ''; Headers = @{} } }
            [pscustomobject]@{ Status = 404; Body = ''; Headers = @{} }
        }
        $seam = New-SIUpdaterRegistrySeam -LoginServer $script:Login -Rest $rest -Token { param($r) 'aad-token' }
        $ls = & $seam.List 'si-orchestrator'
        $ls.Found | Should -BeTrue; @($ls.Manifests).Count | Should -Be 1; @($ls.Manifests)[0].Tags | Should -Be @('v1')
        (& $seam.Manifest 'si-orchestrator' (D 'a')).layers | Should -Not -BeNullOrEmpty
        (& $seam.Delete 'si-orchestrator' (D 'a')).Ok | Should -BeTrue
        $script:Uris.Count | Should -BeGreaterThan 3
        foreach ($u in $script:Uris) { ($u -split ' ', 2)[1] | Should -BeLike "https://$($script:Login)/*" }
        @($script:Uris | Where-Object { $_ -like 'DELETE *' }) | Should -Be @("DELETE https://$($script:Login)/v2/si-orchestrator/manifests/$(D 'a')")
        @($script:Uris | Where-Object { $_ -like '*oauth2/token*' }).Count | Should -Be 1 -Because 'one registry token per repository'
        @($script:Uris | Where-Object { $_ -like '*evil*' }).Count | Should -Be 0 -Because 'a next-page link to another host is never followed'
    }
    It 'the token asks the delete right for that repository only' {
        $script:Bodies = New-Object System.Collections.Generic.List[string]
        $rest = {
            param($Method, $Uri, $Body, $Resource, $Headers)
            if ($Uri -like '*/oauth2/token') { $script:Bodies.Add([string]$Body); return [pscustomobject]@{ Status = 200; Body = '{"access_token":"a"}'; Headers = @{} } }
            if ($Uri -like '*/oauth2/exchange') { return [pscustomobject]@{ Status = 200; Body = '{"refresh_token":"r"}'; Headers = @{} } }
            [pscustomobject]@{ Status = 202; Body = ''; Headers = @{} }
        }
        $seam = New-SIUpdaterRegistrySeam -LoginServer $script:Login -Rest $rest -Token { param($r) 'aad-token' }
        $null = & $seam.Delete 'si-management' (D 'a')
        [uri]::UnescapeDataString($script:Bodies[0]) | Should -Match 'scope=repository:si-management:pull,metadata_read,delete&'
    }
    It 'CONTRACT point 4: the real seam beats before EVERY HTTP request (token calls, each listing page, manifest, delete); a failing beat is tried once per window' {
        $script:Seq = New-Object System.Collections.Generic.List[string]
        $rest = {
            param($Method, $Uri, $Body, $Resource, $Headers)
            $script:Seq.Add("HTTP $Method")
            if ($Uri -like '*/oauth2/exchange') { return [pscustomobject]@{ Status = 200; Body = '{"refresh_token":"r"}'; Headers = @{} } }
            if ($Uri -like '*/oauth2/token') { return [pscustomobject]@{ Status = 200; Body = '{"access_token":"a"}'; Headers = @{} } }
            if ($Uri -like '*_manifests?n=1000') { return [pscustomobject]@{ Status = 200; Body = '{"manifests":[{"digest":"' + (D 'a') + '","tags":["v1"]}]}'; Headers = @{ Link = '</acr/v1/si-orchestrator/_manifests?last=x&n=1000>; rel="next"' } } }
            if ($Uri -like '*_manifests?last=x*') { return [pscustomobject]@{ Status = 200; Body = '{"manifests":[{"digest":"' + (D 'b') + '","tags":["v2"]}]}'; Headers = @{} } }
            [pscustomobject]@{ Status = 202; Body = ''; Headers = @{} }
        }
        $seam = New-SIUpdaterRegistrySeam -LoginServer $script:Login -Rest $rest -Token { param($r) 'aad-token' } -BeatSeconds 0 -Beat { param($w) $script:Seq.Add('BEAT') }
        $ls = & $seam.List 'si-orchestrator'
        @($ls.Manifests).Count | Should -Be 2 -Because 'both pages were read'
        $null = & $seam.Delete 'si-orchestrator' (D 'a')
        $http = @(for ($i = 0; $i -lt $script:Seq.Count; $i++) { if ($script:Seq[$i] -like 'HTTP *') { $i } })
        $http.Count | Should -Be 5 -Because 'exchange + token + 2 listing pages + 1 delete'
        foreach ($i in $http) { $script:Seq[$i - 1] | Should -Be 'BEAT' }
        # a beat that fails: tried once in a long window, the requests all go through
        $script:Tries = 0
        $seam2 = New-SIUpdaterRegistrySeam -LoginServer $script:Login -Rest $rest -Token { param($r) 'aad-token' } -BeatSeconds 3600 -Beat { $script:Tries++; throw 'database unreachable' }
        @((& $seam2.List 'si-orchestrator').Manifests).Count | Should -Be 2
        $script:Tries | Should -Be 1
    }
    It 'the clean-up code calls no module, no CLI and no ARM write' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImagePrune.ps1'))
        $src | Should -Not -Match '(?im)^\s*Import-Module|\baz\s+acr\b|Remove-AzContainerRegistry|Connect-AzAccount'
        $src | Should -Not -Match "Invoke-SIUpdaterArm -Method (PATCH|PUT|DELETE|POST)" -Because 'Azure is only READ here; deletes go to the registry data plane'
    }
}

Describe 'IMAGE-PRUNE NEGATIVE: where the previous release is not recorded, everything is kept' {
    It 'no read before the update, an unreadable one, or one that found nothing: nothing deleted, and it says so' {
        foreach ($p in @($null, (Snap @() -Ok $false -Reason 'the jobs could not be read'), (Snap @()))) {
            $f = New-StandardRegistry
            $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous $p
            $r.Done | Should -BeFalse
            $r.Reason | Should -Match 'previous release are not recorded'
            $r.Reason | Should -Match 'every image is kept'
            @($f.Calls | Where-Object { $_ -like 'DELETE*' }).Count | Should -Be 0
        }
    }
    It 'a kept image that cannot be read keeps its whole repository' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4') @('L0') -Unreadable), (M 'orch-v3' @('v3') @('L0')), (M 'orch-v1' @('v1') @('L1'))) }
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4')) -Previous (Snap @('si-orchestrator:v3'))
        $f.Deleted.Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'si-orchestrator: not cleaned up'
    }
    It 'a repository that cannot be listed is kept, and its bases are kept (their use cannot be proven)' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4') @('L0', 'Lb1', 'L4'))); 'si-base' = @((M 'base-h0' @('h0') @('L0', 'Lb0'))) } -ListFails @('si-management')
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4', 'si-management:src-2')) -Previous (Snap @('si-orchestrator:v4', 'si-management:src-1'))
        $f.Deleted.Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'si-management: not cleaned up -- its images could not be listed'
        ($r.Lines -join "`n") | Should -Match 'si-base: not cleaned up'
    }
}

Describe 'IMAGE-PRUNE: shared tags, base images, multi-platform images, failures' {
    It 'a tag shared with a kept image is kept: an old tag on the current image''s digest is never deleted' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4-aaa', 'v2-ccc', 'latest') @('L0', 'L4')), (M 'orch-v3' @('v3-bbb') @('L0', 'L3')), (M 'orch-v1' @('v1-ddd') @('L0', 'L1'))) }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4-aaa')) -Previous (Snap @('si-orchestrator:v3-bbb'))
        @($f.Deleted) | Should -Be @('si-orchestrator/orch-v1')
        @($f.Calls | Where-Object { $_ -eq ('DELETE si-orchestrator@' + (D 'orch-v4')) }).Count | Should -Be 0
    }
    It 'deletes go by manifest digest only' {
        $f = New-StandardRegistry
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev)
        foreach ($c in @($f.Calls | Where-Object { $_ -like 'DELETE*' })) { $c | Should -Match '@sha256:[0-9a-f]{64}$' }
    }
    It 'a base image a kept build is made FROM is kept; a base only older builds used goes; the updater''s own base too' {
        $f = New-FakeRegistry @{
            'si-updater'      = @((M 'upd-new' @('3.1.11-abc') @('U0', 'Ub2', 'U9')), (M 'upd-prev' @('3.1.10-def') @('U0', 'Ub1', 'U8')), (M 'upd-old' @('3.1.9-0aa') @('U0', 'Ub0', 'U7')))
            'si-updater-base' = @((M 'ub2' @('hb2') @('U0', 'Ub2')), (M 'ub1' @('hb1') @('U0', 'Ub1')), (M 'ub0' @('hb0') @('U0', 'Ub0')))
        }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-updater:3.1.11-abc')) -Previous (Snap @('si-updater:3.1.10-def'))
        @($f.Deleted | Sort-Object) | Should -Be @(@('si-updater-base/ub0', 'si-updater/upd-old') | Sort-Object)
    }
    It 'a base image whose manifest cannot be read is kept (it cannot be proven unused)' {
        $f = New-FakeRegistry @{
            'si-orchestrator' = @((M 'orch-v4' @('v4') @('L0', 'Lb1', 'L4')), (M 'orch-v3' @('v3') @('L0', 'Lb1', 'L3')))
            'si-base' = @((M 'base-h1' @('h1') @('L0', 'Lb1')), (M 'base-hx' @('hx') @('L0', 'Lbx') -Unreadable), (M 'base-h0' @('h0') @('L0', 'Lb0')))
        }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4')) -Previous (Snap @('si-orchestrator:v3'))
        @($f.Deleted) | Should -Be @('si-base/base-h0')
    }
    It 'a base is kept only when ALL its layers are the first layers of a kept image (a shared Microsoft layer is not enough)' {
        (Test-SIUpdaterLayerPrefix -Base @('a', 'b') -Image @('a', 'b', 'c')) | Should -BeTrue
        (Test-SIUpdaterLayerPrefix -Base @('a', 'x') -Image @('a', 'b', 'c')) | Should -BeFalse
        (Test-SIUpdaterLayerPrefix -Base @('b') -Image @('a', 'b')) | Should -BeFalse
        (Test-SIUpdaterLayerPrefix -Base @() -Image @('a')) | Should -BeFalse
        (Test-SIUpdaterLayerPrefix -Base @('a', 'b', 'c', 'd') -Image @('a', 'b', 'c')) | Should -BeFalse
    }
    It 'the platform images of a kept multi-platform image are kept' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @(
                (M 'idx-v4' @('v4') -Children @('p-amd64', 'p-att')),
                (M 'p-amd64' @() @('L0', 'L4')), (M 'p-att' @() @('A0')),
                (M 'orch-v3' @('v3') @('L0', 'L3')), (M 'orch-v1' @('v1') @('L0', 'L1')), (M 'stray' @() @('S0'))) }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4')) -Previous (Snap @('si-orchestrator:v3'))
        @($f.Deleted | Sort-Object) | Should -Be @(@('si-orchestrator/orch-v1', 'si-orchestrator/stray') | Sort-Object)
    }
    It 'a delete the registry refuses is said and kept; the clean-up goes on and never throws' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4') @('L0')), (M 'orch-v3' @('v3') @('L0', 'L3')), (M 'orch-v2' @('v2') @('L0', 'L2')), (M 'orch-v1' @('v1') @('L0', 'L1'))) } -DeleteFails @('orch-v2')
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4')) -Previous (Snap @('si-orchestrator:v3'))
        @($f.Deleted) | Should -Be @('si-orchestrator/orch-v1')
        $o = @($r.Repos)[0]; $o.Failed | Should -Be 1; $o.Left | Should -Be 3
        $o.Line | Should -Match '1 could not be deleted \(HTTP 403\) -- kept, the next update tries again'
    }
    It 'an image locked against deletion is kept and said' {
        $f = New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4') @('L0')), (M 'orch-v3' @('v3') @('L0', 'L3')), (M 'orch-v1' @('v1') @('L0', 'L1') -DeleteEnabled $false)) }
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4')) -Previous (Snap @('si-orchestrator:v3'))
        $f.Deleted.Count | Should -Be 0
        @($r.Repos)[0].Line | Should -Match 'locked against deletion -- kept'
    }
}

Describe 'IMAGE-PRUNE: the switch SI_Updater_ImagePrune (on by default)' {
    It 'on by default; off / false / no / 0 turn it off; anything else stays on and says so' {
        (Get-SIUpdaterImagePruneMode -Value '').On | Should -BeTrue
        (Get-SIUpdaterImagePruneMode -Value $null).On | Should -BeTrue
        foreach ($v in 'off', 'OFF', 'false', 'no', '0') { (Get-SIUpdaterImagePruneMode -Value $v).On | Should -BeFalse }
        foreach ($v in 'on', 'true', 'yes', '1') { (Get-SIUpdaterImagePruneMode -Value $v).On | Should -BeTrue }
        (Get-SIUpdaterImagePruneMode -Value 'maybe').Reason | Should -Match 'not on or off'
    }
    It 'read from the configuration, else the job''s SI_CFG_SI_Updater_ImagePrune, else SI_UPDATER_IMAGE_PRUNE' {
        $keep = $global:SI_Updater_ImagePrune
        try {
            Remove-Variable -Name SI_Updater_ImagePrune -Scope Global -ErrorAction SilentlyContinue
            (Get-SIUpdaterImagePruneSetting -Get { param($n) @{ SI_CFG_SI_Updater_ImagePrune = 'off'; SI_UPDATER_IMAGE_PRUNE = 'on' }[$n] }) | Should -Be 'off'
            (Get-SIUpdaterImagePruneSetting -Get { param($n) @{ SI_UPDATER_IMAGE_PRUNE = 'off' }[$n] }) | Should -Be 'off'
            (Get-SIUpdaterImagePruneSetting -Get { param($n) '' }) | Should -Be ''
            $global:SI_Updater_ImagePrune = 'off'
            (Get-SIUpdaterImagePruneSetting -Get { param($n) 'on' }) | Should -Be 'off'
        } finally { if ($null -ne $keep) { $global:SI_Updater_ImagePrune = $keep } else { Remove-Variable -Name SI_Updater_ImagePrune -Scope Global -ErrorAction SilentlyContinue } }
    }
    It 'off: nothing is read or deleted' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $false -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev)
        $r.Done | Should -BeFalse; $f.Calls.Count | Should -Be 0
        Mock Write-UpdLog { }
        Mock Get-SIUpdaterRegistry { throw 'must not be read' }
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) -Registry $f.Seam -Get { param($n) if ($n -eq 'SI_CFG_SI_Updater_ImagePrune') { 'off' } else { '' } }
        $f.Calls.Count | Should -Be 0
        Should -Invoke Get-SIUpdaterRegistry -Times 0 -Exactly
    }
}

Describe 'IMAGE-PRUNE: what the install records (the read of jobs and apps, the record, the state row)' {
    It 'reads every job and app image of this registry, the active revisions and the pending updater image; nothing of other registries' {
        Mock Get-SIUpdaterJobs { @(
            [pscustomobject]@{ name = 'caj-si-flow'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-orchestrator:v4-aaa' }) } } },
            [pscustomobject]@{ name = 'caj-si-updater'; tags = [pscustomobject]@{ 'si-updater-pending' = '3.1.12-abc' }
                               properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-updater:3.1.11-def' }) } } },
            [pscustomobject]@{ name = 'caj-other'; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'mcr.microsoft.com/azuredocs/aci-helloworld:latest' }) } } }) }
        Mock Invoke-SIUpdaterArm {
            if ($Path -like '*/revisions') {
                return @([pscustomobject]@{ name = 'r-new'; properties = [pscustomobject]@{ active = $true; template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-management:src-2' }) } } },
                         [pscustomobject]@{ name = 'r-old'; properties = [pscustomobject]@{ active = $true; template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-management:src-1' }) } } },
                         [pscustomobject]@{ name = 'r-gone'; properties = [pscustomobject]@{ active = $false; template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-management:src-0' }) } } })
            }
            @([pscustomobject]@{ name = 'ca-si-management'; id = '/subscriptions/sub/resourceGroups/rg-si/providers/Microsoft.App/containerApps/ca-si-management'
                                 properties = [pscustomobject]@{ template = [pscustomobject]@{
                                     containers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-management:src-2' }, [pscustomobject]@{ name = 'signin-front'; image = 'acrsi.azurecr.io/signin-front:2.1.1-src-1' })
                                     initContainers = @([pscustomobject]@{ image = 'acrsi.azurecr.io/si-init:1' }) } } })
        }
        $s = Get-SIUpdaterImageSnapshot -ResourceGroup 'rg-si' -SubscriptionId 'sub' -LoginServer $script:Login
        $s.Ok | Should -BeTrue
        $got = @($s.Refs | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ } | Sort-Object -Unique)
        $got | Should -Be @(@('si-init:1', 'si-management:src-1', 'si-management:src-2', 'si-orchestrator:v4-aaa', 'si-updater:3.1.11-def', 'si-updater:3.1.12-abc', 'signin-front:2.1.1-src-1') | Sort-Object -Unique)
        Should -Invoke Invoke-SIUpdaterArm -Times 0 -Exactly -ParameterFilter { $Method -and $Method -ne 'GET' }
    }
    It 'an unreadable install is not Ok (so nothing is pruned)' {
        Mock Get-SIUpdaterJobs { throw 'HTTP 403' }
        $s = Get-SIUpdaterImageSnapshot -ResourceGroup 'rg-si' -SubscriptionId 'sub' -LoginServer $script:Login
        $s.Ok | Should -BeFalse; $s.Reason | Should -Match 'could not be read'
    }
    It 'image references parse to repository, tag and digest' {
        $d = D 'x'
        $r = ConvertTo-SIUpdaterImageRef -Image "ACRSI.azurecr.io/si-orchestrator:v4-aaa@$d" -LoginServer $script:Login
        $r.Repo | Should -Be 'si-orchestrator'; $r.Tag | Should -Be 'v4-aaa'; $r.Digest | Should -Be $d
        (ConvertTo-SIUpdaterImageRef -Image "acrsi.azurecr.io/team/si-web@$d" -LoginServer $script:Login).Repo | Should -Be 'team/si-web'
        (ConvertTo-SIUpdaterImageRef -Image 'acrsi.azurecr.io/si-web' -LoginServer $script:Login).Tag | Should -Be 'latest'
        (ConvertTo-SIUpdaterImageRef -Image 'acrsi.azurecr.io/si-web@sha256:bad' -LoginServer $script:Login) | Should -BeNullOrEmpty
    }
    It 'the step: one log line per repository, the release record (current + previous) and the state row of at most 400 characters' {
        $f = New-StandardRegistry
        $script:Log = New-Object System.Collections.Generic.List[string]
        Mock Write-UpdLog { $script:Log.Add($m) }
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
        $script:Rows = @{}
        Mock Save-SIUpdaterInstallStateValue { $script:Rows[$Name] = $Value; $true }
        $script:Written = @{}
        $res = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                   -Version '3.1.11' -PreviousVersion '3.1.10' -Registry $f.Seam -Get { param($n) '' } -Store @{ Invoke = {} } `
                   -ReadSecret { param($n) $null } -WriteSecret { param($n, $v) $script:Written[$n] = $v }
        $res.Done | Should -BeTrue
        @($script:Log | Where-Object { $_ -like 'si-orchestrator:*deleted*' }).Count | Should -Be 1
        @($script:Log | Where-Object { $_ -eq 'si-orchestrator: 4 images, 2 kept, 2 to delete' }).Count | Should -Be 1 -Because 'the plan is said before the deletes'
        @($script:Log | Where-Object { $_ -like 'si-management:*deleted*' }).Count | Should -Be 1
        $rec = ConvertFrom-SIUpdaterReleaseImageRecord -Json $script:Written['SI-Release-Images']
        $rec.CurrentVersion | Should -Be '3.1.11'; $rec.PreviousVersion | Should -Be '3.1.10'
        @($rec.Current | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ }) | Should -Be @('si-management:src-2', 'si-orchestrator:v4-aaa')
        @($rec.Previous | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ }) | Should -Be @('si-management:src-1', 'si-orchestrator:v3-bbb')
        $row = $script:Rows['ImagePrune']; $row.Length | Should -BeLessOrEqual 400
        $j = $row | ConvertFrom-Json
        $j.done | Should -BeTrue; $j.deleted | Should -Be 4; $j.left.'si-orchestrator' | Should -Be 2
    }
    It 'the step keeps what the last record names as the release running before, and writes the record also when it prunes nothing' {
        $f = New-StandardRegistry
        Mock Write-UpdLog { }
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
        $old = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.9' -Current @((Snap @('si-orchestrator:v2-ccc')).Refs)
        $script:Written = @{}
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                   -Registry $f.Seam -Get { param($n) '' } -ReadSecret { param($n) $old }.GetNewClosure() -WriteSecret { param($n, $v) $script:Written[$n] = $v }
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v2'
        # previous not recorded: nothing pruned, but the record of THIS release is written for the next update
        $f2 = New-StandardRegistry; $script:Written = @{}
        $r2 = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (Snap @() -Ok $false -Reason 'x') -After (& $script:Cur) `
                   -Version '3.1.11' -Registry $f2.Seam -Get { param($n) '' } -ReadSecret { param($n) $null } -WriteSecret { param($n, $v) $script:Written[$n] = $v }
        $r2.Done | Should -BeFalse
        $f2.Deleted.Count | Should -Be 0
        (ConvertFrom-SIUpdaterReleaseImageRecord -Json $script:Written['SI-Release-Images']).CurrentVersion | Should -Be '3.1.11'
    }
    It 'the step never throws: a registry that cannot be found = a warning, every image kept' {
        $script:Log = New-Object System.Collections.Generic.List[string]
        Mock Write-UpdLog { $script:Log.Add($m) }
        Mock Get-SIUpdaterRegistry { throw 'the container registry was not found' }
        { Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -Get { param($n) '' } } | Should -Not -Throw
        ($script:Log -join "`n") | Should -Match 'WARNING: old images: not cleaned up this time .* every image is kept'
    }
}

Describe 'IMAGE-PRUNE: a long clean-up stays alive and says what it did as it goes (live 2026-11-12: stopped as dead after 15 minutes)' {
    It 'beats at every registry call -- every list, manifest read and delete' {
        $f = New-StandardRegistry
        $script:Beats = New-Object System.Collections.Generic.List[string]
        $script:Seq = New-Object System.Collections.Generic.List[string]
        $seq = $script:Seq
        foreach ($k in 'List', 'Manifest', 'Delete') {
            $orig = $f.Seam[$k]
            $f.Seam[$k] = { $seq.Add('CALL'); & $orig @args }.GetNewClosure()
        }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -BeatSeconds 0 -Beat { param($w) $script:Seq.Add("BEAT $w") }
        # one beat right before EVERY registry call
        $calls = @(for ($i = 0; $i -lt $script:Seq.Count; $i++) { if ($script:Seq[$i] -eq 'CALL') { $i } })
        $calls.Count | Should -Be $f.Calls.Count
        foreach ($i in $calls) { $script:Seq[$i - 1] | Should -BeLike 'BEAT *' -Because 'a beat comes right before every registry call' }
        @($script:Seq | Where-Object { $_ -like 'BEAT deleting si-orchestrator (* of 2)' }).Count | Should -Be 2
    }
    It 'a beat is TRIED at most once per -BeatSeconds, also when it fails (a slow or unreachable database never slows the clean-up to hours)' {
        $f = New-StandardRegistry
        $script:Tries = 0
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -BeatSeconds 3600 -Beat { $script:Tries++; throw 'database unreachable' }
        $script:Tries | Should -Be 1
        $r.Done | Should -BeTrue; $f.Deleted.Count | Should -Be 4
    }
    It 'the step''s beat asks the lock for a beat every 30 seconds at most (with the 15-second try limit: at least once a minute)' {
        $f = New-StandardRegistry
        Mock Write-UpdLog { }
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
        Mock Invoke-SIUpdaterLockBeat { $true }
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                    -Version '3.1.13' -PreviousVersion '3.1.12' -Registry $f.Seam -Get { param($n) '' } -WriteSecret { param($n, $v) }
        Should -Invoke Invoke-SIUpdaterLockBeat -ParameterFilter { $MinSeconds -eq 30 }
    }
    It 'counts the child manifests of a kept multi-platform image apart, and "n of N" leaves locked images out' {
        $f = New-FakeRegistry @{
            'si-orchestrator' = @(
                (M 'orch-v4' @('v4-aaa') @() @('orch-v4-amd64', 'orch-v4-arm64')),
                (M 'orch-v4-amd64' @() @('L0', 'L4')), (M 'orch-v4-arm64' @() @('L0', 'L4a')),
                (M 'orch-v3' @('v3-bbb') @('L0', 'L3')),
                (M 'orch-v2' @('v2-ccc') @('L0', 'L2')),
                (M 'orch-v1' @('v1-ddd') @('L0', 'L1') -DeleteEnabled $false))
        }
        $script:Seq = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (Snap @('si-orchestrator:v4-aaa')) -Previous (Snap @('si-orchestrator:v3-bbb')) `
                 -BeatSeconds 0 -Beat { param($w) $script:Seq.Add($w) } -Log { param($l) $script:Seq.Add($l) }
        $script:Seq | Should -Contain 'si-orchestrator: 6 images, 4 kept (2 of them child manifests of multi-platform images), 2 to delete'
        @($script:Seq | Where-Object { $_ -like 'deleting si-orchestrator (*' }) | Should -Be @('deleting si-orchestrator (1 of 1)')
        $o = @($r.Repos | Where-Object { $_.Repo -eq 'si-orchestrator' })[0]
        $o.Kept | Should -Be 4; $o.Children | Should -Be 2; $o.Deleted | Should -Be 1
        ($o.Line) | Should -Match '1 locked against deletion'
    }
    It 'each repository''s plan is written before its deletes and its result right after, before the next repository' {
        $f = New-StandardRegistry
        $script:Seq = New-Object System.Collections.Generic.List[string]
        $f.Seam.Delete = { param($Repo, $Digest) $script:Seq.Add("DELETE $Repo"); [pscustomobject]@{ Ok = $true; Status = 202; Why = '' } }
        $null = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -Log { param($l) $script:Seq.Add("LOG $l") } -Sleep { param($s) }
        $o = @($script:Seq | Where-Object { $_ -like '*si-orchestrator*' })
        $o[0] | Should -Be 'LOG si-orchestrator: 4 images, 2 kept, 2 to delete'
        $o[1] | Should -Be 'DELETE si-orchestrator'; $o[2] | Should -Be 'DELETE si-orchestrator'
        $o[3] | Should -BeLike 'LOG si-orchestrator: 2 old images deleted*'
        # plan, result, plan, result ... -- a repository's result is written before the next repository starts
        $logs = @($script:Seq | Where-Object { $_ -like 'LOG *' })
        $logs.Count | Should -Be 6
        for ($i = 0; $i -lt $logs.Count; $i += 2) {
            $logs[$i] | Should -BeLike '* to delete'
            $logs[$i + 1] | Should -BeLike '* deleted*'
            ($logs[$i] -split ':')[0] | Should -Be ($logs[$i + 1] -split ':')[0]
        }
    }
    It 'a beat or a log line that fails never stops the clean-up' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -Beat { throw 'lock table gone' } -Log { throw 'log gone' }
        $r.Done | Should -BeTrue
        $f.Deleted.Count | Should -Be 4
        @($r.Lines) | Should -Contain 'si-orchestrator: 2 old images deleted, 2 left (this release and the one before)'
    }
    It 'the step beats the update''s own sign of life through Invoke-SIUpdaterLockBeat and writes each line once' {
        $f = New-StandardRegistry
        $script:Log = New-Object System.Collections.Generic.List[string]
        Mock Write-UpdLog { $script:Log.Add($m) }
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
        Mock Invoke-SIUpdaterLockBeat { $true }
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                    -Version '3.1.13' -PreviousVersion '3.1.12' -Registry $f.Seam -Get { param($n) '' } -WriteSecret { param($n, $v) }
        Should -Invoke Invoke-SIUpdaterLockBeat -ParameterFilter { $What -like 'old images: *' }
        @($script:Log | Where-Object { $_ -like 'si-base: *deleted*' }).Count | Should -Be 1
        @($script:Log | Where-Object { $_ -eq 'old images: 4 deleted in 3 repositories' }).Count | Should -Be 1
    }
}

Describe 'IMAGE-PRUNE CONTRACT point 5: the release record is written BEFORE the first delete' {
    BeforeEach {
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
        $script:Log = New-Object System.Collections.Generic.List[string]
        Mock Write-UpdLog { $script:Log.Add($m) }
    }
    It 'the record (this release + the one before, no result yet) is written before any delete; then again with what was done' {
        $f = New-StandardRegistry
        $script:Seq = New-Object System.Collections.Generic.List[string]
        $seq = $script:Seq; $origDelete = $f.Seam.Delete
        $f.Seam.Delete = { param($Repo, $Digest) $seq.Add('DELETE'); & $origDelete $Repo $Digest }.GetNewClosure()
        $script:Written = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                    -Version '3.1.13' -PreviousVersion '3.1.12' -Registry $f.Seam -Get { param($n) '' } -WriteSecret { param($n, $v) $script:Seq.Add('RECORD'); $script:Written.Add($v) }
        $script:Seq.IndexOf('RECORD') | Should -Be 0 -Because 'the record comes before the first delete'
        $script:Seq.IndexOf('DELETE') | Should -BeGreaterThan 0
        @($script:Seq | Where-Object { $_ -eq 'RECORD' }).Count | Should -Be 2
        $first = $script:Written[0] | ConvertFrom-Json
        $first.current.version | Should -Be '3.1.13'; $first.previous.version | Should -Be '3.1.12'
        $first.PSObject.Properties['prune'] | Should -BeNullOrEmpty -Because 'nothing was done yet when it was written'
        ($script:Written[1] | ConvertFrom-Json).prune.done | Should -BeTrue
    }
    It 'NEGATIVE: the record cannot be written -> NOTHING is deleted, said once' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                 -Version '3.1.13' -PreviousVersion '3.1.12' -Registry $f.Seam -Get { param($n) '' } -WriteSecret { param($n, $v) throw 'vault refused' }
        $r.Done | Should -BeFalse
        $f.Deleted.Count | Should -Be 0
        @($f.Calls | Where-Object { $_ -like 'DELETE*' }).Count | Should -Be 0
        @($script:Log | Where-Object { $_ -like 'old images: not cleaned up -- the release record could not be written before the deletes*' }).Count | Should -Be 1
    }
    It 'the second record write (with what was done) fails: the deletes stand, the first record stands, said once, the step does not throw' {
        $f = New-StandardRegistry
        $script:Writes = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                 -Version '3.1.13' -PreviousVersion '3.1.12' -Registry $f.Seam -Get { param($n) '' } `
                 -WriteSecret { param($n, $v) if ($script:Writes.Count -ge 1) { throw 'vault refused the second write' }; $script:Writes.Add($v) }
        $r.Done | Should -BeTrue
        $f.Deleted.Count | Should -Be 4
        $script:Writes.Count | Should -Be 1
        ($script:Writes[0] | ConvertFrom-Json).current.version | Should -Be '3.1.13'
        @($script:Log | Where-Object { $_ -like 'NOTE: old images: what the clean-up did could not be added to the release record*' }).Count | Should -Be 1
    }
    It 'NEGATIVE: no place to write the record -> nothing is deleted' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (& $script:Prev) -After (& $script:Cur) `
                 -Version '3.1.13' -Registry $f.Seam -Get { param($n) '' }
        $r.Done | Should -BeFalse
        $f.Deleted.Count | Should -Be 0
        @($script:Log | Where-Object { $_ -like '*no place to write the release record*' }).Count | Should -Be 1
    }
    It 'an early "not cleaned up" (the previous release not recorded) goes through the step and is logged exactly once' {
        $f = New-StandardRegistry
        $null = Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before (Snap @() -Ok $false -Reason 'x') -After (& $script:Cur) `
                    -Version '3.1.13' -Registry $f.Seam -Get { param($n) '' } -ReadSecret { param($n) $null } -WriteSecret { param($n, $v) }
        @($script:Log | Where-Object { $_ -like 'old images: not cleaned up -- the images of the previous release are not recorded*' }).Count | Should -Be 1
        $f.Deleted.Count | Should -Be 0
    }
    It 'the plan line is said live but is not one of the result lines' {
        $f = New-StandardRegistry
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current (& $script:Cur) -Previous (& $script:Prev) -Log { param($l) }
        @($r.Lines | Where-Object { $_ -like '* to delete' }).Count | Should -Be 0
    }
}

Describe 'IMAGE-PRUNE: the same release again keeps the release before it (second pass after the self-roll, a re-run)' {
    BeforeAll {
        # the standard registry as releases: v4 / src-2 = 3.1.10, v3 / src-1 = 3.1.9, v2 = 3.1.8, v1 + src-0 older
        $script:R10 = { @((Snap @('si-orchestrator:v4-aaa', 'si-management:src-2')).Refs) }
        $script:R9 = { @((Snap @('si-orchestrator:v3-bbb', 'si-management:src-1')).Refs) }
        $script:R8 = { @((Snap @('si-orchestrator:v2-ccc')).Refs) }
        function script:Invoke-Step($Registry, $Before, $After, [string]$Version, [string]$PreviousVersion = '', [AllowNull()][string]$Record) {
            $script:Vault = @{}; if ("$Record".Trim()) { $script:Vault['SI-Release-Images'] = $Record }
            Invoke-SIUpdaterImagePruneStep -ResourceGroup 'rg-si' -AcrName 'acrsi' -SubscriptionId 'sub' -Healthy $true -Before $Before -After $After `
                -Version $Version -PreviousVersion $PreviousVersion -Registry $Registry -Get { param($n) '' } `
                -ReadSecret { param($n) $script:Vault[$n] } -WriteSecret { param($n, $v) $script:Vault[$n] = $v }
        }
    }
    BeforeEach {
        $script:Log = New-Object System.Collections.Generic.List[string]
        Mock Write-UpdLog { $script:Log.Add($m) }
        Mock Get-SIUpdaterRegistry { [pscustomobject]@{ id = 'x'; name = 'acrsi'; resourceGroup = 'rg-si'; loginServer = 'acrsi.azurecr.io' } }
    }
    It 'the second pass after the self-roll: 3.1.9 (the record''s previous) is kept although the read before the roll is 3.1.10 itself' {
        $f = New-StandardRegistry
        $rec = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.10' -Current (& $script:R10) -PreviousVersion '3.1.9' -Previous (& $script:R9)
        $r = Invoke-Step $f.Seam (& $script:Cur) (& $script:Cur) '3.1.10' '3.1.10' $rec
        $r.Done | Should -BeTrue
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v3'
        @($f.Deleted) | Should -Not -Contain 'si-management/web-s1'
        @($f.Deleted | Sort-Object) | Should -Be @(@('si-base/base-h0', 'si-management/web-s0', 'si-orchestrator/orch-v1', 'si-orchestrator/orch-v2') | Sort-Object)
    }
    It 'a re-run of the same release keeps the previous one, also when the read before the roll differs' {
        $f = New-StandardRegistry
        $rec = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.10' -Current (& $script:R10) -PreviousVersion '3.1.9' -Previous (& $script:R9)
        $null = Invoke-Step $f.Seam (Snap @('si-management:src-2')) (& $script:Cur) '3.1.10' '' $rec
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v3'
        @($f.Deleted) | Should -Contain 'si-orchestrator/orch-v2'
    }
    It 'NEGATIVE: the same release with no record = nothing deleted, and it says the previous release is not known' {
        $f = New-StandardRegistry
        $r = Invoke-Step $f.Seam (& $script:Cur) (& $script:Cur) '3.1.10' '3.1.10' $null
        $r.Done | Should -BeFalse
        $f.Deleted.Count | Should -Be 0
        ($script:Log -join "`n") | Should -Match 'the previous release is not known'
        # a record of this release WITHOUT its previous release is the same: nothing deleted
        $f2 = New-StandardRegistry
        $rec = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.10' -Current (& $script:R10)
        (Invoke-Step $f2.Seam (& $script:Cur) (& $script:Cur) '3.1.10' '' $rec).Done | Should -BeFalse
        $f2.Deleted.Count | Should -Be 0
    }
    It 'NEGATIVE: the same images before and after with no record (version unknown) = nothing deleted' {
        $f = New-StandardRegistry
        (Invoke-Step $f.Seam (& $script:Cur) (& $script:Cur) '' '' $null).Done | Should -BeFalse
        $f.Deleted.Count | Should -Be 0
    }
    It 'the record''s previous survives re-runs: never replaced by the release itself' {
        $f = New-StandardRegistry
        $rec = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.10' -Current (& $script:R10) -PreviousVersion '3.1.9' -Previous (& $script:R9)
        $null = Invoke-Step $f.Seam (& $script:Cur) (& $script:Cur) '3.1.10' '3.1.10' $rec
        $after1 = $script:Vault['SI-Release-Images']
        $null = Invoke-Step $f.Seam (& $script:Cur) (& $script:Cur) '3.1.10' '3.1.10' $after1
        $r = ConvertFrom-SIUpdaterReleaseImageRecord -Json $script:Vault['SI-Release-Images']
        $r.CurrentVersion | Should -Be '3.1.10'
        $r.PreviousVersion | Should -Be '3.1.9'
        @($r.Previous | ForEach-Object { Format-SIUpdaterImageRef -Ref $_ }) | Should -Be @(@('si-management:src-1', 'si-orchestrator:v3-bbb') | Sort-Object -Unique)
        @($f.Repos['si-orchestrator'] | ForEach-Object { $_.Name }) | Should -Be @('orch-v4', 'orch-v3')
    }
    It 'NEGATIVE: a normal update (record current 3.1.9, now 3.1.10) still deletes 3.1.8, and records 3.1.9 as the previous' {
        $f = New-StandardRegistry
        $rec = ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.9' -Current (& $script:R9) -PreviousVersion '3.1.8' -Previous (& $script:R8)
        $r = Invoke-Step $f.Seam (& $script:Prev) (& $script:Cur) '3.1.10' '3.1.9' $rec
        $r.Done | Should -BeTrue
        @($f.Deleted) | Should -Contain 'si-orchestrator/orch-v2'
        @($f.Deleted) | Should -Not -Contain 'si-orchestrator/orch-v3'
        $w = ConvertFrom-SIUpdaterReleaseImageRecord -Json $script:Vault['SI-Release-Images']
        $w.CurrentVersion | Should -Be '3.1.10'; $w.PreviousVersion | Should -Be '3.1.9'
    }
    It 'the same-release rule itself' {
        $rec = ConvertFrom-SIUpdaterReleaseImageRecord -Json (ConvertTo-SIUpdaterReleaseImageRecord -Version '3.1.10' -Current (& $script:R10))
        (Test-SIUpdaterSameRelease -Record $rec -Version '3.1.10' -Before (& $script:Prev) -After (& $script:Cur)) | Should -BeTrue
        (Test-SIUpdaterSameRelease -Record $rec -Version '3.1.11' -Before (& $script:Prev) -After (& $script:Cur)) | Should -BeFalse
        (Test-SIUpdaterSameRelease -Record $null -Version '3.1.11' -Before (& $script:Cur) -After (& $script:Cur)) | Should -BeTrue
        (Test-SIUpdaterSameRelease -Record $null -Version '' -Before (Snap @() -Ok $false) -After (& $script:Cur)) | Should -BeFalse
    }
}
Describe 'IMAGE-PRUNE WIRING: after the read-back, never before' {
    BeforeAll {
        $script:Inv = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
    }
    It 'the updater loads the clean-up and the image carries it' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $u | Should -Match "\. \(Join-Path \`$PSScriptRoot '_shared/SI-UpdaterImagePrune\.ps1'\)"
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile')) | Should -Match 'COPY container/updater/_shared/ \./_shared/'
        $u | Should -Match "ValidateSet\([^)]*'ImagePrune'" -Because 'the state row is an allowed name'
    }
    It 'what ran before is read BEFORE the roll; the clean-up runs only AFTER the post-roll, and only when it ended well' {
        $snap = $script:Inv.IndexOf('$imgBefore = Get-SIUpdaterImageSnapshot')
        $roll = $script:Inv.IndexOf('$roll = Invoke-SIUpdaterRoll ')
        $okRoll = $script:Inv.IndexOf('elseif ($roll.Code -eq 0) {')
        $post = $script:Inv.IndexOf('Invoke-SIUpdaterInvardiaPostRoll -SIRoot $si')
        $postFail = $script:Inv.IndexOf('if ($post.Code -ne 0) {')
        $guard = $script:Inv.IndexOf('if ($post.Code -eq 0) {')
        $step = $script:Inv.IndexOf('Invoke-SIUpdaterImagePruneStep -ResourceGroup')
        $seam = $script:Inv.IndexOf('& $s.ImagePrune $imgBefore')
        $failBranch = $script:Inv.IndexOf('$rc = [int]$roll.Code;')
        foreach ($i in $snap, $roll, $okRoll, $post, $postFail, $guard, $step, $seam, $failBranch) { $i | Should -BeGreaterThan 0 }
        $snap | Should -BeLessThan $roll
        $okRoll | Should -BeLessThan $post
        $post | Should -BeLessThan $postFail
        $postFail | Should -BeLessThan $guard
        $guard | Should -BeLessThan $seam
        $guard | Should -BeLessThan $step
        $step | Should -BeLessThan $failBranch -Because 'the clean-up sits in the branch of a roll that succeeded, never in the failed one'
        ([regex]::Matches($script:Inv, 'Invoke-SIUpdaterImagePruneStep -ResourceGroup')).Count | Should -Be 1 -Because 'one place only'
        ([regex]::Matches($script:Inv, '& \$s\.ImagePrune ')).Count | Should -Be 1 -Because 'one place only'
        $script:Inv.Substring($step, 400) | Should -Match '-Healthy \$true'
    }
    It 'the step runs with this update''s version and the version that ran before it' {
        $step = $script:Inv.IndexOf('Invoke-SIUpdaterImagePruneStep -ResourceGroup')
        $script:Inv.Substring($step, 600) | Should -Match '-Version "\$\(\$code\.Version\)" -PreviousVersion "\$Deployed"'
    }
}

Describe 'IMAGE-PRUNE: the read-back count is the count the registry ends at (its deletes complete after it answers them)' {
    # Live 2026-11-13: the result line said "3 left" right after the deletes while the registry ended at 2 -- a deleted image
    # was still listed for a moment. The listing is read again (short pauses, a sign of life before each) while an image the
    # registry took as deleted is still listed; still listed after the last re-read = "deletes still completing".
    BeforeAll {
        # one engine repository, current v4 + previous v3 kept, v2 + v1 deleted
        function script:New-OneRepo { New-FakeRegistry @{ 'si-orchestrator' = @((M 'orch-v4' @('v4-aaa') @('L0', 'L4')), (M 'orch-v3' @('v3-bbb') @('L0', 'L3')), (M 'orch-v2' @('v2-ccc') @('L0', 'L2')), (M 'orch-v1' @('v1-ddd') @('L0', 'L1'))) } }
        # the first deleted manifest stays listed for -Times listings after it was deleted (-1 = it never goes)
        function script:Add-Ghost($Fake, [int]$Times) {
            $state = @{ Ghost = $null; Left = $Times }
            $origList = $Fake.Seam.List; $origDel = $Fake.Seam.Delete
            $Fake.Seam.Delete = { param($Repo, $Digest) if (-not $state.Ghost) { $state.Ghost = [pscustomobject]@{ Digest = $Digest; Tags = @(); MediaType = ''; DeleteEnabled = $true } }; & $origDel $Repo $Digest }.GetNewClosure()
            $Fake.Seam.List = {
                param($Repo)
                $r = & $origList $Repo
                if ($state.Ghost -and $state.Left -ne 0) { $state.Left--; $r = [pscustomobject]@{ Found = $true; Manifests = @(@($r.Manifests) + @($state.Ghost)) } }
                $r
            }.GetNewClosure()
            $state
        }
        $script:One = @{ Current = (Snap @('si-orchestrator:v4-aaa')); Previous = (Snap @('si-orchestrator:v3-bbb')) }
    }
    BeforeEach {
        $script:Slept = New-Object System.Collections.Generic.List[int]
        $script:Beats = New-Object System.Collections.Generic.List[string]
    }
    It 'a deleted image still listed on the first re-read: read again after a short pause, and the line says the count it ends at' {
        $f = New-OneRepo; $null = Add-Ghost $f 1
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $script:One.Current -Previous $script:One.Previous `
                 -BeatSeconds 0 -Beat { param($w) $script:Beats.Add($w) } -Sleep { param($s) $script:Slept.Add($s) }
        $o = @($r.Repos)[0]
        $o.Deleted | Should -Be 2; $o.Left | Should -Be 2; $o.Pending | Should -Be 0
        $o.Line | Should -Be 'si-orchestrator: 2 old images deleted, 2 left (this release and the one before)'
        @($script:Slept) | Should -Be @(5) -Because 'one short pause before the one re-read that was needed'
        @($f.Calls | Where-Object { $_ -eq 'LIST si-orchestrator' }).Count | Should -Be 3 -Because 'the plan, the read-back, one re-read'
        $wi = $script:Beats.IndexOf('waiting for the deletes of si-orchestrator to complete')
        $wi | Should -BeGreaterOrEqual 0 -Because 'a sign of life before the pause'
        $script:Beats[$wi + 1] | Should -Be 'reading si-orchestrator' -Because 'and before the re-read'
        ($o.Line) | Should -Not -Match 'WARNING'
    }
    It 'the registry settled at once: no pause, no extra read (as before)' {
        $f = New-OneRepo
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $script:One.Current -Previous $script:One.Previous -Sleep { param($s) $script:Slept.Add($s) }
        $script:Slept.Count | Should -Be 0
        @($f.Calls | Where-Object { $_ -eq 'LIST si-orchestrator' }).Count | Should -Be 2
        @($r.Repos)[0].Left | Should -Be 2
    }
    It 'still listed after the last re-read: bounded (three pauses, 30 seconds in all), and said as deletes still completing with the count seen' {
        $f = New-OneRepo; $null = Add-Ghost $f -1
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $script:One.Current -Previous $script:One.Previous -Sleep { param($s) $script:Slept.Add($s) }
        @($script:Slept) | Should -Be @(5, 10, 15)
        @($f.Calls | Where-Object { $_ -eq 'LIST si-orchestrator' }).Count | Should -Be 5 -Because 'the plan, the read-back and three re-reads -- never more'
        $o = @($r.Repos)[0]
        $o.Left | Should -Be 3; $o.Pending | Should -Be 1
        $o.Line | Should -Be 'si-orchestrator: 2 old images deleted, 3 listed right after -- deletes still completing (1 of the deleted images still listed; the registry removes them shortly)'
        $o.Line | Should -Not -Match 'WARNING' -Because 'a delete still completing is not a lost image'
        $r.Done | Should -BeTrue
    }
    It 'a kept image missing stays the loud case, also while deletes are still completing' {
        $f = New-OneRepo; $null = Add-Ghost $f -1
        $origDel = $f.Seam.Delete; $w = $f
        $f.Seam.Delete = { param($Repo, $Digest) $res = & $origDel $Repo $Digest; $k = @($w.Repos[$Repo] | Where-Object { $_.Name -eq 'orch-v3' }) | Select-Object -First 1; if ($k) { $w.Repos[$Repo].Remove($k) }; $res }.GetNewClosure()
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $script:One.Current -Previous $script:One.Previous -Sleep { param($s) }
        @($r.Repos)[0].Line | Should -Match 'deletes still completing'
        @($r.Repos)[0].Line | Should -Match 'WARNING: 1 image\(s\) that should be kept are not there any more'
    }
    It 'a re-read that fails keeps what the read before it saw; a read-back that cannot be read at all is said as before' {
        $f = New-OneRepo; $null = Add-Ghost $f -1
        # (counted for the engine repository only: its base repository is listed too, between the plan and the read-back)
        $inner = $f.Seam.List; $n = @{ c = 0 }
        $f.Seam.List = { param($Repo) if ($Repo -eq 'si-orchestrator') { $n.c++; if ($n.c -ge 3) { throw 'HTTP 500' } }; & $inner $Repo }.GetNewClosure()
        $r = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f.Seam -Current $script:One.Current -Previous $script:One.Previous -Sleep { param($s) }
        $o = @($r.Repos)[0]; $o.Left | Should -Be 3; $o.Line | Should -Match '3 listed right after -- deletes still completing'
        $f2 = New-OneRepo; $inner2 = $f2.Seam.List; $n2 = @{ c = 0 }
        $f2.Seam.List = { param($Repo) if ($Repo -eq 'si-orchestrator') { $n2.c++; if ($n2.c -ge 2) { throw 'HTTP 500' } }; & $inner2 $Repo }.GetNewClosure()
        $r2 = Invoke-SIUpdaterImagePrune -On $true -Healthy $true -Registry $f2.Seam -Current $script:One.Current -Previous $script:One.Previous -Sleep { param($s) }
        @($r2.Repos)[0].Left | Should -Be -1
        @($r2.Repos)[0].Line | Should -Be 'si-orchestrator: 2 old images deleted; what is left could not be read back'
    }
}
Describe 'THE END OF AN UPDATE REACHES THE LOG: flush + a short, bounded pause on every way out of the updater' {
    # Found 2026-11-13 at the clean-up's proof: the last minutes of a finished update never arrived in Log Analytics -- the
    # container ended before its last lines were shipped. Start-SIUpdater.ps1 ends every execution with Complete-SIUpdaterOutput.
    BeforeAll {
        $script:UpdPath = Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'
        $script:UpdAst = [System.Management.Automation.Language.Parser]::ParseFile($script:UpdPath, [ref]$null, [ref]$null)
    }
    It 'flushes and pauses a fixed, bounded time: 15 s by default, never more than 30, none below 0; never throws' {
        $script:Paused = New-Object System.Collections.Generic.List[int]
        Complete-SIUpdaterOutput -Sleep { param($s) $script:Paused.Add($s) }
        Complete-SIUpdaterOutput -Seconds 600 -Sleep { param($s) $script:Paused.Add($s) }
        Complete-SIUpdaterOutput -Seconds -5 -Sleep { param($s) $script:Paused.Add($s) }
        @($script:Paused) | Should -Be @(15, 30)
        { Complete-SIUpdaterOutput -Sleep { throw 'interrupted' } } | Should -Not -Throw
        $src = $script:UpdAst.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Complete-SIUpdaterOutput' }, $true).Extent.Text
        $src | Should -Match ([regex]::Escape('[Console]::Out.Flush()'))
        $src | Should -Match ([regex]::Escape('[Console]::Error.Flush()'))
    }
    It 'WIRING: the one exit of the updater comes right after a try whose finally is the flush -- success, failure and a throw all pass it' {
        $exits = @($script:UpdAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
        $exits.Count | Should -Be 1 -Because 'one way out of the execution'
        $exits[0].Extent.Text | Should -Be 'exit $rc'
        $stmts = @($exits[0].Parent.Statements)
        $i = [array]::IndexOf($stmts, $exits[0])
        $i | Should -BeGreaterThan 0
        $i | Should -Be ($stmts.Count - 1) -Because 'the exit is the last statement'
        $try = $stmts[$i - 1]
        $try | Should -BeOfType ([System.Management.Automation.Language.TryStatementAst])
        $try.Finally | Should -Not -BeNullOrEmpty
        $try.Finally.Extent.Text | Should -Match '^\{\s*Complete-SIUpdaterOutput\s*\}$'
        # the whole execution is inside that try: the run (its own catch = the failure path) and every step after it
        foreach ($s in '$rc = Invoke-SIUpdater', 'Write-UpdLog ("FAILED: {0}"', 'Stop-SIUpdateTrack -ExitCode $rc', 'Invoke-SIUpdaterFailureReport -ExitCode $rc', 'Unregister-SIUpdaterExecutionBeat') {
            $try.Body.Extent.Text.Contains($s) | Should -BeTrue -Because "$s runs inside the try the flush closes"
        }
        @($script:UpdAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Complete-SIUpdaterOutput' }, $true)).Count | Should -Be 1 -Because 'once, at the end only'
    }
    It 'WIRING: nothing else ends the process before it (no exit and no Environment.Exit in the updater''s files)' {
        $files = @(Get-ChildItem -Path (Join-Path $script:SIRoot 'container\updater') -Filter '*.ps1' -Recurse)
        $files.Count | Should -BeGreaterThan 3
        foreach ($fl in $files) {
            $a = [System.Management.Automation.Language.Parser]::ParseFile($fl.FullName, [ref]$null, [ref]$null)
            $n = @($a.FindAll({ param($x) $x -is [System.Management.Automation.Language.ExitStatementAst] }, $true)).Count
            if ($fl.Name -eq 'Start-SIUpdater.ps1') { $n | Should -Be 1 } else { $n | Should -Be 0 -Because $fl.FullName }
            [IO.File]::ReadAllText($fl.FullName) | Should -Not -Match 'Environment\]::Exit\(' -Because $fl.FullName
        }
    }
}