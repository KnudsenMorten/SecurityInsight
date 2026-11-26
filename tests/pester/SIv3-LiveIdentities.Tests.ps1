#Requires -Version 5.1
<#
    #1413 ONLY LIVE USER-ASSIGNED IDENTITIES (setup\_shared\SI-LiveIdentities.ps1). Found read-only at a customer install 2026-11-26: the
    updater built new job bodies by copying EVERY identity key of a source job, and the source jobs still listed identities
    deleted from the resource group -- the PUT was refused ("FailedIdentityOperation ... uami-si-updater was not found" on
    caj-si-image-check, "... id-si-prod-pro-ca was not found" on caj-si-job-requests).
    What must hold:
      * the copy filter: a dead key of the resource group is dropped (one line), a live one kept, compared case-insensitively,
        another resource group's identity kept; the list not read (or not completely) = the body as before; the fingerprint
        follows the filtered body and is stable; the four call sites pass the list;
      * the clean-up: nothing removed without a complete list; only a 404 on the identity's own GET is "dead" (403 / 500 keep
        it); a dead identity still used (registry, secret, sign-in) = the resource is not touched, a WARNING and a problem;
        an identity-only PATCH (live keys {} + the dead key null); one line per removed reference; read back (an app: its new
        revision ready); a read back that still shows it = a problem.
    Offline, against a fake REST seam. The resource shapes follow that install's read of 2026-11-26.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-LiveIdentities.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ImageCheckJob.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-MissingJobs.ps1')
    # the updater's serving check (Test-SIUpdaterRevisionServing) is what the clean-up waits on for an app
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1')
    $script:Sub = '42f21bfd-0000-0000-0000-000000000001'; $script:Rg = 'rg-si-prod-pro-ca'
    # ARM lists ids with "resourcegroups" in lower case; jobs carry "resourceGroups" -- the same id
    $script:IdBase = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' -f $script:Sub, $script:Rg
    $script:JobBase = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' -f $script:Sub, $script:Rg
    function script:Id([string]$Name, [switch]$JobCase) { if ($JobCase) { $script:JobBase + $Name } else { $script:IdBase + $Name } }
    $script:LiveNames = @('id-si-engine', 'id-si-updater', 'id-si-tagging', 'id-si-web', 'id-si-mcp', 'id-si-dbinit')
    $script:DeadNames = @('id-si-prod-pro-ca', 'uami-si-updater', 'uami-securityinsight-tagging', 'uami-si-management', 'uami-si-mcp')

    function script:New-Res([string]$Name, [string[]]$Ids, [string]$Kind = 'job', [string]$RegistryId = '', [hashtable]$ClientIds = @{}, [object[]]$Env = @(), [object[]]$Secrets = @()) {
        $ua = [ordered]@{}; foreach ($i in $Ids) { $ua[$i] = [pscustomobject]@{ clientId = $(if ($ClientIds.ContainsKey($i)) { $ClientIds[$i] } else { 'cid-' + ($i -split '/')[-1] }); principalId = 'p' } }
        $reg = if ($RegistryId) { @([pscustomobject]@{ server = 'acrsi.azurecr.io'; identity = $RegistryId }) } else { @() }
        $p = [ordered]@{ provisioningState = 'Succeeded'; environmentId = '/subs/cae'
                         configuration = [pscustomobject]@{ registries = $reg; secrets = $Secrets }
                         template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = $Name; image = 'acrsi.azurecr.io/si:v1'; env = $Env }) } }
        if ($Kind -eq 'app') { $p.latestRevisionName = "$Name--r1"; $p.latestReadyRevisionName = "$Name--r1" }
        [pscustomobject]@{ name = $Name; location = 'westeurope'; tags = [pscustomobject]@{ product = 'securityinsight' }
                           identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]$ua }; properties = [pscustomobject]$p }
    }
    function script:New-World([object[]]$Jobs = @(), [object[]]$Apps = @(), [string[]]$Live = $script:LiveNames, [hashtable]$Fail = @{}) {
        $w = [pscustomobject]@{ Jobs = [ordered]@{}; Apps = [ordered]@{}; Live = @($Live); Fail = $Fail; Calls = (New-Object System.Collections.Generic.List[string]); Patches = (New-Object System.Collections.Generic.List[object]); AppReadsAfterPatch = 0 }
        foreach ($j in $Jobs) { $w.Jobs[$j.name] = ($j | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
        foreach ($a in $Apps) { $w.Apps[$a.name] = ($a | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
        $w
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        $ok = { param($s, $o) [pscustomobject]@{ Status = $s; Body = $(if ($null -eq $o) { '' } elseif ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 30 -Compress }) } }
        # the resource group's identity list (two pages)
        if ($Method -eq 'GET' -and $Uri -match '/userAssignedIdentities\?api-version=') {
            if ($w.Fail.list) { return (& $ok ([int]$w.Fail.list) '{"error":{"code":"AuthorizationFailed"}}') }
            $all = @($w.Live | ForEach-Object { @{ id = (Id $_); name = $_ } })
            $half = [Math]::Ceiling($all.Count / 2)
            if ($Uri -notmatch 'page=2') { $pg = @{ value = @($all | Select-Object -First $half); nextLink = ($Uri + '&page=2') }; if ($w.Fail.endless) { $pg.nextLink = $Uri }; return (& $ok 200 $pg) }
            if ($w.Fail.page2) { return (& $ok 500 'boom') }
            return (& $ok 200 @{ value = @($all | Select-Object -Skip $half) })
        }
        # one identity
        $mi = [regex]::Match($Uri, '/userAssignedIdentities/([^/?]+)\?')
        if ($Method -eq 'GET' -and $mi.Success) {
            $n = $mi.Groups[1].Value
            if ($w.Fail.ContainsKey('id:' + $n)) { return (& $ok ([int]$w.Fail['id:' + $n]) 'nope') }
            if ($w.Live -contains $n) { return (& $ok 200 @{ id = (Id $n); name = $n }) }
            return (& $ok 404 '{"error":{"code":"ResourceNotFound"}}')
        }
        $rv = [regex]::Match($Uri, '/containerApps/([^/?]+)/revisions/([^/?]+)\?')
        if ($Method -eq 'GET' -and $rv.Success) {
            if ($w.Fail.unhealthy) { return (& $ok 200 @{ name = $rv.Groups[2].Value; properties = @{ runningState = 'Running'; healthState = 'Unhealthy'; provisioningState = 'Provisioned' } }) }
            return (& $ok 200 @{ name = $rv.Groups[2].Value; properties = @{ runningState = 'Running'; healthState = 'Healthy'; provisioningState = 'Provisioned' } })
        }
        foreach ($kind in 'jobs', 'containerApps') {
            $store = if ($kind -eq 'jobs') { $w.Jobs } else { $w.Apps }
            if ($Method -eq 'GET' -and $Uri -match ('/providers/Microsoft\.App/{0}\?api-version=' -f $kind)) { return (& $ok 200 @{ value = @($store.Values) }) }
            $m = [regex]::Match($Uri, ('/providers/Microsoft\.App/{0}/([^/?]+)\?' -f $kind))
            if (-not $m.Success) { continue }
            $n = $m.Groups[1].Value
            if (-not $store.Contains($n)) { return (& $ok 404 'not found') }
            if ($Method -eq 'GET') {
                if ($kind -eq 'containerApps' -and $w.AppReadsAfterPatch -gt 0) { $w.AppReadsAfterPatch--; $x = ($store[$n] | ConvertTo-Json -Depth 30 | ConvertFrom-Json); $x.properties.latestReadyRevisionName = "$n--r1"; return (& $ok 200 $x) }
                return (& $ok 200 $store[$n])
            }
            if ($Method -eq 'PATCH') {
                $b = $Body | ConvertFrom-Json
                $w.Patches.Add([pscustomobject]@{ Name = $n; Body = $b; Text = [string]$Body })
                if ($w.Fail.patch -or ($w.Fail.refuse -and @($w.Fail.refuse) -contains $n)) { return (& $ok 400 'refused') }
                if (-not $w.Fail.ignore) {
                    # JSON merge patch: a null key is removed, the others kept
                    $cur = $store[$n]; $ua = [ordered]@{}
                    foreach ($p in @($cur.identity.userAssignedIdentities.PSObject.Properties)) { $ua[$p.Name] = $p.Value }
                    foreach ($p in @($b.identity.userAssignedIdentities.PSObject.Properties)) { if ($null -eq $p.Value) { $ua.Remove($p.Name) } elseif (-not $ua.Contains($p.Name)) { $ua[$p.Name] = $p.Value } }
                    $cur.identity.userAssignedIdentities = [pscustomobject]$ua
                    if ($kind -eq 'containerApps') { $cur.properties.latestRevisionName = "$n--r2"; $cur.properties.latestReadyRevisionName = "$n--r2"; $w.AppReadsAfterPatch = [int]$w.Fail.slowRevision }
                }
                return (& $ok 200 $store[$n])
            }
        }
        & $ok 404 'unknown'
    }
    function script:Read-Live { Read-SILiveIdentities -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg }
}

Describe 'the resource group''s identity list (Read-SILiveIdentities)' {
    It 'every page is read (nextLink); Ok, every id in the set' {
        $script:World = New-World
        $l = Read-Live
        $l.Ok | Should -BeTrue
        $l.Count | Should -Be $script:LiveNames.Count
        @($script:World.Calls | Where-Object { $_ -match 'userAssignedIdentities\?' }).Count | Should -Be 2
        $l.Ids.Contains((ConvertTo-SILiveIdentityKey (Id 'id-si-engine' -JobCase))) | Should -BeTrue -Because 'compared case-insensitively'
    }
    It 'NEGATIVE: the list refused (403) -> not Ok' {
        $script:World = New-World -Fail @{ list = 403 }
        (Read-Live).Ok | Should -BeFalse
    }
    It 'NEGATIVE: the second page fails -> not Ok (an incomplete list is no list)' {
        $script:World = New-World -Fail @{ page2 = 1 }
        (Read-Live).Ok | Should -BeFalse
    }
    It 'NEGATIVE: a list that never ends -> not Ok' {
        $script:World = New-World -Fail @{ endless = 1 }
        (Read-SILiveIdentities -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -MaxPages 3).Ok | Should -BeFalse
    }
    It 'NEGATIVE: the seam throws -> not Ok, never throws' {
        { $r = Read-SILiveIdentities -Rest { throw 'network down' } -SubscriptionId 's' -ResourceGroup 'r'; $r.Ok | Should -BeFalse } | Should -Not -Throw
    }
}

Describe 'the copy filter (Select-SILiveIdentityKeys, PURE)' {
    BeforeAll { $script:World = New-World; $script:L = Read-Live }
    It 'a dead key of the resource group is dropped with one line; the live one is kept' {
        $s = Select-SILiveIdentityKeys -Keys @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -Live $script:L -Name 'caj-si-job-requests'
        @($s.Keep) | Should -Be @((Id 'id-si-engine' -JobCase))
        @($s.Dropped) | Should -Be @((Id 'id-si-prod-pro-ca' -JobCase))
        @($s.Lines).Count | Should -Be 1
        $s.Lines[0] | Should -Match '^job caj-si-job-requests: identity id-si-prod-pro-ca no longer exists -- not carried'
    }
    It 'case-insensitive: a live key in any casing is kept' {
        $k = (Id 'ID-SI-ENGINE' -JobCase).ToUpperInvariant()
        @((Select-SILiveIdentityKeys -Keys @($k) -Live $script:L -Name 'x').Keep) | Should -Be @($k)
    }
    It 'an identity of ANOTHER resource group is always kept (the list does not cover it)' {
        $k = '/subscriptions/{0}/resourceGroups/rg-shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-shared' -f $script:Sub
        @((Select-SILiveIdentityKeys -Keys @($k) -Live $script:L -Name 'x').Keep) | Should -Be @($k)
    }
    It 'NEGATIVE: the list not read -> every key kept, no line' {
        $s = Select-SILiveIdentityKeys -Keys @((Id 'id-si-prod-pro-ca'), (Id 'id-si-engine')) -Live ([pscustomobject]@{ Ok = $false }) -Name 'x'
        @($s.Keep).Count | Should -Be 2; @($s.Lines).Count | Should -Be 0
        @((Select-SILiveIdentityKeys -Keys @((Id 'id-si-prod-pro-ca')) -Live $null -Name 'x').Keep).Count | Should -Be 1
    }
    It 'NEGATIVE: never an empty identity -- nothing live left = carried as before, a WARNING' {
        $s = Select-SILiveIdentityKeys -Keys @((Id 'uami-si-updater')) -Live $script:L -Name 'caj-si-image-check'
        @($s.Keep).Count | Should -Be 1; $s.Lines[0] | Should -Match '^WARNING'
    }
}

Describe 'call site 1: caj-si-image-check made from the updater (Get-SIImageCheckJobBody / Invoke-SIImageCheckJobEnsure)' {
    BeforeAll {
        $script:World = New-World
        $script:Upd = New-Res -Name 'caj-si-updater' -Ids @((Id 'uami-si-updater' -JobCase), (Id 'id-si-updater' -JobCase)) -RegistryId (Id 'id-si-updater' -JobCase)
        $script:Upd.properties.configuration | Add-Member -NotePropertyName triggerType -NotePropertyValue 'Schedule' -Force
    }
    It 'the deleted uami-si-updater is not carried; id-si-updater is; one line' {
        $b = Get-SIImageCheckJobBody -UpdaterJob $script:Upd -LiveIdentities (Read-Live)
        $b.Ok | Should -BeTrue
        @($b.Body.identity.userAssignedIdentities.Keys) | Should -Be @((Id 'id-si-updater' -JobCase))
        @($b.IdentityLines).Count | Should -Be 1; $b.IdentityLines[0] | Should -Match 'uami-si-updater no longer exists'
    }
    It 'NEGATIVE: the list not read -> both identities, as before (and the fingerprint as before)' {
        $old = Get-SIImageCheckJobBody -UpdaterJob $script:Upd
        $nr = Get-SIImageCheckJobBody -UpdaterJob $script:Upd -LiveIdentities ([pscustomobject]@{ Ok = $false })
        @($nr.Body.identity.userAssignedIdentities.Keys).Count | Should -Be 2
        $nr.Body.tags['si-image-check-spec'] | Should -Be $old.Body.tags['si-image-check-spec']
    }
    It 'the fingerprint follows the FILTERED body and is stable (same live set, any casing -> same hash)' {
        $a = Get-SIImageCheckJobBody -UpdaterJob $script:Upd -LiveIdentities (Read-Live)
        $b = Get-SIImageCheckJobBody -UpdaterJob $script:Upd -LiveIdentities (Read-Live)
        $a.Body.tags['si-image-check-spec'] | Should -Be $b.Body.tags['si-image-check-spec']
        $a.Body.tags['si-image-check-spec'] | Should -Not -Be (Get-SIImageCheckJobBody -UpdaterJob $script:Upd).Body.tags['si-image-check-spec']
        $only = New-Res -Name 'caj-si-updater' -Ids @((Id 'ID-SI-UPDATER' -JobCase)) -RegistryId (Id 'id-si-updater' -JobCase)
        (Get-SIImageCheckJobFingerprint -Body (Get-SIImageCheckJobBody -UpdaterJob $only).Body) | Should -Be (Get-SIImageCheckJobFingerprint -Body $a.Body)
    }
    It 'Invoke-SIImageCheckJobEnsure -Rest: the PUT carries only the live identity' {
        $put = $null
        $arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'PUT') { $script:IcPut = ($Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json); $script:IcPut.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force; return $script:IcPut }
                 if ($Path -like '*/caj-si-updater') { return $script:Upd }; if ($Path -like '*/caj-si-image-check') { return $script:IcPut }; $null }
        $script:IcPut = $null
        $r = Invoke-SIImageCheckJobEnsure -Arm $arm -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Rest $script:Rest -Sleep { }
        $r.Ok | Should -BeTrue
        @($script:IcPut.identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @((Id 'id-si-updater' -JobCase))
        $r.Reason | Should -Match 'uami-si-updater no longer exists'
    }
}

Describe 'call site 2: a missing job made from a donor (Get-SIMissingJobSpec / Invoke-SIMissingJobs)' {
    BeforeAll {
        $script:World = New-World
        $env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'asset-datasync' }, [pscustomobject]@{ name = 'SI_STORAGE_ACCOUNT'; value = 'stsi' }, [pscustomobject]@{ name = 'SI_UAMI_CLIENTID'; value = 'cid-id-si-engine' })
        $script:Donor = New-Res -Name 'caj-si-asset-datasync' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -RegistryId (Id 'id-si-engine' -JobCase) -Env $env
        $script:Donor.properties.configuration | Add-Member -NotePropertyName triggerType -NotePropertyValue 'Manual' -Force
    }
    It 'the --mi-user-assigned and the body carry only id-si-engine; one line' {
        $s = Get-SIMissingJobSpec -Engine 'verification' -Donor $script:Donor -ResourceGroup $script:Rg -Mode flow -LiveIdentities (Read-Live)
        $i = [array]::IndexOf([object[]]$s.Args, '--mi-user-assigned')
        $i | Should -BeGreaterThan -1
        $s.Args[$i + 1] | Should -Be (Id 'id-si-engine' -JobCase)
        @($s.Body.identity.userAssignedIdentities.Keys) | Should -Be @((Id 'id-si-engine' -JobCase))
        @($s.IdentityLines).Count | Should -Be 1
    }
    It 'NEGATIVE: no list -> both identities, as before' {
        $s = Get-SIMissingJobSpec -Engine 'verification' -Donor $script:Donor -ResourceGroup $script:Rg -Mode flow
        @($s.Body.identity.userAssignedIdentities.Keys).Count | Should -Be 2
    }
    It 'the job request job: its queue scaler never signs in as a deleted identity' {
        $only = New-Res -Name 'caj-si-asset-datasync' -Ids @((Id 'id-si-prod-pro-ca' -JobCase)) -Env @([pscustomobject]@{ name = 'SI_STORAGE_ACCOUNT'; value = 'stsi' })
        $live = [pscustomobject]@{ Ok = $true; Ids = (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)); Scope = (Get-SILiveIdentityScope -SubscriptionId $script:Sub -ResourceGroup $script:Rg) }
        $s = Get-SIMissingJobSpec -Engine 'job-requests' -Donor $only -ResourceGroup $script:Rg -Mode flow -LiveIdentities $live
        ($s.Body | ConvertTo-Json -Depth 30) | Should -Not -Match '"identity":\s*"[^"]*id-si-prod-pro-ca' -Because 'the scale rule must not name the deleted identity'
    }
    It 'Invoke-SIMissingJobs reads the list ONCE and the PUT carries only live identities' {
        $script:World = New-World
        $script:MjPuts = New-Object System.Collections.Generic.List[object]
        $rest = { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            if ($Uri -match '/userAssignedIdentities' -or $Uri -match '/Microsoft\.App/(jobs|containerApps)\?') { return (& $script:Rest $Method $Uri $Body $Resource $Headers) }
            if ($Method -eq 'PUT') { $j = $Body | ConvertFrom-Json; $script:MjPuts.Add($j); $j | Add-Member -NotePropertyName name -NotePropertyValue 'caj-si-verification' -Force; $j.properties | Add-Member -NotePropertyName provisioningState -NotePropertyValue 'Succeeded' -Force; $script:MjMade = $j; return [pscustomobject]@{ Status = 201; Body = ($j | ConvertTo-Json -Depth 30 -Compress) } }
            if ($Method -eq 'GET' -and $Uri -match '/jobs/caj-si-verification\?' -and $script:MjMade) { return [pscustomobject]@{ Status = 200; Body = ($script:MjMade | ConvertTo-Json -Depth 30 -Compress) } }
            [pscustomobject]@{ Status = 404; Body = 'not found' } }
        $script:MjMade = $null
        $donor = New-Res -Name 'caj-si-asset-datasync' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -RegistryId (Id 'id-si-engine' -JobCase) -Env @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'asset-datasync' })
        $donor.properties.configuration | Add-Member -NotePropertyName triggerType -NotePropertyValue 'Manual' -Force
        $donor.tags | Add-Member -NotePropertyName 'si-build' -NotePropertyValue '3.1.52' -Force
        $cat = @($script:SIMissingJobCatalog | Where-Object { $_.Engine -eq 'verification' })
        $r = Invoke-SIMissingJobs -Rest $rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Root $script:SIRoot -Jobs @($donor) -Catalog $cat -PollSeconds 0 -PollMax 1 -Conditions @{}
        @($r.Results | Where-Object { $_.Action -eq 'created' }).Count | Should -Be 1 -Because (@($r.Lines) -join ' | ')
        $script:MjPuts.Count | Should -Be 1
        @($script:MjPuts[0].identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @((Id 'id-si-engine' -JobCase))
        @($r.Lines | Where-Object { $_ -match 'id-si-prod-pro-ca no longer exists' }).Count | Should -Be 1
        @($script:World.Calls | Where-Object { $_ -match 'userAssignedIdentities\?api' -and $_ -notmatch 'page=2' }).Count | Should -Be 1
    }
}

Describe 'call site 3: the web app copy (New-SIUpdaterWebAppCopyBody)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterWebApp.ps1')
        $script:World = New-World
    }
    It 'a deleted identity is not carried into the new web app; the live one is; logged' {
        $app = New-Res -Name 'ca-si-management' -Kind app -Ids @((Id 'uami-si-management' -JobCase), (Id 'id-si-web' -JobCase))
        $logged = New-Object System.Collections.Generic.List[string]
        $b = New-SIUpdaterWebAppCopyBody -App $app -LiveIdentities (Read-Live) -Log { param($m) $logged.Add($m) }.GetNewClosure()
        @($b.identity.userAssignedIdentities.Keys) | Should -Be @((Id 'id-si-web' -JobCase))
        @($logged | Where-Object { $_ -match '^app ca-si-management: identity uami-si-management no longer exists' }).Count | Should -Be 1
    }
    It 'NEGATIVE: without the list -> both, as before' {
        $app = New-Res -Name 'ca-si-management' -Kind app -Ids @((Id 'uami-si-management' -JobCase), (Id 'id-si-web' -JobCase))
        @((New-SIUpdaterWebAppCopyBody -App $app).identity.userAssignedIdentities.Keys).Count | Should -Be 2
    }
}

Describe 'call site 4 (wiring): every builder that copies identities is given the list' {
    It 'the updater, the release''s update script, the missing jobs and the web app copy pass it' {
        $read = { param($p) [IO.File]::ReadAllText((Join-Path $script:SIRoot $p)) }
        (& $read 'container\updater\_shared\SI-UpdaterImageCheck.ps1') | Should -Match 'Invoke-SIImageCheckJobEnsure @ensure'
        (& $read 'container\updater\_shared\SI-UpdaterImageCheck.ps1') | Should -Match '\$ensure\.Rest = \$Rest'
        (& $read 'setup\Invoke-SIContainerUpdate.ps1') | Should -Match 'Invoke-SIImageCheckJobEnsure -Arm \$icArm [^\r\n]*-Rest \$rest'
        (& $read 'setup\_shared\SI-MissingJobs.ps1') | Should -Match 'Get-SIMissingJobSpec [^\r\n]*-LiveIdentities \$live'
        (& $read 'container\updater\_shared\SI-UpdaterWebApp.ps1') | Should -Match 'New-SIUpdaterWebAppCopyBody [^\r\n]*-LiveIdentities \$live'
    }
    It 'the clean-up runs after the job steps: in the update script after the nightly schedule (9n), in the updater after the image check job, and after an image check''s swap' {
        $read = { param($p) [IO.File]::ReadAllText((Join-Path $script:SIRoot $p)) }
        (& $read 'setup\Invoke-SIContainerUpdate.ps1') | Should -Match 'Invoke-SIUpdateNightlySchedule; \$null = Invoke-SIUpdateDeadIdentities;'
        $u = & $read 'container\updater\Start-SIUpdater.ps1'
        $u.IndexOf('Invoke-SIUpdaterDeadIdentities -SubscriptionId') | Should -BeGreaterThan $u.IndexOf('Invoke-SIUpdaterImageCheckJob -SubscriptionId $sub')
        (& $read 'container\updater\_shared\SI-UpdaterInvardia.ps1') | Should -Match "s\['DeadIdentities'\]"
    }
}

Describe 'the clean-up of existing jobs and apps (Invoke-SIDeadIdentityCleanup)' {
    BeforeEach {
        $script:Fleet = {
            param([hashtable]$Fail = @{}, [object[]]$ExtraJobs = @())
            $jobs = @(
                (New-Res -Name 'caj-si-asset-datasync' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -RegistryId (Id 'id-si-engine' -JobCase))
                (New-Res -Name 'caj-si-updater' -Ids @((Id 'uami-si-updater' -JobCase), (Id 'id-si-updater' -JobCase)) -RegistryId (Id 'id-si-updater' -JobCase) -Env @([pscustomobject]@{ name = 'SI_UPDATER_CLIENT_ID'; value = 'cid-id-si-updater' }))
                (New-Res -Name 'caj-si-asset-tagging' -Ids @((Id 'uami-securityinsight-tagging' -JobCase), (Id 'id-si-tagging' -JobCase)) -RegistryId (Id 'id-si-engine' -JobCase))
            ) + @($ExtraJobs)
            $apps = @(
                (New-Res -Name 'ca-si-management' -Kind app -Ids @((Id 'uami-si-management' -JobCase), (Id 'id-si-web' -JobCase)))
                (New-Res -Name 'ca-si-mcp' -Kind app -Ids @((Id 'uami-si-mcp' -JobCase), (Id 'id-si-mcp' -JobCase)))
            )
            New-World -Jobs $jobs -Apps $apps -Fail $Fail
        }
        $script:Clean = { param([switch]$WhatIf) Invoke-SIDeadIdentityCleanup -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Sleep { } -Polls 3 -WhatIf:$WhatIf }
    }
    It 'the found shape: the five dead references removed, one identity-only PATCH each, one line each, read back clean' {
        $script:World = & $script:Fleet
        $r = & $script:Clean
        $r.Ok | Should -BeTrue -Because (@($r.Lines) -join ' | ')
        @($r.Removed).Count | Should -Be 5
        $script:World.Patches.Count | Should -Be 5
        foreach ($p in $script:World.Patches) {
            @($p.Body.PSObject.Properties.Name) | Should -Be @('identity') -Because 'an identity-only PATCH, never a full body'
            $nulls = @($p.Body.identity.userAssignedIdentities.PSObject.Properties | Where-Object { $null -eq $_.Value })
            $nulls.Count | Should -Be 1 -Because 'the dead key goes as null (JSON merge patch)'
            ($nulls[0].Name -split '/')[-1] | Should -BeIn $script:DeadNames
            @($p.Body.identity.userAssignedIdentities.PSObject.Properties | Where-Object { $null -ne $_.Value }).Count | Should -Be 1 -Because 'the live key stays'
        }
        foreach ($n in $script:DeadNames) { @($r.Lines | Where-Object { $_ -match "the deleted identity $n taken off" }).Count | Should -BeGreaterThan 0 }
        @($r.Lines | Where-Object { $_ -match '^identities: read back' }).Count | Should -Be 1
        foreach ($j in @($script:World.Jobs.Values) + @($script:World.Apps.Values)) {
            foreach ($k in @($j.identity.userAssignedIdentities.PSObject.Properties.Name)) { ($k -split '/')[-1] | Should -BeIn $script:LiveNames }
        }
        @($script:World.Calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 0 -Because 'never a PUT'
    }
    It 'the updater''s own job: the dead uami-si-updater goes, the identity it signs in with (by client id) stays' {
        $script:World = & $script:Fleet
        $null = & $script:Clean
        @($script:World.Jobs['caj-si-updater'].identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @((Id 'id-si-updater' -JobCase))
    }
    It 'NEGATIVE: the list cannot be read -> NOTHING removed' {
        $script:World = & $script:Fleet @{ list = 403 }
        $r = & $script:Clean
        @($r.Removed).Count | Should -Be 0; $script:World.Patches.Count | Should -Be 0
        $r.Lines[0] | Should -Match 'nothing removed'
    }
    It 'NEGATIVE: an incomplete list (page 2 fails) -> NOTHING removed' {
        $script:World = & $script:Fleet @{ page2 = 1 }
        $r = & $script:Clean
        $script:World.Patches.Count | Should -Be 0
    }
    It 'NEGATIVE: 403 on the identity''s own GET -> kept (only a 404 is dead)' {
        $script:World = & $script:Fleet @{ 'id:id-si-prod-pro-ca' = 403 }
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-asset-datasync' }).Count | Should -Be 0
        @($r.Held | Where-Object { $_.Resource -eq 'caj-si-asset-datasync' }).Count | Should -Be 1
        @($r.Removed).Count | Should -Be 4
    }
    It 'NEGATIVE: 500 on the identity''s own GET -> kept' {
        $script:World = & $script:Fleet @{ 'id:uami-si-mcp' = 500 }
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'ca-si-mcp' }).Count | Should -Be 0
        @($r.Removed | Where-Object { $_.Resource -eq 'ca-si-mcp' }).Count | Should -Be 0
    }
    It 'NEGATIVE: the dead identity is the registry pull -> the job is NOT touched, a WARNING and a problem' {
        $bad = New-Res -Name 'caj-si-flow' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -RegistryId (Id 'id-si-prod-pro-ca' -JobCase)
        $script:World = & $script:Fleet @{} @($bad)
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-flow' }).Count | Should -Be 0
        $r.Ok | Should -BeFalse
        @($r.Problems | Where-Object { $_ -match '^WARNING: identities: caj-si-flow carries the deleted identity id-si-prod-pro-ca, NOT removed' }).Count | Should -Be 1
    }
    It 'NEGATIVE: the dead identity is a Key Vault secret''s identity -> not touched' {
        $bad = New-Res -Name 'caj-si-heartbeat' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -Secrets @([pscustomobject]@{ name = 's'; keyVaultUrl = 'https://kv/secrets/s'; identity = (Id 'id-si-prod-pro-ca' -JobCase) })
        $script:World = & $script:Fleet @{} @($bad)
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-heartbeat' }).Count | Should -Be 0
        $r.Ok | Should -BeFalse
    }
    It 'NEGATIVE: the job signs in with the dead identity (its client id is a setting) -> not touched' {
        $bad = New-Res -Name 'caj-si-ptc' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)) -Env @([pscustomobject]@{ name = 'SI_UAMI_CLIENTID'; value = 'cid-id-si-prod-pro-ca' })
        $script:World = & $script:Fleet @{} @($bad)
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-ptc' }).Count | Should -Be 0
        @($r.Problems | Where-Object { $_ -match 'caj-si-ptc' -and $_ -match 'signs in with it' }).Count | Should -Be 1
    }
    It 'NEGATIVE: only a dead identity on it -> not touched (never left without one)' {
        $bad = New-Res -Name 'caj-si-templates' -Ids @((Id 'id-si-prod-pro-ca' -JobCase))
        $script:World = & $script:Fleet @{} @($bad)
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-templates' }).Count | Should -Be 0
        @($r.Problems | Where-Object { $_ -match 'caj-si-templates' }).Count | Should -Be 1
    }
    It 'NEGATIVE: an identity of another resource group is never removed' {
        $other = '/subscriptions/{0}/resourceGroups/rg-shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-gone' -f $script:Sub
        $j = New-Res -Name 'caj-si-config-backup' -Ids @($other, (Id 'id-si-engine' -JobCase))
        $script:World = & $script:Fleet @{} @($j)
        $null = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-si-config-backup' }).Count | Should -Be 0
    }
    It 'a resource that is not SI''s is never touched' {
        $j = New-Res -Name 'caj-other-thing' -Ids @((Id 'id-si-prod-pro-ca' -JobCase), (Id 'id-si-engine' -JobCase)); $j.tags = [pscustomobject]@{ product = 'other' }
        $script:World = & $script:Fleet @{} @($j)
        $null = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'caj-other-thing' }).Count | Should -Be 0
    }
    It '-WhatIf: the plan only, no PATCH' {
        $script:World = & $script:Fleet
        $r = & $script:Clean -WhatIf
        $script:World.Patches.Count | Should -Be 0
        @($r.Lines | Where-Object { $_ -match 'would lose the deleted identity' }).Count | Should -Be 5
    }
    It 'NEGATIVE: the PATCH refused -> a problem, nothing claimed removed for it' {
        $script:World = & $script:Fleet @{ patch = 1 }
        $r = & $script:Clean
        $r.Ok | Should -BeFalse; @($r.Removed).Count | Should -Be 0
    }
    It 'NEGATIVE: the PATCH answered but Azure kept the key -> the read back is a LOUD problem' {
        $script:World = & $script:Fleet @{ ignore = 1 }
        $r = & $script:Clean
        $r.Ok | Should -BeFalse
        @($r.Problems | Where-Object { $_ -match 'did not read back|still a deleted identity' }).Count | Should -BeGreaterThan 0
    }
    It 'an app: its new revision is waited for until it is the latest READY one' {
        $script:World = & $script:Fleet @{ slowRevision = 2 }
        $r = & $script:Clean
        $r.Ok | Should -BeTrue -Because (@($r.Lines) -join ' | ')
        @($script:World.Calls | Where-Object { $_ -match '^GET .*/containerApps/ca-si-(mcp|management)\?' }).Count | Should -BeGreaterThan 2 -Because 'a revision not yet ready is read again'
    }
    It 'NEGATIVE: an app whose new revision never gets ready -> a problem' {
        $script:World = & $script:Fleet @{ slowRevision = 99 }
        $r = & $script:Clean
        $r.Ok | Should -BeFalse
        @($r.Problems | Where-Object { $_ -match 'ca-si-(management|mcp) did not read back' }).Count | Should -BeGreaterThan 0
    }
    It 'CANARY: the first change refused -> nothing else is PATCHed, one WARNING' {
        $script:World = & $script:Fleet @{ refuse = @('caj-si-asset-datasync') }
        $r = & $script:Clean
        $script:World.Patches.Count | Should -Be 1
        $script:World.Patches[0].Name | Should -Be 'caj-si-asset-datasync' -Because 'a job goes first, never the updater''s own while another exists'
        @($r.Removed).Count | Should -Be 0; $r.Ok | Should -BeFalse
        @($r.Problems | Where-Object { $_ -match 'canary' }).Count | Should -Be 1
        @($r.Problems | Where-Object { $_ -match 'still a deleted identity' }).Count | Should -Be 0 -Because 'the ones not sent are said once, as held'
    }
    It 'CANARY: Azure keeps the dead key on the first change -> nothing else is PATCHed, no long waits' {
        $script:World = & $script:Fleet @{ ignore = 1 }
        $sleeps = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIDeadIdentityCleanup -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Sleep { param($s) $sleeps.Add($s) }.GetNewClosure() -Polls 3
        $script:World.Patches.Count | Should -Be 1
        $sleeps.Count | Should -BeLessOrEqual 3
        @($r.Problems | Where-Object { $_ -match 'the canary\) did not read back' }).Count | Should -Be 1
    }
    It 'ONE wait budget for the whole step: the read backs stop when it is used up' {
        $script:World = & $script:Fleet @{ slowRevision = 999 }
        $sleeps = New-Object System.Collections.Generic.List[int]
        $r = Invoke-SIDeadIdentityCleanup -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Sleep { param($s) $sleeps.Add($s) }.GetNewClosure() -Polls 100 -MaxWaitSeconds 40
        (($sleeps | Measure-Object -Sum).Sum) | Should -BeLessOrEqual 40
        @($r.Problems | Where-Object { $_ -match 'wait of 40 s is used up' }).Count | Should -BeGreaterThan 0
    }
    It 'an app is done only when its new revision SERVES (Running, Healthy) -- an unhealthy one is a problem' {
        $script:World = & $script:Fleet @{ unhealthy = 1 }
        $r = & $script:Clean
        $r.Ok | Should -BeFalse
        @($r.Problems | Where-Object { $_ -match 'ca-si-(management|mcp) did not read back .*Unhealthy' }).Count | Should -BeGreaterThan 0
        @($r.Problems | Where-Object { $_ -match 'caj-si-' }).Count | Should -Be 0 -Because 'the jobs read back fine'
    }
    It 'an app with a fixed revision suffix is not touched (WARNING)' {
        $script:World = & $script:Fleet
        $script:World.Apps['ca-si-mcp'].properties.template | Add-Member -NotePropertyName revisionSuffix -NotePropertyValue 'v1' -Force
        $r = & $script:Clean
        @($script:World.Patches | Where-Object { $_.Name -eq 'ca-si-mcp' }).Count | Should -Be 0
        @($r.Problems | Where-Object { $_ -match 'ca-si-mcp.*fixed revision suffix' }).Count | Should -Be 1
    }
    It 'an identity that EXISTS (its GET 200) but is missing from the list: kept, one INFO line, not flagged in the read back' {
        $script:World = & $script:Fleet
        $script:World.Live = @($script:LiveNames | Where-Object { $_ -ne 'id-si-engine' })
        $script:World.Fail['id:id-si-engine'] = 200
        $r = & $script:Clean
        @($r.Lines | Where-Object { $_ -match 'id-si-engine is not on the resource group''s list but exists' }).Count | Should -BeGreaterThan 0
        @($r.Problems | Where-Object { $_ -match 'id-si-engine' }).Count | Should -Be 0
        @($r.Removed | Where-Object { ($_.Identity -split '/')[-1] -eq 'id-si-engine' }).Count | Should -Be 0
    }
    It 'SOFT problems: the list not readable, an identity answering 403 -- reported (Soft), not loud' {
        $script:World = & $script:Fleet @{ list = 500 }
        $r = & $script:Clean
        @($r.Soft).Count | Should -Be 1; $r.Ok | Should -BeTrue
        $script:World = & $script:Fleet @{ 'id:uami-si-mcp' = 403 }
        $r = & $script:Clean
        @($r.Soft | Where-Object { $_ -match 'ca-si-mcp keeps uami-si-mcp' }).Count | Should -Be 1
    }
    It 'the off-switch (SI_UPDATER_IDENTITY_CLEANUP): off / false / 0 / no = off; anything else, or not set = ON' {
        foreach ($v in 'off', 'OFF', 'false', '0', 'no', 'disabled') { Test-SIDeadIdentityCleanupOn $v | Should -BeFalse }
        foreach ($v in $null, '', 'on', 'true', '1') { Test-SIDeadIdentityCleanupOn $v | Should -BeTrue }
    }
    It 'the updater step: switched off = nothing called; the clean-up not loaded = a soft problem' {
        . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImageCheck.ps1')
        $script:World = & $script:Fleet
        function script:Write-UpdLog([string]$m) { }
        $null = Invoke-SIUpdaterDeadIdentities -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Rest $script:Rest -Switch 'off'
        $script:World.Calls.Count | Should -Be 0
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterImageCheck.ps1'))
        $src | Should -Match "& \`$soft 'identities: the clean-up of deleted identities is not in this image"
    }
    It 'nothing dead: no PATCH, one quiet line' {
        $script:World = New-World -Jobs @((New-Res -Name 'caj-si-flow' -Ids @((Id 'id-si-engine' -JobCase))))
        $r = & $script:Clean
        $script:World.Patches.Count | Should -Be 0; $r.Ok | Should -BeTrue
        $r.Lines[0] | Should -Match 'every identity on SI''s jobs and apps exists'
    }
    It 'never throws (the seam throws)' {
        { $r = Invoke-SIDeadIdentityCleanup -Rest { throw 'down' } -SubscriptionId 's' -ResourceGroup 'r' -Sleep { }; $r.Removed.Count | Should -Be 0 } | Should -Not -Throw
    }
}
