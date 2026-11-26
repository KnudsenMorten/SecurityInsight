#Requires -Version 5.1
<#
    SI #1414 (framework SEC-PATCH-PIPELINE-1 point 6, owner 2026-11-26: "will an attacker see the new or old image if they try
    to attack ?") -- ONE ACTIVE REVISION after every swap: setup/_shared/SI-SingleRevision.ps1 (Invoke-SISingleRevision), its
    updater step (container/updater/_shared/SI-UpdaterRollSteps.ps1 Invoke-SIUpdaterSingleRevisionStep) on BOTH update paths
    (the normal post-roll, the image-only short path) and the post-roll run, the release script's last step, the heartbeat's
    Update.revisions { single, activeRevisions, apps, readUtc } (Invardia's accepted shape) and new / moved apps made Single.

    What must hold:
      * Multiple mode -> Single (one PATCH, traffic latest 100 %, the rest of the ingress as read); 2 active -> 1 (the old
        one deactivated); a traffic label -> gone; every app with an ingress found in the resource group (not two fixed names);
      * an app already right is only read (no write);
      * the newest revision NOT proven healthy -> nothing changed on that app (the old one keeps answering) + a FAILURE;
      * a read-back that does not prove it -> a FAILURE; a list that cannot be read -> a FAILURE (never "ok");
      * a failure is loud: the update's failure report (step post-roll) and the run fails -- on the normal path, the image-only
        path (component 'revisions') and the post-roll run;
      * the heartbeat value: exactly Invardia's four keys, the LAST key of Update; a failed read leaves it out.
    Offline: a fake ARM. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SingleRevision.ps1')
    $script:Base = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/containerApps'

    function script:New-Rev([string]$Name, [bool]$Active = $true, [string]$Health = 'Healthy', [string]$Run = 'Running', [string]$Prov = 'Provisioned', $Replicas = 1) {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ active = $Active; healthState = $Health; runningState = $Run; provisioningState = $Prov; replicas = $Replicas } }
    }
    function script:New-App([string]$Name, [string]$Mode = 'Single', [string]$Latest = 'r2', [string]$Ready = '', $Traffic = $null, [bool]$Ingress = $true, [bool]$External = $true) {
        if (-not $Ready) { $Ready = $Latest }
        $cfg = [pscustomobject]@{ activeRevisionsMode = $Mode }
        if ($Ingress) {
            $ing = [pscustomobject]@{ external = $External; targetPort = 8080; transport = 'auto'; fqdn = "$Name.env.example.io"; stickySessions = [pscustomobject]@{ affinity = 'sticky' }
                                      customDomains = @([pscustomobject]@{ name = 'si.example.com'; bindingType = 'SniEnabled' })
                                      ipSecurityRestrictions = @([pscustomobject]@{ name = 'office'; action = 'Allow'; ipAddressRange = '10.0.0.0/8' })
                                      corsPolicy = [pscustomobject]@{ allowedOrigins = @('https://si.example.com') } }
            if ($null -ne $Traffic) { $ing | Add-Member -NotePropertyName traffic -NotePropertyValue @($Traffic) }
            $cfg | Add-Member -NotePropertyName ingress -NotePropertyValue $ing
        }
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ provisioningState = 'Succeeded'; latestRevisionName = $Latest; latestReadyRevisionName = $Ready; configuration = $cfg
                                                                       template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = $Name; image = "acr.io/$($Name):new" }) } } }
    }
    # a fake ARM world: apps by name, revisions by app. PATCH sets the mode / traffic, the app InProgress for ProvGets GETs
    # (then Succeeded); AutoDeactivate = Azure deactivates the others itself on Single. POST .../deactivate deactivates
    # (unless Stuck); Busy409 = that many 409s first; Refuse = a non-busy refusal. ActivateAfter = the newest revision runs
    # (Activating -> Running) after that many revision reads.
    function script:New-World {
        @{ Apps = [ordered]@{}; Revs = @{}; Calls = (New-Object System.Collections.Generic.List[string]); Stuck = $false; ListFails = $false
           Bodies = (New-Object System.Collections.Generic.List[object]); ProvGets = 0; AutoDeactivate = $false; Busy409 = 0; Refuse = ''; ActivateAfter = -1; RevReads = 0 }
    }
    function script:New-WorldArm($W) {
        $base = $script:Base
        {
            param([string]$Method, [string]$Path, $Body)
            $W.Calls.Add(('{0} {1}' -f $Method, $Path))
            if ($Method -eq 'LIST' -and $Path -eq $base) { if ($W.ListFails) { throw 'listing failed: HTTP 403' }; return @($W.Apps.Values) }
            $rest = $Path.Substring($base.Length + 1)
            $parts = $rest -split '/'
            $app = $W.Apps[$parts[0]]
            if ($Method -eq 'GET') {
                if ($app -and $app.properties.provisioningState -eq 'InProgress') { if ($W.ProvGets -le 0) { $app.properties.provisioningState = 'Succeeded' } else { $W.ProvGets-- } }
                return $app
            }
            if ($Method -eq 'LIST' -and $parts[1] -eq 'revisions') {
                $W.RevReads++
                if ($W.ActivateAfter -ge 0 -and $W.RevReads -gt $W.ActivateAfter) { foreach ($r in @($W.Revs[$parts[0]])) { if ($r.name -eq $app.properties.latestRevisionName) { $r.properties.runningState = 'Running' } } }
                return @($W.Revs[$parts[0]])
            }
            if ($Method -eq 'PATCH') {
                $W.Bodies.Add($Body)
                $app.properties.configuration.activeRevisionsMode = $Body.properties.configuration.activeRevisionsMode
                $t = @($Body.properties.configuration.ingress.traffic | ForEach-Object { [pscustomobject]@{ latestRevision = $_.latestRevision; weight = $_.weight } })
                if ($app.properties.configuration.ingress.PSObject.Properties['traffic']) { $app.properties.configuration.ingress.traffic = $t }
                else { $app.properties.configuration.ingress | Add-Member -NotePropertyName traffic -NotePropertyValue $t }
                if ($W.ProvGets -gt 0) { $app.properties.provisioningState = 'InProgress' }
                if ($W.AutoDeactivate) { foreach ($r in @($W.Revs[$parts[0]])) { if ($r.name -ne $app.properties.latestRevisionName) { $r.properties.active = $false } } }
                return $app
            }
            if ($Method -eq 'POST' -and $parts[3] -eq 'deactivate') {
                if ($app.properties.provisioningState -ne 'Succeeded') { throw 'POST failed: HTTP 409: ContainerAppOperationInProgress (deactivate during the PATCH)' }
                if ($W.Busy409 -gt 0) { $W.Busy409--; throw 'POST failed: HTTP 409: ContainerAppOperationInProgress' }
                if ($W.Refuse) { throw $W.Refuse }
                $hit = @(@($W.Revs[$parts[0]]) | Where-Object { $_.name -eq $parts[2] })[0]
                if ($hit -and -not $hit.properties.active) { throw 'POST failed: HTTP 400: the revision is already inactive' }
                if (-not $W.Stuck -and $hit) { $hit.properties.active = $false }
                return $null
            }
            throw "unexpected $Method $Path"
        }.GetNewClosure()
    }
    $script:Run = { param($W) Invoke-SISingleRevision -Arm (New-WorldArm $W) -SubscriptionId 'sub' -ResourceGroup 'rg' -PollSeconds 0 -Sleep { } }
    # with waits (a no-op sleep): the bounded waits poll the fake until it changes
    $script:RunWait = { param($W) Invoke-SISingleRevision -Arm (New-WorldArm $W) -SubscriptionId 'sub' -ResourceGroup 'rg' -PollSeconds 1 -WaitSeconds 20 -ReadyWaitSeconds 20 -Sleep { } }
}

Describe 'Invoke-SISingleRevision (setup/_shared/SI-SingleRevision.ps1)' {
    It 'Multiple mode with 2 active revisions -> Single, ONE PATCH, the old revision deactivated, read back' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple' -Traffic @([pscustomobject]@{ latestRevision = $true; weight = 100 })
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeTrue
        @($w.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
        @($w.Calls | Where-Object { $_ -like 'POST *' }) | Should -Be @("POST $($script:Base)/ca-si-management/revisions/r1/deactivate")
        $r.Apps[0].Mode | Should -Be 'Single'; @($r.Apps[0].Active) | Should -Be @('r2')
        $r.Text | Should -Match 'ca-si-management \(r2\)'; $r.Text | Should -Match 'set now'
    }
    It 'Labels mode -> Single as well' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Labels' -Traffic @([pscustomobject]@{ revisionName = 'r2'; weight = 100; label = 'green' })
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeTrue; $r.Apps[0].Mode | Should -Be 'Single'; $r.Apps[0].Labels | Should -Be 0
    }
    It 'traffic PINNED BY NAME to another revision -> refused, nothing changed, a FAILURE' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple' -Traffic @([pscustomobject]@{ revisionName = 'r1'; weight = 50 }, [pscustomobject]@{ revisionName = 'r2'; weight = 50 })
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse; $r.Text | Should -Match 'pinned by name to r1'
        @($w.Calls | Where-Object { $_ -like 'PATCH *' -or $_ -like 'POST *' }).Count | Should -Be 0
    }
    It 'the PATCH body: Single, traffic = latest 100 % (no label), the ingress otherwise as read (custom domains, IP rules, CORS kept), without its address' {
        $w = New-World
        $w.Apps['ca-si-mcp'] = New-App 'ca-si-mcp' -Mode 'Multiple' -Traffic @([pscustomobject]@{ revisionName = 'r2'; weight = 100; label = 'blue' })
        $w.Revs['ca-si-mcp'] = @((New-Rev 'r2'))
        $null = & $script:Run $w
        $b = $w.Bodies[0]
        $b.properties.configuration.activeRevisionsMode | Should -Be 'Single'
        $j = ConvertTo-Json -InputObject $b -Depth 10 -Compress
        $j | Should -Match '"traffic":\[\{"latestRevision":true,"weight":100\}\]'
        $j | Should -Not -Match 'fqdn'; $j | Should -Not -Match 'blue'
        $j | Should -Match '"stickySessions":\{"affinity":"sticky"\}'; $j | Should -Match '"targetPort":8080'
        $j | Should -Match '"customDomains":\[\{"name":"si.example.com","bindingType":"SniEnabled"\}\]'
        $j | Should -Match '"ipSecurityRestrictions":\[\{"name":"office","action":"Allow","ipAddressRange":"10.0.0.0/8"\}\]'
        $j | Should -Match '"corsPolicy":\{"allowedOrigins":\["https://si.example.com"\]\}'
    }
    It 'after the PATCH the app''s provisioning is waited for (Succeeded) BEFORE any deactivation' {
        $w = New-World; $w.ProvGets = 3
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:RunWait $w
        $r.Ok | Should -BeTrue
        $iPatch = $w.Calls.IndexOf(@($w.Calls | Where-Object { $_ -like 'PATCH *' })[0]); $iPost = $w.Calls.IndexOf(@($w.Calls | Where-Object { $_ -like 'POST *' })[0])
        @($w.Calls[($iPatch + 1)..($iPost - 1)] | Where-Object { $_ -like 'GET *' }).Count | Should -BeGreaterOrEqual 4
    }
    It 'Azure deactivates the others itself on Single -> no POST, the read-back proves it' {
        $w = New-World; $w.AutoDeactivate = $true
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeTrue
        @($w.Calls | Where-Object { $_ -like 'POST *' }).Count | Should -Be 0
    }
    It 'a 409 on the deactivation is waited out (no false "NOT proven")' {
        $w = New-World; $w.Busy409 = 2
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        (& $script:Run $w).Ok | Should -BeTrue
        @($w.Calls | Where-Object { $_ -like 'POST *' }).Count | Should -Be 3
    }
    It 'a deactivation that is REFUSED (not busy) -> said, and the read-back decides: still active = a FAILURE' {
        $w = New-World; $w.Refuse = 'POST failed: HTTP 403: AuthorizationFailed'
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse; $r.Text | Should -Match 'does not read back with one active revision'
    }
    It 'Single mode but 2 active -> only the deactivation, no PATCH' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeTrue
        @($w.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        @($w.Calls | Where-Object { $_ -like 'POST *' }).Count | Should -Be 1
    }
    It 'an app that is already right is only read -- no write' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Traffic @([pscustomobject]@{ latestRevision = $true; weight = 100 })
        $w.Revs['ca-si-management'] = @((New-Rev 'r1' -Active $false), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeTrue; @($r.Changed).Count | Should -Be 0
        @($w.Calls | Where-Object { $_ -notlike 'GET *' -and $_ -notlike 'LIST *' }).Count | Should -Be 0
    }
    It 'every app with an ingress in the resource group is looked after (a third one too); one without an ingress is not; a name in another case only once' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'; $w.Revs['ca-si-management'] = @((New-Rev 'r2'))
        $w.Apps['ca-si-portal'] = New-App 'ca-si-portal' -Mode 'Multiple'; $w.Revs['ca-si-portal'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $w.Apps['ca-si-worker'] = New-App 'ca-si-worker' -Ingress $false; $w.Revs['ca-si-worker'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = Invoke-SISingleRevision -Arm (New-WorldArm $w) -SubscriptionId 'sub' -ResourceGroup 'rg' -PollSeconds 0 -Sleep { } -Apps @('CA-SI-MANAGEMENT')
        $r.Ok | Should -BeTrue
        @($r.Apps | ForEach-Object { $_.App }) | Should -Be @('ca-si-management', 'ca-si-portal')
        @($w.Calls | Where-Object { $_ -like '*ca-si-worker*' }).Count | Should -Be 0
        @($w.Calls | Where-Object { $_ -like "POST $($script:Base)/ca-si-portal/revisions/r1/deactivate" }).Count | Should -Be 1
    }
    It 'the NEWEST revision is not healthy -> nothing is changed on that app (the old one keeps answering) and it FAILS' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2' -Health 'Unhealthy'))
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse
        $r.Text | Should -Match 'NOT proven'; $r.Text | Should -Match 'r2 is Unhealthy'; $r.Text | Should -Match 'nothing was changed'
        @($w.Calls | Where-Object { $_ -like 'PATCH *' -or $_ -like 'POST *' }).Count | Should -Be 0
        $w.Revs['ca-si-management'][0].properties.active | Should -BeTrue
    }
    It 'running states: only Running / RunningAtMaxScale with a replica count as running; Stopped, Degraded, 0 replicas, an empty provisioning state do not' {
        foreach ($case in @(@{ Run = 'Stopped' }, @{ Run = 'Degraded' }, @{ Run = 'Running'; Replicas = 0 }, @{ Run = 'Running'; Prov = '' })) {
            $w = New-World
            $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple'
            $rp = if ($case.ContainsKey('Replicas')) { $case.Replicas } else { 1 }
            $pv = if ($case.ContainsKey('Prov')) { $case.Prov } else { 'Provisioned' }
            $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2' -Run $case.Run -Replicas $rp -Prov $pv))
            $r = & $script:Run $w
            $r.Ok | Should -BeFalse -Because ($case | ConvertTo-Json -Compress)
            @($w.Calls | Where-Object { $_ -like 'PATCH *' -or $_ -like 'POST *' }).Count | Should -Be 0
        }
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'
        $w.Revs['ca-si-management'] = @((New-Rev 'r2' -Run 'RunningAtMaxScale'))
        (& $script:Run $w).Ok | Should -BeTrue
    }
    It 'a newest revision still ACTIVATING (an identity PATCH just before made it) is waited for, then judged and kept' {
        $w = New-World; $w.ActivateAfter = 2
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Latest 'r3'
        $w.Revs['ca-si-management'] = @((New-Rev 'r2'), (New-Rev 'r3' -Run 'Activating'))
        $r = & $script:RunWait $w
        $r.Ok | Should -BeTrue; @($r.Apps[0].Active) | Should -Be @('r3')
        @($w.Calls | Where-Object { $_ -like 'POST *' }) | Should -Be @("POST $($script:Base)/ca-si-management/revisions/r2/deactivate")
    }
    It 'the newest revision is not READY yet (latest <> latest ready) and no wait -> nothing is changed and it FAILS' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple' -Latest 'r3' -Ready 'r2'
        $w.Revs['ca-si-management'] = @((New-Rev 'r2'), (New-Rev 'r3' -Health 'None' -Prov 'Provisioning'))
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse; $r.Text | Should -Match 'r3 is not ready'
        @($w.Calls | Where-Object { $_ -like 'PATCH *' -or $_ -like 'POST *' }).Count | Should -Be 0
    }
    It 'a deactivation that does not read back -> a FAILURE that says what was read' {
        $w = New-World; $w.Stuck = $true
        $w.Apps['ca-si-management'] = New-App 'ca-si-management'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse
        $r.Text | Should -Match 'does not read back with one active revision'; $r.Text | Should -Match 'active r1, r2'
    }
    It 'the apps cannot be listed -> a FAILURE, never "ok"' {
        $w = New-World; $w.ListFails = $true
        $r = & $script:Run $w
        $r.Ok | Should -BeFalse; $r.Text | Should -Match 'could not be listed'
    }
    It '-WhatIf reads and says what it WOULD set -- never "set now"' {
        $w = New-World
        $w.Apps['ca-si-management'] = New-App 'ca-si-management' -Mode 'Multiple'
        $w.Revs['ca-si-management'] = @((New-Rev 'r1'), (New-Rev 'r2'))
        $r = Invoke-SISingleRevision -Arm (New-WorldArm $w) -SubscriptionId 'sub' -ResourceGroup 'rg' -PollSeconds 0 -WhatIf
        @($w.Calls | Where-Object { $_ -like 'PATCH *' -or $_ -like 'POST *' }).Count | Should -Be 0
        @($r.Changed)[0] | Should -Match 'would be set'
        $r.Text | Should -Match 'plan only, nothing changed'; $r.Text | Should -Not -Match 'set now'
    }
    It 'no sign-in and no seam -> a FAILURE, never "ok"' {
        (Invoke-SISingleRevision -SubscriptionId 'sub' -ResourceGroup 'rg').Ok | Should -BeFalse
    }
}

Describe 'the updater: the last step on both paths, loud on failure' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
        . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
        Mock Invoke-WebRequest { throw 'no network in tests' }
        Mock Invoke-RestMethod { throw 'no network in tests' }
    }
    AfterEach { $global:SI_SingleRevisionSeam = $null }
    It 'Invoke-SIUpdaterSingleRevisionStep: not proven -> the failure report (step post-roll) and a WARNING; proven -> no failure' {
        Mock Add-SIUpdaterFailureIf { }
        $r = Invoke-SIUpdaterSingleRevisionStep -ResourceGroup 'rg' -SubscriptionId 'sub' -Step { param($g, $s, $a) [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: x' } } 6>$null
        $r.Ok | Should -BeFalse
        Should -Invoke Add-SIUpdaterFailureIf -Times 1 -Exactly -Scope It -ParameterFilter { $Step -eq 'post-roll' -and $Text -match 'NOT proven' }
        $null = Invoke-SIUpdaterSingleRevisionStep -ResourceGroup 'rg' -SubscriptionId 'sub' -Step { param($g, $s, $a) [pscustomobject]@{ Ok = $true; Text = 'ok' } } 6>$null
        Should -Invoke Add-SIUpdaterFailureIf -Times 1 -Exactly -Scope It
    }
    It 'a step that throws is a FAILURE too; a test session without a seam never calls Azure ($null)' {
        Mock Add-SIUpdaterFailureIf { }
        (Invoke-SIUpdaterSingleRevisionStep -ResourceGroup 'rg' -SubscriptionId 'sub' -Step { throw 'boom' } 6>$null).Ok | Should -BeFalse
        Invoke-SIUpdaterSingleRevisionStep -ResourceGroup 'rg' -SubscriptionId 'sub' 6>$null | Should -BeNullOrEmpty
    }
    It 'the step reaches the real library through the updater''s REST seam with the install''s names' {
        Mock Add-SIUpdaterFailureIf { }
        $global:SI_SingleRevisionSeam = { param($g, $s, $a) $global:SRSeen = @($g, $s) + @($a); [pscustomobject]@{ Ok = $true; Text = 'ok' } }
        $null = Invoke-SIUpdaterSingleRevisionStep -ResourceGroup 'rg' -SubscriptionId 'sub' -Apps @('ca-si-management', 'ca-si-mcp') 6>$null
        @($global:SRSeen) | Should -Be @('rg', 'sub', 'ca-si-management', 'ca-si-mcp')
    }
    It 'NORMAL path: the post-roll runs the step LAST (after the web app roll) and says RevisionsOk' {
        $global:SROrder = New-Object System.Collections.Generic.List[string]
        Mock Invoke-SIUpdaterAppRoll { $global:SROrder.Add('web'); [pscustomobject]@{ Code = 0; Text = 'healthy' } }
        Mock Save-SIUpdaterInstalledRecord { $true }
        Mock Invoke-SIUpdaterSelfRoll { $global:SROrder.Add('updater'); [pscustomobject]@{ Action = 'rolled'; Reason = 'moved' } }
        Mock Add-SIUpdaterFailureIf { }
        $global:SI_UpdaterSelfMove = $null
        $global:SI_SingleRevisionSeam = { param($g, $s, $a) $global:SROrder.Add('revisions'); [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: ca-si-management: r2 is Unhealthy' } }
        $env = [pscustomobject]@{ LoginServer = 'acr.io'; UpdaterId = '/x'; UpdaterImage = 'acr.io/si-updater:old' }
        $p = Invoke-SIUpdaterInvardiaPostRoll -SIRoot $TestDrive -Version '3.1.52' -Commit ('c' * 40) -Environment $env -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' 6>$null
        @($global:SROrder) | Should -Be @('web', 'updater', 'revisions')
        $p.Code | Should -Be 0; $p.RevisionsOk | Should -BeFalse; $p.RevisionsText | Should -Match 'NOT proven'
        Should -Invoke Add-SIUpdaterFailureIf -Times 1 -Exactly -Scope It -ParameterFilter { $Step -eq 'post-roll' }
    }
    It 'NORMAL path: a web app roll that FAILED never reaches the step (never deactivate the only healthy revision)' {
        Mock Invoke-SIUpdaterAppRoll { [pscustomobject]@{ Code = 1; Text = 'not healthy' } }
        $global:SRCalled = $false
        $global:SI_SingleRevisionSeam = { param($g, $s, $a) $global:SRCalled = $true; [pscustomobject]@{ Ok = $true; Text = 'ok' } }
        $env = [pscustomobject]@{ LoginServer = 'acr.io'; UpdaterId = '/x'; UpdaterImage = 'acr.io/si-updater:old' }
        $p = Invoke-SIUpdaterInvardiaPostRoll -SIRoot $TestDrive -Version '3.1.52' -Environment $env -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' 6>$null
        $p.Code | Should -Be 1; $global:SRCalled | Should -BeFalse
    }
    It 'NORMAL path wiring: RevisionsOk false fails the run (rc 1, lastError)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        $src | Should -Match ([regex]::Escape("if (`$post.Code -eq 0 -and `$post.PSObject.Properties['RevisionsOk'] -and -not `$post.RevisionsOk) { `$rc = 1; `$state.lastError"))
        $src | Should -Match ([regex]::Escape("if (`"`$(`$ioRes.Component)`" -eq 'revisions') { `$rc = 1 }"))
    }
    It 'IMAGE-ONLY path: the step runs LAST (after the updater); not proven -> Code 0 (installed), swap-failed at revisions' {
        $order = New-Object System.Collections.Generic.List[string]
        $seams = @{
            EngineSwap = { param($r) $order.Add('engine'); [pscustomobject]@{ Code = 0; Stage = '4. VERIFY'; Failures = @(); Error = '' } }.GetNewClosure()
            AppSwap    = { param($r, $t) $order.Add('web'); [pscustomobject]@{ Code = 0; Text = 'healthy' } }.GetNewClosure()
            Record     = { param($v, $c) $order.Add('record'); $true }.GetNewClosure()
            SelfSwap   = { param($r, $t) $order.Add('updater'); [pscustomobject]@{ Action = 'rolled'; Reason = 'moved' } }.GetNewClosure()
            Revisions  = { $order.Add('revisions'); [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: ca-si-management: r9 is Unhealthy' } }.GetNewClosure()
        }
        $r = Invoke-SIUpdaterImageOnly -SIRoot $TestDrive -Version '3.1.52.1' -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -Seams $seams 6>$null
        @($order) | Should -Be @('engine', 'web', 'record', 'updater', 'revisions')
        $r.Code | Should -Be 0; $r.Result | Should -Be 'swap-failed'; $r.Component | Should -Be 'revisions'; $r.Why | Should -Match 'NOT proven'
        $r.SelfAction | Should -Be 'rolled' -Because 'the post-roll run is still started'
        $seams.Revisions = { [pscustomobject]@{ Ok = $true; Text = 'ok' } }
        $r2 = Invoke-SIUpdaterImageOnly -SIRoot $TestDrive -Version '3.1.52.1' -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -Seams $seams 6>$null
        $r2.Result | Should -Be 'done'; @($r2.Parts)[-1] | Should -Be 'revisions'
    }
    It 'IMAGE-ONLY path: revisions AND the updater''s own move failed -> both are reported' {
        Mock Add-SIUpdaterFailureIf { }
        $seams = @{
            EngineSwap = { param($r) [pscustomobject]@{ Code = 0; Stage = ''; Failures = @(); Error = '' } }
            AppSwap    = { param($r, $t) [pscustomobject]@{ Code = 0; Text = 'healthy' } }
            Record     = { param($v, $c) $true }
            SelfSwap   = { param($r, $t) [pscustomobject]@{ Action = 'failed'; Reason = 'the updater job could not be pointed at it' } }
            Revisions  = { [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: x' } }
        }
        $r = Invoke-SIUpdaterImageOnly -SIRoot $TestDrive -Version '3.1.52.1' -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -Seams $seams 6>$null
        $r.Component | Should -Be 'revisions'; $r.Why | Should -Match 'NOT proven'; $r.Why | Should -Match 'could not be pointed'
        $r.Why | Should -Not -Match 'next update run tries again'
        Should -Invoke Add-SIUpdaterFailureIf -Times 1 -Exactly -Scope It -ParameterFilter { $Text -match 'the updater itself' }
        Should -Invoke Add-SIUpdaterFailureIf -Times 1 -Exactly -Scope It -ParameterFilter { $Text -match 'the revisions' }
    }
    It 'IMAGE-ONLY path: a web app swap that failed never reaches the step' {
        $hit = @{ N = 0 }
        $seams = @{
            EngineSwap = { param($r) [pscustomobject]@{ Code = 0; Stage = ''; Failures = @(); Error = '' } }
            AppSwap    = { param($r, $t) [pscustomobject]@{ Code = 1; Text = 'not healthy' } }
            Revisions  = { $hit.N++; [pscustomobject]@{ Ok = $true; Text = 'ok' } }.GetNewClosure()
        }
        $r = Invoke-SIUpdaterImageOnly -SIRoot $TestDrive -Version '3.1.52.1' -ResourceGroup 'rg' -AcrName 'acr' -SubscriptionId 'sub' -Seams $seams 6>$null
        $r.Component | Should -Be 'web app'; $hit.N | Should -Be 0
    }
    It 'the POST-ROLL run (the release''s own code) runs the step last; not proven -> exit 1' {
        Mock Invoke-SIUpdaterWebAppStepsAfter { }
        Mock Invoke-SIUpdaterVulnViewStep { }
        Mock Add-SIUpdaterFailureIf { }
        $global:SI_SingleRevisionSeam = { param($g, $s, $a) [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: x' } }
        Invoke-SIUpdaterPostRollRun -Env @{} -Store $null -SubscriptionId 'sub' -ResourceGroup 'rg' 6>$null | Select-Object -Last 1 | Should -Be 1
        $global:SI_SingleRevisionSeam = { param($g, $s, $a) [pscustomobject]@{ Ok = $true; Text = 'ok' } }
        Invoke-SIUpdaterPostRollRun -Env @{} -Store $null -SubscriptionId 'sub' -ResourceGroup 'rg' 6>$null | Select-Object -Last 1 | Should -Be 0
    }
}

Describe 'the release script and new apps' {
    It 'setup\Invoke-SIContainerUpdate.ps1: ONE ACTIVE REVISION is the last step of Complete-SIUpdate (before the templates), a WARNING only, never the exit code' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $line = @($src -split "`n" | Where-Object { $_ -match '^function Complete-SIUpdate' })[0]
        $line | Should -Match ([regex]::Escape('$null = Invoke-SIUpdatePermissionNote; $null = Invoke-SIUpdateSingleRevision; $null = Invoke-SIUpdateDisplayNames; if ($global:SI_UpdateRunBeat) { Stop-SIUpdateRunBeatAtEnd }; Install-SIUpdateDefaultTemplates }'))
        $fn = $src.Substring($src.IndexOf('function Invoke-SIUpdateSingleRevision')); $fn = $fn.Substring(0, $fn.IndexOf('function Complete-SIUpdate'))
        $fn | Should -Not -Match 'Add-SIUpdaterFailure' -Because 'the failure record is the updater''s own last step (a revision still Activating before the web app roll is no failure)'
        $fn | Should -Match 'Warn \$r\.Text'
    }
    It 'EVERY updater run without an install runs the step (an unproven state is tried again), never an image check' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1'))
        $rx = ([regex]::Escape('if (-not $imgCheck -and (-not $roll -or $roll.Held)) {') + '\s+' + [regex]::Escape('$rvn = if ($s[''Revisions''])'))
        $src | Should -Match $rx
        $src | Should -Match ([regex]::Escape("if (`$rvn -and -not `$rvn.Ok) { `$rc = 1; `$state.lastError"))
    }
    It 'a new web / MCP app is created Single; an existing one in Multiple mode is moved to Single by the deploy' {
        . (Join-Path $script:SIRoot 'pro-management\deploy\SI-ManagementArm.ps1')
        $b = New-SIManagementContainerAppBody -Name 'ca-si-mcp' -Location 'l' -EnvironmentId '/env' -Image 'i' -RegistryServer 'acr.io' -IdentityId '/uami' -External $true
        $b.properties.configuration.activeRevisionsMode | Should -Be 'Single'
        $app = [pscustomobject]@{ name = 'ca-si-mcp'; properties = [pscustomobject]@{ configuration = [pscustomobject]@{ activeRevisionsMode = 'Multiple' }; template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'c'; image = 'i' }) } } }
        (Merge-SIManagementContainerAppUpdate -App $app).properties.configuration.activeRevisionsMode | Should -Be 'Single'
        $app.properties.configuration.activeRevisionsMode = 'Single'
        Merge-SIManagementContainerAppUpdate -App $app | Should -BeNullOrEmpty
    }
}

Describe 'the heartbeat: Update.revisions (Invardia''s shape { single, activeRevisions, apps, readUtc })' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-HeartbeatJob.ps1')
        $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-26T10:00:00', [DateTimeKind]::Utc)
        $script:U = New-SIHeartbeatOrdered -Names (Get-SIHeartbeatFieldsContract).Fields.Update -Values @{ installed = '3.1.52'; lastUpdaterResult = 'succeeded' }
    }
    It 'the value from ARM: internet-facing apps only, the highest active count, single only when every one is right' {
        $apps = @((New-App 'ca-si-management'), (New-App 'ca-si-mcp' -Mode 'Multiple'), (New-App 'ca-si-int' -External $false), (New-App 'ca-si-job' -Ingress $false))
        $by = @{ 'ca-si-management' = @((New-Rev 'r2')); 'ca-si-mcp' = @((New-Rev 'r1'), (New-Rev 'r2')) }
        $v = ConvertTo-SIHeartbeatRevisions -Apps $apps -RevisionsByApp $by -NowUtc $script:Now
        ($v | ConvertTo-Json -Compress) | Should -Be '{"single":false,"activeRevisions":2,"apps":2,"readUtc":"2026-11-26T10:00:00Z"}'
        $ok = ConvertTo-SIHeartbeatRevisions -Apps @((New-App 'ca-si-management')) -RevisionsByApp @{ 'ca-si-management' = @((New-Rev 'r1' -Active $false), (New-Rev 'r2')) } -NowUtc $script:Now
        $ok.single | Should -BeTrue; $ok.activeRevisions | Should -Be 1; $ok.apps | Should -Be 1
        $lab = New-App 'ca-si-management' -Traffic @([pscustomobject]@{ latestRevision = $true; weight = 100; label = 'old' })
        (ConvertTo-SIHeartbeatRevisions -Apps @($lab) -RevisionsByApp @{ 'ca-si-management' = @((New-Rev 'r2')) } -NowUtc $script:Now).single | Should -BeFalse
    }
    It 'an app whose revisions were not read THROWS (never a guess)' {
        { ConvertTo-SIHeartbeatRevisions -Apps @((New-App 'ca-si-management')) -RevisionsByApp @{} -NowUtc $script:Now } | Should -Throw '*not read*'
    }
    It 'Update with revisions as its LAST key passes the check; a wrong shape does not' {
        $v = [pscustomobject][ordered]@{ single = $true; activeRevisions = 1; apps = 2; readUtc = '2026-11-26T10:00:00Z' }
        $ux = Add-SIHeartbeatUpdateRevisions -Update $script:U -Revisions $v
        @($ux.PSObject.Properties | ForEach-Object { $_.Name })[-1] | Should -Be 'revisions'
        Test-SIHeartbeatField -Name 'Update' -Value $ux | Should -Be ''
        $bad = [pscustomobject][ordered]@{ single = 'yes'; activeRevisions = 1; apps = 2; readUtc = '2026-11-26T10:00:00Z' }
        Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateRevisions -Update $script:U -Revisions $bad) | Should -Match 'single'
        $extra = [pscustomobject][ordered]@{ single = $true; activeRevisions = 1; apps = 2; readUtc = '2026-11-26T10:00:00Z'; app = 'ca-si-management' }
        Test-SIHeartbeatField -Name 'Update' -Value (Add-SIHeartbeatUpdateRevisions -Update $script:U -Revisions $extra) | Should -Match 'agreed'
    }
    It 'New-SIHeartbeatFields: revisions ride on Update (switch ON); a bad value leaves the key out and keeps the rest' {
        (Get-SIHeartbeatFieldsContract).UpdateSendRevisions | Should -BeTrue
        $rows = @([pscustomobject]@{ K = 'state'; Name = 'UpdateState'; S = $null; T1 = $null; T2 = $null; T3 = $null; T4 = $null; N1 = $null; Txt = '{"lastCheckUtc":"2026-11-26T09:00:00Z","code":{"version":"3.1.52","action":"current"},"error":""}'; Txt2 = $null })
        $v = [pscustomobject][ordered]@{ single = $true; activeRevisions = 1; apps = 2; readUtc = '2026-11-26T10:00:00Z' }
        $f = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ Update = $true } -CfgRows $rows -Installed '3.1.52' -Revisions $v
        $f['Update'].revisions.single | Should -BeTrue
        @($f['Update'].PSObject.Properties | ForEach-Object { $_.Name })[-1] | Should -Be 'revisions'
        $g = New-SIHeartbeatFields -Ring 0 -NowUtc $script:Now -Switch @{ Update = $true } -CfgRows $rows -Installed '3.1.52' -Revisions ([pscustomobject]@{ single = 1 })
        $g['Update'].installed | Should -Be '3.1.52'
        @($g['Update'].PSObject.Properties | ForEach-Object { $_.Name }) | Should -Not -Contain 'revisions'
    }
    It 'Get-SIHeartbeatRevisions: ONE app list, ONE revision list per internet-facing app; a failed read THROWS' {
        $paths = New-Object System.Collections.Generic.List[string]
        $apps = @((New-App 'ca-si-management'), (New-App 'ca-si-int' -External $false))
        $revs = @((New-Rev 'r2'))
        $arm = {
            param($Path) $paths.Add($Path)
            if ($Path -match '/containerApps\?') { return [pscustomobject]@{ value = $apps } }
            if ($Path -match '/ca-si-management/revisions\?') { return [pscustomobject]@{ value = $revs } }
            $null
        }.GetNewClosure()
        $v = Get-SIHeartbeatRevisions -Arm $arm -Scope ([pscustomobject]@{ Sub = 'sub'; Rg = 'rg' }) -NowUtc $script:Now
        $v.apps | Should -Be 1; $v.single | Should -BeTrue; $v.activeRevisions | Should -Be 1
        $paths.Count | Should -Be 2
        $none = { param($Path) $null }
        { Get-SIHeartbeatRevisions -Arm $none -Scope ([pscustomobject]@{ Sub = 'sub'; Rg = 'rg' }) -NowUtc $script:Now } | Should -Throw '*could not be read*'
    }
}
