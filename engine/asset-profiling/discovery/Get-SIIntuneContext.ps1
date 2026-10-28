#Requires -Version 5.1
<#
    INTUNE -- the managed devices as records of provider 'intune' (data-model/mappings/intune), read by the endpoint
    discovery. The provider was switched off ("planned") although its permission was granted; data-model/collection-scope
    now has it on (a customer switches it off there: providers.intune.enabled = false).

      Invoke-SIIntuneCapture   GET /deviceManagement/managedDevices (DeviceManagementManagedDevices.Read.All), paged, each
                               page handed straight to the record capture: part 'device' of the device's Intune record
                               (encryption, primary user id + name + mail, ownership, last check-in, compliance grace
                               period, jailbroken, manufacturer / model, enrolment, threat state, category).
                               The read is made on the BETA version of Microsoft Graph (owner 2026-10-11: "Use beta for
                               this read"): only beta says whether a device is Autopilot enrolled. When beta refuses,
                               fails or answers rows that are not devices, the same read is made on the STABLE version
                               (v1.0) -- every Intune field is then there as before, "Autopilot enrolled" stays unknown,
                               and that is said once.
                               Then, with DeviceManagementConfiguration.Read.All:
                                 part 'compliance'   the compliance policies the device does NOT meet (id + name + state)
                                 part 'updateRings'  the Windows update rings assigned to it (id + name + state)
                               -- ONE paged read per policy / ring (its device statuses), never one per device.

    A read the identity may not make is SKIPPED and said once with the permission to grant -- never a failure, and nothing
    is asked for that the install did not grant. A tenant without Intune is said as such, and its Entra device records
    carry "not licensed (Microsoft Intune)" (part 'intuneState') so the column never reads as "not managed".
    READ-ONLY: nothing is written to Intune. No PowerShell modules. PowerShell 5.1 safe: no ?. / ??, no ternary.
#>

function Test-SICollectionProviderEnabled {
    <#
        Is a provider switched on in data-model/collection-scope (shipped + the customer's overrides)? A scope that cannot
        be read answers $true: the shipped state, never fewer records because a file could not be read. -Document (tests).
    #>
    param([Parameter(Mandatory)][string]$Provider, $Document)
    try {
        if ($null -eq $Document) {
            if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../data-model/SI-DataModelTemplates.ps1') }
            $Document = (Get-SIDataModelTemplate -Name 'collection-scope' -OverlayRoot $global:SI_DataModelOverlayRoot).Document
        }
        $provs = $null
        if ($Document -is [System.Collections.IDictionary]) { $provs = $Document['providers'] } elseif ($null -ne $Document) { $pp = $Document.PSObject.Properties['providers']; if ($pp) { $provs = $pp.Value } }
        if ($null -eq $provs) { return $true }
        $p = $null
        if ($provs -is [System.Collections.IDictionary]) { $p = $provs[$Provider] } else { $pp = $provs.PSObject.Properties[$Provider]; if ($pp) { $p = $pp.Value } }
        if ($null -eq $p) { return $true }
        $e = $null
        if ($p -is [System.Collections.IDictionary]) { $e = $p['enabled'] } else { $pp = $p.PSObject.Properties['enabled']; if ($pp) { $e = $pp.Value } }
        if ($e -is [bool]) { return $e }
        if ([string]$e -match '^(?i)(false|0|off|no)$') { return $false }
        return $true
    } catch { return $true }
}

function Get-SIIntuneReadOutcome {
    <# PURE. What a failed Intune read means: 'refused' (the identity lacks the permission), 'not-licensed' (the tenant has no
       Intune), or 'failed' (anything else). #>
    param([AllowNull()][AllowEmptyString()][string]$ErrorText)
    $t = [string]$ErrorText
    if ($t -match '(?i)not applicable to target tenant|no (valid )?intune licen[cs]e|not licen[cs]ed|licen[cs]e (is )?required|BadRequest.{0,80}tenant.{0,40}intune|does not have (an? )?intune') { return 'not-licensed' }
    if ($t -match '(?i)\b403\b|forbidden|authorization_requestdenied|insufficient privileges|not authorized to perform|does not have .*permission') { return 'refused' }
    return 'failed'
}

function Get-SIIntuneStatusDeviceId {
    <#
        PURE. The managed device a policy's device status row belongs to. The row's id is built from ids joined by '_'
        (policy, device, sometimes the user): the part that is a known device id wins; else the row's device name and user,
        when exactly one device has them. '' when it cannot be told.
    #>
    param($Row, [Parameter(Mandatory)]$DeviceIds, [hashtable]$ByNameUser = @{})
    if ($null -eq $Row) { return '' }
    foreach ($seg in ([string]$Row.id).ToLowerInvariant().Split('_')) { if ($seg -and $DeviceIds.Contains($seg)) { return $seg } }
    $n = ''; if ($Row.PSObject.Properties['deviceDisplayName']) { $n = ([string]$Row.deviceDisplayName).Trim().ToLowerInvariant() }
    $u = ''; if ($Row.PSObject.Properties['userPrincipalName']) { $u = ([string]$Row.userPrincipalName).Trim().ToLowerInvariant() }
    if ($n) { $k = $n + '|' + $u; if ($ByNameUser.ContainsKey($k) -and [string]$ByNameUser[$k]) { return [string]$ByNameUser[$k] } }
    return ''
}

function Invoke-SIIntuneCapture {
    <#
    .SYNOPSIS  Reads the Intune managed devices (and, when permitted, their failing compliance policies and update rings)
               into the record capture. Returns @{ Devices; Compliance; UpdateRings; Skipped; Complete; Autopilot }
               (Autopilot: 'read' = the beta version answered, 'unknown' = the stable version was used). Never throws.
    .PARAMETER Fetch  (tests) { param($Url, $Label, $OnPage) } -> @{ Rows; Complete; Error } -- with $OnPage the rows go to
                      it page by page. Default: Invoke-SIPagedRest with this install's Graph token.
    #>
    param([string]$Token, [scriptblock]$Fetch, $ScopeDocument, [scriptblock]$Log)
    $res = [ordered]@{ Devices = 0; Compliance = 0; UpdateRings = 0; Skipped = ''; Complete = $false; Autopilot = '' }
    $global:SIIntuneCapture = $null
    if (-not $Log) { $Log = { param($Level, $Message) if ($Level -eq 'WARN') { Write-Warning $Message } else { Write-Host ('[INFO] ' + $Message) } } }
    try {
        if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue) -or $null -eq $global:SIRecordCaptureState) { return $res }
        if (-not (Test-SICollectionProviderEnabled -Provider 'intune' -Document $ScopeDocument)) { $res.Skipped = 'switched off in the collection scope'; return $res }
        if (-not $Fetch) {
            if (-not $Token) {
                if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../../auth/Get-SIGraphToken.ps1') }
                $Token = Get-SIGraphToken -Resource Graph
            }
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1') }
            $tok = $Token
            $Fetch = {
                param($Url, $Label, $OnPage)
                $a = @{ Url = $Url; Token = $tok; SourceLabel = $Label; WarningAction = 'SilentlyContinue' }
                if ($OnPage) { $a['OnPage'] = $OnPage }
                Invoke-SIPagedRest @a
            }
        }
        $full = [bool]((Get-Command -Name Test-SIFullAssetPropertiesOn -ErrorAction SilentlyContinue) -and (Test-SIFullAssetPropertiesOn) -and (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue))
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $byNameUser = @{}
        $siSeen = @{ n = 0 }
        $onDevice = {
            param($Rows)
            foreach ($d in @($Rows)) {
                if ($null -eq $d -or -not $d.id) { continue }
                $id = ([string]$d.id).ToLowerInvariant()
                # at the full level the whole object is also kept as asset metadata (that hook hands it to the record capture)
                if ($full) {
                    # the Entra device id under the stable name, else the name the beta version also carries
                    $aad = [string]$d.azureADDeviceId; if (-not $aad -and $d.PSObject.Properties['azureActiveDirectoryDeviceId']) { $aad = [string]$d.azureActiveDirectoryDeviceId }
                    Add-SIFullSourceObject -SourceSystem 'intune-device' -Object $d -AnchorColumn 'AadDeviceId' -AnchorValue $aad
                }
                else { Add-SIRecordPart -Provider 'intune' -RecordType 'device' -Key $id -Part 'device' -Object $d }
                [void]$ids.Add($id); $siSeen.n++
                $k = ([string]$d.deviceName).Trim().ToLowerInvariant() + '|' + ([string]$d.userPrincipalName).Trim().ToLowerInvariant()
                if ($byNameUser.ContainsKey($k)) { $byNameUser[$k] = '' } else { $byNameUser[$k] = $id }     # '' = two devices share it: no match by name
            }
        }
        # THE DEVICE READ: the BETA version of Microsoft Graph first -- it carries "Autopilot enrolled" (autopilotEnrolled),
        # which the stable version does not -- and the STABLE version whenever beta refuses, fails, stops before the last
        # page or answers rows that are not devices (no id): a change in beta must never cost the Intune device data. After
        # the fall-back every device is the stable object, exactly as before; only the Autopilot field stays unknown.
        $betaUrl = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$top=999'
        $stableUrl = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999'
        $page = $null; $err = ''; $betaWhy = ''
        $siRows = @{ n = 0 }
        $onBeta = {
            param($Rows)
            $got = @($Rows | Where-Object { $null -ne $_ })
            $siRows.n += $got.Count
            # a page of rows none of which has an id is not a page of devices: stop reading beta here
            if ($got.Count -gt 0 -and @($got | Where-Object { $_.id }).Count -eq 0) { throw 'the beta version answered rows without a device id' }
            & $onDevice $got
        }
        try { $page = & $Fetch $betaUrl 'Intune managed devices (beta)' $onBeta }
        catch { $betaWhy = [string]$_.Exception.Message }
        if (-not $betaWhy -and $page -and $page.PSObject.Properties['Error'] -and [string]$page.Error) { $betaWhy = [string]$page.Error }
        # a caller's fetch that returns the rows instead of handing them page by page
        if (-not $betaWhy -and $page -and $page.PSObject.Properties['Rows'] -and @($page.Rows).Count -gt 0 -and $siRows.n -eq 0) {
            try { & $onBeta @($page.Rows) } catch { $betaWhy = [string]$_.Exception.Message }
        }
        if (-not $betaWhy -and $page -and $page.PSObject.Properties['Complete'] -and $null -ne $page.Complete -and -not [bool]$page.Complete) { $betaWhy = 'the read stopped before the last page' }
        if (-not $betaWhy -and $siRows.n -gt 0 -and $siSeen.n -eq 0) { $betaWhy = 'the beta version answered rows without a device id' }
        if ($betaWhy) {
            # start over on the stable version: nothing of the beta attempt is kept beside it (a device's part is replaced
            # by its stable object; the counters and the name look-up start empty; at the full level the objects kept
            # from the beta pages are let go, so no device is kept twice)
            $ids.Clear(); $byNameUser.Clear(); $siSeen.n = 0; $page = $null; $err = ''
            if ($full -and $null -ne $global:SIFullAssetPropertiesState -and $null -ne $global:SIFullAssetPropertiesState.Entries) {
                try { [void]$global:SIFullAssetPropertiesState.Entries.RemoveAll([Predicate[object]] { param($e) [string]$e.SourceSystem -eq 'intune-device' }) } catch { }
            }
            try { $page = & $Fetch $stableUrl 'Intune managed devices' $onDevice }
            catch { $err = [string]$_.Exception.Message }
            if ($page -and $page.PSObject.Properties['Error'] -and [string]$page.Error) { $err = [string]$page.Error }
            # a caller's fetch that returns the rows instead of handing them page by page
            if ($page -and $page.PSObject.Properties['Rows'] -and @($page.Rows).Count -gt 0 -and $siSeen.n -eq 0) { & $onDevice @($page.Rows) }
            $res.Autopilot = 'unknown'
            # said once, and only when the stable version did answer (when it did not, the lines below say why Intune was not read)
            if ($siSeen.n -gt 0) {
                & $Log 'WARN' ('Intune: the device read on the beta version of Microsoft Graph did not work ({0}) -- the devices were read from the stable version instead, so every Intune field is there except "Autopilot enrolled", which stays unknown this run.' -f $betaWhy)
            }
        } else { $res.Autopilot = 'read' }
        $res.Devices = $siSeen.n
        if ($err -and $siSeen.n -eq 0) {
            $why = Get-SIIntuneReadOutcome -ErrorText $err
            if ($why -eq 'refused') {
                $res.Skipped = 'not permitted: the identity may not read Intune devices (DeviceManagementManagedDevices.Read.All)'
                & $Log 'INFO' 'Intune: devices not read -- the identity lacks DeviceManagementManagedDevices.Read.All. Grant it with Grant-SIIdentity.ps1 to add encryption, primary user, compliance and check-in times to the devices.'
                if ($full -and (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue)) { Set-SIFullSourcePull -SourceSystem 'intune-device' -Skipped $res.Skipped }
            } elseif ($why -eq 'not-licensed') {
                $res.Skipped = 'not licensed (Microsoft Intune)'
                $n = 0
                if (Get-Command -Name Get-SIRecordCapturedKeys -ErrorAction SilentlyContinue) {
                    # #721: held or streamed -- the part is captured like any other (a streamed record gets it as one more item)
                    foreach ($dk in @(Get-SIRecordCapturedKeys -Provider 'entra' -RecordType 'device')) {
                        Add-SIRecordPart -Provider 'entra' -RecordType 'device' -Key $dk -Part 'intuneState' -Object ([pscustomobject]@{ notLicensed = 'not licensed (Microsoft Intune)' }); $n++
                    }
                } else {
                    foreach ($r in @($global:SIRecordCaptureState.Records.Values)) {
                        if ([string]$r.Provider -eq 'entra' -and [string]$r.RecordType -eq 'device') { $r.Parts['intuneState'] = [pscustomobject]@{ notLicensed = 'not licensed (Microsoft Intune)' }; $n++ }
                    }
                }
                & $Log 'INFO' ('Intune: this tenant has no Intune -- {0} device(s) say "not licensed (Microsoft Intune)".' -f $n)
                if ($full -and (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue)) { Set-SIFullSourcePull -SourceSystem 'intune-device' -Skipped $res.Skipped }
            } else {
                & $Log 'WARN' ('Intune: devices could not be read ({0}) -- the Intune fields stay as they were this run.' -f $err)
                Set-SIRecordPull -Provider 'intune' -Complete $false -ErrorText $err
                if ($full -and (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue)) { Set-SIFullSourcePull -SourceSystem 'intune-device' -Complete $false -ErrorText $err }
            }
            $global:SIIntuneCapture = [pscustomobject]@{ Read = $true; Devices = 0; Skipped = $res.Skipped }
            return $res
        }
        $complete = $true
        if ($err) { $complete = $false } elseif ($page -and $page.PSObject.Properties['Complete'] -and $null -ne $page.Complete) { $complete = [bool]$page.Complete }
        $res.Complete = $complete
        Set-SIRecordPull -Provider 'intune' -Complete $complete -ErrorText $err
        if ($full -and (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue)) { Set-SIFullSourcePull -SourceSystem 'intune-device' -Complete $complete -ErrorText $err }
        if (-not $complete) { & $Log 'WARN' ('Intune: the device read is partial ({0}) -- devices not read keep an unknown value this run.' -f $err) }
        $global:SIIntuneCapture = [pscustomobject]@{ Read = $true; Devices = $siSeen.n; Skipped = '' }

        # ---- compliance policies and update rings: one paged read per policy / ring --------------------------------------
        if ($siSeen.n -gt 0) {
            $sets = @(
                @{ What = 'compliance policies'; Part = 'compliance'; List = 'policies'; Key = 'Compliance'
                   # LIST KEPT: a name look-up -- policy id + name; the devices that do not meet it are read per policy, never the policy body
                   Url = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName'
                   Status = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/{0}/deviceStatuses'
                   Keep = '^(?i)(nonCompliant|error|conflict)$' },
                @{ What = 'update rings'; Part = 'updateRings'; List = 'rings'; Key = 'UpdateRings'
                   # LIST KEPT: a name look-up -- update ring id + name
                   Url = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$filter=' + [uri]::EscapeDataString("isof('microsoft.graph.windowsUpdateForBusinessConfiguration')") + '&$select=id,displayName'
                   Status = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/{0}/deviceStatuses'
                   Keep = '^(?i)(?!notApplicable$|notAssigned$|unknown$).+$' }
            )
            $refusedSaid = $false
            foreach ($s in $sets) {
                $lp = $null; $lerr = ''
                try { $lp = & $Fetch $s.Url ('Intune ' + $s.What) $null } catch { $lerr = [string]$_.Exception.Message }
                if ($lp -and $lp.PSObject.Properties['Error'] -and [string]$lp.Error) { $lerr = [string]$lp.Error }
                if ($lerr -and -not ($lp -and @($lp.Rows).Count -gt 0)) {
                    if ((Get-SIIntuneReadOutcome -ErrorText $lerr) -eq 'refused') {
                        if (-not $refusedSaid) { & $Log 'INFO' 'Intune: compliance policies and update rings not read -- the identity lacks DeviceManagementConfiguration.Read.All (read only). Grant it with Grant-SIIdentity.ps1 to see which policies a device does not meet and its update ring.'; $refusedSaid = $true }
                    } else { & $Log 'WARN' ('Intune: the {0} could not be read ({1}) -- left out this run.' -f $s.What, $lerr) }
                    continue
                }
                $perDevice = @{}
                foreach ($pol in @($lp.Rows)) {
                    if ($null -eq $pol -or -not $pol.id) { continue }
                    $polId = [string]$pol.id; $polName = [string]$pol.displayName
                    $keep = [string]$s.Keep
                    $onStatus = {
                        param($Rows)
                        foreach ($st in @($Rows)) {
                            if ($null -eq $st) { continue }
                            $state = [string]$st.status
                            if ($state -notmatch $keep) { continue }
                            $dev = Get-SIIntuneStatusDeviceId -Row $st -DeviceIds $ids -ByNameUser $byNameUser
                            if (-not $dev) { continue }
                            if (-not $perDevice.ContainsKey($dev)) { $perDevice[$dev] = New-Object System.Collections.Generic.List[object] }
                            $item = [ordered]@{ id = $polId.ToLowerInvariant() }; if ($polName) { $item['name'] = $polName }; $item['state'] = $state
                            $perDevice[$dev].Add([pscustomobject]$item)
                        }
                    }
                    try {
                        $sp = & $Fetch ($s.Status -f $polId) ('Intune ' + $s.What + ' device status') $onStatus
                        if ($sp -and $sp.PSObject.Properties['Rows'] -and @($sp.Rows).Count -gt 0) { & $onStatus @($sp.Rows) }
                    } catch { & $Log 'WARN' ('Intune: the device status of one of the {0} could not be read ({1}).' -f $s.What, $_.Exception.Message) }
                }
                foreach ($dev in @($perDevice.Keys)) {
                    $items = @($perDevice[$dev].ToArray() | Sort-Object { [string]$_.name }, { [string]$_.id })
                    $o = [ordered]@{}; $o[[string]$s.List] = $items
                    Add-SIRecordPart -Provider 'intune' -RecordType 'device' -Key $dev -Part ([string]$s.Part) -Object ([pscustomobject]$o)
                    $res[[string]$s.Key]++
                }
            }
        }
        & $Log 'INFO' ('Intune: {0} managed device(s) read; {1} with a compliance policy they do not meet, {2} with an update ring' -f $res.Devices, $res.Compliance, $res.UpdateRings)
    } catch {
        & $Log 'WARN' ('Intune: the devices could not be captured ({0}) -- the run continues.' -f $_.Exception.Message)
    }
    return $res
}
