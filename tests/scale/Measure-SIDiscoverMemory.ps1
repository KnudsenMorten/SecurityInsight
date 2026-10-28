#Requires -Version 7.0
<#
.SYNOPSIS
    SCALE MEASUREMENT (offline, test VM only): the identity / endpoint PRODUCER's discovery at a large tenant's size, through
    the real engine code, with only the services faked -- peak memory per stage and the run time.

.DESCRIPTION
    The producer of a run collected in parts (Phase discover) runs Invoke-SIDiscover and then hands the records it captured
    over to the parts' buckets (Save-SIRecordHandover, as container\Start-SIInContainer.ps1 does). This script runs exactly
    that, in ONE process, at the size of the large ring-2 tenant (2026-10-16: 152,842 Entra users, 2,652 service principals,
    296 subscriptions, 1,565,906 Exposure Graph [user] nodes and 351,500 [group] nodes; 195,524 endpoint assets), with -Scale
    to run a fraction. Everything the code reads from a service is generated on demand, page by page, like an answer:
      * Invoke-RestMethod        Microsoft Graph pages (users, service principals, devices, Intune, MFA registrations,
                                 $count), Defender machines, advanced hunting (the endpoint graph nodes, in hash buckets)
      * Invoke-SIEgIdentityQuery the identity profiler's Exposure Graph identity nodes (count probe + hash buckets)
      * Invoke-SIArm             subscriptions, built-in role names, role assignments per subscription
      * Get-SIIdentityInfoByObjectId  the Defender for Identity rows (held whole by the real code too)
      * staging + the state store     local files (the blob text written and read back, as the real stores do)
    A probe samples the process (working set, private bytes, managed heap) every 200 ms; each stage is named when the code
    makes its first call of that stage, so a peak is booked to the stage that caused it.

    Tag Scale: never part of any gate (scale measurements run on demand only). Never on mgmt1.

    #727 -Engine azure: a generated Azure estate (-Scale 1 = 1,200,000 Resource Graph resources -- "tenants can have
    millions of azure obj"), read through the real Get-DiscoveryFromAzureViaEG + Get-DiscoveryFromAzureResources and every
    read after it (Defender for Cloud, management groups, the Azure context): per unit of 12 resources a virtual machine, two
    extensions, an OS disk listed BEFORE its machine, a network interface, a public IP read BEFORE its network interface
    (folded up at the hand-over) and one after it, a key vault, a storage account, a network interface whose machine does
    not exist (a parent that never arrives), an unattached disk and a data collection rule (not recorded). Search-SIAzGraph
    answers page by page (1,000 rows), the Exposure Graph in hash buckets; principal names are generated.
    -EngineRoot runs ANOTHER tree's engine with this harness (the release line, for the before / after and the equivalence).

.EXAMPLE
    pwsh -NoProfile -File tests\scale\Measure-SIDiscoverMemory.ps1 -Engine identity -Scale 1 -OutFile C:\work\si\contososcale\identity.json
.EXAMPLE
    pwsh -NoProfile -File tests\scale\Measure-SIDiscoverMemory.ps1 -Engine azure -Scale 0.01 -KeepFiles -OutFile C:\work\si\az\after.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('identity', 'endpoint', 'azure')][string]$Engine,
    # the SecurityInsight tree whose engine runs (default: this one) -- e.g. a checkout of the release line
    [string]$EngineRoot = '',
    [ValidateRange(0.0001, 4)][double]$Scale = 1.0,
    [string]$OutFile = '',
    [string]$WorkDir = '',
    # the extra rawData text per Exposure Graph identity node (bytes) -- the size of a real node beyond the fields below
    [int]$EgIdentityPad = 600,
    # the extra rawData text per Exposure Graph device node (bytes)
    [int]$EgDevicePad = 1500,
    [int]$SampleMs = 200,
    # keep the staged / handed-over files (equivalence tests read them)
    [switch]$KeepFiles,
    # the run's own lines (information + warnings) on the console
    [switch]$ShowLog
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($EngineRoot) { $siRoot = (Resolve-Path -LiteralPath $EngineRoot).Path }
if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('si-scale-{0}-{1}' -f $Engine, [guid]::NewGuid().ToString('N').Substring(0, 8)) }
$null = New-Item -ItemType Directory -Force -Path $WorkDir

# ---------------------------------------------------------------------------------------------------------------- sizes
$Size = @{}
function script:Sz([double]$v) { [int][Math]::Max(1, [Math]::Round($v * $Scale)) }
if ($Engine -eq 'identity') {
    $Size.Users = Sz 152842; $Size.Sps = Sz 2652; $Size.Subs = Sz 296; $Size.AssignPerSub = 40
    $Size.EgUsers = Sz 1565906; $Size.EgGroups = Sz 351500; $Size.EgSps = $Size.Sps; $Size.EgMis = Sz 400
    # the Entra users the graph also holds (the rest of the [user] nodes are AD-only accounts with a domain SID)
    $Size.EgUsersAad = [Math]::Min($Size.Users, $Size.EgUsers); $Size.EgGroupsAad = Sz 20000
} elseif ($Engine -eq 'azure') {
    # units of 12 resources (see the header); 296 subscriptions, 50 resource groups each
    $Size.Units = Sz 100000; $Size.Resources = $Size.Units * 12; $Size.Subs = [Math]::Min(296, [Math]::Max(1, $Size.Units)); $Size.EgNodes = $Size.Units * 3
} else {
    $Size.Devices = Sz 195524; $Size.Mde = Sz 190000; $Size.Entra = Sz 150000; $Size.Intune = Sz 100000
}

# --------------------------------------------------------------------------------------------------------------- probe
if (-not ('SIScaleProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Diagnostics; using System.Threading;
public static class SIScaleProbe {
    static Timer _t; static readonly object _l = new object();
    public static string Stage = "start";
    public static List<string> Order = new List<string>();
    public static Dictionary<string, long[]> Peaks = new Dictionary<string, long[]>();   // ws, private, heap
    public static Dictionary<string, DateTime> Started = new Dictionary<string, DateTime>();
    public static Dictionary<string, DateTime> Ended = new Dictionary<string, DateTime>();
    public static void Start(int ms) { Mark("start"); _t = new Timer(_ => Tick(), null, 0, ms); }
    public static void Stop() { if (_t != null) { _t.Dispose(); _t = null; } Tick(); lock (_l) { Ended[Stage] = DateTime.UtcNow; } }
    public static void Tick() {
        long ws, pv; using (var p = Process.GetCurrentProcess()) { ws = p.WorkingSet64; pv = p.PrivateMemorySize64; }
        long h = GC.GetTotalMemory(false);
        lock (_l) {
            long[] a; if (!Peaks.TryGetValue(Stage, out a)) { a = new long[3]; Peaks[Stage] = a; }
            if (ws > a[0]) a[0] = ws; if (pv > a[1]) a[1] = pv; if (h > a[2]) a[2] = h;
        }
    }
    public static void Mark(string s) {
        Tick();
        lock (_l) {
            if (s == Stage && Peaks.ContainsKey(s)) return;
            Ended[Stage] = DateTime.UtcNow;
            Stage = s; if (!Order.Contains(s)) { Order.Add(s); Started[s] = DateTime.UtcNow; }
        }
        Tick();
    }
    public static long PeakWorkingSet() { using (var p = Process.GetCurrentProcess()) { return p.PeakWorkingSet64; } }
}
'@
}

# ------------------------------------------------------------------------------------------------------- the engine code
. (Join-Path $siRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
foreach ($f in 'StorageContext.ps1', 'StagingBlob.ps1') { . (Join-Path $siRoot "engine\asset-profiling\storage\$f") }
. (Join-Path $siRoot 'engine\_shared\SI-ErrorClass.ps1')
. (Join-Path $siRoot 'engine\_shared\SI-AzRest.ps1')
. (Join-Path $siRoot 'engine\_shared\SI-CollectParts.ps1')
. (Join-Path $siRoot 'engine\data-model\SI-RecordCapture.ps1')
. (Join-Path $siRoot 'engine\data-model\SI-RecordHandover.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\shared\SI-DiscoverStream.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIEntraContext.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIIntuneContext.ps1')
if ($Engine -eq 'azure') {
    # the Azure sources and every read after them (Invoke-SIDiscover dot-sources the two sources itself)
    . (Join-Path $siRoot 'engine\asset-profiling\discovery\Invoke-SIArgPaged.ps1')
    . (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1')
    . (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSummary.ps1')
    . (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    . (Join-Path $siRoot 'engine\asset-profiling\discovery\Get-SIAzureContext.ps1')
    $global:SI_DataModelOverlayRoot = $null
}
$null = Reset-SIRecordCapture -Engine $Engine -Clear
# progress / console noise off (the run's own lines still go to the information stream)
foreach ($n in 'Write-SIProgress', 'Reset-SIProgress') { Set-Item -Path "function:global:$n" -Value { param([Parameter(ValueFromRemainingArguments)]$x) } }

# ------------------------------------------------------------------------------------------------- generated answers
function script:Gid([string]$p, [long]$i) { '{0}-{1:x4}-4{2:x3}-8{3:x3}-{4:x12}' -f $p, (($i -shr 48) -band 0xffff), (($i -shr 36) -band 0xfff), (($i -shr 24) -band 0xfff), ($i -band 0xffffffffffff) }
$script:IdPad = ('p' * [Math]::Max(0, $EgIdentityPad))
$script:DevPad = ('d' * [Math]::Max(0, $EgDevicePad))

function script:New-EgIdentityRow([string]$Label, [long]$i) {
    # ids: Entra-linked nodes (the first EgUsersAad users / EgGroupsAad groups) carry the Entra object id; every other node is an
    # on-prem AD account / group with a domain SID (AD-only -- recorded as an AD identity)
    $sid = 'S-1-5-21-1004336348-1177238915-682003330-{0}' -f (100000 + $i)
    $aad = $null
    switch ($Label) {
        'user' { if ($i -lt $Size.EgUsersAad) { $aad = Gid 'a0000000' $i } }
        'group' { if ($i -lt $Size.EgGroupsAad) { $aad = Gid 'b0000000' $i } }
        default { $aad = Gid 'c0000000' $i }
    }
    $eids = New-Object System.Collections.Generic.List[string]
    if ($Label -in 'user', 'group') { $eids.Add(('{{\"type\":\"SecurityIdentifier\",\"id\":\"{0}\"}}' -f $sid)) }
    if ($aad) { $eids.Add(('{{\"type\":\"AadObjectId\",\"id\":\"tenantid=f0000000-0000-4000-8000-000000000000;objectid={0}\"}}' -f $aad)) }
    $eids.Add(('{{\"type\":\"AdObjectGuid\",\"id\":\"{0}\"}}' -f (Gid 'd0000000' $i)))
    $name = '{0}{1}' -f $Label, $i
    $raw = '{{"accountName":"{0}","accountDomain":"contoso.local","accountSid":"{1}","accountUpn":"{0}@contoso.example","accountDisplayName":"{2} {3}","department":"School {4}","jobTitle":"Pupil","isActive":true,"accountEnabled":true,"lastSeen":"2026-10-01T08:00:00Z","whenCreated":"2019-08-12T10:11:12Z","adminCount":0,"userAccountControl":["NormalAccount","DontExpirePassword"],"nestedCriticalAdGroups":[],"criticalityLevel":4,"distinguishedName":"CN={2} {3},OU=Pupils,OU=School {4},DC=contoso,DC=local","primaryGroupSid":"S-1-5-21-1004336348-1177238915-682003330-513","pwdLastSet":"2026-03-01T00:00:00Z","lastLogonTimestamp":"/Date(1760608800000)/","lastSeenText":"2026-10-15 07:55:00","isMfaRegistered":false,"hasLeakedCredentials":false,"onPremSyncEnabled":{5},"tags":["school","pupil"],"identityMetadata":{{"source":"ActiveDirectory","lastModified":"2026-10-01T00:00:00Z"}},"pad":"{6}"}}' -f $name, $sid, $Label, $i, ($i % 400), $(if ($aad) { 'true' } else { 'false' }), $script:IdPad
    if ($aad) { $raw = $raw.Replace('"accountName"', ('"accountObjectId":"{0}","accountName"' -f $aad)) }
    [pscustomobject]@{ NodeId = ('{0}-{1}' -f $Label, (Gid 'e0000000' $i)); NodeLabel = $Label; NodeName = $name; Categories = '["identity"]'
        EntityIds = ('[' + (($eids | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'); NodeProperties = ('{"rawData":' + $raw + '}') }
}

function script:Get-EgIdentityLabelCount([string]$Label) {
    switch ($Label) { 'user' { $Size.EgUsers } 'group' { $Size.EgGroups } 'serviceprincipal' { $Size.EgSps } 'managedidentity' { $Size.EgMis } default { 0 } }
}

function script:New-DeviceNodeRow([long]$i, [switch]$Short) {
    $aad = Gid 'f1000000' $i; $mde = '{0:x40}' -f $i
    $raw = '{{"deviceName":"pc{0}.contoso.local","osPlatform":"Windows11","osVersion":"10.0.22631","deviceCategory":"Endpoint","deviceType":"Workstation","onboardingStatus":"Onboarded","sensorHealthState":"Active","exposureScore":"Medium","riskScore":"Low","criticalityLevel":3,"aadDeviceId":"{1}","antivirusEnabled":true,"isExcluded":false,"lastSeen":"2026-10-15T10:00:00Z","machineGroup":"School {2}","ipAddresses":["10.{3}.{4}.{5}"],"publicIP":"198.51.100.{5}","tags":["school"],"pad":"{6}"}}' -f $i, $aad, ($i % 400), (($i -shr 16) -band 255), (($i -shr 8) -band 255), ($i -band 255), $script:DevPad
    $props = '{"rawData":' + $raw + '}'
    if ($Short) { return [pscustomobject]@{ NodeId = ('dev-{0}' -f (Gid 'e1000000' $i)); NodeName = "pc$i.contoso.local"; NodePropertiesJson = $props } }
    [pscustomobject]@{ NodeId = ('dev-{0}' -f (Gid 'e1000000' $i)); NodeName = "pc$i.contoso.local"; NodeLabel = 'device'
        EntityIds = @(('{{"type":"SenseDeviceId","id":"{0}"}}' -f $mde), ('{{"type":"AadDeviceId","id":"{0}"}}' -f $aad)); NodePropertiesJson = $props }
}

function script:Get-Slice([long]$Total, [string]$Query) {
    # a hash bucket of a hunting query -> the indexes it answers (every node in exactly one bucket)
    $n = 1L; $b = 0L
    if ($Query -match 'hash\(NodeId, (\d+)\)(?: \| where _bucket)? == (\d+)') { $n = [long]$Matches[1]; $b = [long]$Matches[2] }
    elseif ($Query -match 'hash\(NodeId, (\d+)\) \| where _bucket == (\d+)') { $n = [long]$Matches[1]; $b = [long]$Matches[2] }
    for ($i = $b; $i -lt $Total; $i += $n) { $i }
}

function script:Get-PageJson([string]$Kind, [long]$i) {
    switch ($Kind) {
        'users' {
            '{{"id":"{0}","displayName":"User {1}","userPrincipalName":"user{1}@contoso.example","accountEnabled":true,"createdDateTime":"2020-08-01T10:00:00Z","jobTitle":"Pupil","department":"School {2}","onPremisesSyncEnabled":true,"mail":"user{1}@contoso.example","userType":"Member","assignedLicenses":[{{"disabledPlans":[],"skuId":"94763226-9b3c-4e75-a931-5c89701abe66"}},{{"disabledPlans":[],"skuId":"314c4481-f395-4525-be8b-2ec4bb1e9d91"}}],"signInActivity":{{"lastSignInDateTime":"2026-10-14T07:55:00Z","lastNonInteractiveSignInDateTime":"2026-10-15T07:55:00Z","lastSignInRequestId":"{3}"}},"customSecurityAttributes":null}}' -f (Gid 'a0000000' $i), $i, ($i % 400), (Gid '90000000' $i)
        }
        'sps' {
            '{{"id":"{0}","displayName":"App {1}","appId":"{2}","servicePrincipalType":"Application","signInAudience":"AzureADMyOrg","accountEnabled":true,"publisherName":"Contoso","verifiedPublisher":{{}},"appOwnerOrganizationId":"f0000000-0000-4000-8000-000000000000","passwordCredentials":[],"keyCredentials":[{{"keyId":"{3}","type":"AsymmetricX509Cert","usage":"Verify","endDateTime":"2027-01-01T00:00:00Z","displayName":"CN=app{1}"}}],"tags":["WindowsAzureActiveDirectoryIntegratedApp"],"homepage":null,"customSecurityAttributes":null,"createdDateTime":"2022-01-01T00:00:00Z"}}' -f (Gid 'c0000000' $i), $i, (Gid '91000000' $i), (Gid '92000000' $i)
        }
        'mfa' {
            '{{"id":"{0}","userPrincipalName":"user{1}@contoso.example","userDisplayName":"User {1}","userType":"member","isAdmin":false,"isSsprRegistered":false,"isSsprEnabled":true,"isSsprCapable":false,"isMfaRegistered":{2},"isMfaCapable":{2},"isPasswordlessCapable":false,"methodsRegistered":["{3}"],"isSystemPreferredAuthenticationMethodEnabled":true,"systemPreferredAuthenticationMethods":[],"userPreferredMethodForSecondaryAuthentication":"none","lastUpdatedDateTime":"2026-10-10T00:00:00Z","defaultMfaMethod":"none"}}' -f (Gid 'a0000000' $i), $i, $(if ($i % 5) { 'false' } else { 'true' }), $(if ($i % 5) { 'email' } else { 'microsoftAuthenticatorPush' })
        }
        'devices' {
            '{{"id":"{0}","deviceId":"{1}","displayName":"pc{2}","operatingSystem":"Windows","deviceCategory":null,"trustType":"AzureAd","profileType":"RegisteredDevice","registrationDateTime":"2023-08-01T00:00:00Z","approximateLastSignInDateTime":"2026-10-15T00:00:00Z","accountEnabled":true}}' -f (Gid 'f2000000' $i), (Gid 'f1000000' $i), $i
        }
        'owners' {
            '{{"id":"{0}","deviceId":"{1}","registeredOwners":[{{"@odata.type":"#microsoft.graph.user","id":"{2}","displayName":"User {3}","userPrincipalName":"user{3}@contoso.example"}}]}}' -f (Gid 'f2000000' $i), (Gid 'f1000000' $i), (Gid 'a0000000' $i), $i
        }
        'intune' {
            '{{"id":"{0}","deviceName":"pc{1}","userPrincipalName":"user{1}@contoso.example","azureADDeviceId":"{2}","operatingSystem":"Windows","osVersion":"10.0.22631.4317","complianceState":"compliant","managedDeviceOwnerType":"company","enrolledDateTime":"2023-08-01T00:00:00Z","lastSyncDateTime":"2026-10-15T06:00:00Z","isEncrypted":true,"model":"Latitude 3440","manufacturer":"Dell Inc.","serialNumber":"SN{1}","managementAgent":"mdm","deviceEnrollmentType":"windowsAzureADJoin","autopilotEnrolled":true,"jailBroken":"Unknown","totalStorageSpaceInBytes":255426048000,"freeStorageSpaceInBytes":112426048000,"wiFiMacAddress":"001122{1:x6}","ethernetMacAddress":null,"physicalMemoryInBytes":0}}' -f (Gid 'f3000000' $i), $i, (Gid 'f1000000' $i)
        }
        'mde' {
            '{{"id":"{0:x40}","computerDnsName":"pc{0}.contoso.local","firstSeen":"2023-08-01T00:00:00Z","lastSeen":"2026-10-15T10:00:00Z","osPlatform":"Windows11","version":"23H2","osProcessor":"x64","lastIpAddress":"10.1.{1}.{2}","lastExternalIpAddress":"198.51.100.{2}","healthStatus":"Active","onboardingStatus":"Onboarded","rbacGroupName":"School {3}","rbacGroupId":{3},"riskScore":"Low","exposureLevel":"Medium","isAadJoined":true,"aadDeviceId":"{4}","machineTags":["school"],"defenderAvStatus":"Updated","osBuild":22631,"managedBy":"Intune","managedByStatus":"Success","deviceValue":"Normal","ipAddresses":[{{"ipAddress":"10.1.{1}.{2}","macAddress":"001122334455","type":"Ethernet","operationalStatus":"Up"}}]}}' -f $i, (($i -shr 8) -band 255), ($i -band 255), ($i % 400), (Gid 'f1000000' $i)
        }
    }
}

function script:Get-PagedAnswer([string]$Kind, [long]$Total, [string]$Uri, [int]$PageSize) {
    $start = 0L; if ($Uri -match '[?&]\$?skiptoken=(\d+)') { $start = [long]$Matches[1] }
    $end = [Math]::Min($Total, $start + $PageSize)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"value":[')
    for ($i = $start; $i -lt $end; $i++) { if ($i -gt $start) { [void]$sb.Append(',') }; [void]$sb.Append((Get-PageJson $Kind $i)) }
    [void]$sb.Append(']')
    if ($end -lt $Total) { $base = ($Uri -replace '[?&]\$?skiptoken=\d+', ''); $sep = if ($base.Contains('?')) { '&' } else { '?' }; [void]$sb.Append((',"@odata.nextLink":"{0}{1}$skiptoken={2}"' -f $base, $sep, $end)) }
    [void]$sb.Append('}')
    ConvertFrom-Json -InputObject $sb.ToString()
}

# ------------------------------------------------------------------------------- the Azure estate (#727), generated per row
function script:AzRg([long]$u) { '/subscriptions/{0}/resourcegroups/rg{1}' -f (Gid '5a000000' ($u % $Size.Subs)), ($u % 50) }
function script:AzIds([long]$u) {
    $rg = AzRg $u
    $vm = "$rg/providers/microsoft.compute/virtualmachines/vm$u"; $nic = "$rg/providers/microsoft.network/networkinterfaces/nic$u"
    @{ Rg = $rg; Vm = $vm; Nic = $nic; Disk = "$rg/providers/microsoft.compute/disks/vm${u}_osdisk"; PipA = "$rg/providers/microsoft.network/publicipaddresses/pip${u}a"
        PipB = "$rg/providers/microsoft.network/publicipaddresses/pip${u}b"; Ext1 = "$vm/extensions/mde.windows"; Ext2 = "$vm/extensions/azuremonitorwindowsagent"
        Kv = "$rg/providers/microsoft.keyvault/vaults/kv$u"; Sa = "$rg/providers/microsoft.storage/storageaccounts/sa$u"
        NicOrphan = "$rg/providers/microsoft.network/networkinterfaces/nic${u}-lost"; VmMissing = "$rg/providers/microsoft.compute/virtualmachines/vm${u}-gone"
        DiskOrphan = "$rg/providers/microsoft.compute/disks/spare$u"; Dcr = "$rg/providers/microsoft.insights/datacollectionrules/dcr$u" }
}
function script:New-AzArgRow([long]$n) {
    # row n of the Resource Graph answer: unit n / 12, slot n % 12 (a child before its parent where the slot says so)
    $u = [long][Math]::Floor($n / 12); $slot = $n % 12; $x = AzIds $u
    $sub = Gid '5a000000' ($u % $Size.Subs)
    $mk = {
        param([string]$Id, [string]$Type, [string]$Props, [string]$Sku = 'null')
        [pscustomobject]@{ ResourceId = $Id; Type = $Type; Name = ($Id -split '/')[-1]; Location = 'westeurope'; RG = ('rg{0}' -f ($u % 50)); Subscription = $sub
            PropertiesJson = $Props; TagsJson = ('{{"owner":"team{0}","env":"prod"}}' -f ($u % 7)); IdentityJson = 'null'; SkuJson = $Sku; Kind = ''; EnvTag = 'prod'; OwnerTag = ('team{0}' -f ($u % 7)) }
    }
    switch ($slot) {
        0 { $r = & $mk $x.Disk 'microsoft.compute/disks' '{"diskSizeGB":128,"osType":"Windows","encryption":{"type":"EncryptionAtRestWithPlatformKey"}}' '{"name":"Premium_LRS"}'; $r | Add-Member -NotePropertyName FullManagedBy -NotePropertyValue $x.Vm; return $r }
        1 { return (& $mk $x.PipA 'microsoft.network/publicipaddresses' ('{{"ipAddress":"20.{0}.{1}.{2}","ipConfiguration":{{"id":"{3}/ipconfigurations/ipconfig1"}}}}' -f (($u -shr 16) -band 255), (($u -shr 8) -band 255), ($u -band 255), $x.Nic)) }
        2 { return (& $mk $x.Vm 'microsoft.compute/virtualmachines' ('{{"hardwareProfile":{{"vmSize":"Standard_D2s_v5"}},"storageProfile":{{"osDisk":{{"name":"vm{0}_osdisk","managedDisk":{{"id":"{1}"}}}}}},"osProfile":{{"computerName":"vm{0}"}}}}' -f $u, $x.Disk)) }
        3 { return (& $mk $x.Ext1 'microsoft.compute/virtualmachines/extensions' '{"type":"MDE.Windows","publisher":"Microsoft.Azure.AzureDefenderForServers","typeHandlerVersion":"1.0"}') }
        4 { return (& $mk $x.Ext2 'microsoft.compute/virtualmachines/extensions' '{"type":"AzureMonitorWindowsAgent","publisher":"Microsoft.Azure.Monitor","typeHandlerVersion":"1.2"}') }
        5 { return (& $mk $x.Nic 'microsoft.network/networkinterfaces' ('{{"virtualMachine":{{"id":"{0}"}},"ipConfigurations":[{{"properties":{{"privateIPAddress":"10.0.{1}.{2}"}}}}]}}' -f $x.Vm, (($u -shr 8) -band 255), ($u -band 255))) }
        6 { return (& $mk $x.PipB 'microsoft.network/publicipaddresses' ('{{"ipAddress":"52.{0}.{1}.{2}","ipConfiguration":{{"id":"{3}/ipconfigurations/ipconfig2"}}}}' -f (($u -shr 16) -band 255), (($u -shr 8) -band 255), ($u -band 255), $x.Nic)) }
        7 { return (& $mk $x.Kv 'microsoft.keyvault/vaults' '{"enableSoftDelete":true,"enablePurgeProtection":false,"publicNetworkAccess":"Enabled"}' '{"family":"A","name":"standard"}') }
        8 { return (& $mk $x.Sa 'microsoft.storage/storageaccounts' '{"allowBlobPublicAccess":false,"minimumTlsVersion":"TLS1_2","supportsHttpsTrafficOnly":true}' '{"name":"Standard_LRS"}') }
        9 { return (& $mk $x.NicOrphan 'microsoft.network/networkinterfaces' ('{{"virtualMachine":{{"id":"{0}"}}}}' -f $x.VmMissing)) }
        10 { return (& $mk $x.DiskOrphan 'microsoft.compute/disks' '{"diskSizeGB":64}' '{"name":"Standard_LRS"}') }
        default { return (& $mk $x.Dcr 'microsoft.insights/datacollectionrules' '{"description":"collect"}') }
    }
}
function script:New-AzEgRow([long]$n) {
    # node n of the Exposure Graph's Azure nodes: per unit the machine, an extension (a child seen by the graph first) and the key vault
    $u = [long][Math]::Floor($n / 3); $x = AzIds $u
    $id = $x.Vm; $label = 'microsoft.compute/virtualmachines'
    if (($n % 3) -eq 1) { $id = $x.Ext1; $label = 'microsoft.compute/virtualmachines/extensions' } elseif (($n % 3) -eq 2) { $id = $x.Kv; $label = 'microsoft.keyvault/vaults' }
    [pscustomobject]@{ NodeId = ('az-{0}' -f (Gid 'e2000000' $n)); NodeName = ($id -split '/')[-1]; NodeLabel = $label
        EntityIds = ('[{{"type":"AzureResourceId","id":"{0}"}}]' -f $id)
        NodePropertiesJson = ('{{"rawData":{{"resourceId":"{0}","exposureScore":"Medium","criticalityLevel":{1},"isProductionEnvironment":true,"hasInternetExposureSignal":{2}}}}}' -f $id, ($u % 4), $(if ($u % 2) { 'true' } else { 'false' })) }
}
function script:Get-AzPage([long]$Total, $SkipToken, [int]$First, [scriptblock]$Row) {
    $start = 0L; if ($SkipToken) { $start = [long]$SkipToken }
    if ($First -le 0) { $First = 100 }
    $end = [Math]::Min($Total, $start + $First)
    $rows = New-Object System.Collections.Generic.List[object]
    for ($j = $start; $j -lt $end; $j++) { $rows.Add((& $Row $j)) }
    $next = $null; if ($end -lt $Total) { $next = [string]$end }
    $p = New-SIAzGraphPage -Rows $rows.ToArray() -SkipToken $next
    return , $p
}
function global:Search-SIScaleAzGraph {
    [CmdletBinding()] param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
    $q = [string]$Query; $U = [long]$Size.Units
    if ($q -match '^\s*Resources' -and $q -match '\|\s*count\s*$') { return , (New-SIAzGraphPage -Rows @([pscustomobject]@{ Count = $Size.Resources })) }
    if ($q -match '^\s*Resources') { [SIScaleProbe]::Mark('source AzureResources (Resource Graph pages)'); return , (Get-AzPage $Size.Resources $SkipToken $First { param($j) New-AzArgRow $j }) }
    if ($q -match "microsoft.security/assessments" -and $q -match 'Assessments = make_set') {
        [SIScaleProbe]::Mark('Defender for Cloud (exposure, assessment summary)')
        return , (Get-AzPage ([long][Math]::Ceiling($U / 4.0)) $SkipToken $First { param($j) [pscustomobject]@{ ResourceId = (AzIds ($j * 4)).Vm; Assessments = @('Management ports should be closed on your virtual machines') } })
    }
    if ($q -match "microsoft.security/assessments") {
        return , (Get-AzPage ($U * 2) $SkipToken $First { param($j) $x = AzIds ([long][Math]::Floor($j / 2)); $id = if ($j % 2) { $x.Disk } else { $x.Vm }
                [pscustomobject]@{ ResourceId = $id; Assessed = 6; Unhealthy = 2; High = 1; Medium = 1; Low = 0; OldestUnhealthy = '2026-09-01T00:00:00Z'; NewestChange = '2026-10-10T00:00:00Z'
                    TopHigh = @([pscustomobject]@{ id = 'a1'; name = 'Endpoint protection should be installed'; severity = 'High' }); TopMedium = @([pscustomobject]@{ id = 'a2'; name = 'Disk encryption'; severity = 'Medium' }); TopLow = @() } })
    }
    if ($q -match '^\s*resourcecontainers') {
        [SIScaleProbe]::Mark('management groups + Azure context')
        return , (Get-AzPage $Size.Subs $SkipToken $First { param($j) [pscustomobject]@{ SubscriptionId = (Gid '5a000000' $j); SubscriptionName = "sub-$j"; TenantId = 'f0000000-0000-4000-8000-000000000000'
                    Chain = @([pscustomobject]@{ name = "mg$($j % 5)"; displayName = "Landing zone $($j % 5)" }, [pscustomobject]@{ name = 'root'; displayName = 'Tenant Root Group' }) } })
    }
    if ($q -match '^\s*recoveryservicesresources') {
        return , (Get-AzPage ([long][Math]::Ceiling($U / 2.0)) $SkipToken $First { param($j) $x = AzIds ($j * 2)
                [pscustomobject]@{ ResourceId = $x.Vm; LastTime = '2026-10-15T01:00:00Z'; LastStatus = 'Completed'; State = 'Protected'; PolicyId = '/subscriptions/x/policies/daily'; PolicyName = 'daily'; VaultId = "$($x.Rg)/providers/microsoft.recoveryservices/vaults/rsv"; VaultName = 'rsv'; Items = 1 } })
    }
    if ($q -match '^\s*authorizationresources') {
        return , (Get-AzPage $U $SkipToken $First { param($j) $x = AzIds $j; $scope = if ($j % 2) { $x.Kv } else { $x.Rg }
                [pscustomobject]@{ Scope = $scope; Assignments = @([pscustomobject]@{ p = (Gid 'b0000000' ($j % 40)); t = 'User'; r = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' }, [pscustomobject]@{ p = (Gid 'b1000000' ($j % 11)); t = 'ServicePrincipal'; r = 'b24988ac-6180-42a0-ab88-20f7382dd24c' }) } })
    }
    if ($q -match 'policyinsights/policystates') {
        return , (Get-AzPage ([long][Math]::Ceiling($U / 3.0)) $SkipToken $First { param($j) $x = AzIds ($j * 3)
                [pscustomobject]@{ ResourceId = $x.Kv; NonCompliant = 3; Top = @([pscustomobject]@{ id = '/providers/microsoft.authorization/policydefinitions/p1'; name = 'Key vaults should have purge protection enabled' }, [pscustomobject]@{ id = '/providers/microsoft.authorization/policydefinitions/p2'; name = '' }) } })
    }
    if ($q -match '^\s*policyresources') {
        return , (Get-AzPage 2 $SkipToken $First { param($j) [pscustomobject]@{ PolicyId = ('/providers/microsoft.authorization/policydefinitions/p{0}' -f ($j + 1)); PolicyName = ('Policy {0}' -f ($j + 1)) } })
    }
    if ($q -match '^\s*resourcechanges') {
        return , (Get-AzPage $U $SkipToken $First { param($j) $x = AzIds $j
                # half the change times as dates (what a parsed answer holds), half as text
                $t = '2026-10-{0:D2}T{1:D2}:15:00Z' -f (1 + ($j % 14)), ($j % 24); $tv = $t; if ($j % 2) { $tv = [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) }
                [pscustomobject]@{ ResourceId = $x.Sa; ChangeTime = $tv; ChangedBy = (Gid 'c1000000' ($j % 25)); ChangedByType = 'Application'; ChangeType = 'Update'; ClientType = 'ARM template'; Changes = (1 + ($j % 5)) } })
    }
    if ($q -match '^\s*patchassessmentresources') {
        return , (Get-AzPage $U $SkipToken $First { param($j) [pscustomobject]@{ ResourceId = (AzIds $j).Vm; AssessedAt = '2026-10-14T02:00:00Z'; Critical = ($j % 3); Security = ($j % 6); RebootPending = (($j % 2) -eq 0); Status = 'Succeeded' } })
    }
    if ($q -match "microsoft.security/pricings") {
        $plans = @('VirtualMachines', 'KeyVaults', 'StorageAccounts', 'CloudPosture')
        return , (Get-AzPage ($Size.Subs * 4) $SkipToken $First { param($j) [pscustomobject]@{ SubscriptionId = (Gid '5a000000' ([long][Math]::Floor($j / 4))); Plan = $plans[$j % 4]; Tier = $(if ($j % 3) { 'Standard' } else { 'Free' }); SubPlan = $(if (($j % 4) -eq 0) { 'P2' } else { '' }) } })
    }
    , (New-SIAzGraphPage -Rows @())
}
function global:Resolve-SIScaleAzNames { param([string[]]$Ids) $m = @{}; foreach ($i in @($Ids)) { if ($i) { $m[([string]$i).ToLowerInvariant()] = 'principal-' + ([string]$i).Substring(0, 8) } }; $m }
if ($Engine -eq 'azure') {
    Set-Alias -Name Search-SIAzGraph -Value Search-SIScaleAzGraph -Scope Global
    Set-Alias -Name Resolve-SIAzurePrincipalNames -Value Resolve-SIScaleAzNames -Scope Global
}

$script:Calls = @{}
function global:Invoke-SIScaleFakeRest {
    [CmdletBinding()]
    param([string]$Method = 'Get', $Uri, $Headers, $Body, $ContentType, [Parameter(ValueFromRemainingArguments)]$Rest)
    $u = [string]$Uri
    $script:Calls[$u -replace '\?.*$', ''] = 1 + [int]$script:Calls[$u -replace '\?.*$', '']
    if ($u -match 'runHuntingQuery' -and $Engine -eq 'azure') {
        $q = [string](($Body | ConvertFrom-Json).Query)
        if ($q -match 'distinct NodeLabel') { return [pscustomobject]@{ results = @('microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults', 'microsoft.authorization/roleassignments' | ForEach-Object { [pscustomobject]@{ NodeLabel = $_ } }) } }
        if ($q -match '\|\s*count\s*$') { return [pscustomobject]@{ results = @([pscustomobject]@{ Count = $Size.EgNodes }) } }
        [SIScaleProbe]::Mark('source ExposureGraph (Azure nodes)')
        return [pscustomobject]@{ results = @(foreach ($i in (Get-Slice $Size.EgNodes $q)) { New-AzEgRow $i }) }
    }
    if ($u -match 'runHuntingQuery') {
        $q = [string](($Body | ConvertFrom-Json).Query)
        if ($Engine -ne 'endpoint' -or $q -notmatch "NodeLabel (==|in \() ?['""]device['""]") { return [pscustomobject]@{ results = @() } }
        if ($q -match '\|\s*count\s*$') { return [pscustomobject]@{ results = @([pscustomobject]@{ Count = $Size.Devices }) } }
        if ($q -match 'NodePropertiesJson = tostring\(NodeProperties\)' -and $q -match 'NodeLabel, EntityIds') {
            [SIScaleProbe]::Mark('source EndpointEG (Exposure Graph endpoint nodes)')
            return [pscustomobject]@{ results = @(foreach ($i in (Get-Slice $Size.Devices $q)) { New-DeviceNodeRow $i }) }
        }
        [SIScaleProbe]::Mark('source ExposureGraph (device nodes)')
        return [pscustomobject]@{ results = @(foreach ($i in (Get-Slice $Size.Devices $q)) { New-DeviceNodeRow $i -Short }) }
    }
    if ($u -match '/\$count') {
        if ($u -match '/users/') { return [string]$Size.Users }
        if ($u -match '/servicePrincipals/') { return [string]$Size.Sps }
        if ($u -match '/devices/') { return [string]$Size.Entra }
        return '0'
    }
    if ($u -match 'graph\.microsoft\.com/v1\.0/users\?') { [SIScaleProbe]::Mark('source EntraUsers (user pages)'); return (Get-PagedAnswer 'users' $Size.Users $u 999) }
    if ($u -match 'graph\.microsoft\.com/v1\.0/servicePrincipals\?\$select=id,displayName,appId') { [SIScaleProbe]::Mark('source EntraServicePrincipals'); return (Get-PagedAnswer 'sps' $Size.Sps $u 999) }
    if ($u -match 'userRegistrationDetails') { [SIScaleProbe]::Mark('lookup MFA registrations'); return (Get-PagedAnswer 'mfa' $Size.Users $u 999) }
    if ($Engine -eq 'endpoint') {
        if ($u -match '/v1\.0/devices\?\$select=id,deviceId&\$expand=registeredOwners') { [SIScaleProbe]::Mark('context device owners'); return (Get-PagedAnswer 'owners' $Size.Entra $u 100) }
        if ($u -match '/v1\.0/devices\?') { [SIScaleProbe]::Mark('source Entra (devices)'); return (Get-PagedAnswer 'devices' $Size.Entra $u 999) }
        if ($u -match '/deviceManagement/managedDevices\?') { [SIScaleProbe]::Mark('Intune devices'); return (Get-PagedAnswer 'intune' $Size.Intune $u 999) }
        if ($u -match 'api\.securitycenter\.microsoft\.com/api/machines') { [SIScaleProbe]::Mark('source MDE (machines)'); return (Get-PagedAnswer 'mde' $Size.Mde $u 10000) }
    }
    return [pscustomobject]@{ value = @() }
}
Set-Alias -Name Invoke-RestMethod -Value Invoke-SIScaleFakeRest -Scope Global

# the Resource Graph source (Azure VMs / Arc machines): none in this tenant's endpoint estate -- an empty answer
function global:Get-SIScaleNoArg { param([Parameter(ValueFromRemainingArguments)]$x) @() }
Set-Alias -Name Get-DiscoveryFromARG -Value Get-SIScaleNoArg -Scope Global

function global:Get-SIScaleToken { param([Parameter(ValueFromRemainingArguments)]$x) 'fake-token' }
Set-Alias -Name Get-SIGraphToken -Value Get-SIScaleToken -Scope Global

function global:Invoke-SIScaleEgIdentityQuery {
    param([Parameter(Mandatory)][string]$Query, [int]$MaxAttempts = 3, [int]$BackoffBaseSeconds = 5)
    [SIScaleProbe]::Mark('lookup Exposure Graph identity nodes')
    $label = ''; if ($Query -match "NodeLabel == '([a-z]+)'") { $label = $Matches[1] }
    $total = Get-EgIdentityLabelCount $label
    if ($Query -match '\| count$') { return @{ Ok = $true; Rows = @([pscustomobject]@{ Count = $total }); Error = $null } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($i in (Get-Slice $total $Query)) { $rows.Add((New-EgIdentityRow $label $i)) }
    @{ Ok = $true; Rows = $rows.ToArray(); Error = $null }
}
Set-Alias -Name Invoke-SIEgIdentityQuery -Value Invoke-SIScaleEgIdentityQuery -Scope Global

function global:Invoke-SIScaleArm {
    param($Path, $ApiVersion, [switch]$List, $Method, $Body, [Parameter(ValueFromRemainingArguments)]$Rest)
    $p = [uri]::UnescapeDataString([string]$Path)
    if ($p -match '^/subscriptions$' -or $p -match '^/subscriptions\?') {
        [SIScaleProbe]::Mark('lookup Azure RBAC (role assignments per subscription)')
        return @(for ($s = 0; $s -lt $Size.Subs; $s++) { [pscustomobject]@{ subscriptionId = (Gid '5b000000' $s); displayName = "contoso-sub-$s"; state = 'Enabled'; tenantId = 'f0000000-0000-4000-8000-000000000000' } })
    }
    if ($p -like '*/roleDefinitions*') {
        if ($p -match "CustomRole") { return @() }
        return @(for ($r = 0; $r -lt 800; $r++) { [pscustomobject]@{ name = (Gid '6d000000' $r); properties = [pscustomobject]@{ roleName = "Role $r"; type = 'BuiltInRole' } } })
    }
    if ($p -like '*/roleAssignments*') {
        $sub = ($p -split '/')[2]
        return @(for ($k = 0; $k -lt $Size.AssignPerSub; $k++) {
            [pscustomobject]@{ id = "/subscriptions/$sub/providers/Microsoft.Authorization/roleAssignments/$k"; name = "$sub-$k"
                properties = [pscustomobject]@{ scope = $(if ($k -lt 10) { '/providers/Microsoft.Management/managementGroups/contoso' } else { "/subscriptions/$sub" })
                    principalId = (Gid 'a0000000' ($k * 37)); principalType = 'User'; roleDefinitionId = ('/providers/Microsoft.Authorization/roleDefinitions/{0}' -f (Gid '6d000000' ($k % 800))) } } })
    }
    @()
}
Set-Alias -Name Invoke-SIArm -Value Invoke-SIScaleArm -Scope Global
function global:Resolve-SIScalePrincipalNames { param([string[]]$Ids) @{} }
Set-Alias -Name Resolve-SIAzRestPrincipalNames -Value Resolve-SIScalePrincipalNames -Scope Global

function global:Get-SIScaleIdentityInfo {
    param([Parameter(ValueFromRemainingArguments)]$x)
    [SIScaleProbe]::Mark('lookup IdentityInfo (Defender for Identity)')
    $m = @{}
    for ($i = 0L; $i -lt $Size.Users; $i++) {
        $oid = Gid 'a0000000' $i
        $m[$oid] = [pscustomobject]@{ AccountObjectId = $oid; AccountUPN = "user$i@contoso.example"; AccountDisplayName = "User $i"; GroupMembership = '["Pupils","School ' + ($i % 400) + '"]'
            IsMFARegistered = $false; IsAccountEnabled = $true; IsServiceAccount = $false; RiskLevel = 'Low'; RiskState = 'None'; EntityRiskScore = 0; BlastRadius = 'Low'
            InvestigationPriority = 0; AssignedRoles = '[]'; OnPremisesDistinguishedName = "CN=User $i,OU=Pupils,DC=contoso,DC=local"; LastSeenDate = '2026-10-15T00:00:00Z'
            OnPremSid = ('S-1-5-21-1004336348-1177238915-682003330-{0}' -f (100000 + $i)); Department = 'School ' + ($i % 400); JobTitle = 'Pupil' }
    }
    $m
}
Set-Alias -Name Get-SIIdentityInfoByObjectId -Value Get-SIScaleIdentityInfo -Scope Global
$global:SI_WorkspaceResourceId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z'

# ------------------------------------------------------------- staging + the state store: local files (text, as the blobs)
$stageDir = Join-Path $WorkDir 'staging'; $stateDir = Join-Path $WorkDir 'state'
$null = New-Item -ItemType Directory -Force -Path $stageDir, $stateDir
$script:BytesStaged = 0L; $script:BytesHanded = 0L; $script:FilesHanded = 0
function global:Write-SIScaleStageShard {
    param($Context, $ContainerName, $RunId, $Stage, [int]$ShardIndex, [object[]]$Records, [int]$ReplicaIndex = 0, [Parameter(ValueFromRemainingArguments)]$x)
    $d = Join-Path $stageDir ('{0}\replica-{1:D3}' -f $Stage, $ReplicaIndex); $null = New-Item -ItemType Directory -Force -Path $d
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $Records) { [void]$sb.AppendLine((ConvertTo-Json -InputObject $r -Depth 20 -Compress)) }
    $t = $sb.ToString(); $script:BytesStaged += $t.Length
    [IO.File]::WriteAllText((Join-Path $d ('shard-{0:D5}.jsonl' -f $ShardIndex)), $t)
}
function global:Read-SIScaleStageShards {
    param($Context, $ContainerName, $RunId, $Stage, [int]$ReplicaIndex = -1, [scriptblock]$OnRecord, [Parameter(ValueFromRemainingArguments)]$x)
    if ($Stage -eq 'DiscoverRaw') { [SIScaleProbe]::Mark('stream route (raw buckets -> parts)') }
    if ($Stage -eq 'DiscoverRouted') { [SIScaleProbe]::Mark('stream merge (one part at a time)') }
    $d = Join-Path $stageDir ('{0}\replica-{1:D3}' -f $Stage, $ReplicaIndex)
    if (-not (Test-Path -LiteralPath $d)) { return }
    foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter '*.jsonl' | Sort-Object Name)) {
        foreach ($line in [IO.File]::ReadLines($f.FullName)) { if ($line) { if ($OnRecord) { & $OnRecord (ConvertFrom-Json -InputObject $line) } else { ConvertFrom-Json -InputObject $line } } }
    }
}
Set-Alias -Name Write-SIStageShard -Value Write-SIScaleStageShard -Scope Global
Set-Alias -Name Read-SIStageShards -Value Read-SIScaleStageShards -Scope Global
$script:StateStore = [pscustomobject]@{
    Read  = { param($Path) $f = Join-Path $stateDir $Path; if (Test-Path -LiteralPath $f) { [IO.File]::ReadAllText($f) } else { $null } }.GetNewClosure()
    Write = { param($Path, $Text) $f = Join-Path $stateDir $Path; $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $f); [IO.File]::WriteAllText($f, [string]$Text); $script:BytesHanded += ([string]$Text).Length; $script:FilesHanded++ }
    List  = { param($Prefix) $d = Join-Path $stateDir $Prefix; if (-not (Test-Path -LiteralPath $d)) { return @() }; @(Get-ChildItem -LiteralPath $d -Recurse -File | ForEach-Object { $Prefix.TrimEnd('/') + '/' + [IO.Path]::GetRelativePath($d, $_.FullName).Replace('\', '/') }) }.GetNewClosure()
    Claim = { param($Path, $Text) $true }
}
function global:New-SIScaleCollectBlobStore { param([Parameter(ValueFromRemainingArguments)]$x) $script:StateStore }
Set-Alias -Name New-SICollectBlobStore -Value New-SIScaleCollectBlobStore -Scope Global

# ------------------------------------------------------------------------------------------------------------ the run
$runId = '{0:yyyyMMddTHHmmssZ}-{1}-scale' -f [datetime]::UtcNow, $Engine
$global:SI_StorageAccount = 'scalefake'
$rc = [pscustomobject]@{
    Engine = $Engine; Phase = 'discover'; RunId = $runId; AssetLimit = 0; ShardCount = 1; ShardIndex = 0
    StorageContext = [pscustomobject]@{ Mode = 'Blob'; AccountName = 'scalefake' }; StagingContainer = 'sistaging'
    CollectionTime = [datetime]::UtcNow; StageResults = @{}
}
$global:SI_CollectRunInfo = [pscustomobject]@{ RunId = $runId; Phase = 'discover'; Parts = 0; CollectionTime = $rc.CollectionTime }

[GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
$baseWs = [Diagnostics.Process]::GetCurrentProcess().WorkingSet64
[SIScaleProbe]::Start($SampleMs)
$t0 = [datetime]::UtcNow
$err = ''
$discover = $null; $handed = 0; $buckets = 0; $recordCount = 0L; $recordChars = 0L
try {
    [SIScaleProbe]::Mark('discovery start (counts, role lookups)')
    if ($ShowLog) { $discover = Invoke-SIDiscover -RunContext $rc } else { $discover = Invoke-SIDiscover -RunContext $rc 6>$null 3>$null }
    # what the capture holds when discovery ends (before the hand-over)
    [SIScaleProbe]::Mark('records held at the end of discovery')
    if ($global:SIRecordCaptureState) {
        $recordCount = [long]$global:SIRecordCaptureState.Records.Count
        foreach ($r in $global:SIRecordCaptureState.Records.Values) { foreach ($p in $r.Parts.Values) { if ($p -and $p.PSObject.Properties['SIJson']) { $recordChars += ([string]$p.SIJson).Length } } }
    }
    $heldHeap = [GC]::GetTotalMemory($true)
    # the producer's hand-over, as container\Start-SIInContainer.ps1 does it
    [SIScaleProbe]::Mark('records hand-over (Save-SIRecordHandover)')
    $parts = [Math]::Max(1, [int]$global:SI_CollectRunInfo.Parts)
    # exactly as container\Start-SIInContainer.ps1 decides it (the #721 line: held + streamed; the release line: the held keys)
    if (Get-Command -Name Get-SIRecordCaptureCount -ErrorAction SilentlyContinue) { $buckets = Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount) -Parts $parts }
    elseif ($global:SIRecordCaptureState) { $buckets = Get-SIRecordBucketCount -Records ([long]@($global:SIRecordCaptureState.Records.Keys).Count) -Parts $parts }
    else { $buckets = $parts }
    $handed = Save-SIRecordHandover -Store (New-SICollectBlobStore -Account 'scalefake') -Engine $Engine -RunId $runId -Who 'discover' -Buckets $buckets
    [SIScaleProbe]::Mark('done')
} catch {
    $err = [string]$_.Exception.Message
    Write-Warning ('the measured run failed: {0}' -f $err)
} finally {
    [SIScaleProbe]::Stop()
}
$secs = ([datetime]::UtcNow - $t0).TotalSeconds

$stages = foreach ($s in [SIScaleProbe]::Order) {
    $pk = [SIScaleProbe]::Peaks[$s]; if ($null -eq $pk) { continue }
    $st = [SIScaleProbe]::Started[$s]; $en = $null; if ([SIScaleProbe]::Ended.ContainsKey($s)) { $en = [SIScaleProbe]::Ended[$s] }
    [ordered]@{ Stage = $s; PeakWorkingSetMB = [Math]::Round($pk[0] / 1MB); PeakPrivateMB = [Math]::Round($pk[1] / 1MB); PeakManagedHeapMB = [Math]::Round($pk[2] / 1MB)
        Seconds = $(if ($en) { [Math]::Round(($en - $st).TotalSeconds, 1) } else { $null }) }
}
$res = [ordered]@{
    Engine = $Engine; Scale = $Scale; Sizes = $Size; Commit = $(try { (git -C $siRoot rev-parse --short HEAD 2>$null) } catch { '' })
    Runtime = $PSVersionTable.PSVersion.ToString(); Seconds = [Math]::Round($secs, 1); Error = $err
    BaselineWorkingSetMB = [Math]::Round($baseWs / 1MB); PeakWorkingSetMB = [Math]::Round([SIScaleProbe]::PeakWorkingSet() / 1MB)
    Stages = @($stages)
    Discover = $(if ($discover) { [ordered]@{ AssetCount = $discover.AssetCount; Summary = [string]$discover.Summary } } else { $null })
    RecordsHeldAtEndOfDiscovery = $recordCount; RecordJsonCharsHeld = $recordChars; ManagedHeapAfterDiscoveryMB = $(if ($heldHeap) { [Math]::Round($heldHeap / 1MB) } else { $null })
    RecordsHandedOver = $handed; RecordBuckets = $buckets; HandoverFiles = $script:FilesHanded; HandoverMB = [Math]::Round($script:BytesHanded / 1MB); StagedMB = [Math]::Round($script:BytesStaged / 1MB)
    Parts = [int]$global:SI_CollectRunInfo.Parts; WorkDir = $WorkDir
}
$json = ConvertTo-Json -InputObject $res -Depth 6
if ($OutFile) { [IO.File]::WriteAllText($OutFile, $json) }
$json
if (-not $KeepFiles) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
