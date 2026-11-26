#Requires -Version 7.0
<#
    Measure-SIRowBuilderSpeed.ps1 -- #1389: the four profile row builders, BEFORE vs AFTER, on the same fixtures.

    Owner 2026-11-25 ("Yes, all builders"): fix the per-row Get-Command cost in the identity row builder and the same
    pattern in the endpoint / Azure / public IP builders -- IDENTICAL OUTPUT, measured before/after, one path for every size.

    What it does, per engine (identity, endpoint, azure, publicip):
      1. The BEFORE tree is `git archive <BaseRef> SOLUTIONS/SecurityInsight`, unpacked to a temp folder; the AFTER tree is
         this checkout.
      2. Each builder runs in its OWN runspace in THIS process (the four builders define the same function names, so they
         cannot share a scope), dot-sourced inside a script block -- the way Invoke-Output dot-sources it inside a function.
         ONE process on purpose: .NET randomises string hashing per process, so a hashtable's key order -- and with it the
         JSON of every nested hashtable and the four row hashes -- is only comparable within one process.
      3. The fixtures (synthetic records only, no customer data) are built twice per engine: in-process shape (hashtable
         Metadata, as Classify hands them over) and the staging-blob shape (JSON round trip -> PSCustomObject).
      4. OUTPUT: every built row is serialised with ConvertTo-Json -Depth 20 -Compress. The first row of each fixture AND the
         last timed row of each fixture must be byte-identical between BEFORE and AFTER -- the last one proves a builder that
         now loads its helpers once still builds row N exactly like row 1.
      5. SPEED: -Rows rows (cycling the fixtures) after -Warmup rows, ms/row reported for BEFORE and AFTER.

    Exit code 0 = every row identical; 1 = a difference (named, with the first differing column). Runs on the Azure test
    runner (never on the development machine):
      Use-InvardiaTestContainer.ps1 -Session si -Lane rowspeed -Ref <commit> -Run 'pwsh -NoProfile -File ./SOLUTIONS/SecurityInsight/tests/scale/Measure-SIRowBuilderSpeed.ps1'
#>
[CmdletBinding()]
param(
    [string]$BaseRef = '1e64b83d0',
    [ValidateRange(10, 100000)][int]$Rows = 300,
    [ValidateRange(0, 1000)][int]$Warmup = 5,
    [string[]]$Engine = @('identity', 'endpoint', 'azure', 'publicip')
)
$ErrorActionPreference = 'Stop'

$afterSi = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$repoRoot = (& git -c safe.directory=* -C $afterSi rev-parse --show-toplevel).Trim()
$headSha = (& git -c safe.directory=* -C $repoRoot rev-parse HEAD).Trim()
$baseSha = (& git -c safe.directory=* -C $repoRoot rev-parse "$BaseRef^{commit}" 2>$null)
if (-not $baseSha) { throw "the BEFORE commit '$BaseRef' is not in this clone -- the comparison cannot run (a skip is not a pass)" }
$baseSha = ([string]$baseSha).Trim()

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-rowspeed-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
$tar = Join-Path $tmp 'before.tar'
& git -c safe.directory=* -C $repoRoot archive --format=tar -o $tar $baseSha -- SOLUTIONS/SecurityInsight
if ($LASTEXITCODE -ne 0) { throw "git archive $baseSha failed" }
& tar -xf $tar -C $tmp
if ($LASTEXITCODE -ne 0) { throw 'tar -xf failed' }
$beforeSi = Join-Path $tmp 'SOLUTIONS/SecurityInsight'

"row builder speed + identical output (#1389): before $baseSha, after $headSha; pwsh $($PSVersionTable.PSVersion), $([Environment]::ProcessorCount) cpu(s), $Rows timed row(s) after $Warmup warm-up row(s)"

# ------------------------------------------------------------------------------------------------ the fixtures
# PowerShell text, evaluated in each runspace, so BEFORE and AFTER get the very same objects. Synthetic values only.
$fixtures = @{}
$fixtures['identity'] = @'
$egUser = [ordered]@{ '@odata.type' = '#microsoft.graph.user'; accountObjectId = $null; isSensitive = $false; sidHistory = @(); alternativeNames = @('x=y')
    nested = [ordered]@{ '@odata.type' = '#Collection(String)'; values = @('a', 'b') } }
$egMi = [ordered]@{ managedIdentityMetadata = [ordered]@{ accountType = 'UserAssignedManagedIdentity'; attachedResourceId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app/providers/Microsoft.Web/sites/app1' }
    alternativeNames = @('isExplicit=True', '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app/providers/Microsoft.Web/sites/app1') }
$ts = { param($o) ($o | ConvertTo-Json -Depth 8 -Compress) }
@(
    [pscustomobject]@{ AssetId = 'entra-user:11111111-0000-0000-0000-000000000001'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; SI_Classify_Status = 'catalog'
        CmdbMatchPhase = 'orphan'; CmdbSource = 'none'; cmdbId = @{}; cmdbName = 'Payroll'
        Metadata = @{ ENTRA_AssetType = 'User'; ENTRA_UserId = '11111111-0000-0000-0000-000000000001'; ENTRA_UPN = 'First.Last@contoso.example'; ENTRA_Mail = 'First.Last@contoso.example'
            ENTRA_DisplayName = 'First Last'; ENTRA_Enabled = $true; ENTRA_UserType = 'Member'; ENTRA_OnPrem = $true; ENTRA_OnPremSID = 'S-1-5-21-1-2-3-1001'
            ENTRA_OnPremObjectId = '22222222-0000-0000-0000-000000000001'; ENTRA_OnPremSamAccountName = 'flast'; ENTRA_LastSignInDays = 5; ENTRA_Department = 'Sales'
            ENTRA_LicenseSkuIds = @('33333333-0000-0000-0000-000000000001'); ENTRA_Groups = @('Group 1', 'Group 2', 'Domain Admins'); ENTRA_Groups_Critical = @('Domain Admins')
            ENTRA_DirectoryRolesPermanent = @('Global Administrator'); ENTRA_DirectoryRolesEligible = @('Security Reader'); ENTRA_AzureDelegations = @()
            ENTRA_MfaIsRegistered = $true; ENTRA_MfaMethods = @('microsoftAuthenticatorPush', 'sms'); ENTRA_MfaMethodCount = 2
            ENTRA_CustomSecurityAttributes = @{ SISet = @{ '@odata.type' = '#microsoft.graph.customSecurityAttributeValue'; tier = 'tier-0' } }
            ENTRA_EgRawData = $egUser; EG_NodeId = 'eg-node-user-1'; CMDB_name = 'Payroll'; CMDB_owner = 'HR' }
        Verdict = [pscustomobject]@{ SI_Tier = 0; SI_Group = 'Admins'; SI_ServiceType = 'User'; IsBreakGlass = $false
            SI_RuleMatches = @([pscustomobject]@{ RuleId = 'r-ga'; DetectionId = 'd1'; Tier = 0 })
            TierSources = (& $ts @{ EntraID_Roles_Permanent = @{ CatalogMatches = @(@{ Role = 'Global Administrator'; Tier = 0; Reason = 'catalog' }) }
                    EntraID_Roles_Eligible = @{ CatalogMatches = @(@{ Role = 'Security Reader'; Tier = 2 }) }; EntraID_APIPermissions = @{ CatalogMatches = @() }
                    AD = @{ CatalogMatches = @(@{ Name = 'Domain Admins'; Tier = 0; Reason = 'builtin' }) }
                    Azure = @{ Assignments = @(@{ RoleName = 'Owner'; ScopeLabel = 'sub-1'; EffectiveTier = 0 }, @{ RoleName = 'Reader'; EffectiveTier = 2 }) } }) } }
    [pscustomobject]@{ AssetId = 'entra-sp:11111111-0000-0000-0000-000000000002'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; SI_Classify_Status = 'no-ai'
        Metadata = @{ ENTRA_AssetType = 'ServicePrincipal'; ENTRA_SPObjectId = '11111111-0000-0000-0000-000000000002'; ENTRA_DisplayName = 'Contoso Sync App'; ENTRA_SPType = 'Application'
            ENTRA_SPAppId = '44444444-0000-0000-0000-000000000002'; ENTRA_SPAppOwnerTenant = '55555555-0000-0000-0000-000000000002'; ENTRA_SPPublisher = 'Contoso'
            ENTRA_AppPermissions_Application = @('Directory.ReadWrite.All', 'Mail.Read'); ENTRA_Enabled = $true }
        Verdict = [pscustomobject]@{ SI_Tier = 1; SI_RuleTier = 1; SI_Group = 'Apps'; SI_ServiceType = 'MultiTenantSP'
            SI_RuleMatches = @([pscustomobject]@{ RuleId = 'r-app'; Tier = 1 })
            TierSources = (& $ts @{ EntraID_APIPermissions = @{ CatalogMatches = @(@{ Permission = 'Directory.ReadWrite.All'; Tier = 0 }, @{ Permission = 'Mail.Read'; CatalogTier = 1 }) } }) } }
    [pscustomobject]@{ AssetId = 'entra-sp:11111111-0000-0000-0000-000000000003'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ ENTRA_AssetType = 'ServicePrincipal'; ENTRA_SPObjectId = '11111111-0000-0000-0000-000000000003'; ENTRA_SPType = 'ManagedIdentity'; ENTRA_EgRawData = $egMi }
        Verdict = [pscustomobject]@{ SI_Tier = $null } }
    [pscustomobject]@{ AssetId = 'entra-user:11111111-0000-0000-0000-000000000004'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ ENTRA_AssetType = 'User'; ENTRA_UserId = '11111111-0000-0000-0000-000000000004'; ENTRA_UserType = 'Guest'; ENTRA_Enabled = $false; ENTRA_Groups_Critical = @('Enterprise Admins') }
        Verdict = [pscustomobject]@{ SI_Tier = 3 } }
)
'@

$fixtures['endpoint'] = @'
$eg = [ordered]@{ '@odata.type' = '#microsoft.graph.device'; isDomainController = $true; isExchangeServerDnsName = $false; lastSeen = '2026-11-24T10:00:00Z'
    deviceRole = @('DomainController'); nested = [ordered]@{ '@odata.type' = '#Int64'; value = 4 } }
@(
    [pscustomobject]@{ AssetId = 'endpoint-mde:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; SI_Classify_Status = 'deterministic'
        cmdbId = 'CI0001'; CmdbMatchPhase = 'rule'; CmdbMatchConfidence = 90
        Metadata = @{ MDE_DeviceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1'; MDE_DeviceName = 'dc01.contoso.example'; MDE_OSPlatform = 'WindowsServer2022'; MDE_OSVersion = '10.0'
            MDE_SensorHealthState = 'Active'; MDE_OnboardingStatus = 'Onboarded'; MDE_MachineTags = @('tier1--SI', 'Servers'); MDE_DeviceCategory = 'Endpoint'; MDE_DeviceType = 'Server'
            MDE_AadDeviceId = 'bbbbbbbb-0000-0000-0000-000000000001'; MDE_LastSeen = '2026-11-24T10:00:00Z'; MDE_PublicIp = '203.0.113.5'
            EG_NodeId = 'eg-node-dev-1'; EG_RawData = $eg; EG_DeviceManualTags = 'tier0--SI;Critical'; MostFrequentUserTier = 1; PrivilegedLogonEvidence = 'adm (Tier 0) logged on 2026-11-20 (RDP)'
            ENTRA_DisplayName = 'DC01'; ENTRA_TrustType = 'ServerAd'; AZ_Name = 'dc01'; CMDB_name = 'Domain controllers'; CMDB_criticality = 'Critical' }
        Verdict = [pscustomobject]@{ SI_Tier = 0; SI_RuleTier = 0; SI_Group = 'Servers'; SI_ServiceType = 'Workstation'
            SI_RuleMatches = @([pscustomobject]@{ RuleId = 'r-dc'; DetectionId = 'dc'; Tier = 0 }, [pscustomobject]@{ RuleId = 'r-srv'; Tier = 1 }) } }
    [pscustomobject]@{ AssetId = 'endpoint-mde:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ MDE_DeviceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2'; MDE_OSPlatform = 'Windows11'; MDE_SensorHealthState = 'Inactive'; MDE_LastSeen = '2026-10-01T10:00:00Z'
            MDE_MachineTags = @('tier2--SI') }
        Verdict = [pscustomobject]@{ SI_Tier = 3 } }
    [pscustomobject]@{ AssetId = 'endpoint-eg:eg-node-dev-3'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ EG_NodeId = 'eg-node-dev-3'; EG_Name = 'printer-7'; EG_RawData = [ordered]@{ deviceRole = @('Printer') } }
        Verdict = $null }
)
'@

$fixtures['azure'] = @'
$vmId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-web-01'
$stId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stdata01'
$j = { param($o) ($o | ConvertTo-Json -Depth 8 -Compress) }
@(
    [pscustomobject]@{ AssetId = $vmId; PrimaryEntityId = $vmId.ToLowerInvariant(); TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; SI_Classify_Status = 'no-ai'
        Metadata = @{ Name = 'vm-web-01'; AZ_ResourceId = $vmId; AZ_Type = 'microsoft.compute/virtualmachines'; AZ_Location = 'westeurope'; AZ_SubscriptionId = '00000000-0000-0000-0000-000000000001'
            AZ_ResourceGroup = 'rg-prod'; AZ_TagsJson = (& $j @{ env = 'prod'; owner = 'web' }); AZ_PropertiesJson = (& $j @{ hardwareProfile = @{ vmSize = 'Standard_D2s_v5' }; osProfile = @{ computerName = 'vm-web-01' } })
            AZ_EnvTag = 'prod'; AZ_NodeId = 'eg-node-az-1'; CMDB_name = 'Web' }
        Verdict = [pscustomobject]@{ SI_Tier = 1; SI_RuleTier = 1; SI_RuleMatches = @([pscustomobject]@{ RuleId = 'same-machine'; DetectionId = 'device'; Tier = 1 }) } }
    [pscustomobject]@{ AssetId = $stId; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ Name = 'stdata01'; AZ_ResourceId = $stId; AZ_Type = 'microsoft.storage/storageaccounts'; AZ_Kind = 'StorageV2'
            AZ_PropertiesJson = (& $j @{ allowBlobPublicAccess = $true; minimumTlsVersion = 'TLS1_0'; supportsHttpsTrafficOnly = $false }) }
        Verdict = [pscustomobject]@{ SI_Tier = 2 } }
    [pscustomobject]@{ AssetId = '9f0c0ffee0000000000000000000000000000001'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ AZ_NodeId = '9f0c0ffee0000000000000000000000000000001'; AZ_NodeLabel = 'microsoft.web/sites_webapp'
            AZ_PropertiesRawJson = (& $j @{ nativeEnvironmentRegionName = 'northeurope'; hierarchyType = 'subscriptionid'; hierarchyIdentifier = '00000000-0000-0000-0000-000000000002' }) }
        Verdict = $null }
)
'@

$fixtures['publicip'] = @'
@(
    [pscustomobject]@{ AssetId = 'ip:203.0.113.9'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'
        Metadata = @{ IP_Address = '203.0.113.9'; AssetTier = '0'; AssetEngine = 'endpoint'; IP_AssetName = 'dc7'; SHODAN_InShodan = $true; SHODAN_OpenPorts = @(443, 3389)
            SHODAN_RawJson = @{ ports = @(443, 3389); vulns = @('CVE-2024-0001') }; EG_RawData = [ordered]@{ '@odata.type' = '#microsoft.graph.ip'; x = 1 }; CMDB_name = 'Edge' }
        Verdict = [pscustomobject]@{ SI_Tier = 3 } }
    [pscustomobject]@{ AssetId = 'ip:203.0.113.10'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; Metadata = @{ IP_Address = '203.0.113.10' }; Verdict = $null }
    [pscustomobject]@{ AssetId = 'ip:2001:db8::1'; TimeGenerated = '2026-11-25T01:00:00Z'; SI_RunId = 'rowspeed'; Metadata = @{ IP_Address = '2001:db8::1'; IP_AssetName = '2001:db8::1' }
        Verdict = [pscustomobject]@{ SI_Tier = 2; SI_RuleTier = 2; SI_RuleMatches = @([pscustomobject]@{ RuleId = 'r-ip'; Tier = 2 }) } }
)
'@

$builders = @{
    identity = @{ File = 'Build-IdentityProfileRow.ps1'; Function = 'Build-SIIdentityProfileRow' }
    endpoint = @{ File = 'Build-EndpointProfileRow.ps1'; Function = 'Build-SIEndpointProfileRow' }
    azure    = @{ File = 'Build-AzureProfileRow.ps1'; Function = 'Build-SIAzureProfileRow' }
    publicip = @{ File = 'Build-PublicIpProfileRow.ps1'; Function = 'Build-SIPublicIpProfileRow' }
}

# ------------------------------------------------------------------------------------------------ one builder, one runspace
$runOne = @'
param($BuilderPath, $Function, $Engine, $FixtureText, $Rows, $Warmup)
$ErrorActionPreference = 'Continue'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# no tenant: the cross-engine LA lookup is off, the Azure parent-scope read fails once and is cached as failed
$global:SI_DisableEndpointAzureCorrelation = $true
function global:Write-SIInfo { param([Parameter(Position = 0)]$Message) }
function global:Write-SIWarn { param([Parameter(Position = 0)]$Message) }
function global:Write-SIStep { param([Parameter(Position = 0)]$Message) }
. $BuilderPath
$rc = [pscustomobject]@{ Engine = $Engine; RunId = 'rowspeed'; CollectionTime = '2026-11-25T00:57:00Z'; ShardCount = 1 }
$mk = [scriptblock]::Create($FixtureText)
# both shapes: in-process (hashtable Metadata) and the staging-blob round trip (PSCustomObject)
$make = { $a = @(& $mk); $a + @($a | ForEach-Object { ($_ | ConvertTo-Json -Depth 12 -Compress) | ConvertFrom-Json }) }
$ser = { param($r) if ($null -eq $r) { '<null>' } else { ConvertTo-Json -InputObject $r -Depth 20 -Compress -WarningAction SilentlyContinue } }
$fx = @(& $make)
$first = New-Object System.Collections.Generic.List[string]
foreach ($r in $fx) { $first.Add((& $ser (& $Function -Record $r -RunContext $rc))) }
for ($i = 0; $i -lt $Warmup; $i++) { $null = & $Function -Record (@(& $make)[$i % $fx.Count]) -RunContext $rc }
$recs = New-Object System.Collections.Generic.List[object]
while ($recs.Count -lt $Rows) { foreach ($r in @(& $make)) { if ($recs.Count -lt $Rows) { $recs.Add($r) } } }
$out = New-Object object[] $Rows
$sw = [Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt $Rows; $i++) { $out[$i] = & $Function -Record $recs[$i] -RunContext $rc }
$sw.Stop()
$last = New-Object System.Collections.Generic.List[string]
for ($k = 0; $k -lt $fx.Count; $k++) {
    $idx = $Rows - 1; while ($idx -ge 0 -and ($idx % $fx.Count) -ne $k) { $idx-- }
    $last.Add($(if ($idx -ge 0) { & $ser $out[$idx] } else { '<none>' }))
}
[pscustomobject]@{ First = $first.ToArray(); Last = $last.ToArray(); MsPerRow = $sw.Elapsed.TotalMilliseconds / $Rows; Fixtures = $fx.Count }
'@

function Invoke-SIRowSpeedBuilder {
    param([string]$SiRoot, [string]$EngineName)
    $b = $builders[$EngineName]
    $path = [IO.Path]::Combine($SiRoot, 'engine', 'asset-profiling', 'shared', $b.File)
    $ps = [powershell]::Create()
    try {
        [void]$ps.AddScript($runOne).AddParameters(@{ BuilderPath = $path; Function = $b.Function; Engine = $EngineName; FixtureText = $fixtures[$EngineName]; Rows = $Rows; Warmup = $Warmup })
        $res = @($ps.Invoke())
        $errs = @($ps.Streams.Error)
        $r = $res | Where-Object { $_ -and $_.PSObject.Properties['MsPerRow'] } | Select-Object -Last 1
        if (-not $r) { throw ("{0} builder at {1} produced no result: {2}" -f $EngineName, $SiRoot, (($errs | Select-Object -First 3 | ForEach-Object { "$_" }) -join ' | ')) }
        [pscustomobject]@{ Result = $r; Errors = $errs.Count; FirstError = $(if ($errs.Count) { "$($errs[0])" } else { '' }) }
    } finally { $ps.Dispose() }
}

function Get-SIFirstJsonDifference {
    param([string]$A, [string]$B)
    try {
        $oa = $A | ConvertFrom-Json -AsHashtable; $ob = $B | ConvertFrom-Json -AsHashtable
        foreach ($k in @($oa.Keys) + @($ob.Keys) | Select-Object -Unique) {
            $ja = ConvertTo-Json -InputObject $oa[$k] -Depth 20 -Compress; $jb = ConvertTo-Json -InputObject $ob[$k] -Depth 20 -Compress
            if ($ja -cne $jb) { return ('column {0}: before={1} after={2}' -f $k, $ja.Substring(0, [Math]::Min(160, $ja.Length)), $jb.Substring(0, [Math]::Min(160, $jb.Length))) }
        }
    } catch { }
    $i = 0; while ($i -lt [Math]::Min($A.Length, $B.Length) -and $A[$i] -ceq $B[$i]) { $i++ }
    'first difference at character {0}' -f $i
}

$failed = $false
$summary = New-Object System.Collections.Generic.List[object]
foreach ($e in $Engine) {
    $before = Invoke-SIRowSpeedBuilder -SiRoot $beforeSi -EngineName $e
    $after = Invoke-SIRowSpeedBuilder -SiRoot $afterSi -EngineName $e
    $n = $after.Result.Fixtures
    $diffs = New-Object System.Collections.Generic.List[string]
    for ($k = 0; $k -lt $n; $k++) {
        foreach ($pair in @(@{ What = 'first'; A = $before.Result.First[$k]; B = $after.Result.First[$k] }, @{ What = 'last timed'; A = $before.Result.Last[$k]; B = $after.Result.Last[$k] })) {
            if ($pair.A -cne $pair.B) { $diffs.Add(('fixture {0} ({1} row): {2}' -f $k, $pair.What, (Get-SIFirstJsonDifference $pair.A $pair.B))) }
        }
        # and AFTER's row N is AFTER's row 1 (the helpers load once and stay)
        if ($after.Result.First[$k] -cne $after.Result.Last[$k]) { $diffs.Add(('fixture {0}: AFTER row N differs from AFTER row 1: {1}' -f $k, (Get-SIFirstJsonDifference $after.Result.First[$k] $after.Result.Last[$k]))) }
    }
    $bytes = ($after.Result.First | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum
    $ok = ($diffs.Count -eq 0)
    if (-not $ok) { $failed = $true }
    $summary.Add([pscustomobject]@{
            Engine = $e; Fixtures = $n; JsonBytes = $bytes; Identical = $ok
            BeforeMsPerRow = [Math]::Round($before.Result.MsPerRow, 2); AfterMsPerRow = [Math]::Round($after.Result.MsPerRow, 2)
            Speedup = [Math]::Round($before.Result.MsPerRow / [Math]::Max(0.001, $after.Result.MsPerRow), 1)
            BeforeErrors = $before.Errors; AfterErrors = $after.Errors
        })
    ('{0,-9} {1} fixture rows ({2:n0} JSON bytes)  identical={3}  before {4,8:n2} ms/row  after {5,8:n2} ms/row  x{6}  (errors before/after {7}/{8})' -f $e, $n, $bytes, $ok, $before.Result.MsPerRow, $after.Result.MsPerRow, $summary[-1].Speedup, $before.Errors, $after.Errors)
    if ($before.Errors -or $after.Errors) { '          first error -- before: {0} | after: {1}' -f $before.FirstError, $after.FirstError }
    foreach ($d in $diffs) { "          DIFF $d" }
}

$summaryPath = Join-Path $repoRoot 'TestResults'
New-Item -ItemType Directory -Force -Path $summaryPath | Out-Null
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $summaryPath 'rowspeed-summary.json') -Encoding utf8
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) { 'RESULT: DIFFERENT OUTPUT -- see DIFF lines'; exit 1 }
'RESULT: every row byte-identical before/after'
exit 0
