#Requires -Version 5.1
<#
    #1389 -- A ROW BUILDER LOOKS UP ITS HELPERS ONCE, NEVER PER ROW.

    Owner 2026-11-25 ("Yes, all builders"): the identity row builder took 76.9 ms/row on the test runner, ~50 ms of it six
    `Get-Command -Name X` calls (8.3 ms each, found or not); a large customer's ~9.9k-row part spent 537-636 s in it (82%
    of the Output step). The endpoint, Azure and public IP builders had the same pattern. And a dot-source INSIDE the row
    function defined the helpers in that call's own scope, so they were gone when the row returned and every next row
    parsed the file again.

    The fix loads the helpers once at the top of each builder file; a guard that must stay is `Test-Path function:<name>`.
    This suite holds that:
      1. STATIC: no Get-Command / Get-Module / Import-Module and no dot-source inside any function of the four builders,
         except the schema loaders (run once per process, cached).
      2. BEHAVIOUR: building rows 2..4 calls Get-Command ZERO times, and the helpers are already defined once the builder
         file is loaded (before any row).
    That the output is byte-identical to the code before the change is proven by tests\scale\Measure-SIRowBuilderSpeed.ps1
    (before/after on the same fixtures, in one process) -- a one-off proof against a named commit, so it is not a gate suite.

    Each builder runs in its OWN runspace: all four define Get-SIDerivedValue, so one scope would measure the wrong file.
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Shared = Join-Path $script:SIRootDir 'engine\asset-profiling\shared'

    $script:Builders = @{
        identity = @{ File = 'Build-IdentityProfileRow.ps1'; Function = 'Build-SIIdentityProfileRow'
            Helpers = @('Resolve-SIAssetIdValue', 'Get-SISolutionVersion', 'Get-SISyntheticAssetName', 'Get-SIIdentityRiskFactors', 'Set-SIProfileTierAttribution')
            Record = "[pscustomobject]@{ AssetId = 'entra-user:11111111-2222-3333-4444-555555555555'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; SI_Classify_Status = 'catalog'; Metadata = @{ ENTRA_AssetType = 'User'; ENTRA_UserId = '11111111-2222-3333-4444-555555555555'; ENTRA_UPN = 'ada@contoso.test' }; Verdict = [pscustomobject]@{ SI_Tier = 0; TierSources = '{`"EntraID_Roles_Permanent`":{`"CatalogMatches`":[{`"Role`":`"Global Administrator`",`"Tier`":0}]}}' } }" }
        endpoint = @{ File = 'Build-EndpointProfileRow.ps1'; Function = 'Build-SIEndpointProfileRow'
            Helpers = @('Resolve-SIAssetIdentityPair', 'Test-SINameIsIdentifier', 'Get-SISolutionVersion', 'ConvertTo-SICleanedEgBlob', 'Get-SIEndpointRiskFactors', 'Get-SITierAttribution', 'Get-SITierFromAssetTags', 'Resolve-SITierClaims', 'Get-SITierTrustList', 'Select-SIPayloadBucket', 'Resolve-SIAssetDecisions')
            Record = "[pscustomobject]@{ AssetId = 'endpoint-mde:abc'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; Metadata = @{ MDE_DeviceId = 'abc'; MDE_DeviceName = 'web7.contoso.test'; MDE_MachineTags = @('tier1--SI') }; Verdict = [pscustomobject]@{ SI_Tier = 2; SI_RuleTier = 2 } }" }
        azure    = @{ File = 'Build-AzureProfileRow.ps1'; Function = 'Build-SIAzureProfileRow'
            Helpers = @('Resolve-SIAssetIdValue', 'Get-SIAzureSubscriptionScope', 'Get-SIEndpointMdeDeviceIdForAzureResource', 'Get-SIAzureRiskFactors', 'Get-SISyntheticAssetName', 'Get-SISolutionVersion', 'Set-SIProfileTierAttribution')
            Record = "[pscustomobject]@{ AssetId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; Metadata = @{ Name = 'st1'; AZ_ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1' }; Verdict = [pscustomobject]@{ SI_Tier = 2 } }" }
        publicip = @{ File = 'Build-PublicIpProfileRow.ps1'; Function = 'Build-SIPublicIpProfileRow'
            Helpers = @('Get-SISyntheticAssetName', 'Get-SISolutionVersion', 'ConvertTo-SICleanedEgBlob', 'Set-SIProfileTierAttribution')
            Record = "[pscustomobject]@{ AssetId = 'ip:203.0.113.9'; SI_RunId = 'r1'; TimeGenerated = '2026-01-01T00:00:00Z'; Metadata = @{ IP_Address = '203.0.113.9' }; Verdict = `$null }" }
    }

    # Load one builder in a fresh runspace, report which helpers exist BEFORE any row, then count Get-Command calls while
    # rows 2..4 are built (row 1 may load the schema once).
    function script:Measure-SIBuilderLookups {
        param([Parameter(Mandatory)][string]$Engine)
        $b = $script:Builders[$Engine]
        $script = @'
param($Path, $Function, $RecordText, $Helpers, $Engine)
$ErrorActionPreference = 'Continue'
$WarningPreference = 'SilentlyContinue'
$global:SI_DisableEndpointAzureCorrelation = $true
function Write-SIInfo { param([Parameter(Position = 0)]$Message) }
. $Path
$missing = @($Helpers | Where-Object { -not (Test-Path -Path ('function:' + $_)) })
$global:__siGc = 0
function global:Get-Command { $global:__siGc++; Microsoft.PowerShell.Core\Get-Command @args }
$rc = [pscustomobject]@{ CollectionTime = '2026-01-01T00:00:00Z'; Engine = $Engine; RunId = 'r1' }
$mk = [scriptblock]::Create($RecordText)
$row1 = & $Function -Record (& $mk) -RunContext $rc
$global:__siGc = 0
$rows = @(foreach ($i in 2..4) { & $Function -Record (& $mk) -RunContext $rc })
$calls = $global:__siGc
Remove-Item -Path function:global:Get-Command
[pscustomobject]@{ Missing = $missing; Calls = $calls; Built = @($rows | Where-Object { $null -ne $_ }).Count; Row1 = ($null -ne $row1) }
'@
        $ps = [powershell]::Create()
        try {
            [void]$ps.AddScript($script).AddParameters(@{ Path = (Join-Path $script:Shared $b.File); Function = $b.Function; RecordText = $b.Record; Helpers = $b.Helpers; Engine = $Engine })
            $r = @($ps.Invoke()) | Where-Object { $_ -and $_.PSObject.Properties['Calls'] } | Select-Object -Last 1
            if (-not $r) { throw ("the {0} builder produced no result: {1}" -f $Engine, ((@($ps.Streams.Error) | Select-Object -First 3 | ForEach-Object { "$_" }) -join ' | ')) }
            $r
        } finally { $ps.Dispose() }
    }
}

Describe 'the four row builders: no command lookup or dot-source inside a function (static)' {

    It '<f>: Get-Command / Get-Module / Import-Module / dot-source only at file level or in the once-cached schema loader' -ForEach @(
        @{ f = 'Build-IdentityProfileRow.ps1' }, @{ f = 'Build-EndpointProfileRow.ps1' }, @{ f = 'Build-AzureProfileRow.ps1' }, @{ f = 'Build-PublicIpProfileRow.ps1' }
    ) {
        $path = Join-Path $script:Shared $f
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $bad = foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            if ($fn.Name -match '^Get-SI(Identity|Endpoint|Azure|PublicIp)Schema$') { continue }   # once per process, cached
            foreach ($c in $fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                if ($c.InvocationOperator -eq 'Dot' -or $c.GetCommandName() -in 'Get-Command', 'Get-Module', 'Import-Module') {
                    '{0} line {1}: {2}' -f $fn.Name, $c.Extent.StartLineNumber, $c.Extent.Text
                }
            }
        }
        @($bad) | Should -BeNullOrEmpty -Because 'a lookup or dot-source inside a row function runs once per row (8 ms per Get-Command; a dot-source re-parses the file every row)'
    }
}

Describe 'the four row builders: helpers loaded with the file, zero Get-Command per row (behaviour)' {

    It '<e>: every helper exists before the first row, and rows 2..4 make no Get-Command call' -ForEach @(
        @{ e = 'identity' }, @{ e = 'endpoint' }, @{ e = 'azure' }, @{ e = 'publicip' }
    ) {
        $r = script:Measure-SIBuilderLookups -Engine $e
        $r.Row1 | Should -BeTrue
        $r.Built | Should -Be 3
        @($r.Missing) | Should -BeNullOrEmpty -Because 'the builder file loads its per-row helpers once, at the top'
        $r.Calls | Should -Be 0 -Because 'Get-Command costs 8.3 ms per call on the runner; a row builder runs it never'
    }
}
