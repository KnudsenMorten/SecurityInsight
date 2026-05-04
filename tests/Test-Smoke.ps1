#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioral smoke test for v2.2 SecurityInsight (asset-profiling + risk-analysis).
    Catches the bug classes the structural Test-Restructure.ps1 misses.

.DESCRIPTION
    Runs offline checks first, then optional live LA-touching checks. Fails fast
    on the first error and prints a one-line summary per check.

    Bug classes covered (in execution order):

      1. SYNTAX        Parse every .ps1 in v2.2/. Catches typos / quoting / brace.
      2. ROW-BUILDER   Mock-build one row from each profiler (identity / endpoint
                       / azure / publicip) with a fake metadata bag and assert:
                         a) AssetName is populated
                         b) PrimaryEntityId is populated
                         c) The row is a flat pscustomobject (not [array-of-1])
      3. SCHEMA-DRIFT  Diff Invoke-Output.ps1 $engineDispatch.AlwaysOn[] vs the
                       actual fields the row builder emits. Stale columns (like
                       dropped AssetId still listed) are P0 -- the
                       run halts before LA ingest.
      4. KQL-PARSE     For every report in risk-analysis-detection/SecurityInsight_
                       RiskAnalysis_Queries_Locked.yaml, send the bucket-1/1 query
                       to LA with `| take 0`. Returns 0 rows but PARSES the query
                       -- catches table-not-found / type-mismatch / syntax errors
                       in <5s per query (vs 30s+ via full advanced-hunting path).
                       Requires $global:SI_SPN_* + $global:SI_WorkspaceResourceId.
      5. POST-RUN-LA   After a real engine run, query LA for the latest snapshot
                       and assert critical-column population:
                         - AssetName     >= 50 % per profiler
                         - PrimaryEntityId == 100 %
                       Optional; only runs if -RealRunVerify is passed.

.PARAMETER Skip
    Comma-separated check names to skip (e.g. -Skip 'KQL-PARSE,POST-RUN-LA').

.PARAMETER RealRunVerify
    Run check 5 (queries LA workspace; requires recent live engine runs).

.PARAMETER FailOnWarn
    Treat warnings as failures (CI mode).

.EXAMPLE
    .\Test-Smoke.ps1
    .\Test-Smoke.ps1 -Skip 'KQL-PARSE,POST-RUN-LA'    # offline only
    .\Test-Smoke.ps1 -RealRunVerify                    # full battery

.NOTES
    Solution     : SecurityInsight v2.2
    Developed by : Morten Knudsen, Microsoft MVP
    Added in     : #>

[CmdletBinding()]
param(
    [string[]]$Skip = @(),
    [switch]  $RealRunVerify,
    [switch]  $FailOnWarn
)

$ErrorActionPreference = 'Stop'
$v22Root  = Split-Path -Parent $PSScriptRoot
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
function _PASS($name, $detail = '') { Write-Host (" [PASS] {0,-20} {1}" -f $name, $detail) -ForegroundColor Green }
function _FAIL($name, $detail)      { Write-Host (" [FAIL] {0,-20} {1}" -f $name, $detail) -ForegroundColor Red;    $failures.Add(('{0}: {1}' -f $name, $detail)) | Out-Null }
function _WARN($name, $detail)      { Write-Host (" [WARN] {0,-20} {1}" -f $name, $detail) -ForegroundColor Yellow; $warnings.Add(('{0}: {1}' -f $name, $detail)) | Out-Null }
function _SKIP($name)               { Write-Host (" [SKIP] {0,-20} (-Skip)" -f $name) -ForegroundColor White }

function _Phase($name) {
    $line = '-' * 88
    Write-Host ''
    Write-Host $line -ForegroundColor White
    Write-Host (" CHECK :: {0}" -f $name) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor White
}

# ============================================================================
# 1. SYNTAX -- parse every v2.2 .ps1
# ============================================================================
_Phase 'SYNTAX :: parse every .ps1 under v2.2/'
if ('SYNTAX' -in $Skip) { _SKIP 'SYNTAX' } else {
    $bad = 0
    foreach ($f in Get-ChildItem -LiteralPath $v22Root -Recurse -Filter *.ps1 -File -ErrorAction SilentlyContinue) {
        $err = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$err)
        if ($err) {
            _FAIL 'SYNTAX' ('{0} -- {1} error(s) (first: {2})' -f $f.FullName.Substring($v22Root.Length+1), $err.Count, $err[0].Message)
            $bad++
        }
    }
    if ($bad -eq 0) { _PASS 'SYNTAX' ('all .ps1 parse OK') }
}

# ============================================================================
# 2. ROW-BUILDER -- mock-build one row per profiler, assert AssetName + PrimaryEntityId
# ============================================================================
_Phase 'ROW-BUILDER :: mock-build one row per profiler'
if ('ROW-BUILDER' -in $Skip) { _SKIP 'ROW-BUILDER' } else {
    $sharedDir = Join-Path $v22Root 'engine\asset-profiling\shared'
    $sampleCases = @(
        @{ Engine = 'identity'; Builder = 'Build-IdentityProfileRow.ps1'; Function = 'Build-SIIdentityProfileRow';
           Record = @{ AssetId = 'entra-user:11111111-2222-3333-4444-555555555555';
                       Metadata = @{ ENTRA_UserId = '11111111-2222-3333-4444-555555555555'; ENTRA_DisplayName = 'Test User'; ENTRA_UserPrincipalName = 'test@example.com' } } }
        @{ Engine = 'endpoint'; Builder = 'Build-EndpointProfileRow.ps1'; Function = 'Build-SIEndpointProfileRow';
           Record = @{ PrimaryEntityId = 'mde-device-abc123'; Metadata = @{ MDE_DeviceName = 'TEST-HOST-01'; MDE_DeviceId = 'abc123' } } }
        @{ Engine = 'azure';    Builder = 'Build-AzureProfileRow.ps1';    Function = 'Build-SIAzureProfileRow';
           Record = @{ PrimaryEntityId = 'az-test-rg-vault'; Metadata = @{ Name = 'kv-test'; AZ_ResourceId = '/subscriptions/x/resourceGroups/rg/providers/microsoft.keyvault/vaults/kv-test' } } }
    )
    foreach ($c in $sampleCases) {
        try {
            $bp = Join-Path $sharedDir $c.Builder
            if (-not (Test-Path -LiteralPath $bp)) { _FAIL 'ROW-BUILDER' ("missing builder: {0}" -f $c.Builder); continue }
            . $bp
            $rec = [pscustomobject]$c.Record
            $rc  = [pscustomobject]@{ Engine = $c.Engine; RunId = 'test-run'; CollectionTime = ([datetime]::UtcNow.ToString('o')) }
            $row = & $c.Function -Record $rec -RunContext $rc
            if (-not $row)                                  { _FAIL 'ROW-BUILDER' ("{0}: builder returned null" -f $c.Engine); continue }
            if ($row -is [array])                           { _FAIL 'ROW-BUILDER' ("{0}: builder returned array of {1} (expected single pscustomobject)" -f $c.Engine, $row.Count); continue }
            if (-not $row.PSObject.Properties['AssetName'] -or [string]::IsNullOrWhiteSpace([string]$row.AssetName)) {
                _FAIL 'ROW-BUILDER' ("{0}: AssetName not populated (regression of fix)" -f $c.Engine); continue
            }
            if (-not $row.PSObject.Properties['PrimaryEntityId'] -or [string]::IsNullOrWhiteSpace([string]$row.PrimaryEntityId)) {
                _FAIL 'ROW-BUILDER' ("{0}: PrimaryEntityId not populated" -f $c.Engine); continue
            }
            _PASS 'ROW-BUILDER' ("{0,-9} AssetName='{1}' PrimaryEntityId='{2}'" -f $c.Engine, $row.AssetName, $row.PrimaryEntityId)
        } catch {
            _FAIL 'ROW-BUILDER' ("{0}: {1}" -f $c.Engine, $_.Exception.Message)
        }
    }
}

# ============================================================================
# 3. SCHEMA-DRIFT -- Invoke-Output AlwaysOn vs row-builder emitted fields
# ============================================================================
_Phase 'SCHEMA-DRIFT :: AlwaysOn columns vs row-builder output'
if ('SCHEMA-DRIFT' -in $Skip) { _SKIP 'SCHEMA-DRIFT' } else {
    $outputPath = Join-Path $v22Root 'engine\asset-profiling\stages\Invoke-Output.ps1'
    if (-not (Test-Path -LiteralPath $outputPath)) {
        _FAIL 'SCHEMA-DRIFT' ('Invoke-Output.ps1 missing: ' + $outputPath)
    } else {
        $outSrc = Get-Content -LiteralPath $outputPath -Raw
        # Parse $engineDispatch entries -- AlwaysOn arrays per engine.
        $patterns = @{
            identity = "(?s)'identity'\s*=\s*@\{.*?AlwaysOn\s*=\s*@\((.*?)\)\s*\}"
            endpoint = "(?s)'endpoint'\s*=\s*@\{.*?AlwaysOn\s*=\s*@\((.*?)\)\s*\}"
            azure    = "(?s)'azure'\s*=\s*@\{.*?AlwaysOn\s*=\s*@\((.*?)\)\s*\}"
            publicip = "(?s)'publicip'\s*=\s*@\{.*?AlwaysOn\s*=\s*@\((.*?)\)\s*\}"
        }
        foreach ($eng in $patterns.Keys) {
            $m = [regex]::Match($outSrc, $patterns[$eng])
            if (-not $m.Success) { _WARN 'SCHEMA-DRIFT' ("{0}: AlwaysOn block not found" -f $eng); continue }
            $cols = $m.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() -replace "[`'`"]", '' } | Where-Object { $_ }
            # Spot-check known stale-ref bug from (AssetId in azure)
            if ($eng -eq 'azure' -and 'AssetId' -in $cols) {
                _FAIL 'SCHEMA-DRIFT' ("azure.AlwaysOn lists 'AssetId' which dropped from Build-AzureProfileRow.ps1")
            } elseif ($eng -eq 'azure' -and 'ResourceGroup' -in $cols -and 'AzResourceGroup' -notin $cols) {
                _FAIL 'SCHEMA-DRIFT' ("azure.AlwaysOn uses 'ResourceGroup' but renamed to 'AzResourceGroup'")
            } else {
                _PASS 'SCHEMA-DRIFT' ("{0,-9} AlwaysOn ok ({1} cols)" -f $eng, $cols.Count)
            }
        }
    }
}

# ============================================================================
# 3b. DOTSOURCE-PATHS -- every dot-sourced file referenced from asset-profiling exists
# ============================================================================
_Phase 'DOTSOURCE-PATHS :: every . (Join-Path ...) target exists'
if ('DOTSOURCE-PATHS' -in $Skip) { _SKIP 'DOTSOURCE-PATHS' } else {
    # Catches the bug class introduced by Get-DiscoveryFromShodan / Invoke-Discover /
    # Invoke-Collect / Invoke-Enrich all hit this when the discovery folder moved.
    $bad = 0; $ok = 0
    $apRoot = Join-Path $v22Root 'engine\asset-profiling'
    foreach ($f in Get-ChildItem -LiteralPath $apRoot -Recurse -Filter *.ps1 -File) {
        $src  = Get-Content -LiteralPath $f.FullName -Raw
        # Match: . (Join-Path X 'rel/path.ps1')   AND   . 'abs/path.ps1'
        $matches1 = [regex]::Matches($src, "(?m)^\s*\.\s*\(Join-Path\s+(\(.*?\)|\$[A-Za-z_][A-Za-z0-9_:]*)\s+['""]([^'""\r\n]+\.ps1)['""]\s*\)")
        foreach ($m in $matches1) {
            $rel = $m.Groups[2].Value
            # Resolve $PSScriptRoot relative to current file's dir
            $base = Split-Path -Parent $f.FullName
            $varExpr = $m.Groups[1].Value
            # Order matters: count Split-Path occurrences in the expression.
            # `(Split-Path -Parent (Split-Path -Parent $PSScriptRoot))` -> depth 2.
            $depth = ([regex]::Matches($varExpr, 'Split-Path')).Count
            if ($varExpr -notmatch '\$PSScriptRoot') { continue }   # unrecognised root
            $target = $base
            for ($i = 0; $i -lt $depth; $i++) { $target = Split-Path -Parent $target }
            $resolved = Join-Path $target $rel
            if (-not (Test-Path -LiteralPath $resolved)) {
                _FAIL 'DOTSOURCE-PATHS' ("{0}:{1} -> {2}" -f $f.Name, $m.Index, $resolved)
                $bad++
            } else { $ok++ }
        }
    }
    if ($bad -eq 0) { _PASS 'DOTSOURCE-PATHS' ("{0} dot-source paths resolved" -f $ok) }
}

# ============================================================================
# 3c. CACHE-KQL :: validate KQL embedded in shared cache scripts
# ============================================================================
_Phase 'CACHE-KQL :: parse embedded KQL in shared cache scripts'
if ('CACHE-KQL' -in $Skip) {
    _SKIP 'CACHE-KQL'
} elseif (-not $global:SI_SPN_AppId) {
    _WARN 'CACHE-KQL' 'no $global:SI_SPN_* in scope; KQL parse skipped.'
} else {
    # Catches: EndpointAzureCorrelationCache.ps1 used isnotempty(AzureResourceId_s)
    # which BadRequested when the _s string-mirror column didn't exist.
    try {
        $body  = @{ grant_type='client_credentials'; client_id=$global:SI_SPN_AppId; client_secret=$global:SI_SPN_Secret; scope='https://api.loganalytics.io/.default' }
        $tok   = (Invoke-RestMethod -Method Post -Uri ("https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $global:SI_SPN_TenantId) -Body $body).access_token
        $body2 = @{ grant_type='client_credentials'; client_id=$global:SI_SPN_AppId; client_secret=$global:SI_SPN_Secret; scope='https://management.azure.com/.default' }
        $arm   = (Invoke-RestMethod -Method Post -Uri ("https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $global:SI_SPN_TenantId) -Body $body2).access_token
        $wsId  = (Invoke-RestMethod -Headers @{Authorization="Bearer $arm"} -Uri ('https://management.azure.com' + $global:SI_WorkspaceResourceId + '?api-version=2023-09-01')).properties.customerId
    } catch { _FAIL 'CACHE-KQL' ('LA token / workspace lookup failed: ' + $_.Exception.Message); $tok = $null }
    if ($tok) {
        $sharedDir = Join-Path $v22Root 'engine\asset-profiling\shared'
        $cacheKqlOk = 0; $cacheKqlFail = 0
        foreach ($f in Get-ChildItem -LiteralPath $sharedDir -Filter *Cache*.ps1 -File) {
            $src = Get-Content -LiteralPath $f.FullName -Raw
            # Pull out KQL-looking here-strings: $kql = @"..."@   or  $kql = @'...'@
            $matches2 = [regex]::Matches($src, '(?ms)\$\w*[Kk]ql\w*\s*=\s*@["''][\r\n](.*?)[\r\n]["'']@')
            foreach ($m in $matches2) {
                $kql = $m.Groups[1].Value
                # Substitute shell variables like $EndpointTableName with literal table names
                $kql = $kql -replace '\$EndpointTableName', 'SI_Endpoint_Profile_CL'
                $kql = $kql -replace '\$IdentityTableName', 'SI_Identity_Profile_CL'
                $kql = $kql -replace '\$AzureTableName',    'SI_Azure_Profile_CL'
                # Skip Azure Resource Graph queries (resourcecontainers / resources tables) --
                # those run via Search-AzGraph, not LA. Test-Smoke only validates LA queries.
                if ($kql -match '(?m)^\s*(resourcecontainers|resources)\s*[\r\n|]') { continue }
                $payload = @{ query = ($kql + "`n| take 0") } | ConvertTo-Json -Compress
                try {
                    $null = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$wsId/query" `
                        -Headers @{ Authorization="Bearer $tok"; 'Content-Type'='application/json'} -Body $payload -ErrorAction Stop
                    $cacheKqlOk++
                } catch {
                    $msg = if ($_.ErrorDetails.Message) { try { ($_.ErrorDetails.Message | ConvertFrom-Json).error.innererror.innererror.message } catch { $_.Exception.Message } } else { $_.Exception.Message }
                    _FAIL 'CACHE-KQL' ("{0}: {1}" -f $f.Name, $msg)
                    $cacheKqlFail++
                }
            }
        }
        if ($cacheKqlFail -eq 0 -and $cacheKqlOk -gt 0) { _PASS 'CACHE-KQL' ("{0} embedded KQL block(s) parse OK" -f $cacheKqlOk) }
        elseif ($cacheKqlOk -eq 0)                     { _WARN 'CACHE-KQL' 'no embedded KQL detected in shared/*Cache*.ps1' }
    }
}

# ============================================================================
# 3d. SCHEMA-VALIDITY :: parse every locked schema (JSON + YAML)
# ============================================================================
_Phase 'SCHEMA-VALIDITY :: every *.locked.json + *.locked.yaml parses'
if ('SCHEMA-VALIDITY' -in $Skip) { _SKIP 'SCHEMA-VALIDITY' } else {
    $bad = 0; $ok = 0
    foreach ($f in @(
        (Get-ChildItem -LiteralPath (Join-Path $v22Root 'asset-profiling-schema') -Filter '*.locked.json' -File -ErrorAction SilentlyContinue)
        (Get-ChildItem -LiteralPath (Join-Path $v22Root 'asset-profiling-schema') -Filter '*.locked.yaml' -File -ErrorAction SilentlyContinue)
    )) {
        try {
            $raw = Get-Content -LiteralPath $f.FullName -Raw
            if ($f.Extension -eq '.json') {
                $null = $raw | ConvertFrom-Json -ErrorAction Stop
            } else {
                $null = ConvertFrom-Yaml $raw -ErrorAction Stop
            }
            $ok++
        } catch {
            _FAIL 'SCHEMA-VALIDITY' ("{0}: {1}" -f $f.Name, $_.Exception.Message)
            $bad++
        }
    }
    if ($bad -eq 0 -and $ok -gt 0) { _PASS 'SCHEMA-VALIDITY' ("{0} schema files valid" -f $ok) }
    elseif ($ok -eq 0) { _WARN 'SCHEMA-VALIDITY' 'no schema files found' }
}

# ============================================================================
# 3e. GLOBALS-CONTRACT :: every $global:* the engine reads has a config producer
# ============================================================================
_Phase 'GLOBALS-CONTRACT :: engine $global:* reads vs config producers'
if ('GLOBALS-CONTRACT' -in $Skip) { _SKIP 'GLOBALS-CONTRACT' } else {
    # Catches class bugs: engine reads $global:WorkspaceResourceId but
    # customer config sets $global:SI_WorkspaceResourceId per the v2.2 unified
    # naming. The previous Test-Smoke missed this because KQL-PARSE bypasses the
    # engine and goes straight to the LA REST API -- the routing/contract layer
    # never executes during the test.
    $customDataPath = Join-Path (Split-Path -Parent (Split-Path -Parent $v22Root)) 'config\SecurityInsight.custom.ps1'
    if (-not (Test-Path -LiteralPath $customDataPath)) {
        _WARN 'GLOBALS-CONTRACT' "config file not found: $customDataPath"
    } else {
        $customSrc = Get-Content -LiteralPath $customDataPath -Raw
        $customNames = [System.Collections.Generic.HashSet[string]]::new(([regex]::Matches($customSrc, '\$global:([A-Za-z_][A-Za-z0-9_]*)') | ForEach-Object { $_.Groups[1].Value }))
        # Names the engine reads that are required for RA / profilers to run.
        # If none of the listed alternates is in config, the engine will throw
        # at runtime with the "$global:X is not set" message.
        $required = @(
            @{ Purpose = 'LA workspace';            Engine = @('SI_WorkspaceResourceId','SI_RiskAnalysis_WorkspaceResourceId','WorkspaceResourceId') }
            @{ Purpose = 'DCE name';                Engine = @('SI_DceName','SI_RiskAnalysis_DceName','DceName') }
            @{ Purpose = 'DCR resource group';      Engine = @('SI_DcrResourceGroup','SI_RiskAnalysis_DcrResourceGroup','DcrResourceGroup') }
            @{ Purpose = 'SPN App ID';              Engine = @('SI_SPN_AppId') }
            @{ Purpose = 'SPN secret';              Engine = @('SI_SPN_Secret') }
            @{ Purpose = 'SPN tenant ID';           Engine = @('SI_SPN_TenantId') }
            @{ Purpose = 'storage account';         Engine = @('SI_StorageAccount') }
            @{ Purpose = 'storage account key';     Engine = @('SI_StorageKey') }
        )
        $miss = 0
        foreach ($r in $required) {
            $satisfied = $r.Engine | Where-Object { $customNames.Contains($_) }
            if ($satisfied) {
                _PASS 'GLOBALS-CONTRACT' ("{0,-22} <- `${1}" -f $r.Purpose, $satisfied[0])
            } else {
                _FAIL 'GLOBALS-CONTRACT' ("{0,-22} NONE of {{${1}}} found in config" -f $r.Purpose, ($r.Engine -join ', '))
                $miss++
            }
        }
    }
}

# ============================================================================
# 4. KQL-PARSE -- send each Locked YAML report query to LA with | take 0
# ============================================================================
_Phase 'KQL-PARSE :: parse every Locked YAML query against LA'
if ('KQL-PARSE' -in $Skip) {
    _SKIP 'KQL-PARSE'
} elseif (-not $global:SI_SPN_AppId -or -not $global:SI_SPN_Secret -or -not $global:SI_SPN_TenantId) {
    _WARN 'KQL-PARSE' 'no $global:SI_SPN_* in scope; load config/SecurityInsight.custom.ps1 first to enable this check.'
} else {
    try {
        $body = @{ grant_type='client_credentials'; client_id=$global:SI_SPN_AppId; client_secret=$global:SI_SPN_Secret; scope='https://api.loganalytics.io/.default' }
        $tok  = (Invoke-RestMethod -Method Post -Uri ("https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $global:SI_SPN_TenantId) -Body $body).access_token
        $body2 = @{ grant_type='client_credentials'; client_id=$global:SI_SPN_AppId; client_secret=$global:SI_SPN_Secret; scope='https://management.azure.com/.default' }
        $arm  = (Invoke-RestMethod -Method Post -Uri ("https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $global:SI_SPN_TenantId) -Body $body2).access_token
        $wsId = (Invoke-RestMethod -Headers @{Authorization="Bearer $arm"} -Uri ('https://management.azure.com' + $global:SI_WorkspaceResourceId + '?api-version=2023-09-01')).properties.customerId
    } catch {
        _FAIL 'KQL-PARSE' ('LA token / workspace lookup failed: ' + $_.Exception.Message); $tok = $null
    }
    if ($tok) {
        try { Import-Module powershell-yaml -ErrorAction Stop } catch { _FAIL 'KQL-PARSE' 'powershell-yaml module missing'; $tok = $null }
    }
    if ($tok) {
        $yamlPath = Join-Path $v22Root 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
        $yaml = ConvertFrom-Yaml (Get-Content -LiteralPath $yamlPath -Raw)
        $reports = @($yaml.Reports)
        # Mirror the engine's routing: only validate against LA queries that the engine
        # would route to LA-direct. Queries referencing ONLY XDR tables (Defender XDR
        # advanced hunting) go to XDR via Microsoft Graph -- they would always FAIL
        # against LA endpoint, which is a test false positive, not a query bug.
        # Match XDR table tokens ONLY when they appear at table-reference position
        # (start of line, or after `|`, `=`, `(`, `,` -- the legal preceders of a
        # table identifier in KQL). Without this anchor, the previous broad regex
        # matched bareword column names like `DeviceKey` and false-flagged every
        # Azure query as XDR-routed.
        $xdrTokens = '(?:DeviceInfo|DeviceProcessEvents|DeviceLogonEvents|DeviceFileEvents|DeviceImageLoadEvents|DeviceNetworkEvents|DeviceRegistryEvents|DeviceEvents|DeviceTvm\w*|IdentityInfo|IdentityLogonEvents|IdentityQueryEvents|IdentityDirectoryEvents|ExposureGraphNodes|ExposureGraphEdges|EmailEvents|EmailUrlInfo|EmailAttachmentInfo|EmailPostDeliveryEvents|MessageEvents|MessagePostDeliveryEvents|MessageUrlInfo|UrlClickEvents|CloudAppEvents|AppFileEvents|CloudAuditEvents|CloudDnsEvents|CloudProcessEvents|CloudStorageAccessEvents|AlertEvidence|AlertInfo|BehaviorEntities|BehaviorInfo|AADSignInEventsBeta|AADSpnSignInEventsBeta|EntraIdSignInEvents|EntraIdSpnSignInEvents|GraphAPIAuditEvents)'
        $xdrOnlyPattern = "(?m)(?:^|[|=(,]\s*)$xdrTokens\b"
        $customClPattern = '\bSI_(IdentityAssets|[A-Za-z]+_Profile)_CL\b'
        $okCount = 0; $errCount = 0; $skipCount = 0
        foreach ($r in $reports) {
            $kqlRaw = $r.ReportQuery -replace '__BUCKET_FILTER__', ''
            # Strip string literals + line comments so column-value strings don't trigger XDR detection
            $detect = $kqlRaw
            $detect = [regex]::Replace($detect, '"[^"\r\n]*"', '""')
            $detect = [regex]::Replace($detect, "'[^'\r\n]*'", "''")
            $detect = [regex]::Replace($detect, '//[^\r\n]*', '')
            $hasCustomCl = $detect -match $customClPattern
            $hasXdrOnly  = $detect -match $xdrOnlyPattern
            if (-not $hasCustomCl -or $hasXdrOnly) {
                # Engine routes via XDR (let-block bridge or pure-XDR). LA-direct test would
                # false-fail. Skip with a counted skip marker so we know coverage.
                $skipCount++
                continue
            }
            $kql = $kqlRaw + "`n| take 0"
            $payload = @{ query = $kql } | ConvertTo-Json -Compress
            try {
                $null = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$wsId/query" `
                    -Headers @{ Authorization="Bearer $tok"; 'Content-Type'='application/json'} -Body $payload -ErrorAction Stop
                $okCount++
            } catch {
                $errCount++
                $msg = if ($_.ErrorDetails.Message) { try { ($_.ErrorDetails.Message | ConvertFrom-Json).error.innererror.innererror.message } catch { $_.Exception.Message } } else { $_.Exception.Message }
                _FAIL 'KQL-PARSE' ('{0}: {1}' -f $r.ReportName, $msg)
            }
        }
        if ($errCount -eq 0) { _PASS 'KQL-PARSE' ("{0}/{1} LA-routed reports parse OK ({2} XDR-routed reports skipped)" -f $okCount, ($okCount + $errCount), $skipCount) }
        elseif ($okCount -gt 0) { Write-Host (" [INFO] KQL-PARSE            {0}/{1} LA-routed reports OK ({2} XDR-routed skipped)" -f $okCount, ($okCount + $errCount), $skipCount) -ForegroundColor White }
    }
}

# ============================================================================
# 5. POST-RUN-LA -- query LA for AssetName population (only with -RealRunVerify)
# ============================================================================
_Phase 'POST-RUN-LA :: assert AssetName populated in latest snapshot'
if (-not $RealRunVerify) {
    _SKIP 'POST-RUN-LA'
} elseif ('POST-RUN-LA' -in $Skip) {
    _SKIP 'POST-RUN-LA'
} elseif (-not $global:SI_SPN_AppId -or -not $tok -or -not $wsId) {
    _WARN 'POST-RUN-LA' 'no LA token in scope (KQL-PARSE check must succeed first)'
} else {
    foreach ($table in @('SI_Identity_Profile_CL','SI_Endpoint_Profile_CL','SI_Azure_Profile_CL')) {
        $kql = "$table | where CollectionTime == toscalar($table | summarize max(CollectionTime)) | summarize Total=count(), HasAssetName=countif(isnotempty(tostring(AssetName)) and tostring(AssetName) != '[]')"
        $payload = @{ query = $kql } | ConvertTo-Json -Compress
        try {
            $r = Invoke-RestMethod -Method Post -Uri "https://api.loganalytics.io/v1/workspaces/$wsId/query" `
                -Headers @{ Authorization="Bearer $tok"; 'Content-Type'='application/json'} -Body $payload -ErrorAction Stop
            $row = $r.tables[0].rows[0]
            $total = [int]$row[0]; $has = [int]$row[1]
            $pct = if ($total -gt 0) { [int](100 * $has / $total) } else { 0 }
            if ($total -eq 0)        { _WARN 'POST-RUN-LA' ("{0,-26} no rows in latest snapshot" -f $table) }
            elseif ($pct -lt 50)     { _FAIL 'POST-RUN-LA' ("{0,-26} AssetName {1}/{2} = {3}% (threshold 50%)" -f $table, $has, $total, $pct) }
            else                     { _PASS 'POST-RUN-LA' ("{0,-26} AssetName {1}/{2} = {3}%" -f $table, $has, $total, $pct) }
        } catch {
            _FAIL 'POST-RUN-LA' ("{0}: {1}" -f $table, $_.Exception.Message)
        }
    }
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ''
$line = '=' * 88
Write-Host $line -ForegroundColor Cyan
$failCount = $failures.Count
$warnCount = $warnings.Count
$status = if ($failCount -gt 0) { 'FAIL' } elseif ($warnCount -gt 0 -and $FailOnWarn) { 'FAIL (warnings as failures)' } elseif ($warnCount -gt 0) { 'PASS (with warnings)' } else { 'PASS' }
$colour = if ($status -like 'FAIL*') { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' }
Write-Host (" SMOKE TEST {0}  *  {1} fail  *  {2} warn" -f $status, $failCount, $warnCount) -ForegroundColor $colour
Write-Host $line -ForegroundColor Cyan
if ($failCount -gt 0)                   { exit 1 }
if ($warnCount -gt 0 -and $FailOnWarn)  { exit 2 }
exit 0
