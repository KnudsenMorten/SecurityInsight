#Requires -Version 5.1
<#
    SecurityInsight -- the privilege tier catalog: which source it comes from, and the checked download of the daily
    classified catalog (framework TIER-CATALOG-1, SI #1194).

    WHY. With AI off the classifier sends nothing and keeps the tiers of its previous catalog, and the shipped
    privilege-tier-catalog.locked.json is only as new as the release that carried it. An install without AI therefore
    tiered from a catalog that could be months old, and a role or permission Microsoft added since fell to the default
    tier. The catalog is now built and classified daily and published for download; this file fetches it.

    ONE SETTING chooses the source: SI_PrivilegeTierCatalog_Source (owner 2026-11-11: "all existing + new installs must have
    possibility to download from invardia the latest catalog (prio 1). if AI integration is enabled, customer can opt-in to
    build the tier classifier themselves (optional) - and it wins over prio 1 (but also adds more cost to customer). ai
    integration with tier classification is not on by default.")
        'invardia' (default)  download the daily classified catalog -- every install, new and existing, also with Azure OpenAI
                              configured; no AI request is sent by the classifier
        'ai'                  the customer's explicit OPT-IN (it costs them AI calls): built here with AI -- only valid when AI
                              can be used; otherwise the catalog is downloaded, with a warning
        'auto' / empty / any other value  = 'invardia' (an opt-in that costs money is never inferred)
    "AI can be used" = AI integration is on (SI_EnableAI) AND the classifier's own switch (SI_PrivilegeTierClassifier_RunAI)
    is not off AND the Azure OpenAI endpoint, deployment and key are set. SI_PrivilegeTierClassifier_RunAI alone never
    switches the source to AI.

    THE DOWNLOAD (Update-SITierCatalogDownload): read the manifest, and only when it names a NEWER version than the local
    copy, download that version's file and CHECK it -- the manifest's schema, its byte count, its SHA-256, the file's own
    version, and every tier section present and non-empty -- before it replaces the local copy (written beside it, then
    moved over it: never a half file). A failed download or a failed check keeps the last good copy and SAYS how old it is.
    It never throws: a run is never failed by the catalog source.

    Content: the BUILT-IN sections only (AD built-in groups, Entra built-in roles, API permissions, Azure built-in roles,
    their catalogs, Summary, Metadata) -- never a *_CustomRoles_* section. Any that arrive are ignored by the reader.

    Plain REST through the shared HTTP seam, no PowerShell modules. Public, no sign-in: the content is Microsoft's own definitions,
    classified; no customer data travels in either direction.
#>

# The shared HTTP seam (plain REST, no PowerShell modules).
if (-not (Get-Command -Name Invoke-SIAzRestHttp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }

$script:SITierCatalogBaseUrl   = 'https://invardia.com/catalog/privilege-tier'
$script:SITierCatalogSchema    = 'si-privilege-tier-catalog/2'
$script:SITierCatalogFileName  = 'privilege-tier-catalog.downloaded.custom.json'
# The tier families of the built-in sections. Each has _Tier0.._Tier3; every one must be present and non-empty.
$script:SITierCatalogFamilies  = @('AD_BuiltInPermissionGroups', 'EntraID_BuiltInRoles', 'EntraID_APIPermissions', 'Azure_BuiltInRoles')
# The other built-in sections a download may carry (taken over as they are when present).
$script:SITierCatalogExtraSections = @('EntraID_APIPermissions_Catalog', 'Azure_Roles_Catalog')

function Get-SITierCatalogTierSectionNames {
    <# PURE. The 16 tier sections a downloaded catalog must carry. #>
    foreach ($f in $script:SITierCatalogFamilies) { foreach ($t in 0..3) { '{0}_Tier{1}' -f $f, $t } }
}

function Test-SITierCatalogAIAvailable {
    <# PURE (its inputs default to the settings). May the classifier build the catalog with AI in this install (the opt-in
       is only valid then)? AI integration on, the classifier's own switch not off, and the Azure OpenAI settings set. #>
    param($RunAI = $global:SI_PrivilegeTierClassifier_RunAI,
          [AllowEmptyString()][string]$Endpoint = [string]$global:OpenAI_Endpoint,
          [AllowEmptyString()][string]$Deployment = [string]$global:OpenAI_Deployment,
          [AllowEmptyString()][string]$ApiKey = [string]$global:OpenAI_ApiKey,
          $AIIntegration = $global:SI_EnableAI)
    $on = { param($x) if ($null -eq $x) { return $false }; if ($x -is [bool]) { return $x }; ("$x").Trim().ToLowerInvariant() -in @('true', '1', 'yes', 'on') }
    if (-not (& $on $AIIntegration)) { return $false }
    if ($RunAI -eq $false -or "$RunAI".Trim() -eq 'False' -or "$RunAI".Trim() -eq '0') { return $false }
    foreach ($v in @($Endpoint, $Deployment, $ApiKey)) { if ([string]::IsNullOrWhiteSpace($v)) { return $false } }
    $true
}

function Resolve-SITierCatalogSource {
    <#
        PURE. Which source this run uses. Returns @{ Source = 'invardia' | 'ai'; Setting = the value as read; Warning }.
        Only an explicit 'ai' with AI usable builds with AI; 'ai' with AI not usable -> 'invardia' and a warning (the run
        goes on). Empty / 'auto' (kept for compatibility) -> 'invardia', silently; an unknown value -> 'invardia' with a warning.
    #>
    param([AllowNull()]$Value = $global:SI_PrivilegeTierCatalog_Source, [bool]$AIAvailable = $false)
    $v = ("$Value").Trim().ToLowerInvariant()
    $warn = ''
    if ($v -eq '' -or $v -eq 'auto') {
        $src = 'invardia'
    } elseif ($v -eq 'invardia') {
        $src = 'invardia'
    } elseif ($v -eq 'ai') {
        if ($AIAvailable) { $src = 'ai' }
        else {
            $src = 'invardia'
            $warn = "The privilege tier catalog is set to be built here with AI (SI_PrivilegeTierCatalog_Source = 'ai'), but AI cannot be used by the privilege tier classifier (AI integration is off, its AI switch is off, or the Azure OpenAI endpoint, deployment or key is not set). The daily classified catalog is downloaded instead."
        }
    } else {
        $src = 'invardia'
        $warn = ("SI_PrivilegeTierCatalog_Source has an unknown value '{0}' (allowed: invardia, ai); the daily classified catalog is downloaded." -f "$Value")
    }
    [pscustomobject]@{ Source = $src; Setting = $(if ($v) { $v } else { 'invardia' }); Warning = $warn }
}

function ConvertTo-SITierCatalogVersion {
    <# PURE. 'YYYY.MM.DD' (optionally a further '.N') -> [version]; anything else -> $null. #>
    param([AllowNull()]$Text)
    $s = ("$Text").Trim()
    if ($s -notmatch '^\d{4}\.\d{1,2}\.\d{1,2}(\.\d+)?$') { return $null }
    $ver = $null
    if ([version]::TryParse($s, [ref]$ver)) { return $ver }
    $null
}

function Get-SITierCatalogVersionDate {
    <# PURE. The UTC date a version names ('2026.11.10' -> 2026-11-10), or $null. #>
    param([AllowNull()]$Text)
    $ver = ConvertTo-SITierCatalogVersion $Text
    if ($null -eq $ver) { return $null }
    try { return [datetime]::SpecifyKind((New-Object datetime ($ver.Major, $ver.Minor, $ver.Build)), 'Utc') } catch { return $null }
}

function Get-SITierCatalogMetaValue {
    <# PURE. A Metadata property, case-insensitive, or ''. #>
    param($Meta, [string[]]$Names)
    if ($null -eq $Meta) { return '' }
    foreach ($n in $Names) {
        $p = $Meta.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)".Trim()) {
            if ($p.Value -is [datetime]) { return ([datetime]$p.Value).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
            return "$($p.Value)".Trim()
        }
    }
    ''
}

function Test-SITierCatalogSections {
    <# PURE. The problems of a parsed catalog's tier sections (empty list = every tier section present and non-empty). #>
    param($Catalog)
    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Catalog) { return 'the file is empty' }
    foreach ($name in @(Get-SITierCatalogTierSectionNames)) {
        $p = $Catalog.PSObject.Properties[$name]
        if (-not $p -or $null -eq $p.Value) { $problems.Add("section $name is missing"); continue }
        $rows = @($p.Value | Where-Object { $null -ne $_ })
        if ($rows.Count -eq 0) { $problems.Add("section $name is empty") }
    }
    $problems.ToArray()
}

function ConvertFrom-SITierCatalogBytes {
    <# PURE. UTF-8 bytes (a BOM is allowed) -> parsed JSON. Throws when it is not JSON. #>
    param([byte[]]$Bytes)
    $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    $text | ConvertFrom-Json -ErrorAction Stop
}

function Get-SITierCatalogSha256 {
    <# PURE. Lower-case hex SHA-256 of the bytes. #>
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-SITierCatalogManifest {
    <# PURE. The problems of a parsed manifest (empty list = usable). #>
    param($Manifest)
    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Manifest) { return 'the manifest is empty' }
    $schema = Get-SITierCatalogMetaValue $Manifest @('schema')
    if ($schema -ne $script:SITierCatalogSchema) { $problems.Add(("the manifest's schema is '{0}', expected '{1}'" -f $schema, $script:SITierCatalogSchema)) }
    if ($null -eq (ConvertTo-SITierCatalogVersion (Get-SITierCatalogMetaValue $Manifest @('version')))) { $problems.Add('the manifest has no valid version (YYYY.MM.DD)') }
    if ((Get-SITierCatalogMetaValue $Manifest @('sha256')) -notmatch '^(sha256:)?[0-9a-fA-F]{64}$') { $problems.Add('the manifest has no SHA-256') }
    $n = 0L
    if (-not [long]::TryParse((Get-SITierCatalogMetaValue $Manifest @('bytes')), [ref]$n) -or $n -le 0) { $problems.Add('the manifest has no byte count') }
    $problems.ToArray()
}

function Test-SITierCatalogContent {
    <#
        PURE. Checks a downloaded file against its manifest: byte count, SHA-256, that it is JSON, that its own version (if
        it states one) is the manifest's, and every tier section present and non-empty.
        Returns @{ Ok; Problems; Catalog (parsed, when it parsed) }.
    #>
    param([byte[]]$Bytes, $Manifest)
    $problems = New-Object System.Collections.Generic.List[string]
    $catalog = $null
    if ($null -eq $Bytes) { $Bytes = [byte[]]@() }
    $want = 0L; [void][long]::TryParse((Get-SITierCatalogMetaValue $Manifest @('bytes')), [ref]$want)
    if ($Bytes.Length -ne $want) { $problems.Add(("the file has {0} bytes, the manifest says {1}" -f $Bytes.Length, $want)) }
    $wantHash = ((Get-SITierCatalogMetaValue $Manifest @('sha256')) -replace '^sha256:', '').ToLowerInvariant()
    $gotHash = Get-SITierCatalogSha256 $Bytes
    if ($gotHash -ne $wantHash) { $problems.Add('the file''s SHA-256 does not match the manifest') }
    if ($problems.Count -eq 0) {
        try { $catalog = ConvertFrom-SITierCatalogBytes $Bytes } catch { $problems.Add(("the file is not valid JSON ({0})" -f $_.Exception.Message)) }
        if ($null -ne $catalog) {
            $meta = $null; if ($catalog.PSObject.Properties['Metadata']) { $meta = $catalog.Metadata }
            $fileVer = Get-SITierCatalogMetaValue $meta @('version')
            $manVer = Get-SITierCatalogMetaValue $Manifest @('version')
            if ($fileVer -and $fileVer -ne $manVer) { $problems.Add(("the file says version {0}, the manifest {1}" -f $fileVer, $manVer)) }
            foreach ($p in @(Test-SITierCatalogSections $catalog)) { $problems.Add($p) }
        }
    }
    [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = @($problems); Catalog = $catalog }
}

function Get-SITierCatalogDownloadState {
    <#
        What the local downloaded copy says about itself: @{ Version; BuiltUtc; Path } ($null when there is none or it
        cannot be read). The version is the file's Metadata.version; the date is its builtUtc / GeneratedAtUtc, else the
        date the version names.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { $j = ConvertFrom-SITierCatalogBytes ([System.IO.File]::ReadAllBytes($Path)) } catch { return $null }
    if ($null -eq $j) { return $null }
    $meta = $null; if ($j.PSObject.Properties['Metadata']) { $meta = $j.Metadata }
    $ver = Get-SITierCatalogMetaValue $meta @('version')
    if ($null -eq (ConvertTo-SITierCatalogVersion $ver)) { return $null }
    $built = $null
    $bt = Get-SITierCatalogMetaValue $meta @('builtUtc', 'GeneratedAtUtc')
    if ($bt) { try { $built = [datetime]::Parse($bt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $built = $null } }
    if ($null -eq $built) { $built = Get-SITierCatalogVersionDate $ver }
    [pscustomobject]@{ Version = $ver; BuiltUtc = $built; Path = $Path; Catalog = $j }
}

function Invoke-SITierCatalogHttpGet {
    <#
        The one network call: the raw bytes of a public URL (no sign-in, no Authorization header). A seam -- the tests
        replace it. Goes through SecurityInsight's shared HTTP seam (Invoke-SIAzRestHttp, SI-AzRest.ps1) and retries the
        transient answers (no answer, 408, 429, 5xx; Retry-After honoured, at most 60 s) a few times. Throws on any other
        answer or when the retries run out.
    #>
    param([Parameter(Mandatory)][string]$Uri, [int]$TimeoutSec = 120, [int]$MaxAttempts = 4)
    $code = 0; $what = ''
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $r = Invoke-SIAzRestHttp -Method 'GET' -Uri $Uri -AsBytes -TimeoutSec $TimeoutSec -Headers @{ 'Accept' = 'application/json' }
        $code = [int]$r.StatusCode
        if ($code -eq 200) {
            # assigned in a statement, never through $( ... ): a subexpression enumerates a byte array into object[]
            [byte[]]$raw = $r.Bytes
            if ($null -eq $raw) { $raw = [byte[]]@() }
            return ,$raw
        }
        $what = $(if ($code -eq 0) { 'no answer: ' + [string]$r.Content } else { 'HTTP ' + $code })
        $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
        if (-not $transient -or $attempt -ge $MaxAttempts) { break }
        $wait = [Math]::Min(60, 5 * $attempt)
        $ra = 0
        if ([int]::TryParse(([string]$r.RetryAfter).Trim(), [ref]$ra) -and $ra -gt 0) { $wait = [Math]::Min(60, $ra) }
        Start-Sleep -Seconds $wait
    }
    throw ("{0} answered {1}" -f $Uri, $what)
}

function Format-SITierCatalogAge {
    <# PURE. "3 days old" / "less than a day old". #>
    param([AllowNull()]$BuiltUtc, [datetime]$NowUtc)
    if ($null -eq $BuiltUtc) { return 'of unknown age' }
    $d = [int][Math]::Floor(($NowUtc - ([datetime]$BuiltUtc).ToUniversalTime()).TotalDays)
    if ($d -lt 1) { return 'less than a day old' }
    if ($d -eq 1) { return '1 day old' }
    ('{0} days old' -f $d)
}

function Update-SITierCatalogDownload {
    <#
        Bring the local downloaded catalog up to date. NEVER throws, never fails the run.
        Returns @{ Status; Version; BuiltUtc; AgeDays; Path; Warning; Updated }:
          downloaded  a newer version passed every check and replaced the local copy
          current     the local copy is the published version (or newer)
          kept        the download or a check failed; the last good copy is kept (Warning says why and how old it is)
          none        failed, and there is no downloaded copy yet (Warning says the shipped catalog is used)
    #>
    param([Parameter(Mandatory)][string]$LocalPath,
          [string]$BaseUrl = $script:SITierCatalogBaseUrl,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $local = Get-SITierCatalogDownloadState -Path $LocalPath
    $result = {
        param($Status, $State, [string]$Warning, [bool]$Updated)
        $age = $null
        if ($State -and $State.BuiltUtc) { $age = [Math]::Round(($NowUtc - ([datetime]$State.BuiltUtc).ToUniversalTime()).TotalDays, 1) }
        [pscustomobject]@{ Status = $Status; Version = $(if ($State) { [string]$State.Version } else { '' })
                           BuiltUtc = $(if ($State) { $State.BuiltUtc } else { $null }); AgeDays = $age
                           Path = $LocalPath; Warning = $Warning; Updated = $Updated }
    }
    $keep = {
        param([string]$Why)
        if ($local) {
            & $result 'kept' $local ("The daily privilege tier catalog could not be updated ({0}). The last good copy is kept: version {1}, {2}." -f $Why, $local.Version, (Format-SITierCatalogAge $local.BuiltUtc $NowUtc)) $false
        } else {
            & $result 'none' $null ("The daily privilege tier catalog could not be downloaded ({0}), and there is no earlier downloaded copy: the catalog shipped with SecurityInsight is used until a download succeeds." -f $Why) $false
        }
    }
    $base = $BaseUrl.TrimEnd('/')
    try {
        try { [byte[]]$mb = Invoke-SITierCatalogHttpGet -Uri ($base + '/manifest.json'); $manifest = ConvertFrom-SITierCatalogBytes $mb }
        catch { return (& $keep ("the manifest could not be read: {0}" -f $_.Exception.Message)) }
        $mp = @(Test-SITierCatalogManifest $manifest)
        if ($mp.Count -gt 0) { return (& $keep ("the manifest did not pass its checks: {0}" -f ($mp -join '; '))) }
        $manVer = Get-SITierCatalogMetaValue $manifest @('version')
        $newVer = ConvertTo-SITierCatalogVersion $manVer
        if ($local) {
            $locVer = ConvertTo-SITierCatalogVersion $local.Version
            if ($newVer -eq $locVer) { return (& $result 'current' $local '' $false) }
            if ($newVer -lt $locVer) {
                return (& $result 'current' $local ("The published privilege tier catalog (version {0}) is older than the local copy (version {1}); the local copy is kept." -f $manVer, $local.Version) $false)
            }
        }
        try { [byte[]]$bytes = Invoke-SITierCatalogHttpGet -Uri ('{0}/{1}.json' -f $base, $manVer) }
        catch { return (& $keep ("version {0} could not be downloaded: {1}" -f $manVer, $_.Exception.Message)) }
        $check = Test-SITierCatalogContent -Bytes $bytes -Manifest $manifest
        if (-not $check.Ok) { return (& $keep ("version {0} did not pass its checks: {1}" -f $manVer, ($check.Problems -join '; '))) }

        # Written beside the target, then moved over it: a reader never sees a half file, and a failed write keeps the old one.
        $dir = Split-Path -Parent $LocalPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $tmp = Join-Path $dir ('.tiercatalog-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        try {
            [System.IO.File]::WriteAllBytes($tmp, $bytes)
            Move-Item -LiteralPath $tmp -Destination $LocalPath -Force
        } catch {
            return (& $keep ("version {0} could not be saved: {1}" -f $manVer, $_.Exception.Message))
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        $built = $null
        $bt = Get-SITierCatalogMetaValue $manifest @('builtUtc')
        if ($bt) { try { $built = [datetime]::Parse($bt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $built = $null } }
        if ($null -eq $built) { $built = Get-SITierCatalogVersionDate $manVer }
        return (& $result 'downloaded' ([pscustomobject]@{ Version = $manVer; BuiltUtc = $built }) '' $true)
    } catch {
        return (& $keep $_.Exception.Message)
    }
}

function Merge-SITierCatalogBuiltIns {
    <#
        PURE. The shipped catalog with its BUILT-IN sections replaced by the downloaded catalog's. Everything else of the
        shipped catalog -- its *_CustomRoles_* and AD_CustomGroups_* sections -- is kept; a *_CustomRoles_* section in the
        download is never taken. The customer's custom catalog is merged on top of the result by the reader, as before, so
        it still wins. Returns a new object; neither input is changed.
    #>
    param([Parameter(Mandatory)]$Shipped, [Parameter(Mandatory)]$Downloaded)
    $out = [ordered]@{}
    foreach ($p in $Shipped.PSObject.Properties) { $out[$p.Name] = $p.Value }
    foreach ($name in @(@(Get-SITierCatalogTierSectionNames) + $script:SITierCatalogExtraSections)) {
        $p = $Downloaded.PSObject.Properties[$name]
        if ($p -and $null -ne $p.Value) { $out[$name] = @($p.Value) }
    }
    [pscustomobject]$out
}
