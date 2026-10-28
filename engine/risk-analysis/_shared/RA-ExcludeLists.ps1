#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Exclusion lists: per-report and global exclude JSON, and placeholder substitution.
#
#  How a report learns what NOT to report on - the per-report and global exclude files, and the
#  substitution that turns EXCLUDED_* placeholders in a locked query into real literals.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Get-SIMisplacedExcludeFiles {
    <#
        Exclusion files in <SIRoot>\config\ -- the place the README once documented. NOTHING reads them (not 2.2, not
        3.0): the engine reads them from its SettingsPath (risk-analysis-detection\). Per file: Path, Name, ShouldBe.
        Used by the run (one warning per run) and by the Pro importer (listed in its report).
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $cfg = Join-Path $SIRoot 'config'
    if (-not (Test-Path -LiteralPath $cfg -PathType Container)) { return @() }
    @(Get-ChildItem -LiteralPath $cfg -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)^[^.]+\.exclude(\.custom)?\.json$' -or $_.Name -ieq 'RiskAnalysisGlobalExclusions.custom.json' } |
        Sort-Object Name | ForEach-Object {
            [pscustomobject]@{ Path = $_.FullName; Name = $_.Name; ShouldBe = (Join-Path (Join-Path $SIRoot 'risk-analysis-detection') $_.Name) }
        })
}

function Write-SIMisplacedExcludeWarning {
    # Once per run: an exclusion file in config\ is never read -- say where it belongs. The solution root is the parent of
    # the Risk Analysis SettingsPath (risk-analysis-detection\) -- no $PSScriptRoot here (see the header).
    if ($script:_MisplacedExcludeWarned) { return }
    $script:_MisplacedExcludeWarned = $true
    if ([string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) { return }
    try {
        foreach ($m in @(Get-SIMisplacedExcludeFiles -SIRoot (Split-Path -Parent ([string]$global:SettingsPath)))) {
            $msg = ("[exclude] {0} is NOT read -- exclusion files in config\ have never been read. Move it to {1} to use it." -f $m.Path, $m.ShouldBe)
            if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 $msg } else { Write-Warning $msg }
        }
    } catch { }
}

function Get-ReportExcludeJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReportName)

    Write-SIMisplacedExcludeWarning
    if ($null -eq $script:_ReportExcludeJsonCache) { $script:_ReportExcludeJsonCache = @{} }
    if ($script:_ReportExcludeJsonCache.ContainsKey($ReportName)) {
        return $script:_ReportExcludeJsonCache[$ReportName]
    }
    $result = $null
    # SecurityInsight Pro (#211): the settings database is the closest layer. Layer 5b materialises its exclusion
    # documents into a run-local folder (SI_ProRaSettingsPath); a document there wins, a report without one falls
    # back to the files below exactly as before. Unset (every Community / VM run) = no change.
    $proFirst = @()
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath)) {
        $proFirst = @(Join-Path ([string]$global:SI_ProRaSettingsPath) ('{0}.exclude.custom.json' -f $ReportName))
    }
    if (-not [string]::IsNullOrWhiteSpace($global:SettingsPath) -or $proFirst.Count) {
        # Customer .custom.json wins over repo-shipped .json (matches the
        # .locked.yaml / .custom.yaml convention used elsewhere in v2.2).
        $candidates = @($proFirst)
        if (-not [string]::IsNullOrWhiteSpace($global:SettingsPath)) {
            $candidates += (Join-Path $global:SettingsPath ('{0}.exclude.custom.json' -f $ReportName))
            $candidates += (Join-Path $global:SettingsPath ('{0}.exclude.json'        -f $ReportName))
        }
        foreach ($path in $candidates) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            try {
                $result = [pscustomobject]@{
                    Path = $path
                    Body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
                }
                break
            } catch {
                Write-Warn2 ("[exclude] failed to parse {0}: {1}" -f $path, $_.Exception.Message)
            }
        }
    }
    $script:_ReportExcludeJsonCache[$ReportName] = $result
    return $result
}

function Get-GlobalExcludeJson {
    [CmdletBinding()]
    param()
    if ($null -ne $script:_GlobalExcludeJsonCache) {
        if ($script:_GlobalExcludeJsonCache -is [string] -and $script:_GlobalExcludeJsonCache -eq '__none__') { return $null }
        return $script:_GlobalExcludeJsonCache
    }
    $script:_GlobalExcludeJsonCache = '__none__'
    # Pro (#211): the database's global exclusions, materialised run-locally, win over the file.
    $path = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProRaSettingsPath)) {
        $p = Join-Path ([string]$global:SI_ProRaSettingsPath) $script:_GlobalExcludeFileName
        if (Test-Path -LiteralPath $p) { $path = $p }
    }
    if (-not $path) {
        if ([string]::IsNullOrWhiteSpace($global:SettingsPath)) { return $null }
        $path = Join-Path $global:SettingsPath $script:_GlobalExcludeFileName
    }
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $obj = [pscustomobject]@{
            Path = $path
            Body = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        $script:_GlobalExcludeJsonCache = $obj
        Write-Info ("[exclude] global fallback loaded: {0}" -f $path)
        return $obj
    } catch {
        Write-Warn2 ("[exclude] failed to parse global file {0}: {1}" -f $path, $_.Exception.Message)
        return $null
    }
}

function Get-ExcludedListForReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]  $ReportName,
        [Parameter(Mandatory)][string[]]$PropertyNames,
        [string]                        $Token = ''
    )
    $loaded = Get-ReportExcludeJson -ReportName $ReportName
    $list   = @()
    $found  = $false
    if ($null -ne $loaded) {
        $body = $loaded.Body
        # Bare array file: maps to the first property name requested
        if ($body -is [System.Array]) {
            $list  = $body
            $found = $true
        } else {
            foreach ($p in $PropertyNames) {
                if ($body.PSObject.Properties[$p] -and $body.$p) {
                    $list  = $body.$p
                    $found = $true
                    break
                }
            }
        }
    }
    # Global fallback ONLY for whitelisted tokens (e.g. ExcludedAssetTags) when
    # per-report file didn't carry the property.
    if (-not $found -and -not [string]::IsNullOrWhiteSpace($Token) -and ($script:_GlobalExcludeTokens -contains $Token)) {
        $g = Get-GlobalExcludeJson
        if ($null -ne $g) {
            foreach ($p in $PropertyNames) {
                if ($g.Body.PSObject.Properties[$p] -and $g.Body.$p) {
                    $list = $g.Body.$p
                    break
                }
            }
        }
    }
    $clean = @($list | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })
    return $clean
}

# Moved VERBATIM out of Invoke-RiskAnalysis.ps1 (2026-10-15): the data health check (engine\data-health) reads a report's CVE minimum age
# through this one function, never a copy of it.
function Get-ScalarValueForReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $ReportName,
        [Parameter(Mandatory)][string[]] $PropertyNames,
        [Parameter(Mandatory)]           $Default
    )
    $loaded = Get-ReportExcludeJson -ReportName $ReportName
    if ($null -ne $loaded -and $loaded.Body -isnot [System.Array]) {
        foreach ($p in $PropertyNames) {
            if ($loaded.Body.PSObject.Properties[$p] -and $null -ne $loaded.Body.$p) {
                return $loaded.Body.$p
            }
        }
    }
    return $Default
}

function Resolve-ExcludePlaceholders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName
    )
    # Block-marker form ONLY (portal-safe). Source query must wrap a default
    # `let _foo = dynamic([]);` between begin/end line-comment markers, e.g.:
    #
    #     //__EXCLUDED_CVES_BEGIN__
    #     let _excludedCves = dynamic([]);
    #     //__EXCLUDED_CVES_END__
    #
    # Engine replaces the ENTIRE block with a real let binding sourced from
    # <ReportName>.exclude.custom.json (or .exclude.json fallback). The let
    # variable name is recovered from the inline default so it doesn't have
    # to be hardcoded per token. Without engine substitution (raw portal
    # paste) the inline default applies and the query parses fine.

    foreach ($token in $script:_ExcludeTokenMap.Keys) {
        $tokenName  = $token.Trim('_')   # 'EXCLUDED_CVES'
        $beginMark  = ('//__{0}_BEGIN__' -f $tokenName)
        $endMark    = ('//__{0}_END__'   -f $tokenName)

        $blockRx   = [regex]::Escape($beginMark) + '(?<body>.*?)' + [regex]::Escape($endMark)
        $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $bodyMatch.Success) { continue }

        $items = @(Get-ExcludedListForReport -ReportName $ReportName -PropertyNames $script:_ExcludeTokenMap[$token] -Token $token)
        $kqlArray = if ($items.Count -gt 0) {
            '[' + (($items | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }) -join ',') + ']'
        } else {
            '[]'
        }
        $varName = if ($bodyMatch.Groups['body'].Value -match 'let\s+(\w+)\s*=') { $matches[1] } else { '_excludedItems' }
        $newBlock = ($beginMark + [Environment]::NewLine +
                     ('let {0} = dynamic({1});' -f $varName, $kqlArray) + [Environment]::NewLine +
                     $endMark)
        $Query = $Query.Replace($bodyMatch.Value, $newBlock)
        Write-Info ("[exclude] {0}: substituted block {1} ({2}) with {3} item(s)" -f $ReportName, $tokenName, $varName, $items.Count)
    }
    # #211: an exclusion set for THIS report (the web app's Exclusions page, or its file) that its query has no filter for
    # changes nothing -- said once per report, never silent.
    $unused = @(Get-RAUnusedExclusions -Query $Query -ReportName $ReportName)
    if ($unused.Count) {
        $msg = ("[exclude] {0}: these exclusions are set for this report but change nothing, because the report does not filter on them: {1}. Remove them from the report's exclusions (Reports > Exclusions in the web app, or {2}), or set them on a report that filters on them." -f
            $ReportName, (($unused | ForEach-Object { '{0} ({1})' -f $_.Property, $_.Count }) -join ', '), (Split-Path -Leaf ([string](Get-ReportExcludeJson -ReportName $ReportName).Path)))
        if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 $msg } else { Write-Warning $msg }
    }
    return $Query
}

function Get-RAUnusedExclusions {
    <#
        The lists (and the CVE minimum age) a report's OWN exclusion document sets that its query has no block for -- so
        they exclude nothing. Per entry: Property, Count (items; the age for CveMinAgeDays). The global asset-tag list is
        not checked here: it applies to every report that filters on tags, by design.
    #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$ReportName)
    $loaded = Get-ReportExcludeJson -ReportName $ReportName
    if ($null -eq $loaded -or $null -eq $loaded.Body -or $loaded.Body -is [System.Array]) { return @() }
    $body = $loaded.Body
    $out = New-Object System.Collections.Generic.List[object]
    # #541: the scope preamble applies every exclusion list to the reports whose scope part declares it
    # (data-model/report-scope) -- no block in the query any more. Unused = set, but the report's part is off.
    if (Get-Command -Name Get-RAReportScope -ErrorAction SilentlyContinue) {
        $spec = Get-RAReportScope -ReportName $ReportName -Template (Get-RAReportScopeTemplate)
        $parts = [ordered]@{ ExcludedCves = 'cves'; CveMinAgeDays = 'cves'; ExcludedConfigurationIds = 'configurationIds'; ExcludedAssetTags = 'assetTags'; ExcludedAssets = 'excludedAssets'; ExcludedIpRanges = 'ipRanges' }
        foreach ($p in $parts.Keys) {
            if (-not $body.PSObject.Properties[$p] -or [bool]$spec.Scope[$parts[$p]]) { continue }
            $v = $body.$p
            if ($p -eq 'CveMinAgeDays') { $n = 0.0; if ([double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -gt 0) { $out.Add([pscustomobject]@{ Property = $p; Count = $n }) }; continue }
            $c = @($v | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
            if ($c -gt 0) { $out.Add([pscustomobject]@{ Property = $p; Count = $c }) }
        }
        return $out.ToArray()
    }
    $maps = @()
    if ($script:_ExcludeTokenMap) { foreach ($t in $script:_ExcludeTokenMap.Keys) { $maps += , @($t, @($script:_ExcludeTokenMap[$t]), $false) } }
    if ($script:_ScalarTokenMap)  { foreach ($t in $script:_ScalarTokenMap.Keys)  { $maps += , @($t, @($script:_ScalarTokenMap[$t].JsonProps), $true) } }
    foreach ($m in $maps) {
        $begin = '//__{0}_BEGIN__' -f ([string]$m[0]).Trim('_')
        if ($Query.IndexOf($begin, [StringComparison]::Ordinal) -ge 0) { continue }
        foreach ($p in @($m[1])) {
            if (-not $body.PSObject.Properties[$p]) { continue }
            $v = $body.$p
            if ($m[2]) {
                $n = 0.0
                if ($null -ne $v -and [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -gt 0) { $out.Add([pscustomobject]@{ Property = $p; Count = $n }) }
            } else {
                $c = @($v | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
                if ($c -gt 0) { $out.Add([pscustomobject]@{ Property = $p; Count = $c }) }
            }
            break
        }
    }
    $out.ToArray()
}
