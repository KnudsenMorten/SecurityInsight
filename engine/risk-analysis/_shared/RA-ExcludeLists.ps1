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

function Get-ReportExcludeJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReportName)

    if ($null -eq $script:_ReportExcludeJsonCache) { $script:_ReportExcludeJsonCache = @{} }
    if ($script:_ReportExcludeJsonCache.ContainsKey($ReportName)) {
        return $script:_ReportExcludeJsonCache[$ReportName]
    }
    $result = $null
    if (-not [string]::IsNullOrWhiteSpace($global:SettingsPath)) {
        # Customer .custom.json wins over repo-shipped .json (matches the
        # .locked.yaml / .custom.yaml convention used elsewhere in v2.2).
        $candidates = @(
            (Join-Path $global:SettingsPath ('{0}.exclude.custom.json' -f $ReportName)),
            (Join-Path $global:SettingsPath ('{0}.exclude.json'        -f $ReportName))
        )
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
    if ([string]::IsNullOrWhiteSpace($global:SettingsPath)) { return $null }
    $path = Join-Path $global:SettingsPath $script:_GlobalExcludeFileName
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
    return $Query
}
