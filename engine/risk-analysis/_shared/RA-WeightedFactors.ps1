#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Weighted risk-factor KQL: building the substitution block and resolving it into a query.
#
#  The KQL half of weighted factors.
#
#  NOTE Get-WeightedFactorsConfig deliberately stays in the main script: it reads $PSScriptRoot, and
#  in a _shared/ file that resolves one directory deeper and would yield a different $siRoot.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Build-WeightedFactorsKql {
    <# Generates the KQL chain that computes per-field multipliers (case() over
       a value->multiplier map), combines them per Combine mode, and emits the
       3 columns RiskScore_Weight_Factor + RiskScore_Weight_Detailed (and the
       intermediate RF_W_<field> per-field multiplier).
       Pure JSON->KQL transform -- no rule semantics hardcoded. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Config)

    $nl  = [Environment]::NewLine
    $sb  = New-Object System.Text.StringBuilder

    # Sanitize: keep only fields that have a non-empty valueMap
    $valid = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Config.Fields) {
        if (-not $f.field) { continue }
        if ($null -eq $f.valueMap) { continue }
        $mapProps = @($f.valueMap.PSObject.Properties)
        if ($mapProps.Count -eq 0) { continue }
        [void]$valid.Add($f)
    }

    # Per-field case() extends:
    #   RF_W_<safeFieldName> = case(
    #       tolower(trim(" ", tostring(column_ifexists("<field>", "")))) == "critical", 1.5,
    #       ... ,
    #       <default | 1.0>
    #   )
    foreach ($f in $valid) {
        $field      = [string]$f.field
        $safeName   = ($field -replace '[^A-Za-z0-9_]','_')
        $defaultMul = if ($f.PSObject.Properties['default'] -and ($null -ne $f.default)) {
                          [double]$f.default
                      } else { 1.0 }

        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        # BASIS-100 INTEGERS. JSON values are now integers (Critical=150
        # = 1.5x, Low=105 = 1.05x, default=100 = 1.0x). Engine post-query divides by
        # 100 to apply the weight. Integers eliminate the locale-decimal trap (1.5
        # parsing as 15 on da-DK).
        [void]$sb.AppendFormat($inv, '| extend RF_W_{0} = case({1}', $safeName, $nl)
        foreach ($prop in $f.valueMap.PSObject.Properties) {
            $matchValue = ([string]$prop.Name -replace '"','\"').ToLowerInvariant()
            $multInt    = [int]([double]$prop.Value)
            [void]$sb.AppendFormat($inv, '      tolower(trim(" ", tostring(column_ifexists("{0}", "")))) == "{1}", {2},{3}',
                $field, $matchValue, $multInt, $nl)
        }
        $defaultMulInt = [int]([double]$defaultMul)
        [void]$sb.AppendFormat($inv, '      {0}{1}){1}', $defaultMulInt, $nl)
    }

    # Combine per-field multipliers into RiskScore_Weight_Factor
    $multParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $valid) {
        $safeName = ([string]$f.field -replace '[^A-Za-z0-9_]','_')
        [void]$multParts.Add(('RF_W_{0}' -f $safeName))
    }
    # BASIS-100 combine math. All factors are integers where 100 = 1.0x
    # baseline. Combine modes adapted accordingly:
    #   product:       (f1 * f2 * ... * fN) / 100^(N-1)
    #                  e.g. cmdbCriticality=Medium(110) * cmdbDataSensitivity=Confidential(150) / 100 = 165 (1.65x)
    #   max:           max_of(100, f1, f2, ...)
    #                  e.g. max(100, 110, 150) = 150 (1.50x) -- worst single signal wins
    #   sum-of-deltas: 100 + sum(fi - 100 for each field)
    #                  e.g. 100 + (110-100) + (150-100) = 160 (1.60x) -- additive lift
    switch ($Config.Combine) {
        'max' {
            $multExpr = if ($multParts.Count -gt 0) { 'max_of(100,' + ($multParts -join ',') + ')' } else { '100' }
        }
        'sum-of-deltas' {
            $deltaParts = New-Object System.Collections.Generic.List[string]
            foreach ($p in $multParts) { [void]$deltaParts.Add(('({0} - 100)' -f $p)) }
            $multExpr = if ($deltaParts.Count -gt 0) { '100 + ' + ($deltaParts -join ' + ') } else { '100' }
        }
        default {
            # product: chain multiplications then divide by 100^(N-1) to stay basis-100.
            if     ($multParts.Count -eq 0) { $multExpr = '100' }
            elseif ($multParts.Count -eq 1) { $multExpr = $multParts[0] }
            else {
                $divisor = [int][Math]::Pow(100, $multParts.Count - 1)
                $multExpr = '(' + ($multParts -join ' * ') + ") / $divisor"
            }
        }
    }
    if ($Config.MaxMultiplier -gt 0) {
        # integer cap (basis-100). 500 = 5x cap. All-integer min_of()
        # avoids any decimal/locale formatting concerns.
        $maxMul = [int]([double]$Config.MaxMultiplier)
        $multExpr = ('min_of({0}, {1})' -f $maxMul, $multExpr)
    }
    [void]$sb.AppendFormat('| extend RiskScore_Weight_Factor = {0}{1}', $multExpr, $nl)
    # Engine-compat alias -- existing post-query layer reads `RiskFactor_Weight`
    # to compute RiskScoreTotal_Weighted = RiskScoreTotal * RiskFactor_Weight.
    [void]$sb.Append('| extend RiskFactor_Weight = RiskScore_Weight_Factor' + $nl)

    # Detail string: ;-joined "<field>=<currentValue>" for fields whose
    # multiplier resolved to something other than 1.0 (i.e. the value
    # actually contributed to the weight). Reader sees WHY this row got weighted.
    $detailedParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $valid) {
        $field    = [string]$f.field
        $safeName = ($field -replace '[^A-Za-z0-9_]','_')
        [void]$detailedParts.Add(
            ('iff(RF_W_{0} != 100, pack_array(strcat("{1}=", tostring(column_ifexists("{1}", "")))), dynamic([]))' -f $safeName, $field)
        )
    }
    if ($detailedParts.Count -gt 0) {
        [void]$sb.AppendFormat('| extend RiskScore_Weight_Detailed = strcat_array(array_concat({0}), ";"){1}',
            ($detailedParts -join ', '), $nl)
    } else {
        [void]$sb.Append('| extend RiskScore_Weight_Detailed = ""' + $nl)
    }

    return $sb.ToString().TrimEnd()
}

function Resolve-WeightedFactorsBlock {
    <# Replaces the //__WEIGHTED_FACTORS_BEGIN__ ... //__WEIGHTED_FACTORS_END__
       block with the engine-generated KQL chain (or leaves the no-op default
       in place when no JSON config is present for this engine). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$ReportName,
        [Parameter(Mandatory)][string]$Engine
    )
    $beginMark = $script:_WeightedFactorsBeginMark
    $endMark   = $script:_WeightedFactorsEndMark
    if ($Query.IndexOf($beginMark) -lt 0 -or $Query.IndexOf($endMark) -lt 0) { return $Query }

    $cfg = Get-WeightedFactorsConfig -ReportName $ReportName -Engine $Engine
    if ($null -eq $cfg -or @($cfg.Fields).Count -eq 0) { return $Query }   # leave no-op default

    $blockRx   = [regex]::Escape($beginMark) + '(?<body>.*?)' + [regex]::Escape($endMark)
    $bodyMatch = [regex]::Match($Query, $blockRx, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $bodyMatch.Success) { return $Query }

    $generatedKql = Build-WeightedFactorsKql -Config $cfg
    $newBlock = ($beginMark + [Environment]::NewLine + $generatedKql + [Environment]::NewLine + $endMark)
    $Query = $Query.Replace($bodyMatch.Value, $newBlock)
    Write-Verbose ("[weight] {0} (engine={1}): substituted {2} weighted-factor field(s) (combine={3}, source={4})" -f $ReportName, $cfg.Engine, @($cfg.Fields).Count, $cfg.Combine, (Split-Path -Leaf $cfg.Path))
    return $Query
}
