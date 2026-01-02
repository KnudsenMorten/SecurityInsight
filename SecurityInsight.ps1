param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $ReportTemplate,

  [Parameter(Mandatory=$false)]
  [switch] $Detailed,

  [Parameter(Mandatory=$false)]
  [switch] $Summary,

  [Parameter(Mandatory=$false)]
  [switch] $SendMail,

  [Parameter(Mandatory=$false)]
  [string[]] $MailTo,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework,

  [Parameter(Mandatory=$true)]
  [string] $SettingsPath,

  [Parameter(Mandatory=$false)]
  [switch] $BuildSummaryByAI
)

#------------------------------------------------------------------------------------------------ 
Write-host "***********************************************************************************************"
Write-host "Risk-based Security Exposure Insight"
Write-host ""
write-host "Security Insight: Rethink Secure Score into a new risk-based security risk score, based on consequence, probability and risk factors. "
write-host "Solution includes critical asset tagging, ready-to-use reports (based on Defender Exposure Graph and Azure Resource Graphs),"
write-host "automation-scripts, risk index and more"
Write-host ""
Write-host "Support: mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight"
Write-host "***********************************************************************************************"

if (-not $PSBoundParameters.ContainsKey('SettingsPath') -or [string]::IsNullOrWhiteSpace($SettingsPath)) {

    if (-not [string]::IsNullOrWhiteSpace($SettingsPath_Default)) {
        # Default value is enabled
        $SettingsPath = $SettingsPath_Default
    }
    else {
        # Default not enabled -> run from where the script was started
        # (wrapper script location)
        $SettingsPath = $PSScriptRoot
    }
}


#######################################################################################################
# FUNCTIONS (begin)
#######################################################################################################

# ========== lightweight logging helpers ==========
function Write-Step   ($msg){ Write-Host ("[STEP] {0}" -f $msg) -ForegroundColor Cyan }
function Write-Info   ($msg){ Write-Host ("[INFO] {0}" -f $msg) -ForegroundColor Gray }
function Write-Ok     ($msg){ Write-Host ("[OK]   {0}" -f $msg) -ForegroundColor Green }
function Write-Warn2  ($msg){ Write-Host ("[WARN] {0}" -f $msg) -ForegroundColor Yellow }
function Write-Err2   ($msg){ Write-Host ("[ERR]  {0}" -f $msg) -ForegroundColor Red }
function Tick { param([string]$Label="") if($script:_sw){ $script:_sw.Stop(); Write-Info ("{0} completed in {1:n2}s" -f $Label,$script:_sw.Elapsed.TotalSeconds); $script:_sw=$null } }
function Tock { $script:_sw = [System.Diagnostics.Stopwatch]::StartNew() }


function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope AllUsers -Force -AllowClobber
  }
}

# ===== reset helper (delete workbook at start when OverwriteXlsx is true) =====
function Reset-ExcelOutput {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter()][switch]$ForceRemove = $true
  )
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  if (Test-Path $Path) {
    if ($ForceRemove) {
      try { [System.IO.File]::SetAttributes($Path, 'Normal') } catch {}
      $deleted = $false
      for ($i = 1; $i -le 5 -and -not $deleted; $i++) {
        try {
          Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
          $deleted = $true
        } catch {
          Write-Warn2 ("excel file locked (attempt {0}/5); retrying..." -f $i)
          Start-Sleep -Milliseconds 500
        }
      }
      if (-not $deleted) { throw "Could not delete existing Excel file: $Path (locked)" }
    } else {
      Write-Warn2 "Overwrite disabled; keeping existing Excel file and appending sheets."
    }
  }
  $script:_sheetWritten = @{}
}


function Connect-GraphHighPriv {
    [CmdletBinding()]
    param()

    Write-Info "Connecting to Microsoft Graph (app+secret)..."
    Connect-MicrosoftGraphPS -AppId $global:SpnClientId `
                             -AppSecret $global:SpnClientSecret `
                             -TenantId $global:SpnTenantId

    # increase Graph SDK HTTP timeout + tune retries
    Set-MgRequestContext -ClientTimeout 900 -MaxRetry 6 -RetryDelay 5 -RetriesTimeLimit 600

    $script:GraphLastConnectUtc = [datetime]::UtcNow
    Write-Ok ("Graph connected at {0:u}" -f $script:GraphLastConnectUtc)
    Write-Info "Graph request context: ClientTimeout=900s, MaxRetry=6, RetryDelay=5s, RetriesTimeLimit=600s"
}

function Ensure-GraphAuth {
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 45
    )

    $need = $false

    if ($script:GraphLastConnectUtc -eq [datetime]::MinValue) { $need = $true }
    else {
        $ageMin = ([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes
        if ($ageMin -ge $MaxAgeMinutes) { $need = $true }
    }

    if ($need) {
        Connect-GraphHighPriv
    }
}

function Invoke-GraphHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$ReconnectMaxAgeMinutes = 45,
        [int]$MaxRetries = 4
    )

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Ensure-GraphAuth -MaxAgeMinutes $ReconnectMaxAgeMinutes

        try {
            return Start-MgSecurityHuntingQuery -Query $Query
        } catch {
            $msg = $_.Exception.Message

            $isTaskCanceled = ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) -or ($msg -match 'A task was canceled')
            $looksAuth      = ($msg -match 'InvalidAuthenticationToken|Access token|Authentication|Unauthorized|401')
            $looksThrottle  = ($msg -match 'Too Many Requests|429|throttl|temporar')

            if ($looksAuth) {
                Write-Warn2 "Graph auth issue detected. Reconnecting and retrying..."
                try { Connect-GraphHighPriv } catch { Write-Err2 "Graph reconnect failed: $($_.Exception.Message)"; throw }
            }

            if ($attempt -lt $MaxRetries) {
                $sleepSec = if ($looksThrottle) { [math]::Min(60, 5 * $attempt) }
                            elseif ($isTaskCanceled) { [math]::Min(90, 15 * $attempt) }
                            else { [math]::Min(20, 2 * $attempt) }

                $reason = if ($isTaskCanceled) { "Likely Graph client timeout (TaskCanceledException)" } else { "Query failed" }
                Write-Warn2 ("{0} (attempt {1}/{2}). Waiting {3}s then retrying... {4}" -f $reason, $attempt, $MaxRetries, $sleepSec, $msg)
                Start-Sleep -Seconds $sleepSec
                continue
            }

            Write-Err2 ("Query failed after {0} attempts: {1}" -f $MaxRetries, $msg)
            throw
        }
    }
}

function Export-AISummaryWorksheet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)][string]$SummaryText
  )

  # Normalize line endings and split into rows so it’s readable in Excel
  $text = ($SummaryText -replace "`r`n", "`n" -replace "`r", "`n").Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { $text = "No AI summary output was produced." }

  $lines = @($text -split "`n")
  $rows = for ($i=0; $i -lt $lines.Count; $i++) {
    [pscustomobject]@{
      LineNo = ($i + 1)
      Text   = $lines[$i]
    }
  }

  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  $tableName = ($safeSheet -replace '\W','_')

  $excel = $rows | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle 'Medium9' `
    -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

  $ws = $excel.Workbook.Worksheets[$safeSheet]
  $ws.Cells.AutoFitColumns()
  for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
    if ($ws.Column($col).Width -gt 90) { $ws.Column($col).Width = 90 }
  }

  Close-ExcelPackage $excel
}


function New-BucketFilterKql {
    param(
        [int]$BucketCount,
        [int]$BucketIndex
    )

@"
| extend __bucket_key = coalesce(
    tostring(column_ifexists('AadDeviceId','')),
    tostring(column_ifexists('DeviceId','')),
    tostring(column_ifexists('MachineId','')),
    tostring(column_ifexists('AssetName','')),
    tostring(column_ifexists('Computer','')),
    tostring(column_ifexists('DeviceName','')),
    'unknown'
)
| extend __bucket = abs(hash(__bucket_key)) % $BucketCount
| where __bucket == $BucketIndex
"@
}

function Deduplicate-Rows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Rows   # accept list/array/anything enumerable
    )

    if ($null -eq $Rows) { return @() }

    # Normalize input to array
    $rowsArr = @()
    foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
    if ($rowsArr.Count -eq 0) { return @() }

    $seen = @{}
    $out  = New-Object System.Collections.Generic.List[object]

    foreach ($r in $rowsArr) {
        $aad   = if ($r.PSObject.Properties['AadDeviceId'])     { [string]$r.AadDeviceId } else { "" }
        $asset = if ($r.PSObject.Properties['AssetName'])       { [string]$r.AssetName } else { "" }
        $cfg   = if ($r.PSObject.Properties['ConfigurationId']) { [string]$r.ConfigurationId } else { "" }
        $cat   = if ($r.PSObject.Properties['Category'])        { [string]$r.Category } else { "" }
        $sub   = if ($r.PSObject.Properties['SubCategory'])     { [string]$r.SubCategory } else { "" }

        $key = ("{0}|{1}|{2}|{3}|{4}" -f $aad,$asset,$cfg,$cat,$sub).ToLowerInvariant()

        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $out.Add($r) | Out-Null
        }
    }

    # return a plain object[]
    return @($out.ToArray())
}

function Apply-ScopeFilter {
  [CmdletBinding()]
  param(
    [Parameter()][AllowNull()]$Rows,
    [Parameter(Mandatory)][string]$ColumnName,
    [Parameter()][AllowNull()]$Scope
  )

  # Always return an array, never $null
  if ($null -eq $Rows) { return @() }

  # Normalize Rows to a plain array (works for List[object] too)
  $rowsArr = @()
  foreach ($r in $Rows) { $rowsArr += ,$r }

  # If no scope -> pass-through
  if ($null -eq $Scope -or ($Scope -is [string] -and [string]::IsNullOrWhiteSpace($Scope))) {
    return @($rowsArr)
  }

  # Normalize scope to array
  if ($Scope -is [string]) {
    $Scope = $Scope -split '\s*,\s*'
  }
  elseif ($Scope -isnot [System.Collections.IEnumerable]) {
    $Scope = @($Scope)
  }
  if (@($Scope).Count -eq 0) { return @($rowsArr) }

  # Filter (always return array)
  $filtered = @(Filter-ObjectsByColumn -InputObject $rowsArr -ColumnToFilter $ColumnName -InScopeData @($Scope) -CaseInsensitive)
  return @($filtered)
}

function ConvertTo-PSObjectDeep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $InputObject,
        [switch] $StripOData,
        [switch] $CastPrimitiveArrays,
        [switch] $ConvertArraysToString,
        [string] $ArrayJoinChar = ', ',
        [switch] $PreserveRootArray = $true
    )
    function _IsPrimitive([object]$x) {
        if ($null -eq $x) { return $true }
        $t = $x.GetType()
        return ($t.IsPrimitive -or $t.FullName -in @('System.String','System.Decimal','System.DateTime','System.Guid','System.TimeSpan'))
    }
    function _Convert([object]$obj, [bool]$isRoot = $false) {
        if ($null -eq $obj) { return $null }
        if ($obj -is [pscustomobject]) {
            $ordered = [ordered]@{}
            foreach ($p in $obj.PSObject.Properties) {
                if ($StripOData -and ($p.Name -like '*@odata*')) { continue }
                $ordered[$p.Name] = _Convert $p.Value $false
            }
            return [pscustomobject]$ordered
        }
        if ($obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($k in $obj.Keys) {
                if ($StripOData -and ($k -is [string]) -and ($k -like '*@odata*')) { continue }
                $ordered[$k] = _Convert $obj[$k] $false
            }
            return [pscustomobject]$ordered
        }
        if (($obj -is [System.Collections.IEnumerable]) -and -not ($obj -is [string])) {
            $items = @()
            foreach ($item in $obj) { $items += ,(_Convert $item $false) }
            if ($ConvertArraysToString -and -not ($isRoot -and $PreserveRootArray)) {
                $pieces = foreach ($e in $items) { if (_IsPrimitive $e) { $e } else { ($e | ConvertTo-Json -Compress -Depth 12) } }
                return ($pieces -join $ArrayJoinChar)
            }
            if ($CastPrimitiveArrays -and -not $ConvertArraysToString -and $items.Count -gt 0) {
                $nonNull   = $items | Where-Object { $_ -ne $null }
                $typeNames = $nonNull | ForEach-Object { $_.GetType().FullName } | Select-Object -Unique
                $allPrim   = ($nonNull | ForEach-Object { _IsPrimitive $_ } | Where-Object { -not $_ } | Measure-Object).Count -eq 0
                if ($allPrim -and $typeNames.Count -eq 1) {
                    switch ($typeNames[0]) {
                        'System.String'  { return [string[]]  $items }
                        'System.Int32'   { return [int[]]     $items }
                        'System.Int64'   { return [long[]]    $items }
                        'System.Double'  { return [double[]]  $items }
                        'System.Boolean' { return [bool[]]    $items }
                    }
                }
            }
            return @($items)
        }
        return $obj
    }
    $rootIsArray = (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]))
    if ($rootIsArray -and $PreserveRootArray) {
        $out = @()
        foreach ($i in $InputObject) { $out += ,(_Convert $i $false) }
        return @($out)
    }
    return (_Convert $InputObject $true)
}

# ===========================
# NEW: Supports mixed YAML for ReportsIncluded (string or object)
# ===========================
function Resolve-ReportInclude {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Item
    )

    if ($Item -is [string]) {
        return [pscustomobject]@{
            Name                   = $Item
            UseQueryBucketing      = $null
            DefaultBucketCount     = $null
            BucketPlaceholderToken = $null
        }
    }

    $name = $null
    if     ($Item.PSObject.Properties['Name'])       { $name = [string]$Item.Name }
    elseif ($Item.PSObject.Properties['ReportName']) { $name = [string]$Item.ReportName }

    if ([string]::IsNullOrWhiteSpace($name)) {
        throw "ReportsIncluded item is missing 'Name'. Item: $($Item | ConvertTo-Json -Depth 8 -Compress)"
    }

    $useBucketing = $null
    if ($Item.PSObject.Properties['UseQueryBucketing']) { $useBucketing = [bool]$Item.UseQueryBucketing }

    $bucketCount = $null
    if ($Item.PSObject.Properties['DefaultBucketCount']) { $bucketCount = [int]$Item.DefaultBucketCount }

    $token = $null
    if ($Item.PSObject.Properties['BucketPlaceholderToken']) { $token = [string]$Item.BucketPlaceholderToken }

    return [pscustomobject]@{
        Name                   = $name
        UseQueryBucketing      = $useBucketing
        DefaultBucketCount     = $bucketCount
        BucketPlaceholderToken = $token
    }
}

function Calculate-RiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [object[]] $Rows,
        [Parameter(Mandatory=$true)] [psobject] $RiskIndex,
        [string] $SecurityDomain,
        [Parameter(Mandatory=$true)] [string] $CategoryInputName,
        [Parameter(Mandatory=$true)] [string] $SubCategoryInputName,
        [Parameter(Mandatory=$true)] [string] $ConfigurationIdInputName,
        [Parameter(Mandatory=$true)] [string] $SecuritySeverityInputName,
        [Parameter(Mandatory=$true)] [string] $CriticalityTierLevelInputName,
        [string] $SecurityDomainInputName,
        [string[]] $OutputPropertyOrder,
        [string[]] $SortBy,
        [switch]   $Descending,

        [string] $RiskConsequenceScoreOutputName  = 'RiskConsequenceScore_SecuritySeverity',
        [string] $RiskProbabilityScoreOutputName  = 'RiskProbablityScore_CriticialityTierLevel',
        [string] $RiskScoreOutputName             = 'RiskScore',

        # Risk factor columns (KQL can output these; treat 0/1/true/false/yes/no)
        [string] $RiskFactorConsequenceInputName  = 'riskfactor_consequence',
        [string] $RiskFactorProbabilityInputName  = 'riskfactor_probability',

        [switch] $Trace
    )

    function _get([object]$o,[string]$n) {
        if ($null -eq $o -or [string]::IsNullOrWhiteSpace([string]$n)) { return $null }
        $p = $o.PSObject.Properties[$n]
        if ($null -eq $p) { return $null }
        $p.Value
    }

    function _mkKey([hashtable]$kv,[string[]]$pattern) {
        $vals = foreach ($c in $pattern) {
            $v = $kv[$c]
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    function _asBit([object]$v) {
        if ($null -eq $v) { return 0 }
        if ($v -is [bool]) { return [int]($v -eq $true) }
        $s = ([string]$v).Trim().ToLowerInvariant()
        if ($s -in @('1','true','yes','y')) { return 1 }
        0
    }

    function _toDouble([object]$v) {
        if ($null -eq $v) { return 0.0 }
        if ($v -is [double]) { return [double]$v }
        if ($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [single]) { return [double]$v }
        $n = 0.0
        [void][double]::TryParse([string]$v, [ref]$n)
        $n
    }

    function _findScore {
        param(
            [ValidateSet('Consequence','Probability')] [string] $Kind,
            [hashtable] $kv,
            [psobject]  $Index,
            [switch]    $TraceLocal
        )

        $hasDomain = -not [string]::IsNullOrWhiteSpace([string]$kv[$Index.SecurityDomainColumn])

        if ($Kind -eq 'Consequence') {
            $patWith  = $Index.Conseq_WithDomainPatterns
            $mapWith  = $Index.Conseq_WithDomainMaps
            $patNo    = $Index.Conseq_NoDomainPatterns
            $mapNo    = $Index.Conseq_NoDomainMaps
            $scoreCol = $Index.ConseqScoreColumn
            $valCol   = $Index.SevValueColumn
        } else {
            $patWith  = $Index.Prob_WithDomainPatterns
            $mapWith  = $Index.Prob_WithDomainMaps
            $patNo    = $Index.Prob_NoDomainPatterns
            $mapNo    = $Index.Prob_NoDomainMaps
            $scoreCol = $Index.ProbScoreColumn
            $valCol   = $Index.TierValueColumn
        }

        if ($hasDomain) {
            for ($i=0; $i -lt $patWith.Count; $i++) {
                $key = _mkKey -kv $kv -pattern $patWith[$i]
                if ($key -and $mapWith[$i].ContainsKey($key)) {
                    $row = $mapWith[$i][$key]
                    $num = _toDouble $row.$scoreCol
                    if ($TraceLocal) { Write-Host ("[{0}] matched WITH-domain #{1}: {2} -> {3}" -f $Kind, ($i+1), $key, $num) -ForegroundColor Yellow }
                    return @{ Score=$num; PatternIndex=($i+1); ValueColumnUsed=$valCol }
                }
                if ($TraceLocal -and $key) { Write-Host ("[{0}] tried WITH-domain #{1}: {2} -> no match" -f $Kind, ($i+1), $key) -ForegroundColor DarkGray }
            }
        }

        for ($j=0; $j -lt $patNo.Count; $j++) {
            $key = _mkKey -kv $kv -pattern $patNo[$j]
            if ($key -and $mapNo[$j].ContainsKey($key)) {
                $row = $mapNo[$j][$key]
                $num = _toDouble $row.$scoreCol
                if ($TraceLocal) { Write-Host ("[{0}] matched NO-domain #{1}: {2} -> {3}" -f $Kind, ($j+1), $key, $num) -ForegroundColor Yellow }
                return @{ Score=$num; PatternIndex=($j+1); ValueColumnUsed=$valCol }
            }
            if ($TraceLocal -and $key) { Write-Host ("[{0}] tried NO-domain #{1}: {2} -> no match" -f $Kind, ($j+1), $key) -ForegroundColor DarkGray }
        }

        if ($TraceLocal) { Write-Host ("[{0}] no match -> 0" -f $Kind) -ForegroundColor Red }
        @{ Score=0.0; PatternIndex=0; ValueColumnUsed=$valCol }
    }

    if ([string]::IsNullOrWhiteSpace($SecurityDomainInputName)) {
        $SecurityDomainInputName = $RiskIndex.SecurityDomainColumn
    }

    if ($null -eq $Rows) { return @() }
    $rowsArr = @()
    foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
    if ($rowsArr.Count -eq 0) { return @() }

    $out   = New-Object System.Collections.Generic.List[object]
    $total = $rowsArr.Count
    $done  = 0

    foreach ($r in $rowsArr) {
        $done++
        Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Status "Row $done of $total" -PercentComplete ([math]::Floor(($done/[math]::Max($total,1))*100))

        $domainValue = if ([string]::IsNullOrWhiteSpace($SecurityDomain)) { _get $r $SecurityDomainInputName } else { $SecurityDomain }

        $kv = @{
            ($RiskIndex.SecurityDomainColumn) = $domainValue
            ($RiskIndex.CategoryColumn)       = _get $r $CategoryInputName
            ($RiskIndex.SubCategoryColumn)    = _get $r $SubCategoryInputName
            ($RiskIndex.ConfigIdColumn)       = _get $r $ConfigurationIdInputName
            ($RiskIndex.SevValueColumn)       = _get $r $SecuritySeverityInputName
            ($RiskIndex.TierValueColumn)      = _get $r $CriticalityTierLevelInputName
        }

        $rfCons = _asBit (_get $r $RiskFactorConsequenceInputName)
        $rfProb = _asBit (_get $r $RiskFactorProbabilityInputName)

        $consBase = _findScore -Kind 'Consequence' -kv $kv -Index $RiskIndex -TraceLocal:$Trace
        $probBase = _findScore -Kind 'Probability' -kv $kv -Index $RiskIndex -TraceLocal:$Trace

        $consAdj = ([double]$consBase.Score) + ([double]$rfCons)
        $probAdj = ([double]$probBase.Score) + ([double]$rfProb)
        $risk    = $consAdj * $probAdj

        $tmp = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $tmp[$p.Name] = $p.Value }

        $tmp[$SecurityDomainInputName]        = $domainValue
        $tmp[$RiskConsequenceScoreOutputName] = [double]$consAdj
        $tmp[$RiskProbabilityScoreOutputName] = [double]$probAdj
        $tmp[$RiskScoreOutputName]            = [double]$risk

        if (-not $tmp.Contains('RiskFactor_Consequence')) { $tmp['RiskFactor_Consequence'] = [int]$rfCons }
        if (-not $tmp.Contains('RiskFactor_Probability')) { $tmp['RiskFactor_Probability'] = [int]$rfProb }

        if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
            $h = [ordered]@{}
            foreach ($name in $OutputPropertyOrder) { if ($tmp.Contains($name)) { $h[$name] = $tmp[$name] } }
            foreach ($k in $tmp.Keys) { if (-not $h.Contains($k)) { $h[$k] = $tmp[$k] } }
            $out.Add([pscustomobject]$h) | Out-Null
        } else {
            $out.Add([pscustomobject]$tmp) | Out-Null
        }
    }

    Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Completed

    $finalOut = $null
    try {
        $finalOut = [object[]]$out.ToArray()
    } catch {
        $tmpList = New-Object System.Collections.Generic.List[object]
        foreach ($x in $out) { $tmpList.Add($x) | Out-Null }
        $finalOut = [object[]]$tmpList.ToArray()
    }

    if ($SortBy -and $SortBy.Count -gt 0) {
        if ($Descending) { $finalOut = @($finalOut | Sort-Object -Property $SortBy -Descending) }
        else             { $finalOut = @($finalOut | Sort-Object -Property $SortBy) }
    }

    return @($finalOut)
}

function Filter-ObjectsByColumn {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowNull()]
    [object[]] $InputObject,

    [Parameter(Mandatory)]
    [string] $ColumnToFilter,

    [Parameter(Mandatory)][AllowNull()]
    [object[]] $InScopeData,

    [switch] $CaseInsensitive
  )

  if ($null -eq $InputObject -or $InputObject.Count -eq 0) { return @() }
  if ($null -eq $InScopeData -or $InScopeData.Count -eq 0) { return @($InputObject) }

  function _Normalize([object] $val, [bool] $ci) {
    if ($null -eq $val) { return $null }
    $s = ([string]$val).Trim()
    if ($ci) { return $s.ToLowerInvariant() }
    return $s
  }

  $normalizedScope = @()
  foreach ($x in $InScopeData) {
    $nx = _Normalize -val $x -ci:$CaseInsensitive.IsPresent
    if ($null -ne $nx -and $nx -ne '') { $normalizedScope += $nx }
  }
  if ($normalizedScope.Count -eq 0) { return @($InputObject) }

  $out = New-Object System.Collections.Generic.List[object]

  foreach ($obj in $InputObject) {

    if ($null -eq $obj) { continue }

    if (-not ($obj.PSObject.Properties.Name -contains $ColumnToFilter)) {
      $out.Add($obj) | Out-Null
      continue
    }

    $val = $obj.$ColumnToFilter

    $candidates = @()
    if ($null -eq $val) {
      $candidates = @()
    }
    elseif ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
      foreach ($item in $val) { $candidates += $item }
    }
    else {
      $s = [string]$val
      if ($s -like "*,*") { $candidates = $s -split '\s*,\s*' }
      else { $candidates = @($s) }
    }

    $match = $false
    foreach ($cand in $candidates) {
      $nc = _Normalize -val $cand -ci:$CaseInsensitive.IsPresent
      if ($null -ne $nc -and $normalizedScope -contains $nc) { $match = $true; break }
    }

    if ($match) { $out.Add($obj) | Out-Null }
  }

  return @($out.ToArray())
}

function Write-Section($text) {
  Write-Host ""
  Write-Host "==== $text ====" -ForegroundColor Cyan
}

# exporter (single-write workflow; still supports -ClearSheet)
function Export-Worksheet {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)]$Rows,
    [string]$SortColumn,
    [switch]$SortDescending,
    [string[]]$DesiredColumns,
    [string[]]$ColumnsToFlatten = @(),
    [string]$TableStyle = 'Medium9'
  )

  function Convert-CellValue {
    param(
      [Parameter()][AllowNull()]$Value,
      [string]$JoinChar = ', '
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or
        $Value -is [int] -or $Value -is [long] -or
        $Value -is [double] -or $Value -is [decimal] -or
        $Value -is [datetime] -or $Value -is [bool] -or
        $Value -is [guid]) {
      return $Value
    }

    if ($Value -is [pscustomobject] -or $Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
      try { return ($Value | ConvertTo-Json -Compress -Depth 12) } catch { return ($Value | Out-String).Trim() }
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
      $items = @()
      foreach ($i in $Value) {
        if ($null -eq $i) { continue }
        if ($i -is [string] -or $i.GetType().IsPrimitive) {
          $items += [string]$i
        } else {
          try { $items += ($i | ConvertTo-Json -Compress -Depth 12) }
          catch { $items += ([string]($i | Out-String).Trim()) }
        }
      }
      return ($items -join $JoinChar)
    }

    return [string]$Value
  }

  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  $tableName = ($safeSheet -replace '\W','_')

  if (-not $Rows -or $Rows.Count -eq 0) {
    $excel = ([pscustomobject]@{ Info = 'No rows returned' }) |
      Export-Excel -Path $Path -WorksheetName $safeSheet -TableName $tableName -TableStyle $TableStyle `
        -AutoSize -FreezeTopRow -BoldTopRow -ClearSheet -PassThru
    $ws = $excel.Workbook.Worksheets[$safeSheet]
    $ws.Cells.AutoFitColumns()
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
    }
    Close-ExcelPackage $excel
    $script:_sheetWritten[$safeSheet] = $true
    return
  }

  $Data = $Rows
  if ($DesiredColumns) { $Data = $Data | Select-Object -Property $DesiredColumns }

  if ($ColumnsToFlatten.Count -gt 0) {
    $Data = $Data | ForEach-Object {
      $o = [ordered]@{}
      foreach ($p in $_.PSObject.Properties) {
        $v = $p.Value
        if ($ColumnsToFlatten -contains $p.Name) {
          $v = Convert-CellValue -Value $v
        }
        $o[$p.Name] = $v
      }
      [pscustomobject]$o
    }
  }

  if ($SortColumn) {
    $Data = $Data | Sort-Object -Property $SortColumn -Descending:$SortDescending.IsPresent
  }

  $excel = $Data | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle $TableStyle `
    -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

  $ws = $excel.Workbook.Worksheets[$safeSheet]
  $ws.Cells.AutoFitColumns()
  for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
    if ($ws.Column($col).Width -gt 50) { $ws.Column($col).Width = 50 }
  }
  Close-ExcelPackage $excel

  $script:_sheetWritten[$safeSheet] = $true
}

function New-RiskIndex {
    param(
        [Parameter(Mandatory=$true)][object[]] $CsvRows,
        [Parameter(Mandatory=$true)][string] $ColSecurityDomain,
        [Parameter(Mandatory=$true)][string] $ColCategory,
        [Parameter(Mandatory=$true)][string] $ColSubCategory,
        [Parameter(Mandatory=$true)][string] $ColConfigId,
        [Parameter(Mandatory=$true)][string] $ColSevValue,
        [Parameter(Mandatory=$true)][string] $ColTierValue,
        [Parameter(Mandatory=$true)][string] $ColConseqScore,
        [Parameter(Mandatory=$true)][string] $ColProbScore
    )
    if (-not $CsvRows) { throw "Risk definitions CSV is empty." }
    $firstCols = $CsvRows[0].PSObject.Properties.Name
    $required  = @($ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue,$ColTierValue,$ColConseqScore,$ColProbScore)
    $missing   = $required | Where-Object { $firstCols -notcontains $_ }
    if ($missing.Count) { throw "CSV missing required columns: $($missing -join ', ')" }

    function _MakeKey([object]$Row,[string[]]$Pattern){
        $vals = foreach ($c in $Pattern){
            $v = $Row.$c
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    $seqWithDomain_Conseq = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSevValue),
        @($ColSecurityDomain,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )
    $seqNoDomain_Conseq = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColCategory,$ColSubCategory,$ColSevValue),
        @($ColCategory,$ColSevValue),
        @($ColSevValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )
    $seqWithDomain_Prob = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColTierValue),
        @($ColSecurityDomain,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )
    $seqNoDomain_Prob = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColCategory,$ColSubCategory,$ColTierValue),
        @($ColCategory,$ColTierValue),
        @($ColTierValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    $mapsConseq_With = foreach ($pat in $seqWithDomain_Conseq) { @{} }
    $mapsConseq_No   = foreach ($pat in $seqNoDomain_Conseq)   { @{} }
    $mapsProb_With   = foreach ($pat in $seqWithDomain_Prob)   { @{} }
    $mapsProb_No     = foreach ($pat in $seqNoDomain_Prob)     { @{} }

    foreach ($row in $CsvRows) {
        for ($i=0; $i -lt $seqWithDomain_Conseq.Count; $i++){
            $k = _MakeKey $row $seqWithDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_With[$i].ContainsKey($k)) { $mapsConseq_With[$i][$k]=$row }
        }
        for ($i=0; $i -lt $seqNoDomain_Conseq.Count; $i++){
            $k = _MakeKey $row $seqNoDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_No[$i].ContainsKey($k)) { $mapsConseq_No[$i][$k]=$row }
        }
        for ($i=0; $i -lt $seqWithDomain_Prob.Count; $i++){
            $k = _MakeKey $row $seqWithDomain_Prob[$i]
            if ($k -and -not $mapsProb_With[$i].ContainsKey($k)) { $mapsProb_With[$i][$k]=$row }
        }
        for ($i=0; $i -lt $seqNoDomain_Prob.Count; $i++){
            $k = _MakeKey $row $seqNoDomain_Prob[$i]
            if ($k -and -not $mapsProb_No[$i].ContainsKey($k)) { $mapsProb_No[$i][$k]=$row }
        }
    }

    [pscustomobject]@{
        SecurityDomainColumn = $ColSecurityDomain
        CategoryColumn       = $ColCategory
        SubCategoryColumn    = $ColSubCategory
        ConfigIdColumn       = $ColConfigId
        SevValueColumn       = $ColSevValue
        TierValueColumn      = $ColTierValue
        ConseqScoreColumn    = $ColConseqScore
        ProbScoreColumn      = $ColProbScore
        Conseq_WithDomainPatterns = $seqWithDomain_Conseq
        Conseq_NoDomainPatterns   = $seqNoDomain_Conseq
        Prob_WithDomainPatterns   = $seqWithDomain_Prob
        Prob_NoDomainPatterns     = $seqNoDomain_Prob
        Conseq_WithDomainMaps = $mapsConseq_With
        Conseq_NoDomainMaps   = $mapsConseq_No
        Prob_WithDomainMaps   = $mapsProb_With
        Prob_NoDomainMaps     = $mapsProb_No
    }
}

function Send-MailAnonymous {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    $params = @{
        SmtpServer = $SmtpServer
        Port       = $Port
        From       = $From
        To         = $To
        Subject    = $Subject
        Body       = $BodyHtml
        BodyAsHtml = $true
        Encoding   = 'UTF8'
        Priority   = $Priority
    }

    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    Write-Output ("Sending mail (anonymous) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)
    Send-MailMessage @params
}

function Send-MailSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        Credential  = $Credential
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $BodyHtml
        BodyAsHtml  = $true
        Encoding    = 'UTF8'
        Priority    = $Priority
    }

    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    Write-Output ("Sending mail (secure) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)
    Send-MailMessage @params
}

function Test-AzModuleInstalled {
    return @(Get-Module -ListAvailable | Where-Object { $_.Name -like 'Az.*' }).Count -gt 0
}

function Test-MicrosoftGraphInstalled {
    return @(Get-Module -ListAvailable | Where-Object { $_.Name -like 'Microsoft.Graph.*' }).Count -gt 0
}


#####################################################################################################
# POWERSHEL MODULE VALIDATION
#####################################################################################################

Write-Step "initializing"

if (-not (Test-AzModuleInstalled)) {
    Write-Step "Installing Az modules ... Please Wait !"
    Install-Module Az -Scope AllUsers -Force -AllowClobber
}

if (-not (Test-MicrosoftGraphInstalled)) {
    Write-Step "Installing Microsoft Graph modules ... Please Wait !"
    Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber
}

Ensure-Module Az.Accounts
Ensure-Module Az.Resources
Ensure-Module Az.ResourceGraph
Ensure-Module Microsoft.Graph.Security
Ensure-Module MicrosoftGraphPS
Ensure-Module ImportExcel
Ensure-Module powershell-yaml


#####################################################################################################
# CONNECTION
#####################################################################################################

if ($AutomationFramework) {

    #----------------------
    # AUTOMATION FRAMEWORK
    #----------------------

    $ScriptDirectory = $PSScriptRoot
    $global:PathScripts = Split-Path -parent $ScriptDirectory
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # Loading function modules (2LINKIT)
    Write-Step "importing function modules"
    Tock
    try {
      Import-Module "$($global:PathScripts)\FUNCTIONS\2LINKIT-Functions.psm1" -Global -Force -WarningAction SilentlyContinue
      Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-ConnectDetails.psm1" -Global -Force -WarningAction SilentlyContinue
      Write-Ok "modules imported"
    } catch { Write-Err2 "failed to import one or more modules: $($_.Exception.Message)"; throw }
    Tick "module import"

    Write-Step "loading connect details and defaults"
    Tock
    try {
      ConnectDetails
      Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-DefaultVariables.psm1" -Global -Force -WarningAction SilentlyContinue
      Default_Variables
      Write-Ok "connect details and defaults loaded"
    } catch { Write-Err2 "failed while loading connect details/defaults: $($_.Exception.Message)"; throw }
    Tick "connect details + defaults"

    Write-Step "connecting to Azure (helper Connect_Azure.ps1)"
    Tock
    try {
      & "$($global:PathScripts)\FUNCTIONS\Connect_Azure.ps1"
      Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }

    $global:SpnTenantId         = $global:AzureTenantId
    $global:SpnClientId         = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret     = $global:HighPriv_Modern_Secret_Azure

    # ==============================
    # Graph auth helpers (app+cert)
    # ==============================
    $script:GraphLastConnectUtc = [datetime]::MinValue

    # Graph re-auth settings
    $GraphReconnectMaxAgeMinutes = 45               # proactive reconnect interval during long bucket loops
    $GraphQueryMaxRetries        = 4                # retries per bucket/single query

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try {
      Connect-GraphHighPriv
    } catch {
      Write-Err2 "initial graph connect failed: $($_.Exception.Message)"
      throw
    }
    Tick "graph connect"

    #------------------------------------------------------------------------------------------------------------
    # Output File
    #------------------------------------------------------------------------------------------------------------

    $OutputDir  = Join-Path $global:PathScripts 'OUTPUT'
    Ensure-Directory -Path $OutputDir
    $OutputXlsx = Join-Path $OutputDir ("{0}.xlsx" -f $ReportTemplate)

    #------------------------------------------------------------------------------------------------------------
    # Mail routing (Summary vs Detailed)
    #------------------------------------------------------------------------------------------------------------

    if ($Detailed -and $Summary) {
      throw "Invalid parameters: Use only one of -Detailed or -Summary."
    }

    if ($Detailed) {
      Write-Info "Mail mode selected: Detailed"
      $Report_SendMail = $global:Mail_Security_ExposureInsights_Detailed_SendMail
      $Report_To       = $global:Mail_Security_ExposureInsights_Detailed_To
    }
    elseif ($Summary) {
      Write-Info "Mail mode selected: Summary"
      $Report_SendMail = $global:Mail_Security_ExposureInsights_Summary_SendMail
      $Report_To       = $global:Mail_Security_ExposureInsights_Summary_To
    }
    else {
      # Default behavior (keep what you want as default)
      Write-Info "Mail mode selected: Default (no -Detailed/-Summary provided)"
      $Report_SendMail = $global:Mail_Security_ExposureInsights_Detailed_SendMail
      $Report_To       = $global:Mail_Security_ExposureInsights_Detailed_To
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $Report_SendMail, ($Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # ExposureInsight settings
    #------------------------------------------------------------------------------------------------------------

    $ReportSettingsFile     = "SecurityInsight_RiskAnalysis.yaml"
    $RiskDefinitionsCsvPath = "$SettingsPath\SecurityInsight_RiskIndex.csv"

} Else {

    #----------------------
    # Connect Custom Auth
    #----------------------

    write-host "Connect using ServicePrincipal with AppId & Secret"

    Write-Step "connecting to Azure"
    Tock
    try {

        $SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force

        $Credential = New-Object System.Management.Automation.PSCredential (
            $global:SpnClientId,
            $SecureSecret
        )

        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $Credential -WarningAction SilentlyContinue

        Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
    Tick "azure connect"

    #------------------------------------------------------------------------------------------------------------
    # Graph auth helpers (app+cert)
    #------------------------------------------------------------------------------------------------------------
    $script:GraphLastConnectUtc = [datetime]::MinValue

    # Graph re-auth settings
    $GraphReconnectMaxAgeMinutes = 45               # proactive reconnect interval during long bucket loops
    $GraphQueryMaxRetries        = 4                # retries per bucket/single query

    #------------------------------------------------------------------------------------------------------------
    # Graph connect (initial)
    #------------------------------------------------------------------------------------------------------------
    Write-Step "connecting to Microsoft Graph (initial)"
    Tock
    try {
      Connect-GraphHighPriv
    } catch {
      Write-Err2 "initial graph connect failed: $($_.Exception.Message)"
      throw
    }
    Tick "graph connect"


    #------------------------------------------------------------------------------------------------------------
    # Output File
    #------------------------------------------------------------------------------------------------------------

    Write-Info "Chosen ReportTemplate: $ReportTemplate"


    #------------------------------------------------------------------------------------------------------------
    # Mail routing (Summary vs Detailed)
    #------------------------------------------------------------------------------------------------------------

      $Report_SendMail = $SendMail
      $Report_To       = $MailTo

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $Report_SendMail, ($Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # ExposureInsight settings
    #------------------------------------------------------------------------------------------------------------

    $OutputDir  = Join-Path $SettingsPath 'OUTPUT'
    Ensure-Directory -Path $OutputDir
    $OutputXlsx = Join-Path $OutputDir ("{0}.xlsx" -f $ReportTemplate)

    $ReportSettingsFile     = "SecurityInsight_RiskAnalysis.yaml"
    $RiskDefinitionsCsvPath = "$SettingsPath\SecurityInsight_RiskIndex.csv"
}


# Generic bucketing configuration (for large queries)
$UseQueryBucketing      = $false                # global default; can be overridden per report in YAML (report) or per include item (template)
$DefaultBucketCount     = 2                     # split query into this many buckets (default)
$BucketPlaceholderToken = "__BUCKET_FILTER__"   # marker string in KQL where bucket filter will be injected (default)

Write-Step "settings overview"
Write-Info "OutputXlsx: $OutputXlsx"
Write-Info "SettingsPath: $SettingsPath"
Write-Info "Risk Analysis Settings File: $ReportSettingsFile"
Write-Info "Risk Index Csv Path: $RiskDefinitionsCsvPath"
Write-Info "Chosen ReportTemplate: $ReportTemplate"
Write-Info "Query bucketing: UseQueryBucketing=$UseQueryBucketing, DefaultBucketCount=$DefaultBucketCount, Placeholder='$BucketPlaceholderToken'"
Write-Info "Graph reconnect: MaxAgeMinutes=$GraphReconnectMaxAgeMinutes, MaxRetries=$GraphQueryMaxRetries"


#####################################################################################################
# INITIALIZATION
#####################################################################################################

Reset-ExcelOutput -Path $OutputXlsx -ForceRemove:([bool]$OverwriteXlsx)

# track sheet first/append state per run (kept for compatibility; export is now single-write)
if (-not $script:_sheetWritten) { $script:_sheetWritten = @{} }

# Get data
Write-Step "loading report settings from YAML"
Tock
try {
  $Report_Settings_raw = Get-Content -Raw "$SettingsPath\$ReportSettingsFile" | ConvertFrom-Yaml
  $Report_Settings     = ConvertTo-PSObjectDeep $Report_Settings_raw
  Write-Ok "report settings loaded"
} catch { Write-Err2 "failed to read/parse report settings yaml: $($_.Exception.Message)"; throw }
Tick "yaml load"

$Exposure_Reports   = $Report_Settings.Reports
$Exposure_Template  = $Report_Settings.ReportTemplates | Where-Object { $_.ReportName -eq $ReportTemplate }

if (-not $Exposure_Template) {
  throw "ReportTemplate '$ReportTemplate' not found in YAML under ReportTemplates."
}

$Exposure_Template_ReportsIncluded = $Exposure_Template.ReportsIncluded
if (-not $Exposure_Template_ReportsIncluded) {
  throw "ReportTemplate '$ReportTemplate' has no ReportsIncluded."
}

# Log resolved report names
$incNamesForLog = @()
foreach ($x in $Exposure_Template_ReportsIncluded) {
  $inc = Resolve-ReportInclude -Item $x
  $incNamesForLog += $inc.Name
}
Write-Info ("reports in template: {0}" -f ($incNamesForLog -join ', '))

# ---------- Risk Index --------------------------------------------------------------------
Write-Section "building risk index (CSV map)"

$CsvSecurityDomainColumnName        = 'SecurityDomain'
$CsvCategoryColumnName              = 'Category'
$CsvSubCategoryColumnName           = 'SubCategory'
$CsvConfigurationIdColumnName       = 'ConfigurationId'
$CsvSecuritySeverityColumnName      = 'SecuritySeverity'
$CsvCriticalityTierLevelColumnName  = 'CriticalityTierLevel'
$CsvConsequenceScoreColumnName      = 'RiskConsequenceScore_SecuritySeverity'
$CsvProbabilityScoreColumnName      = 'RiskProbablityScore_CriticialityTierLevel'

Tock
try {
  $RiskDefinitions = Import-Csv -Path $RiskDefinitionsCsvPath
  Write-Info ("risk rows: {0}" -f ($RiskDefinitions | Measure-Object | Select-Object -ExpandProperty Count))
} catch { Write-Err2 "cannot read risk definitions csv: $($_.Exception.Message)"; throw }


Tock
try {
  $RiskIndex = New-RiskIndex `
      -CsvRows $RiskDefinitions `
      -ColSecurityDomain       $CsvSecurityDomainColumnName `
      -ColCategory             $CsvCategoryColumnName `
      -ColSubCategory          $CsvSubCategoryColumnName `
      -ColConfigId             $CsvConfigurationIdColumnName `
      -ColSevValue             $CsvSecuritySeverityColumnName `
      -ColTierValue            $CsvCriticalityTierLevelColumnName `
      -ColConseqScore          $CsvConsequenceScoreColumnName `
      -ColProbScore            $CsvProbabilityScoreColumnName
  Write-Ok "risk index built"
} catch { Write-Err2 "failed to build risk index: $($_.Exception.Message)"; throw }
Tick "risk index build"

#####################################################################################################
# MAIN LOOP
#####################################################################################################

Write-Section "executing reports"

$AllShapedRows = New-Object System.Collections.Generic.List[object]
$FinalRiskScoreColumnName = $null
$FinalDesiredColumns = $null

foreach ($includeItem in $Exposure_Template_ReportsIncluded) {

    $inc = Resolve-ReportInclude -Item $includeItem
    $ReportNameFromTemplate = $inc.Name

    $Entry = $Exposure_Reports | Where-Object { $_.ReportName -eq $ReportNameFromTemplate }

    if (-not $Entry) {
        Write-Warn2 ("report '{0}' defined in template but not found in report configurations" -f $ReportNameFromTemplate)
        continue
    }

    $ReportName                     = $Entry.ReportName
    $ReportPurpose                  = $Entry.ReportPurpose

    $SecurityDomain                 = $Entry.SecurityDomain
    $CategoryInputName              = $Entry.CategoryInputName
    $SubcategoryInputName           = $Entry.SubcategoryInputName
    $ConfigurationIdInputName       = $Entry.ConfigurationIdInputName

    $CriticalityTierLevelInputName  = $Entry.CriticalityTierLevelInputName
    $CriticalityTierLevelScope      = $Entry.CriticalityTierLevelScope

    $SecuritySeverityInputName      = $Entry.SecuritySeverityInputName
    $SecuritySeverityScope          = $Entry.SecuritySeverityScope

    $RiskConsequenceScoreOutputName = $Entry.RiskConsequenceScoreOutputName
    $RiskProbabilityScoreOutputName = $Entry.RiskProbabilityScoreOutputName
    $RiskScoreOutputName            = $Entry.RiskScoreOutputName

    $OutputPropertyOrder            = $Entry.OutputPropertyOrder
    $SortBy                         = $Entry.SortBy

    $Query                          = $Entry.ReportQuery

    # Bucketing resolution: include item > report entry > script defaults
    $effectiveUseBucket   = [bool]$UseQueryBucketing
    $effectiveBucketCount = [int]$DefaultBucketCount
    $effectivePlaceholder = [string]$BucketPlaceholderToken

    if ($Entry.PSObject.Properties['UseBucketFilter'] -and $Entry.UseBucketFilter -ne $null) {
        $effectiveUseBucket = [bool]$Entry.UseBucketFilter
    }
    if ($Entry.PSObject.Properties['BucketCount'] -and $Entry.BucketCount) {
        $bc = [int]$Entry.BucketCount
        if ($bc -gt 0) { $effectiveBucketCount = $bc }
    }

    if ($inc.UseQueryBucketing -ne $null) {
        $effectiveUseBucket = [bool]$inc.UseQueryBucketing
    }
    if ($inc.DefaultBucketCount -ne $null) {
        $bc2 = [int]$inc.DefaultBucketCount
        if ($bc2 -gt 0) { $effectiveBucketCount = $bc2 }
    }
    if (-not [string]::IsNullOrWhiteSpace($inc.BucketPlaceholderToken)) {
        $effectivePlaceholder = [string]$inc.BucketPlaceholderToken
    }

    $querySupportsBucket = ($Query -like "*$effectivePlaceholder*")

    Write-Step ("report '{0}' - {1}" -f $ReportName,$ReportPurpose)
    Write-Info ("domain='{0}', category='{1}', sub='{2}', configId='{3}', sevCol='{4}', tierCol='{5}'" -f `
      $SecurityDomain,$CategoryInputName,$SubcategoryInputName,$ConfigurationIdInputName,$SecuritySeverityInputName,$CriticalityTierLevelInputName)
    Write-Info ("bucketing: UseQueryBucketing={0}, BucketCount={1}, Token='{2}', QueryHasToken={3}" -f `
      $effectiveUseBucket, $effectiveBucketCount, $effectivePlaceholder, $querySupportsBucket)

    $ResultAll = @()

    if ($effectiveUseBucket -and $querySupportsBucket -and $effectiveBucketCount -gt 1) {
        Write-Info ("query contains placeholder '{0}' and bucketing is enabled. Running in {1} buckets." -f $effectivePlaceholder,$effectiveBucketCount)

        for ($b = 0; $b -lt $effectiveBucketCount; $b++) {

            $bucketNo = $b + 1
            $bucketFilter = New-BucketFilterKql -BucketCount $effectiveBucketCount -BucketIndex $b
            $thisQuery    = $Query.Replace($effectivePlaceholder, $bucketFilter)

            Write-Info ("bucket {0}/{1}: running advanced hunting query against Defender Exposure Management Graph ... Please wait !" -f $bucketNo, $effectiveBucketCount)
            Tock
            try {
                $resp = Invoke-GraphHuntingQuery -Query $thisQuery -ReconnectMaxAgeMinutes $GraphReconnectMaxAgeMinutes -MaxRetries $GraphQueryMaxRetries
                Tick ("hunting query bucket {0}/{1}" -f $bucketNo, $effectiveBucketCount)
            } catch {
                Write-Err2 ("advanced hunting query failed for bucket {0}/{1}: {2}" -f $bucketNo, $effectiveBucketCount, $_.Exception.Message)
                continue
            }

            $rawResults = $null
            if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }

            if ($null -eq $rawResults) {
                Write-Info ("bucket {0}/{1}: no results" -f $bucketNo, $effectiveBucketCount)
                continue
            }

            Tock
            try {
                $bucketResult = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
            } catch {
                Write-Err2 ("result conversion failed for bucket {0}/{1}: {2}" -f $bucketNo, $effectiveBucketCount, $_.Exception.Message)
                continue
            }
            $bucketCount  = ($bucketResult | Measure-Object).Count
            Tick ("result conversion (bucket {0}/{1})" -f $bucketNo, $effectiveBucketCount)

            Write-Info ("bucket {0}/{1}: {2} rows" -f $bucketNo, $effectiveBucketCount, $bucketCount)
            foreach ($row in $bucketResult) { $ResultAll += ,$row }
        }

        Write-Info ("total rows across all buckets before dedupe: {0}" -f $ResultAll.Count)
        $ResultAll = Deduplicate-Rows -Rows $ResultAll
        Write-Info ("total rows after dedupe: {0}" -f ($ResultAll | Measure-Object).Count)
    }
    else {
        if ($effectiveUseBucket -and -not $querySupportsBucket) {
            Write-Warn2 ("bucketing enabled but query does not contain placeholder '{0}'. Running single query." -f $effectivePlaceholder)
        }

        Tock
        try {
            Write-Info "running advanced hunting query against Defender Exposure Management Graph ... Please wait !"
            $resp = Invoke-GraphHuntingQuery -Query $Query -ReconnectMaxAgeMinutes $GraphReconnectMaxAgeMinutes -MaxRetries $GraphQueryMaxRetries
            Tick "hunting query"
        } catch {
            Write-Err2 "advanced hunting query failed: $($_.Exception.Message)"
            continue
        }

        $rawResults = $null
        if ($null -ne $resp -and $null -ne $resp.Results) { $rawResults = $resp.Results.AdditionalProperties }
        if ($null -eq $rawResults) {
            Write-Warn2 "query returned no results"
            continue
        }

        Tock
        try {
            $ResultSingle = ConvertTo-PSObjectDeep $rawResults -StripOData -CastPrimitiveArrays
        } catch {
            Write-Err2 "result conversion failed: $($_.Exception.Message)"
            continue
        }
        Tick "result conversion"

        foreach ($row in $ResultSingle) { $ResultAll += ,$row }
        Write-Info ("rows before filters: {0}" -f $ResultAll.Count)
    }

    if ($ResultAll.Count -eq 0) {
        Write-Warn2 "no rows returned from query; skipping this report"
        continue
    }

    # Filters (pass-through if scope is null/empty)
    $ResultFiltered = @($ResultAll)

    # Debug if filters later remove everything: sample BEFORE filtering
    $sampleBefore = $ResultFiltered | Select-Object -First 5

    Tock
    $ResultFiltered = Apply-ScopeFilter -Rows $ResultFiltered -ColumnName $CriticalityTierLevelInputName -Scope $CriticalityTierLevelScope
    $ResultFiltered = Apply-ScopeFilter -Rows $ResultFiltered -ColumnName $SecuritySeverityInputName     -Scope $SecuritySeverityScope
    $totalAfter = ($ResultFiltered | Measure-Object).Count
    Tick "apply filters"
    Write-Info ("rows after filters:  {0}" -f $totalAfter)

    if ($totalAfter -eq 0) {
      Write-Warn2 "no rows after filtering; skipping risk calculation for this report"
      continue
    }

    # Risk calc
    Tock
    Write-Info "calculating risk scores (trace off)"
    $RiskScoreArray = Calculate-RiskScore `
      -Rows @($ResultFiltered) `
      -RiskIndex $RiskIndex `
      -SecurityDomain $SecurityDomain `
      -CategoryInputName $CategoryInputName `
      -SubCategoryInputName $SubcategoryInputName `
      -ConfigurationIdInputName $ConfigurationIdInputName `
      -SecuritySeverityInputName $SecuritySeverityInputName `
      -CriticalityTierLevelInputName $CriticalityTierLevelInputName `
      -SecurityDomainInputName 'SecurityDomain' `
      -OutputPropertyOrder $OutputPropertyOrder `
      -SortBy @($SortBy) -Descending `
      -RiskConsequenceScoreOutputName $RiskConsequenceScoreOutputName `
      -RiskProbabilityScoreOutputName $RiskProbabilityScoreOutputName `
      -RiskScoreOutputName $RiskScoreOutputName
    Tick "risk scoring"

    # Shape columns: enforce YAML order + computed columns, preserve types
    $ComputedCols = @($RiskConsequenceScoreOutputName, $RiskProbabilityScoreOutputName, $RiskScoreOutputName)
    $DesiredColumns = @()
    if ($OutputPropertyOrder) { $DesiredColumns += $OutputPropertyOrder }
    foreach ($c in $ComputedCols) { if ($DesiredColumns -notcontains $c) { $DesiredColumns += $c } }

    $firstObj = $RiskScoreArray | Select-Object -First 1
    if ($firstObj) {
      $allProps = ($firstObj | Get-Member -MemberType NoteProperty).Name
      foreach ($p in $allProps) { if ($DesiredColumns -notcontains $p) { $DesiredColumns += $p } }
    }

    $Shaped = $RiskScoreArray | Select-Object -Property $DesiredColumns

    # Ensure RiskScore is numeric for sorting
    $Shaped = $Shaped | ForEach-Object {
      if ($_.$RiskScoreOutputName -isnot [double]) {
        $num = 0.0
        [void][double]::TryParse([string]($_.$RiskScoreOutputName), [ref]$num)
        $_.$RiskScoreOutputName = $num
      }
      $_
    }

    if (-not $FinalRiskScoreColumnName -and -not [string]::IsNullOrWhiteSpace($RiskScoreOutputName)) {
        $FinalRiskScoreColumnName = $RiskScoreOutputName
    }
    if (-not $FinalDesiredColumns) {
        $FinalDesiredColumns = $DesiredColumns
    }

    foreach ($row in @($Shaped)) { $AllShapedRows.Add($row) | Out-Null }
    Write-Ok ("added {0} rows to export pool (total now {1})" -f (@($Shaped).Count), $AllShapedRows.Count)
}

# Final export (single write, already sorted)
Write-Section "final excel export"

if ($AllShapedRows.Count -eq 0) {
    Write-Warn2 "no rows collected across reports; nothing to export"
} else {
    if ([string]::IsNullOrWhiteSpace($FinalRiskScoreColumnName)) {
        $FinalRiskScoreColumnName = 'RiskScore'
        Write-Warn2 "FinalRiskScoreColumnName not set; using default 'RiskScore'"
    }
    if (-not $FinalDesiredColumns) {
        $FinalDesiredColumns = ($AllShapedRows[0] | Get-Member -MemberType NoteProperty).Name
    }

    Write-Step "sorting rows by risk score (descending)"
    Tock

    $allRows = @()
    foreach ($r in $AllShapedRows) { $allRows += ,$r }

    $final = $allRows | Sort-Object -Descending -Property @{
        Expression = {
            $n = 0.0
            $v = $null
            if ($_.PSObject.Properties[$FinalRiskScoreColumnName]) { $v = $_.$FinalRiskScoreColumnName }
            [void][double]::TryParse([string]$v, [ref]$n)
            $n
        }
    }
    Tick "final sort"

    Write-Step "exporting to excel (single write)"
    Write-Info ("path: {0}" -f $OutputXlsx)
    Tock
    Export-Worksheet -Path $OutputXlsx -SheetName 'Details' `
      -Rows @($final) `
      -SortColumn $FinalRiskScoreColumnName -SortDescending `
      -DesiredColumns $FinalDesiredColumns `
      -ColumnsToFlatten @('ImpactedAssets','Logins','Benchmarks','EG_AssetProps','AssetProps','Properties') `
      -TableStyle 'Medium9'
    Tick "excel export"
    Write-Ok "report exported"
}

Write-Host ""
Write-Ok ("excel file ready: {0}" -f $OutputXlsx)


#########################################################################################################
# BUILD AI SUMMARY CONTEXT (based on the final shaped + sorted export rows)
#########################################################################################################

$AI_apiKey     = "Eet1UxphX9YsHncQ98vS51jAUX0xwO3l9FqcKn95zhfuQVhisUw3JQQJ99BEAC5RqLJXJ3w3AAABACOGPGBy"
$AI_endpoint   = "https://pim-role-advisor.openai.azure.com"
$AI_deployment = "gpt-4o-mini"
$AI_apiVersion = "2024-12-01-preview"
$AI_uri        = "$AI_endpoint/openai/deployments/$AI_deployment/chat/completions?api-version=$AI_apiVersion"

Write-Host "[AI] URI = $AI_uri"
if ($AI_uri -notmatch '^https?://') { throw "[AI] URI is not absolute: $AI_uri" }

# Make sure we always have a variable for mail body usage
$AI_SummaryText = ""

if ($PSBoundParameters.ContainsKey('BuildSummaryByAI') -or $BuildSummaryByAI) {

    Write-Section "AI summary"

    if ($null -eq $final -or @($final).Count -eq 0) {
        Write-Warn2 "BuildSummaryByAI requested, but there are no final rows to summarize."
        # still continue, but AI will be empty
    }
    else {

        # How many top findings to include in the AI context
        $TopN = 50
        if ($PSBoundParameters.ContainsKey('AISummaryTopN')) {
            try { $TopN = [int]$AISummaryTopN } catch { }
            if ($TopN -lt 10)  { $TopN = 10 }
            if ($TopN -gt 200) { $TopN = 200 }
        }

        # How many top assets to include in asset rollup for AI context
        $TopAssetsN = 25
        if ($PSBoundParameters.ContainsKey('AISummaryTopAssetsN')) {
            try { $TopAssetsN = [int]$AISummaryTopAssetsN } catch { }
            if ($TopAssetsN -lt 10)  { $TopAssetsN = 10 }
            if ($TopAssetsN -gt 200) { $TopAssetsN = 200 }
        }

        function Get-RowValue {
            param(
                [Parameter(Mandatory=$true)] $Row,
                [Parameter(Mandatory=$true)] [string[]] $Names
            )
            foreach ($n in $Names) {
                if ($Row.PSObject.Properties.Name -contains $n) {
                    $v = $Row.$n
                    if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
                }
            }
            return ""
        }

        function Test-LooksLikeHost {
            param([string]$s)
            if ([string]::IsNullOrWhiteSpace($s)) { return $false }
            $t = $s.Trim()
            if ($t -match '^[a-zA-Z0-9][a-zA-Z0-9\-]{1,63}$') { return $true }
            if ($t -match '^[a-zA-Z0-9][a-zA-Z0-9\-]{1,63}(\.[a-zA-Z0-9\-]{1,63}){1,10}$') { return $true }
            return $false
        }

        function Split-ImpactedAssets {
            param([string]$AssetsText)

            if ([string]::IsNullOrWhiteSpace($AssetsText)) { return @() }

            $t = $AssetsText.Trim()

            if ($t.StartsWith('[') -and $t.EndsWith(']')) {
                try {
                    $j = $t | ConvertFrom-Json -ErrorAction Stop
                    $out = @()
                    foreach ($item in $j) {
                        if ($null -eq $item) { continue }
                        if ($item -is [string]) { $out += $item; continue }
                        $name = (Get-RowValue -Row $item -Names @("Name","name","DeviceName","deviceName","MachineName","machineName","DnsName","dnsName","Id","id"))
                        if ($name) { $out += $name }
                    }
                    return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
                } catch { }
            }

            $parts = @($t -split '\s*,\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

            $expanded = New-Object System.Collections.Generic.List[string]
            foreach ($p in $parts) {
                if (Test-LooksLikeHost $p) {
                    $expanded.Add($p) | Out-Null
                    continue
                }

                $tokens = @($p -split '\s+' | Where-Object { $_ })
                $hostTokens = @($tokens | Where-Object { Test-LooksLikeHost $_ })

                if ($hostTokens.Count -ge 2) {
                    foreach ($ht in $hostTokens) { $expanded.Add($ht.Trim()) | Out-Null }
                } elseif ($tokens.Count -eq 1) {
                    $expanded.Add($tokens[0].Trim()) | Out-Null
                } else {
                    $expanded.Add($p) | Out-Null
                }
            }

            return @($expanded | Where-Object { $_ } | Select-Object -Unique)
        }

        $colRiskScore = if ($FinalRiskScoreColumnName) { $FinalRiskScoreColumnName } else { "RiskScore" }

        $topRows = @($final | Select-Object -First $TopN)

        $findingLines = @()
        $assetAgg = @{}  # asset -> object

        function Add-AssetAgg {
            param(
                [string]$Asset,
                [double]$RiskScore,
                [string]$TierLevel,
                [string]$Severity,
                [string]$Domain,
                [string]$Category,
                [string]$Subcat,
                [string]$ConfName,
                [string]$ConfId
            )

            if ([string]::IsNullOrWhiteSpace($Asset)) { return }

            if (-not $assetAgg.ContainsKey($Asset)) {
                $assetAgg[$Asset] = [pscustomobject]@{
                    Asset          = $Asset
                    TierLevel      = $TierLevel
                    Findings       = 0
                    RiskScoreTotal = 0.0
                    MaxRiskScore   = 0.0
                    Domains        = New-Object System.Collections.Generic.HashSet[string]
                    TopItems       = New-Object System.Collections.Generic.List[string]
                }
            }

            $o = $assetAgg[$Asset]
            $o.Findings++
            $o.RiskScoreTotal += $RiskScore
            if ($RiskScore -gt $o.MaxRiskScore) { $o.MaxRiskScore = $RiskScore }

            if ($Domain) { [void]$o.Domains.Add($Domain) }

            if ($o.TopItems.Count -lt 12) {
                $o.TopItems.Add(("{0} [{1}] ({2}/{3})" -f $ConfName, $ConfId, $Category, $Subcat))
            }
        }

        $i = 0
        foreach ($r in $topRows) {
            $i++

            $riskScoreText = Get-RowValue -Row $r -Names @($colRiskScore, "RiskScore")
            [double]$riskScore = 0
            [void][double]::TryParse(($riskScoreText -replace ',', '.'), [ref]$riskScore)

            $severity    = Get-RowValue -Row $r -Names @("SecuritySeverity", "Severity", "securityseverity")
            $tierLevel   = Get-RowValue -Row $r -Names @("CriticalityTierLevel", "CriticalityTier", "Tier", "criticalitytierlevel")
            $domain      = Get-RowValue -Row $r -Names @("SecurityDomain", "Domain", "securitydomain")
            $category    = Get-RowValue -Row $r -Names @("Category", "category")
            $subcat      = Get-RowValue -Row $r -Names @("Subcategory", "SubCategory", "subcategory")
            $confName    = Get-RowValue -Row $r -Names @("ConfigurationName", "RecommendationName", "FindingName", "Title", "Name")
            $confId      = Get-RowValue -Row $r -Names @("ConfigurationId", "RecommendationId", "FindingId", "Id")
            $devices     = Get-RowValue -Row $r -Names @("Devices", "DeviceCount", "ImpactedDevices")
            $assetsText  = Get-RowValue -Row $r -Names @("ImpactedAssets", "Assets", "AffectedAssets", "Machines")

            $findingLines += ("[{0}] RiskScore={1}; Tier={2}; Severity={3}; Domain={4}; Config={5} [{6}]; Category={7}/{8}; Devices={9}; ImpactedAssets={10}" -f `
                $i, $riskScoreText, $tierLevel, $severity, $domain, $confName, $confId, $category, $subcat, $devices, $assetsText)

            $assetList = Split-ImpactedAssets -AssetsText $assetsText
            foreach ($a in $assetList) {
                Add-AssetAgg -Asset $a -RiskScore $riskScore -TierLevel $tierLevel -Severity $severity -Domain $domain `
                    -Category $category -Subcat $subcat -ConfName $confName -ConfId $confId
            }
        }

        $findingsText = $findingLines -join "`n"

        # Rank assets: primary by MaxRiskScore, secondary by RiskScoreTotal, then Findings
        $assetRanked = @()
        if ($assetAgg.Count -gt 0) {
            $assetRanked = $assetAgg.Values |
                Sort-Object -Property @{Expression="MaxRiskScore";Descending=$true}, @{Expression="RiskScoreTotal";Descending=$true}, @{Expression="Findings";Descending=$true} |
                Select-Object -First $TopAssetsN
        }

        $assetLines = @()
        $rank = 0
        foreach ($a in $assetRanked) {
            $rank++

            $domainSummary = ""
            if ($a.Domains.Count -gt 0) {
                $domainSummary = (@($a.Domains) | Sort-Object) -join ", "
            }

            $topItems = ""
            if ($a.TopItems.Count -gt 0) {
                $topItems = ($a.TopItems | Select-Object -First 8) -join "; "
            }

            $assetLines += ("{0}. Asset={1}; Tier={2}; Findings={3}; MaxRiskScore={4:N2}; RiskScoreTotal={5:N2}; Domains=[{6}]; TopItems={7}" -f `
                $rank, $a.Asset, $a.TierLevel, $a.Findings, $a.MaxRiskScore, $a.RiskScoreTotal, $domainSummary, $topItems)
        }

        $assetsTextForAI = $assetLines -join "`n"

        $runMeta = @"
ReportTemplate: $ReportTemplate
Final rows:     $(@($final).Count)
Included in AI: $(@($topRows).Count) (TopN findings)
Asset rollup:   $($assetAgg.Keys.Count) unique assets (TopAssetsN=$TopAssetsN included)
RiskScore col:  $colRiskScore
Output file:    $OutputXlsx
Generated:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

        $intro = @"
This summary is generated from Microsoft Defender data to answer one practical question:
what should we fix first, and on which assets, to reduce RiskScore the fastest.

Scope:
- This summary only covers the Top $TopAssetsN highest-risk assets for this run.
- Full evidence and the complete set of findings per asset is in the attached Excel report (Details sheet).
- A separate Summary sheet in the Excel contains the same AI text as this email.

Risk scoring is transparent: Consequence × Probability = RiskScore, based on raw Kusto query outputs and a customizable risk index.
"@

        $userPrompt = @"
$intro

You are a security advisor AI.

You MUST focus on ASSETS and prioritize remediation by RiskScore.
You are given:
A) An asset rollup (already ranked).
B) The top findings (highest RiskScore first) for traceability.

$runMeta

A) Asset rollup:
$assetsTextForAI

B) Top findings:
$findingsText

Return format (STRICT):
1) Top 25 risky assets (one line per asset):
   - <Rank>. <AssetName> | Tier=<Tier> | MaxRiskScore=<Max> | RiskScoreTotal=<Total> | Findings=<Count> | Domains=<Domains>

2) For the Top 10 assets only, include per asset:
   - Asset: <AssetName>
     - Why it is high risk (cite MaxRiskScore + 2-3 TopItems)
     - Top 5 actions to reduce RiskScore FAST (each action MUST reference ConfigName [ConfigId])
       Format each action line as:
       - <Action> | <Why> | <Expected impact> | <References: ConfigName [ConfigId]>
     - Expected overall risk reduction (High/Medium/Low)

3) Cross-asset quick wins (max 8):
   - <Action> [ConfigId] | Affects <N> assets | Example assets: <up to 4>

Rules:
- Do NOT write generic advice. Every action must tie back to ConfigName [ConfigId] and assets.
- Do NOT merge multiple assets into one line. Each line must be one asset.
- Keep the output concise and structured. No long paragraphs.
"@

        Write-Host "`n[AI SUMMARY RESPONSE]`n" -ForegroundColor Cyan

        # capture streamed output
        $sb = New-Object System.Text.StringBuilder

        try {
            $body = @{
                model = $AI_deployment
                stream = $true
                temperature = 0.2
                top_p = 1.0
                max_tokens = 16000
                messages = @(
                    @{
                        role = "system"
                        content = "You are a helpful security advisor. You produce asset-focused prioritization and remediation guidance using the provided Defender-based risk data."
                    },
                    @{
                        role = "user"
                        content = $userPrompt
                    }
                )
            } | ConvertTo-Json -Depth 12 -Compress

            $handler = [System.Net.Http.HttpClientHandler]::new()
            $client  = [System.Net.Http.HttpClient]::new($handler)

            $request = [System.Net.Http.HttpRequestMessage]::new(
                [System.Net.Http.HttpMethod]::Post,
                $AI_uri
            )

            $request.Headers.Add("api-key", $AI_apiKey)
            $request.Headers.Add("Accept", "text/event-stream")
            $request.Content = [System.Net.Http.StringContent]::new(
                $body,
                [System.Text.Encoding]::UTF8,
                "application/json"
            )

            $response = $client.SendAsync(
                $request,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).Result

            if (-not $response.IsSuccessStatusCode) {
                $err = $response.Content.ReadAsStringAsync().Result
                throw "Azure OpenAI returned HTTP $([int]$response.StatusCode): $err"
            }

            $stream = $response.Content.ReadAsStreamAsync().Result
            $reader = [System.IO.StreamReader]::new($stream)

            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($line -and $line.StartsWith("data: ")) {
                    $json = $line.Substring(6)
                    if ($json -eq "[DONE]") { break }

                    try {
                        $obj  = $json | ConvertFrom-Json
                        $text = $obj.choices[0].delta.content
                        if ($text) {
                            [void]$sb.Append($text)
                            Write-Host -NoNewline $text
                        }
                    } catch {
                        Write-Warning "Failed to parse AI chunk: $json"
                    }
                }
            }

            $reader.Close()
            $client.Dispose()

            $AI_SummaryText = ($sb.ToString() -replace "`r`n","`n" -replace "`r","`n").Trim()

            # Write AI summary into Excel Summary sheet
            try {
              Write-Step "writing AI summary to excel sheet 'Summary'"
              Tock
              Export-AISummaryWorksheet -Path $OutputXlsx -SheetName 'Summary' -SummaryText $AI_SummaryText
              Tick "excel summary export"
              Write-Ok "AI summary added to Excel (Summary sheet)"
            } catch {
              Write-Warn2 ("failed to write AI summary to excel: {0}" -f $_.Exception.Message)
            }

        } catch {
            Write-Error "Azure OpenAI request failed: $($_.Exception.Message)"
            if ($reader) { $reader.Close() }
            if ($client) { $client.Dispose() }

            # still try to write a summary sheet with error note
            try {
              $AI_SummaryText = "AI summary failed: $($_.Exception.Message)"
              Export-AISummaryWorksheet -Path $OutputXlsx -SheetName 'Summary' -SummaryText $AI_SummaryText
            } catch { }
        }
    }
}

#####################################################################################################
# SEND OUTPUT VIA MAIL
#####################################################################################################

Write-Section "mail dispatch decision"

if ($Report_SendMail -eq $true) {

    $to          = $Report_To
    $from        = $SMTPUser
    $subject     = "Security Insights | Risk Analysis | $ReportTemplate"
    $attachments = @($OutputXlsx)

    # Decide body content based on AI enablement + actual output
    $aiEnabled = ($PSBoundParameters.ContainsKey('BuildSummaryByAI') -or $BuildSummaryByAI)

    if ($aiEnabled) {

        # HTML-safe AI summary (if AI ran but produced nothing, keep message clear)
        $aiHtml = ""
        if (-not [string]::IsNullOrWhiteSpace($AI_SummaryText)) {
          $aiHtml = ($AI_SummaryText.Trim() -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;")
          $aiHtml = $aiHtml -replace "`r`n","`n" -replace "`r","`n"
          $aiHtml = $aiHtml -replace "`n","<br>"
        } else {
          $aiHtml = "AI summary was enabled, but no AI summary output was produced."
        }

        # Body html WITH AI section + disclaimer
        $bodyHtml = @"
Risk Analysis<br>
<br>
Attached you will find prioritized security risks, ranked by RiskScore.<br>
The Excel file contains full evidence, raw data, and detailed findings per asset (Details sheet).<br>
<br>
AI summary (also included in the Excel Summary sheet):<br>
<br>
$aiHtml
<br>
<br>
---## ---<br>
Security Insight | Risk Analysis | support: Morten Knudsen | mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight.<br>
This summary was generated using AI and may contain mistakes or incomplete conclusions. Please validate critical decisions using the detailed findings and raw data in the attached Excel report.
"@

    } else {

        # Body html WITHOUT AI section (different text)
        $bodyHtml = @"
Risk Analysis<br>
<br>
Attached you will find prioritized security risks, ranked by RiskScore.<br>
The Excel file contains full evidence, raw data, and detailed findings per asset (Details sheet).<br>
<br>
AI summary was not included for this run (BuildSummaryByAI was not enabled).<br>
If you want an AI-based prioritization summary in both the email and the Excel (Summary sheet), run again with -BuildSummaryByAI.<br>
<br>
Security Insight | Risk Analysis | support: Morten Knudsen | mok@mortenknudsen.net | https://github.com/KnudsenMorten/SecurityInsight.<br>
"@
    }

    try {
        if ($Mail_SendAnonymous) {
            Write-Step ("sending mail anonymously to: {0}" -f ($to -join ', '))
            Send-MailAnonymous -SmtpServer $SmtpServer -Port $SMTPPort -UseSsl $SMTP_UseSSL `
                -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            Write-Ok "anonymous mail sent"
        }
        else {
            Write-Step ("sending mail using secure credentials to: {0}" -f ($to -join ', '))
            Send-MailSecure -SmtpServer $SmtpServer -Port $SMTPPort -UseSsl $SMTP_UseSSL `
                -Credential $SecureCredentialsSMTP -From $from -To $to -Subject $subject -BodyHtml $bodyHtml -Attachments $attachments
            Write-Ok "secure mail sent"
        }
    }
    catch {
        Write-Err2 ("mail failed: {0}" -f $_.Exception.Message)
    }
}
else {
    Write-Info "mail flag disabled; not sending"
}

Write-Section "script completed"
