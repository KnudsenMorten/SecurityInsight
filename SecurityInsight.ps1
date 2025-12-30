param(
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string] $ReportTemplate,

  [Parameter(Mandatory=$false)]
  [switch] $Detailed,

  [Parameter(Mandatory=$false)]
  [switch] $Summary,

  [Parameter(Mandatory=$false)]
  [switch] $AutomationFramework
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

$AutomationFramework = $false    # Must be set fo $false when you test this out ! Solution can also be integrated with Morten Knudsen's automation framework !

If (!($AutomationFramework)) {

    <# PRE-REQ: ONBOARDING OF SERVICE PRINCIPAL IN ENTRA
        # SPN Privilege (API permissions) - found under 'APIs my organization uses'. Remember: Grant Admin Control
            Microsoft Threat Protection
                AdvancedHunting.Read.All   (to run queries against Exposure Graph)

            Microsoft Graph
                ThreatHunting.Read.All     (to run queries against Exposure Graph)

            WindowsDefenderATP
                Machine.ReadWrite.All      (to set tag info on device)
    #>

    $SettingsPath               = "c:\scripts\securityinsights"
    $DefaultReportTemplate      = "RiskAnalysis_Summary_v2"

    $OverwriteXlsx              = $true      # Overwrite existing Excel file if true

    $global:SpnTenantId         = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId         = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret     = "<CLIENT SECRET VALUE>"

    # Email Notifications
    $SMTPFrom                   = "<SMTP from address>"
    $SmtpServer                 = "<SMTP server>"
    $SMTPPort                   = 587        # or 587 / 465
    $SMTP_UseSSL                = $true    # or $false

    $Report_SendMail_Detailed   = $true
    $Report_To_Detailed         = @("<email address>")

    $Report_SendMail_Summary    = $true
    $Report_To_Summary          = @("<email address>")

    $Mail_SendAnonymous         = $false

    # Consider to use an Azure Keyvault and retrieve credentials from there !
    $SmtpUsername               = "<SMTP username>"
    $SmtpPassword               = "<SMTP password>"

    $SecurePassword = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
    $SecureCredentialsSMTP = New-Object System.Management.Automation.PSCredential (
        $SmtpUsername,
        $SecurePassword
    )
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

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Step ("Installing module $($Name)...")
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    Write-Done ("Installed module $($Name).")
  }
  Import-Module $Name -ErrorAction Stop
  Write-Info ("Imported module $($Name).")
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

    # Normalize Rows to a safe array (never null)
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

        # Clone original row properties to ordered hashtable
        $tmp = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $tmp[$p.Name] = $p.Value }

        # Write computed fields
        $tmp[$SecurityDomainInputName]        = $domainValue
        $tmp[$RiskConsequenceScoreOutputName] = [double]$consAdj
        $tmp[$RiskProbabilityScoreOutputName] = [double]$probAdj
        $tmp[$RiskScoreOutputName]            = [double]$risk

        # Also expose normalized risk factors with consistent names
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

    # ---- FIX: finalize output safely in PS 5.1 (no @($out) casting) ----
    $finalOut = $null
    try {
        $finalOut = [object[]]$out.ToArray()
    } catch {
        # fallback (very defensive)
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

  # Always return an array
  if ($null -eq $InputObject -or $InputObject.Count -eq 0) { return @() }
  if ($null -eq $InScopeData -or $InScopeData.Count -eq 0) { return @($InputObject) }  # no scope -> pass-through

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

    # ---- FIX: if column missing on object, KEEP the object (avoid filtering-to-zero on mismatch) ----
    if (-not ($obj.PSObject.Properties.Name -contains $ColumnToFilter)) {
      $out.Add($obj) | Out-Null
      continue
    }
    # --------------------------------------------------------------------------------------------

    $val = $obj.$ColumnToFilter

    # Build candidate list
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


#####################################################################################################
# POWERSHEL MODULE VALIDATION
#####################################################################################################

Write-Step "initializing"

Ensure-Module Az.Accounts
Ensure-Module Az.ResourceGraph
Ensure-Module Az.Resources
Ensure-Module Microsoft.Graph.Authentication
Ensure-Module Microsoft.Graph.Security
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

    $DefaultReportTemplate = "RiskAnalysis_Summary_v2"

    # If cmdline -ReportTemplate is provided, it wins. Otherwise use the internal default.
    if (-not [string]::IsNullOrWhiteSpace($ReportTemplate)) {
      Write-Info "ReportTemplate override from command line: $ReportTemplate"
    } else {
      $ReportTemplate = $DefaultReportTemplate
      Write-Info "ReportTemplate not provided on command line. Using default: $ReportTemplate"
    }

    Write-Info "Chosen ReportTemplate: $ReportTemplate"

    $OutputXlsx     = "$global:PathScripts\OUTPUT\$ReportTemplate.xlsx"
    $OverwriteXlsx  = $true      # Overwrite existing Excel file if true

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

    $SettingsPath           = "$($global:PathScripts)\SecurityInsights"
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

    # If cmdline -ReportTemplate is provided, it wins. Otherwise use the internal default.
    if (-not [string]::IsNullOrWhiteSpace($ReportTemplate)) {
      Write-Info "ReportTemplate override from command line: $ReportTemplate"
    } else {
      $ReportTemplate = $DefaultReportTemplate
      Write-Info "ReportTemplate not provided on command line. Using default: $ReportTemplate"
    }

    Write-Info "Chosen ReportTemplate: $ReportTemplate"


    #------------------------------------------------------------------------------------------------------------
    # Mail routing (Summary vs Detailed)
    #------------------------------------------------------------------------------------------------------------

    if ($Detailed -and $Summary) {
      throw "Invalid parameters: Use only one of -Detailed or -Summary."
    }

    if ($Detailed) {
      Write-Info "Mail mode selected: Detailed"
      $Report_SendMail = $Report_SendMail_Detailed
      $Report_To       = $Report_To_Detailed
    }
    elseif ($Summary) {
      Write-Info "Mail mode selected: Summary"
      $Report_SendMail = $Report_SendMail_Summary
      $Report_To       = $Report_To_Summary
    }
    else {
      # Default behavior (keep what you want as default)
      Write-Info "Mail mode selected: Default (no -Detailed/-Summary provided)"
      $Report_SendMail = $Report_SendMail_Detailed
      $Report_To       = $Report_To_Detailed
    }

    Write-Info ("Mail routing: Report_SendMail={0}, Report_To={1}" -f $Report_SendMail, ($Report_To -join ', '))

    #------------------------------------------------------------------------------------------------------------
    # ExposureInsight settings
    #------------------------------------------------------------------------------------------------------------

    $OutputXlsx             = $SettingsPath + "\" + "$ReportTemplate.xlsx"

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
    Export-Worksheet -Path $OutputXlsx -SheetName 'RiskAnalysis' `
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

#####################################################################################################
# SEND OUTPUT VIA MAIL
#####################################################################################################

Write-Section "mail dispatch decision"

if ($Report_SendMail -eq $true) {

    $to          = $Report_To
    $from        = $SMTPFrom
    $subject     = "Risk Analysis | $ReportTemplate"
    $bodyHtml    = "<font color=red>Risk Analysis</font><br><br>Attached you will find priotized security risks, based on risk score<br><br>"
    $attachments = @($OutputXlsx)

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
