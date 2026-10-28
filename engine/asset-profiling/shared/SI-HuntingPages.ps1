#Requires -Version 5.1
<#
    Read-SIHuntingPages -- a Defender advanced hunting read for MANY devices, one query per PAGE of ids (never one query
    for every device: the scale target is 500,000 devices, and one failed query used to lose the data of all of them).

      every page   asked through the product's hunting request (Invoke-SIHuntingQueryResult: throttled / busy / 5xx / no
                   answer asked again with a growing wait, an expired token renewed, a cut answer read whole in parts;
                   a refused query -- 400 -- never asked again)
      a page that  still failed is asked ONCE more at the END, after every other page (the service has had the time of the
                   whole read to recover); a refused query is not
      the result   @{ Rows; ReadIds; Pages; Failed } -- ReadIds holds only the ids of pages that were READ. A page that
                   failed is in Failed (@{ Count; Error; Defect }) for the caller to SAY; its devices are unknown this
                   run and keep what they had, never written as "nothing found".

    -Kql { param([string[]]$Ids) } -> the query of one page ('' = nothing to ask). -Query { param($Kql) rows } is the test
    seam (it throws like a failed call). -OnRows { param($Rows) }: each page's rows handed over and let go instead of
    kept (a long per-device answer, e.g. the software inventory). Never throws. PowerShell 5.1 / 7, REST only.
#>

function Read-SIHuntingPages {
    param([AllowNull()][AllowEmptyCollection()][string[]]$Ids, [Parameter(Mandatory)][scriptblock]$Kql, [scriptblock]$Query,
          [int]$PageSize = 1000, [scriptblock]$OnRows)
    # 🪤 the variables here carry a __pg prefix: the caller's -Kql / -OnRows blocks run INSIDE this function and read their
    # own caller's variables by name (e.g. a $res counter) -- a plain name here would shadow them
    $__pgOut = [pscustomobject]@{
        Rows    = [System.Collections.ArrayList]::new()
        ReadIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Pages   = 0
        Failed  = [System.Collections.ArrayList]::new()
    }
    $__pgAll = @($Ids | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($__pgAll.Count -eq 0) { return $__pgOut }
    if ($PageSize -lt 1) { $PageSize = 1 }
    if (-not $Query -and -not (Get-Command -Name Invoke-SIHuntingQueryResult -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'HuntingQuery.ps1') }
    $__pgAsk = {
        param([string]$__pgQ)
        if (-not $Query) { return (Invoke-SIHuntingQueryResult -Query $__pgQ) }
        try { [pscustomobject]@{ Ok = $true; Rows = @(& $Query $__pgQ); Error = ''; Defect = $false } }
        catch {
            $__pgM = $_.Exception.Message; if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $__pgM = $_.ErrorDetails.Message }
            $__pgD = if (Get-Command -Name Test-SIHuntingQueryDefect -ErrorAction SilentlyContinue) { Test-SIHuntingQueryDefect -Message $__pgM } else { [bool]($__pgM -match '(?i)semantic error|syntax error|Failed to resolve|BadRequest|\(400\)') }
            [pscustomobject]@{ Ok = $false; Rows = @(); Error = $__pgM; Defect = $__pgD }
        }
    }
    $__pgTake = {
        param($__pgPage, $__pgR)
        if ($OnRows) { & $OnRows @($__pgR.Rows) } else { foreach ($__pgRow in @($__pgR.Rows)) { if ($null -ne $__pgRow) { [void]$__pgOut.Rows.Add($__pgRow) } } }
        foreach ($__pgId in $__pgPage) { [void]$__pgOut.ReadIds.Add($__pgId) }
    }
    $__pgAgain = New-Object System.Collections.Generic.List[object]
    for ($__pgI = 0; $__pgI -lt $__pgAll.Count; $__pgI += $PageSize) {
        $__pgPage = @($__pgAll[$__pgI..([Math]::Min($__pgI + $PageSize, $__pgAll.Count) - 1)])
        $__pgQ = [string](& $Kql $__pgPage)
        if (-not $__pgQ) { continue }
        $__pgOut.Pages++
        $__pgR = & $__pgAsk $__pgQ
        if ($__pgR.Ok) { & $__pgTake $__pgPage $__pgR; continue }
        $__pgAgain.Add([pscustomobject]@{ Page = $__pgPage; Kql = $__pgQ; Error = [string]$__pgR.Error; Defect = [bool]$__pgR.Defect })
    }
    # the last try of every failed page, after all the others -- a refused query is not asked again (same answer)
    foreach ($__pgP in $__pgAgain) {
        if (-not $__pgP.Defect) {
            $__pgR = & $__pgAsk $__pgP.Kql
            if ($__pgR.Ok) { & $__pgTake $__pgP.Page $__pgR; continue }
            $__pgP.Error = [string]$__pgR.Error; $__pgP.Defect = [bool]$__pgR.Defect
        }
        [void]$__pgOut.Failed.Add([pscustomobject]@{ Count = @($__pgP.Page).Count; Error = $__pgP.Error; Defect = $__pgP.Defect })
    }
    $__pgOut
}

function Get-SIHuntingFailureKind {
    <# PURE. The words for a failed page: a refused query must be fixed; anything else is a read that failed. #>
    param($Failure)
    if ($Failure.Defect) { return 'the query was refused and must be fixed (running it again gives the same answer)' }
    'the read failed after it was asked again'
}
