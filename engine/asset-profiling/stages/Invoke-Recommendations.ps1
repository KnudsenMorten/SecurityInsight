#Requires -Version 5.1
<#
    Stage Recommendations (azure engine only) -- publish every Defender for Cloud recommendation to
    SI_AzureRecommendation_CL (#147). Runs LAST, after the profile rows have landed, so a problem here can
    never cost the profile output.

    * Resource Graph not readable to the end -> NOTHING is published and a loud warning says the previous
      snapshot stays the latest. A shorter list would read as "fixed" (working rule 4).
    * Publishing fails -> the stage throws: the recommendations ARE this stage's output.
    * Opt out with $global:SI_CollectDefenderRecommendations = $false.
#>

function Invoke-SIRecommendations {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$RunContext)

    if ($RunContext.Engine -ne 'azure') {
        return [pscustomobject]@{ Summary = 'n/a for this engine'; Published = 0 }
    }
    if ($global:SI_CollectDefenderRecommendations -eq $false) {
        return [pscustomobject]@{ Summary = 'Defender for Cloud recommendations: turned off (SI_CollectDefenderRecommendations = $false)'; Published = 0 }
    }

    $discoveryRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery'
    . (Join-Path $discoveryRoot 'Invoke-SIArgPaged.ps1')
    . (Join-Path $discoveryRoot 'Get-SIDefenderRecommendations.ps1')
    # The generic publisher lives in engine/_shared: the correlation engine is Pro and absent from the
    # Community edition, so this free stage must never load a file from its folder.
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-LogIngest.ps1')

    # Azure child resources (a VM extension, a disk, a SQL database ...) roll up into their parent: one row per parent and
    # recommendation, the children listed (data-model collection-scope; never a row -- or a CI -- of their own)
    $azScope = $null; $childParents = @{}
    try {
        if (-not (Get-Command -Name Get-SIAzureCiScope -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\SI-AzureChildren.ps1') }
        $azScope = Get-SIAzureCiScope
        $childParents = Get-SIRecordChildParentMap
    } catch { Write-Warning ('Defender for Cloud recommendations: Azure child resources are not rolled up into their parent this run -- {0}' -f $_.Exception.Message) }

    $ct = [datetime]$RunContext.CollectionTime
    $res = Get-SIDefenderRecommendations -CollectionTime $ct -RunId ([string]$RunContext.RunId) -Scope $azScope -ChildParents $childParents

    if (-not $res.Complete) {
        Write-Warning ("Defender for Cloud recommendations: Resource Graph could not be read to the end ({0} assessment(s) retrieved before it failed). NOTHING was published -- the previous complete snapshot stays the latest, because a shorter list would read as recommendations that were fixed. {1}" -f $res.RawCount, $res.Error)
        return [pscustomobject]@{ Summary = ('INCOMPLETE -- not published ({0} read before failure)' -f $res.RawCount); Published = 0 }
    }
    $rows = @($res.Rows)
    if ($rows.Count -eq 0) {
        return [pscustomobject]@{ Summary = 'Defender for Cloud: 0 unhealthy recommendations -- nothing to publish'; Published = 0 }
    }

    if ([bool]$RunContext.WhatIf) {
        return [pscustomobject]@{ Summary = ('dry run: {0} Defender for Cloud row(s) found, not published' -f $rows.Count); Published = 0 }
    }
    $table = if ($global:SI_AzureRecommendation_TableName) { [string]$global:SI_AzureRecommendation_TableName } else { 'SI_AzureRecommendation' }
    $dcr   = if ($global:SI_AzureRecommendation_DcrName)   { [string]$global:SI_AzureRecommendation_DcrName }   else { 'dcr-si-azure-recommendation' }
    $posted = Send-SIObjectMapRows -Rows $rows -TableName $table -DcrName $dcr

    $byKind = @($rows | Group-Object RowKind | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ' '
    $entities = (@($rows | Where-Object { $_.RowKind -eq 'RolledUpEntities' }) | Measure-Object AffectedEntityCount -Sum).Sum
    [pscustomobject]@{
        Summary   = ('Defender for Cloud: {0} unhealthy assessment(s) -> {1} row(s) [{2}] ({3} container-image / cloud-posture entities and Azure child resources rolled up; {5} finding(s) listed on their recommendation) -> {4}_CL' -f $res.RawCount, $posted, $byKind, [int]$entities, $table, [int]$res.SubCount)
        Published = $posted
    }
}
