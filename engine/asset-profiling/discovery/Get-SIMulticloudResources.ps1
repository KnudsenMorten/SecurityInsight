#Requires -Version 5.1
<#
    Get-SIMulticloudResources -- resources in AWS and GCP, as Defender for Cloud's multicloud connectors report them, as
    provider RECORDS (REQUIREMENTS #500): provider mdc, record type multicloud_resource, class cloud_resource
    (data-model/mappings/mdc.locked.json) -> one cloud_resource CI per resource.

    WHAT. Defender for Cloud assesses the AWS accounts / GCP projects a connector covers and lists every assessed
    resource in Azure Resource Graph (securityresources, microsoft.security/assessments, resourceDetails.Source = Aws |
    Gcp). ONE query, summarised per resource INSIDE the query (the same summary as the Azure resources' assessments,
    Get-SIMdcAssessmentSummary): the resource's details (native id -- the AWS ARN / GCP resource name --, cloud, name,
    type, region, account / project, connector) and its assessments (counts per severity, oldest / newest, the top
    unhealthy ones). Paged to the end and sorted; each page becomes record parts and is let go.

    The record's key is Defender for Cloud's own id of the resource (resourceDetails.Id), the id its recommendations
    carry -- so the Defender for Cloud recommendation report finds the resource's CI by it (the FINDINGS arrive through
    Risk Analysis, #494). mdc_native_resource_id (strong) joins the same resource seen by another source.

    SOURCE NOT PRESENT. First the connectors (resources, microsoft.security/securityconnectors, environment AWS / GCP).
    None = the tenant has no multicloud source: said in one line, nothing read, nothing removed, never a failure.
    COMPLETENESS. A read that does not finish marks the Defender for Cloud pull not complete (working rule 4).
    READ ONLY (Resource Graph, the Reader access the Azure collector already holds). Never throws. PowerShell 7, REST only.
#>

if (-not (Get-Command -Name Invoke-SIArgPaged -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1') }
if (-not (Get-Command -Name ConvertTo-SIMdcAssessmentObjects -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIMdcAssessmentSummary.ps1') }

$script:SIMulticloudClouds = @('aws', 'gcp')

function Get-SIMulticloudConnectorKql {
    <# PURE. The multicloud connectors (AWS / GCP) of Defender for Cloud. #>
    @"
resources
| where type =~ 'microsoft.security/securityconnectors'
| extend cloud = tostring(properties.environmentName)
| where cloud in~ ('AWS', 'GCP')
| project id = tolower(id), name, cloud, hierarchy = tostring(properties.hierarchyIdentifier)
| order by id asc
"@
}

function Get-SIMulticloudResourceKql {
    <#
        PURE. One row per AWS / GCP resource Defender for Cloud assessed: its details and the assessment summary (the
        columns ConvertTo-SIMdcAssessmentObjects reads). The resourceDetails paths of a multicloud assessment differ by
        connector generation; each detail takes the first that has a value (to be confirmed on live rows).
    #>
    param([int]$Top = $script:SIMdcAssessmentTop)
    if ($Top -lt 1) { $Top = 1 }
    @"
securityresources
| where type =~ 'microsoft.security/assessments'
| extend _rd = properties.resourceDetails
| extend Cloud = tostring(_rd.Source)
| where Cloud in~ ('Aws', 'Gcp')
| extend ResourceId = tolower(tostring(_rd.Id)), Status = tostring(properties.status.code), Severity = tostring(properties.metadata.severity),
         AssessmentName = tostring(properties.displayName), AssessmentKey = tolower(name),
         FirstEvaluated = todatetime(properties.status.firstEvaluationDate), StatusChanged = todatetime(properties.status.statusChangeDate),
         NativeId = coalesce(tostring(_rd.NativeResourceId), tostring(_rd.ResourceArn), tostring(_rd.AwsResourceArn), tostring(_rd.GcpResourceName)),
         ResName = coalesce(tostring(_rd.ResourceName), tostring(_rd.Name)),
         ResType = iff(isnotempty(tostring(_rd.ResourceProvider)) and isnotempty(tostring(_rd.ResourceType)), strcat(tostring(_rd.ResourceProvider), '.', tostring(_rd.ResourceType)), tostring(_rd.ResourceType)),
         Region = coalesce(tostring(_rd.Region), tostring(_rd.Location)),
         Account = coalesce(tostring(_rd.HierarchyId), tostring(_rd.AwsAccountId), tostring(_rd.AccountId), tostring(_rd.GcpProjectId), tostring(_rd.ProjectId)),
         ConnectorId = tolower(coalesce(tostring(_rd.ConnectorId), extract(@'(?i)(.*/providers/microsoft\.security/securityconnectors/[^/]+)', 1, tostring(_rd.Id))))
| where isnotempty(ResourceId)
| extend Bad = (Status =~ 'Unhealthy'), Item = pack('id', AssessmentKey, 'name', AssessmentName, 'severity', Severity)
| summarize Cloud = take_any(Cloud), NativeId = take_anyif(NativeId, isnotempty(NativeId)), ResName = take_anyif(ResName, isnotempty(ResName)),
            ResType = take_anyif(ResType, isnotempty(ResType)), Region = take_anyif(Region, isnotempty(Region)), Account = take_anyif(Account, isnotempty(Account)),
            ConnectorId = take_anyif(ConnectorId, isnotempty(ConnectorId)),
            Assessed = count(), Unhealthy = countif(Bad), High = countif(Bad and Severity =~ 'High'), Medium = countif(Bad and Severity =~ 'Medium'), Low = countif(Bad and Severity =~ 'Low'),
            OldestUnhealthy = minif(FirstEvaluated, Bad), NewestChange = maxif(StatusChanged, Bad),
            TopHigh = make_list_if(Item, Bad and Severity =~ 'High', $Top), TopMedium = make_list_if(Item, Bad and Severity =~ 'Medium', $Top),
            TopLow = make_list_if(Item, Bad and not(Severity =~ 'High') and not(Severity =~ 'Medium'), $Top) by ResourceId
| order by ResourceId asc
"@
}

function ConvertTo-SIMulticloudObjects {
    <#
    .SYNOPSIS  PURE. Resource Graph rows -> one object per resource: @{ resourceId; Resource = the 'resource' part;
               Assessments = the 'assessments' part ($null when nothing was assessed) }. -Connectors: connector id -> name.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Connectors = @{})
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $id = ([string]$r.ResourceId).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $g = { param($n) $p = $r.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { ([string]$p.Value).Trim() } else { '' } }
        $cloud = (& $g 'Cloud').ToUpperInvariant()
        if ($cloud -notin 'AWS', 'GCP') { continue }
        $res = [ordered]@{ resourceId = $id; cloud = $cloud }
        $native = & $g 'NativeId'; if ($native) { $res['nativeId'] = $native.ToLowerInvariant() }
        foreach ($pair in @(@('name', 'ResName'), @('type', 'ResType'), @('region', 'Region'), @('account', 'Account'))) { $v = & $g $pair[1]; if ($v) { $res[$pair[0]] = $v } }
        $cid = (& $g 'ConnectorId').ToLowerInvariant()
        if ($cid) {
            $cname = ''
            if ($Connectors.ContainsKey($cid)) { $cname = [string]$Connectors[$cid] }
            elseif ($cid -match '/securityconnectors/([^/]+)$') { $cname = $matches[1] }
            if ($cname) { $res['connector'] = $cname }
        }
        $sum = @(ConvertTo-SIMdcAssessmentObjects -Rows @($r))
        $ass = $null; if ($sum.Count -gt 0) { $ass = $sum[0].Assessments }
        $out.Add([pscustomobject]@{ resourceId = $id; Resource = [pscustomobject]$res; Assessments = $ass })
    }
    return , $out.ToArray()
}

function Invoke-SIMulticloudCapture {
    <#
    .SYNOPSIS  Reads the AWS / GCP resources Defender for Cloud reports and hands each to the record capture (provider
               mdc, record type multicloud_resource, parts 'resource' and 'assessments'). Returns @{ Present; Connectors;
               Resources; Complete; Text }. Never throws.
    .PARAMETER Query  test seam: { param($Kql) } -> rows (the whole answer) for both queries.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query)
    $out = @{ Present = $false; Connectors = 0; Resources = 0; Complete = $true; Text = '' }
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { $out.Text = 'Other clouds (AWS / GCP): the record capture is not loaded -- nothing read.'; return $out }
    # 1. the connectors -- none: the source is not present (never a failure, nothing removed)
    $conn = @{}
    try {
        $kql = Get-SIMulticloudConnectorKql
        $rows = @()
        if ($Query) { $rows = @(& $Query $kql) }
        else {
            $page = Invoke-SIArgPaged -Query $kql -SourceLabel 'Defender for Cloud multicloud connectors' -SubscriptionIds $SubscriptionIds -WarningAction SilentlyContinue
            if (-not [bool]$page.Complete) { throw [string]$page.Error }
            $rows = @($page.Rows)
        }
        foreach ($c in $rows) { $cid = ([string]$c.id).Trim().ToLowerInvariant(); if ($cid) { $conn[$cid] = [string]$c.name } }
    } catch {
        $out.Complete = $false
        $out.Text = ('Other clouds (AWS / GCP): the Defender for Cloud connectors could not be read ({0}) -- their resources are UNKNOWN this run, not removed.' -f $_.Exception.Message)
        if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'mdc' -Complete $false -ErrorText ('multicloud connectors: ' + $_.Exception.Message) }
        return $out
    }
    $out.Connectors = $conn.Count
    if ($conn.Count -eq 0) {
        $out.Text = 'Other clouds (AWS / GCP): Defender for Cloud has no AWS or GCP connector on this tenant -- the source is not present (nothing read, nothing removed).'
        return $out
    }
    $out.Present = $true
    # 2. the resources, page by page
    $script:SIMulticloudTaken = 0
    $take = {
        param($Rows)
        foreach ($o in (ConvertTo-SIMulticloudObjects -Rows @($Rows) -Connectors $conn)) {
            try {
                Add-SIRecordPart -Provider 'mdc' -RecordType 'multicloud_resource' -Key $o.resourceId -Part 'resource' -Object $o.Resource
                if ($null -ne $o.Assessments) { Add-SIRecordPart -Provider 'mdc' -RecordType 'multicloud_resource' -Key $o.resourceId -Part 'assessments' -Object $o.Assessments }
                $script:SIMulticloudTaken++
            } catch { }
        }
    }
    $err = ''
    try {
        $kql = Get-SIMulticloudResourceKql
        if ($Query) { $null = & $take @(& $Query $kql) }
        else {
            $page = Invoke-SIArgPaged -Query $kql -SourceLabel 'Defender for Cloud AWS / GCP resources' -SubscriptionIds $SubscriptionIds -OnPage $take -WarningAction SilentlyContinue
            if (-not [bool]$page.Complete) { $out.Complete = $false; $err = [string]$page.Error }
        }
    } catch { $out.Complete = $false; $err = [string]$_.Exception.Message }
    $out.Resources = [int]$script:SIMulticloudTaken
    if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'mdc' -Complete ([bool]$out.Complete) -ErrorText $(if ($err) { 'multicloud resources: ' + $err } else { '' }) }
    if ($out.Complete) { $out.Text = ('Other clouds (AWS / GCP): {0} resource(s) from {1} Defender for Cloud connector(s)' -f $out.Resources, $out.Connectors) }
    else { $out.Text = ('Other clouds (AWS / GCP): {0} resource(s) from {1} connector(s); the read did not finish ({2}) -- the resources not read are UNKNOWN this run, not removed.' -f $out.Resources, $out.Connectors, $err) }
    $out
}
