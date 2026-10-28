<#
.SYNOPSIS
    SecurityInsight: give an existing install's directory objects the names people read -- the same names a new install gets.

.DESCRIPTION
    One naming convention for every Invardia product: "a short code in Azure, the full name where people read". Azure cannot
    rename a container app, a job, a managed identity, a SQL server, a Key Vault or a registry, so those keep their names.
    What CAN be renamed is renamed here, and ONLY from SecurityInsight's earlier default name (a name you chose is kept):

      SecurityInsight's engine application        "SecurityInsight"            -> "SecurityInsight Engine"
      the web app's sign-in application           "SecurityInsight Management" -> "SecurityInsight"
      the SQL admin group (display name only)     "grp-si-sql-admins"          -> "SecurityInsight SQL admins"

    Each is found by its id -- the sign-in application by the client id the web app signs in with, the engine's by
    -EngineAppId, the group as the SQL server's Entra admin -- never by its name. The engine's application is renamed first:
    while another application is still named "SecurityInsight" the sign-in application is not renamed (one line says which).
    Every rename is read back; one that does not read back is put back to the earlier name. The app registration and its
    enterprise application are renamed together. The group's mailNickname, the mail sender's address and display name and the
    Exchange scope are never changed.

    The product's update does the same on every install (SI_Update_RenameDisplayNames, ON by default); its identity usually may
    not change an application or a role-assignable group, and then it names this script.

    Plan by default (one line per change); -Apply renames; -WhatIf is the plan, whatever else is given.

    RIGHTS. The applications: an owner of each, or Application Administrator / Cloud Application Administrator (or Microsoft
    Graph Application.ReadWrite.All for an app). The group is role-assignable: Privileged Role Administrator (or Graph
    Group.ReadWrite.All with RoleManagement.ReadWrite.Directory for an app). Reading the web app and the SQL server: Reader
    on the resource group.

.EXAMPLE
    .\Set-SIDisplayNames.ps1 -ResourceGroupName rg-si-prod-pro-ca -SubscriptionId <sub>
.EXAMPLE
    .\Set-SIDisplayNames.ps1 -ResourceGroupName rg-si-prod-pro-ca -SubscriptionId <sub> -EngineAppId <engine client id> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SIDisplayNames/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [string]$SubscriptionId,
    # the web app's sign-in application (client id); empty = read from the web app in the resource group
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')][string]$WebAppId = '',
    # SecurityInsight's engine application (client id, SI_SPN_AppId in the install's config); empty = not renamed
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')][string]$EngineAppId = '',
    # the Pro SQL server; empty = the only sql-si-* server in the resource group
    [string]$SqlServerName = '',
    [switch]$Apply
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SIDisplayNames' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: nothing is renamed
try {
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-DisplayNames.ps1'))
. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-InstallNames.ps1'))
# Azure over native REST, no PowerShell module. An existing sign-in in this process is reused; otherwise a person signs in.
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
if (-not (Get-Command -Name Invoke-SIRestMethod -ErrorAction SilentlyContinue)) {
    & { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-AzRest.ps1')) }
}
$azCtx = Get-SISetupAzureContext
if (-not $azCtx) { $azCtx = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
if (-not $SubscriptionId) { $SubscriptionId = [string]$azCtx.Subscription.Id }
$hdr = @{ Authorization = 'Bearer ' + [string](Get-SIAzureToken -Audience Graph) }
$graph = {
    param([string]$Method, [string]$Uri, $Body)
    $a = @{ Method = $Method; Uri = $Uri; Headers = $hdr }
    if ($null -ne $Body) { $a.ContentType = 'application/json'; $a.Body = $(if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Compress -Depth 5 }) }
    Invoke-SIRestMethod @a   # through the support recorder in a support session
}
$arm = {
    param([string]$Path)
    $r = $null; try { $r = Invoke-SIAzRestMethod -Method GET -Path $Path } catch { return $null }
    if (-not $r -or [int]$r.StatusCode -ge 300 -or -not "$($r.Content)".Trim()) { return $null }
    $r.Content | ConvertFrom-Json
}
$rgPath = '/subscriptions/{0}/resourceGroups/{1}/providers' -f $SubscriptionId, $ResourceGroupName
Write-Host ("SecurityInsight -- the names people read, in {0}{1}" -f $ResourceGroupName, $(if ($Apply) { '' } else { ' -- plan only (add -Apply)' }))

# the web app's sign-in application: the client id the web app signs in with
if (-not $WebAppId) {
    foreach ($wn in @(@(Get-SIInstallNameCandidates -Role web) + @('ca-si-web') | Select-Object -Unique)) {
        $app = & $arm ('{0}/Microsoft.App/containerApps/{1}?api-version=2024-03-01' -f $rgPath, $wn)
        if (-not $app) { continue }
        foreach ($c in @($app.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq 'AzureAd__ClientId' -and [string]$e.value -match '^[0-9a-fA-F-]{36}$') { $WebAppId = [string]$e.value } } }
        if ($WebAppId) { Write-Host ('  the web app {0} signs in with the application {1}' -f $wn, $WebAppId); break }
    }
    if (-not $WebAppId) { Write-Host '  no web app found in the resource group (or it cannot be read) -- the sign-in application is not looked at; name it with -WebAppId' -ForegroundColor DarkGray }
}
# the SQL admin group: the Pro SQL server's Entra admin
$adminSid = ''
if (-not $SqlServerName) {
    $list = & $arm ('{0}/Microsoft.Sql/servers?api-version=2021-11-01' -f $rgPath)
    $si = @(@($(if ($list) { $list.value })) | Where-Object { $_ -and [string]$_.name -match '^sql-si-' })
    if ($si.Count -eq 1) { $SqlServerName = [string]$si[0].name }
    elseif ($si.Count -gt 1) { Write-Host ('  {0} SecurityInsight SQL servers in the resource group -- name one with -SqlServerName' -f $si.Count) -ForegroundColor Yellow }
}
if ($SqlServerName) {
    $srv = & $arm ('{0}/Microsoft.Sql/servers/{1}?api-version=2021-11-01' -f $rgPath, $SqlServerName)
    if ($srv -and $srv.properties -and $srv.properties.PSObject.Properties['administrators'] -and $srv.properties.administrators) { $adminSid = [string]$srv.properties.administrators.sid }
    if (-not $adminSid) { Write-Host ('  the SQL server {0} has no Entra admin that could be read -- the admin group is not looked at' -f $SqlServerName) -ForegroundColor DarkGray }
}

$plan = @(Get-SIDisplayNamePlan -Graph $graph -WebAppId $WebAppId -EngineAppId $EngineAppId -SqlAdminSid $adminSid)
if (-not $plan.Count) { Write-Host '  nothing to look at.'; return }
foreach ($it in @($plan | Where-Object { $_.Action -ne 'rename' })) { Write-Host ('  [{0,-9}] {1}' -f $it.Action, $it.Line) }
$r = Invoke-SIDisplayNameRenames -Graph $graph -Plan $plan -Apply:$Apply -SetupCommand ('.\setup\Set-SIDisplayNames.ps1 -ResourceGroupName {0} -SubscriptionId {1} -Apply (signed in with the rights named above)' -f $ResourceGroupName, $SubscriptionId)
foreach ($it in @($r.Items | Where-Object { $_.Action -eq 'rename' })) {
    Write-Host ('  [{0,-9}] {1}' -f $it.State, $it.Line) -ForegroundColor $(if ($it.State -in 'renamed', 'planned') { 'Green' } else { 'Yellow' })
}
if ($Apply -and $r.Renamed) { Write-Host ('  {0} renamed. The product''s update sees the new names on its next run and leaves them.' -f $r.Renamed) }
if (@($r.Items | Where-Object { $_.State -in 'failed', 'put-back-failed', 'no-rights' }).Count) { throw 'not every display name was renamed -- see the lines above.' }
} finally { Stop-SIScriptRun -Run $siRun }
