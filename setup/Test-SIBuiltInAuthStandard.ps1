<#
.SYNOPSIS
    SecurityInsight (container install) -- READ ONLY: is this install's sign-in exactly the ONE standard of Microsoft's
    built-in sign-in, with no leftovers of the sign-in front? One line per install: OK, or every difference named.

.DESCRIPTION
    Invardia's daily second check of the built-in sign-in (framework SECURE-WEB-1 "one standard + no leftovers"). It reads,
    and never writes:
      * EVERY container app of the resource group with an external ingress (not only the two below by name): no
        authConfig, platform off or AllowAnonymous is flagged; an API-only app wants Return401. The only way out is a named
        exception with a reason ($script:SIBuiltInAuthPublicExceptions in setup\_shared\SI-BuiltInAuthStandard.ps1, kept empty);
      * the web app (ca-si-management): its own container only, SI_Web_BuiltInAuth=1, the ingress on 8080, the container-app
        secret override-use-mi-fic-assertion-client-id; its authConfig: platform on, RedirectToLoginPage, the sign-in app
        registration of AzureAd__ClientId, the v2.0 issuer, both audiences, prompt=select_account, the token store in
        si-auth-tokens reached with id-si-web, a FixedTime 08:00:00 session, HTTPS only;
      * the MCP app (ca-si-mcp): Return401 (bearer tokens only), the same app registration, both audiences, no sign-in, no
        token store, no secret setting, no open path but /healthz;
      * the sign-in app registration: ID tokens ON, access tokens OFF, the web app's callback, a federated credential for
        id-si-web;
      * id-si-web and id-si-mcp: no Key Vault role and none of the roles an internet-facing identity may not hold
        (setup\_shared\SI-WebJobRights.ps1's list), anywhere in the subscription;
      * the LEFTOVERS of the sign-in front era: its settings on the web container, era secrets, redirect URIs other than the
        built-in sign-in's callback, client secrets / certificates on the app registration, signin-front images still
        stored in the install's registry.
    The rules are the update's own (setup\_shared\SI-BuiltInAuthStandard.ps1, Test-SIBuiltInAuthStandard): the updater
    prints the same summary after every update.

    Runs inside an Invardia Support session (dot-source Connect-InvardiaSupport.ps1 first: every request goes through the
    session's recorder) or as a person's own sign-in (browser / Cloud Shell). No PowerShell module.

    Output: 'OK    <install>' or 'DIFF  <install>: a | b | ...', then 'LEFTOVERS <install>: ...' when there are any.
    Returns the result object (Ok, Diff, Leftovers, Summary). Exit code 0 always: a difference is a finding, not a failure.

.PARAMETER ResourceGroupName
    The install's resource group (where ca-si-management and ca-si-mcp are).
.PARAMETER SubscriptionId
    The install's subscription (a Support session's own when not given).
.PARAMETER Name
    The install's name in the output line (default: the resource group).

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'read only: built-in sign-in standard check'
    .\setup\Test-SIBuiltInAuthStandard.ps1 -ResourceGroupName <rg> -SubscriptionId <sub> -Name <handle>
#>
[CmdletBinding()]
param(
    [string]$ResourceGroupName = $(if ($global:SI_Bootstrap_ResourceGroupName) { [string]$global:SI_Bootstrap_ResourceGroupName } else { '' }),
    [string]$SubscriptionId = $(if ($global:SI_Bootstrap_SubscriptionId) { [string]$global:SI_Bootstrap_SubscriptionId } else { [string]$global:SI_AzSubscriptionId }),
    [string]$Name = '',
    [string]$WebAppName = 'ca-si-management',
    [string]$McpAppName = 'ca-si-mcp',
    # TEST SEAMS (the script passes the real ones): ARM, Microsoft Graph, the registry listing
    [Parameter(DontShow)][scriptblock]$Arm,
    [Parameter(DontShow)][scriptblock]$Graph,
    [Parameter(DontShow)][scriptblock]$ListImages
)

#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-BuiltInAuthStandard.ps1'))
if (-not $ResourceGroupName) { throw 'Give -ResourceGroupName: the resource group of the install''s ca-si-* apps. Nothing was read.' }
if (-not $Name) { $Name = $ResourceGroupName }

if (-not $Arm -or -not $Graph) {
    # setup's own REST sign-in: a sign-in of this process is reused; else the person signs in (browser / Cloud Shell); in an
    # Invardia Support session the session's identity, every request through its recorder. ARM directly, no az CLI.
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1'))
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-GraphRest.ps1'))
    if (-not $SubscriptionId) { $sess = $null; try { $sess = Get-SISupportSession } catch { $sess = $null }; if ($sess -and $sess.SubscriptionId) { $SubscriptionId = [string]$sess.SubscriptionId } }
    if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the subscription of the install. Nothing was read.' }
    if (-not (Get-SISetupAzureContext -SubscriptionId $SubscriptionId)) { $null = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
    # a GetNewClosure block does not see this script's functions: the functions themselves are captured
    $siArm = ${function:Invoke-SIArm}; $siGraph = ${function:Invoke-SIGraphRequest}
    if (-not $Arm) {
        $Arm = {
            param([string]$Method, [string]$Path, $Body)
            if ($Method -ne 'GET') { throw ('this check only reads -- a {0} was refused' -f $Method) }
            & $siArm -Method GET -Path $Path -AllowNotFound
        }.GetNewClosure()
    }
    if (-not $Graph) {
        $Graph = {
            param([string]$Method, [string]$Uri, $Body)
            if ($Method -ne 'GET') { throw ('this check only reads -- a {0} was refused' -f $Method) }
            & $siGraph -Method GET -Uri $Uri
        }.GetNewClosure()
    }
    if (-not $ListImages) {
        try {
            . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-UpdateRest.ps1'))
            . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-AcrBuild.ps1'))
            $ListImages = { param([string]$LoginServer, [string]$Repo) Get-SIBuiltInAuthFrontImageTags -Rest (New-SIUpdateRestSeam) -LoginServer $LoginServer -Repo $Repo }
        } catch { $ListImages = $null }
    }
}
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the subscription of the install. Nothing was read.' }

$rg = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroupName
$fa = @{ Arm = $Arm; Graph = $Graph; WebAppId = ($rg + '/providers/Microsoft.App/containerApps/' + $WebAppName)
         McpAppId = ($rg + '/providers/Microsoft.App/containerApps/' + $McpAppName); RoleScope = ('/subscriptions/{0}' -f $SubscriptionId) }
if ($ListImages) { $fa['ListImages'] = $ListImages }
$facts = Read-SIBuiltInAuthStandardFacts @fa
$r = Test-SIBuiltInAuthStandard -Facts $facts

$line = if (@($r.Diff).Count) { 'DIFF  {0}: {1}' -f $Name, (@($r.Diff) -join ' | ') } else { 'OK    {0}' -f $Name }
Write-Host $line
if (@($r.Leftovers).Count) { Write-Host ('      LEFTOVERS {0}: {1}' -f $Name, (@($r.Leftovers) -join ' | ')) }
foreach ($n in @($facts.Notes)) { Write-Host ('      note {0}: {1}' -f $Name, $n) }
[pscustomobject]@{ Install = $Name; Ok = $r.Ok; Diff = @($r.Diff); Leftovers = @($r.Leftovers); Notes = @($facts.Notes); Summary = $r.Summary; Line = $line }
