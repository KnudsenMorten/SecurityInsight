#Requires -Version 5.1
<#
.SYNOPSIS
    Build + deploy the SecurityInsight Analyzer (SIA) to Azure Container Apps in the
    internal env, with a CEH-parity DEV/PROD split: DEV does a direct revision deploy;
    PROD does a blue/green revision swap that WARMS the new (staging) revision and
    REFUSES to shift traffic unless /health returns 200, then a post-deploy /health gate.
    It also finalizes the runtime wiring SIA needs: a system-assigned Managed Identity
    granted Log Analytics Reader on the SI workspace (read-only data plane), Azure OpenAI
    config (AI-on), and Entra Easy Auth in front. Mirrors CEH's deploy-app.ps1 shape
    (DEV=direct, PROD=staging->health->swap, retry once on transient cold-start). READY TO
    RUN BY THE MAIN SESSION (which holds Azure creds) - this agent does NOT run it.

.DESCRIPTION
    SIA targets its OWN dedicated resource group (NOT PIM's rg-pim-manager-web) - default
    rg-securityinsight (Phase 1 cutover). Container Apps has no App-Service "slots", so the
    CEH slot-swap is modelled as a REVISION blue/green in multiple-revision mode:

      DEV (-Env dev):
        1. az acr build the image.
        2. az containerapp update to the new image (single active revision; brief restart).
        3. MI + Log Analytics Reader grant (read-only), optional AOAI grant, Easy Auth.
        4. Post-deploy /health gate on the app FQDN.

      PROD (-Env prod):
        1. az acr build the image.
        2. Ensure the app is in MULTIPLE-revision mode (so the running revision keeps 100%
           of traffic while the new one warms - zero-downtime, instant rollback).
        3. az containerapp update to the new image => a NEW revision is created. Its
           per-revision FQDN is warmed and HEALTH-GATED: the script REFUSES to shift
           traffic unless https://<new-revision-fqdn>/health returns 200 (retry the warm
           loop once on a transient cold start).
        4. Shift 100% of ingress traffic to the new (now-healthy) revision; the old
           revision stays provisioned for instant rollback (shift traffic back).
        5. MI + Log Analytics Reader grant (read-only), optional AOAI grant, Easy Auth.
        6. Post-deploy /health gate on the public app FQDN.

    The app reads its data plane + AI config from container-app settings (env vars set
    here, themselves Key-Vault-backable). NO secrets are hard-coded in this script.

    Steps that grant/auth are idempotent and can be skipped with -SkipGrant / -SkipAuth.

.PARAMETER Env                 dev | prod. DEV = direct revision deploy; PROD = blue/green revision swap + health gate. Default dev.
.PARAMETER ResourceGroup       SIA's OWN resource group hosting the container app env + ACR (e.g. rg-securityinsight). NEVER PIM's rg-pim-manager-web.
.PARAMETER AcrName             Azure Container Registry name (build target).
.PARAMETER AppName             Container App name.
.PARAMETER WorkspaceId         Log Analytics workspace customerId (GUID) the app QUERIES read-only via MI = the internal SI workspace (the default base).
.PARAMETER WorkspaceResourceId Full ARM resource id of that same workspace - the SCOPE of the Log Analytics Reader role grant. Required unless -SkipGrant.
.PARAMETER OpenAiEndpoint      Azure OpenAI endpoint (https://<name>.openai.azure.com) - AI on by default when set.
.PARAMETER OpenAiDeployment    Azure OpenAI deployment name.
.PARAMETER OpenAiAccountId     ARM resource id of the Azure OpenAI account - scope for the "Cognitive Services OpenAI User" MI grant (only needed when AOAI uses MI, no key).
.PARAMETER AuthClientId        Entra app-registration client id for Easy Auth. When set with -AuthTenantId, the script enables require-auth.
.PARAMETER AuthTenantId        Entra tenant id (issuer) for Easy Auth.
.PARAMETER StorageAccountId    ARM resource id of the storage account holding SIA's own durable state - the governance register (audit #7) and the scheduler's send markers (audit #9). Scope for the single "Storage Table Data Contributor" MI grant, and the source of BOTH table endpoints so they cannot drift. Omit and both fall back to in-memory (the register loses everything on restart and says so; the exec email can double-send across replicas). Alias: -GovernanceStorageAccountId.
.PARAMETER GovernanceTableName Governance register table name (default sigovernance). One table, three partitions.
.PARAMETER ScheduleTableName   Scheduler send-marker table name (default sischedule). One row per scheduled job.
.PARAMETER SkipGrant           Skip the MI + role grant - run them manually instead.
.PARAMETER SkipAuth            Skip Easy Auth - configure it manually instead.

.EXAMPLE
    # DEV (direct revision deploy):
    .\deploy\Deploy-SIAnalyzer.ps1 -Env dev -ResourceGroup rg-securityinsight `
        -AcrName <acr> -AppName ca-sia-dev -WorkspaceId <workspace-customerId-guid> `
        -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/<ws>"

.EXAMPLE
    # PROD (blue/green revision swap + health gate):
    .\deploy\Deploy-SIAnalyzer.ps1 -Env prod -ResourceGroup rg-securityinsight `
        -AcrName <acr> -AppName ca-sia -WorkspaceId <workspace-customerId-guid> `
        -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/<ws>" `
        -OpenAiEndpoint https://<aoai>.openai.azure.com -OpenAiDeployment <deployment> `
        -AuthClientId <app-reg-client-id> -AuthTenantId <tenant-id> `
        -StorageAccountId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.Storage/storageAccounts/<storage-account>"
#>
[CmdletBinding()]
param(
    [ValidateSet('dev','prod')][string]$Env = 'dev',
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$AppName = 'ca-sia',
    [Parameter(Mandatory)][string]$WorkspaceId,
    [string]$WorkspaceResourceId,
    [string]$OpenAiEndpoint,
    [string]$OpenAiDeployment,
    [string]$OpenAiAccountId,
    [string]$AuthClientId,
    [string]$AuthTenantId,
    # Audit #7 + #9 -- SIA's OWN durable state. Full ARM resource id of the storage account
    # holding it; the MI is granted 'Storage Table Data Contributor' on it once, covering BOTH
    # tables: the governance register (default sigovernance) and the scheduler's send markers
    # (default sischedule). Both endpoints are derived from this ONE value so they cannot drift
    # apart. These are SIA's own tables, never a security platform. Omit only for a deliberately
    # non-durable deployment: the register falls back to in-memory and says so on the page, and
    # the scheduler warns that the exec email can double-send across replicas.
    [Alias('GovernanceStorageAccountId')]
    [string]$StorageAccountId,
    [string]$GovernanceTableName = 'sigovernance',
    [string]$ScheduleTableName = 'sischedule',
    [switch]$SkipGrant,
    [switch]$SkipAuth,
    # Audit #33 -- skip the az CLI sign-in because the CALLER has already established it.
    # Not a way to opt out of authentication: without a context every az call below fails.
    [switch]$SkipAzLogin,
    # Audit #3b escape hatch -- only when the SI workspace legitimately lives in a
    # different resource group than the app. Never to co-locate in another solution.
    [switch]$AllowResourceGroupMismatch,
    # Audit #3a.3 escape hatch -- SIA must not be reachable from the internet.
    # Only for a deliberate, temporary public-ingress deployment.
    [switch]$AllowPublicIngress,
    # Audit #13 -- ASP.NET Core host filtering. Always SET explicitly (like the #3a auth gate and
    # the #7 register flag) so the live value is readable in `az containerapp show` instead of
    # inferred from a default.
    #   '*'    (default) accept any Host header. What the app shipped with.
    #   'auto' derive "<app fqdn>;*.<parent domain>" from the live ingress fqdn.
    #   or a literal semicolon-separated list.
    #
    # 'auto' is NOT the default on purpose, and this is the trap to understand before using it:
    #   1. The PROD path health-gates the new revision on its PER-REVISION fqdn
    #      (sia--<suffix>.<parent>), which is a DIFFERENT host from the app fqdn. Pinning to the
    #      app fqdn alone would 400 the health check and REFUSE THE SWAP. Hence the wildcard.
    #   2. Container Apps probes can address the container by IP. A default ACA setup uses TCP
    #      probes, which never reach host filtering -- but an HTTP probe would, and would fail.
    # Both are hosted-gate facts this workstation cannot verify, so the safe value ships as the
    # default and pinning is a deliberate, informed act.
    [string]$AllowedHosts = '*',
    [string]$ImageTag = ('sia-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
)

$ErrorActionPreference = 'Stop'
# deploy/ -> analyzer-web/ -> SecurityInsight/ (the docker build context root).
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dockerfile = Join-Path $PSScriptRoot 'Dockerfile'
$image = "$AcrName.azurecr.io/securityinsight-analyzer:$ImageTag"

# ---------------------------------------------------------------------------
# GUARDRAIL: SIA deploys into SecurityInsight's OWN resource group -- never inside
# another solution's (audit #3b, operator 2026-08-05: "it must never be placed
# inside another solution. it must be deployed into the same rg as the remaining
# si application").
#
# This used to be a DENYLIST OF ONE NAME (`-ieq 'rg-pim-manager-web'`) -- the same
# structural flaw as audit #1a and #20: a gate that only knows the one mistake
# already made. PlatformMonitoring's or PlatformConfiguration's resource group, or
# any future solution's, sailed straight through it.
#
# Inverted to an ALLOWLIST derived from data the script already receives:
# -WorkspaceResourceId contains /resourceGroups/<rg>/, and that IS SecurityInsight's
# resource group. Requiring -ResourceGroup to equal it enforces "same RG as the rest
# of SI" structurally, with no solution names to maintain.
#
# Escape hatch, fail-closed: if a deployment legitimately has the SI workspace in a
# DIFFERENT resource group, pass -AllowResourceGroupMismatch. It warns loudly rather
# than silently permitting co-location.
if ($WorkspaceResourceId -match '/resourceGroups/(?<rg>[^/]+)/') {
    $siResourceGroup = $Matches['rg']
    if ($ResourceGroup -ine $siResourceGroup) {
        $msg = "ResourceGroup '$ResourceGroup' is NOT SecurityInsight's resource group ('$siResourceGroup', derived from -WorkspaceResourceId). " +
               "SIA must deploy into the SAME resource group as the rest of SecurityInsight, never inside another solution's. " +
               "If the SI workspace genuinely lives in a different RG, re-run with -AllowResourceGroupMismatch."
        if ($AllowResourceGroupMismatch) { Write-Warning $msg }
        else { throw $msg }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
    throw "WorkspaceResourceId '$WorkspaceResourceId' does not contain a /resourceGroups/<name>/ segment, so SIA's resource group cannot be verified. Fix the resource id."
}
if (-not $SkipGrant -and [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
    throw "WorkspaceResourceId is required for the Log Analytics Reader grant. Pass it, or use -SkipGrant to grant manually (see README-DEPLOY.md)."
}

# az CLI writes harmless warnings to stderr (e.g. the 32-bit-Python notice), which PS 5.1
# under EAP=Stop turns into terminating NativeCommandErrors. Run az with EAP=Continue and
# judge by exit code (CEH deploy-app.ps1 pattern).
function Invoke-Az {
    param([Parameter(Mandatory)][string[]]$AzArgs)
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $errFile = Join-Path $env:TEMP ("az-err-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    try { $out = az @AzArgs 2>$errFile } finally { $ErrorActionPreference = $eap }
    $script:AzExit = $LASTEXITCODE
    if ($script:AzExit -ne 0 -and (Test-Path $errFile)) {
        Get-Content $errFile | Where-Object {
            $_ -and $_ -notmatch '32-bit Python|UserWarning|cryptography|CategoryInfo|FullyQualifiedErrorId|NativeCommandError|^\s*\+ ' -and $_.Trim() -ne ''
        } | Select-Object -First 10 | ForEach-Object { Write-Host "   az: $_" -ForegroundColor Red }
    }
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    return $out
}

# Poll a /health URL until it answers 200 (or give up). Returns $true/$false.
function Wait-Health {
    param([Parameter(Mandatory)][string]$Url, [int]$Attempts = 30, [int]$DelaySeconds = 5)
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $r = Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 20
            if ($r.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

Write-Host ">> SIA deploy - Env=$Env, App=$AppName, RG=$ResourceGroup" -ForegroundColor Cyan

# --- AZ CLI SIGN-IN (audit #33) --------------------------------------------
# This script is entirely az-based and used to have NO authentication step at all --
# it assumed a human had already run `az login`. Run unattended by the daily sync
# (PIM REQUIREMENTS.md sec.1, "Generic sync-triggered auto-deploy") there is no such
# session, and it would die on the FIRST az call below, on every customer.
#
# The trap: an Az PowerShell context is NOT an az CLI context. Connect-AzAccount and
# a VM's Managed Identity as consumed by Az PowerShell do nothing for `az` -- separate
# token caches -- so a session that can read Key Vault happily still fails every az
# command with "Please run 'az login'". Both halves must be established independently.
#
# Connect-SIAzCli bridges exactly that, from the customer's existing config globals:
# MI -> Az PowerShell -> read the SPN secret from THAT customer's AutomateIT Key Vault
# ($global:SpnKeyVaultName) -> `az login` as the SPN. Idempotent: an existing az
# context is reused, so an interactive run by a human is unaffected.
#
# -SkipAzLogin is for a caller that has already signed the CLI in (e.g. a chained
# deploy) -- it does not disable the check, it just declines to re-do it.
if (-not $SkipAzLogin) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth\Connect-SIAzCli.ps1')
    Connect-SIAzCli
}

# --- LISTEN-PORT GATE (audit #12) ------------------------------------------
# The image binds Kestrel to a FIXED port (deploy/Dockerfile: ASPNETCORE_URLS).
# Container Apps does not inject a port -- it routes ingress to the container's
# target-port -- and the app reads neither PORT nor WEBSITES_PORT. So the two halves
# have to agree, and until now nothing checked that they did: the container app kept
# whatever target-port it was CREATED with, out-of-band and undocumented.
#
# A mismatch was never silent (prod health-gates the new revision and refuses to swap;
# dev warns), but it surfaced late and looked like an app fault rather than a config
# one. Assert it here instead -- BEFORE the ACR build -- so the failure names its own
# cause. This constant is the single source of truth the Dockerfile is tested against
# (tests/pester/SIA-Container.Tests.ps1), so the two cannot drift apart.
$ContainerListenPort = 8080
$targetPort = Invoke-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.targetPort','-o','tsv')
if ($script:AzExit -ne 0) {
    Write-Host ">> [port] Could not read ingress target-port (app may not exist yet). Skipping the check -- if you are CREATING the app, it must be created with --target-port $ContainerListenPort." -ForegroundColor Yellow
} elseif ([string]::IsNullOrWhiteSpace($targetPort)) {
    Write-Host ">> [port] Ingress has no target-port set (ingress may be disabled). The image listens on $ContainerListenPort." -ForegroundColor Yellow
} elseif ("$targetPort".Trim() -ne "$ContainerListenPort") {
    throw "INGRESS TARGET-PORT MISMATCH -- $AppName in $ResourceGroup routes ingress to port $targetPort, but the image listens on $ContainerListenPort (deploy/Dockerfile ASPNETCORE_URLS). Nothing injects the port into the container, so this deployment would not serve traffic. Fix it with: az containerapp ingress update -g $ResourceGroup -n $AppName --target-port $ContainerListenPort"
} else {
    Write-Host ">> [port] Ingress target-port=$targetPort matches the image's listen port. OK." -ForegroundColor Green
}

# --- PLAIN-HTTP GATE (audit #13) -------------------------------------------
# #13 asked for UseHttpsRedirection in the app. That is the WRONG layer here and the app
# deliberately does not do it: Container Apps terminates TLS and forwards plain HTTP to the
# container, so an in-app redirect sees every request as insecure and loops forever. What
# actually decides whether plain HTTP is accepted is the INGRESS, so it is checked here --
# the same reasoning as the #12 target-port gate: enforce it where it is enforceable.
$allowInsecure = Invoke-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.allowInsecure','-o','tsv')
if ($script:AzExit -eq 0 -and "$allowInsecure".Trim() -ieq 'true') {
    $msg = "INGRESS ACCEPTS PLAIN HTTP -- $AppName in $ResourceGroup has ingress.allowInsecure=true, so posture data can be served over an unencrypted connection and the HSTS header the app now emits is undermined. " +
           "Fix it with: az containerapp ingress update -g $ResourceGroup -n $AppName --allow-insecure false"
    if ($AllowPublicIngress) { Write-Warning $msg }   # same deliberate-exception switch as #3a.3
    else { throw $msg }
} elseif ($script:AzExit -eq 0) {
    Write-Host ">> [https] ingress.allowInsecure=$allowInsecure -- plain HTTP is refused by the platform. OK." -ForegroundColor Green
}

# --- HOST FILTERING (audit #13) --------------------------------------------
# Resolved BEFORE the deploy so the value is part of the same env-var write as everything else.
if ($AllowedHosts -ieq 'auto') {
    $autoFqdn = Invoke-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.fqdn','-o','tsv')
    if ($script:AzExit -ne 0 -or [string]::IsNullOrWhiteSpace($autoFqdn)) {
        throw "-AllowedHosts auto needs the app's ingress fqdn and it could not be read. Pass a literal list, or '*'."
    }
    $autoFqdn = "$autoFqdn".Trim()
    # Everything after the first label is the Container Apps environment domain, which the
    # per-revision fqdns (sia--<suffix>.<parent>) also live under -- see the parameter note.
    $parent = $autoFqdn.Substring($autoFqdn.IndexOf('.') + 1)
    $AllowedHosts = "$autoFqdn;*.$parent"
    Write-Host ">> [hosts] AllowedHosts derived: $AllowedHosts" -ForegroundColor Cyan
    Write-Host ">> [hosts]   the wildcard is REQUIRED -- the prod health gate calls the per-revision fqdn, which is a different host." -ForegroundColor Cyan
} elseif ($AllowedHosts -eq '*') {
    Write-Host ">> [hosts] AllowedHosts='*' (default) -- any Host header is accepted." -ForegroundColor Yellow
} else {
    Write-Host ">> [hosts] AllowedHosts='$AllowedHosts' (explicit)." -ForegroundColor Cyan
}

# --- 1. Build image --------------------------------------------------------
Write-Host ">> [build] Building image $image (context = $siRoot)" -ForegroundColor Cyan
[void](Invoke-Az @('acr','build','--registry',$AcrName,'--image',"securityinsight-analyzer:$ImageTag",'--file',$dockerfile,$siRoot,'--output','none'))
if ($script:AzExit -ne 0) { throw 'az acr build failed.' }

# --- 2. Env vars (data plane + AI) -----------------------------------------
$envVars = @(
    "SIAnalyzer__WorkspaceId=$WorkspaceId",
    "SIAnalyzer__UseDemoData=false",
    # Audit #3a: set the in-app auth gate EXPLICITLY, every deploy.
    # It now defaults to true in code, but this script previously set it NOWHERE
    # (verified: zero references), so the four-endpoint gate that existed was OFF in
    # production and protected nothing -- a switch that exists but is never thrown.
    # Stating it here means the deployed value is visible in `az containerapp show`
    # rather than inferred from a code default.
    "SIAnalyzer__Auth__RequireClientPrincipal=true",
    # Audit #7/#8: the governance register is ACTIVE. Stated here for the same reason as the
    # auth gate above -- the live value must be readable in `az containerapp show`, not
    # inferred from a code default. This enables SIA's OWN register only; the PLATFORM
    # exemption sync stays hard-locked off in code (the no-auto-revoke rule) and no
    # environment variable can turn it on.
    "SIAnalyzer__Governance__LocalRegisterEnabled=true",
    "SIAnalyzer__Governance__TableName=$GovernanceTableName",
    "SIAnalyzer__Schedule__TableName=$ScheduleTableName",
    # Audit #13: host filtering, stated explicitly for the same reason as the two above.
    "AllowedHosts=$AllowedHosts"
)
if ($OpenAiEndpoint)   { $envVars += "SIAnalyzer__OpenAiEndpoint=$OpenAiEndpoint" }
if ($OpenAiDeployment) { $envVars += "SIAnalyzer__OpenAiDeployment=$OpenAiDeployment" }

# The governance table endpoint is derived from the storage account NAME in its resource id,
# so the caller passes one value and cannot get the two out of step.
if ($StorageAccountId) {
    if ($StorageAccountId -notmatch '/storageAccounts/(?<acct>[^/]+)') {
        throw "StorageAccountId does not look like a storage account resource id: $StorageAccountId"
    }
    $stateAccount = $Matches['acct']
    $tableBase = "https://$stateAccount.table.core.windows.net"
    $envVars += "SIAnalyzer__Governance__TableEndpoint=$tableBase"
    $envVars += "SIAnalyzer__Schedule__TableEndpoint=$tableBase"
    Write-Host ">> [state] DURABLE in storage account '$stateAccount': governance register '$GovernanceTableName' (audit #7), scheduler send markers '$ScheduleTableName' (audit #9)" -ForegroundColor Cyan
} else {
    Write-Host ">> [state] WARNING: no -StorageAccountId. Both of SIA's durable stores fall back to IN-MEMORY:" -ForegroundColor Yellow
    Write-Host ">> [state]   * governance (audit #7): risk-acceptances, exemptions and the audit trail do NOT survive a restart and are not shared between replicas. The governance page states this." -ForegroundColor Yellow
    Write-Host ">> [state]   * scheduler (audit #9): the exec-summary email can be sent TWICE per window with more than one replica, and a restart can skip a window. The scheduler logs this at startup." -ForegroundColor Yellow
}

if ($Env -eq 'prod') {
    # --- PROD: blue/green revision swap with a health gate ------------------
    # Ensure multiple-revision mode so the running revision keeps serving while the new
    # one warms (zero-downtime + instant rollback). Idempotent.
    Write-Host ">> [prod] Ensuring multiple-revision mode (keeps the live revision serving during warm-up)" -ForegroundColor Cyan
    [void](Invoke-Az @('containerapp','revision','set-mode','-g',$ResourceGroup,'-n',$AppName,'--mode','multiple','--output','none'))
    if ($script:AzExit -ne 0) { throw 'Could not set multiple-revision mode.' }

    # Capture the CURRENT live revision (for rollback messaging) before we add a new one.
    $oldRevision = Invoke-Az @('containerapp','revision','list','-g',$ResourceGroup,'-n',$AppName,'--query',"[?properties.active && properties.trafficWeight>``0``].name | [0]",'-o','tsv')

    # Deploy the new image -> creates a NEW revision. With multiple-revision mode + the
    # default revision suffix, the new revision starts with 0% traffic until we shift it.
    $revSuffix = $ImageTag.ToLowerInvariant() -replace '[^a-z0-9-]','-'
    Write-Host ">> [prod] Creating new revision (suffix $revSuffix) with the new image (0% traffic until health-gated)" -ForegroundColor Cyan
    [void](Invoke-Az (@('containerapp','update','-g',$ResourceGroup,'-n',$AppName,'--image',$image,'--revision-suffix',$revSuffix,'--set-env-vars') + $envVars + @('--output','none')))
    if ($script:AzExit -ne 0) { throw 'az containerapp update (new revision) failed.' }

    $newRevision = Invoke-Az @('containerapp','revision','list','-g',$ResourceGroup,'-n',$AppName,'--query',"[?contains(name, '$revSuffix')].name | [0]",'-o','tsv')
    if ([string]::IsNullOrWhiteSpace($newRevision)) { throw "Could not resolve the new revision name (suffix $revSuffix)." }

    # Warm + HEALTH-GATE the new revision on its per-revision FQDN. Refuse to swap unless 200.
    $newFqdn = Invoke-Az @('containerapp','revision','show','-g',$ResourceGroup,'-n',$AppName,'--revision',$newRevision,'--query','properties.fqdn','-o','tsv')
    if ([string]::IsNullOrWhiteSpace($newFqdn)) { throw "Could not resolve the new revision FQDN ($newRevision)." }
    $newHealth = "https://$newFqdn/health"
    Write-Host ">> [prod] Warming + health-gating the new revision: $newHealth" -ForegroundColor Cyan
    $healthy = Wait-Health -Url $newHealth -Attempts 30 -DelaySeconds 5
    if (-not $healthy) {
        Write-Host ">> [prod] New revision did not answer /health 200 - retrying the warm loop once (transient cold-start)" -ForegroundColor Yellow
        $healthy = Wait-Health -Url $newHealth -Attempts 18 -DelaySeconds 5
    }
    if (-not $healthy) {
        throw "REFUSING TO SWAP: the new revision $newRevision never returned 200 from /health ($newHealth). The live revision is untouched (still serving 100%). Investigate: az containerapp logs show -g $ResourceGroup -n $AppName --revision $newRevision"
    }

    # Health-gate passed -> shift 100% traffic to the new revision; keep the old one for rollback.
    Write-Host ">> [prod] Health OK - shifting 100% traffic to $newRevision" -ForegroundColor Cyan
    [void](Invoke-Az @('containerapp','ingress','traffic','set','-g',$ResourceGroup,'-n',$AppName,'--revision-weight',"$newRevision=100",'--output','none'))
    if ($script:AzExit -ne 0) { throw 'Traffic shift to the new revision failed.' }
    if (-not [string]::IsNullOrWhiteSpace($oldRevision) -and $oldRevision -ne $newRevision) {
        Write-Host ">> [prod] Swapped. Rollback = az containerapp ingress traffic set -g $ResourceGroup -n $AppName --revision-weight $oldRevision=100" -ForegroundColor Green
    }
} else {
    # --- DEV: direct revision deploy (brief restart, simplest path) ---------
    Write-Host ">> [dev] Direct deploy of $image to $AppName" -ForegroundColor Cyan
    [void](Invoke-Az (@('containerapp','update','-g',$ResourceGroup,'-n',$AppName,'--image',$image,'--set-env-vars') + $envVars + @('--output','none')))
    if ($script:AzExit -ne 0) { throw 'az containerapp update failed.' }
}

# --- MI + Log Analytics Reader (read-only data plane) ----------------------
if ($SkipGrant) {
    Write-Host ">> [grant] Skipping MI + role grant (-SkipGrant). Grant manually per README-DEPLOY.md." -ForegroundColor Yellow
} else {
    Write-Host ">> [grant] Ensuring system-assigned Managed Identity on $AppName" -ForegroundColor Cyan
    [void](Invoke-Az @('containerapp','identity','assign','-g',$ResourceGroup,'-n',$AppName,'--system-assigned','--output','none'))
    if ($script:AzExit -ne 0) { throw 'az containerapp identity assign failed.' }
    $principalId = Invoke-Az @('containerapp','identity','show','-g',$ResourceGroup,'-n',$AppName,'--query','principalId','-o','tsv')
    if ([string]::IsNullOrWhiteSpace($principalId)) { throw 'Could not read the container app MI principalId.' }

    Write-Host ">> [grant] Granting MI 'Log Analytics Reader' (READ-ONLY) on the workspace" -ForegroundColor Cyan
    [void](Invoke-Az @('role','assignment','create','--assignee-object-id',$principalId,'--assignee-principal-type','ServicePrincipal','--role','Log Analytics Reader','--scope',$WorkspaceResourceId,'--output','none'))
    if ($script:AzExit -ne 0) { throw 'Log Analytics Reader role assignment failed.' }

    if ($OpenAiAccountId) {
        Write-Host ">> [grant] Granting MI 'Cognitive Services OpenAI User' on the AOAI account" -ForegroundColor Cyan
        [void](Invoke-Az @('role','assignment','create','--assignee-object-id',$principalId,'--assignee-principal-type','ServicePrincipal','--role','Cognitive Services OpenAI User','--scope',$OpenAiAccountId,'--output','none'))
        if ($script:AzExit -ne 0) { throw 'Cognitive Services OpenAI User role assignment failed.' }
    }

    if ($StorageAccountId) {
        # Audit #7 + #9: the data-plane grant for SIA's own state (governance register + the
        # scheduler's send markers). Scoped to the ONE storage account, and it is a TABLE data
        # role only -- it grants nothing on blobs, queues or any security platform. Without it
        # the app starts, logs the failure loudly and falls back to in-memory rather than
        # serving a broken page.
        Write-Host ">> [grant] Granting MI 'Storage Table Data Contributor' on SIA's state storage account" -ForegroundColor Cyan
        [void](Invoke-Az @('role','assignment','create','--assignee-object-id',$principalId,'--assignee-principal-type','ServicePrincipal','--role','Storage Table Data Contributor','--scope',$StorageAccountId,'--output','none'))
        if ($script:AzExit -ne 0) { throw 'Storage Table Data Contributor role assignment failed (governance register and scheduler markers would fall back to in-memory).' }
    }
}

# --- Entra Easy Auth (a hosted security analyzer is never anonymous) --------
if ($SkipAuth -or [string]::IsNullOrWhiteSpace($AuthClientId) -or [string]::IsNullOrWhiteSpace($AuthTenantId)) {
    Write-Host ">> [auth] Skipping Easy Auth (no -AuthClientId/-AuthTenantId or -SkipAuth). Configure per README-DEPLOY.md." -ForegroundColor Yellow
} else {
    Write-Host ">> [auth] Enabling Entra Easy Auth (require authentication) on $AppName" -ForegroundColor Cyan
    [void](Invoke-Az @('containerapp','auth','microsoft','update','-g',$ResourceGroup,'-n',$AppName,'--client-id',$AuthClientId,'--issuer',"https://login.microsoftonline.com/$AuthTenantId/v2.0",'--output','none'))
    if ($script:AzExit -ne 0) { throw 'az containerapp auth microsoft update failed.' }
    [void](Invoke-Az @('containerapp','auth','update','-g',$ResourceGroup,'-n',$AppName,'--unauthenticated-client-action','RedirectToLoginPage','--redirect-provider','azureactivedirectory','--output','none'))
    if ($script:AzExit -ne 0) { throw 'az containerapp auth update failed.' }
}

# --- INGRESS EXPOSURE GATE (audit #3a.3) -----------------------------------
# Operator 2026-08-05: "none of this must be exposed to internet but accessible
# from internal trusted locations only (private networks in azure)."
#
# This script previously never inspected ingress at all -- it only READ the fqdn to
# build the health URL and shifted revision traffic weights. Whatever the container
# app happened to be created with was what it kept, which is not a control. A
# SecurityInsight Analyzer publishing an organisation's posture data must fail the
# deploy rather than quietly go public.
#
# NOTE: `external=false` requires the Container Apps ENVIRONMENT to be VNet-integrated
# and internal-only -- that is fixed at environment creation, so it cannot be
# retrofitted here. This gate therefore DETECTS and REFUSES; provisioning the
# internal environment belongs to the Phase 1 dedicated-infra cutover (#3b).
$ingressExternal = Invoke-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.external','-o','tsv')
if ($script:AzExit -eq 0 -and "$ingressExternal".Trim() -ieq 'true') {
    $msg = "INGRESS IS EXTERNAL -- $AppName in $ResourceGroup is reachable from the internet. " +
           "SIA serves security-posture data and must be reachable only from trusted Azure private networks. " +
           "Deploy it to a VNet-integrated, internal-only Container Apps environment (Phase 1 dedicated infra). " +
           "To proceed anyway for a deliberate, temporary public deployment, re-run with -AllowPublicIngress."
    if ($AllowPublicIngress) { Write-Warning $msg }
    else { throw $msg }
} elseif ($script:AzExit -eq 0) {
    Write-Host ">> [ingress] external=$ingressExternal -- not internet-facing. OK." -ForegroundColor Green
}

# --- Post-deploy /health gate on the app FQDN ------------------------------
$fqdn = Invoke-Az @('containerapp','show','-g',$ResourceGroup,'-n',$AppName,'--query','properties.configuration.ingress.fqdn','-o','tsv')
$healthUrl = "https://$fqdn/health"
Write-Host ">> [health] Post-deploy /health gate: $healthUrl" -ForegroundColor Cyan
$live = Wait-Health -Url $healthUrl -Attempts 24 -DelaySeconds 5
if ($live) {
    Write-Host ">> $Env is healthy." -ForegroundColor Green
} else {
    Write-Host ">> WARNING: $healthUrl not answering 200 after ~2 minutes - check logs: az containerapp logs show -g $ResourceGroup -n $AppName" -ForegroundColor Red
}

# --- Report ----------------------------------------------------------------
Write-Host ">> Deployed ($Env)." -ForegroundColor Green
Write-Host "   URL:    https://$fqdn"      -ForegroundColor Green
Write-Host "   Health: https://$fqdn/health" -ForegroundColor Green
Write-Host ""
Write-Host ">> LIVE-VERIFY (the release gate - see deploy/README-DEPLOY.md sec.4):" -ForegroundColor Yellow
Write-Host "   - Open / -> lands on the EXEC view; sign in with Entra." -ForegroundColor Yellow
Write-Host "   - Banner shows 'Live data' + an AI-written exec summary grounded in real RA findings." -ForegroundColor Yellow
Write-Host "   - /analyst prompt + a guarded KQL run; a write attempt is rejected." -ForegroundColor Yellow
Write-Host "   - POST /mcp tools/list returns the read-only tool catalogue (behind Easy Auth)." -ForegroundColor Yellow
