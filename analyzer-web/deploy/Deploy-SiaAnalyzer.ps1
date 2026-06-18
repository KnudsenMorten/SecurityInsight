#Requires -Version 5.1
<#
.SYNOPSIS
    Build + deploy the SecurityInsight Analyzer (SIA) to Azure Container Apps in the
    internal env, AND finalize the runtime wiring it needs: a system-assigned Managed
    Identity granted Log Analytics Reader on the SI workspace (read-only data plane),
    Azure OpenAI config (AI-on), and Entra Easy Auth in front. Mirrors the CEH/PIM deploy
    pattern (build -> image -> deploy -> grant -> auth). READY TO RUN BY THE MAIN SESSION
    (which holds Azure creds) - this agent does NOT run it.

.DESCRIPTION
    Flow:
      1. az acr build the image from analyzer-web/deploy/Dockerfile (context = the
         SecurityInsight solution root so analyzer/seed is included).
      2. az containerapp update to the new image revision + set the data-plane / AI env vars.
      3. Ensure a system-assigned MI on the app.
      4. Grant that MI "Log Analytics Reader" on the workspace resource id (READ-ONLY).
         (Optionally "Cognitive Services OpenAI User" on the AOAI account when AI uses MI.)
      5. Configure Entra Easy Auth (when -AuthClientId/-AuthTenantId given).
      6. Print the app URL + health + the post-deploy live-verify checklist.

    The app reads its data plane + AI config from container-app settings (env vars set
    here, themselves Key-Vault-backable). NO secrets are hard-coded in this script.

    Steps 3-6 are idempotent and can be skipped with -SkipGrant / -SkipAuth if the main
    session prefers to run those grants by hand from README-DEPLOY.md.

.PARAMETER ResourceGroup        Internal env resource group hosting the container app env + ACR (e.g. rg-securityinsight).
.PARAMETER AcrName              Azure Container Registry name (build target).
.PARAMETER AppName              Container App name.
.PARAMETER WorkspaceId         Log Analytics workspace customerId (GUID) the app QUERIES read-only via MI = the internal SI workspace (the default base).
.PARAMETER WorkspaceResourceId Full ARM resource id of that same workspace - the SCOPE of the Log Analytics Reader role grant (step 4). Required unless -SkipGrant.
.PARAMETER OpenAiEndpoint      Azure OpenAI endpoint (https://<name>.openai.azure.com) - AI on by default when set.
.PARAMETER OpenAiDeployment    Azure OpenAI deployment name.
.PARAMETER OpenAiAccountId     ARM resource id of the Azure OpenAI account - scope for the "Cognitive Services OpenAI User" MI grant (only needed when AOAI uses MI, no key).
.PARAMETER AuthClientId        Entra app-registration client id for Easy Auth (step 5). When set with -AuthTenantId, the script enables require-auth.
.PARAMETER AuthTenantId        Entra tenant id (issuer) for Easy Auth.
.PARAMETER SkipGrant           Skip steps 3-4 (MI + role grant) - run them manually instead.
.PARAMETER SkipAuth            Skip step 5 (Easy Auth) - configure it manually instead.

.EXAMPLE
    # The EXACT command the MAIN SESSION runs (real workspace/sub IDs live in internal/ENGINE-IDENTITY.md
    # + deploy/README-DEPLOY.md, never in public docs):
    .\deploy\Deploy-SiaAnalyzer.ps1 -ResourceGroup rg-securityinsight `
        -AcrName <acr> -AppName sia-analyzer `
        -WorkspaceId <workspace-customerId-guid> `
        -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/log-platform-management-securityinsight" `
        -OpenAiEndpoint https://<aoai>.openai.azure.com -OpenAiDeployment <deployment> `
        -AuthClientId <app-reg-client-id> -AuthTenantId <tenant-id>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$AppName = 'sia-analyzer',
    [Parameter(Mandatory)][string]$WorkspaceId,
    [string]$WorkspaceResourceId,
    [string]$OpenAiEndpoint,
    [string]$OpenAiDeployment,
    [string]$OpenAiAccountId,
    [string]$AuthClientId,
    [string]$AuthTenantId,
    [switch]$SkipGrant,
    [switch]$SkipAuth,
    [string]$ImageTag = ('sia-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
)

$ErrorActionPreference = 'Stop'
# deploy/ -> analyzer-web/ -> SecurityInsight/ (the docker build context root).
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dockerfile = Join-Path $PSScriptRoot 'Dockerfile'
$image = "$AcrName.azurecr.io/securityinsight-analyzer:$ImageTag"

if (-not $SkipGrant -and [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
    throw "WorkspaceResourceId is required for the Log Analytics Reader grant (step 4). Pass it, or use -SkipGrant to grant manually (see README-DEPLOY.md)."
}

# --- 1. Build image --------------------------------------------------------
Write-Host ">> [1/6] Building image $image (context = $siRoot)" -ForegroundColor Cyan
az acr build --registry $AcrName --image "securityinsight-analyzer:$ImageTag" `
    --file $dockerfile $siRoot --output none
if ($LASTEXITCODE -ne 0) { throw 'az acr build failed.' }

# --- 2. Deploy image + env vars -------------------------------------------
$envVars = @(
    "Sia__WorkspaceId=$WorkspaceId",
    "Sia__UseDemoData=false"
)
if ($OpenAiEndpoint)   { $envVars += "Sia__OpenAiEndpoint=$OpenAiEndpoint" }
if ($OpenAiDeployment) { $envVars += "Sia__OpenAiDeployment=$OpenAiDeployment" }

Write-Host ">> [2/6] Updating container app $AppName to $image" -ForegroundColor Cyan
az containerapp update -g $ResourceGroup -n $AppName --image $image `
    --set-env-vars @envVars --output none
if ($LASTEXITCODE -ne 0) { throw 'az containerapp update failed.' }

# --- 3+4. Managed Identity + Log Analytics Reader (read-only data plane) ---
if ($SkipGrant) {
    Write-Host ">> [3-4/6] Skipping MI + role grant (-SkipGrant). Grant manually per README-DEPLOY.md." -ForegroundColor Yellow
} else {
    Write-Host ">> [3/6] Ensuring system-assigned Managed Identity on $AppName" -ForegroundColor Cyan
    az containerapp identity assign -g $ResourceGroup -n $AppName --system-assigned --output none
    if ($LASTEXITCODE -ne 0) { throw 'az containerapp identity assign failed.' }
    $principalId = az containerapp identity show -g $ResourceGroup -n $AppName --query principalId -o tsv
    if ([string]::IsNullOrWhiteSpace($principalId)) { throw 'Could not read the container app MI principalId.' }

    Write-Host ">> [4/6] Granting MI 'Log Analytics Reader' (READ-ONLY) on the workspace" -ForegroundColor Cyan
    # Idempotent: az returns the existing assignment if it already exists.
    az role assignment create `
        --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
        --role "Log Analytics Reader" --scope $WorkspaceResourceId --output none
    if ($LASTEXITCODE -ne 0) { throw 'Log Analytics Reader role assignment failed.' }

    if ($OpenAiAccountId) {
        Write-Host ">>        Granting MI 'Cognitive Services OpenAI User' on the AOAI account" -ForegroundColor Cyan
        az role assignment create `
            --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
            --role "Cognitive Services OpenAI User" --scope $OpenAiAccountId --output none
        if ($LASTEXITCODE -ne 0) { throw 'Cognitive Services OpenAI User role assignment failed.' }
    }
}

# --- 5. Entra Easy Auth (a hosted security analyzer is never anonymous) -----
if ($SkipAuth -or [string]::IsNullOrWhiteSpace($AuthClientId) -or [string]::IsNullOrWhiteSpace($AuthTenantId)) {
    Write-Host ">> [5/6] Skipping Easy Auth (no -AuthClientId/-AuthTenantId or -SkipAuth). Configure per README-DEPLOY.md." -ForegroundColor Yellow
} else {
    Write-Host ">> [5/6] Enabling Entra Easy Auth (require authentication) on $AppName" -ForegroundColor Cyan
    az containerapp auth microsoft update -g $ResourceGroup -n $AppName `
        --client-id $AuthClientId `
        --issuer "https://login.microsoftonline.com/$AuthTenantId/v2.0" --output none
    if ($LASTEXITCODE -ne 0) { throw 'az containerapp auth microsoft update failed.' }
    az containerapp auth update -g $ResourceGroup -n $AppName `
        --unauthenticated-client-action RedirectToLoginPage `
        --redirect-provider azureactivedirectory --output none
    if ($LASTEXITCODE -ne 0) { throw 'az containerapp auth update failed.' }
}

# --- 6. Report -------------------------------------------------------------
$fqdn = az containerapp show -g $ResourceGroup -n $AppName --query 'properties.configuration.ingress.fqdn' -o tsv
Write-Host ">> [6/6] Deployed." -ForegroundColor Green
Write-Host "   URL:    https://$fqdn"     -ForegroundColor Green
Write-Host "   Health: https://$fqdn/health" -ForegroundColor Green
Write-Host ""
Write-Host ">> LIVE-VERIFY (the release gate - see deploy/README-DEPLOY.md sec.4):" -ForegroundColor Yellow
Write-Host "   - Open / -> lands on the EXEC view; sign in with Entra." -ForegroundColor Yellow
Write-Host "   - Banner shows 'Live data' + an AI-written exec summary grounded in real RA findings." -ForegroundColor Yellow
Write-Host "   - /analyst prompt + a guarded KQL run; a write attempt is rejected." -ForegroundColor Yellow
Write-Host "   - POST /mcp tools/list returns the read-only tool catalogue." -ForegroundColor Yellow
