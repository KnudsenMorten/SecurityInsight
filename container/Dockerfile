# SecurityInsight v2.2 -- orchestrator + Risk Analysis container image.
# Runs the same engines that execute locally, in PowerShell 7 on Linux
# inside Azure Container Apps Jobs.
#
# Two entrypoints share this image:
#   * /app/container/Start-SIInContainer.ps1            (collection: endpoint/identity/azure/schema-discovery)
#   * /app/container/Start-RiskAnalysisInContainer.ps1  (Risk Analysis report builder)
#
# Bootstrap-ContainerAppJob.ps1 picks the entrypoint per-engine via the
# Container App Job's --command override. The default ENTRYPOINT runs the
# collection orchestrator.
#
# Build context: SOLUTIONS/SecurityInsight/  (everything under the solution
# is copied verbatim into /app/, so engine + auth + launcher + setup + etc.
# are all present at runtime). Bootstrap-ContainerAppJob.ps1 sets the build
# context to this directory automatically.
#
# Build (no local Docker needed -- ACR Tasks builds server-side):
#   cd SOLUTIONS/SecurityInsight
#   az acr build --registry <acr> --image si-orchestrator:<tag> --file container/Dockerfile .

FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

# Modules both entrypoints need at runtime. Pinned to current major-stable
# versions; bump deliberately + retest, not via 'latest'.
# RA-specific addition: ImportExcel for the XLSX writer.
RUN pwsh -NoProfile -Command \
    "Install-Module -Name Az.Accounts            -RequiredVersion 5.4.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Resources           -RequiredVersion 9.0.3 -Force -Scope AllUsers; \
     Install-Module -Name Az.Storage             -RequiredVersion 9.6.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Monitor             -RequiredVersion 7.0.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.ResourceGraph       -RequiredVersion 1.2.1 -Force -Scope AllUsers; \
     Install-Module -Name Az.OperationalInsights -RequiredVersion 3.4.0 -Force -Scope AllUsers; \
     Install-Module -Name powershell-yaml        -RequiredVersion 0.4.12 -Force -Scope AllUsers; \
     Install-Module -Name AzLogDcrIngestPS       -RequiredVersion 1.6.2 -Force -Scope AllUsers; \
     Install-Module -Name ImportExcel            -RequiredVersion 7.8.10 -Force -Scope AllUsers"

# Whole-solution copy. Build context is SOLUTIONS/SecurityInsight/; the entire
# tree (engine, auth, launcher, setup, container, asset-profiling-*, etc.)
# lands under /app/ so any entrypoint can reach any sibling helper.
COPY . /app/

WORKDIR /app

# Default entrypoint = collection orchestrator.
# Risk Analysis Container App Job overrides this via --command in Bootstrap.
ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/container/Start-SIInContainer.ps1"]
