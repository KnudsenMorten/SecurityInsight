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

# THE BASE (IMAGE-PATCH-1 1b, owner 2026-11-10): the .NET 10 SDK image on Ubuntu 24.04 -- it ships PowerShell 7.6 LTS
# (installed as a .NET tool under /usr/share/powershell, /usr/bin/pwsh links to it) on the .NET 10 runtime. The old
# powershell:lts-ubuntu-22.04 image carried PowerShell 7.4 on .NET 8, both out of support on 2026-11-10. Runs as root,
# as the old base did (no USER is set). Pinned by digest (release\Update-SIBaseImageDigests.ps1).
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e

# NO POWERSHELL MODULES. SecurityInsight reaches Azure, Log Analytics, storage, Key
# Vault, Resource Graph, Microsoft Graph and the Log Ingestion API over plain REST
# with its own sign-in (managed identity, certificate or client secret), so the
# image installs no PowerShell module -- nothing to keep in step with a gallery.
# Risk Analysis writes its .xlsx with SI's own .NET writer
# (engine/risk-analysis/_shared/RA-XlsxWriter.ps1), so no Excel module either.

# The time zone database. The Ubuntu base image ships without it, so .NET knew no zone at all and the daily pipeline
# ("22:00 in the install's time zone", SI_Pipeline_TimeZone) ran on UTC instead -- "the time zone 'Romance Standard
# Time' is not known on this machine" (live 2026-10-06, Community rehearsal). With tzdata, IANA ids (Europe/Copenhagen)
# resolve, and Windows ids through SI-Pipeline's map. Before the COPY, so it stays in the cached base layer.
# #574: fonts-dejavu-core -- the fonts of the mail PDF (the PDF builder uses the system's fonts; none is bundled).
# IMAGE-PATCH-1 (2026-11-10): the base's OS packages are upgraded at build -- a digest-pinned base never moves, so its
# fixed Ubuntu security updates reach the image only this way.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# THE POWERSHELL VERSION: the build FAILS unless pwsh is 7.6 -- the release is made for 7.6, and a base image that
# moved to another PowerShell line must not ship unnoticed.
RUN ["pwsh","-NoProfile","-NonInteractive","-Command","if ($PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion.Minor -ne 6) { Write-Error ('PowerShell 7.6 required, got ' + $PSVersionTable.PSVersion); exit 1 }; Write-Host ('PowerShell ' + $PSVersionTable.PSVersion)"]

# THE CULTURE the old base image set (LANG / LC_ALL en_US.UTF-8): the .NET SDK image sets none, and without it .NET runs
# the engines in the invariant culture -- dates and numbers formatted by the current culture would change (24-hour times
# instead of AM/PM). Kept, so a mail or report reads as before. .NET takes the culture data from ICU (in the base).
ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# #574: the mail PDF's library -- the managed DLLs of PDFsharp + MigraDoc 6.2.4 (MIT), downloaded at build from nuget.org
# exactly as pinned in engine/_shared/pdf/SI.Pdf.packages.json; a package whose SHA-512 differs fails the build. DLLs
# only: no native code, no executable, no PowerShell module. Before the solution COPY, so the layer stays cached.
COPY engine/_shared/pdf/SI.Pdf.packages.json /tmp/si-pdf/engine/_shared/pdf/
COPY container/Install-SIPdfLibrary.ps1 /tmp/si-pdf/container/
RUN pwsh -NoProfile -NonInteractive -File /tmp/si-pdf/container/Install-SIPdfLibrary.ps1 -Destination /opt/si/pdf \
 && rm -rf /tmp/si-pdf
ENV SI_PDF_LIB=/opt/si/pdf

# Whole-solution copy. Build context is SOLUTIONS/SecurityInsight/; the entire
# tree (engine, auth, launcher, setup, container, asset-profiling-*, etc.)
# lands under /app/ so any entrypoint can reach any sibling helper.
COPY . /app/

WORKDIR /app

# Default entrypoint = collection orchestrator.
# Risk Analysis Container App Job overrides this via --command in Bootstrap.
# The image carries no Azure CLI and no Azure / Graph PowerShell module (owner 2026-10-10: "the base container image
# should be stripped also"): SecurityInsight calls Azure over REST only. The build FAILS if either is present, so a
# release can never ship an image that has them.
RUN ["pwsh","-NoProfile","-NonInteractive","-Command","if (Get-Command az -ErrorAction SilentlyContinue) { Write-Error 'the image contains the Azure CLI'; exit 1 }; $m = @(Get-Module -ListAvailable -Name 'Az', 'Az.*', 'AzureAD*', 'Microsoft.Graph*', 'MSOnline', 'ExchangeOnlineManagement'); if ($m.Count) { Write-Error ('the image contains PowerShell modules: ' + (($m.Name | Sort-Object -Unique) -join ', ')); exit 1 }"]
ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/app/container/Start-SIInContainer.ps1"]
