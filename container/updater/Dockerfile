# caj-si-updater -- keeps a container-hosted SecurityInsight on the version its update ring approves (#160).
# PowerShell 7 ONLY (#521, operator 2026-10-09: "pure rest or arm only"): no Azure CLI, no PowerShell module. The
# updater signs in with SecurityInsight's own REST token client and builds / rolls over ARM (/si/setup/_shared/
# SI-UpdateRest.ps1, SI-AcrBuild.ps1, SI-FastRoll.ps1); the build context is packed with .NET (System.Formats.Tar),
# no tar binary. Nothing of SecurityInsight's engine code is baked in: every run downloads exactly the ref the ring
# approves, so this image changes only when the updater itself changes.
# THE BASE (IMAGE-PATCH-1 1b, owner 2026-11-10): the .NET 10 SDK image on Ubuntu 24.04 -- it ships PowerShell 7.6 LTS
# (installed as a .NET tool under /usr/share/powershell, /usr/bin/pwsh links to it) on the .NET 10 runtime. The old
# powershell:lts-ubuntu-22.04 image carried PowerShell 7.4 on .NET 8, both out of support on 2026-11-10. Runs as root,
# as the old base did (no USER is set). Pinned by digest (release\Update-SIBaseImageDigests.ps1).
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e

# IMAGE-PATCH-1 (2026-11-10): the base's OS packages are upgraded at build -- a digest-pinned base never moves, so its
# fixed Ubuntu security updates reach the image only this way.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# THE POWERSHELL VERSION: the build FAILS unless pwsh is 7.6 -- the release is made for 7.6, and a base image that
# moved to another PowerShell line must not ship unnoticed.
RUN ["pwsh","-NoProfile","-NonInteractive","-Command","if ($PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion.Minor -ne 6) { Write-Error ('PowerShell 7.6 required, got ' + $PSVersionTable.PSVersion); exit 1 }; Write-Host ('PowerShell ' + $PSVersionTable.PSVersion)"]

# THE CULTURE the old base image set (LANG / LC_ALL en_US.UTF-8): the .NET SDK image sets none, and without it .NET runs
# the engines in the invariant culture -- dates and numbers formatted by the current culture would change (24-hour times
# instead of AM/PM). Kept, so a mail or report reads as before. .NET takes the culture data from ICU (in the base).
ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# #574: the updater's licence mail carries its PDF too -- the fonts above and the PDF library's managed DLLs (PDFsharp +
# MigraDoc 6.2.4, MIT), pinned by SHA-512 in engine/_shared/pdf/SI.Pdf.packages.json. DLLs only, no module.
COPY engine/_shared/pdf/SI.Pdf.packages.json /tmp/si-pdf/engine/_shared/pdf/
COPY container/Install-SIPdfLibrary.ps1 /tmp/si-pdf/container/
RUN pwsh -NoProfile -NonInteractive -File /tmp/si-pdf/container/Install-SIPdfLibrary.ps1 -Destination /opt/si/pdf \
 && rm -rf /tmp/si-pdf
ENV SI_PDF_LIB=/opt/si/pdf
# Pro: the release's template gate reads its YAML templates with the release's own reader (engine/_shared/SI-Yaml.ps1);
# no YAML module is installed.

WORKDIR /updater
# Built with the SecurityInsight folder as the context (setup/Install-SIUpdaterJob.ps1), so the licence request step
# (#239) carries the client, the framework licence verifier and the licence setter (engine/_shared, auth, setup under
# /si) -- not the engines themselves.
COPY container/updater/Start-SIUpdater.ps1 ./
COPY container/updater/_shared/ ./_shared/
COPY VERSION /si/
COPY engine/SI-FeatureCatalog.ps1 /si/engine/
# Whole folders, not single files: the Community copy has no setup/Set-SILicense.ps1, and a COPY of a missing file
# fails the build (the step then reports that the licence cannot be installed, and the update runs on).
COPY engine/_shared/ /si/engine/_shared/
COPY auth/ /si/auth/
COPY setup/ /si/setup/
# The size rule (setup/_shared/SI-JobSizing.ps1 loads container/_shared/SI-ContainerConfig.ps1): without this folder every
# update said "job size: not checked" (2026-10-09 .. 3.0.18) and no job or web app was ever sized by an update.
COPY container/_shared/ /si/container/_shared/
# ... and the pipeline's job map, which the size rule and the run limit read (without it a job's own run limit setting was
# looked for under its own name only)
COPY config/job-flow.locked.json /si/config/
# #1145 the identity names (setup/_shared/SI-IdentityNamesStep.ps1): the web identity's move checks and adds the sign-in
# app's federated credential with the web deploy's own builder -- that one file, not the web app
COPY pro-management/deploy/SI-ManagementSignInCredential.ps1 /si/pro-management/deploy/
# After an automatic licence request the updater mails the result with the transports the guard mails use.
COPY engine/risk-analysis/_shared/RA-Mail.ps1 /si/engine/risk-analysis/_shared/

# The image carries no Azure CLI and no Azure / Graph PowerShell module (owner 2026-10-10: "the base container image
# should be stripped also"): SecurityInsight calls Azure over REST only. The build FAILS if either is present, so a
# release can never ship an image that has them.
RUN ["pwsh","-NoProfile","-NonInteractive","-Command","if (Get-Command az -ErrorAction SilentlyContinue) { Write-Error 'the image contains the Azure CLI'; exit 1 }; $m = @(Get-Module -ListAvailable -Name 'Az', 'Az.*', 'AzureAD*', 'Microsoft.Graph*', 'MSOnline', 'ExchangeOnlineManagement'); if ($m.Count) { Write-Error ('the image contains PowerShell modules: ' + (($m.Name | Sort-Object -Unique) -join ', ')); exit 1 }"]
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/updater/Start-SIUpdater.ps1"]
