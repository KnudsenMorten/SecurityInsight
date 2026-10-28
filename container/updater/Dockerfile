# caj-si-updater -- keeps a container-hosted SecurityInsight on the version its update ring approves (#160).
# PowerShell 7 ONLY (#521, operator 2026-10-09: "pure rest or arm only"): no Azure CLI, no PowerShell module. The
# updater signs in with SecurityInsight's own REST token client and builds / rolls over ARM (/si/setup/_shared/
# SI-UpdateRest.ps1, SI-AcrBuild.ps1, SI-FastRoll.ps1); the build context is packed with .NET (System.Formats.Tar),
# no tar binary. Nothing of SecurityInsight's engine code is baked in: every run downloads exactly the ref the ring
# approves, so this image changes only when the updater itself changes.
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
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
# After an automatic licence request the updater mails the result with the transports the guard mails use.
COPY engine/risk-analysis/_shared/RA-Mail.ps1 /si/engine/risk-analysis/_shared/

# The image carries no Azure CLI and no Azure / Graph PowerShell module (owner 2026-10-10: "the base container image
# should be stripped also"): SecurityInsight calls Azure over REST only. The build FAILS if either is present, so a
# release can never ship an image that has them.
RUN ["pwsh","-NoProfile","-NonInteractive","-Command","if (Get-Command az -ErrorAction SilentlyContinue) { Write-Error 'the image contains the Azure CLI'; exit 1 }; $m = @(Get-Module -ListAvailable -Name 'Az', 'Az.*', 'AzureAD*', 'Microsoft.Graph*', 'MSOnline', 'ExchangeOnlineManagement'); if ($m.Count) { Write-Error ('the image contains PowerShell modules: ' + (($m.Name | Sort-Object -Unique) -join ', ')); exit 1 }"]
ENTRYPOINT ["pwsh", "-NoProfile", "-NonInteractive", "-File", "/updater/Start-SIUpdater.ps1"]
