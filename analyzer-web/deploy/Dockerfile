# =============================================================================
#  SecurityInsight Analyzer (SIA) - container image for Azure Container Apps /
#  App Service for Containers. Multi-stage: build + publish with the .NET 8 SDK,
#  run on the slim ASP.NET runtime. The app authenticates to Log Analytics +
#  Azure OpenAI with its Managed Identity (no secrets baked in). Easy Auth (Entra)
#  is enforced by the platform in front of the container - see README-DEPLOY.md.
# =============================================================================

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore against the csproj graph first for layer caching.
COPY analyzer-web/src/SIAnalyzer.Core/SIAnalyzer.Core.csproj src/SIAnalyzer.Core/
COPY analyzer-web/src/SIAnalyzer.Web/SIAnalyzer.Web.csproj   src/SIAnalyzer.Web/
RUN dotnet restore src/SIAnalyzer.Web/SIAnalyzer.Web.csproj

# Copy the web + core sources AND the shared demo seed. The csproj links the seed
# from ../../../analyzer/seed, which from the csproj at /src/src/SIAnalyzer.Web/ resolves
# to the ABSOLUTE /analyzer/seed -- so the seed MUST land there, not at the relative
# /src/analyzer/seed. (A relative COPY breaks `dotnet publish` with MSB3030
# "Could not copy /analyzer/seed/demo-snapshot.json".) The build context is the
# SecurityInsight solution root so both analyzer-web/ and analyzer/seed/ are visible.
COPY analyzer-web/src/ src/
COPY analyzer/seed/ /analyzer/seed/

RUN dotnet publish src/SIAnalyzer.Web/SIAnalyzer.Web.csproj -c Release -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS run
WORKDIR /app
COPY --from=build /app ./

# LISTEN PORT (audit #12). Kestrel binds 8080 on all interfaces, fixed.
#
# The comment that used to sit here claimed "Container Apps / App Service inject the
# listen port via PORT/WEBSITES_PORT; bind Kestrel to it". That was wrong twice over
# and the code never did it:
#   * WEBSITES_PORT is an APP SERVICE setting. Container Apps does not inject a port
#     at all -- the platform routes ingress to the container's `--target-port`.
#   * Nothing in the app reads PORT or WEBSITES_PORT (no UseUrls / ListenAnyIP).
#
# So the real contract is one-directional and must be stated, not implied: the image
# listens on 8080, and the container app's ingress target-port MUST equal it.
# Deploy-SIAnalyzer.ps1 ASSERTS that before it builds ($ContainerListenPort), so a
# mismatch is refused up front instead of surfacing later as a failed health gate.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# NON-ROOT (audit #12). The image ran as root because no USER was ever declared.
# $APP_UID is the non-root user the .NET 8 base images ship for exactly this.
# Safe here because SIA writes NOTHING to the filesystem at run time (verified: no
# File.Write*/Directory.Create/FileStream/GetTempPath anywhere in analyzer-web/src) and
# 8080 is unprivileged. The ASP.NET DataProtection key ring is the one thing that wants
# a writable home; it was already ephemeral in a container, so this is no regression.
USER $APP_UID

ENTRYPOINT ["dotnet", "SIAnalyzer.Web.dll"]
