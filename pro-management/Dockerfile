# SecurityInsight Pro management web app.
#
# BUILD CONTEXT: a STAGED folder, not the SecurityInsight folder itself. deploy\Deploy-SIManagement.ps1 -Apply builds it:
#   <stage>\VERSION                                (the SecurityInsight release)
#   <stage>\BUILD.json                             (the build: "3.0.0-rc.12" in the header + footer; commit on /about)
#   <stage>\config\settings.catalog.locked.json   (the Community catalog the web app validates by -- linked by the csproj)
#   <stage>\pro-management\Dockerfile                 (this file)
#   <stage>\pro-management\src\...                    (source only: no bin\ or obj\)
# Why staged: the SecurityInsight folder's own .dockerignore excludes **/config/ (customer config must never reach the
# build service), and a Windows obj\ folder copied into a Linux build breaks the restore.
#   az acr build --registry <acr> --image si-management:<tag> --file pro-management/Dockerfile <stage>
#   docker build -f pro-management/Dockerfile -t si-management:dev <stage>

# BASE IMAGES PINNED BY DIGEST (2026-10-31): a tag (sdk:10.0, aspnet:10.0) is a pointer Microsoft moves on every patch, so
# the same release could build a different image at each install. Every FROM is written image:tag@sha256:<digest> --
# the tag stays for people, the digest is what is built. release\Update-SIBaseImageDigests.ps1 reads each tag's digest
# from the registry and writes it here; a release whose Dockerfiles carry a FROM without a digest is refused
# (New-SIReleaseCodeArchive -RequirePinnedBaseImages), and the digests go into the release's SBOM.
# THE .NET RESTORE IS LOCKED: every project carries packages.lock.json (RestorePackagesWithLockFile) and the restore runs
# --locked-mode -- a package (or a package it brings in) that differs from the lock file fails the build.
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
WORKDIR /src
# every shipped config file the projects link (settings catalog, audit actions, guard catalog, ...): the stage holds
# exactly those, read from the csproj files by Deploy-SIManagement.ps1
COPY config/ config/
# the release the header + footer show (SI.Management.Web.csproj reads ../../../VERSION)
COPY VERSION ./
# the build this image is (version, "3.0.0-rc.12" display, commit, build time): stamped by Deploy-SIManagement.ps1 into
# the stage, linked by SI.Management.Web.csproj next to the app (AppInfo reads it)
COPY BUILD.json ./
COPY pro-management/src/SI.Management.Core/SI.Management.Core.csproj pro-management/src/SI.Management.Core/packages.lock.json pro-management/src/SI.Management.Core/
COPY pro-management/src/SI.Management.Web/SI.Management.Web.csproj pro-management/src/SI.Management.Web/packages.lock.json pro-management/src/SI.Management.Web/
RUN dotnet restore pro-management/src/SI.Management.Web/SI.Management.Web.csproj --locked-mode
COPY pro-management/src/ pro-management/src/
RUN dotnet publish pro-management/src/SI.Management.Web/SI.Management.Web.csproj -c Release -o /app --no-restore -p:UseAppHost=false

# IMAGE-PATCH-1 (2026-11-10): the runtime is Ubuntu 24.04 CHISELED -- no shell, no package manager, only the .NET runtime's
# own files, so far fewer OS packages to carry a vulnerability. The -extra flavour keeps ICU + tzdata: the web app formats
# numbers and times in the viewer's culture and time zone. Non-root by default (APP_UID 1654). Nothing below may need a shell.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:cae5b962bfb786606def03d250c6a645cc98839095c89e806e4bd8978a68115b AS runtime
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
# the non-root user the .NET images ship (uid 1654)
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.Web.dll"]
