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

# BASE IMAGES PINNED BY DIGEST (2026-10-31): a tag (sdk:8.0, aspnet:8.0) is a pointer Microsoft moves on every patch, so
# the same release could build a different image at each install. Every FROM is written image:tag@sha256:<digest> --
# the tag stays for people, the digest is what is built. release\Update-SIBaseImageDigests.ps1 reads each tag's digest
# from the registry and writes it here; a release whose Dockerfiles carry a FROM without a digest is refused
# (New-SIReleaseCodeArchive -RequirePinnedBaseImages), and the digests go into the release's SBOM.
# THE .NET RESTORE IS LOCKED: every project carries packages.lock.json (RestorePackagesWithLockFile) and the restore runs
# --locked-mode -- a package (or a package it brings in) that differs from the lock file fails the build.
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:6ba9644da07bb5b560a402acec9ca38711a0762969f1b61da261df5c9f6f85da AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:ea721098d6ea2894ff9bd8387821a1659d4765d6c014b8d648bb1da16f016f5a AS runtime
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
# the non-root user the .NET 8 images ship (uid 1654)
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.Web.dll"]
