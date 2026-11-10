# signin-front image. Build context = FRAMEWORK/signin-front/src at the VERSION the product pins.
# 1.4.3 (SECAUDIT-1, SEC-88): both base images pinned by DIGEST (the tag alone can be re-pointed), and the NuGet restore is
# LOCKED to packages.lock.json (a dependency cannot change under the same version). Move a digest only on purpose:
#   HEAD https://mcr.microsoft.com/v2/dotnet/<sdk|aspnet>/manifests/<tag>  -> Docker-Content-Digest (the multi-arch index)
# 1.4.6 (IMAGE-PATCH-1, 2026-11-10): both digests moved to the current patch (read 2026-11-10), and the runtime is the
# CHISELED Ubuntu 24.04 image: no shell, no package manager, only the libraries .NET needs, non-root "app" user built in --
# far fewer OS packages for a scanner to find. The "-extra" variant because the app is NOT invariant-globalization
# (1.4.1: Microsoft.Data.SqlClient refuses invariant mode on Linux): it carries ICU and tzdata, the plain chiseled one
# does not. No HEALTHCHECK and no RUN in the runtime stage (there is no shell there); Container Apps probes are HTTP.
# 2.0.0 (IMAGE-PATCH-1 point 0, 2026-11-10): .NET 10 LTS (.NET 8 ends support 2026-11-10). Build: sdk:10.0-noble
# (SDK 10.0.403, runtime 10.0.14); runtime: aspnet:10.0-noble-chiseled-extra (ASP.NET Core 10.0.14). Both digests read
# 2026-11-10. The .NET 10 image still sets ASPNETCORE_HTTP_PORTS=8080 and the non-root "app" user (APP_UID 1654) itself;
# both are kept explicit below so the contract does not hang on a base-image default.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
WORKDIR /src
COPY SigninFront.csproj packages.lock.json ./
RUN dotnet restore SigninFront.csproj --locked-mode
COPY . .
RUN dotnet publish SigninFront.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:a9298ccc39c6258ae71228479e2f3f8d2ceb6639a9927262a4b0ff7d319a0e7e
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "SigninFront.dll"]
