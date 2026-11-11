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
# 2.1.1 (DOTNET-10015, Invardia 2026-11-11): both digests moved to .NET 10.0.15 (SDK 10.0.404, runtime + ASP.NET Core 10.0.15,
# read 2026-11-11 from the MCR v2 API): 10.0.14's runtime packs carried CVE-2026-114146 (Critical), -114147 / -114149 / -109475.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
WORKDIR /src
COPY SigninFront.csproj packages.lock.json ./
RUN dotnet restore SigninFront.csproj --locked-mode
COPY . .
RUN dotnet publish SigninFront.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:cae5b962bfb786606def03d250c6a645cc98839095c89e806e4bd8978a68115b
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "SigninFront.dll"]
