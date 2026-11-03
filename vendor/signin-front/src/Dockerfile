# signin-front image. Build context = FRAMEWORK/signin-front/src at the VERSION the product pins.
# 1.4.3 (SECAUDIT-1, SEC-88): both base images pinned by DIGEST (the tag alone can be re-pointed), and the NuGet restore is
# LOCKED to packages.lock.json (a dependency cannot change under the same version). Move a digest only on purpose:
#   HEAD https://mcr.microsoft.com/v2/dotnet/<sdk|aspnet>/manifests/8.0  -> Docker-Content-Digest
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:6ba9644da07bb5b560a402acec9ca38711a0762969f1b61da261df5c9f6f85da AS build
WORKDIR /src
COPY SigninFront.csproj packages.lock.json ./
RUN dotnet restore SigninFront.csproj --locked-mode
COPY . .
RUN dotnet publish SigninFront.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:ea721098d6ea2894ff9bd8387821a1659d4765d6c014b8d648bb1da16f016f5a
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "SigninFront.dll"]
