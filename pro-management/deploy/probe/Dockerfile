# The post-deploy probe image (deploy\Test-SIManagementDeployment.ps1 builds it from a staged context):
#   <stage>\pro-management\src\SI.Management.Core\...   <stage>\pro-management\deploy\probe\...
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
WORKDIR /src
COPY pro-management/src/SI.Management.Core/ pro-management/src/SI.Management.Core/
COPY pro-management/deploy/probe/ pro-management/deploy/probe/
RUN dotnet publish pro-management/deploy/probe/SI.Management.LiveProbe.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:80a51954ac70925e5783cb1ed35129a4243dcb1cddef20066b67346e17db284d AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.LiveProbe.dll"]
