# The post-deploy probe image (deploy\Test-SIManagementDeployment.ps1 builds it from a staged context):
#   <stage>\pro-management\src\SI.Management.Core\...   <stage>\pro-management\deploy\probe\...
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY pro-management/src/SI.Management.Core/ pro-management/src/SI.Management.Core/
COPY pro-management/deploy/probe/ pro-management/deploy/probe/
RUN dotnet publish pro-management/deploy/probe/SI.Management.LiveProbe.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.LiveProbe.dll"]
