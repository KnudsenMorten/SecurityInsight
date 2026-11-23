# The post-deploy probe image (deploy\Test-SIManagementDeployment.ps1 builds it from a staged context):
#   <stage>\pro-management\src\SI.Management.Core\...   <stage>\pro-management\deploy\probe\...
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:8c6edfb26c85153f236d26efebd9ad349aec403583f343f201ee67838b23658d AS build
WORKDIR /src
COPY pro-management/src/SI.Management.Core/ pro-management/src/SI.Management.Core/
COPY pro-management/deploy/probe/ pro-management/deploy/probe/
RUN dotnet publish pro-management/deploy/probe/SI.Management.LiveProbe.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:0a0e20d12b84b081fb737fddb92d8d205edce9ac2dc62796d2aab30f03804498 AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.LiveProbe.dll"]
