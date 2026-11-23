# The post-deploy probe image (deploy\Test-SIManagementDeployment.ps1 builds it from a staged context):
#   <stage>\pro-management\src\SI.Management.Core\...   <stage>\pro-management\deploy\probe\...
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:2b1e13a22e46b55117f9cdb4b38e73172de08a30370166c8227d06cdaff82473 AS build
WORKDIR /src
COPY pro-management/src/SI.Management.Core/ pro-management/src/SI.Management.Core/
COPY pro-management/deploy/probe/ pro-management/deploy/probe/
RUN dotnet publish pro-management/deploy/probe/SI.Management.LiveProbe.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:21bf94ddcec8efebe4ffa64a6bfd30fc270ee87f54277aa08210e4a1d5a0c560 AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.LiveProbe.dll"]
