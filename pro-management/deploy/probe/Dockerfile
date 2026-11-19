# The post-deploy probe image (deploy\Test-SIManagementDeployment.ps1 builds it from a staged context):
#   <stage>\pro-management\src\SI.Management.Core\...   <stage>\pro-management\deploy\probe\...
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:bef136a371963aaa46ec97882845ef6f54dec15728bb4b128b1c2a400ffbc9b4 AS build
WORKDIR /src
COPY pro-management/src/SI.Management.Core/ pro-management/src/SI.Management.Core/
COPY pro-management/deploy/probe/ pro-management/deploy/probe/
RUN dotnet publish pro-management/deploy/probe/SI.Management.LiveProbe.csproj -c Release -o /app -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:64a538092439382d055c87c0f49092efb8bca883c736c54ae523da7fd8e02d18 AS runtime
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
ENTRYPOINT ["dotnet", "SI.Management.LiveProbe.dll"]
