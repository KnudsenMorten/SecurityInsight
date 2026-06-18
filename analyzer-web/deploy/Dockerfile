# =============================================================================
#  SecurityInsight Analyzer (SIA) - container image for Azure Container Apps /
#  App Service for Containers. Multi-stage: build + publish with the .NET 8 SDK,
#  run on the slim ASP.NET runtime. The app authenticates to Log Analytics +
#  Azure OpenAI with its Managed Identity (no secrets baked in). Easy Auth (Entra)
#  is enforced by the platform in front of the container - see README-DEPLOY.md.
# =============================================================================

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore against the csproj graph first for layer caching.
COPY analyzer-web/src/Sia.Core/Sia.Core.csproj src/Sia.Core/
COPY analyzer-web/src/Sia.Web/Sia.Web.csproj   src/Sia.Web/
RUN dotnet restore src/Sia.Web/Sia.Web.csproj

# Copy the web + core sources AND the shared demo seed. The csproj links the seed
# from ../../../analyzer/seed, which from the csproj at /src/src/Sia.Web/ resolves
# to the ABSOLUTE /analyzer/seed -- so the seed MUST land there, not at the relative
# /src/analyzer/seed. (A relative COPY breaks `dotnet publish` with MSB3030
# "Could not copy /analyzer/seed/demo-snapshot.json".) The build context is the
# SecurityInsight solution root so both analyzer-web/ and analyzer/seed/ are visible.
COPY analyzer-web/src/ src/
COPY analyzer/seed/ /analyzer/seed/

RUN dotnet publish src/Sia.Web/Sia.Web.csproj -c Release -o /app /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS run
WORKDIR /app
COPY --from=build /app ./

# Container Apps / App Service inject the listen port via PORT/WEBSITES_PORT;
# bind Kestrel to it (the hosted equivalent of the POC's "bind ingress, not 127.0.0.1").
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "Sia.Web.dll"]
