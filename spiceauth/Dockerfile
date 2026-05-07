# ── Build stage ────────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

# Copy project files first for layer-cached NuGet restore
COPY SpiceAuth.Core/SpiceAuth.Core.csproj               SpiceAuth.Core/
COPY SpiceAuth.Application/SpiceAuth.Application.csproj SpiceAuth.Application/
COPY SpiceAuth.Infrastructure/SpiceAuth.Infrastructure.csproj SpiceAuth.Infrastructure/
COPY SpiceAuth.API/SpiceAuth.API.csproj                 SpiceAuth.API/

RUN dotnet restore SpiceAuth.API/SpiceAuth.API.csproj \
    --runtime linux-musl-x64 \
    --locked-mode 2>/dev/null || dotnet restore SpiceAuth.API/SpiceAuth.API.csproj --runtime linux-musl-x64

# Copy source and publish
COPY . .
RUN dotnet publish SpiceAuth.API/SpiceAuth.API.csproj \
    --configuration Release \
    --runtime linux-musl-x64 \
    --self-contained false \
    --output /app/publish \
    -p:UseAppHost=false \
    -p:TrimUnusedDependencies=false

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS runtime

# Security: run as non-root user
RUN addgroup -S spiceauth && adduser -S spiceauth -G spiceauth

WORKDIR /app

# Create log directory with correct permissions
RUN mkdir -p /app/logs && chown spiceauth:spiceauth /app/logs

COPY --from=build --chown=spiceauth:spiceauth /app/publish .

USER spiceauth

# Health-check polls the lightweight /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

EXPOSE 8080

# Override default ASP.NET port to 8080 (unprivileged)
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

# Reduce .NET GC overhead for server workloads
ENV DOTNET_GCConserveMemory=5
ENV DOTNET_GCHeapHardLimit=536870912

ENTRYPOINT ["dotnet", "SpiceAuth.API.dll"]
