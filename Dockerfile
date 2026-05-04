# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source

# Copy csproj and restore
COPY *.csproj .
RUN dotnet restore

# Copy everything else and build
COPY . .
RUN dotnet publish -c Release -o /app

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .

# Render uses the PORT environment variable, which defaults to 10000
# We set ASPNETCORE_URLS to listen on all interfaces at that port
ENV ASPNETCORE_URLS=http://+:10000

ENTRYPOINT ["dotnet", "MLB.dll"]
