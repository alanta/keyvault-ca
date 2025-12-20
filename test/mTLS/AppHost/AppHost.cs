#:package Aspire.Hosting.AppHost
#:package Aspire.Hosting.Azure.Storage
#:reference ..\OcspResponder\OcspResponder.csproj
#:reference ..\ApiServer\ApiServer.csproj
#:reference ..\ClientApp\ClientApp.csproj

var builder = DistributedApplication.CreateBuilder(args);

// Add Azure Table Storage (Azurite for local development)
var storage = builder.AddAzureStorage("storage")
	.RunAsEmulator();

var tables = storage.AddTables("tables");

// Add OCSP Responder service (uses Azurite for revocation data)
var ocspResponder = builder.AddProject<Projects.OcspResponder>("ocsp-responder")
	.WithReference(tables)
	.WithHttpEndpoint(port: 5000, name: "http")
	.WithEnvironment("ASPNETCORE_URLS", "http://ocsp.localhost:5000");

// Add API Server with mTLS and OCSP dependency
var apiServer = builder.AddProject<Projects.ApiServer>("api-server")
	.WithHttpsEndpoint(port: 7001, name: "https")
	.WaitFor(ocspResponder);

// Add Client App that calls the API Server via client certificate auth
builder.AddProject<Projects.ClientApp>("client-app")
	.WithReference(apiServer)
	.WaitFor(apiServer);

builder.Build().Run();
