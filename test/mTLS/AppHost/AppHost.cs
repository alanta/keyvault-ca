#:sdk Aspire.AppHost.Sdk@13.1.0
#:package Aspire.Hosting.AppHost
#:package Aspire.Hosting.Azure.Storage
#:project ..\OcspResponder\OcspResponder.csproj
#:project ..\ApiServer\ApiServer.csproj
#:project ..\ClientApp\ClientApp.csproj

var builder = DistributedApplication.CreateBuilder(args);

// Azure Table Storage (Azurite emulator for local development)
var storage = builder.AddAzureStorage("storage").RunAsEmulator();
var tables = storage.AddTables("tables");

// OCSP Responder - validates certificate revocation status
var ocspResponder = builder.AddProject<Projects.OcspResponder>("ocsp-responder")
	.WithReference(tables)
	.WithHttpHealthCheck("/health")
	.WaitFor(storage);

// API Server - requires mTLS with OCSP validation
var apiServer = builder.AddProject<Projects.ApiServer>("api-server")
	.WaitFor(ocspResponder);

// Client App - calls API Server using client certificate
builder.AddProject<Projects.ClientApp>("client-app")
	.WithReference(apiServer)
	.WaitFor(apiServer)
	.WaitFor(ocspResponder);

builder.Build().Run();
