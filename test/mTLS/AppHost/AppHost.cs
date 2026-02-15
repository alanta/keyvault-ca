#:sdk Aspire.AppHost.Sdk@13.1.1
#:package Aspire.Hosting.AppHost
#:project ..\OcspResponder\OcspResponder.csproj
#:project ..\ApiServer\ApiServer.csproj
#:project ..\ClientApp\ClientApp.csproj

var builder = DistributedApplication.CreateBuilder(args);

// OCSP Responder - validates certificate revocation status
// Now uses Key Vault tags for revocation data (no external storage needed)
var ocspResponder = builder.AddProject<Projects.OcspResponder>("ocsp-responder")
	.WithHttpHealthCheck("/health");

// API Server - requires mTLS with OCSP validation
var apiServer = builder.AddProject<Projects.ApiServer>("api-server")
	.WaitFor(ocspResponder);

// Client App - calls API Server using client certificate
builder.AddProject<Projects.ClientApp>("client-app")
	.WithReference(apiServer)
	.WaitFor(apiServer)
	.WaitFor(ocspResponder);

builder.Build().Run();
