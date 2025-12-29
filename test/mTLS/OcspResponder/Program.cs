using KeyVaultCa.Revocation.Ocsp.Hosting;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add OCSP responder with Azure Key Vault
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);

// Add revocation store
var tableConnectionString = builder.Configuration.GetConnectionString("tables")
    ?? throw new InvalidOperationException("Table Storage connection string not configured");
builder.Services.AddTableStorageRevocationStore(tableConnectionString);

var app = builder.Build();

// Map OCSP endpoints
app.MapOcspResponder();
app.MapDefaultEndpoints();

await app.RunAsync();