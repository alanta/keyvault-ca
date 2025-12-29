using KeyVaultCa.Revocation.Ocsp.Hosting;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add output caching (in-memory for this demo)
builder.Services.AddOutputCache();

// Add OCSP responder with Azure Key Vault
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);

// Add revocation store
var tableConnectionString = builder.Configuration.GetConnectionString("tables")
    ?? throw new InvalidOperationException("Table Storage connection string not configured");
builder.Services.AddTableStorageRevocationStore(tableConnectionString);

var app = builder.Build();

// Enable output cache middleware if caching is configured
app.UseOutputCache();

// Map OCSP endpoints
app.MapOcspResponder();
app.MapDefaultEndpoints();

await app.RunAsync();