using KeyVaultCa.Revocation.KeyVault;
using KeyVaultCa.Revocation.Ocsp.Hosting;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add output caching (in-memory for this demo)
builder.Services.AddOutputCache();

// Add OCSP responder with Azure Key Vault
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);

// Add revocation store using Key Vault certificate tags
builder.Services.AddKeyVaultRevocationStore(builder.Configuration.GetValue<Uri>("OcspResponder:KeyVaultUrl"));

var app = builder.Build();

// Enable output cache middleware if caching is configured
app.UseOutputCache();

// Map OCSP endpoints
app.MapOcspResponder();
app.MapDefaultEndpoints();

await app.RunAsync();