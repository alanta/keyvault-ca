# KeyVaultCa.Revocation.Ocsp.Hosting

A modern, easy-to-use ASP.NET Core hosting package for OCSP (Online Certificate Status Protocol) responders backed by Azure Key Vault.

## Features

- ✅ **Minimal setup**: 3 lines of code to get started
- ✅ **RFC 6960 compliant**: Full OCSP protocol support via [OcspResponseBuilder](../KeyVaultCa.Revocation/OcspResponseBuilder.cs)
- ✅ **Azure Key Vault integration**: Secure signing without local key material
- ✅ **Fail-fast health checks**: Ensures certificates are loaded before accepting requests
- ✅ **Modern ASP.NET Core**: Uses minimal APIs for better performance
- ✅ **Both POST and GET**: Supports RFC 6960 standard POST and optional GET methods

## Quick Start

### 1. Add Package References

```xml
<!-- OCSP hosting with Azure Key Vault -->
<PackageReference Include="KeyVaultCa.Revocation.Ocsp.Hosting" />

<!-- Revocation store implementation (Table Storage example) -->
<PackageReference Include="KeyVaultCa.Revocation.TableStorage" />
```

**Note**: The hosting package is agnostic to the revocation store. You can use any `IRevocationStore` implementation.

### 2. Configure in appsettings.json

```json
{
  "OcspResponder": {
    "KeyVaultUrl": "https://your-vault.vault.azure.net",
    "OcspSignerCertName": "ocsp-signer",
    "IssuerCertName": "root-ca",
    "ResponseValidityMinutes": 1440
  },
  "ConnectionStrings": {
    "tables": "UseDevelopmentStorage=true"
  }
}
```

### 3. Update Program.cs

```csharp
using KeyVaultCa.Revocation.Ocsp.Hosting;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

// Add OCSP responder with Azure Key Vault
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);

// Add revocation store (Table Storage implementation)
builder.Services.AddTableStorageRevocationStore(
    builder.Configuration.GetConnectionString("tables")!);

var app = builder.Build();

// Map OCSP endpoints
app.MapOcspResponder();

await app.RunAsync();
```

That's it! Your OCSP responder is ready to handle certificate status requests.

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `KeyVaultUrl` | Azure Key Vault URL (required) | - |
| `OcspSignerCertName` | Name of OCSP signing certificate in Key Vault | `ocsp-signer` |
| `IssuerCertName` | Name of CA certificate in Key Vault | `root-ca` |
| `ResponseValidityMinutes` | How long OCSP responses are valid (thisUpdate to nextUpdate) | `10` |

## How It Works

1. **Startup**: Loads OCSP signing and CA certificates from Azure Key Vault
2. **Health Check**: Marks service as healthy only after certificates are loaded (fail-fast)
3. **Request Handling**:
   - Receives OCSP request (POST or GET)
   - Extracts certificate serial number
   - Queries revocation store
   - Builds RFC 6960-compliant response
   - Signs with Azure Key Vault
   - Returns DER-encoded response

## Endpoints

- **POST /**: Standard OCSP request (content-type: `application/ocsp-request`)
- **GET /{base64Request}**: Optional GET method with base64-encoded request (RFC 6960 Appendix A.1)
- **GET /health**: Health check endpoint (requires adding `app.MapHealthChecks("/health")`)

## Azure Permissions Required

The Azure identity (managed identity, service principal, or user) must have:

- **Key Vault**: `Certificates Reader` and `Crypto User` roles
- **Storage**: `Storage Table Data Contributor` role (for revocation store)

## Example: Using with .NET Aspire

```csharp
// Program.cs
using KeyVaultCa.Revocation.Ocsp.Hosting;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults(); // Aspire defaults

builder.Services.AddKeyVaultOcspResponder(builder.Configuration);
builder.Services.AddTableStorageRevocationStore(
    builder.Configuration.GetConnectionString("tables")!);

var app = builder.Build();

app.MapOcspResponder();
app.MapDefaultEndpoints(); // Aspire endpoints

await app.RunAsync();
```

See [test/mTLS/OcspResponder](../../test/mTLS/OcspResponder/) for a complete working example.

## Architecture

This package is part of the KeyVaultCa toolkit:

```
┌─────────────────────────────────────────┐
│  KeyVaultCa.Revocation.Ocsp.Hosting     │  ← This package (ASP.NET Core hosting)
│  - OcspServiceCollectionExtensions      │
│  - OcspEndpointExtensions               │
│  - OcspHealthCheck                      │
└─────────────────────────────────────────┘
              ↓ depends on
┌─────────────────────────────────────────┐
│  KeyVaultCa.Revocation                  │  ← Core OCSP logic
│  - OcspResponseBuilder (RFC 6960)       │
│  - IRevocationStore                     │
└─────────────────────────────────────────┘
              ↓ depends on
┌─────────────────────────────────────────┐
│  KeyVaultCa.Core                        │  ← Key Vault integration
│  - KeyVaultSignatureGenerator           │
└─────────────────────────────────────────┘
```

## Performance: Output Caching

Enable response caching to dramatically improve performance by eliminating Table Storage lookups and Key Vault signing operations on cache hits.

### Performance Impact

- **Without cache**: ~100-300ms per request (Table Storage + Key Vault signing)
- **With in-memory cache hit**: <1ms
- **With Redis cache hit**: ~5ms

### How It Works

This package configures an OCSP-specific cache policy when `EnableCaching` is true, but **does not add caching services**. You choose your own caching implementation based on your deployment needs:

- **In-memory**: Best for single-instance deployments, lowest latency
- **Redis**: Best for multi-instance/load-balanced deployments, shared cache

### Setup: In-Memory Cache (Single Instance)

**appsettings.json:**
```json
{
  "OcspResponder": {
    "EnableCaching": true
    // CacheDurationMinutes defaults to ResponseValidityMinutes if not set
  }
}
```

**Program.cs:**
```csharp
using KeyVaultCa.Revocation.Ocsp.Hosting;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

// Add in-memory output caching
builder.Services.AddOutputCache();

// Add OCSP responder (configures the "ocsp" cache policy)
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);
builder.Services.AddTableStorageRevocationStore(
    builder.Configuration.GetConnectionString("tables")!);

var app = builder.Build();

// Enable output cache middleware
app.UseOutputCache();

app.MapOcspResponder();
await app.RunAsync();
```

### Setup: Distributed Cache (Redis - Multi-Instance)

**Install Redis package:**
```bash
dotnet add package Microsoft.AspNetCore.OutputCaching.StackExchangeRedis
```

**appsettings.json:**
```json
{
  "OcspResponder": {
    "EnableCaching": true
    // CacheDurationMinutes defaults to ResponseValidityMinutes if not set
  },
  "ConnectionStrings": {
    "redis": "localhost:6379"
  }
}
```

**Program.cs:**
```csharp
using KeyVaultCa.Revocation.Ocsp.Hosting;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

// Add Redis distributed output caching
builder.Services.AddStackExchangeRedisOutputCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("redis");
});

// Add OCSP responder (configures the "ocsp" cache policy)
builder.Services.AddKeyVaultOcspResponder(builder.Configuration);
builder.Services.AddTableStorageRevocationStore(
    builder.Configuration.GetConnectionString("tables")!);

var app = builder.Build();

// Enable output cache middleware
app.UseOutputCache();

app.MapOcspResponder();
await app.RunAsync();
```

### Cache Invalidation Considerations

When a certificate is revoked, cached "good" responses will persist until the TTL expires.

**Default Behavior:**
- By default, `CacheDurationMinutes` equals `ResponseValidityMinutes`, so cached responses expire exactly when the OCSP response itself expires
- This maximizes cache effectiveness while maintaining OCSP protocol correctness

**Alternative Strategies:**

1. **Short TTL**: Set `CacheDurationMinutes` to 5-10 minutes (less than `ResponseValidityMinutes`)
   - Faster revocation propagation
   - Good for high-security environments
   - Reduces cache effectiveness

2. **Manual Invalidation**: Implement cache eviction on revocation events
   - Requires custom code using `IOutputCacheStore`
   - Best freshness guarantee
   - More complex to implement

### Cache Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `EnableCaching` | Enable OCSP cache policy | `false` (opt-in) |
| `CacheDurationMinutes` | How long to cache responses (must be ≤ ResponseValidityMinutes) | `0` (uses ResponseValidityMinutes) |

**Notes**:
- The caching implementation (in-memory vs Redis) is controlled by which `AddOutputCache*()` method you call, not by configuration
- If `CacheDurationMinutes` is not set or is 0, it defaults to `ResponseValidityMinutes` to match OCSP response validity
- Setting `CacheDurationMinutes` higher than `ResponseValidityMinutes` will throw an exception at startup

## Troubleshooting

### Service fails at startup with "Key Vault URL not configured"

Ensure `OcspResponder:KeyVaultUrl` is set in appsettings.json or environment variables.

### Health check shows "unhealthy"

This means certificates failed to load from Key Vault. Check:
- Key Vault URL is correct
- Certificate names exist in Key Vault
- Azure identity has proper permissions
- Network connectivity to Key Vault

### Build error: "X509CertificateLoader does not exist"

This package requires .NET 10.0 or later. Update your project's `<TargetFramework>` to `net10.0`.

## Related Packages

- **[KeyVaultCa.Revocation](../KeyVaultCa.Revocation/)**: Core OCSP response building logic
- **[KeyVaultCa.Revocation.TableStorage](../KeyVaultCa.Revocation.TableStorage/)**: Azure Table Storage revocation store
- **[KeyVaultCa.Core](../KeyVaultCa.Core/)**: Azure Key Vault signing and certificate operations

## License

See the repository root for license information.
