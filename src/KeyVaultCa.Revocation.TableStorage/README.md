# KeyVaultCa.Revocation.TableStorage

Azure Table Storage implementation of `IRevocationStore` with automatic HybridCache decorator for optimal performance.

## Features

- ✅ **Azure Table Storage**: Scalable, cost-effective revocation storage
- ✅ **Automatic caching**: HybridCache decorator applied automatically
- ✅ **Stampede protection**: Prevents cache stampedes under high load
- ✅ **Partition strategy**: Uses first 2 characters of serial number for efficient lookups
- ✅ **Simple setup**: One line of code to register

## Quick Start

### 1. Install Package

```bash
dotnet add package KeyVaultCa.Revocation.TableStorage
```

### 2. Configure Connection String

**appsettings.json:**
```json
{
  "ConnectionStrings": {
    "tables": "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=..."
  }
}
```

For local development with Azurite:
```json
{
  "ConnectionStrings": {
    "tables": "UseDevelopmentStorage=true"
  }
}
```

### 3. Register in DI Container

```csharp
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

// Add Table Storage revocation store (with automatic caching)
builder.Services.AddTableStorageRevocationStore(
    builder.Configuration.GetConnectionString("tables")!);

var app = builder.Build();
```

That's it! The revocation store is now ready with automatic caching.

## How It Works

### Automatic Decorator Pattern

When you call `AddTableStorageRevocationStore()`, it automatically:

1. Creates `TableStorageRevocationStore` (handles Azure Table Storage)
2. Wraps it with `CachedRevocationStore` (adds HybridCache)
3. Registers the wrapped instance as `IRevocationStore`

```csharp
// What happens internally:
services.AddSingleton<IRevocationStore>(sp =>
{
    // 1. Create the underlying Table Storage store
    var tableStore = new TableStorageRevocationStore(
        connectionString,
        sp.GetRequiredService<ILoggerFactory>());

    // 2. Wrap it with the caching decorator
    return new CachedRevocationStore(
        tableStore,
        sp.GetRequiredService<HybridCache>(),
        sp.GetRequiredService<ILogger<CachedRevocationStore>>());
});
```

### Table Storage Schema

**Table Name**: `CertificateRevocations`

**Partition Key**: First 2 characters of serial number (hex, uppercase)
**Row Key**: Full serial number (hex, uppercase)

| PartitionKey | RowKey | SerialNumber | RevokedAt | Reason | IssuerDistinguishedName |
|--------------|--------|--------------|-----------|--------|-------------------------|
| `1A` | `1A2B3C4D5E6F` | `1A2B3C4D5E6F` | `2025-01-15T10:30:00Z` | `1` | `CN=My CA, O=Example` |
| `FF` | `FFAABBCCDDEE` | `FFAABBCCDDEE` | `2025-01-20T14:45:00Z` | `0` | `CN=My CA, O=Example` |

**Why this partition strategy?**
- Evenly distributes load across partitions
- Fast lookups (serial number is always uppercase and deterministic)
- Scales well (100 partitions for hex characters 00-FF)

### Caching Behavior

**Cache TTL**: 10 minutes

**Cached Operations**:
- `GetRevocationAsync(serialNumber)` → Caches result (both revoked and not-revoked)

**Cache Invalidation**:
- Automatic when `AddRevocationAsync()` is called
- Automatic TTL expiration after 10 minutes

**Performance Impact**:
| Scenario | Latency | Table Storage Queries |
|----------|---------|----------------------|
| First request | ~100-200ms | 1 query |
| Cached hit | ~10-50ms | 0 queries (Key Vault signing only) |
| 100 concurrent requests (same cert) | ~10-50ms | 1 query (stampede protection) |

## API Reference

### AddTableStorageRevocationStore

```csharp
public static IServiceCollection AddTableStorageRevocationStore(
    this IServiceCollection services,
    string connectionString)
```

Registers Azure Table Storage as the revocation store with automatic HybridCache decorator.

**Parameters**:
- `connectionString`: Azure Storage connection string

**Returns**: The service collection for chaining

**Throws**:
- `ArgumentNullException`: If connection string is null or empty

## Table Creation

The table `CertificateRevocations` is **automatically created** on first use if it doesn't exist.

To pre-create the table (recommended for production):

```bash
# Using Azure CLI
az storage table create \
  --name CertificateRevocations \
  --account-name myaccount

# Using Azure Storage Explorer
# Navigate to Tables → Right-click → Create Table
```

## Azure Permissions Required

The Azure identity (managed identity, service principal, or user) must have:

- **Storage Table Data Contributor** role on the Storage Account

Or assign granular permissions:
- `Microsoft.Storage/storageAccounts/tableServices/tables/read`
- `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read`
- `Microsoft.Storage/storageAccounts/tableServices/tables/entities/write`

## Usage Examples

### Revoking a Certificate

```csharp
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;

// Inject IRevocationStore
public class CertificateService
{
    private readonly IRevocationStore _revocationStore;

    public CertificateService(IRevocationStore revocationStore)
    {
        _revocationStore = revocationStore;
    }

    public async Task RevokeCertificateAsync(string serialNumber)
    {
        var record = new RevocationRecord
        {
            SerialNumber = serialNumber,
            RevokedAt = DateTime.UtcNow,
            Reason = 1, // Key compromise
            IssuerDistinguishedName = "CN=My CA, O=Example"
        };

        await _revocationStore.AddRevocationAsync(record);
        // Cache is automatically invalidated
    }
}
```

### Checking Revocation Status

```csharp
var record = await _revocationStore.GetRevocationAsync("1A2B3C4D5E6F");

if (record != null)
{
    Console.WriteLine($"Certificate revoked at {record.RevokedAt}");
    Console.WriteLine($"Reason: {record.Reason}");
}
else
{
    Console.WriteLine("Certificate is not revoked (good)");
}
```

### Listing All Revocations for an Issuer

```csharp
var revocations = await _revocationStore.GetRevocationsByIssuerAsync(
    "CN=My CA, O=Example");

foreach (var rev in revocations)
{
    Console.WriteLine($"{rev.SerialNumber} revoked at {rev.RevokedAt}");
}
```

## Local Development with Azurite

[Azurite](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite) is the Azure Storage emulator for local development.

### Using Docker

```bash
docker run -p 10002:10002 mcr.microsoft.com/azure-storage/azurite \
  azurite-table --tableHost 0.0.0.0
```

### Connection String

```json
{
  "ConnectionStrings": {
    "tables": "UseDevelopmentStorage=true"
  }
}
```

### Browse Data

Use [Azure Storage Explorer](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) to browse local Azurite tables.

## Cost Optimization

Azure Table Storage pricing (as of 2025):
- **Storage**: ~$0.045/GB/month
- **Transactions**: ~$0.00036 per 10K operations

**Cost Estimate** (10M OCSP requests/month with caching):
- Storage: < $1/month (revocation records are tiny)
- Transactions: ~$0.04/month (90%+ cache hit rate = 1M Table Storage queries)

**Total**: < $2/month for moderate traffic

**Without caching**: ~$36/month (10M queries × $0.00036/10K)

## Monitoring

Use Application Insights or Azure Monitor to track:

```csharp
// Logged by CachedRevocationStore
LogDebug("Cache hit for certificate {SerialNumber}", serialNumber);
LogDebug("Cache miss for certificate {SerialNumber}", serialNumber);

// Logged by TableStorageRevocationStore
LogDebug("Looking up revocation in Table Storage for certificate {SerialNumber}");
LogDebug("Found revocation for certificate {SerialNumber}");
LogDebug("No revocation found for certificate {SerialNumber}");
```

## Alternatives

If you don't want to use Azure Table Storage, implement `IRevocationStore`:

```csharp
using KeyVaultCa.Revocation.Interfaces;

public class MyCustomRevocationStore : IRevocationStore
{
    // Implement using SQL Server, Cosmos DB, etc.
}

// Register without automatic caching
services.AddSingleton<IRevocationStore, MyCustomRevocationStore>();

// Or manually add caching decorator
services.AddHybridCache();
services.AddSingleton<IRevocationStore>(sp =>
{
    var innerStore = new MyCustomRevocationStore();
    return new CachedRevocationStore(
        innerStore,
        sp.GetRequiredService<HybridCache>(),
        sp.GetRequiredService<ILogger<CachedRevocationStore>>());
});
```

## Troubleshooting

### Table doesn't exist error

**Error**: `The specified resource does not exist (404)`

**Fix**: The table is created automatically on first use. If you see this error, check:
- Connection string is correct
- Azure identity has proper permissions
- Network connectivity to Azure Storage

### Cache not working

**Symptoms**: High Table Storage transaction count

**Check**:
- Ensure `AddTableStorageRevocationStore()` is called (not manually registering `TableStorageRevocationStore`)
- Verify HybridCache is registered (it's automatic, but check DI container)
- Look for cache-related log entries

### Slow lookups

**Expected**: First request ~100-200ms (Table Storage + Key Vault signing)
**Cached**: Subsequent requests ~10-50ms

**If always slow**:
- Check if caching is enabled (see above)
- Verify network latency to Azure Storage
- Consider using Azure Storage private endpoints for better performance

## Related Packages

- **[KeyVaultCa.Revocation](../KeyVaultCa.Revocation/)**: Core OCSP logic and `CachedRevocationStore`
- **[KeyVaultCa.Revocation.Ocsp.Hosting](../KeyVaultCa.Revocation.Ocsp.Hosting/)**: ASP.NET Core hosting for OCSP responders
- **[KeyVaultCa.Core](../KeyVaultCa.Core/)**: Azure Key Vault signing operations

## License

See the repository root for license information.
