# KeyVaultCa.Revocation

Core OCSP (Online Certificate Status Protocol) response building logic with RFC 6960 compliance and optional caching support.

## Features

- ✅ **RFC 6960 compliant**: Full OCSP protocol implementation
- ✅ **Issuer validation**: Validates `issuerNameHash` and `issuerKeyHash` (prevents answering for certificates not issued by your CA)
- ✅ **Nonce support**: Extracts and echoes nonces to prevent replay attacks
- ✅ **"nocheck" extension**: Required extension for OCSP signing certificates
- ✅ **Multiple hash algorithms**: Supports SHA-1, SHA-256, SHA-384, SHA-512
- ✅ **Decorator pattern caching**: Optional HybridCache decorator for performance
- ✅ **Security hardened**: Constant-time comparisons, DoS protection, proper error codes

## Package Structure

This package contains the core OCSP logic without any hosting or storage dependencies:

```
KeyVaultCa.Revocation
├── OcspResponseBuilder.cs          # RFC 6960 OCSP response builder
├── CrlGenerator.cs                 # X.509 CRL generation
├── BouncyCastleSignatureFactory.cs # BouncyCastle ↔ Key Vault signing adapter
├── CachedRevocationStore.cs        # HybridCache decorator for IRevocationStore
├── Interfaces/
│   └── IRevocationStore.cs         # Revocation store abstraction
└── Models/
    ├── RevocationRecord.cs          # Revocation data model
    └── RevocationReason.cs          # RFC 5280 revocation reason codes
```

## Quick Start

### 1. Install Package

```bash
dotnet add package KeyVaultCa.Revocation
```

### 2. Implement IRevocationStore

```csharp
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;

public class MyRevocationStore : IRevocationStore
{
    public async Task<RevocationRecord?> GetRevocationAsync(
        string serialNumber,
        CancellationToken ct = default)
    {
        // Query your database/storage for revocation record
        // Return null if certificate is not revoked
    }

    public async Task AddRevocationAsync(
        RevocationRecord record,
        CancellationToken ct = default)
    {
        // Store revocation record in your database/storage
    }

    public async Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(
        string issuerDistinguishedName,
        CancellationToken ct = default)
    {
        // Query all revocations for a specific issuer (for CRL generation, etc.)
    }
}
```

### 3. Build OCSP Responses

```csharp
using KeyVaultCa.Revocation;
using KeyVaultCa.Core; // For KeyVaultSignatureGenerator

var revocationStore = new MyRevocationStore();
var signatureGenerator = new KeyVaultSignatureGenerator(/* ... */);
var ocspSigningCert = /* Load OCSP signing certificate */;
var issuerCert = /* Load CA certificate */;

var responseBuilder = new OcspResponseBuilder(
    revocationStore,
    signatureGenerator,
    ocspSigningCert,
    issuerCert,
    logger,
    responseValidityMinutes: 10);

// Process OCSP request
byte[] requestBytes = /* Receive from HTTP POST body or decode from GET URL */;
byte[] responseBytes = await responseBuilder.BuildResponseAsync(
    requestBytes,
    cancellationToken);

// Return responseBytes with content-type: application/ocsp-response
```

## OcspResponseBuilder - RFC 6960 Implementation

### Critical Security Features (RFC 6960 Phase 1 + 2)

The `OcspResponseBuilder` implements the following critical RFC 6960 requirements:

#### 1. Issuer Validation (RFC 6960 Section 4.1.1)
```csharp
// Validates issuerNameHash and issuerKeyHash from CertID
// Prevents answering for certificates not issued by your CA
// Uses constant-time comparison to prevent timing attacks
```

**Security Impact**: Without this, someone could ask about a Let's Encrypt certificate and get a "good" response, falsely suggesting you vouch for certificates you never issued.

#### 2. "nocheck" Extension (RFC 6960 Section 4.2.2.2.1)
```csharp
// Adds id-pkix-ocsp-nocheck extension (1.3.6.1.5.5.7.48.1.5)
// Prevents infinite validation loops
```

**Security Impact**: Clients could attempt to validate the OCSP signing cert via the same OCSP responder, causing infinite loops.

#### 3. Nonce Handling (RFC 6960 Appendix B)
```csharp
// Extracts nonce from request (OID 1.3.6.1.5.5.7.48.1.2)
// Echoes it back in response
// Prevents replay attacks
```

**Security Impact**: Clients can't prevent replay attacks when they provide a nonce if it's not echoed correctly.

#### 4. Request Size Limits (RFC 6960 Appendix A.1)
- POST requests: 64KB max (enforced at HTTP level via `RequestSizeLimitAttribute`)
- GET requests: 1KB max (base64-encoded, enforced before decoding)

**Security Impact**: DoS protection - prevents attackers from exhausting memory with huge requests.

#### 5. EKU Validation
```csharp
// Validates OCSP signing certificate has id-kp-OCSPSigning EKU
// OID: 1.3.6.1.5.5.7.3.9
```

**Security Impact**: Ensures only certificates explicitly authorized for OCSP signing can be used.

#### 6. Error Status Codes (RFC 6960 Section 4.2.3)
- `MalformedRequest`: ASN.1 parsing errors, unsupported hash algorithms, multiple requests
- `Unauthorized`: Certificate not issued by this CA (issuer validation failure)
- `InternalError`: Unexpected errors during processing

### Supported Hash Algorithms

The response builder supports the following hash algorithms for `CertID`:

- SHA-1 (OID: 1.3.14.3.2.26)
- SHA-256 (OID: 2.16.840.1.101.3.4.2.1)
- SHA-384 (OID: 2.16.840.1.101.3.4.2.2)
- SHA-512 (OID: 2.16.840.1.101.3.4.2.3)

All responses are signed using SHA-256.

## CachedRevocationStore - Decorator Pattern

The `CachedRevocationStore` is a decorator that adds HybridCache to any `IRevocationStore` implementation.

### Features

- **Stampede protection**: Multiple concurrent requests for the same serial number trigger only one backend lookup
- **Automatic**: Caches both "revoked" and "not revoked" states
- **Async-first**: Uses `HybridCache.GetOrCreateAsync()`
- **TTL**: 10-minute cache expiration (configurable in future versions)
- **Invalidation**: Automatic cache clearing when certificates are revoked

### Usage Example

```csharp
using KeyVaultCa.Revocation;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

// Add HybridCache
services.AddHybridCache();

// Register your store implementation
var innerStore = new MyRevocationStore();

// Wrap it with the caching decorator
services.AddSingleton<IRevocationStore>(sp =>
{
    return new CachedRevocationStore(
        innerStore,
        sp.GetRequiredService<HybridCache>(),
        sp.GetRequiredService<ILogger<CachedRevocationStore>>());
});
```

### Performance Benefits

**Without caching**:
- Every OCSP request queries the backend store (e.g., Table Storage, database)
- Typical latency: 50-200ms per lookup

**With caching**:
- First request: Queries backend + populates cache
- Subsequent requests: Served from cache (< 1ms for in-memory)
- **Stampede protection**: 100 concurrent requests for the same cert = 1 backend query

### Cache Behavior

**Cached Operations**:
- `GetRevocationAsync(serialNumber)` - Caches by serial number (both revoked and not-revoked)

**Not Cached**:
- `GetRevocationsByIssuerAsync()` - Admin operation, freshness more important

**Cache Invalidation**:
- Automatic when `AddRevocationAsync()` is called
- Automatic TTL expiration (10 minutes)

### Why Not HTTP-Level Caching?

Previously, this package used ASP.NET Core Output Caching at the HTTP level. This was removed because:

1. **RFC 6960 nonces**: Each response must echo the client's nonce
   - HTTP cache key = CertID only (no nonce)
   - Cached responses would return wrong nonces
   - This defeats replay attack prevention

2. **Fresh signatures**: OCSP responses should be freshly signed
   - Each response has unique `thisUpdate`/`producedAt` timestamps
   - Caching entire responses violates this principle

3. **Better separation**: Caching at the store level is cleaner
   - HTTP layer handles protocol (nonce, signatures, timestamps)
   - Store layer handles data access (cached lookups)

## Revocation Record Model

```csharp
public class RevocationRecord
{
    public required string SerialNumber { get; set; }              // Certificate serial number (hex, uppercase)
    public required DateTimeOffset RevocationDate { get; set; }    // When the certificate was revoked
    public required RevocationReason Reason { get; set; }          // RFC 5280 revocation reason
    public required string IssuerDistinguishedName { get; set; }   // Issuer DN
    public string? Comments { get; set; }                          // Optional revocation comments
}
```

### CRL Reason Codes

- `0`: Unspecified
- `1`: Key compromise
- `2`: CA compromise
- `3`: Affiliation changed
- `4`: Superseded
- `5`: Cessation of operation
- `6`: Certificate hold
- `8`: Remove from CRL (for delta CRLs)
- `9`: Privilege withdrawn
- `10`: AA compromise

## Architecture

This package fits into the KeyVaultCa toolkit as the core OCSP logic layer:

```
┌──────────────────────────────────────┐
│ KeyVaultCa.Revocation.Ocsp.Hosting   │ ← HTTP hosting (ASP.NET Core)
└──────────────────────────────────────┘
              ↓ depends on
┌──────────────────────────────────────┐
│   KeyVaultCa.Revocation              │ ← This package (core OCSP/CRL logic)
│   - OcspResponseBuilder              │
│   - CrlGenerator                     │
│   - CachedRevocationStore            │
│   - IRevocationStore                 │
└──────────────────────────────────────┘
         ↑ implements              ↓ depends on
┌────────────────────────┐  ┌──────────────────────────────────┐
│ Revocation.KeyVault    │  │   KeyVaultCa.Core                │
│ - KeyVault tags store  │  │   - KeyVaultSignatureGenerator   │
└────────────────────────┘  └──────────────────────────────────┘
```

## Dependencies

- **Microsoft.Extensions.Caching.Hybrid** (9.3.0+): For `CachedRevocationStore`
- **Microsoft.Extensions.Logging.Abstractions** (9.0.3+): For logging
- **Portable.BouncyCastle** (1.9.0+): For ASN.1 parsing and OCSP structures
- **KeyVaultCa.Core**: For `ISignatureGenerator` abstraction

## Testing

See `KeyVaultCa.Revocation.Tests` for comprehensive unit tests covering:

- OCSP response building for "good" and "revoked" certificates
- Issuer validation (correct and incorrect issuer hashes)
- Nonce extraction and echo
- "nocheck" extension presence
- Error handling (malformed requests, empty requests)

## Related Packages

- **[KeyVaultCa.Revocation.Ocsp.Hosting](../KeyVaultCa.Revocation.Ocsp.Hosting/)**: ASP.NET Core hosting for OCSP responders
- **[KeyVaultCa.Revocation.KeyVault](../KeyVaultCa.Revocation.KeyVault/)**: Azure Key Vault certificate tags `IRevocationStore` implementation (recommended)
- **[KeyVaultCa.Core](../KeyVaultCa.Core/)**: Azure Key Vault signing and certificate operations

## License

See the repository root for license information.
