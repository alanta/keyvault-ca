# Implementation Plan: OCSP and CRL Support for KeyVault CA

## Overview
Add RFC 6960 (OCSP) and RFC 5280 (CRL) support to enable certificate revocation checking for B2B partner mTLS authentication. All services communicate through APIM, so OCSP/CRL endpoints will be accessible internally with option to expose publicly later.

## Key Design Decisions
- **OCSP as primary protocol** - Standards-compliant, works with .NET X509Chain automatically
- **AIA/CDP extensions in certificates** - Points to internal DNS names (e.g., `ocsp.internal.company.com`)
- **Azure Table Storage** - Cost-effective storage for revocation data
- **CLI-first revocation** - `keyvaultca revoke-cert` command, admin API can come later
- **Dedicated OCSP signing certificate** - Better security isolation than signing with CA key directly
- **Specific CLI flags over generic options** - Use `--ocsp-signing` flag instead of generic `--eku <OID>` for better UX and simplicity

## Solution Structure

### New Projects to Create

1. **KeyVaultCa.Revocation** (Class Library)
   - `Models/RevocationRecord.cs` - Entity for revoked certificates
   - `Models/RevocationReason.cs` - Enum matching RFC 5280 reason codes
   - `Interfaces/IRevocationStore.cs` - Storage abstraction
   - `CrlGenerator.cs` - CRL generation using BouncyCastle
   - `OcspResponseBuilder.cs` - OCSP response construction using BouncyCastle

2. **KeyVaultCa.Revocation.TableStorage** (Class Library)
   - `TableStorageRevocationStore.cs` - Implementation of IRevocationStore
   - `RevocationTableEntity.cs` - Azure Table entity mapping
   - Package: `Azure.Data.Tables`

3. **KeyVaultCa.OcspResponder** (ASP.NET Core 8.0 Web App)
   - `Controllers/OcspController.cs` - HTTP POST/GET endpoints
   - `Services/OcspSigningService.cs` - Signs responses via Key Vault
   - `Program.cs`, `appsettings.json`
   - Dockerfile for Azure Container Apps deployment

### Projects to Modify

4. **KeyVaultCa.Core**
   - Add AIA/CDP extension builders to `CertificateFactory.cs`
   - Add revocation config parameter to `SignRequest()` method
   - Add BouncyCastle signature factory adapter for `KeyVaultSignatureGenerator`
   - Add new OIDs to `WellKnownOids.cs`

5. **KeyVaultCa.Cli**
   - New handler: `Handlers/RevokeCert.cs`
   - New handler: `Handlers/GenerateCrl.cs`
   - Update `IssueCert.cs` and `IssueIntermediateCert.cs` to accept OCSP/CRL URL options
   - Add `--ocsp-signing` flag to `IssueCert.cs` for issuing OCSP signing certificates

## Implementation Phases

**Status Overview:**
- ✅ Phase 1: Core Models & Storage - COMPLETE
- ✅ Phase 2: Certificate Extensions (AIA/CDP) - COMPLETE
- ✅ Phase 3: CLI Revocation Command - COMPLETE
- ✅ Phase 4: CRL Generation - COMPLETE
- ✅ Phase 5: OCSP Responder Service - COMPLETE
- ✅ Unit Tests - COMPLETE (9 tests passing)
- 🔄 **Phase 6: OCSP Signing Certificate Support - READY TO IMPLEMENT**

---

### Phase 1: Core Models & Storage (Foundation) ✅ COMPLETE

**Files to create:**
- `src/KeyVaultCa.Revocation/Models/RevocationRecord.cs`
- `src/KeyVaultCa.Revocation/Models/RevocationReason.cs`
- `src/KeyVaultCa.Revocation/Interfaces/IRevocationStore.cs`
- `src/KeyVaultCa.Revocation.TableStorage/TableStorageRevocationStore.cs`
- `src/KeyVaultCa.Revocation.TableStorage/RevocationTableEntity.cs`

**Key types:**

```csharp
public class RevocationRecord
{
    public string SerialNumber { get; set; }           // Hex string (uppercase)
    public DateTimeOffset RevocationDate { get; set; }
    public RevocationReason Reason { get; set; }
    public string IssuerDistinguishedName { get; set; }
    public string? Comments { get; set; }
}

public enum RevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10
}

public interface IRevocationStore
{
    Task AddRevocationAsync(RevocationRecord record, CancellationToken ct);
    Task<RevocationRecord?> GetRevocationAsync(string serialNumber, CancellationToken ct);
    Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(string issuerDN, CancellationToken ct);
}
```

**Table Storage schema:**
- Table name: `CertificateRevocations`
- PartitionKey: First 2 chars of serial number (for distribution)
- RowKey: Full serial number (hex uppercase)

**Update `Directory.Packages.props`:**
- Add `Azure.Data.Tables` (version 12.x)

### Phase 2: Certificate Extensions

**Files to modify:**
- `src/KeyVaultCa.Core/WellKnownOids.cs`
- `src/KeyVaultCa.Core/CertificateFactory.cs`

**Changes to WellKnownOids.cs:**
```csharp
public static class Extensions
{
    public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    public const string CrlDistributionPoints = "2.5.29.31";
}

public static class AccessMethods
{
    public const string Ocsp = "1.3.6.1.5.5.7.48.1";
    public const string CaIssuers = "1.3.6.1.5.5.7.48.2";
}
```

**Changes to CertificateFactory.cs:**

Add new class:
```csharp
public class RevocationConfig
{
    public string? OcspUrl { get; set; }
    public string? CrlUrl { get; set; }
    public string? CaIssuersUrl { get; set; }
}
```

Add new parameter to `SignRequest()`:
```csharp
public static Task<X509Certificate2> SignRequest(
    byte[] csr,
    X509Certificate2 issuerCert,
    X509SignatureGenerator generator,
    DateTimeOffset notBefore,
    DateTimeOffset notAfter,
    HashAlgorithmName? hashAlgorithm = null,
    IReadOnlyList<X509Extension>? extensions = null,
    RevocationConfig? revocationConfig = null,  // NEW
    CancellationToken ct = default)
```

Add new methods (follow pattern of `BuildAuthorityKeyIdentifier`):
```csharp
private static X509Extension BuildAuthorityInformationAccessExtension(string? ocspUrl, string? caIssuersUrl)
{
    // Use AsnWriter to build AIA extension per RFC 5280 section 4.2.2.1
    // SEQUENCE of AccessDescription
    //   AccessDescription ::= SEQUENCE {
    //     accessMethod OBJECT IDENTIFIER,
    //     accessLocation GeneralName (uniformResourceIdentifier [6]) }
}

private static X509Extension BuildCrlDistributionPointsExtension(string crlUrl)
{
    // Use AsnWriter to build CDP extension per RFC 5280 section 4.2.1.13
    // DistributionPoint with fullName GeneralNames containing URI
}
```

Inside `SignRequest()`, after existing extension handling:
```csharp
// Add AIA extension if configured
if (revocationConfig != null)
{
    if (revocationConfig.OcspUrl != null || revocationConfig.CaIssuersUrl != null)
    {
        var aiaExt = BuildAuthorityInformationAccessExtension(
            revocationConfig.OcspUrl,
            revocationConfig.CaIssuersUrl);
        request.CertificateExtensions.Add(aiaExt);
    }

    // Add CDP extension if configured
    if (revocationConfig.CrlUrl != null)
    {
        var cdpExt = BuildCrlDistributionPointsExtension(revocationConfig.CrlUrl);
        request.CertificateExtensions.Add(cdpExt);
    }
}
```

### Phase 3: CLI Revocation Command

**Files to create:**
- `src/KeyVaultCa.Cli/Handlers/RevokeCert.cs`

**Structure (following IssueCert pattern):**
```csharp
public class RevokeCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(
        string serialNumber,
        RevocationReason reason,
        string? comments,
        string tableStorageConnectionString,
        CancellationToken ct)
    {
        var store = new TableStorageRevocationStore(tableStorageConnectionString, loggerFactory);

        await store.AddRevocationAsync(new RevocationRecord
        {
            SerialNumber = serialNumber.ToUpperInvariant(),
            RevocationDate = DateTimeOffset.UtcNow,
            Reason = reason,
            Comments = comments,
            IssuerDistinguishedName = "TBD" // May need to lookup cert
        }, ct);

        _logger.LogInformation("Certificate {serial} revoked", serialNumber);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        // Add options: --serial, --reason, --comments, --storage-connection
    }
}
```

**File to modify:**
- `src/KeyVaultCa.Cli/CliApp.cs` - Add `app.Command("revoke-cert", RevokeCert.Configure);`

**Add CLI options to IssueCert.cs and IssueIntermediateCert.cs:**
```csharp
var ocspUrlOpt = cmd.Option<string>("--ocsp-url <URL>",
    "OCSP responder URL for AIA extension", CommandOptionType.SingleValue);
var crlUrlOpt = cmd.Option<string>("--crl-url <URL>",
    "CRL distribution point URL", CommandOptionType.SingleValue);
```

Pass to signing:
```csharp
var revocationConfig = new RevocationConfig
{
    OcspUrl = ocspUrlOpt.Value(),
    CrlUrl = crlUrlOpt.Value()
};
```

### Phase 4: CRL Generation

**Files to create:**
- `src/KeyVaultCa.Revocation/CrlGenerator.cs`
- `src/KeyVaultCa.Revocation/BouncyCastleSignatureFactory.cs` (adapter for KeyVaultSignatureGenerator)
- `src/KeyVaultCa.Cli/Handlers/GenerateCrl.cs`

**Key implementation in CrlGenerator.cs:**
```csharp
public class CrlGenerator
{
    public async Task<byte[]> GenerateCrlAsync(
        X509Certificate2 issuerCert,
        KeyVaultSignatureGenerator signatureGenerator,
        IRevocationStore revocationStore,
        string issuerDistinguishedName,
        TimeSpan validityPeriod,
        CancellationToken ct)
    {
        // 1. Get revocations from store
        var revocations = await revocationStore.GetRevocationsByIssuerAsync(issuerDistinguishedName, ct);

        // 2. Build CRL using BouncyCastle
        var crlGen = new Org.BouncyCastle.X509.X509V2CrlGenerator();
        crlGen.SetIssuerDN(new Org.BouncyCastle.Asn1.X509.X509Name(issuerDistinguishedName));
        crlGen.SetThisUpdate(DateTime.UtcNow);
        crlGen.SetNextUpdate(DateTime.UtcNow.Add(validityPeriod));

        foreach (var rev in revocations)
        {
            var serialBigInt = new Org.BouncyCastle.Math.BigInteger(rev.SerialNumber, 16);
            crlGen.AddCrlEntry(serialBigInt, rev.RevocationDate.UtcDateTime, (int)rev.Reason);
        }

        // 3. Sign with KeyVault via adapter
        var bcSignatureFactory = new BouncyCastleSignatureFactory(signatureGenerator);
        var crl = crlGen.Generate(bcSignatureFactory);

        return crl.GetEncoded();
    }
}
```

**BouncyCastleSignatureFactory** - Adapter that implements `Org.BouncyCastle.Crypto.ISignatureFactory` and delegates to `KeyVaultSignatureGenerator`.

**GenerateCrl CLI handler** - Similar to IssueCert structure, takes issuer cert reference, output path, validity period.

**Update CliApp.cs:**
```csharp
app.Command("generate-crl", GenerateCrl.Configure);
```

### Phase 5: OCSP Responder Service

**Files to create:**
- `src/KeyVaultCa.OcspResponder/Controllers/OcspController.cs`
- `src/KeyVaultCa.OcspResponder/Services/OcspSigningService.cs`
- `src/KeyVaultCa.OcspResponder/Program.cs`
- `src/KeyVaultCa.OcspResponder/appsettings.json`
- `src/KeyVaultCa.OcspResponder/Dockerfile`

**OcspController.cs:**
```csharp
[ApiController]
[Route("")]
public class OcspController : ControllerBase
{
    private readonly OcspResponseBuilder _responseBuilder;

    [HttpPost]
    [Consumes("application/ocsp-request")]
    [Produces("application/ocsp-response")]
    public async Task<IActionResult> Post()
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        var requestBytes = ms.ToArray();

        var responseBytes = await _responseBuilder.BuildResponseAsync(requestBytes);
        return File(responseBytes, "application/ocsp-response");
    }

    // Optional GET support for base64-encoded requests
    [HttpGet("{base64Request}")]
    [Produces("application/ocsp-response")]
    public async Task<IActionResult> Get(string base64Request) { ... }
}
```

**Move OcspResponseBuilder from Phase 4 to:**
- `src/KeyVaultCa.Revocation/OcspResponseBuilder.cs`

**OcspResponseBuilder.cs:**
```csharp
public class OcspResponseBuilder
{
    private readonly IRevocationStore _revocationStore;
    private readonly KeyVaultSignatureGenerator _signatureGenerator;
    private readonly X509Certificate2 _ocspSigningCert;

    public async Task<byte[]> BuildResponseAsync(byte[] requestBytes, CancellationToken ct)
    {
        // 1. Parse OCSP request using BouncyCastle
        var ocspReq = new Org.BouncyCastle.Ocsp.OcspRequest(requestBytes);
        var certReq = ocspReq.GetRequestList()[0];
        var certId = certReq.GetCertID();
        var serialNumber = certId.SerialNumber.ToString(16).ToUpperInvariant();

        // 2. Lookup revocation status
        var revocation = await _revocationStore.GetRevocationAsync(serialNumber, ct);

        // 3. Build OCSP response
        var responseGen = new Org.BouncyCastle.Ocsp.BasicOcspRespGenerator(
            /* responder ID from OCSP cert */);

        CertificateStatus status = revocation != null
            ? new Org.BouncyCastle.Ocsp.RevokedStatus(
                revocation.RevocationDate.UtcDateTime,
                (int)revocation.Reason)
            : Org.BouncyCastle.Ocsp.CertificateStatus.Good;

        responseGen.AddResponse(certId, status);

        // 4. Sign using BouncyCastle adapter
        var bcSignatureFactory = new BouncyCastleSignatureFactory(_signatureGenerator);
        var basicResp = responseGen.Generate(bcSignatureFactory, /* cert chain */);

        // 5. Wrap in final response
        var respGen = new Org.BouncyCastle.Ocsp.OcspRespGenerator();
        var finalResp = respGen.Generate(
            Org.BouncyCastle.Ocsp.OcspRespStatus.Successful,
            basicResp);

        return finalResp.GetEncoded();
    }
}
```

**Program.cs:**
```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddHealthChecks();

// Azure authentication
var credential = new DefaultAzureCredential();

// Revocation store
var storageConnectionString = builder.Configuration["TableStorage:ConnectionString"];
builder.Services.AddSingleton<IRevocationStore>(sp =>
    new TableStorageRevocationStore(storageConnectionString, sp.GetRequiredService<ILoggerFactory>()));

// OCSP signing service
builder.Services.AddSingleton<OcspSigningService>(sp =>
{
    var keyVaultUrl = builder.Configuration["OcspSigning:KeyVaultUrl"];
    var certName = builder.Configuration["OcspSigning:CertificateName"];
    // Load cert and create KeyVaultSignatureGenerator
});

builder.Services.AddSingleton<OcspResponseBuilder>();

var app = builder.Build();
app.MapControllers();
app.MapHealthChecks("/health");
app.Run();
```

**appsettings.json:**
```json
{
  "TableStorage": {
    "ConnectionString": ""
  },
  "OcspSigning": {
    "KeyVaultUrl": "https://my-ca-vault.vault.azure.net/",
    "CertificateName": "ocsp-signer"
  }
}
```

**Dockerfile:**
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["src/KeyVaultCa.OcspResponder/*.csproj", "OcspResponder/"]
COPY ["src/KeyVaultCa.Revocation/*.csproj", "Revocation/"]
COPY ["src/KeyVaultCa.Revocation.TableStorage/*.csproj", "Revocation.TableStorage/"]
COPY ["src/KeyVaultCa.Core/*.csproj", "Core/"]
RUN dotnet restore "OcspResponder/KeyVaultCa.OcspResponder.csproj"

COPY src/ .
RUN dotnet publish "OcspResponder/KeyVaultCa.OcspResponder.csproj" -c Release -o /app/publish

FROM base AS final
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "KeyVaultCa.OcspResponder.dll"]
```

### Phase 6: OCSP Signing Certificate Support 🔄 READY TO IMPLEMENT

**Design Decision:** Use a specific `--ocsp-signing` flag instead of generic `--eku <OID>` for simplicity and better UX.

**Files to modify:**
- `src/KeyVaultCa.Cli/Handlers/IssueCert.cs`
- `src/KeyVaultCa.Core/KeyVaultCertificateProvider.cs`
- `src/KeyVaultCa.Core/KeyVaultServiceOrchestrator.cs`

**Implementation Steps:**

1. **Add --ocsp-signing flag to IssueCert.cs** (in `Configure` method):
```csharp
var ocspSigningOption = cmd.Option("--ocsp-signing",
    "Add OCSP Signing Extended Key Usage (EKU) extension (OID 1.3.6.1.5.5.7.3.9)",
    CommandOptionType.NoValue);
```

2. **Update Execute signature** to accept `bool ocspSigning` parameter

3. **Pass flag through execution chain**:
   - IssueCert.Execute() → KeyVaultCertificateProvider.IssueCertificate() → KeyVaultServiceOrchestrator.IssueCertificateAsync()

4. **Build EKU extension conditionally** in KeyVaultServiceOrchestrator.IssueCertificateAsync():
```csharp
if (ocspSigning)
{
    extensions.Add(new X509EnhancedKeyUsageExtension(
        new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.OCSPSigning) },
        critical: true));  // RFC 6960 requires critical=true
}
```

**Create OCSP signing cert:**
```bash
keyvaultca issue-cert \
  --issuer root-ca@my-vault \
  --ocsp-signing \
  ocsp-signer@my-vault
```

**Note:** The OID `1.3.6.1.5.5.7.3.9` is already defined in `WellKnownOids.ExtendedKeyUsages.OCSPSigning`

## Deployment

### Azure Resources Needed
1. **Azure Table Storage** - For revocation data
2. **Azure Container Apps** - Host OCSP responder
3. **Azure Container Registry** - Store OCSP responder image
4. **APIM endpoint** - Route `/ocsp` to Container App

### Container App Deployment
```bash
# Build and push
docker build -f src/KeyVaultCa.OcspResponder/Dockerfile -t myacr.azurecr.io/ocsp-responder:latest .
docker push myacr.azurecr.io/ocsp-responder:latest

# Deploy to Container Apps
az containerapp create \
  --name ocsp-responder \
  --resource-group my-rg \
  --environment my-env \
  --image myacr.azurecr.io/ocsp-responder:latest \
  --target-port 8080 \
  --ingress internal \
  --env-vars \
    TableStorage__ConnectionString=secretref:storage-connection \
    OcspSigning__KeyVaultUrl=https://my-ca-vault.vault.azure.net/ \
    OcspSigning__CertificateName=ocsp-signer

# Assign managed identity for Key Vault access
az containerapp identity assign --name ocsp-responder --resource-group my-rg --system-assigned
```

### APIM Integration
Create API in APIM that proxies to Container App internal endpoint:
- Backend: Container App FQDN
- Path: `/ocsp` → forward to Container App `/`

### DNS Setup
Create internal DNS records:
- `ocsp.internal.company.com` → APIM endpoint
- `crl.internal.company.com` → APIM endpoint (or Azure Blob Storage if CRL hosted separately)

## Testing Strategy

### Unit Tests
- Extension building (AIA, CDP) in CertificateFactory
- Revocation storage (TableStorageRevocationStore with Azurite)
- OCSP request parsing and response building
- CRL generation

### Integration Tests
- Issue cert with OCSP/CRL URLs, verify extensions present
- Revoke cert via CLI, verify in Table Storage
- Generate CRL, verify serial number in output
- Call OCSP responder, verify response format

### End-to-End Test
1. Create OCSP signing certificate
2. Issue test certificate with AIA/CDP extensions
3. Deploy OCSP responder locally (Azurite + mock Key Vault)
4. Validate certificate with .NET X509Chain (should succeed)
5. Revoke certificate
6. Validate again (should fail with revoked status)
7. Test with OpenSSL: `openssl ocsp -issuer ca.pem -cert test.pem -url http://localhost:5000`

## Critical Files Modified

### Core Library
- `src/KeyVaultCa.Core/CertificateFactory.cs` - Add AIA/CDP extension builders, RevocationConfig parameter
- `src/KeyVaultCa.Core/WellKnownOids.cs` - Add AIA, CDP OIDs
- `src/KeyVaultCa.Core/KeyVaultServiceOrchestrator.cs` - Thread RevocationConfig through signing methods

### CLI
- `src/KeyVaultCa.Cli/Handlers/IssueCert.cs` - Add --ocsp-url, --crl-url, --ocsp-signing options
- `src/KeyVaultCa.Cli/Handlers/IssueIntermediateCert.cs` - Add --ocsp-url, --crl-url options
- `src/KeyVaultCa.Cli/CliApp.cs` - Register new commands

## Success Criteria

✅ Certificates issued with `--ocsp-url` contain AIA extension pointing to OCSP responder
✅ Certificates issued with `--crl-url` contain CDP extension pointing to CRL
✅ `keyvaultca revoke-cert --serial ABC123` stores revocation in Table Storage
✅ OCSP responder returns "good" for non-revoked certs, "revoked" for revoked certs
✅ `keyvaultca generate-crl` produces valid CRL with revoked certificates
✅ ASP.NET Core services using `X509Chain` with `RevocationMode.Online` automatically check OCSP
✅ No custom configuration needed in API services (AIA extension does the work)

## Future Enhancements (Out of Scope)
- Web UI for revocation management
- Automated CRL publishing to Azure Blob Storage
- Background job for scheduled CRL generation
- OCSP stapling support
- Metrics/monitoring for OCSP responder
- Bulk revocation API
- Certificate metadata tracking (link to customer/agent IDs)