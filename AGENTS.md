# Project Guidelines

## Architecture

Layered .NET library for Azure Key Vault-based Certificate Authority operations (issuance, OCSP, CRL).

**Dependency direction** (strict — never reverse):
```
KeyVaultCa.Core                    ← Foundation, no project references
  ↑
KeyVaultCa.Revocation             ← OCSP/CRL logic, IRevocationStore interface
  ↑
KeyVaultCa.Revocation.KeyVault   ← IRevocationStore impl using KV certificate tags
KeyVaultCa.Revocation.Ocsp.Hosting ← ASP.NET Core OCSP endpoints
  ↑
KeyVaultCa.Cli                    ← CLI tool (depends on all above)
```

**Core must never depend on Revocation.** If revocation types are needed in Core, extract an interface or move the type.

**Separate assemblies for integrations**: External system integrations (e.g., Key Vault, Table Storage) and optional functionality must be isolated in separate projects following the pattern `KeyVaultCa.<Area>.<System>`. This enables consumers to reference only what they need and keeps core abstractions free from implementation dependencies.

**Revocation storage**: Certificate tags in Azure Key Vault (no Table Storage). Tags: `SerialNumber`, `Revoked`, `RevokedDate`, `RevocationReason`, `IssuerDN`, `RevocationComments`. See [`KeyVaultRevocationStore.cs`](src/KeyVaultCa.Revocation.KeyVault/KeyVaultRevocationStore.cs). See [ADR-0001](Docs/adr/0001-tag-based-revocation-storage.md) for design rationale.

## Code Style

- **Target**: `net10.0`, C# 12, `<Nullable>enable</Nullable>`
- **ImplicitUsings**: `disable` in Core and Revocation libraries; `enable` in CLI, tests, hosting
- **Fields**: `_camelCase`; **Constants**: `PascalCase`; **Async methods**: `Async` suffix
- **Primary constructors**: CLI handlers and simple classes; traditional constructors for domain classes with multiple fields
- **Guard clauses**: `ArgumentNullException.ThrowIfNull()`
- **Async**: Always accept `CancellationToken ct = default`
- **OID constants**: Centralized in [`WellKnownOids.cs`](src/KeyVaultCa.Core/WellKnownOids.cs) — never hardcode OID strings
- **Central package management**: All versions in [`Directory.Packages.props`](Directory.Packages.props)

## Build and Test

```bash
dotnet build keyvault-ca.sln
dotnet test keyvault-ca.sln
dotnet build test/mTLS/mTls.sln          # Aspire-based end-to-end test
```

## Test Conventions

- **Frameworks**: xUnit + FakeItEasy + Shouldly
- **Class naming**: `When_<scenario>` (e.g., `When_generating_a_crl`)
- **Method naming**: `It_should_<expected>` or `Should_<expected>`
- **Shared helpers**: [`TestBase`](src/KeyVaultCa.Revocation.Tests/TestBase.cs) for certificate/mock creation
- **Key Vault fakes**: [`CertificateStore`](src/KeyVaultCa.Tests/KeyVault/) wraps in-memory `CertificateClient`

## CLI Commands

Each command is a handler class in [`src/KeyVaultCa.Cli/Handlers/`](src/KeyVaultCa.Cli/Handlers/):
- Static `Configure(CommandLineApplication cmd)` method registered in [`CliApp.cs`](src/KeyVaultCa.Cli/Handlers/CliApp.cs)
- Primary constructor takes `ILoggerFactory`
- Shared options via [`CommonOptions.cs`](src/KeyVaultCa.Cli/Handlers/CommonOptions.cs) extension methods
- Key Vault references parsed as `name@vault` via `KeyVaultSecretReference`

## DI Extension Patterns

- Extension methods on `IServiceCollection`, return `IServiceCollection` for chaining
- `AddKeyVaultRevocationStore(Uri)` wraps store with `CachedRevocationStore` + `HybridCache`
- `AddKeyVaultOcspResponder(IConfiguration)` binds `OcspHostingOptions` and loads certs at startup
- `Func<Uri, CertificateClient>` factory pattern for `CertificateClient` (not direct injection)
- `DefaultAzureCredential` with interactive browser excluded

## End-to-End Tests (`test/mTLS/`)

Aspire-orchestrated mTLS test suite validating the full certificate lifecycle. Separate solution at `test/mTLS/mTls.sln`.

- **AppHost**: Aspire orchestrator — defines all resources in `AppHost.cs`
- **ApiServer**: WebAPI secured with mTLS
- **ClientApp**: Console app calling the API with a client certificate
- **OcspResponder**: ASP.NET Core OCSP endpoint backed by `KeyVaultRevocationStore`
- Run with `aspire run` from the `test/mTLS` directory
- See [`test/mTLS/AGENTS.md`](test/mTLS/AGENTS.md) for Aspire-specific agent instructions

## Key Libraries

- **BouncyCastle** (`Portable.BouncyCastle`): ASN.1, OCSP responses, CRL generation
- **System.Security.Cryptography**: X.509 certificate creation, `X509SignatureGenerator`
- **Azure.Security.KeyVault.Certificates/Keys**: Key Vault operations
- **McMaster.Extensions.Hosting.CommandLine**: CLI framework
