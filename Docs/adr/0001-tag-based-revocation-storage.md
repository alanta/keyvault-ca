# ADR-0001: Tag-Based Revocation Storage Using Key Vault Certificate Tags

**Status:** Accepted  
**Date:** 2026-02-16  
**Context:** PR #11 (OCSP/CRL Support)

## Context

The KeyVault CA library requires persistent storage for certificate revocation metadata to support OCSP responders and CRL generation. This metadata includes:
- Serial number
- Revocation status
- Revocation date and reason
- Issuer DN
- Revocation comments

The initial design used Azure Table Storage as a separate persistence layer. During PR review, an alternative approach was proposed: storing revocation metadata directly as tags on Key Vault certificates.

**Project Scope:** This is a library/toolkit for small-to-medium scale certificate operations, not intended for full-scale production CA deployments serving millions of certificates.

## Decision

We will store certificate revocation metadata as **Key Vault certificate tags** and provide an abstraction (`IRevocationStore`) to enable alternative implementations.

### Implementation

1. **Tag Schema:** Each certificate has the following tags:
   - `SerialNumber`: Hex-encoded certificate serial number
   - `Revoked`: `"true"` or `"false"`
   - `RevokedDate`: ISO 8601 timestamp (when revoked)
   - `RevocationReason`: Integer (RFC 5280 CRLReason enumeration)
   - `IssuerDN`: Distinguished name of issuing CA
   - `RevocationComments`: Optional human-readable notes

2. **Abstraction:** `IRevocationStore` interface in `KeyVaultCa.Revocation` enables alternative storage backends

3. **Default Implementation:** `KeyVaultRevocationStore` in separate project `KeyVaultCa.Revocation.KeyVault`

4. **Performance Mitigation:** `CachedRevocationStore` decorator with `HybridCache` (5-minute expiry, 1-minute local cache) reduces Key Vault API calls

5. **Migration:** `backfill-serial-tags` CLI command for adding tags to existing certificates

6. **Project Structure:** Integration with specific systems (Key Vault, Table Storage, etc.) is isolated in separate assemblies following the pattern `KeyVaultCa.Revocation.<System>`. This aligns with the general architectural principle that optional functionality and external system integrations should be in separate projects.

### Alternatives Considered

- **Azure Table Storage:** Original design, rejected due to infrastructure complexity (separate storage account/emulator, cross-service queries)
- **Cosmos DB / SQL Database:** Beyond project scope — this library targets small-to-medium deployments, not enterprise-scale CAs

## Consequences

### Positive
- **Single source of truth:** Revocation data lives with the certificate
- **Simplified infrastructure:** No separate storage account, no Azurite in tests
- **Data locality:** Revocation metadata is co-located with certificate data
- **Reduced operational complexity:** One fewer Azure resource to manage
- **Aligns with project scope:** Key Vault is already required; no additional dependencies

### Negative
- **Key Vault tag limits:** 50 tags per certificate, 256 characters per tag value
- **Query performance:** Listing all certificates for issuer-based queries depends on Key Vault pagination
- **No secondary indexes:** Cannot efficiently query by arbitrary fields beyond what Key Vault provides
- **Scalability ceiling:** Key Vault throttling limits (list operations are relatively expensive)

### Mitigations
- **Caching:** `HybridCache` significantly reduces query load for OCSP/CRL generation
- **Scope alignment:** Not designed for million-certificate CAs; appropriate for development, testing, and small-scale internal PKI

### Trade-offs
- Cost model shifts from Storage transactions (~$0.0004 per 10K operations) to Key Vault operations (~$0.03 per 10K transactions)
- For the target use case (hundreds to low thousands of certificates), this trade-off is acceptable

## Related Decisions
- **Architectural Principle:** External system integrations and optional functionality are isolated in separate assemblies (see `AGENTS.md`)

## References
- PR #11: https://github.com/alanta/keyvault-ca/pull/11
- `KeyVaultRevocationStore.cs`: Implementation
- RFC 5280: X.509 Certificate and CRL Profile
- RFC 6960: OCSP Protocol
