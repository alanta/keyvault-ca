# ACME Protocol Support for KeyVault-CA

## Executive Summary

The ACME (Automatic Certificate Management Environment) protocol ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)) is an industry-standard protocol for automating certificate issuance and renewal. It's the protocol behind Let's Encrypt and is supported by major web servers (Caddy, Traefik, Nginx, Apache) and clients (certbot, acme.sh).

**Recommendation**: ACME support is highly feasible and would significantly enhance KeyVault-CA's value proposition by enabling automated certificate lifecycle management for mTLS deployments.

**Estimated Effort**: 8-9 weeks for full implementation with 3 challenge types and production hardening.

**Key Benefit**: Organizations could use tools like Traefik, certbot, or acme.sh to automatically obtain and renew certificates from this CA, eliminating manual certificate management.

---

## What is ACME?

ACME automates the certificate lifecycle:
1. **Account Registration**: Client creates account with CA
2. **Order Creation**: Client requests certificate for domain(s)
3. **Domain Validation**: Client proves control via challenges (HTTP-01, DNS-01, TLS-ALPN-01)
4. **Certificate Issuance**: CA signs CSR and returns certificate
5. **Renewal**: Automated before expiration

**Key Technical Characteristics**:
- REST API with JSON payloads (not binary like OCSP)
- JWS (JSON Web Signature) request authentication using account keys
- Challenge-based domain ownership validation
- Nonce-based replay protection
- Stateful protocol with order lifecycle management

**Recent Development (2025)**: RFC 9773 adds ACME Renewal Information (ARI) for CA-suggested renewal windows, supporting upcoming 47-day certificate lifetime limits by 2029.

---

## Feasibility Assessment

### Strengths of Current Architecture

✅ **Solid Foundation**: Existing components provide excellent building blocks:
- **Certificate Issuance**: [KeyVaultServiceOrchestrator.cs](../src/KeyVaultCa.Core/KeyVaultServiceOrchestrator.cs) `SignRequestAsync()` can be reused for ACME order finalization
- **CSR Processing**: [CertificateFactory.cs](../src/KeyVaultCa.Core/CertificateFactory.cs) `SignRequest()` handles PKCS#10 CSRs
- **Web Service Pattern**: [OcspResponder](../src/KeyVaultCa.OcspResponder/) establishes ASP.NET Core pattern to follow
- **Storage Pattern**: [TableStorageRevocationStore.cs](../src/KeyVaultCa.Revocation.TableStorage/TableStorageRevocationStore.cs) demonstrates Azure Table Storage integration
- **Revocation Infrastructure**: OCSP/CRL URLs can be embedded in ACME-issued certificates

✅ **Azure-Native**: Key Vault for signing, Table Storage for state, App Service for hosting

✅ **Modular Design**: Clean separation between Core, CLI, and web services

### Challenges to Address

⚠️ **Authentication Model**: ACME uses account key-based JWS signing (not Azure AD)
- Current services use `DefaultAzureCredential` for Azure resources
- ACME requires validating JWS signatures from client public keys

⚠️ **Stateful Protocol**: ACME requires persistent state management
- Need to store: accounts, orders, authorizations, challenges, nonces
- Current system is primarily CLI-driven with minimal state

⚠️ **Challenge Validation**: Requires external HTTP/DNS requests
- HTTP-01: Must fetch `http://{domain}/.well-known/acme-challenge/{token}`
- DNS-01: Must query DNS TXT records at `_acme-challenge.{domain}`
- TLS-ALPN-01: Must validate TLS connections with ALPN extension

⚠️ **Network Accessibility**:
- Current OCSP responder assumes network isolation
- HTTP-01 validation requires CA to make outbound HTTP requests to client domains
- Consider security implications of outbound requests

---

## Proposed Architecture

### New Projects

**1. KeyVaultCa.Acme** (Class Library)
- Core ACME protocol logic (RFC 8555 implementation)
- JWS validation and signing
- Challenge validators (HTTP-01, DNS-01, TLS-ALPN-01)
- Order lifecycle management
- Domain validation logic
- No Azure-specific dependencies

**2. KeyVaultCa.Acme.TableStorage** (Class Library)
- Azure Table Storage implementation for ACME state
- Stores: accounts, orders, authorizations, challenges, nonces
- Follows pattern from `KeyVaultCa.Revocation.TableStorage`

**3. KeyVaultCa.AcmeServer** (ASP.NET Core Web API)
- REST API implementing ACME endpoints
- Similar to `KeyVaultCa.OcspResponder`
- Deployable to Azure App Service or Container Apps
- Integrates with existing certificate issuance via `KeyVaultServiceOrchestrator`

### Integration Points

```
ACME Client (certbot/acme.sh)
    ↓ HTTP POST (JWS-signed)
AcmeServer Controllers
    ↓ Validate JWS, manage order lifecycle
KeyVaultServiceOrchestrator.SignRequestAsync()
    ↓ Sign CSR using Key Vault
Azure Key Vault (CA private key)
    ↓ Return signed certificate
ACME Client (receives certificate with OCSP/CRL URLs)
```

### Data Storage Design

**Azure Table Storage Tables**:

| Table | PartitionKey | RowKey | Purpose |
|-------|-------------|---------|---------|
| AcmeAccounts | "account" | Account ID | Store account public keys, contact info |
| AcmeOrders | Account ID | Order ID | Track certificate orders and status |
| AcmeAuthorizations | Order ID | Authorization ID | Domain authorization records |
| AcmeChallenges | Authorization ID | Challenge ID | Challenge tokens and validation status |
| AcmeNonces | "nonce" | Nonce value | Replay protection (30-minute TTL) |

### ACME Endpoints (RFC 8555)

```
GET  /directory                    - Service discovery
GET  /acme/new-nonce              - Get replay-protection nonce
POST /acme/new-account            - Create/retrieve account
POST /acme/new-order              - Request certificate
POST /acme/authz/{id}             - Get authorization status
POST /acme/challenge/{id}         - Trigger challenge validation
POST /acme/finalize/{id}          - Submit CSR
POST /acme/cert/{id}              - Download certificate
POST /acme/revoke-cert            - Revoke certificate
```

---

## Implementation Phases

### Phase 1: Core Infrastructure (Weeks 1-2)
**Deliverables**:
- Create `KeyVaultCa.Acme` project with core models
- Implement JWS validation (RS256, ES256, ES384, ES512)
- Implement nonce management for replay protection
- Create storage interfaces (`IAcmeAccountStore`, `IAcmeNonceStore`)
- Implement Table Storage adapters
- Unit tests for JWS and nonce management

**Success Criteria**: JWS validation works with test vectors, nonce generation prevents replay attacks

### Phase 2: ACME Server & Account Management (Weeks 2-3)
**Deliverables**:
- Create `KeyVaultCa.AcmeServer` ASP.NET Core project
- Implement directory endpoint
- Implement account creation and management
- JWS validation middleware
- Nonce injection middleware
- Configuration via appsettings.json

**Success Criteria**: ACME clients can create accounts and retrieve directory

### Phase 3: Order & Authorization Management (Weeks 3-4)
**Deliverables**:
- Implement order creation and lifecycle
- Create authorization and challenge entities
- Order status endpoints
- Order state machine (pending → ready → processing → valid)

**Success Criteria**: Clients can create orders with multiple identifiers

### Phase 4: HTTP-01 Challenge Validation (Weeks 4-5)
**Deliverables**:
- Implement HTTP-01 challenge validator
- Background validation service (async challenge processing)
- Challenge trigger endpoint
- Domain allowlist/blocklist configuration

**Success Criteria**: HTTP-01 challenges validate successfully, authorization becomes valid

### Phase 5: Certificate Finalization (Weeks 5-6)
**Deliverables**:
- Implement CSR validation
- Integrate with `KeyVaultServiceOrchestrator.SignRequestAsync()`
- Certificate download endpoint (PEM format)
- Include OCSP/CRL URLs in issued certificates

**Success Criteria**: End-to-end certificate issuance with certbot/acme.sh

### Phase 6: DNS-01 & TLS-ALPN-01 (Weeks 6-7)
**Deliverables**:
- DNS-01 validator (TXT record validation)
- TLS-ALPN-01 validator
- Wildcard certificate support (requires DNS-01)

**Success Criteria**: Wildcard certificates work with DNS-01 validation

### Phase 7: Production Hardening (Weeks 7-8)
**Deliverables**:
- Rate limiting (per account, per IP, per domain)
- External Account Binding (EAB) for restricted registration
- Certificate revocation endpoint
- Account key rollover
- Security hardening and audit logging
- Health checks and monitoring

**Success Criteria**: System handles 100+ concurrent orders, rate limits enforce policies

### Phase 8: Documentation & Deployment (Week 8-9)
**Deliverables**:
- Deployment guide (Azure App Service, Container Apps)
- Client integration guides (certbot, acme.sh, Traefik, Caddy)
- Configuration reference
- Security best practices
- ARM/Bicep templates

**Success Criteria**: Deployable to Azure with complete documentation

---

## Security Considerations

### 1. Domain Validation Security
- **CAA Record Checking**: Verify CAA DNS records before issuance
- **Domain Allowlist/Blocklist**: Configurable domain restrictions
- **High-Risk TLD Blocking**: Reject suspicious TLDs
- **Private IP Rejection**: Prevent HTTP-01 validation to RFC 1918 addresses (prevent SSRF)
- **Redirect Limiting**: Max 5 redirects during HTTP-01 validation

### 2. Rate Limiting (Abuse Prevention)
- Per-account: 50 orders/day, 5 orders/hour
- Per-IP: 100 new-nonce/hour, 10 new-account/hour
- Per-domain: 5 certificates/domain/week
- Consider Azure API Management for advanced rate limiting

### 3. Authentication & Authorization
- **JWS Validation**: All POST requests must be JWS-signed
- **Nonce Management**: Single-use, 30-minute expiration
- **External Account Binding (EAB)**: Optional pre-registration requirement for restricted CAs
- **Account Key Rollover**: Dual-signature proof required

### 4. Network Security
- **Outbound HTTP Filtering**: Validate destination IPs before HTTP-01 requests
- **DNS Security**: Query multiple authoritative nameservers for DNS-01
- **TLS Validation**: Strict ALPN extension validation for TLS-ALPN-01
- **Consider**: Deploy behind Azure Application Gateway with WAF

### 5. CSR Validation
- Verify CSR signature
- Validate public key matches order identifiers
- Minimum key size enforcement (2048-bit RSA)
- Reject CSRs with malicious extensions

---

## Configuration Design

### Key Configuration Settings

```json
{
  "AcmeServer": {
    "BaseUrl": "https://acme.internal.company.com",
    "ExternalAccountBindingRequired": false,

    "ChallengeTypes": {
      "Http01Enabled": true,
      "Dns01Enabled": true,
      "TlsAlpn01Enabled": false
    },

    "DomainValidation": {
      "AllowedDomains": ["*.internal.company.com"],
      "BlockedDomains": [],
      "CheckCAA": true
    },

    "RateLimits": {
      "MaxOrdersPerDay": 50,
      "MaxOrdersPerHour": 5,
      "MaxNewAccountsPerIpPerHour": 10
    }
  },

  "Issuer": {
    "KeyVaultUrl": "https://my-ca-vault.vault.azure.net/",
    "CertificateName": "intermediate-ca"
  },

  "Revocation": {
    "OcspUrl": "https://ocsp.internal.company.com",
    "CrlUrl": "https://crl.internal.company.com/ca.crl"
  }
}
```

---

## Technical Challenges & Solutions

### Challenge 1: JWS Validation Complexity
**Solution**: Use `System.IdentityModel.Tokens.Jwt` library for JWS parsing, support multiple algorithms (RS256, ES256, ES384, ES512), implement middleware for automatic validation on all protected endpoints.

### Challenge 2: Asynchronous Challenge Validation
**Solution**: Background hosted service polls challenges with status "processing", implements retry logic with exponential backoff, updates challenge status when validation completes. Client POST to challenge endpoint returns immediately.

### Challenge 3: CSR to Certificate Issuance
**Solution**: Parse CSR with BouncyCastle (already a dependency), use `CertificateFactory.SignRequest()` directly, or create temporary certificate operation in Key Vault and use existing `SignRequestAsync()` flow.

### Challenge 4: Order Expiration & Cleanup
**Solution**: Background cleanup service (Azure Functions or hosted service) to mark expired entities, implement manual cleanup since Azure Table Storage TTL not supported for complex types.

### Challenge 5: Network Isolation vs HTTP-01
**Conflict**: Current design assumes network isolation, but HTTP-01 requires CA to make outbound HTTP requests.
**Solution**:
- Option A: Run ACME server in separate network zone with outbound access
- Option B: Use DNS-01 only for fully private deployment
- Option C: Implement HTTP-01 with strict IP filtering and security controls

---

## Use Case Examples

### Use Case 1: Automated mTLS for Microservices
**Scenario**: Internal microservices need client certificates for mTLS authentication

**Setup**:
1. Deploy KeyVault-CA with ACME server to Azure App Service
2. Configure Traefik as reverse proxy with ACME client
3. Enable DNS-01 challenge for internal domains

**Result**: Traefik automatically obtains and renews certificates for all services, no manual certificate management

### Use Case 2: IoT Device Provisioning
**Scenario**: IoT devices need unique certificates during provisioning

**Setup**:
1. Enable External Account Binding (EAB) for restricted registration
2. Pre-generate EAB keys for each device
3. Devices use acme.sh during first boot with EAB token

**Result**: Secure, automated device certificate provisioning with proof of authorization

### Use Case 3: Development Environment Automation
**Scenario**: Developers need certificates for local testing

**Setup**:
1. Deploy ACME server internally with HTTP-01 challenges
2. Configure certbot on developer workstations
3. Use domain allowlist (*.dev.company.com)

**Result**: Developers run `certbot certonly --acme-server https://acme.company.com` to get valid certificates

---

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| Abuse/DoS attacks | High | Medium | Rate limiting, IP allowlisting, monitoring |
| Unauthorized certificate issuance | High | Low | Domain validation, CAA checking, allowlist |
| Challenge validation vulnerabilities (SSRF, DNS poisoning) | High | Medium | Strict validation, IP filtering, DNSSEC |
| Key Vault rate limits exceeded | Medium | Low | Caching, request batching |
| Table Storage performance bottleneck | Medium | Low | Partition key strategy, consider Cosmos DB for scale |
| JWS implementation vulnerabilities | High | Low | Use established libraries, security audit |

---

## Comparison with Existing CLI Workflow

### Current CLI Workflow
```bash
# Manual certificate issuance
keyvaultca issue-cert \
  --issuer ca@vault \
  --dns device1.example.com \
  --duration 90d \
  device1@vault

# Manual renewal (before expiration)
keyvaultca issue-cert --issuer ca@vault --dns device1.example.com device1@vault
```

### ACME Workflow (Post-Implementation)
```bash
# One-time setup
certbot register --acme-server https://acme.company.com

# Automated issuance and renewal
certbot certonly \
  --acme-server https://acme.company.com \
  -d device1.example.com \
  --standalone

# Or with Traefik (fully automated, zero-touch)
# Traefik automatically handles registration, issuance, and renewal
```

**Benefit**: Eliminates manual renewal tracking, integrates with standard tooling (certbot, Traefik, Caddy, acme.sh)

---

## Dependencies & Libraries

### Required NuGet Packages
- `System.IdentityModel.Tokens.Jwt` - JWS validation
- `Microsoft.AspNetCore.App` - Web API framework (already used)
- `Azure.Data.Tables` - Table Storage (already used)
- `Portable.BouncyCastle` - Advanced crypto operations (already used)
- Consider: `DnsClient` for DNS-01 validation

### Existing Libraries to Leverage
- `Azure.Security.KeyVault.Certificates` - Certificate operations
- `Azure.Security.KeyVault.Keys` - Cryptographic operations
- `Azure.Identity` - Azure authentication

---

## Success Metrics

### Functional Metrics
- ✓ Certbot can successfully obtain certificate
- ✓ acme.sh can successfully obtain certificate
- ✓ Traefik can automatically manage certificates
- ✓ Wildcard certificates work with DNS-01
- ✓ Certificate includes correct OCSP/CRL URLs

### Performance Metrics
- Support 100+ concurrent orders
- Challenge validation completes within 30 seconds
- Order finalization (CSR to certificate) within 5 seconds
- System uptime 99.9%

### Security Metrics
- Zero unauthorized certificate issuances
- Rate limits prevent abuse
- All requests properly authenticated (JWS validation)
- No SSRF/DNS poisoning vulnerabilities

---

## Alternative Approaches Considered

### Alternative 1: Extend Existing CLI
**Approach**: Add ACME client capabilities to CLI instead of server
**Pros**: Simpler, no web service needed
**Cons**: Doesn't enable standard ACME clients (certbot, Traefik), limited automation
**Decision**: Rejected - defeats purpose of ACME standardization

### Alternative 2: Use Existing ACME Server (step-ca, smallstep)
**Approach**: Integrate step-ca with Key Vault backend
**Pros**: Mature ACME implementation
**Cons**: Complex integration, doesn't leverage existing codebase patterns, licensing considerations
**Decision**: Rejected - custom implementation maintains consistency and control

### Alternative 3: ACME Server + CLI Hybrid
**Approach**: ACME server for automated issuance, CLI for manual operations
**Pros**: Best of both worlds
**Cons**: More complex, two issuance paths to maintain
**Decision**: **Selected** - This is the recommended approach (ACME server as addition, not replacement)

---

## Next Steps

### Immediate Actions
1. **User Validation**: Confirm ACME support aligns with project goals and use cases
2. **Challenge Type Selection**: Determine which challenge types are required (HTTP-01, DNS-01, TLS-ALPN-01)
3. **Security Review**: Validate security model for outbound HTTP/DNS requests
4. **Resource Planning**: Allocate 8-9 weeks for full implementation

### Proof of Concept (Optional)
Before full implementation, consider 2-week PoC:
- Implement minimal ACME server (HTTP-01 only)
- Account creation and order management
- Single certificate issuance with certbot
- Validates integration with existing `KeyVaultServiceOrchestrator`

### Questions for Stakeholders
1. **Primary Use Case**: What's the main driver? (mTLS automation, IoT provisioning, developer productivity)
2. **Deployment Model**: Public-facing or internal-only?
3. **Challenge Types**: Which validation methods are needed?
4. **Scale Requirements**: Expected certificate volume?
5. **External Account Binding**: Required for restricted registration?

---

## Conclusion

ACME protocol support is **highly feasible** and **strategically valuable** for KeyVault-CA. The existing architecture provides excellent foundations, and the implementation can be phased to deliver value incrementally.

**Recommended Path Forward**:
1. Validate use cases and requirements
2. Start with Phase 1-2 (core infrastructure + account management)
3. Implement HTTP-01 validation (Phase 4) for initial testing
4. Add DNS-01 (Phase 6) for wildcard certificates if needed
5. Production hardening (Phase 7) before wider deployment

**Timeline**: 8-9 weeks for complete implementation, or 4-5 weeks for MVP (HTTP-01 only)

**Effort**: ~1 full-time developer with .NET and PKI experience

---

## References

- [RFC 8555 - ACME Protocol](https://datatracker.ietf.org/doc/html/rfc8555)
- [RFC 9773 - ACME Renewal Information (ARI)](https://www.rfc-editor.org/rfc/rfc9773)
- [Wikipedia - Automatic Certificate Management Environment](https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment)
- [Certkit - How ACME Protocol Automates Certificate Issuance](https://www.certkit.io/blog/how-acme-protocol-automates-certificate-issuance)
- [Eunetic - Understanding IETF RFC 8555](https://www.eunetic.com/en/kb/cyber-threats-and-attack-vectors/ietf-rfc-8555-2018)

---

## Critical Files for Implementation

If proceeding with implementation, these are the key files to modify or reference:

1. [KeyVaultServiceOrchestrator.cs](../src/KeyVaultCa.Core/KeyVaultServiceOrchestrator.cs) - Core signing logic, `SignRequestAsync()` method is primary integration point
2. [CertificateFactory.cs](../src/KeyVaultCa.Core/CertificateFactory.cs) - CSR parsing and signing, `SignRequest()` for direct CSR processing
3. [OcspResponder/Program.cs](../src/KeyVaultCa.OcspResponder/Program.cs) - Reference for ASP.NET Core service setup pattern
4. [TableStorageRevocationStore.cs](../src/KeyVaultCa.Revocation.TableStorage/TableStorageRevocationStore.cs) - Pattern for Table Storage implementation
5. [OcspController.cs](../src/KeyVaultCa.OcspResponder/Controllers/OcspController.cs) - Controller pattern to follow for ACME endpoints
