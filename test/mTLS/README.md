# mTLS End-to-End Test with OCSP Verification

This test demonstrates two .NET applications communicating using mutual TLS (mTLS) with certificates issued by our KeyVault CA tooling, including OCSP-based revocation checking.

**🚀 Powered by .NET Aspire** - Single command to start all services with orchestration and observability!

## Test Scenario

```
┌─────────────┐                          ┌─────────────┐
│   Client    │  mTLS (client cert)      │  API Server │
│   App       │─────────────────────────>│   (WebAPI)  │
└─────────────┘                          └─────────────┘
      │                                         │
      │ OCSP Check                              │ OCSP Check
      │ (server cert valid?)                    │ (client cert valid?)
      ▼                                         ▼
┌──────────────────────────────────────────────────────┐
│         OCSP Responder (ocsp.localhost:5000)         │
└──────────────────────────────────────────────────────┘
                        │
                        │ Lookup revocation status
                        │ (Key Vault certificate tags)
                        ▼
                ┌───────────────┐
                │ Azure Key     │
                │ Vault         │
                └───────────────┘

All orchestrated by .NET Aspire AppHost with:
- Automatic service startup and health monitoring
- Service discovery between apps
- Aspire Dashboard for observability
```

## Prerequisites

- **.NET 10.0 SDK** installed
- **Azure Key Vault** - An existing Azure Key Vault (development/test vault)
- **Azure CLI** or authenticated with `DefaultAzureCredential`
- **PowerShell Core** (for setup script) - Works on Windows, macOS, and Linux
- **OpenSSL** (optional) - For certificate verification

## Infrastructure Components

1. **Azure Key Vault (Real)** - Stores CA certificate, private keys, and revocation data (as certificate tags)
2. **OCSP Responder** - ASP.NET Core minimal API responding to OCSP requests at `http://ocsp.localhost:5000`
3. **API Server** - Sample WebAPI secured with mTLS (server + client certificates)
4. **Client App** - Console app calling the API with client certificate
5. **Aspire AppHost** - Orchestrates all services with health monitoring and dashboard

## Certificate Hierarchy

```
Root CA (root-ca)
├── OCSP Signing Certificate (ocsp-signer)
├── API Server Certificate (api-server)
└── Client Certificate (api-client)
```

All certificates except the Root CA include the AIA extension pointing to `http://ocsp.localhost:5000`.

## Step-by-Step Guide

### Step 1: Authenticate to Azure

Ensure you're authenticated to Azure with access to your Key Vault:

```bash
# Using Azure CLI
az login

# OR using your preferred Azure authentication method
# DefaultAzureCredential will automatically pick up your credentials
```

### Step 2: Build the CLI Tool

```bash
dotnet build src/KeyVaultCa.Cli/KeyVaultCa.Cli.csproj
```

### Step 3: Create Certificates

Run the certificate setup script with your Key Vault name:

```powershell
cd test/mTLS/scripts
./setup-certificates.ps1 -KeyVaultName "your-keyvault-name"
```

**Replace `your-keyvault-name` with your actual Azure Key Vault name** (without `.vault.azure.net`).

This script will:
1. ✅ Create Root CA certificate in Key Vault
2. ✅ Create OCSP Signing certificate with `--ocsp-signing` flag
3. ✅ Create API Server certificate with `--ocsp-url http://ocsp.localhost:5000`
4. ✅ Create Client certificate with `--ocsp-url http://ocsp.localhost:5000`
5. ✅ Download all certificates to `../certs/` directory

### Step 4: Install Root CA in System Trust Store

**IMPORTANT**: For OCSP checking to work automatically, the root CA must be installed in your system's trust store.

```bash
cd test/mTLS/scripts
./manage-trust-store.sh install
```

This will:
- ✅ Copy the root CA certificate to `/usr/local/share/ca-certificates/`
- ✅ Update the system trust store with `update-ca-certificates`
- ✅ Enable automatic OCSP validation without custom code

**Why this is needed**: .NET's X509Chain automatically performs OCSP revocation checking, but ONLY when using system trust mode. When using `CustomRootTrust` (loading CAs programmatically), .NET disables OCSP checking entirely. By installing the CA in the system trust store, we get:
- ✅ Automatic OCSP checking via the standard .NET chain validator
- ✅ No custom certificate validation code required
- ✅ Standard enterprise security pattern
- ✅ OCSP requests to `http://ocsp.localhost:5000` happen automatically

**To uninstall** (when done testing):
```bash
./manage-trust-store.sh uninstall
```

### Step 5: Configure OCSP Responder

Update `OcspResponder/appsettings.json` with your Key Vault URL:

```json
{
  "KeyVault": {
    "Url": "https://your-keyvault-name.vault.azure.net",
    "OcspSignerCertName": "ocsp-signer"
  }
}
```

### Step 6: Add ocsp.localhost to hosts file (if needed)

The `.localhost` TLD should resolve automatically to 127.0.0.1, but if you encounter issues:

- **Linux/Mac**: Add `127.0.0.1 ocsp.localhost` to `/etc/hosts`
- **Windows**: Add `127.0.0.1 ocsp.localhost` to `C:\Windows\System32\drivers\etc\hosts`

### Step 7: Start the Aspire AppHost

**This single command starts everything!** 🚀

```bash
cd test/mTLS/AppHost
aspire run
```

Aspire will:
- ✅ Start OCSP Responder on `http://localhost:5000`
- ✅ Start API Server with mTLS enabled
- ✅ Start Client App (runs 3 requests with 10-second intervals to demonstrate OCSP caching)
- ✅ Open Aspire Dashboard (URL shown in console output)

### Step 8: Monitor in Aspire Dashboard

Open the Aspire Dashboard (URL shown in console) to see:

- **Resources** tab: All running services and their health status
- **Console Logs** tab: Real-time logs from all services
- **Traces** tab: OpenTelemetry traces showing the mTLS request flow
- **Metrics** tab: Performance metrics

### Step 9: Watch for OCSP Requests

In the Aspire Dashboard, select the **ocsp-responder** service to see OCSP requests:

```
info: Program[0]
      OCSP request received, size: 123 bytes
info: KeyVaultCa.Revocation.OcspResponseBuilder[0]
      Certificate serial 1A2B3C status: Good
info: Program[0]
      OCSP response generated, size: 456 bytes
```

### Step 10: Verify Client Success

Check the **client-app** service logs in Aspire Dashboard:

```
info: ClientWorker[0]
      === Run 1/3 ===
info: ClientWorker[0]
      Calling API server at https://api-server
info: ClientWorker[0]
      ✅ Successfully received weather forecast from API:

Weather Forecast:
==================
2025-12-26: 15°C (59°F) - Mild
2025-12-27: 22°C (72°F) - Warm
...

info: ClientWorker[0]
      ✅ mTLS communication successful with OCSP validation!
info: ClientWorker[0]
      Waiting 10 seconds before next run...
```

The client runs 3 times to demonstrate OCSP response caching - only the first run triggers OCSP requests.

## Expected Results

✅ **Success Scenario**:
- ✅ Aspire starts all services automatically
- ✅ Client successfully calls the API with mTLS
- ✅ OCSP responder logs show "Good" status for both certificates
- ✅ Client displays weather forecast data from API
- ✅ Both client and server certificates are validated via OCSP
- ✅ All telemetry visible in Aspire Dashboard

## Troubleshooting

### Aspire Won't Start

If Aspire fails to start:
1. Check port 15888 is not in use (Aspire Dashboard)

### Key Vault Access Denied

If you get Key Vault access errors:
1. Verify you're authenticated: `az login`
2. Check you have permissions on the Key Vault (Get, List certificates/secrets)
3. Ensure `DefaultAzureCredential` can find your credentials

### OCSP Responder Not Accessible

If you get connection errors to `ocsp.localhost:5000`:
1. Verify hosts file entry: `127.0.0.1 ocsp.localhost` (if needed)
2. Check OCSP responder health in Aspire Dashboard
3. Verify port 5000 is not in use

### Certificate Validation Errors

If you get certificate validation errors:
1. Verify certificates were created correctly: check Aspire logs
2. Verify certificates contain the correct AIA extension:
   ```bash
   openssl x509 -in certs/api-server.crt -text -noout | grep -A 5 "Authority Information Access"
   ```
3. Check OCSP responder is returning valid responses (check Aspire logs)

### OCSP Validation Silently Fails

If client certificate OCSP validation doesn't work but shows no errors:
1. **Check OCSP caching**: .NET caches OCSP responses. Re-issue the certificate to force a fresh lookup
2. **Verify OCSP responder is reachable**:
   ```bash
   curl http://ocsp.localhost:5000/
   # Should return 405 (Method Not Allowed) - means it's reachable
   ```
3. **Check OCSP responder logs**: Look for incoming requests in the Aspire Dashboard
4. **Verify root CA is in system trust store**: Run `scripts/manage-trust-store.sh install`

## Testing Revocation (Optional - Future Enhancement)

To test the revocation scenario, you would:

1. Revoke a certificate using the CLI: `kv-ca-cli revoke-cert -kv https://your-vault.vault.azure.net -s <serial-number>`
2. The OCSP responder would return "revoked" status
3. Certificate validation would fail

## Clean Up

Stop Aspire and clean up:

```bash
# Stop Aspire (Ctrl+C in the terminal running AppHost)

# Remove downloaded certificates
rm -rf certs/

# (Optional) Delete test certificates from Key Vault
az keyvault certificate delete --vault-name your-keyvault-name --name root-ca
az keyvault certificate delete --vault-name your-keyvault-name --name ocsp-signer
az keyvault certificate delete --vault-name your-keyvault-name --name api-server
az keyvault certificate delete --vault-name your-keyvault-name --name api-client
```

## File Structure

```
test/mTLS/
├── README.md                           # This file
├── mTls.slnx                           # Solution file
├── AppHost/                            # .NET Aspire orchestration
│   └── AppHost.cs                      # Aspire app host (file-scoped program)
├── ServiceDefaults/                    # Shared Aspire service configuration
│   ├── Extensions.cs                   # Service defaults (telemetry, health checks)
│   └── ServiceDefaults.csproj          # Service defaults project
├── OcspResponder/                      # OCSP Responder Service
│   ├── Program.cs                      # Minimal API OCSP endpoints
│   ├── appsettings.json                # Key Vault config
│   └── OcspResponder.csproj            # Project file
├── ApiServer/                          # API Server with mTLS
│   ├── Program.cs                      # mTLS configuration & WeatherForecast endpoint
│   ├── appsettings.json                # Certificate paths configuration
│   └── ApiServer.csproj                # Project file
├── ClientApp/                          # Client Application
│   ├── Program.cs                      # HTTP client with mTLS (runs 3 requests)
│   ├── appsettings.json                # Certificate paths configuration
│   └── ClientApp.csproj                # Project file
├── scripts/
│   ├── setup-certificates.ps1          # PowerShell script to create all certificates
│   └── manage-trust-store.sh           # Script to install/uninstall root CA in system trust
└── certs/                              # Downloaded certificates (generated by script)
    ├── root-ca.crt                     # Root CA public certificate
    ├── ocsp-signer.pfx                 # OCSP signing certificate with private key
    ├── api-server.pfx                  # API server certificate with private key
    └── api-client.pfx                  # Client certificate with private key
```

## Key Features Demonstrated

- **Certificate Issuance**: Using KeyVault CA CLI to issue certificates with custom extensions
- **OCSP Signing**: Dedicated OCSP signing certificate with `--ocsp-signing` flag
- **AIA Extension**: Automatic OCSP URL injection via `--ocsp-url` parameter
- **mTLS**: Mutual TLS authentication between client and server
- **OCSP Validation**: Automatic revocation checking via .NET's TLS stack
- **OCSP Caching**: Client runs 3 requests to demonstrate response caching (only first triggers OCSP)
- **BouncyCastle Integration**: OCSP response generation using BouncyCastle
- **Azure Integration**: Key Vault for certificate storage and revocation data (via certificate tags)
- **.NET Aspire**: Modern cloud-native orchestration with observability

## Notes

- This test uses **real Azure Key Vault** (development/test vault)
- The `.localhost` TLD is reserved and automatically resolves to 127.0.0.1 (RFC 6761)
- **Root CA must be in system trust store** for OCSP to work - `CustomRootTrust` mode disables OCSP checking in .NET
- OCSP checking happens automatically via .NET's `X509Chain` validation when using system trust
- Certificate serial numbers are in hex format (uppercase)
- Aspire provides automatic service discovery, health monitoring, and telemetry
- All HTTP communication is observable through OpenTelemetry in the Aspire Dashboard

### OCSP Response Caching

.NET caches OCSP responses based on the `nextUpdate` field in the response. This can cause confusion during development when certificates appear to not be validated:

- **Production**: OCSP responses typically have 24-hour validity (1440 minutes)
- **Demo/Testing**: The OcspResponder in this demo uses 1-minute validity to allow quick testing

If OCSP validation appears to not work:
1. **Check if it's cached**: Re-issue the certificate to get a new serial number, forcing a fresh OCSP lookup
2. **Wait for cache expiry**: The cache duration equals the OCSP response validity period

The OCSP response validity is configurable in `OcspResponder/appsettings.json`:
```json
{
  "Ocsp": {
    "ResponseValidityMinutes": 1440
  }
}
```

For development, `appsettings.Development.json` overrides this to 1 minute for quick iteration.

### Production Deployment Notes

For containerized deployments (Azure Container Apps, AKS):
- Install the root CA at container startup using a script or init container
- Mount the CA certificate as a Kubernetes secret
- Update the system trust store with `update-ca-certificates` before starting the app
- This enables OCSP validation without requiring `CustomRootTrust` code
- See `scripts/manage-trust-store.sh` for the trust store installation logic
