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
      │                                         │
      │ OCSP Check                              │ OCSP Check
      │ (client cert valid?)                    │ (server cert valid?)
      ▼                                         ▼
┌──────────────────────────────────────────────────────┐
│         OCSP Responder (ocsp.localhost:5000)         │
└──────────────────────────────────────────────────────┘
                        │
                        │ Lookup revocation status
                        ▼
                ┌───────────────┐
                │ Azure Table   │
                │ Storage       │
                │ (Azurite)     │
                └───────────────┘

All orchestrated by .NET Aspire AppHost with:
- Automatic service startup and health monitoring
- Azurite container for Table Storage
- Service discovery between apps
- Dashboard at http://localhost:15888
```

## Prerequisites

- **.NET 8.0 SDK** installed
- **.NET Aspire workload** - Install with: `dotnet workload install aspire`
- **Docker Desktop** - Required for Aspire to run Azurite container
- **Azure Key Vault** - An existing Azure Key Vault (development/test vault)
- **Azure CLI** or authenticated with `DefaultAzureCredential`
- **PowerShell Core** (for setup script) - Works on Windows, macOS, and Linux
- **OpenSSL** (optional) - For certificate verification

## Infrastructure Components

1. **Azure Key Vault (Real)** - Stores CA certificate and private keys
2. **Azurite (Aspire Container)** - Stores certificate revocation records in Table Storage
3. **OCSP Responder** - ASP.NET Core minimal API responding to OCSP requests at `http://ocsp.localhost:5000`
4. **API Server** - Sample WebAPI secured with mTLS (server + client certificates)
5. **Client App** - Console app calling the API with client certificate
6. **Aspire AppHost** - Orchestrates all services with health monitoring and dashboard

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

### Step 4: Configure OCSP Responder

Update `OcspResponder/appsettings.json` with your Key Vault URL:

```json
{
  "KeyVault": {
    "Url": "https://your-keyvault-name.vault.azure.net",
    "OcspSignerCertName": "ocsp-signer"
  }
}
```

### Step 5: Add ocsp.localhost to hosts file (if needed)

The `.localhost` TLD should resolve automatically to 127.0.0.1, but if you encounter issues:

- **Linux/Mac**: Add `127.0.0.1 ocsp.localhost` to `/etc/hosts`
- **Windows**: Add `127.0.0.1 ocsp.localhost` to `C:\Windows\System32\drivers\etc\hosts`

### Step 6: Start the Aspire AppHost

**This single command starts everything!** 🚀

```bash
cd test/mTLS/AppHost
dotnet run
```

Aspire will:
- ✅ Start Azurite container for Table Storage
- ✅ Start OCSP Responder on `http://ocsp.localhost:5000`
- ✅ Start API Server on `https://localhost:7001`
- ✅ Start Client App (runs once and exits)
- ✅ Open Aspire Dashboard at `http://localhost:15888`

### Step 7: Monitor in Aspire Dashboard

Open the Aspire Dashboard at **http://localhost:15888** to see:

- **Resources** tab: All running services and their health status
- **Console Logs** tab: Real-time logs from all services
- **Traces** tab: OpenTelemetry traces showing the mTLS request flow
- **Metrics** tab: Performance metrics

### Step 8: Watch for OCSP Requests

In the Aspire Dashboard, select the **ocsp-responder** service to see OCSP requests:

```
info: Program[0]
      OCSP request received, size: 123 bytes
info: KeyVaultCa.Revocation.OcspResponseBuilder[0]
      Certificate serial 1A2B3C status: Good
info: Program[0]
      OCSP response generated, size: 456 bytes
```

### Step 9: Verify Client Success

Check the **client-app** service logs in Aspire Dashboard:

```
info: Program[0]
      ✅ Successfully received weather forecast from API:

Weather Forecast:
==================
2025-12-15: 15°C (59°F) - Mild
2025-12-16: 22°C (72°F) - Warm
...

info: Program[0]
      ✅ mTLS communication successful with OCSP validation!
```

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
1. Ensure Docker Desktop is running (required for Azurite container)
2. Install Aspire workload: `dotnet workload install aspire`
3. Check port 15888 is not in use (Aspire Dashboard)

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

### Azurite Container Issues

If Azurite has connection issues:
1. Check Azurite container is running in Aspire Dashboard
2. Verify Table Storage health endpoint
3. Restart Aspire if needed

## Testing Revocation (Optional - Future Enhancement)

To test the revocation scenario, you would:

1. Revoke a certificate using the CLI
2. The OCSP responder would return "revoked" status
3. Certificate validation would fail

This requires implementing the revoke-cert CLI command with Table Storage support.

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

Aspire automatically cleans up Docker containers (Azurite) when stopped.

## File Structure

```
test/mTLS/
├── README.md                           # This file
├── AppHost/                            # .NET Aspire orchestration
│   ├── Program.cs                      # Aspire app host configuration
│   ├── AppHost.csproj                  # Aspire host project file
│   └── appsettings.json               # Aspire configuration
├── ServiceDefaults/                    # Shared Aspire service configuration
│   ├── Extensions.cs                   # Service defaults (telemetry, health checks)
│   └── ServiceDefaults.csproj         # Service defaults project
├── OcspResponder/                      # OCSP Responder Service
│   ├── Program.cs                      # Minimal API OCSP endpoints
│   ├── appsettings.json               # Key Vault & Table Storage config
│   └── OcspResponder.csproj           # Project file
├── ApiServer/                          # API Server with mTLS
│   ├── Program.cs                      # mTLS configuration & WeatherForecast endpoint
│   ├── appsettings.json               # Certificate paths configuration
│   └── ApiServer.csproj               # Project file
├── ClientApp/                          # Client Application
│   ├── Program.cs                      # HTTP client with mTLS calling API
│   ├── appsettings.json               # Certificate paths configuration
│   └── ClientApp.csproj               # Project file
├── scripts/
│   └── setup-certificates.ps1         # PowerShell script to create all certificates
└── certs/                              # Downloaded certificates (generated by script)
    ├── root-ca.crt                    # Root CA public certificate
    ├── ocsp-signer.crt                # OCSP signing public certificate
    ├── ocsp-signer.pfx                # OCSP signing certificate with private key
    ├── api-server.crt                 # API server public certificate
    ├── api-server.pfx                 # API server certificate with private key
    ├── api-client.crt                 # Client public certificate
    └── api-client.pfx                 # Client certificate with private key
```

## Key Features Demonstrated

✅ **Certificate Issuance**: Using KeyVault CA CLI to issue certificates with custom extensions
✅ **OCSP Signing**: Dedicated OCSP signing certificate with `--ocsp-signing` flag
✅ **AIA Extension**: Automatic OCSP URL injection via `--ocsp-url` parameter
✅ **mTLS**: Mutual TLS authentication between client and server
✅ **OCSP Validation**: Automatic revocation checking via .NET `X509Chain`
✅ **BouncyCastle Integration**: OCSP response generation using BouncyCastle
✅ **Azure Integration**: Key Vault for certificate storage, Table Storage for revocation data
✅ **.NET Aspire**: Modern cloud-native orchestration with observability

## Notes

- This test uses **real Azure Key Vault** (development/test vault)
- The `.localhost` TLD is reserved and automatically resolves to 127.0.0.1 (RFC 6761)
- OCSP checking happens automatically via .NET's `X509Chain` validation
- Certificate serial numbers are in hex format (uppercase)
- Aspire provides automatic service discovery, health monitoring, and telemetry
- All HTTP communication is observable through OpenTelemetry in the Aspire Dashboard
