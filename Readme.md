# KeyVault Certificate Authority

This repository contains a .NET library and CLI that help you run a small Certificate Authority entirely inside Azure Key Vault. All key material stays in Key Vault; the tooling orchestrates certificate creation, issuance, and renewal by driving the Key Vault APIs for you.

Today the toolset covers the basics needed for internal mTLS deployments: create a root CA, issue intermediates or end-entity certificates (across multiple vaults if desired), renew existing certs, and download PEM/PKCS8 material for distribution. Features such as certificate revocation, PKCS12 export, and automated renewal workers are still on the backlog, and the README calls out workarounds where needed (for example, building a certificate chain manually).

Typical scenarios include:
* Application Gateway needs to communicate with Azure API Management using mTLS
* Event Grid MQTT with certificate authentication
* Services communicating with each other using mTLS

Keeping certificates in Key Vault means you avoid managing private keys on developer machines and can drive issuance from automation such as Azure Pipelines or GitHub Actions. The CLI commands described below are script-friendly and make it easy to renew or reissue certificates as part of your existing deployment workflows.

## Setup

Please make sure these tools are installed:

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) - used to authenticate to Azure
- [Dotnet 8](https://dotnet.microsoft.com/download/dotnet/8.0) - used to build the tools
- An Azure subscription with Key Vault enabled and sufficient permissions to either create resources and grant rights on them,
  or, an existing KeyVault with sufficient permissions to create and manage certificates and read secrets.

You'll also need to login to Azure CLI and have a Key Vault ready to store the certificates in.

## Setup an offline CA

- Setup resources, assign roles
  - Create 2 Key Vaults, one for the CA and one for the leaf certificates
  - Ensure you have the following permissions:
    - Certificate Officer - allows you to create and update certificates
    - Crypto User - allows you to sign data using keys stored in Key Vault
    - Secrets User - allows you to read secrets from Key Vault, including certificates and keys

- Create a CA certificate

```bash
keyvaultca create-ca-cert --common-name "KeyVault-ca" --duration 2y root-ca@my-ca-keyvault
```

> **Required permissions** (CA vault): Certificate Officer, Crypto User, and Secrets User.

### Issue a leaf certificate
```bash
# Issuer and leaf can now live in different vaults by using secret@vault syntax.
keyvaultca issue-cert \
  --issuer root-ca@my-ca-keyvault \
  --duration 90d \
  --not-before 2025-04-01T00:00:00Z \
  --dns device1.alanta.local --dns device1 \
  device1@my-certs-keyvault

# If both certs share a vault you can still rely on --key-vault.
keyvaultca issue-cert --key-vault my-certs-keyvault --issuer root-ca --duration 90d device1
```

> **Required permissions**: 
> - Issuer vault: Crypto User (to sign) and Secrets User (to read the CA cert).
> - Target vault (where the new certificate lives): Certificate Officer and Secrets User.

### Renew a certificate

Simply run `keyvaultca issue-cert` again with the same issuer/leaf references and a new validity window—the tool will create the next version for you (no Azure Portal pre-work required):

```bash
keyvaultca issue-cert \
  --issuer root-ca@my-ca-keyvault \
  --duration 90d \
  device1@my-certs-keyvault
```

> **Required permissions**: same as issuing a new leaf certificate (Crypto + Secrets on the issuer vault, Certificate Officer + Secrets on the target vault).

### Create an intermediate certificate

If you want your leaf certificates to chain off an intermediate instead of the root, use `issue-intermediate-cert`. The issuer argument points to the parent CA while the `name` argument defines the intermediate certificate you are creating. Subject/SAN flags work exactly like `issue-cert` (defaults to `CN=<name>` if omitted).

```bash
# Create an intermediate in another vault so you can isolate issuing rights.
keyvaultca issue-intermediate-cert \
  --issuer root-ca@my-ca-keyvault \
  --duration 365d \
  --dns intermediate.alanta.local \
  intermediate-ca@my-intermediate-vault

# Or reuse the same vault via --key-vault
keyvaultca issue-intermediate-cert --key-vault my-ca-keyvault --issuer root-ca intermediate-ca
```

After the intermediate is created, use it as the `--issuer` when issuing your leaf certificates.

> **Required permissions**: 
> - Parent CA vault: Crypto User and Secrets User.
> - Intermediate vault (if different): Certificate Officer and Secrets User.

### Download the certificates

Use `download-cert` when you need to export a PEM (and optionally the private key) from Key Vault. The command always writes `<name>.pem`; pass `--key` if you also need `<name>.key` (RSA only for now).

```bash
# Export just the certificate
keyvaultca download-cert --key-vault my-certs-keyvault device1

# Export the certificate plus the private key (PEM PKCS8)
keyvaultca download-cert --key-vault my-certs-keyvault --key device1

# Full vault URI works too
# Full vault URI works too
keyvaultca download-cert --key-vault https://my-certs-keyvault.vault.azure.net/ device1
```

The files land in the current directory; move them into your chain/keystore workflow as needed.

> **Required permissions**: Secrets User on the vault that stores the certificate (Certificate Officer is not needed for read-only export).

### Build a chain if needed

The CLI doesn’t build a full PEM bundle yet, but you can assemble one manually once the certificates are exported:

1. Download each certificate you need in the chain (leaf, intermediate(s), root) with `keyvaultca download-cert`.
2. Concatenate them in order (leaf first, root last):

  ```bash
  cat device1.pem intermediate-ca.pem root-ca.pem > device1-chain.pem
  ```

3. Use the combined file anywhere a full chain is required (App Gateway, MQTT broker, etc.).

If you also need PKCS12 (`.pfx`), use OpenSSL locally for now:

```bash
openssl pkcs12 -export -out device1.pfx -inkey device1.key -in device1.pem -certfile intermediate-ca.pem -certfile root-ca.pem
```

> **Required permissions**: whatever was needed to download the individual certificates (Secrets User on each vault). The concatenation/OpenSSL steps run locally.

## References
- [Create and merge a certificate signing request in Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/certificates/create-certificate-signing-request?tabs=azure-powershell#add-more-information-to-the-csr)
- [Application Gateway : Generate an Azure Application Gateway self-signed certificate with a custom root CA](https://learn.microsoft.com/en-us/azure/application-gateway/self-signed-certificates)