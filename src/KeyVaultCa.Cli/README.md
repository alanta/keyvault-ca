# KeyVaultCa CLI

A .NET tool for running a small Certificate Authority entirely inside Azure Key Vault. All private key material stays in Key Vault; the CLI drives certificate creation, issuance, renewal, and revocation through the Key Vault APIs.

## Installation

```bash
dotnet tool install -g KeyVaultCa.Cli --add-source https://f.feedz.io/alanta/keyvault-ca/nuget/index.json
```

Requires the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) for authentication. Log in before using the tool:

```bash
az login
```

## Commands

### `create-ca-cert` — Create a root CA certificate

Creates a self-signed CA certificate in Key Vault.

```bash
keyvaultca create-ca-cert --common-name "My Root CA" --duration 2y root-ca@my-ca-keyvault
```

> Required permissions on the CA vault: Certificate Officer, Crypto User, Secrets User.

---

### `issue-cert` — Issue or renew a leaf certificate

Issues a new leaf certificate signed by the specified CA. Running the same command again renews it (Key Vault versioning keeps the history).

```bash
keyvaultca issue-cert \
  --issuer root-ca@my-ca-keyvault \
  --duration 90d \
  --dns device1.example.com --dns device1 \
  device1@my-certs-keyvault
```

> Required permissions: Crypto User + Secrets User on the issuer vault; Certificate Officer + Secrets User on the target vault.

---

### `issue-intermediate-cert` — Create an intermediate CA

Issues an intermediate CA certificate signed by a parent CA. Use the intermediate as `--issuer` when issuing leaf certificates to isolate signing rights.

```bash
keyvaultca issue-intermediate-cert \
  --issuer root-ca@my-ca-keyvault \
  --duration 365d \
  intermediate-ca@my-intermediate-vault
```

> Required permissions: Crypto User + Secrets User on the parent CA vault; Certificate Officer + Secrets User on the intermediate vault.

---

### `download-cert` — Export a certificate from Key Vault

Downloads a certificate in PEM or PFX (PKCS#12) format. Use `--key` to include the private key in PEM output, or `--pfx` to export as PKCS#12.

```bash
# PEM certificate only
keyvaultca download-cert --key-vault my-certs-keyvault device1

# PEM with private key
keyvaultca download-cert --key-vault my-certs-keyvault --key device1

# PFX with private key
keyvaultca download-cert --key-vault my-certs-keyvault --pfx device1

# PFX with password
keyvaultca download-cert --key-vault my-certs-keyvault --pfx --pfx-password "secret" device1
```

> Required permissions: Secrets User on the vault.

---

### `revoke-cert` — Revoke a certificate

Marks a certificate as revoked by recording the revocation in Key Vault tags (looked up by serial number). The serial number is printed by `issue-cert` and visible in the certificate itself.

```bash
keyvaultca revoke-cert \
  --key-vault my-ca-keyvault \
  --issuer "CN=My Root CA" \
  --reason keyCompromise \
  1A2B3C4D5E6F
```

Valid reasons: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `aaCompromise`.

> Required permissions: Certificate Officer on the vault (to update certificate tags).

---

### `generate-crl` — Generate a Certificate Revocation List

Generates a signed CRL file from the revoked certificates recorded in Key Vault. Publish this file at the CRL Distribution Point URL embedded in your certificates.

```bash
keyvaultca generate-crl \
  --output ./my-ca.crl \
  --validity 7d \
  root-ca@my-ca-keyvault
```

> Required permissions: Crypto User + Secrets User on the CA vault (to sign the CRL and read revocation records).

---

### `backfill-serial-tags` — Backfill serial number tags

One-time migration command for vaults that contain certificates issued before revocation support was added. Tags each certificate with its serial number so `revoke-cert` can find them.

```bash
# Preview changes without modifying anything
keyvaultca backfill-serial-tags --key-vault my-ca-keyvault --dry-run

# Apply
keyvaultca backfill-serial-tags --key-vault my-ca-keyvault
```

> Required permissions: Certificate Officer on the vault (to update certificate tags).

---

## Certificate and vault references

Most commands accept certificate references in the form `name@vault` to address a certificate and vault in a single argument:

```
root-ca@my-ca-keyvault        # certificate 'root-ca' in vault 'my-ca-keyvault'
device1@my-certs-keyvault     # certificate 'device1' in vault 'my-certs-keyvault'
```

Alternatively, use `--key-vault` to specify the vault separately when issuer and target share the same vault.
