# Offline Certificate Authority

This repository demonstrates how to set up an offline Certificate Authority for an internal domain.
It can be used to sign certificates for your local domain names, used in a private network within, for example in Azure.
The main purpose of this is to facilitate the use of mTLS in Azure services, where the certificates are managed in Azure Key Vault.

Scenarios where this could be useful are:
* Application Gateway needs to communicate with Azure API Management using mTLS
* Event Grid MQTT with certificate authentication
* Services communicating with each other using mTLS

In real life we don't want to use self-signed certificates, and we definitely don't want to manage the certificates manually on our machines.
This repository has tooling you can use to easily manage the certificates in Azure Key Vault, without any private keys ever leaving that service.
The provided tools support automating the process of issuing and renewing certificates, and can be used in Azure Pipelines, GitHub Actions or other automation scenarios.

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
# Either embed the vault in the argument…
keyvaultca create-ca-cert --common-name "KeyVault-ca" --duration 2y root-ca@my-ca-keyvault

# …or keep using --key-vault when you prefer shorter names.
keyvaultca create-ca-cert --key-vault my-ca-keyvault --common-name "KeyVault-ca" --duration 2y root-ca
```

- Issue a leaf certificate
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

- Renew a certificate

Start a new version through the Azure portal. Then issue the certificate again.

- Create an intermediate certificate
- Create a leaf certificate
- Download the certificates
- Build a chain if needed

## References
- [Create and merge a certificate signing request in Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/certificates/create-certificate-signing-request?tabs=azure-powershell#add-more-information-to-the-csr)
- [Application Gateway : Generate an Azure Application Gateway self-signed certificate with a custom root CA](https://learn.microsoft.com/en-us/azure/application-gateway/self-signed-certificates)