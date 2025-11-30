using System;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace KeyVaultCa.Cli.Handlers;

internal class CachedClientFactory
{
    private readonly TokenCredential _credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
    {
        ExcludeWorkloadIdentityCredential = true,
        ExcludeManagedIdentityCredential = true,
        ExcludeAzureDeveloperCliCredential = true,
        ExcludeVisualStudioCodeCredential = true,
        ExcludeVisualStudioCredential = true,
        ExcludeAzurePowerShellCredential = true,
        ExcludeInteractiveBrowserCredential = true
    });
    
    private readonly IDictionary<string, CertificateClient> _certificateClient 
        = new Dictionary<string, CertificateClient>();

    private readonly IDictionary<string, CryptographyClient> _cryptographyClients =
        new Dictionary<string, CryptographyClient>(StringComparer.OrdinalIgnoreCase);

    public CertificateClient GetCertificateClientFactory(Uri vaultUri)
    {
        var hostName = vaultUri.Host.ToLowerInvariant();
        if (!_certificateClient.TryGetValue(hostName, out var client))
        {
            client = new CertificateClient(vaultUri, _credential);
            _certificateClient[hostName] = client;
        }

        return client;
    }

    public CryptographyClient GetCryptographyClient(Uri uri)
    { 
        var cacheKey = uri.ToString();
        if (!_cryptographyClients.TryGetValue(cacheKey, out var client))
        {
            client = new CryptographyClient(uri, _credential);
            _cryptographyClients[cacheKey] = client;
        }

        return client;
    }
}