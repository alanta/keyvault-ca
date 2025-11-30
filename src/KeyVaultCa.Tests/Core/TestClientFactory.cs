using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using FakeItEasy;
using KeyVaultCA.Tests.KeyVault;

namespace KeyVaultCA.Tests.Core;

internal class TestClientFactory(params CertificateStore[] certificateStores)
{
    public CertificateClient GetCertificateClient(Uri vaultUri)
    {
        var store = certificateStores.FirstOrDefault(s => s.VaultUri == vaultUri);
        if (store == null)
        {
            throw new ArgumentException($"No certificate store found for vault URI: {vaultUri}");
        }
        return store.GetFakeCertificateClient();
    }
        
    public CryptographyClient GetCryptographyClient(Uri vaultUri)
    {
        // For simplicity, we return a fake cryptography client.
        // In a real scenario, you would return a client that can handle the keyId.
        return A.Fake<CryptographyClient>();
    }
}