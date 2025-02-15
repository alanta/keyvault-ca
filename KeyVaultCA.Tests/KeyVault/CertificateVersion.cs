using Azure.Security.KeyVault.Certificates;

namespace KeyVaultCA.Tests.KeyVault;

public class CertificateVersion
{
    public string Name { get; set; }
    public string Version { get; set; }
    public CertificatePolicy Policy { get; set; }
    public CertificateOperationProperties Properties { get; set; }
    public byte[]? Certificate { get; set; }
    public byte[]? CertSigningRequest { get; set; }
    public bool HasCompleted => Certificate != null;
}