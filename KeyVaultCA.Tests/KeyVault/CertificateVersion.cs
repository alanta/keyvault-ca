using Azure.Security.KeyVault.Certificates;

namespace KeyVaultCA.Tests.KeyVault;

/// <summary>
/// Used to represent a version of a certificate in the <see cref="CertificateStore"/>.
/// </summary>
public class CertificateVersion
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required CertificatePolicy Policy { get; init; }
    public CertificateOperationProperties? Properties { get; set; }
    public byte[]? Certificate { get; set; }
    public byte[]? CertSigningRequest { get; set; }
    public bool HasCompleted => Certificate != null;
    public bool Enabled { get; set; } = true;
}