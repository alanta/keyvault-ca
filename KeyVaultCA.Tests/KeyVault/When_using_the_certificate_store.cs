using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using FakeItEasy;
using FluentAssertions;

namespace KeyVaultCA.Tests.KeyVault;

/// <summary>
/// Verifies that the CertificateStore behaves as it should so we can use it to fake KeyVault.
/// </summary>
public class When_using_the_certificate_store
{
    [Fact]
    public void It_should_store_a_certificate_request()
    {
        // Arrange
        var certStore = new CertificateStore();
        var name = Guid.NewGuid().ToString();

        // Act
        var operation = certStore.StartOperation(name, A.Fake<CertificatePolicy>());

        // Assert
        var operation2 = certStore.GetCertificateOperationById(operation.Id);
        operation2.Should().NotBeNull();
        operation2!.HasCompleted.Should().BeFalse();
    }

    [Fact]
    public void It_should_merge_the_certificate_with_the_request()
    {
        // Arrange
        var certStore = new CertificateStore();
        var name = Guid.NewGuid().ToString();
        var csr = new CertificateRequest(new X500DistinguishedName("CN=test"), ECDsa.Create(), HashAlgorithmName.SHA256);
        var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var operation = certStore.StartOperation(name, A.Fake<CertificatePolicy>());

        // Act
        certStore.Merge(name, cert.RawData);

        // Assert
        var operation2 = certStore.GetCertificateOperationById(operation.Id);
        operation2.Should().NotBeNull();
        operation2!.HasCompleted.Should().BeTrue();
        operation2.Value.Cer.Should().BeEquivalentTo(cert.RawData);
    }
}