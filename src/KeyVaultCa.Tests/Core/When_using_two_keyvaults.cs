using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using FluentAssertions;
using KeyVaultCa.Core;
using KeyVaultCA.Tests.KeyVault;
using KeyVaultCA.Tests.Tools;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests.Core;

public class When_using_two_keyvaults(ITestOutputHelper output)
{
    [Fact]
    public async Task It_should_be_able_to_issue_a_certificate_signed_by_a_different_keyvault()
    {
        // Arrange
        var ct = CancellationToken.None;
        var kv1 = new CertificateStore();
        var kv2 = new CertificateStore();
        var clientFactory = new TestClientFactory(kv1, kv2);
        
        var kvServiceClient = new KeyVaultServiceOrchestrator(clientFactory.GetCertificateClient,  clientFactory.GetCryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));  
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));
        
        var today = DateTimeOffset.UtcNow.Date;
        
        // Act
        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(kv1.VaultUri, "UnitTestCA"), 
            "CN=UnitTestCA", 
            today.AddDays(-1),  
            today.AddDays(120), 
            1, 
            ct);

        // Issue certificate in kv2 signed by CA from kv1
        await kvCertProvider.IssueCertificate(
                new KeyVaultSecretReference(kv1.VaultUri, "UnitTestCA"),
                new KeyVaultSecretReference(kv2.VaultUri, "UnitTestCert"),
            "CN=UnitTestCert",
            today.AddDays(-1),
            today.AddDays(30),
                new SubjectAlternativeNames{DnsNames = { "cert1.test.local" }},
            revocationConfig: null,
            ct);
        
        // Assert
        var issuedCert = kv2.GetCertificateByName("UnitTestCert");
        issuedCert.Should().NotBeNull("the issued certificate should exist in the second Key Vault");

        var caCert = kv1.GetCertificateByName("UnitTestCA");
        caCert.Should().NotBeNull("the CA certificate should exist in the first Key Vault");

        var issuedX509 = new X509Certificate2(issuedCert!.Cer);
        var caX509 = new X509Certificate2(caCert!.Cer);

        issuedX509.Issuer.Should().Be(caX509.Subject, "the leaf certificate should be issued by the CA stored in the other Key Vault");
    }
}