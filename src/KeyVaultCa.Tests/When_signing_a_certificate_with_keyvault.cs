using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using FakeItEasy;
using FluentAssertions;
using KeyVaultCa.Core;
using KeyVaultCA.Tests.KeyVault;
using KeyVaultCA.Tests.Tools;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests;

public class When_signing_a_certificate_with_keyvault(ITestOutputHelper output)
{
    [Fact]
    public async Task Should_create_a_CA_certificate()
    {
        // Arrange
        var store = new CertificateStore();
        var certificateClient = store.GetFakeCertificateClient();
        
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        // Act
        await kvCertProvider.CreateRootCertificate(new KeyVaultSecretReference(store.VaultUri, "UnitTestCA"), "CN=UnitTestCA", DateTime.UtcNow, DateTime.UtcNow.AddDays(30),1, default);

        // Assert
        var certificate = store.GetCertificateByName("UnitTestCA");
        var certBytes = certificate!.Cer;
        certBytes.Should().NotBeNull();
        var cert = new X509Certificate2(certBytes);
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.Should().BeTrue();

        store.CertificateVersions[1].Policy.ReuseKey.Should().BeTrue("CA root should reuse the key created for it in the first version.");
    }

    [Fact]
    public async Task Should_sign_an_intermediate_certificate()
    {
        // Arrange
        var certificateOperations = new CertificateStore();
        var certificateClient = certificateOperations.GetFakeCertificateClient();
        
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"), 
            "CN=UnitTestCA",
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(30),
            1,
            default);

        // Act
        output.WriteLine("------ ACT -------");
        
        await kvCertProvider.IssueIntermediateCertificate(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"),
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestIntermediate"),
            "CN=intermediate.local", 
            DateTime.UtcNow.Date, 
            DateTime.UtcNow.Date.AddDays(30),
            new SubjectAlternativeNames()
            {
                DnsNames = { "intermediate.local" }
            }, 
            0, 
            default);


        // Assert
        var certificate = certificateOperations.GetCertificateByName("UnitTestIntermediate");
        var certBytes = certificate!.Cer;
        certBytes.Should().NotBeNull();
        var cert = new X509Certificate2(certBytes);
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.Should().BeTrue("Intermediate certificate should be a CA certificate");
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().HasPathLengthConstraint.Should().BeTrue("Intermediate certificate should have a path length constraint");
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().PathLengthConstraint.Should().Be(0, "Intermediate certificate should have a path length constraint of 0");
        cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault().Should().NotBeNull("Intermediate certificate should have a subject key identifier");
    }

    [Fact]
    public async Task It_should_add_SANs()
    {
        // Arrange
        var certificateOperations = new CertificateStore();
        var certificateClient = certificateOperations.GetFakeCertificateClient();

        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient, _ => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        // Setup CA cert
        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"),
            "CN=UnitTestCA", 
            DateTimeOffset.UtcNow.AddDays(-1),  
            DateTimeOffset.UtcNow.AddDays(30), 
            1, 
            default);
        
        // setup intermediate cert
        await certificateClient.StartCreateCertificateAsync("UnitTestIntermediate", new CertificatePolicy("Unknown", "CN=intermediate.local"));
        var signedCert = await kvServiceClient.SignRequestAsync(
            new Uri("https://localhost/certificate/UnitTestIntermediate"), 
            new Uri("http://localhost/certificates/UnitTestCA"), 
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddDays(30),
            uri => certificateClient,
            uri => cryptographyClient,
            extensions:[new X509BasicConstraintsExtension(true, true, 0, true)]);

        var result = await certificateClient.MergeCertificateAsync(new MergeCertificateOptions("UnitTestIntermediate", [signedCert.RawData]), default);

        // Act
        var sans = new SubjectAlternativeNames();
        sans.DnsNames.Add("test.alanta.local");
        sans.DnsNames.Add($"{Guid.NewGuid():N}.alanta.local");

        sans.Emails.Add("postmaster@alanta.local");

        sans.UserPrincipalNames.Add("test@alanta.nl");

        await certificateClient.StartCreateCertificateAsync("LeafWithSAN", new CertificatePolicy("Unknown", "CN=test.local", sans ));
        var signedCert2 = await kvServiceClient.SignRequestAsync(
            new Uri("https://localhost/certificate/LeafWithSAN"),
            new Uri("http://localhost/certificates/UnitTestIntermediate"),
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddDays(30),
            uri => certificateClient,
            uri => cryptographyClient);
        await certificateClient.MergeCertificateAsync(new MergeCertificateOptions("LeafWithSAN", [signedCert2.RawData]), default);

        // Assert
        var certificate = certificateOperations.GetCertificateByName("LeafWithSAN");
        var certBytes = certificate!.Cer;
        certBytes.Should().NotBeNull();
        var cert = new X509Certificate2(certBytes);
        cert.NotAfter.Should().BeBefore(DateTime.Now.AddDays(30));
        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        basicConstraints!.CertificateAuthority.Should().BeFalse();
        basicConstraints.HasPathLengthConstraint.Should().BeFalse();

        var alternativeDnsNames = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(x => x.EnumerateDnsNames()).ToArray();
        alternativeDnsNames.Should().Contain("test.alanta.local");

        var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        keyUsage!.KeyUsages.Should().Be(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyEncipherment);
    }
}