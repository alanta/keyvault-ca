using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using FakeItEasy;
using FluentAssertions;
using KeyVaultCa.Core;
using KeyVaultCA.Tests.Tools;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests.KeyVault;

public class When_signing_a_certificate_with_keyvault(ITestOutputHelper output)
{
    [Fact]
    public async Task Should_create_a_CA_certificate()
    {
        // Arrange
        var certName = Guid.NewGuid().ToString();
        var store = new CertificateStore();
        var certificateClient = A.Fake<CertificateClient>() // x => x.Strict()
            .WithCreateCertificateBehavior(store)
            .WithMergeCertificateBehavior(store)
            .WithGetCertificateBehavior(store);
        
        
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceClient(certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceClient>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        // Act
        await kvCertProvider.CreateCACertificateAsync("UnitTestCA", "CN=UnitTestCA", 1, default);

        // Assert
        var certificate = store.GetCertificateByName("UnitTestCA");
        var certBytes = certificate.Cer;
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
        var certificateClient = A.Fake<CertificateClient>(x => x.Strict())
            .WithCreateCertificateBehavior(certificateOperations)
            .WithMergeCertificateBehavior(certificateOperations)
            .WithGetCertificateBehavior(certificateOperations)
            .WithGetCertificateOperationBehavior(certificateOperations)
            .WithGetCertificateVersionBehavior(certificateOperations);
        
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceClient(certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceClient>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        await kvCertProvider.CreateCACertificateAsync("UnitTestCA", "CN=UnitTestCA", 1, default);
        

        // Act
        await certificateClient.StartCreateCertificateAsync("UnitTestIntermediate", new CertificatePolicy("Unknown", "CN=test.local"));
        var signedCert = await kvServiceClient.SignRequestAsync(
            new Uri("https://localhost/certificate/UnitTestIntermediate"), 
            new Uri("http://localhost/certificates/UnitTestCA"), 
            30,
            uri => certificateClient,
            uri => cryptographyClient) ;

        await certificateClient.MergeCertificateAsync(new MergeCertificateOptions("UnitTestIntermediate", [signedCert.RawData]), default);

        // Assert
        var certificate = certificateOperations.GetCertificateByName("UnitTestIntermediate");
        var certBytes = certificate.Cer;
        certBytes.Should().NotBeNull();
        var cert = new X509Certificate2(certBytes);
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.Should().BeFalse();

    }

    [Fact]
    public async Task It_should_add_SANs()
    {
        // Arrange
        var certificateOperations = new CertificateStore();
        var certificateClient = A.Fake<CertificateClient>(x => x.Strict())
            .WithCreateCertificateBehavior(certificateOperations)
            .WithMergeCertificateBehavior(certificateOperations)
            .WithGetCertificateBehavior(certificateOperations)
            .WithGetCertificateOperationBehavior(certificateOperations)
            .WithGetCertificateVersionBehavior(certificateOperations);

        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceClient(certificateClient, uri => cryptographyClient, new XUnitLogger<KeyVaultServiceClient>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        // Setup CA cert
        await kvCertProvider.CreateCACertificateAsync("UnitTestCA", "CN=UnitTestCA", 1, default);
        // setup intermediate cert
        await certificateClient.StartCreateCertificateAsync("UnitTestIntermediate", new CertificatePolicy("Unknown", "CN=intermediate.local"));
        var signedCert = await kvServiceClient.SignRequestAsync(
            new Uri("https://localhost/certificate/UnitTestIntermediate"), 
            new Uri("http://localhost/certificates/UnitTestCA"), 
            30,
            uri => certificateClient,
            uri => cryptographyClient);

        await certificateClient.MergeCertificateAsync(new MergeCertificateOptions("UnitTestIntermediate", [signedCert.RawData]), default);
        

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
            30,
            uri => certificateClient,
            uri => cryptographyClient);
        await certificateClient.MergeCertificateAsync(new MergeCertificateOptions("LeafWithSAN", [signedCert2.RawData]), default);

        // Assert
        var certificate = certificateOperations.GetCertificateByName("LeafWithSAN");
        var certBytes = certificate.Cer;
        certBytes.Should().NotBeNull();
        var cert = new X509Certificate2(certBytes);
        cert.NotAfter.Should().BeBefore(DateTime.Now.AddDays(30));
        var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        basicConstraints.CertificateAuthority.Should().BeFalse();
        basicConstraints.HasPathLengthConstraint.Should().BeFalse();

        var alternativeDNSNames = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(x => x.EnumerateDnsNames()).ToArray();
        alternativeDNSNames.Should().Contain("test.alanta.local");

        var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        keyUsage.KeyUsages.Should().Be(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyEncipherment);
    }
}