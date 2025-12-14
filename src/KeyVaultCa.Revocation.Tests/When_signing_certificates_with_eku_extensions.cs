using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KeyVaultCa.Core;
using Shouldly;

namespace KeyVaultCa.Revocation.Tests;

public class When_signing_certificates_with_eku_extensions : TestBase
{
    [Fact]
    public async Task It_should_add_ocsp_signing_eku_when_specified()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);

        // Create a CSR for the certificate
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=OCSP Signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = request.CreateSigningRequest();

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);

        // Build extensions list with OCSP Signing EKU (simulating ocspSigning=true)
        var extensions = new List<X509Extension>
        {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.OCSPSigning) },
                critical: true)
        };

        // Act
        var signedCert = await CertificateFactory.SignRequest(
            csr,
            issuerCert,
            signatureGenerator,
            notBefore,
            notAfter,
            HashAlgorithmName.SHA256,
            extensions,
            null,
            CancellationToken.None);

        // Assert
        signedCert.ShouldNotBeNull();

        // Verify EKU extension exists
        var ekuExtension = signedCert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        ekuExtension.ShouldNotBeNull();
        ekuExtension.Critical.ShouldBeTrue(); // RFC 6960 requires critical=true

        // Verify it contains OCSP Signing OID
        var oids = ekuExtension.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToList();
        oids.ShouldContain(WellKnownOids.ExtendedKeyUsages.OCSPSigning);
        oids.Count.ShouldBe(1); // Should only have OCSP Signing
    }

    [Fact]
    public async Task It_should_add_server_and_client_auth_ekus_for_normal_certificates()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);

        // Create a CSR for the certificate
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test Server", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = request.CreateSigningRequest();

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(90);

        // Build extensions list with ServerAuth + ClientAuth (simulating ocspSigning=false)
        var extensions = new List<X509Extension>
        {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.ServerAuth), new Oid(WellKnownOids.ExtendedKeyUsages.ClientAuth) },
                critical: false)
        };

        // Act
        var signedCert = await CertificateFactory.SignRequest(
            csr,
            issuerCert,
            signatureGenerator,
            notBefore,
            notAfter,
            HashAlgorithmName.SHA256,
            extensions,
            null,
            CancellationToken.None);

        // Assert
        signedCert.ShouldNotBeNull();

        // Verify EKU extension exists
        var ekuExtension = signedCert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        ekuExtension.ShouldNotBeNull();
        ekuExtension.Critical.ShouldBeFalse(); // Standard certificates should not be critical

        // Verify it contains ServerAuth and ClientAuth OIDs
        var oids = ekuExtension.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToList();
        oids.ShouldContain(WellKnownOids.ExtendedKeyUsages.ServerAuth);
        oids.ShouldContain(WellKnownOids.ExtendedKeyUsages.ClientAuth);
        oids.Count.ShouldBe(2); // Should have both ServerAuth and ClientAuth
    }

    [Fact]
    public async Task It_should_include_basic_constraints_and_key_usage_extensions()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test Cert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csr = request.CreateSigningRequest();

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(90);

        var extensions = new List<X509Extension>
        {
            new X509BasicConstraintsExtension(false, false, 0, true),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true),
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.ServerAuth) },
                critical: false)
        };

        // Act
        var signedCert = await CertificateFactory.SignRequest(
            csr,
            issuerCert,
            signatureGenerator,
            notBefore,
            notAfter,
            HashAlgorithmName.SHA256,
            extensions,
            null,
            CancellationToken.None);

        // Assert
        signedCert.ShouldNotBeNull();

        // Verify Basic Constraints
        var basicConstraints = signedCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        basicConstraints.ShouldNotBeNull();
        basicConstraints.CertificateAuthority.ShouldBeFalse();
        basicConstraints.HasPathLengthConstraint.ShouldBeFalse();
        basicConstraints.Critical.ShouldBeTrue();

        // Verify Key Usage
        var keyUsage = signedCert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        keyUsage.ShouldNotBeNull();
        keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature).ShouldBeTrue();
        keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment).ShouldBeTrue();
        keyUsage.Critical.ShouldBeTrue();
    }
}
