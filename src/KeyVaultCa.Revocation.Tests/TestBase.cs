using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using FakeItEasy;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation.Interfaces;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.Tests;

/// <summary>
/// Base class for tests with shared setup methods to reduce duplication.
/// </summary>
public abstract class TestBase
{
    protected static X509Certificate2 CreateTestCertificate(string subject, bool isCa = false)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Add basic constraints for CA certificates
        if (isCa)
        {
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: false,
                    pathLengthConstraint: 0,
                    critical: true));
        }

        // Add Subject Key Identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        return cert;
    }

    protected static KeyVaultSignatureGenerator CreateFakeSignatureGenerator(X509Certificate2 certificate)
    {
        var fakeGenerator = A.Fake<KeyVaultSignatureGenerator>(options => options
            .WithArgumentsForConstructor(() => new KeyVaultSignatureGenerator(
                _ => A.Fake<Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient>(),
                new Uri("https://fake.vault.azure.net/keys/test/1"),
                certificate.SignatureAlgorithm)));

        // Setup SignDataAsync to return a fake signature
        A.CallTo(() => fakeGenerator.SignDataAsync(
                A<byte[]>._,
                A<HashAlgorithmName>._,
                A<CancellationToken>._))
            .ReturnsLazily((byte[] data, HashAlgorithmName hashAlg, CancellationToken ct) =>
            {
                // Generate a fake signature using the certificate's private key
                using var rsa = certificate.GetRSAPrivateKey() ?? RSA.Create(2048);
                return Task.FromResult(rsa.SignData(data, hashAlg, RSASignaturePadding.Pkcs1));
            });

        // Setup GetSignatureAlgorithmIdentifier to return proper OID
        A.CallTo(() => fakeGenerator.GetSignatureAlgorithmIdentifier(A<HashAlgorithmName>._))
            .ReturnsLazily((HashAlgorithmName hashAlg) => [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00]);

        return fakeGenerator;
    }

    protected static ILogger<T> CreateFakeLogger<T>()
    {
        return A.Fake<ILogger<T>>();
    }

    protected static IRevocationStore CreateFakeRevocationStore()
    {
        return A.Fake<IRevocationStore>();
    }
}
