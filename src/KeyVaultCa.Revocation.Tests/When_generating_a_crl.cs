using System.Security.Cryptography;
using FakeItEasy;
using KeyVaultCa.Revocation.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Shouldly;

namespace KeyVaultCa.Revocation.Tests;

public class When_generating_a_crl : TestBase
{
    [Fact]
    public async Task It_should_generate_a_valid_crl_with_no_revocations()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);
        var revocationStore = CreateFakeRevocationStore();

        A.CallTo(() => revocationStore.GetRevocationsByIssuerAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<IEnumerable<RevocationRecord>>(Array.Empty<RevocationRecord>()));

        var crlGenerator = new CrlGenerator(revocationStore);

        // Act
        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCert,
            signatureGenerator,
            issuerCert.Subject,
            TimeSpan.FromDays(7),
            HashAlgorithmName.SHA256,
            crlNumber: 1,
            CancellationToken.None);

        // Assert
        crlBytes.ShouldNotBeNull();
        crlBytes.Length.ShouldBeGreaterThan(0);

        // Verify it's a valid CRL
        var crl = new X509Crl(crlBytes);
        crl.IssuerDN.ToString().ShouldBe(issuerCert.Subject);
        crl.NextUpdate.ShouldNotBeNull();
        crl.ThisUpdate.ShouldNotBe(default(DateTime));
    }

    [Fact]
    public async Task It_should_include_revoked_certificates_in_crl()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);
        var revocationStore = CreateFakeRevocationStore();

        var revokedSerials = new List<RevocationRecord>
        {
            new()
            {
                SerialNumber = "1234567890ABCDEF",
                RevocationDate = DateTimeOffset.UtcNow.AddDays(-1),
                Reason = RevocationReason.KeyCompromise,
                IssuerDistinguishedName = issuerCert.Subject
            },
            new()
            {
                SerialNumber = "FEDCBA0987654321",
                RevocationDate = DateTimeOffset.UtcNow.AddDays(-2),
                Reason = RevocationReason.Superseded,
                IssuerDistinguishedName = issuerCert.Subject
            }
        };

        A.CallTo(() => revocationStore.GetRevocationsByIssuerAsync(issuerCert.Subject, A<CancellationToken>._))
            .Returns(Task.FromResult<IEnumerable<RevocationRecord>>(revokedSerials));

        var crlGenerator = new CrlGenerator(revocationStore);

        // Act
        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCert,
            signatureGenerator,
            issuerCert.Subject,
            TimeSpan.FromDays(7),
            HashAlgorithmName.SHA256,
            crlNumber: 2,
            CancellationToken.None);

        // Assert
        crlBytes.ShouldNotBeNull();

        var crl = new X509Crl(crlBytes);
        var revokedCerts = crl.GetRevokedCertificates();

        revokedCerts.ShouldNotBeNull();
        revokedCerts.Count.ShouldBe(2);

        var serials = revokedCerts.Cast<X509CrlEntry>()
            .Select(e => e.SerialNumber.ToString(16).ToUpperInvariant())
            .ToList();

        serials.ShouldContain("1234567890ABCDEF");
        serials.ShouldContain("FEDCBA0987654321");
    }

    [Fact]
    public async Task It_should_include_crl_number_extension()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);
        var revocationStore = CreateFakeRevocationStore();

        A.CallTo(() => revocationStore.GetRevocationsByIssuerAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<IEnumerable<RevocationRecord>>(Array.Empty<RevocationRecord>()));

        var crlGenerator = new CrlGenerator(revocationStore);

        const long expectedCrlNumber = 42;

        // Act
        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCert,
            signatureGenerator,
            issuerCert.Subject,
            TimeSpan.FromDays(7),
            HashAlgorithmName.SHA256,
            crlNumber: expectedCrlNumber,
            CancellationToken.None);

        // Assert
        var crl = new X509Crl(crlBytes);
        var crlNumberExt = crl.GetExtensionValue(X509Extensions.CrlNumber);

        crlNumberExt.ShouldNotBeNull();

        var crlNumberAsn = DerInteger.GetInstance(Asn1Object.FromByteArray(crlNumberExt.GetOctets()));
        crlNumberAsn.Value.LongValue.ShouldBe(expectedCrlNumber);
    }

    [Fact]
    public async Task It_should_include_authority_key_identifier_extension()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);
        var revocationStore = CreateFakeRevocationStore();

        A.CallTo(() => revocationStore.GetRevocationsByIssuerAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<IEnumerable<RevocationRecord>>(Array.Empty<RevocationRecord>()));

        var crlGenerator = new CrlGenerator(revocationStore);

        // Act
        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCert,
            signatureGenerator,
            issuerCert.Subject,
            TimeSpan.FromDays(7),
            HashAlgorithmName.SHA256,
            crlNumber: 1,
            CancellationToken.None);

        // Assert
        var crl = new X509Crl(crlBytes);
        var akiExt = crl.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);

        akiExt.ShouldNotBeNull();
    }

    [Fact]
    public async Task It_should_set_validity_period_correctly()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var signatureGenerator = CreateFakeSignatureGenerator(issuerCert);
        var revocationStore = CreateFakeRevocationStore();

        A.CallTo(() => revocationStore.GetRevocationsByIssuerAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<IEnumerable<RevocationRecord>>(Array.Empty<RevocationRecord>()));

        var crlGenerator = new CrlGenerator(revocationStore);
        var validityPeriod = TimeSpan.FromDays(30);
        var before = DateTime.UtcNow;

        // Act
        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCert,
            signatureGenerator,
            issuerCert.Subject,
            validityPeriod,
            HashAlgorithmName.SHA256,
            crlNumber: 1,
            CancellationToken.None);

        var after = DateTime.UtcNow;

        // Assert
        var crl = new X509Crl(crlBytes);

        // Add tolerance of 2 seconds to account for fast execution
        crl.ThisUpdate.ShouldBeInRange(before.AddSeconds(-2), after.AddSeconds(2));
        crl.NextUpdate.Value.ShouldBeInRange(
            before.Add(validityPeriod).AddSeconds(-2),
            after.Add(validityPeriod).AddSeconds(2));
    }
}
