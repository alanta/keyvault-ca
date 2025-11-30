using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using FakeItEasy;
using FluentAssertions;
using KeyVaultCa.Core;
using KeyVaultCA.Tests.KeyVault;
using KeyVaultCA.Tests.Tools;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests.Core;

public class When_renewing_a_certificate(ITestOutputHelper output)
{
    [Fact]
    public async Task It_should_renew_an_existing_cert()
    {
        // Arrange
        var ct = CancellationToken.None;
        var certificateOperations = new CertificateStore();
        var certificateClient = certificateOperations.GetFakeCertificateClient();
        
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        var today = DateTimeOffset.UtcNow.Date;

        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"), 
            "CN=UnitTestCA", 
            today.AddDays(-1),  
            today.AddDays(120), 
            1, 
            ct);

        await kvCertProvider.IssueCertificate(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"),
            new KeyVaultSecretReference(certificateOperations.VaultUri, "RenewMe"), 
            "CN=test.local", 
            today, 
            today.AddDays(30),
            new SubjectAlternativeNames()
            {
                DnsNames = { "test.local" }
            }, 
            ct);
        ;
        // Act
        // Re-issue the leaf cert
        // It should keep all extensions but update the validity period.
        // It should create a new key (NIST recommendation)
        
        // Load the existing certificate from keyvault
        await kvServiceClient.IssueCertificateAsync(
            new KeyVaultSecretReference(certificateOperations.VaultUri, "UnitTestCA"),
            new KeyVaultSecretReference(certificateOperations.VaultUri, "RenewMe"), 
            "CN=test.local",
            today.AddDays(30),
            today.AddDays(60),
            new SubjectAlternativeNames()
            {
                DnsNames = { "test.local" }
            },
            ct);

        /*await kvCertProvider.RenewCertificateAsync(
            "RenewMe",
            today.AddDays(1),
            today.AddDays(31),
            default);*/
        
        // Verify
        // Validity period starts after previous version
        var renewedCert = await certificateClient.GetCertificateAsync("RenewMe", ct);
        var x509Renewed = new X509Certificate2(renewedCert.Value.Cer);
        x509Renewed.NotBefore.Should().Be(today.AddDays(30));
        x509Renewed.NotAfter.Should().Be(today.AddDays(60));
    }

    [Fact]
    public async Task It_should_cancel_pending_operation_for_other_issuer()
    {
        // Arrange
        var ct = CancellationToken.None;
        var certificateStore = new CertificateStore();
        var certificateClient = certificateStore.GetFakeCertificateClient();
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient, _ => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        var today = DateTimeOffset.UtcNow.Date;

        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(certificateStore.VaultUri, "UnitTestCA"),
            "CN=UnitTestCA",
            today.AddDays(-1),
            today.AddDays(120),
            1,
            ct);

        // Simulate a pending operation created with a different issuer (e.g. manually via portal)
        var pendingPolicy = new CertificatePolicy("Self", "CN=test.local", new SubjectAlternativeNames
        {
            DnsNames = { "pending.test.local" }
        });
        await certificateClient.StartCreateCertificateAsync("RenewMe", pendingPolicy, true, null, ct);

        var pendingVersion = certificateStore.CertificateVersions.Single(v => v.Name == "RenewMe");
        pendingVersion.HasCompleted = false;
        pendingVersion.Certificate = null;

        // Act
        Func<Task> issueTask = () => kvCertProvider.IssueCertificate(
            new KeyVaultSecretReference(certificateStore.VaultUri, "UnitTestCA"),
            new KeyVaultSecretReference(certificateStore.VaultUri, "RenewMe"),
            "CN=test.local",
            today,
            today.AddDays(30),
            new SubjectAlternativeNames
            {
                DnsNames = { "test.local" }
            },
            ct);

        // Assert
        await issueTask.Should().NotThrowAsync("pending operations from other issuers should be cancelled before issuing");

        var versions = certificateStore.CertificateVersions.Where(v => v.Name == "RenewMe").ToList();
        versions.Should().HaveCount(1);
        versions[0].HasCompleted.Should().BeTrue();
    }
    
    [Fact]
    public async Task It_should_continue_pending_operation()
    {
        // Arrange
        var ct = CancellationToken.None;
        var certificateStore = new CertificateStore();
        var certificateClient = certificateStore.GetFakeCertificateClient();
        var cryptographyClient = A.Fake<CryptographyClient>();
        var kvServiceClient = new KeyVaultServiceOrchestrator(_ => certificateClient, _ => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        var today = DateTimeOffset.UtcNow.Date;

        await kvCertProvider.CreateRootCertificate(
            new KeyVaultSecretReference(certificateStore.VaultUri, "UnitTestCA"),
            "CN=UnitTestCA",
            today.AddDays(-1),
            today.AddDays(120),
            1,
            ct);

        // Simulate an earlier issuance that left a pending CSR with issuer Unknown (the orchestrator's default)
        var pendingPolicy = new CertificatePolicy("Unknown", "CN=test.local", new SubjectAlternativeNames
        {
            DnsNames = { "test.local" }
        });
        await certificateClient.StartCreateCertificateAsync("RenewMe", pendingPolicy, true, null, ct);

        var pendingVersion = certificateStore.CertificateVersions.Single(v => v.Name == "RenewMe");
        pendingVersion.HasCompleted.Should().BeFalse();

        // Act
        Func<Task> issueTask = () => kvCertProvider.IssueCertificate(
            new KeyVaultSecretReference(certificateStore.VaultUri, "UnitTestCA"),
            new KeyVaultSecretReference(certificateStore.VaultUri, "RenewMe"),
            "CN=test.local",
            today,
            today.AddDays(30),
            new SubjectAlternativeNames
            {
                DnsNames = { "test.local" }
            },
            ct);

        // Assert
        await issueTask.Should().NotThrowAsync("pending operations with issuer Unknown should be continued");

        var versions = certificateStore.CertificateVersions.Where(v => v.Name == "RenewMe").ToList();
        versions.Should().HaveCount(1, "continuing should reuse the existing pending operation");
        versions[0].HasCompleted.Should().BeTrue();
        versions[0].Certificate.Should().NotBeNull();
    }
}