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
        var kvServiceClient = new KeyVaultServiceOrchestrator(certificateClient,  uri => cryptographyClient, new XUnitLogger<KeyVaultServiceOrchestrator>(output));
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, new XUnitLogger<KeyVaultCertificateProvider>(output));

        var today = DateTimeOffset.UtcNow.Date;

        await kvCertProvider.CreateCACertificateAsync(
            "UnitTestCA", 
            "CN=UnitTestCA", 
            today.AddDays(-1),  
            today.AddDays(120), 
            1, 
            ct);

        await kvCertProvider.IssueCertificate(
            "UnitTestCA", 
            "RenewMe",
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
        //var cert = await kvServiceClient.GetCertificateAsync("RenewMe", ct);
        await kvServiceClient.IssueCertificateAsync("UnitTestCA",
            "RenewMe",
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

    public async Task It_should_cancel_pending_operation_for_other_issuer()
    {
        // TODO
    }
    
    public async Task It_should_continue_pending_operation()
    {
        // TODO
    }
    
    public async Task It_should_not_allow_overlapping_validity_periods()
    {
        // TODO
    }
}