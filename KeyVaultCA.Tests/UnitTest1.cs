using System.Security.Cryptography;
using Azure.Identity;
using FluentAssertions;
using KeyVaultCa.Core;
using KeyVaultCA.Tests.Tools;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Xunit.Abstractions;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace KeyVaultCA.Tests
{
    public class UnitTest1
    {
        private readonly ITestOutputHelper _output;
        private readonly ILoggerFactory _loggerFactory;

        private readonly string keyVaultUrl = "https://mvv-kv-ca.vault.azure.net/";
        private readonly static TokenCredential credential = CreateCredential();

        private static TokenCredential CreateCredential()
        {
            return new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeWorkloadIdentityCredential = true,
                ExcludeManagedIdentityCredential = true,
                ExcludeAzureDeveloperCliCredential = true,
                ExcludeVisualStudioCodeCredential = true, 
                ExcludeVisualStudioCredential = true,
                ExcludeAzurePowerShellCredential = true,
                ExcludeInteractiveBrowserCredential = true
            });
        }

        public UnitTest1(ITestOutputHelper output)
        {
            _output = output;
            _loggerFactory = new XunitLoggerFactory(output);
        }

        [Fact(Skip = "Integration test")]
        public async Task CreateCACertificate()
        {
            var certificateClient = new CertificateClient(new Uri(keyVaultUrl), credential);
            var kvServiceClient = new KeyVaultServiceClient(certificateClient, uri => new CryptographyClient(uri, credential), _loggerFactory.CreateLogger<KeyVaultServiceClient>());
            var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, _loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

            await kvCertProvider.CreateCACertificateAsync("UnitTestCA", "CN=UnitTestCA", DateTime.UtcNow, DateTime.UtcNow.AddDays(30), 1, default);
        }

        [Fact(Skip = "Integration test")]
        public async Task Test1()
        {
            var issuerCertificateName = "alanta-local-intermediate";
            var pendingCertificateName = "test";

            var pendingCertificateIdentifier = new KeyVaultCertificateIdentifier(new Uri($"{keyVaultUrl}certificates/{pendingCertificateName}"));
            var issuerCertificateIdentifier = new KeyVaultCertificateIdentifier(new Uri($"{keyVaultUrl}certificates/{issuerCertificateName}"));

            var certificateClient = new CertificateClient(new Uri(keyVaultUrl), credential);
            var kvServiceClient = new KeyVaultServiceClient(certificateClient, uri => new CryptographyClient(uri, credential), NullLoggerFactory.Instance.CreateLogger<KeyVaultServiceClient>());

            var cert = await kvServiceClient.SignRequestAsync(
                pendingCertificateIdentifier.SourceId,
                issuerCertificateIdentifier.SourceId, 
                30, 
                uri => new CertificateClient(uri, credential),
                uri => new CryptographyClient(uri, credential));

            cert.Should().NotBeNull();

            _output.WriteLine(cert.ExportCertificatePem());

            //cert.NotAfter.Should().BeCloseTo(DateTime.Now.AddDays(30), TimeSpan.FromMinutes(5));

            var builder = new SubjectAlternativeNameBuilder();
            builder.AddDnsName("test.local");
            builder.Build(true);

            var alternativeDNSNames = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(x => x.EnumerateDnsNames()).ToArray();
            alternativeDNSNames.Should().Contain("test.alanta.local");

            /*var credential = new DefaultAzureCredential();
            var csrKeyVault = new CertificateClient(pendingCertificateIdentifier.VaultUri, credential);

            MergeCertificateOptions options = new MergeCertificateOptions(pendingCertificateIdentifier.Name, new[] { cert.Export(X509ContentType.Pkcs12) });
            var mergeResult = await csrKeyVault.MergeCertificateAsync(options);*/
        }

        [Fact(Skip = "Integration test")]
        public async Task Test2()
        {
            var keyVaultUrl = "https://mvv-kv-ca.vault.azure.net/";
            var issuerCertificateName = "alanta-local-intermediate";
            var pendingCertificateName = "test";

            var certificateClient = new CertificateClient(new Uri(keyVaultUrl), credential);
            
            var operation = await certificateClient.GetCertificateOperationAsync(pendingCertificateName);
            
            var certBundle = await certificateClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);
            var signingCert = new X509Certificate2(certBundle.Value.Cer);

            var signatureGenerator = new KeyVaultSignatureGenerator(uri => new CryptographyClient(uri, credential), certBundle.Value.KeyId,  signingCert.SignatureAlgorithm);

            var cert = await CertificateFactory.SignRequest(operation.Properties.Csr, signingCert, signatureGenerator, 30, HashAlgorithmName.SHA256 );

            // TODO : build chain

            cert.Should().NotBeNull();

            _output.WriteLine(cert.ExportCertificatePem());

            cert.NotAfter.Should().BeBefore(DateTime.Now.AddDays(30));
            var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            basicConstraints.CertificateAuthority.Should().BeFalse();
            basicConstraints.HasPathLengthConstraint.Should().BeFalse();

            var alternativeDNSNames = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(x => x.EnumerateDnsNames()).ToArray();
            alternativeDNSNames.Should().Contain("test.alanta.local");

            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            keyUsage.KeyUsages.Should().Be(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyEncipherment);
        }

        [Fact]
        public async Task VerifyCSR()
        {
            var req = CertificateRequest.LoadSigningRequest(Convert.FromBase64String(csr), HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Should().NotBeEmpty();

            req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Should().NotBeEmpty();
            var alternativeDNSNames = req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(x => x.EnumerateDnsNames()).ToArray();
            alternativeDNSNames.Should().Contain("test.alanta.local");


            //var request = new Pkcs10CertificationRequestDelaySigned(Convert.FromBase64String(csr)); 
            //var extensions = request.GetRequestedExtensions();
            //var san = new GeneralName(GeneralName.DnsName, extensions.GetExtension(X509Extensions.SubjectAlternativeName).GetParsedValue()).Name;
            //san.Should().Be("DNS:test.alanta.local");
            //GeneralName altName = new GeneralName(GeneralName.DnsName, "fred.flintstone.com");
            //GeneralNames subjectAltName = new GeneralNames(altName);
            //cGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
        }

        private static readonly string csr = "MIICyjCCAbICAQAwHDEaMBgGA1UEAxMRdGVzdC5hbGFudGEubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIdIflP7mH+71SGf5YtBYGPkiW3NX2DMuqVZeR1bi2Xsd12D4MtfeEq6Sk3x7a/fUTdSFdvT3jX5SBY2VOSiYOtpcWXkRrKbCJoHDMBniW1dfCxD2DOyJQ/KI72RfqzyX+Uj8vIYuATM+pOC40y3nAy69Ht7P7PE5XHzH0uGUW8yV60j5rFyQnXiJVWxTP5w+Gic1aBMY3P85btDxtGn0BydhmIMWfrI6Q89wxY9lRc4bt5AL0tMOpfbs+2RCkwp0oLKFwRefD6+zu0XnfAx7hCvvdY+nDHT/h+NL1YZXwC98eGPswt7hBDUCY2AWUyO2g2ljtSNg4sHLqIb6twvadAgMBAAGgaTBnBgkqhkiG9w0BCQ4xWjBYMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHAYDVR0RBBUwE4IRdGVzdC5hbGFudGEubG9jYWwwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAihkyqUxdXPTlMufqQ/YVuANK2ilzWXva9yeUtVws7gkFILHSNIUQxXfTUkDea1B6MMpLqbEDHVJOah19Fr5zaWTlgcOT5KBwPwKdOnvHAn1ezbS7a7vW67Ar2M7ZDzqi0F5QjqO5cIKow5UWFnxMBJb06ps3lCB7wiYGSXt3j+W2ZGjK1C2h+pl7SxDZD6MoxnRoDgssHdZlgs8eHd2xqG4A/FCwX3fCBaQLuZhnXDDTimosV3WwgHqnG+stL5cAhEhj7LXuf+K1peiUwc0HBC+r4kkXR1FYPStydavEkU8T34cL8dYAY0w4K5tb9ys4q5rC8CVjrUAZN9ts8WapoQ==";
    }

    
}