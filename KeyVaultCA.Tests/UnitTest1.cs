using Azure.Identity;
using FluentAssertions;
using KeyVaultCa.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace KeyVaultCA.Tests
{
    public class UnitTest1
    {
        private readonly ITestOutputHelper _output;

        public UnitTest1(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task Test1()
        {
            var kvServiceClient = new KeyVaultServiceClient(
                               "https://mvv-kv-ca.vault.azure.net/",
                                              new DefaultAzureCredential(),
                               NullLoggerFactory.Instance.CreateLogger<KeyVaultServiceClient>());
            var kvCertProvider = new KeyVaultCertificateProvider( kvServiceClient, NullLoggerFactory.Instance.CreateLogger<KeyVaultCertificateProvider>());

            var operation = await kvServiceClient.GetCertificateSigningRequestAsync("test");
            var issuerCertName = "alanta-local-intermediate";
            
            var cert = await kvCertProvider.SignRequestAsync(operation.Properties.Csr, issuerCertName, 30, false);

            cert.Should().NotBeNull();

            _output.WriteLine(cert.ExportCertificatePem());

            cert.NotAfter.Should().BeCloseTo(DateTime.Now.AddDays(30), TimeSpan.FromMinutes(5));
        }
    }
}