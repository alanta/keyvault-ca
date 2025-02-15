using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;

namespace KeyVaultCa.Core
{
    public class KeyVaultCertificateProvider
    {
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;

        public KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILogger<KeyVaultCertificateProvider> logger)
        {
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
        }

        public async Task CreateCACertificateAsync(string issuerCertificateName, string subject, int certPathLength, CancellationToken ct)
        {
            var certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(issuerCertificateName, ct).ConfigureAwait(false);

            if (certVersions != 0)
            {
                _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", issuerCertificateName);
            }
            else
            {
                _logger.LogInformation("No existing certificate found, starting to create a new one.");
                var notBefore = DateTime.UtcNow.AddDays(-1);
                await _keyVaultServiceClient.CreateCACertificateAsync(
                        issuerCertificateName,
                        subject,
                        notBefore,
                        notBefore.AddMonths(48),
                        4096,
                        HashAlgorithmName.SHA256,
                        certPathLength,
                        ct);
                _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", issuerCertificateName, certPathLength);
            }
        }
        
        public async Task IssueCertificate(string issuerCertificateName, string certificateName, string subject, int validityInDays, CancellationToken ct)
        {
            try
            {
                var certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(certificateName, ct).ConfigureAwait(false);
                if (certVersions != 0)
                {
                    _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificateName);
                    
                }
            }
            catch (Azure.RequestFailedException requestEx)
            {
                _logger.LogError(requestEx.Message);
                return;
            }
            
            var sans = new SubjectAlternativeNames();
            sans.DnsNames.Add($"{certificateName}");
            //sans.Emails.Add("postmaster@alanta.local");
            //sans.UserPrincipalNames.Add("test@alanta.nl");

            await _keyVaultServiceClient.IssueCertificateAsync(
                issuerCertificateName,
                certificateName,
                subject,
                validityInDays,
                sans,
                ct);
        }
    }
}