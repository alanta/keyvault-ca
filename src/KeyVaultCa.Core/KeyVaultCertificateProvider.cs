using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;

namespace KeyVaultCa.Core
{
    
    /// <summary>
    /// High-level API for creating and issuing certificates using Azure Key Vault.
    /// </summary>
    /// <param name="keyVaultServiceOrchestrator"></param>
    /// <param name="logger"></param>
    public class KeyVaultCertificateProvider(
        KeyVaultServiceOrchestrator keyVaultServiceOrchestrator,
        ILogger<KeyVaultCertificateProvider> logger)
    {
        private readonly ILogger _logger = logger;

        public async Task CreateCACertificateAsync(
            string certificateName, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            int? certPathLength, 
            CancellationToken ct)
        {
            var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificateName, ct).ConfigureAwait(false);

            if (certVersions != 0)
            {
                _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificateName);
            }
            else
            {
                _logger.LogInformation("No existing certificate found, starting to create a new one.");
                
                await keyVaultServiceOrchestrator.CreateRootCertificateAsync(
                        certificateName,
                        subject,
                        notBefore,
                        notAfter,
                        4096,
                        HashAlgorithmName.SHA256,
                        certPathLength,
                        ct);
                _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created successfully.", certificateName, certPathLength);
            }
        }
        
        public async Task IssueIntermediateCertificateAsync(
            string issuerCertificateName, 
            string certificateName, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            SubjectAlternativeNames sans,
            int? certPathLength, 
            CancellationToken ct)
        {
            try
            {
                var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificateName, ct).ConfigureAwait(false);
                if (certVersions != 0)
                {
                    _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificateName);
                }
                else
                {
                    _logger.LogInformation("No existing certificate found, starting to create a new one.");
                }
            }
            catch (Azure.RequestFailedException requestEx)
            {
                _logger.LogError(requestEx.Message);
                return;
            }

            await keyVaultServiceOrchestrator.IssueIntermediateCertificateAsync(
                issuerCertificateName,
                certificateName,
                subject,
                notBefore,
                notAfter,
                sans,
                certPathLength,
                ct);
            _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created successfully.", certificateName, certPathLength);
            
        }
        
        public async Task IssueCertificate(
            string issuerCertificateName, 
            string certificateName, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            SubjectAlternativeNames sans,
            CancellationToken ct)
        {
            try
            {
                var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificateName, ct).ConfigureAwait(false);
                if (certVersions != 0)
                {
                    _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificateName);
                }
                else
                {
                    
                    _logger.LogInformation("No existing certificate found, starting to create a new one.");
                }
            }
            catch (Azure.RequestFailedException requestEx)
            {
                _logger.LogError(requestEx.Message);
                return;
            }

            await keyVaultServiceOrchestrator.IssueCertificateAsync(
                issuerCertificateName,
                certificateName,
                subject,
                notBefore,
                notAfter,
                sans,
                ct);
        }
    }
}