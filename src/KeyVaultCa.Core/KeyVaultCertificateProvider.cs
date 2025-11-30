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

        public async Task CreateRootCertificate(
            KeyVaultSecretReference certificate, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            int? certPathLength, 
            CancellationToken ct)
        {
            var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificate, ct).ConfigureAwait(false);

            if (certVersions != 0)
            {
                _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificate.SecretName);
            }
            else
            {
                _logger.LogInformation("No existing certificate found, starting to create a new one.");
                
                await keyVaultServiceOrchestrator.CreateRootCertificateAsync(
                        certificate,
                        subject,
                        notBefore,
                        notAfter,
                        4096,
                        HashAlgorithmName.SHA256,
                        certPathLength,
                        ct);
                _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created successfully.", certificate.SecretName, certPathLength);
            }
        }
        
        public async Task IssueIntermediateCertificate(
            KeyVaultSecretReference issuerCertificate, 
            KeyVaultSecretReference certificate, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            SubjectAlternativeNames sans,
            int? certPathLength, 
            CancellationToken ct)
        {
            try
            {
                var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificate, ct).ConfigureAwait(false);
                if (certVersions != 0)
                {
                    _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificate.SecretName);
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
                issuerCertificate,
                certificate,
                subject,
                notBefore,
                notAfter,
                sans,
                certPathLength,
                ct);
            _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created successfully.", certificate.SecretName, certPathLength);
            
        }
        
        public async Task IssueCertificate(
            KeyVaultSecretReference issuerCertificate, 
            KeyVaultSecretReference certificate, 
            string subject, 
            DateTimeOffset notBefore, 
            DateTimeOffset notAfter, 
            SubjectAlternativeNames sans,
            CancellationToken ct)
        {
            try
            {
                var certVersions = await keyVaultServiceOrchestrator.GetCertificateVersionsAsync(certificate, ct).ConfigureAwait(false);
                if (certVersions != 0)
                {
                    _logger.LogWarning("A certificate with the specified issuer name {name} already exists.", certificate.SecretName);
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
                issuerCertificate,
                certificate,
                subject,
                notBefore,
                notAfter,
                sans,
                ct);
        }
    }
}