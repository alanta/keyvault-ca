using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;

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
                _logger.LogInformation("A certificate with the specified issuer name {name} already exists.", issuerCertificateName);
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

        /// <summary>
        /// Sings a KeyVault Certificate Request with a CA certificate, also in KeyVault.
        /// </summary>
        public async Task<X509Certificate2> SignRequestAsync(
            Uri certificateUri,
            Uri issuerCertificateUri,
            int validityInDays)
        {
            if (!KeyVaultCertificateIdentifier.TryCreate(certificateUri, out var csrCertificateIdentifier))
            {
                throw new ArgumentException($"Invalid certificate identifier: {certificateUri}", nameof(certificateUri));
            }

            var credential = new DefaultAzureCredential();
            var csrKeyVault = new CertificateClient(csrCertificateIdentifier.VaultUri, credential );

            if (!KeyVaultCertificateIdentifier.TryCreate(issuerCertificateUri, out var issuerCertificateIdentifier))
            {
                throw new ArgumentException($"Invalid issuer certificate identifier: {issuerCertificateUri}", nameof(issuerCertificateUri));
            }
            var issuerKeyVault = new CertificateClient(issuerCertificateIdentifier.VaultUri, credential);
            
            var csrOperation = await csrKeyVault.GetCertificateOperationAsync(csrCertificateIdentifier.Name).ConfigureAwait(false);

            _logger.LogInformation("CSR: {csr}", Convert.ToBase64String(csrOperation.Properties.Csr));

            if (csrOperation?.Properties?.Csr == null)
            {
                throw new ArgumentException("CSR not found.");
            }
            if (csrOperation.HasCompleted)
            {
                throw new ArgumentException("No pending CSR on certificate.");
            }

            /*
            var requestedExtensions = pkcs10CertificationRequest.GetRequestedExtensions();
            foreach (var oid in requestedExtensions.GetExtensionOids())
            {
                
                // TODO: implement extension handling
                // 2.5.29.19 - Basic Constraints
                // 2.5.29.37 - Extended key usage
                // 2.5.29.15 - Key Usage
                // 2.5.29.17 - Subject Alternative Name

                _logger.LogInformation("Extension {oid} requested.", oid);
            }*/


            var certBundle = await issuerKeyVault.GetCertificateAsync(issuerCertificateIdentifier.Name).ConfigureAwait(false);
            if (certBundle.Value == null)
            {
                throw new ArgumentException("Issuer certificate not found.");
            }

            var signingCert = new X509Certificate2(certBundle.Value.Cer);
            
            return await CertificateFactory.SignRequest(
                csrOperation.Properties.Csr,
                signingCert,
                new KeyVaultSignatureGenerator(certBundle.Value.KeyId, credential, signingCert.SignatureAlgorithm),
                validityInDays,
                HashAlgorithmName.SHA256 );
        }
    }

    public static class ObjectIdentifierExtensions
    {
        public static bool IsEllipticCurveKey(this Oid? oid)
        {
            return oid != null && new DerObjectIdentifier(oid.Value).On(X9ObjectIdentifiers.ansi_X9_62);
        }

        public static bool IsDiffieHellmanKey(this Oid? oid)
        {
            return oid!=null && new DerObjectIdentifier(oid.Value).On(X9ObjectIdentifiers.DHPublicNumber);
        }
    }
}