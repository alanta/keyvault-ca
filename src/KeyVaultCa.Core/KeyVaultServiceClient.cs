// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Azure;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace KeyVaultCa.Core
{
    /// <summary>
    /// The KeyVault service client.
    /// </summary>
    public class KeyVaultServiceClient
    {
        private readonly CertificateClient _certificateClient;
        private readonly Func<Uri, CryptographyClient> _cryptoClientFactory;
        private readonly ILogger _logger;

        /// <summary>
        /// Create the certificate client for managing certificates in Key Vault, using developer authentication locally or managed identity in the cloud.
        /// </summary>
        public KeyVaultServiceClient(
            CertificateClient certificateClient,
            Func<Uri, CryptographyClient> cryptoClientFactory, ILogger<KeyVaultServiceClient> logger)
        {
            _certificateClient = certificateClient;
            _cryptoClientFactory = cryptoClientFactory;
            _logger = logger;
        }

        internal async Task<X509Certificate2> CreateCACertificateAsync(
            string id,
            string subject,
            DateTime notBefore,
            DateTime notAfter,
            int keySize,
            HashAlgorithmName hashAlgorithm,
            int? certPathLength = 1,
            CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", id);
                var op = await _certificateClient.GetCertificateOperationAsync(id, ct);
                await op.DeleteAsync(ct);
            }
            catch
            {
                // intentionally ignore errors 
            }

            string? caTempCertIdentifier = null;

            try
            {
                // create policy for self-signed certificate with a new key
                var policySelfSignedNewKey =
                    CreateCertificatePolicy(subject, keySize, true, CertificateKeyType.Rsa, reuseKey: false);

                var newCertificateOperation = await _certificateClient
                    .StartCreateCertificateAsync(id, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", id);

                var createdCertificateBundle =
                    await _certificateClient.GetCertificateAsync(id, ct).ConfigureAwait(false);
                caTempCertIdentifier = createdCertificateBundle.Value.Id.Segments.Last();

                _logger.LogDebug("Temporary certificate identifier is {certIdentifier}.", caTempCertIdentifier);
                _logger.LogDebug("Temporary certificate backing key identifier is {key}.",
                    createdCertificateBundle.Value.KeyId);

                // create policy for unknown issuer and reuse key
                var policyUnknownReuse =
                    CreateCertificatePolicy(subject, keySize, false, CertificateKeyType.Rsa, reuseKey: true);
                var tags = CreateCertificateTags(id, false);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                var createResult = await _certificateClient
                    .StartCreateCertificateAsync(id, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                var pkcs10CertificationRequest =
                    new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(createResult.Properties.Csr);
                var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }

                // create the self-signed root CA certificate
                _logger.LogDebug("Create the self signed root CA certificate.");
                var publicKey = CertificateFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                var signedcert = await CertificateFactory.CreateSignedCACertificate(
                    subject,
                    notBefore,
                    notAfter,
                    hashAlgorithm,
                    publicKey,
                    new KeyVaultSignatureGenerator(_cryptoClientFactory, createdCertificateBundle.Value.KeyId),
                    certPathLength);

                // merge Root CA cert with the signed certificate
                _logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                MergeCertificateOptions options =
                    new MergeCertificateOptions(id, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                var mergeResult = await _certificateClient.MergeCertificateAsync(options, ct);

                return signedcert;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new Root CA certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse =
                            await _certificateClient.GetCertificateAsync(caTempCertIdentifier, ct);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _certificateClient.UpdateCertificatePropertiesAsync(certificateProperties, ct);
                    }
                    catch(Exception ex)
                    {
                        // intentionally ignore error
                        _logger.LogError(ex, "Failed to disable temporary certificate.");
                    }
                }
            }
        }

        /// <summary>
        /// Get Certificate with Policy from Key Vault.
        /// </summary>
        public async Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certName,
            CancellationToken ct = default)
        {
            return await _certificateClient.GetCertificateAsync(certName, ct).ConfigureAwait(false);
        }

        public async Task<CertificateOperation> GetCertificateSigningRequestAsync(string certName,
            CancellationToken ct = default)
        {
            return await _certificateClient.GetCertificateOperationAsync(certName, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Get certificate versions for given certificate name.
        /// </summary>
        public async Task<int> GetCertificateVersionsAsync(string certName, CancellationToken ct)
        {
            var versions = 0;
            await foreach (CertificateProperties cert in _certificateClient.GetPropertiesOfCertificateVersionsAsync(
                               certName, ct).ConfigureAwait(false))
            {
                versions++;
            }

            return versions;
        }

        private Dictionary<string, string> CreateCertificateTags(string id, bool trusted)
        {
            var tags = new Dictionary<string, string>
            {
                [id] = trusted ? "Trusted" : "Issuer"
            };

            _logger.LogDebug("Created certificate tags for certificate with id {id} and trusted flag set to {trusted}.",
                id, trusted);
            return tags;
        }

        private CertificatePolicy CreateCertificatePolicy(
            string subject,
            int keySize, // 512, 1024, 2048, 3072, 4096
            bool selfSigned,
            CertificateKeyType keyType,
            bool reuseKey = false,
            bool exportable = false)
        {
            var issuerName = selfSigned ? "Self" : "Unknown";
            var policy = new CertificatePolicy(issuerName, subject)
            {

                Exportable = exportable,
                KeySize = keySize,
                KeyType = keyType,
                ReuseKey = reuseKey,
                ContentType = CertificateContentType.Pkcs12
            };

            _logger.LogDebug(
                "Created certificate policy for certificate with issuer name {issuerName}, self signed {selfSigned} and reused key {reuseKey}.",
                issuerName, selfSigned, reuseKey);
            return policy;
        }

        /// <summary>
        /// Sings a KeyVault Certificate Request with a CA certificate, also in KeyVault.
        /// </summary>
        public async Task<X509Certificate2> SignRequestAsync(
            Uri certificateUri,
            Uri issuerCertificateUri,
            int validityInDays,
            Func<Uri, CertificateClient> keyVaultClientFactory,
            Func<Uri, CryptographyClient> cryptoClientFactory)
        {
            if (!KeyVaultCertificateIdentifier.TryCreate(certificateUri, out var csrCertificateIdentifier))
            {
                throw new ArgumentException($"Invalid certificate identifier: {certificateUri}",
                    nameof(certificateUri));
            }

            var csrKeyVault = keyVaultClientFactory(csrCertificateIdentifier.VaultUri);

            if (!KeyVaultCertificateIdentifier.TryCreate(issuerCertificateUri, out var issuerCertificateIdentifier))
            {
                throw new ArgumentException($"Invalid issuer certificate identifier: {issuerCertificateUri}",
                    nameof(issuerCertificateUri));
            }

            var issuerKeyVault = keyVaultClientFactory(issuerCertificateIdentifier.VaultUri);

            var csrOperation = await csrKeyVault.GetCertificateOperationAsync(csrCertificateIdentifier.Name)
                .ConfigureAwait(false);

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


            var certBundle = await issuerKeyVault.GetCertificateAsync(issuerCertificateIdentifier.Name)
                .ConfigureAwait(false);
            if (certBundle.Value == null)
            {
                throw new ArgumentException("Issuer certificate not found.");
            }

            var signingCert = new X509Certificate2(certBundle.Value.Cer);

            return await CertificateFactory.SignRequest(
                csrOperation.Properties.Csr,
                signingCert,
                new KeyVaultSignatureGenerator(cryptoClientFactory, certBundle.Value.KeyId,
                    signingCert.SignatureAlgorithm),
                validityInDays,
                HashAlgorithmName.SHA256);
        }

        public async Task IssueCertificateAsync(
            string issuerCertificateName, 
            string certificateName, 
            string subject, int validityInDays, SubjectAlternativeNames sans, CancellationToken ct)
        {
            await _certificateClient.StartCreateCertificateAsync(certificateName, new CertificatePolicy("Unknown", subject, sans ), cancellationToken: ct);
            var signedCert2 = await SignRequestAsync(
                new Uri($"{_certificateClient.VaultUri}certificates/{certificateName}"),
                new Uri($"{_certificateClient.VaultUri}certificates/{issuerCertificateName}"),
                validityInDays,
                uri => _certificateClient, // WARNING : Assuming the same keyvault for now
                _cryptoClientFactory);
            await _certificateClient.MergeCertificateAsync(new MergeCertificateOptions(certificateName, new []{signedCert2.RawData}), default);
        }
    }
}