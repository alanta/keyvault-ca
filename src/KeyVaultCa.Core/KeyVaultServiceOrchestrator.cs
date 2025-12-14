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
    /// Implements multistep certificate operations to provide X509 certificate issuing using certificates stored in Azure Key Vault.
    /// </summary>
    public class KeyVaultServiceOrchestrator
    {
        private readonly Func<Uri, CertificateClient> _certificateClientFactory;
        private readonly Func<Uri, CryptographyClient> _cryptoClientFactory;
        private readonly ILogger _logger;

        /// <summary>
        /// Create the certificate client for managing certificates in Key Vault, using developer authentication locally or managed identity in the cloud.
        /// </summary>
        public KeyVaultServiceOrchestrator(
            Func<Uri, CertificateClient> certificateClientFactory,
            Func<Uri, CryptographyClient> cryptoClientFactory, 
            ILogger<KeyVaultServiceOrchestrator> logger)
        {
            _certificateClientFactory = certificateClientFactory;
            _cryptoClientFactory = cryptoClientFactory;
            _logger = logger;
        }

        public async Task<X509Certificate2> CreateRootCertificateAsync(
            KeyVaultSecretReference certificateReference,
            string subject,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            int keySize,
            HashAlgorithmName hashAlgorithm,
            int? certPathLength,
            CancellationToken ct = default)
        {
            var certificateClient = _certificateClientFactory(certificateReference.KeyVaultUrl);
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", certificateReference.SecretName);
                var op = await certificateClient.GetCertificateOperationAsync(certificateReference.SecretName, ct);
                await op.DeleteAsync(ct);
            }
            catch
            {
                // intentionally ignore errors 
            }

            var id = certificateReference.SecretName;
            string? caTempCertIdentifier = null;

            try
            {
                // create policy for self-signed certificate with a new key
                var policySelfSignedNewKey =
                    CreateCertificatePolicy(subject, keySize, true, CertificateKeyType.Rsa, reuseKey: false);

                var newCertificateOperation = await certificateClient
                    .StartCreateCertificateAsync(id, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", id);

                var createdCertificateBundle =
                    await certificateClient.GetCertificateAsync(id, ct).ConfigureAwait(false);
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
                var createResult = await certificateClient
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
                    new MergeCertificateOptions(id, [signedcert.Export(X509ContentType.Pkcs12)]);
                var mergeResult = await certificateClient.MergeCertificateAsync(options, ct);

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

                        Response<KeyVaultCertificate> certificateResponse =
                            await certificateClient.GetCertificateVersionAsync(id, caTempCertIdentifier, ct);
                        KeyVaultCertificate certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await certificateClient.UpdateCertificatePropertiesAsync(certificateProperties, ct);
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
        /// Get certificate versions for given certificate name.
        /// </summary>
        public async Task<int> GetCertificateVersionsAsync(KeyVaultSecretReference secret, CancellationToken ct)
        {
            var certificateClient = _certificateClientFactory(secret.KeyVaultUrl);
            
            var versions = 0;
            await foreach (CertificateProperties cert in certificateClient.GetPropertiesOfCertificateVersionsAsync(
                               secret.SecretName, ct).ConfigureAwait(false))
            {
                versions++;
                break;
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
        /// Signs a KeyVault Certificate Request with a CA certificate, also in KeyVault.
        /// </summary>
        public async Task<X509Certificate2> SignRequestAsync(
            Uri certificateUri,
            Uri issuerCertificateUri,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            Func<Uri, CertificateClient> keyVaultClientFactory,
            Func<Uri, CryptographyClient> cryptoClientFactory,
            IReadOnlyList<X509Extension>? extensions = null,
            RevocationConfig? revocationConfig = null,
            CancellationToken ct = default)
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

            var csrOperation = await csrKeyVault.GetCertificateOperationAsync(csrCertificateIdentifier.Name, ct)
                .ConfigureAwait(false);

            _logger.LogDebug("CSR: {csr}", Convert.ToBase64String(csrOperation.Properties.Csr));

            if (csrOperation?.Properties?.Csr == null)
            {
                throw new ArgumentException("CSR not found.");
            }

            if (csrOperation.HasCompleted)
            {
                throw new ArgumentException("No pending CSR on certificate.");
            }

            var certBundle = await issuerKeyVault.GetCertificateAsync(issuerCertificateIdentifier.Name, ct)
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
                notBefore,
                notAfter,
                HashAlgorithmName.SHA256,
                extensions,
                revocationConfig,
                ct);
        }

        public async Task IssueIntermediateCertificateAsync(
            KeyVaultSecretReference issuerCertificate,
            KeyVaultSecretReference certificate,
            string subject,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            SubjectAlternativeNames sans,
            int? pathLength,
            RevocationConfig? revocationConfig = null,
            CancellationToken ct = default)
        {
            var certificateClient = _certificateClientFactory(certificate.KeyVaultUrl);
            var startOperation = await CheckForPendingOperations(certificateClient, certificate.SecretName, ct);

            if (startOperation)
            {
                await certificateClient.StartCreateCertificateAsync(certificate.SecretName,
                    new CertificatePolicy("Unknown", subject, sans), cancellationToken: ct);
            }

            var signedCert2 = await SignRequestAsync(
                certificate.CertificateUri,
                issuerCertificate.CertificateUri,
                notBefore,
                notAfter,
                _certificateClientFactory,
                _cryptoClientFactory,
                extensions: [
                    new X509BasicConstraintsExtension(true, pathLength.HasValue, pathLength ?? 0, true),
                    new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true),
                    new X509EnhancedKeyUsageExtension(new OidCollection(){ new Oid(WellKnownOids.ExtendedKeyUsages.ServerAuth), new Oid(WellKnownOids.ExtendedKeyUsages.ClientAuth) }, false)
                ],
                revocationConfig,
                ct);
            await certificateClient.MergeCertificateAsync(new MergeCertificateOptions(certificate.SecretName,
                [signedCert2.RawData]), ct);
        }

        public async Task IssueCertificateAsync(
            KeyVaultSecretReference issuerCertificate,
            KeyVaultSecretReference certificate,
            string subject,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            SubjectAlternativeNames sans,
            RevocationConfig? revocationConfig = null,
            bool ocspSigning = false,
            CancellationToken ct = default)
        {
            var certificateClient = _certificateClientFactory(certificate.KeyVaultUrl);
            var startOperation = await CheckForPendingOperations(certificateClient, certificate.SecretName, ct);

            if (startOperation)
            {
                await certificateClient.StartCreateCertificateAsync(certificate.SecretName,
                    new CertificatePolicy("Unknown", subject, sans), cancellationToken: ct);
            }

            var extensionsList = new List<X509Extension>
            {
                new X509BasicConstraintsExtension(false, false, 0, true),
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true)
            };

            if (ocspSigning)
            {
                // RFC 6960 requires the OCSP Signing EKU extension to be marked as critical
                extensionsList.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.OCSPSigning) },
                    critical: true));
            }
            else
            {
                extensionsList.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid(WellKnownOids.ExtendedKeyUsages.ServerAuth), new Oid(WellKnownOids.ExtendedKeyUsages.ClientAuth) },
                    critical: false));
            }

            var signedCert2 = await SignRequestAsync(
                certificate.CertificateUri,
                issuerCertificate.CertificateUri,
                notBefore,
                notAfter,
                _certificateClientFactory,
                _cryptoClientFactory,
                extensions: extensionsList,
                revocationConfig,
                ct);
            await certificateClient.MergeCertificateAsync(new MergeCertificateOptions(certificate.SecretName,
                [signedCert2.RawData]), ct);
        }

        /// <summary>
        /// See if there are any pending operations for the given certificate name.
        /// Cancels the operation if it is not completed and the issuer is not "Unknown".
        /// </summary>
        /// <param name="client">A KeyVault CertificateClient for the Key Vault containing the certificate.</param>
        /// <param name="certificateName">The name of the certificate.</param>
        /// <param name="ct">A cancellation token</param>
        /// <returns>True if a new operation should be started.</returns>
        private async Task<bool> CheckForPendingOperations(CertificateClient client, string certificateName, CancellationToken ct)
        {
            var startOperation = true;
            try
            {
                var op = await client.GetCertificateOperationAsync(certificateName, ct);
                if (!(op.HasCompleted || string.Equals(op.Properties.Status, "completed", StringComparison.InvariantCulture)))
                {
                    _logger.LogWarning("Operation {operationId} is pending for certificate {certificateName}.",  op.Id, certificateName);
                    if (op.Properties.IssuerName != "Unknown")
                    {
                        _logger.LogInformation("Cancelling pending operation {operationId}.", op.Id);
                        await op.CancelAsync(ct);
                    }
                    else
                    {
                        startOperation = false;
                    }
                }
            }
            catch (RequestFailedException requestEx) when (requestEx.Status == 404)
            {
                // No pending operation found, continue
                _logger.LogDebug("No pending operation found for certificate {certificateName}.", certificateName);
            }

            return startOperation;
        }
    }
}