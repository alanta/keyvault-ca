using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    public static class CertificateFactory
    {
        public const string AuthorityKeyIdentifierOid = "2.5.29.35";
        public const int SerialNumberLength = 20;

        /// <summary>
        /// Signs a certificate request using an issuer certificate.
        /// </summary>
        /// <param name="csr">The certificate signing request.</param>
        /// <param name="issuerCert">The issuer certificate.</param>
        /// <param name="generator">The signature generator.</param>
        /// <param name="notAfter">The date and time in UTC until which the certificate must be valid.</param>
        /// <param name="notBefore">The date and time in UTC before which after which the certificate becomes valid.</param>
        /// <param name="hashAlgorithm">Optional. The hashing algorithm. Defaults tp SHA256</param>
        /// <param name="extensions">Optional. Aditional extension for the certificate. These extensions will replace
        /// extensions with the same OID in the CSR.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="NotSupportedException"></exception>
        public static Task<X509Certificate2> SignRequest(byte[] csr, X509Certificate2 issuerCert,
            X509SignatureGenerator generator, 
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            HashAlgorithmName? hashAlgorithm = null,
            IReadOnlyList<X509Extension>? extensions = null,
            CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(csr);
            ArgumentNullException.ThrowIfNull(issuerCert);
            
            if (notBefore >= notAfter)
            {
                throw new ArgumentException("Invalid validity period. notBefore must be before notAfter");
            }
            
            if (notAfter > issuerCert.NotAfter)
            {   
                throw new ArgumentException("Invalid validity period. Requested validity period is longer than the issuer certificate.");
            }
            if (notBefore < issuerCert.NotBefore)
            {
                throw new ArgumentException("Invalid validity period. Requested validity period starts before the issuer certificate is valid.");
            }
            
            var request = CertificateRequest.LoadSigningRequest(csr, hashAlgorithm ?? HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
            
            // Merge extensions
            if (extensions != null) MergeExtensions(request.CertificateExtensions, extensions);

            var alternativeDNSNames = request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(x => x.EnumerateDnsNames()).ToArray();
            // TODO : verify subject alternative names are allowed

            // Verify base constraints
            var basicConstraints = request.CertificateExtensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (basicConstraints == null)
            {
                basicConstraints = new X509BasicConstraintsExtension(false, false, 0, true);
                request.CertificateExtensions.Add(basicConstraints);
            }
            VerifyPathLengthConstraint(basicConstraints, issuerCert);

            var keyUsage = request.CertificateExtensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage == null)
            {
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyEncipherment, true));
            }
            
            var enhancedKeyUsage = request.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (enhancedKeyUsage == null)
            {
                // Enhanced key usage
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection
                        {
                            new Oid(WellKnownOids.ExtendedKeyUsages.ServerAuth),
                            new Oid(WellKnownOids.ExtendedKeyUsages.ClientAuth) 
                        },
                        true));
            }
            
            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);
            request.CertificateExtensions.Add(ski);
            
            // Authority Key Identifier
            var authorityKeyIdentifier = request.CertificateExtensions.FirstOrDefault(ext => ext.Oid?.Value == AuthorityKeyIdentifierOid);
            if(authorityKeyIdentifier == null)
            {
                request.CertificateExtensions.Add(BuildAuthorityKeyIdentifier(issuerCert));
            }

            var serialNumber = GenerateSerialNumber();

            X509Certificate2 signedCert = request.Create(
                issuerCert.SubjectName,
                generator,
                notBefore,
                notAfter,
                serialNumber
            );

            return Task.FromResult(signedCert);
        }

        /// <summary>
        /// Merge extensions by replacing any extension in the request of the same OID with the new extensions.
        /// If no existing extension is found, the new extension is added to the request.
        /// </summary>
        /// <param name="request">The collection to update.</param>
        /// <param name="extensions">The extensions to merge in.</param>
        public static void MergeExtensions(Collection<X509Extension> request, IReadOnlyList<X509Extension> extensions)
        {
            if (extensions.Count == 0)
            {
                return;
            }

            foreach (var extension in extensions)
            {
                var existingExtension = request.FirstOrDefault(x => x.Oid?.Value == extension.Oid?.Value);
                if (existingExtension != null)
                {
                    request.Remove(existingExtension);
                }
                request.Add(extension);
            }
        }

        private static void VerifyPathLengthConstraint(X509BasicConstraintsExtension basicConstraints, X509Certificate2 issuerCert)
        {
            var issuerBasicConstraints = issuerCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if( issuerBasicConstraints == null)
            {
                throw new NotSupportedException("Issuer certificate does not have basic constraints.");
            }
            if( !issuerBasicConstraints.CertificateAuthority )
            {
                throw new NotSupportedException("Issuer certificate is not a CA certificate.");
            }
            if (basicConstraints.CertificateAuthority && issuerBasicConstraints is { HasPathLengthConstraint: true })
            {
                if( issuerBasicConstraints.PathLengthConstraint <= 0)
                {
                    throw new InvalidOperationException("Path length constraint on the issuing certificate does not allow it to issue a CA certificate.");
                }
                if (basicConstraints.HasPathLengthConstraint && basicConstraints.PathLengthConstraint >= issuerBasicConstraints.PathLengthConstraint)
                {
                    throw new InvalidOperationException(
                        $"Path length constraint on the issuing certificate does not allow it to issue a CA certificate with the desired path length of {basicConstraints.PathLengthConstraint}.");
                }
            }
            
            // TODO: verify the actual length of the chain 
        }

        /// <summary>
        /// Creates a KeyVault signed certificate.
        /// </summary>
        /// <returns>The signed certificate</returns>
        public static Task<X509Certificate2> CreateSignedCACertificate(
            string subjectName,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            HashAlgorithmName hashAlgorithm,
            RSA publicKey,
            X509SignatureGenerator generator,
            int? certPathLength)
        {
            if (publicKey == null)
            {
                throw new NotSupportedException("Need a public key and a CA certificate.");
            }
            
            if (notBefore > notAfter)
            {
                throw new ArgumentException("notBefore must be before notAfter");
            }

            // new serial number
            var serialNumber = GenerateSerialNumber();

            var subjectDN = new X500DistinguishedName(subjectName);
            var request = new CertificateRequest(subjectDN, publicKey, hashAlgorithm, RSASignaturePadding.Pkcs1);
            
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, certPathLength.HasValue, certPathLength ?? 0, true));

            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);

            request.CertificateExtensions.Add(ski);

            // Authority Key Identifier
            request.CertificateExtensions.Add(BuildAuthorityKeyIdentifier(subjectDN, serialNumber.Reverse().ToArray(), ski));
        
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                    true));
            
            X509Certificate2 signedCert = request.Create(
                subjectDN,
                generator,
                notBefore,
                notAfter,
                serialNumber
                );

            return Task.FromResult(signedCert);
        }

        private static byte[] GenerateSerialNumber()
        {
            byte[] serialNumber = new byte[SerialNumberLength];
            RandomNumberGenerator.Fill(serialNumber);
            serialNumber[0] &= 0x7F;
            return serialNumber;
        }

        /// <summary>
        /// Get RSA public key from a CSR.
        /// </summary>
        public static RSA GetRSAPublicKey(Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter asymmetricKeyParameter = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
            if(!(asymmetricKeyParameter is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters))
            {
                throw new NotSupportedException("Only RSA public keys are supported.");
            }
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsaKeyParameters = (Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaKeyInfo = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            RSA rsa = RSA.Create(rsaKeyInfo);
            return rsa;
        }

        /// <summary>
        /// Convert a hex string to a byte array.
        /// </summary>
        /// <param name="hexString">The hex string</param>
        private static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, System.Globalization.NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        /// <summary>
        /// Build the Authority Key Identifier from an Issuer CA certificate.
        /// </summary>
        /// <param name="issuerCaCertificate">The issuer CA certificate</param>
        private static X509Extension BuildAuthorityKeyIdentifier(X509Certificate2 issuerCaCertificate)
        {
            // force exception if SKI is not present
            var ski = issuerCaCertificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
            return BuildAuthorityKeyIdentifier(issuerCaCertificate.SubjectName, issuerCaCertificate.GetSerialNumber(), ski);
        }

        /// <summary>
        /// Build the X509 Authority Key extension.
        /// </summary>
        /// <param name="issuerName">The distinguished name of the issuer</param>
        /// <param name="issuerSerialNumber">The serial number of the issuer</param>
        /// <param name="ski">The subject key identifier extension to use</param>
        private static X509Extension BuildAuthorityKeyIdentifier(
            X500DistinguishedName issuerName,
            byte[] issuerSerialNumber,
            X509SubjectKeyIdentifierExtension? ski
            )
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            {
                writer.PushSequence();

                if (ski is { SubjectKeyIdentifier: not null })
                {
                    Asn1Tag keyIdTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                    writer.WriteOctetString(HexToByteArray(ski.SubjectKeyIdentifier), keyIdTag);
                }

                Asn1Tag issuerNameTag = new Asn1Tag(TagClass.ContextSpecific, 1);
                writer.PushSequence(issuerNameTag);

                // Add the tag to constructed context-specific 4 (GeneralName.directoryName)
                Asn1Tag directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, true);
                writer.PushSetOf(directoryNameTag);
                byte[] issuerNameRaw = issuerName.RawData;
                writer.WriteEncodedValue(issuerNameRaw);
                writer.PopSetOf(directoryNameTag);
                writer.PopSequence(issuerNameTag);

                Asn1Tag issuerSerialTag = new Asn1Tag(TagClass.ContextSpecific, 2);
                System.Numerics.BigInteger issuerSerial = new System.Numerics.BigInteger(issuerSerialNumber);
                writer.WriteInteger(issuerSerial, issuerSerialTag);

                writer.PopSequence();
                return new X509Extension(AuthorityKeyIdentifierOid, writer.Encode(), false);
            }
        }
    }
}
