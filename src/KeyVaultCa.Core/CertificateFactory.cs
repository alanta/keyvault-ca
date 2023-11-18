// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    public static class CertificateFactory
    {
        public const int SerialNumberLength = 20;
        public const int DefaultKeySize = 2048;

        public static Task<X509Certificate2> SignRequest(byte[] csr, X509Certificate2 issuerCert,
            X509SignatureGenerator generator, int validityInDays, HashAlgorithmName? hashAlgorithm = null)
        {
            if (csr == null)
            {
                throw new ArgumentNullException(nameof(csr));
            }

            if (issuerCert == null)
            {
                throw new ArgumentNullException(nameof(issuerCert));
            }

            if (validityInDays <= 0)
            {
                throw new ArgumentException("validityInDays must be greater than 0");
            }

            var request = CertificateRequest.LoadSigningRequest(csr, hashAlgorithm ?? HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);

            var alternativeDNSNames = request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(x => x.EnumerateDnsNames()).ToArray();
            // TODO : verify subject alternative names are allowed

            var basicConstraints =
                request.CertificateExtensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (basicConstraints == null)
            {
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            }
            else
            {
                // make sure it's not a CA cert
                if (basicConstraints.CertificateAuthority)
                {
                    throw new NotSupportedException("Cannot issue a CA certificate.");
                }
            }


            var defaultFlags = X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyEncipherment;
            var keyUsage = request.CertificateExtensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage == null)
            {
                request.CertificateExtensions.Add(new X509KeyUsageExtension(defaultFlags, true));
            }
            else
            {

            }

            var enhancedKeyUsage =
                request.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (enhancedKeyUsage == null)
            {
                // Enhanced key usage
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection
                        {
                            new Oid("1.3.6.1.5.5.7.3.1"), // serverAuth
                            new Oid("1.3.6.1.5.5.7.3.2") }, // clientAuth
                        true));
            }
       
            var serialNumber = GenerateSerialNumber();
            var notBefore = DateTime.UtcNow.AddDays(-1);
            var notAfter = notBefore.AddDays(validityInDays);

            if (notAfter > issuerCert.NotAfter)
            {
                notAfter = issuerCert.NotAfter;
            }
            if (notBefore < issuerCert.NotBefore)
            {
                notBefore = issuerCert.NotBefore;
            }

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
        /// Creates a KeyVault signed certificate.
        /// </summary>
        /// <returns>The signed certificate</returns>
        public static Task<X509Certificate2> CreateSignedCACertificate(
            string subjectName,
            DateTime notBefore,
            DateTime notAfter,
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
            RandomNumberGenerator.Fill(serialNumber); // yikes... should be using a crypto RNG?
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
            X509SubjectKeyIdentifierExtension ski
            )
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            {
                writer.PushSequence();

                if (ski != null)
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
                return new X509Extension("2.5.29.35", writer.Encode(), false);
            }
        }
    }
}
