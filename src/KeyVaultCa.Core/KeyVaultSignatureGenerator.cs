using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Threading;
using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace KeyVaultCa.Core
{
    public class KeyVaultSignatureGenerator : X509SignatureGenerator
    {
        private readonly Lazy<CryptographyClient> _client;
        private readonly X509SignatureGenerator _generator;
        private readonly bool _isEcdsa;

        private class FakeECDsaKey : ECDsa
        {
            public override byte[] SignHash(byte[] hash)
            {
                throw new NotImplementedException();
            }

            public override bool VerifyHash(byte[] hash, byte[] signature)
            {
                throw new NotImplementedException();
            }
        }

        private class FakeRsaKey : RSA
        {
            public override RSAParameters ExportParameters(bool includePrivateParameters)
            {
                throw new NotImplementedException();
            }

            public override void ImportParameters(RSAParameters parameters)
            {
                throw new NotImplementedException();
            }
        }

        public KeyVaultSignatureGenerator(Uri keyUri, TokenCredential credential, bool ellipticCurve)
        {
            _client = new Lazy<CryptographyClient>(() => new CryptographyClient(keyUri, credential));
            _generator = ellipticCurve ? CreateForECDsa(new FakeECDsaKey()) : CreateForRSA(new FakeRsaKey(), RSASignaturePadding.Pkcs1);
            _isEcdsa = ellipticCurve;
        }

        protected override PublicKey BuildPublicKey()
        {
            throw new NotImplementedException();
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            return _generator.GetSignatureAlgorithmIdentifier(hashAlgorithm);
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            return SignDataAsync(data, hashAlgorithm, CancellationToken.None).GetAwaiter().GetResult();
        }

        public Task<byte[]> SignDataAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken ct)
        {
            HashAlgorithm hash;
            if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                hash = SHA256.Create();
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                hash = SHA384.Create();
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                hash = SHA512.Create();
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), "The hash algorithm " + hashAlgorithm.Name + " is not supported.");
            }
            var digest = hash.ComputeHash(data);
            return SignDigestAsync(digest, hashAlgorithm, ct);
        }

        /// <summary>
        /// Sign a digest with the signing key.
        /// </summary>
        public async Task<byte[]> SignDigestAsync(
            byte[] digest,
            HashAlgorithmName hashAlgorithm,
            CancellationToken ct)
        {
            SignatureAlgorithm algorithm;

            switch (hashAlgorithm.Name)
            {
                case "SHA256":
                    algorithm = _isEcdsa ? SignatureAlgorithm.ES256 : SignatureAlgorithm.RS256;
                    break;
                case "SHA384":
                    algorithm = _isEcdsa ? SignatureAlgorithm.ES384 : SignatureAlgorithm.RS384;
                    break;
                case "SHA512":
                    algorithm = _isEcdsa ? SignatureAlgorithm.ES512 : SignatureAlgorithm.RS512;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), "The hash algorithm " + hashAlgorithm.Name + " is not supported.");
            }
            
            SignResult result = null;

            /*Random jitterer = new();

            var retryPolicy = await Policy
              .Handle<Exception>() // etc
              .WaitAndRetryAsync(6, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt))  // exponential back-off: 2, 4, 8 etc
                               + TimeSpan.FromMilliseconds(jitterer.Next(0, 1000))) // plus some jitter: up to 1 second                                                                                                  
              .ExecuteAndCaptureAsync(async () =>
              {
                  result = ;
              });*/

            result = await _client.Value.SignAsync(algorithm, digest, ct).ConfigureAwait(false);

            return result.Signature;
        }
    }
}
