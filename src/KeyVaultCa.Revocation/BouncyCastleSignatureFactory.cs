using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using KeyVaultCa.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace KeyVaultCa.Revocation;

/// <summary>
/// Adapter that allows BouncyCastle CRL and OCSP generators to use Azure Key Vault for signing.
/// Implements BouncyCastle's ISignatureFactory interface by delegating to KeyVaultSignatureGenerator.
/// </summary>
public class BouncyCastleSignatureFactory : ISignatureFactory
{
    private readonly KeyVaultSignatureGenerator _signatureGenerator;
    private readonly X509Certificate2 _signerCertificate;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly string _algorithmOid;

    public BouncyCastleSignatureFactory(
        KeyVaultSignatureGenerator signatureGenerator,
        X509Certificate2 signerCertificate,
        HashAlgorithmName hashAlgorithm)
    {
        _signatureGenerator = signatureGenerator;
        _signerCertificate = signerCertificate;
        _hashAlgorithm = hashAlgorithm;

        // Determine the signature algorithm OID based on key type and hash algorithm
        _algorithmOid = DetermineAlgorithmOid(signerCertificate, hashAlgorithm);
    }

    public object AlgorithmDetails => AlgorithmIdentifier.GetInstance(Asn1Object.FromByteArray(
        _signatureGenerator.GetSignatureAlgorithmIdentifier(_hashAlgorithm)));

    public IStreamCalculator CreateCalculator()
    {
        return new SignatureStreamCalculator(_signatureGenerator, _hashAlgorithm);
    }

    private static string DetermineAlgorithmOid(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm)
    {
        var isEcdsa = certificate.GetECDsaPublicKey() != null;

        if (isEcdsa)
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => WellKnownOids.SignatureAlgorithms.ECDsaWithSha256,
                "SHA384" => WellKnownOids.SignatureAlgorithms.ECDsaWithSha384,
                "SHA512" => WellKnownOids.SignatureAlgorithms.ECDsaWithSha512,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm.Name}")
            };
        }
        else
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => WellKnownOids.SignatureAlgorithms.Sha256WithRSAEncryption,
                "SHA384" => WellKnownOids.SignatureAlgorithms.Sha384WithRSAEncryption,
                "SHA512" => WellKnownOids.SignatureAlgorithms.Sha512WithRSAEncryption,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm.Name}")
            };
        }
    }

    private class SignatureStreamCalculator : IStreamCalculator
    {
        private readonly KeyVaultSignatureGenerator _signatureGenerator;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly MemoryStream _dataStream;

        public SignatureStreamCalculator(KeyVaultSignatureGenerator signatureGenerator, HashAlgorithmName hashAlgorithm)
        {
            _signatureGenerator = signatureGenerator;
            _hashAlgorithm = hashAlgorithm;
            _dataStream = new MemoryStream();
        }

        public Stream Stream => _dataStream;

        public object GetResult()
        {
            var data = _dataStream.ToArray();
            var signature = _signatureGenerator.SignDataAsync(data, _hashAlgorithm, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            return new SignatureResult(signature);
        }
    }

    private class SignatureResult : IBlockResult
    {
        private readonly byte[] _signature;

        public SignatureResult(byte[] signature)
        {
            _signature = signature;
        }

        public byte[] Collect()
        {
            return _signature;
        }

        public int Collect(byte[] destination, int offset)
        {
            Array.Copy(_signature, 0, destination, offset, _signature.Length);
            return _signature.Length;
        }
    }
}
