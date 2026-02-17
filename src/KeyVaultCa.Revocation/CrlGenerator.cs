using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation.Interfaces;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KeyVaultCa.Revocation;

/// <summary>
/// Generates Certificate Revocation Lists (CRLs) per RFC 5280.
/// </summary>
public class CrlGenerator
{
    private readonly IRevocationStore _revocationStore;

    public CrlGenerator(IRevocationStore revocationStore)
    {
        _revocationStore = revocationStore;
    }

    /// <summary>
    /// Generates a CRL signed by the specified issuer certificate using Azure Key Vault.
    /// </summary>
    /// <param name="issuerCertificate">The CA certificate that will sign the CRL</param>
    /// <param name="signatureGenerator">The Key Vault signature generator for the issuer's key</param>
    /// <param name="issuerDistinguishedName">The issuer DN to filter revocations</param>
    /// <param name="validityPeriod">How long the CRL is valid (thisUpdate to nextUpdate)</param>
    /// <param name="hashAlgorithm">Hash algorithm to use for signing (default: SHA256)</param>
    /// <param name="crlNumber">Sequential CRL number for tracking versions</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>DER-encoded CRL bytes</returns>
    public async Task<byte[]> GenerateCrlAsync(
        X509Certificate2 issuerCertificate,
        KeyVaultSignatureGenerator signatureGenerator,
        string issuerDistinguishedName,
        TimeSpan validityPeriod,
        HashAlgorithmName? hashAlgorithm = null,
        long? crlNumber = null,
        CancellationToken ct = default)
    {
        hashAlgorithm ??= HashAlgorithmName.SHA256;

        // Get all revocations for this issuer
        var revocations = await _revocationStore.GetRevocationsByIssuerAsync(issuerDistinguishedName, ct);

        // Build CRL using BouncyCastle
        var crlGen = new X509V2CrlGenerator();

        // Set issuer DN
        crlGen.SetIssuerDN(new X509Name(issuerDistinguishedName));

        // Set validity period
        var thisUpdate = DateTime.UtcNow;
        var nextUpdate = thisUpdate.Add(validityPeriod);
        crlGen.SetThisUpdate(thisUpdate);
        crlGen.SetNextUpdate(nextUpdate);

        // Add revoked certificates
        foreach (var revocation in revocations)
        {
            try
            {
                var serialNumber = new BigInteger(revocation.SerialNumber, 16);
                crlGen.AddCrlEntry(
                    serialNumber,
                    revocation.RevocationDate.UtcDateTime,
                    (int)revocation.Reason);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    $"Invalid serial number format: {revocation.SerialNumber}. Serial numbers must be valid hexadecimal strings.",
                    ex);
            }
        }

        // Add CRL Number extension (optional but recommended)
        if (crlNumber.HasValue)
        {
            crlGen.AddExtension(
                X509Extensions.CrlNumber,
                critical: false,
                extensionValue: new CrlNumber(BigInteger.ValueOf(crlNumber.Value)));
        }

        // Add Authority Key Identifier extension
        var authorityKeyIdentifier = BuildAuthorityKeyIdentifier(issuerCertificate);
        crlGen.AddExtension(
            X509Extensions.AuthorityKeyIdentifier,
            critical: false,
            extensionValue: authorityKeyIdentifier);

        // Sign using Key Vault via BouncyCastle adapter
        var signatureFactory = new BouncyCastleSignatureFactory(
            signatureGenerator,
            issuerCertificate,
            hashAlgorithm.Value);

        var crl = crlGen.Generate(signatureFactory);

        return crl.GetEncoded();
    }

    private static AuthorityKeyIdentifier BuildAuthorityKeyIdentifier(X509Certificate2 issuerCertificate)
    {
        // Find the Subject Key Identifier extension in the issuer certificate
        var skiExtension = issuerCertificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (skiExtension != null)
        {
            // Parse the SKI from the extension
            var skiBytes = Convert.FromHexString(skiExtension.SubjectKeyIdentifier!);
            return new AuthorityKeyIdentifier(skiBytes);
        }

        // If no SKI extension, compute from public key (fallback per RFC 5280)
        var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
            DotNetUtilities.GetRsaPublicKey(issuerCertificate.GetRSAPublicKey()!));

        return new AuthorityKeyIdentifier(publicKeyInfo);
    }
}
