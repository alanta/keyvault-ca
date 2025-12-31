using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation.Interfaces;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KeyVaultCa.Revocation;

/// <summary>
/// Builds OCSP responses per RFC 6960.
/// </summary>
public class OcspResponseBuilder
{
    private readonly IRevocationStore _revocationStore;
    private readonly KeyVaultSignatureGenerator _signatureGenerator;
    private readonly X509Certificate2 _ocspSigningCert;
    private readonly X509Certificate2 _issuerCert;
    private readonly TimeSpan _responseValidity;
    private readonly ILogger<OcspResponseBuilder> _logger;

    /// <summary>
    /// Creates a new OCSP response builder.
    /// </summary>
    /// <param name="revocationStore">Store for looking up revocation status</param>
    /// <param name="signatureGenerator">Generator for signing responses</param>
    /// <param name="ocspSigningCert">Certificate used to sign OCSP responses</param>
    /// <param name="issuerCert">CA certificate that issued the certificates being checked</param>
    /// <param name="logger">Logger instance</param>
    /// <param name="responseValidity">How long OCSP responses are valid (default: 24 hours)</param>
    public OcspResponseBuilder(
        IRevocationStore revocationStore,
        KeyVaultSignatureGenerator signatureGenerator,
        X509Certificate2 ocspSigningCert,
        X509Certificate2 issuerCert,
        ILogger<OcspResponseBuilder> logger,
        TimeSpan? responseValidity = null)
    {
        _revocationStore = revocationStore;
        _signatureGenerator = signatureGenerator;
        _ocspSigningCert = ocspSigningCert;
        _issuerCert = issuerCert;
        _responseValidity = responseValidity ?? TimeSpan.FromHours(24);
        _logger = logger;
    }

    /// <summary>
    /// Builds an OCSP response for the given request bytes.
    /// </summary>
    /// <param name="requestBytes">DER-encoded OCSP request</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>DER-encoded OCSP response</returns>
    public async Task<byte[]> BuildResponseAsync(byte[] requestBytes, CancellationToken ct = default)
    {
        try
        {
            // Parse OCSP request at ASN.1 level
            var asn1 = Asn1Object.FromByteArray(requestBytes);
            var ocspReq = OcspRequest.GetInstance(asn1);
            var tbsRequest = ocspReq.TbsRequest;
            var requestList = tbsRequest.RequestList;

            // Extract nonce from request extensions (RFC 6960 Appendix B)
            var nonce = ExtractNonce(tbsRequest.RequestExtensions);

            if (requestList == null || requestList.Count == 0)
            {
                _logger.LogWarning("OCSP request contains no certificate requests");
                return CreateErrorResponse(OcspResponseStatus.MalformedRequest);
            }

            // RFC 6960 allows multiple requests, but we only support one for simplicity
            if (requestList.Count > 1)
            {
                _logger.LogWarning("OCSP request contains {Count} requests; only one supported",
                    requestList.Count);
                return CreateErrorResponse(OcspResponseStatus.MalformedRequest);
            }

            // Process the first request (OCSP typically contains one request)
            var certReq = Request.GetInstance(requestList[0]);
            var certId = certReq.ReqCert;
            var serialNumber = certId.SerialNumber.Value.ToString(16).ToUpperInvariant();

            _logger.LogInformation("Processing OCSP request for certificate serial: {Serial}", serialNumber);

            // Validate that the certificate was issued by our CA (RFC 6960 Section 4.1.1)
            if (!ValidateIssuer(certId, _issuerCert))
            {
                _logger.LogWarning("OCSP request for certificate not issued by this CA (serial: {Serial})", serialNumber);
                return CreateErrorResponse(OcspResponseStatus.Unauthorized);
            }

            // Lookup revocation status
            var revocation = await _revocationStore.GetRevocationAsync(serialNumber, ct);

            // Determine certificate status
            CertStatus certStatus;
            if (revocation != null)
            {
                _logger.LogInformation("Certificate {Serial} is revoked (reason: {Reason})",
                    serialNumber, revocation.Reason);

                var revokedInfo = new RevokedInfo(
                    new DerGeneralizedTime(revocation.RevocationDate.UtcDateTime),
                    new CrlReason((int)revocation.Reason));

                certStatus = new CertStatus(revokedInfo);
            }
            else
            {
                _logger.LogInformation("Certificate {Serial} is good (not revoked)", serialNumber);
                certStatus = new CertStatus();
            }

            // Build single response
            var thisUpdate = new DerGeneralizedTime(DateTime.UtcNow);
            var nextUpdate = new DerGeneralizedTime(DateTime.UtcNow.Add(_responseValidity));

            // Build single extensions (echo nonce if present in request)
            var singleExtensions = BuildSingleExtensions(nonce);

            var singleResp = new SingleResponse(
                certId,
                certStatus,
                thisUpdate,
                nextUpdate,
                singleExtensions);

            // Build response data
            var responderID = GetResponderId();
            var producedAt = new DerGeneralizedTime(DateTime.UtcNow);
            var responses = new DerSequence(singleResp);

            // Build response extensions (RFC 6960 Section 4.2.2.2.1 - nocheck required)
            var responseExtensions = BuildResponseExtensions();

            var responseData = new ResponseData(
                responderID,
                producedAt,
                responses,
                responseExtensions);

            // Sign the response data
            var signatureBytes = await SignResponseDataAsync(responseData, ct);

            // Build certificate chain
            var certs = BuildCertificateChain();

            // Create BasicOcspResponse
            var sigAlgOid = GetSignatureAlgorithmOid();
            var signatureAlg = new AlgorithmIdentifier(new DerObjectIdentifier(sigAlgOid));

            var basicResp = new BasicOcspResponse(
                responseData,
                signatureAlg,
                new DerBitString(signatureBytes),
                certs);

            // Wrap in OCSPResponse
            var responseBytes = new ResponseBytes(
                OcspObjectIdentifiers.PkixOcspBasic,
                new DerOctetString(basicResp.GetEncoded()));

            var ocspResponse = new OcspResponse(
                new OcspResponseStatus(OcspResponseStatus.Successful),
                responseBytes);

            _logger.LogInformation("Successfully generated OCSP response for {Serial}", serialNumber);
            return ocspResponse.GetEncoded();
        }
        catch (Asn1ParsingException ex)
        {
            _logger.LogError(ex, "Malformed OCSP request (ASN.1 parsing error)");
            return CreateErrorResponse(OcspResponseStatus.MalformedRequest);
        }
        catch (NotSupportedException ex)
        {
            _logger.LogError(ex, "Unsupported hash algorithm in OCSP request");
            return CreateErrorResponse(OcspResponseStatus.MalformedRequest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Internal error processing OCSP request");
            return CreateErrorResponse(OcspResponseStatus.InternalError);
        }
    }

    private async Task<byte[]> SignResponseDataAsync(ResponseData responseData, CancellationToken ct)
    {
        var tbsBytes = responseData.GetEncoded();
        return await _signatureGenerator.SignDataAsync(tbsBytes, HashAlgorithmName.SHA256, ct);
    }

    private ResponderID GetResponderId()
    {
        // Use key hash for responder ID (recommended in RFC 6960)
        var skiExtension = _ocspSigningCert.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (skiExtension != null)
        {
            var skiBytes = Convert.FromHexString(skiExtension.SubjectKeyIdentifier!);
            return new ResponderID(new DerOctetString(skiBytes));
        }

        // Fallback to DN-based responder ID
        var bcCert = DotNetUtilities.FromX509Certificate(_ocspSigningCert);
        return new ResponderID(bcCert.SubjectDN);
    }

    private DerSequence BuildCertificateChain()
    {
        // Include OCSP signing certificate and issuer certificate in response
        var bcOcspCert = DotNetUtilities.FromX509Certificate(_ocspSigningCert);
        var bcIssuerCert = DotNetUtilities.FromX509Certificate(_issuerCert);

        return new DerSequence(
            X509CertificateStructure.GetInstance(
                Asn1Object.FromByteArray(bcOcspCert.GetEncoded())),
            X509CertificateStructure.GetInstance(
                Asn1Object.FromByteArray(bcIssuerCert.GetEncoded())));
    }

    private string GetSignatureAlgorithmOid()
    {
        var isEcdsa = _ocspSigningCert.GetECDsaPublicKey() != null;

        if (isEcdsa)
        {
            return "1.2.840.10045.4.3.2"; // ecdsa-with-SHA256
        }
        else
        {
            return "1.2.840.113549.1.1.11"; // sha256WithRSAEncryption
        }
    }

    /// <summary>
    /// Extracts nonce from OCSP request extensions.
    /// RFC 6960 Appendix B - Nonce extension OID 1.3.6.1.5.5.7.48.1.2
    /// </summary>
    private byte[]? ExtractNonce(X509Extensions? extensions)
    {
        if (extensions == null) return null;

        var nonceOid = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
        var nonceExt = extensions.GetExtension(nonceOid);
        if (nonceExt == null) return null;

        var octets = Asn1OctetString.GetInstance(
            Asn1Object.FromByteArray(nonceExt.Value.GetOctets()));
        return octets.GetOctets();
    }

    /// <summary>
    /// Builds single response extensions, echoing nonce if present.
    /// RFC 6960 Appendix B requires echoing nonce to prevent replay attacks.
    /// </summary>
    private X509Extensions? BuildSingleExtensions(byte[]? nonce)
    {
        if (nonce == null) return null;

        var nonceOid = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1.2");
        var nonceValue = new DerOctetString(nonce);
        var nonceExt = new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(nonceValue.GetEncoded()));

        var extensions = new Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>
        {
            { nonceOid, nonceExt }
        };

        return new X509Extensions(extensions);
    }

    /// <summary>
    /// Builds response extensions including the required "nocheck" extension.
    /// RFC 6960 Section 4.2.2.2.1 requires OCSP signing certificates to have nocheck extension.
    /// </summary>
    private X509Extensions BuildResponseExtensions()
    {
        // id-pkix-ocsp-nocheck (1.3.6.1.5.5.7.48.1.5)
        var nocheckOid = new DerObjectIdentifier("1.3.6.1.5.5.7.48.1.5");
        var nocheckValue = DerNull.Instance.GetEncoded();
        var nocheckExt = new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(nocheckValue));

        var extensions = new Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>
        {
            { nocheckOid, nocheckExt }
        };

        return new X509Extensions(extensions);
    }

    /// <summary>
    /// Validates that the CertID in the OCSP request matches our issuer certificate.
    /// Computes issuerNameHash and issuerKeyHash and compares them using constant-time comparison.
    /// </summary>
    private bool ValidateIssuer(CertID certId, X509Certificate2 issuerCert)
    {
        // Get hash algorithm from CertID
        var hashAlgOid = certId.HashAlgorithm.Algorithm.Id;
        HashAlgorithm hashAlg = hashAlgOid switch
        {
            "1.3.14.3.2.26" => SHA1.Create(),                   // sha1
            "2.16.840.1.101.3.4.2.1" => SHA256.Create(),        // sha256
            "2.16.840.1.101.3.4.2.2" => SHA384.Create(),        // sha384
            "2.16.840.1.101.3.4.2.3" => SHA512.Create(),        // sha512
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgOid} not supported in OCSP request")
        };

        // Compute expected issuerNameHash
        var issuerDN = issuerCert.SubjectName.RawData;
        var expectedNameHash = hashAlg.ComputeHash(issuerDN);

        // Compute expected issuerKeyHash (from subject public key field)
        var issuerKeyInfo = issuerCert.PublicKey.EncodedKeyValue.RawData;
        var expectedKeyHash = hashAlg.ComputeHash(issuerKeyInfo);

        // Constant-time comparison to prevent timing attacks
        var nameHashMatch = CryptographicOperations.FixedTimeEquals(
            certId.IssuerNameHash.GetOctets(), expectedNameHash);
        var keyHashMatch = CryptographicOperations.FixedTimeEquals(
            certId.IssuerKeyHash.GetOctets(), expectedKeyHash);

        return nameHashMatch && keyHashMatch;
    }

    private static byte[] CreateErrorResponse(int status)
    {
        var ocspResponse = new OcspResponse(
            new OcspResponseStatus(status),
            null); // No response bytes for errors

        return ocspResponse.GetEncoded();
    }
}
