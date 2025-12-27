using System;
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

            if (requestList == null || requestList.Count == 0)
            {
                _logger.LogWarning("OCSP request contains no certificate requests");
                return CreateErrorResponse(OcspResponseStatus.MalformedRequest);
            }

            // Process the first request (OCSP typically contains one request)
            var certReq = Request.GetInstance(requestList[0]);
            var certId = certReq.ReqCert;
            var serialNumber = certId.SerialNumber.Value.ToString(16).ToUpperInvariant();

            _logger.LogInformation("Processing OCSP request for certificate serial: {Serial}", serialNumber);

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

            var singleResp = new SingleResponse(
                certId,
                certStatus,
                thisUpdate,
                nextUpdate,
                null); // No single extensions

            // Build response data
            var responderID = GetResponderId();
            var producedAt = new DerGeneralizedTime(DateTime.UtcNow);
            var responses = new DerSequence(singleResp);

            var responseData = new ResponseData(
                responderID,
                producedAt,
                responses,
                null); // No response extensions

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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing OCSP request");
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

    private static byte[] CreateErrorResponse(int status)
    {
        var ocspResponse = new OcspResponse(
            new OcspResponseStatus(status),
            null); // No response bytes for errors

        return ocspResponse.GetEncoded();
    }
}
