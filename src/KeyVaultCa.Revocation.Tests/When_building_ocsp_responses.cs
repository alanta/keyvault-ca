using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FakeItEasy;
using KeyVaultCa.Revocation.Models;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Shouldly;
using Xunit;

namespace KeyVaultCa.Revocation.Tests;

public class When_building_ocsp_responses : TestBase
{
    [Fact]
    public async Task It_should_return_good_status_for_non_revoked_certificate()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var ocspSigningCert = CreateTestCertificate("CN=OCSP Signer", isCa: false);
        var signatureGenerator = CreateFakeSignatureGenerator(ocspSigningCert);
        var revocationStore = CreateFakeRevocationStore();
        var logger = CreateFakeLogger<OcspResponseBuilder>();

        // Setup: certificate is NOT revoked
        A.CallTo(() => revocationStore.GetRevocationAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<RevocationRecord?>(null));

        var responseBuilder = new OcspResponseBuilder(
            revocationStore,
            signatureGenerator,
            ocspSigningCert,
            issuerCert,
            logger);

        var ocspRequest = CreateOcspRequest("1234567890ABCDEF");

        // Act
        var responseBytes = await responseBuilder.BuildResponseAsync(ocspRequest, CancellationToken.None);

        // Assert
        responseBytes.ShouldNotBeNull();
        responseBytes.Length.ShouldBeGreaterThan(0);

        // Parse the response
        var ocspResponse = OcspResponse.GetInstance(Asn1Object.FromByteArray(responseBytes));
        ocspResponse.ResponseStatus.IntValueExact.ShouldBe(OcspResponseStatus.Successful);

        var responseBytes2 = ResponseBytes.GetInstance(ocspResponse.ResponseBytes);
        var basicResponse = BasicOcspResponse.GetInstance(
            Asn1Object.FromByteArray(responseBytes2.Response.GetOctets()));

        var singleResponses = basicResponse.TbsResponseData.Responses;
        singleResponses.Count.ShouldBe(1);

        var singleResponse = SingleResponse.GetInstance(singleResponses[0]);
        var certStatus = singleResponse.CertStatus;

        // CertStatus with no tag means "good"
        certStatus.TagNo.ShouldBe(0); // Good status
    }

    [Fact]
    public async Task It_should_return_revoked_status_for_revoked_certificate()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var ocspSigningCert = CreateTestCertificate("CN=OCSP Signer", isCa: false);
        var signatureGenerator = CreateFakeSignatureGenerator(ocspSigningCert);
        var revocationStore = CreateFakeRevocationStore();
        var logger = CreateFakeLogger<OcspResponseBuilder>();

        const string serialNumber = "1234567890ABCDEF";
        var revocationDate = DateTimeOffset.UtcNow.AddDays(-1);

        // Setup: certificate IS revoked
        A.CallTo(() => revocationStore.GetRevocationAsync(serialNumber, A<CancellationToken>._))
            .Returns(Task.FromResult<RevocationRecord?>(new RevocationRecord
            {
                SerialNumber = serialNumber,
                RevocationDate = revocationDate,
                Reason = RevocationReason.KeyCompromise,
                IssuerDistinguishedName = issuerCert.Subject
            }));

        var responseBuilder = new OcspResponseBuilder(
            revocationStore,
            signatureGenerator,
            ocspSigningCert,
            issuerCert,
            logger);

        var ocspRequest = CreateOcspRequest(serialNumber);

        // Act
        var responseBytes = await responseBuilder.BuildResponseAsync(ocspRequest, CancellationToken.None);

        // Assert
        responseBytes.ShouldNotBeNull();

        var ocspResponse = OcspResponse.GetInstance(Asn1Object.FromByteArray(responseBytes));
        var responseBytes2 = ResponseBytes.GetInstance(ocspResponse.ResponseBytes);
        var basicResponse = BasicOcspResponse.GetInstance(
            Asn1Object.FromByteArray(responseBytes2.Response.GetOctets()));

        var singleResponse = SingleResponse.GetInstance(basicResponse.TbsResponseData.Responses[0]);
        var certStatus = singleResponse.CertStatus;

        // TagNo 1 means "revoked"
        certStatus.TagNo.ShouldBe(1);

        var revokedInfo = RevokedInfo.GetInstance(certStatus.Status);
        revokedInfo.ShouldNotBeNull();
    }

    [Fact]
    public async Task It_should_include_certificate_chain_in_response()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var ocspSigningCert = CreateTestCertificate("CN=OCSP Signer", isCa: false);
        var signatureGenerator = CreateFakeSignatureGenerator(ocspSigningCert);
        var revocationStore = CreateFakeRevocationStore();
        var logger = CreateFakeLogger<OcspResponseBuilder>();

        A.CallTo(() => revocationStore.GetRevocationAsync(A<string>._, A<CancellationToken>._))
            .Returns(Task.FromResult<RevocationRecord?>(null));

        var responseBuilder = new OcspResponseBuilder(
            revocationStore,
            signatureGenerator,
            ocspSigningCert,
            issuerCert,
            logger);

        var ocspRequest = CreateOcspRequest("1234567890ABCDEF");

        // Act
        var responseBytes = await responseBuilder.BuildResponseAsync(ocspRequest, CancellationToken.None);

        // Assert
        var ocspResponse = OcspResponse.GetInstance(Asn1Object.FromByteArray(responseBytes));
        var responseBytes2 = ResponseBytes.GetInstance(ocspResponse.ResponseBytes);
        var basicResponse = BasicOcspResponse.GetInstance(
            Asn1Object.FromByteArray(responseBytes2.Response.GetOctets()));

        var certs = basicResponse.Certs;
        certs.ShouldNotBeNull();
        certs.Count.ShouldBe(2); // OCSP signing cert + issuer cert
    }

    [Fact]
    public async Task It_should_return_malformed_request_for_empty_request()
    {
        // Arrange
        var issuerCert = CreateTestCertificate("CN=Test CA", isCa: true);
        var ocspSigningCert = CreateTestCertificate("CN=OCSP Signer", isCa: false);
        var signatureGenerator = CreateFakeSignatureGenerator(ocspSigningCert);
        var revocationStore = CreateFakeRevocationStore();
        var logger = CreateFakeLogger<OcspResponseBuilder>();

        var responseBuilder = new OcspResponseBuilder(
            revocationStore,
            signatureGenerator,
            ocspSigningCert,
            issuerCert,
            logger);

        var emptyRequest = CreateOcspRequestWithNoRequests();

        // Act
        var responseBytes = await responseBuilder.BuildResponseAsync(emptyRequest, CancellationToken.None);

        // Assert
        var ocspResponse = OcspResponse.GetInstance(Asn1Object.FromByteArray(responseBytes));
        ocspResponse.ResponseStatus.IntValueExact.ShouldBe(OcspResponseStatus.MalformedRequest);
        ocspResponse.ResponseBytes.ShouldBeNull(); // Error responses don't have response bytes
    }

    // Helper methods to create OCSP requests
    private static byte[] CreateOcspRequest(string serialNumberHex)
    {
        var serialNumber = new BigInteger(serialNumberHex, 16);
        var certId = new CertID(
            new AlgorithmIdentifier(new DerObjectIdentifier("1.3.14.3.2.26")), // SHA-1
            new DerOctetString(new byte[20]), // Fake issuer name hash
            new DerOctetString(new byte[20]), // Fake issuer key hash
            new DerInteger(serialNumber));

        var request = new Request(certId, null);
        var requests = new DerSequence(request);

        var tbsRequest = new TbsRequest(null, requests, null);
        var ocspRequest = new OcspRequest(tbsRequest, null);

        return ocspRequest.GetEncoded();
    }

    private static byte[] CreateOcspRequestWithNoRequests()
    {
        var requests = new DerSequence(); // Empty sequence
        var tbsRequest = new TbsRequest(null, requests, null);
        var ocspRequest = new OcspRequest(tbsRequest, null);

        return ocspRequest.GetEncoded();
    }
}
