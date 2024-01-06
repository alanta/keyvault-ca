using System.Diagnostics.CodeAnalysis;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using FakeItEasy;

namespace KeyVaultCA.Tests.KeyVault;

public static class MockKeyVault
{
    public static CertificateClient WithMergeCertificateBehavior(this CertificateClient certificateClient, CertificateStore certificates)
    {
        // Merge a certificate
        A.CallTo(() => certificateClient.MergeCertificateAsync(A<MergeCertificateOptions>._, A<CancellationToken>._))
            .ReturnsLazily((MergeCertificateOptions options, CancellationToken ct) =>
            {
                var certOperation = certificates.Merge(options.Name, options.X509Certificates.First());
                var model = CertificateModelFactory.KeyVaultCertificateWithPolicy(certOperation.Value.Properties, certOperation.Value.KeyId, certOperation.Value.SecretId, certOperation.Value.Cer );
                return Response.FromValue(model, MockResponse.Ok());
            });

        return certificateClient;
    }

    public static CertificateClient WithCreateCertificateBehavior(this CertificateClient certificateClient, CertificateStore certificates)
    {
        // Start a certificate creation operation. Returns a completed operation.
        A.CallTo(() => certificateClient.StartCreateCertificateAsync(A<string>._, A<CertificatePolicy>._,
                A<bool?>._, A<IDictionary<string, string>>._, A<CancellationToken>._))
            .ReturnsLazily((string name, CertificatePolicy policy, bool? _, IDictionary<string, string>? _, CancellationToken _) =>
            {
                var operation = certificates.StartOperation(name, policy);
                return Response.FromValue(operation, MockResponse.Ok());
            });

        return certificateClient;
    }

    public static CertificateClient WithGetCertificateBehavior(this CertificateClient certificateClient, CertificateStore certificates)
    {
        // Get a certificate
        A.CallTo(() => certificateClient.GetCertificateAsync(A<string>._, A<CancellationToken>._))
            .ReturnsLazily((string name, CancellationToken ct) =>
            {
                var cert = certificates.GetCertificateByName(name);
                if( cert == null)
                    throw new RequestFailedException(404, "Not Found");

                return Response.FromValue(cert, MockResponse.Ok());
                
            });

        return certificateClient;
    }

    public static CertificateClient WithGetCertificateVersionBehavior(this CertificateClient certificateClient, CertificateStore certificates)
    {
        A.CallTo(() => certificateClient.GetCertificateVersionAsync(A<string>._, A<string>._, A<CancellationToken>._))
            .ReturnsLazily((string name, string version, CancellationToken ct) =>
            {
                var cert = certificates.GetCertificateByNameAndVersion(name, version);
                if (cert == null)
                    throw new RequestFailedException(404, "Not Found");

                return Response.FromValue(cert, MockResponse.Ok());

            });

        A.CallTo(() => certificateClient.GetPropertiesOfCertificateVersionsAsync(A<string>._, A<CancellationToken>._))
            .ReturnsLazily((string certName, CancellationToken ct) =>
            {
                var results = certificates.GetPropertiesOfCertificateVersionsByName(certName);

                var pages = AsyncPageable<CertificateProperties>.FromPages(new[] { Page<CertificateProperties>.FromValues(results, "nope", MockResponse.Ok()) });

                return Response.FromValue( pages, MockResponse.Ok());
            });

        return certificateClient;
    }

    public static CertificateClient WithGetCertificateOperationBehavior(this CertificateClient certificateClient,
        CertificateStore certificates)
    {
        // Get a certificate operation
        A.CallTo(() => certificateClient.GetCertificateOperationAsync(A<string>._, A<CancellationToken>._))
            .ReturnsLazily((string name, CancellationToken ct) =>
            {
                var cert = certificates.GetCertificateOperationByName(name);
                if( cert == null)
                    throw new RequestFailedException(404, "Not Found");

                return Response.FromValue(cert, MockResponse.Ok());
                
            });

        return certificateClient;
    }
}


public sealed class MockResponse : Response
{
    public static MockResponse NotFound() => new (404, "Not Found");
    public static MockResponse Ok() => new (200, "OK");

    private MockResponse( int status, string reasonPhrase)
    {
        Status = status;
        ReasonPhrase = reasonPhrase;
        ClientRequestId = Guid.NewGuid().ToString();
    }

    public override int Status { get; }

    public override string ReasonPhrase { get; }

    public override Stream? ContentStream
    {
        get => throw new NotImplementedException();
        set => throw new NotImplementedException();
    }
    public override string ClientRequestId { get; set; }

    public override void Dispose() {}
    protected override bool ContainsHeader(string name) => false;
    protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];
    protected override bool TryGetHeader(
        string name,
        [NotNullWhen(true)] out string? value) =>
        throw new NotImplementedException();
    protected override bool TryGetHeaderValues(
        string name,
        [NotNullWhen(true)] out IEnumerable<string>? values) =>
        throw new NotImplementedException();
}


