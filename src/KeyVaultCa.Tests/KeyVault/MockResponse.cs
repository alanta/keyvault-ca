using System.Diagnostics.CodeAnalysis;
using Azure;
using Azure.Core;

namespace KeyVaultCA.Tests.KeyVault;

/// <summary>
/// Mock typed response for a KeyVault operation.
/// </summary>
/// <typeparam name="T">The type of the value.</typeparam>
public sealed class MockResponse<T> : Response<T>
{
    public static MockResponse<T> Ok(T value) => new (MockResponse.Ok(), value);
    
    private readonly Response _rawResponse;
    
    private MockResponse( MockResponse response, T value)
    {
        _rawResponse = response;
        Value = value;
    }

    public override Response GetRawResponse()
    {
        return _rawResponse;
    }

    public override T Value { get; }
}

/// <summary>
/// Mock response for a KeyVault operation.
/// </summary>
public sealed class MockResponse : Response
{
    public static MockResponse NotFound() => new(404, "Not Found");
    public static MockResponse Ok() => new(200, "OK");

    private MockResponse(int status, string reasonPhrase)
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

    public override void Dispose()
    {
    }

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